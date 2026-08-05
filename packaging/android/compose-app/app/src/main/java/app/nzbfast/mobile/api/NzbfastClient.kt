package app.nzbfast.mobile.api

import org.json.JSONObject

/**
 * Hand-rolled client for the daemon endpoints this app uses. The full
 * request/response inventory is CONTRACT.md next to the app; keep the
 * two in sync when this grows.
 *
 * Auth: the API key rides the X-Api-Key header for /api calls (query
 * fallback exists server-side but headers keep keys out of logs).
 * Never send a `t` query param to /api - that path belongs to the
 * newznab facade.
 */
class NzbfastClient(private val baseUrl: String, private val apiKey: String) {

    private fun api(query: String): String =
        Http.get("$baseUrl/api?$query", apiKey = apiKey)

    fun version(): String = Parse.version(api("mode=version"))

    fun queue(): QueueSnapshot = Parse.queue(api("mode=queue"))

    fun history(): List<HistorySlot> = Parse.history(api("mode=history"))

    fun addFile(fileName: String, bytes: ByteArray, category: String? = null): AddResult {
        val fields = buildMap {
            put("apikey", apiKey)
            category?.let { put("cat", it) }
        }
        val body = Http.postMultipart(
            "$baseUrl/api?mode=addfile",
            fields,
            fileField = "nzbfile",
            fileName = fileName,
            fileBytes = bytes,
        )
        return Parse.addResult(body)
    }

    fun addNzbLnk(link: String): AddResult =
        Parse.addResult(api("mode=addnzblnk&link=${Http.encode(link)}"))

    fun pauseJob(nzoId: String): Boolean =
        Parse.statusOk(api("mode=queue&name=pause&value=${Http.encode(nzoId)}"))

    fun resumeJob(nzoId: String): Boolean =
        Parse.statusOk(api("mode=queue&name=resume&value=${Http.encode(nzoId)}"))

    fun deleteJob(nzoId: String, deleteFiles: Boolean): Boolean =
        Parse.statusOk(
            api(
                "mode=queue&name=delete&value=${Http.encode(nzoId)}" +
                    if (deleteFiles) "&del_files=1" else ""
            )
        )

    fun deleteHistory(nzoId: String, deleteFiles: Boolean): Boolean =
        Parse.statusOk(
            api(
                "mode=history&name=delete&value=${Http.encode(nzoId)}" +
                    if (deleteFiles) "&del_files=1" else ""
            )
        )

    fun pauseAll(): Boolean = Parse.statusOk(api("mode=pause"))

    fun resumeAll(): Boolean = Parse.statusOk(api("mode=resume"))

    fun serversConfigured(): Boolean = Parse.serversConfigured(api("mode=get_config"))

    /** Probe playability; 404 while nothing is downloadable yet. */
    fun probe(nzoId: String): ProbeResult? = try {
        Parse.probe(Http.get("$baseUrl/preview/probe/${Http.encode(nzoId)}", apiKey = apiKey))
    } catch (e: Http.HttpError) {
        null
    }

    /**
     * URL the player should open for a job. The /m3u body embeds the
     * per-job stream token, so the long-lived player URL never carries
     * the API key. Falls back to an apikey-authed /stream URL if the
     * m3u fetch fails.
     */
    fun streamUrl(nzoId: String): String {
        val id = Http.encode(nzoId)
        return try {
            val m3u = Http.get("$baseUrl/m3u/$id", apiKey = apiKey)
            Parse.m3uUrl(m3u) ?: fallbackStreamUrl(id)
        } catch (e: Exception) {
            fallbackStreamUrl(id)
        }
    }

    private fun fallbackStreamUrl(encodedId: String): String {
        val key = if (apiKey.isEmpty()) "" else "?apikey=${Http.encode(apiKey)}"
        return "$baseUrl/stream/$encodedId$key"
    }

    /** First-run news-server save. index -1 appends. */
    fun serverSave(
        host: String,
        port: Int,
        tls: Boolean,
        username: String,
        password: String,
        connections: Int = 8,
    ): Boolean {
        val body = serverJson(host, port, tls, username, password, connections)
        return Parse.statusOk(postJson("mode=server_save", body))
    }

    fun serverTest(
        host: String,
        port: Int,
        tls: Boolean,
        username: String,
        password: String,
        connections: Int = 8,
    ): ServerTestResult {
        val body = serverJson(host, port, tls, username, password, connections)
        return Parse.serverTest(postJson("mode=server_test", body))
    }

    private fun serverJson(
        host: String,
        port: Int,
        tls: Boolean,
        username: String,
        password: String,
        connections: Int,
    ): String {
        val server = JSONObject()
            .put("host", host)
            .put("port", port)
            .put("tls", tls)
            .put("username", username)
            .put("password", password)
            .put("connections", connections)
        return JSONObject().put("index", -1).put("server", server).toString()
    }

    private fun postJson(query: String, jsonBody: String): String =
        Http.postJson("$baseUrl/api?$query", jsonBody, apiKey = apiKey)
}

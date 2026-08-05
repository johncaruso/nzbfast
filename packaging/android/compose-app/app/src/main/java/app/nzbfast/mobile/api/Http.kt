package app.nzbfast.mobile.api

import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.net.HttpURLConnection
import java.net.URL
import java.net.URLEncoder

/**
 * Minimal HTTP plumbing for the hand-rolled daemon client. The app
 * deliberately has no HTTP library dependency: the daemon API is a
 * handful of GETs plus one multipart POST, and HttpURLConnection
 * covers both on every supported API level.
 */
internal object Http {

    class HttpError(val code: Int, message: String) : Exception("HTTP $code: $message")

    fun encode(v: String): String = URLEncoder.encode(v, "UTF-8")

    fun get(url: String, apiKey: String? = null, timeoutMs: Int = 10_000): String {
        val c = URL(url).openConnection() as HttpURLConnection
        c.connectTimeout = timeoutMs
        c.readTimeout = timeoutMs
        if (!apiKey.isNullOrEmpty()) c.setRequestProperty("X-Api-Key", apiKey)
        try {
            val code = c.responseCode
            val body = readAll(if (code in 200..299) c.inputStream else c.errorStream)
            if (code !in 200..299) throw HttpError(code, body.take(200))
            return body
        } finally {
            c.disconnect()
        }
    }

    /** One multipart/form-data POST: form fields plus a single file part. */
    fun postMultipart(
        url: String,
        fields: Map<String, String>,
        fileField: String,
        fileName: String,
        fileBytes: ByteArray,
        timeoutMs: Int = 30_000,
    ): String {
        val boundary = "nzbfast-${System.nanoTime()}"
        val c = URL(url).openConnection() as HttpURLConnection
        c.connectTimeout = timeoutMs
        c.readTimeout = timeoutMs
        c.requestMethod = "POST"
        c.doOutput = true
        c.setRequestProperty("Content-Type", "multipart/form-data; boundary=$boundary")
        try {
            c.outputStream.use { out ->
                val w = out.bufferedWriter(Charsets.UTF_8)
                for ((k, v) in fields) {
                    w.write("--$boundary\r\n")
                    w.write("Content-Disposition: form-data; name=\"$k\"\r\n\r\n")
                    w.write("$v\r\n")
                }
                w.write("--$boundary\r\n")
                w.write(
                    "Content-Disposition: form-data; name=\"$fileField\"; " +
                        "filename=\"${fileName.replace("\"", "_")}\"\r\n"
                )
                w.write("Content-Type: application/x-nzb\r\n\r\n")
                w.flush()
                out.write(fileBytes)
                out.flush()
                w.write("\r\n--$boundary--\r\n")
                w.flush()
            }
            val code = c.responseCode
            val body = readAll(if (code in 200..299) c.inputStream else c.errorStream)
            if (code !in 200..299) throw HttpError(code, body.take(200))
            return body
        } finally {
            c.disconnect()
        }
    }

    /** JSON POST used by server_save / server_test. */
    fun postJson(url: String, body: String, apiKey: String? = null, timeoutMs: Int = 20_000): String {
        val c = URL(url).openConnection() as HttpURLConnection
        c.connectTimeout = timeoutMs
        c.readTimeout = timeoutMs
        if (!apiKey.isNullOrEmpty()) c.setRequestProperty("X-Api-Key", apiKey)
        c.requestMethod = "POST"
        c.doOutput = true
        c.setRequestProperty("Content-Type", "application/json")
        try {
            c.outputStream.use { it.write(body.toByteArray(Charsets.UTF_8)) }
            val code = c.responseCode
            val text = readAll(if (code in 200..299) c.inputStream else c.errorStream)
            if (code !in 200..299) throw HttpError(code, text.take(200))
            return text
        } finally {
            c.disconnect()
        }
    }

    private fun readAll(s: InputStream?): String {
        if (s == null) return ""
        val buf = ByteArrayOutputStream()
        s.use { it.copyTo(buf) }
        return buf.toString("UTF-8")
    }
}

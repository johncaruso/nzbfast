package app.nzbfast.mobile

import android.content.Context

/**
 * Where the UI points. On-device mode execs the bundled engine and
 * talks to 127.0.0.1; server mode talks to a daemon the user runs
 * elsewhere. One UI, two sources - which daemon is a setting.
 */
enum class Mode { DEVICE, SERVER }

data class Connection(val mode: Mode, val baseUrl: String, val apiKey: String)

object Store {
    private const val PREFS = "nzbfast"

    fun load(ctx: Context): Connection? {
        val p = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val mode = p.getString("mode", null) ?: return null
        return if (mode == "device") {
            Connection(
                Mode.DEVICE,
                "http://127.0.0.1:${EngineService.PORT}",
                EngineService.apiKey(ctx),
            )
        } else {
            val url = p.getString("server_url", null) ?: return null
            val key = p.getString("server_key", "") ?: ""
            Connection(Mode.SERVER, url.trimEnd('/'), key)
        }
    }

    fun saveDevice(ctx: Context) {
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit().putString("mode", "device").apply()
    }

    fun saveServer(ctx: Context, url: String, key: String) {
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit()
            .putString("mode", "server")
            .putString("server_url", url.trim().trimEnd('/'))
            .putString("server_key", key.trim())
            .apply()
    }

    fun clear(ctx: Context) {
        ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            .edit().remove("mode").apply()
    }
}

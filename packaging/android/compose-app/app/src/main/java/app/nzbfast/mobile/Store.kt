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

    /**
     * Which source the user chose, with no endpoint resolved.
     *
     * On-device mode has no endpoint to resolve until the engine is
     * running and has said where it is listening, so deciding "do I start
     * the engine?" has to be answerable before that. [load] is the one
     * that needs a live listener; this one only needs the choice.
     */
    fun savedMode(ctx: Context): Mode? =
        when (ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getString("mode", null)) {
            "device" -> Mode.DEVICE
            null -> null
            else -> Mode.SERVER
        }

    /**
     * The endpoint of an on-device engine that has PROVEN it is ours.
     *
     * Takes the proven [EngineIdentity.Runtime] rather than re-reading
     * runtime.json, so the URL the key is sent to is the exact listener
     * that answered the challenge. Re-reading would reopen a gap the
     * proof closed: the file is rewritten on every daemon start, so a
     * restart between the challenge and the read would point the key at
     * an endpoint nothing verified.
     */
    fun deviceConnection(ctx: Context, rt: EngineIdentity.Runtime): Connection =
        Connection(
            Mode.DEVICE,
            "http://127.0.0.1:${rt.port}",
            EngineService.apiKey(ctx),
        )

    /**
     * The saved connection, or null when there is nothing to connect to.
     *
     * The device arm reads the port out of runtime.json and has NO
     * constant to fall back on. It used to build
     * `http://127.0.0.1:${EngineService.PORT}` from a hardcoded 6791; the
     * engine now binds whatever the OS gives it (see EngineService), so a
     * constant here would dial a port that belongs to nobody, or worse to
     * somebody else - which is the whole reason the port stopped being
     * fixed.
     *
     * Upgrading from the fixed-port build needs no migration, and this is
     * why: the saved shape never carried a port. `saveDevice` writes the
     * single key `mode=device` and the URL was always derived at load
     * time, so an install carrying state from the old app arrives here
     * with nothing stale to correct - the derivation changed underneath
     * it, and the answer now comes from the running engine. What such an
     * install DOES carry is the old daemon's runtime.json, naming 6791
     * with a dead token; that record cannot pass the challenge and is
     * replaced the moment the new engine starts.
     *
     * Null with `mode=device` saved therefore means "the engine has not
     * reported in yet", not "not configured". Callers that can start the
     * engine should do that and wait for [EngineIdentity.awaitVerified],
     * which is the path MainActivity takes.
     */
    fun load(ctx: Context): Connection? {
        val p = ctx.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
        val mode = p.getString("mode", null) ?: return null
        return if (mode == "device") {
            EngineIdentity.readRuntime(ctx)?.let { deviceConnection(ctx, it) }
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

package app.nzbfast.mobile

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Build
import android.os.IBinder
import java.io.File
import java.security.SecureRandom

/**
 * Foreground service hosting the on-device engine. The binary ships as
 * libnzbfast.so in jniLibs; with legacy packaging the installer puts a
 * real file in nativeLibraryDir, and exec from there is the
 * post-API-29-legal way to run a bundled binary. Same mechanism as the
 * proven packaging/android/app test APK.
 *
 * The daemon binds 127.0.0.1 only, on a port the OS chooses. Downloads
 * land in filesDir/downloads until the export story exists.
 */
class EngineService : Service() {

    companion object {
        private const val CHANNEL = "engine"

        /** One API key per install, minted on first use. */
        fun apiKey(ctx: Context): String {
            val p = ctx.getSharedPreferences("nzbfast", Context.MODE_PRIVATE)
            p.getString("apikey", null)?.let { return it }
            val b = ByteArray(24)
            SecureRandom().nextBytes(b)
            val k = b.joinToString("") { "%02x".format(it) }
            p.edit().putString("apikey", k).apply()
            return k
        }
    }

    private var engine: Process? = null

    override fun onCreate() {
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL, "Engine", NotificationManager.IMPORTANCE_LOW)
        )
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val n: Notification = Notification.Builder(this, CHANNEL)
            .setSmallIcon(android.R.drawable.stat_sys_download)
            .setContentTitle("nzbfast")
            .setContentText("engine running on this device")
            .setOngoing(true)
            .build()
        if (Build.VERSION.SDK_INT >= 29) {
            startForeground(1, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC)
        } else {
            startForeground(1, n)
        }
        startEngine()
        return START_STICKY
    }

    private fun startEngine() {
        if (engine?.isAlive == true) return
        try {
            val base = filesDir
            val dl = File(base, "downloads").apply { mkdirs() }
            val watch = File(base, "watch").apply { mkdirs() }
            val cfg = File(base, "config").apply { mkdirs() }
            val bin = applicationInfo.nativeLibraryDir + "/libnzbfast.so"
            val pb = ProcessBuilder(
                bin,
                "--config", File(cfg, "config.json").absolutePath,
                "serve",
                "--bind", "127.0.0.1",
                // 0 = let the OS pick. The engine used to bind a fixed
                // 6791, and every app on a phone shares ONE loopback
                // namespace, so a port a sibling app can predict is a
                // port it can pre-bind before us (Codex sweep 12 Aug F4).
                // Identity is still proved by the runtime.json token, not
                // by the port - see EngineIdentity - but a port nobody can
                // name in advance is one nobody can lie in wait on.
                //
                // Where the answer comes back: the daemon reports the port
                // it actually bound in runtime.json, and Store.load reads
                // it from there. Nothing in this app holds a port constant.
                "--port", "0",
                "--apikey", apiKey(this),
                "--out", dl.absolutePath,
                "--watch", watch.absolutePath,
            )
            // The launcher owns the port, so a `port` in settings.json must
            // not overrule the `--port 0` above. Without this a value saved
            // from the daemon's own embedded dashboard would pin the
            // listener back to one fixed port, and the randomisation would
            // stop happening with nothing to show it had.
            pb.environment()["NZBFAST_PORT_LOCKED"] = "1"
            pb.environment()["HOME"] = base.absolutePath
            pb.environment()["TMPDIR"] = cacheDir.absolutePath
            pb.redirectErrorStream(true)
            pb.redirectOutput(File(base, "daemon.log"))
            engine = pb.start()
        } catch (e: Exception) {
            stopSelf()
        }
    }

    override fun onDestroy() {
        engine?.destroy()
        engine = null
    }

    override fun onBind(intent: Intent?): IBinder? = null
}

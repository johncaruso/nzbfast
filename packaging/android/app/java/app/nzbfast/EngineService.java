package app.nzbfast;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.Service;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.ServiceInfo;
import android.os.Build;
import android.os.IBinder;
import java.io.File;
import java.security.SecureRandom;

/**
 * Foreground service hosting the engine. The binary ships as
 * libnzbfast.so in jniLibs; with extractNativeLibs=true the installer
 * puts a real file in nativeLibraryDir, and exec from there is the
 * post-API-29-legal way to run a bundled binary.
 *
 * The daemon binds 127.0.0.1 only; the WebView in MainActivity is the
 * UI. Downloads land in filesDir/downloads until the export story
 * (Phase 2 of the plan) exists.
 */
public class EngineService extends Service {
    public static final int PORT = 6789;
    private static final String CHANNEL = "engine";
    private Process engine;

    /** One API key per install, minted on first use. */
    public static String apiKey(Context ctx) {
        SharedPreferences p = ctx.getSharedPreferences("nzbfast", MODE_PRIVATE);
        String k = p.getString("apikey", null);
        if (k == null) {
            byte[] b = new byte[24];
            new SecureRandom().nextBytes(b);
            StringBuilder sb = new StringBuilder();
            for (byte x : b) sb.append(String.format("%02x", x));
            k = sb.toString();
            p.edit().putString("apikey", k).apply();
        }
        return k;
    }

    @Override
    public void onCreate() {
        NotificationManager nm = getSystemService(NotificationManager.class);
        nm.createNotificationChannel(
                new NotificationChannel(CHANNEL, "Engine", NotificationManager.IMPORTANCE_LOW));
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        Notification n = new Notification.Builder(this, CHANNEL)
                .setSmallIcon(android.R.drawable.stat_sys_download)
                .setContentTitle("nzbfast")
                .setContentText("engine running on 127.0.0.1:" + PORT)
                .setOngoing(true)
                .build();
        if (Build.VERSION.SDK_INT >= 29) {
            startForeground(1, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_DATA_SYNC);
        } else {
            startForeground(1, n);
        }
        startEngine();
        return START_STICKY;
    }

    private void startEngine() {
        if (engine != null && engine.isAlive()) return;
        try {
            File base = getFilesDir();
            File dl = new File(base, "downloads");
            File watch = new File(base, "watch");
            File cfg = new File(base, "config");
            dl.mkdirs();
            watch.mkdirs();
            cfg.mkdirs();
            String bin = getApplicationInfo().nativeLibraryDir + "/libnzbfast.so";
            ProcessBuilder pb = new ProcessBuilder(
                    bin,
                    "--config", new File(cfg, "config.json").getAbsolutePath(),
                    "serve",
                    "--bind", "127.0.0.1",
                    "--port", String.valueOf(PORT),
                    "--apikey", apiKey(this),
                    "--out", dl.getAbsolutePath(),
                    "--watch", watch.getAbsolutePath());
            pb.environment().put("HOME", base.getAbsolutePath());
            pb.environment().put("TMPDIR", getCacheDir().getAbsolutePath());
            pb.redirectErrorStream(true);
            pb.redirectOutput(new File(base, "daemon.log"));
            engine = pb.start();
        } catch (Exception e) {
            stopSelf();
        }
    }

    @Override
    public void onDestroy() {
        if (engine != null) engine.destroy();
        engine = null;
    }

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }
}

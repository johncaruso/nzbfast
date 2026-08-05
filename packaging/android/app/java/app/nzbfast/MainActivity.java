package app.nzbfast;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import java.net.HttpURLConnection;
import java.net.URL;

/**
 * The whole UI: a WebView on the engine's own dashboard at
 * 127.0.0.1:6789 (the mac wrapper's twin). Starts the foreground
 * service, polls until the daemon answers, then loads the dashboard
 * with the install's API key.
 */
public class MainActivity extends Activity {
    private WebView web;
    private final Handler main = new Handler(Looper.getMainLooper());

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        startForegroundService(new Intent(this, EngineService.class));

        web = new WebView(this);
        WebSettings s = web.getSettings();
        s.setJavaScriptEnabled(true);
        s.setDomStorageEnabled(true);
        web.setWebViewClient(new WebViewClient());
        setContentView(web);
        waitForDaemon(0);
    }

    private void waitForDaemon(final int attempt) {
        new Thread(() -> {
            boolean up = false;
            try {
                HttpURLConnection c = (HttpURLConnection)
                        new URL("http://127.0.0.1:" + EngineService.PORT + "/api?mode=version")
                                .openConnection();
                c.setConnectTimeout(500);
                c.getResponseCode();
                up = true;
            } catch (Exception ignored) {
            }
            final boolean ok = up;
            main.post(() -> {
                if (ok) {
                    web.loadUrl("http://127.0.0.1:" + EngineService.PORT
                            + "/?apikey=" + EngineService.apiKey(this));
                } else if (attempt < 60) {
                    main.postDelayed(() -> waitForDaemon(attempt + 1), 500);
                }
            });
        }).start();
    }

    @Override
    public void onBackPressed() {
        if (web.canGoBack()) {
            web.goBack();
        } else {
            super.onBackPressed();
        }
    }
}

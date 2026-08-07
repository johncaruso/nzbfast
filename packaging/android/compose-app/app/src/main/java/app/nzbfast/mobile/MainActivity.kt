package app.nzbfast.mobile

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.BackHandler
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.lifecycle.lifecycleScope
import app.nzbfast.mobile.api.NzbfastClient
import app.nzbfast.mobile.api.PlaybackJob
import app.nzbfast.mobile.api.PlaybackSnapshot
import app.nzbfast.mobile.ui.AddScreen
import app.nzbfast.mobile.ui.ConnectScreen
import app.nzbfast.mobile.ui.HomeScreen
import app.nzbfast.mobile.ui.NzbfastTheme
import app.nzbfast.mobile.ui.PlayerScreen
import app.nzbfast.mobile.ui.ServerSetupScreen
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/** Which screen is on top. A hand-rolled stack: four screens do not
 *  earn a navigation library. */
sealed class Screen {
    data object Connect : Screen()
    data object ServerSetup : Screen()
    data object Home : Screen()
    data object Add : Screen()
    data class Player(val nzoId: String, val url: String, val title: String) : Screen()
}

class MainActivity : ComponentActivity() {

    private var screen by mutableStateOf<Screen>(Screen.Connect)
    private var connection by mutableStateOf<Connection?>(null)
    private var busy by mutableStateOf(false)
    private var note by mutableStateOf<String?>(null)

    /** The one poll: mode=playback carries queue, history, per-file
     *  readiness and the byte-serving telemetry in a single response. */
    private var snapshot by mutableStateOf<PlaybackSnapshot?>(null)

    private var pollJob: Job? = null

    private val client: NzbfastClient?
        get() = connection?.let { NzbfastClient(it.baseUrl, it.apiKey) }

    private val pickNzb =
        registerForActivityResult(ActivityResultContracts.OpenDocument()) { uri ->
            if (uri != null) addFromUri(uri)
        }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        connection = Store.load(this)
        if (connection != null) {
            if (connection!!.mode == Mode.DEVICE) {
                startForegroundService(Intent(this, EngineService::class.java))
            }
            screen = Screen.Home
            startPolling()
        }
        handleIntent(intent)

        setContent {
            NzbfastTheme {
                AppScaffold()
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleIntent(intent)
    }

    /** True while the activity is in a PiP window: the player hides its
     *  chrome (controller, overlays) - the window is thumbnail-sized and
     *  the OS draws its own controls over it. */
    private var inPip by mutableStateOf(false)

    /** Home button while the test preview is up: keep the picture going
     *  in a PiP window instead of stopping. Only the player earns it -
     *  minimizing a queue screen should just minimize. */
    override fun onUserLeaveHint() {
        if (screen is Screen.Player) {
            enterPictureInPictureMode(
                android.app.PictureInPictureParams.Builder().build()
            )
        }
    }

    override fun onPictureInPictureModeChanged(
        isInPictureInPictureMode: Boolean,
        newConfig: android.content.res.Configuration,
    ) {
        super.onPictureInPictureModeChanged(isInPictureInPictureMode, newConfig)
        inPip = isInPictureInPictureMode
    }

    override fun onDestroy() {
        pollJob?.cancel()
        super.onDestroy()
    }

    @OptIn(ExperimentalMaterial3Api::class)
    @Composable
    private fun AppScaffold() {
        val s = screen
        BackHandler(enabled = s is Screen.Add || s is Screen.Player) {
            screen = Screen.Home
        }
        when (s) {
            is Screen.Player -> PlayerScreen(
                streamUrl = s.url,
                title = s.title,
                job = { snapshot?.let { snap ->
                    (snap.queue + snap.history).firstOrNull { it.nzoId == s.nzoId }
                } },
                telemetry = { snapshot?.stream },
                inPip = { inPip },
            )
            else -> Scaffold(
                topBar = {
                    if (s is Screen.Home) {
                        TopAppBar(
                            title = { Text("nzbfast") },
                            actions = {
                                val paused = snapshot?.paused == true
                                TextButton(onClick = { togglePauseAll(paused) }) {
                                    Text(if (paused) "Resume all" else "Pause all")
                                }
                            },
                        )
                    }
                },
                floatingActionButton = {
                    if (s is Screen.Home) {
                        FloatingActionButton(onClick = { screen = Screen.Add }) {
                            Text("+")
                        }
                    }
                },
            ) { pad ->
                val mod = Modifier.padding(pad)
                when (s) {
                    is Screen.Connect -> androidx.compose.foundation.layout.Box(mod) {
                        ConnectScreen(
                            busy = busy,
                            error = note,
                            onUseDevice = ::useDevice,
                            onUseServer = ::useServer,
                        )
                    }
                    is Screen.ServerSetup -> androidx.compose.foundation.layout.Box(mod) {
                        ServerSetupScreen(
                            busy = busy,
                            status = note,
                            onTest = ::testNewsServer,
                            onSave = ::saveNewsServer,
                        )
                    }
                    is Screen.Home -> androidx.compose.foundation.layout.Box(mod) {
                        HomeScreen(
                            snapshot = snapshot,
                            statusLine = note,
                            onPlay = ::play,
                            onPauseJob = { io { client?.pauseJob(it) } },
                            onResumeJob = { io { client?.resumeJob(it) } },
                            onDeleteJob = { io { client?.deleteJob(it, deleteFiles = false) } },
                            onDeleteHistory = {
                                io { client?.deleteHistory(it, deleteFiles = false) }
                            },
                        )
                    }
                    is Screen.Add -> androidx.compose.foundation.layout.Box(mod) {
                        AddScreen(
                            busy = busy,
                            status = note,
                            onPickFile = {
                                pickNzb.launch(arrayOf("*/*"))
                            },
                            onSubmitLink = ::addLink,
                        )
                    }
                    is Screen.Player -> {}
                }
            }
        }
    }

    // ---- connect flows ----

    private fun useDevice() {
        busy = true
        note = null
        startForegroundService(Intent(this, EngineService::class.java))
        lifecycleScope.launch {
            val local = NzbfastClient(
                "http://127.0.0.1:${EngineService.PORT}",
                EngineService.apiKey(this@MainActivity),
            )
            val up = withContext(Dispatchers.IO) {
                var ok = false
                var tries = 0
                while (!ok && tries < 60) {
                    ok = runCatching { local.version() }.getOrDefault("").isNotEmpty()
                    if (!ok) {
                        delay(500)
                        tries++
                    }
                }
                ok
            }
            busy = false
            if (!up) {
                note = "The engine did not start. Check daemon.log in app storage."
                return@launch
            }
            Store.saveDevice(this@MainActivity)
            connection = Store.load(this@MainActivity)
            val configured = withContext(Dispatchers.IO) {
                runCatching { client!!.serversConfigured() }.getOrDefault(false)
            }
            if (configured) {
                note = null
                screen = Screen.Home
                startPolling()
            } else {
                note = null
                screen = Screen.ServerSetup
            }
        }
    }

    private fun useServer(url: String, key: String) {
        busy = true
        note = null
        val base = if (url.startsWith("http")) url else "http://$url"
        lifecycleScope.launch {
            val probe = NzbfastClient(base.trimEnd('/'), key)
            // Validate with the call the app lives on: mode=playback
            // needs the full key and proves the daemon speaks contract v1.
            val err = withContext(Dispatchers.IO) {
                runCatching { probe.playback(limit = 1) }.exceptionOrNull()
            }
            busy = false
            if (err != null) {
                note = "Could not connect: ${err.message}"
            } else {
                Store.saveServer(this@MainActivity, base, key)
                connection = Store.load(this@MainActivity)
                note = null
                screen = Screen.Home
                startPolling()
            }
        }
    }

    private fun testNewsServer(host: String, port: Int, tls: Boolean, user: String, pass: String) {
        busy = true
        note = null
        lifecycleScope.launch {
            val r = withContext(Dispatchers.IO) {
                runCatching { client!!.serverTest(host, port, tls, user, pass) }
                    .getOrElse { app.nzbfast.mobile.api.ServerTestResult(false, it.message ?: "failed") }
            }
            busy = false
            note = if (r.ok) "Connected: ${r.detail}" else "Failed: ${r.detail}"
        }
    }

    private fun saveNewsServer(host: String, port: Int, tls: Boolean, user: String, pass: String) {
        busy = true
        note = null
        lifecycleScope.launch {
            val ok = withContext(Dispatchers.IO) {
                runCatching { client!!.serverSave(host, port, tls, user, pass) }
                    .getOrDefault(false)
            }
            busy = false
            if (ok) {
                note = null
                screen = Screen.Home
                startPolling()
            } else {
                note = "Saving the server failed."
            }
        }
    }

    // ---- add flows ----

    private fun handleIntent(intent: Intent?) {
        intent ?: return
        when (intent.action) {
            Intent.ACTION_SEND -> {
                val uri: Uri? = if (android.os.Build.VERSION.SDK_INT >= 33) {
                    intent.getParcelableExtra(Intent.EXTRA_STREAM, Uri::class.java)
                } else {
                    @Suppress("DEPRECATION")
                    intent.getParcelableExtra(Intent.EXTRA_STREAM)
                }
                val text = intent.getStringExtra(Intent.EXTRA_TEXT)
                when {
                    uri != null -> addFromUri(uri)
                    text != null && text.contains("nzblnk:") -> addLink(text.trim())
                }
            }
            Intent.ACTION_VIEW -> {
                val data = intent.data ?: return
                if (data.scheme == "nzblnk") addLink(data.toString())
            }
        }
    }

    private fun addFromUri(uri: Uri) {
        if (connection == null) {
            note = "Connect first, then add NZBs."
            return
        }
        busy = true
        note = null
        lifecycleScope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching {
                    val bytes = contentResolver.openInputStream(uri)?.use { it.readBytes() }
                        ?: error("could not read the file")
                    val name = queryDisplayName(uri) ?: "shared.nzb"
                    client!!.addFile(name, bytes)
                }
            }
            busy = false
            result.fold(
                onSuccess = { r ->
                    note = if (r.ok) "Added." else "Add failed: ${r.error ?: "unknown error"}"
                    if (r.ok) screen = Screen.Home
                },
                onFailure = { note = "Add failed: ${it.message}" },
            )
        }
    }

    private fun addLink(link: String) {
        if (connection == null) {
            note = "Connect first, then add links."
            return
        }
        busy = true
        note = null
        lifecycleScope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching { client!!.addNzbLnk(link) }
            }
            busy = false
            result.fold(
                onSuccess = { r ->
                    note = if (r.ok) "Added." else "Add failed: ${r.error ?: "unknown error"}"
                    if (r.ok) screen = Screen.Home
                },
                onFailure = { note = "Add failed: ${it.message}" },
            )
        }
    }

    private fun queryDisplayName(uri: Uri): String? =
        contentResolver.query(uri, null, null, null, null)?.use { c ->
            val i = c.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME)
            if (i >= 0 && c.moveToFirst()) c.getString(i) else null
        }

    // ---- play ----

    private fun play(job: PlaybackJob) {
        val cl = client ?: return
        busy = true
        lifecycleScope.launch {
            // Row 16 already hands over the tokenized play URL; /m3u is
            // only the fallback for a snapshot that lacked one.
            val url = withContext(Dispatchers.IO) {
                job.stream.ifEmpty { cl.streamUrl(job.nzoId) }
            }
            // mode=playback is read-only by design; the probe is what
            // promotes a live job's file index, so fire it once for the
            // one job the user opened (contract row 13).
            if (job.playback.source == "live") {
                io { cl.probe(job.nzoId) }
            }
            busy = false
            screen = Screen.Player(job.nzoId, url, job.name)
        }
    }

    private fun togglePauseAll(paused: Boolean) {
        io { if (paused) client?.resumeAll() else client?.pauseAll() }
    }

    // ---- polling ----

    private fun startPolling() {
        pollJob?.cancel()
        pollJob = lifecycleScope.launch {
            while (isActive) {
                val cl = client
                // One poll for everything: readiness rides the job rows
                // (no per-job probes) and the telemetry feeds the player
                // overlay, so keep polling while the player is up.
                if (cl != null && (screen is Screen.Home || screen is Screen.Player)) {
                    val snap = withContext(Dispatchers.IO) {
                        runCatching { cl.playback() }.getOrNull()
                    }
                    if (snap != null) {
                        snapshot = snap
                        if (note?.startsWith("Could not reach") == true) note = null
                    } else {
                        note = "Could not reach the server."
                    }
                }
                delay(2_000)
            }
        }
    }

    private fun io(block: () -> Unit) {
        lifecycleScope.launch(Dispatchers.IO) {
            runCatching(block)
        }
    }
}

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
import app.nzbfast.mobile.api.ProbeResult
import app.nzbfast.mobile.api.QueueSnapshot
import app.nzbfast.mobile.api.HistorySlot
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
    data class Player(val url: String, val title: String) : Screen()
}

class MainActivity : ComponentActivity() {

    private var screen by mutableStateOf<Screen>(Screen.Connect)
    private var connection by mutableStateOf<Connection?>(null)
    private var busy by mutableStateOf(false)
    private var note by mutableStateOf<String?>(null)

    private var queue by mutableStateOf<QueueSnapshot?>(null)
    private var history by mutableStateOf<List<HistorySlot>>(emptyList())
    private var probes by mutableStateOf<Map<String, ProbeResult>>(emptyMap())

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
            is Screen.Player -> PlayerScreen(s.url, s.title)
            else -> Scaffold(
                topBar = {
                    if (s is Screen.Home) {
                        TopAppBar(
                            title = { Text("nzbfast") },
                            actions = {
                                val paused = queue?.paused == true
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
                            queue = queue,
                            history = history,
                            probes = probes,
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
            val err = withContext(Dispatchers.IO) {
                runCatching { probe.queue() }.exceptionOrNull()
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

    private fun play(nzoId: String, name: String) {
        val cl = client ?: return
        busy = true
        lifecycleScope.launch {
            val url = withContext(Dispatchers.IO) { cl.streamUrl(nzoId) }
            busy = false
            screen = Screen.Player(url, name)
        }
    }

    private fun togglePauseAll(paused: Boolean) {
        io { if (paused) client?.resumeAll() else client?.pauseAll() }
    }

    // ---- polling ----

    private fun startPolling() {
        pollJob?.cancel()
        pollJob = lifecycleScope.launch {
            var lastProbe = 0L
            while (isActive) {
                val cl = client
                if (cl != null && screen is Screen.Home) {
                    val snap = withContext(Dispatchers.IO) {
                        runCatching {
                            Triple(cl.queue(), cl.history(), Unit)
                        }.getOrNull()
                    }
                    if (snap != null) {
                        queue = snap.first
                        history = snap.second
                        if (note?.startsWith("Could not reach") == true) note = null
                        // Probe downloading jobs for playability every 6 s,
                        // matching the dashboard's cadence. The probe result
                        // drives the Play affordance.
                        val now = System.currentTimeMillis()
                        if (now - lastProbe > 6_000) {
                            lastProbe = now
                            val active = snap.first.slots.filter {
                                it.status == "Downloading" || it.status == "Queued" ||
                                    it.status == "Moving"
                            }
                            val results = withContext(Dispatchers.IO) {
                                active.associate { s ->
                                    s.nzoId to runCatching { cl.probe(s.nzoId) }.getOrNull()
                                }
                            }
                            probes = results.filterValues { it != null }
                                .mapValues { it.value!! }
                        }
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

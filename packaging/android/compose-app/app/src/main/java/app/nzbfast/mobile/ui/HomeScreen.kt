package app.nzbfast.mobile.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.SwipeToDismissBox
import androidx.compose.material3.SwipeToDismissBoxValue
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberSwipeToDismissBoxState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import app.nzbfast.mobile.api.PlaybackJob
import app.nzbfast.mobile.api.PlaybackSnapshot

/**
 * The playback-first single list, fed by the one mode=playback poll:
 * active jobs with live progress and a Play affordance the moment the
 * job row's readiness says the file is readable, then history. Swipe
 * right to pause or resume, swipe left to delete.
 */
@Composable
fun HomeScreen(
    snapshot: PlaybackSnapshot?,
    statusLine: String?,
    onPlay: (PlaybackJob) -> Unit,
    onPauseJob: (String) -> Unit,
    onResumeJob: (String) -> Unit,
    onDeleteJob: (String) -> Unit,
    onDeleteHistory: (String) -> Unit,
) {
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        verticalArrangement = Arrangement.spacedBy(8.dp),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
    ) {
        if (snapshot == null) {
            item {
                Text("Connecting...", style = MaterialTheme.typography.bodyLarge)
            }
        } else {
            if (snapshot.queue.isEmpty() && snapshot.history.isEmpty()) {
                item {
                    Text(
                        "Nothing here yet. Tap + to add an NZB.",
                        style = MaterialTheme.typography.bodyLarge,
                    )
                }
            }
            items(snapshot.queue, key = { it.nzoId }) { job ->
                SwipeRow(
                    key = job.nzoId,
                    onSwipeRight = {
                        if (job.status == "Paused") onResumeJob(job.nzoId)
                        else onPauseJob(job.nzoId)
                    },
                    onSwipeLeft = { onDeleteJob(job.nzoId) },
                    rightLabel = if (job.status == "Paused") "Resume" else "Pause",
                ) {
                    QueueRow(job = job, onPlay = { onPlay(job) })
                }
            }
            if (snapshot.history.isNotEmpty()) {
                item {
                    Spacer(Modifier.height(8.dp))
                    Text("History", style = MaterialTheme.typography.titleMedium)
                }
                items(snapshot.history, key = { "h-" + it.nzoId }) { job ->
                    SwipeRow(
                        key = job.nzoId,
                        onSwipeRight = {},
                        onSwipeLeft = { onDeleteHistory(job.nzoId) },
                        rightLabel = null,
                    ) {
                        HistoryRow(job, onPlay = { onPlay(job) })
                    }
                }
            }
        }
        if (statusLine != null) {
            item {
                Text(
                    statusLine,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.secondary,
                )
            }
        }
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun SwipeRow(
    key: String,
    onSwipeRight: () -> Unit,
    onSwipeLeft: () -> Unit,
    rightLabel: String?,
    content: @Composable () -> Unit,
) {
    val right = rememberUpdatedState(onSwipeRight)
    val left = rememberUpdatedState(onSwipeLeft)
    // confirmValueChange fires the action and refuses the dismiss, so
    // the row snaps back and the next poll shows the new state. The
    // LazyColumn keys rows by nzo_id, so each row owns its own state.
    val state = rememberSwipeToDismissBoxState(
        confirmValueChange = { v ->
            when (v) {
                SwipeToDismissBoxValue.StartToEnd -> right.value()
                SwipeToDismissBoxValue.EndToStart -> left.value()
                else -> {}
            }
            false
        },
    )
    SwipeToDismissBox(
        state = state,
        enableDismissFromStartToEnd = rightLabel != null,
        enableDismissFromEndToStart = true,
        backgroundContent = {
            Row(
                Modifier
                    .fillMaxSize()
                    .background(MaterialTheme.colorScheme.surfaceVariant)
                    .padding(horizontal = 16.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                if (rightLabel != null) Text(rightLabel)
                Spacer(Modifier.weight(1f))
                Text("Delete", color = MaterialTheme.colorScheme.error)
            }
        },
        content = { content() },
    )
}

@Composable
private fun QueueRow(job: PlaybackJob, onPlay: () -> Unit) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(
                job.name,
                style = MaterialTheme.typography.titleSmall,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
            )
            LinearProgressIndicator(
                progress = { (job.percentage / 100f).coerceIn(0f, 1f) },
                modifier = Modifier.fillMaxWidth(),
            )
            Row(verticalAlignment = Alignment.CenterVertically) {
                val left = job.mbLeft
                val detail = buildString {
                    append(job.status)
                    if (job.status == "Downloading" && job.timeLeft.isNotEmpty() &&
                        job.timeLeft != "0:00:00"
                    ) {
                        append("  ·  ")
                        append(job.timeLeft)
                        append(" left")
                    }
                    if (left > 0.0) {
                        append("  ·  ")
                        append("%.0f MB to go".format(left))
                    }
                }
                Text(
                    detail,
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.weight(1f),
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                // playback.ready on the row replaces the per-job probe:
                // reason "live" (or "disk") means /stream serves it now.
                if (job.playback.ready) {
                    FilledTonalButton(onClick = onPlay) {
                        Text("Play test preview")
                    }
                }
            }
        }
    }
}

@Composable
private fun HistoryRow(job: PlaybackJob, onPlay: () -> Unit) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Row(
            Modifier.padding(12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(
                    job.name,
                    style = MaterialTheme.typography.titleSmall,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                )
                val sub = when (job.status) {
                    "Completed" ->
                        if (job.bytes > 0) "%.1f MB".format(job.bytes / 1e6) else "Completed"
                    "Failed" -> job.failMessage.ifEmpty { "Failed" }
                    else -> job.status
                }
                Text(
                    sub,
                    style = MaterialTheme.typography.bodySmall,
                    color = if (job.status == "Failed") MaterialTheme.colorScheme.error
                    else MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            // reason "disk" = the file is really still there; a row whose
            // media has been cleaned away ("no_media") gets no Play.
            if (job.playback.ready) {
                TextButton(onClick = onPlay) { Text("Play") }
            }
        }
    }
}

package app.nzbfast.mobile.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
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
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberUpdatedState
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import app.nzbfast.mobile.api.HistorySlot
import app.nzbfast.mobile.api.ProbeResult
import app.nzbfast.mobile.api.QueueSlot
import app.nzbfast.mobile.api.QueueSnapshot

/**
 * The playback-first single list: active jobs with live progress and a
 * Play affordance the moment the daemon says the file is readable,
 * then history. Swipe right to pause or resume, swipe left to delete.
 */
@Composable
fun HomeScreen(
    queue: QueueSnapshot?,
    history: List<HistorySlot>,
    probes: Map<String, ProbeResult>,
    statusLine: String?,
    onPlay: (nzoId: String, name: String) -> Unit,
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
        if (queue == null) {
            item {
                Text("Connecting...", style = MaterialTheme.typography.bodyLarge)
            }
        } else {
            if (queue.slots.isEmpty() && history.isEmpty()) {
                item {
                    Text(
                        "Nothing here yet. Tap + to add an NZB.",
                        style = MaterialTheme.typography.bodyLarge,
                    )
                }
            }
            items(queue.slots, key = { it.nzoId }) { slot ->
                SwipeRow(
                    key = slot.nzoId,
                    onSwipeRight = {
                        if (slot.status == "Paused") onResumeJob(slot.nzoId)
                        else onPauseJob(slot.nzoId)
                    },
                    onSwipeLeft = { onDeleteJob(slot.nzoId) },
                    rightLabel = if (slot.status == "Paused") "Resume" else "Pause",
                ) {
                    QueueRow(
                        slot = slot,
                        probe = probes[slot.nzoId],
                        onPlay = { onPlay(slot.nzoId, slot.name) },
                    )
                }
            }
            if (history.isNotEmpty()) {
                item {
                    Spacer(Modifier.height(8.dp))
                    Text("History", style = MaterialTheme.typography.titleMedium)
                }
                items(history, key = { "h-" + it.nzoId }) { h ->
                    SwipeRow(
                        key = h.nzoId,
                        onSwipeRight = {},
                        onSwipeLeft = { onDeleteHistory(h.nzoId) },
                        rightLabel = null,
                    ) {
                        HistoryRow(h, onPlay = { onPlay(h.nzoId, h.name) })
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
private fun QueueRow(slot: QueueSlot, probe: ProbeResult?, onPlay: () -> Unit) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(
                slot.name,
                style = MaterialTheme.typography.titleSmall,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
            )
            LinearProgressIndicator(
                progress = { (slot.percentage / 100f).coerceIn(0f, 1f) },
                modifier = Modifier.fillMaxWidth(),
            )
            Row(verticalAlignment = Alignment.CenterVertically) {
                val left = slot.mbLeft
                val detail = buildString {
                    append(slot.status)
                    if (slot.status == "Downloading" && slot.timeLeft.isNotEmpty() &&
                        slot.timeLeft != "0:00:00"
                    ) {
                        append("  ·  ")
                        append(slot.timeLeft)
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
                if (probe?.mediaReady == true) {
                    FilledTonalButton(onClick = onPlay) {
                        Text("Play test preview")
                    }
                }
            }
        }
    }
}

@Composable
private fun HistoryRow(h: HistorySlot, onPlay: () -> Unit) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Row(
            Modifier.padding(12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text(
                    h.name,
                    style = MaterialTheme.typography.titleSmall,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                )
                val sub = when (h.status) {
                    "Completed" -> h.size
                    "Failed" -> h.failMessage.ifEmpty { "Failed" }
                    else -> h.status
                }
                Text(
                    sub,
                    style = MaterialTheme.typography.bodySmall,
                    color = if (h.status == "Failed") MaterialTheme.colorScheme.error
                    else MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            if (h.status == "Completed") {
                TextButton(onClick = onPlay) { Text("Play") }
            }
        }
    }
}

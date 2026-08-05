package app.nzbfast.mobile.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

/**
 * Add an NZB: document picker, or paste an nzblnk / http link. The
 * share-target path (ACTION_SEND / ACTION_VIEW) lands directly in
 * MainActivity and does not pass through here.
 */
@Composable
fun AddScreen(
    busy: Boolean,
    status: String?,
    onPickFile: () -> Unit,
    onSubmitLink: (String) -> Unit,
) {
    var link by rememberSaveable { mutableStateOf("") }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text("Add", style = MaterialTheme.typography.headlineMedium)

        Card(modifier = Modifier.fillMaxWidth()) {
            Column(
                Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text("NZB file", style = MaterialTheme.typography.titleMedium)
                Text(
                    "Pick a .nzb file from this phone. Sharing a file to nzbfast from another app works too.",
                    style = MaterialTheme.typography.bodyMedium,
                )
                Button(onClick = onPickFile, enabled = !busy) {
                    Text("Choose file")
                }
            }
        }

        Card(modifier = Modifier.fillMaxWidth()) {
            Column(
                Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text("Link", style = MaterialTheme.typography.titleMedium)
                Text(
                    "Paste an nzblnk link.",
                    style = MaterialTheme.typography.bodyMedium,
                )
                OutlinedTextField(
                    value = link,
                    onValueChange = { link = it },
                    label = { Text("nzblnk:?...") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedButton(
                    onClick = { onSubmitLink(link) },
                    enabled = !busy && link.isNotBlank(),
                ) {
                    Text("Add link")
                }
            }
        }

        if (busy) {
            CircularProgressIndicator()
        }
        if (status != null) {
            Text(status, style = MaterialTheme.typography.bodyMedium)
        }
    }
}

package app.nzbfast.mobile.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
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
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp

/**
 * First-run screen: pick where the engine lives. "This device" execs
 * the bundled engine; "My server" points the same UI at a daemon the
 * user already runs. Which daemon is a setting - that one decision
 * keeps the two modes from diverging.
 */
@Composable
fun ConnectScreen(
    busy: Boolean,
    error: String?,
    onUseDevice: () -> Unit,
    onUseServer: (url: String, apiKey: String) -> Unit,
) {
    var url by rememberSaveable { mutableStateOf("") }
    var key by rememberSaveable { mutableStateOf("") }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Spacer(Modifier.height(32.dp))
        Text("nzbfast", style = MaterialTheme.typography.headlineLarge)
        Text(
            "Where should downloads run?",
            style = MaterialTheme.typography.titleMedium,
        )

        Card(modifier = Modifier.fillMaxWidth()) {
            Column(
                Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text("This device", style = MaterialTheme.typography.titleMedium)
                Text(
                    "Run the bundled engine on this phone. Downloads stay in app storage.",
                    style = MaterialTheme.typography.bodyMedium,
                )
                Button(onClick = onUseDevice, enabled = !busy) {
                    Text("Use this device")
                }
            }
        }

        Card(modifier = Modifier.fillMaxWidth()) {
            Column(
                Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text("My server", style = MaterialTheme.typography.titleMedium)
                Text(
                    "Connect to an nzbfast server you already run, like a NAS or a seedbox.",
                    style = MaterialTheme.typography.bodyMedium,
                )
                OutlinedTextField(
                    value = url,
                    onValueChange = { url = it },
                    label = { Text("Server address") },
                    placeholder = { Text("http://192.168.1.10:6789") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = key,
                    onValueChange = { key = it },
                    label = { Text("API key") },
                    singleLine = true,
                    visualTransformation = PasswordVisualTransformation(),
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedButton(
                    onClick = { onUseServer(url, key) },
                    enabled = !busy && url.isNotBlank(),
                ) {
                    Text("Connect")
                }
            }
        }

        if (busy) {
            CircularProgressIndicator()
        }
        if (error != null) {
            Text(
                error,
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodyMedium,
            )
        }
    }
}

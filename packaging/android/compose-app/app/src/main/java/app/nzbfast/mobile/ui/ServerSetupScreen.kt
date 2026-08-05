package app.nzbfast.mobile.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
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
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp

/**
 * On-device first run: the engine needs a Usenet provider before it
 * can download - the same three fields as the dashboard wizard.
 */
@Composable
fun ServerSetupScreen(
    busy: Boolean,
    status: String?,
    onTest: (host: String, port: Int, tls: Boolean, user: String, pass: String) -> Unit,
    onSave: (host: String, port: Int, tls: Boolean, user: String, pass: String) -> Unit,
) {
    var host by rememberSaveable { mutableStateOf("") }
    var port by rememberSaveable { mutableStateOf("563") }
    var tls by rememberSaveable { mutableStateOf(true) }
    var user by rememberSaveable { mutableStateOf("") }
    var pass by rememberSaveable { mutableStateOf("") }
    val portNum = port.toIntOrNull() ?: 563

    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(24.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("News server", style = MaterialTheme.typography.headlineMedium)
        Text(
            "The engine on this phone needs your Usenet provider to download.",
            style = MaterialTheme.typography.bodyMedium,
        )
        OutlinedTextField(
            value = host,
            onValueChange = { host = it },
            label = { Text("Host") },
            placeholder = { Text("news.example.com") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        Row(
            horizontalArrangement = Arrangement.spacedBy(12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            OutlinedTextField(
                value = port,
                onValueChange = { port = it.filter(Char::isDigit).take(5) },
                label = { Text("Port") },
                singleLine = true,
                modifier = Modifier.weight(1f),
            )
            Checkbox(checked = tls, onCheckedChange = { tls = it })
            Text("SSL/TLS")
        }
        OutlinedTextField(
            value = user,
            onValueChange = { user = it },
            label = { Text("Username") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )
        OutlinedTextField(
            value = pass,
            onValueChange = { pass = it },
            label = { Text("Password") },
            singleLine = true,
            visualTransformation = PasswordVisualTransformation(),
            modifier = Modifier.fillMaxWidth(),
        )
        Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
            OutlinedButton(
                onClick = { onTest(host.trim(), portNum, tls, user.trim(), pass) },
                enabled = !busy && host.isNotBlank(),
            ) { Text("Test") }
            Button(
                onClick = { onSave(host.trim(), portNum, tls, user.trim(), pass) },
                enabled = !busy && host.isNotBlank(),
            ) { Text("Save and continue") }
        }
        if (busy) CircularProgressIndicator()
        if (status != null) {
            Text(status, style = MaterialTheme.typography.bodyMedium)
        }
    }
}

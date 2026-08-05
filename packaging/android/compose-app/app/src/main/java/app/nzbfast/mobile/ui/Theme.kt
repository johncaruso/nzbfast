package app.nzbfast.mobile.ui

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

// Dark-first, platform-default Material 3 with the dashboard's accent.
private val Accent = Color(0xFF4FC3F7)
private val AccentDeep = Color(0xFF0288D1)

private val DarkColors = darkColorScheme(
    primary = Accent,
    onPrimary = Color(0xFF00263A),
    secondary = Accent,
    surface = Color(0xFF121417),
    background = Color(0xFF0C0E10),
)

private val LightColors = lightColorScheme(
    primary = AccentDeep,
)

@Composable
fun NzbfastTheme(content: @Composable () -> Unit) {
    MaterialTheme(
        colorScheme = if (isSystemInDarkTheme()) DarkColors else LightColors,
        content = content,
    )
}

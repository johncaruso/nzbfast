package app.nzbfast.mobile.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalView
import androidx.compose.ui.unit.dp
import androidx.compose.foundation.layout.padding
import androidx.compose.ui.viewinterop.AndroidView
import androidx.media3.common.MediaItem
import androidx.media3.exoplayer.ExoPlayer
import androidx.media3.ui.PlayerView

/**
 * The test preview player: ExoPlayer on the daemon's /stream URL.
 * ExoPlayer plays Matroska natively with hardware decode, which is
 * the whole point of going native on Android. Transport controls come
 * from the Media3 PlayerView; the screen stays on while this screen
 * is visible.
 */
@Composable
fun PlayerScreen(streamUrl: String, title: String) {
    val context = LocalContext.current
    val view = LocalView.current

    val player = remember(streamUrl) {
        ExoPlayer.Builder(context).build().apply {
            setMediaItem(MediaItem.fromUri(streamUrl))
            playWhenReady = true
            prepare()
        }
    }

    DisposableEffect(player) {
        view.keepScreenOn = true
        onDispose {
            view.keepScreenOn = false
            player.release()
        }
    }

    Surface(modifier = Modifier.fillMaxSize(), color = Color.Black) {
        Box(modifier = Modifier.fillMaxSize()) {
            AndroidView(
                factory = { ctx ->
                    PlayerView(ctx).apply {
                        this.player = player
                        setShowNextButton(false)
                        setShowPreviousButton(false)
                    }
                },
                modifier = Modifier.fillMaxSize(),
            )
            Text(
                text = "Test preview  ·  $title",
                style = MaterialTheme.typography.labelMedium,
                color = Color.White,
                modifier = Modifier
                    .align(Alignment.TopCenter)
                    .padding(top = 8.dp)
                    .background(Color(0x80000000))
                    .padding(horizontal = 8.dp, vertical = 2.dp),
            )
        }
    }
}

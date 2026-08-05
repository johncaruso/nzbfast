# nzbfast for Android (Jetpack Compose)

The native Android app: Material 3, dark-first, playback-first. One
UI, two sources - "this device" runs the bundled slim engine on the
phone (exec'd from nativeLibraryDir, same mechanism as the test APK in
`../app`); "my server" points the same screens at an nzbfast daemon
you already run. The player is Media3 ExoPlayer on the daemon's
/stream endpoint, so Matroska plays with hardware decode and range
seeks.

Screens: Connect (mode picker + first-run news-server form), Home
(active jobs with live progress, a "Play test preview" button the
moment the daemon says the file is readable, then history; swipe to
pause/resume/delete), Add (document picker, nzblnk paste, and
share-target for .nzb files and nzblnk links).

The endpoints the app uses are inventoried in `CONTRACT.md`. The API
client is hand-rolled (HttpURLConnection + the platform org.json);
its parsers are exercised by JVM snapshot tests against responses
recorded from a real daemon (`app/src/test/resources/snapshots/`).

## Build

Requires the Android SDK (a platforms/android-36 install), JDK 17+,
and the slim engine binary:

```sh
export ANDROID_NDK_HOME=$ANDROID_HOME/ndk/<version>
cargo ndk -t arm64-v8a --platform 26 build --release -p nzbfast --no-default-features

cd packaging/android/compose-app
./fetch-engine.sh        # stages the engine as a jniLib (gitignored)
ANDROID_HOME=... ./gradlew :app:assembleDebug
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

Tests: `./gradlew :app:testDebugUnitTest`.

Gradle is pinned by the wrapper (8.13, AGP 8.11.1, Kotlin 2.1.21) -
build through `./gradlew`, not a system gradle. The debug APK is
signed with the standard debug keystore; nothing here is a release
artifact. The on-device engine binds 127.0.0.1:6791 (the WebView test
APK's engine owns 6789, and both apps can be installed at once).

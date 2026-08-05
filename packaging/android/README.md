# nzbfast on Android - adb test kit

> The native Jetpack Compose app now lives in `compose-app/` (screens,
> ExoPlayer test preview, remote mode - see its README and
> CONTRACT.md). The WebView APK below stays as the fallback shell; its
> on-device engine owns port 6789, the compose app's owns 6791.

Proof-of-life kit for the Android port: build the slim engine for
aarch64, push it to a phone or emulator with adb, run the daemon on
127.0.0.1, drive it from the device's own browser.

This is the Phase 0 shape from `research/PLAN-ANDROID.md`: no app yet,
just the engine binary under adb. The slim build (`--no-default-features`)
compiles out the indexer stack (index, Spotnet, oracle ledger,
enrichment) and with it sqlite; the download pipeline - NNTP, yEnc
decode, PAR2 verify/repair, extraction - and the embedded dashboard are
all there.

## Build

Requires the Android NDK and cargo-ndk, plus the rust targets:

```sh
rustup target add aarch64-linux-android x86_64-linux-android
cargo install cargo-ndk
```

From the repo root (ANDROID_NDK_HOME must point at an installed NDK):

```sh
cargo ndk -t arm64-v8a -p 26 build --release -p nzbfast --no-default-features
cp target/aarch64-linux-android/release/nzbfast packaging/android/nzbfast-android-arm64
```

For the x86_64 emulator image swap `-t x86_64` and the target dir
accordingly. `-p 26` = API 26 / Android 8, the plan's floor.

## Run

Connect a device (USB debugging on) or start an emulator, then:

```sh
cd packaging/android
./run-on-device.sh
```

The script pushes the binary to `/data/local/tmp/nzbfast`, starts
`nzbfast serve --bind 127.0.0.1 --port 6789` with a throwaway API key,
and opens the dashboard in the device browser. Add a test NZB either
through the dashboard or by pushing it into the watch folder:

```sh
adb push test.nzb /data/local/tmp/nzbfast/watch/
```

Servers are configured in the dashboard (Settings - Servers) exactly as
on any other platform.

## Notes

- `NZBFAST_NO_ENRICH=1` is set by the script; the slim build has no
  enrichment workers to begin with, the variable is belt and braces.
- Everything stays under `/data/local/tmp/nzbfast`; remove with
  `adb shell rm -rf /data/local/tmp/nzbfast`.
- The daemon binds 127.0.0.1 only - nothing off-device can reach it.
- This kit is for local testing; nothing here is a release artifact.

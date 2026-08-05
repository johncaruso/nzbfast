# nzbfast iOS shell (workstream C1)

A native SwiftUI client for an nzbfast daemon. This phase is remote
mode only ("my server": URL + API key); the on-device engine arrives
with workstream A3 (see the spike harness below - the engine side is
proven). Simulator-only for now - building and running needs no Apple
developer identity.

## Requirements

- Xcode 16 or newer (project uses folder-synchronized groups).
- Network access on first build: the VLCKit xcframework resolves via
  Swift Package Manager (tylerjonesio/vlckit-spm 3.6.0, checksum
  pinned in the package).

## Build and run (Simulator)

```sh
cd packaging/ios
xcodebuild -project NzbfastMobile.xcodeproj -scheme NzbfastMobile \
  -destination 'platform=iOS Simulator,name=iPhone 17 Pro' build
```

Or open `NzbfastMobile.xcodeproj` in Xcode and run on any iPhone
simulator. Install and launch from the command line:

```sh
xcrun simctl install booted <path-to>/NzbfastMobile.app
xcrun simctl launch booted com.nzbfast.mobile
```

## Test rig

Run a daemon on the Mac; the Simulator reaches the host's localhost
directly:

```sh
NZBFAST_NO_ENRICH=1 nzbfast serve --port 7789 --bind 127.0.0.1 \
  --apikey <key> --config <config-with-local-chaos-servers>
```

Connect the app to `http://127.0.0.1:7789` with that key. For a
playable job, post a real media file through a local mock NNTP server
(`nzbfast chaos-serve --profile clean`, then `nzbfast post file.mp4
--post-server 127.0.0.1:<port>`) and add the generated NZB to the
daemon.

## Notes

- The player is VLCKit because most real posts are Matroska and
  AVPlayer refuses the container.
- All playback copy stays under the "test preview" framing.
- Info.plist allows arbitrary HTTP loads for development (local
  daemons are plain http); tighten before any store build.
- Share-sheet registration for .nzb files is deferred to P2.

## A3 spike harness (in-process engine)

`HarnessApp.swift` + `build-harness.sh` are a THROWAWAY Simulator app
proving the engine runs in-process on iOS behind the C ABI in
`crates/nzbfast-ffi` (iOS forbids exec, so the Android child-process
shape does not transfer). Not a product app - the shell above is that;
it adopts the same staticlib for on-device mode.

```sh
packaging/ios/build-harness.sh
xcrun simctl install <device> packaging/ios/NZBFastHarness.app
xcrun simctl launch <device> com.nzbfast.spike-harness
```

The harness starts the engine on 127.0.0.1:8724 (the Simulator shares
the host's loopback - 6789 would collide with a dev Mac's live daemon)
and shows the dashboard it serves in a WKWebView. Details, sizes and
the aws-lc-rs verdict: `research/SPIKE-IOS-STATICLIB-2026-08-05.md`.

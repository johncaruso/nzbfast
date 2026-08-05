# Minimal test APK

Single-activity WebView on the engine's own dashboard plus a foreground
service that execs the engine from `nativeLibraryDir` - the Phase 1
skeleton from `research/PLAN-ANDROID.md`, cut down to what a tester
needs. No gradle: `../build-apk.sh` drives aapt2 + javac + d8 +
zipalign + apksigner straight from the SDK.

- API 26+ (`--min-sdk-version` in build-apk.sh), target 34.
- The engine ships as `lib/arm64-v8a/libnzbfast.so`;
  `extractNativeLibs="true"` makes the installer place a real file in
  `nativeLibraryDir`, and exec from there is the post-API-29-legal way
  to run a bundled binary.
- One API key per install (SharedPreferences), daemon bound to
  127.0.0.1 only; downloads land in the app-private files dir until the
  Phase 2 export story exists.
- Signed with a throwaway debug keystore minted per build. NOT a
  release artifact, do not distribute: the production signing identity
  is a separate decision (same gate as the update-manifest key).

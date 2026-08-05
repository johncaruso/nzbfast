#!/bin/sh
# Copy the slim Android engine binary into the jniLibs source dir the
# gradle build packages from. Build the binary first:
#   cargo ndk -t arm64-v8a --platform 26 build --release -p nzbfast --no-default-features
# The .so name is load-bearing: with useLegacyPackaging the installer
# extracts it to nativeLibraryDir where EngineService execs it.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../../.." && pwd)
BIN="${1:-$REPO/target/aarch64-linux-android/release/nzbfast}"
[ -f "$BIN" ] || { echo "engine binary not found: $BIN (build it first)" >&2; exit 1; }
mkdir -p "$HERE/app/engine/arm64-v8a"
cp "$BIN" "$HERE/app/engine/arm64-v8a/libnzbfast.so"
echo "engine staged: $HERE/app/engine/arm64-v8a/libnzbfast.so"

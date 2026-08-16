#!/bin/sh
# Regenerate cargo-sources.json from Cargo.lock.
#
# A Flathub build has no network, so every crate the build downloads has
# to be listed as a source with a URL and a checksum first. This is the
# community tool that turns Cargo.lock into that list; run it after ANY
# Cargo.lock change or the build stops offline at the first crate that
# moved.
#
# Path-only dependencies (vendor/rars, vendor/tiny_http) carry no
# registry source, so the generator skips them - they arrive inside the
# source tarball like the rest of the tree.
#
# Needs python3 with aiohttp + toml. On a machine without them:
#   python3 -m venv /tmp/fcg && /tmp/fcg/bin/pip install aiohttp toml
#   FCG_PYTHON=/tmp/fcg/bin/python3 ./generate-cargo-sources.sh
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$HERE/../.." && pwd)
PYTHON="${FCG_PYTHON:-python3}"
GEN="${FCG_SCRIPT:-$HERE/.flatpak-cargo-generator.py}"
UPSTREAM=https://raw.githubusercontent.com/flatpak/flatpak-builder-tools/master/cargo/flatpak-cargo-generator.py

if [ ! -f "$GEN" ]; then
    echo "fetching flatpak-cargo-generator.py"
    curl -fsSL -o "$GEN" "$UPSTREAM"
fi

"$PYTHON" "$GEN" "$ROOT/Cargo.lock" -o "$HERE/cargo-sources.json"

# The generator is happy to emit an empty list if it could not parse the
# lock file, and an empty list fails much later and much less clearly, as
# a missing crate halfway through a twenty-minute build.
COUNT=$("$PYTHON" -c 'import json,sys; print(len(json.load(open(sys.argv[1]))))' "$HERE/cargo-sources.json")
if [ "$COUNT" -lt 100 ]; then
    echo "cargo-sources.json has only $COUNT entries - that is not a real dependency set" >&2
    exit 1
fi
echo "cargo-sources.json: $COUNT entries"

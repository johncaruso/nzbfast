#!/bin/sh
# make-latest-json.sh <dist-dir> [notes]
#
# Generate the auto-update manifest (latest.json) from a dist directory
# containing the autoupdate payload binaries. Platform keys must match
# platform_key() in crates/nzbfast/src/serve.rs; the windows payload
# carries an .exe suffix (see the v1.0.0 release assets).
#
# Version comes from crates/nzbfast/Cargo.toml (the source of truth).
#
# EVERY platform payload must be present. A missing one used to be a
# warning on stderr, which meant a typo in the asset names (a stray `v`,
# say) produced a manifest that was written, valid JSON, signed, and
# exited 0 while advertising nothing - a dead release that looks like a
# success at every step. Missing payloads are now fatal. Omit a platform
# on purpose by naming it:
#   ALLOW_MISSING="linux-arm64 windows-x64" packaging/make-latest-json.sh dist
# ALLOW_MISSING=all waives them all, but an EMPTY platforms map is always
# fatal - a manifest that installs nowhere is never what anyone meant.
set -eu

DIST=${1:?usage: make-latest-json.sh <dist-dir> [notes]}
NOTES=${2:-}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' "$ROOT/crates/nzbfast/Cargo.toml" | head -1)
[ -n "$VERSION" ] || { echo "could not read version from Cargo.toml" >&2; exit 1; }
BASE="https://github.com/nzbfast/nzbfast/releases/download/v$VERSION"

if [ -z "$NOTES" ] && [ -f "$DIST/RELEASE_NOTES.md" ]; then
    # First non-heading, non-blank line of the release notes.
    NOTES=$(grep -v '^#' "$DIST/RELEASE_NOTES.md" | grep -m1 . || true)
fi

sha() { shasum -a 256 "$1" | cut -d' ' -f1; }

# Updater payloads carry the product name + version so a human who
# stumbles on the raw binary can tell what it is, while `autoupdate`
# (and the lack of a .dmg/.zip/.tar.gz extension) keeps it visibly
# distinct from the human download. Renamed from bare `autoupdate-*`
# (v1.0.4) - the manifest URL follows the file's basename, so the
# updater, which reads the URL from here, needs no change.
# NOTE: no `v` in the asset name. The tag is vX.Y.Z; the files are not.
PLATFORMS='macos-universal windows-x64 linux-x64 linux-arm64'
payload() {   # $1 = platform key -> path of its autoupdate payload
    if [ "$1" = windows-x64 ]; then
        printf '%s' "$DIST/nzbfast-$VERSION-autoupdate-$1.exe"
    else
        printf '%s' "$DIST/nzbfast-$VERSION-autoupdate-$1"
    fi
}

# ---- Pre-flight: refuse to build a manifest that installs nowhere ------
WAIVED=$(printf ' %s ' "${ALLOW_MISSING:-}" | tr ',' ' ')
missing=''
waived=''
present=0
for plat in $PLATFORMS; do
    f=$(payload "$plat")
    if [ -f "$f" ]; then
        present=$((present + 1))
    elif [ "${ALLOW_MISSING:-}" = all ] || printf '%s' "$WAIVED" | grep -q " $plat "; then
        waived="$waived    $plat  ($(basename "$f"))
"
    else
        missing="$missing    $plat  ($(basename "$f"))
"
    fi
done

if [ -n "$missing" ]; then
    echo "ERROR: autoupdate payload(s) not found in $DIST:" >&2
    printf '%s' "$missing" >&2
    echo "       A manifest without them is still valid JSON and still" >&2
    echo "       signs fine - it just never updates those platforms." >&2
    echo "       Build the missing payloads, check the names (no 'v'," >&2
    echo "       version $VERSION), or waive them deliberately with:" >&2
    echo "         ALLOW_MISSING=\"<platform> ...\" $0 $DIST" >&2
    exit 1
fi
if [ "$present" -eq 0 ]; then
    echo "ERROR: no autoupdate payloads at all in $DIST - the platforms" >&2
    echo "       map would be empty. A signed, valid manifest advertising" >&2
    echo "       no downloads is a dead release, so this is never allowed" >&2
    echo "       (not even with ALLOW_MISSING). Expected one or more of:" >&2
    for plat in $PLATFORMS; do echo "         $(basename "$(payload "$plat")")" >&2; done
    exit 1
fi
if [ -n "$waived" ]; then
    echo "note: platform(s) deliberately omitted via ALLOW_MISSING:" >&2
    printf '%s' "$waived" >&2
fi

OUT="$DIST/latest.json"
first=1
{
    printf '{\n  "version": "%s",\n  "notes": %s,\n  "platforms": {' \
        "$VERSION" "$(printf '%s' "$NOTES" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))')"
    for plat in $PLATFORMS; do
        # Absence is already decided above: anything still missing here
        # was explicitly waived via ALLOW_MISSING.
        f=$(payload "$plat")
        if [ ! -f "$f" ]; then
            continue
        fi
        [ $first = 1 ] || printf ','
        first=0
        printf '\n    "%s": {\n      "url": "%s/%s",\n      "sha256": "%s"\n    }' \
            "$plat" "$BASE" "$(basename "$f")" "$(sha "$f")"
    done
    printf '\n  }\n}\n'
} > "$OUT"

python3 -c "import json; json.load(open('$OUT'))" || { echo "generated manifest is invalid JSON" >&2; exit 1; }
echo "wrote $OUT (version $VERSION)"

# Sign the manifest. The daemon REFUSES any manifest without a valid
# ed25519 signature by the key embedded in the binary (serve.rs
# UPDATE_PUBKEY_HEX), so an unsigned release is a broken release: no client
# will ever accept it. The private key lives only in $NZBFAST_UPDATE_SIGNING_KEY
# (a path to the offline hex key), never in the repo or CI.
if [ -z "${NZBFAST_UPDATE_SIGNING_KEY:-}" ]; then
    echo "" >&2
    echo "ERROR: NZBFAST_UPDATE_SIGNING_KEY is not set - $OUT is UNSIGNED." >&2
    echo "       Clients refuse unsigned manifests. Set it to the path of the" >&2
    echo "       offline ed25519 private key (hex) and re-run. Generate a pair" >&2
    echo "       with: cargo run -p nzbfast --example update_sign -- keygen" >&2
    exit 1
fi
SIGNER="$ROOT/target/release/examples/update_sign"
[ -x "$SIGNER" ] || SIGNER="$ROOT/target/debug/examples/update_sign"
if [ ! -x "$SIGNER" ]; then
    echo "building update_sign tool…" >&2
    ( cd "$ROOT" && cargo build --release -p nzbfast --example update_sign >&2 )
    SIGNER="$ROOT/target/release/examples/update_sign"
fi
"$SIGNER" sign "$NZBFAST_UPDATE_SIGNING_KEY" "$OUT" || { echo "signing failed" >&2; exit 1; }
echo "signed $OUT -> $OUT.sig"

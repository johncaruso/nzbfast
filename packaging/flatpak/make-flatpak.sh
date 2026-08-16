#!/bin/sh
# Build the nzbfast Flatpak and export a single-file .flatpak bundle.
#
# The bundle is what we ship on the release page, the same way NZBGet
# ships com.nzbget.nzbget.<ver>.<arch>.flatpak. It installs on any distro
# with `flatpak install ./nzbfast-<ver>-<arch>.flatpak` and needs no
# Flathub listing. A bundle is arch-specific: run this on the machine
# whose architecture you want, or Flathub's builders do both for you.
#
# It is NOT added to packaging/make-latest-json.sh. Flatpak updates
# through Flatpak; see the header of the manifest.
#
#   ./make-flatpak.sh                 # build from the tagged release
#   ./make-flatpak.sh --local         # build from THIS working tree
#
# --local rewrites only the source stanza, so what it exercises is the
# manifest that ships, less the download.
set -eu

HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$HERE/../.." && pwd)
APP_ID=io.github.nzbfast.nzbfast
MANIFEST="$HERE/$APP_ID.yaml"
BUILDDIR="${BUILDDIR:-$HERE/.build}"
REPO="${REPO:-$HERE/.repo}"
# flatpak-builder hardlinks between its state dir and the build dir, so
# the two have to sit on one filesystem or it refuses to start. Keeping
# the default beside BUILDDIR means overriding BUILDDIR (to build off a
# bind mount, say) moves both together instead of splitting them.
STATEDIR="${STATEDIR:-$BUILDDIR/../.flatpak-builder}"
LOCAL=0

for a in "$@"; do
    case "$a" in
        --local) LOCAL=1 ;;
        *) echo "unknown option: $a" >&2; exit 2 ;;
    esac
done

VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' "$ROOT/crates/nzbfast/Cargo.toml" | head -1)
ARCH=$(uname -m)
OUT="$HERE/nzbfast-$VERSION-$ARCH.flatpak"

command -v flatpak-builder >/dev/null 2>&1 || {
    echo "flatpak-builder is not installed" >&2; exit 1; }

if [ ! -f "$HERE/cargo-sources.json" ]; then
    echo "cargo-sources.json is missing - run ./generate-cargo-sources.sh" >&2
    exit 1
fi

# --local: swap the release tarball for the working tree. `dir` sources
# are copied into the build, so the tree is never written to.
if [ "$LOCAL" = 1 ]; then
    MANIFEST="$HERE/.$APP_ID.local.yaml"
    python3 - "$HERE/$APP_ID.yaml" "$MANIFEST" "$ROOT" <<'PY'
import re, sys
src, dst, root = sys.argv[1], sys.argv[2], sys.argv[3]
s = open(src).read()
# The whole archive stanza, from its `- type: archive` line up to the
# cargo-sources entry that follows it.
pat = re.compile(r"      - type: archive\n(?:        .*\n|          .*\n|        #.*\n)*")
new = "      - type: dir\n        path: %s\n" % root
s, n = pat.subn(new, s, count=1)
assert n == 1, "could not find the archive source stanza to replace"
open(dst, "w").write(s)
PY
    echo "building from the working tree: $ROOT"
fi

flatpak-builder --force-clean --disable-rofiles-fuse \
    --state-dir="$STATEDIR" --repo="$REPO" "$BUILDDIR" "$MANIFEST"

flatpak build-bundle "$REPO" "$OUT" "$APP_ID"

echo
echo "bundle: $OUT"
ls -lh "$OUT"
echo
echo "install it with:  flatpak install --user ./$(basename "$OUT")"

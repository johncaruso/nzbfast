#!/usr/bin/env bash
# Build the human-download Linux tarballs - static musl, one per CPU.
#
#   packaging/build-linux-tarballs.sh [dist-dir] [arch ...]
#
# With no arch arguments it builds all of them. Named archs build only
# those: `packaging/build-linux-tarballs.sh dist armv7`.
#
#   x64    x86_64-unknown-linux-musl        nzbfast-X.Y.Z-linux-x64.tar.gz
#   arm64  aarch64-unknown-linux-musl       nzbfast-X.Y.Z-linux-arm64.tar.gz
#   armv7  armv7-unknown-linux-musleabihf   nzbfast-X.Y.Z-linux-armv7-beta.tar.gz
#
# This recipe lived only in the publish-release skill and a handoff note
# until 15 Aug 2026, which is how v1.1.2 nearly shipped -gnu binaries
# (see upload-release-assets.sh's linkage gate, added after that).
#
# WHY MUSL, not -gnu: a glibc build links whatever the build host has
# (ubuntu-latest = glibc 2.39) and refuses to start on Debian 12, Ubuntu
# 22.04, Alpine, or DSM. Measured 28 Jul 2026. The `nzbfast-<triple>.tar.gz`
# assets on the same release ARE glibc on purpose - they are the attested
# CI provenance build, not the download anyone is pointed at.
#
# armv7 IS BETA and is deliberately NOT in the signed update manifest -
# see the platform-key note in make-latest-json.sh. Read TODO 178 before
# promoting it.
#
# Prereq: cargo-zigbuild + zig. Plain cargo wants `x86_64-linux-musl-gcc`
# and friends, which are not installed on the release Mac (rediscovered
# four times; recorded here so it is five).
#   cargo install cargo-zigbuild && brew install zig
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT=$(pwd)

# Owner metadata. tar records the BUILDING ACCOUNT's uid, gid, user name
# and group name in every member header unless told not to, and this
# project is anonymous in public: the 1.1.x tarballs shipped the build
# account name in every entry. The publish-release skill has carried the
# correct flags since the day that was found; this script, which is what
# actually builds the assets, did not use them.
#
# The spelling differs by tar and both are in play (bsdtar on the release
# Mac, GNU tar on a Linux runner), so ask rather than assume - a wrong
# flag here is a hard error mid-release, and a missing one is a silent
# leak. --numeric-owner is what stops GNU tar writing names at all.
if tar --version 2>&1 | head -1 | grep -qi bsdtar; then
    TAR_OWNER=(--uid 0 --gid 0 --uname "" --gname "")
else
    TAR_OWNER=(--owner=0 --group=0 --numeric-owner)
fi

# Print them and stop. Nothing above this line builds anything, so a test
# can check the flags on any OS without a cross-compiler, the way
# make-packages.sh --print-unit is checked.
if [ "${1:-}" = "--print-tar-owner-flags" ]; then
    printf '%s\n' "${TAR_OWNER[@]}"
    exit 0
fi

DIST=${1:-dist}
shift || true
VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' crates/nzbfast/Cargo.toml | head -1)
[ -n "$VERSION" ] || { echo "could not read version from crates/nzbfast/Cargo.toml" >&2; exit 1; }

ALL_ARCHES="x64 arm64 armv7"
ARCHES=${*:-$ALL_ARCHES}

triple_of() {
    case $1 in
        x64)   echo x86_64-unknown-linux-musl ;;
        arm64) echo aarch64-unknown-linux-musl ;;
        armv7) echo armv7-unknown-linux-musleabihf ;;
        *) echo "unknown arch '$1' - one of: $ALL_ARCHES" >&2; exit 1 ;;
    esac
}

# The asset name. armv7 wears BETA in the FILENAME, not only in the
# release notes: the notes are one page a downloader may never read, and
# an asset list is the thing they actually click.
asset_of() {
    case $1 in
        armv7) echo "nzbfast-$VERSION-linux-armv7-beta.tar.gz" ;;
        *)     echo "nzbfast-$VERSION-linux-$1.tar.gz" ;;
    esac
}

command -v cargo-zigbuild >/dev/null 2>&1 || {
    echo "cargo-zigbuild not found - see the prereq note at the top of this script" >&2
    exit 1
}

# An absolute output directory has to survive being used twice: mkdir
# here and the tar target below. It used to be created directly and then
# written as "$ROOT/$DIST", so an absolute path became a repo-relative
# one with the absolute path embedded in it. Resolve it once, here.
mkdir -p "$DIST"
DIST=$(cd "$DIST" && pwd)

# MANUAL.html ships inside every tarball; generate it once.
MANUAL=$(mktemp -d)/MANUAL.html
packaging/make-offline-manual.sh docs/MANUAL.html "$MANUAL"

for arch in $ARCHES; do
    triple=$(triple_of "$arch")
    asset=$(asset_of "$arch")
    echo "== $arch ($triple) =="
    rustup target add "$triple" >/dev/null 2>&1 || true
    # --locked: build the committed dependency graph, or fail.
    cargo zigbuild --release --locked -p nzbfast --target "$triple"

    bin=target/$triple/release/nzbfast
    # Assert the positive. An unreadable `file` output must fail here,
    # never pass by failing to match a negative - the same reasoning
    # upload-release-assets.sh's gate carries.
    if ! file "$bin" | grep -q "statically linked"; then
        echo "✗ $triple: NOT statically linked - $(file -b "$bin")" >&2
        echo "    A dynamically linked Linux asset will not start on the" >&2
        echo "    distributions this download exists for. Refusing." >&2
        exit 1
    fi

    work=$(mktemp -d)
    inner="$work/nzbfast-$VERSION-linux-$arch"   # NOTE: no BETA in the
    mkdir -p "$inner"                            # inner dir - push-image.sh
    cp "$bin" "$inner/nzbfast"                   # reads this exact path.
    chmod +x "$inner/nzbfast"
    cp LICENSE COPYRIGHT.md "$inner/"
    cp "$MANUAL" "$inner/MANUAL.html"
    if [ "$arch" = armv7 ]; then
        cat > "$inner/BETA.txt" <<'BETA'
This 32-bit ARM (armv7) build is BETA.

It is for 32-bit Raspberry Pi OS on a Pi 2/3/Zero 2 W. If `uname -m`
says aarch64, you are running the 64-bit OS - take the arm64 download
instead, which is faster and is not beta.

What beta means here, concretely:

  - The full test suite passes on this CPU, but it has been run under
    emulation rather than on Pi hardware for every release so far.
  - Auto-update does not offer it. The update manifest has no 32-bit ARM
    entry on purpose, so this install will never be handed a payload it
    cannot run. Update by downloading the next tarball by hand.
  - A single RAR member larger than 4 GB of PACKED data is refused
    rather than mis-extracted, because a 32-bit process cannot address
    the extent. Usenet sets are split far below that; a one-piece
    archive that big is the shape to watch for.
  - Memory is the binding constraint on a 1 GB Pi, not CPU. The
    defaults size themselves to the RAM they find. `--mem-limit` above
    1 GB is clamped: a 32-bit process has ~3 GB of address space in
    total and cannot spend more than that however it is asked to.

Please report anything that looks wrong, with `uname -a` and the
version, at https://github.com/nzbfast/nzbfast/issues
BETA
    fi
    # COPYFILE_DISABLE=1 is load-bearing, not hygiene. bsdtar (the tar on
    # the release Mac) stores an AppleDouble `._name` member for any file
    # carrying an xattr, and macOS 15+ puts com.apple.provenance on
    # anything it has seen - so a plain `tar czf` here yields a `._<dir>`
    # SECOND top-level entry, which breaks unpackers that collapse a lone
    # wrapper directory. v1.1.2 shipped both linux tarballs that way.
    #
    # It survived inspection because `tar tzvf` ON A MAC LISTS SUCH A
    # TARBALL CLEAN - bsdtar consumes AppleDouble members on read, GNU tar
    # on Linux does not. So do not "verify" this with tar on this machine;
    # upload-release-assets.sh refuses the shape with python's tarfile,
    # which is the check that actually sees it.
    COPYFILE_DISABLE=1 tar "${TAR_OWNER[@]}" -czf "$DIST/$asset" -C "$work" "nzbfast-$VERSION-linux-$arch"
    rm -rf "$work"
    echo "  -> $DIST/$asset"
done

rm -rf "$(dirname "$MANUAL")"
echo
echo "== built =="
for arch in $ARCHES; do
    a=$(asset_of "$arch")
    printf '%s  %s\n' "$( { shasum -a 256 "$DIST/$a" 2>/dev/null || sha256sum "$DIST/$a"; } | awk '{print $1}')" "$a"
done
echo
echo "Next: packaging/scan-release-assets.sh then packaging/upload-release-assets.sh"

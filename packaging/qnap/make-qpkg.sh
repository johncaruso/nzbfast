#!/bin/sh
# Build the QNAP package (.qpkg) from the static musl binaries already
# attached to the GitHub Release - the same trick make-spk.sh and
# push-image.sh use, so the package ships the exact released bits and
# needs no cross-compiler here.
#
#   packaging/qnap/make-qpkg.sh 1.1.2 [outdir] [port]
#   packaging/qnap/make-qpkg.sh --binaries <dir> 1.1.2 [outdir] [port]
#
# With --binaries, the two static musl binaries are taken from <dir>
# (named nzbfast-x86_64 and nzbfast-aarch64) instead of downloaded. That
# is how release.yml builds it: the `packages` job already cross-compiles
# both musl targets for the .deb and .rpm, so the package can be built
# during the release run rather than after it, from the same bits. The
# downloading form stays for rebuilding a package against a release that
# has already shipped.
#
# Produces ONE package, nzbfast-<ver>-qnap-beta.qpkg, carrying both the
# x86_64 and aarch64 binaries; nzbfast-setup.sh keeps the one this NAS can
# run and deletes the other. The reasoning for one file rather than one
# per architecture is in qpkg.cfg.
#
# BETA. Nobody on this team owns a QNAP, so nothing here has been proven
# on real hardware: the install decisions are tested off-box
# (packaging/tests/qnap-install.sh) and the built package is verified by
# taking it apart again below, but "it unpacks correctly" is not "it
# installs and runs". The filename says beta for that reason, and the
# package is deliberately NOT in the signed update manifest - see
# packaging/qnap/README.md.
#
# The build itself runs QDK, QNAP's own kit, pinned in qdk-pin.txt. It
# cannot run on macOS (BSD sed -i, see Dockerfile), so this script runs it
# in a container when it has to and natively when qbuild is already on
# PATH, which is what CI does.
set -eu

BINDIR=""
if [ "${1:-}" = "--binaries" ]; then
    BINDIR="${2:?--binaries needs a directory}"
    shift 2
fi
VER="${1:?usage: make-qpkg.sh [--binaries <dir>] <version> [outdir] [port]}"
OUTDIR="${2:-dist}"
# The port is baked in at build time because QTS reads Web_Port and
# Service_Port out of the package at install and cannot be told a
# different one later - App Center's Open button would point at the wrong
# place if the service picked a port dynamically. 6789 is right for
# essentially everyone; a different value exists so a second instance can
# be built for testing alongside a running one.
PORT="${3:-6789}"
REL="https://github.com/nzbfast/nzbfast/releases/download/v${VER}"
SELF="$(cd "$(dirname "$0")" && pwd)"
QDK_COMMIT="$(grep -v '^#' "$SELF/qdk-pin.txt" | grep -m1 . )"

if command -v sha256sum >/dev/null 2>&1; then SHA256C="sha256sum -c -"
else SHA256C="shasum -a 256 -c -"; fi

DIR="$(mktemp -d)"
trap 'rm -rf "$DIR"' EXIT
mkdir -p "$OUTDIR"
OUTDIR="$(cd "$OUTDIR" && pwd)"

# ---- payload ----------------------------------------------------------
if [ -z "$BINDIR" ]; then
    # Fetch + verify the released linux binaries. Each archive is checked
    # against its OWN checksum line and that line has to exist, so a
    # partial SHA256SUMS.txt cannot let an unverified binary into a
    # package.
    for a in linux-x64 linux-arm64; do
        curl -fsSL -o "$DIR/nzbfast-$VER-$a.tar.gz" "$REL/nzbfast-$VER-$a.tar.gz"
    done
    curl -fsSL -o "$DIR/SHA256SUMS.txt" "$REL/SHA256SUMS.txt"
    for a in linux-x64 linux-arm64; do
        art="nzbfast-$VER-$a.tar.gz"
        n=$(grep -c "[ *]$art\$" "$DIR/SHA256SUMS.txt" || true)
        if [ "$n" != "1" ]; then
            echo "✗ SHA256SUMS.txt has $n checksum lines for $art (need exactly 1)" >&2
            exit 1
        fi
        (cd "$DIR" && grep "[ *]$art\$" SHA256SUMS.txt | $SHA256C)
    done
fi

# ---- staging ----------------------------------------------------------
# A QDK build root: qpkg.cfg and package_routines at the top, shared/
# holding everything that lands in the installed package directory, and
# icons/ named after the package. Built in a temp copy so the repo never
# holds a version- or port-substituted file.
WORK="$DIR/build"
mkdir -p "$WORK/shared/bin" "$WORK/icons"
cp "$SELF/qpkg.cfg" "$SELF/package_routines" "$WORK/"
cp "$SELF/shared/nzbfast.sh" "$SELF/shared/nzbfast-setup.sh" "$WORK/shared/"
cp "$SELF/icons/nzbfast.png" "$SELF/icons/nzbfast_80.png" \
   "$SELF/icons/nzbfast_gray.png" "$WORK/icons/"

# linux-x64 -> x86_64, linux-arm64 -> aarch64. These are the names
# nzbfast-setup.sh looks for; they are not our release-asset names.
for pair in "linux-x64 x86_64" "linux-arm64 aarch64"; do
    asset=${pair% *}; arch=${pair#* }
    if [ -n "$BINDIR" ]; then
        src="$BINDIR/nzbfast-$arch"
        [ -f "$src" ] || { echo "✗ --binaries: $src is not there" >&2; exit 1; }
    else
        tar xzf "$DIR/nzbfast-$VER-$asset.tar.gz" -C "$DIR" "nzbfast-$VER-$asset/nzbfast"
        src="$DIR/nzbfast-$VER-$asset/nzbfast"
    fi
    cp "$src" "$WORK/shared/bin/nzbfast-$arch"
    chmod 755 "$WORK/shared/bin/nzbfast-$arch"
done

# Whichever way they arrived, they have to be STATIC. A binary linked
# against a build host's glibc does not start on a NAS (measured 28 Jul:
# GLIBC_2.39 not found on debian:bookworm, and QTS is older than that),
# and the failure is a package that installs cleanly and never runs.
# upload-release-assets.sh enforces the same rule for the human tarballs.
# Assert the positive. This used to reject only when `file` was present
# AND said "dynamically linked", so every other way of being wrong went
# through: no file(1) on the box, a text file, an empty file, or the
# right linkage on the WRONG ARCHITECTURE - an aarch64 binary shipped as
# nzbfast-x86_64 passes a linkage-only check and fails on the NAS, which
# is the failure this gate exists to prevent.
command -v file >/dev/null 2>&1 || {
    echo "✗ file(1) is not installed, so the packaged binaries cannot be" >&2
    echo "  checked. Refusing rather than shipping an unverified .qpkg." >&2
    exit 1
}
for arch in x86_64 aarch64; do
    f="$WORK/shared/bin/nzbfast-$arch"
    desc=$(file -b "$f" 2>/dev/null || true)
    case "$desc" in
        *"statically linked"*) ;;
        *)
            echo "✗ $f is not a statically linked binary." >&2
            echo "  file says: ${desc:-<nothing>}" >&2
            echo "  The package needs the static musl build, not a glibc one." >&2
            exit 1
            ;;
    esac
    case "$arch" in
        x86_64)  want="x86-64" ;;
        aarch64) want="aarch64" ;;
    esac
    case "$desc" in
        *"$want"*) ;;
        *)
            echo "✗ $f is not a $arch binary - file says: $desc" >&2
            echo "  The two binaries are picked by name at install time, so" >&2
            echo "  a swapped pair installs cleanly and never starts." >&2
            exit 1
            ;;
    esac
done
chmod 755 "$WORK/shared/nzbfast.sh" "$WORK/shared/nzbfast-setup.sh"

# Bake in the version and the port. Anything still holding a placeholder
# afterwards is a file someone added without wiring it up, so fail loudly
# rather than shipping a package with "@@PORT@@" where a port belongs.
for f in "$WORK/qpkg.cfg" "$WORK/package_routines" \
         "$WORK/shared/nzbfast.sh" "$WORK/shared/nzbfast-setup.sh"; do
    sed -e "s/@@PORT@@/$PORT/g" -e "s/@@VERSION@@/$VER/g" "$f" > "$f.tmp"
    mv "$f.tmp" "$f"
done
chmod 755 "$WORK/shared/nzbfast.sh" "$WORK/shared/nzbfast-setup.sh"
if grep -rl "@@PORT@@\|@@VERSION@@" "$WORK" 2>/dev/null | grep -q .; then
    echo "✗ unsubstituted placeholder left in:" >&2
    grep -rl "@@PORT@@\|@@VERSION@@" "$WORK" >&2
    exit 1
fi

# ---- build ------------------------------------------------------------
# --gzip: the data archive stays a plain tar.gz. QDK also offers 7z and
# xz, both of which make the package depend on an extractor being present
# on the NAS, and both of which would put the shipped binaries out of
# reach of packaging/scan-release-assets.sh - a leak gate that cannot open
# an asset is a gate that passes it blind.
QBUILD_ARGS="--root $WORK --build-dir $WORK/out --build-version $VER --gzip --verbose"

# QDK has to be told where it lives. qbuild works out a default QDK_PATH
# from its own location and then sources qdk.conf, which overwrites it
# with a value derived from the CURRENT DIRECTORY:
#     QDK_PATH_P=`pwd | awk 'BEGIN { FS = "QDK" } ; { print $1 }'`
# That resolves to <cwd>/QDK, which is right only when you happen to be
# building from inside a directory tree named QDK, and is why a checkout
# anywhere else fails with "<repo>/QDK/scripts/qinstall.sh: no such
# file". QDK_SCRIPTS_DIR and QDK_TEMPLATE_DIR are read from the
# environment before that default is applied, so setting them is the
# supported way past it.
qdk_env_from_qbuild() {
    _qb="$1"
    _share=$(dirname "$(dirname "$(readlink -f "$_qb" 2>/dev/null || echo "$_qb")")")
    QDK_SCRIPTS_DIR="${QDK_SCRIPTS_DIR:-$_share/scripts}"
    QDK_TEMPLATE_DIR="${QDK_TEMPLATE_DIR:-$_share/template}"
    export QDK_SCRIPTS_DIR QDK_TEMPLATE_DIR
    if [ ! -f "$QDK_SCRIPTS_DIR/qinstall.sh" ]; then
        echo "✗ $QDK_SCRIPTS_DIR/qinstall.sh is not there." >&2
        echo "  qbuild at $_qb does not look like a QDK checkout. Point" >&2
        echo "  QDK_SCRIPTS_DIR and QDK_TEMPLATE_DIR at one." >&2
        exit 1
    fi
    # qbuild's last step stamps a checksum into the package trailer with
    # qpkg_encrypt, a small C program that lives in QDK's src/ and is NOT
    # built by cloning. Missing, qbuild prints one "command not found"
    # line among its progress messages and still exits 0, leaving a
    # package whose checksum field is blank - which App Center is the one
    # to discover. Refuse here instead.
    if ! command -v qpkg_encrypt >/dev/null 2>&1; then
        echo "✗ qpkg_encrypt is not on PATH." >&2
        echo "  It is QDK's own checksum tool and has to be compiled:" >&2
        echo "      make -C <qdk-checkout>/src" >&2
        echo "  then put <qdk-checkout>/src/bin on PATH. Without it" >&2
        echo "  qbuild still writes a .qpkg, and the checksum field in" >&2
        echo "  its trailer is left blank." >&2
        exit 1
    fi
}

if command -v qbuild >/dev/null 2>&1; then
    echo "building with qbuild on PATH ($(command -v qbuild))"
    qdk_env_from_qbuild "$(command -v qbuild)"
    # shellcheck disable=SC2086  # deliberate word splitting of the args
    qbuild $QBUILD_ARGS
elif command -v docker >/dev/null 2>&1 || command -v podman >/dev/null 2>&1; then
    RUNTIME=docker
    command -v docker >/dev/null 2>&1 || RUNTIME=podman
    echo "building with QDK in a $RUNTIME container (QDK $QDK_COMMIT)"
    $RUNTIME build -q -t "nzbfast-qdk:$QDK_COMMIT" \
        --build-arg "QDK_COMMIT=$QDK_COMMIT" "$SELF" >/dev/null
    # The staging directory is the only thing mounted, and qbuild runs as
    # the container's root over a copy - the repo is never in scope.
    $RUNTIME run --rm -v "$WORK:/work" "nzbfast-qdk:$QDK_COMMIT" \
        qbuild --root /work --build-dir /work/out --build-version "$VER" \
               --gzip --verbose
else
    echo "✗ no qbuild and no container runtime." >&2
    echo "  The .qpkg is built by QNAP's own QDK, which does not run on" >&2
    echo "  macOS (see packaging/qnap/Dockerfile). Either:" >&2
    echo "    - install Docker or Podman and re-run this, or" >&2
    echo "    - let CI do it: the qnap-qpkg workflow builds and uploads" >&2
    echo "      the package on an Ubuntu runner." >&2
    echo "  Do not hand-assemble the package layout instead." >&2
    exit 1
fi

BUILT="$(ls "$WORK/out"/*.qpkg 2>/dev/null | head -1 || true)"
[ -n "$BUILT" ] || { echo "✗ qbuild produced no .qpkg" >&2; exit 1; }

# A non-default port means a test build, so say so in the filename. The
# shipped artifact must never be ambiguous about which port it claims,
# and these do get passed around by hand.
NAME="nzbfast-$VER-qnap-beta"
[ "$PORT" = "6789" ] || NAME="$NAME-port$PORT"
cp "$BUILT" "$OUTDIR/$NAME.qpkg"

# ---- verify -----------------------------------------------------------
# Take the package apart again and look inside. qbuild reports success
# for a build whose payload is empty, whose version was never
# substituted, or whose service script did not survive staging - and none
# of those can be caught by reading its output. This is the same recipe
# packaging/scan-release-assets.sh uses on the shipped asset.
"$SELF/unpack-qpkg.sh" "$OUTDIR/$NAME.qpkg" "$DIR/verify"
fail=0
check() {
    if [ -e "$DIR/verify/$2" ]; then echo "  ok   $1"
    else echo "  FAIL $1 (missing $2)" >&2; fail=1; fi
}
echo "verifying $NAME.qpkg:"
check "control: qpkg.cfg"          control/qpkg.cfg
check "control: package_routines"  control/package_routines
check "control: qinstall.sh"       control/qinstall.sh
check "payload: x86_64 binary"     data/bin/nzbfast-x86_64
check "payload: aarch64 binary"    data/bin/nzbfast-aarch64
check "payload: service script"    data/nzbfast.sh
check "payload: setup script"      data/nzbfast-setup.sh
if grep -q "^QPKG_VER=\"$VER\"" "$DIR/verify/control/qpkg.cfg" 2>/dev/null; then
    echo "  ok   control: version is $VER"
else
    echo "  FAIL control: qpkg.cfg does not carry version $VER" >&2; fail=1
fi
if grep -q "^QPKG_WEB_PORT=\"$PORT\"" "$DIR/verify/control/qpkg.cfg" 2>/dev/null; then
    echo "  ok   control: web port is $PORT"
else
    echo "  FAIL control: qpkg.cfg does not carry port $PORT" >&2; fail=1
fi
# The 100-byte trailer is what App Center reads to identify the package:
#   [MODEL(10)|RESERVED(40)|FW_VERSION(10)|NAME(20)|VERSION(10)|FLAG(10)]
# qbuild appends it, then qpkg_encrypt overwrites ten bytes 60 from the
# end with the checksum. Both are silent when they do not happen.
TRAILER=$(tail -c 100 "$OUTDIR/$NAME.qpkg" | LC_ALL=C tr -d '\000')
case "$TRAILER" in
    *QNAPQPKG*) echo "  ok   trailer: carries the QNAPQPKG marker" ;;
    *) echo "  FAIL trailer: no QNAPQPKG marker - App Center reads this" >&2; fail=1 ;;
esac
case "$TRAILER" in
    *"$VER"*) echo "  ok   trailer: names version $VER" ;;
    *) echo "  FAIL trailer: does not name version $VER" >&2; fail=1 ;;
esac
ENC=$(tail -c 60 "$OUTDIR/$NAME.qpkg" | head -c 10 | LC_ALL=C tr -d ' \000')
if [ -n "$ENC" ]; then
    echo "  ok   trailer: checksum field is stamped"
else
    echo "  FAIL trailer: checksum field is blank - qpkg_encrypt did not run" >&2
    fail=1
fi
if grep -rq "@@PORT@@\|@@VERSION@@" "$DIR/verify" 2>/dev/null; then
    echo "  FAIL a placeholder survived into the package" >&2; fail=1
else
    echo "  ok   no unsubstituted placeholders"
fi
[ "$fail" = 0 ] || { echo "✗ the built package is not what it should be." >&2; exit 1; }

echo
echo "built $OUTDIR/$NAME.qpkg ($(du -h "$OUTDIR/$NAME.qpkg" | cut -f1), port $PORT)"
echo
echo "install: App Center → the gear icon → Install Manually → this file."
echo "         QTS will warn that it is not from the App Center. It is a"
echo "         BETA nobody has been able to run on real hardware yet."

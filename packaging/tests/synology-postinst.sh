#!/bin/sh
# Exercise the DSM package's postinst folder choice against fake volume
# layouts. This runs off-box because the decision it makes - where a
# user's downloads land - is the one part of the package that cannot be
# tried out before a NAS installs it.
set -eu

SELF="$(cd "$(dirname "$0")" && pwd)"
TEMPLATE="$SELF/../synology/spk/scripts/postinst"
[ -f "$TEMPLATE" ] || { echo "missing $TEMPLATE" >&2; exit 1; }

# make-spk.sh bakes the port in before shipping, so test what ships rather
# than the template - with the placeholder left in, every port comparison
# in the script is against a literal "@@PORT@@" and silently takes the
# non-default branch.
SUBST="$(mktemp -d)"
trap 'rm -rf "$SUBST"' EXIT
POSTINST="$SUBST/postinst"
sed 's/@@PORT@@/6789/g' "$TEMPLATE" > "$POSTINST"
POSTINST_ALT="$SUBST/postinst-alt"
sed 's/@@PORT@@/6790/g' "$TEMPLATE" > "$POSTINST_ALT"

pass=0; fail=0
check() {
    name="$1"; want="$2"; got="$3"
    if [ "$want" = "$got" ]; then
        pass=$((pass + 1)); echo "  ok   $name"
    else
        fail=$((fail + 1)); echo "  FAIL $name: want '$want' got '$got'" >&2
    fi
}

run_case() {
    root="$1"
    var="$root/var"
    mkdir -p "$var"
    SPK_TEST_ROOT="$root" SYNOPKG_PKGVAR="$var" sh "$POSTINST" >/dev/null 2>&1
    grep '^NZBFAST_OUT=' "$var/nzbfast.env" | cut -d= -f2-
}

T="$(mktemp -d)"
trap 'rm -rf "$T"' EXIT

# 1. Single volume with a conventional downloads share -> use it, because
#    only a shared folder is visible in File Station.
r="$T/a"; mkdir -p "$r/volume1/downloads"
check "single volume, downloads share" "$r/volume1/downloads/nzbfast/downloads" "$(run_case "$r")"

# 2. No shared folder at all -> fall back to package storage rather than
#    inventing a bare directory the user cannot browse.
r="$T/b"; mkdir -p "$r/volume1"
check "no share, falls back to var" "$r/var/downloads" "$(run_case "$r")"

# 3. A 'media' share counts too.
r="$T/c"; mkdir -p "$r/volume1/media"
check "media share accepted" "$r/volume1/media/nzbfast/downloads" "$(run_case "$r")"

# 4. Re-running (an upgrade) must not move an existing choice.
r="$T/d"; mkdir -p "$r/volume1/downloads" "$r/var"
printf 'NZBFAST_PORT=6789\nNZBFAST_OUT=/somewhere/chosen\nNZBFAST_WATCH=/somewhere/w\n' \
    > "$r/var/nzbfast.env"
SPK_TEST_ROOT="$r" SYNOPKG_PKGVAR="$r/var" sh "$POSTINST" >/dev/null 2>&1
check "upgrade keeps existing paths" "/somewhere/chosen" \
    "$(grep '^NZBFAST_OUT=' "$r/var/nzbfast.env" | cut -d= -f2-)"

# 5. The watch folder is created, not just named.
r="$T/e"; mkdir -p "$r/volume1/downloads"
run_case "$r" >/dev/null
if [ -d "$r/volume1/downloads/nzbfast/watch" ]; then
    pass=$((pass + 1)); echo "  ok   watch folder created"
else
    fail=$((fail + 1)); echo "  FAIL watch folder not created" >&2
fi

# --- architecture selection (the package is noarch and carries both) ----

arch_case() {
    root="$1"; machine="$2"
    mkdir -p "$root/var" "$root/target/bin"
    : > "$root/target/bin/nzbfast-x86_64"
    : > "$root/target/bin/nzbfast-aarch64"
    mkdir -p "$root/volume1/downloads"
    SPK_TEST_ROOT="$root" SPK_TEST_UNAME="$machine" \
        SYNOPKG_PKGVAR="$root/var" SYNOPKG_PKGDEST="$root/target" \
        sh "$POSTINST" >/dev/null 2>&1
}

r="$T/f"; arch_case "$r" x86_64
check "x86_64 links the x86_64 binary" "nzbfast-x86_64" \
    "$(readlink "$r/target/bin/nzbfast")"
if [ -e "$r/target/bin/nzbfast-aarch64" ]; then
    fail=$((fail + 1)); echo "  FAIL unused aarch64 binary left on disk" >&2
else
    pass=$((pass + 1)); echo "  ok   unused binary removed"
fi

r="$T/g"; arch_case "$r" aarch64
check "aarch64 links the aarch64 binary" "nzbfast-aarch64" \
    "$(readlink "$r/target/bin/nzbfast")"

# An unsupported model must fail the INSTALL, not install a package that
# dies at every start with nothing saying why.
r="$T/h"; mkdir -p "$r/var" "$r/target/bin" "$r/volume1/downloads"
: > "$r/target/bin/nzbfast-x86_64"; : > "$r/target/bin/nzbfast-aarch64"
if SPK_TEST_ROOT="$r" SPK_TEST_UNAME="armv7l" SYNOPKG_PKGVAR="$r/var" \
     SYNOPKG_PKGDEST="$r/target" sh "$POSTINST" >/dev/null 2>&1; then
    fail=$((fail + 1)); echo "  FAIL armv7l install was allowed to succeed" >&2
else
    pass=$((pass + 1)); echo "  ok   unsupported arch refuses to install"
fi

# An upgrade re-extracts both binaries, so the symlink has to be redone
# even though the env file already exists and short-circuits the rest.
r="$T/i"; arch_case "$r" x86_64
: > "$r/target/bin/nzbfast-aarch64"          # as a fresh payload would
rm -f "$r/target/bin/nzbfast"
SPK_TEST_ROOT="$r" SPK_TEST_UNAME="x86_64" SYNOPKG_PKGVAR="$r/var" \
    SYNOPKG_PKGDEST="$r/target" sh "$POSTINST" >/dev/null 2>&1
check "upgrade relinks the binary" "nzbfast-x86_64" \
    "$(readlink "$r/target/bin/nzbfast")"

# --- a second instance must not land on the first one's folder ----------
#
# The default path, <share>/nzbfast, is exactly what an existing Container
# Manager install uses. A build on another port is a deliberate second
# instance, so it gets its own parent directory - sharing one would mean
# two daemons claiming the same jobs, which is worse than a port clash.
# Lowercase here: the host running these tests may have a
# case-insensitive filesystem, where "Downloads" would also match
# the lowercase candidate and make the expected path ambiguous.
r="$T/j"; mkdir -p "$r/volume1/downloads" "$r/var"
SPK_TEST_ROOT="$r" SYNOPKG_PKGVAR="$r/var" SPK_TEST_SKIP_PORTCHECK=1 \
    sh "$POSTINST_ALT" >/dev/null 2>&1
check "non-default port gets its own parent dir" \
    "$r/volume1/downloads/nzbfast-port6790/downloads" \
    "$(grep '^NZBFAST_OUT=' "$r/var/nzbfast.env" | cut -d= -f2-)"

# --- never chown a folder we did not create -----------------------------
#
# Someone migrating from Docker has <share>/nzbfast sitting there full of
# their live config, index.db and downloads. Recursively chowning that to
# the package account would take a running install's files away from it.
r="$T/k"
mkdir -p "$r/volume1/downloads/nzbfast/downloads" \
         "$r/volume1/downloads/nzbfast/watch" "$r/var"
echo "existing data" > "$r/volume1/downloads/nzbfast/downloads/keep.txt"
before=$(stat -f "%Su:%Sg" "$r/volume1/downloads/nzbfast/downloads" 2>/dev/null \
         || stat -c "%U:%G" "$r/volume1/downloads/nzbfast/downloads")
SPK_TEST_ROOT="$r" SYNOPKG_PKGVAR="$r/var" SPK_TEST_SKIP_PORTCHECK=1 \
    sh "$POSTINST" >/dev/null 2>&1
after=$(stat -f "%Su:%Sg" "$r/volume1/downloads/nzbfast/downloads" 2>/dev/null \
        || stat -c "%U:%G" "$r/volume1/downloads/nzbfast/downloads")
check "existing folder keeps its ownership" "$before" "$after"
if [ -f "$r/volume1/downloads/nzbfast/downloads/keep.txt" ]; then
    pass=$((pass + 1)); echo "  ok   existing contents untouched"
else
    fail=$((fail + 1)); echo "  FAIL existing contents disturbed" >&2
fi

echo
echo "$pass passed, $fail failed"
[ "$fail" = 0 ]

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
T="$(mktemp -d)"
trap 'rm -rf "$SUBST" "$T"' EXIT
POSTINST="$SUBST/postinst"
sed 's/@@PORT@@/6789/g' "$TEMPLATE" > "$POSTINST"
POSTINST_ALT="$SUBST/postinst-alt"
sed 's/@@PORT@@/6790/g' "$TEMPLATE" > "$POSTINST_ALT"

# Stubs for the two commands postinst runs against the HOST rather than
# against the fake volume tree below. Each is shadowed only by the cases
# that want it, by putting its directory first on PATH; neither is on
# PATH otherwise.
STUB_CURL="$SUBST/stub-curl"; mkdir -p "$STUB_CURL"
cat > "$STUB_CURL/curl" <<'EOF'
#!/bin/sh
exit "${STUB_CURL_RC:-0}"
EOF
STUB_DF="$SUBST/stub-df"; mkdir -p "$STUB_DF"
cat > "$STUB_DF/df" <<'EOF'
#!/bin/sh
exit 1
EOF
chmod +x "$STUB_CURL/curl" "$STUB_DF/df"

pass=0; fail=0
check() {
    name="$1"; want="$2"; got="$3"
    if [ "$want" = "$got" ]; then
        pass=$((pass + 1)); echo "  ok   $name"
    else
        fail=$((fail + 1)); echo "  FAIL $name: want '$want' got '$got'" >&2
    fi
}

# Every folder-choice case skips the port probe, and every invocation
# below tolerates a non-zero exit. The probe is the one part of this
# script that talks to the REAL host - `curl http://127.0.0.1:6789/` -
# so on any machine running nzbfast (a developer's, mostly) postinst
# refused before it chose anything: three cases read back an empty path,
# the fourth exited non-zero under `set -e` and killed the run before it
# reached the other ten, and the summary line never printed. The probe
# gets its own cases further down with curl stubbed, so skipping it here
# costs no coverage.
run_case() {
    root="$1"
    var="$root/var"
    mkdir -p "$var"
    SPK_TEST_ROOT="$root" SYNOPKG_PKGVAR="$var" SPK_TEST_SKIP_PORTCHECK=1 \
        sh "$POSTINST" >/dev/null 2>&1 || true
    grep '^NZBFAST_OUT=' "$var/nzbfast.env" 2>/dev/null | cut -d= -f2-
}

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
SPK_TEST_ROOT="$r" SYNOPKG_PKGVAR="$r/var" SPK_TEST_SKIP_PORTCHECK=1 \
    sh "$POSTINST" >/dev/null 2>&1 || true
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
        SPK_TEST_SKIP_PORTCHECK=1 sh "$POSTINST" >/dev/null 2>&1 || true
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
     SYNOPKG_PKGDEST="$r/target" SPK_TEST_SKIP_PORTCHECK=1 \
     sh "$POSTINST" >/dev/null 2>&1; then
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
    SYNOPKG_PKGDEST="$r/target" SPK_TEST_SKIP_PORTCHECK=1 \
    sh "$POSTINST" >/dev/null 2>&1 || true
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
    sh "$POSTINST_ALT" >/dev/null 2>&1 || true
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
# GNU stat and BSD stat spell this differently, and GNU's -f is a
# different question entirely (it stats the FILESYSTEM), so ask the GNU
# way first: on macOS -c simply fails and the BSD form answers, whereas
# the other order gets a filesystem answer out of GNU stat and compares
# it against itself.
before=$(stat -c "%U:%G" "$r/volume1/downloads/nzbfast/downloads" 2>/dev/null \
         || stat -f "%Su:%Sg" "$r/volume1/downloads/nzbfast/downloads")
SPK_TEST_ROOT="$r" SYNOPKG_PKGVAR="$r/var" SPK_TEST_SKIP_PORTCHECK=1 \
    sh "$POSTINST" >/dev/null 2>&1
after=$(stat -c "%U:%G" "$r/volume1/downloads/nzbfast/downloads" 2>/dev/null \
        || stat -f "%Su:%Sg" "$r/volume1/downloads/nzbfast/downloads")
check "existing folder keeps its ownership" "$before" "$after"
if [ -f "$r/volume1/downloads/nzbfast/downloads/keep.txt" ]; then
    pass=$((pass + 1)); echo "  ok   existing contents untouched"
else
    fail=$((fail + 1)); echo "  FAIL existing contents disturbed" >&2
fi

# --- an unwritable share must fall back, not fail the install -----------
#
# This is the real DSM 7 behaviour, not a hypothetical: a package's
# internal user has no access to shared folders until an admin grants it,
# so /volume1/Downloads can be mode 777 and still be unwritable - and
# unlistable - from postinst. Install failed outright on a real NAS this
# way. Install must never depend on a shared folder.
r="$T/l"; mkdir -p "$r/volume1/downloads" "$r/var"
chmod 500 "$r/volume1/downloads"          # readable, not writable
SPK_TEST_ROOT="$r" SYNOPKG_PKGVAR="$r/var" SPK_TEST_SKIP_PORTCHECK=1 \
    sh "$POSTINST" >/dev/null 2>&1
rc=$?
chmod 700 "$r/volume1/downloads"          # so the cleanup trap can remove it
if [ "$rc" = 0 ]; then
    pass=$((pass + 1)); echo "  ok   unwritable share does not fail install"
else
    fail=$((fail + 1)); echo "  FAIL unwritable share failed install (rc=$rc)" >&2
fi
check "unwritable share falls back to package storage" \
    "$r/var/downloads" \
    "$(grep '^NZBFAST_OUT=' "$r/var/nzbfast.env" 2>/dev/null | cut -d= -f2-)"

# --- a reused folder we cannot write to must fall back too --------------
#
# A Container Manager migration leaves <share>/nzbfast/downloads owned by
# the container's PUID at 0755: searchable by the package account, not
# writable by it. [ -d ] alone accepts that, the install reports success,
# and then every job dies at create_dir_all and every watch import fails,
# with nothing in the GUI saying why. Existence is not permission.
r="$T/m"
mkdir -p "$r/volume1/downloads/nzbfast/downloads" \
         "$r/volume1/downloads/nzbfast/watch" "$r/var"
chmod 555 "$r/volume1/downloads/nzbfast/downloads"
chmod 555 "$r/volume1/downloads/nzbfast/watch"
SPK_TEST_ROOT="$r" SYNOPKG_PKGVAR="$r/var" SPK_TEST_SKIP_PORTCHECK=1 \
    sh "$POSTINST" >/dev/null 2>&1
chmod 755 "$r/volume1/downloads/nzbfast/downloads"   # for the cleanup trap
chmod 755 "$r/volume1/downloads/nzbfast/watch"
check "unwritable reused folder falls back to package storage" \
    "$r/var/downloads" \
    "$(grep '^NZBFAST_OUT=' "$r/var/nzbfast.env" 2>/dev/null | cut -d= -f2-)"
# The probe runs inside somebody's live download folder, so it has to
# leave it exactly as it found it, on the declining path as much as the
# accepting one.
check "probe leaves nothing behind" "" \
    "$(ls -A "$r/volume1/downloads/nzbfast/downloads" 2>/dev/null)"

# --- the port probe, against a stub and never against the host ----------
#
# postinst refuses to install over something already serving the port,
# because the likeliest something is nzbfast in Container Manager, and two
# instances on one download folder claim the same jobs. Every case above
# skips that probe, so this is where it is covered - with curl stubbed,
# so the result does not depend on what the machine running these tests
# happens to be serving on 6789.
r="$T/n"; mkdir -p "$r/volume1/downloads" "$r/var"
if PATH="$STUB_CURL:$PATH" STUB_CURL_RC=0 SPK_TEST_ROOT="$r" \
     SYNOPKG_PKGVAR="$r/var" sh "$POSTINST" >/dev/null 2>&1; then
    fail=$((fail + 1)); echo "  FAIL install proceeded over a served port" >&2
else
    pass=$((pass + 1)); echo "  ok   a served port refuses the install"
fi
check "a refused install writes no env file" "" \
    "$(cat "$r/var/nzbfast.env" 2>/dev/null)"

# 7 is curl's "could not connect", which is what a free port answers with.
r="$T/o"; mkdir -p "$r/volume1/downloads" "$r/var"
PATH="$STUB_CURL:$PATH" STUB_CURL_RC=7 SPK_TEST_ROOT="$r" \
    SYNOPKG_PKGVAR="$r/var" sh "$POSTINST" >/dev/null 2>&1 || true
check "a free port installs normally" \
    "$r/volume1/downloads/nzbfast/downloads" \
    "$(grep '^NZBFAST_OUT=' "$r/var/nzbfast.env" 2>/dev/null | cut -d= -f2-)"

# --- free space is a tie-break, not a requirement -----------------------
#
# The share search used to compare free space before it would take a share
# at all, so a df that reports nothing left every volume at zero free, no
# share selected, and the downloads in package storage where File Station
# cannot show them - the exact outcome the share search exists to avoid.
# df can report nothing for reasons that have nothing to do with the
# volume: a mount it cannot stat, or a device name long enough that
# busybox wraps the row and NR==2 is no longer the numbers.
r="$T/p"; mkdir -p "$r/volume1/downloads" "$r/var"
PATH="$STUB_DF:$PATH" SPK_TEST_ROOT="$r" SYNOPKG_PKGVAR="$r/var" \
    SPK_TEST_SKIP_PORTCHECK=1 sh "$POSTINST" >/dev/null 2>&1 || true
check "a share still wins when df says nothing" \
    "$r/volume1/downloads/nzbfast/downloads" \
    "$(grep '^NZBFAST_OUT=' "$r/var/nzbfast.env" 2>/dev/null | cut -d= -f2-)"

echo
echo "$pass passed, $fail failed"
[ "$fail" = 0 ]

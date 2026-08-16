#!/bin/zsh
# The release-notes gate must FAIL CLOSED, and the notes it validates
# must be the notes the release publishes.
#
# Both halves shipped broken. make-latest-json.sh wrapped its notes
# check in `if [ -f "$DIST/RELEASE_NOTES.md" ]`, so a run made before
# the notes were written - which is the order publish-release documented
# - signed a manifest with an empty `notes` field, printed nothing, and
# exited 0. And publish-release's own `gh release create` line passed
# `--notes "<highlights>"`, so the generated header (platform table,
# Unraid Community Applications row, machine-only asset warning) was
# built, validated, and then never reached GitHub. Nothing uploads
# RELEASE_NOTES.md as an asset either.
#
# Cases A-C drive the real script; case D pins the documented command,
# because a gate on a file nobody publishes is theatre.
# Run: packaging/tests/release-notes-gate.sh
set -uo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
SCRIPT=$ROOT/packaging/make-latest-json.sh
SKILL=$ROOT/.claude/skills/publish-release/SKILL.md
[ -x "$SCRIPT" ] || { echo "cannot find make-latest-json.sh"; exit 1; }

VERSION=$(sed -n 's/^version = "\(.*\)"/\1/p' "$ROOT/crates/nzbfast/Cargo.toml" | head -1)
[ -n "$VERSION" ] || { echo "cannot read the version from Cargo.toml"; exit 1; }

PASS=0
FAIL=0
ok()  { echo "  ok   - $1"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL - $1"; FAIL=$((FAIL + 1)); }

# The mac trio is waived rather than faked: the universal payload is fed
# to `lipo -thin`, and an empty file is not a mach-o. The linux/windows
# payloads are enough to get past the empty-payloads pre-flight.
ALLOW='macos-universal macos-arm64 macos-x64'

make_dist() {   # -> path of a dist dir with the non-mac payloads present
  local d
  d=$(mktemp -d)
  for plat in linux-x64 linux-arm64; do
    : > "$d/nzbfast-updater-$VERSION-$plat"
  done
  : > "$d/nzbfast-updater-$VERSION-windows-x64.exe"
  printf '%s' "$d"
}

# NZBFAST_UPDATE_SIGNING_KEY is deliberately unset in every case: the
# signing refusal is the marker for "got past the gate", and no case
# here may ever produce a signed manifest or touch update-serial.txt
# (the serial is only written after signing succeeds).
#
# The combined output goes to a FILE and the exit code is the function's
# own: `out=$(run_script ...)` would run the whole thing in a subshell
# and throw the exit code away, which is the shape that makes a red test
# look green.
LOG=$(mktemp)
run_script() {  # $1 = dist dir; rest = env assignments -> $LOG, returns rc
  local dist=$1; shift
  (cd "$ROOT" && env -u NZBFAST_UPDATE_SIGNING_KEY \
     ALLOW_MISSING="$ALLOW" "$@" "$SCRIPT" "$dist") > "$LOG" 2>&1
}

echo "release-notes gate"

# --- A: no notes file at all. This is the case that went green today. --
dist=$(make_dist)
run_script "$dist"; rc=$?
if [ "$rc" -eq 0 ]; then
  bad "A: missing RELEASE_NOTES.md exited 0 - the gate is fail-open again"
elif grep -q 'RELEASE_NOTES.md' "$LOG"; then
  ok "A: missing RELEASE_NOTES.md is fatal and names the file"
else
  # Matching the message, not just the exit code: without the fix the
  # run also fails, but later and for an unrelated reason (no signing
  # key), and with a key set it would exit 0 having signed unvalidated.
  bad "A: refused, but not for the notes: $(tail -3 "$LOG" | tr '\n' ' ')"
fi
rm -rf "$dist"

# --- B: notes present but a platform row deleted -----------------------
dist=$(make_dist)
body=$dist/body.md
{
  echo "One line of summary that ends in a full stop."
  echo
  echo "## What changed"
  echo
  echo "Nothing at all, this is a fixture."
} > "$body"
"$ROOT/packaging/make-release-notes.sh" "$VERSION" "$body" > "$dist/RELEASE_NOTES.md"
grep -v '^| Unraid |' "$dist/RELEASE_NOTES.md" > "$dist/notes.tmp"
mv "$dist/notes.tmp" "$dist/RELEASE_NOTES.md"
run_script "$dist"; rc=$?
if [ "$rc" -ne 0 ] && grep -qi 'unraid' "$LOG"; then
  ok "B: a notes file with the Unraid row deleted is refused by name"
else
  bad "B: dropped Unraid row was not caught (rc=$rc)"
fi
rm -rf "$dist"

# --- C: the waiver still works, loudly ---------------------------------
dist=$(make_dist)
run_script "$dist" SKIP_NOTES_CHECK=1; rc=$?
if [ "$rc" -eq 0 ]; then
  bad "C: SKIP_NOTES_CHECK=1 exited 0 with no signing key - impossible"
elif grep -q 'SKIP_NOTES_CHECK=1 - release notes NOT validated' "$LOG" \
   && grep -q 'NZBFAST_UPDATE_SIGNING_KEY' "$LOG"; then
  ok "C: SKIP_NOTES_CHECK=1 warns and gets past the gate (tester bundles)"
else
  bad "C: waiver did not warn or did not reach the signing step"
fi
rm -rf "$dist"

# --- D: the documented publish command uses the validated file ---------
create=$(grep -n -- '--notes' "$SKILL" | grep -v 'notes-file' | grep -- '--notes "')
if [ -n "$create" ]; then
  bad "D: publish-release still publishes a bare --notes string: $create"
else
  ok "D: no bare --notes \" string in publish-release"
fi
if grep -q -- '--notes-file <dist-dir>/RELEASE_NOTES.md' "$SKILL"; then
  ok "D: publish-release publishes --notes-file <dist-dir>/RELEASE_NOTES.md"
else
  bad "D: publish-release does not pass --notes-file RELEASE_NOTES.md"
fi

rm -f "$LOG"

echo
echo "passed: $PASS  failed: $FAIL"
[ "$FAIL" -eq 0 ]

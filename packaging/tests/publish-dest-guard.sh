#!/bin/zsh
# Guard tests for publish-public.sh's destructive-target check.
#
# The script replaces its destination's working tree with `rm -rf`. These
# tests pin the cases where it must refuse BEFORE deleting anything - the
# `publish-public.sh .` case erased untracked work in the private repo.
#
# Each case builds a throwaway "private repo" with a sentinel untracked
# file and asserts the sentinel survives. Run: packaging/tests/publish-dest-guard.sh
set -uo pipefail

SCRIPT=$(cd "$(dirname "$0")/.." && pwd)/publish-public.sh
[ -f "$SCRIPT" ] || { echo "cannot find publish-public.sh"; exit 1; }

PASS=0
FAIL=0
ok()   { echo "  ok   - $1"; PASS=$((PASS + 1)); }
bad()  { echo "  FAIL - $1"; FAIL=$((FAIL + 1)); }

# A fake private repo laid out like the real one: the script resolves
# ROOT as dirname($0)/.., so publish-public.sh must sit in packaging/.
make_fake_root() {
  local root=$1
  mkdir -p "$root/packaging"
  cp "$SCRIPT" "$root/packaging/publish-public.sh"
  chmod +x "$root/packaging/publish-public.sh"
  # TODO 63c made the pattern file a hard requirement: rather than report
  # a clean scan over an unscanned tree, the script REFUSES when it is
  # missing. That refusal is not the destructive-target guard, and it
  # happens on every run - so a fake root without this copy made the
  # allowed-destination case read as a guard failure, and made the three
  # refusal cases pass without the guard ever firing. Copy it (and
  # nothing else: PUBLIC_MANIFEST is read further down, past the point
  # these cases reach).
  cp "$(dirname "$SCRIPT")/private-patterns.txt" "$root/packaging/" || {
    echo "cannot build the fake root: packaging/private-patterns.txt is missing" >&2
    exit 1
  }
  git -C "$root" init -q -b main 2>/dev/null
  echo "PRECIOUS UNTRACKED WORK" > "$root/untracked-sentinel.txt"
}

# $4 is the guard's OWN refusal text, and asserting on it is the point:
# "some REFUSING line appeared" is satisfied by any prerequisite failure
# the script grows later. That is exactly what happened when the pattern
# file became mandatory - three cases went on reporting ok while the
# guard they exist to test was never reached.
run_case() {
  local desc=$1 dest=$2 expect_refuse=$3 want=${4:-}
  local tmp
  tmp=$(mktemp -d)
  local root="$tmp/private"
  make_fake_root "$root"
  # $dest is a template that may reference $root / $tmp
  local resolved
  resolved=$(eval echo "$dest")

  local out rc
  out=$(cd "$root" && "$root/packaging/publish-public.sh" "$resolved" 2>&1)
  rc=$?

  if [ "$expect_refuse" = "yes" ]; then
    if [ $rc -eq 0 ]; then
      bad "$desc: expected a refusal, got exit 0"
    elif ! echo "$out" | grep -qF "$want"; then
      bad "$desc: exited $rc, but not via the destructive-target guard.
         wanted: $want
         got:    $(echo "$out" | grep -m1 REFUSING || echo "(no REFUSING line) $(echo "$out" | head -1)")"
    elif [ ! -f "$root/untracked-sentinel.txt" ]; then
      bad "$desc: refused but the sentinel was already deleted"
    else
      ok "$desc"
    fi
  else
    # Not asserting a full successful publish here (that needs the whole
    # manifest + leak scan); only that the guard itself let it through.
    # It gets as far as `git rev-parse HEAD`, which fails in the fake
    # root because that repo has no commits - well past the guard, and
    # before anything is deleted.
    if echo "$out" | grep -q "REFUSING"; then
      bad "$desc: refused a legitimate destination: $(echo "$out" | grep -m1 REFUSING)"
    elif ! echo "$out" | grep -q "^publish target"; then
      bad "$desc: never reached the guard's verdict: $(echo "$out" | head -1)"
    else
      ok "$desc"
    fi
  fi
  rm -rf "$tmp"
}

echo "publish-public.sh destructive-target guard"
run_case "destination == private repo ('.')"        '$root'       yes \
  "REFUSING - destination is the private repo itself"
run_case "destination is the repo by absolute path" '$root'       yes \
  "REFUSING - destination is the private repo itself"
run_case "destination is the repo's parent"         '$tmp'        yes \
  "REFUSING - destination contains the private repo"
run_case "sibling public checkout is allowed"       '$tmp/public' no

# The populated-non-git case needs its directory to actually have content,
# so it gets built explicitly rather than through run_case (an empty
# destination is legitimate and must stay allowed).
tmp=$(mktemp -d)
root="$tmp/private"
make_fake_root "$root"
mkdir -p "$tmp/populated"
echo "someone else's files" > "$tmp/populated/important.txt"
out=$(cd "$root" && "$root/packaging/publish-public.sh" "$tmp/populated" 2>&1)
if echo "$out" | grep -qF "REFUSING - destination is not a git checkout but is not empty" \
   && [ -f "$tmp/populated/important.txt" ]; then
  ok "populated non-git destination keeps its files"
else
  bad "populated non-git destination was not protected: $(echo "$out" | grep -m1 REFUSING || echo "(no REFUSING line) $(echo "$out" | head -1)")"
fi
rm -rf "$tmp"

echo
echo "passed: $PASS  failed: $FAIL"
[ "$FAIL" -eq 0 ]

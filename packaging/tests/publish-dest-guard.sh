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
  git -C "$root" init -q -b main 2>/dev/null
  echo "PRECIOUS UNTRACKED WORK" > "$root/untracked-sentinel.txt"
}

run_case() {
  local desc=$1 dest=$2 expect_refuse=$3
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
    elif ! echo "$out" | grep -q "REFUSING"; then
      bad "$desc: exited $rc but not via the guard: $(echo "$out" | head -2)"
    elif [ ! -f "$root/untracked-sentinel.txt" ]; then
      bad "$desc: refused but the sentinel was already deleted"
    else
      ok "$desc"
    fi
  else
    # Not asserting a full successful publish here (that needs the whole
    # manifest + leak scan); only that the guard itself let it through.
    if echo "$out" | grep -q "REFUSING"; then
      bad "$desc: guard refused a legitimate destination: $(echo "$out" | grep REFUSING | head -1)"
    else
      ok "$desc"
    fi
  fi
  rm -rf "$tmp"
}

echo "publish-public.sh destructive-target guard"
run_case "destination == private repo ('.')"        '$root'            yes
run_case "destination is the repo by absolute path" '$root'            yes
run_case "destination is the repo's parent"         '$tmp'             yes
run_case "sibling public checkout is allowed"       '$tmp/public'      no

# The populated-non-git case needs its directory to actually have content,
# so it gets built explicitly rather than through run_case (an empty
# destination is legitimate and must stay allowed).
tmp=$(mktemp -d)
root="$tmp/private"
make_fake_root "$root"
mkdir -p "$tmp/populated"
echo "someone else's files" > "$tmp/populated/important.txt"
out=$(cd "$root" && "$root/packaging/publish-public.sh" "$tmp/populated" 2>&1)
if echo "$out" | grep -q "REFUSING" && [ -f "$tmp/populated/important.txt" ]; then
  ok "populated non-git destination keeps its files"
else
  bad "populated non-git destination was not protected"
fi
rm -rf "$tmp"

echo
echo "passed: $PASS  failed: $FAIL"
[ "$FAIL" -eq 0 ]

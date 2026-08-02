#!/bin/zsh
# Guard for the offline manual: what ships in an installer must be the
# page the daemon serves, not the template it serves it from.
#
# docs/MANUAL.html keeps a `__NZBFAST_UI_TOKENS__` marker so the palette
# lives in exactly one file (web/ui-tokens.html). Every packager used to
# copy that raw, so the manual on a Windows/macOS/Homebrew install
# carried the marker as visible body text and had no design tokens at
# all. Both halves are pinned here: the source still HAS the marker (the
# daemon path depends on it), and the generated copy has none.
#
# Run: packaging/tests/offline-manual.sh
set -uo pipefail

REPO=$(cd "$(dirname "$0")/../.." && pwd)
GEN="$REPO/packaging/make-offline-manual.sh"
SRC="$REPO/docs/MANUAL.html"

PASS=0
FAIL=0
ok()  { echo "  ok   - $1"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL - $1"; FAIL=$((FAIL + 1)); }

echo "offline manual"

[ -x "$GEN" ] && ok "make-offline-manual.sh is executable" \
              || bad "make-offline-manual.sh is missing or not executable"

if grep -q "__NZBFAST_UI_TOKENS__" "$SRC"; then
  ok "docs/MANUAL.html still carries the marker the daemon substitutes"
else
  bad "docs/MANUAL.html lost its marker - /manual would serve an unstyled page"
fi

OUT=$(mktemp -d)/MANUAL.html
if "$GEN" "$SRC" "$OUT" >/dev/null 2>&1; then
  ok "generator ran"
else
  bad "generator failed"
fi

if [ -f "$OUT" ] && ! grep -q "__NZBFAST_" "$OUT"; then
  ok "the generated manual carries no unsubstituted marker"
else
  bad "the generated manual still names a marker"
fi

if [ -f "$OUT" ] && grep -q -- "--bg" "$OUT"; then
  ok "the generated manual carries the design tokens"
else
  bad "the generated manual has no design tokens"
fi

# Every packager that stages a manual must go through the generator. A
# bare `cp docs/MANUAL.html` into a bundle is the bug this replaces.
STRAY=$(grep -rn "cp .*docs/MANUAL\.html" "$REPO/packaging" "$REPO/.github/workflows" 2>/dev/null \
        | grep -v "^$REPO/packaging/tests/" || true)
if [ -z "$STRAY" ]; then
  ok "no packager copies the raw manual"
else
  bad "a packager still copies the raw manual: $STRAY"
fi

rm -rf "$(dirname "$OUT")"
echo
echo "passed: $PASS  failed: $FAIL"
[ "$FAIL" -eq 0 ]

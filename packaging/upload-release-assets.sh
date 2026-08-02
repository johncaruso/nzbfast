#!/bin/zsh
# upload-release-assets.sh - the ONLY sanctioned way to put assets on a
# GitHub Release. TODO 63f: nothing uploads while unscanned.
#
#   packaging/upload-release-assets.sh vX.Y.Z <asset>...
#
# Refuses to upload any file that does not carry a scan stamp matching
# its CURRENT sha256. Stamps are written by scan-release-assets.sh into
# .scan-stamps next to each asset, only for assets it judged clean - a
# CANNOT INSPECT refusal writes nothing, and a rebuild changes the hash,
# so "scanned some earlier version of this file" does not count either.
#
# Why a separate gate instead of trusting the operator to run the scan
# first: cutting v1.0.13 the installer tripped CANNOT INSPECT and was
# uploaded anyway, with the refusal resolved only after publication. It
# happened to be clean. The order of operations must be structural, not
# a step in a checklist.
#
# The release must already exist (create it with --draft and NO asset
# arguments; publish after this succeeds). Uploads run under the anon
# account and refuse any other login.
set -euo pipefail
export LC_ALL=C

REPO=nzbfast/nzbfast
GH_CONFIG_DIR="${GH_CONFIG_DIR:-$HOME/.config/gh-nzbfast}"
export GH_CONFIG_DIR

if [ $# -lt 2 ]; then
  echo "usage: $0 vX.Y.Z <asset>..." >&2
  exit 1
fi
TAG=$1; shift
case "$TAG" in
  v[0-9]*) ;;
  *) echo "first argument must be the tag (vX.Y.Z), got: $TAG" >&2; exit 1 ;;
esac

LOGIN=$(gh api user --jq .login 2>/dev/null || true)
if [ "$LOGIN" != "nzbfast" ]; then
  echo "✗ REFUSING: gh login under $GH_CONFIG_DIR is '${LOGIN:-none}', not 'nzbfast'." >&2
  echo "    Public releases are cut by the release account only." >&2
  exit 1
fi

fail=0
for f in "$@"; do
  if [ ! -f "$f" ]; then
    echo "✗ no such file: $f" >&2; fail=1; continue
  fi
  dir=$(dirname "$f"); base=$(basename "$f")
  sum=$( { shasum -a 256 "$f" 2>/dev/null || sha256sum "$f"; } | awk '{print $1; exit}' )
  if [ ! -f "$dir/.scan-stamps" ] || ! grep -q "^$sum  $base\$" "$dir/.scan-stamps"; then
    echo "✗ UNSCANNED: $base has no scan stamp for its current contents." >&2
    echo "    Run: packaging/scan-release-assets.sh $f" >&2
    fail=1
  fi
done
if [ $fail -ne 0 ]; then
  echo "REFUSING to upload. Scan every asset first - and if the scan says" >&2
  echo "CANNOT INSPECT, fix the extractor, never upload around it." >&2
  exit 1
fi

echo "all $# asset(s) carry a current scan stamp - uploading to $TAG"
gh release upload "$TAG" --repo "$REPO" --clobber "$@"
echo "✓ uploaded $# asset(s) to $TAG"

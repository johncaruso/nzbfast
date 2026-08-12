#!/bin/sh
# bump-bucket.sh [version] [--push]
#
# Verify the generated Scoop manifest against a published release and (with
# --push) publish it to the public bucket repo, so
# `scoop bucket add nzbfast https://github.com/nzbfast/scoop-bucket` serves
# the new version. Run it AFTER `packaging/make-pkg-manifests.sh <version>`
# has regenerated packaging/scoop/nzbfast.json from the published release.
#
#   packaging/scoop/bump-bucket.sh              # verify the manifest only
#   packaging/scoop/bump-bucket.sh 1.0.23       # explicit version
#   packaging/scoop/bump-bucket.sh --push       # verify, then push the bucket
#
# Version defaults to crates/nzbfast/Cargo.toml.
#
# ANONYMITY: every git and gh operation against the public bucket runs under
# GH_CONFIG_DIR=~/.config/gh-nzbfast, the release account's login, and commits
# are authored `nzbfast <releases@nzbfast.com>`. gh's credential helper
# resolves against that directory, so `git push` needs it too. A push made
# with the personal login attributes a public commit to that account, and
# GitHub keeps the attribution even after a force-push.
set -eu

REPO=nzbfast/nzbfast
BUCKET_REPO=nzbfast/scoop-bucket
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
MANIFEST="$ROOT/packaging/scoop/nzbfast.json"
GH_CONFIG_DIR="${GH_CONFIG_DIR:-$HOME/.config/gh-nzbfast}"
export GH_CONFIG_DIR

PUSH=no
VERSION=
for a in "$@"; do
    case "$a" in
        --push) PUSH=yes ;;
        -*) echo "unknown option: $a" >&2; exit 2 ;;
        *) VERSION=$a ;;
    esac
done

if [ -z "$VERSION" ]; then
    VERSION=$(awk '/^version = "/ { gsub(/[^0-9.]/, "", $3); print $3; exit }' \
        "$ROOT/crates/nzbfast/Cargo.toml")
fi
case "$VERSION" in
    ''|*[!0-9.]*) echo "bad version: '$VERSION'" >&2; exit 2 ;;
esac

# The anonymous account, checked before anything reaches the network. A slip
# here is not recoverable: GitHub keeps the authorship forever.
who=$(gh api user --jq .login 2>/dev/null || echo "")
if [ "$who" != "nzbfast" ]; then
    echo "gh identity is '$who', expected 'nzbfast' (GH_CONFIG_DIR=$GH_CONFIG_DIR)" >&2
    exit 1
fi

# The manifest must already describe this version - it is GENERATED, and a
# stale one would serve the previous release under the new version's name.
mver=$(sed -n 's/.*"version": *"\([^"]*\)".*/\1/p' "$MANIFEST" | head -1)
if [ "$mver" != "$VERSION" ]; then
    echo "manifest says $mver, expected $VERSION - run packaging/make-pkg-manifests.sh $VERSION first" >&2
    exit 1
fi

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
BASE="https://github.com/$REPO/releases/download/v$VERSION"
ZIP="nzbfast-$VERSION-windows-x64.zip"

# Recompute from the bytes GitHub actually serves rather than trusting the
# manifest: its hash is what every user's install verifies against, so it has
# to describe the published artifact. This also fails loudly when the asset
# is missing or the release is still a draft.
if ! curl -fsSL --retry 3 -o "$WORK/$ZIP" "$BASE/$ZIP"; then
    echo "cannot fetch $BASE/$ZIP - is the release published?" >&2
    exit 1
fi
if command -v sha256sum >/dev/null 2>&1; then
    got=$(sha256sum "$WORK/$ZIP" | cut -d' ' -f1)
else
    got=$(shasum -a 256 "$WORK/$ZIP" | cut -d' ' -f1)
fi
want=$(sed -n 's/.*"hash": *"\([^"]*\)".*/\1/p' "$MANIFEST" | head -1)
if [ "$want" != "$got" ]; then
    echo "manifest hash $want but the published zip hashes $got" >&2
    exit 1
fi
echo "manifest hash matches the published $ZIP"

[ "$PUSH" = yes ] || { echo "not pushing (pass --push)"; exit 0; }

echo "publishing to $BUCKET_REPO ..."
# ANONYMITY, enforced structurally: a fresh clone has no local git config,
# so the machine-wide credential helper (osxkeychain, holding the personal
# login) would serve the push. Blank the helper list and pin gh's - gh
# resolves against GH_CONFIG_DIR, exported above, so the only credential
# this clone can ever use is the release account's. Same pattern as
# packaging/homebrew/bump-tap.sh, for the same v1.0.21 reason.
anon_git() {
    git -c credential.helper= \
        -c 'credential.helper=!gh auth git-credential' "$@"
}
anon_git clone -q "https://github.com/$BUCKET_REPO.git" "$WORK/bucket"
mkdir -p "$WORK/bucket/bucket"
cp "$MANIFEST" "$WORK/bucket/bucket/nzbfast.json"
# The bucket's README lives here too, so a change to it ships with the next
# release instead of drifting until someone notices.
cp "$ROOT/packaging/scoop/bucket-README.md" "$WORK/bucket/README.md"

cd "$WORK/bucket"
if git diff --quiet -- . && [ -z "$(git status --porcelain)" ]; then
    echo "bucket already at $VERSION, nothing to push"
    exit 0
fi
git add -A
git -c user.name=nzbfast -c user.email=releases@nzbfast.com \
    commit -qm "nzbfast $VERSION"
anon_git push -q origin HEAD:main
echo "pushed $VERSION to $BUCKET_REPO"

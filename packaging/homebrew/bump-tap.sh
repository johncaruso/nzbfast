#!/bin/sh
# bump-tap.sh [version] [--push]
#
# Point the Homebrew formula at a published release and (with --push) publish
# it to the public tap repo, so `brew install nzbfast/tap/nzbfast` serves the
# new version. Run it AFTER the GitHub Release exists, because it reads the
# three archives back off the release page.
#
#   packaging/homebrew/bump-tap.sh              # rewrite the formula only
#   packaging/homebrew/bump-tap.sh 1.0.11        # explicit version
#   packaging/homebrew/bump-tap.sh --push        # rewrite, then push the tap
#
# Version defaults to crates/nzbfast/Cargo.toml.
#
# ANONYMITY: every git and gh operation against the public tap runs under
# GH_CONFIG_DIR=~/.config/gh-nzbfast, the release account's login, and commits
# are authored `nzbfast <releases@nzbfast.com>`. gh's credential helper
# resolves against that directory, so `git push` needs it too. A push made
# with the personal login attributes a public commit to that account, and
# GitHub keeps the attribution even after a force-push.
set -eu

REPO=nzbfast/nzbfast
TAP_REPO=nzbfast/homebrew-tap
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
FORMULA="$ROOT/packaging/homebrew/nzbfast.rb"
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

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
BASE="https://github.com/$REPO/releases/download/v$VERSION"

# Recompute from the bytes GitHub actually serves rather than trusting the
# local dist directory: the formula's sha256 is what every user's install
# verifies against, so it has to describe the published artifact. This also
# fails loudly when an asset is missing or the release is still a draft.
sha_of() {
    asset=$1
    if ! curl -fsSL --retry 3 -o "$WORK/$asset" "$BASE/$asset"; then
        echo "cannot fetch $BASE/$asset - is the release published?" >&2
        exit 1
    fi
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$WORK/$asset" | cut -d' ' -f1
    else
        shasum -a 256 "$WORK/$asset" | cut -d' ' -f1
    fi
}

MAC_ASSET="nzbfast-$VERSION-macos-universal.zip"
X64_ASSET="nzbfast-$VERSION-linux-x64.tar.gz"
ARM_ASSET="nzbfast-$VERSION-linux-arm64.tar.gz"

echo "fetching release assets for v$VERSION ..."
MAC_SHA=$(sha_of "$MAC_ASSET")
X64_SHA=$(sha_of "$X64_ASSET")
ARM_SHA=$(sha_of "$ARM_ASSET")

# Cross-check against the release's own SHA256SUMS when it is attached. The
# download above already proves what GitHub serves; this catches the other
# direction, an asset that was rebuilt after SHA256SUMS was generated.
if curl -fsSL -o "$WORK/SHA256SUMS" "$BASE/SHA256SUMS" 2>/dev/null; then
    for pair in "$MAC_ASSET:$MAC_SHA" "$X64_ASSET:$X64_SHA" "$ARM_ASSET:$ARM_SHA"; do
        asset=${pair%:*}; got=${pair#*:}
        want=$(awk -v a="$asset" '$2 == a { print $1 }' "$WORK/SHA256SUMS")
        if [ -n "$want" ] && [ "$want" != "$got" ]; then
            echo "$asset: SHA256SUMS says $want but the download hashes $got" >&2
            exit 1
        fi
    done
    echo "cross-checked against SHA256SUMS"
else
    echo "note: no SHA256SUMS on the release, skipped the cross-check" >&2
fi

# Rewrite in place. The formula carries no `version` stanza (Homebrew derives
# it from the URL, and declaring it too fails the audit), so the version lives
# in the URL lines: the tag, the filename, and on Linux the `#/` fragment that
# stops the parser reading "64" out of "-x64". Rewriting every dotted numeral
# on a release-download line covers all three without having to know which
# version it is replacing.
#
# The sha256 lines are identified by the URL line above them rather than by
# their own contents, which change every release.
awk -v ver="$VERSION" -v mac="$MAC_SHA" -v x64="$X64_SHA" -v arm="$ARM_SHA" '
    /releases\/download\// {
        gsub(/[0-9]+\.[0-9]+\.[0-9]+/, ver)
        print
        if ($0 ~ /macos-universal/)   want = mac
        else if ($0 ~ /linux-x64/)    want = x64
        else if ($0 ~ /linux-arm64/)  want = arm
        next
    }
    /^ *sha256 "/ && want != "" {
        sub(/"[^"]*"/, "\"" want "\""); print; want = ""; next
    }
    { print }
' "$FORMULA" > "$FORMULA.tmp" && mv "$FORMULA.tmp" "$FORMULA"

echo "formula now:"
grep -n 'releases/download/\|sha256 "' "$FORMULA"

# Guard against an awk pass that matched nothing: a formula still carrying a
# previous release's hashes would install the wrong bytes or fail every user's
# checksum, and it looks fine to a casual read.
for want in "$MAC_SHA" "$X64_SHA" "$ARM_SHA"; do
    grep -q "\"$want\"" "$FORMULA" || { echo "sha $want did not land in the formula" >&2; exit 1; }
done
# Same for the URLs: a stale one still resolves (old releases stay up), so it
# would install the PREVIOUS version under the new version's name.
stale=$(grep -c "releases/download/" "$FORMULA")
fresh=$(grep -c "releases/download/v$VERSION/" "$FORMULA")
if [ "$stale" -ne "$fresh" ]; then
    echo "only $fresh of $stale download URLs point at v$VERSION" >&2
    exit 1
fi

[ "$PUSH" = yes ] || { echo "not pushing (pass --push)"; exit 0; }

echo "publishing to $TAP_REPO ..."
# ANONYMITY, enforced structurally: a fresh clone has no local git config,
# so the machine-wide credential helper (osxkeychain, holding the personal
# login) would serve the push. Blank the helper list and pin gh's - gh
# resolves against GH_CONFIG_DIR, exported above, so the only credential
# this clone can ever use is the release account's. Found the hard way on
# v1.0.21: the bare push here went out under the personal login and was
# 403'd by the tap repo's permissions - the last line of defence, not one
# to lean on.
anon_git() {
    git -c credential.helper= \
        -c 'credential.helper=!gh auth git-credential' "$@"
}
anon_git clone -q "https://github.com/$TAP_REPO.git" "$WORK/tap"
mkdir -p "$WORK/tap/Formula"
cp "$FORMULA" "$WORK/tap/Formula/nzbfast.rb"
# The tap's README and CI live here too, so a change to either ships with the
# next release instead of drifting until someone notices.
cp "$ROOT/packaging/homebrew/tap/README.md" "$WORK/tap/README.md"
mkdir -p "$WORK/tap/.github/workflows"
cp "$ROOT/packaging/homebrew/tap/ci.yml" "$WORK/tap/.github/workflows/ci.yml"

cd "$WORK/tap"
if git diff --quiet -- . && [ -z "$(git status --porcelain)" ]; then
    echo "tap already at $VERSION, nothing to push"
    exit 0
fi
git add -A
git -c user.name=nzbfast -c user.email=releases@nzbfast.com \
    commit -qm "nzbfast $VERSION"
anon_git push -q origin HEAD:main
echo "pushed $VERSION to $TAP_REPO"

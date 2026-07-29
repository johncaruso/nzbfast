#!/bin/sh
# Build + push the nzbfast image (linux/amd64 + linux/arm64) from the
# static musl binaries already attached to the GitHub Release - no qemu
# compile, the image gets the exact released bits.
#
# Pushes to TWO registries in a single buildx build (no rebuild):
#   - ghcr.io/nzbfast/nzbfast   (always)
#   - docker.io/nzbfast/nzbfast (only when DOCKERHUB_TOKEN is set)
# Docker Hub is what makes nzbfast searchable/one-click in Synology
# Container Manager, Unraid Community Apps, etc. - ghcr images do not
# show up in those GUIs. Publish to both so every install path works.
#
# Run on any Linux box with docker + buildx (Ubuntu: apt install
# docker.io docker-buildx; add qemu-user-static binfmt-support to smoke-
# test the arm64 image). Auth:
#   - GHCR_TOKEN: a token for the ANONYMOUS `nzbfast` GitHub account with
#     write:packages - never a personal token.
#   - DOCKERHUB_TOKEN (optional): an access token for the Docker Hub
#     `nzbfast` account/org with Read/Write. DOCKERHUB_USER defaults to
#     `nzbfast`. Omit both to push ghcr only.
#
#   GHCR_TOKEN=$(GH_CONFIG_DIR=~/.config/gh-nzbfast gh auth token) \
#   DOCKERHUB_TOKEN=dckr_pat_xxx \
#     ./push-image.sh 1.0.0
#
# Sanity rules:
#   - docker inspect of the pushed image must contain no personal names,
#     paths or hostnames - only nzbfast.com / github.com/nzbfast.
#   - The ghcr package must end up PUBLIC and linked to nzbfast/nzbfast
#     (the org.opencontainers.image.source label links it; visibility is
#     flipped in the package settings UI on first publish). The Docker
#     Hub repo is public from creation (set Visibility: Public when the
#     `nzbfast/nzbfast` repo is first made).
set -eu

VER="${1:?usage: GHCR_TOKEN=... push-image.sh <version>}"
: "${GHCR_TOKEN:?set GHCR_TOKEN to the nzbfast write:packages token}"
IMAGE="ghcr.io/nzbfast/nzbfast"
HUB="docker.io/nzbfast/nzbfast"
DOCKERHUB_USER="${DOCKERHUB_USER:-nzbfast}"
REL="https://github.com/nzbfast/nzbfast/releases/download/v${VER}"

# Checksum verify, portable across Linux (sha256sum) and macOS (shasum) -
# push-image.sh runs on either the Linux build box or a dev Mac.
if command -v sha256sum >/dev/null 2>&1; then SHA256C="sha256sum -c -"
else SHA256C="shasum -a 256 -c -"; fi

DIR="$(mktemp -d)"
trap 'rm -rf "$DIR"' EXIT
SELF="$(cd "$(dirname "$0")" && pwd)"

# Fetch + checksum the released linux binaries.
for a in linux-x64 linux-arm64; do
    curl -fsSL -o "$DIR/nzbfast-$VER-$a.tar.gz" "$REL/nzbfast-$VER-$a.tar.gz"
done
curl -fsSL -o "$DIR/SHA256SUMS.txt" "$REL/SHA256SUMS.txt"
# Each archive is verified against its OWN line, and the line has to
# exist. One `grep | sha256sum -c` over both names was not that check: it
# only required the pipeline to succeed, so a SHA256SUMS.txt carrying the
# x64 entry alone passed - and the arm64 archive nobody had verified was
# still unpacked into the image, pushed, and then attested. An
# attestation over an unverified layer is worse than no attestation.
for a in linux-x64 linux-arm64; do
    art="nzbfast-$VER-$a.tar.gz"
    n=$(grep -c "[ *]$art\$" "$DIR/SHA256SUMS.txt" || true)
    if [ "$n" != "1" ]; then
        echo "✗ SHA256SUMS.txt has $n checksum lines for $art (need exactly 1)" >&2
        exit 1
    fi
    (cd "$DIR" && grep "[ *]$art\$" SHA256SUMS.txt | $SHA256C)
done

# Context: bin/<TARGETARCH>/nzbfast + entrypoint + Dockerfile.release.
mkdir -p "$DIR/ctx/bin/amd64" "$DIR/ctx/bin/arm64"
tar xzf "$DIR/nzbfast-$VER-linux-x64.tar.gz"   -C "$DIR" "nzbfast-$VER-linux-x64/nzbfast"
tar xzf "$DIR/nzbfast-$VER-linux-arm64.tar.gz" -C "$DIR" "nzbfast-$VER-linux-arm64/nzbfast"
mv "$DIR/nzbfast-$VER-linux-x64/nzbfast"   "$DIR/ctx/bin/amd64/nzbfast"
mv "$DIR/nzbfast-$VER-linux-arm64/nzbfast" "$DIR/ctx/bin/arm64/nzbfast"
cp "$SELF/Dockerfile.release" "$DIR/ctx/Dockerfile"
cp "$SELF/../docker-entrypoint.sh" "$DIR/ctx/docker-entrypoint.sh"

echo "$GHCR_TOKEN" | docker login ghcr.io -u nzbfast --password-stdin

# One buildx build, one or two registries. Tags accumulate: ghcr always,
# Docker Hub too when a token is supplied.
TAGS="-t $IMAGE:$VER -t $IMAGE:latest"
if [ -n "${DOCKERHUB_TOKEN:-}" ]; then
    echo "$DOCKERHUB_TOKEN" | docker login docker.io -u "$DOCKERHUB_USER" --password-stdin
    TAGS="$TAGS -t $HUB:$VER -t $HUB:latest"
    echo "will also push $HUB:$VER + :latest"
else
    echo "DOCKERHUB_TOKEN not set - pushing ghcr only (Docker Hub skipped)"
fi

# docker-container driver: the default docker driver can't push a
# multi-arch manifest list.
docker buildx inspect nzbfast-builder >/dev/null 2>&1 \
    || docker buildx create --name nzbfast-builder --driver docker-container
# shellcheck disable=SC2086  # $TAGS is intentionally word-split
docker buildx build --builder nzbfast-builder \
    --platform linux/amd64,linux/arm64 \
    --provenance=false --sbom=false \
    --build-arg "VERSION=$VER" \
    $TAGS \
    --push "$DIR/ctx"

echo "pushed $IMAGE:$VER + :latest"
[ -n "${DOCKERHUB_TOKEN:-}" ] && echo "pushed $HUB:$VER + :latest"
echo "next (first publish of each registry only):"
echo "  ghcr:      package settings → visibility PUBLIC + link nzbfast/nzbfast"
echo "             https://github.com/users/nzbfast/packages/container/nzbfast/settings"
echo "  dockerhub: hub.docker.com → nzbfast/nzbfast → Settings → Visibility: Public"

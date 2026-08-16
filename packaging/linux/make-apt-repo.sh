#!/bin/sh
# Build and sign the flat APT repository that Debian and Ubuntu users
# add with `sources.list.d`, so `apt upgrade` carries nzbfast forward.
#
# The repository is a directory tree, published to the `gh-pages` branch
# of the public repo under `apt/`. It holds the .deb files themselves -
# a flat repository's `Filename:` is relative to its own base URL, so
# the packages cannot live on the releases page and be indexed here.
#
# THE SIGNING KEY IS NOT THE UPDATE-MANIFEST KEY. That one is ed25519,
# it signs latest.json, and its compromise would let somebody publish a
# fake update notification. This one is an OpenPGP key that signs the
# repository index, and its compromise would let somebody publish a
# package that apt installs as root. They are separate keys with
# separate blast radii. The private half belongs in the release
# maintainer's own GnuPG keyring, never in this repository and never on
# a build server - the same rule the update-manifest key follows.
#
# Run (release machine, the private key in the local keyring):
#   packaging/linux/make-apt-repo.sh --add dist/nzbfast_*.deb \
#       --key apt@nzbfast.com --repo build/apt
#
# Generate the signing key once, on the release machine and nowhere else:
#   packaging/linux/make-apt-repo.sh --keygen
set -eu

cd "$(dirname "$0")/../.."                      # repo root
ROOT=$(pwd)
PKGDIR=packaging/linux

REPO="$ROOT/$PKGDIR/apt-out"
KEY=""
KEEP=3
ADD=""
KEYGEN=0
BASE_URL="https://nzbfast.github.io/nzbfast/apt"
KEYRING_NAME="nzbfast-archive-keyring"

usage() { sed -n '2,24p' "$0"; }

while [ $# -gt 0 ]; do
    case "$1" in
        --repo)   REPO=$2; shift 2 ;;
        --key)    KEY=$2; shift 2 ;;
        # Keep the newest N versions of each package+architecture. The
        # repository carries its own .deb files, so without a cap the
        # gh-pages branch grows by ~16 MB every release and never
        # shrinks - git keeps the blobs even after a later prune.
        --keep)   KEEP=$2; shift 2 ;;
        --base-url) BASE_URL=$2; shift 2 ;;
        --keygen) KEYGEN=1; shift ;;
        --add)    shift
                  while [ $# -gt 0 ] && [ "${1#--}" = "$1" ]; do
                      ADD="$ADD $1"; shift
                  done ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 1 ;;
    esac
done

command -v gpg >/dev/null 2>&1 || {
    echo "make-apt-repo: gpg is not installed" >&2; exit 1; }

# ------------------------------------------------------------- key generation
# A dedicated key, generated once, interactively, by the person who will
# hold it. Nothing here writes the private half anywhere but the local
# GnuPG keyring, and nothing here can export it.
if [ "$KEYGEN" = "1" ]; then
    cat <<'EOF'
Generating a DEDICATED OpenPGP key for the nzbfast APT repository.

  - This is NOT the update-manifest key. Do not reuse that one.
  - RSA 4096, no expiry date: an expired repository key makes
    `apt update` fail for everyone who ever added the repository, and
    they cannot fix it without re-running the install instructions.
  - Give it a passphrase. The private half stays in your own keyring.

EOF
    printf 'Continue? [y/N] '
    read -r answer
    case "$answer" in y|Y|yes|YES) ;; *) echo "aborted"; exit 1 ;; esac
    # No --batch and no --passphrase flag on purpose: that makes gpg
    # prompt for the passphrase itself, through pinentry, so the
    # passphrase is never an argument, an environment variable, or a
    # line in anybody's shell history.
    gpg --quick-generate-key \
        "nzbfast repository signing key <apt@nzbfast.com>" rsa4096 sign never
    echo
    echo "Done. Publish this fingerprint with the install instructions:"
    gpg --list-keys --with-colons "apt@nzbfast.com" \
        | awk -F: '/^fpr:/ { print "  " $10; exit }'
    exit 0
fi

[ -n "$KEY" ] || { echo "make-apt-repo: --key is required (see --help)" >&2; exit 1; }

# Refuse early and loudly if the key cannot sign, rather than building a
# whole repository and failing on the last step.
gpg --list-secret-keys "$KEY" >/dev/null 2>&1 || {
    echo "make-apt-repo: no secret key matching '$KEY' in this keyring" >&2
    exit 1; }

# ------------------------------------------------------------------- the pool
mkdir -p "$REPO/pool"
for deb in $ADD; do
    [ -f "$deb" ] || { echo "make-apt-repo: no such file: $deb" >&2; exit 1; }
    case "$deb" in
        *.deb) ;;
        *) echo "make-apt-repo: not a .deb: $deb" >&2; exit 1 ;;
    esac
    cp -f "$deb" "$REPO/pool/$(basename "$deb")"
    echo "added $(basename "$deb")"
done

# ------------------------------------------------------------------ the index
"$PKGDIR/apt-index.py" --repo "$REPO" --keep "$KEEP"

# ---------------------------------------------------------------- the signature
# Both forms, because both are still fetched in the wild: apt asks for
# InRelease (inline signature) first and falls back to Release +
# Release.gpg on repositories that predate it. Publishing only InRelease
# works with current apt and breaks older clients for no gain.
rm -f "$REPO/InRelease" "$REPO/Release.gpg"
gpg --default-key "$KEY" --armor --detach-sign \
    --output "$REPO/Release.gpg" "$REPO/Release"
gpg --default-key "$KEY" --clearsign \
    --output "$REPO/InRelease" "$REPO/Release"

# The public half, armored, at a stable path inside the repository. This
# is what the install instructions pipe through `gpg --dearmor`, so it
# has to be served from the same origin as the packages.
gpg --armor --export "$KEY" > "$REPO/$KEYRING_NAME.asc"
[ -s "$REPO/$KEYRING_NAME.asc" ] || {
    echo "make-apt-repo: exporting the public key produced nothing" >&2; exit 1; }

FPR=$(gpg --list-keys --with-colons "$KEY" | awk -F: '/^fpr:/ { print $10; exit }')

# --------------------------------------------------------------- verification
# Verify what was just written, with gpg alone, using the exported
# public key and nothing else in the keyring. This is the check that a
# user's apt will run, and doing it here means a broken signature is
# found on the release machine rather than by the first person to run
# `apt update`.
VERIFY=$(mktemp -d)
trap 'rm -rf "$VERIFY"' EXIT
gpg --quiet --homedir "$VERIFY" --import "$REPO/$KEYRING_NAME.asc" 2>/dev/null
gpg --quiet --homedir "$VERIFY" --trust-model always \
    --verify "$REPO/Release.gpg" "$REPO/Release" 2>/dev/null || {
    echo "make-apt-repo: the detached signature does not verify" >&2; exit 1; }
gpg --quiet --homedir "$VERIFY" --trust-model always \
    --verify "$REPO/InRelease" 2>/dev/null || {
    echo "make-apt-repo: InRelease does not verify" >&2; exit 1; }

cat <<EOF

Signed with $FPR
Repository: $REPO

Publish the contents of that directory to gh-pages at apt/, then the
install line is:

  curl -fsSL $BASE_URL/$KEYRING_NAME.asc \\
    | sudo gpg --dearmor -o /usr/share/keyrings/$KEYRING_NAME.gpg
  echo "deb [signed-by=/usr/share/keyrings/$KEYRING_NAME.gpg] $BASE_URL ./" \\
    | sudo tee /etc/apt/sources.list.d/nzbfast.list
EOF

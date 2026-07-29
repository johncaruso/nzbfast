#!/bin/sh
# The Synology compose file exists twice on purpose: packaging/synology/
# is the copy that ships in the repo, and website/ holds the one the site
# actually serves (gh-pages can only serve what is under website/, and a
# same-origin file is what makes the download link one click rather than
# a raw text page on github.com). They must not drift.
#
# Run: packaging/tests/synology-compose-parity.sh
#
# The website/ tree is private and absent from the public repo export, so
# a missing copy there is a skip, not a failure.
set -eu
cd "$(dirname "$0")/../.."

SRC=packaging/synology/docker-compose.yml
WEB=website/nzbfast-synology.yml

[ -f "$SRC" ] || { echo "FAIL: $SRC is missing"; exit 1; }

if [ ! -f "$WEB" ]; then
    echo "SKIP: $WEB not present (public export has no website/)"
    exit 0
fi

if diff -u "$SRC" "$WEB"; then
    echo "PASS: $WEB matches $SRC"
else
    echo
    echo "FAIL: the two copies have drifted. To resync:"
    echo "  cp $SRC $WEB"
    exit 1
fi

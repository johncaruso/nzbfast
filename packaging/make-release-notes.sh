#!/bin/sh
# make-release-notes.sh <version> [body-file] > RELEASE_NOTES.md
#
# Emit a release-notes file whose HEADER is generated, never hand-typed:
# the summary line and the human-written sections come from <body-file>,
# the "Which file do I download?" table comes from
# packaging/release-notes-header.md with @VERSION@ substituted.
#
# Why generated. The table was retyped for every release, and 1.1.2
# shipped with Unraid folded into a "QNAP / Unraid: the Docker image, or
# the Linux tar.gz" row - the hard path for the one platform that has a
# one-click install. The CA listing has existed since 30 Jul and no
# release had ever mentioned it. A hand-copied table also carries the
# previous version's filenames until someone notices, which is a dead
# download link on the page people land on.
#
# Body-file layout: the FIRST line is the one-sentence summary (it also
# becomes the manifest's `notes` field, via make-latest-json.sh), then a
# blank line, then the sections. The header is inserted between them.
# With no body-file, the header alone goes to stdout, which is what you
# want when checking what the table currently renders as.
set -eu

VERSION=${1:?usage: make-release-notes.sh <version> [body-file]}
case "$VERSION" in
    *[!0-9.]*|.*|*.) echo "version must be dotted numerals, e.g. 1.1.3" >&2; exit 1 ;;
esac
ROOT=$(cd "$(dirname "$0")/.." && pwd)
HEADER=$ROOT/packaging/release-notes-header.md
[ -f "$HEADER" ] || { echo "missing $HEADER" >&2; exit 1; }

render_header() { sed "s/@VERSION@/$VERSION/g" "$HEADER"; }

BODY=${2:-}
if [ -z "$BODY" ]; then
    render_header
    exit 0
fi
[ -f "$BODY" ] || { echo "no such body file: $BODY" >&2; exit 1; }

# Summary line, then header, then everything after the summary. A body
# that already carries a download table is a mistake worth naming rather
# than silently duplicating.
if grep -q '^## Which file do I download' "$BODY"; then
    echo "✗ $BODY already contains a download table - the header is generated." >&2
    echo "    Keep only the summary line and the written sections in the body." >&2
    exit 1
fi
head -1 "$BODY"
echo
render_header
echo
tail -n +2 "$BODY" | sed '/./,$!d'

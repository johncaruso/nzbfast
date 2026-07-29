#!/bin/sh
# Generate the Package Center feed that turns "download a file and use
# Manual Install" into "add one URL, then click Install" - and, more
# usefully, makes DSM offer the upgrade itself on every later release.
#
#   packaging/synology/make-package-feed.sh <version> <path-to-.spk> [outdir]
#
# Writes <outdir>/packages.json. The .spk is NOT copied: `link` points at
# the GitHub Release asset, so the feed stays a few kB and the release
# remains the single place binaries live. That also keeps a 19 MB package
# out of the gh-pages history, which nothing can ever remove once pushed.
#
# The schema is what Package Center actually consumes, read off a live
# response from an existing community repository rather than from docs:
#   {"packages": [ {package, version, dname, desc, link, md5, size, ...} ]}
#
# Two things worth knowing before changing how this is served:
#   - The feed protocol filters by architecture SERVER-side. A response
#     carries no arch field for the client to filter on, and a real
#     repository returns a different package list per arch. Our package is
#     noarch and picks its binary at install time precisely so one static
#     response is correct for every model.
#   - GitHub Pages answers GET and HEAD only. If Package Center turns out
#     to POST, this exact JSON still works but needs a host that accepts
#     POST; only the transport changes, not the content.
set -eu

VER="${1:?usage: make-package-feed.sh <version> <spk> [outdir]}"
SPK="${2:?usage: make-package-feed.sh <version> <spk> [outdir]}"
OUTDIR="${3:-dist}"
[ -f "$SPK" ] || { echo "✗ no such .spk: $SPK" >&2; exit 1; }

BASE="https://github.com/nzbfast/nzbfast/releases/download/v${VER}"
SITE="https://nzbfast.github.io/nzbfast"

if command -v md5sum >/dev/null 2>&1; then
    MD5=$(md5sum "$SPK" | awk '{print $1}')
else
    MD5=$(md5 -q "$SPK")
fi
# stat's flags differ between GNU and BSD; wc -c is the portable answer.
SIZE=$(wc -c < "$SPK" | tr -d ' ')

mkdir -p "$OUTDIR"
cat > "$OUTDIR/packages.json" <<EOF
{
  "packages": [
    {
      "package": "nzbfast",
      "version": "$VER",
      "dname": "nzbfast",
      "desc": "Fast Usenet (NZB) downloader with a web dashboard and a SABnzbd- and NZBGet-compatible API. Sonarr, Radarr, nzb360 and LunaSea work out of the box. PAR2 repair and RAR extraction are native, so there is no par2 or unrar to install.",
      "link": "$BASE/nzbfast-$VER-noarch.spk",
      "md5": "$MD5",
      "size": $SIZE,
      "maintainer": "nzbfast",
      "maintainer_url": "https://github.com/nzbfast/nzbfast",
      "distributor": "nzbfast",
      "distributor_url": "https://github.com/nzbfast/nzbfast",
      "support_url": "https://github.com/nzbfast/nzbfast/issues",
      "thumbnail": ["$SITE/syno/PACKAGE_ICON_256.PNG"],
      "changelog": "https://github.com/nzbfast/nzbfast/releases/tag/v$VER",
      "qinst": true,
      "qstart": true,
      "qupgrade": true,
      "startable": true,
      "deppkgs": null,
      "conflictpkgs": null
    }
  ]
}
EOF

python3 -m json.tool "$OUTDIR/packages.json" > /dev/null \
    || { echo "✗ generated feed is not valid JSON" >&2; exit 1; }

echo "wrote $OUTDIR/packages.json"
echo "  version $VER, md5 $MD5, size $SIZE"
echo "  link    $BASE/nzbfast-$VER-noarch.spk"
echo
echo "The link must resolve before the feed goes live, or Package Center"
echo "will list nzbfast and then fail to install it. Check with:"
echo "  curl -fsIL \"$BASE/nzbfast-$VER-noarch.spk\" | head -1"

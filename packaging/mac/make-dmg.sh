#!/bin/bash
# Build the styled nzbfast DMG (packaging/INSTALLER-SPEC.md, chip A).
#
#   ./make-dmg.sh                 uses macapp/build/NzbFast.app (builds it
#                                 via macapp/make-app.sh if missing)
#   APP=/path/to/NzbFast.app ./make-dmg.sh
#
# Output: packaging/mac/build/nzbfast-<version>-macos.dmg
# Needs once: pip3 install --user ds-store mac-alias  (Finder layout is
# written headless - no AppleScript/Automation permission required).
set -euo pipefail
cd "$(dirname "$0")"
REPO="$(cd ../.. && pwd)"

VERSION=$(grep '^version' "$REPO/crates/nzbfast/Cargo.toml" | head -1 | cut -d'"' -f2)
VOL="nzbfast $VERSION"
OUT="build/nzbfast-$VERSION-macos.dmg"

APP="${APP:-$REPO/macapp/build/NzbFast.app}"
if [ ! -d "$APP" ]; then
    echo "== NzbFast.app missing - building it"
    "$REPO/macapp/make-app.sh"
fi
[ -d "$APP" ] || { echo "no app at $APP"; exit 1; }

mkdir -p build
STAGE=$(mktemp -d)/dmg
RW=$(mktemp -d)/rw.dmg
trap 'hdiutil detach "/Volumes/$VOL" -quiet 2>/dev/null || true' EXIT

# --- stage -------------------------------------------------------------
mkdir -p "$STAGE/.background" "$STAGE/.extras"
cp -R "$APP" "$STAGE/NzbFast.app"
ln -s /Applications "$STAGE/Applications"
# Visible beside the app: a plain-HTML walkthrough of the unsigned first
# launch (opens in a browser with no Gatekeeper friction).
cp how-to-install.html "$STAGE/How to install.html"
# Substituted, not copied raw: docs/MANUAL.html carries the shared
# design tokens as a placeholder the DAEMON fills in when it serves
# /manual. A raw copy shows the marker as body text and styles itself
# against variables that were never declared.
"$REPO/packaging/make-offline-manual.sh" "$REPO/docs/MANUAL.html" "$STAGE/.extras/MANUAL.html"
cp "$REPO/LICENSE" "$STAGE/.extras/LICENSE"
cp "$REPO/COPYRIGHT.md" "$STAGE/.extras/COPYRIGHT.md"
cp "$APP/Contents/Resources/NzbFast.icns" "$STAGE/.VolumeIcon.icns"

# Background: render the committed SVG at 2x, mark it 144 dpi so Finder
# draws it at 660x660 points, crisp on retina (the 660x400 window shows
# the styled top; the square canvas avoids qlmanage's white padding).
qlmanage -t -s 1320 -o "$STAGE/.background" dmg-background.svg >/dev/null
mv "$STAGE/.background/dmg-background.svg.png" "$STAGE/.background/background.png"
sips -s dpiWidth 144 -s dpiHeight 144 "$STAGE/.background/background.png" >/dev/null

# --- RW image → layout → compress -------------------------------------
hdiutil create -srcfolder "$STAGE" -volname "$VOL" -fs HFS+ \
    -format UDRW -ov "$RW" >/dev/null
hdiutil attach "$RW" -noautoopen >/dev/null
python3 make-dmg-dsstore.py "/Volumes/$VOL"
SetFile -a C "/Volumes/$VOL"          # honor .VolumeIcon.icns
sync
hdiutil detach "/Volumes/$VOL" >/dev/null
trap - EXIT
rm -f "$OUT"
hdiutil convert "$RW" -format UDZO -imagekey zlib-level=9 -o "$OUT" >/dev/null
rm -f "$RW"

echo "built $OUT"
ls -lh "$OUT" | awk '{print $5, $9}'

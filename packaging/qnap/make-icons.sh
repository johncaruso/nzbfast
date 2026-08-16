#!/bin/sh
# Regenerate the three App Center icons from the committed master raster.
#
#   packaging/qnap/make-icons.sh
#
# QTS wants three files named after the package: 64 px, 80 px, and a
# greyed-out 64 px used while the app is stopped. It serves them from its
# own web image folder as <name>.gif, and qbuild's add_icons() copies
# either `<name>.gif` or `<name>.png` into that slot - so the extension
# on disk is a QDK input name, not the format QTS requires.
#
# We ship PNG. A GIF's one-bit transparency turns the antialiased edge of
# a downscaled 1024 px icon into a ring of white crumbs against the App
# Center's tile; PNG keeps the alpha channel, every browser sniffs the
# real format regardless of the name it is served under, and qbuild
# supports the .png names outright.
#
# Same tool as packaging/icon/make-icon.sh: sips downscaling the one
# committed master, so every platform's icon comes off the same art.
set -e
cd "$(dirname "$0")"
MASTER=../icon/icon-1024.png
# The greyscale step imports the icon pipeline's PNG reader; without this
# that import drops a __pycache__ directory into packaging/icon/, which is
# untracked, unwanted, and turns up in the next person's git status.
export PYTHONDONTWRITEBYTECODE=1

sips -z 64 64 "$MASTER" --out icons/nzbfast.png >/dev/null
sips -z 80 80 "$MASTER" --out icons/nzbfast_80.png >/dev/null

# The stopped-state icon. sips cannot do this: `sips -M` against a grey
# ColorSync profile writes no output at all for an image that has an alpha
# channel, and it fails silently - the first cut of this script shipped a
# "grey" icon byte-identical to the colour one, which would have had App
# Center drawing a stopped app exactly like a running one. Greyscale it by
# hand instead, reusing the PNG reader the icon pipeline already has.
sips -z 64 64 "$MASTER" --out icons/nzbfast_gray.png >/dev/null
python3 - <<'GRAY'
import sys
sys.path.insert(0, "../icon")
from rasterize import read_png, write_rgba

w, h, ch, px = read_png("icons/nzbfast_gray.png")
out = bytearray()
for i in range(0, len(px), ch):
    # Rec. 601 luma, alpha untouched: the tile keeps its shape and its
    # rounded corners, the artwork loses its colour.
    g = (px[i] * 299 + px[i + 1] * 587 + px[i + 2] * 114) // 1000
    out += bytes((g, g, g, px[i + 3] if ch == 4 else 255))
write_rgba("icons/nzbfast_gray.png", w, h, out)
GRAY

echo "wrote icons/nzbfast.png icons/nzbfast_80.png icons/nzbfast_gray.png"

#!/bin/sh
# Regenerate the nzbfast icon artifacts from the two masters. Produces:
#   icon-1024.png    committed source-of-truth raster (large art)
#   NzbFast.icns     (in a temp dir; consumed by macapp/make-app.sh)
# Windows: run make-ico.py for nzbfast.ico, same masters.
#
# Two masters, one per size band - .icns stores an image per size, so this
# is the format working as intended rather than a compromise:
#   icon-small.svg   16 and 32 px entries (bolt alone)
#   icon.svg         64 px and up        (bolt plus slipstream)
# At 16 px the slipstream and the bolt fight over the same handful of pixels.
#
# rasterize.py drives qlmanage (WebKit) and recovers a real alpha channel;
# qlmanage on its own flattens onto opaque white, which is how every icon we
# shipped ended up with a white square behind the rounded tile. sips is only
# used where it downscales an already-transparent PNG. Stock macOS tools
# plus python3 - no third-party deps.
set -e
cd "$(dirname "$0")"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

python3 rasterize.py icon.svg 1024 icon-1024.png
echo "wrote icon-1024.png"

# Full iconset for iconutil. The two 16 px entries come from the small
# master; everything from icon_32x32@2x (64 px) up comes from the large one,
# downscaled from the 1024 master so the whole band stays pixel-consistent.
ICONSET="$TMP/NzbFast.iconset"
mkdir -p "$ICONSET"
python3 rasterize.py icon-small.svg 16 "$ICONSET/icon_16x16.png"
python3 rasterize.py icon-small.svg 32 "$ICONSET/icon_16x16@2x.png"
python3 rasterize.py icon-small.svg 32 "$ICONSET/icon_32x32.png"
for entry in 64:icon_32x32@2x 128:icon_128x128 256:icon_128x128@2x \
             256:icon_256x256 512:icon_256x256@2x 512:icon_512x512 \
             1024:icon_512x512@2x; do
  size=${entry%%:*}; name=${entry#*:}
  sips -z "$size" "$size" icon-1024.png --out "$ICONSET/$name.png" >/dev/null
done
iconutil -c icns "$ICONSET" -o "${1:-NzbFast.icns}"
echo "wrote ${1:-NzbFast.icns}"

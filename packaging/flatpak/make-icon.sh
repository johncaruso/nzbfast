#!/bin/sh
# Regenerate the Flatpak icon from the committed master raster.
#
#   packaging/flatpak/make-icon.sh
#
# Same tool and same master as packaging/qnap/make-icons.sh and
# packaging/icon/make-icon.sh: sips downscaling icon-1024.png, so every
# platform's icon comes off the one piece of art.
#
# PNG rather than the SVG master, even though Flathub accepts either and
# a scalable icon is the nicer thing to ship. appstreamcli compose - the
# step flatpak-builder runs at the end of every build - refuses this
# SVG outright with "Unrecognized image file format", and it is fatal:
# the whole compose run fails and no metadata is produced at all, so the
# build stops with no bundle. It is the icon LOADER that is missing, not
# anything wrong with the file (rsvg-convert renders it fine, and
# appstreamcli succeeds the moment the .svg is not there). A PNG has no
# loader question and meets the requirement either way - Flathub asks for
# an SVG *or* a PNG of at least 256x256.
set -e
cd "$(dirname "$0")"
MASTER=../icon/icon-1024.png
export PYTHONDONTWRITEBYTECODE=1

sips -z 256 256 "$MASTER" --out io.github.nzbfast.nzbfast.png >/dev/null
echo "wrote io.github.nzbfast.nzbfast.png (256x256)"

#!/usr/bin/env python3
"""Write the Finder .DS_Store for the mounted nzbfast DMG staging volume.

Called by make-dmg.sh with the mount point as argv[1] while the RW image
is attached (the background-image alias must point at real, mounted
paths). Finder AppleScript would do the same job but needs Automation
TCC approval; this works headless.

Needs:  pip3 install --user ds-store mac-alias
"""
import sys
from pathlib import Path

try:
    from ds_store import DSStore
    from mac_alias import Alias
except ImportError:
    sys.exit("missing deps - run: pip3 install --user ds-store mac-alias")

if len(sys.argv) != 2:
    sys.exit("usage: make-dmg-dsstore.py /Volumes/<volname>")
vol = Path(sys.argv[1])
bg = vol / ".background" / "background.png"
if not bg.exists():
    sys.exit(f"{bg} missing - stage the volume first")

alias = Alias.for_file(str(bg))

# Window frame at (200,120). Icon view, no chrome. Two measured facts
# (verified live on macOS 27, 2026-08-08) size the frame:
#   - WindowBounds is the WHOLE window frame including the ~28 pt title
#     bar, not the content area. A 400-tall frame left ~372 pt of
#     content and cropped the bottom of the step panels (they end at
#     y=386 in the 660x400 design).
#   - Finder IGNORES the Show* booleans below and follows the user's
#     global path-bar/status-bar preference, costing up to ~56 pt more.
#     The flags stay for older Finders that do honor them.
# So: 400 design + 28 title bar + 56 optional bars = 484. For users
# without the bars the spare height just shows more of the background's
# dark gradient (the canvas is a 660x660 square), which reads as margin.
bwsp = {
    "ShowStatusBar": False,
    "ShowToolbar": False,
    "ShowPathbar": False,
    "ShowSidebar": False,
    "ShowTabView": False,
    "ContainerShowSidebar": False,
    "PreviewPaneVisibility": False,
    "SidebarWidth": 0,
    "WindowBounds": "{{200, 120}, {660, 484}}",
}
icvp = {
    "viewOptionsVersion": 1,
    "iconSize": 104.0,
    "textSize": 12.0,
    "labelOnBottom": True,
    "arrangeBy": "none",
    "gridSpacing": 100.0,
    "gridOffsetX": 0.0,
    "gridOffsetY": 0.0,
    "showIconPreview": False,
    "showItemInfo": False,
    "backgroundType": 2,
    "backgroundColorRed": 1.0,
    "backgroundColorGreen": 1.0,
    "backgroundColorBlue": 1.0,
    "backgroundImageAlias": alias.to_bytes(),
}

store_path = vol / ".DS_Store"
with DSStore.open(str(store_path), "w+") as d:
    d["."]["bwsp"] = bwsp
    d["."]["icvp"] = icvp
    # Icon centers, y from the top, matching the layout contract noted
    # in dmg-background.svg: the two protagonists sit on the arrow line,
    # the install guide sits beside step panel 4 ("Full guide ->"), and
    # housekeeping entries are parked far below the window.
    d["NzbFast.app"]["Iloc"] = (165, 165)
    d["Applications"]["Iloc"] = (495, 165)
    d["How to install.html"]["Iloc"] = (585, 322)
    for hidden in (".background", ".extras", ".VolumeIcon.icns", ".fseventsd"):
        d[hidden]["Iloc"] = (330, 700)

print(f"wrote {store_path}")

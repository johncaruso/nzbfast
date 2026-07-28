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

# Window: 660x400 at (200,120). Icon view, no chrome.
bwsp = {
    "ShowStatusBar": False,
    "ShowToolbar": False,
    "ShowPathbar": False,
    "ShowSidebar": False,
    "SidebarWidth": 0,
    "WindowBounds": "{{200, 120}, {660, 400}}",
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
    # Icon centers, y from the top. The two protagonists sit on the
    # arrow line; housekeeping entries are parked far below the window.
    d["NzbFast.app"]["Iloc"] = (165, 185)
    d["Applications"]["Iloc"] = (495, 185)
    for hidden in (".background", ".extras", ".VolumeIcon.icns", ".fseventsd"):
        d[hidden]["Iloc"] = (330, 700)

print(f"wrote {store_path}")

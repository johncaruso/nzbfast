#!/usr/bin/env python3
"""Build nzbfast.ico from the two SVG masters - stdlib only, rasterizing
through rasterize.py (qlmanage) and downscaling with macOS `sips`. Entries
are PNG-compressed (fine on Windows Vista+; we support Win10/11). Run from
packaging/icon/:

    python3 make-ico.py

16/24/32 come from icon-small.svg (bolt alone) and everything larger from
icon.svg (bolt plus slipstream) - an .ico stores one image per size, which is
exactly what that split is for. Windows picks the entry matching the surface
it is drawing, so the taskbar and the alt-tab list each get art drawn for
their size instead of a downscale of the other one's.

Each small entry is rasterized at its own size rather than downscaled: at
16 px a resample smears the bolt's edges into the tile and the mark turns to
mush, which was the original complaint.
"""
import os
import subprocess
import struct
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
LARGE = os.path.join(HERE, "icon.svg")
SMALL = os.path.join(HERE, "icon-small.svg")
MASTER = os.path.join(HERE, "icon-1024.png")
OUT = os.path.join(HERE, "nzbfast.ico")
SIZES = [16, 24, 32, 48, 64, 128, 256]
SMALL_SIZES = {16, 24, 32}

datas = []
with tempfile.TemporaryDirectory() as td:
    for s in SIZES:
        p = os.path.join(td, f"{s}.png")
        if s in SMALL_SIZES:
            subprocess.run(
                ["python3", os.path.join(HERE, "rasterize.py"), SMALL, str(s), p],
                check=True)
        else:
            subprocess.run(
                ["sips", "-z", str(s), str(s), MASTER, "--out", p],
                check=True, capture_output=True)
        with open(p, "rb") as f:
            datas.append(f.read())

# ICONDIR + one ICONDIRENTRY per size, then the raw PNG payloads.
hdr = struct.pack("<HHH", 0, 1, len(SIZES))
entries = b""
off = 6 + 16 * len(SIZES)
for s, d in zip(SIZES, datas):
    entries += struct.pack(
        "<BBBBHHII", s % 256, s % 256, 0, 0, 1, 32, len(d), off)
    off += len(d)
with open(OUT, "wb") as f:
    f.write(hdr + entries + b"".join(datas))
print(f"wrote {OUT} ({off} bytes, sizes {SIZES})")

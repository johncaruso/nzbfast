#!/usr/bin/env python3
"""Rasterize an SVG to a PNG with a real alpha channel.

    python3 rasterize.py <in.svg> <size> <out.png>

qlmanage is the only SVG rasterizer on a stock Mac, and it flattens onto an
opaque white background - so every icon we shipped had a white square where
the rounded tile's corners should have been transparent. On a dark taskbar
that reads as a white tile with our artwork inset inside it, which is half
of the "logo is too small and hard to see" report.

Recovering the alpha exactly: render the same SVG twice, once over white and
once over black. For a pixel with straight colour C and coverage a,

    over white:  Cw = C*a + 255*(1-a)
    over black:  Cb = C*a

so a = 1 - (Cw - Cb)/255 and C = Cb/a. Both renders come from the same
rasterizer at the same size, so the two agree to the bit and the result is
the true antialiased edge, not a threshold.

Stdlib only: zlib and struct do the PNG work.
"""
import os
import struct
import subprocess
import sys
import tempfile
import zlib


def read_png(path):
    """Minimal PNG reader: 8-bit, non-interlaced, which is all qlmanage emits."""
    data = open(path, "rb").read()
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError(f"{path}: not a PNG")
    i, idat, ihdr = 8, b"", None
    while i < len(data):
        ln = struct.unpack(">I", data[i:i + 4])[0]
        typ, chunk = data[i + 4:i + 8], data[i + 8:i + 8 + ln]
        i += 12 + ln
        if typ == b"IHDR":
            ihdr = struct.unpack(">IIBBBBB", chunk)
        elif typ == b"IDAT":
            idat += chunk
    w, h, depth, ctype, _, _, interlace = ihdr
    if depth != 8 or interlace:
        raise ValueError(f"{path}: unsupported PNG ({depth}-bit, interlace={interlace})")
    ch = {0: 1, 2: 3, 4: 2, 6: 4}[ctype]
    raw = zlib.decompress(idat)
    stride = w * ch
    out, prev, pos = bytearray(), bytearray(stride), 0
    for _ in range(h):
        filt = raw[pos]
        pos += 1
        line = bytearray(raw[pos:pos + stride])
        pos += stride
        for x in range(stride):
            a = line[x - ch] if x >= ch else 0
            b = prev[x]
            c = prev[x - ch] if x >= ch else 0
            if filt == 1:
                line[x] = (line[x] + a) & 255
            elif filt == 2:
                line[x] = (line[x] + b) & 255
            elif filt == 3:
                line[x] = (line[x] + (a + b) // 2) & 255
            elif filt == 4:
                p = a + b - c
                pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                pred = a if (pa <= pb and pa <= pc) else (b if pb <= pc else c)
                line[x] = (line[x] + pred) & 255
        out += line
        prev = line
    return w, h, ch, bytes(out)


def write_rgba(path, w, h, px):
    raw = b"".join(b"\0" + px[y * w * 4:(y + 1) * w * 4] for y in range(h))

    def chunk(typ, payload):
        body = typ + payload
        return struct.pack(">I", len(payload)) + body + struct.pack(">I", zlib.crc32(body))

    open(path, "wb").write(
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 6, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(raw, 9))
        + chunk(b"IEND", b""))


def render(svg_text, colour, size, tmp, tag):
    """Render svg_text over a solid backdrop and return the decoded pixels."""
    # The backdrop goes immediately after the opening <svg ...> tag so it sits
    # behind everything, whatever the document draws.
    cut = svg_text.index(">", svg_text.index("<svg")) + 1
    backdrop = f'<rect width="100%" height="100%" fill="{colour}"/>'
    doc = svg_text[:cut] + backdrop + svg_text[cut:]
    src = os.path.join(tmp, f"{tag}.svg")
    open(src, "w").write(doc)
    subprocess.run(["qlmanage", "-t", "-s", str(size), "-o", tmp, src],
                   check=True, capture_output=True)
    return read_png(os.path.join(tmp, f"{tag}.svg.png"))


def rasterize(svg_path, size, out_path):
    svg_text = open(svg_path).read()
    with tempfile.TemporaryDirectory() as tmp:
        w, h, chw, white = render(svg_text, "#ffffff", size, tmp, "w")
        _, _, chb, black = render(svg_text, "#000000", size, tmp, "b")
    if (w, h) != (size, size):
        raise SystemExit(f"{svg_path}: qlmanage returned {w}x{h}, wanted {size}x{size}")
    px = bytearray(w * h * 4)
    for i in range(w * h):
        ow, ob, o = i * chw, i * chb, i * 4
        # Coverage is the same for every channel; average the three estimates
        # so JPEG-free but still lossy rasterizer rounding cancels out.
        a = 0
        for c in range(3):
            a += 255 - (white[ow + c] - black[ob + c])
        a = max(0, min(255, (a + 1) // 3))
        px[o + 3] = a
        if a:
            for c in range(3):
                px[o + c] = max(0, min(255, round(black[ob + c] * 255 / a)))
    write_rgba(out_path, w, h, bytes(px))


if __name__ == "__main__":
    if len(sys.argv) != 4:
        raise SystemExit(__doc__)
    rasterize(sys.argv[1], int(sys.argv[2]), sys.argv[3])

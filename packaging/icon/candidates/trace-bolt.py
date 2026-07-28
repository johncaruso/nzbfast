#!/usr/bin/env python3
"""Emit the traced bolt's path data - the provenance for the shape in
../icon-small.svg and ../icon.svg.

    python3 trace-bolt.py [scale] [dy] [dx]

The bolt in gemini-bolt-1024.jpg is better proportioned than anything drawn
by hand here, but it is raster: it baked about 15% padding around its own
tile and can only ever be downscaled, which turns to mush by 16 px. So the
silhouette was measured off it rather than copied.

Method: the reference is a seven-vertex polygon with four straight edges and
three horizontal ones. For each straight edge, every scanline's left or right
boundary pixel inside that edge's run was collected and least-squares fitted
to x = m*y + b; the constants below are those fits. The vertices are then the
intersections of the fitted lines, which recovers the sharp corners the
reference itself has rounded off - the fit is not disturbed by that rounding
because the rounded runs are excluded from it. Finally the reference's tile
bbox (127..896 of 1024) is mapped onto ours (60..964), so the bolt keeps its
proportions relative to the tile.

The output is our own geometry, and being vector it is drawn fresh at every
size instead of resampled.

    scale  size about the bolt's own centre; the masters ship 1.14 (small,
           bolt alone, filling the tile) and 1.0 (large, beside the
           slipstream)
    dy dx  offset applied after scaling
"""
import math
import sys

# Edge lines fitted from the reference's pixels (x = m*y + b), in its
# coordinates. UL/UR are the upper arm's two sides, LL/LR the lower arm's.
UL = (-0.4997, 590.66)
UR = (-0.6984, 864.36)
LL = (-0.5097, 743.31)
LR = (-1.1125, 1227.36)
# The three horizontal edges: the flat top, the notch on the right where the
# upper arm hands over to the lower one, and the notch on the left.
Y_TOP, Y_NOTCH_R, Y_NOTCH_L = 252.0, 455.5, 553.5

# Reference tile bbox (origin, size) -> ours (x=60 y=60 w=904 h=904).
SRC_TILE, DST_TILE, DST_ORIGIN = (127.0, 770.0), 904.0, 60.0

# How far to cut back along both edges at each vertex before curving through
# it. A bare acute point - the bottom tip above all - renders as a needle
# that antialiases away at 16 px, so every corner is blunted, more where the
# angle is sharper. Same order as V below.
CUT = [34, 34, 34, 48, 76, 34, 44]


def X(line, y):
    return line[0] * y + line[1]


def intersect(a, b):
    y = (b[1] - a[1]) / (a[0] - b[0])
    return (X(a, y), y)


def unit(a, b):
    vx, vy = b[0] - a[0], b[1] - a[1]
    n = math.hypot(vx, vy)
    return vx / n, vy / n


def bolt(k=1.0, dy=0.0, dx=0.0):
    V = [(X(UL, Y_TOP), Y_TOP),          # top-left of the flat top
         (X(UR, Y_TOP), Y_TOP),          # top-right
         (X(UR, Y_NOTCH_R), Y_NOTCH_R),  # inner corner, right notch
         (X(LR, Y_NOTCH_R), Y_NOTCH_R),  # right point
         intersect(LL, LR),              # bottom tip
         (X(LL, Y_NOTCH_L), Y_NOTCH_L),  # inner corner, left notch
         (X(UL, Y_NOTCH_L), Y_NOTCH_L)]  # left point

    origin, size = SRC_TILE
    s = DST_TILE / size
    V = [(DST_ORIGIN + (x - origin) * s, DST_ORIGIN + (y - origin) * s)
         for x, y in V]

    xs = [p[0] for p in V]
    ys = [p[1] for p in V]
    cx, cy = (min(xs) + max(xs)) / 2, (min(ys) + max(ys)) / 2
    V = [(cx + (x - cx) * k + dx, cy + (y - cy) * k + dy) for x, y in V]

    n = len(V)
    f = lambda v: ("%.1f" % v).rstrip("0").rstrip(".")
    seg = []
    for i, p in enumerate(V):
        ux, uy = unit(p, V[(i - 1) % n])
        wx, wy = unit(p, V[(i + 1) % n])
        d = CUT[i]
        seg.append(((p[0] + ux * d, p[1] + uy * d), p,
                    (p[0] + wx * d, p[1] + wy * d)))

    out = "M %s %s" % (f(seg[0][0][0]), f(seg[0][0][1]))
    for i in range(n):
        _, v, b = seg[i]
        out += " Q %s %s %s %s" % (f(v[0]), f(v[1]), f(b[0]), f(b[1]))
        nxt = seg[(i + 1) % n][0]
        out += " L %s %s" % (f(nxt[0]), f(nxt[1]))
    return out + " Z"


if __name__ == "__main__":
    print(bolt(*(float(v) for v in sys.argv[1:])))

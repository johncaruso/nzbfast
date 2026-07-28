#!/usr/bin/env python3
"""Rebuild icon-candidates.html - the comparison sheet the icon was judged on.

Every tile is a TRUE render at 16/32/48/128 px, never a downscale of the
1024 px art, and every render goes through ../rasterize.py so it keeps a real
alpha channel. The first cut of this sheet used qlmanage directly, which
flattens onto opaque white - so its "on a dark taskbar" column was showing a
white box behind every candidate and could not have judged the one thing the
sheet exists to judge.

Sources that are already raster (the previous icon, the reference render) are
downscaled with sips and shown as-is; that is what they are.

The previous icon's 1024 px raster is not kept in the tree - recreate it from
history if you want that row:

    git show <rev-before-the-icon-change>:packaging/icon/icon-1024.png \\
        > shipped-old-1024.png

    python3 build-sheet.py
"""
import base64
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ICON = os.path.dirname(HERE)
SIZES = [16, 32, 48, 128]


def renders(src, tmp, tag):
    """Return {size: data-uri} for one source, SVG or PNG."""
    out = {}
    for s in SIZES:
        p = os.path.join(tmp, f"{tag}-{s}.png")
        if src.endswith(".svg"):
            subprocess.run(["python3", os.path.join(ICON, "rasterize.py"), src, str(s), p],
                           check=True)
        else:
            subprocess.run(["sips", "-z", str(s), str(s), src, "--out", p],
                           check=True, capture_output=True)
        out[s] = "data:image/png;base64," + base64.b64encode(open(p, "rb").read()).decode()
    return out


ROWS = [
    dict(tag="shipped", src=os.path.join(ICON, "icon-small.svg"), cls="pick",
         title="Bolt, traced", chip="Shipped", chipcls="pick",
         note="The mark we ship at 16, 24 and 32&nbsp;px. Its silhouette is "
              "traced from the reference render below by fitting each edge to "
              "that image's pixels and taking the vertices as the line "
              "intersections - so it keeps the better proportions but is our "
              "own geometry, drawn once at every size instead of resampled. "
              "Corners are blunted rather than left sharp: at 16&nbsp;px a "
              "bare point is a needle that antialiases away."),
    dict(tag="slip", src=os.path.join(ICON, "icon.svg"), cls="",
         title="Bolt with slipstream", chip="Shipped, 128&nbsp;px and up", chipcls="",
         note="The same traced bolt with three trailing bars, on an identical "
              "tile. Shown here at 16 and 32&nbsp;px only to make the case for "
              "the split: the bars and the bolt fight over the same pixels and "
              "the mark turns to noise. Both <code>.ico</code> and "
              "<code>.icns</code> store one image per size, so the small band "
              "simply drops them."),
    dict(tag="gemini", src=os.path.join(HERE, "gemini-bolt-1024.jpg"), cls="",
         title="Reference render", chip="Traced from, not shipped", chipcls="",
         note="Better proportioned than anything drawn by hand here, which is "
              "why it became the reference. It is not shippable as-is: it "
              "baked about 15% padding around its own tile, throwing away an "
              "eighth of the pixels, and being raster it can only be "
              "downscaled - the antialiasing compounds into mush by "
              "16&nbsp;px. Compare its 16 with the traced one."),
    dict(tag="refined", src=os.path.join(HERE, "d-refined.svg"), cls="",
         title="Bolt, refined", chip="Previous best, superseded", chipcls="",
         note="The best of the hand-drawn attempts and the baseline the trace "
              "had to beat. Widened waist and rounded joins, but the arms are "
              "thin and the two notches are shallow, so at 16&nbsp;px it reads "
              "as a diagonal slash rather than a bolt."),
    dict(tag="chisel", src=os.path.join(HERE, "e-chisel.svg"), cls="",
         title="Bolt, chiselled", chip="Alternative", chipcls="",
         note="Two broad wedges meeting at a shared waist - the most "
              "downscale-tolerant way to draw a bolt, but the arms taper to "
              "nothing at the tips and it starts to read as an arrow."),
    dict(tag="current", src=os.path.join(HERE, "shipped-old-1024.png"), cls="problem",
         title="Previous icon", chip="The reported bug", chipcls="problem",
         note="Near-black tile with no silhouette against a dark taskbar, and "
              "a lowercase <em>nz</em> that collapses into a smudge. Note the "
              "white square: the build flattened every icon onto opaque white, "
              "so the rounded tile shipped inside a white box - fixed in the "
              "same change as the artwork."),
]

CSS = """
:root{
  --bg:#f6f7f9; --card:#fff; --ink:#191c24; --muted:#5d6472;
  --line:rgba(25,28,36,.11); --acc:#2f6fd0; --pick:#127a52; --bad:#b0341f;
  --taskdark:#1f2229; --tasklight:#e8eaef;
  color-scheme:light;
}
@media (prefers-color-scheme:dark){:root{
  --bg:#101218; --card:#171a21; --ink:#e8eaf0; --muted:#949cb0;
  --line:rgba(150,160,185,.15); --acc:#6cb0ff; --pick:#48d69b; --bad:#f0806c;
  color-scheme:dark;
}}
:root[data-theme=dark]{
  --bg:#101218; --card:#171a21; --ink:#e8eaf0; --muted:#949cb0;
  --line:rgba(150,160,185,.15); --acc:#6cb0ff; --pick:#48d69b; --bad:#f0806c;
  color-scheme:dark;
}
:root[data-theme=light]{
  --bg:#f6f7f9; --card:#fff; --ink:#191c24; --muted:#5d6472;
  --line:rgba(25,28,36,.11); --acc:#2f6fd0; --pick:#127a52; --bad:#b0341f;
  color-scheme:light;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);
  font:15px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;
  -webkit-font-smoothing:antialiased}
.wrap{max-width:900px;margin:0 auto;padding:40px 20px 72px;display:flex;flex-direction:column;gap:28px}
header p{max-width:64ch;color:var(--muted);margin:.5em 0 0}
h1{font-size:clamp(1.5rem,3.4vw,2rem);letter-spacing:-.02em;margin:0;text-wrap:balance}
.eyebrow{font-size:11px;text-transform:uppercase;letter-spacing:.1em;color:var(--muted);
  font-weight:600;display:block;margin-bottom:8px}
.row{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:20px;
  display:grid;grid-template-columns:128px 1fr;gap:20px 22px;align-items:start}
.row.pick{border-color:var(--pick);box-shadow:0 0 0 1px var(--pick) inset}
.big{border-radius:14px;display:block;max-width:100%;height:auto}
.meta h2{margin:0 0 6px;font-size:1.06rem;letter-spacing:-.01em;
  display:flex;align-items:center;gap:9px;flex-wrap:wrap}
.meta p{margin:0;color:var(--muted);font-size:14px;max-width:60ch}
.tag{font-size:10.5px;text-transform:uppercase;letter-spacing:.07em;font-weight:700;
  border:1px solid var(--muted);color:var(--muted);border-radius:99px;padding:2px 9px}
.tag.pick{border-color:var(--pick);color:var(--pick)}
.tag.no,.tag.problem{border-color:var(--bad);color:var(--bad)}
.grounds{grid-column:1/-1;display:flex;flex-wrap:wrap;gap:12px}
.ground,.zoomwrap{border-radius:9px;padding:11px 13px;border:1px solid var(--line)}
.ground.dark{background:var(--taskdark)}
.ground.light{background:var(--tasklight)}
.zoomwrap{background:transparent}
.glabel{display:block;font-size:10px;text-transform:uppercase;letter-spacing:.08em;
  margin-bottom:9px;font-weight:600;color:var(--muted)}
.ground.dark .glabel{color:#9aa2b6}
.ground.light .glabel{color:#5b6273}
.ladder{display:flex;align-items:flex-end;gap:15px}
.sz{margin:0;display:flex;flex-direction:column;align-items:center;gap:5px}
.sz img{display:block;image-rendering:auto}
.sz figcaption{font-size:9.5px;color:var(--muted);font-variant-numeric:tabular-nums}
.ground.dark figcaption{color:#8b93a7}
.ground.light figcaption{color:#666d7d}
.zoomrow{display:flex;gap:13px}
.zoom{width:96px;height:96px;image-rendering:pixelated;display:block;border-radius:6px}
.zoom.dk{background:var(--taskdark)}
.zoom.lt{background:var(--tasklight)}
code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.9em}
footer{color:var(--muted);font-size:13.5px;max-width:66ch}
footer h2{font-size:.95rem;color:var(--ink);margin:0 0 6px}
@media(max-width:620px){.row{grid-template-columns:1fr}.big{margin:0 auto}}
"""


def ladder(r, ground, name):
    cells = "".join(
        f'<figure class="sz"><img src="{r[s]}" width="{s}" height="{s}" '
        f'alt="{name} at {s} pixels"><figcaption>{s}px</figcaption></figure>'
        for s in (16, 32, 48))
    label = "on a dark taskbar" if ground == "dark" else "on a light taskbar"
    return (f'<div class="ground {ground}"><span class="glabel">{label}</span>'
            f'<div class="ladder">{cells}</div></div>')


def main():
    parts = []
    with tempfile.TemporaryDirectory() as tmp:
        for row in ROWS:
            if not os.path.exists(row["src"]):
                print(f"skipping {row['tag']}: {row['src']} not present", file=sys.stderr)
                continue
            r = renders(row["src"], tmp, row["tag"])
            name = row["title"]
            chip = (f'<span class="tag {row["chipcls"]}">{row["chip"]}</span>'
                    if row["chip"] else "")
            parts.append(f"""<article class="row {row['cls']}">
  <img class="big" src="{r[128]}" width="128" height="128" alt="{name}, at 128 pixels">
  <div class="meta"><h2>{name} {chip}</h2><p>{row['note']}</p></div>
  <div class="grounds">
    {ladder(r, 'dark', name)}
    {ladder(r, 'light', name)}
    <div class="zoomwrap"><span class="glabel">16px, enlarged</span><div class="zoomrow">
      <img class="zoom dk" src="{r[16]}" alt="{name} at 16px, enlarged on dark">
      <img class="zoom lt" src="{r[16]}" alt="{name} at 16px, enlarged on light">
    </div></div>
  </div>
</article>""")

    html = f"""<title>nzbfast icon candidates</title>
<style>{CSS}</style>
<div class="wrap">
<header>
  <span class="eyebrow">nzbfast &middot; app icon</span>
  <h1>Judged at the size that actually matters</h1>
  <p>The reported problem was never how the icon looks large, it is that it
  disappears in a taskbar. So everything below is a true 16, 32 and
  48&nbsp;pixel render - not the 1024&nbsp;px art scaled down in the browser -
  shown on both a dark and a light taskbar ground, with the 16&nbsp;pixel
  version enlarged on each. The tile on the left is the same art at
  128&nbsp;px.</p>
</header>
{chr(10).join(parts)}
<footer>
  <h2>What shipped</h2>
  <p>The traced bolt at 16, 24 and 32&nbsp;px and the slipstream version from
  128&nbsp;px up. That split is ordinary: both Windows <code>.ico</code> and
  macOS <code>.icns</code> store separate images per size, so the small art can
  drop detail the large art keeps. Two things went with it. The build no longer
  flattens icons onto opaque white, which is why every icon we shipped had a
  white square where the rounded tile's corners should have been transparent.
  And the dashboard's emoji <code>data:</code> favicon is now real PNGs plus a
  web manifest - an emoji favicon draws in the tab strip but gives the OS
  nothing to build a shortcut from, which is why a pinned dashboard showed a
  generated letter&nbsp;N.</p>
</footer>
</div>
"""
    out = os.path.join(HERE, "icon-candidates.html")
    open(out, "w").write(html)
    print(f"wrote {out} ({len(html)} bytes)", file=sys.stderr)


main()

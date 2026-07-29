#!/usr/bin/env python3
"""damage_nzb.py IN.nzb OUT.nzb N - poison N data-file segments (spread evenly,
skipping .par2 files and each file's first segment) by rewriting their
message-ids to nonexistent ones. Prints what was poisoned."""
import re
import sys

src, dst, n = sys.argv[1], sys.argv[2], int(sys.argv[3])
s = open(src, encoding="utf-8", errors="replace").read()

# File blocks: <file ...subject="...">...</file>
files = list(re.finditer(r'<file[^>]*subject="([^"]*)"[^>]*>.*?</file>', s, re.S))
targets = []  # (start, end, msgid) of <segment> elements eligible for damage
for f in files:
    subj = f.group(1)
    if ".par2" in subj.lower():
        continue
    segs = list(re.finditer(r"<segment[^>]*>([^<]+)</segment>", f.group(0)))
    for seg in segs[1:]:  # skip first segment (keep headers resolvable)
        targets.append((f.start() + seg.start(1), f.start() + seg.end(1), seg.group(1)))

if len(targets) < n:
    sys.exit("not enough segments to damage")
step = len(targets) // n
picked = [targets[i * step] for i in range(n)]

out = []
prev = 0
for start, end, msgid in sorted(picked):
    out.append(s[prev:start])
    out.append("bench-damaged-" + s[start:end])
    prev = end
out.append(s[prev:])
open(dst, "w", encoding="utf-8").write("".join(out))
print(f"poisoned {len(picked)} of {len(targets)} eligible segments")
for _, _, m in picked[:5]:
    print("  e.g.", m[:60])

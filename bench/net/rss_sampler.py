#!/usr/bin/env python3
"""Sample process-tree RSS. usage: rss_sampler.py OUTFILE PATTERN [PATTERN...]
Matches ps command lines against the regex patterns, adds all descendants,
writes the running max total RSS (KB) to OUTFILE until SIGTERM/roots-gone."""
import re
import signal
import subprocess
import sys
import time

out, pats = sys.argv[1], [re.compile(p) for p in sys.argv[2:]]
mx = 0
run = True


def stop(*_):
    global run
    run = False


signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGINT, stop)

while run:
    try:
        ps = subprocess.run(["ps", "-axo", "pid=,ppid=,rss=,command="],
                            capture_output=True, text=True, timeout=10).stdout
    except Exception:
        break
    procs = {}
    for line in ps.splitlines():
        try:
            pid, ppid, rss, cmd = line.split(None, 3)
        except ValueError:
            continue
        if "rss_sampler" in cmd:
            continue
        procs[int(pid)] = (int(ppid), int(rss), cmd)
    roots = {p for p, (_, _, c) in procs.items() if any(r.search(c) for r in pats)}
    children = {}
    for p, (pp, _, _) in procs.items():
        children.setdefault(pp, []).append(p)
    seen, stack = set(), list(roots)
    while stack:
        p = stack.pop()
        if p in seen:
            continue
        seen.add(p)
        stack.extend(children.get(p, []))
    tot = sum(procs[p][1] for p in seen)
    if tot > mx:
        mx = tot
        with open(out, "w") as f:
            f.write(str(mx))
    time.sleep(0.5)

with open(out, "w") as f:
    f.write(str(mx))

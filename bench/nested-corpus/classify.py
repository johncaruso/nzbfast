#!/usr/bin/env python3
"""classify.py - grade one client run of one nested-corpus leg.

    classify.py <manifest.json> <outdir> <client-exit-code>

Prints one line:  class=<c> matched=<k>/<n> [missing=a,b] [leftover=x,y]

Classes (the "automatic vs manual intervention" framing):
  auto-complete        every manifest payload exists under <outdir> with a
                       matching sha256 (found anywhere in the tree)
  manual-intervention  the client finished without an error but the final
                       payloads are not all there - an operator would have
                       to keep unpacking or repairing by hand
  fail                 nonzero exit / timeout, and no complete payload set
"""

import hashlib
import json
import os
import sys


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    manifest = json.load(open(sys.argv[1]))
    outdir, rc = sys.argv[2], int(sys.argv[3])

    # Index every file under outdir by basename and by size (clients
    # differ on layout, and some rename the extracted payload to the job
    # name - SAB renames a lone unpacked file to the NZB name). A payload
    # is "present" when its exact bytes exist anywhere in the tree, so we
    # match on content (size + sha256), not on the corpus-side basename.
    by_name, by_size = {}, {}
    for root, _dirs, files in os.walk(outdir):
        for name in files:
            path = os.path.join(root, name)
            by_name.setdefault(name, []).append(path)
            try:
                by_size.setdefault(os.path.getsize(path), []).append(path)
            except OSError:
                pass

    missing, matched = [], 0
    for p in manifest["payloads"]:
        ok = False
        # Fast path: a file with the same basename and matching content.
        for cand in by_name.get(p["name"], []):
            if os.path.getsize(cand) == p["bytes"] and sha256(cand) == p["sha256"]:
                ok = True
                break
        # Name-independent path: any file of the right size and sha256
        # (credits clients that renamed the extracted payload).
        if not ok:
            for cand in by_size.get(p["bytes"], []):
                if sha256(cand) == p["sha256"]:
                    ok = True
                    break
        if ok:
            matched += 1
        else:
            missing.append(p["name"])

    # Leftover archives = a visible signal that denesting stopped early.
    leftover = sorted(
        n for n in by_name
        if n.rsplit(".", 1)[-1].lower() in ("rar", "7z", "par2")
    )

    n = len(manifest["payloads"])
    if matched == n and n > 0:
        cls = "auto-complete"
    elif rc == 0:
        cls = "manual-intervention"
    else:
        cls = "fail"
    line = f"class={cls} matched={matched}/{n}"
    if missing:
        line += " missing=" + ",".join(missing[:5])
    if leftover:
        line += " leftover=" + ",".join(leftover[:5])
    print(line)


if __name__ == "__main__":
    main()

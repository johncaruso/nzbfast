#!/usr/bin/env python3
"""Apply a recorded PAR2 damage map to a copy of a pristine corpus.

    apply-damage.py <pristine-dir> <damaged-dir> <map-file>

The map is the cross-rig contract: line 1 is the block size, every
further line is "<volume> <block index>". One byte mid-block is flipped
(XOR 0xFF) per entry, which is exactly what `harness/assemble.ps1` does
on Windows. Both rigs must apply the SAME map rather than re-rolling
damage from a seed, or the machines stop being comparable - a corpus
whose damaged blocks land in different volumes changes how much each
tool has to read, and that difference is worth more than the margins
being measured.
"""
import os
import shutil
import sys


def main():
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    src, dst, mapfile = sys.argv[1:4]

    if os.path.exists(dst):
        shutil.rmtree(dst)
    shutil.copytree(src, dst)

    with open(mapfile) as fh:
        lines = [line.strip() for line in fh if line.strip()]
    block_size = int(lines[0])

    handles = {}
    try:
        for line in lines[1:]:
            name, block = line.split()
            if name not in handles:
                handles[name] = open(os.path.join(dst, name), "r+b")
            fh = handles[name]
            offset = int(block) * block_size + block_size // 2
            fh.seek(offset)
            byte = fh.read(1)
            if not byte:
                sys.exit(f"{name}: block {block} is past end of file")
            fh.seek(offset)
            fh.write(bytes([byte[0] ^ 0xFF]))
    finally:
        for fh in handles.values():
            fh.close()

    print(f"{dst}: damaged {len(lines) - 1} blocks in {len(handles)} volumes")


if __name__ == "__main__":
    main()

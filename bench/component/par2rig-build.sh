#!/bin/bash
# Rebuild the PAR2 shootout corpus on this machine, to the same shape the
# other two rigs already hold: 1 GiB of non-periodic random payload packed
# store-mode into 21 RAR volumes of 50 MB, then two PAR2 sets at 10%
# redundancy - 1 MiB blocks for the "site" legs and 64 KiB for the heavy one -
# then fixed damage maps.
#
#   par2rig-build.sh <root> <payload-file> <rar> <par2>
#
# The payload must be truly random: a payload with 32-byte periodicity
# inflates par2cmdline-turbo's sliding-scan work and flatters us by ~7% on the
# heavy leg.
set -euo pipefail

ROOT=${1:?usage: par2rig-build.sh <root> <payload> <rar> <par2>}
PAYLOAD=${2:?need a payload file}
RAR=${3:-rar}
PAR2=${4:-par2}

rm -rf "$ROOT"
mkdir -p "$ROOT/pristine" "$ROOT/pristine-heavy"

echo "== 21 store volumes"
( cd "$(dirname "$PAYLOAD")" && "$RAR" a -idq -ep -m0 -v50m "$ROOT/pristine/set.rar" "$(basename "$PAYLOAD")" )
cp "$ROOT/pristine"/*.rar "$ROOT/pristine-heavy/"
echo "   volumes: $(ls "$ROOT"/pristine/*.rar | wc -l | tr -d ' ')"

echo "== site PAR2 (1 MiB blocks, 10%)"
( cd "$ROOT/pristine" && "$PAR2" create -q -s1048576 -r10 site.par2 ./*.rar )
echo "== heavy PAR2 (64 KiB blocks, 10%)"
( cd "$ROOT/pristine-heavy" && "$PAR2" create -q -s65536 -r10 heavy.par2 ./*.rar )

damage() { # damage <srcdir> <dstdir> <blocksize> <nblocks>
  local src=$1 dst=$2 bs=$3 n=$4
  rm -rf "$dst"; cp -R "$src" "$dst"
  python3 - "$dst" "$bs" "$n" <<'PY'
import os, sys
d, bs, n = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
vols = sorted(f for f in os.listdir(d) if f.endswith('.rar'))
# Spread the damaged blocks over as few volumes as the count allows, the way
# real article loss lands: 3 blocks in 2 volumes, 101 in 6, 1500 everywhere.
nv = len(vols) if n > 200 else (2 if n <= 3 else 6)
per = [n // nv + (1 if i < n % nv else 0) for i in range(nv)]
hit = 0
for vi in range(nv):
    p = os.path.join(d, vols[vi])
    size = os.path.getsize(p)
    blocks = size // bs
    want = per[vi]
    if want == 0:
        continue
    # evenly spaced blocks inside the volume, one byte flipped mid-block
    with open(p, 'r+b') as f:
        for k in range(want):
            b = (k * blocks) // want
            off = b * bs + bs // 2
            if off >= size:
                continue
            f.seek(off)
            byte = f.read(1)
            f.seek(off)
            f.write(bytes([byte[0] ^ 0xFF]))
            hit += 1
print(f"   damaged {hit} blocks across {nv} volumes")
PY
}

echo "== damage maps"
damage "$ROOT/pristine"       "$ROOT/damaged-3"     1048576 3
damage "$ROOT/pristine"       "$ROOT/damaged-101"   1048576 101
damage "$ROOT/pristine-heavy" "$ROOT/damaged-heavy"   65536 1500

echo "== done"
du -sh "$ROOT"/*/ 2>/dev/null

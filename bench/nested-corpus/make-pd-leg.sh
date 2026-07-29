#!/bin/zsh
# Build a nested-corpus-compatible LEG from real public-domain media, so
# the existing loopback rig (nzbserve + run-legs.sh) can drive every
# client against reproducible PD content instead of /dev/urandom.
#
#   make-pd-leg.sh <src-media-dir> <leg-dir> [vol-size] [par2-%]
#
# Produces:  <leg-dir>/post/   store-mode RAR volumes + PAR2 + .nfo
#            <leg-dir>/manifest.json   payload sha256s for classify.py
# Then:      nzbserve build <leg-dir>   (writes <leg>.nzb)
set -u
SRC=${1:?src media dir}; LEG=${2:?leg dir}; VOL=${3:-200m}; RED=${4:-10}
LEGNAME=$(basename "$LEG")
command -v rar  >/dev/null || { echo "need rar";  exit 1; }
command -v par2 >/dev/null || { echo "need par2"; exit 1; }

rm -rf "$LEG"; mkdir -p "$LEG/post" "$LEG/work"
FILES=()
while IFS= read -r l; do FILES+=("$l"); done < <(find "$SRC" -type f \
    \( -iname '*.mkv' -o -iname '*.mp4' -o -iname '*.mov' -o -iname '*.webm' \) | sort)
[[ ${#FILES[@]} -gt 0 ]] || { echo "no media in $SRC"; exit 1; }
echo "[pd-leg] $LEGNAME: ${#FILES[@]} payload file(s)"

# Attribution travels INSIDE the set - CC-BY requires credit.
cat > "$LEG/work/attribution.nfo" <<'EOF'
nzbfast public benchmark corpus - freely redistributable content only.
  Blender Open Movies (c) Blender Foundation - Creative Commons Attribution 3.0
    https://www.blender.org/about/projects/
  NASA footage - public domain (17 U.S.C. 105) - https://www.nasa.gov/
Posted so anyone can reproduce nzbfast's benchmarks. No copyrighted material.
EOF

# Store-mode (-m0) multi-volume, -ep so no local paths reach the wire.
( cd "$LEG/post" && rar a -ma5 -m0 -ep -idq -v"$VOL" set.rar "${FILES[@]}" \
    "$LEG/work/attribution.nfo" ) || { echo "rar failed"; exit 1; }
( cd "$LEG/post" && par2 create -q -r"$RED" set.par2 set*.rar >/dev/null ) \
    || { echo "par2 failed"; exit 1; }

# manifest.json: classify.py matches payloads by size+sha256 anywhere in
# the client's output tree, so list the ORIGINAL media files.
python3 - "$LEG" "$LEGNAME" "${FILES[@]}" <<'PY'
import hashlib, json, os, sys
leg, legname, files = sys.argv[1], sys.argv[2], sys.argv[3:]
def sha256(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()
payloads = [{"name": os.path.basename(p), "bytes": os.path.getsize(p),
             "sha256": sha256(p)} for p in files]
post = sorted(os.listdir(os.path.join(leg, "post")))
json.dump({
    "leg": legname, "tier": "pd", "shape": "rar(store,vols)+par2 > public-domain media",
    "depth": 1, "payloads": payloads, "post_files": post, "ghost_files": [],
    "content": "public domain / CC-BY (Blender open movies, NASA)",
}, open(os.path.join(leg, "manifest.json"), "w"), indent=2)
print(f"[pd-leg] manifest: {len(payloads)} payload(s), {len(post)} posted files")
PY

rm -rf "$LEG/work"
echo "[pd-leg] post/ $(du -sh "$LEG/post" | cut -f1), $(ls "$LEG/post" | wc -l | tr -d ' ') files"

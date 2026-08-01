#!/bin/bash
# Build the inline recovery-record corpus: one store-mode archive per size,
# each carrying a 5% inline recovery record.
#
#   rr-build.sh <root> <payload-file> <rar> [sizes-MB]
#
# The payload is a prefix of a fixed-seed generator file (bench/component
# corpusgen's rand.bin), NOT /dev/urandom as the scratch rig used, so the
# archives rebuild identically on every machine. Store mode keeps this a
# measurement of the recovery kernel rather than of the decompressor.
set -euo pipefail

ROOT=${1:?usage: rr-build.sh <root> <payload> <rar> [sizes]}
PAYLOAD=${2:?need a payload file}
RAR=${3:-rar}
SIZES=${4:-16 32 128 512 2048}

mkdir -p "$ROOT"
cd "$ROOT"

for mb in $SIZES; do
  name=a$mb
  [[ -f $name.pristine.rar ]] && { echo "$name.pristine.rar exists, keeping"; continue; }
  # A prefix of the shared payload: deterministic, and every size is a
  # prefix of the next so the corpus stays one file's worth of entropy.
  dd if="$PAYLOAD" of="$name.bin" bs=1048576 count="$mb" 2>/dev/null
  "$RAR" a -m0 -rr5p -ep -idq "$name.rar" "$name.bin" >/dev/null
  rm -f "$name.bin"
  mv "$name.rar" "$name.pristine.rar"
  echo "built $name.pristine.rar ($(du -h "$name.pristine.rar" | cut -f1))"
done

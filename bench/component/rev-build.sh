#!/bin/bash
# Build the .rev leg's corpus: a 21-volume store set with three standalone
# recovery volumes, then a copy with three data volumes deleted.
#
#   rev-build.sh <root> <payload> <rar>
#
# Three lost volumes against three .rev files is the worst case the set can
# still survive, which is the case worth timing.
set -euo pipefail
ROOT=${1:?usage: rev-build.sh <root> <payload> <rar>}
PAYLOAD=${2:?payload}
RAR=${3:-rar}

rm -rf "$ROOT"
mkdir -p "$ROOT/pristine"
( cd "$(dirname "$PAYLOAD")" && "$RAR" a -idq -ep -m0 -v50m "$ROOT/pristine/revset.rar" "$(basename "$PAYLOAD")" )
( cd "$ROOT/pristine" && "$RAR" rv3 -idq revset.part01.rar )
echo "volumes: $(ls "$ROOT"/pristine/*.rar | wc -l | tr -d ' ')  rev: $(ls "$ROOT"/pristine/*.rev | wc -l | tr -d ' ')"

rm -rf "$ROOT/damaged"; cp -R "$ROOT/pristine" "$ROOT/damaged"
# Lose three volumes spread through the set, not three adjacent ones.
for n in 04 11 19; do rm -f "$ROOT/damaged/revset.part$n.rar"; done
echo "damaged set: $(ls "$ROOT"/damaged/*.rar | wc -l | tr -d ' ') volumes left"

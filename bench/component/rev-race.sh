#!/bin/bash
# .rev recovery-volume restoration: rebuild missing data volumes from the
# standalone .rev files RAR writes with `rar rv`.
#
# This is the leg Weaver's rarpar CAN run - it implements exactly this and
# nothing else on the recovery side - so it is here to give it a fair fight.
#
#   rev-race.sh <root> <rounds> <ours-bin> <rar> <rarpar>
#
# Protocol matches every other leg: fresh copy of the damaged set, pre-warm
# every byte, time, then gate on the rebuilt volumes being byte-identical to
# the pristine ones.
set -euo pipefail
ROOT=${1:?usage: rev-race.sh <root> <rounds> <ours> <rar> <rarpar>}
ROUNDS=${2:-3}
OURS=${3:?ours}
RAR=${4:-rar}
RARPAR=${5:-rarpar}
WORK=$ROOT/work

now() { python3 -c 'import time; print(time.time())'; }

run_one() {
  local tool=$1
  rm -rf "$WORK"
  cp -c -R "$ROOT/damaged" "$WORK" 2>/dev/null || cp -R "$ROOT/damaged" "$WORK"
  cat "$WORK"/* > /dev/null 2>&1   # pre-warm
  local t0 t1; t0=$(now)
  case $tool in
    ours)   ( "$OURS" "$WORK" >/dev/null 2>&1 || true ) ;;
    # RARLab's own reconstruct. It wants the first volume by name.
    rar)    ( cd "$WORK" && "$RAR" rc "$(ls ./*.part01.rar 2>/dev/null || ls ./*.rar | head -1)" >/dev/null 2>&1 || true ) ;;
    rarpar) ( "$RARPAR" rar restore-volumes "$WORK"/*.rev >/dev/null 2>&1 || true ) ;;
  esac
  t1=$(now)
  local bad=0 missing=0
  for f in "$ROOT/pristine"/*.rar; do
    b=$(basename "$f")
    if [[ ! -f "$WORK/$b" ]]; then missing=$((missing+1)); continue; fi
    cmp -s "$f" "$WORK/$b" || bad=$((bad+1))
  done
  local flag=""
  (( missing == 0 && bad == 0 )) || flag="  !! NOT-RESTORED (missing=$missing wrong=$bad)"
  python3 -c "print('  %-8s %8.3fs%s' % ('$tool', $t1-$t0, '$flag'))"
}

echo "=== .rev restore ($ROUNDS rounds, warm protocol) ==="
for _ in $(seq "$ROUNDS"); do
  for t in ours rar rarpar; do run_one "$t"; done
done
rm -rf "$WORK"

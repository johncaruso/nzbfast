#!/bin/bash
# PAR2 bench round, macOS rigs. Same protocol as the existing round.sh, plus
# the classic par2cmdline column: fresh copy of the corpus -> PRE-WARM (read
# every byte once) -> time. Pre-warming is what makes the three rigs
# comparable: `cp -c` here is an APFS clone that leaves pages cached while a
# Windows copy does not.
#
#   round2.sh <leg> <rounds> <root> <ours-bin> [tools]
set -euo pipefail
leg=${1:-verify}; rounds=${2:-3}; ROOT=${3:?root}; OURS=${4:?ours binary}
tools=${5:-ours,turboT,turboD,rarpar,classic}
TURBO=${TURBO:-$ROOT/bin/par2turbo}
RARPAR=${RARPAR:-$ROOT/bin/rarpar}
CLASSIC=${CLASSIC:-$ROOT/bin/par2}
WORK=$ROOT/work-round2

D_SITE=${D_SITE:-pristine}
D_R101=${D_R101:-damaged-101}
D_R3=${D_R3:-damaged-3}
D_HEAVYP=${D_HEAVYP:-pristine-heavy}
D_HEAVYD=${D_HEAVYD:-damaged-heavy}
case $leg in
  verify) src=$D_SITE;   pris=$D_SITE;   repair=0 ;;
  rep101) src=$D_R101;   pris=$D_SITE;   repair=1 ;;
  rep3)   src=$D_R3;     pris=$D_SITE;   repair=1 ;;
  heavy)  src=$D_HEAVYD; pris=$D_HEAVYP; repair=1 ;;
  *) echo "unknown leg $leg" >&2; exit 2 ;;
esac
par2=$(cd "$ROOT/$src" && ls ./*.par2 | grep -v vol | head -1)

now() { python3 -c 'import time; print(time.time())'; }

run_one() {
  local tool=$1
  rm -rf "$WORK"
  cp -c -R "$ROOT/$src" "$WORK" 2>/dev/null || cp -R "$ROOT/$src" "$WORK"
  cat "$WORK"/* > /dev/null 2>&1   # pre-warm
  local t0 t1; t0=$(now)
  case $tool in
    # The product default since e206ede6: the driver mirrors the daemon's
    # "fast par mode", so this row is what a user gets today.
    ours)   ( cd "$WORK" && "$OURS" . >/dev/null 2>&1 || true ) ;;
    # `oursntt` is retained as an explicit-NTT row for older drivers and
    # for A/B against the fold; on a current driver it matches `ours`.
    oursntt) ( cd "$WORK" && NZBFAST_NTT=1 "$OURS" . >/dev/null 2>&1 || true ) ;;
    # The streaming fold, i.e. fast par mode turned off. This is the
    # comparison column, not the shipping one.
    oursfold) ( cd "$WORK" && NZBFAST_NTT=0 "$OURS" . >/dev/null 2>&1 || true ) ;;
    turboT) if [[ $repair == 1 ]]; then ( cd "$WORK" && "$TURBO" repair -q -T16 "$par2" >/dev/null 2>&1 || true )
            else ( cd "$WORK" && "$TURBO" verify -q -T16 "$par2" >/dev/null 2>&1 || true ); fi ;;
    turboD) if [[ $repair == 1 ]]; then ( cd "$WORK" && "$TURBO" repair -q "$par2" >/dev/null 2>&1 || true )
            else ( cd "$WORK" && "$TURBO" verify -q "$par2" >/dev/null 2>&1 || true ); fi ;;
    rarpar) if [[ $repair == 1 ]]; then ( "$RARPAR" par repair -C "$WORK" "$WORK" >/dev/null 2>&1 || true )
            else ( "$RARPAR" par verify "$WORK" >/dev/null 2>&1 || true ); fi ;;
    classic) if [[ $repair == 1 ]]; then ( cd "$WORK" && DYLD_FALLBACK_LIBRARY_PATH="$ROOT/bin" "$CLASSIC" repair -q "$par2" >/dev/null 2>&1 || true )
            else ( cd "$WORK" && DYLD_FALLBACK_LIBRARY_PATH="$ROOT/bin" "$CLASSIC" verify -q "$par2" >/dev/null 2>&1 || true ); fi ;;
  esac
  t1=$(now)
  local bad=0
  if [[ $repair == 1 ]]; then
    for f in "$ROOT/$pris"/*.rar; do cmp -s "$f" "$WORK/$(basename "$f")" || bad=1; done
  fi
  local flag=""
  [[ $bad == 0 ]] || flag="  !! MISMATCH"
  python3 -c "print('  %-8s %8.3fs%s' % ('$tool', $t1-$t0, '$flag'))"
}

echo "=== $leg (warm protocol, $rounds rounds, $tools) ==="
for _ in $(seq "$rounds"); do
  for t in ${tools//,/ }; do run_one "$t"; done
done
rm -rf "$WORK"

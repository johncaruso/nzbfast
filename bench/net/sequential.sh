#!/bin/zsh
# sequential.sh - SEQUENTIAL job queue, the warm-connection-pool leg.
#
# queue.sh adds every NZB at t0, so they run as one continuous fleet and
# a connection pool's park/claim cycle never happens. This driver runs
# jobs strictly one at a time: add, wait for it to reach history, record
# its wall, then add the next. Job 1 pays a cold fleet (TCP + TLS +
# AUTHINFO + spawn ramp + TCP slow start). Jobs 2..N should claim parked
# connections and skip all of it. The metric is the PER-JOB series, not
# the total.
#
# Clients that build and quit a fleet per job have no equivalent: their
# series should stay flat at job 1's cost.
#
#   NZBDIR=... [N=8] [TIMEOUT=900] ./sequential.sh <nzbfast|nzbfast-cold|nzbget|sab|rustnzb>
#
# NZBDIR must hold N DISTINCT jobs named seq1.nzb .. seqN.nzb - not one
# NZB repeated: every client dedupes history by name, and nzbget needs
# -o DupeCheck=no on top. Small jobs (a few hundred MB) show the effect
# best; on short setup-dominated jobs the connect ramp IS the wall time.
#
#   nzbfast-cold sets NZBFAST_WARM_POOL=0 - the same binary with the
#   pool off, which is the honest A/B (no cross-version build diffs).
#
# Prints one line per job:
#   LEG6 <client> job=<i> wall_s=<s> gbytes=<GB>
# then: LEG6 <client> TOTAL wall_s=<s> jobs=<n> cold_s=<job1> warm_med_s=<med>
set -u
cd "$(dirname "$0")"
source ./lib.sh

TIMEOUT=${TIMEOUT:-900}
NZBDIR=${NZBDIR:?set NZBDIR= (holds seq1.nzb .. seqN.nzb)}
N=${N:-8}
# How many ServerN.Connections entries to force for the NZBGet arm -
# set to your configured server count.
NG_NSERVERS=${NG_NSERVERS:-1}
# Extra -o overrides for the NZBGet arm, e.g. NGEXTRA="-o Server2.Active=no"
# to drop a server. MUST be passed to BOTH the daemon start and every -A
# add: NZBGet re-reads its options per invocation, so an override given
# only to the daemon is silently absent from the adds.
NGEXTRA=${NGEXTRA:-}

zs=(); for i in $(seq 1 $N); do z=$NZBDIR/seq$i.nzb
  [[ -f $z ]] || { echo "LEG6 ${1:-?} ABORT missing NZB: $z"; exit 1; }; zs+=$z; done

# Sub-second timing is mandatory here. These jobs can run ~4 s, of which
# the transfer is a fraction of a second on a fast line - the rest is
# the connect ramp a warm pool exists to remove, and it is worth a few
# hundred ms. A 1-second `date +%s` timer quantises the entire signal away.
zmodload zsh/datetime

walls=()
# Run one job and time it. $1 done-fn, $2 add-fn, $3 client label, $4 nzb, $5 idx
one_job() {
  local donefn=$1 addfn=$2 label=$3 z=$4 idx=$5
  local before=$($donefn) t0=$EPOCHREALTIME b0=$(ib)
  $addfn $z
  local st=timeout
  while (( EPOCHREALTIME - t0 <= TIMEOUT )); do
    sleep 0.25
    [[ $($donefn) -ge $((before+1)) ]] && { st=done; break; }
  done
  local t1=$EPOCHREALTIME b1=$(ib)
  local w=$(( t1 - t0 ))
  walls+=$w
  printf "LEG6 %s job=%s wall_s=%.2f gbytes=%s status=%s\n" \
    "$label" "$idx" "$w" "$(gb $b0 $b1)" "$st"
}

# A client's own "Completed" is NOT evidence that it did the work. A
# client can report completions in seconds and leave an EMPTY complete/
# directory - which reads as "Nx faster" until the output is checked.
# Every arm reports the bytes it actually produced; an arm whose output
# is far below the payload is void regardless of what its API said.
outbytes() { # $1 = directory
  [[ -d $1 ]] || { echo 0; return }
  du -sk $1 2>/dev/null | awk '{print $1*1024}'
}

summary() { # $1 label  $2 output dir
  local produced=$(outbytes ${2:-/nonexistent})
  printf "LEG6 %s OUTPUT bytes=%s (%.2f GB produced)\n" \
    "$1" "$produced" "$(( produced / 1073741824.0 ))"
  (( produced < 500000000 )) && \
    echo "LEG6 $1 WARNING output far below payload - treat this arm as VOID"
  local total=0; for w in $walls; do total=$(( total + w )); done
  local cold=$walls[1]
  # median of jobs 2..N - sort -g, not zsh's ${(n)}, which is integer-oriented
  local warm=(${(f)"$(printf '%s\n' ${walls[@]:1} | sort -g)"})
  local m=$warm[$(( (${#warm}+1)/2 ))]
  printf "LEG6 %s TOTAL wall_s=%.2f jobs=%s cold_s=%.2f warm_med_s=%.2f\n" \
    "$1" "$total" "${#walls}" "$cold" "$m"
}

case "${1:-}" in
nzbfast|nzbfast-cold)
  have_nf || { skip nzbfast "set NZBFAST="; exit 0; }
  [[ -n $NFCONF ]] || { skip $1 "set NFCONF= (server config for nzbfast serve)"; exit 0; }
  [[ $1 == nzbfast-cold ]] && export NZBFAST_WARM_POOL=0
  pkill -f "nzbfast serve.*--port $NF_PORT"; sleep 1
  rm -rf $BENCH_ROOT/seq-out $BENCH_ROOT/seq-state; mkdir -p $BENCH_ROOT/seq-out
  (cd $BENCH_ROOT && nohup $NZBFAST serve --config $NFCONF --connections $CONNS \
      --port $NF_PORT --bind 127.0.0.1 --out seq-out > $BENCH_ROOT/leg6.$1.log 2>&1 &)
  sleep 4
  nf_add() { curl -s -F "name=@$1" "http://127.0.0.1:$NF_PORT/api?mode=addfile" > /dev/null; }
  for i in $(seq 1 $N); do one_job nf_done nf_add $1 $zs[$i] $i; done
  summary $1 $BENCH_ROOT/seq-out
  pkill -f "nzbfast serve.*--port $NF_PORT"
  ;;
nzbget)
  have_ng || { skip nzbget "set NZBGET= and NGCONF="; exit 0; }
  pkill -f "$NZBGET"; sleep 2
  rm -rf $NGDATA/dst $NGDATA/inter $NGDATA/queue
  $NZBGET -c $NGCONF ${=NGOPTS} $(for i in $(seq 1 $NG_NSERVERS); do print -n " -o Server$i.Connections=$CONNS"; done) -o DupeCheck=no ${=NGEXTRA} -D; sleep 3
  ng_add() { $NZBGET -c $NGCONF ${=NGOPTS} -o DupeCheck=no ${=NGEXTRA} -A $1 > /dev/null 2>&1; }
  for i in $(seq 1 $N); do one_job ng_done ng_add nzbget $zs[$i] $i; done
  summary nzbget $NGDATA/dst
  pkill -f "$NZBGET"
  ;;
sab)
  have_sab || { skip sab "set SAB_CMD= and SAB_INI="; exit 0; }
  pkill -f "$SAB_CMD"; sleep 2
  rm -rf $SABDATA/complete $SABDATA/incomplete
  mkdir -p $SABDATA/complete $SABDATA/incomplete
  nohup $SAB_CMD -f $SAB_INI > $BENCH_ROOT/sab.out 2>&1 &
  sleep 10
  # Start from a known-empty history so the capped page cannot saturate.
  curl -s "http://127.0.0.1:$SAB_PORT/api?mode=history&name=delete&value=all&del_files=1&apikey=$SAB_APIKEY" >/dev/null
  sleep 2
  sab_add() { curl -s -F "name=@$1" "http://127.0.0.1:$SAB_PORT/api?mode=addfile&apikey=$SAB_APIKEY" > /dev/null; }
  for i in $(seq 1 $N); do one_job sab_done sab_add sab $zs[$i] $i; done
  summary sab $SABDATA/complete
  curl -s "http://127.0.0.1:$SAB_PORT/api?mode=shutdown&apikey=$SAB_APIKEY" >/dev/null
  ;;
rustnzb)
  have_rn || { skip rustnzb "set RUSTNZB= and RUSTNZB_TOML="; exit 0; }
  pkill -f "$RUSTNZB"; sleep 2
  rm -rf $RNDATA/complete $RNDATA/incomplete $RNDATA/data
  mkdir -p $RNDATA/complete $RNDATA/incomplete $RNDATA/data
  nohup $RUSTNZB -c $RUSTNZB_TOML > $BENCH_ROOT/leg6.rustnzb.log 2>&1 &
  sleep 5
  rn_add() { curl -s -F "name=@$1" "http://127.0.0.1:$RN_PORT/api?mode=addfile" > /dev/null; }
  for i in $(seq 1 $N); do one_job rn_done rn_add rustnzb $zs[$i] $i; done
  summary rustnzb $RNDATA/complete
  pkill -f "$RUSTNZB"
  ;;
*) echo "usage: NZBDIR=... sequential.sh <nzbfast|nzbfast-cold|nzbget|sab|rustnzb>"; exit 2;;
esac

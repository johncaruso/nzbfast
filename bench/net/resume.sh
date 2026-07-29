#!/bin/zsh
# resume.sh - kill -9 mid-job, restart, measure re-downloaded bytes.
# The metric is phase2_gb: how much a client re-fetches after a hard
# crash tells you how good its on-disk resume state is.
#
#   NZB=... [KILL_AT_GB=15] [TIMEOUT=...] ./resume.sh <client>
#
# Prints: LEG4 <client> phase1_s=<s> phase1_gb=<GB> phase2_s=<s> phase2_gb=<GB> total_gb=<GB> status=<st>
set -u
cd "$(dirname "$0")"
source ./lib.sh

NZB=${NZB:?set NZB=/path/to/job.nzb}
[[ -f $NZB ]] || { echo "ABORT missing NZB: $NZB"; exit 1; }
KILL_AT_GB=${KILL_AT_GB:-15}

wait_gb() { # $1 b0 - poll until KILL_AT_GB reached
  while true; do
    sleep 2
    local cur=$(ib)
    (( cur - $1 > KILL_AT_GB * 1073741824 )) && return 0
    (( $(date +%s) - T0 > TIMEOUT )) && return 1
  done
}

case "${1:-}" in
nzbfast)
  have_nf || { skip nzbfast "set NZBFAST="; exit 0; }
  rm -rf $BENCH_ROOT/k9-out
  T0=$(date +%s); b0=$(ib)
  (cd $BENCH_ROOT && $NZBFAST get $NZB ${NFCONF:+--config} ${NFCONF:+$NFCONF} --out k9-out --connections $CONNS --window 4 --decoders 8 > $BENCH_ROOT/leg4.nzbfast.log 2>&1) &
  wait_gb $b0
  pkill -9 -f "nzbfast get $NZB"; wait 2>/dev/null
  t1=$(date +%s); b1=$(ib)
  (cd $BENCH_ROOT && $NZBFAST get $NZB ${NFCONF:+--config} ${NFCONF:+$NFCONF} --out k9-out --connections $CONNS --window 4 --decoders 8 >> $BENCH_ROOT/leg4.nzbfast.log 2>&1)
  st=$?
  t2=$(date +%s); b2=$(ib)
  echo "LEG4 nzbfast phase1_s=$((t1-T0)) phase1_gb=$(gb $b0 $b1) phase2_s=$((t2-t1)) phase2_gb=$(gb $b1 $b2) total_gb=$(gb $b0 $b2) status=rc=$st"
  ;;
nzbget)
  have_ng || { skip nzbget "set NZBGET= and NGCONF="; exit 0; }
  # daemon with FlushQueue=yes for its best crash-resume behavior
  pkill -f "$NZBGET"; sleep 2
  rm -rf $NGDATA/dst $NGDATA/inter $NGDATA/queue
  $NZBGET -c $NGCONF ${=NGOPTS} -o FlushQueue=yes -D; sleep 3
  before=$(ng_done)
  T0=$(date +%s); b0=$(ib)
  $NZBGET -c $NGCONF ${=NGOPTS} -o FlushQueue=yes -A $NZB > /dev/null 2>&1
  wait_gb $b0
  pkill -9 -f "$NZBGET"; sleep 2
  t1=$(date +%s); b1=$(ib)
  $NZBGET -c $NGCONF ${=NGOPTS} -o FlushQueue=yes -D; sleep 3
  st=$(wait_past ng_done $before $(date +%s))
  t2=$(date +%s); b2=$(ib)
  echo "LEG4 nzbget phase1_s=$((t1-T0)) phase1_gb=$(gb $b0 $b1) phase2_s=$((t2-t1)) phase2_gb=$(gb $b1 $b2) total_gb=$(gb $b0 $b2) status=$st"
  pkill -f "$NZBGET"
  ;;
sab)
  have_sab || { skip sab "set SAB_CMD= and SAB_INI="; exit 0; }
  pkill -f "$SAB_CMD"; sleep 2
  rm -rf $SABDATA/complete $SABDATA/incomplete $SABDATA/admin; mkdir -p $SABDATA/complete $SABDATA/incomplete
  nohup $SAB_CMD -f $SAB_INI > $BENCH_ROOT/sab.out 2>&1 &
  sleep 10
  before=$(sab_done)
  T0=$(date +%s); b0=$(ib)
  curl -s -F "name=@$NZB" "http://127.0.0.1:$SAB_PORT/api?mode=addfile&apikey=$SAB_APIKEY" > /dev/null
  wait_gb $b0
  pkill -9 -f "$SAB_CMD"; sleep 2
  t1=$(date +%s); b1=$(ib)
  nohup $SAB_CMD -f $SAB_INI > $BENCH_ROOT/sab.out 2>&1 &
  sleep 10
  st=$(wait_past sab_done $before $(date +%s))
  t2=$(date +%s); b2=$(ib)
  echo "LEG4 sab phase1_s=$((t1-T0)) phase1_gb=$(gb $b0 $b1) phase2_s=$((t2-t1)) phase2_gb=$(gb $b1 $b2) total_gb=$(gb $b0 $b2) status=$st"
  curl -s "http://127.0.0.1:$SAB_PORT/api?mode=shutdown&apikey=$SAB_APIKEY" >/dev/null
  ;;
rustnzb)
  have_rn || { skip rustnzb "set RUSTNZB= and RUSTNZB_TOML="; exit 0; }
  pkill -f "$RUSTNZB"; sleep 2
  rm -rf $RNDATA/complete $RNDATA/incomplete $RNDATA/data; mkdir -p $RNDATA/complete $RNDATA/incomplete $RNDATA/data
  nohup $RUSTNZB -c $RUSTNZB_TOML > $BENCH_ROOT/rustnzb.out 2>&1 &
  sleep 5
  before=$(rn_done)
  T0=$(date +%s); b0=$(ib)
  curl -s -F "name=@$NZB" "http://127.0.0.1:$RN_PORT/api?mode=addfile" > /dev/null
  wait_gb $b0
  pkill -9 -f "$RUSTNZB"; sleep 2
  t1=$(date +%s); b1=$(ib)
  nohup $RUSTNZB -c $RUSTNZB_TOML > $BENCH_ROOT/rustnzb.out 2>&1 &
  sleep 5
  st=$(wait_past rn_done $before $(date +%s))
  t2=$(date +%s); b2=$(ib)
  echo "LEG4 rustnzb phase1_s=$((t1-T0)) phase1_gb=$(gb $b0 $b1) phase2_s=$((t2-t1)) phase2_gb=$(gb $b1 $b2) total_gb=$(gb $b0 $b2) status=$st"
  pkill -f "$RUSTNZB"
  ;;
*) echo "usage: NZB=... resume.sh <nzbfast|nzbget|sab|rustnzb>"; exit 2 ;;
esac

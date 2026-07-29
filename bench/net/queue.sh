#!/bin/zsh
# queue.sh - multi-job queue soak. Adds 3 NZBs at t0, waits for all 3 to
# reach history. A rate time-series (epoch rx-bytes, 2 s cadence) is
# written to $BENCH_ROOT/rate.<client>.log for plotting.
#
#   NZB1=... NZB2=... NZB3=... [TIMEOUT=...] ./queue.sh <client>
#
# Prints: LEG5 <client> wall_s=<s> gbytes=<GB> status=<st>
set -u
cd "$(dirname "$0")"
source ./lib.sh

NZB1=${NZB1:?set NZB1=}; NZB2=${NZB2:?set NZB2=}; NZB3=${NZB3:?set NZB3=}
# A missing NZB makes the addfile silently no-op, so the wait-for-3 loop
# can never finish. Abort instead. Note gbytes below is the WHOLE
# interface's rx bytes - anything else downloading on the box lands in
# this leg's number; keep the box quiet.
for z in $NZB1 $NZB2 $NZB3; do
  [[ -f $z ]] || { echo "LEG5 ${1:-?} ABORT missing NZB: $z"; exit 1; }
done

rate_start() { ( while :; do echo "$(date +%s) $(ib)"; sleep 2; done > $BENCH_ROOT/rate.$1.log ) & RATE_PID=$!; }
rate_stop() { kill $RATE_PID 2>/dev/null; }

case "${1:-}" in
nzbfast)
  have_nf || { skip nzbfast "set NZBFAST="; exit 0; }
  [[ -n $NFCONF ]] || { skip nzbfast "set NFCONF= (server config for nzbfast serve)"; exit 0; }
  pkill -f "nzbfast serve.*--port $NF_PORT"; sleep 1
  rm -rf $BENCH_ROOT/soak-out $BENCH_ROOT/soak-state; mkdir -p $BENCH_ROOT/soak-out
  (cd $BENCH_ROOT && nohup $NZBFAST serve --config $NFCONF --connections $CONNS --port $NF_PORT --bind 127.0.0.1 --out soak-out > $BENCH_ROOT/leg5.nzbfast.log 2>&1 &)
  sleep 4
  T0=$(date +%s); b0=$(ib); rate_start nzbfast
  for z in $NZB1 $NZB2 $NZB3; do curl -s -F "name=@$z" "http://127.0.0.1:$NF_PORT/api?mode=addfile" > /dev/null; done
  st=$(wait_n nf_done 3)
  t1=$(date +%s); b1=$(ib); rate_stop
  echo "LEG5 nzbfast wall_s=$((t1-T0)) gbytes=$(gb $b0 $b1) status=$st"
  pkill -f "nzbfast serve.*--port $NF_PORT"
  ;;
nzbget)
  have_ng || { skip nzbget "set NZBGET= and NGCONF="; exit 0; }
  pkill -f "$NZBGET"; sleep 2
  rm -rf $NGDATA/dst $NGDATA/inter $NGDATA/queue
  $NZBGET -c $NGCONF ${=NGOPTS} -D; sleep 3
  before=$(ng_done)
  T0=$(date +%s); b0=$(ib); rate_start nzbget
  for z in $NZB1 $NZB2 $NZB3; do $NZBGET -c $NGCONF ${=NGOPTS} -A $z > /dev/null 2>&1; done
  st=$(wait_n ng_done $((before+3)))
  t1=$(date +%s); b1=$(ib); rate_stop
  echo "LEG5 nzbget wall_s=$((t1-T0)) gbytes=$(gb $b0 $b1) status=$st"
  pkill -f "$NZBGET"
  ;;
sab)
  have_sab || { skip sab "set SAB_CMD= and SAB_INI="; exit 0; }
  pkill -f "$SAB_CMD"; sleep 2
  rm -rf $SABDATA/complete $SABDATA/incomplete; mkdir -p $SABDATA/complete $SABDATA/incomplete
  nohup $SAB_CMD -f $SAB_INI > $BENCH_ROOT/sab.out 2>&1 &
  sleep 10
  before=$(sab_done)
  T0=$(date +%s); b0=$(ib); rate_start sab
  for z in $NZB1 $NZB2 $NZB3; do curl -s -F "name=@$z" "http://127.0.0.1:$SAB_PORT/api?mode=addfile&apikey=$SAB_APIKEY" > /dev/null; done
  st=$(wait_n sab_done $((before+3)))
  t1=$(date +%s); b1=$(ib); rate_stop
  echo "LEG5 sab wall_s=$((t1-T0)) gbytes=$(gb $b0 $b1) status=$st"
  curl -s "http://127.0.0.1:$SAB_PORT/api?mode=shutdown&apikey=$SAB_APIKEY" >/dev/null
  ;;
rustnzb)
  have_rn || { skip rustnzb "set RUSTNZB= and RUSTNZB_TOML="; exit 0; }
  pkill -f "$RUSTNZB"; sleep 2
  rm -rf $RNDATA/complete $RNDATA/incomplete $RNDATA/data; mkdir -p $RNDATA/complete $RNDATA/incomplete $RNDATA/data
  nohup $RUSTNZB -c $RUSTNZB_TOML > $BENCH_ROOT/rustnzb.out 2>&1 &
  sleep 5
  before=$(rn_done)
  T0=$(date +%s); b0=$(ib); rate_start rustnzb
  for z in $NZB1 $NZB2 $NZB3; do curl -s -F "name=@$z" "http://127.0.0.1:$RN_PORT/api?mode=addfile" > /dev/null; done
  st=$(wait_n rn_done $((before+3)))
  t1=$(date +%s); b1=$(ib); rate_stop
  echo "LEG5 rustnzb wall_s=$((t1-T0)) gbytes=$(gb $b0 $b1) status=$st"
  pkill -f "$RUSTNZB"
  ;;
*) echo "usage: NZB1= NZB2= NZB3= queue.sh <nzbfast|nzbget|sab|rustnzb>"; exit 2 ;;
esac

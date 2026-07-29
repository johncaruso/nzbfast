#!/bin/zsh
# throughput.sh - competitive single-job driver (nzbfast / nzbget / sab
# / rustnzb). One leg prints one TSV line:
#   LEG <client> <tag> wall_s=<s> gbytes=<GB-in> rsspeak_mb=<MB> status=<st> out=<biggest file>
#
#   NZB=/path/to/job.nzb [TAG=label] [TIMEOUT=secs] ./throughput.sh <client|round|stopall>
#
# gbytes is the interface's rx delta (ground truth); clientgb is what the
# client itself accounted. If the interface saw >5% more than the client,
# the NIC was shared with unrelated traffic and the leg is flagged
# contaminated - rerun it on a quiet box.
set -u
cd "$(dirname "$0")"
source ./lib.sh

NZB=${NZB:-}
TAG=${TAG:-run}
if [[ "${1:-}" != "stopall" ]]; then
  [[ -n $NZB ]] || { echo "ABORT: set NZB=/path/to/job.nzb"; exit 1; }
  [[ -f $NZB ]] || { echo "ABORT missing NZB: $NZB"; exit 1; }
fi

# ---------- client-accounted bytes (cross-check vs iface delta) ----------
# nzbfast: sum the per-server "host  5369.3 MB · 8 conns, 0 reconnects" lines.
nf_client_bytes() { awk '$3=="MB" && /conns/ {s+=$2} END{printf "%.0f", s*1048576}' $BENCH_ROOT/leg.nzbfast.log; }
# nzbget: newest history entry, exact bytes from DownloadedSizeHi*2^32+Lo.
ng_client_bytes() {
  local h=$(curl -s http://127.0.0.1:$NG_PORT/jsonrpc/history)
  local lo=$(echo "$h" | grep -oE '"DownloadedSizeLo" : [0-9]+' | head -1 | grep -oE '[0-9]+$')
  local hi=$(echo "$h" | grep -oE '"DownloadedSizeHi" : [0-9]+' | head -1 | grep -oE '[0-9]+$')
  echo $(( ${hi:-0} * 4294967296 + ${lo:-0} ))
}
# sab: newest history slot's "bytes" (job size - SAB exposes no downloaded-bytes field).
sab_client_bytes() {
  curl -s "http://127.0.0.1:$SAB_PORT/api?mode=history&apikey=$SAB_APIKEY&output=json" \
    | grep -oE '"bytes": ?[0-9]+' | head -1 | grep -oE '[0-9]+$'
}

report() { # client status rssfile outdir t0 t1 b0 b1 extra [client_bytes]
  local rss=0; [[ -f $3 ]] && rss=$(cat $3)
  local big=$(find $4 -type f -size +50M 2>/dev/null | head -1)
  local sz=""; [[ -n "$big" ]] && sz="$(du -g "$big" 2>/dev/null | cut -f1)G:${big:t}"
  local line="LEG $1 $TAG wall_s=$((${6}-${5})) gbytes=$(( (${8}-${7}) / 1073741824 )).$((( (${8}-${7}) % 1073741824) * 10 / 1073741824 )) rsspeak_mb=$((rss/1024)) status=$2 out=$sz $9"
  # appended fields only - the LEG format stays backward-compatible
  local cb=${10:-0} ifb=$(( ${8} - ${7} ))
  if (( cb > 0 )); then
    line="$line clientgb=$((cb/1073741824)).$(((cb%1073741824)*10/1073741824))"
    # iface > client-accounted by >5% => NIC shared with unrelated traffic
    (( ifb * 100 > cb * 105 )) && line="$line WARN=iface_exceeds_client:+$(( (ifb-cb)*100/cb ))%"
  fi
  echo "$line"
}

# ---------- legs ----------
leg_nzbfast() {
  have_nf || { skip nzbfast "set NZBFAST="; return; }
  rm -rf $BENCH_ROOT/nf-out
  local rssf=$BENCH_ROOT/rss.nzbfast b0=$(ib) t0=$(date +%s)
  sampler_start $rssf "nzbfast get"
  (cd $BENCH_ROOT && $NZBFAST get $NZB ${NFCONF:+--config} ${NFCONF:+$NFCONF} --out nf-out --connections $CONNS --window 4 --decoders 8 > $BENCH_ROOT/leg.nzbfast.log 2>&1)
  local st=$?
  local t1=$(date +%s) b1=$(ib)
  sampler_stop
  report nzbfast rc=$st $rssf $BENCH_ROOT/nf-out $t0 $t1 $b0 $b1 "$(grep -E '^mem:' $BENCH_ROOT/leg.nzbfast.log | tail -1)" $(nf_client_bytes)
}

leg_nzbget() {
  have_ng || { skip nzbget "set NZBGET= and NGCONF="; return; }
  start_ng
  rm -rf $NGDATA/dst $NGDATA/inter
  local rssf=$BENCH_ROOT/rss.ng before=$(ng_done) b0=$(ib) t0=$(date +%s)
  sampler_start $rssf "$NZBGET" "(unrar|7za)" "par2"
  $NZBGET -c $NGCONF ${=NGOPTS} -A $NZB > /dev/null 2>&1
  local st=$(wait_past ng_done $before $t0)
  local t1=$(date +%s) b1=$(ib)
  sampler_stop
  local hs=$(curl -s http://127.0.0.1:$NG_PORT/jsonrpc/history | grep -o '"Status" : "[^"]*"' | head -1 | tr -d '" ' )
  report nzbget "$st:$hs" $rssf $NGDATA/dst $t0 $t1 $b0 $b1 "" $(ng_client_bytes)
}

leg_sab() {
  have_sab || { skip sab "set SAB_CMD= and SAB_INI="; return; }
  start_sab
  rm -rf $SABDATA/complete $SABDATA/incomplete; mkdir -p $SABDATA/complete $SABDATA/incomplete
  local rssf=$BENCH_ROOT/rss.sab before=$(sab_done) b0=$(ib) t0=$(date +%s)
  sampler_start $rssf "$SAB_CMD" "par2" "unrar"
  curl -s -F "name=@$NZB" "http://127.0.0.1:$SAB_PORT/api?mode=addfile&apikey=$SAB_APIKEY" > /dev/null
  local st=$(wait_past sab_done $before $t0)
  local t1=$(date +%s) b1=$(ib)
  sampler_stop
  report sab $st $rssf $SABDATA/complete $t0 $t1 $b0 $b1 "" $(sab_client_bytes)
}

leg_rustnzb() {
  have_rn || { skip rustnzb "set RUSTNZB= and RUSTNZB_TOML="; return; }
  start_rn
  rm -rf $RNDATA/complete $RNDATA/incomplete; mkdir -p $RNDATA/complete $RNDATA/incomplete
  local rssf=$BENCH_ROOT/rss.rn before=$(rn_done) b0=$(ib) t0=$(date +%s)
  sampler_start $rssf "$RUSTNZB" "unrar" "7z"
  curl -s -F "name=@$NZB" "http://127.0.0.1:$RN_PORT/api?mode=addfile" > /dev/null
  local st=$(wait_past rn_done $before $t0)
  local t1=$(date +%s) b1=$(ib)
  sampler_stop
  report rustnzb $st $rssf $RNDATA/complete $t0 $t1 $b0 $b1 ""
}

case "${1:-}" in
  nzbfast) leg_nzbfast ;;
  nzbget)  leg_nzbget ;;
  sab)     leg_sab ;;
  rustnzb) leg_rustnzb ;;
  round)   leg_nzbfast; leg_nzbget; leg_sab; leg_rustnzb ;;
  stopall) stop_ng; stop_sab; stop_rn ;;
  *) echo "usage: NZB=... throughput.sh nzbfast|nzbget|sab|rustnzb|round|stopall" ;;
esac

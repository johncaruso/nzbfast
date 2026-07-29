# lib.sh - shared config + helpers for the real-network bench drivers.
# Sourced by throughput.sh / resume.sh / queue.sh / sequential.sh.
# Everything is overridable from the environment; see README.md.
#
# These drivers measure real downloads from YOUR news server(s), with
# YOUR account, against NZBs YOU supply. Nothing here embeds a provider,
# a hostname, or a credential - each client reads its own config file.

# Where per-leg work dirs and logs live
BENCH_ROOT=${BENCH_ROOT:-$PWD/bench-run}
mkdir -p "$BENCH_ROOT"

# ---- clients (a leg whose binary/config is missing is skipped) -------
NZBFAST=${NZBFAST:-$(command -v nzbfast || true)}
NFCONF=${NFCONF:-}          # nzbfast config (server list) for `serve` legs
NZBGET=${NZBGET:-$(command -v nzbget || true)}
NGCONF=${NGCONF:-}          # nzbget config file
NGOPTS=${NGOPTS:-}          # extra nzbget -o overrides (space-separated)
SAB_CMD=${SAB_CMD:-}        # e.g. /Applications/SABnzbd.app/Contents/MacOS/SABnzbd
SAB_INI=${SAB_INI:-}        # SABnzbd ini (must set api_key = $SAB_APIKEY)
SAB_APIKEY=${SAB_APIKEY:-harnesskey}
RUSTNZB=${RUSTNZB:-}
RUSTNZB_TOML=${RUSTNZB_TOML:-}

# ---- ports (must match the client configs) ---------------------------
NG_PORT=${NG_PORT:-6791}
SAB_PORT=${SAB_PORT:-8085}
RN_PORT=${RN_PORT:-9090}
NF_PORT=${NF_PORT:-6799}

TIMEOUT=${TIMEOUT:-3600}
# Connections PER SERVER, identical for every client (nzbfast's
# --connections, NZBGet's ServerN.Connections and SAB's per-server
# `connections` are all per-server counts, so this is what makes the
# arms comparable).
CONNS=${CONNS:-8}

# ---- interface byte counter (downloaded-bytes ground truth) ----------
# The whole interface's rx bytes: anything else downloading on the box
# lands in the leg's number. Keep the box quiet during a leg.
if [[ "$(uname)" == "Darwin" ]]; then
  IFACE=${IFACE:-$(route -n get default 2>/dev/null | awk '/interface/{print $2}')}
  ib() { netstat -ibn -I $IFACE | awk 'NR==2{print $7}'; }
else
  IFACE=${IFACE:-$(ip route show default 2>/dev/null | awk '{for(i=1;i<NF;i++) if($i=="dev"){print $(i+1); exit}}')}
  ib() { cat /sys/class/net/$IFACE/statistics/rx_bytes; }
fi
[[ -n "${IFACE:-}" ]] || { echo "ABORT: could not detect default interface; set IFACE=" >&2; exit 1; }

gb() { echo $(( ($2 - $1) / 1073741824 )).$(( (($2 - $1) % 1073741824) * 10 / 1073741824 )); }

# ---- history polls ---------------------------------------------------
# The status regex must tolerate whitespace after the colon, and must
# COUNT OCCURRENCES, not matching lines: these APIs return the whole
# history as ONE line of JSON, so `grep -c` answers 1 no matter how many
# jobs finished. And the history endpoint must be asked for ENOUGH slots
# (SAB pages at 10 by default) or the count saturates and every job
# "times out" while the client is actually finishing them in seconds.
# Symptom to recognise: completions spaced exactly TIMEOUT apart.
DONE_RE='"status":[[:space:]]*"(Completed|Failed)"'
count_done() { command grep -oE "$DONE_RE" | wc -l | tr -d " "; }
ng_done()  { curl -s "http://127.0.0.1:$NG_PORT/jsonrpc/history" | grep -c '"NZBName"'; }
sab_done() { curl -s "http://127.0.0.1:$SAB_PORT/api?mode=history&apikey=$SAB_APIKEY&output=json&limit=500" | count_done; }
rn_done()  { curl -s "http://127.0.0.1:$RN_PORT/api?mode=history&output=json" | count_done; }
nf_done()  { curl -s "http://127.0.0.1:$NF_PORT/api?mode=history&output=json" | count_done; }

wait_past() { # $1 done-fn, $2 before-count, $3 t0 - one more completion or timeout
  while true; do
    sleep 2
    [[ $($1) -gt $2 ]] && { echo done; return; }
    [[ $(( $(date +%s) - $3 )) -gt $TIMEOUT ]] && { echo timeout; return; }
  done
}
wait_n() { # $1 done-fn, $2 target count
  local t0=$(date +%s)
  while true; do
    sleep 2
    [[ $($1) -ge $2 ]] && { echo done; return; }
    (( $(date +%s) - t0 > TIMEOUT )) && { echo timeout; return; }
  done
}

# ---- daemons ---------------------------------------------------------
have_ng()  { [[ -n "$NZBGET" && -n "$NGCONF" ]]; }
have_sab() { [[ -n "$SAB_CMD" && -n "$SAB_INI" ]]; }
have_rn()  { [[ -n "$RUSTNZB" && -n "$RUSTNZB_TOML" ]]; }
have_nf()  { [[ -n "$NZBFAST" ]]; }
skip() { echo "LEG $1 SKIP: $2"; }

NGDATA=$BENCH_ROOT/ngdata
SABDATA=$BENCH_ROOT/sabdata
RNDATA=$BENCH_ROOT/rustnzbdata

# Every pkill goes through kill_client: pkill -f with an empty pattern
# matches EVERY process on the box, so an unset client var must be a
# no-op, never a bare pkill.
kill_client() { [[ -n "${1:-}" ]] && pkill ${2:-} -f "$1" 2>/dev/null; true; }

start_ng()  { pgrep -f "$NZBGET" >/dev/null || { $NZBGET -c $NGCONF ${=NGOPTS} "$@" -D; sleep 3; } }
stop_ng()   { have_ng || return 0; $NZBGET -c $NGCONF ${=NGOPTS} -Q >/dev/null 2>&1; sleep 2; kill_client "$NZBGET"; }
start_sab() { pgrep -f "$SAB_CMD" >/dev/null || { nohup $SAB_CMD -f $SAB_INI > $BENCH_ROOT/sab.out 2>&1 & sleep 10; } }
stop_sab()  { have_sab || return 0; curl -s "http://127.0.0.1:$SAB_PORT/api?mode=shutdown&apikey=$SAB_APIKEY" >/dev/null; sleep 4; kill_client "$SAB_CMD"; }
start_rn()  { pgrep -f "$RUSTNZB" >/dev/null || { nohup $RUSTNZB -c $RUSTNZB_TOML > $BENCH_ROOT/rustnzb.out 2>&1 & sleep 5; } }
stop_rn()   { have_rn || return 0; kill_client "$RUSTNZB"; sleep 2; }

# ---- process-tree RSS sampler ----------------------------------------
SAMPLER=${SAMPLER:-$(dirname $0)/rss_sampler.py}
sampler_start() { # $1 outfile, rest: ps command-line patterns
  local f=$1; shift
  rm -f $f
  python3 $SAMPLER $f "$@" &
  SAMPLER_PID=$!
}
sampler_stop() { kill $SAMPLER_PID 2>/dev/null; wait $SAMPLER_PID 2>/dev/null; }

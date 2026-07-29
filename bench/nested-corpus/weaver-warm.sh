#!/bin/zsh
# Weaver at its BEST: persistent daemon, warmed connection ramp + tuner,
# job submitted over its nzbget-compat JSON-RPC. Weaver auto-ramps its
# connection count (up to 120) and warms pools on the FIRST job, so the
# one-shot `weaver download` CLI measures a client that is still climbing
# - unfair. This warms the daemon on a throwaway pass first, then measures.
#
#   WEAVER=/path/to/weaver weaver-warm.sh <legdir> <nzbserve-port>
#
# Env: WEAVER  path to the weaver binary (required)
#      WARMDIR work dir for this run (default: ./wv-warm next to this script)
set -u
LEG=${1:?legdir}; PORT=${2:-11920}
LEG=${LEG:A}   # absolute, so the cd below can't break it
LEGNAME=$(basename "$LEG")
NZB=$LEG/$LEGNAME.nzb
WEAVER=${WEAVER:?set WEAVER to the weaver binary path}
WEAVER_NAME=$(basename "$WEAVER")
cd "$(dirname "$0")"
W=${WARMDIR:-$PWD/wv-warm}
WPORT=9096

pkill -9 -f "$WEAVER_NAME" 2>/dev/null; sleep 1
rm -rf "$W"; mkdir -p "$W/data" "$W/inter" "$W/complete"

./nzbserve/target/release/nzbserve serve "$LEG" --port $PORT > "$W/nzbserve.log" 2>&1 &
SRV=$!
until nc -z 127.0.0.1 $PORT 2>/dev/null; do sleep 0.3; done

export RUST_LOG=info
export WEAVER_ENCRYPTION_KEY="$(openssl rand -base64 32)"
export WEAVER_DATA_DIR=$W/data
export WEAVER_INTERMEDIATE_DIR=$W/inter
export WEAVER_COMPLETE_DIR=$W/complete
export WEAVER_CLEANUP_AFTER_EXTRACT=true
export WEAVER_SERVER_1_HOSTNAME=127.0.0.1
export WEAVER_SERVER_1_PORT=$PORT
export WEAVER_SERVER_1_TLS=false
export WEAVER_SERVER_1_USERNAME=""
export WEAVER_SERVER_1_PASSWORD=""
# Give the ramp room to climb: its ceiling is total configured
# connections, and the tuner is the thing we are warming.
export WEAVER_SERVER_1_CONNECTIONS=120
export WEAVER_SERVER_1_ACTIVE=true

(cd "$W" && nohup "$WEAVER" serve --port $WPORT > "$W/weaver.out" 2>&1 &)

for _ in {1..30}; do curl -s -o /dev/null --max-time 3 http://127.0.0.1:$WPORT/ && break; sleep 1; done
TOKEN=$(curl -s -D - -o /dev/null http://127.0.0.1:$WPORT/ \
  | awk -F'[=;]' 'tolower($0) ~ /^set-cookie: *weaver_session/{print $2; exit}')
if [[ -z "${TOKEN:-}" ]]; then
  curl -s -c "$W/cookies" http://127.0.0.1:$WPORT/ > /dev/null
  TOKEN=$(awk '/weaver_session/{print $NF}' "$W/cookies" | tail -1)
fi
[[ -n "${TOKEN:-}" ]] || { echo "RESULT weaver status=no-token"; pkill -9 -f "$WEAVER_NAME"; kill $SRV; exit 1; }

rpc() { curl -s -u "nzbget:$TOKEN" -H 'Content-Type: application/json' --data-binary @"$1" http://127.0.0.1:$WPORT/jsonrpc; }
mkjson() { b64=$(base64 < "$1" | tr -d '\n')
  print -r -- "{\"method\":\"append\",\"params\":[\"${1:t}\",\"$b64\",\"\",0,false,false,\"\",0,\"FORCE\"],\"id\":1}" > "$2"; }
hist() { print -r -- '{"method":"history","params":[],"id":2}' > "$W/h.json"
  rpc "$W/h.json" | grep -o -i '"nzbname"' | wc -l | tr -d ' '; }

vcheck=$(curl -s -u "nzbget:$TOKEN" -H 'Content-Type: application/json' \
  --data '{"method":"version","params":[],"id":0}' http://127.0.0.1:$WPORT/jsonrpc)
[[ "$vcheck" == *'"result"'* ]] || { echo "RESULT weaver status=auth-failed"; pkill -9 -f "$WEAVER_NAME"; kill $SRV; exit 1; }

# ---- WARM PASS: same NZB, discarded. Climbs the ramp + warms pools ----
mkjson "$NZB" "$W/warm.json"; rpc "$W/warm.json" > "$W/warm.resp"
tw0=$(date +%s)
while [[ $(hist) -lt 1 ]]; do
    sleep 3
    [[ $(( $(date +%s) - tw0 )) -gt 900 ]] && { echo "RESULT weaver status=warmup-timeout"; pkill -9 -f "$WEAVER_NAME"; kill $SRV; exit 1; }
done
WARM_S=$(( $(date +%s) - tw0 ))
# let the ramp plateau (ANSI codes sit inside the key, so strip them)
for _ in {1..60}; do
    perl -pe 's/\e\[[0-9;]*m//g' "$W/weaver.out" | grep -q "connection_ramp=120" && break
    sleep 5
done
RAMP=$(perl -pe 's/\e\[[0-9;]*m//g' "$W/weaver.out" | grep -o "connection_ramp=[0-9]*" | tail -1)
rm -rf "$W/complete"/*; sleep 2

# ---- MEASURED PASS: warm daemon, ramp already climbed ----------------
# Disk HIGH-WATER, polled - not a single du at the end. Weaver deletes
# its volumes after extract (WEAVER_CLEANUP_AFTER_EXTRACT), so a final
# du reports the tidied-up aftermath (~content size) and would wrongly
# suggest one-pass streaming. The peak is what says whether volumes were
# materialised. Same 0.5 s cadence as run-legs.sh du_start.
: > "$W/hiwater"
( while :; do
    k=$(du -sk "$W" 2>/dev/null | cut -f1)
    [[ -n ${k:-} ]] && {
        cur=$(cat "$W/hiwater" 2>/dev/null)
        [[ -z ${cur:-} || $k -gt ${cur:-0} ]] && echo "$k" > "$W/hiwater"
    }
    sleep 0.5
  done ) &
DU=$!
before=$(hist)
t0=$(date +%s)
mkjson "$NZB" "$W/run.json"; rpc "$W/run.json" > "$W/run.resp"
while [[ $(hist) -le $before ]]; do
    sleep 2
    [[ $(( $(date +%s) - t0 )) -gt 900 ]] && { echo "RESULT weaver status=measured-timeout warm_s=$WARM_S ramp=$RAMP"; break; }
done
T=$(( $(date +%s) - t0 ))
kill $DU 2>/dev/null; wait $DU 2>/dev/null
HW=$(cat "$W/hiwater" 2>/dev/null || echo 0)
FINAL=$(du -sk "$W" 2>/dev/null | cut -f1)
echo "RESULT weaver warm_cold_s=$WARM_S warm_measured_s=$T ramp=${RAMP:-unknown} hiwater_mb=$(( HW / 1024 )) final_mb=$(( FINAL / 1024 ))"
echo "--- payloads present ---"
find "$W/complete" -type f \( -iname '*.mkv' -o -iname '*.mp4' -o -iname '*.mov' \) -exec ls -la {} \; 2>/dev/null | awk '{print $5, $NF}'
pkill -9 -f "$WEAVER_NAME" 2>/dev/null; kill $SRV 2>/dev/null
echo "WEAVER_WARM_DONE"

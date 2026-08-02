#!/bin/zsh
# run-legs.sh - drive the nested-corpus legs through the loopback rig,
# nzbfast vs nzbget vs SABnzbd vs rustnzb vs Weaver. One LEG result line
# per client per leg (daemon start/append/poll/stop), plus a
# du(1) poller for disk high-water - the number nested extraction is
# supposed to improve.
#
#   ./run-legs.sh <leg-dir|tier-dir|corpus-root> [client ...]
#
# Clients: nzbfast nzbget sab rustnzb weaver (default: "nzbfast nzbget"; a
# client whose binary/env is missing is skipped with a SKIP line).
#
# Env:
#   NZBFAST   nzbfast binary (default ../../target/release/nzbfast)
#   NZBSERVE  rig binary (default ./nzbserve/target/release/nzbserve,
#             auto-built when cargo is available)
#   NZBGET    nzbget binary (default: `command -v nzbget`)
#   SAB_CMD   SABnzbd launcher, e.g.
#             /Applications/SABnzbd.app/Contents/MacOS/SABnzbd
#   RUSTNZB   rustnzb binary
#   WEAVER    weaver binary (one-shot CLI; needs no keychain, see leg_weaver)
#   PORT=11901  CONNS=8  TIMEOUT=1800  STALL=120  OUTROOT=$PWD/corpus-run
#
# One result line per client per leg, appended to $OUTROOT/suite.log:
#   LEG <leg> <client> wall_s=<s> hiwater_mb=<MB> rc=<rc> class=<c> ...
#
# Loopback rig - no providers, no Usenet account, no network access.
#
# ---- FAIRNESS: every client runs at its documented best --------------
# House rule - a competitor must never lose because we failed to
# configure it. What each client is given, and why:
#
#   nzbfast   --connections $CONNS --window 4 --decoders 8. Defaults
#             otherwise (auto memory budget, fast verify).
#   nzbget    ArticleCache=1000, WriteBuffer=1024, DirectWrite=yes,
#             DirectUnpack=yes, ParQuick=yes, ParBuffer=500,
#             ParThreads=0 (auto), UnpackCleanupDisk + NzbCleanupDisk=yes
#             (there is NO ParCleanupDisk option - an invalid option
#             makes NZBGet start fully PAUSED, which reads as 0 MB/s). NOTE: a standalone `-c` config uses
#             NZBGet's BUILT-IN defaults for anything unset (article
#             cache OFF, DirectWrite off) rather than the values in its
#             shipped nzbget.conf - so each must be stated explicitly.
#             Cleanup matters twice: leftovers, and disk high-water.
#   sab       pipelining_requests=8 PER SERVER (SABnzbd ships 1, i.e.
#             unpipelined - the single most valuable setting it has,
#             ~22% on a big job), receive_threads=4, cache_limit=1G,
#             direct_unpack=1, direct_unpack_threads=3.
#   rustnzb   pipelining=4, cache_size=1G, direct_unpack=false. The
#             last one is REQUIRED, not a handicap: its DirectUnpack
#             drives `unrar -vp` prompts that RARLab unrar never emits,
#             and the run hangs.
#   weaver    connections=$CONNS. One-shot `download` CLI; no further
#             documented tuning knobs found. Revisit if its docs grow.
#
# When a setting changes, say so alongside the published numbers - they
# are only defensible if the tuning is auditable.

set -u
cd "$(dirname "$0")"

PORT=${PORT:-11901}
CONNS=${CONNS:-8}
TIMEOUT=${TIMEOUT:-1800}
# A client that stops making progress is hung, not slow. Waiting out the full
# TIMEOUT for it wastes half an hour per leg and tells us nothing extra, so a
# leg whose output tree has not grown for STALL seconds is called and killed.
STALL=${STALL:-120}
OUTROOT=${OUTROOT:-$PWD/corpus-run}
NZBFAST=${NZBFAST:-$PWD/../../target/release/nzbfast}
NZBSERVE=${NZBSERVE:-$PWD/nzbserve/target/release/nzbserve}
NZBGET=${NZBGET:-$(command -v nzbget || true)}
SAB_CMD=${SAB_CMD:-}
RUSTNZB=${RUSTNZB:-}
WEAVER=${WEAVER:-}
NG_PORT=${NG_PORT:-6795}
SAB_PORT=${SAB_PORT:-8086}
RN_PORT=${RN_PORT:-9091}

[[ $# -ge 1 ]] || { echo "usage: run-legs.sh <leg-or-tier-dir> [clients...]" >&2; exit 2; }
ROOT=$1; shift
CLIENTS=(${@:-nzbfast nzbget})
mkdir -p "$OUTROOT"
SUITE=$OUTROOT/suite.log

if [[ ! -x $NZBSERVE ]]; then
    command -v cargo >/dev/null || { echo "nzbserve missing and no cargo" >&2; exit 1; }
    cargo build --release --quiet --manifest-path "$PWD/nzbserve/Cargo.toml"
fi

# ---- helpers ----------------------------------------------------------

now() { date +%s; }
log() { echo "$*" | tee -a "$SUITE"; }

# Disk high-water poller: track max du -sk of a tree, 0.5 s cadence.
# Meaningful on full-size legs; a --quick leg can finish inside one poll.
du_start() { # $1 dir, $2 statefile
    : > "$2"
    ( while :; do
        k=$(du -sk "$1" 2>/dev/null | cut -f1)
        [[ -n ${k:-} ]] && {
            cur=$(cat "$2" 2>/dev/null)
            [[ -z ${cur:-} || $k -gt ${cur:-0} ]] && echo "$k" > "$2"
        }
        sleep 0.5
      done ) &
    DU_PID=$!
}
du_stop() { # $1 statefile -> echoes MB
    kill $DU_PID 2>/dev/null; wait $DU_PID 2>/dev/null
    echo $(( $(cat "$1" 2>/dev/null || echo 0) / 1024 ))
}

# Foreground command with a hard timeout (rc 124 on expiry).
tmo() {
    python3 - "$TIMEOUT" "$@" <<'PY'
import subprocess, sys
t = float(sys.argv[1])
p = subprocess.Popen(sys.argv[2:])
try:
    sys.exit(p.wait(t))
except subprocess.TimeoutExpired:
    p.kill(); p.wait(); sys.exit(124)
PY
}

wait_gone() { # poll fn until it returns >0 or timeout; echoes done|timeout
    local fn=$1 before=$2 t0=$3
    while :; do
        sleep 2
        [[ $($fn) -gt $before ]] && { echo done; return; }
        [[ $(( $(now) - t0 )) -gt $TIMEOUT ]] && { echo timeout; return; }
    done
}

serve_start() { # $1 legdir
    "$NZBSERVE" serve "$1" --port $PORT > "$OUTROOT/nzbserve.log" 2>&1 &
    SRV_PID=$!
    local n=0
    until nc -z 127.0.0.1 $PORT 2>/dev/null; do
        sleep 0.3
        n=$((n+1))
        [[ $n -gt 200 ]] && { echo "nzbserve never came up (see $OUTROOT/nzbserve.log)" >&2; return 1; }
        kill -0 $SRV_PID 2>/dev/null || { echo "nzbserve exited (see $OUTROOT/nzbserve.log)" >&2; return 1; }
    done
}
serve_stop() { kill $SRV_PID 2>/dev/null; wait $SRV_PID 2>/dev/null; }

classify() { # $1 manifest, $2 outdir, $3 rc
    python3 "$PWD/classify.py" "$1" "$2" "$3"
}

# ---- client legs ------------------------------------------------------
# Each leg_<client> gets: $LEGDIR $LEGNAME $NZB $MANIFEST set.

leg_nzbfast() {
    [[ -x $NZBFAST ]] || { log "SKIP $LEGNAME nzbfast (binary not found: $NZBFAST)"; return; }
    local out=$OUTROOT/$LEGNAME/nzbfast
    rm -rf "$out"; mkdir -p "$out"
    printf '{"servers":[{"host":"127.0.0.1","port":%s,"tls":false,"connections":32}]}' $PORT \
        > "$OUTROOT/loopback.json"
    local pw=$(jq -r '.passwords.level1 // empty' "$MANIFEST")
    local pwargs=()
    [[ -n $pw ]] && pwargs=(--password "$pw")
    du_start "$out" "$OUTROOT/du.nzbfast"
    local t0=$(now)
    tmo "$NZBFAST" --config "$OUTROOT/loopback.json" get "$NZB" --out "$out" \
        --connections $CONNS --window 4 --decoders 8 "${pwargs[@]}" \
        > "$OUTROOT/$LEGNAME/nzbfast.log" 2>&1
    local rc=$?
    local t1=$(now)
    local hw=$(du_stop "$OUTROOT/du.nzbfast")
    log "LEG $LEGNAME nzbfast wall_s=$((t1-t0)) hiwater_mb=$hw rc=$rc $(classify "$MANIFEST" "$out" $rc) $(grep -E '^mem:' "$OUTROOT/$LEGNAME/nzbfast.log" | tail -1)"
}

ng_done() { curl -s "http://127.0.0.1:$NG_PORT/jsonrpc/history" | grep -c '"NZBName"'; }

leg_nzbget() {
    [[ -n $NZBGET && -x $NZBGET ]] || { log "SKIP $LEGNAME nzbget (set NZBGET or install nzbget)"; return; }
    local base=$OUTROOT/$LEGNAME/nzbget
    rm -rf "$base"; mkdir -p "$base"
    cat > "$OUTROOT/nzbget-bench.conf" <<EOF
MainDir=$base
DestDir=$base/dst
InterDir=$base/inter
TempDir=$base/tmp
QueueDir=$base/queue
LockFile=$base/lock
LogFile=$base/log
WebDir=
ConfigTemplate=
Server1.Host=127.0.0.1
Server1.Port=$PORT
Server1.Connections=$CONNS
Server1.Encryption=no
ControlIP=127.0.0.1
ControlPort=$NG_PORT
ControlUsername=
ControlPassword=
OutputMode=log
ParCheck=auto
ParRename=yes
RarRename=yes
Unpack=yes
DirectUnpack=yes
DirectWrite=yes
# Perf tuning to NZBGet's documented best. A standalone -c config takes
# NZBGet's BUILT-IN defaults for anything unset (ArticleCache=0,
# DirectWrite=no), NOT the values in its shipped nzbget.conf - so these
# must be stated explicitly or we would be benchmarking it with article
# caching switched off.
ArticleCache=1000
WriteBuffer=1024
ParQuick=yes
ParBuffer=500
ParThreads=0
# Tune NZBGet to its documented best, as the house rule requires: clean
# up archives + par2 after a successful unpack. Without these it leaves
# volumes behind and carries them in its disk high-water, which would be
# our misconfiguration showing up as its result.
UnpackCleanupDisk=yes
NzbCleanupDisk=yes
HealthCheck=none
NzbLog=no
DupeCheck=no
# A standalone -c config also inherits NZBGet's BUILT-IN UnrarCmd="unrar" /
# SevenZipCmd="7z", which resolve against PATH - and the bench boxes have
# neither on PATH, so every leg ended "Could not start unrar: No such file
# or directory" and the whole NZBGet column read manual-intervention on
# shapes it can actually finish (found 2 Aug 2026; the m3 25 Jul round has
# the same fault). Point both at the binaries NZBGet itself ships.
UnrarCmd=${NG_UNRAR:-$(dirname $NZBGET)/unrar}
SevenZipCmd=${NG_7Z:-$(dirname $NZBGET)/7za}
EOF
    "$NZBGET" -c "$OUTROOT/nzbget-bench.conf" -D || { log "LEG $LEGNAME nzbget rc=start-failed class=fail"; return; }
    sleep 2
    local before=$(ng_done)
    du_start "$base" "$OUTROOT/du.ng"
    local t0=$(now)
    "$NZBGET" -c "$OUTROOT/nzbget-bench.conf" -A "$NZB" >/dev/null 2>&1
    local st=$(wait_gone ng_done $before $t0)
    local t1=$(now)
    local hw=$(du_stop "$OUTROOT/du.ng")
    local hs=$(curl -s "http://127.0.0.1:$NG_PORT/jsonrpc/history" | grep -o '"Status" : "[^"]*"' | head -1 | tr -d '" ')
    "$NZBGET" -c "$OUTROOT/nzbget-bench.conf" -Q >/dev/null 2>&1
    sleep 1
    local rc=0; [[ $st == timeout ]] && rc=124
    log "LEG $LEGNAME nzbget wall_s=$((t1-t0)) hiwater_mb=$hw rc=$rc:$hs $(classify "$MANIFEST" "$base/dst" $rc)"
}

sab_done() { curl -s "http://127.0.0.1:$SAB_PORT/api?mode=history&apikey=harnesskey&output=json" | grep -oE '"status": ?"(Completed|Failed)"' | wc -l | tr -d ' '; }

leg_sab() {
    [[ -n $SAB_CMD && -x $SAB_CMD ]] || { log "SKIP $LEGNAME sab (set SAB_CMD to the SABnzbd launcher)"; return; }
    local base=$OUTROOT/$LEGNAME/sab
    rm -rf "$base"; mkdir -p "$base/complete" "$base/incomplete" "$base/admin"
    cat > "$OUTROOT/sabnzbd-bench.ini" <<EOF
[misc]
api_key = harnesskey
nzb_key = harnesskey
port = $SAB_PORT
host = 127.0.0.1
download_dir = $base/incomplete
complete_dir = $base/complete
admin_dir = $base/admin
auto_browser = 0
check_new_rel = 0
# SABnzbd's documented best, mirroring the provider harness. Pipelining
# is the decisive one: SAB SHIPS pipelining_requests=1 (unpipelined),
# and raising it to 8 is worth ~22% on a big job. Leaving it at the
# shipped default would make our result look better than it is.
cache_limit = 1G
receive_threads = 4
direct_unpack = 1
direct_unpack_threads = 3
[servers]
[[loopback]]
host = 127.0.0.1
port = $PORT
connections = $CONNS
ssl = 0
pipelining_requests = 8
enabled = 1
EOF
    nohup "$SAB_CMD" -f "$OUTROOT/sabnzbd-bench.ini" -s 127.0.0.1:$SAB_PORT -b0 \
        > "$OUTROOT/sab.out" 2>&1 &
    local sab_pid=$!
    sleep 8
    # SABnzbd REWRITES its ini on startup and reset our
    # pipelining_requests=8 back to its shipped 1, so the file is not a
    # reliable way to tune it - set it over the API where the value
    # sticks, then read it back and say so. Unpipelined SAB is the single
    # biggest handicap we could accidentally hand it.
    curl -s "http://127.0.0.1:$SAB_PORT/api?mode=set_config&section=servers&keyword=loopback&pipelining_requests=8&apikey=harnesskey&output=json" >/dev/null 2>&1
    curl -s "http://127.0.0.1:$SAB_PORT/api?mode=set_config&section=misc&keyword=receive_threads&value=4&apikey=harnesskey&output=json" >/dev/null 2>&1
    local pipe=$(curl -s "http://127.0.0.1:$SAB_PORT/api?mode=get_config&section=servers&apikey=harnesskey&output=json" 2>/dev/null | tr ',' '\n' | grep -o '"pipelining_requests": *[0-9]*' | grep -o '[0-9]*$' | head -1)
    log "  sab tuning: pipelining_requests=${pipe:-unknown} (SAB ships 1)"
    local before=$(sab_done)
    du_start "$base" "$OUTROOT/du.sab"
    local t0=$(now)
    curl -s -F "name=@$NZB" "http://127.0.0.1:$SAB_PORT/api?mode=addfile&apikey=harnesskey" >/dev/null
    local st=$(wait_gone sab_done $before $t0)
    local t1=$(now)
    local hw=$(du_stop "$OUTROOT/du.sab")
    curl -s "http://127.0.0.1:$SAB_PORT/api?mode=shutdown&apikey=harnesskey" >/dev/null
    sleep 3; kill $sab_pid 2>/dev/null
    local rc=0; [[ $st == timeout ]] && rc=124
    log "LEG $LEGNAME sab wall_s=$((t1-t0)) hiwater_mb=$hw rc=$rc $(classify "$MANIFEST" "$base/complete" $rc)"
}

rn_done() { curl -s "http://127.0.0.1:$RN_PORT/api?mode=history&output=json" | grep -oE '"status": ?"(Completed|Failed)"' | wc -l | tr -d ' '; }

leg_rustnzb() {
    [[ -n $RUSTNZB && -x $RUSTNZB ]] || { log "SKIP $LEGNAME rustnzb (set RUSTNZB)"; return; }
    local base=$OUTROOT/$LEGNAME/rustnzb
    rm -rf "$base"; mkdir -p "$base/complete" "$base/incomplete" "$base/data"
    cat > "$OUTROOT/rustnzb-bench.toml" <<EOF
[general]
listen_addr = "127.0.0.1"
port = $RN_PORT
incomplete_dir = "$base/incomplete"
complete_dir = "$base/complete"
data_dir = "$base/data"
speed_limit_bps = 0
direct_unpack = false
cache_size = 1073741824
log_level = "info"
log_file = "$base/rustnzb.log"

[[servers]]
id = "loopback"
name = "loopback"
host = "127.0.0.1"
port = $PORT
ssl = false
ssl_verify = false
connections = $CONNS
priority = 0
enabled = true
retention = 5000
pipelining = 4
optional = false

[[categories]]
name = "Default"
post_processing = 3
EOF
    nohup "$RUSTNZB" -c "$OUTROOT/rustnzb-bench.toml" > "$OUTROOT/rustnzb.out" 2>&1 &
    local rn_pid=$!
    sleep 5
    local before=$(rn_done)
    du_start "$base" "$OUTROOT/du.rn"
    local t0=$(now)
    curl -s -F "name=@$NZB" "http://127.0.0.1:$RN_PORT/api?mode=addfile" >/dev/null
    local st=$(wait_gone rn_done $before $t0)
    local t1=$(now)
    local hw=$(du_stop "$OUTROOT/du.rn")
    kill $rn_pid 2>/dev/null
    local rc=0; [[ $st == timeout ]] && rc=124
    log "LEG $LEGNAME rustnzb wall_s=$((t1-t0)) hiwater_mb=$hw rc=$rc $(classify "$MANIFEST" "$base/complete" $rc)"
}

leg_weaver() {
    [[ -n $WEAVER && -x $WEAVER ]] || { log "SKIP $LEGNAME weaver (set WEAVER)"; return; }
    local base=$OUTROOT/$LEGNAME/weaver
    rm -rf "$base"; mkdir -p "$base/complete" "$base/inter" "$base/data"
    du_start "$base" "$OUTROOT/du.wv"
    local t0=$(now)
    # Weaver has a one-shot CLI (`download`), so no daemon/API dance.
    # It bootstraps an encryption key through the macOS Keychain, which
    # fails outright over ssh ("User interaction is not allowed") -
    # WEAVER_ENCRYPTION_KEY supplies one directly, freshly generated per
    # run so nothing persistent is stored. Servers come from env too.
    : > "$OUTROOT/weaver.out"   # stale verdict from the previous leg must not leak in
    # Weaver dedupes submissions against its own state and answers a repeat
    # NZB with "duplicate submission blocked", writing nothing at all - so a
    # re-run of a leg measures the dedupe, not the client. Start it clean.
    rm -rf "$base/data" "$base/inter"
    (
        export WEAVER_ENCRYPTION_KEY=$(openssl rand -base64 32)
        export WEAVER_DATA_DIR=$base/data
        export WEAVER_INTERMEDIATE_DIR=$base/inter
        export WEAVER_COMPLETE_DIR=$base/complete
        export WEAVER_CLEANUP_AFTER_EXTRACT=true
        export WEAVER_SERVER_1_HOSTNAME=127.0.0.1
        export WEAVER_SERVER_1_PORT=$PORT
        export WEAVER_SERVER_1_TLS=false
        export WEAVER_SERVER_1_CONNECTIONS=$CONNS
        export WEAVER_SERVER_1_ACTIVE=true
        # --force bypasses Weaver's semantic duplicate blocking. Without it a
        # leg it has seen before - and it matches on release identity, not
        # content, so the quick corpus poisons the full one - is rejected
        # outright with "duplicate submission blocked", writes nothing, and
        # scores as a failure of the client rather than of the harness.
        "$WEAVER" download --force "$NZB" -o "$base/complete"
    ) > "$OUTROOT/weaver.out" 2>&1 &
    local wv=$!
    # Weaver's `download` does NOT exit after finishing (observed: still
    # running at a 900 s cap with every payload already byte-correct and
    # an empty log). Process exit is therefore not a finish signal -
    # poll for the manifest's payload sizes appearing in the output tree
    # and take THAT as time-to-usable-files, which is what the other
    # clients' completion signals mean too.
    local want=$(python3 -c "import json;m=json.load(open('$MANIFEST'));print(' '.join(str(p['bytes']) for p in m['payloads']))")
    local nwant=$(echo $want | wc -w | tr -d ' ')
    local rc=124 i n sz last_sz=-1 last_move=$(now)
    for i in $(seq 1 $((TIMEOUT/2))); do
        sleep 2
        n=0
        for w in ${=want}; do
            find "$base/complete" -type f -size "${w}c" 2>/dev/null | grep -q . && n=$((n+1))
        done
        [[ $n -eq $nwant ]] && { rc=0; break; }
        # progress = the output tree growing. Weaver's `download` never exits,
        # so process liveness proves nothing; bytes on disk do.
        # Weaver reports terminal failure in its own log and then keeps
        # running, so read the log before judging it by disk activity. Without
        # this the stall timer fires on every failed leg and reports a HANG,
        # which is a different and much more serious claim than a failure.
        # Weaver emits at least two terminal strings - "job failed" and
        # "download failed" - and matching only the first made legs that
        # reported the second run out the stall timer and read as HUNG.
        # A failure and a hang are very different published claims.
        if grep -qE "job failed|download failed|ERROR .*failed" "$OUTROOT/weaver.out" 2>/dev/null; then rc=1; break; fi
        sz=$(du -sk "$base" 2>/dev/null | cut -f1)
        if [[ ${sz:-0} -ne $last_sz ]]; then last_sz=${sz:-0}; last_move=$(now); fi
        # a genuine hang: no payloads, no log verdict, and nothing written for
        # STALL seconds. Only this may be called hung.
        [[ $(( $(now) - last_move )) -ge $STALL ]] && { rc=125; break; }
    done
    local t1=$(now)
    kill -9 $wv 2>/dev/null; pkill -9 -f "$(basename $WEAVER)" 2>/dev/null
    local hw=$(du_stop "$OUTROOT/du.wv")
    local cls=$(classify "$MANIFEST" "$base/complete" $rc)
    [[ $rc -eq 125 ]] && cls=$(echo "$cls" | sed 's/class=[a-z-]*/class=hung/')
    log "LEG $LEGNAME weaver wall_s=$((t1-t0)) hiwater_mb=$hw rc=$rc $cls"
}

# ---- main -------------------------------------------------------------

run_leg() { # $1 legdir
    LEGDIR=$1
    LEGNAME=$(basename "$LEGDIR")
    MANIFEST=$LEGDIR/manifest.json
    NZB=$LEGDIR/$LEGNAME.nzb
    [[ -f $MANIFEST && -f $NZB ]] || { echo "skipping $LEGDIR (no manifest/nzb)" >&2; return; }
    mkdir -p "$OUTROOT/$LEGNAME"
    log "### leg $LEGNAME shape=$(jq -r .shape "$MANIFEST") depth=$(jq -r .depth "$MANIFEST")"
    serve_start "$LEGDIR" || return
    for c in $CLIENTS; do
        case $c in
            nzbfast) leg_nzbfast ;;
            nzbget) leg_nzbget ;;
            sab) leg_sab ;;
            rustnzb) leg_rustnzb ;;
            weaver) leg_weaver ;;
            *) echo "unknown client $c" >&2 ;;
        esac
    done
    serve_stop
}

log "### run-legs $(date -u +%Y-%m-%dT%H:%M:%SZ) root=$ROOT clients=$CLIENTS conns=$CONNS timeout=$TIMEOUT"
if [[ -f $ROOT/manifest.json ]]; then
    run_leg "$ROOT"
else
    for m in "$ROOT"/**/manifest.json(N); do
        run_leg "$(dirname "$m")"
    done
fi
log "### run-legs END"

#!/bin/sh
# Push a slim Android nzbfast binary to a device (or emulator) over adb,
# start the daemon on 127.0.0.1:6789, and open the dashboard in the
# device's browser.
#
# Usage: ./run-on-device.sh [path-to-binary] [serial]
#   path-to-binary  default: ./nzbfast-android-arm64
#   serial          default: the only connected device
#
# The binary runs from /data/local/tmp - the adb-writable, exec-permitted
# scratch space every device exposes to the shell user. Everything this
# script creates on the device lives under /data/local/tmp/nzbfast:
#   downloads/  completed downloads      watch/  drop .nzb files here
#   config/     config + settings        daemon.log
# Remove it all with:  adb shell rm -rf /data/local/tmp/nzbfast
set -eu

BIN="${1:-./nzbfast-android-arm64}"
SERIAL="${2:-}"
ADB="adb"
[ -n "$SERIAL" ] && ADB="adb -s $SERIAL"

if [ ! -f "$BIN" ]; then
    echo "binary not found: $BIN" >&2
    echo "build it first - see README.md in this directory" >&2
    exit 1
fi

DEV_DIR=/data/local/tmp/nzbfast
PORT=6789

echo "==> pushing $BIN"
$ADB shell mkdir -p "$DEV_DIR/downloads" "$DEV_DIR/config" "$DEV_DIR/watch"
$ADB push "$BIN" "$DEV_DIR/nzbfast" >/dev/null
$ADB shell chmod 755 "$DEV_DIR/nzbfast"

echo "==> stopping any previous instance"
# Kill by pid file, never by process-name pattern (repo rule).
$ADB shell "[ -f $DEV_DIR/pid ] && kill \$(cat $DEV_DIR/pid) 2>/dev/null; true"
sleep 1

# A fixed key per kit run keeps the URL printable and the dashboard
# reachable without fishing the minted key back off the device. Local
# testing only: the daemon binds 127.0.0.1, nothing off-device can reach it.
KEY=$(head -c 24 /dev/urandom | od -An -tx1 | tr -d ' \n')

echo "==> starting daemon"
# NZBFAST_NO_ENRICH=1: no metadata/enrichment traffic during testing.
# </dev/null on stdin or adb shell never returns: it waits for every fd
# of the remote command to close, and the daemon inherits the pty
# otherwise.
$ADB shell "cd $DEV_DIR && NZBFAST_NO_ENRICH=1 HOME=$DEV_DIR TMPDIR=$DEV_DIR nohup ./nzbfast \
    --config $DEV_DIR/config/config.json serve \
    --bind 127.0.0.1 --port $PORT \
    --apikey $KEY \
    --out $DEV_DIR/downloads \
    --watch $DEV_DIR/watch \
    > $DEV_DIR/daemon.log 2>&1 < /dev/null & echo \$! > $DEV_DIR/pid"
sleep 2

if ! $ADB shell "grep -q 'listening\|dashboard' $DEV_DIR/daemon.log 2>/dev/null"; then
    echo "daemon may not have started - log so far:" >&2
    $ADB shell "cat $DEV_DIR/daemon.log" >&2 || true
fi
$ADB shell "head -20 $DEV_DIR/daemon.log" || true

URL="http://127.0.0.1:$PORT/?apikey=$KEY"

echo "==> opening dashboard in the device browser"
$ADB shell am start -a android.intent.action.VIEW -d "$URL" >/dev/null || true

echo
echo "daemon is up: $URL"
echo "  add an NZB:  adb push some.nzb $DEV_DIR/watch/"
echo "  log:         adb shell cat $DEV_DIR/daemon.log"
echo "  stop:        adb shell 'kill \$(cat $DEV_DIR/pid)'"
echo "  remove:      adb shell rm -rf $DEV_DIR"

#!/usr/bin/env bash
# nzbfast Flatpak launcher - BETA
#
# nzbfast is a daemon with a web dashboard, not a windowed program, so
# there is nothing to put on screen. This script is what the desktop
# entry runs, and it gives the icon the behaviour a desktop user expects
# from clicking it: the dashboard opens in their browser.
#
# The shape is copied from SABnzbd's Flathub package rather than invented
# (org.sabnzbd.sabnzbd runs `SABnzbd.py --browser 1` from its .desktop
# file): one foreground process per launch, the browser opened once the
# listener is up, and no background service that outlives the session.
# nzbfast already has the flag for the second half - `serve --open` opens
# the dashboard when the port is listening, and is what the macOS and
# Windows double-click launchers use - so the only thing this adds is the
# second-launch case below.
#
# Clicking the icon twice must not try to bind the port twice. A daemon
# that is already listening is the common case (the first click left one
# running), and starting a second one would fail on the bind and show the
# user an error about a program that is working perfectly. So: if the
# port answers, just open the dashboard and exit.
set -eu

APP_ID=io.github.nzbfast.nzbfast

# Inside the sandbox XDG_CONFIG_HOME is already the app's own private
# directory (~/.var/app/$APP_ID/config on the host), so the data
# directory needs no filesystem permission at all and cannot collide with
# a tarball or .deb install of nzbfast on the same machine. The daemon
# derives the whole data directory from the config file's parent, which
# is why only NZBFAST_CONFIG is set rather than four separate paths.
CONF_HOME="${XDG_CONFIG_HOME:-$HOME/.config}"
DATA_DIR="$CONF_HOME/nzbfast"
CONFIG="$DATA_DIR/config.json"
mkdir -p "$DATA_DIR"

# The port to TALK to, which is not always the port to start on. A port
# changed in the dashboard is saved in settings.json and wins over the
# --port flag on every later start, so a launcher that only ever knew
# 6789 would probe a dead port, decide nothing was running, start a
# second daemon, and watch it fail the bind on the port the first one
# actually holds. The daemon records where it really landed in
# runtime.json beside its settings; that file is rewritten on every start
# and can be stale after a crash, which is why the port it names is
# probed rather than trusted.
RUNTIME="$DATA_DIR/runtime.json"
PORT="${NZBFAST_PORT:-6789}"
SCHEME=http
if [ -r "$RUNTIME" ]; then
    _p=$(grep -o '"port":[0-9]*' "$RUNTIME" | head -1 | cut -d: -f2)
    case "$_p" in
        ''|*[!0-9]*) ;;                      # absent or not a number: keep the default
        *) PORT="$_p" ;;
    esac
    grep -q '"tls":true' "$RUNTIME" && SCHEME=https
fi

# The user's real Downloads folder, which on a localised desktop is not
# called "Downloads". xdg-user-dir cannot answer this inside the sandbox:
# it reads $XDG_CONFIG_HOME/user-dirs.dirs, and that variable now points
# at the app's private config directory, where there is no such file. The
# host's copy is still readable through the home permission, so read it
# from its real path and fall back to the English default.
download_dir() {
    _d=""
    if [ -r "$HOME/.config/user-dirs.dirs" ]; then
        _d=$(
            XDG_DOWNLOAD_DIR=""
            # shellcheck disable=SC1091  # the host's user-dirs file
            . "$HOME/.config/user-dirs.dirs" 2>/dev/null || true
            eval printf '%s' "\"${XDG_DOWNLOAD_DIR:-}\"" 2>/dev/null || true
        )
    fi
    [ -n "$_d" ] || _d="$HOME/Downloads"
    printf '%s' "$_d"
}

DL=$(download_dir)
OUT="${NZBFAST_OUT:-$DL/nzbfast}"
WATCH="${NZBFAST_WATCH:-$DL/nzbfast/watch}"

# Is a daemon already listening? The runtime carries neither curl nor ss,
# so ask the shell for a TCP connect - which is why this script is bash
# and not sh: /dev/tcp is a bash feature and dash returns "no such file"
# for it, which would read here as "the port is free" and send every
# second click into a doomed bind.
port_is_up() {
    (exec 3<>/dev/tcp/127.0.0.1/"$PORT") >/dev/null 2>&1
}

# ...and is it OURS? A listener is not an identity. Anything at all on
# 6789 used to be treated as nzbfast, which meant a different local
# service on that port stopped nzbfast from ever starting AND got opened
# in the user's browser by us. INSTALLER-SPEC.md is explicit: attach
# only when the port answers mode=version and reports nzbfast.
#
# mode=version is answered without an API key by design (the container
# healthcheck depends on it), and the reply carries an "nzbfast" field
# that SABnzbd's does not, which is what makes it an identity check
# rather than a liveness one. Same /dev/tcp as above, because the
# runtime has neither curl nor wget; read with a timeout so a socket
# that accepts and says nothing cannot hang the launcher.
port_is_nzbfast() {
    local line body=""
    exec 3<>/dev/tcp/127.0.0.1/"$PORT" 2>/dev/null || return 1
    printf 'GET /api?mode=version&output=json HTTP/1.0\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n' >&3 2>/dev/null || {
        exec 3<&- 3>&- 2>/dev/null; return 1; }
    # `|| [ -n "$line" ]` is load-bearing: the body's last line carries no
    # trailing newline, and a plain `read` returns false on that EOF -
    # dropping the one line the JSON is on. Without it this probe says
    # "not nzbfast" about a real daemon, which would break attach for
    # every user instead of only the ones with a port conflict.
    while IFS= read -r -t 3 line <&3 || [ -n "$line" ]; do
        body="$body$line"
        line=""
    done
    exec 3<&- 3>&- 2>/dev/null
    case "$body" in
        *'"nzbfast"'*) return 0 ;;
        *) return 1 ;;
    esac
}

open_dashboard() {
    # xdg-open in the runtime is a shim onto the OpenURI portal, so this
    # reaches the user's real browser on the host without the sandbox
    # holding any display socket or bus name of its own.
    xdg-open "$SCHEME://127.0.0.1:$PORT/" >/dev/null 2>&1 || true
}

# A .nzb passed by the file manager ("Open with nzbfast"). There is no
# CLI verb that hands a file to a running daemon, so it goes through the
# watch folder, which is the mechanism the daemon already polls - and it
# works whether or not the daemon is up yet.
for arg in "$@"; do
    case "$arg" in
        *.nzb|*.nzb.gz)
            mkdir -p "$WATCH"
            cp -f -- "$arg" "$WATCH/" 2>/dev/null || true
            ;;
    esac
done

if port_is_up; then
    if port_is_nzbfast; then
        open_dashboard
        exit 0
    fi
    # Somebody else owns the port. Do NOT open it in the browser: that
    # would hand the user a stranger's service under our name. Do not
    # kill it either - "never kill a daemon you didn't spawn". Say what
    # is wrong and how to move, then stop.
    echo "nzbfast: something else is already listening on port $PORT," >&2
    echo "  and it is not nzbfast, so there is nothing here to attach to." >&2
    echo "  Set a different port and start again:" >&2
    echo "    flatpak run --env=NZBFAST_PORT=6790 com.nzbfast.nzbfast" >&2
    echo "  (a port saved in settings.json beats that on later runs)." >&2
    exit 1
fi

mkdir -p "$OUT" "$WATCH"

# --bind 0.0.0.0 is the house default on every other platform and is kept
# here on purpose: this is the same daemon a phone remote or a Sonarr on
# another box talks to, and a desktop install is no different. The API
# key the daemon mints on first run is what protects it; the dashboard
# says so loudly if one is ever missing.
# --port is the FIRST-RUN default only: a port saved in settings.json
# beats it, which is the behaviour every other launcher relies on. So
# this passes the plain default rather than whatever runtime.json said,
# and lets the daemon resolve where it belongs.
exec nzbfast serve \
    --config "$CONFIG" \
    --port "${NZBFAST_PORT:-6789}" \
    --out "$OUT" \
    --watch "$WATCH" \
    --index-db "$DATA_DIR/index.db" \
    --open

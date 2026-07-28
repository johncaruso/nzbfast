#!/bin/sh
# nzbfast container entrypoint. Honors PUID/PGID (linuxserver convention)
# so bind-mounted /downloads is owned by the host user, and writes a
# starter config on first run if none is mounted.
set -e

# The image is the update channel. Mark this a bundled/managed install so
# nzbfast refuses to self-swap its binary (a container's filesystem is
# ephemeral, and the binary is root-owned while serve runs as PUID). It
# still checks and surfaces "update available"; users update by pulling a
# newer image (or via Watchtower). See docs/SYNOLOGY.md.
export NZBFAST_BUNDLED=1

CONFIG="${NZBFAST_CONFIG:-/config/config.json}"
PORT="${NZBFAST_PORT:-6789}"
OUT="${NZBFAST_OUT:-/downloads}"
WATCH="${NZBFAST_WATCH:-/watch}"

# Is this the very first run? (No config yet.) Used to pick a secure
# default without changing behaviour for anyone who already has an
# install - existing configs are never touched below.
FIRST_RUN=0
[ -f "$CONFIG" ] || FIRST_RUN=1

if [ "$FIRST_RUN" = "1" ]; then
    echo "nzbfast: no config at $CONFIG - writing a starter template."
    echo "         Add your Usenet server(s) and restart."
    cat > "$CONFIG" <<'JSON'
{
  "servers": [
    {
      "host": "news.example.com",
      "port": 563,
      "tls": true,
      "username": "CHANGEME",
      "password": "CHANGEME",
      "connections": 20
    }
  ]
}
JSON
    # 0600: this is the file the user is told to put their provider password
    # into, and root's default umask would leave it 0644 in a bind-mounted
    # /config (the chown -R below fixes the owner but never the mode, and
    # editors preserve it).
    chmod 600 "$CONFIG" 2>/dev/null || true
fi

# Secure-by-default API key - PRE-FLIGHT ONLY.
#
# The daemon now mints, persists and reuses the first-run key itself, for
# every launcher (see first_run_apikey in crates/nzbfast/src/serve.rs). This
# script used to do the same job a second time, writing the same file to the
# same path with the same resolution order; that duplicate is gone.
#
# What stays is the one property the daemon deliberately does NOT have. The
# daemon warns and carries on when the key cannot be read or stored, which is
# right for a desktop where the operator sees the warning and the listener is
# usually loopback. A container publishes the control API on 0.0.0.0 with no
# console anyone reads, so "carry on" there means the whole API - provider
# passwords in cleartext, the post-processing script path, queue deletion -
# open to the LAN. So the container fails CLOSED instead: check the three
# states in which the daemon would fall back, and refuse to start in any of
# them.
#
# Nothing below writes the key file. Resolution itself is the daemon's:
#   1. NZBFAST_APIKEY set   -> passed through as --apikey (bottom of file).
#   2. NZBFAST_OPEN=1       -> deliberately keyless; both halves skip out.
#   3. an existing key file -> the daemon reads it, stable across restarts.
#   4. a first run          -> the daemon generates one and prints it once.
KEYFILE="$(dirname "$CONFIG")/apikey"
SETTINGS="$(dirname "$CONFIG")/settings.json"
if [ -z "$NZBFAST_APIKEY" ] && [ "${NZBFAST_OPEN:-0}" != "1" ]; then
    if [ -f "$KEYFILE" ]; then
        # An empty or unreadable key file makes the daemon warn and start
        # keyless while the operator believes a key is set. Both halves of
        # that are reachable: an ENOSPC mid-write leaves a 0-byte file, and
        # switching from root+PUID to `--user 1000` leaves a root:0600 file
        # the daemon can no longer read.
        if [ ! -r "$KEYFILE" ] || [ ! -s "$KEYFILE" ]; then
            echo "nzbfast: ERROR - $KEYFILE is empty or could not be read." >&2
            echo "         Refusing to start keyless on a published port. Fix the" >&2
            echo "         file's owner/permissions, delete it to generate a new key," >&2
            echo "         pass -e NZBFAST_APIKEY=..., or set -e NZBFAST_OPEN=1 to" >&2
            echo "         deliberately run without a key." >&2
            exit 1
        fi
    elif grep -q '"apikey"[[:space:]]*:[[:space:]]*"[^"]' "$SETTINGS" 2>/dev/null; then
        # No key file, but Settings holds one. That is a real, keyed
        # install: a key set in the dashboard is written to settings.json,
        # which WINS over the key file when the daemon loads. So the
        # listener will be authenticated and there is nothing to refuse.
        #
        # Reachable because clearing the key in the dashboard deletes the
        # key file (deliberately - that is what makes "keyless" survive a
        # restart) and setting one again only rewrote the file from a
        # later build. A container that cleared and then re-set its key
        # under an older build has settings.json keyed and no key file,
        # and used to be unable to start at all.
        :
    elif [ -e "$SETTINGS" ] || [ -e "$(dirname "$CONFIG")/.spool" ]; then
        # No key file, but this install has run before. The daemon mints only
        # on a genuinely first run - deliberately, so a key can never appear
        # under a desktop install and lock out remotes the user already wired
        # up. In a container that same restraint means starting open on
        # 0.0.0.0, so refuse and let the operator choose which they meant.
        echo "nzbfast: ERROR - no API key at $KEYFILE, and this install has" >&2
        echo "         already run, so the daemon will not create one." >&2
        echo "         Refusing to publish the control API keyless. Pass" >&2
        echo "         -e NZBFAST_APIKEY=... to set a key, or -e NZBFAST_OPEN=1" >&2
        echo "         to deliberately run without one." >&2
        exit 1
    elif ! ( umask 077; : > "$KEYFILE.probe.$$" ) 2>/dev/null; then
        # A first run, but the directory that should hold the key is not
        # writable (read-only mount, ENOSPC, no inodes). The daemon would mint
        # a key it cannot save and warn that it changes on every start, which
        # silently breaks every *arr the operator wires up. Say so now, once.
        rm -f "$KEYFILE.probe.$$" 2>/dev/null || true
        echo "nzbfast: ERROR - cannot create an API key file at $KEYFILE." >&2
        echo "         Refusing to start, because a key that cannot be stored" >&2
        echo "         changes on every restart and breaks Sonarr/Radarr." >&2
        echo "         Check that /config is writable and has free space," >&2
        echo "         pass -e NZBFAST_APIKEY=..., or set -e NZBFAST_OPEN=1" >&2
        echo "         to deliberately run without a key." >&2
        exit 1
    else
        rm -f "$KEYFILE.probe.$$" 2>/dev/null || true
    fi
fi

set -- serve --config "$CONFIG" --port "$PORT" --out "$OUT" --watch "$WATCH"
[ -n "$NZBFAST_APIKEY" ] && set -- "$@" --apikey "$NZBFAST_APIKEY"

# Never run the daemon as root. When started as root (the default so PUID
# remapping can chown bind mounts), drop to an unprivileged uid before
# exec: an explicit PUID/PGID wins; otherwise adopt the owner of /config
# (respects a bind mount the host already owns) or fall back to 1000. So a
# bare `docker run` with no PUID still runs the parser/extractor code as a
# non-root user, not root. gosu takes a numeric uid:gid directly - no user
# account need exist. The recursive chown is skipped for dirs already
# owned by the target uid so a large /downloads isn't re-walked each start.
if [ "$(id -u)" = "0" ]; then
    if [ -z "$PUID" ]; then
        _cfg_owner="$(stat -c %u /config 2>/dev/null || echo 0)"
        [ "$_cfg_owner" != "0" ] && PUID="$_cfg_owner" || PUID=1000
    fi
    PGID="${PGID:-$PUID}"
    # The daemon reads the key file itself now, as PUID rather than as root.
    # A key written by an older image is root:0600, and the loop below skips
    # a /config that is already owned by PUID (the common case: a bind mount
    # the host user owns, which is also where PUID's default comes from), so
    # that file would stay unreadable and the daemon would start keyless.
    # Chown it directly - it is one file, and being wrong here means an open
    # control API on the LAN.
    if [ -f "$KEYFILE" ]; then
        chown "$PUID:$PGID" "$KEYFILE" 2>/dev/null || true
    fi
    for d in /config /downloads /watch /incomplete; do
        [ -d "$d" ] || continue
        [ "$(stat -c %u "$d")" = "$PUID" ] || chown -R "$PUID:$PGID" "$d" 2>/dev/null || true
    done
    exec gosu "$PUID:$PGID" nzbfast "$@"
fi

# Already non-root (image run with --user, or re-exec): serve directly.
exec nzbfast "$@"

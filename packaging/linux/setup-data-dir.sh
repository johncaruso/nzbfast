#!/bin/sh
# Create the service account and the data directory, and seed a config
# file only if there is not one already.
#
# ONE implementation, called by BOTH package formats (the .deb postinst
# and the .rpm %post), because this is the script that decides whether an
# upgrade keeps somebody's settings. Two copies of it would be two
# chances to get that wrong, and the difference would only ever show up
# on one of the two distros, on an upgrade, in someone else's terminal.
# It ships inside the package at /usr/share/nzbfast/setup-data-dir.sh so
# an admin can read what their install did.
#
# It is idempotent by construction: every write is guarded by a test for
# what is already there. Running it twice, or on every upgrade for the
# rest of the install's life, must be a no-op after the first time.
#
# NZBFAST_PKG_ROOT prefixes every path so packaging/tests can exercise
# this against a fake root as an ordinary user. dpkg and rpm never set
# it; when it is set, the account and ownership steps are skipped (there
# is no account to create in a directory tree that is not a system).
set -e

ROOT="${NZBFAST_PKG_ROOT:-}"
ENVFILE="$ROOT/etc/nzbfast/nzbfast.env"
EXAMPLE="$ROOT/usr/share/nzbfast/config.example.json"
SVC_USER=nzbfast
SVC_GROUP=nzbfast

# Defaults duplicated from the shipped env file so a deleted or emptied
# env file still lands on the documented locations rather than on empty
# strings - which would put the data directory at "/" and the download
# folder in the daemon's working directory.
NZBFAST_CONFIG=/var/lib/nzbfast/config.json
NZBFAST_OUT=/var/lib/nzbfast/downloads
NZBFAST_WATCH=/var/lib/nzbfast/watch
# shellcheck disable=SC1090  # a conffile, read at install time
[ -f "$ENVFILE" ] && . "$ENVFILE"

# An admin who blanked a value in the env file gets the default back, not
# a path of "".
[ -n "$NZBFAST_CONFIG" ] || NZBFAST_CONFIG=/var/lib/nzbfast/config.json
[ -n "$NZBFAST_OUT" ]    || NZBFAST_OUT=/var/lib/nzbfast/downloads
[ -n "$NZBFAST_WATCH" ]  || NZBFAST_WATCH=/var/lib/nzbfast/watch

CONFIG="$ROOT$NZBFAST_CONFIG"
DATA=$(dirname "$CONFIG")
OUT="$ROOT$NZBFAST_OUT"
WATCH="$ROOT$NZBFAST_WATCH"

# ---------------------------------------------------------------- account
# Created on first install and left alone afterwards. Never removed on
# uninstall either: the data directory keeps its ownership, so a reinstall
# finds its own files instead of a tree owned by a recycled uid.
if [ -z "$ROOT" ] && ! getent passwd "$SVC_USER" >/dev/null 2>&1; then
    # useradd, not Debian's adduser, on both distros. `adduser` EXISTS on
    # Fedora too - as a symlink to useradd - so "is adduser present" is
    # not the Debian test it looks like, and Debian's long options handed
    # to useradd fail the install on the distro that was supposed to be
    # the easy one. useradd itself is on both (Debian ships it in
    # `passwd`, priority required, which the control file depends on).
    nologin=/usr/sbin/nologin
    [ -x "$nologin" ] || nologin=/sbin/nologin
    [ -x "$nologin" ] || nologin=/bin/false
    groupadd --system "$SVC_GROUP" >/dev/null 2>&1 || true
    useradd --system --gid "$SVC_GROUP" --no-create-home \
            --home-dir "$DATA" --shell "$nologin" \
            --comment "nzbfast Usenet downloader" "$SVC_USER" >/dev/null
fi

# ------------------------------------------------------------ directories
# Only what we create gets chowned. Never `chown -R` the data directory:
# on a box that has been running for months it holds finished downloads,
# and on an upgrade that recursive walk is both slow and a way to take
# files away from something else that legitimately owns them (the
# Synology package learned this one the hard way).
for d in "$DATA" "$OUT" "$WATCH"; do
    [ -d "$d" ] && continue
    mkdir -p "$d"
    if [ -z "$ROOT" ]; then
        chown "$SVC_USER:$SVC_GROUP" "$d"
        # 0750: the spool beside the config holds the API key and the
        # provider credentials, so no other local account may read it.
        chmod 750 "$d"
    fi
done

# ---------------------------------------------------------------- config
# The one file we seed, and ONLY when nothing is there. An upgrade
# reaches this line with a config full of the user's provider passwords
# sitting at $CONFIG, so the test is the whole point of the block.
#
# settings.json, apikey and .spool live in this same directory and are
# never created, copied or removed here. Neither dpkg nor rpm knows they
# exist - nothing in the package owns a path under the data directory -
# so an upgrade physically cannot replace them.
if [ ! -e "$CONFIG" ] && [ -f "$EXAMPLE" ]; then
    # 0600 from the start, not `cp` then `chmod`. The file is about to
    # hold a Usenet provider password, and the window between the two
    # commands is a window where it is world-readable.
    ( umask 077; cat "$EXAMPLE" > "$CONFIG" )
    [ -z "$ROOT" ] && chown "$SVC_USER:$SVC_GROUP" "$CONFIG"
    echo "nzbfast: wrote a starter config to $NZBFAST_CONFIG"
fi

exit 0

#!/bin/sh
# The install / start / upgrade / remove checks, run INSIDE the systemd
# container that packaging/tests/linux-install.sh starts. Not meant to be
# run by hand on a real machine - it installs, upgrades and then REMOVES
# nzbfast, and it writes to /var/lib/nzbfast.
#
#   checks.sh deb|rpm <package> <the-same-package-one-beta-later>
#
# The interesting half is steps 4 to 6: an upgrade over a RUNNING daemon
# has to keep settings.json byte-identical, keep the admin's edits to the
# env file, restart the daemon onto the new binary - and, when the daemon
# was stopped, leave it stopped.
set -eu
FMT=$1; PKG_A=$2; PKG_B=$3
PORT=6789
pass=0
say()  { printf '\n\033[1m=== %s ===\033[0m\n' "$*"; }
ok()   { pass=$((pass+1)); echo "  ok   $*"; }
fail() { echo "  FAIL $*" >&2; exit 1; }
inst() { case $FMT in deb) dpkg -i "$1" ;; rpm) rpm -i "$1" ;; esac; }
upgr() { case $FMT in deb) dpkg -i "$1" ;; rpm) rpm -U "$1" ;; esac; }
rem()  { case $FMT in deb) dpkg -r nzbfast ;; rpm) rpm -e nzbfast ;; esac; }
purge(){ case $FMT in deb) dpkg -P nzbfast ;; rpm) : ;; esac; }
api()  { curl -s -m 5 "http://127.0.0.1:$PORT/api?$1"; }

say "1. install $PKG_A"
inst "$PKG_A"
getent passwd nzbfast >/dev/null || fail "no nzbfast account"
ok "service account created: $(getent passwd nzbfast | cut -d: -f1,6,7)"
[ -x /usr/bin/nzbfast ] || fail "/usr/bin/nzbfast missing"
[ -f /usr/lib/systemd/system/nzbfast.service ] || fail "unit not installed"
[ -f /etc/nzbfast/nzbfast.env ] || fail "env file not installed"
ok "files in place"
[ -d /var/lib/nzbfast/downloads ] && [ -d /var/lib/nzbfast/watch ] || fail "data dirs missing"
[ "$(stat -c '%U:%a' /var/lib/nzbfast)" = "nzbfast:750" ] || fail "data dir ownership: $(stat -c '%U:%a' /var/lib/nzbfast)"
ok "data dir: $(stat -c '%U:%G %a' /var/lib/nzbfast)"
[ "$(stat -c '%U:%a' /var/lib/nzbfast/config.json)" = "nzbfast:600" ] || fail "config perms: $(stat -c '%U:%a' /var/lib/nzbfast/config.json)"
ok "config.json seeded 0600 nzbfast"
systemctl is-enabled nzbfast >/dev/null || fail "unit not enabled"
ok "unit is enabled at boot"
systemctl is-active nzbfast >/dev/null 2>&1 && fail "unit was STARTED by the install"
ok "unit was NOT started by the install"
systemd-analyze verify /usr/lib/systemd/system/nzbfast.service 2>&1 | grep -v '^$' && fail "systemd-analyze verify complained" || true
ok "systemd-analyze verify is clean"

say "2. start the service"
systemctl start nzbfast
i=0; while [ $i -lt 30 ]; do api "mode=version" | grep -q version && break; i=$((i+1)); sleep 1; done
V=$(api "mode=version&output=json")
echo "$V" | grep -q '"version"' || fail "no version from the API: $V"
ok "api?mode=version -> $V"
systemctl is-active nzbfast >/dev/null || fail "service not active"
ok "service active, main pid $(systemctl show -p MainPID --value nzbfast)"

say "3. write a setting through the daemon"
KEY=$(cat /var/lib/nzbfast/apikey)
[ -n "$KEY" ] || fail "no apikey file"
api "mode=config&name=speedlimit&value=1234567&apikey=$KEY" >/dev/null
sleep 1
[ -f /var/lib/nzbfast/settings.json ] || fail "settings.json was not written"
grep -q 1234567 /var/lib/nzbfast/settings.json || fail "setting not in settings.json"
ok "settings.json: $(tr -d '\n ' < /var/lib/nzbfast/settings.json)"
SETTINGS_BEFORE=$(md5sum /var/lib/nzbfast/settings.json | cut -d' ' -f1)
KEY_BEFORE=$KEY

say "4. admin edits the env file (port 6790)"
sed -i 's/^NZBFAST_PORT=6789/NZBFAST_PORT=6790/' /etc/nzbfast/nzbfast.env
echo '# an admin comment that must survive the upgrade' >> /etc/nzbfast/nzbfast.env
systemctl restart nzbfast
PORT=6790
i=0; while [ $i -lt 30 ]; do api "mode=version" | grep -q version && break; i=$((i+1)); sleep 1; done
api "mode=version" | grep -q version || fail "daemon did not move to port 6790"
ok "EnvironmentFile is wired: daemon now serves :6790"
PID_BEFORE=$(systemctl show -p MainPID --value nzbfast)

say "5. UPGRADE over the running install: $PKG_B"
upgr "$PKG_B"
sleep 3
i=0; while [ $i -lt 30 ]; do api "mode=version" | grep -q version && break; i=$((i+1)); sleep 1; done
[ -f /var/lib/nzbfast/settings.json ] || fail "settings.json GONE after upgrade"
[ "$(md5sum /var/lib/nzbfast/settings.json | cut -d' ' -f1)" = "$SETTINGS_BEFORE" ] \
    || fail "settings.json CHANGED across the upgrade"
ok "settings.json byte-identical across the upgrade"
[ "$(cat /var/lib/nzbfast/apikey)" = "$KEY_BEFORE" ] || fail "apikey changed across the upgrade"
ok "apikey unchanged"
grep -q '^NZBFAST_PORT=6790' /etc/nzbfast/nzbfast.env || fail "env file was replaced by the upgrade"
grep -q 'an admin comment' /etc/nzbfast/nzbfast.env || fail "env file comment lost"
ok "/etc/nzbfast/nzbfast.env kept the admin's edits"
systemctl is-active nzbfast >/dev/null || fail "service not running after upgrade"
PID_AFTER=$(systemctl show -p MainPID --value nzbfast)
[ "$PID_AFTER" != "$PID_BEFORE" ] || fail "daemon was not restarted onto the new binary"
ok "daemon restarted onto the new binary (pid $PID_BEFORE -> $PID_AFTER)"
api "mode=version" | grep -q version || fail "API not answering after upgrade"
ok "api?mode=version answers after the upgrade on :6790"
S=$(api "mode=get_config&apikey=$(cat /var/lib/nzbfast/apikey)" | grep -o 1234567 | head -1)
[ "$S" = "1234567" ] || fail "the saved setting is not in the running daemon"
ok "the setting saved before the upgrade is live after it"

say "6. upgrade with the daemon STOPPED must not start it"
systemctl stop nzbfast
upgr "$PKG_A" 2>/dev/null || case $FMT in deb) dpkg -i --force-downgrade "$PKG_A" ;; rpm) rpm -U --oldpackage "$PKG_A" ;; esac
systemctl is-active nzbfast >/dev/null 2>&1 && fail "a stopped daemon was started by an upgrade"
ok "a stopped daemon stays stopped across an upgrade"
[ -f /var/lib/nzbfast/settings.json ] || fail "settings.json gone after downgrade"
ok "settings.json still there after the second package swap"

say "7. remove"
rem
[ -f /usr/bin/nzbfast ] && fail "binary still present after remove"
[ -f /var/lib/nzbfast/settings.json ] || fail "REMOVE DELETED settings.json"
[ -f /var/lib/nzbfast/config.json ] || fail "REMOVE DELETED config.json"
ok "remove left /var/lib/nzbfast alone"
systemctl is-enabled nzbfast 2>/dev/null | grep -q enabled && fail "unit still enabled after remove" || true
ok "unit no longer enabled"

if [ "$FMT" = deb ]; then
say "8. purge"
purge
[ -f /etc/nzbfast/nzbfast.env ] && fail "purge left the conffile"
ok "purge removed /etc/nzbfast"
[ -f /var/lib/nzbfast/settings.json ] || fail "PURGE DELETED settings.json"
ok "purge left /var/lib/nzbfast (settings + downloads) alone"
fi

printf '\n\033[1mALL %s CHECKS PASSED (%s)\033[0m\n' "$pass" "$FMT"

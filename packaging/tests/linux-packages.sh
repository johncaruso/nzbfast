#!/bin/sh
# Off-box checks for the .deb / .rpm packaging, on any OS.
#
# The install itself is tested by installing: `dpkg -i` into a Debian
# systemd container and `rpm -i` into a Fedora one (packaging/linux/README.md).
# What is checked HERE is everything that can be wrong before a container
# is even built, and the one property that no smoke test would notice
# until it had already cost somebody their settings: that nothing in this
# packaging can remove or replace the data directory.
#
# Run: packaging/tests/linux-packages.sh
set -u

cd "$(dirname "$0")/../.." || exit 1
PKG=packaging/linux
PASS=0
FAIL=0
ok()  { echo "  ok   - $1"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL - $1"; FAIL=$((FAIL + 1)); }

echo "1. the generated service unit"
UNIT=$(mktemp); $PKG/make-packages.sh --print-unit > "$UNIT" 2>/dev/null
if [ ! -s "$UNIT" ]; then
    bad "make-packages.sh --print-unit produced nothing"
else
    grep -q '^ExecStart=/usr/bin/nzbfast serve' "$UNIT" \
        && ok "ExecStart is /usr/bin/nzbfast (a package may not use /usr/local)" \
        || bad "ExecStart is not /usr/bin/nzbfast"
    grep -q '/usr/local' "$UNIT" \
        && bad "the unit still names /usr/local" \
        || ok "no /usr/local anywhere in the unit"
    grep -q '^EnvironmentFile=-/etc/nzbfast/nzbfast.env$' "$UNIT" \
        && ok "reads /etc/nzbfast/nzbfast.env, and tolerates it missing" \
        || bad "EnvironmentFile line is wrong or missing"
    # Every value the env file sets must actually be USED by the unit,
    # or the file is a lie that an admin edits and nothing happens.
    for v in NZBFAST_CONFIG NZBFAST_PORT NZBFAST_OUT NZBFAST_WATCH NZBFAST_INDEX_DB; do
        if grep -q "^Environment=$v=" "$UNIT" && grep -q "\${$v}" "$UNIT"; then
            ok "$v has a default in the unit and is used by ExecStart"
        else
            bad "$v is not both defaulted and used"
        fi
    done
    for v in NZBFAST_PORT NZBFAST_CONFIG NZBFAST_OUT NZBFAST_WATCH NZBFAST_INDEX_DB; do
        grep -q "^$v=" $PKG/nzbfast.env \
            && ok "$v is documented in the shipped env file" \
            || bad "$v is used by the unit but absent from $PKG/nzbfast.env"
    done
    grep -q '^ReadWritePaths=.*/var/lib/nzbfast' "$UNIT" \
        && ok "the data directory is writable under ProtectSystem=strict" \
        || bad "ProtectSystem=strict with no ReadWritePaths for the data dir"
fi
rm -f "$UNIT"

echo
echo "2. nothing deletes or overwrites the data directory"
# The whole upgrade-safety claim in one grep. settings.json, the API key
# and the queue spool live in /var/lib/nzbfast, and the reason an upgrade
# cannot touch them is that no packaging file mentions removing it.
for f in $PKG/setup-data-dir.sh $PKG/deb/postinst $PKG/deb/prerm \
         $PKG/deb/postrm $PKG/rpm/nzbfast.spec.in; do
    if grep -nE '(rm|rmdir|rm -rf|shred)[^|;&]*/var/lib/nzbfast' "$f" \
         | grep -v '^\s*#' >/dev/null 2>&1; then
        bad "$f has a command that removes something under /var/lib/nzbfast"
    else
        ok "$f: no removal of /var/lib/nzbfast"
    fi
done
# The rpm must own no path inside the data directory either - a %files
# entry there would make an erase delete somebody's downloads.
if grep -E '^\s*[^#]*%?(dir|config|attr)?[^#]*/var/lib/nzbfast' $PKG/rpm/nzbfast.spec.in \
     | grep -vE '^\s*#' | grep -q 'var/lib/nzbfast'; then
    if sed -n '/^%files/,/^%post/p' $PKG/rpm/nzbfast.spec.in | grep -v '^#' | grep -q '/var/lib/nzbfast'; then
        bad "the rpm %files section claims a path under /var/lib/nzbfast"
    else
        ok "the rpm %files section owns nothing under /var/lib/nzbfast"
    fi
else
    ok "the rpm %files section owns nothing under /var/lib/nzbfast"
fi
# Both formats must go through the same setup script, or the two distros
# drift on exactly the code path that decides whether settings survive.
grep -q 'setup-data-dir.sh' $PKG/deb/postinst \
    && ok "the deb postinst calls setup-data-dir.sh" \
    || bad "the deb postinst does not call setup-data-dir.sh"
grep -q 'setup-data-dir.sh' $PKG/rpm/nzbfast.spec.in \
    && ok "the rpm %post calls setup-data-dir.sh" \
    || bad "the rpm %post does not call setup-data-dir.sh"
# An upgrade restarts a RUNNING daemon and must not start a stopped one.
grep -q 'try-restart' $PKG/deb/postinst \
    && ok "the deb upgrade path uses try-restart" \
    || bad "the deb upgrade path does not use try-restart"
grep -q 'try-restart' $PKG/rpm/nzbfast.spec.in \
    && ok "the rpm upgrade path uses try-restart" \
    || bad "the rpm upgrade path does not use try-restart"

echo
echo "3. setup-data-dir.sh against a fake root"
T=$(mktemp -d)
mkdir -p "$T/usr/share/nzbfast" "$T/etc/nzbfast"
cp packaging/config.example.json "$T/usr/share/nzbfast/config.example.json"
cp $PKG/nzbfast.env "$T/etc/nzbfast/nzbfast.env"
run_setup() { NZBFAST_PKG_ROOT="$T" sh $PKG/setup-data-dir.sh >/dev/null 2>&1; }

run_setup || bad "setup-data-dir.sh exited non-zero on a fresh root"
[ -d "$T/var/lib/nzbfast/downloads" ] && [ -d "$T/var/lib/nzbfast/watch" ] \
    && ok "creates the data, downloads and watch directories" \
    || bad "did not create the data directories"
[ -f "$T/var/lib/nzbfast/config.json" ] \
    && ok "seeds config.json when there is none" \
    || bad "did not seed config.json"

# The upgrade case, which is the one that matters. Put a config and a
# settings file in place, run it again the way every upgrade does, and
# require both to come out untouched byte for byte.
echo '{"servers":[{"host":"real.example.com"}]}' > "$T/var/lib/nzbfast/config.json"
echo '{"speedlimit":42}' > "$T/var/lib/nzbfast/settings.json"
echo 'aaaabbbbccccdddd' > "$T/var/lib/nzbfast/apikey"
before_c=$(cat "$T/var/lib/nzbfast/config.json")
run_setup || bad "setup-data-dir.sh exited non-zero on a second run"
[ "$(cat "$T/var/lib/nzbfast/config.json")" = "$before_c" ] \
    && ok "an existing config.json is left alone (this is the upgrade path)" \
    || bad "config.json was REPLACED on the second run"
[ "$(cat "$T/var/lib/nzbfast/settings.json")" = '{"speedlimit":42}' ] \
    && ok "settings.json is left alone" \
    || bad "settings.json was touched"
[ "$(cat "$T/var/lib/nzbfast/apikey")" = 'aaaabbbbccccdddd' ] \
    && ok "the apikey file is left alone" \
    || bad "the apikey file was touched"

# A blanked-out env file must fall back to the documented paths, not to
# an empty string - which would put the data directory at the filesystem
# root and the downloads in the daemon's working directory.
printf 'NZBFAST_CONFIG=\nNZBFAST_OUT=\nNZBFAST_WATCH=\n' > "$T/etc/nzbfast/nzbfast.env"
rm -rf "$T/var/lib/nzbfast"
run_setup || bad "setup-data-dir.sh exited non-zero with an emptied env file"
[ -f "$T/var/lib/nzbfast/config.json" ] \
    && ok "an emptied env file falls back to the default paths" \
    || bad "an emptied env file did not fall back to the defaults"

# An env file that moves the install must be followed, including for the
# seeded config - otherwise an admin who moved the data directory gets a
# fresh config at the OLD path and a daemon reading the new one.
rm -rf "$T/var/lib/nzbfast" "$T/srv"
printf 'NZBFAST_CONFIG=/srv/nzb/config.json\nNZBFAST_OUT=/srv/nzb/dl\nNZBFAST_WATCH=/srv/nzb/watch\n' \
    > "$T/etc/nzbfast/nzbfast.env"
run_setup || bad "setup-data-dir.sh exited non-zero with a moved data directory"
[ -f "$T/srv/nzb/config.json" ] && [ -d "$T/srv/nzb/dl" ] \
    && ok "a moved data directory in the env file is followed" \
    || bad "the env file's paths were ignored"
[ -e "$T/var/lib/nzbfast/config.json" ] \
    && bad "seeded a config at the default path as well as the moved one" \
    || ok "nothing is left at the default path when the env file moves it"
rm -rf "$T"

echo
echo "passed: $PASS  failed: $FAIL"
[ "$FAIL" -eq 0 ]

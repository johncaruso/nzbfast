# What to capture on a real QNAP

The package was built and tested without one. Everything below is either
a guess that only a real box can settle, or a claim the package makes
that nobody has watched it keep. Ordered so that each step's answer is
still useful if a later one fails.

Run it over SSH with a shell as admin. Paste the transcript back whole -
the raw output is worth more than a summary, because several of these
are "what does this actually return" rather than pass/fail.

## 0. Before anything is installed

```sh
uname -m; uname -a
/sbin/getcfg System Version -f /etc/config/uLinux.conf
/sbin/getcfg "" Platform -f /etc/platform.conf
```

**`uname -m` decides whether the rest of this is a test of the package
or of its refusal.** `x86_64` or `aarch64` and everything below applies.
`armv7l` (the TS-x31/x41 families) and the install is supposed to refuse
with a message naming the architecture, before anything is unpacked - in
which case skip to §6, which is then the whole test. Anything else is a
result worth having on its own.

The shares, which is **the biggest guess in the package**. The install
picks the download folder from these, and the answer was read out of
QDK's source, never off a NAS:

```sh
/sbin/getcfg SHARE_DEF defDownload -f /etc/config/def_share.info
/sbin/getcfg SHARE_DEF defPublic   -f /etc/config/def_share.info
ls -ld /share/*/          # which volumes exist, and their real names
ls -ld /share/Download /share/Public 2>&1
```

If `defDownload` is empty or names a share that does not exist, the
install falls back through Public to the package's own directory and
says so loudly. That is a supported path, not a bug - but knowing which
path a real box takes is the point of asking.

## 1. Install

App Center > the gear icon > Install Manually > the `.qpkg`. Expect one
"not from the App Center" style warning; that is normal for any
third-party package and there is no signature to buy.

Capture the App Center log (Control Panel > System > System Logs, or
`/sbin/log_tool -q -e 0 | tail -40`). The install prints its own
decisions and they are the interesting part:

```
nzbfast: data folder: /share/CACHEDEV1_DATA/Download/nzbfast
```

Then:

```sh
QPKG_ROOT=$(/sbin/getcfg nzbfast Install_Path -f /etc/config/qpkg.conf)
echo "$QPKG_ROOT"
cat "$QPKG_ROOT/nzbfast.env"
ls -la "$QPKG_ROOT" "$QPKG_ROOT/bin"
```

Three claims to check against that output:
- `bin/nzbfast` is a symlink to the arch this box runs, and **the other
  architecture's binary is gone** (the package ships both; install
  deletes the one it cannot run).
- `nzbfast.env` names a data folder **outside** `$QPKG_ROOT`. That is
  the whole reason the layout looks the way it does: App Center's
  uninstall does `rm -rf` over `$QPKG_ROOT`.
- the volume picker's answer was honoured, if the box has more than one
  volume.

## 2. Does it run

```sh
/etc/init.d/nzbfast.sh status
cat /var/run/nzbfast.pid; ps | grep -c [n]zbfast
id -u; ls -ld "$(grep NZBFAST_DATA "$QPKG_ROOT/nzbfast.env" | cut -d= -f2-)"/config
curl -sS -o /dev/null -w '%{http_code}\n' http://127.0.0.1:6789/
tail -30 "$QPKG_ROOT/nzbfast.log"
```

- **Which user is the daemon?** The package assumes QTS runs its service
  scripts as root, unlike Synology's DSM 7, where the package account
  cannot see shared folders at all and that assumption cost a whole
  investigation. `ls -ld` on the created folders answers it.
- App Center should show the app as **running** (it reads the pidfile
  named in `qpkg.cfg`), and its **Open** button should land on the
  dashboard rather than on a QTS proxy path.
- `status` must agree with reality. It identifies our daemon by matching
  the config path in `/proc/<pid>/cmdline`, deliberately, so that a
  Container Station nzbfast on the same box is not mistaken for this
  one - but that match has only ever run against GNU tools.

Two smaller ones while there is a shell open:
- Settings > the port field should refuse to change, with an
  explanation. QTS owns that port and nzbfast cannot move it.
- `/etc/init.d/nzbfast.sh stop` then `start` - stop should return only
  once the process is actually gone.

## 3. THE ONE THAT MATTERS: upgrade over it

Other platforms have lost people's settings here, so do it deliberately.
Add a server in the dashboard first, so there is something real to lose.

Before:

```sh
D=$(grep NZBFAST_DATA "$QPKG_ROOT/nzbfast.env" | cut -d= -f2-)
md5sum "$D/config/settings.json" "$D/config/config.local.json" "$D/config/apikey" 2>&1
ls -la "$D/config" "$D/downloads"
md5sum "$QPKG_ROOT/nzbfast.env"
```

Install the same `.qpkg` again (or a newer one) over the top. Then the
same three commands, plus:

```sh
find "$D" "$QPKG_ROOT" -name '*.qdkorig' -o -name '*.qdksave'   # MUST be empty
ls -l "$QPKG_ROOT/bin"                                          # relinked, still one binary
cat "$QPKG_ROOT/.oldlist" 2>/dev/null | head -20                # QDK's own accounting
```

Every md5 must be unchanged and **`.qdkorig` / `.qdksave` must not
exist anywhere**. Those two suffixes are what QDK's `store_config`
leaves behind when it decides a config file is its business, and the
package is built so that it never is: nothing is listed in
`QPKG_CONFIG`, and the package ships no config file for QDK's
obsolete-file sweep to delete. If either file appears, that reasoning is
wrong and it is the single most important thing to bring back.

Then confirm the dashboard still has the server that was added, and the
API key did not change (an integration would break if it did).

## 4. A job end to end

One small NZB through the queue, if there is a provider configured.
Downloads should land under the folder from §1 and be visible in File
Station - the reason the install prefers a real shared folder over a
bare directory is precisely that File Station cannot show the latter.

## 5. Uninstall, LAST

```sh
D=$(grep NZBFAST_DATA "$QPKG_ROOT/nzbfast.env" | cut -d= -f2-)
echo "$D"          # note it down BEFORE removing
```

Remove in App Center, then:

```sh
ls -la "$D" "$D/config" "$D/downloads"
ls -la "$QPKG_ROOT" 2>&1     # should be gone
/sbin/log_tool -q -e 0 | tail -5
```

**The data folder must survive.** Uninstalling a downloader is not a
request to delete the downloads, and App Center gives no undo. The log
should carry a line naming where the data was left.

## 6. If this box is 32-bit ARM

Then the install is supposed to fail, and what to check is that it fails
*well*:

- App Center shows a message naming the architecture and saying nzbfast
  ships 64-bit builds only.
- `ls -la /share/*/.qpkg/ | grep nzbfast` - **nothing should have been
  created**. The refusal runs before the payload is unpacked, so a
  half-installed directory left behind would be a bug worth reporting.

That is still a useful visit: it is the first time that arm has run
anywhere. Widening the package to armv7 is scoped in TODO 176 and gated
on the 32-bit build landing, not on packaging.

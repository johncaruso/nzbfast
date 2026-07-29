# nzbfast Homebrew tap

Homebrew formula for [nzbfast](https://github.com/nzbfast/nzbfast), the fast
Usenet (NZB) downloader: one self-contained executable that downloads at line
rate, verifies and extracts in a single pass, and speaks the SABnzbd and
NZBGet APIs so Sonarr and Radarr connect unmodified.

## Install

```sh
brew install nzbfast/tap/nzbfast
```

That is the whole thing. There is no config file to edit: start the daemon and
add your Usenet server in the web UI.

```sh
brew services start nzbfast
open http://localhost:6789
```

Prefer the terminal? `nzbfast setup` walks through the same questions.

To update, `brew upgrade nzbfast` like anything else.

## What you get

A single `nzbfast` binary, plus the manual at
`$(brew --prefix)/share/doc/nzbfast/MANUAL.html`.

Nothing else is installed and nothing else is required. PAR2 repair and RAR
extraction are native to the binary, so there is no dependency on `par2` or
`unrar`. If you happen to have them on PATH they are still honoured as a
fallback, but the formula does not pull them in.

Supported: macOS on Apple Silicon and Intel, Linux on x86_64 and arm64. The
Linux builds are statically linked, so they do not care which distribution or
glibc version you are on.

## Where your data lives

| What | Where |
| --- | --- |
| Settings, API key, job state | `$(brew --prefix)/etc/nzbfast` |
| Downloads and watch folder | `$(brew --prefix)/var/nzbfast` |
| Daemon log | `$(brew --prefix)/var/log/nzbfast.log` |

Both directories survive `brew upgrade` and `brew uninstall`, so your server
credentials and queue are not something a reinstall throws away.

## Sonarr and Radarr

Add nzbfast as a SABnzbd or NZBGet download client pointing at
`http://localhost:6789/api`. The API key is on the Settings page. No other
configuration is needed on either side.

## Other ways to install

This tap is for the command line. The download page has a macOS disk image, a
Windows installer, Docker images and plain archives:
<https://nzbfast.github.io/nzbfast/>

There is deliberately no Cask here. A Cask would install the `NzbFast.app`
bundle from the disk image, and Homebrew quarantines what it downloads. The
app is not yet signed with an Apple Developer ID, so a Cask install would
produce an app that macOS refuses to open until the user clears the quarantine
by hand. That is a worse first run than either this formula or the disk image,
which explains the extra step where the user is already looking. A Cask
becomes worth adding once the app is signed and notarised.

## Reporting problems

Formula bugs (a bad checksum, a broken `brew` step) belong here. Anything
about nzbfast itself belongs on the
[main repo](https://github.com/nzbfast/nzbfast/issues).

## Why a tap and not homebrew-core

homebrew-core only accepts projects that clear its notability bar, currently
75 GitHub stars, 30 forks or 30 watchers. nzbfast is not there yet, so the tap
is the supported route. The intent is to submit to homebrew-core once the
project qualifies, at which point `brew install nzbfast` works without tapping
anything and this repo stays as a fallback.

nzbfast is GPL-3.0-or-later. This repository only carries the packaging.

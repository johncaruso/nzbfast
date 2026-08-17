# Deploying nzbfast

nzbfast ships as one static binary (`nzbfast`) - RAR extraction and
PAR2 repair are native (an external `unrar`/`par2` on `$PATH` is only
ever used as a last-resort fallback). The `serve` subcommand
runs the daemon: queue manager, watch folder, web UI, and a
SABnzbd-compatible API (so Sonarr / Radarr / Prowlarr work unchanged).

Everything here is deployment glue - no code. The engine is `crates/`.

## Docker (recommended for NAS / seedbox)

```sh
docker compose up -d          # pulls ghcr.io/nzbfast/nzbfast (or `build: .`)
```

UI + API at `http://<host>:6789`; add your Usenet server in the Welcome
panel there. There is no config file to write by hand any more - the
wizard writes it - though `config.example.json` still documents the
shape for anyone provisioning one from configuration management.
Volumes: `./config`, `./downloads`, `./watch` (drop `.nzb` files there to
auto-queue). `PUID`/`PGID` set the owner of downloaded files
(linuxserver convention).

On the first start nzbfast generates an API key, prints it in the
container log, and stores it as `apikey` in the `config` volume - that is
the value Sonarr/Radarr want. Set `NZBFAST_APIKEY` instead to choose your
own, or `NZBFAST_OPEN=1` to run keyless behind your own auth layer.

Because the container publishes its control API on the LAN, its
entrypoint refuses to start in the cases where the daemon would otherwise
warn and carry on keyless: an `apikey` file that is empty or unreadable, a
`config` volume that cannot be written on a first run, and an install that
has run before but has no key. Each message names the fix, and
`NZBFAST_OPEN=1` is always the way to say "keyless on purpose".

Multi-arch image (amd64 + arm64) is built by `.github/workflows/release.yml`.

`synology/docker-compose.yml` is the ready-to-run version of the root
compose for a Synology Container Manager Project: Synology defaults for
`PUID`/`PGID`, the Watchtower sidecar, and the socket-free scheduled-task
alternative written out in the comments. The website serves a byte-copy
of it as `website/nzbfast-synology.yml` so the download link on
`download.html` is one click; `tests/synology-compose-parity.sh` fails if
the two drift.

## Linux (systemd, bare metal)

```sh
sudo install -m755 target/release/nzbfast /usr/local/bin/
sudo useradd -r -s /usr/sbin/nologin nzbfast || true
sudo mkdir -p /etc/nzbfast /var/lib/nzbfast/{downloads,watch}
sudo install -m600 packaging/config.example.json /etc/nzbfast/config.json  # edit
sudo chown -R nzbfast:nzbfast /etc/nzbfast /var/lib/nzbfast
sudo cp packaging/systemd/nzbfast.service /etc/systemd/system/
sudo systemctl enable --now nzbfast
```

The unit is hardened (`ProtectSystem=strict`, `NoNewPrivileges`, writes
confined to its data dirs).

## API key and listening address

From 1.0.9 every launcher behaves like the container: on a genuinely new
install the daemon generates an API key, stores it 0600 as `apikey` next
to the config file, and prints it once at startup. An install that has
run before is left exactly as it was - no key appears under it, so an
already-configured Sonarr keeps working across the upgrade. `--apikey`
still wins outright, and `NZBFAST_OPEN=1` keeps the daemon deliberately
keyless for deployments fronted by Authelia, oauth2-proxy or similar.

`serve --bind` sets the listening address. It defaults to `0.0.0.0`, and
should stay there for NAS and headless boxes, phones, and *arr apps on
another host. `--bind 127.0.0.1` restricts the daemon to its own machine
(for example when a reverse proxy on the same box is the only thing that
should talk to it).

## macOS

**Homebrew** (`nzbfast/homebrew-tap`, published; `packaging/homebrew/bump-tap.sh`
pushes each release's formula to it):
```sh
brew install nzbfast/tap/nzbfast
brew services start nzbfast
```

**launchd** (manual): edit `packaging/launchd/com.nzbfast.daemon.plist`
(replace `REPLACE_HOME`), copy to `~/Library/LaunchAgents/`, then
`launchctl load` it.

**Native app**: `macapp/` - a SwiftUI front-end over the daemon (see its
README). It can point at a local or remote `nzbfast serve`.

## Config

`config.json` is the server list (see `config.example.json`). List
several providers on different backbones - nzbfast fetches every article
from the union, so a post missing on one completes from another.

| Field | Meaning |
|---|---|
| `host`/`port`/`tls` | server address; 563 = NNTPS |
| `username`/`password` | credentials |
| `connections` | max simultaneous connections for this server |

## Everything else under packaging/

This file covers the three paths most people take. The rest each carry
their own README, and this is the index so they are findable:

| Path | What it is | Status |
|---|---|---|
| `linux/` | `.deb` / `.rpm` builder, maintainer scripts, apt repo | beta |
| `flatpak/` | Flatpak manifest and cargo-sources generator | beta |
| `freebsd/` | rc.d script and smoke test; built in a VM each release | beta, untested on real hardware |
| `qnap/` | native App Center `.qpkg` | beta |
| `synology/` | `.spk` package and the Container Manager compose | shipped |
| `windows/` | Inno Setup installer and the portable zip layout | shipped |
| `mac/` | DMG build, background art, install page | shipped |
| `docker/` | release image and push script | shipped |
| `homebrew/` | formula and the tap bump script | shipped |
| `scoop/`, `winget/` | generated manifests (`make-pkg-manifests.sh`) | manifests generated; catalogue submission not complete |
| `catalogues/` | source of truth for third-party app catalogue listings (Unraid, CasaOS, TrueNAS, Umbrel, Proxmox) | per-catalogue |
| `android/`, `ios/` | mobile shells and test kits | experimental |

## Building the image locally

```sh
docker build -t nzbfast .
docker run --rm -p 6789:6789 -v "$PWD/config:/config" nzbfast
```

## Licensing note

The workspace is **GPL-3.0-or-later** (`LICENSE`), with the full
third-party breakdown in `COPYRIGHT.md`. RAR extraction is native (the
vendored `rars` crate); an `unrar` or `par2` you install yourself is
only ever invoked as a subprocess fallback (clean process boundary, no
linking). rapidyenc (vendored, public domain) is the only
compiled-in third-party C. Note that several Rust dependencies are
Apache-2.0-only, which is why the project is v3 rather than v2.

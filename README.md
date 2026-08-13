# nzbfast

**The fast Usenet downloader.** One self-contained executable: download engine,
web dashboard, poster-wall media browser, built-in indexer, realtime preview,
and the repair/extraction tools, nothing else to install.

[**Website**](https://nzbfast.github.io/nzbfast/) ·
[Features](https://nzbfast.github.io/nzbfast/features.html) ·
[Benchmarks](https://nzbfast.github.io/nzbfast/benchmarks.html) ·
[Manual](https://nzbfast.github.io/nzbfast/MANUAL.html) ·
[Download](https://nzbfast.github.io/nzbfast/download.html)

[![The nzbfast dashboard mid-download](https://nzbfast.github.io/nzbfast/assets/dash-hero.png)](https://nzbfast.github.io/nzbfast/)

The rest of the screenshots (poster wall, queue detail, settings, mobile) are on
the [home](https://nzbfast.github.io/nzbfast/) and
[features](https://nzbfast.github.io/nzbfast/features.html) pages, and the
measured numbers with full method notes are on the
[benchmarks](https://nzbfast.github.io/nzbfast/benchmarks.html) page.

## Why it's fast

- **Pipelined NNTP** - many article requests in flight per connection, so
  round-trip latency never idles a socket. Line-rate on 10 GbE has been
  measured and sustained.
- **One-pass pipeline** - download, PAR2 verification, and extraction overlap.
  Store-mode RAR volumes are extracted *in the stream* and never touch disk:
  a job needs 1× the release size, not 2×, and post-processing time is ~zero.
- **Multi-provider union availability** - every server contributes; articles
  missing on one backbone are fetched from another. Dead servers never stall
  the queue.
- **Bounded memory** - all engine caches share one budget and degrade to disk
  rather than swapping your machine.

## Features

- Web dashboard: live throughput/resource charts, drag-to-reorder queue with
  per-job detail, provider leaderboard, data-usage history, in-UI log,
  every setting editable in the browser
- Poster wall: your newsgroups as a media library, keyless metadata
  (TVmaze / iTunes / IMDb datasets / Wikidata / AniList), preview or download
  from the tile
- Preview with real seeking while the download runs
- Built-in indexer, with a newznab endpoint, so nzbfast can be your indexer
- Watchlist auto-grab with quality upgrades, RSS automation, Smart Folders,
  weekly scheduler, SABnzbd-compatible post-processing scripts
- SABnzbd-compatible API and NZBGet JSON-RPC: Sonarr/Radarr, nzb360,
  LunaSea etc. work out of the box
- Crash-safe resume from an article journal; automatic PAR2 repair;
  encrypted-archive handling
- Single static-ish binary for macOS (universal) and Windows; Docker image

Full documentation: [**User Manual**](https://nzbfast.github.io/nzbfast/MANUAL.html)
- also served by the app itself at `/manual`.

Downloads: [Releases](https://github.com/nzbfast/nzbfast/releases) ·
Issues: [issue tracker](https://github.com/nzbfast/nzbfast/issues)

**NAS / Docker** - multi-arch image (amd64 + arm64) on Docker Hub and ghcr:

```sh
docker run -d -p 6789:6789 \
  -e NZBFAST_OUT=/data/usenet \
  -v /srv/nzbfast/config:/config \
  -v /srv/nzbfast/watch:/watch \
  -v /data/usenet:/data/usenet \
  nzbfast/nzbfast
```

Pick your own host folders, but give the volumes **absolute** paths: the
mapped `/config` folder *is* your install (settings, API key, queue), and a
relative path like `./config` points at a different, empty folder every
time the command runs from a different directory - which looks exactly like
an update that wiped your settings. To update, pull the new image and
recreate the container with the same mappings. Easier still is the repo's
[docker-compose.yml](docker-compose.yml), where updating is
`docker compose pull && docker compose up -d`.

**Running Sonarr or Radarr too?** The downloads line above is mapped to the
same path on both sides, and under a root you also give them, and both
halves matter. nzbfast reports where a finished job is, so that path has to
mean the same thing inside their container as inside this one - otherwise
the download sits in the queue and the \*arr reports a remote path mapping
error while the files are perfectly fine. And when downloads and the
library sit under one root (`/data/usenet` and `/data/media`), an import is
a rename: instant, with no second copy. On separate mounts Docker makes
them look like separate filesystems even when they are not, and every
import copies the whole 5-50 GB release and deletes the original. The root
does not have to be `/data` - `/shared`, `/storage`, anything - as long as
every container uses the same one. Give nzbfast the usenet subtree only;
your \*arr is what moves the files and it sees both sides.

There is no `incomplete` folder to map. SABnzbd needs one because it writes
there and moves everything when a job finishes; nzbfast writes at the final
path from the first article on, so a SAB migrant has two filesystem
boundaries to get right and an nzbfast user has exactly one.

Then open `http://<host>:6789` and add your provider in the Welcome panel.
On a new install nzbfast generates an API key for itself, prints it once at
startup, and stores it as `apikey` beside the config - that is the value
Sonarr/Radarr and phone apps want. An existing install is never given one,
so upgrading changes nothing. Wiring up Sonarr/Radarr? Add
`-e NZBFAST_APIKEY=<your key>` to the run command (or the compose
environment) instead: a key stored in the container definition lives on the
host and survives any container recreation, and a key set later in Settings
still wins over it.
Synology (Container Manager) has a step-by-step guide:
[**docs/SYNOLOGY.md**](docs/SYNOLOGY.md). Unraid / TrueNAS SCALE / QNAP use
the same image.

## Verifying a download

From v1.0.5, releases include binaries built on GitHub's hosted runners
straight from this repository, each carrying a signed **build-provenance
attestation** (SLSA, via Sigstore). The attestation binds the exact file
to the workflow run and commit that produced it - you can confirm a
binary was built from this source without trusting us to hold any key.

With the [GitHub CLI](https://cli.github.com):

```sh
gh attestation verify nzbfast-x86_64-unknown-linux-gnu.tar.gz --repo nzbfast/nzbfast
```

A successful verify prints the source repo, commit SHA, and workflow
run. Attestations are also browsable under this repository's
**Attestations** tab, and every release ships `SHA256SUMS.txt` for a
plain checksum check (`shasum -a 256 -c SHA256SUMS.txt`).

Newer releases also attach the attestation beside each tarball, so the
proof is a file you can download and keep rather than a lookup (older
releases publish it only through the attestations API, where the plain
`verify` above still finds it):

```sh
gh attestation verify nzbfast-x86_64-unknown-linux-gnu.tar.gz \
  --bundle nzbfast-x86_64-unknown-linux-gnu.tar.gz.intoto.jsonl \
  --repo nzbfast/nzbfast
```

The attested files are the `nzbfast-<target-triple>.tar.gz` assets. The
convenience packages (DMG, Windows installer, platform zips) are built
and signed through separate channels; grab a target-triple tarball when
you want a binary you can verify against source.

Container images are attested the same way once they are pushed by the
public workflow rather than by hand - the workflow assembles the image
from the release's own binaries (after checking them against
`SHA256SUMS.txt`) and attests the pushed manifest digest:

```sh
gh attestation verify oci://ghcr.io/nzbfast/nzbfast:<version> --repo nzbfast/nzbfast
```

The Docker Hub tags (`nzbfast/nzbfast`) are pushed from the same build
and carry the identical manifest digest. Images pushed before the
attestation pipeline existed predate it, and `gh attestation verify`
will simply report that no attestation is found for those digests.

That covers the binary. For the data it downloads,
[docs/INTEGRITY.md](docs/INTEGRITY.md) documents every integrity check the
engine performs and when, each claim citing the source line that implements it,
including the exact boundary where the in-stream fast path stops applying.

Security reports: see [SECURITY.md](SECURITY.md).

## Build

The toolchain is pinned by `rust-toolchain.toml` (rustup picks it up
automatically).

```sh
cargo build --release -p nzbfast
./target/release/nzbfast setup     # interactive server setup
./target/release/nzbfast serve --open
```

Cross-builds: macOS universal via `--target aarch64-apple-darwin
x86_64-apple-darwin` + `lipo`; Windows via `x86_64-pc-windows-gnu` (mingw-w64)
with `-C link-arg=-static`.

## Third-party components

- [rapidyenc](vendor/rapidyenc) - SIMD yEnc decoding (see its license)
- [rars](vendor/rars) (MIT OR Apache-2.0) - pure-Rust RAR extraction,
  so RAR handling is fully native. PAR2 repair is native too; a
  separately installed `unrar` or `par2` is invoked from `$PATH` only
  as a last-resort fallback.

## Contributing

Contributions of every size are welcome - typo fixes, docs, UI polish,
bug reports, code. Start with [CONTRIBUTING.md](CONTRIBUTING.md);
issues labeled **`good first issue`** are picked to be approachable.
Every PR gets built and tested by CI automatically.

## License

**GNU General Public License v3.0 or later** - see [LICENSE](LICENSE), with
the third-party breakdown in [COPYRIGHT.md](COPYRIGHT.md).

nzbfast is free software: use it, study it, share it, and modify it. If you
distribute a modified version, those changes must be shared under the same
terms.

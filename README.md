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
  -v ./config:/config -v ./downloads:/downloads -v ./watch:/watch \
  nzbfast/nzbfast
```

Then open `http://<host>:6789` and add your provider in the Welcome panel.
On a new install nzbfast generates an API key for itself, prints it once at
startup, and stores it as `apikey` beside the config - that is the value
Sonarr/Radarr and phone apps want. An existing install is never given one,
so upgrading changes nothing.
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

The attested files are the `nzbfast-<target-triple>.tar.gz` assets. The
convenience packages (DMG, Windows installer, platform zips) are built
and signed through separate channels; grab a target-triple tarball when
you want a binary you can verify against source.

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

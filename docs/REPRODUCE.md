# Rebuilding a release from source

This document is the recipe for rebuilding a released
`nzbfast-<target-triple>.tar.gz` from public source, and an honest,
measured ledger of how close a rebuild currently gets to the released
digest. It makes no claim beyond what the ledger shows.

This is a different claim from the build-provenance attestation
(README, "Verifying a download"). The attestation proves a binary came
out of a run of the public workflow at a named commit, with GitHub and
Sigstore as the trust anchors; it requires trusting that GitHub's
runner executed the workflow as written. A digest-matching rebuild
removes even that assumption: you build it yourself and compare bytes.
The attestation is live today. The rebuild story is a work in progress,
and the ledger below says exactly where it stands.

## Where releases are built

The `nzbfast-<target-triple>.tar.gz` release assets are built by
[`.github/workflows/provenance-release.yml`](../.github/workflows/provenance-release.yml)
on GitHub-hosted runners (`ubuntu-latest` for the Linux targets,
`macos-latest` for the mac targets), at the release tag's commit. The
exact runner image name and version for any run are printed in that
run's "Set up job" log under "Runner Image". The Rust toolchain is
pinned by `rust-toolchain.toml`; dependencies are pinned by
`Cargo.lock` and built with `--locked`.

## The recipe

For tags where the workflow sets `SOURCE_DATE_EPOCH` and the remap flag
(see the ledger for which tags that covers):

Build each target on the same kind of host the workflow used: the Linux
targets on x86_64 Ubuntu, the mac targets on macOS. Building a target on
a different host than CI did is not a rebuild of that asset.

```sh
git clone https://github.com/nzbfast/nzbfast
cd nzbfast
git checkout vX.Y.Z                 # rustup picks up the pinned toolchain
rustup target add <target-triple>

# aarch64-unknown-linux-gnu ONLY. CI cross-compiles this target from an
# x86_64 runner, so it installs a cross toolchain and points cargo and
# the `cc` crate at it. `rustup target add` alone gives you the Rust
# std for the target and no linker, and the build fails at link time -
# closed, not wrong, but it will not get you an artifact.
sudo apt-get update
sudo apt-get install -y gcc-aarch64-linux-gnu g++-aarch64-linux-gnu
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc
export CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc
export CXX_aarch64_unknown_linux_gnu=aarch64-linux-gnu-g++

# Pin the clock the same way the workflow does (the tag's commit time),
# and remap the builder's home the same way. RUSTFLAGS must match the
# workflow EXACTLY: the flags feed cargo's -Cmetadata symbol hashes, so
# a build with different flags diverges even where no path is embedded.
# Assumes your cargo registry lives under $HOME/.cargo (the default).
export SOURCE_DATE_EPOCH=$(git log -1 --format=%ct)
export RUSTFLAGS="--remap-path-prefix=$HOME=/build"

CARGO_INCREMENTAL=0 cargo build --release --locked -p nzbfast \
    --target <target-triple>

# Package identically: entry mtime pinned to the commit time, owner
# zeroed, gzip with no name or timestamp in its header. The
# ownership-zeroing flags are spelled differently by the two tar
# flavours; use the one matching your platform (GNU tar on Linux,
# bsdtar on macOS - the same split the workflow's runners have).
BIN=target/<target-triple>/release/nzbfast
python3 -c 'import os,sys;t=int(os.environ["SOURCE_DATE_EPOCH"]);os.utime(sys.argv[1],(t,t))' "$BIN"
# GNU tar:
tar --owner=0 --group=0 --numeric-owner \
    -cf - -C "$(dirname "$BIN")" nzbfast | gzip -n -9 > nzbfast-<target-triple>.tar.gz
# bsdtar:
tar --uid 0 --gid 0 --uname "" --gname "" \
    -cf - -C "$(dirname "$BIN")" nzbfast | gzip -n -9 > nzbfast-<target-triple>.tar.gz
shasum -a 256 nzbfast-<target-triple>.tar.gz
```

## Three levels of comparison

Compare against the released asset at whichever level your environment
supports, strictest first:

1. **Tarball digest** - `shasum -a 256` of the `.tar.gz` itself. This
   additionally requires your `gzip` to emit the same deflate stream as
   the runner's; gzip output is stable across common versions at a given
   level, but it is a real variable.
2. **Tar-stream digest** - `gzip -dc file.tar.gz | shasum -a 256`.
   Drops the gzip variable; still covers all tar metadata.
3. **Inner binary digest** - extract and `shasum -a 256 nzbfast`. The
   comparison that matters most: the actual code you would run.

## Environment requirements

- rustc is pinned by the repo, so it is never a variable if you use
  rustup. `CARGO_INCREMENTAL=0` and `--locked` are mandatory.
- The workspace contains C dependencies (mimalloc, SQLite) compiled by
  your system C compiler. On mac targets that is Apple clang: a
  different Xcode/clang major than the runner's produces different
  (same-length) machine code - measured as the entire remaining
  divergence in the v1.0.10 ledger. Match the runner's image for a
  strict comparison. Same for gcc on the Linux targets.
- The linker matters the same way the C compiler does; it ships with
  the same Xcode / distro toolchain, so matching the image covers it.
- Absolute build paths affect exactly 48 bytes (the `LC_UUID` class,
  ledger row F) and nothing else. Replicate the runner's paths to pin
  them, or exclude those two ranges from the comparison.
- macOS arm64 binaries end with an ad-hoc code signature and carry an
  LC_UUID; both are content-derived, so they match if and only if
  everything before them matches. No signing identity is involved.

## Measured ledger

### v1.0.10 (tested 28 Jul 2026): does NOT rebuild to the same digest

Target `aarch64-apple-darwin`, released asset from run 30325908707
(runner image `macos-26-arm64` 20260720.0258.1). Rebuild machine: arm64
macOS 27, Apple clang 21, rustc 1.97.0 (the pin). Released tarball
sha256
`410f09bc64d32f2598832fa00d03f81c9a7e6aaca79a3b3519efc5e0e04d5a9e`,
inner binary
`b4c773a9fe90e97e810174088ee1f48153c85743f8d9a86f9dea7134de3b279b`,
19,915,872 bytes.

| Build | Config | Result |
|---|---|---|
| A | exactly the workflow's env at that tag (no remap, no pinned clock) | vs released binary: identical size; 255,819 bytes differ (1.28%) |
| B | A + `--remap-path-prefix` of the local home onto the runner's | vs released binary: 24,491 bytes differ (0.12%) |
| C | identical to B, fresh target dir | B and C differ from each other by only 83 bytes |
| D, E | two builds with `SOURCE_DATE_EPOCH` pinned to the tag's commit time + remap, same paths | **bit-identical to each other**, twice over (repeated with the full packaging step on both mac targets: binaries AND tarballs identical) |
| F | D's config, but a different workspace path, target-dir path, or remap-flag literal | exactly **48 bytes** differ in every combination tried: the 16-byte `LC_UUID` and one 32-byte signature slot derived from it; all code, data and strings byte-stable |

What the diffs are, measured, not guessed:

- **Build A's 1.28%** is dominated by 398 absolute cargo-registry path
  strings (`/Users/runner/.cargo/...` on the runner vs the local home)
  embedded in panic metadata, plus everything those strings shift.
- **Build B's 0.12%** residual includes the build clock: mimalloc's
  version banner embeds `__DATE__`/`__TIME__`, so the released binary
  carries the literal wall-clock second CI built it. The rest sits in
  code, literal-pool ordering and linker tables, and is attributed by
  elimination: row F measures flag and path differences at exactly 48
  bytes, and rows D/E measure the pinned-clock toolchain at zero, so
  the only variable left standing is the **Apple toolchain version**
  (this machine's clang/linker is one Xcode generation newer than the
  runner image's). Rebuild on a matching image to remove it.
- **B vs C's 83 bytes** bound the true nondeterminism of the toolchain
  at zero: LC_UUID (16 bytes), the 8-character `__TIME__` string, and
  two content-derived 32-byte hash slots downstream of those. Nothing
  else moved across two clean builds.
- **Row F's 48 bytes** are worth knowing when comparing: the linker
  salts `LC_UUID` with the raw absolute build paths (path remapping
  does not reach it), so a rebuild from a different directory matches
  everything except the UUID and the one signature slot derived from
  it. Replicate the runner's absolute paths for a strict full-file
  match (`/Users/runner/work/nzbfast/nzbfast` on mac,
  `/home/runner/work/nzbfast/nzbfast` on Linux, default `target/`
  dir), or treat exactly those two byte ranges as expected variance.
- The tar.gz adds three more wall clocks on top of the binary: the
  entry mtime (build time), the gzip header mtime (packaging time), and
  the recorded owner `runner/staff`.

The conclusion, stated plainly: **v1.0.10 cannot be rebuilt to its
released digest by anyone, including a re-run of the same workflow on
the same tag**, because the artifact embeds its own build clock in the
binary and in the tarball metadata.

### What changed as a result

As of the workflow revision that ships alongside this document,
`provenance-release.yml` pins `SOURCE_DATE_EPOCH` to the tag's commit
time (both gcc and clang honor it for `__DATE__`/`__TIME__`), remaps
the runner home prefix out of the binary, pins the packaged entry
mtime, zeroes tar ownership, and gzips with `-n`. Together those remove
every difference source identified above except the C-toolchain match,
which the recipe's environment requirements cover.

Builds D and E in the ledger are the validation: under exactly that
regime two clean builds produce the same digest at both the binary and
tarball level, on both mac targets, and the binary's embedded banner
date becomes the tag's commit time instead of the build's wall clock.
Row F bounds every path and flag variation tried at the 48-byte UUID
class. What remains undemonstrated is a match against a real released
asset built by the actual CI image - the toolchain version is the one
variable a local machine could not hold equal in this test. **The
first tag cut with the revised workflow is the first candidate. Until a
rebuild of a released asset measurably matches at level 1 or 2, no
nzbfast copy anywhere may claim rebuilds match, and this ledger is the
only place that status lives.**

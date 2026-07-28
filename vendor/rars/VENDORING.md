# Vendoring `rars`

`vendor/rars/` is a curated copy of the `rars` crate from our perf fork of
[bitplane/rars](https://github.com/bitplane/rars). It is **not** a git subtree
or submodule — it is a mirrored subset, produced by
[`sync-from-fork.sh`](sync-from-fork.sh).

Upstream-tracking policy is FREEZE + cherry-pick: watch the fork for decoder
fixes, port selectively, re-run the gates, then re-vendor.

## What is vendored

| Path | Source in fork | How |
| --- | --- | --- |
| `src/**` | `crates/rars/src/**` | exact mirror (`rsync --delete`) |
| `tests/fixtures/**` | `crates/rars/tests/fixtures/**` | **exact mirror — all of it** |
| `COPYING` | fork repo-root `COPYING` | copied |
| `Cargo.toml` | `crates/rars/Cargo.toml` | **hand-maintained, see below** |

Not vendored: `tests/*.rs` (fork integration tests — we run only the inline
`--lib` tests), `benches/`, `fuzz/`, `python/`, `scripts/`, `target/`.

## Why `tests/fixtures/**` must always come along

The rars unit tests live **inline** in `src/lib.rs` and load inputs via
`env!("CARGO_MANIFEST_DIR")/tests/fixtures/rar15_40/...`. If any referenced
fixture is missing, `cargo test -p rars --lib` fails with `NotFound` on a clean
checkout.

This exact bug shipped once: an earlier sync copied `src/` but dropped
`tests/fixtures/`, and it was hotfixed by hand-vendoring only the two fixtures
the then-current tests happened to read. Hand-picking fixtures re-introduces the
same fragility — the next inline test that references a third fixture breaks
again. So the sync mirrors the **whole** fixtures tree; do not trim it to a
subset.

## Re-vendoring to a newer fork rev

```sh
# 1. Sync src/ + tests/fixtures/ + COPYING from your fork checkout.
RARS_FORK=~/path/to/rars ./vendor/rars/sync-from-fork.sh

# 2. Reconcile Cargo.toml BY HAND *only if* the fork's [dependencies] changed.
#    The vendored manifest deliberately differs from the fork's:
#      - de-workspaced deps (concrete versions, not `.workspace = true`)
#      - version = "0.4.6+nzbfast"
#      - [lints.rust] unsafe_code = "forbid", unused_must_use = "deny"
#      - no [dev-dependencies], no [[bench]] (not vendored)
#    The script never overwrites Cargo.toml, so it survives a re-sync.

# 3. Gate: must stay green.
cargo test -p rars --lib

# 4. Commit.
git add -A vendor/rars
git commit -m "vendor/rars: sync to fork rev <rev>"
```

## Deep gate before a release (decoder changes especially)

The `--lib` gate above and the fuzzers use small inputs, so they are blind to
size-dependent decode bugs: back-references reaching past the streaming window
(>64 MiB), solid cross-member history, and volume-split members only appear in
large real archives. The fork carries a real-`rar` round-trip rig for exactly
these axes at `crates/rars/tests/real_archive_diff.rs`. It is NOT vendored (a
`tests/*.rs` file) and needs a local `rar` 7.x, so run it in the fork checkout
before cutting a release or dropping the external `unrar` fallback:

```sh
cargo test -p rars --test real_archive_diff -- --ignored --nocapture
```

It builds ~76 MiB archives across RAR5/RAR7 dictionary sizes (128 MiB..1 GiB),
solid multi-file sets, and multivolume splits, and asserts rars decodes each
byte-for-byte. This is what would have caught the 64 MiB streaming-window cap.

The whole export ships in the public repo (`vendor` is in
`packaging/PUBLIC_MANIFEST`; `/vendor/` is leak-scan-exempt as third-party
source), which satisfies build-from-source.

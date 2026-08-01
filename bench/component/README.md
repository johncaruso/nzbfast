# Component shootout: how the published RAR and PAR2 numbers are made

Everything on the benchmarks page's "component shootouts" section comes from
the scripts in this directory. They are here so the numbers can be reproduced,
continued, or argued with. An earlier round's recipe was never written down and
those figures could not be reproduced a month later, which is a bad way to
publish a benchmark.

Nothing here is part of the product. It is a bench rig.

## What gets built

`corpusgen.rs` writes four payloads, byte-for-byte identically on every
machine, from a fixed-seed xoshiro256\*\* stream:

| payload | size | character |
|---|---|---|
| `rand.bin` | 1 GiB | incompressible |
| `mixed.bin` | 1 GiB | equal thirds text, structured records, incompressible bytes, with long-range replays |
| `rep.bin` | 1 GiB | 1 MiB of material repeated |
| `small/` | 400 files, 1 GiB | same mixed material, one seed per file |

The payload character is not a detail. A payload built out of block copies
turns every compressed shape into a `memcpy` benchmark; a payload of pure text
turns it into a literal-and-Huffman benchmark; the two do not agree on who
wins. `mixed.bin` is deliberately in the middle, and the `store` and `rep`
shapes cover the two ends on purpose.

`mixed.bin` replays 1 MiB spans from up to 384 MiB back at roughly one slice in
five. That is what makes the 128 MiB-dictionary shape mean anything: those
matches are reachable with `-md128m` and not with the 32 MiB default.

## The seven archive shapes

`shapes-build.sh` turns those payloads into archives with RAR 7.23:

| shape | input | flags |
|---|---|---|
| `store` | `rand.bin` | `-m0` |
| `small` | `small/` | `-m3` |
| `solid` | `small/` | `-m3 -s` |
| `rep` | `rep.bin` | `-m3` |
| `big` | `mixed.bin` | `-m3 -v125m` (4 volumes) |
| `enc` | `mixed.bin` | `-m3 -hpbenchpw` (encrypted headers) |
| `r7dict` | `mixed.bin` | `-m3 -md128m` |

Two flags on every archive matter more than they look:

- **`-ep`**, so archives store bare names. An earlier corpus stored absolute
  paths on some shapes only, and the extractors that recreated the directory
  chain on those legs alone looked slow for a reason that had nothing to do
  with extraction.
- **`-tsm- -tsc- -tsa- -mt4`**, so the archives are byte-identical on every
  machine. Dropping timestamps is obvious; pinning the compressor to four
  threads is not. RAR's block split follows the host core count, so a 32-core
  box and a 20-core box otherwise produce different bytes from the same input,
  and the machines stop being comparable.

The encrypted shape is the one exception to byte-identity: its AES salt is
random by construction, so the archives differ while the compressed stream
underneath does not.

## Running the extraction race

`shootout.rs` is the harness. It is one file with no dependencies because it
has to build with plain `rustc -O --edition 2021` on a box with no cargo:

```
shootout manifest <payload-dir> <manifest-file>
shootout race --shapes D --work D --manifest F --rounds N --tools a,b,c \
              [--only shape,...] [--tool-bin name=path ...]
```

Per run it makes a fresh output directory, reads every input byte to warm the
cache, times the child process, and then compares a content fingerprint of the
output against the manifest. A tool that drops or corrupts a member reports
`WRONG-OUTPUT` rather than a fast time; a tool that cannot do the job at all
reports the reason it gave. **A blank cell is not an acceptable result for any
competitor**, which is why the harness records failures verbatim.

Tools are interleaved inside each round rather than run in blocks, so a machine
that warms up or throttles part way through affects every tool equally.

## Running the PAR2 race

`par2rig-build.sh` builds the PAR2 corpus: 1 GiB of non-periodic random payload
packed store-mode into 21 RAR volumes of 50 MB, then two PAR2 sets at 10%
redundancy - 1 MiB blocks for the standard legs, 64 KiB for the heavy one -
then three fixed damage maps (3 blocks in 2 volumes, 101 in 6, 1500 across all
21). The payload must be truly random: one with 32-byte periodicity inflates
par2cmdline-turbo's sliding-scan work and flatters us by about 7% on the heavy
leg.

`round2.sh <leg> <rounds> <root> <ours-bin> [tools]` runs it, with the same
protocol as the extraction race - fresh copy, explicit pre-warm, then time -
and compares every repaired volume against the pristine set on every round.

`rev-race.sh` is the `.rev` recovery-volume leg.

`apply-damage.py` applies a recorded damage map (`map-*.txt`: block size on
line 1, then `<volume> <block index>`) to a copy of a pristine set. It is the
portable twin of the rig's `assemble.ps1`; before it existed only Windows
could reproduce a map, so the Macs re-rolled damage from a seed instead.

## Running the recovery-record race

`rr-build.sh <root> <payload> <rar> [sizes]` then
`rr-race.sh <root> <rounds> <ours-bin> <rar> [sizes]` cover the inline `-rr`
leg. Both moved in-repo from a session scratchpad, where the race carried a
hardcoded worktree path that no longer resolves and built its corpus from
`/dev/urandom`, so no two runs shared a corpus. The payload is now a prefix
of the same fixed-seed `rand.bin` everything else uses.

**Time the right recovery path.** `bench_rr_product` drives
`ArchiveReader` -> `repair_recovery_to_file`, which is what the daemon takes
whenever the headers still parse. `bench_rr_stream` drives the raw `{RB}`
marker scan used only when headers are unreadable. Payload damage leaves
headers intact, so timing the stream driver measures a path no user reaches
on that input - an earlier round did exactly that and published it.

## The `oursntt` contestant

`round2.sh` and `round2.ps1` accept `oursntt` alongside `ours`. It is the
same binary with `NZBFAST_NTT=1`, which enables the experimental NTT syndrome
path. **That gate is OFF by default**, so `ours` is what a user gets today and
`oursntt` is what flipping the default would buy. Publishing the `oursntt`
number as our number requires the default to move first - that is a release
decision, not a benchmark one.

## Traps, each of which produced a wrong answer at least once

- **Check the box is idle before trusting anything.** `top -l 1 | grep CPU`.
  A closed session once left 64 busy-loops running and every number was
  inflated 2-12x, including a competitor's, which would have read as a crushing
  win for us and been fiction.
- **Build bench drivers with `-F rars/parallel`.** `crates/nzbkit` depends on
  `rars` without that feature - only `crates/nzbfast` enables it - so a driver
  built `-p nzbkit` alone runs serial decode and reads about 50% slow.
- **Time the binary, never `cargo run`.** The build check adds ~0.15 s to
  whichever side you run that way.
- **Pre-warm explicitly.** macOS `cp -c` is an APFS clone, so the source pages
  stay cached and the copy is warm; a Windows `Copy-Item` really copies a
  gigabyte and is cold. Without an explicit pre-warm the two platforms measure
  different things. It moved one macOS verify leg from 0.220 s to 0.118 s, so
  `cp -c` alone is not warm either.
- **`ourrars` is not the product.** `vendor/rars/examples/ourrars` attaches no
  execution policy and runs a configuration nobody ships. The extraction
  contestant is `crates/nzbkit/examples/prodrar`, which takes the same options
  object the daemon does; the `.rev` contestant is `prodrev`, likewise.
- **The three rigs do NOT all hold the same PAR2 corpus, whatever the older
  rig notes say.** Measured 31 Jul by hashing the volumes: the M3 and the
  Windows laptop are byte-identical, and the M1 holds a different random
  draw of the same shape (21 volumes, same sizes, same block sizes, damage
  verified as 3 blocks in 2 volumes / 101 in 6 / 1500 in 21). That is fine for
  every published claim, because each row compares tools *within* one machine
  on bytes all of them share. It is not fine for reading one machine's row
  against another's as if the input were the same, and payload character is
  known to move turbo's scan by ~7%. Bringing the M1 into line means shipping
  ~2.3 GB to it, and the link measured 0.47 MB/s, so it stays as it is; say
  which corpus a number came from rather than implying one corpus.
- **`cargo test` can silently re-install a serial driver.** Running
  `cargo test --release -p nzbkit` reinstates a cached
  `target/release/examples/prodrar` built *without* `rars/parallel`. It races
  ~2.5x slow and reads as a catastrophic regression. Always rebuild with
  `-F rars/parallel` immediately before copying any contestant binary.

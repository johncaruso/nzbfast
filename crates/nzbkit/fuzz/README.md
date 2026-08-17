# nzbkit fuzz targets

Coverage-guided (libFuzzer / cargo-fuzz) fuzzers for the untrusted-input
parsers. Everything here takes attacker-controlled bytes: article bodies,
`.nzb` files, `.par2` recovery volumes, and downloaded RAR archives.

Needs nightly + `cargo install cargo-fuzz`.

## Targets

- `yenc_decode`  - the SIMD yEnc decoder (`yenc_simd::decode`) plus the
  scalar reference (`yenc::decode`) on RAW bytes. Complements the in-repo
  round-trip lite fuzzer, which never feeds the decoder malformed input.
- `nzb_parse`    - `Nzb::parse` (XML).
- `nzblnk_parse` - `nzblnk::parse` + `looks_like` on pasted text. Also
  asserts the two agree about whether a string IS a link: the dashboard
  gates on `looks_like` and the daemon then runs `parse`, so a
  disagreement is a link the UI accepts and the API refuses.
- `par2_parse`   - `Par2Set::parse`, single- and split-input framing.
- `rar_extract`  - `ArchiveReader::read_with_options` + `extract_to`
  (the RAR13/15-40/50 decompressor). Window and output are bounded so a
  decompression bomb can't OOM/hang the run.
- `mediaprobe`   - the container probe behind the preview-and-verify
  panel (`mediaprobe::probe` over MKV/WebM, MP4 and AVI). It reads a file
  that is still ARRIVING, before PAR2 has verified anything, so every
  length it follows is attacker-declared. Asserts determinism (the same
  bytes must probe to the same answer - which is why the parser's budgets
  contain no wall clock) and that the track/chapter/warning lists stay
  bounded, since a list that grows with a declared length is an
  allocation attack.
- `rar_recovery_scan` - the streaming recovery scanners:
  `scan_inline_recovery_chunks` (`{RB}` inline records) and
  `read_rev5_meta` / `verify_rev5_payload` (`.rev` headers). These size
  their own allocations from attacker-controlled header fields - the
  route the 64 GiB-from-1.8 MiB REV bomb took - and they run
  AUTOMATICALLY once extraction fails, so a panic or hang here is
  reachable by downloading a file. Asserts the ranges the scan reports
  stay inside the input, since callers read parity straight from them.

## Run

    cd crates/nzbkit/fuzz
    cargo +nightly fuzz run rar_extract -- -max_total_time=120 -rss_limit_mb=4096 -timeout=10

`yenc_decode` also ships a dictionary - always pass it, or the fuzzer
essentially never guesses a yEnc header:

    cargo +nightly fuzz run yenc_decode -- -dict=yenc.dict -max_total_time=180

## Seed corpora (recommended, esp. for rar_extract)

The corpus is gitignored. Seed it from the in-tree fixtures so the fuzzer
starts from valid inputs and reaches the decode paths fast:

    mkdir -p corpus/rar_extract corpus/par2_parse corpus/rar_recovery_scan
    cp ../../../vendor/rars/tests/fixtures/rar*/*.rar corpus/rar_extract/
    cp ../tests/fixtures/par2/*.par2                  corpus/par2_parse/
    # mediaprobe's fixtures are generated, not committed - the test
    # suite writes them out on request:
    NZBFAST_WRITE_FUZZ_SEEDS=$PWD/corpus/mediaprobe \
      cargo test -p nzbkit --test mediaprobe write_fuzz_seeds
    # `remux` walks the same containers a layer deeper (sample tables,
    # block lacing), so it wants the same seeds. The two fixtures that
    # actually carry payload - mkv_remux, mp4_remux - are the ones that
    # reach the sample walk at all; the header-only ones stop at track
    # selection, which is worth fuzzing but is not where the arithmetic
    # is.
    NZBFAST_WRITE_FUZZ_SEEDS=$PWD/corpus/remux \
      cargo test -p nzbkit --test mediaprobe write_fuzz_seeds
    # rar_recovery_scan needs CRC-valid headers to get past its first gate,
    # so seed it with real .rev volumes and RR-bearing archives.
    cp ../../../vendor/rars/tests/fixtures/rar*/**/*.rev \
       ../../../vendor/rars/tests/fixtures/rar*/*.rev    corpus/rar_recovery_scan/ 2>/dev/null

## Status

23 Jul 2026 smoke pass (cold-start, ~60-120s each): ~5.8M+ total
executions across the four targets that existed then (`yenc_decode`,
`nzb_parse`, `par2_parse`, `rar_extract`), ZERO crashes. Longer campaigns
with the seed corpora are the next step for deeper coverage. The targets
added since have their own entries below; a green smoke run is evidence
about that run, not a standing property of the target.

25 Jul 2026 - `yenc_decode`'s corpus was found to contain ZERO inputs with
`=y` in them: it had only ever exercised the header-absent early return,
which is how three silent-truncation bugs in the `=y` control-line handling
survived it. Seeded with encoder output (CRLF, bare-LF, dot-stuffed,
multi-part, all-256-byte-values) plus the known bug shapes, and given
`yenc.dict`. The first seeded run found six real decoder divergences in
under ten minutes (dot unstuffing, duplicate/junk header keys, `name=`
swallowing later fields, whitespace-glued keys, multi-trailer gates); all
are fixed, and the target now runs clean at ~1.1M execs / 180s.

25 Jul 2026 - `rar_recovery_scan` added with the streaming recovery
rewrite. Cold-start smoke: 3.1M executions in 121s, ZERO crashes, RSS
flat at 112 MB throughout, which is the property the target exists to
pin. Coverage was only 95 edges cold: the chunk parser is behind a CRC64
gate the fuzzer will not guess, so this one genuinely needs its seed
corpus to reach the plan arithmetic.

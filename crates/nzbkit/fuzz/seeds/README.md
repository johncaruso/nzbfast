# Committed fuzz seeds

`corpus/` is gitignored (it is machine-local and grows), so a repro that
CI found would be lost the moment its artifact expired. Anything in
`seeds/<target>/` is copied into `corpus/<target>/` by the seed step in
`.github/workflows/fuzz-smoke.yml`, so every future smoke run replays it.

Put a crash/OOM/timeout repro here under the name libFuzzer gave it, so
it maps back to the CI artifact it came from, and note it below.

- `rar_name_probe/crash-f064a660a000d079ef552779894d5aa9ba76d15c` - a
  RAR4 main header declaring `head_size` 7 while carrying `MHD_COMMENT`,
  whose CRC range is a fixed 13 bytes: the probe's truncated-half feed
  left 12 bytes and `v4_header_crc` sliced `h[2..13]` out of them. Fixed
  by the `head_size < 13` guard in `rar.rs`; the unit-test twin is
  `a_comment_block_shorter_than_its_fixed_crc_range_is_refused`.

# Environment variables

Every `NZBFAST_*` variable read by the code in `crates/*/src`, grouped
Supported first. "Supported" means an operator may reasonably set it;
"Debug-only" covers rollout kill-switches, bench/tuning knobs, and test
harness plumbing - they can vanish or change meaning between releases.

Strings like `__NZBFAST_INDEX__`, `__NZBFAST_INDEXERS__`,
`__NZBFAST_SPOTS__`, `__NZBFAST_LOCALE__`, and `__NZBFAST_UI_TOKENS__`
also appear in the source but are HTML placeholder tokens substituted
into the embedded dashboard pages, not environment variables.

## Supported

| Name | Purpose | Default | Class |
|---|---|---|---|
| `NZBFAST_CONFIG` | Config file path, same as `--config`; makes every subcommand and the daemon agree on one file (the container image sets `/config/config.json`) | `config.local.json` in the cwd | Supported |
| `NZBFAST_STORAGE` | Force storage-type detection for the output path: `rotational`, `ssd`, or `auto` | `auto` (detect) | Supported |
| `NZBFAST_READ_TIMEOUT_SECS` | Read-stall timeout for pooled NNTP connections, in seconds | 30 | Supported |
| `NZBFAST_STALL_ABORT_SECS` | Download stall watchdog: abort when decoded bytes AND outstanding articles are both frozen this long | 180 | Supported |
| `NZBFAST_AUTO_RETRY_SECS` | Auto-retry interval for failed jobs, in seconds; overrides the `auto_retry_mins` setting (tests use it to compress the timeline) | `auto_retry_mins * 60` | Supported |
| `NZBFAST_THROTTLE_WRITE_MBPS` | Cap the consumer's write rate (MB/s) to simulate a slow disk; backpressure then closes TCP windows upstream | unset (no throttle) | Supported |
| `NZBFAST_LOG` | Log filter, by level and by `[tag]`: `debug`, or `warn,queue=debug,index=off`. The tag in each log line is the filter key. `RUST_LOG` is honoured too, second | `info` | Supported |
| `NZBFAST_LOG_CAP_MB` | Size cap for the stdout log file before in-place truncation; `0` = uncapped | 50 | Supported |
| `NZBFAST_EXTRA_CA` | Path to a PEM file of extra TLS trust anchors (self-signed news servers, the benchserve rig) | unset | Supported |
| `NZBFAST_KTLS` | `1` moves TLS record crypto into the kernel after the handshake (Linux, builds made with `--features ktls` only). Measured a 40% CPU **regression** on kernel 6.8/x86_64, so it is off by default and only worth trying on a kernel whose AES-GCM is not slower than aws-lc-rs' (x86_64 >= 6.11, or arm64). A kernel that refuses falls back to userspace TLS silently, one log line | unset (userspace TLS) | Experimental |
| `NZBFAST_SHARDS` | Force the number of I/O runtime shards, clamped 1..16 (`1` = single runtime) | auto: 1, or 2..4 on 12+ cores with 24+ connections | Supported |
| `NZBFAST_NNTP_COMPRESS` | `0` disables RFC 8054 COMPRESS DEFLATE on header-scan connections (download connections never compress) | on when the server advertises it | Supported |
| `NZBFAST_PORT_LOCKED` | `1` = the launcher owns the listening port (container mapping, Synology adminport); a dashboard-saved port must not move it | unset | Supported |
| `NZBFAST_OPEN` | `1` runs the daemon deliberately keyless: no API key is minted or required. For installs behind another auth layer | unset (a key is minted on first run and required) | Supported |
| `NZBFAST_CONTAINER` | `1` marks a container runtime that drops neither `/.dockerenv` nor `/run/.containerenv`, so container-specific UI and update guidance apply | unset (marker files detected) | Supported |
| `NZBFAST_ALLOW_EPHEMERAL_CONFIG` | `1` silences the container entrypoint's warning that the config directory is not a mounted volume (settings die with the container). For deliberate throwaway runs | unset (warning prints) | Supported |
| `NZBFAST_BUNDLED` | Internal launcher plumbing: the Mac .app and Windows tray set `1` at spawn to mark a wrapper-owned binary (gates bundled-install behaviour). Not meant to be set by hand | unset | Supported |

## Debug-only

### Kill-switches (rollout escape hatches)

`=1` for the extraction gates; the ones marked "set" trigger on presence
with any value.

| Name | Purpose | Default | Class |
|---|---|---|---|
| `NZBFAST_NO_ENRICH` | Set: disables all metadata-enrichment workers and identity-oracle network calls - the test suite's "do not touch the real internet" switch | unset (enrichment on) | Debug-only |
| `NZBFAST_PREDB_ALLOW_PLAINTEXT` | `1`: let the pre feed connect to the plain IRC port when TLS fails. Off by default because the downgrade is one anybody on the path can force - block 6697, answer on 6667, and inject release names the exact legs match on automatically. Only for a network with no TLS relay | unset (TLS required) | Supported |
| `NZBFAST_NO_NATIVE_REPAIR` | Set: disables the native PAR2 repair path (misnamed/shifted-data adoption included) | unset (native repair on) | Debug-only |
| `NZBFAST_NO_NATIVE_UNRAR` | Set: prefer an external `unrar` over native rars extraction (env twin of the `prefer_external_unrar` setting; also latches the top-level RAR chase off) | unset (native) | Debug-only |
| `NZBFAST_NO_INSTREAM_DECRYPT` | `1`: decrypt encrypted store-mode RAR in a finish pass instead of in-stream during download | unset (in-stream) | Debug-only |
| `NZBFAST_NO_NESTED_ONEPASS` | `1`: turn off one-pass routing of nested archives | unset (on) | Debug-only |
| `NZBFAST_NO_NESTED_CHASE` | `1`: disable the chasing decompressor for nested compressed RAR (inner archive lands on disk instead) | unset (on) | Debug-only |
| `NZBFAST_NO_NESTED_7Z` | `1`: demote an inner .7z to a disk pass instead of chasing it | unset (on) | Debug-only |
| `NZBFAST_NO_NESTED_ZIP` | `1`: demote an inner zip to a disk pass instead of chasing it | unset (on) | Debug-only |
| `NZBFAST_NO_TOP_7Z` | `1`: disable one-pass extraction of a top-level 7z | unset (on) | Debug-only |
| `NZBFAST_NO_TOP_RAR_CHASE` | `1`: disable the top-level compressed-RAR chase | unset (on) | Debug-only |
| `NZBFAST_NO_TOP_ZIP` | `1`: disable one-pass extraction of a top-level zip (a zip nested inside another archive still streams - use `NZBFAST_NO_NESTED_ONEPASS` for that) | unset (on) | Debug-only |
| `NZBFAST_NO_7Z_TRIM` | `1`: disable drop-behind trimming of already-consumed archive bytes | unset (trim on) | Debug-only |
| `NZBFAST_NO_RAR_TRIM` | `1`: disable drop-behind trimming in the RAR chase - a set over the held-bytes cap demotes to the unrar ladder instead of being released volume by volume | unset (trim on) | Debug-only |
| `NZBFAST_NO_OUTPUT_CRC` | `1`: skip the final-output CRC pass on extracted files | unset (CRC on) | Debug-only |
| `NZBFAST_NO_HOLDS_PAGE` | `1`: restore pre-paging behaviour - held bytes stay in memory instead of paging to scratch under the cap | unset (paging on) | Debug-only |
| `NZBFAST_NO_SPEC_PREFETCH` | Set: CLI runs skip speculative recovery-volume prefetch when an article first goes terminally Missing (daemon runs are gated by `hub.spec_prefetch` instead) | unset (prefetch on for CLI) | Debug-only |

### Tuning and bench knobs

| Name | Purpose | Default | Class |
|---|---|---|---|
| `NZBFAST_FAST_VERIFY` | `0`/`1` overrides the fast-verify setting in either direction (bench A/Bs) | setting; on by default | Debug-only |
| `NZBFAST_WARM_POOL` | `0` forces the warm connection pool off everywhere, regardless of per-server settings | per-server `warm_pool` setting | Debug-only |
| `NZBFAST_NTT` | Overrides "fast par mode" NTT dispatch: `1` on (behind shape gates), `force` skips the shape gates, `0`/`off` disables. Beats the daemon setting | unset (setting decides; on by default) | Debug-only |
| `NZBFAST_NTT_BUDGET` | NTT retention memory budget in bytes | scaled from physical RAM / cgroup limit | Debug-only |
| `NZBFAST_NTT_W` | NTT stripe width in 16-bit words (min 16) | 512 | Debug-only |
| `NZBFAST_NTT_THREADS` | NTT syndrome worker count | available cores, clamped to the stripe count | Debug-only |
| `NZBFAST_STREAM_WINDOW` | Per-connection pipeline depth while a media stream reader is attached | 1 | Debug-only |
| `NZBFAST_STREAM_RUNWAY_MB` | Contiguous data required past a stalled stream position before the response resumes (`0` = resume on first covered chunk) | 16 | Debug-only |
| `NZBFAST_DEFER_WARMUP_SECS` | Warmup before the slow-job defer monitor starts judging (tests compress it) | 45 | Debug-only |
| `NZBFAST_DEFER_WINDOW_SECS` | Measurement window for the slow-job defer decision | 30 | Debug-only |
| `NZBFAST_HEALTH_TICK_SECS` | Interval between §77 post-health probe ticks (tests compress it) | 15 | Debug-only |
| `NZBFAST_HEALTH_RECHECK_SECS` | How long a job must sit queued before its one post-health re-probe | 3600 | Debug-only |
| `NZBFAST_NESTED_MAX_DEPTH` | Overrides the nested-extraction depth cap (test override; beats the daemon setting) | daemon setting, else built-in default | Debug-only |
| `NZBFAST_SCAN_IDLE_SECS` | Indexer header-scan idle deadline before a pass is abandoned | 300 | Debug-only |
| `NZBFAST_DROP_CACHE` | `1`/`0` force page-cache drop-behind of written data on Linux (benching; the CLI defaults on, the daemon off because a stream reader can attach) | path default | Debug-only |
| `NZBFAST_TLS_AES256` | Set: force the full TLS cipher list on every host - escape hatch for an untested provider that misbehaves with the trimmed list | unset (per-host list) | Debug-only |
| `NZBFAST_SKIP_PCRC` | `1` skips per-article yEnc CRC checks. Loopback-rig measurement switch ONLY: the CRC is the sole guard on PAR2-less sets | unset (CRC checked) | Debug-only |

### Diagnostics and test-harness plumbing

| Name | Purpose | Default | Class |
|---|---|---|---|
| `NZBFAST_POOL_DEBUG` | Set: dump unresolved queue/in-flight pool state when an idle stall is detected | unset | Debug-only |
| `NZBFAST_REPAIR_TIMING` | Set: print PAR2 repair phase timings | unset | Debug-only |
| `NZBFAST_FOLD_TRACE` | Set: trace the repair streaming-fold pass | unset | Debug-only |
| `NZBFAST_DEBUG_HOOKS` | Set: expose test-only API hooks (e.g. `debug_hold_index` wedges the shared index lock to reproduce daemon starvation) | unset | Debug-only |
| `NZBFAST_TEST_FORBID_UNRAR` | Test canary: set makes any external `unrar` invocation fail loudly, proving encrypted-store jobs completed natively | unset | Debug-only |
| `NZBFAST_TEST_STALL_FINALIZE_MS` | Test hook: sleep this many ms in job finalize to pin the drained-but-still-Downloading window in the queue suite | unset | Debug-only |
| `NZBFAST_SOAK_MINUTES` | Long-run soak (TODO 82, `tests/leak_soak.rs`): how long to keep cycling the mixed queue. The run always does at least warmup+6 cycles, however short this is | 20 | Debug-only |
| `NZBFAST_SOAK_SETTLE_SECS` | Soak: idle wait between a cycle draining and the resource sample. Must stay above the daemon's 60 s idle memory trim plus its 15 s tick, or RSS drift measures allocator retention instead of a leak; values under 80 are rejected | 90 | Debug-only |
| `NZBFAST_SOAK_WARMUP_CYCLES` | Soak: leading cycles excluded from the statistics (startup faulting, pool warm-up, caches reaching working size - RSS was measured flat from cycle 6) | 5 | Debug-only |
| `NZBFAST_SOAK_REPORT` | Soak: where to write the JSON report (verdicts plus every sample - what a new baseline gets re-recorded from) | the run's temp dir | Debug-only |
| `NZBFAST_BETA` | Build-time only: `build.rs` bakes the beta serial from `packaging/beta-serial.txt` in via `cargo:rustc-env`; the API reports it. Never read at runtime | empty (not a beta) | Debug-only |

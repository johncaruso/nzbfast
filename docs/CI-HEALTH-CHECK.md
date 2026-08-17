# CI gate health check

`gh` commands below use `:owner/:repo`, which gh resolves from the
checkout you run them in - the same idiom the workflow comments use.

A monthly routine runs this. It is a MEASURE-and-REPORT pass: change
nothing, report what regressed and which lever applies.

## Why this exists

On 17 Aug 2026 the per-push gate took ~49 min on a release commit and
blocked a release. Root cause: `packaging/bump-version.sh` rewrites
Cargo.lock on every release and both caches keyed on
`hashFiles('Cargo.lock')`, so **the release path was always the cold
path**. Rebuilt to ~19 min. Gate timings creep back as tests are added,
which is what this checks.

## 1. Measure

Verdicts are **per job, never per run** - a run reads `cancelled` at run
level while a job inside it passed or failed:

```sh
gh run list --workflow ci-private.yml --branch main --limit 5
gh api repos/:owner/:repo/actions/runs/<ID>/jobs \
  -q '.jobs[] | "\(.name) \(.conclusion) \(.started_at) \(.completed_at)"'
```

Baselines, 17 Aug 2026, release-shaped commit, warm cache. Flag anything
~25% over:

| job | baseline |
|---|---|
| `check` | 9m11s (target: under 10m) |
| `windows-build` | 13m35s |
| `windows-unit` x4 shards | 3m54s - 5m35s each |
| `windows-clippy` | 6m27s |
| `windows-arm64` | 5m26s |
| `linux-tests` x4 shards | 2m59s - 4m52s each |
| **whole gate, wall clock** | **19m18s** |

## 2. Split any regression into build vs execution

The fix differs, so never report a slow job without this split. In the
job log, compare the timestamp of nextest's `Starting N tests` line with
its `Summary [Ns]` line: everything before `Starting` is build, the
`Summary` figure is execution.

On Windows also find the **last `Compiling` line** - the gap from there
to `Starting` is pure LINK time, which was 439s of a 699s warm build and
is the leg's dominant cost.

Do not cost a nextest job from `cargo test` numbers, and do not cost a
4-vCPU runner from a many-core laptop: the local full-suite wall clock
is set by the critical path, not total CPU, and hides regressions that
matter on CI.

## 3. Check the fixes have not regressed

- **No cargo cache key may use `hashFiles('Cargo.lock')`.** All must use
  `tools/dep-cache-key.py`, which normalises the workspace members' own
  version lines out so a release bump does not discard ~600 compiled
  crates. Check with
  `grep -rn "hashFiles('Cargo.lock')" .github/workflows/` - hits inside
  comments are fine. Run `tools/dep-cache-key.py --selftest`.
- **No cargo cache may use the combined `actions/cache`.** Its post step
  does NOT save when the job fails, so one red run leaves the next run
  cold too - worst exactly while someone iterates on a fix. Every one
  must be `actions/cache/restore` plus an explicit `actions/cache/save`
  with `if: always()`, placed right after the build.
- **Cache budget.** GitHub allows 10 GB per repo with LRU eviction, and
  this repo has been over it. `gh api repos/:owner/:repo/actions/cache/usage`.
  Delete entries whose key no longer appears in any workflow, and
  entries whose `ref` is a deleted branch. Do NOT delete the
  `coverage-table-*` or `fuzz-corpus-*` entries: those are run_id-keyed
  WITH `restore-keys`, so the old entry is still read.
- **Shard jobs must gate on the archive, not on `needs:`.** `check` also
  runs clippy, deny and five gates; `needs: check` alone would let a
  one-line clippy error skip 5,000+ tests.

## 4. Levers, with verdicts already measured

Do not re-derive these:

| lever | verdict |
|---|---|
| dependency-normalised cache key | **DONE** - the big one |
| `nextest archive` + `--partition` | **DONE** - build once, shard the run |
| split suite / clippy / ARM64 into jobs | **DONE** - was ~8.5 min serial |
| `line-tables-only` on Windows | **DONE** |
| merge light integration targets | **DONE** - 54 to 32 binaries |
| `rars` at `opt-level = 2` in dev | **DONE** - 6.2x on the chase tests |
| `CARGO_PROFILE_TEST_DEBUG=0` | **NO** - measured, only 87s |
| larger runners | **NO** - personal account, unavailable |
| sharding nightly | **NO** - no wall pressure, +26% billed |
| caching `windows-clippy` | **NO** - measured slower with the cache |

Remaining known lever, if the Windows leg regresses: link time is the
dominant term and it scales with the NUMBER of test executables. Merging
more `[[test]]` targets into `tests/integration/` is the move. The six
heavy `required-features = ["heavy-tests"]` targets must stay separate -
that gate is per-target.

## Traps

- An unmatched `binary()` predicate is tolerated in a command-line `-E`
  expression but is a **hard error** in a `.config/nextest.toml` override
  filter. Renaming or merging a test target breaks those filters.
- `env!("CARGO_BIN_EXE_*")` is resolved at COMPILE time, so archived test
  binaries carry an absolute path; shards must unpack with
  `--extract-to "$GITHUB_WORKSPACE"`. `--workspace-remap` does not fix it.
- A bash `run:` block on a Windows job needs `shell: bash` - pwsh is the
  default there.

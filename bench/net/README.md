# Real-network benchmark drivers

The scripts we use for competitive real-network rounds: nzbfast vs
NZBGet vs SABnzbd vs rustnzb, downloading real posts from a real news
server. For the fully offline harness (no Usenet account needed), see
[`../nested-corpus/`](../nested-corpus/), which serves a generated
corpus over loopback NNTP.

Nothing here embeds a provider, hostname, or credential: each client
reads its own config file, and you supply the NZBs. Results depend
heavily on your line, your provider, and the moment you run - see
"Methodology" before comparing numbers with anyone else's.

## The drivers

| script | scenario | result line |
| --- | --- | --- |
| `throughput.sh` | single job, wall time + bytes + peak process-tree RSS | `LEG ...` |
| `resume.sh` | kill -9 mid-job, restart, measure re-downloaded bytes | `LEG4 ...` |
| `queue.sh` | 3 jobs added at once, wall for all 3 + rate time-series | `LEG5 ...` |
| `sequential.sh` | N jobs strictly one at a time - the warm-connection-pool leg | `LEG6 ...` |
| `damage_nzb.py` | poison N segments of an NZB (nonexistent message-ids) for repair legs | - |
| `rss_sampler.py` | process-tree RSS peak sampler used by `throughput.sh` | - |

All scripts are zsh (stock on macOS, packaged everywhere else) and need
only `curl`, `python3`, and the clients you want to race.

## Setup

Everything is configured by environment variables (see `lib.sh` for the
full list). A leg whose binary or config is unset prints a `SKIP` line
instead of failing the round.

```bash
export NZBFAST=/path/to/nzbfast          # found on PATH by default
export NFCONF=/path/to/nzbfast.json      # server list, for the daemon legs
export NZBGET=/path/to/nzbget
export NGCONF=/path/to/nzbget.conf
export SAB_CMD=/Applications/SABnzbd.app/Contents/MacOS/SABnzbd
export SAB_INI=/path/to/sabnzbd.ini      # must set api_key = harnesskey
export RUSTNZB=/path/to/rustnzb
export RUSTNZB_TOML=/path/to/rustnzb.toml
export BENCH_ROOT=$HOME/bench-run        # work dirs + logs land here
```

Point every client at the same server(s) with the same connection count
per server (`CONNS`, default 8). Ports default to NZBGet 6791, SAB
8085, rustnzb 9090, nzbfast 6799; override `NG_PORT`/`SAB_PORT`/
`RN_PORT`/`NF_PORT` if your configs differ.

Then:

```bash
NZB=/path/to/job.nzb TAG=myrun ./throughput.sh round   # all four clients
NZB=/path/to/job.nzb ./resume.sh nzbget                # one client
NZB1=a.nzb NZB2=b.nzb NZB3=c.nzb ./queue.sh sab
NZBDIR=/path/to/seqdir N=8 ./sequential.sh nzbfast
./throughput.sh stopall                                # kill leftover daemons
```

Test NZBs: use posts you have the right to download. SABnzbd publishes
reusable test NZBs for exactly this purpose, or generate your own posts
with `nzbfast post` against a test group your provider allows.
`sequential.sh` needs N distinct jobs named `seq1.nzb` .. `seqN.nzb`
(clients dedupe history by name).

## Fairness: every client runs at its documented best

House rule - a competitor must never lose because we failed to
configure it. The tuning each client gets, and why:

- **nzbfast** `--connections $CONNS --window 4 --decoders 8`, defaults
  otherwise.
- **nzbget** set `ArticleCache=1000, WriteBuffer=1024, DirectWrite=yes,
  DirectUnpack=yes, ParQuick=yes, ParBuffer=500, ParThreads=0` in your
  config or `NGOPTS`. A standalone `-c` config uses NZBGet's BUILT-IN
  defaults for anything unset (article cache OFF, DirectWrite off)
  rather than the values in its shipped nzbget.conf - so each must be
  stated explicitly. Also: an invalid option name makes NZBGet start
  fully PAUSED, which reads as 0 MB/s.
- **sab** `pipelining_requests = 8` PER SERVER (SABnzbd ships 1, i.e.
  unpipelined - the single most valuable setting it has, ~22% on a big
  job), `receive_threads = 4`, `cache_limit = 1G`, `direct_unpack = 1`.
- **rustnzb** `pipelining = 4`, `cache_size = "1G"`,
  `direct_unpack = false` - the last one is REQUIRED, not a handicap:
  its DirectUnpack drives `unrar -vp` prompts that RARLab unrar never
  emits, and the run hangs.

When a tuning changes, say so next to the published numbers - they are
only defensible if the tuning is auditable.

## Methodology - what makes a number valid

- **Provider throughput varies 2-3x minute-to-minute.** Never compare
  two single runs. Alternate the arms back-to-back (A/B/A/B) and
  compare medians.
- **The interface counter is ground truth.** `gbytes` is the whole
  NIC's rx delta. Keep the box otherwise quiet; `throughput.sh`
  cross-checks against the client's own accounting and flags the leg
  `WARN=iface_exceeds_client` when >5% of the traffic wasn't the
  client's.
- **A client's own "Completed" is NOT evidence it did the work.**
  `sequential.sh` measures the bytes actually produced in the output
  directory and voids an arm whose output is far below the payload.
- **Some providers limit simultaneous source IPs.** Bench from ONE
  machine at a time; a second box can lock the first out for minutes
  and poison both sets of numbers.
- Stop all daemons between rounds (`throughput.sh stopall`): a
  leftover client still draining its queue contaminates the next leg.

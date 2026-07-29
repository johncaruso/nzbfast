# Posting the benchmark corpus

`nzbfast post` uploads local files as yEnc articles to a test newsgroup and
writes the matching NZB, so published benchmarks can reference real,
downloadable posts. It is an internal ops tool - it is not documented in the
user manual and its defaults are tuned for corpus uploads, not general
posting.

## The one rule: pick the server yourself

`--post-server` is mandatory and must name exactly ONE server from the
config. There is no default, and there is deliberately no "post through all
servers" mode. The tool refuses to run without the flag, refuses an
ambiguous name (two entries sharing a host - disambiguate with `host:port`),
and refuses a server that is disabled in the config. It prints the chosen
server and a summary line before any byte moves - read that line.

## Typical corpus upload

```bash
nzbfast post bench/nested-corpus/generated --post-server news.example.com \
  --nzb bench/nested-corpus/corpus.nzb --title "nzbfast bench corpus v1" --verify
```

- Directories are walked recursively; files post under their file name only
  (local directory layout never reaches the wire). Duplicate names and
  empty files are errors.
- Subjects follow the standard yEnc convention every downloader parses:
  `title [i/n] - "file.bin" yEnc (part/parts)`, or just
  `"file.bin" yEnc (part/parts)` without `--title`.
- The NZB is written even without `--verify`; segments carry the encoded
  article sizes and the generated message-ids.

## Options that matter

| Flag | Default | Notes |
| --- | --- | --- |
| `--post-server` | none, required | host or host:port of ONE config entry |
| `--group` | alt.binaries.test | target newsgroup |
| `--from` | corpus@nzbfast.com | From header |
| `--msgid-domain` | corpus.nzbfast.com | right-hand side of message-ids |
| `--article-size` | 700K | decoded payload bytes per article |
| `--connections` | 4 | concurrent posting sessions |
| `--nzb` | posted.nzb | output NZB path |
| `--verify` | off | re-download + hash check, see below |

## Header hygiene

Articles carry exactly five headers: From, Newsgroups, Subject, Message-ID,
Date. No User-Agent, no X-Newsreader, no Organization. Message-ID local
parts are random hex with a caller-chosen domain and Date is always +0000,
so neither the posting host nor its timezone leaks into the group. Keep it
that way when touching `crates/nzbkit/src/post.rs` - the test
`wire_article_has_only_the_five_headers` pins this.

## Verify

`--verify` parses the NZB it just wrote, downloads every segment back
through the normal engine connection pool from the SAME server, reassembles
into `<nzb>.verify.tmp/`, and compares SHA-256 per file against the
sources. On success the temp directory is removed; on failure it is kept
for inspection and the command exits non-zero.

Freshly posted articles can take a moment to become retrievable; the tool
waits 2 seconds before verifying. If verify still reports missing articles
on a real provider, wait a minute and re-run the download by hand:

```bash
nzbfast get bench/nested-corpus/corpus.nzb --out /tmp/corpus-check
```

## Protocol notes

- POST first; a server answering 440 (posting not permitted) flips the run
  to IHAVE automatically. A rejection after the article body is a hard
  error - a partially posted corpus is worse than a loud failure.
- Any article that fails three attempts (with reconnects between) aborts
  the whole run.

## Testing

- Unit + e2e tests live in `crates/nzbkit/src/post.rs` (encoder round-trip
  against the production decoder, split boundaries, NZB emission, POST and
  IHAVE e2e against the in-memory mock NNTP server) and
  `crates/nzbfast/src/post_cmd.rs` (server selection rules, full CLI run
  with verify).
- The test mock (`nzbkit::mock::MockServer`) accepts POST and IHAVE. The
  standalone `nzbfast mockserve` loopback bench server does NOT - it serves
  a synthetic set for download benchmarks only; do not point `post` at it.

#!/bin/sh
# Offline end-to-end smoke for a freshly built nzbfast binary.
#
# WHY THIS EXISTS. The FreeBSD build has no GitHub-hosted runner and no
# machine in the lab, so the only thing standing between "it compiled"
# and "we published a tarball nobody has run" is a test that actually
# executes the pipeline on the target OS. `nzbfast mockserve` makes that
# possible with no network and no provider: it serves a synthetic release
# over loopback NNTP and writes the matching .nzb, so `nzbfast get`
# against it drives the whole one-pass path - pipelined NNTP, in-place
# yEnc decode, incremental PAR2 verify, preallocation and positioned
# writes - and the assertions below fail if any of it is wrong.
#
# Deliberately POSIX /bin/sh: FreeBSD's /bin/sh is not bash, and this
# script has to run on a stock base system with nothing installed from
# ports. It is not FreeBSD-specific otherwise - run it on Linux or macOS
# to check the script itself before shipping a change to it.
#
# Usage: packaging/freebsd/smoke.sh <path-to-nzbfast> [workdir]
set -eu

BIN=${1:?usage: smoke.sh <path-to-nzbfast> [workdir]}
WORK=${2:-./freebsd-smoke}
PORT=${NZBFAST_SMOKE_PORT:-11190}
FILES=2
FILE_SIZE=32M

# Never let the metadata/indexer enrichment workers reach the internet
# from a CI VM (or a tester's box) - the smoke is offline by contract.
NZBFAST_NO_ENRICH=1
export NZBFAST_NO_ENRICH

# $WORK is caller-supplied and goes straight to `rm -rf`. CI passes the
# literal /root/smoke and the default is ./freebsd-smoke, so no automated
# path is exposed - but a tired operator typing `/root` or `/usr/local`
# gets no second chance, and this script runs as root on a VM by design.
# Refuse the shapes that are obviously not a scratch directory.
# Resolve WITHOUT cd: the directory does not exist yet on a first run, and
# a `cd $(dirname ...)` that fails silently yields a different path than
# the one about to be deleted - which is how a first draft of this guard
# waved through /root and refused the /root/smoke that CI actually uses.
case "$WORK" in
    /*) _abs="$WORK" ;;
    *)  _abs="$PWD/$WORK" ;;
esac
case "$_abs" in
    *..*) echo "smoke.sh: '$WORK' contains '..'; give a plain path" >&2; exit 1 ;;
esac
_abs=$(printf '%s' "$_abs" | sed 's|//*|/|g')     # collapse repeats
while :; do
    case "$_abs" in
        */) _abs=${_abs%/} ;;
        *)  break ;;
    esac
done
[ -n "$_abs" ] || _abs=/
case "$_abs" in
    /|/root|/home|/usr|/etc|/var|/bin|/sbin|/lib|/boot|/dev|/proc|/tmp|"$HOME")
        echo "smoke.sh: '$_abs' is a system or home directory, not a scratch" >&2
        echo "  directory. This script deletes the path it is given." >&2
        exit 1 ;;
esac
# Depth as the general rule: a scratch directory is never top-level.
case "$_abs" in
    /*/*) ;;
    *) echo "smoke.sh: '$_abs' is too shallow to be a scratch directory" >&2; exit 1 ;;
esac
WORK=$_abs

rm -rf "$WORK"
mkdir -p "$WORK/out"
BIN=$(cd "$(dirname "$BIN")" && pwd)/$(basename "$BIN")
cd "$WORK"

echo "== identity =="
"$BIN" --version

cat > config.json <<JSON
{
  "servers": [
    {
      "host": "127.0.0.1",
      "port": $PORT,
      "tls": false,
      "connections": 8
    }
  ]
}
JSON

echo "== mock provider on 127.0.0.1:$PORT =="
"$BIN" mockserve --port "$PORT" --bind 127.0.0.1 \
  --files "$FILES" --file-size "$FILE_SIZE" --par2 --nzb loop.nzb \
  > mockserve.log 2>&1 &
MOCK=$!
# Always take the mock down, including on a failed assertion below.
trap 'kill "$MOCK" 2>/dev/null || true' EXIT INT TERM

# The NZB is written as the server comes up; wait for the file rather
# than for the port, since `get` needs both and the file is the later of
# the two. 30 x 1s is generous for a synthetic release.
i=0
while [ ! -s loop.nzb ]; do
  i=$((i + 1))
  if [ "$i" -gt 30 ]; then
    echo "FAIL: mockserve never wrote loop.nzb" >&2
    sed -n '1,40p' mockserve.log >&2
    exit 1
  fi
  sleep 1
done

echo "== download =="
"$BIN" --config config.json get loop.nzb --out out --connections 8

echo "== assertions =="
# 1. The right number of payload files came out, at exactly the right
#    size. mockserve's --file-size is decimal, so 32M is 32000000 bytes
#    on the nose - an exact comparison, not a floor, so a short final
#    article or an over-long write both fail here.
n=0
for f in out/*; do
  [ -f "$f" ] || continue
  case "$f" in
    *.par2) continue ;;
  esac
  bytes=$(wc -c < "$f" | tr -d ' ')
  if [ "$bytes" -ne 32000000 ]; then
    echo "FAIL: $f is $bytes bytes, expected exactly 32000000" >&2
    exit 1
  fi
  n=$((n + 1))
done
if [ "$n" -ne "$FILES" ]; then
  echo "FAIL: expected $FILES payload files in out/, found $n" >&2
  ls -l out >&2
  exit 1
fi

# 2. Nothing was left holed. A short-file or sparse-write bug on a
#    filesystem we have never run on shows up here and nowhere else:
#    the byte counts above would still pass on a file of zeroes.
if ! od -A n -N 4096 -t x1 out/* | tr -d ' \n' | grep -qv '^0*$'; then
  echo "FAIL: output files start with 4 KB of zeroes - decode wrote nothing" >&2
  exit 1
fi

echo "PASS: end-to-end download completed on $(uname -srm)"

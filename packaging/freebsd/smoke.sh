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
#        packaging/freebsd/smoke.sh --self-test   # the workdir guard only
set -eu

if [ "${1:-}" = "--self-test" ]; then
    SELF_TEST=1
    BIN=
    WORK=
else
    SELF_TEST=0
    BIN=${1:?usage: smoke.sh <path-to-nzbfast> [workdir]}
    WORK=${2:-./freebsd-smoke}
fi
PORT=${NZBFAST_SMOKE_PORT:-11190}
FILES=2
FILE_SIZE=32M

# Never let the metadata/indexer enrichment workers reach the internet
# from a CI VM (or a tester's box) - the smoke is offline by contract.
NZBFAST_NO_ENRICH=1
export NZBFAST_NO_ENRICH

# $WORK is caller-supplied and goes straight to `rm -rf`, as root, on a
# VM. CI passes the literal /root/smoke and the default is ./freebsd-smoke,
# so no automated path is exposed - but a tired operator typing `/root` or
# `/usr/local` gets no second chance.
#
# The first cut of this guard was a deny list of exact top-level names plus
# a depth rule, and it did NOT do what its own comment claimed: in a `case`
# pattern `*` matches `/`, so `/*/*` means only "depth >= 2", and
# /usr/local, /var/db, /root/.ssh and $HOME/.ssh all cleared the deny list
# and then matched the depth rule. A deny list can never be finished - the
# next descendant nobody thought of is always one typo away.
#
# So this does not try to enumerate what is dangerous. It requires the path
# to be one we OWN, on two independent counts:
#
#   1. the final component has to look like a scratch name (`smoke`,
#      `smoke-*`, `*-smoke`). An operator typo lands on `local`, `db`,
#      `.ssh`, `etc` or their login name - none of which can be mistaken
#      for a scratch directory. /root/smoke and ./freebsd-smoke pass.
#   2. if the directory already EXISTS, it has to carry the sentinel file
#      a previous run of this script left in it. Nothing else is deleted,
#      ever - a pre-existing /var/db/smoke is refused, not removed.
#
# Resolve WITHOUT cd: the directory does not exist yet on a first run, and
# a `cd $(dirname ...)` that fails silently yields a different path than
# the one about to be deleted - which is how a first draft of this guard
# waved through /root and refused the /root/smoke that CI actually uses.
SENTINEL=.nzbfast-smoke-scratch

# Prints the normalised absolute path on stdout, or refuses on stderr and
# returns 1. Pure: it touches no filesystem, so the self-test below can
# drive it with paths that exist and paths that do not.
resolve_workdir() {
    case "$1" in
        /*) _abs="$1" ;;
        *)  _abs="$PWD/$1" ;;
    esac
    case "$_abs" in
        *..*) echo "smoke.sh: '$1' contains '..'; give a plain path" >&2
              return 1 ;;
    esac
    _abs=$(printf '%s' "$_abs" | sed 's|//*|/|g')     # collapse repeats
    # Collapse `/./` too. The DEFAULT workdir is the literal
    # `./freebsd-smoke`, so without this every message and every rm -rf
    # names $PWD/./freebsd-smoke - a path that works but that nobody can
    # eyeball against the one they meant to type.
    while :; do
        case "$_abs" in
            */./*) _abs=$(printf '%s' "$_abs" | sed 's|/\./|/|') ;;
            */.)   _abs=${_abs%/.} ;;
            */)    _abs=${_abs%/} ;;
            *)     break ;;
        esac
    done
    [ -n "$_abs" ] || _abs=/
    # Belt: the shapes that are never a scratch directory whatever they are
    # called. $HOME is here because a login directory named `smoke` would
    # otherwise satisfy the name rule below.
    case "$_abs" in
        /|/root|/home|/usr|/etc|/var|/bin|/sbin|/lib|/boot|/dev|/proc|/tmp|"${HOME:-}")
            echo "smoke.sh: '$_abs' is a system or home directory, not a scratch" >&2
            echo "  directory. This script deletes the path it is given." >&2
            return 1 ;;
    esac
    # Braces: the name rule is what actually stops /usr/local and /var/db.
    _base=${_abs##*/}
    case "$_base" in
        smoke|smoke-*|*-smoke) ;;
        *)  echo "smoke.sh: refusing '$_abs' - this script DELETES the path it" >&2
            echo "  is given, so it only accepts a directory whose last component" >&2
            echo "  is a scratch name: 'smoke', 'smoke-*' or '*-smoke'." >&2
            echo "  e.g. /root/smoke (what CI uses) or ./freebsd-smoke (default)." >&2
            return 1 ;;
    esac
    # Depth: a scratch directory is never top-level.
    case "$_abs" in
        /*/*) ;;
        *) echo "smoke.sh: '$_abs' is too shallow to be a scratch directory" >&2
           return 1 ;;
    esac
    printf '%s\n' "$_abs"
}

# Take ownership of the scratch directory. An EXISTING directory is only
# removed if this script created it, proven by the sentinel it drops on
# the way in - so a name collision with somebody's real data is a refusal
# rather than an unrecoverable rm -rf.
claim_workdir() {
    if [ -e "$1" ]; then
        if [ ! -d "$1" ] || [ ! -f "$1/$SENTINEL" ]; then
            echo "smoke.sh: '$1' already exists and was not created by this" >&2
            echo "  script (no $SENTINEL marker). Refusing to delete it." >&2
            echo "  Remove it yourself, or point the smoke at a fresh path." >&2
            return 1
        fi
        rm -rf "$1"
    fi
    mkdir -p "$1/out"
    : > "$1/$SENTINEL"
}

if [ "$SELF_TEST" -eq 1 ]; then
    # A guard nobody exercises is a guard that quietly stops guarding: the
    # version this replaced ACCEPTED /usr/local, the exact path its own
    # comment named as the thing to refuse. These cases are that comment,
    # made executable.
    _sp=0
    _sf=0
    _reject() {
        if resolve_workdir "$1" >/dev/null 2>&1; then
            echo "  FAIL - accepted '$1', must refuse"; _sf=$((_sf + 1))
        else
            echo "  ok   - refused '$1'"; _sp=$((_sp + 1))
        fi
    }
    _accept() {
        if _got=$(resolve_workdir "$1" 2>/dev/null); then
            if [ "$_got" = "$2" ]; then
                echo "  ok   - accepted '$1' as $_got"; _sp=$((_sp + 1))
            else
                echo "  FAIL - '$1' resolved to $_got, expected $2"; _sf=$((_sf + 1))
            fi
        else
            echo "  FAIL - refused '$1', must accept"; _sf=$((_sf + 1))
        fi
    }
    echo "workdir guard - paths that must be refused"
    for _p in / /usr /usr/local /var /var/db /root /root/.ssh /etc /etc/rc.d \
              /tmp /home /home/OTHERUSER /usr/local/etc ../smoke; do
        _reject "$_p"
    done
    _reject "${HOME:-/nonexistent}"
    _reject "${HOME:-/nonexistent}/.ssh"
    _reject "${HOME:-/nonexistent}/Documents"

    echo "workdir guard - the shapes the smoke actually uses"
    _accept /root/smoke /root/smoke                     # .github/workflows/release.yml
    _accept ./freebsd-smoke "$PWD/freebsd-smoke"        # the default
    _accept freebsd-smoke "$PWD/freebsd-smoke"
    _accept /root/smoke/ /root/smoke                    # trailing slash
    _accept //root//smoke /root/smoke                   # repeated separators
    _accept /var/tmp/nzbfast-smoke /var/tmp/nzbfast-smoke

    echo "sentinel - only a directory this script made is deleted"
    _t=$(mktemp -d)
    mkdir -p "$_t/smoke"
    : > "$_t/smoke/precious.txt"
    if claim_workdir "$_t/smoke" >/dev/null 2>&1; then
        echo "  FAIL - deleted a pre-existing directory with no sentinel"
        _sf=$((_sf + 1))
    elif [ -f "$_t/smoke/precious.txt" ]; then
        echo "  ok   - refused a pre-existing directory, left it untouched"
        _sp=$((_sp + 1))
    else
        echo "  FAIL - refused but the contents are gone"; _sf=$((_sf + 1))
    fi
    rm -rf "$_t/smoke"
    if claim_workdir "$_t/smoke" >/dev/null 2>&1 && [ -d "$_t/smoke/out" ]; then
        echo "  ok   - created a fresh scratch directory"; _sp=$((_sp + 1))
    else
        echo "  FAIL - could not create a fresh scratch directory"; _sf=$((_sf + 1))
    fi
    : > "$_t/smoke/leftover.txt"
    if claim_workdir "$_t/smoke" >/dev/null 2>&1 && [ ! -f "$_t/smoke/leftover.txt" ]; then
        echo "  ok   - re-used its own scratch directory (wiped)"; _sp=$((_sp + 1))
    else
        echo "  FAIL - could not re-claim its own scratch directory"; _sf=$((_sf + 1))
    fi
    rm -rf "$_t"
    echo ""
    echo "$_sp passed, $_sf failed"
    [ "$_sf" -eq 0 ]
    exit
fi

WORK=$(resolve_workdir "$WORK") || exit 1
claim_workdir "$WORK" || exit 1
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

#!/bin/zsh
# Guard tests for docker-entrypoint.sh's API-key pre-flight.
#
# The container fails CLOSED: it refuses to publish the control API on
# 0.0.0.0 when it cannot see a key. Getting that wrong in either
# direction is bad - too loose opens provider passwords to the LAN, too
# strict makes the container unstartable with no console to explain it.
#
# The entrypoint execs `nzbfast` last, so a stub on PATH stands in for
# the daemon and "STARTED" in the output means the pre-flight let it
# through. Run: packaging/tests/docker-entrypoint-key.sh
set -uo pipefail

SCRIPT=$(cd "$(dirname "$0")/.." && pwd)/docker-entrypoint.sh
[ -f "$SCRIPT" ] || { echo "cannot find docker-entrypoint.sh"; exit 1; }

PASS=0
FAIL=0
ok()   { echo "  ok   - $1"; PASS=$((PASS + 1)); }
bad()  { echo "  FAIL - $1"; FAIL=$((FAIL + 1)); }

# One case: build a /config, run the entrypoint against it with a stub
# daemon on PATH, and say whether it started or refused.
#
# $2 is shell run inside the config dir to set the install's state.
run_case() {
  local desc=$1 setup=$2 expect=$3
  local tmp cfgdir out
  tmp=$(mktemp -d)
  cfgdir="$tmp/config"
  mkdir -p "$cfgdir" "$tmp/bin"
  printf '#!/bin/sh\necho STARTED\n' > "$tmp/bin/nzbfast"
  chmod +x "$tmp/bin/nzbfast"
  echo '{"servers":[]}' > "$cfgdir/config.json"
  ( cd "$cfgdir" && eval "$setup" )

  out=$(PATH="$tmp/bin:$PATH" NZBFAST_CONFIG="$cfgdir/config.json" \
        NZBFAST_APIKEY= NZBFAST_OPEN=0 sh "$SCRIPT" 2>&1)

  if [ "$expect" = "start" ]; then
    if echo "$out" | grep -q STARTED; then
      ok "$desc"
    else
      bad "$desc: refused when it should have started: $(echo "$out" | head -2)"
    fi
  else
    if echo "$out" | grep -q STARTED; then
      bad "$desc: started when it should have refused"
    elif echo "$out" | grep -q "ERROR"; then
      ok "$desc"
    else
      bad "$desc: neither started nor refused: $(echo "$out" | head -2)"
    fi
  fi
  rm -rf "$tmp"
}

echo "docker-entrypoint.sh API-key pre-flight"

# The states that must still refuse.
run_case "established install, no key anywhere" \
  'echo "{}" > settings.json' refuse
run_case "spool only, no key anywhere" \
  'mkdir -p .spool' refuse
run_case "key file exists but is empty" \
  'echo "{}" > settings.json; : > apikey' refuse
run_case "settings.json holds an EMPTY apikey" \
  'printf "{\"apikey\": \"\"}\n" > settings.json' refuse
run_case "settings.json holds a null apikey" \
  'printf "{\"apikey\": null}\n" > settings.json' refuse

# The states that must start.
run_case "first run, writable /config" \
  'true' start
run_case "key file present and non-empty" \
  'echo "{}" > settings.json; echo deadbeef > apikey' start

# THE REGRESSION: clearing the key in the dashboard deletes the key file,
# and re-setting one used to write only settings.json. settings.json WINS
# at load, so that install is keyed - but the entrypoint looked only at
# the file and refused, leaving the container unable to restart at all.
run_case "settings.json holds a key, key file was cleared away" \
  'printf "{\n  \"apikey\": \"deadbeef\"\n}\n" > settings.json' start
run_case "same, written compactly by hand" \
  'printf "{\"apikey\":\"deadbeef\"}\n" > settings.json' start

echo
echo "passed: $PASS  failed: $FAIL"
[ "$FAIL" -eq 0 ]

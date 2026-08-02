#!/bin/zsh
# Every packaging script the release flow invokes by path must be
# committed executable.
#
# upload-release-assets.sh shipped as mode 100644. The release skill
# runs it directly - `packaging/upload-release-assets.sh vX.Y.Z ...` -
# so a fresh Unix checkout got EACCES before the asset stamp validation
# it exists to enforce ever ran, at the one step that puts binaries in
# front of the public. A shebang cannot grant itself the execute bit,
# and "just run it with zsh" is not the documented workflow.
#
# Checks the INDEX, not the worktree: the mode that ships is the one git
# recorded, and a local chmod that was never staged is exactly the state
# that looked fine to the author and broke for everyone else.
#
# Run: packaging/tests/script-modes.sh
set -uo pipefail

cd "$(dirname "$0")/../.." || exit 1

PASS=0
FAIL=0
ok()  { echo "  ok   - $1"; PASS=$((PASS + 1)); }
bad() { echo "  FAIL - $1"; FAIL=$((FAIL + 1)); }

# Scripts that are deliberately NOT executable, with the reason. Anything
# listed here must be run some other way that sets the bit itself.
#   docker-entrypoint.sh - never invoked from the checkout; both
#   Dockerfiles COPY it and `RUN chmod +x` it inside the image.
NON_EXEC="packaging/docker-entrypoint.sh"

listing=$(git ls-files -s 'packaging/*.sh' 'packaging/**/*.sh')
[ -n "$listing" ] || { echo "no packaging scripts found - wrong directory?"; exit 1; }

echo "packaging script modes"
while IFS= read -r row; do
  mode=${row%% *}
  path=${row#*$'\t'}
  case " $NON_EXEC " in
    *" $path "*)
      if [ "$mode" = "100644" ]; then
        ok "$path: non-executable by design"
      else
        bad "$path: listed as non-executable by design but has mode $mode"
      fi
      ;;
    *)
      if [ "$mode" = "100755" ]; then
        ok "$path: executable"
      else
        bad "$path: mode $mode, expected 100755"
      fi
      ;;
  esac
done <<< "$listing"

echo
echo "passed: $PASS  failed: $FAIL"
[ "$FAIL" -eq 0 ]

#!/bin/sh
# bump-version.sh <new-version>
#
# One command to move every version reference in lockstep:
#   crates/nzbfast/Cargo.toml   (source of truth)
#   crates/nzbtray/Cargo.toml   (installer stamps both exes)
#   packaging/homebrew/nzbfast.rb
#   Cargo.lock                  (via cargo, if available)
set -eu

NEW=${1:?usage: bump-version.sh <new-version>}
case "$NEW" in
    *[!0-9.]*|.*|*.) echo "version must be dotted numerals, e.g. 1.0.3" >&2; exit 1 ;;
esac
ROOT=$(cd "$(dirname "$0")/.." && pwd)

bump_toml() {
    # Only the first `version = "..."` line (the [package] one).
    awk -v new="$NEW" '!done && /^version = "/ { sub(/"[^"]*"/, "\"" new "\""); done=1 } { print }' \
        "$1" > "$1.tmp" && mv "$1.tmp" "$1"
}

bump_toml "$ROOT/crates/nzbfast/Cargo.toml"
bump_toml "$ROOT/crates/nzbtray/Cargo.toml"
sed -i '' "s/^  version \"[^\"]*\"/  version \"$NEW\"/" "$ROOT/packaging/homebrew/nzbfast.rb" 2>/dev/null \
    || sed -i "s/^  version \"[^\"]*\"/  version \"$NEW\"/" "$ROOT/packaging/homebrew/nzbfast.rb"

if command -v cargo >/dev/null 2>&1; then
    (cd "$ROOT" && cargo update -q -p nzbfast -p nzbtray 2>/dev/null) || true
fi

# Website download buttons are version-pinned (asset filenames inside
# /releases/latest/download/ URLs). They must move in lockstep with the
# release publish or the live site 404s - all locales, one pass.
for f in "$ROOT"/website/download*.html; do
    [ -f "$f" ] || continue
    sed -i '' -E "s/nzbfast-[0-9]+(\.[0-9]+)+-/nzbfast-$NEW-/g" "$f" 2>/dev/null \
        || sed -i -E "s/nzbfast-[0-9]+(\.[0-9]+)+-/nzbfast-$NEW-/g" "$f"
done

echo "bumped to $NEW:"
grep -Hn '^version' "$ROOT/crates/nzbfast/Cargo.toml" "$ROOT/crates/nzbtray/Cargo.toml"
grep -Hn 'version "' "$ROOT/packaging/homebrew/nzbfast.rb" | head -1

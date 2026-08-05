#!/usr/bin/env python3
"""Refuse new poison-intolerant lock sites in production code. TODO 102b.

`crates/nzbkit/src/sync.rs` exists because a panicking worker used to take the
whole daemon down with it: every other thread touching the same mutex inherited
the poison and panicked in turn. `lock_ok()` / `read_ok()` / `write_ok()`
recover the guard instead, and the 1 Aug sweep converted ~1,000 sites to them.

Then new code went back to `.lock().unwrap()`. The 3 Aug scorecard predicted
that a second sweep would not hold either, and it was right - `spawn_watch_folder`
alone had grown three fresh sites by 4 Aug. This is the gate it asked for
instead.

Why a script and not clippy's `disallowed-methods`: that lint cannot see
`#[cfg(test)]`, so with CI's `-D warnings` it would fail on ~70 test-side sites
where `.unwrap()` is the RIGHT call - a test SHOULD die on a poisoned lock. The
alternative was ~70 `#[allow]` annotations sprayed across files that other
concurrent sessions are editing. This resolves test scope properly instead.

Usage:
    tools/lock-gate.py            # gate: exit 1 if any production site exists
    tools/lock-gate.py --list     # report every site, test ones included
"""

import os
import re
import sys

CRATES = "crates"
# `.lock()`, `.read()` and `.write()` are all std lock APIs; `.unwrap()` on any
# of them is the poison-intolerant shape. `read`/`write` do collide with
# io::Read / io::Write, so a hit is reported with its line for eyeballing
# rather than auto-rewritten.
SITE = re.compile(r"\.(lock|read|write)\(\)\.unwrap\(\)")
CFG_TEST = re.compile(r"\s*#\[cfg\(test\)\]")
# `#[cfg(test)] mod foo;` makes the WHOLE of foo.rs test code. Missing this is
# how a naive version of this script reported crates/nzbkit/src/extract/
# testutil.rs - 2 sites of pure test scaffolding - as a production regression.
CFG_TEST_MOD = re.compile(r"\s*#\[cfg\(test\)\]\s*(?:\n\s*)?(?:pub(?:\([^)]*\))?\s+)?mod\s+(\w+)\s*;")


def strip_noise(line):
    """Blank out string literals and line comments before counting braces.

    This repo's copy is full of braces inside strings (`format!("{n}/{d}")`,
    the i18n keys, the SABnzbd JSON shapes), and a naive brace counter closes
    a module dozens of lines early because of them.
    """
    line = re.sub(r'"(\\.|[^"\\])*"', '""', line)
    line = re.sub(r"'(\\.|[^'\\])'", "''", line)
    return re.sub(r"//.*", "", line)


def test_only_modules(path, lines):
    """Names of child modules this file declares as #[cfg(test)]."""
    joined = "\n".join(lines)
    return set(CFG_TEST_MOD.findall(joined))


def test_line_mask(lines):
    """True for every line inside an inline `#[cfg(test)]` block."""
    mask = [False] * len(lines)
    i = 0
    while i < len(lines):
        if CFG_TEST.match(lines[i]):
            depth, started, j = 0, False, i
            while j < len(lines):
                s = strip_noise(lines[j])
                depth += s.count("{") - s.count("}")
                if "{" in s:
                    started = True
                if started and depth <= 0:
                    break
                j += 1
            if started:
                for k in range(i, min(j + 1, len(lines))):
                    mask[k] = True
                i = j + 1
                continue
        i += 1
    return mask


def collect():
    """Return (production_sites, test_sites) as (path, lineno, text) tuples."""
    test_files = set()
    contents = {}
    for root, _dirs, files in os.walk(CRATES):
        if f"{os.sep}fuzz{os.sep}" in root + os.sep:
            continue
        for f in files:
            if not f.endswith(".rs"):
                continue
            p = os.path.join(root, f)
            contents[p] = open(p, encoding="utf8", errors="replace").read().split("\n")

    for p, lines in contents.items():
        for name in test_only_modules(p, lines):
            d = os.path.dirname(p)
            base = p[:-3]  # strip .rs, for the `foo/` sibling-dir layout
            for cand in (os.path.join(d, name + ".rs"), os.path.join(base, name + ".rs")):
                if cand in contents:
                    test_files.add(cand)

    prod, test = [], []
    for p, lines in contents.items():
        # tests/ and benches/ are whole test targets; so is any module a parent
        # declared #[cfg(test)].
        whole_file_is_test = (
            f"{os.sep}tests{os.sep}" in p or f"{os.sep}benches{os.sep}" in p or p in test_files
        )
        mask = test_line_mask(lines)
        for i, line in enumerate(lines):
            if not SITE.search(line):
                continue
            entry = (p, i + 1, line.strip())
            (test if whole_file_is_test or mask[i] else prod).append(entry)
    return prod, test


def main():
    prod, test = collect()
    if "--list" in sys.argv:
        for label, rows in (("production", prod), ("test", test)):
            print(f"\n=== {label}: {len(rows)} ===")
            for p, n, line in sorted(rows):
                print(f"  {p}:{n}\n      {line[:100]}")
        return 0

    if not prod:
        print(f"lock-gate: 0 poison-intolerant lock sites in production ({len(test)} in tests, fine)")
        return 0

    print(f"lock-gate: {len(prod)} poison-intolerant lock site(s) in PRODUCTION code:\n", file=sys.stderr)
    for p, n, line in sorted(prod):
        print(f"  {p}:{n}\n      {line[:100]}", file=sys.stderr)
    print(
        "\n  Use the poison-recovering forms from nzbkit::sync instead:\n"
        "      .lock().unwrap()   ->  .lock_ok()\n"
        "      .read().unwrap()   ->  .read_ok()\n"
        "      .write().unwrap()  ->  .write_ok()\n"
        "\n  A poisoned lock means another thread panicked. Inheriting that panic\n"
        "  is what took the whole daemon down before the 1 Aug sweep. See the\n"
        "  module docs in crates/nzbkit/src/sync.rs.\n"
        "\n  In tests .unwrap() is correct and this gate ignores it - a test SHOULD\n"
        "  die on a poisoned lock.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())

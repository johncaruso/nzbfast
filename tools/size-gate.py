#!/usr/bin/env python3
"""Refuse file and function growth past the recorded baseline. TODO 102 / 106.

The scorecard kept measuring the same drift: TODO 43 split `serve()` to 1,819
lines and it regrew to 2,234 within days; `get_with_progress()` reached 3,942
lines - 2.5x the longest function in any competitor - without any list even
naming it. The 3 Aug offender list missed it because a naive brace counter
died on the first string literal containing a brace. This gate exists so the
§106 splits stay split.

Semantics:
  - Every `.rs` file under crates/ (fuzz dirs excluded) must stay under
    FILE_CEILING raw lines; every PRODUCTION function must stay under
    FN_CEILING lines. Test functions are reported but not gated - a table
    of cases is allowed to be long.
  - Today's offenders are allow-listed in BASELINE with their measured
    size. An entry's limit is its recorded size plus 2% slack, so ordinary
    feature work does not trip it while regrowth does. A false-refusal-prone
    gate gets switched off - that is the fmt-hook lesson.
  - The list only shrinks. When a target drops back under the ceiling the
    gate FAILS until its entry is deleted, in the same commit as the split.
    That is the ratchet.

Test scope is resolved properly (inline `#[cfg(test)]` blocks AND
`#[cfg(test)] mod foo;` making the whole of foo.rs test code) - same
resolver family as tools/lock-gate.py, same reason: naive path-based
counting has already produced one wrong scorecard round.

Usage:
    tools/size-gate.py            # gate: exit 1 on any violation
    tools/size-gate.py --list     # report the largest files and functions
"""

import os
import re
import sys

CRATES = "crates"
FILE_CEILING = 3000  # raw lines; the worst competitor file is ~5,400
FN_CEILING = 500  # production function lines; rustnzb ships zero over 500
SLACK = 1.02  # ordinary feature work must not trip an allow-listed entry

# Measured 4 Aug 2026 (post-v1.0.16). Delete each entry as its target is
# split - the gate refuses stale entries, so deletion is enforced, not hoped.
BASELINE_FILES = {
    # path (relative to repo root): raw lines measured
    # serve/mod.rs was here at 13,837, then 12,988, then 13,310. Phase 4
    # moved its flat free functions out to sibling modules and dispersed
    # its 4,800-line inline `mod tests`; it is 852 lines now, so its entry
    # is GONE. Nothing is left to grandfather.
    "crates/nzbfast/tests/daemon.rs": 11803,
    # 7471 when first measured; two concurrent 5 Aug sessions landed
    # test growth (one-pass rigs + the round-6 crc-retry pricing leg).
    "crates/nzbfast/tests/e2e.rs": 7641,
    # 7165 when first measured; pre-gate concurrent work landed 7375.
    "crates/nzbfast/src/smart.rs": 7375,
    # 7081 when first measured; peaked at 10,828 during the fault/tuner
    # campaign. TODO 113 ratchet: the payout/safety rigs moved to
    # pool/rig_tests.rs (their own child module), 10,828 -> 7,855, then
    # the session_loop split (1,084 -> 461, its fn entry deleted) paid
    # ~170 lines of extraction overhead (signatures + docs): 8,011.
    # 8,282 after the §114 consumer-steer graduation merged over the
    # split (note_decoded seam + handed/steer-inbox plumbing; its rigs
    # live in rig_tests.rs, which absorbs the test growth).
    "crates/nzbkit/src/pool.rs": 8282,
    # Born 2,988 in the TODO 113 split (the pool's payout/safety rigs,
    # one file because sibling cfg(test) mods cannot share helpers);
    # 3,125 when the §114 consumer-steer rigs replaced the pool-gate
    # ones. All test code - grandfathered like pool.rs's rig growth
    # was, ratchet when the campaign settles.
    "crates/nzbkit/src/pool/rig_tests.rs": 3125,
    "crates/nzbkit/src/extract/mod.rs": 6192,
    # 6056 when first measured; pre-gate concurrent work landed 6213, and
    "crates/nzbfast/src/serve/tasks.rs": 6400,
    # 5946 when first measured; pre-gate concurrent sessions landed 6106,
    # and the 5 Aug session union 6231 (event taxonomy, 5ab52b20).
    "crates/nzbfast/src/serve/daemon.rs": 6231,
    "crates/nzbkit/src/par2repair.rs": 5150,
    "crates/nzbkit/src/rar.rs": 4088,
    "crates/nzbfast/src/wall.rs": 3911,
    "crates/nzbkit/src/nntp.rs": 3688,
    "crates/nzbkit/src/release.rs": 3505,
    "crates/nzbkit/src/extract/crypto.rs": 3365,
    "crates/nzbfast/src/repair.rs": 3305,
}

BASELINE_FNS = {
    # "path::fn_name": lines measured
    # 688 when first measured; pre-gate concurrent work landed 719, then 770.
    "crates/nzbfast/src/serve/tasks.rs::spawn_download_worker": 770,
    "crates/nzbfast/src/serve/sabcompat.rs::queue_json": 652,
    "crates/nzbfast/src/serve/tasks.rs::spawn_index_scan": 582,
}

CFG_TEST = re.compile(r"\s*#\[cfg\(test\)\]")
# The `#[path = "x_tests.rs"] mod x_tests;` hook puts an attribute between
# the cfg and the mod, and the old pattern stopped dead at it - every file
# attached that way was scored as PRODUCTION code, so a long table-driven
# test in one would have tripped the fn ceiling for no reason. Tolerate any
# run of attributes in between.
CFG_TEST_MOD = re.compile(
    r"\s*#\[cfg\(test\)\]\s*(?:\n\s*)?(?:#\[[^\]]*\]\s*(?:\n\s*)?)*"
    r"(?:pub(?:\([^)]*\))?\s+)?mod\s+(\w+)\s*;"
)
FN_START = re.compile(
    r"(?:^|[\s{}();])(?:pub(?:\([^)]*\))?\s+)?(?:default\s+)?(?:const\s+)?"
    r"(?:async\s+)?(?:unsafe\s+)?(?:extern\s*\"[^\"]*\"\s+)?fn\s+(\w+)"
)


def strip_noise(text):
    """Blank strings and comments, preserving line structure and braces.

    A real tokenizer, not a per-line regex: the 3 Aug offender list was built
    with a per-line version and stopped dead at the first multi-line string
    with an unbalanced brace, silently dropping the biggest function in the
    repo from its own report. Handles nested block comments, escapes, raw
    strings (r#".."#, b"..", br#".."#), and char-literal-vs-lifetime.
    """
    out = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] != "\n":
                i += 1
        elif c == "/" and i + 1 < n and text[i + 1] == "*":
            depth, i = 1, i + 2
            while i < n and depth:
                if text.startswith("/*", i):
                    depth += 1
                    i += 2
                elif text.startswith("*/", i):
                    depth -= 1
                    i += 2
                else:
                    if text[i] == "\n":
                        out.append("\n")
                    i += 1
        elif c == '"':
            i += 1
            while i < n and text[i] != '"':
                if text[i] == "\\":
                    i += 1
                elif text[i] == "\n":
                    out.append("\n")
                i += 1
            i += 1
        elif c in "rb" and re.match(r'(?:r#*"|br#*"|rb#*"|b")', text[i:]):
            m = re.match(r'(?:b?r)(#*)"', text[i:])
            if m:  # raw string: ends at "### with the same hash count
                hashes = m.group(1)
                i += m.end()
                end = text.find('"' + hashes, i)
                end = n if end == -1 else end + 1 + len(hashes)
                out.extend("\n" * text.count("\n", i, end))
                i = end
            else:  # b"..." plain byte string
                i += 2
                while i < n and text[i] != '"':
                    if text[i] == "\\":
                        i += 1
                    elif text[i] == "\n":
                        out.append("\n")
                    i += 1
                i += 1
        elif c == "'":
            m = re.match(r"'(?:\\[^']*|[^'\\])'", text[i:])
            if m:  # char literal; otherwise a lifetime - keep scanning
                i += m.end()
            else:
                out.append(c)
                i += 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


def test_line_mask(clean_lines):
    """True for every line inside an inline `#[cfg(test)]` block."""
    mask = [False] * len(clean_lines)
    i = 0
    while i < len(clean_lines):
        if CFG_TEST.match(clean_lines[i]):
            depth, started, j = 0, False, i
            while j < len(clean_lines):
                s = clean_lines[j]
                depth += s.count("{") - s.count("}")
                if "{" in s:
                    started = True
                if started and depth <= 0:
                    break
                j += 1
            if started:
                for k in range(i, min(j + 1, len(clean_lines))):
                    mask[k] = True
                i = j + 1
                continue
        i += 1
    return mask


def functions(clean_lines):
    """Yield (name, start_line_0based, span_lines) for every fn with a body."""
    text = "\n".join(clean_lines)
    line_of = []
    ln = 0
    for ch in text:
        line_of.append(ln)
        if ch == "\n":
            ln += 1
    for m in FN_START.finditer(text):
        # Scan from the signature to the first `{` or `;`. A `;` first means
        # a trait method declaration or extern item - no body, no entry.
        j = m.end()
        while j < len(text) and text[j] not in "{;":
            j += 1
        if j >= len(text) or text[j] == ";":
            continue
        depth = 0
        k = j
        while k < len(text):
            if text[k] == "{":
                depth += 1
            elif text[k] == "}":
                depth -= 1
                if depth == 0:
                    break
            k += 1
        start = line_of[m.start(1)]
        end = line_of[min(k, len(text) - 1)]
        yield m.group(1), start, end - start + 1


def collect():
    contents = {}
    for root, _dirs, files in os.walk(CRATES):
        if f"{os.sep}fuzz{os.sep}" in root + os.sep:
            continue
        for f in files:
            if not f.endswith(".rs"):
                continue
            p = os.path.join(root, f)
            contents[p] = open(p, encoding="utf8", errors="replace").read()

    test_files = set()
    clean = {p: strip_noise(t).split("\n") for p, t in contents.items()}
    for p, lines in clean.items():
        for name in CFG_TEST_MOD.findall("\n".join(lines)):
            d = os.path.dirname(p)
            base = p[:-3]
            for cand in (os.path.join(d, name + ".rs"), os.path.join(base, name + ".rs")):
                if cand in contents:
                    test_files.add(cand)

    files_out = []  # (path, raw_lines)
    fns_out = []  # (path, name, line_1based, span, is_test)
    for p, text in contents.items():
        files_out.append((p, text.count("\n") + 1))
        whole_file_is_test = (
            f"{os.sep}tests{os.sep}" in p or f"{os.sep}benches{os.sep}" in p or p in test_files
        )
        mask = test_line_mask(clean[p])
        for name, start, span in functions(clean[p]):
            is_test = whole_file_is_test or (start < len(mask) and mask[start])
            fns_out.append((p, name, start + 1, span, is_test))
    return files_out, fns_out


def main():
    files, fns = collect()

    if "--list" in sys.argv:
        print("=== largest files (raw lines) ===")
        for p, n in sorted(files, key=lambda x: -x[1])[:25]:
            print(f"  {n:7,}  {p}")
        print("\n=== longest production functions ===")
        prod = [f for f in fns if not f[4]]
        for p, name, line, span, _ in sorted(prod, key=lambda x: -x[3])[:25]:
            print(f"  {span:7,}  {p}:{line}  {name}")
        print("\n=== longest test functions (not gated) ===")
        test = [f for f in fns if f[4]]
        for p, name, line, span, _ in sorted(test, key=lambda x: -x[3])[:10]:
            print(f"  {span:7,}  {p}:{line}  {name}")
        return 0

    errors = []

    seen_files = {p: n for p, n in files}
    for p, n in sorted(files):
        limit = FILE_CEILING
        if p in BASELINE_FILES:
            limit = int(BASELINE_FILES[p] * SLACK)
        if n > limit:
            errors.append(
                f"file {p} is {n:,} raw lines (limit {limit:,})"
                + (" - it has REGROWN past its baseline" if p in BASELINE_FILES else "")
            )
    for p, base in sorted(BASELINE_FILES.items()):
        if p not in seen_files:
            errors.append(f"baseline entry for missing file {p} - delete the entry")
        elif seen_files[p] <= FILE_CEILING:
            errors.append(
                f"{p} is now {seen_files[p]:,} lines, under the {FILE_CEILING:,} ceiling - "
                "delete its baseline entry (the list only shrinks)"
            )

    prod_fns = {}
    for p, name, line, span, is_test in fns:
        if is_test:
            continue
        key = f"{p}::{name}"
        if span > prod_fns.get(key, (0, 0))[0]:
            prod_fns[key] = (span, line)
    for key, (span, line) in sorted(prod_fns.items()):
        limit = FN_CEILING
        if key in BASELINE_FNS:
            limit = int(BASELINE_FNS[key] * SLACK)
        if span > limit:
            p, name = key.rsplit("::", 1)
            errors.append(
                f"fn {name} ({p}:{line}) is {span:,} lines (limit {limit:,})"
                + (" - it has REGROWN past its baseline" if key in BASELINE_FNS else "")
            )
    for key, base in sorted(BASELINE_FNS.items()):
        if key not in prod_fns:
            errors.append(f"baseline entry for missing fn {key} - delete the entry")
        elif prod_fns[key][0] <= FN_CEILING:
            errors.append(
                f"{key} is now {prod_fns[key][0]:,} lines, under the {FN_CEILING:,} ceiling - "
                "delete its baseline entry (the list only shrinks)"
            )

    if not errors:
        n_files = sum(1 for p in BASELINE_FILES)
        n_fns = sum(1 for k in BASELINE_FNS)
        print(
            f"size-gate: clean ({len(files)} files, {len(prod_fns)} production fns; "
            f"{n_files} file + {n_fns} fn baseline entries still to burn down)"
        )
        return 0

    print(f"size-gate: {len(errors)} violation(s):\n", file=sys.stderr)
    for e in errors:
        print(f"  {e}", file=sys.stderr)
    print(
        "\n  New code must stay under the ceilings. If a listed target was just\n"
        "  split, delete its baseline entry in the same commit. Do not raise a\n"
        "  baseline number to make this pass - the splits are TODO 106 and the\n"
        "  numbers only go down.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    sys.exit(main())

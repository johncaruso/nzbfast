#!/usr/bin/env python3
"""check-release-notes.py <notes-file> <version>

Refuse release notes that would strand a platform or point at the wrong
build. make-latest-json.sh REQUIRES <dist-dir>/RELEASE_NOTES.md and runs
this on it, so every release build either passes this gate or waives it
loudly with SKIP_NOTES_CHECK=1 - the notes are the page almost every
user lands on, and nothing else checks them. (The requirement is the
point: while a missing file merely skipped the check, the guarantee
above was false for exactly the runs that had not written the notes.)

What each rule is here for, all of them from something that shipped:

- Every platform row present. 1.1.2 went out with Unraid folded into a
  "QNAP / Unraid: the Docker image, or the Linux tar.gz" row, sending the
  one platform with a one-click install down the hard path. The CA
  listing had existed for two weeks.
- Asset filenames match THIS version. A hand-copied table keeps the
  previous release's filenames, and every link on it 404s.
- No em-dashes or en-dashes, and never the word "streaming" (house copy
  rules, which the notes are otherwise outside of - no other gate reads
  this file).
- Paragraphs unwrapped. GitHub renders every newline in a release body
  as a hard break, so 70-column source wrapping becomes forced mid
  sentence breaks on phones. This bit v1.0.17.
"""
import re
import sys

REQUIRED_ROWS = [
    ("macOS", r"macOS"),
    ("Windows installer", r"windows-x64-setup\.exe"),
    ("Windows portable zip", r"windows-x64\.zip"),
    # Windows ARM64 is NOT in this list, and its absence is the decision.
    # The row is in release-notes-header.md, so the generated table always
    # carries it and nobody can forget it - but that build is a beta whose
    # whole premise is that it can be withdrawn cheaply. Requiring a row
    # here would mean a release that pulls the ARM64 asset (a bad build, a
    # red CI leg) could not pass its own notes gate without an edit to this
    # file, which is friction pointed the wrong way. Every other row names
    # an asset that has shipped for months.
    ("Linux x86-64", r"linux-x64\.tar\.gz"),
    ("Linux ARM64", r"linux-arm64\.tar\.gz"),
    ("Synology", r"noarch\.spk"),
    ("Unraid", r"\|\s*Unraid\s*\|"),
    ("Unraid one-click install named", r"Community Applications"),
    # The ASSET, not the word. "QNAP" alone is satisfied by the prose
    # below the table (which mentions QNAP four times), so deleting the
    # table row left this row's check green - the one edit it exists to
    # catch. Every other entry here already names a filename or a table
    # cell; this one was the odd one out.
    ("QNAP", r"qnap-beta\.qpkg"),
    ("Docker", r"docker pull nzbfast/nzbfast"),
    ("machine-only assets explained", r"is machine-only"),
    # The .deb/.rpm, armv7, QNAP-as-a-row, TrueNAS and FreeBSD rows are
    # NOT required, and that is the same decision the Windows ARM64 note
    # above records, applied consistently. Every one of them is a beta
    # whose premise is that it can be withdrawn cheaply; requiring a row
    # would mean a release that pulls a bad beta asset could not pass its
    # own notes gate without editing this file. The rows live in
    # release-notes-header.md so the generator always emits them.
    # (Raised as sweep2 L13; the half worth acting on was the QNAP
    # pattern above, which matched prose rather than the row.)
]


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__.strip().splitlines()[0], file=sys.stderr)
        return 2
    path, version = sys.argv[1], sys.argv[2]
    try:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
    except OSError as exc:
        print("✗ cannot read %s: %s" % (path, exc), file=sys.stderr)
        return 1

    bad = []

    for label, pattern in REQUIRED_ROWS:
        if not re.search(pattern, text):
            bad.append("missing from the download table: %s" % label)

    # Any nzbfast-<dotted version>-<asset> that is not this release is a
    # stale row. The updater payloads use the same shape, so this covers
    # them too.
    for stale in sorted(set(re.findall(r"nzbfast-(\d+\.\d+\.\d+)-", text))):
        if stale != version:
            bad.append("names version %s, but this release is %s" % (stale, version))
    if ("nzbfast/nzbfast:%s" % version) not in text:
        bad.append("the Docker row does not pull :%s" % version)

    for dash, name in (("—", "an em-dash"), ("–", "an en-dash")):
        if dash in text:
            bad.append("contains %s (house copy rule: use a spaced hyphen)" % name)
    if "streaming" in text.lower():
        bad.append('contains the word "streaming" (banned in user-facing copy)')

    # Wrapped prose: a short line that is not a heading, table row, list
    # item, or blank, and whose successor continues the sentence.
    lines = text.split("\n")
    for i, line in enumerate(lines[:-1]):
        nxt = lines[i + 1].strip()
        if not line.strip() or not nxt:
            continue
        if line.lstrip()[:1] in "#|-*>" or nxt[:1] in "#|-*>":
            continue
        if len(line) < 72 and not line.rstrip().endswith((".", ":", "?", "!")):
            bad.append("line %d looks wrapped - GitHub hard-breaks it: %r"
                       % (i + 1, line.strip()[:52]))

    if bad:
        print("✗ %s is not shippable:" % path, file=sys.stderr)
        for b in bad:
            print("    - %s" % b, file=sys.stderr)
        print("    Regenerate the header: packaging/make-release-notes.sh %s <body>"
              % version, file=sys.stderr)
        return 1
    print("✓ release notes cover every platform and name %s" % version)
    return 0


if __name__ == "__main__":
    sys.exit(main())

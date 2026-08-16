#!/usr/bin/env python3
"""Generate the index files for a flat APT repository.

Reads a directory of .deb files and writes Packages, Packages.gz and
Release next to them. Signing is NOT done here - make-apt-repo.sh runs
gpg over the Release this writes.

Why this is not `dpkg-scanpackages`: the repository is signed on the
release machine, which is a Mac, and dpkg-dev is not there. This reads
the .deb format directly (an `ar` archive holding control.tar.gz), so
the same script produces the same bytes on macOS and in a container -
which is what makes the container verification meaningful.

Run: packaging/linux/apt-index.py --repo <dir> [--keep N]
"""
import argparse
import email.utils
import gzip
import hashlib
import io
import os
import re
import sys
import tarfile

POOL = "pool"


# ------------------------------------------------------------------ .deb
def ar_members(blob):
    """Yield (name, bytes) for each member of a Unix `ar` archive.

    The format is 8 magic bytes then, per member, a 60-byte header whose
    fields are space-padded ASCII, followed by the data padded to an even
    offset. GNU long names (`/123`) do not appear in a .deb - dpkg only
    ever writes debian-binary, control.tar.* and data.tar.* - so the
    short-name form is all that is handled, and anything else is an
    error rather than a silent skip.
    """
    if blob[:8] != b"!<arch>\n":
        raise ValueError("not an ar archive (bad magic)")
    off = 8
    while off < len(blob):
        header = blob[off:off + 60]
        if len(header) < 60:
            break
        if header[58:60] != b"`\n":
            raise ValueError(f"bad ar header at offset {off}")
        name = header[0:16].decode("ascii", "replace").strip()
        size = int(header[48:58].decode("ascii").strip())
        data = blob[off + 60:off + 60 + size]
        yield name.rstrip("/"), data
        off += 60 + size + (size & 1)          # members are even-aligned


def control_stanza(path):
    """Return the DEBIAN/control text of a .deb, as a string."""
    with open(path, "rb") as fh:
        blob = fh.read()
    for name, data in ar_members(blob):
        if not name.startswith("control.tar"):
            continue
        ext = name[len("control.tar"):]
        if ext not in ("", ".gz", ".xz"):
            # zstd is legal in a .deb and Python's tarfile cannot read
            # it. Our own packages are built with `dpkg-deb -Zgzip`, so
            # this only fires on a foreign .deb - say which, rather than
            # producing a repository that silently omits it.
            raise ValueError(f"{os.path.basename(path)}: unsupported "
                             f"control compression '{name}'")
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tar:
            for member in tar.getmembers():
                if member.name.lstrip("./") == "control":
                    return tar.extractfile(member).read().decode("utf-8")
        raise ValueError(f"{os.path.basename(path)}: no control file")
    raise ValueError(f"{os.path.basename(path)}: no control.tar member")


def field(stanza, name):
    """Read a single-line field out of a control stanza."""
    m = re.search(rf"^{name}:[ \t]*(.*)$", stanza, re.M)
    return m.group(1).strip() if m else ""


# -------------------------------------------------------------- versions
def version_key(v):
    """Order two Debian versions the way dpkg does.

    Only as much of the algorithm as this repository needs: epochs, then
    upstream, then revision, each compared in alternating non-digit and
    digit runs. The non-digit comparison is dpkg's, where `~` sorts
    before everything including the empty string - that is the rule that
    puts 1.1.2-0beta1 below 1.1.2-1, and getting it wrong would let a
    beta shadow a release.
    """
    def order(c):
        if c == "~":
            return -1
        if c.isdigit():
            return 0
        if c.isalpha():
            return ord(c)
        return ord(c) + 256

    def parts(s):
        out, i = [], 0
        while i < len(s):
            nondigit = ""
            while i < len(s) and not s[i].isdigit():
                nondigit += s[i]
                i += 1
            digits = ""
            while i < len(s) and s[i].isdigit():
                digits += s[i]
                i += 1
            out.append(([order(c) for c in nondigit], int(digits or 0)))
        return out

    epoch, _, rest = v.partition(":")
    if not _:
        epoch, rest = "0", v
    upstream, _, revision = rest.rpartition("-")
    if not _:
        upstream, revision = rest, ""
    return (int(epoch or 0), parts(upstream), parts(revision))


# --------------------------------------------------------------- indexing
def hashes(data):
    return (hashlib.md5(data).hexdigest(),
            hashlib.sha1(data).hexdigest(),
            hashlib.sha256(data).hexdigest())


def build_packages(repo, keep):
    """Return the Packages file text for every .deb under repo/pool."""
    pool = os.path.join(repo, POOL)
    debs = sorted(f for f in os.listdir(pool) if f.endswith(".deb"))
    if not debs:
        sys.exit(f"apt-index: no .deb files in {pool}")

    entries = []
    for name in debs:
        path = os.path.join(pool, name)
        stanza = control_stanza(path).rstrip("\n")
        pkg, ver = field(stanza, "Package"), field(stanza, "Version")
        arch = field(stanza, "Architecture")
        if not (pkg and ver and arch):
            sys.exit(f"apt-index: {name} is missing Package/Version/Architecture")
        with open(path, "rb") as fh:
            data = fh.read()
        md5, sha1, sha256 = hashes(data)
        entries.append({
            "pkg": pkg, "ver": ver, "arch": arch, "file": name,
            "text": "\n".join([
                stanza,
                f"Filename: {POOL}/{name}",
                f"Size: {len(data)}",
                f"MD5sum: {md5}",
                f"SHA1: {sha1}",
                f"SHA256: {sha256}",
            ]),
        })

    if keep:
        entries = prune(pool, entries, keep)

    entries.sort(key=lambda e: (e["pkg"], e["arch"], version_key(e["ver"])))
    for e in entries:
        print(f"  {e['pkg']} {e['ver']} {e['arch']}")
    return "\n\n".join(e["text"] for e in entries) + "\n", entries


def prune(pool, entries, keep):
    """Keep the newest `keep` versions of each (package, architecture)."""
    groups = {}
    for e in entries:
        groups.setdefault((e["pkg"], e["arch"]), []).append(e)
    kept = []
    for key, group in groups.items():
        group.sort(key=lambda e: version_key(e["ver"]), reverse=True)
        kept.extend(group[:keep])
        for dead in group[keep:]:
            # Say it out loud. A prune that stays quiet reads, in a
            # release log, exactly like a repository that covered
            # everything.
            print(f"  pruned {dead['pkg']} {dead['ver']} {dead['arch']}")
            os.remove(os.path.join(pool, dead["file"]))
    return kept


def build_release(repo, files, origin, label, suite, codename, arches,
                  description, valid_days, now):
    """Return the Release file text for a flat repository.

    No Valid-Until unless --valid-days is given, and that is deliberate:
    an expired Release makes `apt update` fail hard for every user of the
    repository the moment releases pause, which is a self-inflicted
    outage far more likely than the freeze attack the field defends
    against. See packaging/linux/README-apt.md.
    """
    head = [
        f"Origin: {origin}",
        f"Label: {label}",
        f"Suite: {suite}",
        f"Codename: {codename}",
        f"Date: {email.utils.formatdate(now, usegmt=True)}",
        f"Architectures: {' '.join(arches)}",
        f"Description: {description}",
        "Acquire-By-Hash: no",
    ]
    if valid_days:
        head.insert(5, "Valid-Until: "
                    + email.utils.formatdate(now + valid_days * 86400, usegmt=True))

    body = []
    for algo, idx in (("MD5Sum", 0), ("SHA1", 1), ("SHA256", 2)):
        body.append(f"{algo}:")
        for name in files:
            with open(os.path.join(repo, name), "rb") as fh:
                data = fh.read()
            body.append(f" {hashes(data)[idx]} {len(data)} {name}")
    return "\n".join(head + body) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True, help="repository root (holds pool/)")
    ap.add_argument("--keep", type=int, default=0,
                    help="keep only the newest N versions per package+arch")
    ap.add_argument("--origin", default="nzbfast")
    ap.add_argument("--label", default="nzbfast")
    ap.add_argument("--suite", default="stable")
    ap.add_argument("--codename", default="stable")
    ap.add_argument("--description", default="nzbfast APT repository")
    ap.add_argument("--valid-days", type=int, default=0)
    # SOURCE_DATE_EPOCH keeps a rebuild of an unchanged repository
    # byte-identical, which is what lets the publish step tell "nothing
    # changed" from "the index changed" before it pushes to gh-pages.
    ap.add_argument("--now", type=int,
                    default=int(os.environ.get("SOURCE_DATE_EPOCH", 0)) or None)
    args = ap.parse_args()

    repo = os.path.abspath(args.repo)
    if not os.path.isdir(os.path.join(repo, POOL)):
        sys.exit(f"apt-index: {repo}/{POOL} does not exist")

    print("indexing:")
    packages, entries = build_packages(repo, args.keep)
    with open(os.path.join(repo, "Packages"), "w", encoding="utf-8") as fh:
        fh.write(packages)
    # mtime=0: gzip stamps the time into its header, and a Packages.gz
    # whose bytes change every run would defeat the no-op check above.
    with open(os.path.join(repo, "Packages.gz"), "wb") as fh:
        with gzip.GzipFile(fileobj=fh, mode="wb", mtime=0) as gz:
            gz.write(packages.encode("utf-8"))

    arches = sorted({e["arch"] for e in entries})
    now = args.now if args.now is not None else int(__import__("time").time())
    release = build_release(repo, ["Packages", "Packages.gz"],
                            args.origin, args.label, args.suite, args.codename,
                            arches, args.description, args.valid_days, now)
    with open(os.path.join(repo, "Release"), "w", encoding="utf-8") as fh:
        fh.write(release)
    print(f"wrote Packages ({len(entries)} entries), Packages.gz, Release")


if __name__ == "__main__":
    main()

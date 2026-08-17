#!/usr/bin/env python3
"""Refuse any release archive that names the account that built it.

    packaging/check-archive-identity.py <asset>...

tar writes the BUILDING ACCOUNT's uid, gid, user name and group name
into every member header unless the builder passes flags telling it not
to, and this project is anonymous in public. The leak sits in a field no
unpacker displays, `tar tzvf` on the release Mac makes no fuss about it,
and packaging/scan-release-assets.sh only catches it when the literal
name happens to be in private-patterns.txt - so a CI runner's `runner` /
`docker`, or a FreeBSD VM's `root`, sails straight through the pattern
scanner. Cutting 1.1.3 the FreeBSD tarball did exactly that and only
upload-release-assets.sh's owner gate stopped it.

That gate is at the LAST mile, on the release Mac, on assets a human
uploads by hand. Everything release.yml builds and attaches by itself
never passes it. This is the same rule, runnable in the job that
produces the bytes, over every archive format the workflow ships.

The second check is macOS resource-fork junk (`._name` AppleDouble
members, `__MACOSX/` in zips). bsdtar stores an AppleDouble member for
any file carrying an xattr and macOS 15+ stamps com.apple.provenance on
everything it builds, so a plain `tar czf` on a Mac runner yields a
second TOP-LEVEL entry - which breaks every unpacker that collapses a
lone wrapper directory. v1.1.2 shipped both Linux tarballs that way.

DO NOT "verify" any of this with `tar tzvf` on a Mac. bsdtar CONSUMES
AppleDouble members on read, so a broken tarball lists clean. That is
precisely how v1.1.2 shipped five of them in each Linux tarball. This
reads the stored headers, which is the only view that sees them.

Formats, and the owner policy each is held to:

  .tar.gz .tgz .tar .spk   STRICT - uid/gid 0 AND EMPTY name strings,
                           byte-for-byte what upload-release-assets.sh
                           demands. A CI job that passed something
                           looser would hand the release Mac an asset
                           the upload gate then refuses.
  .zip                     junk only. The format has no uid/gid/uname/
                           gname fields, so there is nothing to leak.
  .deb .rpm .qpkg          ROOT-OK - uid/gid 0, and the name strings may
                           be empty or "root"/"wheel". These are package
                           formats: root:root IS the correct installed
                           ownership and carries no identity. Any OTHER
                           name is a builder leak exactly as above.

An archive that cannot be opened FAILS. It has not been shown to be
clean, so it does not get to pass by failing to match - the same posture
upload-release-assets.sh's linkage and junk gates take.
"""

import io
import os
import struct
import sys
import tarfile
import zipfile

STRICT, ROOT_OK = "strict", "root-ok"
# uid/gid are always 0. Only the NAME strings differ by policy.
OK_NAMES = {STRICT: {""}, ROOT_OK: {"", "root", "wheel"}}


class Unreadable(Exception):
    """The archive could not be opened, or holds something unrecognised."""


def junk(name):
    """A macOS resource-fork member, at any depth."""
    base = os.path.basename(name.rstrip("/"))
    return (base.startswith("._")
            or name.startswith("__MACOSX/") or "/__MACOSX/" in name)


def check_tar(fh, policy, label, bad, recurse=True):
    """Owner + junk over one tar stream, one level into nested tars.

    A .spk is a tar of a tar and a .deb's payload is a tar inside an ar,
    so the junk and the identity can both be a layer down.
    """
    with tarfile.open(fileobj=fh) as t:
        for m in t.getmembers():
            where = f"{label}{m.name}"
            if junk(m.name):
                bad.append(f"{where}: macOS resource-fork member")
            if m.uid or m.gid or m.uname not in OK_NAMES[policy] \
                    or m.gname not in OK_NAMES[policy]:
                bad.append(f"{where}: uid={m.uid} gid={m.gid} "
                           f"uname={m.uname!r} gname={m.gname!r}")
            if not recurse or not m.isfile():
                continue
            if not m.name.endswith((".tar.gz", ".tgz", ".tar")):
                continue
            inner = t.extractfile(m)
            if inner is not None:
                check_tar(io.BytesIO(inner.read()), policy,
                          f"{where}!", bad, recurse=False)


def check_zip(path, bad):
    with zipfile.ZipFile(path) as z:
        for n in z.namelist():
            if junk(n):
                bad.append(f"{n}: macOS resource-fork member")


def check_deb(path, bad):
    """A .deb is an `ar` archive; the tars inside it carry the owners.

    Parsed here rather than shelled out to dpkg-deb so the check runs on
    the release Mac too, where there is no dpkg.
    """
    seen = 0
    with open(path, "rb") as fh:
        if fh.read(8) != b"!<arch>\n":
            raise Unreadable("not an ar archive")
        while True:
            hdr = fh.read(60)
            if len(hdr) < 60:
                break
            name = hdr[:16].decode("ascii", "replace").strip().rstrip("/")
            size = int(hdr[48:58].decode("ascii", "replace").strip() or 0)
            body = fh.read(size)
            if size % 2:
                fh.read(1)          # ar members are 2-byte aligned
            if not name.startswith(("data.tar", "control.tar")):
                continue
            if not name.endswith((".gz", ".xz", ".bz2", ".tar")):
                # zstd, which python's tarfile cannot open. Refusing is
                # the point: unopened is not clean.
                raise Unreadable(f"{name}: unsupported compression")
            seen += 1
            check_tar(io.BytesIO(body), ROOT_OK, f"{name}!", bad,
                      recurse=False)
    if not seen:
        raise Unreadable("no data.tar/control.tar member")


def _rpm_header(fh):
    """One rpm header section -> {tag: value}, for the tags we need.

    Layout per rpm(5): magic 8e ad e8 01, 4 reserved, nindex, hsize;
    then nindex 16-byte index entries (tag, type, offset, count) and a
    hsize-byte data store. Type 8 is STRING_ARRAY, 6 is STRING.
    """
    magic = fh.read(8)
    if magic[:4] != b"\x8e\xad\xe8\x01":
        raise Unreadable("bad rpm header magic")
    nindex, hsize = struct.unpack(">II", fh.read(8))
    index = fh.read(16 * nindex)
    store = fh.read(hsize)
    if len(store) < hsize:
        raise Unreadable("truncated rpm header")
    out = {}
    for i in range(nindex):
        tag, typ, off, count = struct.unpack(">IIII", index[i * 16:i * 16 + 16])
        if typ not in (6, 8) or tag not in (1039, 1040, 1117):
            continue
        vals, p = [], off
        for _ in range(count if typ == 8 else 1):
            end = store.index(b"\x00", p)
            vals.append(store[p:end].decode("utf-8", "replace"))
            p = end + 1
        out[tag] = vals
    return out, hsize


def check_rpm(path, bad):
    """FILEUSERNAME/FILEGROUPNAME out of the rpm header.

    rpm stores owner NAMES, not numeric ids, and it takes them from the
    files in the buildroot - so an rpmbuild run by an unprivileged CI
    account records that account against every path unless the spec says
    otherwise. Nothing extracts a .rpm to find that out; the header is
    where it lives.
    """
    with open(path, "rb") as fh:
        if fh.read(4) != b"\xed\xab\xee\xdb":
            raise Unreadable("not an rpm")
        fh.seek(96)                                   # past the 96-byte lead
        _, hsize = _rpm_header(fh)                    # signature header
        pad = (8 - (fh.tell() % 8)) % 8               # ...is 8-byte aligned
        fh.seek(pad, io.SEEK_CUR)
        tags, _ = _rpm_header(fh)                     # the real header
    names = tags.get(1117, [])
    users, groups = tags.get(1039, []), tags.get(1040, [])
    if not users and not groups:
        raise Unreadable("no FILEUSERNAME/FILEGROUPNAME tags in the header")
    ok = OK_NAMES[ROOT_OK]
    for i, (u, g) in enumerate(zip(users, groups)):
        if u in ok and g in ok:
            continue
        who = names[i] if i < len(names) else f"file #{i}"
        bad.append(f"{who}: user={u!r} group={g!r}")
    for n in names:
        if junk(n):
            bad.append(f"{n}: macOS resource-fork member")


def check_qpkg(path, bad):
    """A .qpkg is [installer sh][control tar][data tar.gz][100-byte trailer].

    The same three-part split packaging/qnap/unpack-qpkg.sh documents,
    done here without extracting: extraction as a non-root user drops
    the very uid/gid this is trying to read.
    """
    import re
    blob = open(path, "rb").read()
    # NULs stripped before the regexes see them: the control tar starts a
    # few kilobytes in, and matching over binary is how this reads a
    # length as empty and fails obscurely. re.M, because every one of
    # these is a whole LINE of the generated installer.
    head = blob[:65536].replace(b"\x00", b"").decode("utf-8", "replace")

    def num(pat):
        m = re.search(pat, head, re.M)
        return int(m.group(1)) if m else None

    script_len = num(r"^\s*script_len=(\d+)\s*$")
    ctrl_len = num(r"^\s*offset=\$\(/usr/bin/expr \$script_len \+ (\d+)\)\s*$")
    data_kib = num(r"bs=1024 count=(\d+)")
    if script_len is None or ctrl_len is None:
        raise Unreadable("no script_len/offset header - not a QDK package?")
    check_tar(io.BytesIO(blob[script_len:script_len + ctrl_len]), ROOT_OK,
              "control.tar!", bad)
    # qbuild appends a 100-byte QNAPQPKG trailer, so the data archive
    # ends before EOF. The `dd bs=1024 count=N` the installer uses is the
    # same length rounded up to a kibibyte: when the two disagree the
    # package carries something extra (QDK can insert a signing area), so
    # fall back to the rounded count rather than call it unreadable.
    ends = [len(blob) - 100]
    if data_kib is not None:
        ends.append(script_len + ctrl_len + data_kib * 1024)
    for i, end in enumerate(ends):
        data = blob[script_len + ctrl_len:end]
        if len(data) <= 0:
            raise Unreadable(f"computed a data archive of {len(data)} bytes")
        try:
            check_tar(io.BytesIO(data), ROOT_OK, "data.tar.gz!", bad,
                      recurse=False)
            return
        except Exception:
            if i == len(ends) - 1:
                raise


def check(path):
    bad = []
    base = os.path.basename(path)
    if base.endswith((".tar.gz", ".tgz", ".tar", ".spk")):
        with open(path, "rb") as fh:
            check_tar(fh, STRICT, "", bad)
    elif base.endswith(".zip"):
        check_zip(path, bad)
    elif base.endswith(".deb"):
        check_deb(path, bad)
    elif base.endswith(".rpm"):
        check_rpm(path, bad)
    elif base.endswith(".qpkg"):
        check_qpkg(path, bad)
    else:
        return None                      # .exe, .sha256, notes: nothing to read
    return bad


def main(argv):
    if len(argv) < 2:
        print(__doc__.strip().split("\n\n")[1], file=sys.stderr)
        return 2
    fail = checked = 0
    for path in argv[1:]:
        base = os.path.basename(path)
        try:
            bad = check(path)
        except Exception as e:            # noqa: BLE001 - unopened is not clean
            print(f"✗ {base}: CANNOT INSPECT - {e}", file=sys.stderr)
            fail = 1
            continue
        if bad is None:
            print(f"  - {base}: not an archive format this checks")
            continue
        checked += 1
        if not bad:
            print(f"  ok {base}")
            continue
        print(f"✗ {base}: builder identity or macOS metadata in the archive:",
              file=sys.stderr)
        for line in bad[:8]:
            print(f"      {line}", file=sys.stderr)
        if len(bad) > 8:
            print(f"      ... and {len(bad) - 8} more", file=sys.stderr)
        fail = 1
    if fail:
        print("", file=sys.stderr)
        print("REFUSING: rebuild with the owner flags for the tar that built", file=sys.stderr)
        print("this - bsdtar takes `--uid 0 --gid 0 --uname \"\" --gname \"\"`,", file=sys.stderr)
        print("GNU tar takes `--owner=0 --group=0 --numeric-owner`, and macOS", file=sys.stderr)
        print("needs COPYFILE_DISABLE=1 in front of it as well. See", file=sys.stderr)
        print("packaging/build-linux-tarballs.sh, which gets this right.", file=sys.stderr)
        return 1
    # Wording matters: callers grep this script's output. Saying "no
    # builder identity" here would be a SUCCESS line containing the exact
    # substring packaging/tests/linux-tarballs.sh matches to detect a
    # REFUSAL, so a clean asset would read as a refused one.
    print(f"== {checked} archive(s) clean - no owner headers, no macOS metadata ==")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

# nzbfast on FreeBSD - BETA, and looking for a tester

**Nobody has run this on a real FreeBSD machine.** It is built and
tested inside a FreeBSD virtual machine on every release, but a qemu
guest is not a NAS: no real hardware, no ZFS pool, no jail, no NIC under
load. If you run FreeBSD and try this, an issue saying what happened -
working or not - is the most useful thing you can send us.

What is here:

| File | What it is |
| --- | --- |
| `nzbfast` | the daemon and CLI, one binary; it needs only base-system libraries (`libc`, `libthr`, `libm`, `libgcc_s`) and nothing from ports |
| `rc.d/nzbfast` | the service script, FreeBSD idiom, `sysrc nzbfast_enable=YES` |
| `config.example.json` | provider credentials template |

x86-64 only. See "aarch64" at the bottom for why there is no ARM build.

## Install

```sh
install -m 755 nzbfast /usr/local/bin/nzbfast
pw groupadd nzbfast
pw useradd nzbfast -g nzbfast -d /var/db/nzbfast -s /usr/sbin/nologin \
   -c "nzbfast daemon"
mkdir -p /usr/local/etc/nzbfast /var/db/nzbfast/downloads /var/db/nzbfast/watch
install -m 600 -o nzbfast -g nzbfast config.example.json \
        /usr/local/etc/nzbfast/config.json      # then edit in your provider
chown -R nzbfast:nzbfast /usr/local/etc/nzbfast /var/db/nzbfast
chmod 750 /usr/local/etc/nzbfast
install -m 755 rc.d/nzbfast /usr/local/etc/rc.d/nzbfast
sysrc nzbfast_enable=YES
service nzbfast start
```

The dashboard is then on <http://127.0.0.1:6789>. It binds loopback by
default - open it to the LAN with `sysrc nzbfast_bind=0.0.0.0` once you
have set an API key, not before. Every other knob (paths, port, user,
log file, extra flags) is a `sysrc` variable, listed in the header of
`rc.d/nzbfast`.

On ZFS, the one path worth moving is the download directory: give it its
own dataset and point `nzbfast_out` at it.

```sh
zfs create tank/media
chown nzbfast:nzbfast /tank/media
sysrc nzbfast_out=/tank/media
service nzbfast restart
```

## What we know works, and what we do not

This is the honest version, because the difference matters when you are
the first person to run something.

**Tested, on every release, inside a FreeBSD VM:** the binary is built
by a FreeBSD-hosted rustc and clang, and then that same binary downloads
a synthetic release over loopback NNTP before the tarball is made -
`packaging/freebsd/smoke.sh`, which drives pipelined NNTP, in-place yEnc
decode, incremental PAR2 verify, preallocation and positioned writes,
and asserts on the bytes that come out. If that fails, no tarball ships.

**A clean cross-build was NOT accepted as evidence.** The platform audit
behind this port was done with a cross-compiler and a FreeBSD sysroot
(recipe below), and it is genuinely useful for finding compile-time
breakage - it is what caught `rlim_t` being signed on the BSDs, which no
amount of reading would have. But a binary that links is not a binary
that runs: a missing syscall, a refused rlimit, a struct field the
kernel fills differently, an interpreter path that resolves against a
sysroot rather than against the box - none of that shows up until
something executes. That is why the release build happens in a VM and
not in a cross-compiler.

**Not tested at all, by anyone:**

- Real hardware. Disk behaviour under load is the whole point of this
  program and a virtual disk tells you nothing about it.
- ZFS. Notably: nzbfast preallocates output files with `ftruncate` and
  does *not* call `posix_fallocate` here (that call is a Linux-only path
  in `disk.rs`, and ZFS would refuse it anyway), so output files start
  sparse. That should be right on both UFS and ZFS. Nobody has watched
  it happen.
- Jails, including whether the fd-limit raise behaves the same inside
  one.
- The NAS distributions. See below.
- Anything on FreeBSD 15.x. The build targets 14.3 and FreeBSD binaries
  run forward, so it should be fine, and "should" is the operative word.

**Known to be missing or degraded on FreeBSD**, all of them deliberate,
none of them fatal:

- No write pacing and no drop-behind cache management. Both are
  measured, platform-specific write-path tuning (macOS and Linux
  respectively); FreeBSD gets the plain path, which is what Linux ships
  with by default anyway.
- `mimalloc` is not the allocator here, so the post-download idle memory
  trim does nothing. Memory is returned by the system allocator on its
  own schedule instead.
- The `NZBFAST_MOVE_IOPOL` background-I/O knob is a no-op: FreeBSD has
  no ioprio equivalent to demote a mover thread with, so a big move can
  compete with a live download for the disk.
- The dashboard's live memory reading falls back to peak RSS rather than
  current RSS: FreeBSD's procfs is not mounted by default, so there is
  no `/proc/self/statm` to read. It only affects the number on the
  chart.
- Delete-to-Trash defaults **off**, as it does on Linux and for the same
  reason: on a headless box the `trash` crate's freedesktop backend just
  moves files into a `.Trash-<uid>` directory on the download volume
  that nothing ever empties. Deletes are permanent unless you turn
  `delete_to_trash` on.
- `Play` and `Show in folder` in the dashboard shell out to `xdg-open`,
  which is in ports (`x11/xdg-utils`) and absent on a server. They fail
  quietly.

## TrueNAS CORE, and who this is actually for

The motivation for a FreeBSD build was TrueNAS CORE, and it does not
reach it: CORE 13.3 is FreeBSD 13, FreeBSD 13 is end of life, and its
releases are off the mirrors - so there is no supported base to build
against, and a 14.3 binary will not run on 13 (FreeBSD ABI compatibility
runs forward, not back). TrueNAS SCALE is Linux and already covered by
the `linux-x64` tarball and the Docker image.

That leaves the people this build is genuinely for: FreeBSD servers and
home NAS boxes, XigmaNAS, and anyone running a jail on a FreeBSD host.
If TrueNAS CORE support ever matters again it needs a 13.x build base,
which means a mirror that still carries 13.5 - reopen that question then
rather than assuming this tarball covers it.

## Building it yourself

On FreeBSD, natively, with nothing from ports (base has clang; rustup
honours the `rust-toolchain.toml` pin):

```sh
fetch -o rustup-init \
  https://static.rust-lang.org/rustup/dist/x86_64-unknown-freebsd/rustup-init
chmod +x rustup-init && ./rustup-init -y --profile minimal \
  --default-toolchain none --no-modify-path
. "$HOME/.cargo/env"
cargo build --release --locked -p nzbfast
packaging/freebsd/smoke.sh target/release/nzbfast
```

Cross-compiling from macOS or Linux, for a fast compile-error loop
only - read the section above before trusting anything it produces:

```sh
# 1. a sysroot from the FreeBSD base system
fetch https://download.freebsd.org/releases/amd64/14.3-RELEASE/base.txz
mkdir sysroot && tar -xf base.txz -C sysroot ./usr/include ./usr/lib ./lib

# 2. a clang that can target FreeBSD (Apple's cannot; brew install llvm),
#    plus any lld - rust ships one with the toolchain
cat > fbsd-cc <<'EOF'
#!/bin/sh
exec /opt/homebrew/opt/llvm/bin/clang --target=x86_64-unknown-freebsd14.3 \
  --sysroot=$PWD/sysroot \
  --ld-path=$HOME/.rustup/toolchains/*/lib/rustlib/*/bin/gcc-ld/ld.lld "$@"
EOF
sed 's/clang /clang++ /' fbsd-cc > fbsd-cxx     # same, for rapidyenc
chmod +x fbsd-cc fbsd-cxx

# 3. build
rustup target add x86_64-unknown-freebsd
export CC_x86_64_unknown_freebsd=$PWD/fbsd-cc
export CXX_x86_64_unknown_freebsd=$PWD/fbsd-cxx
export AR_x86_64_unknown_freebsd=$(brew --prefix llvm)/bin/llvm-ar
export CARGO_TARGET_X86_64_UNKNOWN_FREEBSD_LINKER=$PWD/fbsd-cc
cargo build --release --locked -p nzbfast --target x86_64-unknown-freebsd
```

`AR_*` matters: without it the host `ar`/`ranlib` indexes rapidyenc's
FreeBSD objects and warns about every one of them.

## aarch64

There is no ARM64 FreeBSD build and it is not an oversight.
`aarch64-unknown-freebsd` is a Rust tier-3 target: upstream publishes no
`rust-std` for it, so `rustup target add` fails on the pinned stable
toolchain and building it needs a nightly `-Z build-std`. The
`rust-toolchain.toml` pin is stable by policy, and an unpinned nightly
compiler building shipped bytes is a worse trade than no ARM build.
Revisit if the target is ever promoted.

## Updates

This build is outside the signed update manifest: the in-app update
check will not offer it a new version, so watch the releases page.

That absence is deliberate and it is the gate, not an omission -
`packaging/make-latest-json.sh` says why in full. The short version:
every manifest entry is signed inside a body carrying a monotonic
anti-rollback serial that clients ratchet one way, so a payload that
turns out to be broken cannot be withdrawn by publishing a corrected
manifest. A release asset can be deleted with one command. Until
somebody confirms this runs on real FreeBSD, it stays an asset.

## Checklist for the first tester

If you are that person, these are the answers worth having, roughly in
order of how much they would change:

1. Does `service nzbfast start` bring it up, and does the dashboard load?
2. Does a real download complete - fetch, verify, repair if needed,
   unpack?
3. On ZFS: are the finished files the size they claim, and does `du`
   agree with `ls -l` once a job is done?
4. Does `service nzbfast stop` shut it down cleanly, and does the queue
   survive a restart?
5. In a jail: anything different?
6. Anything in `/var/log/nzbfast.log` that looks like a platform
   complaint rather than a Usenet one?

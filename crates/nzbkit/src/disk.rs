//! Preallocated offset writer (PLAN M1 / 1d).
//!
//! One output file per NZB file, preallocated to its yEnc-declared size
//! (real extents on Linux, sparse elsewhere - see `preallocate`); every
//! decoded article `pwrite`s at its final offset. No temp
//! files, no assembly pass: a direct-write design with no reassembly
//! step. `write_at` takes `&self` - decoded articles from
//! multiple consumer tasks write concurrently.

use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Raise the open-file soft limit toward the hard limit, returning the
/// effective value.
///
/// The engine holds one writer per output file for the life of a job. That
/// is a handful when direct extraction keeps volumes in RAM, but a low
/// memory budget spills them to disk instead - one writer per RAR volume,
/// 431 of them on the 190 GB set. macOS ships a 256 soft limit against a
/// 245k kernel cap, so exactly the low-memory devices that force the spill
/// path also ran out of descriptors and failed every write with EMFILE.
///
/// macOS rejects RLIM_INFINITY here, so step down through candidate targets
/// rather than asking for the hard limit directly.
///
/// Returns the soft limit now in force, or 0 where there is no such limit to
/// raise - which is every non-unix target. On Windows a `File` is a Win32
/// HANDLE bounded by kernel memory rather than by a per-process soft cap, so
/// 0 means "unlimited as far as this matters", NOT "no descriptors": callers
/// must not size the spill path off this number.
pub fn raise_fd_limit() -> u64 {
    #[cfg(unix)]
    unsafe {
        let mut lim: libc::rlimit = std::mem::zeroed();
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) != 0 {
            return 0;
        }
        let start = lim.rlim_cur;
        let hard = lim.rlim_max;
        let cap = |v: u64| if hard == libc::RLIM_INFINITY { v } else { v.min(hard) };
        for target in [65536u64, 16384, 4096, 1024] {
            let want = cap(target);
            if want <= lim.rlim_cur {
                continue;
            }
            let mut next = lim;
            next.rlim_cur = want;
            if libc::setrlimit(libc::RLIMIT_NOFILE, &next) == 0 {
                return want;
            }
        }
        return start;
    }
    #[cfg(not(unix))]
    0
}

/// Positioned read: unix pread never touches the file cursor; Windows
/// `seek_read` does move it, so every access to engine-written files must
/// go through these helpers (nothing reads via the cursor today).
pub fn read_exact_at(f: &File, buf: &mut [u8], off: u64) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        f.read_exact_at(buf, off)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::FileExt;
        let (mut buf, mut off) = (buf, off);
        while !buf.is_empty() {
            match f.seek_read(buf, off) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "failed to fill whole buffer",
                    ));
                }
                Ok(n) => {
                    let rest = buf;
                    buf = &mut rest[n..];
                    off += n as u64;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

/// Process-wide bytes written through the positioned-write path - the
/// dashboard's disk-write rate. Counted here rather than from OS
/// counters: buffered writeback is charged to the kernel, not to us
/// (macOS ri_diskio_byteswritten stays near zero during a download).
static BYTES_WRITTEN: AtomicU64 = AtomicU64::new(0);

pub fn bytes_written() -> u64 {
    BYTES_WRITTEN.load(Ordering::Relaxed)
}

/// Positioned write, same cross-platform contract as [`read_exact_at`].
pub fn write_all_at(f: &File, buf: &[u8], off: u64) -> io::Result<()> {
    BYTES_WRITTEN.fetch_add(buf.len() as u64, Ordering::Relaxed);
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        f.write_all_at(buf, off)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::FileExt;
        let (mut buf, mut off) = (buf, off);
        while !buf.is_empty() {
            match f.seek_write(buf, off) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "failed to write whole buffer",
                    ));
                }
                Ok(n) => {
                    buf = &buf[n..];
                    off += n as u64;
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }
}

/// Process default for [`FileWriter`] cache dropping (see
/// `maybe_drop_cache`). Set BEFORE the first write of the run - the
/// per-process decision is latched on first use.
static DROP_CACHE_DEFAULT: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

pub fn set_drop_cache_default(on: bool) {
    DROP_CACHE_DEFAULT.store(on, Ordering::Relaxed);
}

/// What the output directory is sitting on.
///
/// `Unknown` is a first-class answer and must never be treated as
/// `Rotational`: device mapper, RAID, network mounts (SMB/NFS on a NAS),
/// overlayfs in a container and every non-Linux host all land here, and
/// guessing "spinning" for them would clamp hardware that has no seek
/// problem.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Storage {
    Rotational,
    Solid,
    Unknown,
}

/// What is under `path`, with `NZBFAST_STORAGE=rotational|ssd|auto` as the
/// operator override (`auto`, or anything unset, probes).
///
/// The probe matters because decoded articles `pwrite` at their final
/// offsets: with several decode workers the network's article lanes become
/// the output file's seek lanes, which a spinning disk pays for and an SSD
/// does not.
pub fn detect_storage(path: &Path) -> Storage {
    if let Some(forced) = storage_override(std::env::var("NZBFAST_STORAGE").ok().as_deref()) {
        return forced;
    }
    match rotational(path) {
        Some(true) => Storage::Rotational,
        Some(false) => Storage::Solid,
        None => Storage::Unknown,
    }
}

/// The `NZBFAST_STORAGE` override, parsed. Split out so the mapping is
/// testable without mutating the environment: tests share one process, so
/// a `set_var` here would race every other test that probes storage.
fn storage_override(raw: Option<&str>) -> Option<Storage> {
    match raw {
        Some("rotational") | Some("hdd") => Some(Storage::Rotational),
        Some("ssd") | Some("solid") => Some(Storage::Solid),
        _ => None,
    }
}

/// Read the backing block device's `queue/rotational` flag.
///
/// The device id of the file's filesystem indexes `/sys/dev/block`, which
/// for a partition resolves to the partition's directory - `queue/` lives
/// on the parent disk, hence the walk up one level.
#[cfg(target_os = "linux")]
fn rotational(path: &Path) -> Option<bool> {
    use std::os::unix::fs::MetadataExt;
    // Probe the directory itself, not a file inside it: the caller may not
    // have created anything yet.
    let dev = std::fs::metadata(path).ok()?.dev();
    let (major, minor) = unsafe { (libc::major(dev), libc::minor(dev)) };
    let sys = std::fs::canonicalize(format!("/sys/dev/block/{major}:{minor}")).ok()?;
    let read = |dir: &Path| -> Option<bool> {
        let raw = std::fs::read_to_string(dir.join("queue/rotational")).ok()?;
        match raw.trim() {
            "1" => Some(true),
            "0" => Some(false),
            _ => None,
        }
    };
    read(&sys).or_else(|| read(sys.parent()?))
}

#[cfg(not(target_os = "linux"))]
fn rotational(_path: &Path) -> Option<bool> {
    None
}

/// Core count at or below which a box is treated as NAS-class for the
/// rotational clamp.
const NAS_CORES: usize = 4;

/// How many decode workers to run, given what the output sits on.
///
/// Decoded articles `pwrite` at their final offsets, so N decode workers
/// scatter N interleaved write streams across the output file: the
/// network's article lanes become the platter's seek lanes. One worker
/// keeps them in order.
///
/// Gated on BOTH signals, because the clamp is only free on one side of
/// them. On a NAS-class box it costs nothing - measured flat from 1 to 4
/// decoders on Gracemont E-cores (the N100-class proxy), since this path
/// does not scale with decode workers there. On a big box it is NOT free
/// (1075 -> 3226 MB/s going 1 to 4 decoders on an M3 Ultra), and a
/// rotational device there is usually a wide array that can absorb the
/// parallel writes. `Unknown` never clamps.
pub fn decoders_for_storage(storage: Storage, cores: usize, decoders: usize) -> usize {
    if decoders > 1 && cores <= NAS_CORES && storage == Storage::Rotational {
        1
    } else {
        decoders
    }
}

/// A job-wide cap on the DISTINCT extracted bytes an extraction chain may
/// write, shared by every [`FileWriter`] that carries it.
///
/// The disk/post-pass extraction sinks have had a decompression-bomb
/// budget since M3 (`BombGuardWriter`), but the in-stream one-pass
/// extractor - the default path for every download - wrote through
/// `FileWriter` with no budget at all, so the guard covered the fallback
/// and not the common case. Attaching the budget here puts the accounting
/// on the one write chokepoint the in-stream path shares.
///
/// Charged with the NEWLY-COVERED byte count from [`FileWriter::note_written`],
/// never the raw write length: a repair span rewrites a range that already
/// paid for itself, and charging it twice would trip the guard on a job
/// that is merely healing.
#[derive(Debug)]
pub struct WriteBudget {
    limit: AtomicU64,
    written: AtomicU64,
}

impl WriteBudget {
    pub fn new(limit: u64) -> WriteBudget {
        WriteBudget {
            limit: AtomicU64::new(limit),
            written: AtomicU64::new(0),
        }
    }

    /// No cap - the default everywhere a budget has not been wired.
    pub fn unlimited() -> WriteBudget {
        WriteBudget::new(u64::MAX)
    }

    pub fn set_limit(&self, limit: u64) {
        self.limit.store(limit, Ordering::Relaxed);
    }

    pub fn limit(&self) -> u64 {
        self.limit.load(Ordering::Relaxed)
    }

    pub fn used(&self) -> u64 {
        self.written.load(Ordering::Relaxed)
    }

    /// Charge `n` newly-covered bytes; Err once the running total crosses
    /// the limit. Saturating so a pathological total can't wrap back under
    /// the cap.
    fn charge(&self, n: u64) -> io::Result<()> {
        if n == 0 {
            return Ok(());
        }
        let limit = self.limit.load(Ordering::Relaxed);
        if limit == u64::MAX {
            return Ok(());
        }
        let total = self
            .written
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |w| {
                Some(w.saturating_add(n))
            })
            .unwrap_or(0)
            .saturating_add(n);
        if total > limit {
            return Err(io::Error::other(
                "extraction exceeded available disk space (possible decompression bomb)",
            ));
        }
        Ok(())
    }
}

pub struct FileWriter {
    /// `None` while PARKED - the handle is closed but the writer (and every
    /// `Arc` clone of it) stays alive and reopens on [`FileWriter::unpark`].
    /// See [`FileWriter::park`] for why the handle has to be droppable at
    /// all; ordinary writers are `Some` for their whole life.
    ///
    /// `RwLock` rather than a bare `File` costs one uncontended read
    /// acquisition per `write_at`, which handles a whole article/span - tens
    /// of nanoseconds against a pwrite of tens to hundreds of KB.
    file: std::sync::RwLock<Option<File>>,
    pub path: PathBuf,
    pub size: u64,
    written: AtomicU64,
    /// Job-wide extracted-byte budget (see [`WriteBudget`]); None = the
    /// writer is not an extraction output and is not charged.
    budget: Option<std::sync::Arc<WriteBudget>>,
    /// Written spans, sorted + merged - lets the streaming server ask
    /// "are bytes [off, off+len) really on disk yet?". Out-of-order
    /// arrival keeps this list tiny (≈ number of gaps, not writes).
    intervals: std::sync::Mutex<Vec<(u64, u64)>>,
    /// Next `written` watermark at which maybe_drop_cache fires.
    drop_next: AtomicU64,
}

/// Reserve `size` bytes for `file`, really allocating blocks where the
/// platform lets us.
///
/// `set_len` alone punches a hole - a sparse file whose blocks are
/// allocated lazily at write time. On a near-full or rotational ext4/XFS
/// volume that lazy allocation interleaves blocks from the many files a
/// job writes concurrently, fragmenting all of them. Linux therefore also
/// calls the raw `fallocate(2)` syscall to reserve contiguous extents up
/// front. Raw fallocate, NOT `posix_fallocate`: glibc emulates the latter
/// on EOPNOTSUPP filesystems (FUSE/mergerfs, exFAT, NFS < 4.2) by writing
/// one byte per block over the whole range - a synchronous full-file
/// write pass for a multi-GB output, and it destroys sparseness. Raw
/// fallocate returns EOPNOTSUPP honestly and we ignore it - preallocation
/// is an optimisation, never a correctness requirement.
///
/// `set_len` runs first and unconditionally: it is what truncates a stale
/// longer file at the same path down to exactly `size` (fallocate never
/// shrinks), so create_resume keeps identical semantics on every platform
/// and filesystem. macOS keeps plain `set_len` on purpose: APFS is
/// copy-on-write and SSD-only in practice, so extent contiguity buys
/// nothing and F_PREALLOCATE is not worth the fcntl dance. Windows
/// likewise unchanged.
/// `cap` bounds how much is actually RESERVED (u64::MAX = no ceiling).
///
/// The declared `size` of an extracted inner file comes from a RAR header
/// vint the poster controls. `set_len` plus a real Linux `fallocate` means
/// a few-hundred-KB post declaring `unpacked_size` = 8 TB genuinely
/// reserves the victim's free space for the life of the job - the
/// finish-time header/CRC gates demote such a set, but only long after the
/// blocks are gone. `cap` is the defensible bound (the NZB's own posted
/// byte count at level 0), applied to the RESERVATION only.
///
/// `size` itself is deliberately NOT clamped by the caller: `FileWriter.size`
/// feeds `create_resume`'s stale-file truncation and the reported extracted
/// size, and clamping it corrupts both. Capping the reservation is safe
/// because preallocation is an optimisation, never a correctness
/// requirement (see above) - `write_at` past the preallocated length
/// extends the file normally, exactly as it already does on macOS and
/// Windows where nothing is reserved at all.
///
/// The target is `min(size, max(cap, current_len))`, which
///   * caps a fresh (truncated) file at `cap`,
///   * still trims a stale LONGER file down to `size` (that shrinks, so it
///     reserves nothing), and
///   * never shrinks a resumed file below the bytes it already holds.
fn preallocate_capped(file: &File, size: u64, cap: u64) -> io::Result<()> {
    let target = if cap == u64::MAX {
        size
    } else {
        let cur = file.metadata().map(|m| m.len()).unwrap_or(0);
        size.min(cap.max(cur))
    };
    file.set_len(target)?;
    #[cfg(target_os = "linux")]
    if target > 0 {
        use std::os::unix::io::AsRawFd;
        // Best-effort: mode 0 allocates real blocks for [0, target). Any
        // failure (EOPNOTSUPP, EINVAL, ENOSPC racing) leaves the sparse
        // file from set_len above, which is always correct.
        unsafe { libc::fallocate(file.as_raw_fd(), 0, 0, target as libc::off_t) };
    }
    Ok(())
}

impl FileWriter {
    /// Create (truncating any existing file) and preallocate to `size` -
    /// really allocated on Linux, sparse elsewhere (see `preallocate`).
    pub fn create(path: &Path, size: u64) -> io::Result<FileWriter> {
        Self::create_capped(path, size, u64::MAX)
    }

    /// [`FileWriter::create`] with a ceiling on the RESERVATION only (see
    /// [`preallocate_capped`]). `size` is stored unchanged.
    pub fn create_capped(path: &Path, size: u64, prealloc_cap: u64) -> io::Result<FileWriter> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(true)
            .open(path)?;
        preallocate_capped(&file, size, prealloc_cap)?;
        Ok(FileWriter {
            file: std::sync::RwLock::new(Some(file)),
            path: path.to_path_buf(),
            size,
            written: AtomicU64::new(0),
            budget: None,
            intervals: std::sync::Mutex::new(Vec::new()),
            drop_next: AtomicU64::new(16 << 20),
        })
    }

    /// Open WITHOUT truncating (crash-resume: earlier runs' bytes are
    /// already at their final offsets) and ensure the file spans `size`.
    pub fn create_resume(path: &Path, size: u64) -> io::Result<FileWriter> {
        Self::create_resume_capped(path, size, u64::MAX)
    }

    /// [`FileWriter::create_resume`] with a ceiling on the RESERVATION
    /// only. The cap never shrinks a resumed file below the bytes it
    /// already holds - see [`preallocate_capped`].
    pub fn create_resume_capped(
        path: &Path,
        size: u64,
        prealloc_cap: u64,
    ) -> io::Result<FileWriter> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(path)?;
        preallocate_capped(&file, size, prealloc_cap)?;
        Ok(FileWriter {
            file: std::sync::RwLock::new(Some(file)),
            path: path.to_path_buf(),
            size,
            written: AtomicU64::new(0),
            budget: None,
            intervals: std::sync::Mutex::new(Vec::new()),
            drop_next: AtomicU64::new(16 << 20),
        })
    }

    /// Attach the job-wide extracted-byte budget (see [`WriteBudget`]).
    /// Builder-style so the extraction paths can opt in at construction;
    /// writers without one are never charged.
    pub fn with_budget(mut self, budget: std::sync::Arc<WriteBudget>) -> FileWriter {
        self.budget = Some(budget);
        self
    }

    pub fn write_at(&self, offset: u64, data: &[u8]) -> io::Result<()> {
        write_all_at(self.handle()?.as_ref().unwrap(), data, offset)?;
        let fresh = self.note_written(offset, data.len() as u64);
        self.maybe_drop_cache();
        // Decompression-bomb budget (extraction outputs only). The bytes
        // are already on disk when this trips, exactly like the disk-path
        // `BombGuardWriter` - the point is to stop the NEXT gigabyte, and
        // the error aborts the job the same way a genuine ENOSPC does.
        if let Some(b) = &self.budget {
            b.charge(fresh)?;
        }
        Ok(())
    }

    /// M32 perf (loopback-rig measured): under a small memory cgroup
    /// (1 GB NAS/docker), streaming writes cost ~17% of a core in
    /// page-cache reclaim (evict_folios/memcg walks). When enabled,
    /// every ~16 MB written per file we kick off async writeback and
    /// drop the file's clean pages, so eviction is a driveby instead
    /// of reclaim-scan work. Linux-only. Enablement: the CLI `get`
    /// path turns it on (no /stream readers can exist there; verify
    /// settle read-back of the few Pending blocks comes from disk -
    /// measured negligible, revisit on spinning rust); the daemon
    /// leaves it off (a stream reader can attach mid-job).
    /// NZBFAST_DROP_CACHE=1/0 force-overrides for benching.
    #[cfg(target_os = "linux")]
    fn maybe_drop_cache(&self) {
        static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        let on = *ON.get_or_init(|| match std::env::var("NZBFAST_DROP_CACHE").as_deref() {
            Ok("1") => true,
            Ok("0") => false,
            _ => DROP_CACHE_DEFAULT.load(Ordering::Relaxed),
        });
        if !on {
            return;
        }
        const STRIDE: u64 = 16 << 20;
        let w = self.written.load(Ordering::Relaxed);
        let due = self.drop_next.load(Ordering::Relaxed);
        if w < due || self.drop_next.compare_exchange(
            due, w + STRIDE, Ordering::Relaxed, Ordering::Relaxed
        ).is_err() {
            return;
        }
        use std::os::unix::io::AsRawFd;
        // Parked: the handle is gone and its pages were synced on the way
        // down, so there is nothing to write back or evict.
        let g = self.file.read().unwrap_or_else(|e| e.into_inner());
        let Some(fd) = g.as_ref().map(|f| f.as_raw_fd()) else {
            return;
        };
        unsafe {
            // Start writeback for everything dirty, then drop what's
            // clean. Repeated calls sweep up what writeback finished.
            libc::sync_file_range(fd, 0, 0, libc::SYNC_FILE_RANGE_WRITE);
            libc::posix_fadvise(fd, 0, 0, libc::POSIX_FADV_DONTNEED);
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn maybe_drop_cache(&self) {}

    /// pread through the writer's own handle - spares callers a fresh
    /// open() per read (the mapped-repair path reads thousands of
    /// blocks back through the volume view).
    pub fn read_at(&self, buf: &mut [u8], offset: u64) -> io::Result<()> {
        read_exact_at(self.handle()?.as_ref().unwrap(), buf, offset)
    }

    /// The live handle, or `NotConnected` when the writer is parked.
    ///
    /// Parked is never a state a caller should paper over: it means someone
    /// deliberately handed this file to an external process, so a write that
    /// lands now would be silently overwritten (or would corrupt what that
    /// process is rebuilding). Failing is the honest answer.
    fn handle(&self) -> io::Result<std::sync::RwLockReadGuard<'_, Option<File>>> {
        let g = self.file.read().unwrap_or_else(|e| e.into_inner());
        if g.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                format!("{} is parked for an external tool", self.path.display()),
            ));
        }
        Ok(g)
    }

    /// Close this file's OS handle, keeping the writer itself alive.
    ///
    /// Windows opens are share-negotiated: par2cmdline opens its targets with
    /// share mode 0, so ANY handle we still hold makes its open fail and it
    /// concludes the file is missing ("Repair is not possible"). Unix does not
    /// care, but parking there too keeps one code path and makes the external
    /// tool the sole writer on every platform - which it must be, since it
    /// rewrites these bytes underneath us.
    ///
    /// Syncs first: buffered pwrites that never reached disk would otherwise
    /// hand par2 a stale file and it would "repair" bytes we were about to
    /// write. A sync failure is returned, not swallowed - same contract as
    /// [`Extractor::finish`](crate::extract::Extractor::finish).
    ///
    /// Parking works through the writer's own shared state, NOT by dropping an
    /// `Arc`: releasing one reference cannot close anything while the daemon's
    /// stream picker or a settle reader still holds a clone.
    pub fn park(&self) -> io::Result<()> {
        let mut g = self.file.write().unwrap_or_else(|e| e.into_inner());
        if let Some(f) = g.as_ref() {
            f.sync_data()?;
        }
        *g = None;
        Ok(())
    }

    /// Reopen a parked writer at its original path, without truncating and
    /// without preallocating: the bytes on disk now are the external tool's
    /// repaired output and must survive verbatim. Idempotent - unparking a
    /// live writer is a no-op, so a caller may pair it with [`park`] on a path
    /// that bailed out early.
    ///
    /// `written`/`intervals` are deliberately untouched: they describe which
    /// spans of the file are populated, which is exactly as true after a
    /// repair as before it (repair fills bytes in, it never unwrites them).
    ///
    /// [`park`]: FileWriter::park
    pub fn unpark(&self) -> io::Result<()> {
        let mut g = self.file.write().unwrap_or_else(|e| e.into_inner());
        if g.is_some() {
            return Ok(());
        }
        *g = Some(OpenOptions::new().read(true).write(true).open(&self.path)?);
        Ok(())
    }

    /// Record `[offset, offset+len)` as on-disk without writing - crash
    /// resume seeds the coverage map with spans a previous run persisted.
    ///
    /// `intervals` is kept sorted by start and disjoint (touching runs
    /// merged), so this is a binary-search insert-and-merge: no per-write
    /// allocation and no full re-sort. The old rebuild-and-sort was
    /// O(n log n) + a heap alloc on EVERY span; under heavy out-of-order
    /// arrival (one disjoint region per in-flight connection) every
    /// decoder thread paid that while serialized on this mutex.
    /// Record [offset, offset+len) as written, returning the number of
    /// bytes that were NOT already covered. A rewrite (repair span, or a
    /// duplicate article) returns 0, which is what makes the extraction
    /// budget in `write_at` immune to double-charging a healing file.
    pub fn note_written(&self, offset: u64, len: u64) -> u64 {
        if len == 0 {
            return 0;
        }
        self.written.fetch_add(len, Ordering::Relaxed);
        let (s, e) = (offset, offset + len);
        let mut iv = self.intervals.lock().unwrap();
        // First interval that could touch/overlap on the left (its end
        // reaches `s`), and first that starts beyond `e` (can't touch).
        let lo = iv.partition_point(|&(_, fe)| fe < s);
        let hi = iv.partition_point(|&(fs, _)| fs <= e);
        if lo < hi {
            // Merge the overlapping/adjacent run [lo, hi) into one span.
            // The run's spans are disjoint, so the newly-covered count is
            // the merged length minus what the run already held.
            let held: u64 = iv[lo..hi].iter().map(|&(fs, fe)| fe - fs).sum();
            let ns = s.min(iv[lo].0);
            let ne = e.max(iv[hi - 1].1);
            iv[lo] = (ns, ne);
            iv.drain(lo + 1..hi);
            (ne - ns) - held
        } else {
            iv.insert(lo, (s, e));
            len
        }
    }

    /// True when every byte of [off, off+len) has been written.
    pub fn covered(&self, off: u64, len: u64) -> bool {
        let iv = self.intervals.lock().unwrap();
        iv.iter().any(|&(s, e)| s <= off && off + len <= e)
    }

    /// The written sub-ranges of [off, off+len), clipped, in file offsets.
    /// Anything not returned is a sparse hole that would pread as zeros -
    /// the extractor's fallback read-back must never copy those.
    pub fn covered_intervals(&self, off: u64, len: u64) -> Vec<(u64, u64)> {
        let end = off + len;
        let iv = self.intervals.lock().unwrap();
        iv.iter()
            .filter_map(|&(s, e)| {
                let cs = s.max(off);
                let ce = e.min(end);
                (cs < ce).then_some((cs, ce))
            })
            .collect()
    }

    /// End of the contiguous prefix starting at 0 (the streaming frontier).
    pub fn contiguous_from_start(&self) -> u64 {
        let iv = self.intervals.lock().unwrap();
        match iv.first() {
            Some(&(0, e)) => e,
            _ => 0,
        }
    }

    /// Bytes written so far (not necessarily contiguous).
    pub fn written(&self) -> u64 {
        self.written.load(Ordering::Relaxed)
    }

    /// A PARKED writer syncs nothing and reports success: [`park`] synced it
    /// on the way down and closed the handle, so there is no buffered state
    /// left to lose. Erroring here instead would fail a job whose bytes are
    /// all safely on disk.
    ///
    /// [`park`]: FileWriter::park
    pub fn sync(&self) -> io::Result<()> {
        match self.file.read().unwrap_or_else(|e| e.into_inner()).as_ref() {
            Some(f) => f.sync_data(),
            None => Ok(()),
        }
    }
}

/// Flush a directory's own entries, so a rename that published a file
/// survives a power cut. Best-effort on purpose: no caller may depend on
/// it for correctness (SMB/CIFS and some FUSE mounts - the NAS setups we
/// actually ship to - refuse to open a directory for fsync, and failing a
/// good job over that would be pure harm), and Windows has no directory
/// handle to sync through at all.
pub fn sync_dir(dir: &Path) {
    #[cfg(unix)]
    {
        if let Ok(f) = File::open(dir) {
            let _ = f.sync_all();
        }
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
    }
}

/// Does this directory live on a case-insensitive filesystem?
///
/// Decided by PROBING, not by the build target. Case sensitivity is a
/// property of the destination VOLUME, and `cfg!(target_os)` gets both
/// interesting cases wrong: the Linux container/NAS build writing to a
/// CIFS/SMB share or an exFAT disk is case-INsensitive, and a macOS build
/// writing to a case-sensitive APFS volume is not. Guessing from the build
/// target means `README` and `readme` are treated as two output files on a
/// volume where they name one - and the second write truncates the first.
///
/// Probes the nearest EXISTING ancestor, so it still answers correctly when
/// the output directory has not been created yet (sensitivity is a mount
/// property, and an ancestor is on the same mount). Falls back to the
/// platform default if no probe can be written.
pub fn case_insensitive_dir(dir: &Path) -> bool {
    let default = cfg!(any(target_os = "macos", target_os = "windows"));
    let mut at = Some(dir);
    while let Some(d) = at {
        if d.is_dir() {
            return probe_case_insensitive(d).unwrap_or(default);
        }
        at = d.parent();
    }
    default
}

/// One probe: write a mixed-case name, then ask for it in lower case. The
/// pid + a counter keep concurrent jobs (and concurrent probes of one dir)
/// from deleting each other's probe file.
fn probe_case_insensitive(dir: &Path) -> Option<bool> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let tag = format!(
        ".nzbfast-CaseProbe-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    );
    let mixed = dir.join(&tag);
    std::fs::File::create(&mixed).ok()?;
    // `tag` is deliberately mixed-case, so this differs ONLY in case.
    let lowered = dir.join(tag.to_lowercase());
    let insensitive = std::fs::metadata(&lowered).is_ok();
    let _ = std::fs::remove_file(&mixed);
    Some(insensitive)
}

/// Make a filename safe as a single path component. Neutralises path
/// separators and NUL, ASCII control characters (which have no place in a
/// filename and can confuse terminals/loggers), and - so a crafted archive
/// entry or NZB name is portable and can't open a device on Windows - the
/// reserved DOS device names (CON, NUL, COM1..9, LPT1..9, AUX, PRN) and
/// trailing dots/spaces that Windows silently strips.
pub fn sanitize_filename(name: &str) -> String {
    sanitize_filename_for(name, cfg!(windows))
}

/// `sanitize_filename` with the platform as a parameter, so the Windows-only
/// guarantee is asserted by the suite on every host. A `cfg!`-only guard would
/// leave that test vacuous on the Mac and Linux boxes we actually develop and
/// run CI on - the trap an earlier filesystem-behaviour test fell into.
pub fn sanitize_filename_for(name: &str, windows: bool) -> String {
    let cleaned: String = name
        .chars()
        .map(|c| match c {
            '/' | '\\' | '\0' => '_',
            // Windows only: ':' carries path meaning even with no separator.
            // "C:evil.dll" is a DRIVE-RELATIVE path, and `Path::join` DISCARDS
            // the base when the joined name has a prefix - so an archive entry
            // named that way escapes the download directory entirely (it lands
            // in the process's cwd on C:, which for the installed app is the
            // directory holding nzbfast.exe = first in the DLL search order).
            // "payload.mkv:hidden" is the other half: an NTFS alternate data
            // stream, where the payload writes into the stream and the visible
            // file is left 0 bytes. Neither is a legal Windows filename, so
            // mapping it costs nothing there; on Unix ':' is legal and common
            // in release names ("Movie: The Sequel.mkv"), so leave it alone.
            ':' if windows => '_',
            c if c.is_control() => '_',
            c => c,
        })
        .collect();
    // Windows strips trailing dots and spaces, so "evil. " -> "evil"; strip
    // them ourselves for a stable, portable name (leading dots too: hidden).
    let trimmed = cleaned.trim().trim_matches('.').trim().to_string();
    // The trim chain above is NOT a fixed point: `trim_matches('.')` peels the
    // outer dots, the following `.trim()` then exposes INTERIOR dots as the
    // new ends, and ". .. ." comes out as ".." (". . ." as "."). Both are
    // non-empty, so they used to be returned verbatim - a single path
    // component that escapes its parent. Every caller joins this straight
    // onto a root (`out_dir/<category>/<stem>`) and nothing re-checks
    // containment, so a category or NZB name of ". .. ." put the payload
    // outside the download root, and "Remove + delete files" then ran
    // `remove_dir_all` on that parent. A name that is nothing but dots has no
    // meaning worth preserving.
    if trimmed.is_empty() || trimmed.chars().all(|c| c == '.') {
        return "unnamed".to_string();
    }
    // Reserved DOS device names match case-insensitively on the stem before
    // the first dot (CON, con.txt, and "CON " all open the console device).
    // Normalise for the match: uppercase, map the Unicode superscript digits
    // Windows folds to 1/2/3 (COM\u{B9} opens COM1), and drop a trailing '$'
    // (CLOCK$/CONIN$/CONOUT$ handles).
    let raw_stem = trimmed.split('.').next().unwrap_or(&trimmed).trim();
    let stem: String = raw_stem
        .trim_end_matches('$')
        .chars()
        .map(|c| match c {
            '\u{B9}' => '1', // superscript one
            '\u{B2}' => '2', // superscript two
            '\u{B3}' => '3', // superscript three
            c => c.to_ascii_uppercase(),
        })
        .collect();
    let reserved = matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL" | "CLOCK" | "CONIN" | "CONOUT")
        || ((stem.starts_with("COM") || stem.starts_with("LPT"))
            && stem.len() == 4
            && stem.as_bytes()[3].is_ascii_digit()
            && stem.as_bytes()[3] != b'0');
    if reserved {
        format!("_{trimmed}")
    } else {
        trimmed
    }
}

#[cfg(test)]
mod case_probe_tests {
    use super::*;

    /// The probe must agree with what the filesystem ACTUALLY does, on
    /// whatever volume the suite happens to run on. That is the whole point
    /// of probing instead of reading `cfg!(target_os)`: this assertion is
    /// meaningful on case-sensitive Linux CI, on a case-insensitive macOS
    /// dev box, and on a Linux runner whose tmp is a case-insensitive mount -
    /// where the old build-target guess was simply wrong.
    #[test]
    fn case_probe_agrees_with_the_real_filesystem() {
        let dir = std::env::temp_dir().join(format!("nzbfast-case-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        // Ground truth: write one spelling, ask for the other.
        std::fs::write(dir.join("Ground.txt"), b"x").unwrap();
        let truth = std::fs::metadata(dir.join("ground.txt")).is_ok();

        assert_eq!(
            case_insensitive_dir(&dir),
            truth,
            "probe disagrees with the filesystem at {}",
            dir.display()
        );

        // A not-yet-created output dir must still answer correctly: the
        // probe walks up to the nearest existing ancestor, since case
        // sensitivity is a property of the mount.
        let unborn = dir.join("does").join("not").join("exist");
        assert_eq!(case_insensitive_dir(&unborn), truth);

        // The probe must not leave its scratch file behind.
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains("CaseProbe") || n.contains("caseprobe"))
            .collect();
        assert!(leftovers.is_empty(), "probe left {leftovers:?} behind");

        std::fs::remove_dir_all(&dir).ok();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A parked writer keeps its bytes and its identity, refuses writes while
    /// it is parked, and comes back usable. The refusal is the point: a write
    /// that landed while an external par2 owned the file would be overwritten
    /// by the repair without a word.
    #[test]
    fn park_refuses_writes_then_unpark_restores_the_writer() {
        let dir = std::env::temp_dir().join(format!("nzbfast-park-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("payload.bin");
        let w = FileWriter::create(&path, 8).unwrap();
        w.write_at(0, b"abcd").unwrap();

        w.park().unwrap();
        let e = w.write_at(4, b"efgh").unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::NotConnected, "{e}");
        let mut buf = [0u8; 4];
        assert_eq!(
            w.read_at(&mut buf, 0).unwrap_err().kind(),
            io::ErrorKind::NotConnected
        );
        // Parked syncs are a no-op, not a failure: park() already synced, so
        // erroring here would fail a job whose bytes are all safely on disk.
        w.sync().unwrap();
        // The bytes written before parking reached disk, and the file itself
        // is untouched - that is what the external tool repairs against.
        assert_eq!(&std::fs::read(&path).unwrap()[..4], b"abcd");

        w.unpark().unwrap();
        w.unpark().unwrap(); // idempotent - error paths may double-unpark
        w.write_at(4, b"efgh").unwrap();
        w.read_at(&mut buf, 4).unwrap();
        assert_eq!(&buf, b"efgh");
        assert_eq!(&std::fs::read(&path).unwrap()[..8], b"abcdefgh");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The whole point on Windows: while parked, an EXCLUSIVE open of the file
    /// succeeds. That is exactly what par2cmdline does, and a handle we still
    /// held made it report the target missing and decline to repair.
    #[cfg(windows)]
    #[test]
    fn a_parked_file_can_be_opened_exclusively() {
        use std::os::windows::fs::OpenOptionsExt;
        // share mode 0 - what par2cmdline asks for.
        let exclusive = |p: &Path| OpenOptions::new().read(true).share_mode(0).open(p);

        let dir = std::env::temp_dir().join(format!("nzbfast-excl-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("payload.bin");
        let w = FileWriter::create(&path, 4).unwrap();
        w.write_at(0, b"abcd").unwrap();

        assert!(exclusive(&path).is_err(), "a live writer must block par2");
        w.park().unwrap();
        drop(exclusive(&path).expect("a parked writer must let par2 in"));
        w.unpark().unwrap();
        assert!(exclusive(&path).is_err(), "unpark must retake the handle");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The probe must never answer `Rotational` for something it could not
    /// identify - an unknown answer clamps nothing, a wrong "spinning"
    /// answer would throttle an SSD, a RAID array or an SMB share.
    #[test]
    fn storage_probe_never_guesses_rotational() {
        assert_eq!(
            detect_storage(Path::new("/nonexistent-nzbfast-probe")),
            Storage::Unknown
        );
        let here = detect_storage(Path::new("."));
        #[cfg(not(target_os = "linux"))]
        assert_eq!(here, Storage::Unknown, "only Linux exposes the flag");
        #[cfg(target_os = "linux")]
        assert!(
            matches!(here, Storage::Solid | Storage::Unknown | Storage::Rotational),
            "{here:?}"
        );
    }

    /// The operator override names a profile in both directions, so a
    /// misdetected array or a network mount can be corrected. Anything
    /// else - unset, `auto`, a typo - defers to the probe.
    #[test]
    fn storage_override_maps_both_directions_and_defers_otherwise() {
        assert_eq!(storage_override(Some("rotational")), Some(Storage::Rotational));
        assert_eq!(storage_override(Some("hdd")), Some(Storage::Rotational));
        assert_eq!(storage_override(Some("ssd")), Some(Storage::Solid));
        assert_eq!(storage_override(Some("solid")), Some(Storage::Solid));
        assert_eq!(storage_override(Some("auto")), None);
        assert_eq!(storage_override(Some("SSD")), None, "match is exact");
        assert_eq!(storage_override(None), None);
    }

    /// The clamp fires only for a spinning disk on a NAS-class box. Every
    /// other combination must pass the caller's choice through untouched -
    /// throttling a big box, an SSD, or storage we failed to identify would
    /// cost real throughput (1 decoder is a third of 4 on fast hardware).
    #[test]
    fn rotational_clamp_only_bites_nas_class_boxes() {
        assert_eq!(decoders_for_storage(Storage::Rotational, 4, 4), 1);
        assert_eq!(decoders_for_storage(Storage::Rotational, 2, 8), 1);
        // Big box: a rotational device here is usually a wide array.
        assert_eq!(decoders_for_storage(Storage::Rotational, 8, 4), 4);
        assert_eq!(decoders_for_storage(Storage::Rotational, 32, 4), 4);
        // Never clamp on anything we did not positively identify as spinning.
        assert_eq!(decoders_for_storage(Storage::Unknown, 2, 4), 4);
        assert_eq!(decoders_for_storage(Storage::Solid, 2, 4), 4);
        // Already serial, or explicitly asked for one: nothing to say.
        assert_eq!(decoders_for_storage(Storage::Rotational, 2, 1), 1);
    }

    /// The spill path needs room for one writer per volume; the stock macOS
    /// 256 is not enough for a 431-volume job.
    ///
    /// Unix only, because the limit it is about is. Windows has no
    /// RLIMIT_NOFILE: `std::fs::File` there is a Win32 HANDLE from
    /// `CreateFileW`, and handles are bounded by kernel memory (millions),
    /// not by a per-process soft cap anyone can raise. The CRT's own
    /// 512-descriptor table is a different thing that Rust does not use. So
    /// there is nothing to raise and `raise_fd_limit` reports 0 - which this
    /// test asserted was "too low for the spill path", the reading that made
    /// it fail the first time the suite ran on Windows.
    #[cfg(unix)]
    #[test]
    fn fd_limit_is_raised_above_the_stock_soft_cap() {
        let got = raise_fd_limit();
        assert!(got >= 1024, "fd limit {got} too low for the spill path");
        // Idempotent: a second call must not lower what we already have.
        assert!(raise_fd_limit() >= got);
    }

    /// The other half of the contract above: on Windows the call must be a
    /// harmless no-op rather than something that reports a limit the caller
    /// might then size the spill path against.
    #[cfg(windows)]
    #[test]
    fn fd_limit_is_a_no_op_where_there_is_no_such_limit() {
        assert_eq!(raise_fd_limit(), 0, "nothing to raise on Windows - say so, don't invent one");
    }

    /// Whichever branch `preallocate` takes (raw fallocate where the
    /// Linux fs supports it, plain set_len on macOS/tmpfs/zfs), the
    /// observable contract is the same: the file spans `size` at create
    /// and resume, and writes land at their offsets.
    #[test]
    fn preallocation_yields_correct_length_on_both_paths() {
        let dir = std::env::temp_dir().join(format!("nzbfast-prealloc-{}", std::process::id()));
        let path = dir.join("out.bin");

        let w = FileWriter::create(&path, 300_000).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 300_000);
        w.write_at(299_990, &[7u8; 10]).unwrap();
        w.sync().unwrap();
        drop(w);

        // Resume must keep the earlier bytes and still span `size`.
        let w = FileWriter::create_resume(&path, 300_000).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 300_000);
        let mut tail = [0u8; 10];
        w.read_at(&mut tail, 299_990).unwrap();
        assert_eq!(tail, [7u8; 10]);
        drop(w);

        // Zero-size files skip fallocate (EINVAL on len 0) but must
        // still truncate.
        let w = FileWriter::create(&path, 0).unwrap();
        drop(w);
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 0);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// BUG (HIGH): the in-stream extractor preallocated an
    /// attacker-declared size. An inner file's `unpacked_size` is a RAR
    /// header vint the poster controls, and on Linux `preallocate` is a
    /// real `fallocate` - so a few-hundred-KB post declaring terabytes
    /// genuinely reserved the victim's free space until the finish-time
    /// gates demoted the set. The ceiling bounds the RESERVATION.
    #[test]
    fn a_declared_size_past_the_ceiling_reserves_only_the_ceiling() {
        let dir = std::env::temp_dir().join(format!("nzbfast-cap-{}", std::process::id()));
        let path = dir.join("bomb.bin");
        const HUGE: u64 = 8 << 40; // 8 TiB "declared"
        const POSTED: u64 = 1 << 20; // what the NZB actually posted

        let w = FileWriter::create_capped(&path, HUGE, POSTED).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().len(),
            POSTED,
            "an attacker-declared size must not reserve past the posted ceiling"
        );
        // CRITICAL: `size` itself is NOT clamped - create_resume's stale
        // truncation and the reported extracted size both read it.
        assert_eq!(w.size, HUGE);
        // And the cap is a reservation bound, not a write bound: writing
        // past it extends the file normally.
        w.write_at(POSTED + 4096, &[9u8; 8]).unwrap();
        let mut got = [0u8; 8];
        w.read_at(&mut got, POSTED + 4096).unwrap();
        assert_eq!(got, [9u8; 8]);
        assert_eq!(std::fs::metadata(&path).unwrap().len(), POSTED + 4104);
        drop(w);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// THE test that matters: a wrong fix here silently de-optimises
    /// every real download. A legitimate file that fits under the posted
    /// ceiling must still be reserved IN FULL, on both create paths.
    #[test]
    fn a_legitimate_size_under_the_ceiling_still_preallocates_in_full() {
        let dir = std::env::temp_dir().join(format!("nzbfast-cap-ok-{}", std::process::id()));
        let path = dir.join("movie.bin");
        const SIZE: u64 = 4_000_000;
        const POSTED: u64 = 64_000_000;

        let w = FileWriter::create_capped(&path, SIZE, POSTED).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().len(),
            SIZE,
            "a legitimate file under the ceiling must be preallocated in full"
        );
        assert_eq!(w.size, SIZE);
        drop(w);

        let w = FileWriter::create_resume_capped(&path, SIZE, POSTED).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), SIZE);
        drop(w);

        // Exactly at the ceiling is legitimate too (STORE unpacks 1:1, and
        // the posted count carries yEnc overhead on top).
        let w = FileWriter::create_capped(&path, POSTED, POSTED).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), POSTED);
        drop(w);

        // No ceiling set = byte-for-byte the old behaviour.
        let w = FileWriter::create_capped(&path, SIZE, u64::MAX).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), SIZE);
        drop(w);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The ceiling must never cost a resumed job its bytes: on the resume
    /// path it may not shrink the file below what is already there, and
    /// the stale-longer-file trim (down to `size`, which only ever frees
    /// space) still has to happen.
    #[test]
    fn the_ceiling_never_shrinks_a_resumed_file() {
        let dir = std::env::temp_dir().join(format!("nzbfast-cap-res-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("out.bin");

        // 400 KB already on disk, a 1 KB ceiling, 8 TB declared: the
        // existing bytes stay.
        std::fs::write(&path, vec![0xAAu8; 400_000]).unwrap();
        let w = FileWriter::create_resume_capped(&path, 8 << 40, 1024).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 400_000);
        let mut head = [0u8; 4];
        w.read_at(&mut head, 0).unwrap();
        assert_eq!(head, [0xAA; 4]);
        drop(w);

        // Stale file LONGER than `size`: still trimmed to exactly `size`
        // even under a smaller ceiling - that shrinks, so it reserves
        // nothing.
        std::fs::write(&path, vec![0xAAu8; 500_000]).unwrap();
        let w = FileWriter::create_resume_capped(&path, 300_000, 1024).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 300_000);
        drop(w);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// BUG (MEDIUM): the decompression-bomb guard was installed only on
    /// the disk and post-pass sinks, so it covered the fallback and not
    /// the default in-stream path. The budget now rides the FileWriter,
    /// and is SHARED - a bomb split over many inner files gets one
    /// allowance, not one each.
    #[test]
    fn the_extract_budget_is_shared_and_charges_only_new_bytes() {
        let dir = std::env::temp_dir().join(format!("nzbfast-budget-{}", std::process::id()));
        let budget = std::sync::Arc::new(WriteBudget::new(1000));

        let a = FileWriter::create(&dir.join("a.bin"), 4096)
            .unwrap()
            .with_budget(budget.clone());
        let b = FileWriter::create(&dir.join("b.bin"), 4096)
            .unwrap()
            .with_budget(budget.clone());

        a.write_at(0, &[1u8; 600]).unwrap();
        assert_eq!(budget.used(), 600);
        // A repair span REWRITING bytes already counted must not be
        // charged twice - otherwise a healing job trips its own guard.
        a.write_at(0, &[2u8; 600]).unwrap();
        a.write_at(100, &[3u8; 200]).unwrap();
        assert_eq!(budget.used(), 600, "rewrites must not be charged");
        // Partial overlap charges only the new tail.
        a.write_at(500, &[4u8; 200]).unwrap();
        assert_eq!(budget.used(), 700);

        // The SECOND file draws on the same allowance and trips it.
        let e = b.write_at(0, &[5u8; 400]).unwrap_err();
        assert!(
            e.to_string().contains("decompression bomb"),
            "unexpected error: {e}"
        );

        // A writer with no budget is never charged (plain download slots).
        let c = FileWriter::create(&dir.join("c.bin"), 4096).unwrap();
        c.write_at(0, &[6u8; 100_000]).unwrap();
        drop((a, b, c));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A stale file LONGER than `size` at the resume path must be shrunk
    /// to exactly `size` - fallocate never shrinks, so this pins the
    /// unconditional set_len that precedes it (trailing garbage past
    /// `size` would otherwise ship to the user for unparred files).
    #[test]
    fn create_resume_truncates_stale_longer_file() {
        let dir = std::env::temp_dir().join(format!("nzbfast-resume-trunc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("out.bin");

        std::fs::write(&path, vec![0xAAu8; 500_000]).unwrap();
        let w = FileWriter::create_resume(&path, 300_000).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 300_000);
        // Bytes inside [0, size) survive the resume.
        let mut head = [0u8; 10];
        w.read_at(&mut head, 0).unwrap();
        assert_eq!(head, [0xAAu8; 10]);
        drop(w);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn out_of_order_writes_assemble_correctly() {
        let dir = std::env::temp_dir().join(format!("nzbfast-disk-test-{}", std::process::id()));
        let path = dir.join("out.bin");
        let data: Vec<u8> = (0..100_000u32).map(|i| (i % 251) as u8).collect();

        let w = FileWriter::create(&path, data.len() as u64).unwrap();
        // Write the second half first, then the first.
        w.write_at(60_000, &data[60_000..]).unwrap();
        w.write_at(0, &data[..60_000]).unwrap();
        assert_eq!(w.written(), data.len() as u64);
        w.sync().unwrap();

        assert_eq!(std::fs::read(&path).unwrap(), data);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// note_written keeps `intervals` sorted, disjoint, and adjacency-
    /// merged. Fuzz it against a brute-force byte-set oracle across
    /// overlapping, adjacent, gap-filling and out-of-order spans.
    #[test]
    fn note_written_merges_like_a_byte_set() {
        let path = std::env::temp_dir().join(format!("nzbfast-iv-{}.bin", std::process::id()));
        let w = FileWriter::create(&path, 512).unwrap();
        let mut oracle = vec![false; 512];
        // A deterministic LCG picks spans; includes adjacency (b==c) and
        // full overlaps.
        let mut state = 0x1234_5678u64;
        let mut rng = || {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            (state >> 33) as usize
        };
        for _ in 0..2000 {
            let a = rng() % 500;
            let l = 1 + rng() % 40;
            let b = (a + l).min(512);
            w.note_written(a as u64, (b - a) as u64);
            for x in a..b {
                oracle[x] = true;
            }
            // Coverage must exactly match the oracle for a few probes.
            for _ in 0..4 {
                let qa = rng() % 500;
                let ql = 1 + rng() % 30;
                let qb = (qa + ql).min(512);
                let want = oracle[qa..qb].iter().all(|&c| c);
                assert_eq!(
                    w.covered(qa as u64, (qb - qa) as u64),
                    want,
                    "covered({qa},{qb}) disagrees with oracle"
                );
            }
        }
        // The interval list must be sorted, disjoint and non-adjacent.
        let iv = w.intervals.lock().unwrap();
        for pair in iv.windows(2) {
            assert!(pair[0].1 < pair[1].0, "not disjoint/sorted: {iv:?}");
        }
        for &(s, e) in iv.iter() {
            assert!(s < e, "empty interval {iv:?}");
        }
        drop(iv);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn sanitize() {
        assert_eq!(sanitize_filename("a/b\\c.rar"), "a_b_c.rar");
        assert_eq!(sanitize_filename("  ..hidden  "), "hidden");
        assert_eq!(sanitize_filename(""), "unnamed");
        // Traversal neutralisation (bug sweep: category/stem build the
        // download path). The result must be a single component - no
        // separators survive, so `join` can never escape the base.
        for s in ["../../../../tmp/pwned", "/tmp/abs", "..\\..\\win", "a/../b"] {
            let out = sanitize_filename(s);
            assert!(!out.contains('/') && !out.contains('\\'), "{s:?} -> {out:?}");
            assert!(!out.starts_with('.'), "{s:?} -> {out:?}");
        }
        // Dots separated by spaces. The trim chain is not a fixed point:
        // stripping the outer dots exposes whitespace, and trimming THAT
        // exposes interior dots, so these used to come out as ".." and "." -
        // a component that escapes its parent, with `remove_dir_all` on the
        // delete-with-files path pointed at it. No separator is involved, so
        // the loop above never caught them.
        for s in [". .. .", ".. .. ..", ". . .", " .. ", "...", ". ."] {
            assert_eq!(sanitize_filename(s), "unnamed", "{s:?} escaped");
        }
        // ...and the same names as an on-disk path component stay contained.
        for s in [". .. .", ". . ."] {
            let joined = std::path::Path::new("/srv/dl").join(sanitize_filename(s));
            assert_eq!(joined, std::path::Path::new("/srv/dl/unnamed"), "{s:?}");
        }
        // A drive prefix is a separator too, on Windows. `Path::join` DISCARDS
        // the base when the joined name carries a prefix, so "C:evil.dll" wrote
        // outside the download dir entirely (into the cwd on C: - for the
        // installed app, the directory holding nzbfast.exe, i.e. first in the
        // DLL search order). "x.mkv:s" is the NTFS alternate-data-stream half:
        // the bytes go into the stream and the visible file is left 0 bytes.
        // Asserted through the `_for` seam so this holds on Unix CI too.
        for s in ["C:evil.dll", "payload.mkv:hidden", "\\\\?\\C:\\x", "C:/x"] {
            let out = sanitize_filename_for(s, true);
            assert!(!out.contains(':'), "{s:?} -> {out:?}");
            assert!(
                std::path::Path::new(&out).components().count() == 1,
                "not a single component: {s:?} -> {out:?}"
            );
        }
        // Unix keeps ':' - it is legal there and common in release names.
        assert_eq!(sanitize_filename_for("Movie: The Sequel.mkv", false), "Movie: The Sequel.mkv");
        // Control characters (incl. embedded NUL/newline/tab) are replaced.
        let ctl = sanitize_filename("ev\u{7}il\nname\t.mkv");
        assert!(!ctl.chars().any(|c| c.is_control()), "control char survived: {ctl:?}");
        // Trailing dot/space that Windows would strip.
        assert_eq!(sanitize_filename("evil. "), "evil");
        // Windows reserved device names get a prefix so File::create can't
        // open a device; real names with those as a substring are untouched.
        assert_eq!(sanitize_filename("CON"), "_CON");
        assert_eq!(sanitize_filename("con.txt"), "_con.txt");
        assert_eq!(sanitize_filename("COM1"), "_COM1");
        assert_eq!(sanitize_filename("LPT9.dat"), "_LPT9.dat");
        assert_eq!(sanitize_filename("COM0"), "COM0"); // not a real device
        assert_eq!(sanitize_filename("console.log"), "console.log"); // substring only
        assert_eq!(sanitize_filename("company"), "company");
        // Unicode superscript device names that Windows folds to COM1/LPT1.
        assert_eq!(sanitize_filename("COM\u{B9}"), "_COM\u{B9}");
        assert_eq!(sanitize_filename("LPT\u{B2}.dat"), "_LPT\u{B2}.dat");
        // Trailing-$ console/clock device handles.
        assert_eq!(sanitize_filename("CLOCK$"), "_CLOCK$");
        assert_eq!(sanitize_filename("CONIN$"), "_CONIN$");
        assert_eq!(sanitize_filename("CONOUT$"), "_CONOUT$");
    }
}

/// Mark one of our own bookkeeping files or dirs as hidden.
///
/// We name everything internal with a leading dot - `.nzbfast.journal`,
/// `.spool`, the `.nzbfast-hold` markers - which hides it on macOS and
/// Linux and hides NOTHING on Windows, where the convention does not
/// exist. So a Windows user opening a failed download's folder finds one
/// mysterious file sitting in it, reads it as leftover junk, and is
/// right to: it looks like junk even though it is the resume state that
/// lets a retry fetch only what is still missing.
///
/// Best-effort by design. A filesystem that cannot store the attribute
/// (a network share, a FAT volume mounted oddly) is not a reason to fail
/// the download the file belongs to.
pub fn hide_from_user(path: &Path) {
    #[cfg(windows)]
    {
        const FILE_ATTRIBUTE_HIDDEN: u32 = 0x2;
        const INVALID_FILE_ATTRIBUTES: u32 = u32::MAX;
        unsafe extern "system" {
            fn GetFileAttributesW(name: *const u16) -> u32;
            fn SetFileAttributesW(name: *const u16, attrs: u32) -> i32;
        }
        use std::os::windows::ffi::OsStrExt;
        let wide: Vec<u16> =
            path.as_os_str().encode_wide().chain(std::iter::once(0)).collect();
        unsafe {
            // OR into whatever is already set: replacing the attribute
            // word outright would clear ARCHIVE/READONLY and anything
            // else the volume put there.
            let cur = GetFileAttributesW(wide.as_ptr());
            let base = if cur == INVALID_FILE_ATTRIBUTES { 0 } else { cur };
            SetFileAttributesW(wide.as_ptr(), base | FILE_ATTRIBUTE_HIDDEN);
        }
    }
    #[cfg(not(windows))]
    {
        // The leading dot already does this everywhere else.
        let _ = path;
    }
}

//! Free-space measurement (one `disk_stat` per platform, plus the
//! walk-upward fallback for a directory that does not exist yet) and the
//! rolling daily/monthly quota ledger built on it.
//!
//! Split out of serve/mod.rs by TODO 106 phase 4 - the code is verbatim,
//! only visibility changed.

use super::*;

/// (free, total) bytes of the filesystem holding `path`.
#[cfg(all(unix, not(target_os = "macos")))]
pub(super) fn disk_stat(path: &std::path::Path) -> Option<(u64, u64)> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
    (unsafe { libc::statvfs(c.as_ptr(), &mut s) } == 0).then(|| {
        (
            s.f_bavail as u64 * s.f_frsize as u64,
            s.f_blocks as u64 * s.f_frsize as u64,
        )
    })
}
/// macOS carries statvfs block counts in a 32-bit `fsblkcnt_t`, so a
/// volume past 2^32 blocks (16 TiB at APFS's 4 KiB) wraps and we read a
/// number reduced modulo that: a 22 TB drive measures 4.4 TB, and free
/// can come out LARGER than total. Everything downstream believes it -
/// the dashboard, the SAB/nzbget diskspace fields the *arrs read, the
/// min-free guard, and the extraction bomb budget, which then aborts a
/// healthy unpack as a "decompression bomb" on a disk with terabytes
/// spare. statfs(2) reports the same counts in uint64_t fields, and its
/// f_bsize is the same allocation block size, so ask it instead.
#[cfg(target_os = "macos")]
pub(super) fn disk_stat(path: &std::path::Path) -> Option<(u64, u64)> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut s: libc::statfs = unsafe { std::mem::zeroed() };
    (unsafe { libc::statfs(c.as_ptr(), &mut s) } == 0)
        .then(|| (s.f_bavail * s.f_bsize as u64, s.f_blocks * s.f_bsize as u64))
}
/// Windows has no statvfs. GetDiskFreeSpaceExW takes a directory (a
/// file path fails, which the ancestor walk in `free_bytes` absorbs by
/// stepping up) and answers per-volume, including for UNC shares and
/// mounted folders - so a download dir on a mapped NAS is measured on
/// the NAS, not on C:.
///
/// "Free" is bytes-available-TO-THE-CALLER, the statvfs f_bavail
/// analogue: under a disk quota that is the number the guard must use,
/// since it's what this process can actually write.
#[cfg(windows)]
pub(super) fn disk_stat(path: &std::path::Path) -> Option<(u64, u64)> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    // An interior NUL would silently truncate the path and measure the
    // wrong volume; reject rather than answer about somewhere else.
    if wide.contains(&0) {
        return None;
    }
    wide.push(0);
    let (mut free, mut total) = (0u64, 0u64);
    let ok =
        unsafe { GetDiskFreeSpaceExW(wide.as_ptr(), &mut free, &mut total, std::ptr::null_mut()) };
    (ok != 0).then_some((free, total))
}
#[cfg(not(any(unix, windows)))]
pub(super) fn disk_stat(_path: &std::path::Path) -> Option<(u64, u64)> {
    None
}

/// Free bytes of the filesystem that holds - or will hold - `path`.
///
/// `statvfs` needs a path that EXISTS, and the output directory often
/// doesn't yet: first run before anything has been downloaded, a
/// per-category subfolder created at job time, or (the dangerous one) a
/// NAS mount point whose share isn't mounted. A bare `disk_stat` returns
/// None there, and None silently DISABLES the min-free guard - the
/// download then fills the very disk the guard was set up to protect.
/// The filesystem that will hold `path` is the one holding its nearest
/// existing ancestor, so fall back to asking that.
pub(crate) fn free_bytes(path: &std::path::Path) -> Option<u64> {
    disk_stat_walk(path).map(|(free, _)| free)
}

/// (free, total) of the filesystem that holds - or will hold - `path`,
/// via the same nearest-existing-ancestor walk. The dashboard and the
/// NZBGet-compat status report went through bare `disk_stat` instead
/// and turned "directory not created yet" into "0 MB free on disk" -
/// which the *arrs read as a full disk.
pub(crate) fn disk_stat_walk(path: &std::path::Path) -> Option<(u64, u64)> {
    let mut p = path;
    loop {
        if let Some(stat) = disk_stat(p) {
            return Some(stat);
        }
        p = match p.parent() {
            // A relative path runs out of ancestors at ""; the cwd is the
            // filesystem it resolves against.
            Some(q) if q.as_os_str().is_empty() => std::path::Path::new("."),
            Some(q) => q,
            None => return None,
        };
        if p == std::path::Path::new(".") {
            return disk_stat(p);
        }
    }
}

/// Downloaded-bytes ledger for the quota window, persisted in the spool
/// so restarts don't forget a spent budget.
pub(super) struct QuotaLedger {
    pub(super) path: PathBuf,
    pub(super) period: char,
    pub(super) start: u64,
    pub(super) bytes: u64,
}

impl QuotaLedger {
    pub(super) fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// Start of the current period (UTC midnight / 1st of month).
    pub(super) fn period_start(period: char) -> u64 {
        let now = Self::now();
        let day = 86_400;
        match period {
            'm' => {
                // Days since epoch → walk back to day-of-month 1. Epoch
                // was a Thursday, Jan 1 1970; use civil-from-days math.
                let days = now / day;
                let dom = civil_from_days(days as i64).2 as u64; // 1-based
                (days - (dom - 1)) * day
            }
            _ => now / day * day,
        }
    }

    pub(super) fn open(spool: &std::path::Path, period: char) -> Self {
        let path = spool.join("quota.json");
        let mut led = QuotaLedger {
            path,
            period,
            start: Self::period_start(period),
            bytes: 0,
        };
        // Opened from the download runner's tick, which is a tokio task:
        // the read (and the .bak refresh it may write) is disk IO that
        // must not run undemoted on a worker thread.
        if let Some(v) =
            crate::persist::blocking_db(|| crate::persist::load_json_with_backup(&led.path))
        {
            let start = v["start"].as_u64().unwrap_or(0);
            if start == led.start {
                led.bytes = v["bytes"].as_u64().unwrap_or(0);
            }
        }
        led
    }

    /// Roll the window if a new period began; returns bytes spent so far.
    pub(super) fn spent(&mut self) -> u64 {
        let cur = Self::period_start(self.period);
        if cur != self.start {
            self.start = cur;
            self.bytes = 0;
            self.save();
        }
        self.bytes
    }

    pub(super) fn add(&mut self, n: u64) {
        self.spent();
        self.bytes += n;
        self.save();
    }

    pub(super) fn save(&self) {
        let _ = crate::persist::write_atomic(
            &self.path,
            json!({"start": self.start, "bytes": self.bytes})
                .to_string()
                .as_bytes(),
        );
    }
}

/// (year, month, day) from days-since-epoch - Howard Hinnant's civil
/// calendar algorithm, used for monthly quota rollover.
pub(super) fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Mid-download disk full (the fast halt in get/workers.rs): when the
/// min-free guard is armed AND the output volume is still under its
/// floor, prefer the guard's existing hold over a hard Failed - the job
/// goes back to the queue like a pause, the runner's own pick gate then
/// pauses everything with the live "disk" hold until space frees, and
/// the resume continues from the journal without refetching a byte.
/// Returns true when the job was parked (the caller returns). False =
/// guard off, probe unavailable, or space already freed: the caller
/// falls through and files the distinct failure instead - requeueing
/// then would just re-pick and re-fail in a loop (a quota or a
/// read-only share never comes back on its own). Lifted verbatim out of
/// `spawn_download_worker`'s tail task in tasks.rs for the size gate
/// (the §91 rule: the gate forces fixes into helpers), and it lives
/// with the free-space measurement it is built on.
pub(crate) async fn park_on_full_disk(
    d: &Arc<Daemon>,
    job: &Arc<Mutex<Job>>,
    err: Option<&anyhow::Error>,
    on_disk_bytes: u64,
) -> bool {
    let disk_full_hold = err.is_some_and(|e| crate::serve::disk_full_mid_download(&e.to_string()))
        && !job.lock_ok().tombstone
        && {
            let min = d.min_free.load(Ordering::Relaxed);
            min > 0 && {
                let out = d.out_dir();
                let probe = tokio::task::spawn_blocking(move || free_bytes(&out));
                matches!(
                    tokio::time::timeout(std::time::Duration::from_secs(2), probe).await,
                    Ok(Ok(Some(free))) if free < min
                )
            }
        };
    if !disk_full_hold {
        return false;
    }
    {
        let mut j = job.lock_ok();
        j.state = JobState::Queued;
        j.downloaded_bytes = on_disk_bytes;
        info!(
            target: "guard",
            "{} stopped on a full disk - parked back in the queue \
             ({:.2} GB already on disk); the min-free hold takes it \
             from here",
            j.nzo_id,
            on_disk_bytes as f64 / 1e9
        );
    }
    d.note_event(
        "disk",
        "a download stopped early because the disk filled - it is \
         back in the queue and resumes once space is freed"
            .to_string(),
    );
    d.save_queue();
    true
}

//! §129 perf lane: the process-global gates the engine's post-network
//! tail consults when more than one job's tail can run at once.
//!
//! Two resources live here, both deliberately global for the same reason
//! `eatvol`'s mode is - the repair pass and the disk-unpack ladder run
//! several layers below anything that holds a `Daemon`:
//!
//! 1. **The heavy-CPU permit.** One permit, taken by the repair pass and
//!    the disk re-extract ladder. Two concurrent single-core repairs are
//!    tolerable today, but the sibling §129 MD5-parallelization bullet
//!    makes each repair want every core, and two of those fight. Verify
//!    read-backs, unlock probes, renames and sweeps never take it. A
//!    tail waiting for the permit sits with its activity token unchanged
//!    (it is genuinely "repairing", just queued for the cores).
//!
//! 2. **The per-filesystem outstanding-need ledger.** Concurrent on-disk
//!    unpacks multiply peak usage, and the §101 forecast reads FREE
//!    bytes - two concurrent forecasts would both count the same free
//!    space and both conclude they fit. Each disk unpack registers what
//!    it still needs against its output volume; `eatvol::forecast` and
//!    the admission check both subtract OTHER jobs' registered need
//!    from free. Admission WAITS (never fails) when the unpack would fit
//!    alone but not beside the registered need - the §123 ENOSPC verdict
//!    stays the backstop, we just do not engineer avoidable failures.
//!
//! A job's own registration is excluded from what it reads via a
//! thread-local, the same shape as `eatvol`'s ARMED cell and safe for
//! the same reason: the forecast and the ladder run on the tail's own
//! driving thread.

use std::cell::Cell;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use crate::MutexExt;

// ---------------------------------------------------------------------
// The heavy-CPU permit
// ---------------------------------------------------------------------

fn cpu_sem() -> &'static Arc<tokio::sync::Semaphore> {
    static SEM: OnceLock<Arc<tokio::sync::Semaphore>> = OnceLock::new();
    SEM.get_or_init(|| Arc::new(tokio::sync::Semaphore::new(1)))
}

/// Take the heavy-CPU permit from async code (the settle/repair path).
/// Held for the scope of the returned permit; FIFO-fair across waiters.
pub(crate) async fn heavy_cpu() -> tokio::sync::OwnedSemaphorePermit {
    cpu_sem()
        .clone()
        .acquire_owned()
        .await
        .expect("the heavy-CPU semaphore is never closed")
}

/// Take the heavy-CPU permit from sync code (the disk-unpack ladder,
/// which already runs blocking-style on its task's thread). Polls
/// rather than parking a runtime primitive on a thread it does not own.
pub(crate) fn heavy_cpu_blocking() -> tokio::sync::OwnedSemaphorePermit {
    loop {
        match cpu_sem().clone().try_acquire_owned() {
            Ok(p) => return p,
            Err(_) => std::thread::sleep(std::time::Duration::from_millis(200)),
        }
    }
}

// ---------------------------------------------------------------------
// The per-filesystem outstanding-need ledger
// ---------------------------------------------------------------------

struct Need {
    id: u64,
    vol: u64,
    bytes: u64,
}

fn ledger() -> &'static Mutex<Vec<Need>> {
    static LEDGER: OnceLock<Mutex<Vec<Need>>> = OnceLock::new();
    LEDGER.get_or_init(|| Mutex::new(Vec::new()))
}

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

thread_local! {
    /// The registration owned by the tail driving THIS thread (0 =
    /// none), so its own need is never subtracted from its own view.
    static MINE: Cell<u64> = const { Cell::new(0) };
}

/// One key per filesystem: the device id where the platform gives one,
/// a hash of the path's root component otherwise. Two directories on
/// the same volume must collide here - that is the point.
pub(crate) fn vol_key(dir: &Path) -> u64 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if let Ok(m) = std::fs::metadata(dir) {
            return m.dev();
        }
    }
    use std::hash::{Hash, Hasher};
    let mut h = std::hash::DefaultHasher::new();
    // Windows: the drive letter / UNC prefix is the volume identity.
    dir.components().next().hash(&mut h);
    h.finish()
}

/// Bytes OTHER tails have registered against `dir`'s filesystem.
pub(crate) fn other_need(dir: &Path) -> u64 {
    let vol = vol_key(dir);
    let mine = MINE.with(|m| m.get());
    ledger()
        .lock_ok()
        .iter()
        .filter(|n| n.vol == vol && n.id != mine)
        .map(|n| n.bytes)
        .fold(0u64, u64::saturating_add)
}

/// RAII registration of one unpack's outstanding need. Dropped at the
/// end of the disk stage; restores the thread's previous registration
/// so a nested pass cannot orphan the outer one.
pub(crate) struct NeedGuard {
    id: u64,
    prev: u64,
}

impl Drop for NeedGuard {
    fn drop(&mut self) {
        if self.id == 0 {
            return;
        }
        ledger().lock_ok().retain(|n| n.id != self.id);
        MINE.with(|m| m.set(self.prev));
    }
}

fn register_locked(dir: &Path, bytes: u64) -> NeedGuard {
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    ledger().lock_ok().push(Need {
        id,
        vol: vol_key(dir),
        bytes,
    });
    let prev = MINE.with(|m| m.replace(id));
    NeedGuard { id, prev }
}

/// Admit one disk unpack needing `needed` bytes on `dir`'s filesystem.
///
/// Three outcomes, decided against live figures each pass:
/// - fits beside the other tails' registered need: register and go;
/// - does not fit even ALONE: register and go anyway - waiting cannot
///   help, and the §101 eat decision / §123 ENOSPC verdict own that
///   case exactly as they do today;
/// - fits alone but not beside the others: WAIT here (the caller's
///   activity token already says what stage this is), re-checking as
///   the other tails release their registrations.
///
/// A waiter holds no registration while it waits, so two admissions can
/// never deadlock on each other.
pub(crate) fn admit_unpack(dir: &Path, needed: u64, margin: u64) -> NeedGuard {
    if needed == 0 {
        return NeedGuard { id: 0, prev: 0 };
    }
    let mut said = false;
    loop {
        let free = crate::serve::free_bytes(dir).unwrap_or(u64::MAX);
        let want = needed.saturating_add(margin);
        let others = other_need(dir);
        if free >= want.saturating_add(others) || free < want {
            return register_locked(dir, needed);
        }
        if !said {
            said = true;
            tracing::info!(
                target: "extract",
                "unpack needs {:.1} GB but {:.1} GB is already promised to other \
                 finishing jobs on this disk - waiting for them to release it",
                needed as f64 / 1e9,
                others as f64 / 1e9
            );
        }
        std::thread::sleep(std::time::Duration::from_secs(2));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // One test on purpose: the ledger is process-global and the unit
    // suite runs in parallel, so sequenced assertions about "nobody
    // else has registered" only hold inside a single test body.
    #[test]
    fn ledger_excludes_self_sums_others_and_restores_on_drop() {
        let dir = std::env::temp_dir();
        let a = register_locked(&dir, 5_000_000_000);
        // On this thread `a` is MINE - invisible to our own read.
        assert_eq!(other_need(&dir), 0);
        // A second thread sees a's need but not its own.
        let d2 = dir.clone();
        std::thread::spawn(move || {
            let _b = register_locked(&d2, 3_000_000_000);
            assert_eq!(other_need(&d2), 5_000_000_000);
        })
        .join()
        .unwrap();
        // Nested registration restores the outer one on drop.
        let outer_id = MINE.with(|m| m.get());
        {
            let _inner = register_locked(&dir, 2);
            assert_ne!(MINE.with(|m| m.get()), outer_id);
        }
        assert_eq!(MINE.with(|m| m.get()), outer_id);
        drop(a);
        assert_eq!(MINE.with(|m| m.get()), 0);
        assert_eq!(other_need(&dir), 0);
        // Zero need admits without registering anything.
        let g = admit_unpack(&dir, 0, 0);
        assert_eq!(g.id, 0);
    }
}

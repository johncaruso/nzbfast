//! Scratch-directory guard for the integration suites and the `smart`
//! unit tests (which include this same file via `#[path]` - one guard,
//! not two). `crates/nzbkit/tests/scratch/mod.rs` is a copy; keep the
//! two in step.
//!
//! Every test that puts a `nzbfast-*` directory in the OS temp dir holds
//! one of these for the test's lifetime: the directory is recreated fresh
//! on attach and removed again on drop - the historical leak was ~90k
//! dirs (~360 GB) of scratch in $TMPDIR over five days, and on NTFS a
//! leaked `set_len` reservation is real clusters held for the rest of
//! the run (the §142 red's blast radius). The removal is a plain
//! `remove_dir_all`, never the Trash: routing temp paths through the
//! Trash raced in-flight calls into Finder "-43" dialogs once already.
//!
//! A PANICKING test keeps its tree: the failure someone is about to
//! debug lives in there, and deleting it during unwind destroys the
//! evidence. The kept path is printed to stderr, so it lands in the
//! failing test's captured output.
//!
//! Attaching also sweeps stale `nzbfast-*` directories older than a day
//! (once per test process), so scratch from crashed or SIGKILLed runs -
//! and the trees kept by failing tests above - still gets reclaimed by
//! the next run.

use std::path::{Path, PathBuf};
use std::sync::Once;
use std::time::{Duration, SystemTime};

/// Age beyond which an unclaimed `nzbfast-*` temp dir is presumed dead.
/// Generous enough that no live run (or concurrent session's run) is ever
/// swept: the longest suites finish in minutes, not days.
const STALE_AFTER: Duration = Duration::from_secs(24 * 60 * 60);

/// RAII guard for one test scratch directory.
pub struct ScratchDir {
    path: PathBuf,
}

impl ScratchDir {
    /// Recreate `path` empty and return a guard that removes it on drop.
    ///
    /// The first attach in the process also sweeps day-old `nzbfast-*`
    /// siblings left behind by runs that died without unwinding.
    pub fn attach(path: &Path) -> ScratchDir {
        sweep_stale_siblings();
        let _ = std::fs::remove_dir_all(path);
        std::fs::create_dir_all(path).unwrap();
        ScratchDir {
            path: path.to_path_buf(),
        }
    }
}

impl std::ops::Deref for ScratchDir {
    type Target = Path;
    fn deref(&self) -> &Path {
        &self.path
    }
}

impl AsRef<Path> for ScratchDir {
    fn as_ref(&self) -> &Path {
        &self.path
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!("scratch kept for inspection: {}", self.path.display());
            return;
        }
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn sweep_stale_siblings() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let Ok(entries) = std::fs::read_dir(std::env::temp_dir()) else {
            return;
        };
        let cutoff = SystemTime::now() - STALE_AFTER;
        for entry in entries.flatten() {
            if !entry
                .file_name()
                .to_str()
                .is_some_and(|n| n.starts_with("nzbfast-") || n.starts_with("nzbkit-"))
            {
                continue;
            }
            let Ok(meta) = entry.metadata() else { continue };
            // The mtime of a directory moves whenever its top level does,
            // so anything a live run touches stays out of reach.
            if meta.is_dir() && meta.modified().is_ok_and(|m| m < cutoff) {
                let _ = std::fs::remove_dir_all(entry.path());
            }
        }
    });
}

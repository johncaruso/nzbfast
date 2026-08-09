//! Housekeeping the daemon does to itself: sweeping spool NZBs no job
//! refers to any more, and restarting in place.
//!
//! Split out of serve/mod.rs by TODO 106 phase 4 - the code is verbatim,
//! only visibility changed.

use super::*;

/// Delete spool NZBs that no job refers to any more.
///
/// The spool copy is written BEFORE `save_queue()` records the job, so a
/// crash between the two orphans the file permanently and nothing ever
/// looked for it. Metadata-only "library" jobs keep theirs by design and
/// are indistinguishable from an orphan by name alone, which is exactly
/// why this works from the live set of referenced paths rather than from
/// any naming rule.
///
/// Only files whose name looks like ours are considered, and only ones
/// older than a grace period, so a job being enqueued right now (spool
/// written, not yet in the queue) cannot be swept out from under itself.
#[cfg(feature = "indexer")]
pub(super) fn sweep_orphan_spool_nzbs(d: &Arc<Daemon>) -> usize {
    const GRACE_SECS: u64 = 3600;
    let referenced: std::collections::HashSet<PathBuf> = d
        .queue
        .lock()
        .unwrap()
        .iter()
        .chain(d.history.lock_ok().iter())
        .map(|j| j.lock_ok().nzb_path.clone())
        .collect();
    let Ok(rd) = std::fs::read_dir(&d.spool) else {
        return 0;
    };
    let now = std::time::SystemTime::now();
    let mut removed = 0;
    for e in rd.flatten() {
        let path = e.path();
        if path.extension().and_then(|x| x.to_str()) != Some("nzb") {
            continue;
        }
        let Some(stem) = path.file_name().and_then(|x| x.to_str()) else {
            continue;
        };
        if !stem.starts_with("SABnzbd_nzo_nzbfast") {
            continue; // not one of ours: leave it entirely alone
        }
        if referenced.contains(&path) {
            continue;
        }
        let old = e
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| now.duration_since(t).ok())
            .is_some_and(|age| age.as_secs() > GRACE_SECS);
        if old && std::fs::remove_file(&path).is_ok() {
            removed += 1;
        }
    }
    if removed > 0 {
        info!(target: "spool", "removed {removed} orphaned NZB(s) no job referred to");
    }
    removed
}

/// Replace this process with a fresh copy of the same command line.
///
/// `exec` does not return on success: the kernel swaps the image and the
/// new binary starts from main with our pid. That is what makes this safe
/// for a network daemon - there is no window in which two processes both
/// want the port. The listening socket is closed for us because Rust
/// opens sockets CLOEXEC.
///
/// Note it picks up a REPLACED binary on disk, so this doubles as
/// "restart onto the version I just installed".
///
/// If exec fails there is nothing sensible left to do: the queue is
/// already persisted and the daemon is paused, so exiting is closer to
/// the user's intent (they asked for a restart) than carrying on in a
/// half-stopped state. Whatever supervises us - Docker, systemd, the
/// tray - brings it back.
#[cfg(unix)]
pub(super) fn restart_in_place(
    exe: &std::path::Path,
    args: &[std::ffi::OsString],
    cwd: Option<&std::path::Path>,
) {
    use std::os::unix::process::CommandExt as _;
    let mut cmd = std::process::Command::new(exe);
    cmd.args(args);
    if let Some(d) = cwd {
        cmd.current_dir(d);
    }
    // exec replaces the image without running any exit handler, so the
    // log tee has to be drained here or the last lines before a restart
    // die in its pipe - and then UNINSTALLED, or the replacement image
    // inherits the dead pipe as its stdout and a launcher-attached
    // daemon.log never sees another line (restore_for_exec drains
    // first).
    nzbkit::logtee::restore_for_exec();
    let err = cmd.exec(); // only returns on failure
    error!(
        target: "restart",
        "could not re-exec {}: {err} - exiting instead",
        exe.display()
    );
    std::process::exit(1);
}

#[cfg(not(unix))]
pub(super) fn restart_in_place(
    _exe: &std::path::Path,
    _args: &[std::ffi::OsString],
    _cwd: Option<&std::path::Path>,
) {
    // Unreachable: the handler refuses restart off Unix before spawning.
    warn!(target: "restart", "not supported on this platform");
}

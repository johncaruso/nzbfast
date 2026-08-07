//! Running a post-processing script: a child with a real deadline, its
//! pipes drained so it cannot wedge on a full buffer, and a bounded tail
//! of its stderr kept for the failure report.
//!
//! Split out of serve/mod.rs by TODO 106 phase 4 - the code is verbatim,
//! only visibility changed.

use super::*;

/// Run a child to completion with a deadline, draining its pipes.
///
/// `Command::output()` has no timeout, so a post-processing script that
/// hung held its `spawn_blocking` thread for the life of the daemon, and
/// one per completed job after that. Returns `(None, _)` when the
/// deadline was hit and the child killed; `secs == 0` waits forever,
/// which is what someone running a multi-hour transcode wants.
///
/// stderr is drained by its own thread rather than polled: a child that
/// fills the 64 KB pipe buffer blocks on the write, so waiting on the
/// process alone would turn any chatty script into a timeout. stdout is
/// drained too, and thrown away - nothing reads it, and a script that
/// prints for a living should not be able to spend the daemon's memory
/// proving it.
///
/// Only the LAST [`SCRIPT_ERR_TAIL`] bytes of stderr are kept. The whole
/// stream used to accumulate in a `String`, so an accidental
/// `while true; do echo …; done` grew the daemon until it died - well
/// before any deadline could stop it.
///
/// Two things the deadline has to survive, both of them ordinary
/// post-script shapes rather than hostile ones:
///
///  - A script that backgrounds work (`transcode & `) and exits. The
///    descendant INHERITS stdout/stderr, so the pipes stay open after
///    the direct child is gone and a `join` on the drain threads blocked
///    until the descendant finished. That join ran on the daemon's
///    blocking pool, one leaked worker per completed job, and the pool
///    is finite. The drains are therefore never joined - they are given
///    a short grace and then abandoned, holding nothing but a bounded
///    ring.
///  - The same script when the deadline expires. `Child::kill` signals
///    the direct child alone, so on unix the child is given its own
///    process group and the whole group is signalled. Windows keeps the
///    single-process kill (a job object is the equivalent, and is a
///    bigger change than this fix warrants).
pub(super) fn run_capped(
    mut cmd: std::process::Command,
    secs: u64,
) -> std::io::Result<(Option<std::process::ExitStatus>, String)> {
    use std::process::Stdio;
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // Own process group, so the deadline can reach what the script
    // spawned. Inherited by every descendant that does not deliberately
    // leave it.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        cmd.process_group(0);
    }
    let mut child = cmd.spawn()?;
    let tail = Arc::new(Mutex::new(BoundedTail::default()));
    // Detached on purpose: see the doc comment. Each thread owns its pipe
    // and exits when the last writer closes it, whenever that is.
    if let Some(r) = child.stdout.take() {
        std::thread::spawn(move || drain_to_nowhere(r));
    }
    if let Some(r) = child.stderr.take() {
        let tail = tail.clone();
        std::thread::spawn(move || drain_into(r, &tail));
    }
    let deadline = (secs > 0).then(|| Instant::now() + std::time::Duration::from_secs(secs));
    let status = loop {
        if let Some(st) = child.try_wait()? {
            break Some(st);
        }
        if deadline.is_some_and(|d| Instant::now() >= d) {
            #[cfg(unix)]
            unsafe {
                // Negative pid = the whole group. The direct child is
                // killed by the same signal, so no separate kill needed;
                // fall back to it if the group send fails.
                if libc::kill(-(child.id() as i32), libc::SIGKILL) != 0 {
                    let _ = child.kill();
                }
            }
            #[cfg(not(unix))]
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    };
    // The child is gone; its own writes are already in the ring or in
    // flight. A short grace collects the tail end without waiting on any
    // descendant that may still hold the pipe open.
    std::thread::sleep(std::time::Duration::from_millis(50));
    let stderr = tail.lock_ok().tail_text();
    Ok((status, stderr))
}

/// How much of a script's stderr is worth keeping. Enough for a stack
/// trace or a usage message, which is all the log line quotes.
pub(super) const SCRIPT_ERR_TAIL: usize = 8 << 10;

/// The last [`SCRIPT_ERR_TAIL`] bytes written to it, and nothing else.
#[derive(Default)]
pub(super) struct BoundedTail {
    pub(super) buf: std::collections::VecDeque<u8>,
    pub(super) dropped: usize,
}

impl BoundedTail {
    pub(super) fn push(&mut self, bytes: &[u8]) {
        self.buf.extend(bytes);
        while self.buf.len() > SCRIPT_ERR_TAIL {
            self.buf.pop_front();
            self.dropped += 1;
        }
    }

    /// The kept tail as text, prefixed with what was dropped. Not a
    /// `Display` impl: this is a lossy read-out of a byte ring for one
    /// log line, not a rendering of the value.
    pub(super) fn tail_text(&self) -> String {
        let text =
            String::from_utf8_lossy(&self.buf.iter().copied().collect::<Vec<u8>>()).into_owned();
        if self.dropped == 0 {
            text
        } else {
            // Say what was cut, or a truncated trace reads as the whole
            // story - the interesting line may be the one that went.
            format!("[…{} earlier bytes dropped…]{text}", self.dropped)
        }
    }
}

pub(super) fn drain_into(mut r: impl std::io::Read, tail: &Mutex<BoundedTail>) {
    let mut buf = [0u8; 8192];
    while let Ok(n) = r.read(&mut buf) {
        if n == 0 {
            return;
        }
        tail.lock_ok().push(&buf[..n]);
    }
}

pub(super) fn drain_to_nowhere(mut r: impl std::io::Read) {
    let mut buf = [0u8; 8192];
    while matches!(r.read(&mut buf), Ok(n) if n > 0) {}
}

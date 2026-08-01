//! Self-tee of stdout+stderr into an in-memory ring buffer, so the
//! daemon can serve its own recent log to the dashboard (mode=log) -
//! nothing to configure, works regardless of how the process was
//! launched. Unix: dup2 both fds onto a pipe; a reader thread echoes
//! every line to the ORIGINAL stdout (so terminals/redirects still see
//! it) and keeps the last `CAP` lines. On non-unix the tee is a no-op
//! and the ring stays empty (the dashboard says so).

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};

const CAP: usize = 2000;

/// Handshake line [`drain`] writes down the pipe. Control bytes, so it
/// cannot collide with anything a program or a child process prints; the
/// reader swallows it rather than echoing it or ringing it.
const DRAIN_MARK: &[u8] = b"\x01nzbfast-logtee-drain\x01";

/// Count of drain marks the reader has swallowed, plus the condvar it
/// notifies. Present only while the tee is installed.
static DRAIN: OnceLock<(Mutex<u64>, Condvar)> = OnceLock::new();

/// Longest [`drain`] waits for the reader to catch up. Echoing whatever
/// a pipe can hold takes microseconds; the cap only exists so a reader
/// thread that has already died cannot hold an exiting process open.
const DRAIN_WAIT: std::time::Duration = std::time::Duration::from_millis(500);

/// M32: size cap for a REDIRECTED stdout log file, bytes.
/// Every packaging surface except the Mac app (which rotates its own
/// daemon.log at 5 MB) points stdout at a file - launchd plist, brew
/// services, the Windows installer - and none of them rotate, so an
/// error storm can fill the disk. When the echo target is a regular
/// file past the cap, it is truncated in place with a notice line.
/// NZBFAST_LOG_CAP_MB overrides (0 = uncapped).
fn log_cap_bytes() -> u64 {
    std::env::var("NZBFAST_LOG_CAP_MB")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(50)
        .saturating_mul(1 << 20)
}

static RING: OnceLock<Arc<Mutex<VecDeque<String>>>> = OnceLock::new();

/// Lines ever captured, counting the ones already evicted from the ring.
/// Monotonic, so a caller can bracket a span of output (see [`mark`] and
/// [`since`]) instead of guessing at a line count after the fact.
static SEEN: AtomicU64 = AtomicU64::new(0);

/// Last `n` captured lines, oldest first.
pub fn tail(n: usize) -> Vec<String> {
    match RING.get() {
        None => Vec::new(),
        Some(r) => {
            let g = r.lock().unwrap();
            g.iter().skip(g.len().saturating_sub(n)).cloned().collect()
        }
    }
}

/// A cursor into the captured output, to be paired with [`since`].
///
/// Taken BEFORE the work whose output a caller wants to keep. The ring is
/// global stdout, so a plain `tail(n)` after the fact is a guess at both
/// ends: too small a window truncates the block, too large a one drags in
/// whatever the daemon's background lanes happened to print first.
pub fn mark() -> u64 {
    SEEN.load(Ordering::Relaxed)
}

/// Lines captured since `mark`, oldest first, at most `max` of them
/// (keeping the LAST `max` - a failure block ends with its verdict).
///
/// Returns what survives: the ring holds only `CAP` lines, so a span that
/// outran it comes back short rather than wrong.
pub fn since(mark: u64, max: usize) -> Vec<String> {
    let Some(r) = RING.get() else { return Vec::new() };
    let g = r.lock().unwrap();
    let want = span_len(mark, SEEN.load(Ordering::Relaxed), g.len(), max);
    g.iter().skip(g.len() - want).cloned().collect()
}

/// How many of the ring's newest lines belong to the span `mark..seen`.
///
/// Split out because every term here can outrun another: a span longer
/// than `CAP` has already lost its front, a caller's `max` may be
/// smaller still, and a `mark` taken before a ring that has since been
/// re-created (or simply a nonsense value) must not underflow into
/// "everything". Clamped in that order, and never past what the ring
/// actually holds - the result indexes it.
fn span_len(mark: u64, seen: u64, held: usize, max: usize) -> usize {
    seen.saturating_sub(mark).min(held as u64).min(max as u64) as usize
}

/// True when the tee is capturing on this platform.
pub fn active() -> bool {
    RING.get().is_some()
}

/// Trim one trailing CR/LF and lossily decode a raw captured line. A single
/// undecodable byte becomes U+FFFD - never a dropped line. (Bug sweep: the
/// old `lines()` reader returned Err on the first non-UTF-8 byte, which
/// killed the tee thread and silently took the daemon down with it.)
fn ring_line(buf: &[u8]) -> String {
    String::from_utf8_lossy(trim_newline(buf)).into_owned()
}

/// One captured line without its trailing CR/LF.
fn trim_newline(buf: &[u8]) -> &[u8] {
    let mut end = buf.len();
    if end > 0 && buf[end - 1] == b'\n' {
        end -= 1;
    }
    if end > 0 && buf[end - 1] == b'\r' {
        end -= 1;
    }
    &buf[..end]
}

/// Install the tee. Call once, early; further calls are no-ops.
pub fn install() {
    #[cfg(unix)]
    {
        if RING.get().is_some() {
            return;
        }
        let ring: Arc<Mutex<VecDeque<String>>> = Arc::new(Mutex::new(VecDeque::new()));
        unsafe {
            let mut fds = [0i32; 2];
            if libc::pipe(fds.as_mut_ptr()) != 0 {
                return;
            }
            let (rd, wr) = (fds[0], fds[1]);
            // Keep a copy of the real stdout for the echo.
            let orig = libc::dup(1);
            if orig < 0 || libc::dup2(wr, 1) < 0 || libc::dup2(wr, 2) < 0 {
                return;
            }
            libc::close(wr);
            // Only once the pipe is really in place: a drain with no
            // reader behind it would print its own handshake.
            let _ = DRAIN.set((Mutex::new(0), Condvar::new()));
            let ring2 = ring.clone();
            std::thread::spawn(move || {
                use std::io::{BufRead, BufReader, Write};
                use std::os::unix::io::FromRawFd;
                let mut src = BufReader::new(std::fs::File::from_raw_fd(rd));
                let mut echo = std::fs::File::from_raw_fd(orig);
                // Read raw bytes, NOT `lines()`. `BufRead::lines()` yields
                // Err(InvalidData) on the first non-UTF-8 byte, and a
                // legacy-encoded RAR/PAR2 filename reaches here whenever a
                // child (unrar/par2, run with inherited stdio) prints one.
                // The old `let Ok(line) = line else { break }` then exited
                // this thread, closing the pipe's read end - so the
                // daemon's next print hit EPIPE and panicked, with the
                // panic message lost down the same dead pipe (silent death).
                // read_until only stops on EOF or a genuine read error.
                let mut buf: Vec<u8> = Vec::with_capacity(256);
                // Size-cap bookkeeping for a redirected regular file:
                // fstat only every ~1 MB echoed, not per line.
                let cap = log_cap_bytes();
                let echo_is_file =
                    cap > 0 && echo.metadata().map(|m| m.is_file()).unwrap_or(false);
                let mut since_check: u64 = 0;
                loop {
                    buf.clear();
                    match src.read_until(b'\n', &mut buf) {
                        Ok(0) | Err(_) => break, // pipe closed, or read error
                        Ok(_) => {}
                    }
                    if trim_newline(&buf) == DRAIN_MARK {
                        // A drain handshake, not output: everything
                        // written before it has now been echoed.
                        if let Some((n, cv)) = DRAIN.get() {
                            *n.lock().unwrap() += 1;
                            cv.notify_all();
                        }
                        continue;
                    }
                    if echo_is_file {
                        since_check += buf.len() as u64;
                        if since_check >= 1 << 20 {
                            since_check = 0;
                            if echo.metadata().map(|m| m.len() > cap).unwrap_or(false) {
                                // Truncate in place: the fd is a plain
                                // redirect (not O_APPEND), and this thread
                                // is the file's only writer, so rewinding
                                // is safe. History is sacrificed to keep
                                // the disk alive - the ring still holds
                                // the recent tail for the dashboard.
                                use std::io::Seek;
                                let _ = echo.set_len(0);
                                let _ = echo.seek(std::io::SeekFrom::Start(0));
                                let _ = echo.write_all(
                                    format!(
                                        "[log] size cap {} MB reached - file truncated (NZBFAST_LOG_CAP_MB overrides)\n",
                                        cap >> 20
                                    )
                                    .as_bytes(),
                                );
                            }
                        }
                    }
                    // Echo the exact bytes so terminals/redirects still see
                    // byte-for-byte what was written (newline included).
                    let _ = echo.write_all(&buf);
                    // The ring keeps a lossy, newline-trimmed copy for the
                    // dashboard - U+FFFD in place of undecodable bytes,
                    // never a lost line.
                    let line = ring_line(&buf);
                    let mut g = ring2.lock().unwrap();
                    if g.len() >= CAP {
                        g.pop_front();
                    }
                    g.push_back(line);
                    // Bumped under the ring lock so `since` cannot read a
                    // count that disagrees with the lines it can see.
                    SEEN.fetch_add(1, Ordering::Relaxed);
                }
            });
            // Every exit path drains, including the ones nobody writes:
            // a panic, a bail out of main, `process::exit` in a handler.
            // atexit runs on all of them (never on a signal, where there
            // is nothing to be done anyway).
            libc::atexit(drain_at_exit);
        }
        let _ = RING.set(ring);
    }
}

#[cfg(unix)]
extern "C" fn drain_at_exit() {
    drain();
}

/// Wait until the reader has echoed everything written to stdout/stderr
/// so far.
///
/// Without this the last thing a process says is the thing most likely to
/// be lost: the bytes sit in the pipe, unread, and exiting takes the
/// reader thread down with the process. A fatal error printed on the way
/// out (an empty API key file, a panic) reached the terminal only if the
/// reader happened to be scheduled in time - under load it usually was
/// not, so the user saw a failed start with no reason given.
pub fn drain() {
    use std::io::Write;
    // Ordinary buffered output first: it is not in the pipe yet.
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();
    let Some((count, cv)) = DRAIN.get() else {
        return;
    };
    // Read the count before the mark goes down the pipe. Nothing is held
    // across the write: a full pipe would block us there, and the reader
    // needs this lock to bump the count. A bump we miss in the gap is not
    // a lost wakeup either - the wait tests the counter, not an event.
    let before = *count.lock().unwrap();
    {
        let mut out = std::io::stdout().lock();
        if out.write_all(DRAIN_MARK).is_err() || writeln!(out).is_err() || out.flush().is_err() {
            return;
        }
    }
    // The pipe is FIFO: once the mark comes back, so has everything
    // written before it.
    let seen = count.lock().unwrap();
    let _ = cv.wait_timeout_while(seen, DRAIN_WAIT, |n| *n == before);
}

#[cfg(test)]
mod tests {
    use super::{ring_line, span_len, CAP};

    /// The span a failed job snapshots has to survive every way its ends
    /// can disagree - the ring is global, bounded, and older than any one
    /// caller's mark.
    #[test]
    fn a_marked_span_never_outruns_the_ring() {
        // The ordinary case: 40 lines printed since the mark, all held.
        assert_eq!(span_len(100, 140, 500, 160), 40);
        // Longer than the ring: only what survives comes back, not a
        // count that would index past the front.
        assert_eq!(span_len(0, 10_000, CAP, 160), 160);
        assert_eq!(span_len(0, 10_000, CAP, 100_000), CAP);
        // The caller's own ceiling wins when it is the smallest.
        assert_eq!(span_len(100, 140, 500, 10), 10);
        // A mark from the future (a re-created ring, a bogus value)
        // saturates to zero instead of wrapping to "everything".
        assert_eq!(span_len(500, 140, 500, 160), 0);
        // Nothing printed since the mark: an empty snapshot, not the tail
        // of somebody else's job.
        assert_eq!(span_len(140, 140, 500, 160), 0);
    }

    #[test]
    fn ring_line_survives_non_utf8_and_trims_newline() {
        assert_eq!(ring_line(b"hello\n"), "hello");
        assert_eq!(ring_line(b"hello\r\n"), "hello");
        assert_eq!(ring_line(b"no newline"), "no newline");
        assert_eq!(ring_line(b""), "");
        // A legacy-encoded filename byte (0xFF) off an unrar/par2 line is
        // decoded lossily, NOT dropped - the line that used to kill the tee.
        let out = ring_line(b"unpacking \xFF.rar\n");
        assert!(out.starts_with("unpacking ") && out.ends_with(".rar"));
        assert!(out.contains('\u{FFFD}'));
    }
}

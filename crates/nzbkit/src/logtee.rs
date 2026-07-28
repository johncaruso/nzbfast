//! Self-tee of stdout+stderr into an in-memory ring buffer, so the
//! daemon can serve its own recent log to the dashboard (mode=log) -
//! nothing to configure, works regardless of how the process was
//! launched. Unix: dup2 both fds onto a pipe; a reader thread echoes
//! every line to the ORIGINAL stdout (so terminals/redirects still see
//! it) and keeps the last `CAP` lines. On non-unix the tee is a no-op
//! and the ring stays empty (the dashboard says so).

use std::collections::VecDeque;
use std::sync::{Arc, Mutex, OnceLock};

const CAP: usize = 2000;

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

/// True when the tee is capturing on this platform.
pub fn active() -> bool {
    RING.get().is_some()
}

/// Trim one trailing CR/LF and lossily decode a raw captured line. A single
/// undecodable byte becomes U+FFFD - never a dropped line. (Bug sweep: the
/// old `lines()` reader returned Err on the first non-UTF-8 byte, which
/// killed the tee thread and silently took the daemon down with it.)
fn ring_line(buf: &[u8]) -> String {
    let mut end = buf.len();
    if end > 0 && buf[end - 1] == b'\n' {
        end -= 1;
    }
    if end > 0 && buf[end - 1] == b'\r' {
        end -= 1;
    }
    String::from_utf8_lossy(&buf[..end]).into_owned()
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
                }
            });
        }
        let _ = RING.set(ring);
    }
}

#[cfg(test)]
mod tests {
    use super::ring_line;

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

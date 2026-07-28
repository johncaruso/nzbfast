//! nzbfast patch 10 (see VENDORING.md): total-cost bounds for one request.
//!
//! Patch 4 gave every accepted socket `SO_RCVTIMEO`/`SO_SNDTIMEO`. Those are
//! *inactivity* timeouts for one blocking syscall, and the kernel restarts the
//! timer on every byte that moves - so a peer that dribbles one byte every 20 s
//! never trips them and can hold a worker for as long as it likes. Four such
//! connections are enough to take the whole HTTP surface down, and the drop-
//! drain of an unread body reaches this with no authentication and no
//! body-reading handler at all (`POST /nonexistent` with a `Content-Length`).
//!
//! What actually separates a hostile peer from a slow one is the *sustained
//! rate*, not the duration: a real 256 MiB NZB upload over a bad link still
//! moves tens of KiB/s, while the drip attack moves 0.05 B/s. So the bound here
//! is a minimum sustained rate measured over time genuinely spent blocked,
//! after a grace period long enough that a short hiccup costs nothing.

use std::io::{Error as IoError, ErrorKind, Read, Result as IoResult, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

fn timed_out(what: &'static str) -> IoError {
    IoError::new(ErrorKind::TimedOut, what)
}

/// Has `moved` bytes over `spent` fallen below `min_rate` bytes/second?
///
/// Answers "no" until `grace` has passed, so a slow start is free. Milliseconds
/// rather than seconds, so the check has teeth well inside the first second.
fn too_slow(moved: u64, spent: Duration, grace: Duration, min_rate: u64) -> bool {
    if spent <= grace {
        return false;
    }
    let owed = u128::from(min_rate).saturating_mul(spent.as_millis()) / 1000;
    u128::from(moved) < owed
}

/// Wraps the socket a request body is read from, and fails the read once the
/// body is either taking too long outright or arriving below the minimum
/// sustained rate.
///
/// Installed *beneath* `EqualReader`/`Decoder`, so it bounds the handler's own
/// reads, the small-body pre-read, the chunked decoder, and - the
/// unauthenticated one - `EqualReader`'s drop-drain, all from one place.
pub struct DeadlineReader<R> {
    inner: R,
    started: Instant,
    read: u64,
    grace: Duration,
    min_rate: u64,
    hard: Duration,
}

impl<R: Read> DeadlineReader<R> {
    pub fn new(inner: R, grace: Duration, min_rate: u64, hard: Duration) -> Self {
        DeadlineReader {
            inner,
            started: Instant::now(),
            read: 0,
            grace,
            min_rate,
            hard,
        }
    }
}

impl<R: Read> Read for DeadlineReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        // Checked BEFORE the read, so the bound is the deadline plus at most
        // one socket read timeout rather than being open-ended.
        let elapsed = self.started.elapsed();
        if elapsed > self.hard {
            return Err(timed_out("request body exceeded the total time allowed"));
        }
        if too_slow(self.read, elapsed, self.grace, self.min_rate) {
            return Err(timed_out("request body below the minimum sustained rate"));
        }
        let n = self.inner.read(buf)?;
        self.read += n as u64;
        Ok(n)
    }
}

/// Wraps a response writer and fails it once the peer stops draining the
/// socket fast enough to be believable.
///
/// The clock counts only time spent *inside* `write`/`flush`, never wall time,
/// because a legitimate `/stream` response spends minutes blocked in the
/// reader waiting for articles to land - and that must not look like a stalled
/// client. What it does catch is the peer that reads just enough to keep
/// resetting `SO_SNDTIMEO`: 8 KiB every 25 s turns a 242 KiB dashboard into a
/// twelve-minute hold on one of four workers.
pub struct DeadlineWriter<W> {
    inner: W,
    blocked: Duration,
    written: u64,
    grace: Duration,
    min_rate: u64,
}

impl<W: Write> DeadlineWriter<W> {
    pub fn new(inner: W, grace: Duration, min_rate: u64) -> Self {
        DeadlineWriter {
            inner,
            blocked: Duration::from_secs(0),
            written: 0,
            grace,
            min_rate,
        }
    }
}

impl<W: Write> Write for DeadlineWriter<W> {
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        if too_slow(self.written, self.blocked, self.grace, self.min_rate) {
            return Err(timed_out("response below the minimum sustained rate"));
        }
        let at = Instant::now();
        let result = self.inner.write(buf);
        self.blocked += at.elapsed();
        if let Ok(n) = result {
            self.written += n as u64;
        }
        result
    }

    fn flush(&mut self) -> IoResult<()> {
        let at = Instant::now();
        let result = self.inner.flush();
        self.blocked += at.elapsed();
        result
    }
}

/// Marks a connection unreusable unless the body it wraps was read to its own
/// end.
///
/// A chunked body that nobody decodes to the terminating chunk - a 404 on a
/// chunked POST, say - leaves undecoded bytes on the wire. Handing that
/// connection back to header parsing means the next "request line" comes out of
/// the middle of a body, which is precisely the desynchronisation a
/// `Content-Length`-framing proxy in front gets to resolve the other way. There
/// is no safe place to resume, so we close instead.
pub struct DesyncGuard<R> {
    inner: R,
    finished: bool,
    desynced: Arc<AtomicBool>,
}

impl<R: Read> DesyncGuard<R> {
    pub fn new(inner: R, desynced: Arc<AtomicBool>) -> Self {
        DesyncGuard {
            inner,
            finished: false,
            desynced,
        }
    }
}

impl<R: Read> Read for DesyncGuard<R> {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        let n = self.inner.read(buf)?;
        if n == 0 {
            self.finished = true;
        }
        Ok(n)
    }
}

impl<R> Drop for DesyncGuard<R> {
    fn drop(&mut self) {
        if !self.finished {
            self.desynced.store(true, Ordering::Release);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn a_rate_above_the_floor_is_never_too_slow() {
        // 100 KiB in 10 s against a 8 KiB/s floor, grace already spent.
        assert!(!too_slow(
            100 * 1024,
            Duration::from_secs(10),
            Duration::from_secs(1),
            8 * 1024
        ));
    }

    #[test]
    fn the_drip_rate_is_too_slow_once_grace_expires() {
        // Two bytes in 31 s is the four-connection body-drip attack.
        let grace = Duration::from_secs(30);
        assert!(!too_slow(2, Duration::from_secs(29), grace, 8 * 1024));
        assert!(too_slow(2, Duration::from_secs(31), grace, 8 * 1024));
    }

    #[test]
    fn sub_second_rates_are_measured_too() {
        // 1 byte in 500 ms against 8 KiB/s: owed 4096, so yes.
        assert!(too_slow(
            1,
            Duration::from_millis(500),
            Duration::from_millis(1),
            8 * 1024
        ));
    }

    #[test]
    fn a_prompt_body_reads_normally() {
        let mut r = DeadlineReader::new(
            Cursor::new(b"hello".to_vec()),
            Duration::from_secs(30),
            8 * 1024,
            Duration::from_secs(3600),
        );
        let mut got = Vec::new();
        r.read_to_end(&mut got).unwrap();
        assert_eq!(got, b"hello");
    }

    #[test]
    fn an_expired_hard_deadline_fails_the_read() {
        let mut r = DeadlineReader::new(
            Cursor::new(b"hello".to_vec()),
            Duration::from_secs(30),
            8 * 1024,
            Duration::from_secs(0),
        );
        let mut got = Vec::new();
        assert_eq!(
            r.read_to_end(&mut got).unwrap_err().kind(),
            ErrorKind::TimedOut
        );
    }

    /// A writer whose calls block for `per_call` and move `moved` bytes each.
    struct SlowSink {
        per_call: Duration,
        moved: usize,
    }

    impl Write for SlowSink {
        fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
            std::thread::sleep(self.per_call);
            Ok(buf.len().min(self.moved))
        }
        fn flush(&mut self) -> IoResult<()> {
            Ok(())
        }
    }

    /// The peer that reads just enough to keep resetting SO_SNDTIMEO: every write
    /// returns, so no idle timeout ever fires, but almost nothing moves. That is
    /// how a 242 KiB dashboard response became a twelve-minute hold on one of
    /// four workers.
    #[test]
    fn a_slow_reader_fails_the_response_on_sustained_rate() {
        let mut w = DeadlineWriter::new(
            SlowSink {
                per_call: Duration::from_millis(60),
                moved: 1,
            },
            Duration::from_millis(100),
            8 * 1024,
        );
        let buf = [0u8; 4096];
        let mut failed = None;
        for _ in 0..200 {
            if let Err(e) = w.write(&buf) {
                failed = Some(e);
                break;
            }
        }
        let e = failed.expect("a ~16 B/s reader was allowed to hold the response");
        assert_eq!(e.kind(), ErrorKind::TimedOut);
    }

    /// The /stream non-regression, and the whole reason this counts time spent
    /// INSIDE write rather than wall time.
    ///
    /// A progressive response spends minutes in the READER waiting for articles
    /// to land, then writes promptly whenever it has bytes - so the gaps here are
    /// between the write calls, not inside them. Against wall time this is
    /// indistinguishable from the attack above, and failing it would break
    /// playback of anything still downloading.
    #[test]
    fn gaps_between_writes_do_not_count_against_the_response() {
        let mut w = DeadlineWriter::new(
            SlowSink {
                per_call: Duration::from_millis(0),
                moved: 4096,
            },
            Duration::from_millis(20),
            8 * 1024,
        );
        let buf = [0u8; 4096];
        for i in 0..10 {
            // The article wait: far longer than the grace, and none of it is
            // this response's fault.
            std::thread::sleep(Duration::from_millis(50));
            let n = w
                .write(&buf)
                .unwrap_or_else(|e| panic!("write {} failed on a healthy peer: {}", i, e));
            assert_eq!(n, buf.len());
        }
        assert!(
            w.blocked < Duration::from_millis(20),
            "wall time leaked into the blocked-write clock: {:?}",
            w.blocked
        );
    }

    #[test]
    fn an_unfinished_body_desyncs_the_connection() {
        let flag = Arc::new(AtomicBool::new(false));
        {
            let mut g = DesyncGuard::new(Cursor::new(b"hello".to_vec()), flag.clone());
            let mut one = [0u8; 1];
            g.read_exact(&mut one).unwrap();
        }
        assert!(flag.load(Ordering::Acquire), "a short body must close the connection");
    }

    #[test]
    fn a_body_read_to_eof_keeps_the_connection() {
        let flag = Arc::new(AtomicBool::new(false));
        {
            let mut g = DesyncGuard::new(Cursor::new(b"hello".to_vec()), flag.clone());
            let mut got = Vec::new();
            g.read_to_end(&mut got).unwrap();
        }
        assert!(!flag.load(Ordering::Acquire));
    }
}

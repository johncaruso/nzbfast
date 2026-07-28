use std::io::Read;
use std::io::Result as IoResult;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::channel;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// A `Reader` that reads exactly the number of bytes from a sub-reader.
///
/// If the limit is reached, it returns EOF. If the limit is not reached
/// when the destructor is called, the remaining bytes will be read and
/// thrown away.
pub struct EqualReader<R>
where
    R: Read,
{
    reader: R,
    size: usize,
    last_read_signal: Sender<IoResult<()>>,
    /// nzbfast patch 11 (see VENDORING.md): how many unread body bytes are worth
    /// discarding to keep this connection alive. Above it we close instead.
    max_drain: usize,
    /// nzbfast patch 11: and how long discarding them may take, whatever rate
    /// they arrive at.
    max_drain_time: Duration,
    /// nzbfast patch 11: set when this reader is dropped with the body short of
    /// its declared end, so the connection is closed rather than reused.
    desynced: Option<Arc<AtomicBool>>,
}

impl<R> EqualReader<R>
where
    R: Read,
{
    pub fn new(reader: R, size: usize) -> (EqualReader<R>, Receiver<IoResult<()>>) {
        let (tx, rx) = channel();

        let r = EqualReader {
            reader,
            size,
            last_read_signal: tx,
            // Unbounded drain and no connection to protect: the defaults keep
            // this constructor's behaviour for the crate's own unit tests, which
            // read from a `Cursor` and have no socket behind them.
            max_drain: usize::MAX,
            max_drain_time: Duration::from_secs(u64::from(u32::MAX)),
            desynced: None,
        };

        (r, rx)
    }

    /// nzbfast patch 11 (see VENDORING.md): attach the socket-backed connection
    /// this body belongs to, so a body that is not consumed to its declared end
    /// closes the connection instead of desynchronising it.
    pub fn with_connection_guard(
        mut self,
        max_drain: usize,
        max_drain_time: Duration,
        desynced: Arc<AtomicBool>,
    ) -> Self {
        self.max_drain = max_drain;
        self.max_drain_time = max_drain_time;
        self.desynced = Some(desynced);
        self
    }

    fn desync(&self) {
        if let Some(flag) = &self.desynced {
            flag.store(true, Ordering::Release);
        }
    }
}

impl<R> Read for EqualReader<R>
where
    R: Read,
{
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        if self.size == 0 {
            return Ok(0);
        }

        let buf = if buf.len() < self.size {
            buf
        } else {
            &mut buf[..self.size]
        };

        match self.reader.read(buf) {
            Ok(len) => {
                self.size -= len;
                Ok(len)
            }
            err @ Err(_) => err,
        }
    }
}

impl<R> Drop for EqualReader<R>
where
    R: Read,
{
    fn drop(&mut self) {
        let mut remaining_to_read = self.size;
        if remaining_to_read == 0 {
            // The handler read the whole body: nothing to discard, and the
            // connection is exactly where the next request starts.
            return;
        }

        // nzbfast patch 11 (see VENDORING.md): a body too big to be worth
        // discarding closes the connection instead.
        //
        // Draining is only ever a courtesy that lets the socket be reused, and
        // patch 10 already stops a hostile body from making that courtesy
        // unbounded in TIME. This is the byte half of the same bound: past the
        // cap the honest answer is that we are not reading a gigabyte to save
        // one keep-alive, so mark the connection unreusable and let it close.
        //
        // The marking is not optional. Handing a connection back with body bytes
        // still on the wire means the next "request line" is read out of the
        // middle of a body - the same desynchronisation patch 6 closed on the
        // rejected-framing path, and reachable here whenever a drain stops
        // short, which upstream also did silently on any read error.
        if remaining_to_read > self.max_drain {
            self.desync();
            self.last_read_signal.send(Ok(())).ok();
            return;
        }

        // nzbfast patch 1 (see VENDORING.md): drain through a FIXED,
        // reused buffer.
        //
        // Upstream allocates `vec![0; remaining_to_read]` - the whole
        // *declared* Content-Length, in one zeroed allocation, on whatever
        // thread drops the Request. A client that declares a huge body and
        // sends none therefore picks the server's allocation size:
        //   Content-Length: 140737488355328  (2^47) -> alloc_zeroed fails ->
        //     handle_alloc_error -> abort() - the whole process, from one
        //     ~90-byte unauthenticated request, on any handler that responds
        //     without reading the body (`GET /`, a 404, a 401).
        //   Content-Length: 18446744073709551615  -> capacity overflow panic,
        //     which kills the worker loop that was draining.
        // 64 KiB is plenty for discarding a body, and the loop below is
        // unchanged otherwise, so the drain semantics (and the
        // `last_read_signal` contract) are identical.
        const DRAIN_CHUNK: usize = 64 * 1024;
        let mut buf = vec![0u8; remaining_to_read.min(DRAIN_CHUNK)];
        let started = Instant::now();

        while remaining_to_read > 0 {
            // nzbfast patch 11: the time half of the drain bound, on its own
            // short clock. `body_grace` is for a body a handler is READING; a
            // body nobody wants gets no patience, or the four-connection drip
            // just buys that grace over and over for a body sized under the byte
            // cap.
            if started.elapsed() > self.max_drain_time {
                self.desync();
                self.last_read_signal
                    .send(Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "discarding the unread body took too long",
                    )))
                    .ok();
                break;
            }
            let want = remaining_to_read.min(buf.len());
            let buf = &mut buf[..want];

            match self.reader.read(buf) {
                // Both break arms leave the body short of its declared end -
                // an I/O error (including patch 10's rate/deadline failures) or
                // an early EOF - so the connection cannot be reused.
                Err(e) => {
                    self.desync();
                    self.last_read_signal.send(Err(e)).ok();
                    break;
                }
                Ok(0) => {
                    self.desync();
                    self.last_read_signal.send(Ok(())).ok();
                    break;
                }
                Ok(other) => {
                    remaining_to_read -= other;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::EqualReader;
    use std::io::Read;
    use std::time::Duration;

    /// Long enough that only the byte cap or an early EOF can end these drains.
    fn patient() -> Duration {
        Duration::from_secs(60)
    }

    #[test]
    fn test_limit() {
        use std::io::Cursor;

        let mut org_reader = Cursor::new("hello world".to_string().into_bytes());

        {
            let (mut equal_reader, _) = EqualReader::new(org_reader.by_ref(), 5);

            let mut string = String::new();
            equal_reader.read_to_string(&mut string).unwrap();
            assert_eq!(string, "hello");
        }

        let mut string = String::new();
        org_reader.read_to_string(&mut string).unwrap();
        assert_eq!(string, " world");
    }

    #[test]
    fn test_not_enough() {
        use std::io::Cursor;

        let mut org_reader = Cursor::new("hello world".to_string().into_bytes());

        {
            let (mut equal_reader, _) = EqualReader::new(org_reader.by_ref(), 5);

            let mut vec = [0];
            equal_reader.read_exact(&mut vec).unwrap();
            assert_eq!(vec[0], b'h');
        }

        let mut string = String::new();
        org_reader.read_to_string(&mut string).unwrap();
        assert_eq!(string, " world");
    }

    /// nzbfast patch 11: an unread body under the cap is still drained, so the
    /// connection stays usable and is NOT marked.
    #[test]
    fn a_small_unread_body_is_drained_and_keeps_the_connection() {
        use std::io::Cursor;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let mut org_reader = Cursor::new(b"hello world".to_vec());
        let flag = Arc::new(AtomicBool::new(false));
        {
            let (equal_reader, _) = EqualReader::new(org_reader.by_ref(), 5);
            let _equal_reader =
                equal_reader.with_connection_guard(1024, patient(), flag.clone());
        }
        assert!(!flag.load(Ordering::Acquire), "a drained body must not close the connection");

        let mut string = String::new();
        org_reader.read_to_string(&mut string).unwrap();
        assert_eq!(string, " world", "the drain must consume exactly the body");
    }

    /// ...and one over the cap is not drained at all, which is only safe because
    /// the connection is marked unreusable.
    #[test]
    fn an_oversized_unread_body_closes_the_connection_instead_of_draining() {
        use std::io::Cursor;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let mut org_reader = Cursor::new(b"hello world".to_vec());
        let flag = Arc::new(AtomicBool::new(false));
        {
            let (equal_reader, _) = EqualReader::new(org_reader.by_ref(), 5);
            let _equal_reader = equal_reader.with_connection_guard(2, patient(), flag.clone());
        }
        assert!(flag.load(Ordering::Acquire), "an undrained body must close the connection");

        // Nothing was consumed, which is exactly why reuse is forbidden.
        let mut string = String::new();
        org_reader.read_to_string(&mut string).unwrap();
        assert_eq!(string, "hello world");
    }

    /// A body that ends early is the desynchronisation case upstream handled
    /// silently: the drain breaks and the socket is handed back mid-body.
    #[test]
    fn a_short_body_closes_the_connection() {
        use std::io::Cursor;
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let mut org_reader = Cursor::new(b"hi".to_vec());
        let flag = Arc::new(AtomicBool::new(false));
        {
            let (equal_reader, _) = EqualReader::new(org_reader.by_ref(), 500);
            let _equal_reader =
                equal_reader.with_connection_guard(1024, patient(), flag.clone());
        }
        assert!(flag.load(Ordering::Acquire), "a body that hit EOF early must close the connection");
    }
}

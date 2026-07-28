use std::io::Error as IoError;
use std::io::ErrorKind;
use std::io::Result as IoResult;
use std::io::{Read, Write};

use std::sync::mpsc::channel;
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};

use std::mem;

pub struct SequentialReaderBuilder<R>
where
    R: Read + Send,
{
    inner: SequentialReaderBuilderInner<R>,
}

enum SequentialReaderBuilderInner<R>
where
    R: Read + Send,
{
    First(R),
    NotFirst(Receiver<R>),
}

pub struct SequentialReader<R>
where
    R: Read + Send,
{
    inner: SequentialReaderInner<R>,
    next: Sender<R>,
}

enum SequentialReaderInner<R>
where
    R: Read + Send,
{
    MyTurn(R),
    Waiting(Receiver<R>),
    Empty,
}

pub struct SequentialWriterBuilder<W>
where
    W: Write + Send,
{
    writer: Arc<Mutex<W>>,
    next_trigger: Option<Receiver<()>>,
}

pub struct SequentialWriter<W>
where
    W: Write + Send,
{
    trigger: Option<Receiver<()>>,
    writer: Arc<Mutex<W>>,
    on_finish: Sender<()>,
}

impl<R: Read + Send> SequentialReaderBuilder<R> {
    pub fn new(reader: R) -> SequentialReaderBuilder<R> {
        SequentialReaderBuilder {
            inner: SequentialReaderBuilderInner::First(reader),
        }
    }
}

impl<W: Write + Send> SequentialWriterBuilder<W> {
    pub fn new(writer: W) -> SequentialWriterBuilder<W> {
        SequentialWriterBuilder {
            writer: Arc::new(Mutex::new(writer)),
            next_trigger: None,
        }
    }
}

impl<R: Read + Send> Iterator for SequentialReaderBuilder<R> {
    type Item = SequentialReader<R>;

    fn next(&mut self) -> Option<SequentialReader<R>> {
        let (tx, rx) = channel();

        let inner = mem::replace(&mut self.inner, SequentialReaderBuilderInner::NotFirst(rx));

        match inner {
            SequentialReaderBuilderInner::First(reader) => Some(SequentialReader {
                inner: SequentialReaderInner::MyTurn(reader),
                next: tx,
            }),

            SequentialReaderBuilderInner::NotFirst(previous) => Some(SequentialReader {
                inner: SequentialReaderInner::Waiting(previous),
                next: tx,
            }),
        }
    }
}

impl<W: Write + Send> Iterator for SequentialWriterBuilder<W> {
    type Item = SequentialWriter<W>;
    fn next(&mut self) -> Option<SequentialWriter<W>> {
        let (tx, rx) = channel();
        let mut next_next_trigger = Some(rx);
        ::std::mem::swap(&mut next_next_trigger, &mut self.next_trigger);

        Some(SequentialWriter {
            trigger: next_next_trigger,
            writer: self.writer.clone(),
            on_finish: tx,
        })
    }
}

impl<R: Read + Send> SequentialReader<R> {
    /// nzbfast patch 11 (see VENDORING.md): take our turn on the socket WITHOUT
    /// consuming a byte.
    ///
    /// The connection parser needs a point where the previous request's body
    /// reader has definitely released the socket but nothing has been read yet:
    /// that is the only place it can still decide the connection is unreusable.
    /// Folding the hand-over into the first `read`, as upstream does, means the
    /// decision always comes one byte too late.
    pub fn acquire(&mut self) -> IoResult<()> {
        let received = match self.inner {
            SequentialReaderInner::MyTurn(_) => return Ok(()),
            SequentialReaderInner::Waiting(ref mut recv) => recv.recv(),
            SequentialReaderInner::Empty => {
                return Err(IoError::new(
                    ErrorKind::BrokenPipe,
                    "sequential reader already consumed",
                ))
            }
        };

        match received {
            Ok(reader) => {
                self.inner = SequentialReaderInner::MyTurn(reader);
                Ok(())
            }
            // The previous reader was dropped without handing the socket on -
            // a leaked or forgotten `Request`. Nothing will ever arrive, so say
            // so rather than panicking on the unwrap upstream had here.
            Err(_) => Err(IoError::new(
                ErrorKind::BrokenPipe,
                "the previous request never released the connection",
            )),
        }
    }
}

impl<R: Read + Send> Read for SequentialReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        self.acquire()?;
        match self.inner {
            SequentialReaderInner::MyTurn(ref mut reader) => reader.read(buf),
            // `acquire` returns Ok only in the MyTurn state.
            _ => unreachable!(),
        }
    }
}

impl<W: Write + Send> Write for SequentialWriter<W> {
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        // nzbfast patch 12 (see VENDORING.md): an Err here means the previous
        // writer was dropped without signalling - so it is our turn by default.
        // Upstream unwrapped, turning a leaked writer into a panic on whichever
        // worker happened to hold the next response.
        if let Some(v) = self.trigger.as_mut() {
            let _ = v.recv();
        }
        self.trigger = None;

        self.writer.lock().unwrap().write(buf)
    }

    fn flush(&mut self) -> IoResult<()> {
        if let Some(v) = self.trigger.as_mut() {
            let _ = v.recv();
        }
        self.trigger = None;

        self.writer.lock().unwrap().flush()
    }
}

impl<R> Drop for SequentialReader<R>
where
    R: Read + Send,
{
    fn drop(&mut self) {
        let inner = mem::replace(&mut self.inner, SequentialReaderInner::Empty);

        match inner {
            SequentialReaderInner::MyTurn(reader) => {
                self.next.send(reader).ok();
            }
            SequentialReaderInner::Waiting(recv) => {
                // nzbfast patch 12: if the socket never arrives there is nothing
                // to pass on, and the next reader's own `acquire` reports the
                // broken chain. Upstream unwrapped and panicked instead.
                if let Ok(reader) = recv.recv() {
                    self.next.send(reader).ok();
                }
            }
            SequentialReaderInner::Empty => (),
        }
    }
}

impl<W> Drop for SequentialWriter<W>
where
    W: Write + Send,
{
    fn drop(&mut self) {
        self.on_finish.send(()).ok();
    }
}

use std::io::Result as IoResult;
use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr};

use crate::connection::Connection;
#[cfg(any(feature = "ssl-openssl", feature = "ssl-rustls"))]
use crate::ssl::SslStream;

pub(crate) enum Stream {
    Http(Connection),
    #[cfg(any(feature = "ssl-openssl", feature = "ssl-rustls"))]
    Https(SslStream),
}

impl Stream {
    /// nzbfast patch 8 (see VENDORING.md): fallible split.
    ///
    /// This used to be `impl Clone`, whose signature cannot fail, so it
    /// spelled the `dup` as `try_clone().unwrap()`. `RefinedTcpStream::new`
    /// calls it on every accepted socket, from the server's ONE accept thread.
    /// Descriptor exhaustion is reachable without authenticating - just hold
    /// connections open - and it lands exactly here: `accept()` takes the last
    /// free descriptor and succeeds, then the `dup` fails with EMFILE and the
    /// unwrap panics the accept thread. HTTP never accepts again, even after
    /// the descriptors are released, and the transient-accept-error recovery
    /// (patch 3) cannot help because `accept()` itself did not fail.
    fn try_split(&self) -> IoResult<Self> {
        Ok(match self {
            Stream::Http(tcp_stream) => Stream::Http(tcp_stream.try_clone()?),
            #[cfg(any(feature = "ssl-openssl", feature = "ssl-rustls"))]
            Stream::Https(ssl_stream) => Stream::Https(ssl_stream.clone()),
        })
    }
}

impl From<Connection> for Stream {
    fn from(tcp_stream: Connection) -> Self {
        Stream::Http(tcp_stream)
    }
}

impl Stream {
    fn secure(&self) -> bool {
        match self {
            Stream::Http(_) => false,
            #[cfg(any(feature = "ssl-openssl", feature = "ssl-rustls"))]
            Stream::Https(_) => true,
        }
    }

    fn peer_addr(&mut self) -> IoResult<Option<SocketAddr>> {
        match self {
            Stream::Http(tcp_stream) => tcp_stream.peer_addr(),
            #[cfg(any(feature = "ssl-openssl", feature = "ssl-rustls"))]
            Stream::Https(ssl_stream) => ssl_stream.peer_addr(),
        }
    }

    fn shutdown(&mut self, how: Shutdown) -> IoResult<()> {
        match self {
            Stream::Http(tcp_stream) => tcp_stream.shutdown(how),
            #[cfg(any(feature = "ssl-openssl", feature = "ssl-rustls"))]
            Stream::Https(ssl_stream) => ssl_stream.shutdown(how),
        }
    }
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        match self {
            Stream::Http(tcp_stream) => tcp_stream.read(buf),
            #[cfg(any(feature = "ssl-openssl", feature = "ssl-rustls"))]
            Stream::Https(ssl_stream) => ssl_stream.read(buf),
        }
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        match self {
            Stream::Http(tcp_stream) => tcp_stream.write(buf),
            #[cfg(any(feature = "ssl-openssl", feature = "ssl-rustls"))]
            Stream::Https(ssl_stream) => ssl_stream.write(buf),
        }
    }

    fn flush(&mut self) -> IoResult<()> {
        match self {
            Stream::Http(tcp_stream) => tcp_stream.flush(),
            #[cfg(any(feature = "ssl-openssl", feature = "ssl-rustls"))]
            Stream::Https(ssl_stream) => ssl_stream.flush(),
        }
    }
}

pub struct RefinedTcpStream {
    stream: Stream,
    close_read: bool,
    close_write: bool,
}

impl RefinedTcpStream {
    /// Split an accepted socket into its read and write halves.
    ///
    /// Fallible (patch 8): the split dups the descriptor, which fails under
    /// FD exhaustion, and the caller is the accept thread - it must be able to
    /// drop this one connection and keep listening.
    pub(crate) fn new<S>(stream: S) -> IoResult<(RefinedTcpStream, RefinedTcpStream)>
    where
        S: Into<Stream>,
    {
        let stream: Stream = stream.into();

        let (read, write) = (stream.try_split()?, stream);

        let read = RefinedTcpStream {
            stream: read,
            close_read: true,
            close_write: false,
        };

        let write = RefinedTcpStream {
            stream: write,
            close_read: false,
            close_write: true,
        };

        Ok((read, write))
    }

    /// Returns true if this struct wraps around a secure connection.
    #[inline]
    pub(crate) fn secure(&self) -> bool {
        self.stream.secure()
    }

    pub(crate) fn peer_addr(&mut self) -> IoResult<Option<SocketAddr>> {
        self.stream.peer_addr()
    }
}

impl Drop for RefinedTcpStream {
    fn drop(&mut self) {
        if self.close_read {
            self.stream.shutdown(Shutdown::Read).ok();
        }

        if self.close_write {
            self.stream.shutdown(Shutdown::Write).ok();
        }
    }
}

impl Read for RefinedTcpStream {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        self.stream.read(buf)
    }
}

impl Write for RefinedTcpStream {
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        self.stream.write(buf)
    }

    fn flush(&mut self) -> IoResult<()> {
        self.stream.flush()
    }
}

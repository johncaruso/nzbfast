use ascii::AsciiString;

use std::io::Error as IoError;
use std::io::Result as IoResult;
use std::io::{BufReader, BufWriter, ErrorKind, Read};

use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use crate::common::{HTTPVersion, Method};
use crate::util::RefinedTcpStream;
use crate::util::{SequentialReader, SequentialReaderBuilder, SequentialWriterBuilder};
use crate::{Request, ServerLimits};

/// A ClientConnection is an object that will store a socket to a client
/// and return Request objects.
pub struct ClientConnection {
    // address of the client
    remote_addr: IoResult<Option<SocketAddr>>,

    // sequence of Readers to the stream, so that the data is not read in
    //  the wrong order
    source: SequentialReaderBuilder<BufReader<RefinedTcpStream>>,

    // sequence of Writers to the stream, to avoid writing response #2 before
    //  response #1
    sink: SequentialWriterBuilder<BufWriter<RefinedTcpStream>>,

    // Reader to read the next header from
    next_header_source: SequentialReader<BufReader<RefinedTcpStream>>,

    // set to true if we know that the previous request is the last one
    no_more_requests: bool,

    // true if the connection goes through SSL
    secure: bool,

    /// nzbfast patches 9-11 (see VENDORING.md): what this connection may cost.
    limits: Arc<ServerLimits>,

    /// nzbfast patch 10: absolute deadline for the request currently being
    /// parsed, armed by the first byte that arrives for it.
    request_deadline: Option<Instant>,

    /// nzbfast patch 10: request line plus header bytes read for the request
    /// currently being parsed.
    header_bytes: usize,

    /// nzbfast patch 11: set by a body reader that stopped short of the body's
    /// declared end. There is then no safe place for the next request to start,
    /// so the connection must close instead of being reused.
    desynced: Arc<AtomicBool>,
}

/// Why a header line could not be read. Separate from `ReadError` because the
/// request line is read before the HTTP version is known.
enum LineError {
    Io(IoError),
    TooLong,
}

/// Error that can happen when reading a request.
#[derive(Debug)]
enum ReadError {
    WrongRequestLine,
    WrongHeader(HTTPVersion),
    /// the client sent an unrecognized `Expect` header
    ExpectationFailed(HTTPVersion),
    /// nzbfast patch 5 (see VENDORING.md): a version this server does not
    /// speak, recognised BEFORE a response writer is handed out. Upstream
    /// detected it after building the `Request`, which self-deadlocked the
    /// connection - see the rejection site in `next()`.
    UnsupportedVersion(HTTPVersion),
    /// nzbfast patch 6 (see VENDORING.md): the request's framing headers are
    /// unusable (unparsable/oversized Content-Length, or Content-Length and
    /// Transfer-Encoding together). The body boundary is therefore unknown,
    /// so the connection cannot be reused.
    BadFraming(HTTPVersion),
    /// nzbfast patch 10 (see VENDORING.md): the request line is longer than the
    /// configured limit.
    RequestLineTooLong,
    /// nzbfast patch 10 (see VENDORING.md): one header line, the total header
    /// bytes, or the header count is over the configured limit.
    HeadersTooLarge(HTTPVersion),
    /// nzbfast patch 11 (see VENDORING.md): the previous request's body was not
    /// consumed to its declared end, so where the next request starts is
    /// unknown. Nothing more may be parsed on this connection.
    Desynced,
    ReadIoError(IoError),
}

impl ClientConnection {
    /// Creates a new `ClientConnection` that takes ownership of the `TcpStream`.
    pub fn new(
        write_socket: RefinedTcpStream,
        mut read_socket: RefinedTcpStream,
        limits: Arc<ServerLimits>,
    ) -> ClientConnection {
        let remote_addr = read_socket.peer_addr();
        let secure = read_socket.secure();

        let mut source = SequentialReaderBuilder::new(BufReader::with_capacity(1024, read_socket));
        let first_header = source.next().unwrap();

        ClientConnection {
            source,
            sink: SequentialWriterBuilder::new(BufWriter::with_capacity(1024, write_socket)),
            remote_addr,
            next_header_source: first_header,
            no_more_requests: false,
            secure,
            limits,
            request_deadline: None,
            header_bytes: 0,
            desynced: Arc::new(AtomicBool::new(false)),
        }
    }

    /// true if the connection is HTTPS
    ///
    /// Only the un-vendored TLS paths care: patch 12 gave plain and secure
    /// connections the same one-outstanding-request handshake, so the accept
    /// loop no longer branches on this.
    #[allow(dead_code)]
    pub fn secure(&self) -> bool {
        self.secure
    }

    /// Reads the next line from self.next_header_source.
    ///
    /// Reads until `CRLF` is reached. The next read will start
    ///  at the first byte of the new line.
    ///
    /// nzbfast patch 10 (see VENDORING.md): bounded in length and in time.
    ///
    /// Upstream read headers a byte at a time with no limit of any kind - no
    /// request-line length, no per-line length, no total header bytes, no header
    /// count and no clock. One unterminated ASCII header line could be grown
    /// until the allocator gave up, and a client sending one byte every 20 s held
    /// its parser thread forever while never tripping the socket's idle timeout.
    fn read_next_line(&mut self, max_len: usize) -> Result<AsciiString, LineError> {
        let mut buf = Vec::new();
        let mut prev_byte_was_cr = false;

        loop {
            let byte = self.next_header_source.by_ref().bytes().next();

            let byte = match byte {
                Some(b) => b.map_err(LineError::Io)?,
                None => {
                    return Err(LineError::Io(IoError::new(
                        ErrorKind::ConnectionAborted,
                        "Unexpected EOF",
                    )))
                }
            };

            // The clock starts at the first byte of the request, not when we
            // began waiting for one: an idle keep-alive connection stays governed
            // only by the socket's own read timeout, exactly as under patch 4.
            let deadline = match self.request_deadline {
                Some(deadline) => deadline,
                None => {
                    let deadline = Instant::now() + self.limits.header_deadline;
                    self.request_deadline = Some(deadline);
                    deadline
                }
            };
            // Checked per byte deliberately. A drip attack sends very few bytes,
            // so a cheaper every-N-bytes check would simply never fire.
            if Instant::now() > deadline {
                return Err(LineError::Io(IoError::new(
                    ErrorKind::TimedOut,
                    "request headers took too long",
                )));
            }

            self.header_bytes += 1;
            if buf.len() >= max_len || self.header_bytes > self.limits.max_header_bytes {
                return Err(LineError::TooLong);
            }

            if byte == b'\n' && prev_byte_was_cr {
                buf.pop(); // removing the '\r'
                return AsciiString::from_ascii(buf).map_err(|_| {
                    LineError::Io(IoError::new(
                        ErrorKind::InvalidInput,
                        "Header is not in ASCII",
                    ))
                });
            }

            prev_byte_was_cr = byte == b'\r';

            buf.push(byte);
        }
    }

    /// Reads a request from the stream.
    /// Blocks until the header has been read.
    fn read(&mut self) -> Result<Request, ReadError> {
        // nzbfast patch 11 (see VENDORING.md): take our turn on the socket, then
        // decide whether this connection may be reused at all - in that order,
        // and before a single byte is consumed.
        //
        // `acquire` returns once the previous request's body reader has released
        // the socket, which is also when it has finished deciding whether it left
        // unread body bytes behind. Handing a connection back in that state means
        // the next "request line" comes out of the middle of a body, which is the
        // same desynchronisation patch 6 closed on the rejected-framing path -
        // and it is what upstream did silently whenever a drain stopped short.
        self.next_header_source
            .acquire()
            .map_err(ReadError::ReadIoError)?;
        if self.desynced.load(Ordering::Acquire) {
            return Err(ReadError::Desynced);
        }

        // Patch 10's budget is per request, so re-arm it for this one.
        self.request_deadline = None;
        self.header_bytes = 0;

        let (method, path, version, headers) = {
            // reading the request line
            let (method, path, version) = {
                let line = match self.read_next_line(self.limits.max_request_line) {
                    Ok(line) => line,
                    Err(LineError::TooLong) => return Err(ReadError::RequestLineTooLong),
                    Err(LineError::Io(e)) => return Err(ReadError::ReadIoError(e)),
                };

                let (method, path, version) = parse_request_line(
                    line.as_str().trim(), // TODO: remove this conversion
                )?;
                // nzbfast patch 5 (see VENDORING.md): reject an unsupported
                // HTTP version HERE, before `self.sink.next()` below hands this
                // request a response writer.
                //
                // Upstream checked in `next()`, after `read()` had already
                // taken writer #1 and moved it into the `Request`. The 505 then
                // took writer #2 and printed through it synchronously - but
                // sequential writers block until the previous writer is
                // dropped, and writer #1 could not drop while the blocking
                // print held the frame that owned it. One perfectly
                // well-formed `GET / HTTP/2.0` therefore wedged its parser
                // thread forever, with no slow drip and no way for a socket
                // timeout to break it (the block is on a channel, not the
                // socket). Threads are spawned per connection, so repeating it
                // exhausts the process.
                if version > HTTPVersion(1, 1) {
                    return Err(ReadError::UnsupportedVersion(version));
                }
                (method, path, version)
            };

            // getting all headers
            let headers = {
                let mut headers = Vec::new();
                loop {
                    let line = match self.read_next_line(self.limits.max_header_line) {
                        Ok(line) => line,
                        Err(LineError::TooLong) => {
                            return Err(ReadError::HeadersTooLarge(version))
                        }
                        Err(LineError::Io(e)) => return Err(ReadError::ReadIoError(e)),
                    };

                    if line.is_empty() {
                        break;
                    };
                    // patch 10: a request may not carry an unbounded NUMBER of
                    // headers either, however short each one is.
                    if headers.len() >= self.limits.max_headers {
                        return Err(ReadError::HeadersTooLarge(version));
                    }
                    // nzbfast patch 7 (see VENDORING.md): parse the header line
                    // AS RECEIVED. `read_next_line` has already stripped CRLF,
                    // so the only thing `.trim()` removed here was leading
                    // whitespace - which is exactly what `Header`'s strict
                    // parser exists to reject (see its `test_strict_headers`,
                    // guarding RUSTSEC-2020-0031). Trimming first handed that
                    // parser a repaired line, so an obs-fold continuation
                    //     X: x
                    //      Transfer-Encoding: chunked
                    // arrived as a genuine Transfer-Encoding header. A proxy
                    // that still reads leading whitespace as continuation
                    // frames the message by Content-Length while we frame it
                    // as chunked - a request-smuggling desync straight through
                    // any path-authorising front end.
                    headers.push(match FromStr::from_str(line.as_str()) {
                        // TODO: remove this conversion
                        Ok(h) => h,
                        _ => return Err(ReadError::WrongHeader(version)),
                    });
                }

                headers
            };

            (method, path, version, headers)
        };

        // building the writer for the request
        let writer = self.sink.next().unwrap();

        // follow-up for next potential request
        let mut data_source = self.source.next().unwrap();
        std::mem::swap(&mut self.next_header_source, &mut data_source);

        // building the next reader
        let request = crate::request::new_request(
            self.secure,
            method,
            path,
            version.clone(),
            headers,
            // nzbfast patch 9 (see VENDORING.md): `peer_addr()` on an accepted
            // socket fails with ENOTCONN if the peer RST'd between accept() and
            // ClientConnection::new - which anyone can produce at will. Upstream
            // unwrapped it, so a bare connect-and-reset panicked the connection
            // thread. The address is optional in the request anyway (it always
            // is for UNIX listeners), so treat an unknowable peer as unknown.
            self.remote_addr.as_ref().ok().copied().flatten(),
            data_source,
            writer,
            Some(crate::request::ConnectionGuards {
                limits: self.limits.clone(),
                desynced: self.desynced.clone(),
            }),
        )
        .map_err(|e| {
            use crate::request;
            match e {
                request::RequestCreationError::CreationIoError(e) => ReadError::ReadIoError(e),
                request::RequestCreationError::ExpectationFailed => {
                    ReadError::ExpectationFailed(version)
                }
                request::RequestCreationError::BadFraming => ReadError::BadFraming(version),
            }
        })?;

        // return the request
        Ok(request)
    }
}

impl Iterator for ClientConnection {
    type Item = Request;

    /// Blocks until the next Request is available.
    /// Returns None when no new Requests will come from the client.
    // The `loop` below no longer loops: upstream's one `continue` arm was the
    // unsupported-version path, and patch 5 has to close that connection instead
    // (the rejected request's body was being parsed as another request). Kept as
    // a loop rather than unindented so the diff against upstream 0.12.0 stays
    // readable, which is the whole point of the patch markers.
    #[allow(clippy::never_loop)]
    fn next(&mut self) -> Option<Request> {
        use crate::{Response, StatusCode};

        // the client sent a "connection: close" header in this previous request
        //  or is using HTTP 1.0, meaning that no new request will come
        if self.no_more_requests {
            return None;
        }

        loop {
            let rq = match self.read() {
                Err(ReadError::WrongRequestLine) => {
                    let writer = self.sink.next().unwrap();
                    let response = Response::new_empty(StatusCode(400));
                    response
                        .raw_print(writer, HTTPVersion(1, 1), &[], false, None)
                        .ok();
                    return None; // we don't know where the next request would start,
                                 // se we have to close
                }

                Err(ReadError::WrongHeader(ver)) => {
                    let writer = self.sink.next().unwrap();
                    let response = Response::new_empty(StatusCode(400));
                    response.raw_print(writer, ver, &[], false, None).ok();
                    return None; // we don't know where the next request would start,
                                 // se we have to close
                }

                Err(ReadError::ReadIoError(ref err)) if err.kind() == ErrorKind::TimedOut => {
                    // request timeout
                    let writer = self.sink.next().unwrap();
                    let response = Response::new_empty(StatusCode(408));
                    response
                        .raw_print(writer, HTTPVersion(1, 1), &[], false, None)
                        .ok();
                    return None; // closing the connection
                }

                Err(ReadError::ExpectationFailed(ver)) => {
                    let writer = self.sink.next().unwrap();
                    let response = Response::new_empty(StatusCode(417));
                    response.raw_print(writer, ver, &[], true, None).ok();
                    return None; // TODO: should be recoverable, but needs handling in case of body
                }

                // nzbfast patch 5: answer 505 with the FIRST writer (no
                // Request exists yet, so nothing else holds one) and close.
                // Upstream `continue`d here, which was a second bug even
                // without the deadlock: the rejected request's body was never
                // consumed, so whatever followed it on the wire got parsed as
                // the next request.
                Err(ReadError::UnsupportedVersion(_ver)) => {
                    let writer = self.sink.next().unwrap();
                    let response = Response::from_string(
                        "This server only supports HTTP versions 1.0 and 1.1".to_owned(),
                    )
                    .with_status_code(StatusCode(505));
                    // Answer in 1.1, not in the version we just refused to
                    // speak - echoing it back would put "HTTP/2.0" on the
                    // status line of a response that is not HTTP/2 at all.
                    response
                        .raw_print(writer, HTTPVersion(1, 1), &[], false, None)
                        .ok();
                    return None;
                }

                // nzbfast patch 6: the body boundary is unknown, so there is no
                // safe place to start reading a follow-up request. Say so and
                // close rather than guessing.
                Err(ReadError::BadFraming(ver)) => {
                    let writer = self.sink.next().unwrap();
                    let response = Response::new_empty(StatusCode(400));
                    response.raw_print(writer, ver, &[], false, None).ok();
                    return None;
                }

                // nzbfast patch 10: over a header limit. Close in both cases -
                // we stopped reading mid-request, so we do not know where the
                // next one would begin.
                Err(ReadError::RequestLineTooLong) => {
                    let writer = self.sink.next().unwrap();
                    let response = Response::new_empty(StatusCode(414));
                    response
                        .raw_print(writer, HTTPVersion(1, 1), &[], false, None)
                        .ok();
                    return None;
                }

                Err(ReadError::HeadersTooLarge(ver)) => {
                    let writer = self.sink.next().unwrap();
                    let response = Response::new_empty(StatusCode(431));
                    response.raw_print(writer, ver, &[], false, None).ok();
                    return None;
                }

                // nzbfast patch 11: the previous request's body was not consumed
                // to its declared end. Its response has already gone out, and
                // there is no request here to answer - anything still on the wire
                // is body, not a request line. Just close.
                Err(ReadError::Desynced) => return None,

                Err(ReadError::ReadIoError(_)) => return None,

                Ok(rq) => rq,
            };

            // The version check that used to live here now runs in `read()`,
            // before a response writer is allocated (patch 5).

            // updating the status of the connection
            let connection_header = rq
                .headers()
                .iter()
                .find(|h| h.field.equiv("Connection"))
                .map(|h| h.value.as_str());

            let lowercase = connection_header.map(|h| h.to_ascii_lowercase());

            match lowercase {
                Some(ref val) if val.contains("close") => self.no_more_requests = true,
                Some(ref val) if val.contains("upgrade") => self.no_more_requests = true,
                Some(ref val)
                    if !val.contains("keep-alive") && *rq.http_version() == HTTPVersion(1, 0) =>
                {
                    self.no_more_requests = true
                }
                None if *rq.http_version() == HTTPVersion(1, 0) => self.no_more_requests = true,
                _ => (),
            };

            // returning the request
            return Some(rq);
        }
    }
}

/// Parses a "HTTP/1.1" string.
fn parse_http_version(version: &str) -> Result<HTTPVersion, ReadError> {
    let (major, minor) = match version {
        "HTTP/0.9" => (0, 9),
        "HTTP/1.0" => (1, 0),
        "HTTP/1.1" => (1, 1),
        "HTTP/2.0" => (2, 0),
        "HTTP/3.0" => (3, 0),
        _ => return Err(ReadError::WrongRequestLine),
    };

    Ok(HTTPVersion(major, minor))
}

/// Parses the request line of the request.
/// eg. GET / HTTP/1.1
fn parse_request_line(line: &str) -> Result<(Method, String, HTTPVersion), ReadError> {
    let mut parts = line.split(' ');

    let method = parts.next().and_then(|w| w.parse().ok());
    let path = parts.next().map(ToOwned::to_owned);
    let version = parts.next().and_then(|w| parse_http_version(w).ok());

    method
        .and_then(|method| Some((method, path?, version?)))
        .ok_or(ReadError::WrongRequestLine)
}

#[cfg(test)]
mod test {
    #[test]
    fn test_parse_request_line() {
        let (method, path, ver) = super::parse_request_line("GET /hello HTTP/1.1").unwrap();

        assert!(method == crate::Method::Get);
        assert!(path == "/hello");
        assert!(ver == crate::common::HTTPVersion(1, 1));

        assert!(super::parse_request_line("GET /hello").is_err());
        assert!(super::parse_request_line("qsd qsd qsd").is_err());
    }
}

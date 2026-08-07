//! Async NNTP client (RFC 3977) over TLS (rustls) or plain TCP.
//!
//! Design note: `send_*` and `read_*` are deliberately split so callers can
//! pipeline - write several `BODY` commands, then consume the responses in
//! order. NNTP responses arrive strictly in command order, which is what
//! makes pipelining safe. AUTHINFO is never pipelined (done once at connect).

use crate::sync::MutexExt;
use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

use crate::config::ServerConfig;

#[derive(Debug, thiserror::Error)]
pub enum NntpError {
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid TLS server name")]
    TlsName,
    #[error("connection closed by server")]
    Closed,
    /// The server refused to authenticate us. `kind` says whether that is
    /// worth retrying: see [`AuthRefusal`].
    #[error("authentication failed: {line}")]
    AuthFailed { kind: AuthRefusal, line: String },
    #[error("unexpected response to {cmd}: {line}")]
    Unexpected { cmd: String, line: String },
    /// The response echoed a message-id, and it is not the one the
    /// caller asked for. On a pipelined connection responses are
    /// attributed POSITIONALLY, so one dropped or reordered response
    /// desyncs the whole conversation and silently files every later
    /// body under the wrong article - this is the only check that can
    /// see it. A session-level failure, same as [`Unexpected`]: the
    /// socket's remaining responses cannot be trusted.
    ///
    /// [`Unexpected`]: NntpError::Unexpected
    #[error("response echoed a different message-id (asked for {expected}): {line}")]
    IdMismatch { expected: String, line: String },
    #[error("multiline response exceeded {0} bytes")]
    TooLarge(usize),
    #[error("timed out waiting for a server response")]
    Timeout,
}

/// Why a server refused to authenticate, which decides whether trying
/// again can ever help.
///
/// The reply CODE alone cannot tell these apart. RFC 4643 assigns 481 to
/// "authentication failed/rejected", but real providers overload it:
/// Giganews answers `481 max simultaneous IP addresses reached` for a
/// perfectly valid account that is simply at its cap, and the same 481
/// for a wrong password. So the free-form TEXT is the only signal, and
/// the classification is deliberately conservative - anything not
/// recognisably about capacity is treated as [`Permanent`], because
/// retrying a bad credential forever is the worse failure.
///
/// [`Permanent`]: AuthRefusal::Permanent
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthRefusal {
    /// Bad credentials, a disabled account, a blocked host. Retrying
    /// cannot fix it and hammering makes things worse, so the caller
    /// should stop using this server and say so loudly.
    Permanent,
    /// The account is fine but the server will not give us ANOTHER
    /// session right now: a simultaneous-connection or simultaneous-IP
    /// cap. Retrying at the same connection count re-provokes it; the
    /// useful response is to back off and ask for FEWER connections.
    Capacity,
}

/// Classify an AUTHINFO refusal from the server's own reply line.
///
/// Matched on the text because the codes are not diagnostic (see
/// [`AuthRefusal`]). Substrings are drawn from what real providers
/// actually send: Giganews `481 max simultaneous IP addresses reached`,
/// `502 too many connections`, Astraweb `481 Connection limit reached`,
/// and the RFC's own 482 "too many" family.
pub fn classify_auth_refusal(line: &str) -> AuthRefusal {
    let l = line.to_ascii_lowercase();
    const CAPACITY: &[&str] = &[
        "max simultaneous",
        "simultaneous ip",
        "too many connection",
        "too many session",
        "connection limit",
        "session limit",
        "concurrent connection",
        "maximum connections",
        "max connections",
        "connection count",
        "no more connections",
        "try again later",
    ];
    match CAPACITY.iter().any(|p| l.contains(p)) {
        true => AuthRefusal::Capacity,
        false => AuthRefusal::Permanent,
    }
}

/// Absolute ceiling on a single dot-terminated multiline response (article
/// body, OVER block, HEAD/CAPABILITIES). No legitimate response comes close
/// - real yEnc articles are well under a megabyte and even wide OVER ranges
/// are tens of MB - so this only ever trips on a buggy/hostile/MITM'd peer
/// that streams a body with no terminating `.` line. Without it a single
/// connection appends at link rate for the whole read_timeout window (multi-
/// GB at gigabit) before the timeout fires, and the bloated buffer is then
/// retained by the BufPool for the rest of the run.
pub const MAX_MULTILINE_BYTES: usize = 256 * 1024 * 1024;

/// Cap on a single status line. NNTP status lines are short (a code plus a
/// short message); 64 KiB is orders of magnitude over any real one and
/// exists only to bound a peer that never sends the terminating newline.
pub const MAX_STATUS_BYTES: usize = 64 * 1024;

/// A parsed status line, e.g. `222 0 <id> body follows`.
#[derive(Debug, Clone)]
pub struct Status {
    pub code: u16,
    pub line: String,
}

/// The message-id a status line echoes, when a plausible one is
/// present. RFC 3977 responses to BODY/ARTICLE/STAT echo the id
/// ("222 0 <id> body follows", "220 0 <id> article follows", and some
/// servers echo it on 430/423 refusals too) - but plenty of real
/// providers echo a bare `0` or omit the field entirely, so absence
/// means "no evidence", never "mismatch". Plausible = an
/// angle-bracketed token; anything else on the line is ignored.
pub fn echoed_message_id(line: &str) -> Option<&str> {
    line.split_ascii_whitespace()
        .find(|t| t.len() > 2 && t.starts_with('<') && t.ends_with('>'))
}

/// Enforce the echoed message-id against the id the caller asked for,
/// when the caller supplied one AND the line carries a plausible id
/// (see [`echoed_message_id`]). Case-insensitive: message-ids are
/// compared byte-wise everywhere else, but a server canonicalizing
/// case must not read as a desync. Applies to any status shape that
/// echoes an id - 222 (BODY), 220 (ARTICLE), and refusals (430/423,
/// Giganews's 451) alike.
fn check_echoed_id(st: &Status, expected: Option<&str>) -> Result<(), NntpError> {
    if let Some(exp) = expected
        && let Some(got) = echoed_message_id(&st.line)
        && !got.eq_ignore_ascii_case(exp)
    {
        return Err(NntpError::IdMismatch {
            expected: exp.to_string(),
            line: st.line.clone(),
        });
    }
    Ok(())
}

pub struct GroupInfo {
    pub count: u64,
    pub low: u64,
    pub high: u64,
}

/// One row of an OVER/XOVER response.
#[derive(Debug, Clone)]
pub struct OverEntry {
    pub number: u64,
    pub subject: String,
    pub from: String,
    pub message_id: String,
    pub bytes: u64,
    /// Unix time from the Date field (0 = unparseable).
    pub date: i64,
}

/// Decode one raw header line. Usenet headers are supposed to be ASCII
/// (RFC 2047 for anything else), but a real share of them are raw
/// ISO-8859-1: measured over 40,000 `free.pt` OVER lines, 1.0% are
/// non-ASCII and 99.5% of those are latin-1, not UTF-8.
///
/// `from_utf8_lossy` turns every one of those bytes into U+FFFD, which
/// both mangles the indexed title and destroys the exact bytes a Spotnet
/// signature covers (see [`crate::spot`]). A latin-1 fallback is lossless
/// and reversible - collapsing each char back to one byte recovers the
/// wire bytes exactly.
pub fn decode_header_line(line: &[u8]) -> std::borrow::Cow<'_, str> {
    match std::str::from_utf8(line) {
        Ok(s) => std::borrow::Cow::Borrowed(s),
        Err(_) => std::borrow::Cow::Owned(line.iter().map(|&b| b as char).collect()),
    }
}

/// Parse one raw OVER/XOVER response line. `None` for a line with too few
/// fields (including the empty tail a trailing newline leaves behind).
pub fn parse_over_line(line: &[u8]) -> Option<OverEntry> {
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    let text = decode_header_line(line);
    // number \t subject \t from \t date \t message-id \t refs \t bytes \t lines
    let f: Vec<&str> = text.split('\t').collect();
    if f.len() < 7 {
        return None;
    }
    Some(OverEntry {
        number: f[0].trim().parse().unwrap_or(0),
        subject: f[1].to_string(),
        from: f[2].to_string(),
        message_id: f[4].trim().to_string(),
        bytes: f[6].trim().parse().unwrap_or(0),
        date: parse_nntp_date(f[3]).unwrap_or(0),
    })
}

/// One row of a `LIST ACTIVE` response: the group plus the server's
/// current article-number range (high - low ≈ articles on the server).
#[derive(Debug, Clone)]
pub struct ActiveGroup {
    pub name: String,
    pub high: u64,
    pub low: u64,
    /// Posting status flag: 'y' posting allowed, 'n' not, 'm' moderated.
    pub status: char,
}

/// Parse a `LIST ACTIVE` body: one `name high low status` line per group.
/// Malformed lines are skipped - a 100k-group listing from a busy server
/// routinely carries a few junk entries and must not fail the whole fetch.
pub fn parse_list_active(raw: &[u8]) -> Vec<ActiveGroup> {
    let mut out = Vec::new();
    for line in String::from_utf8_lossy(raw).lines() {
        let mut f = line.split_whitespace();
        let (Some(name), Some(high), Some(low)) = (f.next(), f.next(), f.next()) else {
            continue;
        };
        if name.is_empty() || !name.is_ascii() {
            continue;
        }
        let (Ok(high), Ok(low)) = (high.parse::<u64>(), low.parse::<u64>()) else {
            continue;
        };
        // Same ingress guard as GROUP: article numbers never approach
        // 2^62, so an implausible high-water mark is a poisoned line.
        if high >= 1 << 62 {
            continue;
        }
        out.push(ActiveGroup {
            name: name.to_string(),
            high,
            low,
            status: f.next().and_then(|s| s.chars().next()).unwrap_or('y'),
        });
    }
    out
}

/// Parse a `LIST NEWSGROUPS` body: `name<ws>description` per line.
pub fn parse_list_newsgroups(raw: &[u8]) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in String::from_utf8_lossy(raw).lines() {
        let mut parts = line.splitn(2, ['\t', ' ']);
        let Some(name) = parts.next().filter(|n| !n.is_empty() && n.is_ascii()) else {
            continue;
        };
        let desc = parts.next().unwrap_or("").trim();
        // Placeholder descriptions ("?", "No description.") carry nothing.
        if desc.is_empty() || desc == "?" {
            continue;
        }
        out.push((name.to_string(), desc.to_string()));
    }
    out
}

/// RFC 5322 date as seen in overview lines ("Thu, 02 May 2024 12:34:56
/// +0000", optional weekday/seconds, alpha zones, "(CST)" comments,
/// two-digit years) → unix seconds. None if it doesn't look like a date.
pub fn parse_nntp_date(s: &str) -> Option<i64> {
    let s = s.split('(').next().unwrap_or(s);
    let toks: Vec<&str> = s
        .split([' ', ',', '\t'])
        .filter(|t| !t.is_empty())
        .collect();
    const MONTHS: [&str; 12] = [
        "jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec",
    ];
    let month_of = |t: &str| {
        let l = t.to_ascii_lowercase();
        MONTHS
            .iter()
            .position(|m| l.starts_with(m))
            .map(|i| i as i64 + 1)
    };
    let mi = toks
        .iter()
        .position(|t| t.len() >= 3 && month_of(t).is_some())?;
    let month = month_of(toks[mi])?;
    let day: i64 = toks.get(mi.checked_sub(1)?)?.parse().ok()?;
    if !(1..=31).contains(&day) {
        return None;
    }
    let mut year: i64 = toks.get(mi + 1)?.parse().ok()?;
    if year < 100 {
        year += if year >= 70 { 1900 } else { 2000 };
    }
    let mut hms = toks.get(mi + 2)?.split(':');
    let h: i64 = hms.next()?.parse().ok()?;
    let m: i64 = hms.next()?.parse().ok()?;
    let sec: i64 = hms.next().and_then(|v| v.parse().ok()).unwrap_or(0);
    // Bound before the arithmetic below: year, hour, minute and second come
    // from a POSTER-controlled Date header on every OVER row, and the civil-
    // days maths multiplies them (`era * 146097`, `days * 86400`, `h * 3600`).
    // A year of 300000000000 overflows i64 - a panic in a debug/test build,
    // and in release a wrapped timestamp that is stored as `first_posted` and
    // then drives retention masking and the oracle's age bucket.
    // `newznab::parse_rfc2822` already range-checks for exactly this reason.
    if !(1970..=3000).contains(&year)
        || !(0..=23).contains(&h)
        || !(0..=59).contains(&m)
        || !(0..=60).contains(&sec)
    {
        return None;
    }
    let offset = match toks.get(mi + 3).copied().unwrap_or("+0000") {
        // is_ascii guard: len() counts BYTES but z[1..3] slices a &str -
        // a Usenet-controlled zone like "+€x" panicked the OVER consumer.
        z if z.starts_with(['+', '-']) && z.len() == 5 && z.is_ascii() => {
            let hh: i64 = z[1..3].parse().unwrap_or(0);
            let mm: i64 = z[3..5].parse().unwrap_or(0);
            let v = hh * 3600 + mm * 60;
            if z.starts_with('-') { -v } else { v }
        }
        "EST" => -5 * 3600,
        "EDT" => -4 * 3600,
        "CST" => -6 * 3600,
        "CDT" => -5 * 3600,
        "MST" => -7 * 3600,
        "MDT" => -6 * 3600,
        "PST" => -8 * 3600,
        "PDT" => -7 * 3600,
        _ => 0, // GMT / UT / UTC / Z / unknown
    };
    // Days from 1970-01-01 (Howard Hinnant's civil-days algorithm).
    let (yy, mm) = if month <= 2 {
        (year - 1, month)
    } else {
        (year, month)
    };
    let era = if yy >= 0 { yy } else { yy - 399 } / 400;
    let yoe = yy - era * 400;
    let doy = (153 * ((mm + 9) % 12) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146097 + doe - 719468;
    Some(days * 86400 + h * 3600 + m * 60 + sec - offset)
}

trait Transport: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> Transport for T {}

/// True when a CAPABILITIES response advertises RFC 8054 DEFLATE
/// ("COMPRESS DEFLATE", possibly alongside other algorithms). Labels
/// are case-insensitive per RFC 3977 §9.5.
pub fn caps_support_compress_deflate(caps: &[String]) -> bool {
    caps.iter().any(|line| {
        let mut toks = line.split_whitespace();
        toks.next()
            .is_some_and(|k| k.eq_ignore_ascii_case("COMPRESS"))
            && toks.any(|a| a.eq_ignore_ascii_case("DEFLATE"))
    })
}

/// RFC 8054 framing: after "COMPRESS DEFLATE" → 206, BOTH directions of
/// the connection become raw DEFLATE streams (no zlib header, no
/// per-response framing). Reads decompress on the way in; writes buffer
/// compressed bytes locally and `poll_flush` emits a Z_SYNC_FLUSH so
/// the server sees a complete, decodable command per flush - without
/// the sync marker the encoder could sit on the tail of a command
/// indefinitely and the exchange would deadlock.
struct DeflateTransport<T> {
    inner: T,
    dec: flate2::Decompress,
    enc: flate2::Compress,
    /// Compressed wire bytes not yet fed to the decompressor.
    cbuf: Vec<u8>,
    cpos: usize,
    /// Decompressed bytes not yet handed to the caller.
    dbuf: Vec<u8>,
    dpos: usize,
    /// Compressed output not yet written to the wire. Bounded in
    /// practice: only commands ride the write path (tiny), and every
    /// `Connection::send` flushes.
    wbuf: Vec<u8>,
    wpos: usize,
    /// The peer ended its deflate stream (Z_FINISH) - serve what is
    /// decoded, then EOF.
    reof: bool,
    /// Sync-flush already emitted for the buffered writes - keeps a
    /// re-polled `poll_flush` (inner returned Pending) from appending
    /// one sync marker per wakeup.
    flushed: bool,
}

impl<T> DeflateTransport<T> {
    /// `leftover` = bytes a buffered reader slurped past the 206 status
    /// line - under RFC 8054 those are already deflate-stream bytes.
    fn new(inner: T, leftover: Vec<u8>) -> Self {
        DeflateTransport {
            inner,
            dec: flate2::Decompress::new(false),
            enc: flate2::Compress::new(flate2::Compression::default(), false),
            cbuf: leftover,
            cpos: 0,
            dbuf: Vec::new(),
            dpos: 0,
            wbuf: Vec::new(),
            wpos: 0,
            reof: false,
            flushed: true,
        }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for DeflateTransport<T> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::task::Poll;
        let me = self.get_mut();
        loop {
            // Serve already-decompressed bytes first.
            if me.dpos < me.dbuf.len() {
                let n = buf.remaining().min(me.dbuf.len() - me.dpos);
                buf.put_slice(&me.dbuf[me.dpos..me.dpos + n]);
                me.dpos += n;
                if me.dpos == me.dbuf.len() {
                    me.dbuf.clear();
                    me.dpos = 0;
                }
                return Poll::Ready(Ok(()));
            }
            if me.reof {
                return Poll::Ready(Ok(())); // nothing filled = EOF
            }
            // Refill compressed input from the wire when exhausted.
            if me.cpos == me.cbuf.len() {
                me.cbuf.clear();
                me.cpos = 0;
                let mut tmp = [0u8; 16 * 1024];
                let mut rb = tokio::io::ReadBuf::new(&mut tmp);
                match std::pin::Pin::new(&mut me.inner).poll_read(cx, &mut rb) {
                    Poll::Ready(Ok(())) => {
                        if rb.filled().is_empty() {
                            return Poll::Ready(Ok(())); // wire EOF
                        }
                        me.cbuf.extend_from_slice(rb.filled());
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }
            // Decompress what we have. Consuming input without producing
            // output is legal mid-block - the outer loop reads more wire.
            while me.cpos < me.cbuf.len() && !me.reof {
                me.dbuf.reserve(16 * 1024);
                let before_in = me.dec.total_in();
                let status = match me.dec.decompress_vec(
                    &me.cbuf[me.cpos..],
                    &mut me.dbuf,
                    flate2::FlushDecompress::None,
                ) {
                    Ok(s) => s,
                    // Corrupt stream: fail the connection cleanly - the
                    // caller reconnects uncompressed rather than parse
                    // garbage overview lines.
                    Err(e) => {
                        return Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            e,
                        )));
                    }
                };
                me.cpos += (me.dec.total_in() - before_in) as usize;
                match status {
                    flate2::Status::StreamEnd => me.reof = true,
                    // No forward progress possible (output space was just
                    // reserved, so it needs more input) - read the wire.
                    flate2::Status::BufError => break,
                    flate2::Status::Ok => {}
                }
            }
        }
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for DeflateTransport<T> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        use std::task::Poll;
        let me = self.get_mut();
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        me.flushed = false;
        loop {
            // compress_vec only fills spare capacity - reserve, and grow
            // on the (rare) round where deflate wanted more room.
            me.wbuf.reserve((buf.len() / 2 + 256).max(1024));
            let before = me.enc.total_in();
            if let Err(e) = me
                .enc
                .compress_vec(buf, &mut me.wbuf, flate2::FlushCompress::None)
            {
                return Poll::Ready(Err(std::io::Error::other(e)));
            }
            let used = (me.enc.total_in() - before) as usize;
            if used > 0 {
                return Poll::Ready(Ok(used));
            }
        }
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::task::Poll;
        let me = self.get_mut();
        if !me.flushed {
            // Z_SYNC_FLUSH: push everything buffered in the encoder plus
            // the 00 00 FF FF marker so the peer can decode NOW.
            loop {
                me.wbuf.reserve(4 * 1024);
                let cap = me.wbuf.capacity();
                if let Err(e) = me
                    .enc
                    .compress_vec(&[], &mut me.wbuf, flate2::FlushCompress::Sync)
                {
                    return Poll::Ready(Err(std::io::Error::other(e)));
                }
                // Spare room left over means the encoder is drained.
                if me.wbuf.len() < cap {
                    break;
                }
            }
            me.flushed = true;
        }
        while me.wpos < me.wbuf.len() {
            match std::pin::Pin::new(&mut me.inner).poll_write(cx, &me.wbuf[me.wpos..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::ErrorKind::WriteZero.into()));
                }
                Poll::Ready(Ok(n)) => me.wpos += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        me.wbuf.clear();
        me.wpos = 0;
        std::pin::Pin::new(&mut me.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::task::Poll;
        match self.as_mut().poll_flush(cx) {
            Poll::Ready(Ok(())) => {}
            other => return other,
        }
        std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Whether this CPU has hardware AES (AES-NI / ARMv8 crypto extensions).
/// Boxes without it - Raspberry Pi 4-class ARM, old x86 - do AES-GCM in
/// software at a fraction of ChaCha20-Poly1305's speed, and TLS covers
/// every downloaded byte.
fn aes_accelerated() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        std::arch::is_x86_feature_detected!("aes")
    }
    #[cfg(target_arch = "aarch64")]
    {
        std::arch::is_aarch64_feature_detected!("aes")
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        false
    }
}

/// Whether a suite is ChaCha20-Poly1305 (any TLS version).
fn is_chacha(s: &rustls::SupportedCipherSuite) -> bool {
    matches!(
        s.suite(),
        rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256
            | rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
            | rustls::CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    )
}

/// Whether a suite is AES-**128**-GCM (any TLS version).
fn is_aes128(s: &rustls::SupportedCipherSuite) -> bool {
    matches!(
        s.suite(),
        rustls::CipherSuite::TLS13_AES_128_GCM_SHA256
            | rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            | rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    )
}

/// The aws-lc-rs provider, tuned for bulk transfer.
///
/// TLS covers every downloaded byte, so the AEAD runs over the whole
/// download and its cost per byte is a throughput term on any CPU
/// without headroom. Measured on Apple silicon at 16 KB records:
/// AES-128-GCM 9.70 GB/s, AES-256-GCM 8.25, ChaCha20-Poly1305 2.12.
///
/// `pin_fast_suite` offers exactly ONE suite: the fastest this CPU can
/// run (AES-128-GCM with hardware AES, ChaCha20 without - on a
/// Raspberry Pi 4-class core, software AES-GCM is the slow one and the
/// ranking inverts).
///
/// It has to be exactly one, and that is the whole subtlety. Under TLS
/// 1.3 the SERVER chooses, walking its own preference list for the
/// first suite the client offered; OpenSSL's default order is
/// AES-256 → ChaCha20 → AES-128. So a client that merely REORDERS its
/// list changes nothing, and a client that drops only AES-256 gets
/// handed ChaCha20 - measured on 4 of our 6 providers, a ~4x per-byte
/// REGRESSION over the AES-256 it was trying to improve on. Offering a
/// single suite is the only way to actually choose.
///
/// A server that cannot do our one suite fails the handshake, and
/// `connect_unbounded` retries once with the full list, remembering the
/// host (see [`tls_full_host`]). 128-bit AES is not a meaningful
/// security downgrade for bulk transfer.
fn tls_provider(aes_accelerated: bool, pin_fast_suite: bool) -> rustls::crypto::CryptoProvider {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    if pin_fast_suite {
        if aes_accelerated {
            provider.cipher_suites.retain(is_aes128);
        } else {
            provider.cipher_suites.retain(is_chacha);
        }
    } else if !aes_accelerated {
        // Full-list fallback on a soft-AES CPU: ChaCha first is the best
        // we can do, though a server-preference server will ignore it.
        provider.cipher_suites.sort_by_key(|s| !is_chacha(s));
    }
    provider
}

/// The socket, buffered exactly once.
///
/// TLS deliberately gets NO `BufReader`. rustls already holds decrypted
/// plaintext and `tokio_rustls::TlsStream` hands it out as a borrowed
/// chunk through `AsyncBufRead`, so a `BufReader` on top re-copies every
/// byte for nothing. It cannot even amortise syscalls: rustls stops
/// reading the socket the moment one record's plaintext is available
/// (`wants_read()` is false while `received_plaintext` is non-empty, and
/// its limit is 16 KB), so a 256 KB `BufReader` over TLS still delivers
/// ~16 KB per call - it was pure copy cost. Plain TCP and the
/// DEFLATE-wrapped stream buffer nothing themselves, so those keep ours.
///
/// One stream, not a `tokio::io::split` pair: `send_body` and
/// `read_body_into` are never in flight at the same time (NNTP
/// pipelining batches commands, then reads responses), so the split
/// bought nothing and cost the `AsyncBufRead` impl - `ReadHalf` does not
/// forward it.
enum Wire {
    Tls(Box<tokio_rustls::client::TlsStream<tokio::net::TcpStream>>),
    Buffered(BufReader<Box<dyn Transport>>),
}

impl Wire {
    fn buffered(t: Box<dyn Transport>) -> Wire {
        Wire::Buffered(BufReader::with_capacity(256 * 1024, t))
    }

    /// Bytes already sitting in our buffers, removed. Used only when
    /// swapping the transport underneath ourselves (COMPRESS DEFLATE):
    /// whatever was read past the 206 belongs to the new stream. Never
    /// awaits - it drains what is buffered and nothing more.
    fn take_buffered(&mut self) -> Vec<u8> {
        match self {
            Wire::Buffered(br) => {
                let v = br.buffer().to_vec();
                std::pin::Pin::new(br).consume(v.len());
                v
            }
            Wire::Tls(s) => {
                // rustls' plaintext queue is readable synchronously -
                // `Reader` is a plain `io::Read` over already-decrypted
                // bytes and returns WouldBlock when empty, so this
                // touches the socket not at all.
                use std::io::Read as _;
                let (_, conn) = s.get_mut();
                let mut out = Vec::new();
                let mut tmp = [0u8; 8192];
                while let Ok(n) = conn.reader().read(&mut tmp) {
                    if n == 0 {
                        break;
                    }
                    out.extend_from_slice(&tmp[..n]);
                }
                out
            }
        }
    }

    fn into_transport(self) -> Box<dyn Transport> {
        match self {
            Wire::Tls(s) => s,
            Wire::Buffered(br) => br.into_inner(),
        }
    }
}

macro_rules! wire_dispatch {
    ($self:ident, $s:ident => $body:expr) => {
        match $self.get_mut() {
            Wire::Tls($s) => {
                let $s = std::pin::Pin::new(&mut **$s);
                $body
            }
            Wire::Buffered($s) => {
                let $s = std::pin::Pin::new($s);
                $body
            }
        }
    };
}

impl AsyncRead for Wire {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        wire_dispatch!(self, s => s.poll_read(cx, buf))
    }
}

impl tokio::io::AsyncBufRead for Wire {
    fn poll_fill_buf(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<&[u8]>> {
        wire_dispatch!(self, s => s.poll_fill_buf(cx))
    }

    fn consume(self: std::pin::Pin<&mut Self>, amt: usize) {
        wire_dispatch!(self, s => s.consume(amt))
    }
}

impl AsyncWrite for Wire {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        wire_dispatch!(self, s => s.poll_write(cx, buf))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        wire_dispatch!(self, s => s.poll_flush(cx))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        wire_dispatch!(self, s => s.poll_shutdown(cx))
    }
}

pub struct Connection {
    wire: Wire,
    line: Vec<u8>,
    /// Whether this server understands OVER (RFC 3977) - learned on the
    /// first attempt. Some providers only implement legacy XOVER and
    /// reject OVER with an unknown-command status; without the latch a
    /// header scan pays that doomed round-trip on EVERY chunk.
    over_supported: Option<bool>,
    /// Header compression negotiated via `XFEATURE COMPRESS GZIP`
    /// (Highwinds-style). When on, OVER/XOVER response bodies arrive as
    /// one compressed stream (gzip/zlib/raw-deflate, server's choice)
    /// with the dot terminator either inside the stream or trailing it
    /// in plain text (the "TERMINATOR" capability variant).
    header_gzip: bool,
}

/// Hard bound on the whole connect sequence (DNS + TCP + TLS handshake +
/// greeting + AUTHINFO). None of those steps has its own timeout, so a
/// black-holed provider (SYN swallowed, TLS peer gone mute, greeting never
/// sent) would otherwise park the caller forever - the connect-time twin of
/// the 190 GB QUIT hang. 20 s is an eternity next to a healthy sub-second
/// connect but well under any "the server is down, move on" threshold.
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);

/// Hard bound on a single command/response transaction *after* connect.
/// CONNECT_TIMEOUT only covers the connect sequence; every command issued
/// afterwards (the POST/IHAVE acceptance response, CAPABILITIES, COMPRESS,
/// GROUP, ...) reads a status line with no deadline of its own, so a server
/// that greets and authenticates normally and then goes mute on a later
/// response would park the caller forever - the post worker blocks on the
/// final 240, its coordinator blocks on the join, and the scan worker blocks
/// on CAPABILITIES/COMPRESS. A status line is three digits plus a short
/// message; no healthy server takes anywhere near 60 s to emit one, so this
/// only ever trips a stalled or hostile peer. The download pool bounds its
/// bulk body reads separately (`read_timeout`, per fill).
const COMMAND_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

/// How long [`Connection::quit`] stays polite waiting for the goodbye.
/// The QUIT itself is already sent by then - the wait only avoids
/// closing with the server's `205` still in flight (an unread byte at
/// close can turn a graceful FIN into an RST on some stacks). 150 ms
/// covers any realistic goodbye RTT; the fault matrix's mutequit
/// profile showed mid-run courtesy quits to a never-answering peer
/// each eating the old 500 ms bound (+2 s on a 22 s job).
/// `NZBFAST_QUIT_BOUND_MS` overrides for A/B.
fn quit_bound() -> std::time::Duration {
    static MS: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    std::time::Duration::from_millis(*MS.get_or_init(|| {
        std::env::var("NZBFAST_QUIT_BOUND_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .filter(|&m| m > 0)
            .unwrap_or(150)
    }))
}

/// Idle (no-progress) bound on a multiline body read. `MAX_MULTILINE_BYTES`
/// only bites when bytes KEEP ARRIVING; a peer that emits "224 overview
/// follows" and then goes silent - a provider process that died without a
/// RST, an LB failover that dropped the flow's state, a NAT/CGNAT idle
/// timer evicting a long OVER range - never trips it, and the reader parks
/// forever. The header-scan path is where that hurt: a wedged scan worker
/// never delivers its chunk and never drops its channel sender, so the
/// collector's `recv()` never returns and no further scan pass ever starts.
///
/// This is deliberately an IDLE deadline, not a total-duration one: it wraps
/// each individual awaited socket read, and `fill_buf` returns the moment ANY
/// bytes land, so a legitimate multi-minute 100k-article OVER over a slow
/// link is never cut off - only a stream that has gone silent is. 120 s is
/// larger than `COMMAND_TIMEOUT` on purpose (a mid-stream pause is far more
/// legitimate than a missing status line) and comfortably larger than the
/// download pool's own 30 s per-fill `read_timeout`, so the pool's outer
/// deadline still always wins first and its shedding logic is unchanged.
/// Complementary to `MAX_MULTILINE_BYTES`: that bounds the flood, this
/// bounds the silence.
const STREAM_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

/// Resolve `host`, pin one address (prefer IPv4 - providers count
/// simultaneous source IPs, and macOS can otherwise spread connections
/// across IPv4 + rotating IPv6 privacy addresses), apply the server's
/// bind_ip/rcvbuf, connect. A bind_ip's family overrides the IPv4
/// preference: binding a v6 source to a v4 target can't work.
async fn direct_connect(
    host: &str,
    port: u16,
    server: &ServerConfig,
) -> std::io::Result<tokio::net::TcpStream> {
    direct_connect_opts(host, port, server.bind_ip.as_deref(), server.rcvbuf).await
}

/// As [`direct_connect`], taking the two settings it actually reads.
/// Lets the TLS diagnostic dial a bare host with no `ServerConfig`.
async fn direct_connect_opts(
    host: &str,
    port: u16,
    bind_ip: Option<&str>,
    rcvbuf: Option<u32>,
) -> std::io::Result<tokio::net::TcpStream> {
    let bind: Option<std::net::IpAddr> =
        match bind_ip {
            None => None,
            Some(s) => Some(s.trim().parse().map_err(|_| {
                std::io::Error::other(format!("bind_ip {s:?} is not an IP address"))
            })?),
        };
    let mut addrs: Vec<std::net::SocketAddr> =
        tokio::net::lookup_host((host, port)).await?.collect();
    match bind {
        Some(ip) => addrs.retain(|a| a.is_ipv4() == ip.is_ipv4()),
        None => addrs.sort_by_key(|a| !a.is_ipv4()),
    }
    if addrs.is_empty() {
        return Err(std::io::Error::other(match bind {
            Some(ip) if ip.is_ipv4() => format!("{host} has no IPv4 address to match bind_ip"),
            Some(_) => format!("{host} has no IPv6 address to match bind_ip"),
            None => format!("{host} did not resolve"),
        }));
    }
    let one = |addr: std::net::SocketAddr| async move {
        let socket = if addr.is_ipv4() {
            tokio::net::TcpSocket::new_v4()?
        } else {
            tokio::net::TcpSocket::new_v6()?
        };
        if let Some(rcvbuf) = rcvbuf {
            // Best effort - the kernel clamps to its per-socket max.
            let _ = socket.set_recv_buffer_size(rcvbuf);
        }
        // Keepalive experiment (dark, NZBFAST_KEEPALIVE=1): a NAT or
        // provider silently dropping a connection otherwise costs a full
        // read_timeout of dead air (or kills a parked warm session
        // invisibly). Probe after 15 s idle, every 5 s, give up after 4
        // misses - the kernel declares the death in ~35 s worst case and
        // in seconds for a half-open peer, instead of us inferring it
        // from silence. Best effort on both platforms.
        #[cfg(unix)]
        if std::env::var("NZBFAST_KEEPALIVE").is_ok_and(|v| v == "1") {
            set_keepalive(&socket);
        }
        if let Some(ip) = bind {
            socket.bind(std::net::SocketAddr::new(ip, 0))?;
        }
        socket.connect(addr).await
    };
    // Dial-race experiment (dark, NZBFAST_DIAL_RACE=1): providers sit
    // behind DNS pools and individual nodes vary - a bad node hands out
    // the "one mysteriously slow session" shape everything downstream
    // then has to fight. Race the top two addresses, first TCP connect
    // wins, loser is closed pre-greeting (a transient extra SYN, never
    // an NNTP session, so provider session caps don't see it). The
    // address-family preference above still orders the field.
    let race = addrs.len() >= 2 && std::env::var("NZBFAST_DIAL_RACE").is_ok_and(|v| v == "1");
    if !race {
        return one(addrs[0]).await;
    }
    let (a, b) = (addrs[0], addrs[1]);
    tokio::select! {
        r = one(a) => match r {
            Ok(s) => Ok(s),
            Err(_) => one(b).await,
        },
        r = async {
            // Stagger the second SYN slightly: on a healthy first
            // address this keeps the race nearly free.
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            one(b).await
        } => match r {
            Ok(s) => Ok(s),
            Err(_) => one(a).await,
        },
    }
}

/// Best-effort short TCP keepalive on a not-yet-connected socket (see
/// the keepalive experiment note at the call site). Unix only - the
/// Windows equivalent (WSAIoctl SIO_KEEPALIVE_VALS) is a separate
/// experiment if this one earns its keep.
#[cfg(unix)]
fn set_keepalive(socket: &tokio::net::TcpSocket) {
    use std::os::fd::AsRawFd;
    let fd = socket.as_raw_fd();
    unsafe {
        let on: libc::c_int = 1;
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_KEEPALIVE,
            (&raw const on).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        let idle: libc::c_int = 15;
        let interval: libc::c_int = 5;
        let count: libc::c_int = 4;
        #[cfg(any(target_os = "macos", target_os = "ios"))]
        libc::setsockopt(
            fd,
            libc::IPPROTO_TCP,
            libc::TCP_KEEPALIVE,
            (&raw const idle).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_KEEPIDLE,
                (&raw const idle).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
            // TCP_USER_TIMEOUT: also bound how long WRITTEN data may sit
            // unacknowledged - catches the half-open peer mid-transfer,
            // which keepalive (idle-only) cannot.
            let user_ms: libc::c_uint = 20_000;
            libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_USER_TIMEOUT,
                (&raw const user_ms).cast(),
                std::mem::size_of::<libc::c_uint>() as libc::socklen_t,
            );
        }
        #[cfg(any(
            target_os = "macos",
            target_os = "ios",
            target_os = "linux",
            target_os = "android"
        ))]
        {
            libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_KEEPINTVL,
                (&raw const interval).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
            libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_KEEPCNT,
                (&raw const count).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
        // Other platforms: SO_KEEPALIVE alone, kernel defaults.
        let _ = (interval, count);
    }
}

/// Minimal SOCKS5 client (RFC 1928 CONNECT + RFC 1929 user/pass):
/// `spec` is "host:port" or "user:pass@host:port". The target hostname
/// is sent as ATYP=DOMAIN so the proxy does the resolving.
async fn socks5_connect(
    spec: &str,
    host: &str,
    port: u16,
    server: &ServerConfig,
) -> std::io::Result<tokio::net::TcpStream> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    fn err(m: impl Into<String>) -> std::io::Error {
        std::io::Error::other(m.into())
    }
    let (creds, proxy_hp) = match spec.rsplit_once('@') {
        Some((c, hp)) => (Some(c.split_once(':').unwrap_or((c, ""))), hp),
        None => (None, spec),
    };
    let (phost, pport) = proxy_hp
        .rsplit_once(':')
        .and_then(|(h, p)| p.parse::<u16>().ok().map(|p| (h, p)))
        // `proxy_hp`, never `spec`: the documented form is
        // "user:pass@host:port", so `spec` still carries the proxy password
        // here. This error reaches the log file, the logtee ring served by
        // mode=log, and .spool/bench_history.json (the scheduled-benchmark loop
        // stores the message verbatim) - a port typo would have persisted the
        // credential in all three.
        .ok_or_else(|| err(format!("socks5 {proxy_hp:?}: expected host:port")))?;
    let mut s = direct_connect(phost, pport, server).await?;

    // Method negotiation: offer user/pass only when we have one.
    let methods: &[u8] = if creds.is_some() {
        &[0x00, 0x02]
    } else {
        &[0x00]
    };
    let mut hello = vec![0x05, methods.len() as u8];
    hello.extend_from_slice(methods);
    s.write_all(&hello).await?;
    let mut rep = [0u8; 2];
    s.read_exact(&mut rep).await?;
    match (rep[0], rep[1]) {
        (0x05, 0x00) => {}
        (0x05, 0x02) => {
            let (user, pass) = creds.ok_or_else(|| err("socks5 proxy wants auth"))?;
            if user.len() > 255 || pass.len() > 255 {
                return Err(err("socks5 credentials too long"));
            }
            let mut a = vec![0x01, user.len() as u8];
            a.extend_from_slice(user.as_bytes());
            a.push(pass.len() as u8);
            a.extend_from_slice(pass.as_bytes());
            s.write_all(&a).await?;
            let mut ar = [0u8; 2];
            s.read_exact(&mut ar).await?;
            if ar[1] != 0x00 {
                return Err(err("socks5 auth rejected"));
            }
        }
        _ => return Err(err("socks5 proxy offered no usable auth method")),
    }

    // CONNECT host:port, hostname as a domain literal.
    if host.len() > 255 {
        return Err(err("hostname too long for socks5"));
    }
    let mut req = vec![0x05, 0x01, 0x00, 0x03, host.len() as u8];
    req.extend_from_slice(host.as_bytes());
    req.extend_from_slice(&port.to_be_bytes());
    s.write_all(&req).await?;
    let mut head = [0u8; 4];
    s.read_exact(&mut head).await?;
    if head[1] != 0x00 {
        return Err(err(format!("socks5 connect refused (code {})", head[1])));
    }
    // Drain the BND.ADDR/PORT the reply carries.
    let addr_len = match head[3] {
        0x01 => 4,
        0x04 => 16,
        0x03 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).await?;
            l[0] as usize
        }
        t => return Err(err(format!("socks5 reply ATYP {t} unknown"))),
    };
    let mut skip = vec![0u8; addr_len + 2];
    s.read_exact(&mut skip).await?;
    Ok(s)
}

/// Hosts whose handshake failed on the AES-128-only offer (see
/// [`tls_provider`]). Small and append-only: one entry per genuinely
/// odd provider, for the life of the process.
fn tls_full_hosts() -> &'static std::sync::Mutex<std::collections::HashSet<String>> {
    static S: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<String>>> =
        std::sync::OnceLock::new();
    S.get_or_init(Default::default)
}

fn tls_full_host(host: &str) -> bool {
    // NZBFAST_TLS_AES256=1 forces the old full-list behaviour everywhere:
    // the escape hatch if a provider we never tested behaves oddly.
    if std::env::var_os("NZBFAST_TLS_AES256").is_some() {
        return true;
    }
    tls_full_hosts().lock_ok().contains(host)
}

fn mark_tls_full_host(host: &str) {
    tls_full_hosts().lock_ok().insert(host.to_string());
}

/// The trust anchors: webpki's built-in roots plus anything in
/// `NZBFAST_EXTRA_CA`. Built once.
fn tls_roots() -> rustls::RootCertStore {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    // Extra trust anchors from a PEM file, ADDED to the webpki set,
    // never replacing it. Two real uses: a self-hosted or corporate-
    // MITM'd provider whose CA isn't public, and the TLS bench leg
    // (mockserve's self-signed cert). Opt-in by explicit path - this is
    // deliberately not a "skip verification" switch, which is the thing
    // that quietly ships and then never gets turned back off.
    let Some(p) = std::env::var_os("NZBFAST_EXTRA_CA") else {
        return roots;
    };
    use rustls::pki_types::pem::PemObject;
    match rustls::pki_types::CertificateDer::pem_file_iter(&p) {
        Err(e) => eprintln!("NZBFAST_EXTRA_CA {p:?}: {e}"),
        Ok(it) => {
            let mut added = 0usize;
            for c in it {
                match c
                    .map_err(|e| e.to_string())
                    .and_then(|c| roots.add(c).map_err(|e| e.to_string()))
                {
                    Ok(()) => added += 1,
                    Err(e) => eprintln!("NZBFAST_EXTRA_CA {p:?}: {e}"),
                }
            }
            eprintln!("NZBFAST_EXTRA_CA {p:?}: {added} extra trust anchor(s)");
        }
    }
    roots
}

/// True when this process has asked for kernel TLS. Constant `false`
/// unless the `ktls` feature is built in on Linux, and it is read
/// before the first `ClientConfig` is built so the answer cannot
/// change underneath a cached config.
fn ktls_wanted() -> bool {
    #[cfg(all(feature = "ktls", target_os = "linux"))]
    {
        ktls_offload::wanted()
    }
    #[cfg(not(all(feature = "ktls", target_os = "linux")))]
    {
        false
    }
}

/// One shared ClientConfig per suite policy, for the life of the
/// process: rustls keeps its session ticket cache inside the config, so
/// sharing it enables TLS session RESUMPTION on reconnects (abbreviated
/// handshake - one less round-trip and no fresh key exchange per
/// connection). Two of them, because the AES-128 offer needs a full-list
/// fallback for any server that cannot do it.
fn tls_client_config(pin_fast_suite: bool) -> Arc<rustls::ClientConfig> {
    static LEAN: std::sync::OnceLock<Arc<rustls::ClientConfig>> = std::sync::OnceLock::new();
    static FULL: std::sync::OnceLock<Arc<rustls::ClientConfig>> = std::sync::OnceLock::new();
    let build = |pin_fast_suite: bool| {
        // Name the crypto provider explicitly. The dependency tree links
        // BOTH aws-lc-rs and ring (a transitive dep pulled ring in), so
        // rustls can no longer auto-select a process default - plain
        // `builder()` panics at runtime. Pin aws-lc-rs so the choice is
        // unambiguous regardless of what else links a provider.
        let mut cfg = rustls::ClientConfig::builder_with_provider(Arc::new(tls_provider(
            aes_accelerated(),
            pin_fast_suite,
        )))
        .with_safe_default_protocol_versions()
        .expect("aws-lc-rs supports safe default protocol versions")
        .with_root_certificates(tls_roots())
        .with_no_client_auth();
        // Kernel TLS needs the negotiated traffic secrets after the
        // handshake, and rustls will only part with them when it was
        // told so before the handshake. Left off otherwise: the secrets
        // are in the process either way, but there is no reason to make
        // them extractable when nothing extracts them.
        cfg.enable_secret_extraction = ktls_wanted();
        Arc::new(cfg)
    };
    if pin_fast_suite {
        LEAN.get_or_init(|| build(true)).clone()
    } else {
        FULL.get_or_init(|| build(false)).clone()
    }
}

/// Kernel TLS: after the rustls handshake, hand the traffic keys to the
/// kernel and let it do the record crypto.
///
/// Every downloaded byte crosses this path, and userspace TLS charges
/// three things for it (measured 26 Jul, +43% CPU/GB over plain TCP):
/// the AEAD ~0.120 cpu-s/GB, one extra `recvmsg` per record ~0.079, and
/// one extra copy per record ~0.081 - rustls decrypts in place and then
/// `Payload::into_vec()`s the plaintext out, and it stops reading the
/// socket the moment one record's worth is buffered, so a read is one
/// ~16 KB record and never more. `setsockopt(TCP_ULP, "tls")` plus the
/// extracted `TLS_TX`/`TLS_RX` keys turns the socket back into an
/// ordinary one that happens to return plaintext: the AEAD stays (the
/// kernel runs it on the same AES-NI), the copy goes, and one `read()`
/// can drain every record the kernel has.
///
/// Opt-in twice over - the `ktls` cargo feature has to be built in AND
/// `NZBFAST_KTLS=1` set - because the fallback matters more than the
/// win: NAS firmware kernels predate TLS_RX, containers may not be able
/// to autoload the `tls` module, and a kernel that refuses must cost a
/// user nothing.
///
/// What the kernel will NOT do is renegotiate. A post-handshake
/// KeyUpdate arrives as a control record the kernel cannot act on, so
/// [`KtlsWire`] treats one as a dead connection: the pool reconnects,
/// and that connection finishes in userspace.
#[cfg(all(feature = "ktls", target_os = "linux"))]
mod ktls_offload {
    use super::Wire;
    use std::sync::atomic::{AtomicBool, Ordering};

    /// `NZBFAST_KTLS=1` opts in. Read once, before the first
    /// `ClientConfig` exists - [`super::ktls_wanted`] bakes the answer
    /// into that config's `enable_secret_extraction`.
    pub(super) fn wanted() -> bool {
        static WANTED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        *WANTED.get_or_init(|| {
            matches!(
                std::env::var("NZBFAST_KTLS").as_deref(),
                Ok("1") | Ok("true")
            )
        })
    }

    /// Latched the first time a kernel refuses the handoff. One process
    /// talks to one kernel, so the second refusal would tell us nothing
    /// the first did not - and every attempt costs a spent socket.
    static OFF: AtomicBool = AtomicBool::new(false);

    pub(super) fn active() -> bool {
        wanted() && !OFF.load(Ordering::Relaxed)
    }

    /// Silent and total, one log line the first time. This is the whole
    /// point of the opt-in: an old kernel just downloads in userspace.
    pub(super) fn disable(why: &dyn std::fmt::Display) {
        if !OFF.swap(true, Ordering::Relaxed) {
            eprintln!("kTLS: kernel declined the handoff ({why}); TLS stays in userspace");
        }
    }

    /// Handshake with rustls, then hand the socket to the kernel.
    ///
    /// - `Ok(Some(wire))` - kTLS is live on this connection.
    /// - `Ok(None)` - the kernel refused. kTLS is off for the rest of
    ///   the process and the caller must redial: draining rustls spent
    ///   this socket.
    /// - `Err(e)` - the TLS handshake itself failed, exactly as it
    ///   would have without kTLS, and the caller's existing ladder
    ///   (pinned suite → full cipher list) applies unchanged.
    pub(super) async fn connect(
        name: rustls::pki_types::ServerName<'static>,
        tcp: tokio::net::TcpStream,
        pin_fast_suite: bool,
    ) -> std::io::Result<Option<Wire>> {
        let connector = tokio_rustls::TlsConnector::from(super::tls_client_config(pin_fast_suite));
        // The cork is load-bearing. rustls reads whatever the socket
        // has, so by the time `connect` returns it can be holding a
        // PARTIAL record - and the kernel, handed keys that start at a
        // record boundary, could never decrypt the remainder. A corked
        // stream stops at each boundary, which lets the drain below end
        // exactly where the kernel begins.
        let stream = connector.connect(name, ktls::CorkStream::new(tcp)).await?;
        match ktls::config_ktls_client(stream).await {
            Ok(k) => {
                // Say so once. "It downloaded" is not evidence that the
                // kernel took the socket - the fallback is silent and
                // looks identical from the outside.
                static LOGGED: AtomicBool = AtomicBool::new(false);
                if !LOGGED.swap(true, Ordering::Relaxed) {
                    eprintln!("kTLS: kernel TLS active - record crypto moved into the kernel");
                }
                // Whatever rustls decrypted before the handoff (the NNTP
                // greeting usually arrives in the same flight) rides
                // along inside the stream and comes out of the first
                // reads, ahead of anything the kernel produces.
                let (drained, tcp) = k.into_raw();
                Ok(Some(Wire::buffered(Box::new(super::KtlsWire::new(
                    tcp, drained,
                )))))
            }
            Err(e) => {
                disable(&e);
                Ok(None)
            }
        }
    }
}

/// A socket the kernel decrypts: ordinary `read`/`write`, plaintext on
/// both sides, plus whatever rustls had already decrypted when the
/// kernel took over.
///
/// It exists instead of `ktls::KtlsStream` for one reason: control
/// records. A `read()` on a kTLS socket fails with `EIO` for any record
/// that is not application data, and the only way to see what it was is
/// `recvmsg` with room for a `TLS_GET_RECORD_TYPE` control message. The
/// crate's own stream does that too, but answers the awkward cases -
/// an unexpected `cmsg`, a two-byte alert that arrives as one byte, a
/// `change_cipher_spec` - with `panic!`. A panic in a pool worker takes
/// the download with it (an `Err` never hangs the pool; a panic does),
/// and every one of those cases is reachable from the far end of a
/// socket, which is untrusted input. Here they are all errors, and an
/// error just costs that one connection.
#[cfg(all(feature = "ktls", target_os = "linux"))]
struct KtlsWire {
    tcp: tokio::net::TcpStream,
    fd: std::os::fd::RawFd,
    /// Plaintext rustls decrypted before the handoff (the NNTP greeting
    /// usually), and how much of it has been handed out.
    drained: Option<(usize, Vec<u8>)>,
}

#[cfg(all(feature = "ktls", target_os = "linux"))]
impl KtlsWire {
    /// `SOL_TLS` and `TLS_GET_RECORD_TYPE` from the kernel's
    /// `include/uapi/linux/tls.h`; libc does not export them.
    const SOL_TLS: libc::c_int = 282;
    const TLS_GET_RECORD_TYPE: libc::c_int = 2;
    const RECORD_ALERT: u8 = 21;
    const RECORD_HANDSHAKE: u8 = 22;
    const ALERT_CLOSE_NOTIFY: u8 = 0;
    const HANDSHAKE_NEW_SESSION_TICKET: u8 = 4;
    const HANDSHAKE_KEY_UPDATE: u8 = 24;

    fn new(tcp: tokio::net::TcpStream, drained: Option<Vec<u8>>) -> Self {
        use std::os::fd::AsRawFd as _;
        let fd = tcp.as_raw_fd();
        Self {
            tcp,
            fd,
            drained: drained.map(|d| (0, d)),
        }
    }

    /// Consume the one non-data record the kernel is holding, and say
    /// what to do next. Until it is consumed, nothing behind it can be
    /// read.
    ///
    /// `scratch` is the caller's own read buffer, borrowed and then
    /// discarded: a control record's contents are never application
    /// data, so nothing here is ever handed upward.
    fn take_control_record(&mut self, scratch: &mut [u8]) -> std::io::Result<ControlRecord> {
        // A union with the header, not a byte array: `CMSG_FIRSTHDR`
        // casts this buffer to a `cmsghdr`, so it has to carry that
        // type's alignment. A `[u8; N]` is 1-aligned and reads as a
        // misaligned dereference - which a release build happily runs
        // and a debug build aborts on (it did, first run).
        union CmsgSpace {
            _hdr: libc::cmsghdr,
            bytes: [u8; 64],
        }
        let mut cmsg_space = CmsgSpace { bytes: [0u8; 64] };
        let cmsg_len = std::mem::size_of::<CmsgSpace>();
        // SAFETY: every pointer handed to recvmsg points at a live local
        // buffer, the lengths match those buffers, and the cmsg walk uses
        // the kernel's own macros over the header recvmsg filled in.
        let (n, record_type) = unsafe {
            let mut iov = libc::iovec {
                iov_base: scratch.as_mut_ptr().cast(),
                iov_len: scratch.len(),
            };
            let mut msg: libc::msghdr = std::mem::zeroed();
            msg.msg_iov = &mut iov;
            msg.msg_iovlen = 1;
            msg.msg_control = cmsg_space.bytes.as_mut_ptr().cast();
            msg.msg_controllen = cmsg_len as _;
            let n = libc::recvmsg(self.fd, &mut msg, libc::MSG_DONTWAIT);
            if n < 0 {
                return Err(std::io::Error::last_os_error());
            }
            let mut ty = None;
            let mut c = libc::CMSG_FIRSTHDR(&msg);
            while !c.is_null() {
                if (*c).cmsg_level == Self::SOL_TLS && (*c).cmsg_type == Self::TLS_GET_RECORD_TYPE {
                    ty = Some(*libc::CMSG_DATA(c));
                }
                c = libc::CMSG_NXTHDR(&msg, c);
            }
            (n as usize, ty)
        };
        let Some(record_type) = record_type else {
            // No record-type control message means this was not the
            // control record we were told about. Nothing sane left to
            // do with the connection.
            return Err(std::io::Error::other(
                "kTLS: EIO on read with no TLS record type",
            ));
        };
        let body = &scratch[..n];
        match record_type {
            Self::RECORD_ALERT => match body {
                // A close_notify is the peer hanging up cleanly, which
                // is exactly EOF. Every other alert aborts the session
                // by definition, so it is an error either way.
                [_, Self::ALERT_CLOSE_NOTIFY] | [Self::ALERT_CLOSE_NOTIFY] => {
                    Ok(ControlRecord::Eof)
                }
                _ => Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "kTLS: TLS alert",
                )),
            },
            Self::RECORD_HANDSHAKE => match body.first().copied() {
                // Session tickets: the ordinary post-handshake traffic
                // of any TLS 1.3 server. The kernel cannot use them and
                // neither can we now that rustls is out of the loop, so
                // resumption is a cost kTLS connections pay - one extra
                // round-trip on the NEXT connect to that host.
                Some(Self::HANDSHAKE_NEW_SESSION_TICKET) => Ok(ControlRecord::Skip),
                // A rekey. The kernel holds one set of keys and cannot
                // be handed another mid-stream, so this connection is
                // over - and a server that rekeys once will do it
                // again, so stop using kTLS for the rest of the run.
                Some(Self::HANDSHAKE_KEY_UPDATE) => {
                    ktls_offload::disable(&"server sent a TLS KeyUpdate");
                    Err(std::io::Error::other(
                        "kTLS: TLS KeyUpdate cannot be applied",
                    ))
                }
                _ => Ok(ControlRecord::Skip),
            },
            // change_cipher_spec (20) after the handshake, or anything
            // else: not something a TLS 1.3 peer sends on a live
            // connection.
            other => Err(std::io::Error::other(format!(
                "kTLS: unexpected TLS record type {other}"
            ))),
        }
    }
}

/// What a consumed control record means for the read that hit it.
#[cfg(all(feature = "ktls", target_os = "linux"))]
enum ControlRecord {
    /// Ignorable; read again.
    Skip,
    /// The peer closed cleanly.
    Eof,
}

#[cfg(all(feature = "ktls", target_os = "linux"))]
impl AsyncRead for KtlsWire {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let me = self.get_mut();
        // Pre-handoff plaintext first - it sits in front of everything
        // the kernel will ever produce.
        if let Some((at, d)) = &mut me.drained {
            let n = (d.len() - *at).min(buf.remaining());
            buf.put_slice(&d[*at..*at + n]);
            *at += n;
            if *at >= d.len() {
                me.drained = None;
            }
            return std::task::Poll::Ready(Ok(()));
        }
        match std::pin::Pin::new(&mut me.tcp).poll_read(cx, buf) {
            std::task::Poll::Ready(Err(e)) if e.raw_os_error() == Some(libc::EIO) => {
                // Not a failure: the kernel is holding a record it will
                // not hand over as data, and says so with EIO.
                match me.take_control_record(buf.initialize_unfilled()) {
                    Ok(ControlRecord::Skip) => {
                        // The record is consumed; whatever is behind it
                        // may be readable right now, so try again
                        // rather than wait for the next readiness edge.
                        cx.waker().wake_by_ref();
                        std::task::Poll::Pending
                    }
                    // Nothing filled == EOF.
                    Ok(ControlRecord::Eof) => std::task::Poll::Ready(Ok(())),
                    Err(e) => std::task::Poll::Ready(Err(e)),
                }
            }
            other => other,
        }
    }
}

#[cfg(all(feature = "ktls", target_os = "linux"))]
impl AsyncWrite for KtlsWire {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.get_mut().tcp).poll_write(cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().tcp).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().tcp).poll_shutdown(cx)
    }
}

/// The shared TLS client configuration, for the engine's non-NNTP TLS
/// links (today: the pre feed's IRC connection). Full suite list, not
/// the AES-128 pin - that pin is a per-byte throughput optimisation for
/// the download path and means nothing on a link carrying a line of
/// text a minute. Sharing the config also shares the trust anchors, so
/// `NZBFAST_EXTRA_CA` applies here too.
pub fn shared_tls_client_config() -> Arc<rustls::ClientConfig> {
    tls_client_config(false)
}

/// The plain userspace rung: rustls owns the record layer, as it has
/// on every platform since the beginning.
async fn userspace_tls(
    name: rustls::pki_types::ServerName<'static>,
    tcp: tokio::net::TcpStream,
    pin_fast_suite: bool,
) -> std::io::Result<Wire> {
    let connector = tokio_rustls::TlsConnector::from(tls_client_config(pin_fast_suite));
    Ok(Wire::Tls(Box::new(connector.connect(name, tcp).await?)))
}

/// One rung of the handshake ladder. `Ok(None)` means "the kernel
/// refused kTLS, the socket is spent, dial again" - it cannot happen
/// when kTLS is not compiled in.
#[cfg(all(feature = "ktls", target_os = "linux"))]
async fn tls_handshake(
    name: rustls::pki_types::ServerName<'static>,
    tcp: tokio::net::TcpStream,
    pin_fast_suite: bool,
) -> std::io::Result<Option<Wire>> {
    if ktls_offload::active() {
        return ktls_offload::connect(name, tcp, pin_fast_suite).await;
    }
    userspace_tls(name, tcp, pin_fast_suite).await.map(Some)
}

#[cfg(not(all(feature = "ktls", target_os = "linux")))]
async fn tls_handshake(
    name: rustls::pki_types::ServerName<'static>,
    tcp: tokio::net::TcpStream,
    pin_fast_suite: bool,
) -> std::io::Result<Option<Wire>> {
    userspace_tls(name, tcp, pin_fast_suite).await.map(Some)
}

/// Diagnostic: handshake with `host:port` exactly as a download
/// connection would, and report `(protocol, cipher suite)`. Answers the
/// only question that matters when tuning the AEAD cost - what the
/// server actually PICKED, which under TLS 1.3 is its choice from our
/// offer, not ours (see [`tls_provider`]). No NNTP traffic, no
/// credentials sent.
pub async fn probe_tls(host: &str, port: u16) -> Result<(String, String), NntpError> {
    let tcp = direct_connect_opts(host, port, None, None).await?;
    tcp.set_nodelay(true)?;
    let name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|_| NntpError::TlsName)?;
    let connector = tokio_rustls::TlsConnector::from(tls_client_config(!tls_full_host(host)));
    let stream = connector.connect(name, tcp).await?;
    let (_, conn) = stream.get_ref();
    let proto = conn
        .protocol_version()
        .map_or_else(|| "?".to_string(), |v| format!("{v:?}"));
    let suite = conn
        .negotiated_cipher_suite()
        .map_or_else(|| "?".to_string(), |s| format!("{:?}", s.suite()));
    Ok((proto, suite))
}

impl Connection {
    /// Connect, read the greeting, authenticate if credentials are present.
    /// Bounded by [`CONNECT_TIMEOUT`] end to end.
    pub async fn connect(server: &ServerConfig) -> Result<(Connection, Status), NntpError> {
        match tokio::time::timeout(CONNECT_TIMEOUT, Self::connect_unbounded(server)).await {
            Ok(r) => r,
            Err(_) => Err(NntpError::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "connect timed out",
            ))),
        }
    }

    async fn connect_unbounded(server: &ServerConfig) -> Result<(Connection, Status), NntpError> {
        let tcp_connect = || async {
            let tcp = if let Some(proxy) = &server.socks5 {
                // M32: all traffic (DNS included - the hostname goes to
                // the proxy verbatim) rides the SOCKS5 tunnel.
                socks5_connect(proxy, &server.host, server.port, server).await?
            } else {
                direct_connect(server.host.as_str(), server.port, server).await?
            };
            tcp.set_nodelay(true)?;
            Ok::<_, NntpError>(tcp)
        };
        let tcp = tcp_connect().await?;

        let wire = if server.tls {
            let name = rustls::pki_types::ServerName::try_from(server.host.clone())
                .map_err(|_| NntpError::TlsName)?;
            // The handshake ladder: kernel TLS (when it is built in,
            // asked for, and the kernel takes it), then userspace
            // rustls on the pinned suite, then userspace rustls on the
            // full cipher list. Every rung consumes its socket, so each
            // one redials - and each rung can only be taken once (kTLS
            // latches off, the full-list decision is remembered per
            // host), so a steady-state connect takes the first and
            // stops.
            let mut tcp = tcp;
            let mut wire = None;
            for _ in 0..3 {
                // Hosts that rejected the AES-128-only offer skip
                // straight to the full suite list instead of paying a
                // doomed handshake each time.
                let full = tls_full_host(&server.host);
                match tls_handshake(name.clone(), tcp, !full).await {
                    Ok(Some(w)) => {
                        wire = Some(w);
                        break;
                    }
                    // The kernel refused the handoff. kTLS is off for
                    // the rest of the process now; this connection just
                    // redials and goes through userspace like any
                    // other.
                    Ok(None) => {}
                    Err(e) if !full => {
                        // The reduced offer failed. It is almost
                        // certainly a real fault (cert, name, network)
                        // that will fail again, but a server supporting
                        // neither AES-128 nor ChaCha would look
                        // identical, and that server must still work.
                        // Remember the host and retry ONCE with
                        // everything; a genuine fault surfaces from the
                        // retry with its own error.
                        mark_tls_full_host(&server.host);
                        eprintln!(
                            "{}: TLS handshake failed on the pinned cipher suite ({e}); \
                             retrying with the full cipher list",
                            server.host
                        );
                    }
                    Err(e) => return Err(e.into()),
                }
                tcp = tcp_connect().await?;
            }
            match wire {
                Some(w) => w,
                // Unreachable: the third rung either connects or
                // returns its own error. An error beats a silent
                // reconnect loop if that ever stops being true.
                None => {
                    return Err(NntpError::Io(std::io::Error::other(
                        "TLS handshake did not settle",
                    )));
                }
            }
        } else {
            Wire::buffered(Box::new(tcp))
        };

        let mut conn = Connection {
            wire,
            line: Vec::with_capacity(512),
            over_supported: None,
            header_gzip: false,
        };

        let greeting = conn.read_status().await?;
        if !matches!(greeting.code, 200 | 201) {
            // Providers reject over-cap connections in the GREETING as
            // often as at AUTHINFO ("502 too many connections" before any
            // command). Route those through the same capacity
            // classification so the pool's one-at-a-time yield path takes
            // over instead of the whole fleet hammering the generic
            // connect-failure backoff. A non-capacity refusal stays
            // Unexpected: a greeting 502 is also plain "permission
            // denied" on some servers, and guessing Permanent there
            // would blacklist a server over a transient wording.
            if matches!(greeting.code, 400..=599)
                && classify_auth_refusal(&greeting.line) == AuthRefusal::Capacity
            {
                return Err(NntpError::AuthFailed {
                    kind: AuthRefusal::Capacity,
                    line: greeting.line,
                });
            }
            return Err(NntpError::Unexpected {
                cmd: "<greeting>".into(),
                line: greeting.line,
            });
        }

        if let (Some(user), Some(pass)) = (&server.username, &server.password) {
            let st = conn.exec(&format!("AUTHINFO USER {user}")).await?;
            let st = match st.code {
                281 => st,
                381 => conn.exec(&format!("AUTHINFO PASS {pass}")).await?,
                _ => {
                    return Err(NntpError::AuthFailed {
                        kind: classify_auth_refusal(&st.line),
                        line: st.line,
                    });
                }
            };
            if st.code != 281 {
                return Err(NntpError::AuthFailed {
                    kind: classify_auth_refusal(&st.line),
                    line: st.line,
                });
            }
        }

        Ok((conn, greeting))
    }

    /// A command line must not contain a bare CR or LF: this is a
    /// CRLF-delimited protocol, so an embedded one ends our command and starts
    /// whatever follows it as a NEW command on an authenticated session. The
    /// values that reach here from untrusted input are NZB message-ids and
    /// group names (`BODY <{id}>`, `GROUP {name}`); those are filtered at the
    /// parse boundary by `nzb::is_wire_safe`, and this is the backstop so a
    /// future command built from a new untrusted field cannot reopen the hole.
    fn check_cmd(cmd: &str) -> Result<(), NntpError> {
        if cmd.bytes().any(|b| b == b'\r' || b == b'\n') {
            return Err(NntpError::Unexpected {
                cmd: "send".into(),
                line: "refusing to send a command containing CR/LF".into(),
            });
        }
        Ok(())
    }

    /// Write a command (CRLF appended) and flush.
    pub async fn send(&mut self, cmd: &str) -> Result<(), NntpError> {
        Self::check_cmd(cmd)?;
        self.wire.write_all(cmd.as_bytes()).await?;
        self.wire.write_all(b"\r\n").await?;
        self.wire.flush().await?;
        Ok(())
    }

    /// Write a pre-formatted raw block (already CRLF-lined and
    /// dot-stuffed - a POST/IHAVE article payload) and flush.
    pub async fn send_raw(&mut self, data: &[u8]) -> Result<(), NntpError> {
        self.wire.write_all(data).await?;
        self.wire.flush().await?;
        Ok(())
    }

    /// Write a command without flushing - for batching pipelined commands.
    pub async fn send_unflushed(&mut self, cmd: &str) -> Result<(), NntpError> {
        Self::check_cmd(cmd)?;
        self.wire.write_all(cmd.as_bytes()).await?;
        self.wire.write_all(b"\r\n").await?;
        Ok(())
    }

    pub async fn flush(&mut self) -> Result<(), NntpError> {
        self.wire.flush().await?;
        Ok(())
    }

    /// Read one status line. Capped: a real status line is well under a
    /// kilobyte, so a peer that streams a status response with no `\n`
    /// (buggy, hostile, or MITM'd) is cut off instead of growing the line
    /// buffer without bound. Mirrors the multiline `MAX_MULTILINE_BYTES`
    /// cap for the single-line path.
    pub async fn read_status(&mut self) -> Result<Status, NntpError> {
        use tokio::io::AsyncReadExt as _; // `.take()` on the reader
        self.line.clear();
        let n = tokio::time::timeout(
            COMMAND_TIMEOUT,
            (&mut self.wire)
                .take(MAX_STATUS_BYTES as u64)
                .read_until(b'\n', &mut self.line),
        )
        .await
        .map_err(|_| NntpError::Timeout)??;
        if n == 0 {
            return Err(NntpError::Closed);
        }
        // Hit the cap without a terminating newline: an over-long status
        // line is not a legitimate response.
        if n >= MAX_STATUS_BYTES && self.line.last() != Some(&b'\n') {
            return Err(NntpError::TooLarge(MAX_STATUS_BYTES));
        }
        let text = String::from_utf8_lossy(&self.line).trim_end().to_string();
        let code = text.get(..3).and_then(|c| c.parse().ok()).unwrap_or(0);
        Ok(Status { code, line: text })
    }

    /// Send a command and read its (single-line) response.
    pub async fn exec(&mut self, cmd: &str) -> Result<Status, NntpError> {
        self.send(cmd).await?;
        self.read_status().await
    }

    /// Read a dot-terminated multiline block, appending the raw wire
    /// bytes (still dot-stuffed) to `out`. The terminator line (a lone
    /// "." on its own line, CRLF or bare-LF) is consumed and not
    /// appended. Bytes after the terminator are NOT consumed - with
    /// pipelining the next response is already in the buffer.
    ///
    /// Bulk path (M32 perf, TODO §3c item 2): the old line-at-a-time
    /// `read_until` loop copied every article twice (BufReader → line →
    /// out) and burned ~20% of the loopback-ceiling CPU in memchr/
    /// memmove. This appends whole `fill_buf` chunks and scans them for
    /// the terminator, with an explicit fix-up for a terminator that
    /// straddles a chunk boundary (at most ".\r" ever needs undoing).
    pub async fn read_multiline_into(&mut self, out: &mut Vec<u8>) -> Result<(), NntpError> {
        read_multiline_generic(&mut self.wire, out).await
    }
}

/// Bound one awaited socket read by [`STREAM_IDLE_TIMEOUT`]. Applied per
/// read rather than around the whole body, which makes it a no-progress
/// deadline: any byte arriving resets it.
async fn idle_bounded<F, T>(f: F) -> Result<T, NntpError>
where
    F: std::future::Future<Output = std::io::Result<T>>,
{
    idle_bounded_for(STREAM_IDLE_TIMEOUT, f).await
}

/// [`idle_bounded`] with a caller-chosen no-progress deadline (the
/// adaptive fetch path runs a much tighter stall bound than the 120 s
/// default; see [`Connection::read_body_into_two_phase`]).
async fn idle_bounded_for<F, T>(d: std::time::Duration, f: F) -> Result<T, NntpError>
where
    F: std::future::Future<Output = std::io::Result<T>>,
{
    match tokio::time::timeout(d, f).await {
        Err(_) => Err(NntpError::Timeout),
        Ok(r) => Ok(r?),
    }
}

/// Read one compressed OVER/XOVER response body (XFEATURE COMPRESS
/// GZIP mode): a single gzip/zlib/raw-deflate stream, then the dot
/// terminator - which some servers compress INTO the stream and others
/// (the "TERMINATOR" capability variant, e.g. Newshosting) append in
/// plain text after it. Decompressed output is appended to `out` with
/// the terminator line stripped, so callers parse exactly what the
/// plain path would have produced. Bounded by [`MAX_MULTILINE_BYTES`]
/// on the DECOMPRESSED size (a hostile peer could otherwise expand a
/// tiny wire stream into gigabytes).
pub(crate) async fn read_gzip_multiline_generic<R>(
    reader: &mut R,
    out: &mut Vec<u8>,
) -> Result<(), NntpError>
where
    R: tokio::io::AsyncBufRead + Unpin,
{
    use tokio::io::{AsyncBufReadExt, AsyncReadExt};
    let start = out.len();
    // Sniff the framing from the first byte: 0x1f = gzip, 0x78 = zlib,
    // anything else = raw deflate (all three seen in the wild for this
    // extension - it predates any spec). flate2's Decompress does zlib
    // and raw only, so the gzip wrapper (RFC 1952 header + 8-byte
    // trailer) is handled here around a raw-deflate stream.
    let first = {
        let buf = idle_bounded(reader.fill_buf()).await?;
        if buf.is_empty() {
            return Err(NntpError::Closed);
        }
        buf[0]
    };
    let bad = |what: &str| NntpError::Unexpected {
        cmd: "OVER (compressed)".into(),
        line: format!("bad compressed stream: {what}"),
    };
    let gzip = first == 0x1f;
    if gzip {
        let mut hdr = [0u8; 10];
        idle_bounded(reader.read_exact(&mut hdr)).await?;
        if hdr[0] != 0x1f || hdr[1] != 0x8b || hdr[2] != 8 {
            return Err(bad("gzip header"));
        }
        let flags = hdr[3];
        if flags & 4 != 0 {
            // FEXTRA: little-endian length + payload.
            let mut l = [0u8; 2];
            idle_bounded(reader.read_exact(&mut l)).await?;
            let mut skip = vec![0u8; u16::from_le_bytes(l) as usize];
            idle_bounded(reader.read_exact(&mut skip)).await?;
        }
        for bit in [8u8, 16] {
            // FNAME / FCOMMENT: null-terminated strings. BOUNDED, like every
            // other read in this function: `idle_bounded` wraps the WHOLE
            // future, so a peer that keeps sending non-NUL bytes never trips
            // a no-progress deadline - it just grows this Vec for the full
            // stream timeout (~15 GB at 1 Gbps, an OOM kill on a NAS). A
            // gzip FNAME is a filename; the terminator search below already
            // uses this same `take` idiom for the same reason.
            if flags & bit != 0 {
                let mut z = Vec::new();
                idle_bounded(reader.take(MAX_STATUS_BYTES as u64).read_until(0, &mut z)).await?;
            }
        }
        if flags & 2 != 0 {
            // FHCRC
            let mut c = [0u8; 2];
            idle_bounded(reader.read_exact(&mut c)).await?;
        }
    }
    let mut d = if gzip {
        flate2::Decompress::new(false)
    } else if first == 0x78 {
        flate2::Decompress::new(true)
    } else {
        flate2::Decompress::new(false)
    };
    let mut tmp = vec![0u8; 64 * 1024];
    'stream: loop {
        let buf = idle_bounded(reader.fill_buf()).await?;
        if buf.is_empty() {
            return Err(NntpError::Closed);
        }
        let mut consumed = 0usize;
        while consumed < buf.len() {
            let before_in = d.total_in();
            let before_out = d.total_out();
            let status = d
                .decompress(&buf[consumed..], &mut tmp, flate2::FlushDecompress::None)
                .map_err(|e| bad(&e.to_string()))?;
            let in_used = (d.total_in() - before_in) as usize;
            let out_made = (d.total_out() - before_out) as usize;
            consumed += in_used;
            out.extend_from_slice(&tmp[..out_made]);
            if out.len() - start > MAX_MULTILINE_BYTES {
                reader.consume(consumed);
                return Err(NntpError::TooLarge(MAX_MULTILINE_BYTES));
            }
            match status {
                flate2::Status::StreamEnd => {
                    reader.consume(consumed);
                    break 'stream;
                }
                // Needs more input than this chunk holds (or made no
                // progress) - refill from the socket.
                flate2::Status::BufError => break,
                flate2::Status::Ok if in_used == 0 && out_made == 0 => break,
                flate2::Status::Ok => {}
            }
        }
        reader.consume(consumed);
    }
    if gzip {
        // RFC 1952 trailer: CRC32 + ISIZE (mod 2^32). Verify the length
        // - cheap corruption check the raw-deflate path can't give us.
        let mut tr = [0u8; 8];
        idle_bounded(reader.read_exact(&mut tr)).await?;
        let isize = u32::from_le_bytes([tr[4], tr[5], tr[6], tr[7]]);
        if isize != ((out.len() - start) as u32) {
            return Err(bad("gzip length mismatch"));
        }
    }
    // Terminator: inside the stream ("\n.\r\n" tail, dot-stuffing makes
    // a lone dot line unambiguous) or plain text on the wire after it.
    if out[start..].ends_with(b"\n.\r\n") {
        out.truncate(out.len() - 3);
        return Ok(());
    }
    if out[start..].ends_with(b"\n.\n") {
        out.truncate(out.len() - 2);
        return Ok(());
    }
    // External terminator (TERMINATOR variant): a lone "." line, with a
    // tolerated leading blank line. Cap the search so a peer that never
    // terminates can't hang us here.
    for _ in 0..2 {
        let mut line = Vec::with_capacity(8);
        use tokio::io::AsyncReadExt as _;
        let n = idle_bounded(
            reader
                .take(MAX_STATUS_BYTES as u64)
                .read_until(b'\n', &mut line),
        )
        .await?;
        if n == 0 {
            return Err(NntpError::Closed);
        }
        let trimmed: &[u8] = {
            let mut t = &line[..];
            while t.last().is_some_and(|b| *b == b'\n' || *b == b'\r') {
                t = &t[..t.len() - 1];
            }
            t
        };
        if trimmed == b"." {
            return Ok(());
        }
        if !trimmed.is_empty() {
            return Err(NntpError::Unexpected {
                cmd: "OVER (compressed)".into(),
                line: String::from_utf8_lossy(&line).into_owned(),
            });
        }
    }
    Err(NntpError::Unexpected {
        cmd: "OVER (compressed)".into(),
        line: "no terminator after compressed block".into(),
    })
}

/// See [`Connection::read_multiline_into`]; generic so tests can drive
/// it with tiny buffer capacities to hit every chunk-boundary case.
pub(crate) async fn read_multiline_generic<R>(
    reader: &mut R,
    out: &mut Vec<u8>,
) -> Result<(), NntpError>
where
    R: tokio::io::AsyncBufRead + Unpin,
{
    read_multiline_paced(reader, out, STREAM_IDLE_TIMEOUT).await
}

/// [`read_multiline_generic`] with a caller-chosen per-read no-progress
/// deadline. Any byte arriving resets it, so a slow-but-alive transfer
/// never trips; only a genuine mid-body stall does.
pub(crate) async fn read_multiline_paced<R>(
    reader: &mut R,
    out: &mut Vec<u8>,
    stall: std::time::Duration,
) -> Result<(), NntpError>
where
    R: tokio::io::AsyncBufRead + Unpin,
{
    {
        use tokio::io::AsyncBufReadExt;
        let start = out.len();
        loop {
            let buf = idle_bounded_for(stall, reader.fill_buf()).await?;
            if buf.is_empty() {
                return Err(NntpError::Closed);
            }
            let block = &out[start..];

            // A terminator begun in the previous chunk: the block so far
            // ends with a dot line under construction. `drop` bytes come
            // back off `out`, `consume` bytes complete it from `buf`.
            let after_nl = |b: &[u8]| b.is_empty() || b.ends_with(b"\n");
            let strad: Option<(usize, usize)> = if block.ends_with(b"\n.") || block == b"." {
                if buf.starts_with(b"\r\n") {
                    Some((1, 2))
                } else if buf[0] == b'\n' {
                    Some((1, 1))
                } else {
                    None
                }
            } else if block.ends_with(b"\n.\r") || block == b".\r" {
                (buf[0] == b'\n').then_some((2, 1))
            } else {
                None
            };
            if let Some((drop, consume)) = strad {
                out.truncate(out.len() - drop);
                reader.consume(consume);
                return Ok(());
            }

            // Scan this chunk for a terminator wholly inside it: a '.'
            // at chunk start (when the block so far ends on a newline)
            // or right after any '\n', followed by CRLF or bare LF. A
            // candidate too close to the chunk end to confirm is left
            // for the straddle logic next round.
            let mut found: Option<(usize, usize)> = None; // (dot idx, term len)
            let confirm = |d: usize| -> Option<(usize, usize)> {
                match buf.get(d + 1) {
                    Some(b'\r') if buf.get(d + 2) == Some(&b'\n') => Some((d, 2)),
                    Some(b'\n') => Some((d, 1)),
                    _ => None,
                }
            };
            if buf[0] == b'.' && after_nl(block) {
                found = confirm(0);
            }
            if found.is_none() {
                for nl in memchr::memchr_iter(b'\n', buf) {
                    if buf.get(nl + 1) == Some(&b'.')
                        && let Some(hit) = confirm(nl + 1)
                    {
                        found = Some(hit);
                        break;
                    }
                }
            }

            match found {
                Some((dot, term)) => {
                    out.extend_from_slice(&buf[..dot]);
                    reader.consume(dot + 1 + term);
                    return Ok(());
                }
                None => {
                    let n = buf.len();
                    out.extend_from_slice(buf);
                    reader.consume(n);
                    if out.len() > MAX_MULTILINE_BYTES {
                        // Terminator never came - protocol fault; the pool
                        // requeues elsewhere instead of buffering unboundedly.
                        return Err(NntpError::TooLarge(MAX_MULTILINE_BYTES));
                    }
                }
            }
        }
    }
}

impl Connection {
    // -- Convenience commands -------------------------------------------------

    pub async fn capabilities(&mut self) -> Result<Vec<String>, NntpError> {
        let st = self.exec("CAPABILITIES").await?;
        if st.code != 101 {
            return Err(NntpError::Unexpected {
                cmd: "CAPABILITIES".into(),
                line: st.line,
            });
        }
        let mut raw = Vec::new();
        self.read_multiline_into(&mut raw).await?;
        Ok(String::from_utf8_lossy(&raw)
            .lines()
            .map(str::to_string)
            .collect())
    }

    /// Try to enable Highwinds-style header compression (`XFEATURE
    /// COMPRESS GZIP`). Returns whether the server accepted (290);
    /// anything else leaves the connection in plain mode - callers can
    /// always attempt this and fall back silently. Only OVER/XOVER
    /// reads change behavior; enable it on scan connections, never on
    /// article-body connections.
    pub async fn enable_header_gzip(&mut self) -> bool {
        if self.header_gzip {
            return true;
        }
        match self.exec("XFEATURE COMPRESS GZIP").await {
            Ok(st) if st.code == 290 => {
                self.header_gzip = true;
                true
            }
            _ => false,
        }
    }

    /// Whether header compression is active (see `enable_header_gzip`).
    pub fn header_gzip(&self) -> bool {
        self.header_gzip
    }

    /// RFC 8054: negotiate DEFLATE for the REST of this connection (both
    /// directions - overview text compresses ~10:1 on byte-throttled
    /// backbones; we have measured backbones where server-side
    /// compression CPU made the XFEATURE variant a LOSS - that is why
    /// callers gate on the CAPABILITIES advert and fall back
    /// hard). Consumes the connection: on Err the half-negotiated stream
    /// is unusable and has been dropped - reconnect uncompressed. Only
    /// the indexer scan path opts in; the download path never should
    /// (yEnc bodies don't compress, the CPU would be pure waste).
    /// Mutually exclusive with the XFEATURE gzip mode by construction:
    /// this wraps the whole transport, that one re-frames OVER reads.
    pub async fn enable_compression(mut self) -> Result<Connection, NntpError> {
        let st = self.exec("COMPRESS DEFLATE").await?;
        if st.code != 206 {
            return Err(NntpError::Unexpected {
                cmd: "COMPRESS DEFLATE".into(),
                line: st.line,
            });
        }
        // Anything read past the 206 line is already deflate-stream
        // bytes - seed the adapter with it, then wrap the transport.
        let leftover = self.wire.take_buffered();
        let stream = self.wire.into_transport();
        let wrapped: Box<dyn Transport> = Box::new(DeflateTransport::new(stream, leftover));
        Ok(Connection {
            wire: Wire::buffered(wrapped),
            line: self.line,
            over_supported: self.over_supported,
            header_gzip: false,
        })
    }

    pub async fn group(&mut self, name: &str) -> Result<GroupInfo, NntpError> {
        let st = self.exec(&format!("GROUP {name}")).await?;
        if st.code != 211 {
            return Err(NntpError::Unexpected {
                cmd: format!("GROUP {name}"),
                line: st.line,
            });
        }
        let mut parts = st.line.split_whitespace().skip(1);
        let mut next = || {
            parts
                .next()
                .and_then(|p| p.parse::<u64>().ok())
                .unwrap_or(0)
        };
        let count = next();
        let low = next();
        let high = next();
        // The article numbers are server-supplied and untrusted. A hostile or
        // buggy server can report `high = u64::MAX` or `low > high`, which the
        // scanner's chunk arithmetic (`lo + chunk - 1`, cursor increments)
        // would wrap - re-scanning ranges forever, i.e. a remotely triggered
        // hang. Reject internally inconsistent bounds at ingress; a genuine
        // group never approaches u64::MAX (article numbers are assigned
        // sequentially and reset well below that), so the ceiling below only
        // ever trips a poisoned response.
        // RFC 3977 §6.1.1.2 gives three legitimate EMPTY-group encodings, and
        // the one servers SHOULD use is `211 0 <high+1> <high>` - the high
        // water mark one BELOW the low water mark, retaining the real
        // high-water value. So `low == high + 1` is not an inconsistency: it
        // is the normal answer for a group whose articles have all expired,
        // and rejecting it would fail that group's scan on every pass forever.
        // Only a gap wider than that is genuinely self-contradictory.
        if low > high.saturating_add(1) {
            return Err(NntpError::Unexpected {
                cmd: format!("GROUP {name}"),
                line: format!("inconsistent bounds low={low} > high={high}"),
            });
        }
        // The scan cursor is an atomic `fetch_add`, which WRAPS. Keeping the
        // ceiling far below u64::MAX means `high + chunk·workers` can never
        // reach it, so a poisoned high-water mark cannot wrap the cursor back
        // to zero and walk the whole u64 space in OVER requests. Real article
        // numbers are assigned sequentially and never approach 2^62.
        if high >= 1 << 62 {
            return Err(NntpError::Unexpected {
                cmd: format!("GROUP {name}"),
                line: format!("implausible high-water mark {high}"),
            });
        }
        Ok(GroupInfo { count, low, high })
    }

    /// `LIST ACTIVE`: every group the server carries, with article
    /// ranges. Multi-megabyte on a full-feed server (~100k+ groups);
    /// the read is idle-bounded like every other multiline response.
    pub async fn list_active(&mut self) -> Result<Vec<ActiveGroup>, NntpError> {
        let st = self.exec("LIST ACTIVE").await?;
        if st.code != 215 {
            return Err(NntpError::Unexpected {
                cmd: "LIST ACTIVE".into(),
                line: st.line,
            });
        }
        let mut raw = Vec::new();
        self.read_multiline_into(&mut raw).await?;
        Ok(parse_list_active(&raw))
    }

    /// `LIST NEWSGROUPS`: one-line descriptions. Optional on many binary
    /// providers - callers treat a rejection as "no descriptions".
    pub async fn list_newsgroups(&mut self) -> Result<Vec<(String, String)>, NntpError> {
        let st = self.exec("LIST NEWSGROUPS").await?;
        if st.code != 215 {
            return Err(NntpError::Unexpected {
                cmd: "LIST NEWSGROUPS".into(),
                line: st.line,
            });
        }
        let mut raw = Vec::new();
        self.read_multiline_into(&mut raw).await?;
        Ok(parse_list_newsgroups(&raw))
    }

    /// OVER (falling back to XOVER) for an article-number range in the
    /// currently selected group.
    pub async fn over(&mut self, from: u64, to: u64) -> Result<Vec<OverEntry>, NntpError> {
        let mut st = if self.over_supported == Some(false) {
            // Known XOVER-only server: don't burn a round-trip on a
            // command it rejects (measured ~10-16 ms per chunk).
            self.exec(&format!("XOVER {from}-{to}")).await?
        } else {
            let st = self.exec(&format!("OVER {from}-{to}")).await?;
            if matches!(st.code, 224 | 423) {
                // 423 is an ANSWER, not a rejection: the server ran OVER
                // and found the range empty. Latching on it too matters
                // because the tip watcher's steady state IS the empty
                // range - without this the very first chunk it asks for
                // leaves the capability undecided, and every later empty
                // chunk pays a doomed XOVER round-trip forever.
                self.over_supported = Some(true);
            } else if matches!(st.code, 400 | 500 | 501) {
                // Some servers (Newshosting) reject OVER outright and
                // only implement the legacy XOVER, with nonstandard
                // error codes ("400 Unrecognized command"). Latch only
                // on unknown/unsupported-command codes - a transient
                // failure (e.g. 503) must not pin a compliant server
                // onto XOVER, which an RFC 3977-only server may not
                // implement at all.
                self.over_supported = Some(false);
            }
            st
        };
        // An empty range is already a complete answer, so it must not be
        // retried as XOVER - that is a round-trip spent to be told the
        // same thing, on every empty chunk, for the life of the process.
        if st.code != 224 && !matches!(st.code, 420 | 423) {
            st = self.exec(&format!("XOVER {from}-{to}")).await?;
        }
        if st.code != 224 {
            // A valid range that simply holds no articles answers 423 (RFC
            // 3977; INN says exactly this), or 420 on older servers. That is
            // an empty result, not a failure: an error here made every
            // resuming scan abandon its pass WITHOUT advancing its
            // high-water mark, so it asked for the same empty range forever.
            // Kept narrow on purpose - 411 no-such-group and every 5xx stay
            // errors, because those mean we learned nothing about the range.
            if matches!(st.code, 420 | 423) {
                return Ok(Vec::new());
            }
            return Err(NntpError::Unexpected {
                cmd: "OVER".into(),
                line: st.line,
            });
        }
        let mut raw = Vec::new();
        if self.header_gzip {
            read_gzip_multiline_generic(&mut self.wire, &mut raw).await?;
        } else {
            self.read_multiline_into(&mut raw).await?;
        }

        let mut entries = Vec::new();
        for line in raw.split(|&b| b == b'\n') {
            if let Some(e) = parse_over_line(line) {
                entries.push(e);
            }
        }
        Ok(entries)
    }

    /// Issue a BODY command without waiting for the response (pipelining).
    /// `message_id` must include the angle brackets.
    pub async fn send_body(&mut self, message_id: &str) -> Result<(), NntpError> {
        self.send_unflushed(&format!("BODY {message_id}")).await
    }

    /// Read one BODY response into a caller-supplied buffer (buffer-pool
    /// friendly). `Ok(true)` on 222 with the raw dot-stuffed body appended
    /// to `out`; `Ok(false)` if the article is missing (423/430, plus
    /// Giganews's nonstandard "451 0 <msgid>" for removed/DMCA'd
    /// articles - the same shape `read_stat` already accepts).
    ///
    /// 451 belongs here for the same reason it belongs there, only the
    /// stakes are higher: on this path a protocol error is a SESSION
    /// failure, so it drops the connection and charges the session-backoff
    /// ladder. A takedown is hundreds of adjacent articles, so treating
    /// them as protocol errors retires every worker on that server against
    /// the give-up ceiling - turning "one removed file fails" into "the
    /// whole job fails" on a single-server setup. A removed article is a
    /// miss, not a broken conversation.
    ///
    /// `expected`: the message-id this response is being attributed to
    /// (with angle brackets). On the pipelined path attribution is
    /// positional, so when the status line echoes a DIFFERENT id the
    /// conversation has desynced and this errors ([`NntpError::IdMismatch`],
    /// a session-level failure). `None` skips the check (serial
    /// callers that own the whole conversation).
    ///
    /// `miss_echoed`: set on a miss to whether the refusal line echoed
    /// a (matching) message-id. An un-echoed miss is positional-only
    /// evidence - if an upstream frontend dropped the previous
    /// pipelined response, this "430 no such article" belongs to the
    /// NEXT article - and the pool treats it as suspect rather than
    /// authoritative (see `handle_missing`).
    pub async fn read_body_into(
        &mut self,
        out: &mut Vec<u8>,
        expected: Option<&str>,
        miss_echoed: &std::sync::atomic::AtomicBool,
    ) -> Result<bool, NntpError> {
        let st = self.read_status().await?;
        check_echoed_id(&st, expected)?;
        match st.code {
            222 => {
                self.read_multiline_into(out).await?;
                Ok(true)
            }
            423 | 430 | 451 => {
                // A plausible id on the line already passed
                // check_echoed_id, so presence = confirmed echo.
                miss_echoed.store(
                    echoed_message_id(&st.line).is_some(),
                    std::sync::atomic::Ordering::Release,
                );
                Ok(false)
            }
            _ => Err(NntpError::Unexpected {
                cmd: "BODY".into(),
                line: st.line,
            }),
        }
    }

    /// [`read_body_into`] decomposed into the two phases a flat
    /// whole-response timeout conflates:
    ///
    /// - **pre-byte** (`first_byte`): dispatch to status line. This is
    ///   where a dead connection sits, and where a tight adaptive bound
    ///   (the pool derives it from a per-server TTFB EWMA) detects it in
    ///   seconds instead of the flat timeout's worst case.
    /// - **post-byte** (`stall`): a per-read no-progress deadline on the
    ///   body. Any byte arriving resets it, so a slow-but-alive transfer
    ///   is never killed for taking longer than a flat cap - only a
    ///   genuine mid-body stall trips.
    ///
    /// Both expiries surface as [`NntpError::Timeout`]. Returns the
    /// measured time-to-status alongside the hit/miss so the caller can
    /// feed its EWMA (measured for misses too: a 430 is a healthy,
    /// timed response).
    pub async fn read_body_into_two_phase(
        &mut self,
        out: &mut Vec<u8>,
        expected: Option<&str>,
        first_byte: std::time::Duration,
        stall: std::time::Duration,
    ) -> Result<(bool, std::time::Duration), NntpError> {
        let status_seen = std::sync::atomic::AtomicBool::new(false);
        let miss_echoed = std::sync::atomic::AtomicBool::new(false);
        self.read_body_into_two_phase_noting(
            out,
            expected,
            first_byte,
            stall,
            &status_seen,
            &miss_echoed,
        )
        .await
    }

    /// [`read_body_into_two_phase`], additionally flipping `status_seen`
    /// the moment the status line lands - so a caller racing this read
    /// against a suspicion timer (the TODO 115 TTFB hedge) can tell "still
    /// in pre-byte silence" from "bytes are flowing, just slowly" without
    /// waiting for the read to finish.
    pub async fn read_body_into_two_phase_noting(
        &mut self,
        out: &mut Vec<u8>,
        expected: Option<&str>,
        first_byte: std::time::Duration,
        stall: std::time::Duration,
        status_seen: &std::sync::atomic::AtomicBool,
        miss_echoed: &std::sync::atomic::AtomicBool,
    ) -> Result<(bool, std::time::Duration), NntpError> {
        let t0 = std::time::Instant::now();
        let st = match tokio::time::timeout(first_byte, self.read_status()).await {
            Err(_) => return Err(NntpError::Timeout),
            Ok(r) => r?,
        };
        status_seen.store(true, std::sync::atomic::Ordering::Release);
        let ttfb = t0.elapsed();
        check_echoed_id(&st, expected)?;
        match st.code {
            222 => {
                read_multiline_paced(&mut self.wire, out, stall).await?;
                Ok((true, ttfb))
            }
            423 | 430 | 451 => {
                // See `read_body_into`: presence of a plausible id
                // means it matched `expected` above.
                miss_echoed.store(
                    echoed_message_id(&st.line).is_some(),
                    std::sync::atomic::Ordering::Release,
                );
                Ok((false, ttfb))
            }
            _ => Err(NntpError::Unexpected {
                cmd: "BODY".into(),
                line: st.line,
            }),
        }
    }

    /// Fetch an article's headers via HEAD. `Ok(Some(raw))` on 221 with the
    /// raw dot-stuffed header block appended, `Ok(None)` if the article is
    /// missing (423/430). Spot ingestion (M14j) uses this: the full spot
    /// XML rides in X-XML continuation headers, no body fetch needed.
    pub async fn head(&mut self, message_id: &str) -> Result<Option<Vec<u8>>, NntpError> {
        let st = self.exec(&format!("HEAD {message_id}")).await?;
        match st.code {
            221 => {
                let mut raw = Vec::new();
                self.read_multiline_into(&mut raw).await?;
                Ok(Some(raw))
            }
            // 451 for the same reason as STAT and BODY: a removed article
            // is a miss. Spot ingestion HEADs in batches, so a takedown
            // run would otherwise error out whole batches rather than
            // skipping the articles that are gone.
            423 | 430 | 451 => Ok(None),
            _ => Err(NntpError::Unexpected {
                cmd: "HEAD".into(),
                line: st.line,
            }),
        }
    }

    /// Issue a STAT command without waiting for the response (pipelining).
    /// STAT transfers no body - ~50 bytes per round trip - which is what
    /// makes the pre-flight availability sweep near-free.
    pub async fn send_stat(&mut self, message_id: &str) -> Result<(), NntpError> {
        self.send_unflushed(&format!("STAT {message_id}")).await
    }

    /// Read one STAT response: `Ok(true)` if the article exists (223),
    /// `Ok(false)` if not (423/430, plus Giganews's nonstandard
    /// "451 0 <msgid>" for removed/DMCA'd articles - treating that as a
    /// protocol error threw away whole sample batches, so Giganews
    /// takedowns were never counted as misses).
    pub async fn read_stat(&mut self) -> Result<bool, NntpError> {
        let st = self.read_status().await?;
        match st.code {
            223 => Ok(true),
            423 | 430 | 451 => Ok(false),
            _ => Err(NntpError::Unexpected {
                cmd: "STAT".into(),
                line: st.line,
            }),
        }
    }

    /// Read one BODY response. `Ok(Some(raw))` on 222 (raw dot-stuffed body,
    /// ready for `yenc::decode`), `Ok(None)` if the article is missing.
    /// Serial path (one command in flight): no echoed-id enforcement.
    pub async fn read_body(&mut self) -> Result<Option<Vec<u8>>, NntpError> {
        let mut raw = Vec::with_capacity(800 * 1024);
        let miss_echoed = std::sync::atomic::AtomicBool::new(false);
        Ok(self
            .read_body_into(&mut raw, None, &miss_echoed)
            .await?
            .then_some(raw))
    }

    /// Polite disconnect - lets the server release the session immediately
    /// instead of waiting out a TCP timeout on an abrupt close. Hard-bounded:
    /// a peer can take the QUIT and never answer (seen live - a provider
    /// ACKed the QUIT at TCP level, sent no goodbye, and the unbounded read
    /// here parked a completed 190 GB job forever). Both results are
    /// discarded and dropping `self` closes the socket regardless, so the
    /// bound only caps how long we stay polite.
    pub async fn quit(mut self) {
        let _ = tokio::time::timeout(quit_bound(), async {
            let _ = self.send("QUIT").await;
            let _ = self.read_status().await;
        })
        .await;
    }

    /// RFC 3977 DATE: the cheapest thing that proves a session is still
    /// alive end to end. One line out, one line back, no state touched -
    /// which is what makes it the right keepalive and the right
    /// validation for a connection parked between jobs (see
    /// [`crate::warmpool`]). Bounded by [`COMMAND_TIMEOUT`] through
    /// `read_status`, so a peer that has gone mute fails rather than
    /// parking the caller.
    ///
    /// Any status other than 111 is still a live, responsive server, so
    /// it counts as success for liveness purposes; only an I/O or
    /// protocol failure means the session is gone.
    pub async fn date(&mut self) -> Result<Status, NntpError> {
        self.exec("DATE").await
    }

    /// Fetch one article body, blocking on the response (the serial path).
    pub async fn body(&mut self, message_id: &str) -> Result<Option<Vec<u8>>, NntpError> {
        self.send(&format!("BODY {message_id}")).await?;
        self.read_body().await
    }
}

#[cfg(test)]
mod tls_provider_tests {
    use super::tls_provider;

    fn is_chacha(s: &rustls::SupportedCipherSuite) -> bool {
        format!("{:?}", s.suite()).contains("CHACHA20")
    }

    fn is_aes128(s: &rustls::SupportedCipherSuite) -> bool {
        format!("{:?}", s.suite()).contains("AES_128")
    }

    /// The pinned offer must contain EXACTLY ONE algorithm, because a
    /// TLS 1.3 server picks from its own preference order: an offer with
    /// two entries is the server's choice, not ours. This is the
    /// regression guard for the measured trap - dropping only AES-256
    /// left {AES-128, ChaCha} and 4 of 6 providers answered ChaCha,
    /// which is ~4x slower per byte than the AES-256 it replaced.
    #[test]
    fn pinned_offer_is_a_single_algorithm() {
        let aes = tls_provider(true, true);
        assert!(!aes.cipher_suites.is_empty());
        assert!(
            aes.cipher_suites.iter().all(is_aes128),
            "hardware-AES CPUs must offer AES-128 and nothing else: {:?}",
            aes.cipher_suites
        );

        let soft = tls_provider(false, true);
        assert!(!soft.cipher_suites.is_empty());
        assert!(
            soft.cipher_suites.iter().all(is_chacha),
            "soft-AES CPUs must offer ChaCha20 and nothing else: {:?}",
            soft.cipher_suites
        );
    }

    #[test]
    fn unaccelerated_cpu_gets_chacha_first_in_the_fallback() {
        let p = tls_provider(false, false);
        assert!(is_chacha(&p.cipher_suites[0]), "{:?}", p.cipher_suites);
        // Stable partition: every ChaCha suite precedes every AES suite,
        // and the AES suites keep aws-lc-rs's own relative order.
        let first_aes = p.cipher_suites.iter().position(|s| !is_chacha(s)).unwrap();
        assert!(p.cipher_suites[first_aes..].iter().all(|s| !is_chacha(s)));
        let default = rustls::crypto::aws_lc_rs::default_provider();
        let aes_order: Vec<_> = p.cipher_suites[first_aes..]
            .iter()
            .map(|s| s.suite())
            .collect();
        let default_aes: Vec<_> = default
            .cipher_suites
            .iter()
            .filter(|s| !is_chacha(s))
            .map(|s| s.suite())
            .collect();
        assert_eq!(aes_order, default_aes);
    }

    /// The policy has to reach the handshake. `tls_provider` decides
    /// what to offer, but what a connection actually offers is whatever
    /// `tls_client_config` built - and the two only stay in step while
    /// nothing else in this file constructs a `ClientConfig` of its
    /// own. Verified live on x86_64 (2 Aug): a connection to the bench
    /// server negotiates TLSv1_3 / TLS13_AES_128_GCM_SHA256, which is
    /// the single suite this pin offers.
    #[test]
    fn the_shared_config_carries_the_pinned_offer() {
        let cfg = super::tls_client_config(true);
        let got: Vec<_> = cfg
            .crypto_provider()
            .cipher_suites
            .iter()
            .map(|s| s.suite())
            .collect();
        let want: Vec<_> = tls_provider(super::aes_accelerated(), true)
            .cipher_suites
            .iter()
            .map(|s| s.suite())
            .collect();
        assert_eq!(got, want, "the built config must offer the pinned suite");
        // Extractable traffic secrets are for kTLS and nothing else, so
        // a process that did not ask for kTLS must not have them.
        assert_eq!(cfg.enable_secret_extraction, super::ktls_wanted());
    }

    /// The fallback path must stay a superset - it is what rescues a
    /// server that cannot do the pinned suite.
    #[test]
    fn accelerated_cpu_fallback_keeps_default_order() {
        let p = tls_provider(true, false);
        let default = rustls::crypto::aws_lc_rs::default_provider();
        let got: Vec<_> = p.cipher_suites.iter().map(|s| s.suite()).collect();
        let want: Vec<_> = default.cipher_suites.iter().map(|s| s.suite()).collect();
        assert_eq!(got, want);
    }
}

#[cfg(test)]
mod over_tests {
    use super::Connection;
    use crate::mock::{Chaos, MockServer, OverRow};
    use std::collections::HashMap;

    fn rows() -> Vec<OverRow> {
        (1..=5)
            .map(|n| OverRow {
                number: n,
                subject: format!("post {n}"),
                from: "a@b".into(),
                message_id: format!("<m{n}@x>"),
                bytes: 1000,
            })
            .collect()
    }

    #[tokio::test]
    async fn xover_only_server_latches_after_first_rejection() {
        let srv = MockServer::start_full(
            HashMap::new(),
            HashMap::new(),
            rows(),
            Chaos {
                xover_only: true,
                ..Default::default()
            },
        )
        .await;
        let (mut conn, _) = Connection::connect(&srv.server_config())
            .await
            .expect("connect");
        conn.group("mock.group").await.expect("group");
        let es = conn.over(1, 5).await.expect("over via xover fallback");
        assert_eq!(es.len(), 5);
        assert_eq!(
            conn.over_supported,
            Some(false),
            "unknown-command rejection must latch the XOVER-only path"
        );
        // Second call goes straight to XOVER (no doomed OVER round-trip)
        // and still returns rows.
        let es = conn.over(2, 4).await.expect("second over");
        assert_eq!(es.len(), 3);
        conn.quit().await;
    }

    #[tokio::test]
    async fn gzip_headers_roundtrip_and_fallback() {
        // Server accepts XFEATURE: compressed responses parse to the
        // same entries the plain path produces, repeatedly.
        let srv = MockServer::start_full(
            HashMap::new(),
            HashMap::new(),
            rows(),
            Chaos {
                gzip_headers: true,
                ..Default::default()
            },
        )
        .await;
        let (mut conn, _) = Connection::connect(&srv.server_config())
            .await
            .expect("connect");
        conn.group("mock.group").await.expect("group");
        assert!(conn.enable_header_gzip().await, "290 must enable");
        let es = conn.over(1, 5).await.expect("compressed over");
        assert_eq!(es.len(), 5);
        assert_eq!(es[0].subject, "post 1");
        assert_eq!(es[4].message_id, "<m5@x>");
        let es = conn.over(2, 3).await.expect("second compressed over");
        assert_eq!(es.len(), 2);
        conn.quit().await;

        // Server that rejects the feature: enable returns false and the
        // plain path still works untouched.
        let srv =
            MockServer::start_full(HashMap::new(), HashMap::new(), rows(), Chaos::default()).await;
        let (mut conn, _) = Connection::connect(&srv.server_config())
            .await
            .expect("connect");
        conn.group("mock.group").await.expect("group");
        assert!(!conn.enable_header_gzip().await, "no 290 = stay plain");
        let es = conn.over(1, 5).await.expect("plain over");
        assert_eq!(es.len(), 5);
        conn.quit().await;
    }

    #[tokio::test]
    async fn over_capable_server_latches_supported() {
        let srv =
            MockServer::start_full(HashMap::new(), HashMap::new(), rows(), Chaos::default()).await;
        let (mut conn, _) = Connection::connect(&srv.server_config())
            .await
            .expect("connect");
        conn.group("mock.group").await.expect("group");
        let es = conn.over(1, 5).await.expect("over");
        assert_eq!(es.len(), 5);
        assert_eq!(conn.over_supported, Some(true));
        conn.quit().await;
    }

    #[tokio::test]
    async fn empty_range_reads_as_no_articles_not_a_failed_pass() {
        // A resuming scan asks for everything above its high-water mark.
        // When nothing new has arrived, that range is valid and empty and
        // the server answers 423. Reading that as a failure stalled the
        // whole pass: the caller bailed out, never advanced its mark, and
        // asked for the identical empty range on every retry, forever.
        let srv =
            MockServer::start_full(HashMap::new(), HashMap::new(), rows(), Chaos::default()).await;
        let (mut conn, _) = Connection::connect(&srv.server_config())
            .await
            .expect("connect");
        let g = conn.group("mock.group").await.expect("group");
        let es = conn
            .over(g.high + 1, g.high + 1000)
            .await
            .expect("an empty range is not a failure");
        assert!(es.is_empty(), "an empty range yields no rows");
        // And the session survives it - nothing was left half-read on the
        // wire, so the next chunk of the same pass still returns its rows.
        let es = conn.over(1, 5).await.expect("over after an empty range");
        assert_eq!(es.len(), 5);
        conn.quit().await;
    }

    #[tokio::test]
    async fn a_rejected_over_is_still_an_error() {
        // The empty-range arm stays narrow: 411 no-such-group (like every
        // 5xx) means we learned NOTHING about the range, so it must not
        // read as "nothing here" and let a caller skip past those articles.
        let srv = MockServer::start_full(
            HashMap::new(),
            HashMap::new(),
            rows(),
            Chaos {
                over_rejected: true,
                ..Default::default()
            },
        )
        .await;
        let (mut conn, _) = Connection::connect(&srv.server_config())
            .await
            .expect("connect");
        conn.group("mock.group").await.expect("group");
        assert!(
            conn.over(1, 5).await.is_err(),
            "411 must not be mistaken for an empty range"
        );
        conn.quit().await;
    }
}

#[cfg(test)]
mod compress_tests {
    use super::{Connection, caps_support_compress_deflate};

    #[test]
    fn list_active_parses_and_skips_junk() {
        let raw = b"alt.binaries.teevee 9000 100 y\n\
                    rec.autos.sport.f1 555 12 m\n\
                    broken-line\n\
                    bad.numbers x y z\n\
                    huge.high 4611686018427387904 1 y\n\
                    no.status 50 10\n";
        let g = super::parse_list_active(raw);
        assert_eq!(g.len(), 3);
        assert_eq!(g[0].name, "alt.binaries.teevee");
        assert_eq!((g[0].high, g[0].low, g[0].status), (9000, 100, 'y'));
        assert_eq!(g[1].status, 'm');
        assert_eq!((g[2].name.as_str(), g[2].status), ("no.status", 'y'));
    }

    #[test]
    fn list_newsgroups_parses_tab_and_space_and_drops_placeholders() {
        let raw = b"rec.autos.sport.f1\tFormula 1 motor racing.\n\
                    alt.binaries.sounds.mp3 Music binaries.\n\
                    alt.empty.desc\t?\n\
                    alt.no.desc\n";
        let d = super::parse_list_newsgroups(raw);
        assert_eq!(d.len(), 2);
        assert_eq!(
            d[0],
            (
                "rec.autos.sport.f1".into(),
                "Formula 1 motor racing.".into()
            )
        );
        assert_eq!(d[1].1, "Music binaries.");
    }

    fn caps(lines: &[&str]) -> Vec<String> {
        lines.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn detects_compress_deflate_capability() {
        assert!(caps_support_compress_deflate(&caps(&[
            "VERSION 2",
            "COMPRESS DEFLATE"
        ])));
        // Case-insensitive; DEFLATE may be one of several algorithms.
        assert!(caps_support_compress_deflate(&caps(&[
            "compress shrink deflate"
        ])));
        assert!(!caps_support_compress_deflate(&caps(&[
            "VERSION 2",
            "OVER"
        ])));
        assert!(!caps_support_compress_deflate(&caps(&["COMPRESS SHRINK"])));
        // Label must be exactly COMPRESS, not merely contain it.
        assert!(!caps_support_compress_deflate(&caps(&[
            "XCOMPRESS DEFLATE"
        ])));
        assert!(!caps_support_compress_deflate(&[]));
    }

    fn test_server_config(port: u16) -> crate::config::ServerConfig {
        crate::config::ServerConfig {
            host: "127.0.0.1".into(),
            port,
            tls: false,
            username: None,
            password: None,
            connections: 1,
            pin_connections: false,
            rcvbuf: None,
            level: 0,
            group: None,
            retention_days: 0,
            block_bytes: None,
            bind_ip: None,
            socks5: None,
            enabled: true,
            warm_pool: false,
            idle_release_secs: None,
            idle_keep: None,
            max_source_ips: None,
        }
    }

    /// Read one CRLF line a byte at a time - deliberately unbuffered so
    /// the plain→compressed switch can't strand bytes in a reader.
    fn read_line<R: std::io::Read>(r: &mut R) -> std::io::Result<String> {
        let mut line = Vec::new();
        let mut b = [0u8; 1];
        loop {
            let n = r.read(&mut b)?;
            if n == 0 || b[0] == b'\n' {
                break;
            }
            line.push(b[0]);
        }
        while line.last() == Some(&b'\r') {
            line.pop();
        }
        Ok(String::from_utf8_lossy(&line).into_owned())
    }

    /// Minimal RFC 8054 server: plain greeting/CAPABILITIES, then after
    /// COMPRESS DEFLATE → 206 both directions become raw deflate.
    /// `rows` controls the size of each OVER block so tests can push the
    /// adapter past its internal 16 KiB staging buffers.
    fn spawn_deflate_server(rows: u64, refuse_compress: bool) -> u16 {
        fn handle(
            mut sock: std::net::TcpStream,
            rows: u64,
            refuse_compress: bool,
        ) -> std::io::Result<()> {
            use std::io::Write;
            sock.write_all(b"200 deflate test server\r\n")?;
            loop {
                match read_line(&mut sock)?.as_str() {
                    "CAPABILITIES" => {
                        sock.write_all(b"101 caps\r\nVERSION 2\r\nCOMPRESS DEFLATE\r\n.\r\n")?
                    }
                    "COMPRESS DEFLATE" => {
                        if refuse_compress {
                            sock.write_all(b"502 compression not available\r\n")?;
                            continue;
                        }
                        sock.write_all(b"206 compression active\r\n")?;
                        break;
                    }
                    "QUIT" => return sock.write_all(b"205 bye\r\n"),
                    "" => return Ok(()), // client hung up
                    _ => sock.write_all(b"500 what\r\n")?,
                }
            }
            // Compressed phase. flate2's blocking wrappers do the
            // server-side framing: DeflateEncoder::flush is a sync
            // flush, matching what the client adapter expects.
            // The decoder MUST sit under a BufReader: miniz consumes a
            // whole input frame eagerly and parks decoded bytes in its
            // window, and flate2's read::DeflateDecoder blocks for MORE
            // wire input before draining that window when handed tiny
            // dst buffers - so read_line's 1-byte reads yield one byte
            // and then deadlock on a socket that stays open. Reading
            // through BufReader makes each decoder call an 8 KiB read,
            // which drains whole lines per frame. (Found the hard way -
            // this exact line was the round-trip "deadlock".)
            let mut rd =
                std::io::BufReader::new(flate2::read::DeflateDecoder::new(sock.try_clone()?));
            let mut wr = flate2::write::DeflateEncoder::new(sock, flate2::Compression::default());
            loop {
                let cmd = read_line(&mut rd)?;
                if cmd.starts_with("GROUP ") {
                    write!(wr, "211 {rows} 1 {rows} mock.group\r\n")?;
                } else if cmd.starts_with("OVER ") || cmd.starts_with("XOVER ") {
                    wr.write_all(b"224 overview follows\r\n")?;
                    for n in 1..=rows {
                        write!(
                            wr,
                            "{n}\tpost {n} with a subject long enough to be worth \
                             compressing\ta@b\tThu, 02 May 2024 12:34:56 +0000\t\
                             <m{n}@x>\t\t1000\t10\r\n"
                        )?;
                    }
                    wr.write_all(b".\r\n")?;
                } else if cmd == "QUIT" || cmd.is_empty() {
                    let _ = wr.write_all(b"205 bye\r\n");
                    let _ = wr.flush();
                    return Ok(());
                } else {
                    wr.write_all(b"500 what\r\n")?;
                }
                wr.flush()?;
            }
        }
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            // Sequential accepts: the refusal test reconnects after the
            // failed COMPRESS exchange drops the first connection.
            for sock in listener.incoming() {
                let Ok(sock) = sock else { return };
                let _ = handle(sock, rows, refuse_compress);
            }
        });
        port
    }

    /// Adapter-only round trip over an in-memory duplex: no mock TCP
    /// server, no flate2 blocking codecs on the far side - the test
    /// itself decompresses what the adapter wrote and hand-compresses
    /// the response. Isolates DeflateTransport correctness from the
    /// mock-server plumbing when hunting the round-trip deadlock.
    #[tokio::test]
    async fn deflate_transport_duplex_isolated() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (client_end, mut wire_end) = tokio::io::duplex(64 * 1024);
        let boxed: Box<dyn super::Transport> = Box::new(client_end);
        let wrapped: Box<dyn super::Transport> =
            Box::new(super::DeflateTransport::new(boxed, Vec::new()));
        let (mut r, mut w) = tokio::io::split(wrapped);

        // Client → wire: write a command + flush, then read the raw
        // compressed bytes off the far end and inflate them by hand.
        w.write_all(b"GROUP mock.group\r\n").await.unwrap();
        w.flush().await.unwrap();
        let mut raw = vec![0u8; 4096];
        let n = tokio::time::timeout(std::time::Duration::from_secs(5), wire_end.read(&mut raw))
            .await
            .expect("adapter never wrote to the wire after flush")
            .unwrap();
        assert!(n > 0, "flush wrote nothing");
        let mut dec = flate2::Decompress::new(false);
        let mut out = Vec::with_capacity(1024);
        dec.decompress_vec(&raw[..n], &mut out, flate2::FlushDecompress::None)
            .expect("client frame inflates");
        assert_eq!(&out, b"GROUP mock.group\r\n", "sync-flushed frame decodes");

        // Wire → client: hand-compress a response with a sync flush and
        // read it back through the adapter.
        let mut enc = flate2::Compress::new(flate2::Compression::default(), false);
        let mut frame = Vec::with_capacity(1024);
        enc.compress_vec(
            b"211 5 1 5 mock.group\r\n",
            &mut frame,
            flate2::FlushCompress::Sync,
        )
        .unwrap();
        wire_end.write_all(&frame).await.unwrap();
        let mut got = vec![0u8; 64];
        let n = tokio::time::timeout(std::time::Duration::from_secs(5), r.read(&mut got))
            .await
            .expect("adapter never yielded decompressed bytes")
            .unwrap();
        assert_eq!(&got[..n], b"211 5 1 5 mock.group\r\n");
    }

    // (The 24 Jul "deadlock" here was the MOCK SERVER's read pattern -
    // 1-byte reads through a raw read::DeflateDecoder block for wire
    // input while decoded bytes sit in miniz's window; see the BufReader
    // note in spawn_deflate_server. The shipping adapter was never at
    // fault - deflate_transport_duplex_isolated pins that directly.)
    #[tokio::test]
    async fn deflate_round_trip_group_and_over() {
        // 2000 rows ≈ 250 KB of overview text - well past the adapter's
        // 16 KiB staging buffers, so the chunked-decompress path runs.
        let port = spawn_deflate_server(2000, false);
        let cfg = test_server_config(port);
        let (mut conn, _) = Connection::connect(&cfg).await.expect("connect");
        let caps = conn.capabilities().await.expect("capabilities");
        assert!(caps_support_compress_deflate(&caps));
        let mut conn = conn.enable_compression().await.expect("206 + wrap");
        let g = conn.group("mock.group").await.expect("group over deflate");
        assert_eq!(g.high, 2000);
        let es = conn.over(1, 2000).await.expect("over over deflate");
        assert_eq!(es.len(), 2000);
        assert_eq!(es[0].message_id, "<m1@x>");
        assert_eq!(es[1999].number, 2000);
        // A second command proves stream continuity across sync-flush
        // boundaries - RFC 8054 is one continuous deflate stream, not
        // per-response streams.
        let es = conn.over(1, 2000).await.expect("second over");
        assert_eq!(es.len(), 2000);
        conn.quit().await;
    }

    /// A removed article answered with Giganews's nonstandard 451 is a
    /// MISS, not a protocol error. `read_stat` has always known that; the
    /// BODY path did not, and there it costs far more: a protocol error
    /// drops the session and charges the session-backoff ladder, so a
    /// takedown (hundreds of adjacent articles) retired every worker on
    /// the server against the give-up ceiling and failed the whole job
    /// instead of just the removed file.
    #[tokio::test]
    async fn a_451_takedown_on_body_is_a_miss_not_a_protocol_error() {
        fn spawn_451_server() -> u16 {
            use std::io::Write;
            let l = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
            let port = l.local_addr().unwrap().port();
            std::thread::spawn(move || {
                let Ok((mut sock, _)) = l.accept() else {
                    return;
                };
                let _ = sock.write_all(b"200 takedown test server\r\n");
                loop {
                    let Ok(line) = read_line(&mut sock) else {
                        return;
                    };
                    if line.is_empty() {
                        return;
                    }
                    if line == "QUIT" {
                        let _ = sock.write_all(b"205 bye\r\n");
                        return;
                    }
                    if line.starts_with("BODY ") {
                        let _ = sock.write_all(b"451 0 <gone@example>\r\n");
                    } else {
                        let _ = sock.write_all(b"500 what\r\n");
                    }
                }
            });
            port
        }

        let cfg = test_server_config(spawn_451_server());
        let (mut conn, _) = Connection::connect(&cfg).await.expect("connect");
        conn.send_body("<gone@example>").await.expect("send BODY");
        let mut raw = Vec::new();
        // Expected id supplied: the 451 echoes the SAME id, so the
        // echoed-id check must stay quiet and the miss must stand.
        let miss_echoed = std::sync::atomic::AtomicBool::new(false);
        let got = conn
            .read_body_into(&mut raw, Some("<gone@example>"), &miss_echoed)
            .await;
        assert!(
            matches!(got, Ok(false)),
            "451 must read as a missing article, got {got:?}"
        );
        assert!(
            miss_echoed.load(std::sync::atomic::Ordering::Acquire),
            "an id-echoing refusal must report a confirmed echo"
        );
        assert!(raw.is_empty(), "a miss must append no body bytes");
        // The session survives: that is the whole point, since dropping it
        // is what charged the backoff ladder.
        conn.send_body("<gone2@example>")
            .await
            .expect("reuse session");
        let mut raw2 = Vec::new();
        // This rigged server echoes <gone@example> whatever was asked;
        // the serial caller passes None, so no enforcement applies.
        let miss_echoed2 = std::sync::atomic::AtomicBool::new(false);
        assert!(matches!(
            conn.read_body_into(&mut raw2, None, &miss_echoed2).await,
            Ok(false)
        ));
        conn.quit().await;
    }

    #[tokio::test]
    async fn refused_compress_errors_and_a_plain_reconnect_works() {
        // A server that advertises COMPRESS but refuses the exchange:
        // enable_compression must fail cleanly (connection consumed),
        // and a fresh uncompressed connection must still work - the
        // provider-tolerance contract the scan path relies on.
        let port = spawn_deflate_server(5, true);
        let cfg = test_server_config(port);
        let (conn, _) = Connection::connect(&cfg).await.expect("connect");
        let err = conn
            .enable_compression()
            .await
            .err()
            .expect("502 must error");
        assert!(
            matches!(err, super::NntpError::Unexpected { .. }),
            "{err:?}"
        );
        let (conn2, _) = Connection::connect(&cfg).await.expect("plain reconnect");
        conn2.quit().await;
    }
}

// Read-ladder unit tests (coverage §122.5) - a child module, the
// pool/unit_tests.rs pattern, so nntp.rs stays inside its size-gate
// entry while `super::*` keeps the private internals reachable.
#[cfg(test)]
mod unit_tests;

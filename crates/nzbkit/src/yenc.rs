//! Reference yEnc codec (scalar).
//!
//! This is the *correctness oracle*: simple, obviously-right code used for
//! tests and as the differential baseline when the rapidyenc SIMD path lands.
//! It is fast enough for prototyping (~hundreds of MB/s) but the production
//! decode path will be rapidyenc via FFI.
//!
//! yEnc in one paragraph: every payload byte is `(b + 42) mod 256`; the
//! critical output bytes NUL, LF, CR and `=` are escaped as `=` followed by
//! `(b + 64) mod 256`. Articles carry `=ybegin` / `=ypart` / `=yend` header
//! lines with sizes, part byte-ranges (1-based inclusive) and CRC32s. On the
//! wire, NNTP dot-stuffs lines starting with `.` (doubles the dot); we undo
//! that by stripping exactly one leading dot from any line that starts with
//! one, which is what the production SIMD path does too.

use std::collections::HashMap;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum YencError {
    #[error("no =ybegin header found")]
    MissingBegin,
    #[error("=yend size {actual} does not match decoded length {expected}")]
    LengthMismatch { expected: u64, actual: u64 },
    #[error("CRC32 mismatch: decoded {computed:08x}, header says {header:08x}")]
    CrcMismatch { computed: u32, header: u32 },
    #[error("article ended without a =yend trailer (truncated)")]
    Truncated,
}

/// A decoded yEnc article (one part of a file, or a whole small file).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decoded {
    /// Filename from `=ybegin name=`.
    pub name: String,
    /// Total file size from `=ybegin size=`.
    pub file_size: u64,
    /// Part number from `=ybegin part=` (None for single-part posts).
    pub part: Option<u32>,
    /// 1-based inclusive byte range from `=ypart begin=`/`end=`.
    /// For single-part posts this covers the whole file.
    pub begin: u64,
    pub end: u64,
    pub data: Vec<u8>,
}

impl Decoded {
    /// Zero-based file offset where `data` belongs - feed straight to pwrite.
    /// Saturating: `begin` is normalized to >=1 at parse time, but guard the
    /// subtraction anyway so no code path can produce a u64::MAX offset.
    pub fn offset(&self) -> u64 {
        self.begin.saturating_sub(1)
    }
}

/// Everything a decoded article carries EXCEPT the payload bytes, which
/// [`crate::yenc_simd::decode_into`] writes into a caller-owned (pooled)
/// buffer instead of a fresh per-article `Vec` - the hot download path
/// recycles that buffer, killing the per-article ~800 KB alloc/free the
/// [`crate::pool::BufPool`] already removed on the network side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Meta {
    pub name: String,
    pub file_size: u64,
    pub part: Option<u32>,
    pub begin: u64,
    pub end: u64,
    /// Length of the decoded payload now in the caller's buffer.
    pub len: usize,
}

impl Meta {
    /// Zero-based file offset where the payload belongs - feed to pwrite.
    /// Saturating for the same reason as [`Decoded::offset`].
    pub fn offset(&self) -> u64 {
        self.begin.saturating_sub(1)
    }
}

/// Decode a full article body (the lines between the NNTP BODY response and
/// the terminating `.`), verifying part length and CRC32 when present.
pub fn decode(body: &[u8]) -> Result<Decoded, YencError> {
    decode_checked(body).map(|(d, _)| d)
}

/// Like [`decode`], but also reports whether a CRC field was present AND
/// compared (returned `true` only then). The SIMD bare-LF fallback needs
/// this to avoid vouching `crc_checked` for an article that carried no
/// `pcrc32`/`crc32` at all - decoding success alone is not CRC verification.
pub fn decode_checked(body: &[u8]) -> Result<(Decoded, bool), YencError> {
    let mut name = String::new();
    let mut file_size: u64 = 0;
    let mut part: Option<u32> = None;
    let mut begin: u64 = 1;
    let mut end: u64 = 0;
    let mut expected_crc: Option<u32> = None;
    let mut expected_len: Option<u64> = None;
    let mut seen_begin = false;
    let mut seen_yend = false;
    let mut data = Vec::with_capacity(body.len());

    for raw_line in body.split(|&b| b == b'\n') {
        let mut line = raw_line;
        if line.last() == Some(&b'\r') {
            line = &line[..line.len() - 1];
        }
        if line.is_empty() {
            continue;
        }
        // NNTP dot-unstuffing: the wire ALWAYS doubles a line-leading '.',
        // so exactly one leading dot is removed - `..` -> `.` (a payload
        // byte 0x04, or a stuffed `.=yend`), `.` -> ``. Stripping only the
        // doubled form left this oracle one byte richer than the production
        // SIMD path (rapidyenc unstuffs any line-leading dot), which the
        // differential fuzzer flags as a divergence on every mutated body.
        if line.first() == Some(&b'.') {
            line = &line[1..];
            if line.is_empty() {
                continue;
            }
        }

        if line.starts_with(b"=ybegin ") {
            seen_begin = true;
            let kv = parse_header(&line[8..]);
            if let Some(v) = kv.get("name") {
                name = v.clone();
            }
            file_size = num(&kv, "size").unwrap_or(0);
            part = num(&kv, "part").map(|n| n as u32);
            // Until/unless =ypart overrides, a single-part post spans the file.
            end = file_size;
        } else if line.starts_with(b"=ypart ") {
            let kv = parse_header(&line[7..]);
            // yEnc `begin` is 1-based; a hostile/broken `begin=0` would
            // underflow offset() to u64::MAX. Clamp to the valid floor.
            begin = num(&kv, "begin").filter(|&b| b >= 1).unwrap_or(1);
            end = num(&kv, "end").unwrap_or(0);
        } else if line == b"=yend" || line.starts_with(b"=yend ") {
            seen_yend = true;
            // A bare `=yend` (no trailing space/fields) carries no size or
            // CRC but still marks a complete article.
            let kv = parse_header(line.get(6..).unwrap_or(&[]));
            expected_len = num(&kv, "size");
            // Multi-part posts carry pcrc32 (CRC of this part); single-part
            // posts carry crc32. Prefer the part CRC.
            expected_crc = hex(&kv, "pcrc32").or_else(|| hex(&kv, "crc32"));
        } else if seen_begin {
            decode_line(line, &mut data);
        }
    }

    if !seen_begin {
        return Err(YencError::MissingBegin);
    }
    // No =yend trailer means the article was cut short (the NNTP dot arrived
    // mid-body). Without this the decoder returns Ok on a partial payload;
    // the destination was preallocated to the declared size, so the missing
    // tail stays as sparse zero bytes and a no-PAR job completes with
    // silently corrupt output.
    if !seen_yend {
        return Err(YencError::Truncated);
    }
    if let Some(len) = expected_len
        && len != data.len() as u64
    {
        return Err(YencError::LengthMismatch {
            expected: data.len() as u64,
            actual: len,
        });
    }
    let mut crc_verified = false;
    if let Some(header) = expected_crc {
        let computed = crc32fast::hash(&data);
        if computed != header {
            return Err(YencError::CrcMismatch { computed, header });
        }
        crc_verified = true;
    }

    Ok((
        Decoded {
            name,
            file_size,
            part,
            begin,
            end,
            data,
        },
        crc_verified,
    ))
}

/// Decode one payload line (yEnc unescaping) onto `out`. `pub(crate)` because
/// the SIMD path must decode an unrecognised `=y…` control line as payload
/// through this exact routine to stay byte-identical with this oracle.
pub(crate) fn decode_line(line: &[u8], out: &mut Vec<u8>) {
    let mut i = 0;
    while i < line.len() {
        let b = line[i];
        if b == b'=' {
            if i + 1 < line.len() {
                out.push(line[i + 1].wrapping_sub(64).wrapping_sub(42));
                i += 2;
            } else {
                // Trailing lone '=' - malformed; ignore.
                i += 1;
            }
        } else if b == b'\r' || b == b'\n' {
            // A raw CR/LF is a line separator, never data - valid yEnc escapes
            // them (`=M`/`=J`). rapidyenc drops them, so a stray mid-line CR
            // used to leave this oracle one 0xE3 byte richer (fuzz find).
            i += 1;
        } else {
            out.push(b.wrapping_sub(42));
            i += 1;
        }
    }
}

/// Parse `key=value` pairs from a yEnc header line. `name=` consumes the
/// rest of the line (filenames contain spaces).
pub(crate) fn parse_header(rest: &[u8]) -> HashMap<String, String> {
    let mut map = HashMap::new();
    let text = String::from_utf8_lossy(rest);
    // ASCII SPACE is the only field separator, and the only thing trimmed:
    // `str::trim` also eats \t, \x0b, \x0c and Unicode spaces, which the SIMD
    // extractors (space-delimited byte scan) do not - a form feed glued to a
    // key made the two paths read different `crc32` fields (fuzz find).
    let mut remaining = text.trim_matches(' ');
    while !remaining.is_empty() {
        let Some(eq) = remaining.find('=') else { break };
        // The key is the token immediately before the `=`: everything back to
        // the previous space, exactly what the SIMD path's `find_key` matches
        // (line start or a space, then the key, then `=`). Taking the whole
        // span before the `=` instead made `=ybegin l<junk>128 size=4 …` parse
        // as one key `l<junk>128 size` on this side and as `size` on the SIMD
        // side - a differential-fuzz find, and the shape a poster gets by
        // corrupting one header byte.
        let key = remaining[..eq].rsplit(' ').next().unwrap_or("").to_string();
        let after = &remaining[eq + 1..];
        if key == "name" {
            map.entry(key)
                .or_insert_with(|| after.trim_matches(|c: char| c.is_ascii_whitespace()).to_string());
            break;
        }
        let (value, rest2) = match after.find(' ') {
            Some(sp) => (&after[..sp], after[sp + 1..].trim_start_matches(' ')),
            None => (after, ""),
        };
        // FIRST occurrence wins on a duplicated key. The SIMD path's
        // `find_key` scan stops at the first match, so last-wins here made
        // the two decoders disagree on `begin` (the write offset!) for a
        // header like `begin=5part begin=50000` - found by the differential
        // fuzzer. Well-formed headers never repeat a key.
        map.entry(key).or_insert_with(|| value.to_string());
        remaining = rest2;
    }
    map
}

pub(crate) fn num(kv: &HashMap<String, String>, key: &str) -> Option<u64> {
    kv.get(key)?.parse().ok()
}

pub(crate) fn hex(kv: &HashMap<String, String>, key: &str) -> Option<u32> {
    u32::from_str_radix(kv.get(key)?, 16).ok()
}

// ---------------------------------------------------------------------------
// Allocation-free field extractors for the hot SIMD decode path. The
// `parse_header` HashMap parser above stays the correctness oracle (and
// keeps the two decoders independent for the differential tests); the
// SIMD path uses these to avoid a HashMap + Strings per article. yEnc
// headers are ` key=value` tokens; only `name` may contain spaces (it
// runs to end of line).
// ---------------------------------------------------------------------------

/// Index of `key` in `rest`, matched as a whole token (preceded by the
/// line start or a space, followed by `=`).
fn find_key(rest: &[u8], key: &[u8]) -> Option<usize> {
    let mut i = 0;
    while i + key.len() < rest.len() {
        if (i == 0 || rest[i - 1] == b' ')
            && rest[i..].starts_with(key)
            && rest[i + key.len()] == b'='
        {
            return Some(i);
        }
        i += 1;
    }
    None
}

/// Value of `key=` up to the next space (empty if absent). `name=` runs to
/// end of line, so everything after a `name=` token is a FILENAME, not more
/// fields: the search stops there, matching `parse_header` (which breaks out
/// of its loop on `name`). Without that a filename could carry its own
/// `size=`/`pcrc32=` text and be read as the article's gates on this path
/// but not on the oracle's - a differential-fuzz find.
fn field_value<'a>(rest: &'a [u8], key: &[u8]) -> Option<&'a [u8]> {
    let rest = if key == b"name" {
        rest
    } else {
        match find_key(rest, b"name") {
            Some(n) => &rest[..n],
            None => rest,
        }
    };
    let i = find_key(rest, key)?;
    let vs = i + key.len() + 1;
    let ve = rest[vs..]
        .iter()
        .position(|&b| b == b' ')
        .map_or(rest.len(), |p| vs + p);
    Some(&rest[vs..ve])
}

pub(crate) fn field_u64(rest: &[u8], key: &[u8]) -> Option<u64> {
    std::str::from_utf8(field_value(rest, key)?).ok()?.parse().ok()
}

pub(crate) fn field_hex(rest: &[u8], key: &[u8]) -> Option<u32> {
    u32::from_str_radix(std::str::from_utf8(field_value(rest, key)?).ok()?, 16).ok()
}

/// `name=` value - the remainder of the line, trimmed. Returns None if
/// there is no `name=` token.
pub(crate) fn field_name(rest: &[u8]) -> Option<&[u8]> {
    let i = find_key(rest, b"name")?;
    Some((&rest[i + 5..]).trim_ascii()) // 5 = "name=".len()
}

// ---------------------------------------------------------------------------
// Encoder - used by tests as the round-trip oracle, and eventually by the
// posting feature.
// ---------------------------------------------------------------------------

const LINE_LEN: usize = 128;

/// Encode one part of a file as a complete yEnc article body (no NNTP
/// dot-stuffing - that belongs to the wire layer).
pub fn encode(
    name: &str,
    file_size: u64,
    part: Option<(u32, u32)>, // (part number, total parts)
    begin: u64,               // 1-based inclusive
    data: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + data.len() / 32 + 256);
    let crc = crc32fast::hash(data);

    match part {
        Some((p, total)) => {
            out.extend_from_slice(
                format!(
                    "=ybegin part={p} total={total} line={LINE_LEN} size={file_size} name={name}\r\n"
                )
                .as_bytes(),
            );
            let end = begin + data.len() as u64 - 1;
            out.extend_from_slice(format!("=ypart begin={begin} end={end}\r\n").as_bytes());
        }
        None => {
            out.extend_from_slice(
                format!("=ybegin line={LINE_LEN} size={file_size} name={name}\r\n").as_bytes(),
            );
        }
    }

    let mut col = 0usize;
    for &b in data {
        let enc = b.wrapping_add(42);
        let critical = matches!(enc, 0x00 | 0x0A | 0x0D | b'=') || (col == 0 && enc == b'.');
        if critical {
            out.push(b'=');
            out.push(enc.wrapping_add(64));
            col += 2;
        } else {
            out.push(enc);
            col += 1;
        }
        if col >= LINE_LEN {
            out.extend_from_slice(b"\r\n");
            col = 0;
        }
    }
    if col > 0 {
        out.extend_from_slice(b"\r\n");
    }

    match part {
        Some((p, _)) => out.extend_from_slice(
            format!("=yend size={} part={p} pcrc32={crc:08x}\r\n", data.len()).as_bytes(),
        ),
        None => out.extend_from_slice(
            format!("=yend size={} crc32={crc:08x}\r\n", data.len()).as_bytes(),
        ),
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic byte soup covering all 256 values many times over.
    fn test_data(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 7 + i / 251) as u8).collect()
    }

    #[test]
    fn round_trip_single_part() {
        let data = test_data(10_000);
        let article = encode("test file.bin", data.len() as u64, None, 1, &data);
        let dec = decode(&article).unwrap();
        assert_eq!(dec.name, "test file.bin");
        assert_eq!(dec.file_size, 10_000);
        assert_eq!(dec.part, None);
        assert_eq!(dec.offset(), 0);
        assert_eq!(dec.data, data);
    }

    #[test]
    fn round_trip_multi_part_offsets() {
        let file = test_data(300_000);
        let (a, b) = file.split_at(150_000);
        let art2 = encode("f.bin", 300_000, Some((2, 2)), 150_001, b);
        let dec = decode(&art2).unwrap();
        assert_eq!(dec.part, Some(2));
        assert_eq!(dec.begin, 150_001);
        assert_eq!(dec.end, 300_000);
        assert_eq!(dec.offset(), 150_000);
        assert_eq!(dec.data, b);

        let dec1 = decode(&encode("f.bin", 300_000, Some((1, 2)), 1, a)).unwrap();
        assert_eq!(dec1.offset(), 0);
        assert_eq!(dec1.data, a);
    }

    #[test]
    fn survives_nntp_dot_stuffing() {
        let data = test_data(50_000);
        let article = encode("dots.bin", data.len() as u64, None, 1, &data);
        // Simulate the NNTP wire: any line starting with '.' gets doubled.
        let mut stuffed = Vec::new();
        for line in article.split_inclusive(|&b| b == b'\n') {
            if line.first() == Some(&b'.') {
                stuffed.push(b'.');
            }
            stuffed.extend_from_slice(line);
        }
        let dec = decode(&stuffed).unwrap();
        assert_eq!(dec.data, data);
    }

    #[test]
    fn detects_corruption() {
        let data = test_data(5_000);
        let mut article = encode("c.bin", data.len() as u64, None, 1, &data);
        // Flip a payload byte (past the =ybegin line) to a harmless
        // non-critical value.
        let payload_start = article
            .windows(2)
            .position(|w| w == b"\r\n")
            .unwrap()
            + 2;
        article[payload_start] = if article[payload_start] == b'A' { b'B' } else { b'A' };
        match decode(&article) {
            Err(YencError::CrcMismatch { .. }) => {}
            other => panic!("expected CRC mismatch, got {other:?}"),
        }
    }

    #[test]
    fn missing_begin_rejected() {
        assert_eq!(decode(b"just some text\r\n"), Err(YencError::MissingBegin));
    }

    /// A hostile `=ypart begin=0` must not underflow offset() to u64::MAX
    /// (which panicked the par2-capture consumer). begin is clamped to its
    /// 1-based floor, so offset() is 0.
    #[test]
    fn ypart_begin_zero_does_not_underflow() {
        // No =yend size / crc → no length or CRC gate; payload bytes are
        // irrelevant, only begin/offset matter. (`=yend` with no fields.)
        let body = b"=ybegin part=1 total=1 line=128 size=4 name=x.bin\r\n\
                     =ypart begin=0 end=4\r\n\
                     test\r\n=yend\r\n";
        let dec = decode(body).unwrap();
        assert_eq!(dec.begin, 1, "begin=0 must clamp to the 1-based floor");
        assert_eq!(dec.offset(), 0, "begin=0 must clamp, not wrap to u64::MAX");
    }

    /// Hostile-header torture matrix (shapes catalogued from other
    /// downloaders' yEnc regression suites, synthesized fresh here): every
    /// case must return a clean value or error - never panic, never
    /// allocate from a declared size, never wrap an offset.
    #[test]
    fn hostile_headers_never_panic_or_overallocate() {
        // Declared 1 TiB size with a 4-byte payload: allocation follows the
        // BODY length, not the header, and the size just rides in metadata.
        let huge = b"=ybegin part=1 line=128 size=1099511627776 name=big.bin\r\n\
                     =ypart begin=1 end=4\r\ntest\r\n=yend\r\n";
        let dec = decode(huge).unwrap();
        assert_eq!(dec.file_size, 1_099_511_627_776);
        assert!(dec.data.len() < 16);

        // Negative size: not a u64, parses as absent (0) - no panic.
        let neg = b"=ybegin line=128 size=-5 name=n.bin\r\ntest\r\n=yend\r\n";
        let _ = decode(neg);

        // Garbage / overlong / empty CRC fields: ignored or clean error,
        // never a parse panic.
        for crc in ["pcrc32=XYZNOTHEX", "pcrc32=deadbeefdeadbeefdeadbeef", "pcrc32="] {
            let body = format!(
                "=ybegin part=1 line=128 size=4 name=c.bin\r\n=ypart begin=1 end=4\r\ntest\r\n=yend size=4 {crc}\r\n"
            );
            let _ = decode(body.as_bytes());
        }

        // Double =ybegin: second header must not corrupt state or panic.
        let dbl = b"=ybegin line=128 size=4 name=a.bin\r\n\
                    =ybegin line=128 size=4 name=b.bin\r\ntest\r\n=yend\r\n";
        let _ = decode(dbl);

        // =ypart with begin > end, and =ypart without =ybegin.
        let inv = b"=ybegin part=1 line=128 size=4 name=i.bin\r\n\
                    =ypart begin=9 end=2\r\ntest\r\n=yend\r\n";
        let _ = decode(inv);
        let orphan = b"=ypart begin=1 end=4\r\ntest\r\n";
        assert!(decode(orphan).is_err());

        // Truncations: header cut mid-fields, missing =yend entirely.
        let _ = decode(b"=ybegin part=1 li");
        let _ = decode(b"=ybegin line=128 size=4 name=t.bin\r\ntest\r\n");

        // Dot-stuffing-only body and newline-only body.
        let _ = decode(b"=ybegin line=128 size=2 name=d.bin\r\n..\r\n=yend\r\n");
        let _ = decode(b"=ybegin line=128 size=0 name=e.bin\r\n\r\n\r\n=yend\r\n");

        // NUL bytes and non-ASCII everywhere in the filename.
        let nul = b"=ybegin line=128 size=4 name=a\x00b\xff\xfe.bin\r\ntest\r\n=yend\r\n";
        let _ = decode(nul);

        // Escape byte at end of line (dangling '=').
        let dangling = b"=ybegin line=128 size=3 name=g.bin\r\nte=\r\n=yend\r\n";
        let _ = decode(dangling);
    }

    /// The allocation-free field extractors must agree with the HashMap
    /// oracle on real header shapes, including a spaced filename (runs to
    /// end), whole-token matching, and absent fields.
    #[test]
    fn field_extractors_match_oracle() {
        let h = b"size=123456 part=2 pcrc32=deadBEEF name=My Movie (2026).mkv";
        let kv = parse_header(h);
        assert_eq!(field_u64(h, b"size"), num(&kv, "size"));
        assert_eq!(field_u64(h, b"part"), num(&kv, "part"));
        assert_eq!(field_hex(h, b"pcrc32"), hex(&kv, "pcrc32"));
        assert_eq!(field_u64(h, b"size"), Some(123456));
        assert_eq!(field_hex(h, b"pcrc32"), Some(0xdeadBEEF));
        // name runs to end of line, spaces and all.
        assert_eq!(field_name(h).unwrap(), b"My Movie (2026).mkv");
        // Absent / non-token-boundary keys.
        assert_eq!(field_u64(h, b"begin"), None);
        assert_eq!(field_u64(h, b"art"), None); // must not match inside "part"
        assert_eq!(field_name(b"size=1"), None);
        // Field at end with empty value.
        assert_eq!(field_value(b"size=10 crc32=", b"crc32"), Some(&b""[..]));
    }
}

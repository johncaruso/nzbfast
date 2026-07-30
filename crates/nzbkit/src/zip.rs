//! Zip container detection: the one place that answers "is there a zip
//! here, and which files make it up".
//!
//! Detection lived in three hand-rolled copies scattered through the
//! extraction paths, and they disagreed. The disagreements were not
//! cosmetic: a byte-split `name.zip.001` set matched none of them, so a
//! job whose entire payload was still packed completed *silently*, and
//! a zip sitting in a release subfolder was never looked at because the
//! recursion only seeded subdirs holding RAR or 7z magic. One detector
//! that every path shares is what keeps those shapes from reappearing.
//!
//! Shapes recognised:
//! - single `.zip` / `.zipx` container;
//! - obfuscated single container - extension stripped, identified by
//!   magic (the same trick the RAR and 7z paths use);
//! - WinZip-spanned sets: `.z01`, `.z02`, … with the *final* segment
//!   named `.zip` (that trailing `.zip` is the one holding the central
//!   directory, so it sorts LAST, not first);
//! - byte-split sets: `name.zip.001`/`.002`, or bare `.001`/`.002` where
//!   the first part carries the magic.
//!
//! Two rules the detectors must never break, both learned from real
//! posts:
//!
//! 1. **A named file is never magic-sniffed.** Comics, ebooks, office
//!    documents and java/android bundles are all zip containers wearing
//!    a different extension, and unpacking one destroys the very file
//!    the user downloaded. Sniffing is for files whose name has already
//!    failed to identify them - extensionless, or a bare numeric part.
//! 2. **`.cbz` and friends are payload, not packaging.** Even if a
//!    future caller starts sniffing more widely, [`is_final_name`] is
//!    the explicit stop.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Zip container start signatures we accept at offset 0.
///
/// - `PK\x03\x04` local file header: the ordinary case.
/// - `PK\x07\x08` and `PK00`: spanning markers, written ahead of the
///   first local header in the first segment of a spanned set.
///
/// `PK\x05\x06` (end-of-central-directory) is deliberately absent: alone
/// it means an EMPTY archive, and four bytes is too weak a signal to
/// spend on a container with nothing in it.
const MAGICS: [&[u8; 4]; 3] = [b"PK\x03\x04", b"PK\x07\x08", b"PK00"];

/// Extensions whose bytes ARE a zip container but whose file is the
/// deliverable. Unpacking one is data loss, not extraction.
const FINAL_FILE_EXTS: &[&str] = &[
    "cbz", "epub", "docx", "xlsx", "pptx", "docm", "xlsm", "pptm", "odt", "ods", "odp",
    "odg", "jar", "war", "aar", "apk", "ipa", "xpi", "crx", "vsix", "whl", "kra", "ora",
    "sketch", "usdz",
];

/// How the container is laid out on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shape {
    /// One self-contained file (named, or obfuscated by magic).
    Single,
    /// WinZip-spanned: `.z01`, `.z02`, …, `.zip`.
    Spanned,
    /// Raw byte split: `.zip.001`/`.002`, or bare `.001`/`.002`.
    ByteSplit,
}

impl Shape {
    /// Short label for logs and the dashboard note.
    pub fn label(self) -> &'static str {
        match self {
            Shape::Single => "zip",
            Shape::Spanned => "spanned zip",
            Shape::ByteSplit => "split zip",
        }
    }
}

/// One zip container found in a directory: every on-disk part that forms
/// it, in the order they must be read.
#[derive(Debug, Clone)]
pub struct Finding {
    /// The name to show a user - the recognisable member of the set
    /// (the trailing `.zip` for a spanned set, else the first part).
    pub name: String,
    /// Parts in read order. Single containers hold exactly one.
    pub parts: Vec<PathBuf>,
    pub shape: Shape,
}

/// Does the file start with a zip container signature? Reads 4 bytes.
///
/// Callers must have established that the NAME does not already identify
/// the file (see the module note on never sniffing named files).
pub fn has_magic(path: &Path) -> bool {
    use std::io::Read;
    let mut b = [0u8; 4];
    std::fs::File::open(path)
        .and_then(|mut f| f.read_exact(&mut b))
        .is_ok_and(|()| MAGICS.iter().any(|m| *m == &b))
}

/// A zip-container file whose extension marks it as the payload itself
/// (`.cbz`, `.epub`, `.docx`, …). Never unpack one.
pub fn is_final_file(path: &Path) -> bool {
    path.file_name()
        .is_some_and(|n| is_final_name(&n.to_string_lossy().to_ascii_lowercase()))
}

/// [`is_final_file`] over an already-lowercased file name.
fn is_final_name(lower: &str) -> bool {
    Path::new(lower)
        .extension()
        .is_some_and(|e| FINAL_FILE_EXTS.contains(&&*e.to_string_lossy()))
}

/// WinZip-spanned continuation part: `.z01` … (letter z + at least two
/// digits). `.zip` itself is the set's LAST segment and is matched
/// separately - `ip` is not digits, so it never lands here.
fn spanned_part(lower: &str) -> Option<(String, u32)> {
    let (head, tail) = lower.rsplit_once('.')?;
    let digits = tail.strip_prefix('z')?;
    if digits.len() < 2 || !digits.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    Some((head.to_string(), digits.parse().ok()?))
}

/// Byte-split part of a named zip: `movie.zip.001`. Mirrors the 7z
/// `split_7z_part` grammar exactly, with `.zip`/`.zipx` as the stem.
fn split_part(lower: &str) -> Option<(String, u32)> {
    let (head, tail) = lower.rsplit_once('.')?;
    if tail.is_empty() || !tail.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    (head.ends_with(".zip") || head.ends_with(".zipx"))
        .then(|| (head.to_string(), tail.parse().ok().unwrap_or(u32::MAX)))
}

/// Bare numeric part: `movie.001`. Ambiguous by name alone (RAR numeric
/// volumes and hjsplit use the same grammar), so the caller gates the
/// set on the first part carrying zip magic.
fn numeric_part(lower: &str) -> Option<(String, u32)> {
    let (head, tail) = lower.rsplit_once('.')?;
    if !(2..=4).contains(&tail.len()) || !tail.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    Some((head.to_string(), tail.parse().ok()?))
}

/// Is this single path part of a zip container? Name-identified shapes
/// answer without touching the disk; extensionless files and bare
/// numeric parts need the magic.
///
/// This is the per-path predicate the extraction recursion uses to
/// decide "is there something extractable here", so it deliberately says
/// yes to a lone member of a split set - a directory holding only
/// `movie.zip.002` still has an archive problem worth reporting.
pub fn is_container(path: &Path) -> bool {
    let Some(name) = path.file_name() else {
        return false;
    };
    let lower = name.to_string_lossy().to_ascii_lowercase();
    if is_final_name(&lower) {
        return false;
    }
    if lower.ends_with(".zip") || lower.ends_with(".zipx") {
        return true;
    }
    if spanned_part(&lower).is_some() || split_part(&lower).is_some() {
        return true;
    }
    let sniffable = path.extension().is_none() || numeric_part(&lower).is_some();
    sniffable && has_magic(path)
}

/// Name-only test, for deciding BEFORE anything is on disk whether a
/// post is zip-packed (the NZB's file list at enqueue). Magic-only
/// shapes - obfuscated containers, bare numeric parts - cannot be
/// answered from a name and are deliberately not guessed here.
pub fn name_is_zip_shaped(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    if is_final_name(&lower) {
        return false;
    }
    lower.ends_with(".zip")
        || lower.ends_with(".zipx")
        || spanned_part(&lower).is_some()
        || split_part(&lower).is_some()
}

/// Every zip container directly under `dir` (one level, like the 7z
/// collector), each with its parts in read order.
pub fn scan(dir: &Path) -> Vec<Finding> {
    // `.zip`/`.zipx` singles, keyed by stem so a spanned set can claim
    // its trailing segment back out of here.
    let mut named: BTreeMap<String, PathBuf> = BTreeMap::new();
    let mut spanned: BTreeMap<String, BTreeMap<u32, PathBuf>> = BTreeMap::new();
    let mut split: BTreeMap<String, BTreeMap<u32, PathBuf>> = BTreeMap::new();
    let mut numeric: BTreeMap<String, BTreeMap<u32, PathBuf>> = BTreeMap::new();
    let mut obfuscated: Vec<PathBuf> = Vec::new();

    let Ok(rd) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    for e in rd.flatten() {
        if !e.file_type().is_ok_and(|t| t.is_file()) {
            continue;
        }
        let path = e.path();
        let lower = e.file_name().to_string_lossy().to_ascii_lowercase();
        if is_final_name(&lower) {
            continue;
        }
        if let Some((stem, n)) = spanned_part(&lower) {
            spanned.entry(stem).or_default().insert(n, path);
        } else if let Some((stem, n)) = split_part(&lower) {
            split.entry(stem).or_default().insert(n, path);
        } else if lower.ends_with(".zip") || lower.ends_with(".zipx") {
            let stem = lower.rsplit_once('.').map(|(h, _)| h.to_string()).unwrap_or(lower);
            named.insert(stem, path);
        } else if let Some((stem, n)) = numeric_part(&lower) {
            numeric.entry(stem).or_default().insert(n, path);
        } else if path.extension().is_none() && has_magic(&path) {
            obfuscated.push(path);
        }
    }

    let mut out = Vec::new();
    // Spanned first, so each one can take its trailing `.zip` before the
    // singles pass sees it.
    for (stem, parts) in spanned {
        let mut parts: Vec<PathBuf> = parts.into_values().collect();
        let tail = named.remove(&stem);
        let name = match &tail {
            Some(z) => file_name(z),
            None => file_name(&parts[0]),
        };
        parts.extend(tail);
        out.push(Finding { name, parts, shape: Shape::Spanned });
    }
    for (_stem, parts) in split {
        let parts: Vec<PathBuf> = parts.into_values().collect();
        out.push(Finding { name: file_name(&parts[0]), parts, shape: Shape::ByteSplit });
    }
    // Bare numeric parts are only a zip set if the first part says so -
    // `.001` is also how RAR numeric volumes and hjsplit name themselves.
    for (_stem, parts) in numeric {
        let parts: Vec<PathBuf> = parts.into_values().collect();
        if !has_magic(&parts[0]) {
            continue;
        }
        out.push(Finding { name: file_name(&parts[0]), parts, shape: Shape::ByteSplit });
    }
    for (_stem, path) in named {
        out.push(Finding { name: file_name(&path), parts: vec![path], shape: Shape::Single });
    }
    for path in obfuscated {
        out.push(Finding { name: file_name(&path), parts: vec![path], shape: Shape::Single });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// The first zip container in `dir`, if any - the question every
/// reporting path asks.
pub fn first(dir: &Path) -> Option<Finding> {
    scan(dir).into_iter().next()
}

fn file_name(p: &Path) -> String {
    p.file_name().unwrap_or_default().to_string_lossy().to_string()
}

// ---------------------------------------------------------------------------
// Reader: central-directory driven extraction (disk path)
// ---------------------------------------------------------------------------
//
// Deliberately NOT a streaming reader. The disk path has the whole
// container, so it reads the CENTRAL DIRECTORY, which is the format's
// authoritative index - written after every entry's real size is known.
// That side-steps the two traps that make zip nasty to stream: an entry
// whose local header carries zero sizes with the real ones in a trailing
// data descriptor (general-purpose flag bit 3), and the fact that the
// only way to find the next local header without sizes is to scan for a
// signature that also occurs inside stored payload. Neither can bite a
// reader that never trusts a local header for anything but where the
// bytes begin.
//
// Multi-part sets are read through one logical byte-space rather than
// being concatenated into a scratch file first (the way the 7z path
// does): a split set therefore needs no second copy on disk. For a
// WinZip-SPANNED set the central directory addresses entries as
// (disk number, offset within that disk), so the part lengths are what
// turn those back into logical offsets - see `Parts::logical`.

/// Why a zip could not be read or extracted. Every variant is a
/// sentence fragment the caller prints after "…could not be unpacked: ".
#[derive(Debug)]
pub enum ZipError {
    Io(std::io::Error),
    /// Structurally not a zip we can read (no end-of-central-directory,
    /// truncated headers, offsets outside the file).
    Malformed(&'static str),
    /// Readable, but this entry uses something we deliberately decline.
    /// Carries the user-facing reason.
    Unsupported(String),
    /// An entry's bytes did not match its stored CRC32.
    BadCrc { name: String },
}

impl std::fmt::Display for ZipError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ZipError::Io(e) => write!(f, "{e}"),
            ZipError::Malformed(w) => write!(f, "malformed zip ({w})"),
            ZipError::Unsupported(w) => write!(f, "{w}"),
            ZipError::BadCrc { name } => {
                write!(f, "{name} failed its stored CRC - the archive is damaged")
            }
        }
    }
}

impl From<std::io::Error> for ZipError {
    fn from(e: std::io::Error) -> ZipError {
        ZipError::Io(e)
    }
}

/// Compression methods this reader decodes. Everything else is declined
/// BY NAME so the user learns which one they hit, instead of a blanket
/// "not supported" (store + deflate is ~99% of real zips).
const METHOD_STORE: u16 = 0;
const METHOD_DEFLATE: u16 = 8;

fn method_name(m: u16) -> &'static str {
    match m {
        0 => "store",
        1 => "shrink",
        6 => "implode",
        8 => "deflate",
        9 => "deflate64",
        12 => "bzip2",
        14 => "lzma",
        93 => "zstd",
        95 => "xz",
        98 => "ppmd",
        _ => "an unknown method",
    }
}

/// Refuse absurd directories rather than allocating for them: a crafted
/// header can claim 4 billion entries in 22 bytes.
const MAX_ENTRIES: u64 = 200_000;
/// Longest entry name we will even consider (the sanitizer still has the
/// final say on where it may land).
const MAX_NAME: usize = 4096;

/// One central-directory record, already Zip64-resolved.
#[derive(Debug, Clone)]
pub struct Entry {
    /// Name exactly as stored. NOT yet safe as a path - the caller must
    /// put it through its own sanitizer (zip-slip, drive letters,
    /// backslashes) before touching the filesystem.
    pub name: String,
    pub method: u16,
    pub crc32: u32,
    pub compressed_size: u64,
    pub uncompressed_size: u64,
    /// Whether the entry is a directory marker (trailing `/`, or the
    /// MS-DOS directory attribute).
    pub is_dir: bool,
    /// General-purpose bit flags (bit 0 = encrypted).
    pub flags: u16,
    /// Unix mode from the external attributes' high half, when the
    /// archive was written on a unix-ish host - `0xA000` marks a symlink.
    unix_mode: u16,
    /// Where this entry's LOCAL header starts, in logical byte-space.
    local_offset: u64,
}

impl Entry {
    /// Encrypted entries are declined: we have no zip crypto, and
    /// writing out ciphertext that passes no CRC would be worse than
    /// saying so.
    pub fn is_encrypted(&self) -> bool {
        self.flags & 0x0001 != 0
    }

    /// A symlink entry stores its TARGET as its payload; materializing
    /// one would plant a link pointing anywhere the archive likes, so
    /// they are refused outright (the plan's safety checklist).
    pub fn is_symlink(&self) -> bool {
        self.unix_mode & 0xF000 == 0xA000
    }
}

/// The parts of one container as a single logical byte-space.
struct Parts {
    /// (file, logical start offset, length)
    files: Vec<(std::fs::File, u64, u64)>,
    total: u64,
}

impl Parts {
    fn open(parts: &[PathBuf]) -> Result<Parts, ZipError> {
        let mut files = Vec::with_capacity(parts.len());
        let mut at = 0u64;
        for p in parts {
            let f = std::fs::File::open(p)?;
            let len = f.metadata()?.len();
            files.push((f, at, len));
            at += len;
        }
        if at == 0 {
            return Err(ZipError::Malformed("empty container"));
        }
        Ok(Parts { files, total: at })
    }

    /// Turn a central-directory (disk, offset-within-disk) address into a
    /// logical offset.
    ///
    /// The two multi-part shapes address entries DIFFERENTLY and the part
    /// count cannot tell them apart:
    ///
    /// - a byte-split set (`.zip.001`/`.002`) is one single-disk archive
    ///   cut at arbitrary points after the fact, so its offsets already
    ///   span the whole concatenation and its disk numbers are all 0;
    /// - a WinZip-SPANNED set (`.z01`/`.z02`/`.zip`) is genuinely
    ///   multi-disk, so each offset is relative to the disk that holds it.
    ///
    /// `multi_disk` comes from the end-of-central-directory record's own
    /// disk number, which is the only authority on which shape this is.
    fn logical(&self, multi_disk: bool, disk: u32, off: u64) -> Option<u64> {
        if !multi_disk {
            return (off <= self.total).then_some(off);
        }
        let (_, start, len) = self.files.get(disk as usize)?;
        (off <= *len).then_some(start + off)
    }

    fn read_exact_at(&self, off: u64, buf: &mut [u8]) -> Result<(), ZipError> {
        if off.saturating_add(buf.len() as u64) > self.total {
            return Err(ZipError::Malformed("read past end of container"));
        }
        let mut done = 0usize;
        let mut pos = off;
        while done < buf.len() {
            let (f, start, len) = self
                .files
                .iter()
                .find(|(_, s, l)| pos >= *s && pos < *s + *l)
                .ok_or(ZipError::Malformed("gap in container parts"))?;
            let within = pos - start;
            let n = ((len - within) as usize).min(buf.len() - done);
            crate::disk::read_exact_at(f, &mut buf[done..done + n], within)?;
            done += n;
            pos += n as u64;
        }
        Ok(())
    }
}

/// A zip container opened for extraction.
pub struct Archive {
    parts: Parts,
    entries: Vec<Entry>,
}

fn rd_u16(b: &[u8]) -> u16 {
    u16::from_le_bytes([b[0], b[1]])
}
fn rd_u32(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}
fn rd_u64(b: &[u8]) -> u64 {
    u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
}

impl Archive {
    /// Open a container from its parts in read order (one entry for a
    /// single container; the ordered segments for a spanned or byte-split
    /// set - exactly what [`Finding::parts`] holds).
    pub fn open(parts: &[PathBuf]) -> Result<Archive, ZipError> {
        let parts = Parts::open(parts)?;
        let (cd_off, cd_entries, multi_disk) = find_central_directory(&parts)?;
        let entries = parse_central_directory(&parts, cd_off, cd_entries, multi_disk)?;
        if entries.is_empty() {
            // A zero-entry archive is legal, but "unpacked successfully"
            // having produced nothing is the silent-success shape this
            // codebase refuses everywhere else. Say so instead.
            return Err(ZipError::Malformed("archive contains no entries"));
        }
        Ok(Archive { parts, entries })
    }

    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// Decode one entry into `w`, verifying its stored CRC32 and its
    /// declared uncompressed size before returning Ok.
    ///
    /// The CRC check is the point, not a nicety: it is the only thing
    /// standing between a damaged-before-posting archive and output that
    /// looks like a successful extraction (the same rule the RAR store
    /// path enforces). A mismatch is an error, so the caller deletes the
    /// staged output instead of publishing it.
    pub fn read_entry_to(&self, e: &Entry, w: &mut dyn std::io::Write) -> Result<(), ZipError> {
        use std::io::Read as _;
        if e.is_encrypted() {
            return Err(ZipError::Unsupported(format!(
                "{} is password-protected and encrypted zip is not supported",
                e.name
            )));
        }
        if e.method != METHOD_STORE && e.method != METHOD_DEFLATE {
            return Err(ZipError::Unsupported(format!(
                "{} uses {} compression, which is not built in",
                e.name,
                method_name(e.method)
            )));
        }
        let data = self.entry_data_offset(e)?;
        let src = RangeReader {
            parts: &self.parts,
            pos: data,
            end: data
                .checked_add(e.compressed_size)
                .ok_or(ZipError::Malformed("entry size overflows"))?,
        };
        let mut crc = crc32fast::Hasher::new();
        let mut written = 0u64;
        let mut buf = vec![0u8; 64 * 1024];
        // One code path for both methods: `store` is just the identity
        // decoder, so the CRC/size accounting below cannot drift between
        // them.
        let mut rd: Box<dyn std::io::Read> = match e.method {
            METHOD_STORE => Box::new(src),
            _ => Box::new(flate2::read::DeflateDecoder::new(src)),
        };
        loop {
            let n = rd.read(&mut buf)?;
            if n == 0 {
                break;
            }
            written += n as u64;
            if written > e.uncompressed_size {
                return Err(ZipError::Malformed("entry longer than its declared size"));
            }
            crc.update(&buf[..n]);
            w.write_all(&buf[..n])?;
        }
        if written != e.uncompressed_size {
            return Err(ZipError::Malformed("entry shorter than its declared size"));
        }
        if crc.finalize() != e.crc32 {
            return Err(ZipError::BadCrc { name: e.name.clone() });
        }
        Ok(())
    }

    /// Where this entry's DATA begins: the local header tells us, and it
    /// is the only thing we take from it. Its name and extra fields may
    /// differ in LENGTH from the central directory's copy (writers pad
    /// extra fields differently in the two places), so the lengths must
    /// be read here rather than reused.
    fn entry_data_offset(&self, e: &Entry) -> Result<u64, ZipError> {
        let mut hdr = [0u8; 30];
        self.parts.read_exact_at(e.local_offset, &mut hdr)?;
        if &hdr[0..4] != b"PK\x03\x04" {
            return Err(ZipError::Malformed("entry does not start with a local header"));
        }
        let name_len = rd_u16(&hdr[26..]) as u64;
        let extra_len = rd_u16(&hdr[28..]) as u64;
        e.local_offset
            .checked_add(30 + name_len + extra_len)
            .filter(|&o| o <= self.parts.total)
            .ok_or(ZipError::Malformed("entry data starts past end of container"))
    }
}

/// Reads a bounded logical range, so a decoder can never run past the
/// entry it was given.
struct RangeReader<'a> {
    parts: &'a Parts,
    pos: u64,
    end: u64,
}

impl std::io::Read for RangeReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let left = self.end.saturating_sub(self.pos);
        if left == 0 || buf.is_empty() {
            return Ok(0);
        }
        let n = (left as usize).min(buf.len());
        self.parts
            .read_exact_at(self.pos, &mut buf[..n])
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        self.pos += n as u64;
        Ok(n)
    }
}

/// Locate the end-of-central-directory record and return
/// (central directory logical offset, entry count).
///
/// The EOCD sits at the very end, except for a trailing comment of up to
/// 64 KiB - so it is found by scanning backwards over that window. The
/// LAST match wins: a stored entry can contain the signature, and on a
/// self-extracting or concatenated container so can earlier junk.
fn find_central_directory(parts: &Parts) -> Result<(u64, u64, bool), ZipError> {
    const EOCD_MIN: u64 = 22;
    if parts.total < EOCD_MIN {
        return Err(ZipError::Malformed("too small to be a zip"));
    }
    let window = (EOCD_MIN + u16::MAX as u64).min(parts.total);
    let start = parts.total - window;
    let mut buf = vec![0u8; window as usize];
    parts.read_exact_at(start, &mut buf)?;
    let pos = (0..=(buf.len() - EOCD_MIN as usize))
        .rev()
        .find(|&i| &buf[i..i + 4] == b"PK\x05\x06")
        .ok_or(ZipError::Malformed("no end-of-central-directory record"))?;
    let eocd = &buf[pos..];
    let disk = rd_u16(&eocd[4..]) as u32;
    let cd_disk = rd_u16(&eocd[6..]) as u32;
    // The EOCD's own disk number is the only authority on whether this is
    // a genuinely spanned set (per-disk offsets) or a single-disk archive
    // that merely arrived as several files (logical offsets).
    let multi_disk = disk != 0 || cd_disk != 0;
    let mut entries = rd_u16(&eocd[10..]) as u64;
    let mut cd_off = rd_u32(&eocd[16..]) as u64;
    let mut cd_disk_no = cd_disk;

    // Zip64: any saturated field means the real ones live in the Zip64
    // record, found through a locator 20 bytes ahead of the EOCD. Never
    // trust the 32-bit copies once that record exists.
    let eocd_at = start + pos as u64;
    if entries == u16::MAX as u64 || cd_off == u32::MAX as u64 || disk == u16::MAX as u32 {
        if eocd_at < 20 {
            return Err(ZipError::Malformed("zip64 locator does not fit"));
        }
        let mut loc = [0u8; 20];
        parts.read_exact_at(eocd_at - 20, &mut loc)?;
        if &loc[0..4] != b"PK\x06\x07" {
            return Err(ZipError::Malformed("zip64 sizes without a zip64 locator"));
        }
        let z64_disk = rd_u32(&loc[4..]);
        let z64_off = rd_u64(&loc[8..]);
        let z64_at = parts
            .logical(multi_disk, z64_disk, z64_off)
            .ok_or(ZipError::Malformed("zip64 record outside the container"))?;
        let mut z64 = [0u8; 56];
        parts.read_exact_at(z64_at, &mut z64)?;
        if &z64[0..4] != b"PK\x06\x06" {
            return Err(ZipError::Malformed("zip64 end record not where the locator says"));
        }
        entries = rd_u64(&z64[32..]);
        cd_off = rd_u64(&z64[48..]);
        cd_disk_no = rd_u32(&z64[20..]);
    }
    if entries > MAX_ENTRIES {
        return Err(ZipError::Unsupported(format!(
            "the archive declares {entries} entries, more than this build will open"
        )));
    }
    let cd = parts
        .logical(multi_disk, cd_disk_no, cd_off)
        .ok_or(ZipError::Malformed("central directory outside the container"))?;
    Ok((cd, entries, multi_disk))
}

/// Walk the central directory into [`Entry`] records.
fn parse_central_directory(
    parts: &Parts,
    cd_off: u64,
    count: u64,
    multi_disk: bool,
) -> Result<Vec<Entry>, ZipError> {
    let mut out = Vec::with_capacity(count.min(4096) as usize);
    let mut at = cd_off;
    for _ in 0..count {
        let mut hdr = [0u8; 46];
        parts.read_exact_at(at, &mut hdr)?;
        if &hdr[0..4] != b"PK\x01\x02" {
            return Err(ZipError::Malformed("central directory record expected"));
        }
        let flags = rd_u16(&hdr[8..]);
        let method = rd_u16(&hdr[10..]);
        let crc32 = rd_u32(&hdr[16..]);
        let mut csize = rd_u32(&hdr[20..]) as u64;
        let mut usize_ = rd_u32(&hdr[24..]) as u64;
        let name_len = rd_u16(&hdr[28..]) as usize;
        let extra_len = rd_u16(&hdr[30..]) as usize;
        let comment_len = rd_u16(&hdr[32..]) as usize;
        let mut disk = rd_u16(&hdr[34..]) as u32;
        let external = rd_u32(&hdr[38..]);
        let mut local_off = rd_u32(&hdr[42..]) as u64;
        if name_len > MAX_NAME {
            return Err(ZipError::Malformed("entry name is implausibly long"));
        }
        let mut rest = vec![0u8; name_len + extra_len + comment_len];
        parts.read_exact_at(at + 46, &mut rest)?;
        let name = String::from_utf8_lossy(&rest[..name_len]).into_owned();

        // Zip64 extra field (0x0001): present exactly when one of the
        // 32-bit fields above is saturated, and holds only the saturated
        // ones, in this fixed order.
        let extra = &rest[name_len..name_len + extra_len];
        let mut i = 0usize;
        while i + 4 <= extra.len() {
            let tag = rd_u16(&extra[i..]);
            let len = rd_u16(&extra[i + 2..]) as usize;
            let body_at = i + 4;
            if body_at + len > extra.len() {
                break;
            }
            if tag == 0x0001 {
                let body = &extra[body_at..body_at + len];
                let mut p = 0usize;
                let mut take = |p: &mut usize| -> Option<u64> {
                    if *p + 8 <= body.len() {
                        let v = rd_u64(&body[*p..]);
                        *p += 8;
                        Some(v)
                    } else {
                        None
                    }
                };
                if usize_ == u32::MAX as u64 {
                    usize_ = take(&mut p).ok_or(ZipError::Malformed("zip64 field truncated"))?;
                }
                if csize == u32::MAX as u64 {
                    csize = take(&mut p).ok_or(ZipError::Malformed("zip64 field truncated"))?;
                }
                if local_off == u32::MAX as u64 {
                    local_off =
                        take(&mut p).ok_or(ZipError::Malformed("zip64 field truncated"))?;
                }
                if disk == u16::MAX as u32 && p + 4 <= body.len() {
                    disk = rd_u32(&body[p..]);
                }
                break;
            }
            i = body_at + len;
        }

        let dos_dir = external & 0x10 != 0;
        let is_dir = name.ends_with('/') || name.ends_with('\\') || dos_dir;
        out.push(Entry {
            name,
            method,
            crc32,
            compressed_size: csize,
            uncompressed_size: usize_,
            is_dir,
            flags,
            unix_mode: (external >> 16) as u16,
            local_offset: parts
                .logical(multi_disk, disk, local_off)
                .ok_or(ZipError::Malformed("entry starts outside the container"))?,
        });
        at = at
            .checked_add(46 + (name_len + extra_len + comment_len) as u64)
            .ok_or(ZipError::Malformed("central directory overflows"))?;
    }
    Ok(out)
}

/// Minimal zip WRITER, for unit tests and the fuzz corpus - the same
/// role `rar::fixtures` plays for RAR. Deliberately hand-rolled so the
/// reader is tested against bytes we control completely, including the
/// malformed and declined shapes no real writer would produce.
#[doc(hidden)]
pub mod fixtures {
    /// One entry to encode: (name, payload, method, flags, external attrs).
    pub struct Spec<'a> {
        pub name: &'a str,
        pub data: &'a [u8],
        pub method: u16,
        pub flags: u16,
        pub external: u32,
        /// Override the stored CRC (damage simulation).
        pub crc_override: Option<u32>,
        /// Write the 32-bit size fields saturated and add a Zip64 extra
        /// field carrying the real ones.
        pub zip64: bool,
    }

    impl<'a> Spec<'a> {
        pub fn stored(name: &'a str, data: &'a [u8]) -> Spec<'a> {
            Spec {
                name,
                data,
                method: super::METHOD_STORE,
                flags: 0,
                external: 0,
                crc_override: None,
                zip64: false,
            }
        }
        pub fn deflated(name: &'a str, data: &'a [u8]) -> Spec<'a> {
            Spec { method: super::METHOD_DEFLATE, ..Spec::stored(name, data) }
        }
    }

    fn u16le(v: u16, out: &mut Vec<u8>) {
        out.extend_from_slice(&v.to_le_bytes());
    }
    fn u32le(v: u32, out: &mut Vec<u8>) {
        out.extend_from_slice(&v.to_le_bytes());
    }
    fn u64le(v: u64, out: &mut Vec<u8>) {
        out.extend_from_slice(&v.to_le_bytes());
    }

    fn body(s: &Spec) -> Vec<u8> {
        match s.method {
            super::METHOD_DEFLATE => {
                use std::io::Write as _;
                let mut e = flate2::write::DeflateEncoder::new(
                    Vec::new(),
                    flate2::Compression::default(),
                );
                e.write_all(s.data).unwrap();
                e.finish().unwrap()
            }
            _ => s.data.to_vec(),
        }
    }

    /// Build a complete single-container zip.
    pub fn zip_of(specs: &[Spec]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut cd = Vec::new();
        for s in specs {
            let comp = body(s);
            let crc = s.crc_override.unwrap_or_else(|| crc32fast::hash(s.data));
            let local_off = out.len() as u32;
            let (c32, u32_) = if s.zip64 {
                (u32::MAX, u32::MAX)
            } else {
                (comp.len() as u32, s.data.len() as u32)
            };
            let z64_extra = |out: &mut Vec<u8>| {
                u16le(0x0001, out);
                u16le(16, out);
                u64le(s.data.len() as u64, out);
                u64le(comp.len() as u64, out);
            };
            // Local header
            out.extend_from_slice(b"PK\x03\x04");
            u16le(if s.zip64 { 45 } else { 20 }, &mut out);
            u16le(s.flags, &mut out);
            u16le(s.method, &mut out);
            u16le(0, &mut out); // time
            u16le(0, &mut out); // date
            u32le(crc, &mut out);
            u32le(c32, &mut out);
            u32le(u32_, &mut out);
            u16le(s.name.len() as u16, &mut out);
            u16le(if s.zip64 { 20 } else { 0 }, &mut out);
            out.extend_from_slice(s.name.as_bytes());
            if s.zip64 {
                z64_extra(&mut out);
            }
            out.extend_from_slice(&comp);
            // Central directory record
            cd.extend_from_slice(b"PK\x01\x02");
            u16le(if s.zip64 { 45 } else { 20 }, &mut cd);
            u16le(if s.zip64 { 45 } else { 20 }, &mut cd);
            u16le(s.flags, &mut cd);
            u16le(s.method, &mut cd);
            u16le(0, &mut cd);
            u16le(0, &mut cd);
            u32le(crc, &mut cd);
            u32le(c32, &mut cd);
            u32le(u32_, &mut cd);
            u16le(s.name.len() as u16, &mut cd);
            u16le(if s.zip64 { 20 } else { 0 }, &mut cd);
            u16le(0, &mut cd); // comment len
            u16le(0, &mut cd); // disk
            u16le(0, &mut cd); // internal attrs
            u32le(s.external, &mut cd);
            u32le(local_off, &mut cd);
            cd.extend_from_slice(s.name.as_bytes());
            if s.zip64 {
                z64_extra(&mut cd);
            }
        }
        let cd_off = out.len() as u32;
        let cd_size = cd.len() as u32;
        out.extend_from_slice(&cd);
        out.extend_from_slice(b"PK\x05\x06");
        u16le(0, &mut out);
        u16le(0, &mut out);
        u16le(specs.len() as u16, &mut out);
        u16le(specs.len() as u16, &mut out);
        u32le(cd_size, &mut out);
        u32le(cd_off, &mut out);
        u16le(0, &mut out); // comment len
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, name: &str, head: &[u8]) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, head).unwrap();
        p
    }

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("nzbkit-zip-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    const PK: &[u8] = b"PK\x03\x04rest of a local file header";

    #[test]
    fn single_named_zip() {
        let d = tmp("single");
        write(&d, "movie.zip", PK);
        let f = scan(&d);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].shape, Shape::Single);
        assert_eq!(f[0].name, "movie.zip");
    }

    #[test]
    fn final_files_are_never_containers() {
        let d = tmp("final");
        for n in ["comic.cbz", "book.epub", "sheet.xlsx", "app.apk", "lib.jar"] {
            write(&d, n, PK);
        }
        assert!(scan(&d).is_empty(), "payload formats must never be unpacked");
        assert!(!is_container(&d.join("comic.cbz")));
        assert!(!name_is_zip_shaped("comic.cbz"));
    }

    #[test]
    fn named_non_zip_is_never_sniffed() {
        // A .bin/.dat that happens to start with PK is not ours to open:
        // sniffing named files is exactly how a .cbz gets destroyed.
        let d = tmp("named");
        write(&d, "payload.bin", PK);
        assert!(scan(&d).is_empty());
        assert!(!is_container(&d.join("payload.bin")));
    }

    #[test]
    fn spanned_set_puts_the_zip_last() {
        // The trailing `.zip` holds the central directory: read order is
        // z01, z02, …, zip - NOT lexical order.
        let d = tmp("spanned");
        write(&d, "movie.z02", b"part two");
        write(&d, "movie.zip", b"central directory");
        write(&d, "movie.z01", PK);
        let f = scan(&d);
        assert_eq!(f.len(), 1, "one set, not three containers");
        assert_eq!(f[0].shape, Shape::Spanned);
        assert_eq!(f[0].name, "movie.zip");
        let names: Vec<String> = f[0].parts.iter().map(|p| file_name(p)).collect();
        assert_eq!(names, ["movie.z01", "movie.z02", "movie.zip"]);
    }

    #[test]
    fn byte_split_named_parts() {
        // The shape that matched nothing before and completed silently.
        let d = tmp("split");
        write(&d, "movie.zip.002", b"two");
        write(&d, "movie.zip.001", PK);
        let f = scan(&d);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].shape, Shape::ByteSplit);
        let names: Vec<String> = f[0].parts.iter().map(|p| file_name(p)).collect();
        assert_eq!(names, ["movie.zip.001", "movie.zip.002"]);
    }

    #[test]
    fn bare_numeric_parts_need_the_magic() {
        let d = tmp("numeric");
        write(&d, "movie.001", PK);
        write(&d, "movie.002", b"two");
        // A RAR numeric set in the same directory must not be claimed.
        write(&d, "other.001", b"Rar!\x1a\x07\x01\x00");
        write(&d, "other.002", b"two");
        let f = scan(&d);
        assert_eq!(f.len(), 1, "only the PK-headed set is a zip");
        assert_eq!(f[0].name, "movie.001");
        let names: Vec<String> = f[0].parts.iter().map(|p| file_name(p)).collect();
        assert_eq!(names, ["movie.001", "movie.002"]);
    }

    #[test]
    fn obfuscated_extensionless_container() {
        let d = tmp("obf");
        write(&d, "a3f9c1d2e", PK);
        write(&d, "b7e2", b"not an archive at all");
        let f = scan(&d);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].name, "a3f9c1d2e");
    }

    #[test]
    fn spanning_markers_count_as_magic() {
        let d = tmp("marker");
        write(&d, "marked", b"PK\x07\x08rest");
        write(&d, "marked2", b"PK00rest");
        assert_eq!(scan(&d).len(), 2);
    }

    #[test]
    fn empty_archive_signature_is_not_enough() {
        let d = tmp("eocd");
        write(&d, "nothing", b"PK\x05\x06\x00\x00\x00\x00");
        assert!(scan(&d).is_empty());
    }

    #[test]
    fn two_independent_zips_are_two_findings() {
        let d = tmp("two");
        write(&d, "a.zip", PK);
        write(&d, "b.zip", PK);
        assert_eq!(scan(&d).len(), 2);
    }

    #[test]
    fn name_shape_covers_what_a_nzb_can_show() {
        for n in ["Movie.zip", "MOVIE.ZIP", "movie.zipx", "movie.z01", "movie.zip.001"] {
            assert!(name_is_zip_shaped(n), "{n} should read as zip-packed");
        }
        for n in ["movie.rar", "movie.r01", "movie.7z", "movie.7z.001", "movie.001", "movie"] {
            assert!(!name_is_zip_shaped(n), "{n} must not read as zip-packed");
        }
    }

    // -- reader ---------------------------------------------------------

    use fixtures::Spec;

    fn payload(n: usize, seed: u8) -> Vec<u8> {
        (0..n).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed)).collect()
    }

    /// Write a container to disk and open it.
    fn open_bytes(tag: &str, bytes: &[u8]) -> (PathBuf, Result<Archive, ZipError>) {
        let d = tmp(tag);
        let p = write(&d, "c.zip", bytes);
        let a = Archive::open(&[p]);
        (d, a)
    }

    fn extract(a: &Archive, i: usize) -> Result<Vec<u8>, ZipError> {
        let mut out = Vec::new();
        a.read_entry_to(&a.entries()[i], &mut out)?;
        Ok(out)
    }

    #[test]
    fn stored_and_deflated_entries_round_trip() {
        let a_data = payload(50_000, 3);
        let b_data = payload(30_000, 9);
        let z = fixtures::zip_of(&[
            Spec::stored("a.bin", &a_data),
            Spec::deflated("b.bin", &b_data),
        ]);
        let (d, ar) = open_bytes("rd-ok", &z);
        let ar = ar.unwrap();
        assert_eq!(ar.entries().len(), 2);
        assert_eq!(extract(&ar, 0).unwrap(), a_data);
        assert_eq!(extract(&ar, 1).unwrap(), b_data);
        std::fs::remove_dir_all(&d).unwrap();
    }

    /// The CRC is the only thing standing between a damaged-before-posting
    /// archive and output that looks successful, so a mismatch must be an
    /// ERROR - never bytes the caller goes on to publish.
    #[test]
    fn a_wrong_stored_crc_is_an_error_not_output() {
        let data = payload(20_000, 5);
        let z = fixtures::zip_of(&[Spec {
            crc_override: Some(0xDEAD_BEEF),
            ..Spec::stored("a.bin", &data)
        }]);
        let (d, ar) = open_bytes("rd-crc", &z);
        let ar = ar.unwrap();
        assert!(matches!(extract(&ar, 0), Err(ZipError::BadCrc { .. })));
        std::fs::remove_dir_all(&d).unwrap();
    }

    /// Declined shapes must name what they hit: "not supported" with no
    /// noun is what phase 0 already said, and it taught the user nothing.
    #[test]
    fn declined_methods_and_encryption_say_which() {
        let data = payload(1000, 7);
        let z = fixtures::zip_of(&[Spec { method: 12, ..Spec::stored("a.bin", &data) }]);
        let (d, ar) = open_bytes("rd-bz", &z);
        let e = extract(&ar.unwrap(), 0).unwrap_err();
        assert!(matches!(&e, ZipError::Unsupported(m) if m.contains("bzip2")), "{e}");
        std::fs::remove_dir_all(&d).unwrap();

        let z = fixtures::zip_of(&[Spec { flags: 0x0001, ..Spec::stored("a.bin", &data) }]);
        let (d, ar) = open_bytes("rd-enc", &z);
        let ar = ar.unwrap();
        assert!(ar.entries()[0].is_encrypted());
        let e = extract(&ar, 0).unwrap_err();
        assert!(matches!(&e, ZipError::Unsupported(m) if m.contains("password")), "{e}");
        std::fs::remove_dir_all(&d).unwrap();
    }

    /// A symlink entry stores its TARGET as payload; materializing one
    /// plants a link pointing wherever the archive likes.
    #[test]
    fn symlink_entries_are_identifiable() {
        let z = fixtures::zip_of(&[Spec {
            external: 0xA1FF_0000,
            ..Spec::stored("link", b"/etc/passwd")
        }]);
        let (d, ar) = open_bytes("rd-link", &z);
        assert!(ar.unwrap().entries()[0].is_symlink());
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn zip64_sizes_are_read_from_the_extra_field() {
        let data = payload(40_000, 11);
        let z = fixtures::zip_of(&[Spec { zip64: true, ..Spec::stored("big.bin", &data) }]);
        let (d, ar) = open_bytes("rd-z64", &z);
        let ar = ar.unwrap();
        assert_eq!(ar.entries()[0].uncompressed_size, data.len() as u64);
        assert_eq!(extract(&ar, 0).unwrap(), data);
        std::fs::remove_dir_all(&d).unwrap();
    }

    /// A stored entry can contain the end-of-central-directory signature.
    /// The scan takes the LAST match, so the real record still wins.
    #[test]
    fn an_eocd_signature_inside_payload_does_not_win() {
        let mut data = payload(5_000, 13);
        data.extend_from_slice(b"PK\x05\x06");
        data.extend_from_slice(&[0u8; 40]);
        let z = fixtures::zip_of(&[Spec::stored("a.bin", &data)]);
        let (d, ar) = open_bytes("rd-sig", &z);
        let ar = ar.unwrap();
        assert_eq!(ar.entries().len(), 1);
        assert_eq!(extract(&ar, 0).unwrap(), data);
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn a_directory_entry_is_flagged_and_not_payload() {
        let z = fixtures::zip_of(&[
            Spec::stored("Pack/", b""),
            Spec::stored("Pack/a.bin", b"hello"),
        ]);
        let (d, ar) = open_bytes("rd-dir", &z);
        let ar = ar.unwrap();
        assert!(ar.entries()[0].is_dir);
        assert!(!ar.entries()[1].is_dir);
        std::fs::remove_dir_all(&d).unwrap();
    }

    /// Truncation and junk must be refused, never panic - this parser
    /// eats untrusted input.
    #[test]
    fn malformed_containers_are_refused_without_panicking() {
        let good = fixtures::zip_of(&[Spec::stored("a.bin", &payload(2_000, 17))]);
        for (tag, bytes) in [
            ("empty", Vec::new()),
            ("tiny", b"PK".to_vec()),
            ("no-eocd", payload(3_000, 1)),
            ("head-only", good[..good.len() / 2].to_vec()),
            ("eocd-only", b"PK\x05\x06".iter().copied().chain([0u8; 18]).collect()),
        ] {
            let d = tmp(&format!("rd-bad-{tag}"));
            let p = write(&d, "c.zip", &bytes);
            let r = Archive::open(&[p]);
            assert!(r.is_err(), "{tag} should not open");
            std::fs::remove_dir_all(&d).unwrap();
        }
        // Every byte-prefix of a healthy container: open may succeed or
        // fail, extraction may fail, but nothing may panic.
        for cut in (0..good.len()).step_by(97) {
            let d = tmp("rd-prefix");
            let p = write(&d, "c.zip", &good[..cut]);
            if let Ok(a) = Archive::open(&[p]) {
                for e in a.entries() {
                    let mut sink = Vec::new();
                    let _ = a.read_entry_to(e, &mut sink);
                }
            }
            std::fs::remove_dir_all(&d).unwrap();
        }
    }

    /// A byte-split set is one container cut arbitrarily, so the reader
    /// must span the parts without any joining step (no scratch copy).
    #[test]
    fn a_byte_split_set_reads_across_parts() {
        let data = payload(60_000, 23);
        let z = fixtures::zip_of(&[Spec::deflated("a.bin", &data)]);
        let d = tmp("rd-split");
        let cut = z.len() / 3;
        let p1 = write(&d, "c.zip.001", &z[..cut]);
        let p2 = write(&d, "c.zip.002", &z[cut..cut * 2]);
        let p3 = write(&d, "c.zip.003", &z[cut * 2..]);
        let ar = Archive::open(&[p1, p2, p3]).unwrap();
        assert_eq!(extract(&ar, 0).unwrap(), data);
        std::fs::remove_dir_all(&d).unwrap();
    }

    /// Interop: read archives produced by a REAL zip writer (Python's
    /// `zipfile`), not just by our own fixture builder - a hand-rolled
    /// reader that only ever meets its own writer proves very little.
    /// These same files seed the `zip_parse` fuzz corpus.
    ///
    /// Regenerate with `tools/gen-zip-fixtures.py`.
    #[test]
    fn reads_archives_written_by_a_real_zip_writer() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/zip");
        let cases = [
            ("store_deflate.zip", 3usize),
            ("commented.zip", 1),
            ("zip64.zip", 1),
            ("empty_dirs.zip", 2),
        ];
        for (name, want) in cases {
            let p = root.join(name);
            let a = Archive::open(&[p]).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(a.entries().len(), want, "{name} entry count");
            for e in a.entries() {
                if e.is_dir {
                    continue;
                }
                let mut out = Vec::new();
                a.read_entry_to(e, &mut out)
                    .unwrap_or_else(|err| panic!("{name}/{}: {err}", e.name));
                // read_entry_to already checks the stored CRC and the
                // declared size, so reaching here IS the assertion.
                assert_eq!(out.len() as u64, e.uncompressed_size);
            }
        }
        // The commented archive is the one that pins the EOCD scan: its
        // record sits ~900 bytes before the end of the file.
        let a = Archive::open(&[root.join("commented.zip")]).unwrap();
        assert_eq!(a.entries()[0].name, "a.bin");
    }

    /// An entry whose declared size disagrees with what actually decodes
    /// must fail rather than publish a short or over-long file.
    #[test]
    fn a_size_that_disagrees_with_the_data_is_refused() {
        let data = payload(10_000, 29);
        let mut z = fixtures::zip_of(&[Spec::stored("a.bin", &data)]);
        // Shrink the CD's uncompressed size by one byte (offset 24 of the
        // central record, which starts right after the entry data).
        let cd = z
            .windows(4)
            .position(|w| w == b"PK\x01\x02")
            .expect("central directory");
        let orig = u32::from_le_bytes([z[cd + 24], z[cd + 25], z[cd + 26], z[cd + 27]]);
        z[cd + 24..cd + 28].copy_from_slice(&(orig - 1).to_le_bytes());
        let (d, ar) = open_bytes("rd-size", &z);
        assert!(extract(&ar.unwrap(), 0).is_err());
        std::fs::remove_dir_all(&d).unwrap();
    }
}

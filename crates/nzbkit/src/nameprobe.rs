//! In-band naming probes: bounded byte-peeks that read a release's real
//! name out of the posted bytes themselves - no external catalogue, no
//! correlation, the name IS in the post.
//!
//! First recipe (uploader-recipe registry entry 1): a single store-mode
//! 7z whose end header carries the real inner filename. Measured on the
//! live index (research/R3-B3-* 9 Aug 2026): 0% header-encrypted, ~94%
//! self-naming at ~1-2 MB per probe. Honest scope: the buildable band is
//! ~29% of currently-dark bytes and is effectively ONE automated
//! reposter's TV output in alt.binaries.tv, so yield tracks that one
//! poster's cadence and can drop to zero on any upload-script change -
//! which is exactly what the lane's daily hit-rate telemetry watches.
//!
//! Second recipe: a multi-volume RAR's own volume head ([`rar_head`],
//! TODO 131 rung 5). ON DEMAND only - the continuation pilot
//! (research/RAR-continuation-pilot-2026-08-10) found 98% of that band
//! BY BYTES header-encrypted, which is a NO-GO for a scan-time lane and
//! a fine answer for a question a human just asked. Its
//! `EncryptedHeader` verdict is what the terminal `header_encrypted`
//! classification is written from.
//!
//! Everything in this module treats its input as hostile: the start
//! header, the end header, the RAR volume head, and every name inside
//! them are bytes some anonymous uploader chose. Parsing is CRC-gated,
//! size-capped, and fuzzed (targets `sevenz_name_probe` and
//! `rar_name_probe`; `rar_map` covers the mapper underneath).

use std::io::{self, Read, Seek};

/// 7z container magic at offset 0. Same six bytes as
/// `extract::sevenz::SEVENZ_MAGIC`; duplicated because that one is
/// private to the extraction engine and this module must stay
/// self-contained for the fuzz harness.
pub const SEVENZ_MAGIC: &[u8] = &[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];

/// Cap on the declared end-header size BEFORE any fetch or allocation
/// happens on its behalf. A real end header for a store-mode archive
/// holding one media file is a few hundred bytes; 2 MiB is generous
/// slack for large multi-entry archives while still bounding what one
/// hostile start header can make the prober fetch and buffer.
pub const SEVENZ_END_MAX: u64 = 2 << 20;

/// Cap on the PPMd model memory a packed header's coder props may
/// declare. `Ppmd7Decoder::new` allocates the props' 32-bit memSize up
/// front - before a single output byte exists for the unpack-size cap
/// to bound - and sevenz-rust2's header decode passes an effectively
/// unlimited mem budget, so a 42-byte window declaring 4 GiB is an
/// instant OOM (found by fuzz). Real writers compress headers with
/// LZMA; a PPMd header at all is exotic, and 7-Zip's own PPMd default
/// is 16 MiB, so 64 MiB is generous slack.
pub const SEVENZ_PPMD_MEM_MAX: u64 = 64 << 20;

/// Property ids of the 7z end-header grammar, as sevenz-rust2 and the
/// reference implementation spell them. Only the ones the declared-size
/// pre-scan below needs.
const K_END: u8 = 0x00;
const K_PACK_INFO: u8 = 0x06;
const K_UNPACK_INFO: u8 = 0x07;
const K_SIZE: u8 = 0x09;
const K_CRC: u8 = 0x0A;
const K_FOLDER: u8 = 0x0B;
const K_CODERS_UNPACK_SIZE: u8 = 0x0C;
const K_ENCODED_HEADER: u8 = 0x17;

/// 7z method id of PPMd, the one coder whose construction cost is set
/// by its props (memSize) rather than by the declared output size.
const SEVENZ_ID_PPMD: [u8; 3] = [0x03, 0x04, 0x01];

/// The parsed 32-byte 7z start header. Offsets are relative to byte 32,
/// so the end header (the archive map, kept at the TAIL of a 7z)
/// occupies `[32 + header_off, 32 + header_off + header_size)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SevenzStart {
    pub(crate) header_off: u64,
    pub header_size: u64,
    /// CRC32 of the end-header bytes - the field that lets a probe
    /// verify it fetched the right tail window without knowing the
    /// archive's total size.
    pub(crate) header_crc: u32,
}

/// Parse the 32-byte start header, CRC-checked. Sibling of
/// `extract::sevenz::sevenz_start_header`, kept separate because the
/// probe also needs the end-header CRC that the extraction path throws
/// away. None for anything that is not a well-formed 7z start.
pub fn sevenz_start(head: &[u8]) -> Option<SevenzStart> {
    if head.len() < 32 || !head.starts_with(SEVENZ_MAGIC) {
        return None;
    }
    let crc = u32::from_le_bytes(head[8..12].try_into().unwrap());
    if crc32fast::hash(&head[12..32]) != crc {
        return None;
    }
    Some(SevenzStart {
        header_off: u64::from_le_bytes(head[12..20].try_into().unwrap()),
        header_size: u64::from_le_bytes(head[20..28].try_into().unwrap()),
        header_crc: u32::from_le_bytes(head[28..32].try_into().unwrap()),
    })
}

/// Why a probe could not produce a name. The distinctions matter for
/// telemetry: `EncryptedHeader` is the canary that the poster started
/// encrypting headers (the one change that would zero the lane's
/// yield), and it must stay distinguishable from plain parse noise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeError {
    /// Offset-0 bytes are not a CRC-valid 7z start header.
    BadStart,
    /// Declared end-header size is zero or above [`SEVENZ_END_MAX`],
    /// or a packed (`kEncodedHeader`) header declares a decoded size
    /// above the same cap, or a PPMd coder memSize above
    /// [`SEVENZ_PPMD_MEM_MAX`] (a bomb declaration, not a real header).
    HeaderTooBig,
    /// Caller's tail buffer is shorter than the declared header size.
    TailShort,
    /// The trailing window's CRC32 does not match the start header's
    /// claim - wrong bytes, or an archive whose end header does not sit
    /// flush at the file's tail.
    TailCrcMismatch,
    /// The end header is AES-encrypted (7z `-mhe`): the archive knows
    /// its own names but refuses to say without a password. THE canary
    /// this lane's telemetry watches for.
    EncryptedHeader,
    /// The end header is packed (`kEncodedHeader`) and its pack stream
    /// starts before the fetched tail - one or two more trailing
    /// segments might cover it, but the bounded budget decides.
    HeaderUnreachable,
    /// sevenz-rust2 rejected the header bytes.
    Parse(String),
    /// Parsed clean but contains no usable entry.
    NoEntries,
}

impl std::fmt::Display for ProbeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProbeError::BadStart => write!(f, "not a 7z start header"),
            ProbeError::HeaderTooBig => write!(f, "end header size out of bounds"),
            ProbeError::TailShort => write!(f, "tail shorter than the declared header"),
            ProbeError::TailCrcMismatch => write!(f, "end header crc mismatch"),
            ProbeError::EncryptedHeader => write!(f, "header encrypted (needs a password)"),
            ProbeError::HeaderUnreachable => {
                write!(f, "packed header reaches before the fetched tail")
            }
            ProbeError::Parse(e) => write!(f, "end header parse: {e}"),
            ProbeError::NoEntries => write!(f, "archive lists no usable entry"),
        }
    }
}

/// One entry read out of the end header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SevenzEntryInfo {
    pub(crate) name: String,
    pub(crate) size: u64,
    pub(crate) has_stream: bool,
}

/// Verify that `tail` (the last bytes of the logical archive; for a
/// `.7z.NNN` split set, of the LAST volume) actually ends in the end
/// header the start header describes. 7z writes the end header flush at
/// the file's end, so the window is the trailing `header_size` bytes;
/// the CRC from the start header proves the identification without
/// knowing the archive's total size - which is what makes split sets
/// probeable without fetching every volume.
pub fn locate_end_header<'a>(start: &SevenzStart, tail: &'a [u8]) -> Result<&'a [u8], ProbeError> {
    if start.header_size == 0 || start.header_size > SEVENZ_END_MAX {
        return Err(ProbeError::HeaderTooBig);
    }
    let hs = start.header_size as usize;
    if tail.len() < hs {
        return Err(ProbeError::TailShort);
    }
    let window = &tail[tail.len() - hs..];
    if crc32fast::hash(window) != start.header_crc {
        return Err(ProbeError::TailCrcMismatch);
    }
    Ok(window)
}

/// Byte cursor for the declared-size pre-scan. Every accessor returns
/// None on truncation; the scan never allocates and never loops more
/// times than there are bytes left, so a hostile window costs at most
/// one linear pass over at most [`SEVENZ_END_MAX`] bytes.
struct Scan<'a> {
    b: &'a [u8],
    i: usize,
}

impl Scan<'_> {
    fn u8(&mut self) -> Option<u8> {
        let v = *self.b.get(self.i)?;
        self.i += 1;
        Some(v)
    }

    fn skip(&mut self, n: usize) -> Option<()> {
        self.i = self.i.checked_add(n).filter(|&e| e <= self.b.len())?;
        Some(())
    }

    /// 7z variable-length integer, bit-exact with sevenz-rust2's
    /// `read_variable_u64` (first byte's high bits say how many
    /// little-endian payload bytes follow).
    fn num(&mut self) -> Option<u64> {
        let first = self.u8()? as u64;
        let mut mask = 0x80u64;
        let mut value = 0u64;
        for i in 0..8 {
            if first & mask == 0 {
                return Some(value | ((first & (mask - 1)) << (8 * i)));
            }
            value |= (self.u8()? as u64) << (8 * i);
            mask >>= 1;
        }
        Some(value)
    }

    /// Mirror of `read_all_or_bits` byte consumption: returns how many
    /// of `n` flags are set, which is all the CRC-skipping needs.
    fn all_or_bits_count(&mut self, n: u64) -> Option<u64> {
        if self.u8()? != 0 {
            return Some(n);
        }
        let mut set = 0u64;
        let mut byte = 0u8;
        for i in 0..n {
            if i % 8 == 0 {
                byte = self.u8()?;
            }
            if byte & (0x80 >> (i % 8)) != 0 {
                set += 1;
            }
        }
        Some(set)
    }
}

/// What decoding a `kEncodedHeader` window will cost, as DECLARED by
/// the window itself - the numbers sevenz-rust2 turns into allocations
/// before one honest byte is produced.
struct DeclaredCost {
    /// Sum of every unpack size - the number sevenz-rust2 hands
    /// `Read::take` as the decode bound, plus every intermediate coder
    /// buffer (and the LZMA dictionary, which lzma-rust2 clamps to the
    /// unpack size).
    unpack: u64,
    /// Sum of every PPMd coder's props-declared memSize -
    /// `Ppmd7Decoder::new` allocates it up front, independent of any
    /// output bound, so it needs its own cap ([`SEVENZ_PPMD_MEM_MAX`]).
    ppmd_mem: u64,
}

/// The declared decode cost of a `kEncodedHeader` window. A byte-exact
/// mirror of the library's parse up to `kCodersUnpackSize` (reader.rs:
/// `read_pack_info`, `read_unpack_info`, `read_block`), stopping right
/// after the sizes.
///
/// Returns None when the window does not scan - the library will then
/// reject the same bytes itself BEFORE any decode (its parse is the
/// same grammar, and it cannot reach the decoder without a parsed
/// block), so None safely means "let the library produce its error".
/// Overflow while summing saturates instead of failing: an astronomic
/// declaration must land in the over-cap bucket, not the None one.
fn encoded_header_declared_cost(window: &[u8]) -> Option<DeclaredCost> {
    let limit = window.len() as u64;
    let mut s = Scan { b: window, i: 1 }; // window[0] == K_ENCODED_HEADER
    let mut nid = s.u8()?;
    if nid == K_PACK_INFO {
        let _pack_pos = s.num()?;
        let num_pack = s.num()?;
        if num_pack > limit {
            return None;
        }
        nid = s.u8()?;
        if nid == K_SIZE {
            for _ in 0..num_pack {
                s.num()?;
            }
            nid = s.u8()?;
        }
        if nid == K_CRC {
            let defined = s.all_or_bits_count(num_pack)?;
            s.skip((defined as usize).checked_mul(4)?)?;
            nid = s.u8()?;
        }
        if nid != K_END {
            return None;
        }
        nid = s.u8()?;
    }
    if nid != K_UNPACK_INFO || s.u8()? != K_FOLDER {
        return None;
    }
    let num_blocks = s.num()?;
    if num_blocks > limit || s.u8()? != 0 {
        return None;
    }
    // Out-stream count per block; pushes are paced by parsed bytes (a
    // block consumes at least two), so a declared-huge `num_blocks`
    // truncates out of the loop before it can balloon this vec.
    let mut block_outs = Vec::new();
    let mut ppmd_mem = 0u64;
    for _ in 0..num_blocks {
        let num_coders = s.num()?;
        if num_coders > limit {
            return None;
        }
        let mut total_in = 0u64;
        let mut total_out = 0u64;
        for _ in 0..num_coders {
            let bits = s.u8()?;
            let id_at = s.i;
            s.skip((bits & 0xF) as usize)?;
            let is_ppmd = s.b[id_at..s.i] == SEVENZ_ID_PPMD;
            let (n_in, n_out) = if bits & 0x10 == 0 {
                (1, 1)
            } else {
                (s.num()?, s.num()?)
            };
            total_in = total_in.checked_add(n_in)?;
            total_out = total_out.checked_add(n_out)?;
            if total_in > limit || total_out > limit {
                return None;
            }
            if bits & 0x20 != 0 {
                let props = s.num()?;
                if props > limit {
                    return None;
                }
                let props_at = s.i;
                s.skip(props as usize)?;
                // PPMd props: order byte, then the 32-bit memSize the
                // decoder will allocate whole. Shorter props error in
                // the library before it allocates - safe fall-through.
                if is_ppmd && props >= 5 {
                    let p = &s.b[props_at..];
                    let mem = u32::from_le_bytes([p[1], p[2], p[3], p[4]]);
                    ppmd_mem = ppmd_mem.saturating_add(mem as u64);
                }
            }
            if bits & 0x80 != 0 {
                // Alternative methods: the library refuses these too.
                return None;
            }
        }
        if total_out == 0 {
            return None;
        }
        let bind_pairs = total_out - 1;
        for _ in 0..bind_pairs {
            s.num()?;
            s.num()?;
        }
        if total_in < bind_pairs {
            return None;
        }
        let packed = total_in - bind_pairs;
        if packed != 1 {
            for _ in 0..packed {
                s.num()?;
            }
        }
        block_outs.push(total_out);
    }
    if s.u8()? != K_CODERS_UNPACK_SIZE {
        return None;
    }
    let mut total = 0u64;
    for &outs in &block_outs {
        for _ in 0..outs {
            total = total.saturating_add(s.num()?);
        }
    }
    Some(DeclaredCost {
        unpack: total,
        ppmd_mem,
    })
}

/// A sparse Read+Seek view over the two byte ranges a probe actually
/// holds (the head article and the located end header). Reads inside a
/// gap fail rather than fabricate zeros, so the parser can never be fed
/// bytes the wire did not produce - a `kEncodedHeader` that tries to
/// read its pack streams dies here, cleanly.
struct SparseReader<'a> {
    /// (absolute offset, bytes), non-overlapping, ascending.
    chunks: [(u64, &'a [u8]); 2],
    total: u64,
    pos: u64,
}

impl Read for SparseReader<'_> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if self.pos >= self.total || out.is_empty() {
            return Ok(0);
        }
        for &(off, data) in &self.chunks {
            let end = off + data.len() as u64;
            if self.pos >= off && self.pos < end {
                let at = (self.pos - off) as usize;
                let n = out.len().min(data.len() - at);
                out[..n].copy_from_slice(&data[at..at + n]);
                self.pos += n as u64;
                return Ok(n);
            }
        }
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("read at {} {GAP_SENTINEL}", self.pos),
        ))
    }
}

impl Seek for SparseReader<'_> {
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        let target = match pos {
            io::SeekFrom::Start(o) => o as i128,
            io::SeekFrom::End(d) => self.total as i128 + d as i128,
            io::SeekFrom::Current(d) => self.pos as i128 + d as i128,
        };
        if target < 0 || target > u64::MAX as i128 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "seek range"));
        }
        self.pos = target as u64;
        Ok(self.pos)
    }
}

/// The sentinel a [`SparseReader`] gap read carries, so the error
/// mapping below can tell "the parser wanted bytes we never fetched"
/// from every other IO shape sevenz-rust2 might report.
const GAP_SENTINEL: &str = "outside the fetched tail";

/// Parse the end header out of `head` (the decoded offset-0 bytes, at
/// least 32) plus `tail` (decoded trailing bytes ending at the logical
/// archive's last byte), and list the archive's entries.
///
/// The window is verified by [`locate_end_header`] first, which also
/// pins the archive's total size to `32 + header_off + header_size` -
/// so the sparse view it hands sevenz-rust2 is anchored without knowing
/// any middle volume's size. A packed (`kEncodedHeader`) header decodes
/// in-process when its pack stream falls inside `tail` (7z writers
/// place it directly before the end header, so a normal trailing fetch
/// covers it); an AES-encrypted header reports [`ProbeError::EncryptedHeader`].
pub fn sevenz_tail_names(head: &[u8], tail: &[u8]) -> Result<Vec<SevenzEntryInfo>, ProbeError> {
    let start = sevenz_start(head).ok_or(ProbeError::BadStart)?;
    let window = locate_end_header(&start, tail)?;
    // Decompression-bomb gate: a packed header's pack stream sits in
    // the fetched tail, and sevenz-rust2 decodes it with the DECLARED
    // unpack size as the only output bound - LZMA ratios would turn a
    // couple MB of hostile pack bytes into hundreds of MB of RAM,
    // synchronously on the probe lane. Read the declaration out of the
    // (already CRC-verified) window first and hold it to the same cap
    // as the stored header. Real posters' packed headers decode to a
    // few hundred bytes; 2 MiB of decoded header metadata is generous.
    // A PPMd coder's memSize is a second declared allocation the output
    // cap never touches, so it gets its own cap.
    if window.first() == Some(&K_ENCODED_HEADER)
        && let Some(declared) = encoded_header_declared_cost(window)
        && (declared.unpack > SEVENZ_END_MAX || declared.ppmd_mem > SEVENZ_PPMD_MEM_MAX)
    {
        return Err(ProbeError::HeaderTooBig);
    }
    let total = 32u64
        .checked_add(start.header_off)
        .and_then(|s| s.checked_add(start.header_size))
        .ok_or(ProbeError::HeaderTooBig)?;
    // The CRC match above proved `tail` ends exactly at the archive's
    // last byte, so its absolute position falls out of the total. A
    // tail longer than the archive keeps only the real bytes (tiny
    // archive, generous fetch); any overlap with `head` is fine - the
    // reader serves overlapping ranges first-chunk-first and both hold
    // the same wire bytes.
    let keep = (tail.len() as u64).min(total) as usize;
    let tail = &tail[tail.len() - keep..];
    let mut sparse = SparseReader {
        chunks: [(0, head), (total - keep as u64, tail)],
        total,
        pos: 0,
    };
    let archive = sevenz_rust2::Archive::read(&mut sparse, &sevenz_rust2::Password::default())
        .map_err(|e| match e {
            // Deterministic -mhe verdict: an AES coder on the header
            // chain with no password. This is the telemetry canary.
            sevenz_rust2::Error::PasswordRequired => ProbeError::EncryptedHeader,
            // A gap read wears the sentinel wherever the library
            // buries the io::Error (it rewraps Io as MaybeBadPassword
            // in places, so match on the message, not the variant).
            e if e.to_string().contains(GAP_SENTINEL) => ProbeError::HeaderUnreachable,
            e => ProbeError::Parse(e.to_string()),
        })?;
    let entries: Vec<SevenzEntryInfo> = archive
        .files
        .iter()
        .map(|e| SevenzEntryInfo {
            name: e.name.clone(),
            size: e.size,
            has_stream: e.has_stream,
        })
        .collect();
    if entries.is_empty() {
        return Err(ProbeError::NoEntries);
    }
    Ok(entries)
}

/// The one inner filename worth applying: largest real entry, sanitized.
///
/// The name is an anonymous uploader's choice - treat it like any other
/// untrusted string: keep only the final path component, drop control
/// characters, bound the length. Returns None when nothing survives.
pub fn pick_media_name(entries: &[SevenzEntryInfo]) -> Option<String> {
    let best = entries
        .iter()
        .filter(|e| e.has_stream && e.size > 0)
        .max_by_key(|e| e.size)?;
    let base = best.name.rsplit(['/', '\\']).next().unwrap_or(&best.name);
    let clean: String = base
        .chars()
        .filter(|c| !c.is_control())
        .collect::<String>()
        .trim()
        .to_string();
    if clean.is_empty() || clean.chars().count() > 255 || clean == "." || clean == ".." {
        return None;
    }
    Some(clean)
}

// ---- RAR: the continuation-volume head read (TODO 131 rung 5) --------

/// What one RAR volume's leading bytes said about the file inside it.
///
/// The pilot (research/RAR-continuation-pilot-2026-08-10) established
/// the mechanical fact this type exists to carry: a multi-volume RAR's
/// CONTINUATION volumes repeat the inner file header, so the leading
/// bytes of ANY volume - selected by the stored `part_no=1` tuple, not
/// by a `.partNN.rar` filename - name the file. 44/44 sampled targets
/// decoded at yEnc `begin=1`; 11 of 14 RAR4 sets named in one article.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RarHead {
    /// 4 or 5. Recorded because the plaintext yield is
    /// version-determined (RAR4 79%, RAR5 8%) and the ratio drifts as
    /// posters migrate - a shift shows up here first.
    pub(crate) v5: bool,
    /// RAR5 main-header volume number (0-based), when the volume is a
    /// numbered member. The obfuscation-proof ordering: absent in RAR4
    /// and on a first volume.
    pub(crate) volume_number: Option<u64>,
    pub(crate) entries: Vec<RarEntryInfo>,
}

/// One file piece a volume header described.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RarEntryInfo {
    pub(crate) name: String,
    /// Total unpacked size of the inner file - repeated in EVERY volume,
    /// which is what makes it a usable content key from a mid-set head.
    pub(crate) unpacked_size: u64,
    /// Stored whole-file CRC32, when this piece carries one.
    pub(crate) file_crc: Option<u32>,
    pub(crate) is_dir: bool,
}

/// Read a RAR volume's own leading bytes for the inner filename.
///
/// `head` is the decoded start of ONE volume file (a probe holds a
/// whole article, which is 700 KB against a header of tens of bytes);
/// `volume_size` is that file's declared length, used only for the
/// mapper's EOF rule. Pure - no I/O, no allocation beyond the entries -
/// so the fuzz harness and the unit tests reach it directly.
///
/// The error vocabulary is deliberately the 7z lane's:
/// [`ProbeError::EncryptedHeader`] is THE canary in both containers,
/// and the terminal `header_encrypted` classification keys off it, so
/// the two lanes must not spell the same fact two ways.
pub fn rar_head(head: &[u8], volume_size: u64) -> Result<RarHead, ProbeError> {
    let mut m = crate::rar::VolumeMapper::new(volume_size);
    m.feed(0, head);
    // Blockers first: a mapper can carry entries AND a blocker, and an
    // archive that says "password required" must report that fact even
    // when a stray entry parsed before the wall.
    match &m.blocker {
        // RAR5 type-4 HEAD_CRYPT, or a RAR4 main header with
        // MHD_PASSWORD - nothing after the signature is readable at any
        // fetch budget. 24 of 26 sampled RAR5 sets land here.
        Some(crate::rar::MapBlocker::EncryptedHeaders) => {
            return Err(ProbeError::EncryptedHeader);
        }
        Some(crate::rar::MapBlocker::NotRar) => return Err(ProbeError::BadStart),
        Some(crate::rar::MapBlocker::Corrupt(e)) => {
            return Err(ProbeError::Parse((*e).to_string()));
        }
        // `-p` (data encrypted, headers plain), compressed, or a bad
        // password: the NAMES are still readable, and a name is all this
        // probe wants. Fall through.
        _ => {}
    }
    let v5 = match m.version {
        Some(crate::rar::RarVersion::V5) => true,
        Some(crate::rar::RarVersion::V4) => false,
        // No signature in the bytes we hold: not this volume's head.
        None => return Err(ProbeError::BadStart),
    };
    let entries: Vec<RarEntryInfo> = m
        .entries
        .iter()
        .map(|e| RarEntryInfo {
            name: e.name.clone(),
            // A "size unknown" flag means the field is a placeholder,
            // not a length: refusing to pass it on keeps it out of the
            // content key, where a placeholder would key thousands of
            // unrelated sets together.
            unpacked_size: if e.size_unknown { 0 } else { e.unpacked_size },
            file_crc: e.file_crc,
            is_dir: e.is_dir,
        })
        .collect();
    if entries.is_empty() {
        return Err(ProbeError::NoEntries);
    }
    Ok(RarHead {
        v5,
        volume_number: m.volume_number,
        entries,
    })
}

/// The one inner filename worth applying, and the content key that
/// corroborates it: largest real entry, sanitized by the same rules the
/// 7z lane uses on the same class of untrusted uploader string.
///
/// The key is `{unpacked_size}:{crc32}` from the header the mapper
/// already exposes - exact for the volume, weaker than a PAR2 set ID.
/// When the header carries no CRC (a split piece that is not the last)
/// the size alone keys it, and when it carries neither there is no key:
/// the caller must fall back to the filename, never to a constant, or
/// every keyless RAR in the index would corroborate every other.
pub fn pick_rar_media_name(head: &RarHead) -> Option<(String, Option<String>)> {
    let best = head
        .entries
        .iter()
        .filter(|e| !e.is_dir)
        .max_by_key(|e| e.unpacked_size)?;
    let base = best.name.rsplit(['/', '\\']).next().unwrap_or(&best.name);
    let clean: String = base
        .chars()
        .filter(|c| !c.is_control())
        .collect::<String>()
        .trim()
        .to_string();
    if clean.is_empty() || clean.chars().count() > 255 || clean == "." || clean == ".." {
        return None;
    }
    let key = match (best.unpacked_size, best.file_crc) {
        (0, _) => None,
        (size, Some(crc)) => Some(format!("{size}:{crc:08x}")),
        (size, None) => Some(format!("{size}")),
    };
    Some((clean, key))
}

/// Does this on-disk 7-Zip container need a password to open?
///
/// The disk-side twin of the `-mhe` verdict [`sevenz_tail_names`] returns
/// as [`ProbeError::EncryptedHeader`]: same question, asked of a finished
/// file rather than a head/tail pair. `rar::needs_password` has answered
/// it for RAR volumes since the password affordance shipped; without this,
/// the daemon's post-processing looked for encrypted RARs only, so a
/// header-encrypted 7z ended the job as a generic "an archive could not be
/// unpacked" LOCAL failure - no password prompt, no Retry-with-password -
/// even though the unpacker had already said `PasswordRequired` in the log
/// (soak round 3, 11 Aug, advQ).
///
/// False for anything that is not a readable 7z: a caller asking "does
/// this need a password" about a missing or malformed file wants "no",
/// and the malformed case is somebody else's error to report.
pub fn sevenz_needs_password(path: &std::path::Path) -> bool {
    let Ok(mut f) = std::fs::File::open(path) else {
        return false;
    };
    matches!(
        sevenz_rust2::Archive::read(&mut f, &sevenz_rust2::Password::default()),
        Err(sevenz_rust2::Error::PasswordRequired) | Err(sevenz_rust2::Error::MaybeBadPassword(_))
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real single-entry 7z built by sevenz-rust2 itself (dev-dep has
    /// the `compress` feature), so the parse path is tested against
    /// bytes the library considers well-formed.
    fn fixture(name: &str, payload: &[u8]) -> Vec<u8> {
        let mut w = sevenz_rust2::ArchiveWriter::new(std::io::Cursor::new(Vec::new())).unwrap();
        w.push_archive_entry(sevenz_rust2::ArchiveEntry::new_file(name), Some(payload))
            .unwrap();
        w.finish().unwrap().into_inner()
    }

    const NAME: &str = "Some.Show.S01E01.1080p.WEB-DL.AAC2.0.x264-GRP.mkv";

    /// Incompressible payload (deterministic LCG), so fixture geometry
    /// resembles a real media post: the body dominates and the header's
    /// pack stream sits in the tail, not up against the start header.
    fn noise(n: usize) -> Vec<u8> {
        let mut x = 0x2545F491_4F6CDD1Du64;
        (0..n)
            .map(|_| {
                x = x
                    .wrapping_mul(6364136223846793005)
                    .wrapping_add(1442695040888963407);
                (x >> 33) as u8
            })
            .collect()
    }

    fn split_head_tail(arch: &[u8]) -> (Vec<u8>, Vec<u8>) {
        // Head = first KiB (a probe holds a whole decoded article, the
        // parser needs 32 bytes); tail = last 4 KiB, like a trailing
        // segment fetch would produce.
        let head = arch[..arch.len().min(1024)].to_vec();
        let tail = arch[arch.len().saturating_sub(4096)..].to_vec();
        (head, tail)
    }

    #[test]
    fn recovers_the_inner_name_from_head_plus_tail() {
        let arch = fixture(NAME, &noise(65536));
        let (head, tail) = split_head_tail(&arch);
        let entries = sevenz_tail_names(&head, &tail).unwrap();
        assert_eq!(pick_media_name(&entries).as_deref(), Some(NAME));
    }

    #[test]
    fn whole_archive_as_tail_also_works() {
        // Tiny archive, generous fetch: the tail buffer covers the
        // whole file and overlaps the head chunk.
        let arch = fixture(NAME, b"tiny");
        let entries = sevenz_tail_names(&arch[..64], &arch).unwrap();
        assert_eq!(pick_media_name(&entries).as_deref(), Some(NAME));
    }

    #[test]
    fn start_header_rejects_garbage_and_truncation() {
        assert!(sevenz_start(&[0u8; 40]).is_none());
        let arch = fixture(NAME, b"x");
        assert!(sevenz_start(&arch[..31]).is_none());
        let mut bad = arch.clone();
        bad[13] ^= 1; // breaks the start-header CRC
        assert!(sevenz_start(&bad).is_none());
    }

    #[test]
    fn wrong_tail_window_is_a_crc_mismatch_not_a_name() {
        let arch = fixture(NAME, &noise(65536));
        let (head, mut tail) = split_head_tail(&arch);
        let start = sevenz_start(&head).unwrap();
        let last = tail.len() - 1;
        tail[last] ^= 1;
        assert_eq!(
            locate_end_header(&start, &tail),
            Err(ProbeError::TailCrcMismatch)
        );
    }

    #[test]
    fn short_tail_reports_tail_short() {
        let arch = fixture(NAME, &noise(65536));
        let (head, _) = split_head_tail(&arch);
        let start = sevenz_start(&head).unwrap();
        let short = vec![0u8; (start.header_size - 1) as usize];
        assert_eq!(
            locate_end_header(&start, &short),
            Err(ProbeError::TailShort)
        );
    }

    #[test]
    fn packed_header_without_its_pack_stream_is_unreachable() {
        // The writer LZMA-packs small headers (kEncodedHeader), placing
        // the pack stream directly before the end header. Hand the
        // parser ONLY the end-header window and that stream is a gap -
        // the outcome a too-short trailing fetch produces in the wild.
        let arch = fixture(NAME, &noise(65536));
        let (head, _) = split_head_tail(&arch);
        let start = sevenz_start(&head).unwrap();
        let window = &arch[arch.len() - start.header_size as usize..];
        assert_eq!(
            sevenz_tail_names(&head, window),
            Err(ProbeError::HeaderUnreachable)
        );
    }

    #[test]
    fn encrypted_header_reports_the_canary() {
        // A real -mhe archive: AES content method + the writer's
        // default encrypt_header=true. The probe must say "encrypted",
        // not fold it into parse noise - it is the telemetry canary.
        let mut w = sevenz_rust2::ArchiveWriter::new(std::io::Cursor::new(Vec::new())).unwrap();
        w.set_content_methods(vec![
            sevenz_rust2::encoder_options::AesEncoderOptions::new(sevenz_rust2::Password::from(
                "secret",
            ))
            .into(),
        ]);
        w.push_archive_entry(
            sevenz_rust2::ArchiveEntry::new_file(NAME),
            Some(&noise(4096)[..]),
        )
        .unwrap();
        let arch = w.finish().unwrap().into_inner();
        let (head, tail) = split_head_tail(&arch);
        assert_eq!(
            sevenz_tail_names(&head, &tail),
            Err(ProbeError::EncryptedHeader)
        );
    }

    #[test]
    fn oversized_declared_header_is_capped_before_any_work() {
        let arch = fixture(NAME, b"y");
        let mut head = arch[..64].to_vec();
        head[20..28].copy_from_slice(&(SEVENZ_END_MAX + 1).to_le_bytes());
        let reseal = crc32fast::hash(&head[12..32]);
        head[8..12].copy_from_slice(&reseal.to_le_bytes());
        let start = sevenz_start(&head).unwrap();
        assert_eq!(
            locate_end_header(&start, &arch),
            Err(ProbeError::HeaderTooBig)
        );
    }

    /// A handcrafted kEncodedHeader window: one LZMA-coded block whose
    /// pack stream is 16 bytes and whose decoded size is `declared`.
    /// Grammar-valid up to kCodersUnpackSize, which is all the gate
    /// reads; the pack bytes themselves can be garbage.
    fn encoded_window(declared: u64) -> Vec<u8> {
        let mut w = vec![
            0x17, // kEncodedHeader
            0x06, 0x00, 0x01, // kPackInfo: pack_pos=0, one pack stream
            0x09, 0x10, // kSize: 16 pack bytes
            0x00, // kEnd (pack info)
            0x07, 0x0B, 0x01, 0x00, // kUnpackInfo, kFolder, 1 block, internal
            0x01, // one coder
            0x23, 0x03, 0x01, 0x01, // flags: 3-byte id + attrs; LZMA
            0x05, 0x5D, 0x00, 0x00, 0x10, 0x00, // 5 props bytes
            0x0C, // kCodersUnpackSize
        ];
        w.push(0xFF); // 8-byte number form
        w.extend_from_slice(&declared.to_le_bytes());
        w.extend_from_slice(&[0x00, 0x00]); // kEnd (unpack info), kEnd
        w
    }

    /// Seal `window` behind a CRC-valid start header with 16 pack bytes
    /// between them, the geometry a real packed-header archive has.
    fn seal(window: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let mut head = Vec::with_capacity(32);
        head.extend_from_slice(SEVENZ_MAGIC);
        head.extend_from_slice(&[0x00, 0x04, 0, 0, 0, 0]);
        head.extend_from_slice(&16u64.to_le_bytes()); // header_off
        head.extend_from_slice(&(window.len() as u64).to_le_bytes());
        head.extend_from_slice(&crc32fast::hash(window).to_le_bytes());
        let crc = crc32fast::hash(&head[12..32]);
        head[8..12].copy_from_slice(&crc.to_le_bytes());
        let mut tail = vec![0xAB; 16]; // the (garbage) pack stream
        tail.extend_from_slice(window);
        (head, tail)
    }

    #[test]
    fn bomb_declaring_packed_header_is_rejected_before_decode() {
        // Declares 512 MiB of decoded header out of 16 pack bytes - the
        // shape of an LZMA header bomb. Must die at the size gate, not
        // in the decoder.
        let (head, tail) = seal(&encoded_window(512 << 20));
        assert_eq!(
            sevenz_tail_names(&head, &tail),
            Err(ProbeError::HeaderTooBig)
        );
    }

    #[test]
    fn small_declared_packed_header_passes_the_gate() {
        // Same window declaring a sane size: the gate must let it
        // through to the real parser (which then fails on the garbage
        // pack bytes - any error but HeaderTooBig proves the gate is
        // keyed on the declaration, not on kEncodedHeader itself).
        let (head, tail) = seal(&encoded_window(100));
        let err = sevenz_tail_names(&head, &tail).unwrap_err();
        assert_ne!(err, ProbeError::HeaderTooBig, "gate overrejected: {err}");
    }

    /// Like [`encoded_window`] but the coder is PPMd with the given
    /// props memSize, declaring a tiny (64-byte) decoded size - the
    /// unpack cap alone would wave it through.
    fn ppmd_window(mem: u32) -> Vec<u8> {
        let mut w = vec![
            0x17, // kEncodedHeader
            0x06, 0x00, 0x01, // kPackInfo: pack_pos=0, one pack stream
            0x09, 0x10, // kSize: 16 pack bytes
            0x00, // kEnd (pack info)
            0x07, 0x0B, 0x01, 0x00, // kUnpackInfo, kFolder, 1 block, internal
            0x01, // one coder
            0x23, // flags: 3-byte id + attrs
        ];
        w.extend_from_slice(&SEVENZ_ID_PPMD);
        w.push(0x05); // 5 props bytes: order, then memSize LE
        w.push(0x06); // order
        w.extend_from_slice(&mem.to_le_bytes());
        w.push(0x0C); // kCodersUnpackSize
        w.push(0xFF); // 8-byte number form
        w.extend_from_slice(&64u64.to_le_bytes());
        w.extend_from_slice(&[0x00, 0x00]); // kEnd (unpack info), kEnd
        w
    }

    #[test]
    fn ppmd_mem_bomb_is_rejected_before_decode() {
        // The fuzz-found shape: declared output is tiny (the unpack cap
        // passes it) but the PPMd props declare ~4 GiB of model memory,
        // which Ppmd7Decoder::new would allocate whole before decoding
        // a byte. Must die at the gate.
        let (head, tail) = seal(&ppmd_window(0xF923_EF0F));
        assert_eq!(
            sevenz_tail_names(&head, &tail),
            Err(ProbeError::HeaderTooBig)
        );
    }

    #[test]
    fn ppmd_with_sane_mem_passes_the_gate() {
        // Same window with a modest memSize: the gate must key on the
        // declaration, not on the PPMd method id (any error but
        // HeaderTooBig proves it reached the real parser).
        let (head, tail) = seal(&ppmd_window(1 << 20));
        let err = sevenz_tail_names(&head, &tail).unwrap_err();
        assert_ne!(err, ProbeError::HeaderTooBig, "gate overrejected: {err}");
    }

    #[test]
    fn scanner_agrees_with_the_library_on_a_real_packed_header() {
        // The writer LZMA-packs small headers, so the fixture's end
        // header is a genuine kEncodedHeader: the pre-scan must parse
        // it and see a tiny declared size, and the full probe must
        // still recover the name (the no-regression half of the gate).
        let arch = fixture(NAME, &noise(65536));
        let (head, tail) = split_head_tail(&arch);
        let start = sevenz_start(&head).unwrap();
        let window = locate_end_header(&start, &tail).unwrap();
        assert_eq!(window[0], K_ENCODED_HEADER);
        let declared = encoded_header_declared_cost(window).expect("scan the real window");
        assert!(declared.unpack > 0 && declared.unpack <= SEVENZ_END_MAX);
        assert_eq!(declared.ppmd_mem, 0, "writer headers are LZMA, not PPMd");
        let entries = sevenz_tail_names(&head, &tail).unwrap();
        assert_eq!(pick_media_name(&entries).as_deref(), Some(NAME));
    }

    /// A `-mhe` container must answer the on-disk password question the
    /// same way the in-stream probe answers it, and a plain one must not
    /// claim to need a password. Without the disk-side answer, the
    /// daemon's post-processing (which only ever looked for encrypted
    /// RARs) ended an encrypted-7z job as a generic local unpack failure
    /// with no password prompt - soak round 3, 11 Aug, advQ.
    #[test]
    fn a_header_encrypted_sevenz_is_known_to_need_a_password_on_disk() {
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/sevenz");
        assert!(
            sevenz_needs_password(std::path::Path::new(&format!("{dir}/header-encrypted.7z"))),
            "-mhe container must ask for a password"
        );
        assert!(
            !sevenz_needs_password(std::path::Path::new(&format!("{dir}/store-single.7z"))),
            "a plain store container needs no password"
        );
        assert!(
            !sevenz_needs_password(std::path::Path::new(&format!("{dir}/does-not-exist.7z"))),
            "a missing file is not a password question"
        );
    }

    #[test]
    fn checked_in_fuzz_seeds_keep_their_meaning() {
        // tests/fixtures/sevenz/* seed the sevenz_name_probe fuzz
        // corpus (fuzz-smoke.yml copies them in). Pin what each seed
        // IS, so a regenerated file cannot silently stop covering the
        // path it was built for.
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/sevenz");
        let bomb = std::fs::read(format!("{dir}/bomb-container.7z")).unwrap();
        assert_eq!(
            sevenz_tail_names(&bomb[..32], &bomb),
            Err(ProbeError::HeaderTooBig),
            "bomb seed must die at the declared-size gate"
        );
        let real = std::fs::read(format!("{dir}/store-single.7z")).unwrap();
        let entries = sevenz_tail_names(&real[..32], &real).unwrap();
        assert_eq!(
            pick_media_name(&entries).as_deref(),
            Some("Some.Show.S01E01.1080p.WEB-DL.x264-GRP.mkv"),
            "real store-mode seed must still name itself"
        );
        // The window seeds are raw kEncodedHeader windows (the fuzz
        // target seals them into a container itself). Both are bomb
        // declarations and must die at the gate: one declares an
        // oversize decoded size, the other a ~4 GiB PPMd memSize (the
        // fuzz-found OOM of 10 Aug 2026).
        for name in ["bomb-encoded-header.bin", "ppmd-mem-window.bin"] {
            let window = std::fs::read(format!("{dir}/{name}")).unwrap();
            let (head, tail) = seal(&window);
            assert_eq!(
                sevenz_tail_names(&head, &tail),
                Err(ProbeError::HeaderTooBig),
                "{name} must die at the declared-cost gate"
            );
        }
    }

    #[test]
    fn name_sanitizer_strips_paths_and_control_bytes() {
        let e = |name: &str| SevenzEntryInfo {
            name: name.into(),
            size: 10,
            has_stream: true,
        };
        assert_eq!(
            pick_media_name(&[e("dir/sub\\Evil.\u{7}Name.mkv")]).as_deref(),
            Some("Evil.Name.mkv")
        );
        assert_eq!(pick_media_name(&[e("..")]), None);
        assert_eq!(pick_media_name(&[e("   ")]), None);
        // Directory entries (no stream) never win over the payload.
        let dir = SevenzEntryInfo {
            name: "folder".into(),
            size: 0,
            has_stream: false,
        };
        assert_eq!(
            pick_media_name(&[dir, e("Real.mkv")]).as_deref(),
            Some("Real.mkv")
        );
    }

    #[test]
    fn largest_entry_wins() {
        let mk = |name: &str, size: u64| SevenzEntryInfo {
            name: name.into(),
            size,
            has_stream: true,
        };
        assert_eq!(
            pick_media_name(&[mk("sample.mkv", 5), mk("Main.Feature.mkv", 500)]).as_deref(),
            Some("Main.Feature.mkv")
        );
    }

    // ---- RAR head reads -------------------------------------------

    /// THE mechanical claim the pilot proved, in a test: a CONTINUATION
    /// volume - split before AND after, nowhere near physical volume 1 -
    /// repeats the inner file header, so its own leading bytes name the
    /// file. 11 of 14 sampled RAR4 sets named this way, off mid-set
    /// volumes (part43, part51, part19, part22).
    #[test]
    fn a_rar4_continuation_volume_names_the_file_from_its_own_head() {
        // RAR4's header keeps unpacked size in 32 bits (the high half
        // rides a separate field real archivers add and this fixture
        // does not write), so the fixture's ceiling is 4 GiB - fine, the
        // point under test is the repeated header, not the width.
        let vol =
            crate::rar::fixtures::rar4_volume(&[(NAME, 3_000_000_000, &[7u8; 64], true, true)]);
        let head = rar_head(&vol, vol.len() as u64).unwrap();
        assert!(!head.v5);
        assert_eq!(head.entries.len(), 1);
        assert_eq!(head.entries[0].name, NAME);
        assert_eq!(head.entries[0].unpacked_size, 3_000_000_000);
        let (name, key) = pick_rar_media_name(&head).unwrap();
        assert_eq!(name, NAME);
        // A split piece carries no whole-file CRC (only the final
        // fragment does), so the size alone keys it - weaker, but never
        // a constant, which would join every keyless RAR to every other.
        assert_eq!(key.as_deref(), Some("3000000000"));
    }

    /// A RAR5 numbered member surfaces the volume ordinal the bundle
    /// wanted: obfuscation-proof ordering, read from the main header.
    /// Rarely reachable in the wild only because RAR5 sets that bother
    /// to obfuscate also tend to `-hp`.
    #[test]
    fn a_rar5_member_reports_its_volume_ordinal_and_content_key() {
        let vol = crate::rar::fixtures::rar5_volume_n_crc(
            &[(
                NAME,
                4_000_000_000,
                &[9u8; 32],
                false,
                false,
                Some(0xdeadbeef),
            )],
            27,
        );
        let head = rar_head(&vol, vol.len() as u64).unwrap();
        assert!(head.v5);
        assert_eq!(head.volume_number, Some(27));
        let (name, key) = pick_rar_media_name(&head).unwrap();
        assert_eq!(name, NAME);
        assert_eq!(key.as_deref(), Some("4000000000:deadbeef"));
    }

    /// The wall, in both dialects. 24 of 26 sampled RAR5 sets and 3 of
    /// 14 RAR4 sets stop right here, and the answer must be the SAME
    /// error the 7z lane raises - the terminal `header_encrypted`
    /// classification keys off this one variant, and two spellings of
    /// one fact would leave half the band re-probed forever.
    #[test]
    fn header_encrypted_volumes_report_the_canary_in_both_dialects() {
        let v4 = crate::rar::fixtures::rar4_encrypted_headers(4096);
        assert_eq!(
            rar_head(&v4, v4.len() as u64),
            Err(ProbeError::EncryptedHeader),
            "RAR4 MHD_PASSWORD"
        );
        let f = crate::rar::fixtures::encrypt_file("pw!", &[3u8; 4096], 5);
        let v5 = crate::rar::fixtures::rar5_volume_enc_headers(
            &[("Real.Name.mkv", &f, 0..f.cipher.len(), false, false)],
            Some(12),
            "pw!",
            7,
        );
        assert_eq!(
            rar_head(&v5, v5.len() as u64),
            Err(ProbeError::EncryptedHeader),
            "RAR5 type-4 HEAD_CRYPT: the signature is the last readable byte"
        );
    }

    /// Data encryption alone (`rar -p`, plaintext headers) is NOT the
    /// wall: the names are right there. Classifying it as encrypted
    /// would retire a nameable row forever - the exact over-reach the
    /// versioned stamp exists to be able to take back.
    #[test]
    fn data_encryption_with_plain_headers_still_names() {
        let f = crate::rar::fixtures::encrypt_file("pw!", &[4u8; 2048], 6);
        let vol = crate::rar::fixtures::rar5_volume_enc(
            &[(NAME, &f, 0..f.cipher.len(), false, false)],
            Some(3),
        );
        let head = rar_head(&vol, vol.len() as u64).unwrap();
        assert_eq!(pick_rar_media_name(&head).unwrap().0, NAME);
    }

    /// Not a RAR at all, and a truncated head, both report cleanly
    /// rather than naming something. The head a probe holds is one
    /// article off the wire; nothing here may trust its shape.
    #[test]
    fn non_rar_and_truncated_heads_report_rather_than_name() {
        assert_eq!(
            rar_head(b"not an archive at all", 21),
            Err(ProbeError::BadStart)
        );
        assert_eq!(rar_head(&[], 0), Err(ProbeError::BadStart));
        let vol = crate::rar::fixtures::rar4_volume(&[("x.mkv", 100, &[1u8; 8], false, false)]);
        // Signature only, no block behind it: the mapper has not
        // committed to a version, so the honest answer is "no start
        // here" - which for a probe means fetch elsewhere, not "this
        // archive has nothing in it".
        assert_eq!(
            rar_head(&vol[..7], vol.len() as u64),
            Err(ProbeError::BadStart)
        );
    }

    /// The uploader's string is untrusted exactly like the 7z lane's:
    /// path components, control characters and `..` never reach a title.
    #[test]
    fn rar_inner_names_are_sanitised_like_every_other_uploader_string() {
        let mk = |name: &str, size: u64| RarHead {
            v5: true,
            volume_number: None,
            entries: vec![RarEntryInfo {
                name: name.into(),
                unpacked_size: size,
                file_crc: None,
                is_dir: false,
            }],
        };
        assert_eq!(
            pick_rar_media_name(&mk("dir/sub\\Evil.\u{7}Name.mkv", 10))
                .unwrap()
                .0,
            "Evil.Name.mkv"
        );
        assert_eq!(pick_rar_media_name(&mk("..", 10)), None);
        assert_eq!(pick_rar_media_name(&mk("   ", 10)), None);
        // A directory entry alone names nothing.
        assert_eq!(
            pick_rar_media_name(&RarHead {
                v5: false,
                volume_number: None,
                entries: vec![RarEntryInfo {
                    name: "dir".into(),
                    unpacked_size: 0,
                    file_crc: None,
                    is_dir: true,
                }],
            }),
            None
        );
    }

    /// A "size unknown" RAR5 entry carries a PLACEHOLDER length, not a
    /// real one. It must never become a content key: thousands of
    /// unrelated sets would key together and corroborate each other.
    #[test]
    fn a_placeholder_size_is_never_a_content_key() {
        let head = RarHead {
            v5: true,
            volume_number: None,
            entries: vec![RarEntryInfo {
                name: NAME.into(),
                unpacked_size: 0,
                file_crc: None,
                is_dir: false,
            }],
        };
        let (name, key) = pick_rar_media_name(&head).unwrap();
        assert_eq!(name, NAME);
        assert_eq!(key, None, "no size, no key - the caller must fall back");
    }
}

//! PAR 2.0 packet parser - parsing + verification metadata only, no repair math.
//!
//! Powers incremental verification and minimum-download logic (design: M2):
//! from the small main `.par2` index we learn the recovery set's block size,
//! file names/lengths, whole-file MD5s, and per-block MD5+CRC32 checksums, so
//! downloaded articles can be verified block-by-block and exactly enough
//! recovery volumes fetched when blocks are bad.
//!
//! Spec: <https://parchive.github.io/docs/specifications/parity-volume-spec/article-spec.html>
//!
//! Packet layout (all integers little-endian):
//! ```text
//! offset  size  field
//!      0     8  magic "PAR2\0PKT"
//!      8     8  packet length in bytes (u64; includes this 64-byte header,
//!               always a multiple of 4)
//!     16    16  MD5 of the packet from offset 32 to the end (setid+type+body)
//!     32    16  RecoverySetId
//!     48    16  packet type
//!     64     …  type-specific body
//! ```
//!
//! Hard-learned spec subtleties (verified against par2cmdline 1.2.0 output):
//! - **md5_16k** is the MD5 of the first `min(len, 16384)` bytes of the file.
//!   For a file shorter than 16 KiB it is *not* zero-padded - it simply equals
//!   the whole-file MD5. (Checked empirically on a 10 KiB fixture: the
//!   FileDesc hash16k field matches the raw MD5, not the padded-to-16k MD5.)
//! - The **last block** of a file *is* zero-padded to `block_size` for its
//!   IFSC MD5 and CRC32.
//! - Packets are **duplicated across volumes** (every .volNN+MM file repeats
//!   the critical packets), so the parser dedupes by packet MD5.

use md5::{Digest, Md5};
use std::collections::HashMap;

pub(crate) const MAGIC: &[u8; 8] = b"PAR2\0PKT";
pub(crate) const TYPE_MAIN: &[u8; 16] = b"PAR 2.0\0Main\0\0\0\0";
pub(crate) const TYPE_FILEDESC: &[u8; 16] = b"PAR 2.0\0FileDesc";
pub(crate) const TYPE_IFSC: &[u8; 16] = b"PAR 2.0\0IFSC\0\0\0\0";
pub(crate) const TYPE_RECVSLIC: &[u8; 16] = b"PAR 2.0\0RecvSlic";

/// Header size of every packet.
const HEADER_LEN: u64 = 64;
/// MD5 of the first this-many bytes of a file = the FileDesc "hash16k" field.
const HASH16K_LEN: usize = 16384;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Par2Error {
    /// No valid Main packet found in any input - we can't even know the
    /// block size, so nothing useful can be built.
    #[error("no valid PAR2 Main packet found in the input")]
    NoMainPacket,
    /// Inputs contained valid packets from more than one recovery set.
    #[error("packets from multiple recovery sets mixed in the input")]
    MixedRecoverySets,
}

/// One source file described by the recovery set.
#[derive(Debug, Clone)]
pub struct Par2File {
    pub file_id: [u8; 16],
    pub name: String,
    pub length: u64,
    /// MD5 of the entire file.
    pub md5: [u8; 16],
    /// MD5 of the first `min(length, 16384)` bytes (see module docs - the
    /// short-file case is NOT zero-padded).
    pub md5_16k: [u8; 16],
    /// Per-block checksums from the IFSC packet, in file order. Empty if no
    /// IFSC packet for this file survived parsing.
    pub blocks: Vec<BlockCheck>,
}

/// Checksums for one `block_size` slice of a file (last slice zero-padded).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockCheck {
    pub md5: [u8; 16],
    pub crc32: u32,
}

/// Parsed metadata of one PAR2 recovery set.
#[derive(Debug, Clone)]
pub struct Par2Set {
    pub recovery_set_id: [u8; 16],
    /// Slice/block size in bytes (multiple of 4 per spec).
    pub block_size: u64,
    /// Files in the recovery set, in Main-packet (file-id-sorted) order.
    pub files: Vec<Par2File>,
    /// Number of distinct recovery slices (RecvSlic packets, deduped by
    /// packet MD5) seen across all parsed inputs.
    pub recovery_blocks_seen: usize,
}

/// Whole-file verification result from [`verify_file`].
#[derive(Debug, Clone)]
pub struct FileVerify {
    /// One flag per expected block, `true` when both the MD5 and CRC32 match.
    pub blocks: Vec<bool>,
    /// Whole-file MD5 matched.
    pub md5_ok: bool,
    /// First-16k MD5 matched.
    pub md5_16k_ok: bool,
}

/// FileDesc body fields, keyed by file id during parsing.
pub(crate) struct Desc {
    pub(crate) name: String,
    pub(crate) length: u64,
    pub(crate) md5: [u8; 16],
    pub(crate) md5_16k: [u8; 16],
}

/// A raw packet located inside an input buffer.
pub(crate) struct RawPacket<'a> {
    pub(crate) md5: [u8; 16],
    pub(crate) set_id: [u8; 16],
    pub(crate) ptype: [u8; 16],
    pub(crate) body: &'a [u8],
    /// Byte offset of `body` within the scanned input - lets the repair
    /// path record where recovery-slice data lives in a file and pread
    /// just the slices it needs later.
    pub(crate) body_offset: usize,
}

/// Scan `input` for structurally valid packets. Tolerates leading/trailing
/// garbage and corrupt packets: any packet whose own MD5 doesn't verify is
/// skipped (the scan resumes just past its magic, so a corrupt length field
/// can't make us jump over later good packets).
///
/// Buffers past [`PAR_SCAN_MIN`] take the parallel path: the structural
/// walk is the same, but the per-packet MD5s - the entire cost of scanning
/// a recovery volume, and until now a serial pass over ~all of its bytes -
/// verify across threads first. Any MD5 failure abandons the optimistic
/// walk and re-runs the sequential scan (its +1 resume can surface packets
/// the length-hopping walk never visited), so damaged volumes keep the
/// exact historical behavior and clean ones - the overwhelming case - scan
/// at aggregate hash speed.
pub(crate) fn scan_packets<'a>(input: &'a [u8], f: impl FnMut(RawPacket<'a>)) {
    scan_packets_counted(input, f);
}

/// [`scan_packets`], returning the total bytes fed to MD5 across both paths.
/// That total - not elapsed time - is what the serial scan's hash budget
/// bounds, so it is what the hostile-input test asserts on: a deterministic
/// figure that does not move when the machine running the test is loaded.
fn scan_packets_counted<'a>(input: &'a [u8], f: impl FnMut(RawPacket<'a>)) -> u64 {
    let mut hashed = 0u64;
    if input.len() >= PAR_SCAN_MIN {
        match scan_packets_parallel(input, f, &mut hashed) {
            Ok(()) => return hashed,
            // The optimistic walk hashed its spans before abandoning; those
            // bytes count toward the total just as the serial scan's do.
            Err(f) => return hashed.saturating_add(scan_packets_serial(input, f)),
        }
    }
    scan_packets_serial(input, f)
}

/// Below this the thread fan-out costs more than the hashing it spreads.
const PAR_SCAN_MIN: usize = 4 << 20;

/// The optimistic walk behind [`scan_packets`]: hop packet-to-packet by
/// declared length (identical traversal to the serial scan whenever every
/// MD5 verifies), verify all packet MD5s in parallel, then emit in order.
/// The first bad MD5 returns `Err(f)` - the caller falls back to the
/// serial scan, because the serial +1 resume can find overlapping packets
/// inside a corrupt packet's claimed extent that this walk hops over.
fn scan_packets_parallel<'a, F: FnMut(RawPacket<'a>)>(
    input: &'a [u8],
    mut f: F,
    hashed: &mut u64,
) -> Result<(), F> {
    // (start, end) of each structurally valid packet, in walk order.
    let mut spans: Vec<(usize, usize)> = Vec::new();
    let mut off = 0usize;
    while off + (HEADER_LEN as usize) <= input.len() {
        let Some(rel) = find_magic(&input[off..]) else {
            break;
        };
        let start = off + rel;
        if start + HEADER_LEN as usize > input.len() {
            break;
        }
        let len = u64::from_le_bytes(input[start + 8..start + 16].try_into().unwrap());
        let valid_len = len >= HEADER_LEN
            && len % 4 == 0
            && (start as u64)
                .checked_add(len)
                .is_some_and(|end| end <= input.len() as u64);
        if !valid_len {
            off = start + 1;
            continue;
        }
        spans.push((start, start + len as usize));
        off = start + len as usize;
    }
    if spans.is_empty() {
        return Ok(());
    }
    // The serial scan's hash budget exists to stop crafted overlapping-magic
    // quadratics; this walk hashes each span exactly once and never overlaps,
    // so total hashing is already bounded by the input length.
    let threads = std::thread::available_parallelism()
        .map_or(4, |n| n.get())
        .min(spans.len());
    let ok = std::sync::atomic::AtomicBool::new(true);
    let next = std::sync::atomic::AtomicUsize::new(0);
    // Bytes actually digested, for the caller's running total. Spans never
    // overlap, so this cannot exceed `input.len()`; one relaxed add per
    // packet is noise beside the MD5 it accompanies.
    let bytes = std::sync::atomic::AtomicUsize::new(0);
    std::thread::scope(|s| {
        for _ in 0..threads {
            s.spawn(|| loop {
                let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                if i >= spans.len() || !ok.load(std::sync::atomic::Ordering::Relaxed) {
                    return;
                }
                let (start, end) = spans[i];
                let stored: [u8; 16] = input[start + 16..start + 32].try_into().unwrap();
                bytes.fetch_add(end - (start + 32), std::sync::atomic::Ordering::Relaxed);
                if Md5::digest(&input[start + 32..end]).as_slice() != stored {
                    ok.store(false, std::sync::atomic::Ordering::Relaxed);
                    return;
                }
            });
        }
    });
    *hashed = hashed.saturating_add(bytes.into_inner() as u64);
    if !ok.into_inner() {
        return Err(f);
    }
    for &(start, end) in &spans {
        f(RawPacket {
            md5: input[start + 16..start + 32].try_into().unwrap(),
            set_id: input[start + 32..start + 48].try_into().unwrap(),
            ptype: input[start + 48..start + 64].try_into().unwrap(),
            body: &input[start + 64..end],
            body_offset: start + 64,
        });
    }
    Ok(())
}

/// Returns the total bytes fed to MD5, which is the quantity `budget` below
/// bounds; callers other than [`scan_packets_counted`] may ignore it.
fn scan_packets_serial<'a>(input: &'a [u8], mut f: impl FnMut(RawPacket<'a>)) -> u64 {
    // Budget on total bytes MD5'd, because the bad-MD5 resume below is
    // `start + 1`: a packet with a structurally valid length but a wrong MD5
    // costs a hash over its whole declared length and then advances one byte,
    // so overlapping magics with large lengths make this quadratic. A crafted
    // 16-byte cell (magic + a length reaching to EOF, whose stored-MD5 field is
    // the next cell's bytes and so never matches) gives ~n/16 packets each
    // hashing ~n bytes: a 16 MiB `.par2` is ~9 TB of MD5, i.e. hours, and
    // `.par2` files are read whole with no size cap straight off the wire.
    // A legitimate set hashes each packet exactly once, so its total is one
    // pass over the input - 4x leaves ample headroom for duplicate copies,
    // which is what the +1 resume exists to find.
    let budget = (input.len() as u64)
        .saturating_mul(4)
        .max(16 * 1024 * 1024);
    let mut hashed: u64 = 0;
    let mut off = 0usize;
    while off + (HEADER_LEN as usize) <= input.len() {
        let Some(rel) = find_magic(&input[off..]) else {
            break;
        };
        let start = off + rel;
        if start + HEADER_LEN as usize > input.len() {
            break;
        }
        let len = u64::from_le_bytes(input[start + 8..start + 16].try_into().unwrap());
        // Sanity: header-inclusive length, multiple of 4, fits in the buffer.
        let valid_len = len >= HEADER_LEN
            && len % 4 == 0
            && (start as u64)
                .checked_add(len)
                .is_some_and(|end| end <= input.len() as u64);
        if !valid_len {
            off = start + 1;
            continue;
        }
        let end = start + len as usize;
        let stored_md5: [u8; 16] = input[start + 16..start + 32].try_into().unwrap();
        let charge = (end - (start + 32)) as u64;
        if hashed.saturating_add(charge) > budget {
            // Hostile framing, not a real (even badly damaged) set. Stop with
            // whatever verified so far; the caller then sees an incomplete set
            // and declines, rather than burning hours on hashes. Charge only
            // for what is actually digested, so the returned total is a true
            // count and not budget + one unhashed packet.
            return hashed;
        }
        hashed = hashed.saturating_add(charge);
        let computed = Md5::digest(&input[start + 32..end]);
        if computed.as_slice() != stored_md5 {
            // Corrupt packet: resume the search right after this magic so a
            // duplicated copy elsewhere can still be found.
            off = start + 1;
            continue;
        }
        f(RawPacket {
            md5: stored_md5,
            set_id: input[start + 32..start + 48].try_into().unwrap(),
            ptype: input[start + 48..start + 64].try_into().unwrap(),
            body: &input[start + 64..end],
            body_offset: start + 64,
        });
        off = end;
    }
    hashed
}

fn find_magic(hay: &[u8]) -> Option<usize> {
    hay.windows(MAGIC.len()).position(|w| w == MAGIC)
}

impl Par2Set {
    /// Parse the raw bytes of one or more .par2 files (main index + any
    /// .volNN+MM volumes). Duplicated packets are deduped by packet MD5,
    /// unknown packet types and corrupt packets are skipped, and trailing
    /// garbage is tolerated. Fails only if no valid Main packet is found
    /// (or if inputs mix different recovery sets).
    pub fn parse(inputs: &[&[u8]]) -> Result<Par2Set, Par2Error> {
        // Main body: slice_size u64, file-count u32, then 16-byte file ids
        // (recovery-set files first, then optional non-recovery file ids).
        let mut main: Option<(u64, Vec<[u8; 16]>)> = None;
        let mut set_id: Option<[u8; 16]> = None;
        let mut mixed = false;
        let mut descs: HashMap<[u8; 16], Desc> = HashMap::new();
        // file_id -> blocks
        let mut ifscs: HashMap<[u8; 16], Vec<BlockCheck>> = HashMap::new();
        let mut seen: std::collections::HashSet<[u8; 16]> = Default::default();
        let mut recovery_blocks = 0usize;

        for input in inputs {
            scan_packets(input, |pkt| {
                if !seen.insert(pkt.md5) {
                    return; // duplicate (packets repeat across volumes)
                }
                match set_id {
                    None => set_id = Some(pkt.set_id),
                    Some(id) if id != pkt.set_id => {
                        mixed = true;
                        return;
                    }
                    _ => {}
                }
                match &pkt.ptype {
                    t if t == TYPE_MAIN => {
                        if main.is_none() {
                            main = parse_main(pkt.body);
                        }
                    }
                    t if t == TYPE_FILEDESC => {
                        if let Some((fid, desc)) = parse_filedesc(pkt.body) {
                            descs.entry(fid).or_insert(desc);
                        }
                    }
                    t if t == TYPE_IFSC => {
                        if let Some((fid, blocks)) = parse_ifsc(pkt.body) {
                            ifscs.entry(fid).or_insert(blocks);
                        }
                    }
                    t if t == TYPE_RECVSLIC => recovery_blocks += 1,
                    _ => {} // Creator + anything unknown: skip
                }
            });
        }

        if mixed {
            return Err(Par2Error::MixedRecoverySets);
        }
        let (block_size, file_ids) = main.ok_or(Par2Error::NoMainPacket)?;
        let set_id = set_id.ok_or(Par2Error::NoMainPacket)?;

        let files = file_ids
            .into_iter()
            .filter_map(|fid| {
                let d = descs.remove(&fid)?;
                // An IFSC whose entry count disagrees with the declared
                // length does not describe this file, and a SHORT list is
                // the dangerous shape: live verify sizes its per-block
                // state from `blocks`, so it would call the file clean
                // after checking only a prefix. Drop the packet instead -
                // an empty `blocks` routes the file to the whole-file MD5,
                // which covers every byte.
                let want = (block_size > 0).then(|| d.length.div_ceil(block_size));
                let blocks = ifscs
                    .remove(&fid)
                    .filter(|b| want == Some(b.len() as u64))
                    .unwrap_or_default();
                Some(Par2File {
                    file_id: fid,
                    name: d.name,
                    length: d.length,
                    md5: d.md5,
                    md5_16k: d.md5_16k,
                    blocks,
                })
            })
            .collect();

        Ok(Par2Set {
            recovery_set_id: set_id,
            block_size,
            files,
            recovery_blocks_seen: recovery_blocks,
        })
    }

    /// The set's member files as `(hash16k hex, member name)`.
    ///
    /// `hash16k` is the MD5 of the first 16 KiB of a member file, and
    /// the member files of a usenet post are its OUTER volumes - so this
    /// fingerprints a release without reading a byte of its payload and
    /// without needing an archive to open. That is what makes it the one
    /// identity in the pipeline that survives RAR header encryption: the
    /// sidecar describes the `.r00` files, not what is inside them.
    ///
    /// Recovery volumes are excluded (they are not in the recovery set),
    /// and so are members shorter than 16 KiB, whose hash16k is just the
    /// whole-file MD5 of a sample or an nfo and would collide across
    /// unrelated releases.
    pub fn member_hash16k(&self) -> Vec<(String, String)> {
        self.files
            .iter()
            .filter(|f| f.length >= HASH16K_LEN as u64)
            .map(|f| (hex16(&f.md5_16k), f.name.clone()))
            .collect()
    }

    /// Count the recovery slices (RecvSlic packets) present in one volume's
    /// bytes - e.g. to confirm a `.volNN+MM.par2` really carries MM slices
    /// before relying on it for exact-fit recovery fetching. Corrupt packets
    /// don't count; duplicates within the buffer are deduped.
    pub fn recovery_block_count(vol_bytes: &[u8]) -> usize {
        let mut seen: std::collections::HashSet<[u8; 16]> = Default::default();
        let mut n = 0usize;
        scan_packets(vol_bytes, |pkt| {
            if &pkt.ptype == TYPE_RECVSLIC && seen.insert(pkt.md5) {
                n += 1;
            }
        });
        n
    }
}

/// Lowercase hex of a 16-byte digest - the storage form of a hash16k.
pub fn hex16(d: &[u8; 16]) -> String {
    use std::fmt::Write as _;
    d.iter().fold(String::with_capacity(32), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

pub(crate) fn parse_main(body: &[u8]) -> Option<(u64, Vec<[u8; 16]>)> {
    if body.len() < 12 {
        return None;
    }
    let block_size = u64::from_le_bytes(body[0..8].try_into().unwrap());
    let nfiles = u32::from_le_bytes(body[8..12].try_into().unwrap()) as usize;
    let ids_bytes = &body[12..];
    // `block_size` is attacker-controlled (it comes straight off the wire
    // in the Main packet) and is later allocated and zero-filled per file
    // during verification (`verify_file_blocks`, `live::check_block`). A
    // crafted value like 2^62 sails past the `% 4` check and drives the
    // daemon into an out-of-memory kill (the zeroed alloc is lazy, but the
    // fill/hash touches every byte). Real PAR2 slices are KB to low-MB, so
    // cap far above any genuine set; beyond it the packet is treated as
    // malformed and verification is skipped - the download still completes
    // (PAR2 is repair-only).
    const MAX_BLOCK_SIZE: u64 = 256 << 20;
    if block_size == 0
        || block_size % 4 != 0
        || block_size > MAX_BLOCK_SIZE
        || ids_bytes.len() < nfiles * 16
    {
        return None;
    }
    let file_ids = ids_bytes
        .chunks_exact(16)
        .take(nfiles) // recovery-set ids only; non-recovery ids follow
        .map(|c| c.try_into().unwrap())
        .collect();
    Some((block_size, file_ids))
}

pub(crate) fn parse_filedesc(body: &[u8]) -> Option<([u8; 16], Desc)> {
    if body.len() < 56 {
        return None;
    }
    let fid: [u8; 16] = body[0..16].try_into().unwrap();
    let md5: [u8; 16] = body[16..32].try_into().unwrap();
    let md5_16k: [u8; 16] = body[32..48].try_into().unwrap();
    let length = u64::from_le_bytes(body[48..56].try_into().unwrap());
    // Name is ASCII/UTF-8, null-padded to a multiple of 4.
    let raw_name = &body[56..];
    let trimmed = raw_name
        .iter()
        .rposition(|&b| b != 0)
        .map_or(&raw_name[..0], |i| &raw_name[..=i]);
    let name = String::from_utf8_lossy(trimmed).into_owned();
    Some((
        fid,
        Desc {
            name,
            length,
            md5,
            md5_16k,
        },
    ))
}

pub(crate) fn parse_ifsc(body: &[u8]) -> Option<([u8; 16], Vec<BlockCheck>)> {
    if body.len() < 16 || !(body.len() - 16).is_multiple_of(20) {
        return None;
    }
    let fid: [u8; 16] = body[0..16].try_into().unwrap();
    let blocks = body[16..]
        .chunks_exact(20)
        .map(|c| BlockCheck {
            md5: c[0..16].try_into().unwrap(),
            crc32: u32::from_le_bytes(c[16..20].try_into().unwrap()),
        })
        .collect();
    Some((fid, blocks))
}

/// Hash `data` in `block_size` chunks (last chunk zero-padded to `block_size`,
/// per spec) and compare against `file.blocks`. Returns one flag per expected
/// block: `true` only when both MD5 and CRC32 match. If `data` is shorter
/// than the file, missing blocks are `false`; extra trailing data doesn't
/// create extra flags.
///
/// This is the reference implementation the future incremental hasher is
/// differential-tested against.
pub fn verify_file_blocks(file: &Par2File, block_size: u64, data: &[u8]) -> Vec<bool> {
    let bs = block_size as usize;
    if bs == 0 {
        return vec![false; file.blocks.len()];
    }
    let mut padded = vec![0u8; bs];
    file.blocks
        .iter()
        .enumerate()
        .map(|(i, check)| {
            let start = i * bs;
            if start >= data.len() {
                return false;
            }
            let end = (start + bs).min(data.len());
            let chunk: &[u8] = if end - start == bs {
                &data[start..end]
            } else {
                padded.fill(0);
                padded[..end - start].copy_from_slice(&data[start..end]);
                &padded
            };
            let md5: [u8; 16] = Md5::digest(chunk).into();
            md5 == check.md5 && crc32fast::hash(chunk) == check.crc32
        })
        .collect()
}

/// Full verification of a candidate `data` buffer against `file`: per-block
/// flags plus the whole-file MD5 and MD5-16k checks.
pub fn verify_file(file: &Par2File, block_size: u64, data: &[u8]) -> FileVerify {
    let md5: [u8; 16] = Md5::digest(data).into();
    // See module docs: first min(len, 16k) bytes, NOT zero-padded.
    let head = &data[..data.len().min(HASH16K_LEN)];
    let md5_16k: [u8; 16] = Md5::digest(head).into();
    FileVerify {
        blocks: verify_file_blocks(file, block_size, data),
        md5_ok: data.len() as u64 == file.length && md5 == file.md5,
        md5_16k_ok: md5_16k == file.md5_16k,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A crafted `.par2` of overlapping magics with EOF-reaching lengths used
    /// to make `scan_packets` quadratic: every 16-byte cell paid an MD5 over
    /// the rest of the file and then advanced ONE byte. `.par2` files come off
    /// the wire and are read whole with no size cap, so this was an hours-long
    /// CPU burn (an effective hang) from one downloaded file. The hash budget
    /// bounds it; the scan must find no packets and digest a linear number of
    /// bytes doing so.
    ///
    /// Asserted on bytes hashed, never on elapsed time: hashed bytes are
    /// exactly what the budget controls and are identical on every machine,
    /// whereas a wall-clock bound says nothing on a box where this process
    /// holds a fraction of a core - a 5s bound here failed reproducibly on a
    /// fully loaded machine while the budget was working perfectly.
    #[test]
    fn hostile_overlapping_magics_do_not_hash_quadratically() {
        const N: usize = 4 << 20; // 4 MiB: ~275 GB of MD5 before the fix
        let mut input = vec![0u8; N];
        let mut start = 0usize;
        while start + 16 <= N {
            input[start..start + 8].copy_from_slice(MAGIC);
            // Length reaching to EOF, >= HEADER_LEN and 4-aligned, so it passes
            // the structural gate; the stored-MD5 field is the next cell's
            // bytes, so verification always fails and the scan resumes at +1.
            let len = ((N - start) & !3) as u64;
            input[start + 8..start + 16].copy_from_slice(&len.to_le_bytes());
            start += 16;
        }
        let mut seen = 0usize;
        let hashed = scan_packets_counted(&input, |_| seen += 1);
        assert_eq!(seen, 0, "no cell has a valid MD5, so none may be yielded");
        // The optimistic parallel walk hashes each span once and its spans
        // never overlap, so it digests at most N; the serial scan it falls
        // back to stops the moment its budget (4N, here also the 16 MiB
        // floor) would be exceeded. 5N is therefore the true ceiling and 6N
        // is a margin - against ~65536N had the budget been removed.
        assert!(
            hashed <= 6 * N as u64,
            "scan_packets hashed {hashed} bytes over a {N}-byte input \
             - the hash budget is not bounding it"
        );
        // Guard the guard: a bound nothing reaches would pass even if the
        // scan silently stopped doing any work at all.
        assert!(hashed >= N as u64, "the hostile input must actually be scanned");
    }

    /// The parallel scan (buffers ≥ PAR_SCAN_MIN) must agree with the
    /// serial scan packet-for-packet, in order - on a clean buffer, on one
    /// with inter-packet garbage, and on one with a corrupt packet (which
    /// makes the parallel walk abandon and fall back). A divergence here
    /// is silent data corruption in repair, so compare full packet
    /// identity, not just counts.
    #[test]
    fn parallel_scan_matches_serial_scan() {
        let set_id = [3u8; 16];
        let body = |i: u32| {
            // Recovery-slice-shaped: exponent + ~256 KiB payload, so a
            // handful of packets crosses the parallel threshold.
            let mut b = i.to_le_bytes().to_vec();
            b.extend((0..256 << 10).map(|j| (i as usize * 31 + j) as u8));
            b
        };
        for corrupt_one in [false, true] {
            let mut buf = Vec::new();
            for i in 0..24u32 {
                if i == 7 {
                    buf.extend_from_slice(b"garbage between packets");
                }
                buf.extend(pkt(set_id, TYPE_RECVSLIC, &body(i)));
            }
            assert!(buf.len() >= PAR_SCAN_MIN, "fixture must take the parallel path");
            if corrupt_one {
                let mid = buf.len() / 2;
                buf[mid] ^= 0xFF;
            }
            let mut serial: Vec<([u8; 16], usize, usize)> = Vec::new();
            scan_packets_serial(&buf, |p| serial.push((p.md5, p.body_offset, p.body.len())));
            let mut both: Vec<([u8; 16], usize, usize)> = Vec::new();
            scan_packets(&buf, |p| both.push((p.md5, p.body_offset, p.body.len())));
            assert_eq!(both, serial, "corrupt_one={corrupt_one}");
            assert_eq!(both.len(), if corrupt_one { 23 } else { 24 });
        }
    }

    /// Build a Main-packet body: block_size ‖ nfiles ‖ nfiles×16 id bytes.
    fn main_body(block_size: u64, nfiles: u32) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&block_size.to_le_bytes());
        b.extend_from_slice(&nfiles.to_le_bytes());
        b.extend(std::iter::repeat_n(0u8, nfiles as usize * 16));
        b
    }

    /// Wrap a body in a valid packet header (magic, length, body MD5).
    fn pkt(set_id: [u8; 16], ptype: &[u8; 16], body: &[u8]) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(MAGIC);
        p.extend_from_slice(&(HEADER_LEN + body.len() as u64).to_le_bytes());
        p.extend_from_slice(&[0u8; 16]); // md5 patched below
        p.extend_from_slice(&set_id);
        p.extend_from_slice(ptype);
        p.extend_from_slice(body);
        let md5: [u8; 16] = Md5::digest(&p[32..]).into();
        p[16..32].copy_from_slice(&md5);
        p
    }

    /// A hostile poster can declare a 1000-block file and ship an IFSC
    /// listing ONE block. Live verify sizes its per-block state from the
    /// list, so it would check slice 0, find no bad blocks, and report the
    /// file clean while the other 999 MiB were never posted. A count that
    /// disagrees with the declared length is not a description of the
    /// file: the packet is dropped, which puts the file back on the
    /// whole-file MD5 path.
    #[test]
    fn short_ifsc_is_dropped_not_trusted() {
        let set_id = [7u8; 16];
        let fid = [9u8; 16];
        let block_size: u64 = 1 << 20;
        let length: u64 = 4 << 20; // 4 blocks

        let mut main = Vec::new();
        main.extend_from_slice(&block_size.to_le_bytes());
        main.extend_from_slice(&1u32.to_le_bytes());
        main.extend_from_slice(&fid);

        let mut desc = Vec::new();
        desc.extend_from_slice(&fid);
        desc.extend_from_slice(&[1u8; 16]); // md5
        desc.extend_from_slice(&[2u8; 16]); // md5_16k
        desc.extend_from_slice(&length.to_le_bytes());
        desc.extend_from_slice(b"data.bin");

        let ifsc = |n: usize| {
            let mut b = Vec::new();
            b.extend_from_slice(&fid);
            b.extend(std::iter::repeat_n(0u8, n * 20));
            b
        };

        let build = |n: usize| {
            let mut buf = pkt(set_id, TYPE_MAIN, &main);
            buf.extend(pkt(set_id, TYPE_FILEDESC, &desc));
            buf.extend(pkt(set_id, TYPE_IFSC, &ifsc(n)));
            buf
        };

        // Short list: dropped, so the file settles on the whole-file MD5.
        let short = build(1);
        let set = Par2Set::parse(&[&short]).unwrap();
        assert_eq!(set.files.len(), 1);
        assert!(set.files[0].blocks.is_empty(), "a 1-entry IFSC must not vouch for a 4-block file");

        // A long list is equally untrustworthy.
        let long = build(9);
        assert!(Par2Set::parse(&[&long]).unwrap().files[0].blocks.is_empty());

        // The honest count still parses and is kept.
        let ok = build(4);
        assert_eq!(Par2Set::parse(&[&ok]).unwrap().files[0].blocks.len(), 4);
    }

    #[test]
    fn block_size_bound_rejects_oversized_main() {
        // A real slice parses.
        assert!(parse_main(&main_body(768_000, 1)).is_some());
        // Exactly at the cap is still accepted…
        assert!(parse_main(&main_body(256 << 20, 1)).is_some());
        // …just past it is rejected (would OOM the verifier otherwise).
        assert!(parse_main(&main_body((256 << 20) + 4, 1)).is_none());
        // The crafted 2^62-ish value that drove the out-of-memory kill.
        assert!(parse_main(&main_body(0x7FFF_FFFF_FFFF_FFFC, 1)).is_none());
        // Existing guards still hold: zero, and non-multiple-of-4.
        assert!(parse_main(&main_body(0, 1)).is_none());
        assert!(parse_main(&main_body(1002, 1)).is_none());
    }
}

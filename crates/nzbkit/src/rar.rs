//! RAR volume header parsing + store-mode extraction mapping (design: M3).
//!
//! The one-pass trick: for store-mode (uncompressed) RAR sets - the norm
//! for large scene posts - a volume is just headers wrapped around
//! verbatim slices of the inner files. Parsing only the headers yields a
//! (volume, offset) → (inner file, offset) map, so decoded articles can
//! `pwrite` straight into the *extracted* file and the volumes never
//! touch disk.
//!
//! Both wire formats are supported:
//! - RAR5 (`Rar!\x1a\x07\x01\x00`): vint-encoded blocks, CRC32 header
//!   checksums, split flags 0x08/0x10, method in compression_info bits
//!   7–9 (0 = store), encryption as block type 4 (encrypted headers) or a
//!   file-extra record (encrypted data).
//! - RAR4 (`Rar!\x1a\x07\x00`): fixed little-endian headers, method byte
//!   0x30 = store, split flags 0x01/0x02, MHD_PASSWORD/LHD_PASSWORD.
//!
//! [`VolumeMapper`] parses incrementally from out-of-order article spans:
//! it keeps a small window at the parse cursor (headers are tiny; data
//! areas are skipped arithmetically), so mapping a volume needs only the
//! bytes at its header positions - usually all inside article 1 for
//! single-file volumes.

use std::collections::{HashMap, HashSet};

use crate::rarcrypt;

/// Compression method of an entry piece.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Store,
    Compressed,
}

/// RAR5 file-encryption parameters (extra record 0x01). A multi-volume
/// set encrypts each inner file as ONE continuous AES-256-CBC stream and
/// repeats the SAME record (salt, IV, check) in every volume's file
/// header - piece boundaries are arbitrary byte offsets, only the very
/// end is padded to 16 (total ciphertext = align16(unpacked_size)).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rar5Crypt {
    /// PBKDF2 iteration count exponent (iterations = 2^lg2_count).
    pub lg2_count: u8,
    pub salt: [u8; 16],
    pub iv: [u8; 16],
    /// Stored password check (8-byte value + 4-byte SHA-256 csum), when
    /// the archiver wrote one (WinRAR does by default).
    pub check: Option<[u8; 12]>,
    /// Crypt flag 0x02: the file CRC in the header is TWEAKED (mixed with
    /// the hash key so it can't fingerprint the plaintext). It is still
    /// checkable - fold the computed CRC the same way before comparing
    /// (`rarcrypt::mac_crc32`) - just not against a bare CRC32.
    pub tweaked_checksum: bool,
}

/// RAR4 file-encryption parameters. The whole record is one optional
/// 8-byte salt (file flag `FHD_SALT`, stored after the name): the AES-128
/// key AND the CBC IV both come out of the SHA-1 key schedule, and the
/// format stores no password check and no checksum tweak at all.
///
/// The stream shape matches RAR5's exactly - one continuous CBC stream per
/// inner file across every volume, the same salt repeated in each volume's
/// header, padded to 16 only at the very end - which is what lets the
/// store mapper treat both the same way.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rar4Crypt {
    pub salt: Option<[u8; 8]>,
}

/// Decryption parameters for one encrypted entry, in whichever format the
/// archive uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryCrypt {
    Rar5(Rar5Crypt),
    Rar4(Rar4Crypt),
}

impl EntryCrypt {
    /// The RAR5 record, for the paths that genuinely need RAR5-shaped
    /// parameters (the candidate probe, the resume journal's `E` line).
    pub fn rar5(&self) -> Option<&Rar5Crypt> {
        match self {
            EntryCrypt::Rar5(c) => Some(c),
            EntryCrypt::Rar4(_) => None,
        }
    }

    /// Derive this entry's key material from `password`. `None` only for a
    /// hostile RAR5 iteration count; RAR4's round count is fixed by the
    /// format, so it cannot be attacked this way.
    pub fn derive(&self, password: &str) -> Option<rarcrypt::EntryKeys> {
        match self {
            EntryCrypt::Rar5(c) => {
                let k = rarcrypt::derive_keys(password, &c.salt, c.lg2_count)?;
                Some(rarcrypt::EntryKeys {
                    aes: rarcrypt::AesKey::Aes256(k.key),
                    iv: c.iv,
                    hash_key: Some(k.hash_key),
                    psw_check: Some(k.psw_check),
                })
            }
            EntryCrypt::Rar4(c) => {
                let k = rarcrypt::derive_keys_v4(password, c.salt);
                Some(rarcrypt::EntryKeys {
                    aes: rarcrypt::AesKey::Aes128(k.key),
                    iv: k.iv,
                    hash_key: None,
                    psw_check: None,
                })
            }
        }
    }

    /// Is this entry's stored checksum the keyed fold of the plaintext
    /// CRC32 rather than the CRC32 itself? Only RAR5 has the flag; a RAR4
    /// header always stores the bare plaintext CRC32.
    pub fn tweaked_checksum(&self) -> bool {
        matches!(self, EntryCrypt::Rar5(c) if c.tweaked_checksum)
    }

    /// Does this entry's stored check actually VERIFY `keys`, as opposed
    /// to merely failing to veto them? Only a present, csum-valid check
    /// can: a malformed one rejects nothing for any password, so reading
    /// "did not reject" as "verified" would wave a wrong password
    /// through (see `entry_blocker`).
    ///
    /// Always false for RAR4, which stores no check value of any kind.
    ///
    /// False does NOT mean the password is wrong - it means nothing here
    /// can vouch for it before the data is decrypted, so the caller must
    /// keep a recoverable route: assemble ciphertext rather than
    /// decrypting in place, and require a whole-file checksum to pass
    /// before publishing.
    pub fn check_verifies(&self, keys: &rarcrypt::EntryKeys) -> bool {
        let EntryCrypt::Rar5(c) = self else { return false };
        let Some(psw_check) = keys.psw_check else { return false };
        c.check.as_ref().is_some_and(|chk| {
            rarcrypt::check_is_wellformed(chk) && !rarcrypt::check_rejects(&psw_check, chk)
        })
    }
}

/// One file piece described by a volume's headers.
#[derive(Debug, Clone)]
pub struct FileEntry {
    pub name: String,
    /// Total unpacked size of the inner file (repeated in every volume).
    pub unpacked_size: u64,
    pub method: Method,
    pub encrypted: bool,
    /// Decryption parameters for an encrypted entry (RAR5 only; a RAR4
    /// encrypted entry has `encrypted` set and no params).
    pub crypt: Option<EntryCrypt>,
    /// Stored whole-file CRC32 of the unpacked data (RAR5 file flag
    /// 0x04, or the RAR4 file-header CRC). For an encrypted entry it
    /// verifies the decrypted output - but only when the crypt record's
    /// tweaked-checksum flag is clear.
    pub file_crc: Option<u32>,
    /// Stored RAR5 file-hash extra record (FHEXTRA_HASH, type 0x02):
    /// `(hash_type, digest)`. hash_type 0 is BLAKE2sp (32-byte digest);
    /// carried so a CRC-less entry is not silently treated as verified.
    pub hash: Option<(u64, Vec<u8>)>,
    pub is_dir: bool,
    /// RAR5 "unpacked size unknown" file flag (0x08): `unpacked_size` is
    /// a placeholder, not a real length - nothing may derive offsets
    /// from it.
    pub size_unknown: bool,
    /// Piece continues from the previous volume.
    pub split_before: bool,
    /// Piece continues into the next volume.
    pub split_after: bool,
    /// Offset of this piece's data area within the volume file.
    pub data_off: u64,
    /// Length of this piece's data area.
    pub data_len: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RarVersion {
    V4,
    V5,
}

/// Why a volume can't be (or stopped being) mapped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MapBlocker {
    /// Not a RAR file at all.
    NotRar,
    /// Headers are password-encrypted and no password is available -
    /// nothing can be parsed.
    EncryptedHeaders,
    /// Structure parsed but a piece is compressed, or encrypted without a
    /// usable password; direct extraction is off, volumes must be
    /// materialized.
    NotStore,
    /// Entries are data-encrypted (`rar -p`, plain headers) and NO password
    /// is available at all. Store-shaped, but nothing here or in unrar can
    /// unpack it without a key. Distinct from [`Self::NotStore`] so the
    /// finish ladder keeps the verified volumes and prompts for a password
    /// (like [`Self::EncryptedHeaders`]) instead of running an unrar
    /// attempt that cannot succeed and failing the job.
    EncryptedNoPassword,
    /// The supplied password fails the archive's stored check value.
    BadPassword,
    /// Malformed header (CRC/structure): abort mapping, materialize.
    Corrupt(&'static str),
}

enum ParseState {
    /// Waiting for the signature at offset 0.
    Signature,
    /// Next block header expected at `cursor`.
    Blocks,
    /// Reached end of archive (or unrecoverable blocker).
    Done,
}

/// Incremental single-volume header parser. Feed it decoded spans in any
/// order; it consumes bytes at the parse cursor and skips data areas.
pub struct VolumeMapper {
    pub version: Option<RarVersion>,
    pub entries: Vec<FileEntry>,
    pub blocker: Option<MapBlocker>,
    /// RAR5 main-header volume number (0-based; absent on the first
    /// volume and in RAR4) - the obfuscation-proof volume ordering.
    pub volume_number: Option<u64>,
    /// True once the end-of-archive block (or EOF at `volume_size`) is
    /// reached - `entries` is then complete.
    pub complete: bool,
    /// Declared size of the volume file (yEnc total), for EOF detection.
    volume_size: u64,
    state: ParseState,
    cursor: u64,
    /// Contiguous window starting at `win_base` (== cursor when blocked).
    win_base: u64,
    win: Vec<u8>,
    filled: Vec<(usize, usize)>,
    /// Archive password, when the job has one - unlocks RAR5 encrypted
    /// headers (type-4 block) and encrypted store-mode entries.
    password: Option<std::sync::Arc<str>>,
    /// Header-decryption keys, derived once the type-4 block parses with
    /// a check-passing password. Every subsequent block is then stored as
    /// a 16-byte IV + AES-256-CBC ciphertext.
    hdr_keys: Option<rarcrypt::Rar5Keys>,
    /// RAR4 `-hp`: the main header carried MHD_PASSWORD, so every block
    /// after it is `8-byte salt + AES-128-CBC ciphertext`. (RAR5 keeps its
    /// derived keys in `hdr_keys` instead; RAR4 re-reads a salt per block,
    /// so only the flag is state.)
    v4_hdr_enc: bool,
    /// First RAR5 crypt record seen (header-encryption type-4 block or an
    /// encrypted file entry), captured EVEN when no password is set so a
    /// candidate can be checked against the archive without a full mapping
    /// pass. A multi-volume set repeats one record in every volume, so the
    /// first is representative. Populated regardless of blocker.
    crypt_seen: Option<CryptProbe>,
}

/// RAR5 crypt parameters harvested from an archive head - enough to test
/// a candidate password against the stored check WITHOUT decrypting any
/// data. `check` is `None` for check-less sets (WinRAR writes one by
/// default; without it a wrong password can only be caught by a real
/// extraction attempt, so those are not probeable here).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CryptProbe {
    pub lg2_count: u8,
    pub salt: [u8; 16],
    pub check: Option<[u8; 12]>,
}

/// Verdict of testing one candidate against a [`CryptProbe`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PwVerdict {
    /// Passes a valid stored check - the correct password, no decrypt.
    Verified,
    /// Rejected by a valid stored check - definitely wrong.
    Rejected,
    /// No stored check (or a hostile KDF count): can't decide pre-decrypt.
    Indeterminate,
}

impl VolumeMapper {
    /// The archive's RAR5 crypt parameters as far as this mapper has
    /// seen them: the type-4 header-encryption block if one parsed, else
    /// the record riding the first encrypted file entry. `None` when
    /// nothing testable has been seen (plain set, RAR4 encryption).
    /// The live-extraction candidate probe (Increment A) keys off this -
    /// unlike [`crypt_probe`] it needs no file, only the spans already
    /// fed.
    pub fn crypt_probe_params(&self) -> Option<CryptProbe> {
        if let Some(p) = self.crypt_seen.clone() {
            return Some(p);
        }
        self.entries.iter().find_map(|e| {
            e.crypt.as_ref().and_then(EntryCrypt::rar5).map(|c| CryptProbe {
                lg2_count: c.lg2_count,
                salt: c.salt,
                check: c.check,
            })
        })
    }
}

impl CryptProbe {
    /// Test `candidate` against the stored check. `Verified`/`Rejected`
    /// are definitive; `Indeterminate` means the caller must fall through
    /// to a real extraction attempt to know (check-less set).
    pub fn verify(&self, candidate: &str) -> PwVerdict {
        let Some(keys) = rarcrypt::derive_keys(candidate, &self.salt, self.lg2_count) else {
            return PwVerdict::Indeterminate;
        };
        match &self.check {
            Some(chk) if rarcrypt::check_rejects_password(&keys, chk) => PwVerdict::Rejected,
            // A check whose own csum is invalid rejects nothing, for ANY
            // password, so it cannot be read as confirmation - that turned the
            // first candidate tried into a false Verified and let a wrong
            // password native-decrypt garbage. It is no more informative than
            // a check-less set, which is exactly what Indeterminate means.
            Some(chk) if !rarcrypt::check_is_wellformed(chk) => PwVerdict::Indeterminate,
            Some(_) => PwVerdict::Verified,
            None => PwVerdict::Indeterminate,
        }
    }
}

/// Read `path`'s head and harvest RAR5 crypt parameters for password
/// testing, or `None` when the archive carries no testable RAR5
/// encryption (a plain/compressed set, RAR4 encryption - no RAR5 params,
/// or an unreadable file). Feeds the head through the header parser with
/// no password: a header-encryption type-4 block is captured before the
/// parser blocks, and file-encrypted sets expose the record on the first
/// encrypted entry.
pub fn crypt_probe(path: &std::path::Path) -> Option<CryptProbe> {
    let mut f = std::fs::File::open(path).ok()?;
    let size = f.metadata().map(|m| m.len()).unwrap_or(0);
    let mut m = VolumeMapper::new(size);
    feed_headers_incrementally(&mut f, size, &mut m);
    if let Some(p) = m.crypt_seen.clone() {
        return Some(p);
    }
    // File-encrypted set with readable headers: the record rides the
    // first encrypted entry.
    m.entries.iter().find_map(|e| {
        e.crypt.as_ref().and_then(EntryCrypt::rar5).map(|c| CryptProbe {
            lg2_count: c.lg2_count,
            salt: c.salt,
            check: c.check,
        })
    })
}

/// Feed a mapper the HEADER regions of `f` incrementally, seeking PAST each
/// member's data area (the parser advances its cursor over member payload
/// without needing those bytes). Unlike a single fixed-size prefix read,
/// this reaches a header that sits after a large plaintext member - e.g. an
/// encrypted second entry behind a >512 KiB plaintext first entry, which a
/// 512 KiB prefix probe missed (finding 17). Stops as soon as enough is
/// known (complete / blocked / a crypt record or encrypted entry seen), at
/// EOF, or after a bounded number of reads on hostile input.
/// Diagnostic wrapper over [`feed_headers_incrementally`] for the
/// `rarprobe` example - maps an on-disk volume's headers.
#[doc(hidden)]
pub fn feed_headers_incrementally_pub(f: &mut std::fs::File, size: u64, m: &mut VolumeMapper) {
    feed_headers_incrementally(f, size, m);
}

/// Fuzz entry point for the RAR4 `-hp` header framing, with the key
/// schedule already run (see `parse_block_v4_enc_with`). Returns
/// `(advanced_to, blocked)` rather than the private `BlockResult`:
/// `advanced_to` is where the parser would put the cursor, which is the
/// value every bound in the mapper is derived from.
#[doc(hidden)]
pub fn fuzz_v4_encrypted_header(
    bytes: &[u8],
    base: u64,
    key: [u8; 16],
    iv: [u8; 16],
    volume_size: u64,
) -> (Option<u64>, bool) {
    let keys = rarcrypt::Rar4Keys { key, iv };
    match parse_block_v4_enc_with(bytes, base, &keys, volume_size) {
        BlockResult::Skip { next, .. } => (Some(next), false),
        BlockResult::File { next, .. } => (Some(next), false),
        BlockResult::V4EncryptedHeaders { next } => (Some(next), false),
        BlockResult::Crypt { next, .. } => (Some(next), false),
        BlockResult::End | BlockResult::NeedMore => (None, false),
        BlockResult::Corrupt(_) | BlockResult::BadPassword | BlockResult::EncryptedHeaders => {
            (None, true)
        }
    }
}

fn feed_headers_incrementally(f: &mut std::fs::File, size: u64, m: &mut VolumeMapper) {
    use std::io::{Read, Seek, SeekFrom};
    const CHUNK: usize = 64 * 1024;
    const MAX_READS: usize = 1024;
    let mut buf = vec![0u8; CHUNK];
    let mut fed_upto = 0u64; // file offset one past the last byte fed
    for _ in 0..MAX_READS {
        if m.complete
            || m.blocker.is_some()
            || m.crypt_seen.is_some()
            || m.entries.iter().any(|e| e.crypt.is_some() || e.encrypted)
        {
            return;
        }
        // Read at the parse cursor (skips a member's data) or, when a header
        // straddles the last chunk, the next contiguous bytes.
        let want = m.cursor.max(fed_upto);
        if want >= size {
            return;
        }
        if f.seek(SeekFrom::Start(want)).is_err() {
            return;
        }
        let mut n = 0;
        while n < buf.len() {
            match f.read(&mut buf[n..]) {
                Ok(0) => break,
                Ok(k) => n += k,
                Err(_) => return,
            }
        }
        if n == 0 {
            return;
        }
        m.feed(want, &buf[..n]);
        fed_upto = want + n as u64;
    }
}

/// Headers are small; 4 MiB tolerates huge file-name tables and keeps the
/// window bounded even on hostile input.
const MAX_WIN: usize = 4 << 20;

/// Cap on the entries retained for one volume. The list is held for the
/// whole job and charged to no budget, so a stream of back-to-back file
/// headers (32 bytes each in RAR4, and none of them CRC-checked) grows it
/// at line rate. A real multi-file RAR carries tens of members, not
/// thousands, so this only ever fires on hostile input.
const MAX_ENTRIES: usize = 100_000;

const SIG5: &[u8; 8] = b"Rar!\x1a\x07\x01\x00";
const SIG4: &[u8; 7] = b"Rar!\x1a\x07\x00";

impl VolumeMapper {
    pub fn new(volume_size: u64) -> VolumeMapper {
        Self::with_password(volume_size, None)
    }

    /// A mapper that can parse RAR5 encrypted headers and accept
    /// encrypted store-mode entries (the password is check-verified
    /// against the archive before any entry is trusted).
    pub fn with_password(
        volume_size: u64,
        password: Option<std::sync::Arc<str>>,
    ) -> VolumeMapper {
        VolumeMapper {
            version: None,
            entries: Vec::new(),
            blocker: None,
            volume_number: None,
            complete: false,
            volume_size,
            state: ParseState::Signature,
            cursor: 0,
            win_base: 0,
            win: Vec::new(),
            filled: Vec::new(),
            password,
            hdr_keys: None,
            v4_hdr_enc: false,
            crypt_seen: None,
        }
    }

    /// Feed one decoded span. Returns true if new entries were parsed (the
    /// caller should re-try held spans and re-resolve bases).
    pub fn feed(&mut self, offset: u64, data: &[u8]) -> bool {
        if matches!(self.state, ParseState::Done) {
            return false;
        }
        self.stash(offset, data);
        let before = self.entries.len();
        self.advance();
        self.entries.len() > before || matches!(self.state, ParseState::Done)
    }

    /// Copy the part of the span that overlaps the parse window.
    fn stash(&mut self, offset: u64, data: &[u8]) {
        let win_end = self.win_base + MAX_WIN as u64;
        let s = offset.max(self.win_base);
        let e = (offset + data.len() as u64).min(win_end);
        if s >= e {
            return;
        }
        let need_len = (e - self.win_base) as usize;
        if self.win.len() < need_len {
            self.win.resize(need_len, 0);
        }
        let dst = (s - self.win_base) as usize;
        let src = (s - offset) as usize;
        let n = (e - s) as usize;
        self.win[dst..dst + n].copy_from_slice(&data[src..src + n]);
        merge_interval(&mut self.filled, dst, dst + n);
    }

    /// Contiguous bytes available at the cursor.
    fn avail(&self) -> &[u8] {
        debug_assert_eq!(self.win_base, self.cursor);
        match self.filled.first() {
            Some(&(0, e)) => &self.win[..e.min(self.win.len())],
            _ => &[],
        }
    }

    /// Move the parse cursor to `next`, refusing a jump that does not advance.
    ///
    /// `next` is `base + header_size + data_len` over an attacker-declared
    /// 64-bit length, and release builds WRAP silently (no `overflow-checks`
    /// in the release profile). A RAR4 header declaring `data_len = 2^64 - 40`
    /// makes `next` land exactly back on the current block: `rebase` is then a
    /// no-op, the window is unchanged, and the Blocks loop re-parses the same
    /// bytes forever - pushing a fresh `FileEntry` (with a heap `String`) each
    /// pass, i.e. 100% CPU plus unbounded memory growth from any RAR volume in
    /// any downloaded NZB. A wrapped `next` BELOW `win_base` instead underflows
    /// `rebase`'s subtraction. Every block strictly advances, so require it.
    fn advance_to(&mut self, next: u64) -> bool {
        if next <= self.cursor {
            self.fail(MapBlocker::Corrupt("block length does not advance"));
            return false;
        }
        // A block whose data area RUNS OFF THE END of the volume. `next` is
        // header end + an attacker-declared `data_size`, and a merely-large
        // (non-wrapping) value passes the advance check above: the cursor
        // then lands past `volume_size`, the next parse finds an empty
        // window, and the EOF rule at the `NeedMore` arm below declares the
        // volume COMPLETE. The oversized entry stays in `entries` with a
        // data area nothing will ever fill, `mapped_through()` returns
        // u64::MAX so no tail-hold fires, and the extractor preallocates
        // the declared size and ships a mostly-sparse file as a successful
        // extraction. Refuse instead: `Corrupt` sets the blocker, the
        // extractor demotes to materialized volumes, and unrar fails the
        // job honestly.
        //
        // This never trips a real split set. `data_len` is the PER-VOLUME
        // packed portion, not the whole-file length - `ArchiveMap::resolve`
        // accumulates `data_len` ACROSS consecutive volumes to derive each
        // continuation's inner-file base - so every genuine block ends at or
        // before the volume end, which is the same invariant the EOF rule
        // already assumes (`cursor == volume_size` means complete). Guarded
        // on `volume_size > 0` because a yEnc span with no `size=` leaves it
        // unknown.
        if self.volume_size > 0 && next > self.volume_size {
            self.fail(MapBlocker::Corrupt("data area exceeds volume"));
            return false;
        }
        self.cursor = next;
        self.rebase(next);
        true
    }

    /// Move the window base forward to `new_base` (>= win_base).
    fn rebase(&mut self, new_base: u64) {
        let skip = (new_base - self.win_base) as usize;
        if skip == 0 {
            return;
        }
        if skip >= self.win.len() {
            self.win.clear();
            self.filled.clear();
        } else {
            self.win.drain(..skip);
            let mut nf = Vec::with_capacity(self.filled.len());
            for &(s, e) in &self.filled {
                if e > skip {
                    nf.push((s.saturating_sub(skip), e - skip));
                }
            }
            self.filled = nf;
        }
        self.win_base = new_base;
    }

    fn fail(&mut self, b: MapBlocker) {
        self.blocker = Some(b);
        self.state = ParseState::Done;
        self.win = Vec::new();
        self.filled.clear();
    }

    fn advance(&mut self) {
        loop {
            match self.state {
                ParseState::Done => return,
                ParseState::Signature => {
                    let a = self.avail();
                    if a.len() < 8 {
                        if self.volume_size > 0
                            && self.volume_size < 8
                            && a.len() as u64 >= self.volume_size
                        {
                            self.fail(MapBlocker::NotRar);
                        }
                        return;
                    }
                    if &a[..8] == SIG5 {
                        self.version = Some(RarVersion::V5);
                        self.cursor = 8;
                    } else if &a[..7] == SIG4 {
                        self.version = Some(RarVersion::V4);
                        self.cursor = 7;
                    } else {
                        self.fail(MapBlocker::NotRar);
                        return;
                    }
                    self.rebase(self.cursor);
                    self.state = ParseState::Blocks;
                }
                ParseState::Blocks => {
                    let res = match self.version {
                        Some(RarVersion::V5) => match &self.hdr_keys {
                            Some(keys) => parse_block_v5_enc(self.avail(), self.cursor, keys),
                            None => parse_block_v5(self.avail(), self.cursor),
                        },
                        Some(RarVersion::V4) => match (self.v4_hdr_enc, &self.password) {
                            (true, Some(pw)) => parse_block_v4_enc(
                                self.avail(),
                                self.cursor,
                                pw,
                                self.volume_size,
                            ),
                            // MHD_PASSWORD with no password: nothing past
                            // the main header can be read at all.
                            (true, None) => BlockResult::EncryptedHeaders,
                            (false, _) => parse_block_v4(self.avail(), self.cursor),
                        },
                        None => unreachable!(),
                    };
                    match res {
                        BlockResult::NeedMore => {
                            // EOF without an end block: v4 archives (and
                            // truncated v5) just stop.
                            if self.volume_size > 0 && self.cursor >= self.volume_size {
                                self.state = ParseState::Done;
                                self.complete = true;
                            }
                            return;
                        }
                        BlockResult::Corrupt(why) => {
                            self.fail(MapBlocker::Corrupt(why));
                            return;
                        }
                        BlockResult::EncryptedHeaders => {
                            self.fail(MapBlocker::EncryptedHeaders);
                            return;
                        }
                        BlockResult::BadPassword => {
                            self.fail(MapBlocker::BadPassword);
                            return;
                        }
                        BlockResult::V4EncryptedHeaders { next } => {
                            // With no password this volume is as opaque as
                            // it ever was; the decision is re-taken at the
                            // next block so the blocker still reads
                            // EncryptedHeaders rather than a parse error.
                            self.v4_hdr_enc = true;
                            if !self.advance_to(next) {
                                return;
                            }
                        }
                        BlockResult::Crypt { next, lg2_count, salt, check } => {
                            // RAR5 archive-encryption block: with a
                            // check-passing password, header parsing
                            // continues in decrypting mode; otherwise the
                            // volume is as opaque as it ever was. Stash the
                            // crypt params first (for the no-password probe)
                            // so a candidate can be tested even here.
                            if self.crypt_seen.is_none() {
                                self.crypt_seen = Some(CryptProbe { lg2_count, salt, check });
                            }
                            let Some(pw) = self.password.clone() else {
                                self.fail(MapBlocker::EncryptedHeaders);
                                return;
                            };
                            let Some(keys) = rarcrypt::derive_keys(&pw, &salt, lg2_count)
                            else {
                                self.fail(MapBlocker::Corrupt("hostile KDF count"));
                                return;
                            };
                            if let Some(chk) = &check {
                                if rarcrypt::check_rejects_password(&keys, chk) {
                                    self.fail(MapBlocker::BadPassword);
                                    return;
                                }
                            }
                            self.hdr_keys = Some(keys);
                            if !self.advance_to(next) {
                                return;
                            }
                        }
                        BlockResult::End => {
                            self.state = ParseState::Done;
                            self.complete = true;
                            return;
                        }
                        BlockResult::Skip { next, volume_number } => {
                            if volume_number.is_some() {
                                self.volume_number = volume_number;
                            }
                            if !self.advance_to(next) {
                                return;
                            }
                        }
                        BlockResult::File { entry, next } => {
                            // Past the cap the volume stops being mapped.
                            // NotStore (not Corrupt) so it still routes
                            // through materialize + unrar, keeping the
                            // "never a hard job failure" property.
                            if self.entries.len() >= MAX_ENTRIES {
                                self.fail(MapBlocker::NotStore);
                                return;
                            }
                            if let Some(b) = self.entry_blocker(&entry) {
                                // Remember the entry (for diagnostics) but
                                // flag the volume unfit for direct extract.
                                self.entries.push(entry);
                                self.fail(b);
                                return;
                            }
                            self.entries.push(entry);
                            if !self.advance_to(next) {
                                return;
                            }
                        }
                    }
                }
            }
        }
    }

    /// Whether a parsed file entry blocks direct extraction. Encrypted
    /// STORE entries stay mappable when a password is in hand and nothing
    /// rejects it - the extractor then assembles the ciphertext stream at
    /// the usual store offsets and decrypts at finish.
    ///
    /// Only RAR5 can REJECT one here, via its stored check; that costs a
    /// KDF, cached per (password, salt, count), and a multi-volume set
    /// repeats one salt in every volume, so it is one derivation per
    /// archive rather than per volume. RAR4 has no check to test, so it
    /// derives nothing at all.
    fn entry_blocker(&self, e: &FileEntry) -> Option<MapBlocker> {
        if e.method == Method::Compressed {
            return Some(MapBlocker::NotStore);
        }
        if !e.encrypted {
            return None;
        }
        let Some(pw) = &self.password else {
            // No password anywhere: the verified volumes are the
            // deliverable until one arrives.
            return Some(MapBlocker::EncryptedNoPassword);
        };
        let Some(crypt) = &e.crypt else {
            // Encryption this parser has no key schedule for - a pre-3.0
            // RAR cipher (`unp_ver` < 29). Hand to unrar, which can use the
            // password we do have.
            return Some(MapBlocker::NotStore);
        };
        let Some(c) = crypt.rar5() else {
            // RAR4: the format stores nothing a password can be tested
            // against before decrypting, so this entry takes the same
            // unverified route a check-less RAR5 entry does - assemble the
            // posted CIPHERTEXT at store offsets (byte-identical to the
            // volumes, so a demote loses nothing) and let the finish pass
            // adjudicate against the header's whole-file CRC32, which for
            // RAR4 is a plain CRC of the PLAINTEXT.
            //
            // Answered BEFORE deriving anything, and not merely for speed:
            // a RAR4 salt is 8 attacker-chosen bytes in a plaintext file
            // header, and its schedule is 0x40000 SHA-1 rounds (~8x RAR5's
            // default). Deriving here would let a volume of back-to-back
            // distinct-salt file headers burn tens of CPU-minutes inside
            // the routing lock, bounded only by `MAX_ENTRIES`. Nothing here
            // needs the key, so nothing derives one; the finish pass
            // derives once per inner FILE, off the lock.
            return None;
        };
        let Some(keys) = crypt.derive(pw) else {
            return Some(MapBlocker::Corrupt("hostile KDF count"));
        };
        match &c.check {
            Some(chk) if keys.psw_check.is_some_and(|p| rarcrypt::check_rejects(&p, chk)) => {
                Some(MapBlocker::BadPassword)
            }
            // Only a csum-VALID stored check actually verifies the password:
            // `check_rejects_password` deliberately refuses to veto on a
            // corrupt check (a damaged check must not condemn a correct
            // password). So "did not veto" is not the same as "verified" - a
            // check whose 4-byte SHA-256 tail is wrong vetoes NOTHING, for any
            // password, and it must never take the "verified" arm: an attacker
            // who also sets the tweaked-checksum flag would otherwise have a
            // wrong password native-decrypt garbage that ships as success.
            //
            // Such an entry (and a genuinely check-less one) is still
            // MAPPABLE, because the verdict has simply moved to finish: the
            // extractor refuses plaintext-once for an unverified password, so
            // the inner file assembles CIPHERTEXT - byte-identical to the
            // volumes, hence still demotable - and `decrypt_finished` requires
            // the whole-file checksum (the group's last piece carries it) to
            // pass before anything publishes. No checksum available there
            // means the group fails and the volumes materialize, which is
            // exactly where this used to route immediately.
            Some(chk) if !rarcrypt::check_is_wellformed(chk) => None,
            Some(_) => None, // password verified - safe to native-decrypt
            // No stored check at all: same deal - unverifiable here,
            // adjudicated at finish against the whole-file checksum. Rare;
            // WinRAR writes a check by default.
            None => None,
        }
    }

    /// Map a decoded span (volume offset, len) onto parsed pieces.
    /// Returns (entry index, offset within the piece, offset within the
    /// span, len) for every intersection with a known data area. Parts of
    /// the span beyond the parsed region are NOT reported - the caller
    /// holds those bytes until more headers parse.
    pub fn map_span(&self, off: u64, len: u64) -> Vec<(usize, u64, u64, u64)> {
        let mut out = Vec::new();
        self.map_span_into(off, len, &mut out);
        out
    }

    /// [`Self::map_span`] into a caller-owned buffer - the article hot
    /// path reuses one scratch vector instead of allocating per article
    /// under the routing lock. Appends; the caller clears.
    pub fn map_span_into(&self, off: u64, len: u64, out: &mut Vec<(usize, u64, u64, u64)>) {
        let span_end = off + len;
        // Entries come off a forward-only parse cursor, so data areas are
        // ordered and disjoint; skip straight to the first one this span can
        // touch instead of scanning every parsed entry per article (this runs
        // under the routing lock for EVERY article of a many-member volume).
        debug_assert!(
            self.entries
                .windows(2)
                .all(|w| w[0].data_off + w[0].data_len <= w[1].data_off),
            "RAR entry data areas must be ordered and disjoint"
        );
        let start = self
            .entries
            .partition_point(|e| e.data_off + e.data_len <= off);
        for (i, e) in self.entries.iter().enumerate().skip(start) {
            if e.data_off >= span_end {
                break;
            }
            let ds = e.data_off;
            let de = e.data_off + e.data_len;
            let s = off.max(ds);
            let x = span_end.min(de);
            if s < x {
                out.push((i, s - ds, s - off, x - s));
            }
        }
    }

    /// The volume offset below which every byte is either header (parsed)
    /// or inside a known data area - i.e. mappable. Bytes at/after this
    /// need more header parsing.
    pub fn mapped_through(&self) -> u64 {
        if self.complete {
            u64::MAX
        } else {
            self.cursor
        }
    }
}

enum BlockResult {
    NeedMore,
    Corrupt(&'static str),
    EncryptedHeaders,
    /// A RAR4 header decrypted to something that is not a header, or whose
    /// CRC16 misses: with the right password neither can happen.
    BadPassword,
    /// RAR4 main header carrying MHD_PASSWORD: it and the marker are
    /// plaintext, every block from `next` onward is `salt + AES-128-CBC`.
    V4EncryptedHeaders { next: u64 },
    /// RAR5 archive-encryption block (type 4): all following headers are
    /// encrypted with keys derived from these parameters.
    Crypt {
        next: u64,
        lg2_count: u8,
        salt: [u8; 16],
        check: Option<[u8; 12]>,
    },
    End,
    /// Non-file block: next block starts at `next`. Main headers carry
    /// the RAR5 volume number when present.
    Skip {
        next: u64,
        volume_number: Option<u64>,
    },
    File { entry: FileEntry, next: u64 },
}

/// Read a RAR5 vint. Returns (value, bytes consumed) or None if truncated.
fn vint(b: &[u8]) -> Option<(u64, usize)> {
    let mut v: u64 = 0;
    for i in 0..10.min(b.len()) {
        v |= ((b[i] & 0x7f) as u64) << (7 * i);
        if b[i] & 0x80 == 0 {
            return Some((v, i + 1));
        }
    }
    None
}

fn rd_u32(b: &[u8]) -> u32 {
    u32::from_le_bytes(b[..4].try_into().unwrap())
}
fn rd_u16(b: &[u8]) -> u16 {
    u16::from_le_bytes(b[..2].try_into().unwrap())
}

/// Parse one RAR5 block whose header starts at `a[0]` (= volume offset
/// `base`).
fn parse_block_v5(a: &[u8], base: u64) -> BlockResult {
    // crc32(4) + header_size vint + header
    if a.len() < 5 {
        return BlockResult::NeedMore;
    }
    let stored_crc = rd_u32(a);
    let Some((hsize, hs_len)) = vint(&a[4..]) else {
        return if a.len() < 15 {
            BlockResult::NeedMore
        } else {
            BlockResult::Corrupt("bad header size vint")
        };
    };
    if hsize == 0 || hsize > (MAX_WIN as u64 - 16) {
        return BlockResult::Corrupt("implausible header size");
    }
    let hstart = 4 + hs_len;
    let hend = hstart + hsize as usize;
    if a.len() < hend {
        return BlockResult::NeedMore;
    }
    let hdr = &a[hstart..hend];
    // Per spec the CRC covers the header-size vint AND the header data.
    if crc32fast::hash(&a[4..hend]) != stored_crc {
        return BlockResult::Corrupt("header CRC mismatch");
    }
    parse_v5_body(hdr, base, hend as u64)
}

/// Parse one ENCRYPTED RAR5 block at `a[0]` (= volume offset `base`):
/// 16-byte IV, then AES-256-CBC ciphertext of the usual crc + size-vint +
/// header, padded to 16. The first cipher block is decrypted alone to
/// learn the header size, then the rest.
fn parse_block_v5_enc(a: &[u8], base: u64, keys: &rarcrypt::Rar5Keys) -> BlockResult {
    if a.len() < 32 {
        return BlockResult::NeedMore;
    }
    let iv: [u8; 16] = a[0..16].try_into().unwrap();
    let mut first = [0u8; 16];
    first.copy_from_slice(&a[16..32]);
    rarcrypt::cbc_decrypt(&keys.aes(), &iv, &mut first);
    let stored_crc = rd_u32(&first);
    let Some((hsize, hs_len)) = vint(&first[4..]) else {
        // 12 plaintext bytes hold any sane size vint.
        return BlockResult::Corrupt("bad encrypted header size vint");
    };
    if hsize == 0 || hsize > (MAX_WIN as u64 - 64) {
        return BlockResult::Corrupt("implausible header size");
    }
    let inner_len = 4 + hs_len + hsize as usize;
    let cipher_len = rarcrypt::align16(inner_len as u64) as usize;
    if a.len() < 16 + cipher_len {
        return BlockResult::NeedMore;
    }
    let mut plain = a[16..16 + cipher_len].to_vec();
    rarcrypt::cbc_decrypt(&keys.aes(), &iv, &mut plain);
    if crc32fast::hash(&plain[4..inner_len]) != stored_crc {
        // Wrong-password garbage is caught by the type-4 check value
        // before we ever get here - a CRC mismatch means damage.
        return BlockResult::Corrupt("encrypted header CRC mismatch");
    }
    let hdr = &plain[4 + hs_len..inner_len];
    parse_v5_body(hdr, base, (16 + cipher_len) as u64)
}

/// Parse a RAR5 header body (already decrypted if need be). `envelope` =
/// physical bytes the header occupies in the volume, so the block's data
/// area starts at `base + envelope`.
fn parse_v5_body(hdr: &[u8], base: u64, envelope: u64) -> BlockResult {
    let mut p = 0usize;
    let Some((btype, n)) = vint(&hdr[p..]) else {
        return BlockResult::Corrupt("type vint");
    };
    p += n;
    let Some((hflags, n)) = vint(&hdr[p..]) else {
        return BlockResult::Corrupt("flags vint");
    };
    p += n;
    let mut extra_size = 0u64;
    if hflags & 0x01 != 0 {
        let Some((v, n)) = vint(&hdr[p..]) else {
            return BlockResult::Corrupt("extra vint");
        };
        extra_size = v;
        p += n;
    }
    let mut data_size = 0u64;
    if hflags & 0x02 != 0 {
        let Some((v, n)) = vint(&hdr[p..]) else {
            return BlockResult::Corrupt("data vint");
        };
        data_size = v;
        p += n;
    }
    let next = base + envelope + data_size;

    match btype {
        4 => {
            // Archive encryption block: version vint (0 = AES-256), flags
            // vint (0x01 = password check present), KDF count byte, salt.
            let Some((ver, n)) = vint(&hdr[p..]) else {
                return BlockResult::Corrupt("crypt version");
            };
            p += n;
            if ver != 0 {
                return BlockResult::EncryptedHeaders; // unknown scheme
            }
            let Some((cflags, n)) = vint(&hdr[p..]) else {
                return BlockResult::Corrupt("crypt flags");
            };
            p += n;
            if hdr.len() < p + 17 {
                return BlockResult::Corrupt("crypt salt");
            }
            let lg2_count = hdr[p];
            p += 1;
            let salt: [u8; 16] = hdr[p..p + 16].try_into().unwrap();
            p += 16;
            let mut check = None;
            if cflags & 0x01 != 0 && hdr.len() >= p + 12 {
                check = Some(<[u8; 12]>::try_from(&hdr[p..p + 12]).unwrap());
            }
            BlockResult::Crypt { next, lg2_count, salt, check }
        }
        5 => BlockResult::End,
        1 => {
            // Main archive header: archive_flags vint, then volume number
            // (vint) when flag 0x02 is set. A volume archive (flag 0x01)
            // without an explicit number is the FIRST volume (0).
            let mut volume_number = None;
            if let Some((aflags, n)) = vint(&hdr[p..]) {
                if aflags & 0x02 != 0 {
                    if let Some((vn, _)) = vint(&hdr[p + n..]) {
                        volume_number = Some(vn);
                    }
                } else if aflags & 0x01 != 0 {
                    volume_number = Some(0);
                }
            }
            BlockResult::Skip {
                next,
                volume_number,
            }
        }
        2 | 3 => {
            // File (2) / service (3) header. Service blocks (CMT, QO, RR…)
            // carry data areas too and are skipped via `next`.
            if btype == 3 {
                return BlockResult::Skip {
                    next,
                    volume_number: None,
                };
            }
            let Some((file_flags, n)) = vint(&hdr[p..]) else {
                return BlockResult::Corrupt("file flags");
            };
            p += n;
            let Some((unp_size, n)) = vint(&hdr[p..]) else {
                return BlockResult::Corrupt("unpacked size");
            };
            p += n;
            let Some((_attr, n)) = vint(&hdr[p..]) else {
                return BlockResult::Corrupt("attributes");
            };
            p += n;
            if file_flags & 0x02 != 0 {
                if hdr.len() < p + 4 {
                    return BlockResult::Corrupt("mtime");
                }
                p += 4;
            }
            let mut file_crc = None;
            if file_flags & 0x04 != 0 {
                if hdr.len() < p + 4 {
                    return BlockResult::Corrupt("crc");
                }
                file_crc = Some(rd_u32(&hdr[p..]));
                p += 4;
            }
            let Some((comp_info, n)) = vint(&hdr[p..]) else {
                return BlockResult::Corrupt("compression info");
            };
            p += n;
            let Some((_host, n)) = vint(&hdr[p..]) else {
                return BlockResult::Corrupt("host os");
            };
            p += n;
            let Some((name_len, n)) = vint(&hdr[p..]) else {
                return BlockResult::Corrupt("name len");
            };
            p += n;
            if name_len > 0xFFFF || hdr.len() < p + name_len as usize {
                return BlockResult::Corrupt("name");
            }
            let name = String::from_utf8_lossy(&hdr[p..p + name_len as usize]).into_owned();

            // Extra area: scan records for file-encryption (type 0x01)
            // and the file-hash record (type 0x02), lifting decryption
            // parameters and any stored integrity digest.
            let mut encrypted = false;
            let mut crypt = None;
            let mut hash = None;
            if extra_size > 0 {
                let ex_start = hdr.len().saturating_sub(extra_size as usize);
                let mut q = ex_start;
                while q < hdr.len() {
                    let Some((rec_size, n)) = vint(&hdr[q..]) else { break };
                    let rec_start = q + n;
                    if rec_start >= hdr.len() {
                        break;
                    }
                    let Some((rec_type, tn)) = vint(&hdr[rec_start..]) else {
                        break;
                    };
                    // rec_size spans the type vint PLUS the record body, so it
                    // must be >= tn AND fit within the header; without the lower
                    // bound a crafted rec_size < tn makes the slice start exceed
                    // its end and panics.
                    let body_ok = rec_size as usize >= tn && rec_size as usize <= hdr.len() - rec_start;
                    if rec_type == 0x01 {
                        encrypted = true;
                        if body_ok {
                            crypt = parse_crypt_record(
                                &hdr[rec_start + tn..rec_start + rec_size as usize],
                            );
                        }
                    } else if rec_type == 0x02 && body_ok {
                        // FHEXTRA_HASH: hash_type vint then the raw digest.
                        let body = &hdr[rec_start + tn..rec_start + rec_size as usize];
                        if let Some((htype, hn)) = vint(body) {
                            hash = Some((htype, body[hn..].to_vec()));
                        }
                    }
                    // A hostile rec_size near 2^64 wrapped this addition
                    // (release profile: no overflow checks) and mapped q
                    // onto itself - an infinite loop holding the
                    // extractor's global lock. Bound it instead.
                    if rec_size as usize > hdr.len() - rec_start {
                        break;
                    }
                    q = rec_start + rec_size as usize;
                }
            }

            let method_bits = (comp_info >> 7) & 0x7;
            let is_dir = file_flags & 0x01 != 0;
            BlockResult::File {
                entry: FileEntry {
                    name,
                    unpacked_size: unp_size,
                    method: if method_bits == 0 {
                        Method::Store
                    } else {
                        Method::Compressed
                    },
                    encrypted,
                    crypt,
                    file_crc,
                    hash,
                    is_dir,
                    size_unknown: file_flags & 0x08 != 0,
                    split_before: hflags & 0x08 != 0,
                    split_after: hflags & 0x10 != 0,
                    data_off: base + envelope,
                    data_len: data_size,
                },
                next,
            }
        }
        _ => BlockResult::Skip { next, volume_number: None }, // main header (1), unknown types
    }
}

/// File-encryption extra record body (after the record-type vint):
/// version vint (0), flags vint (0x01 check present, 0x02 tweaked
/// checksums), KDF count byte, 16-byte salt, 16-byte IV, optional
/// 12-byte check.
fn parse_crypt_record(rec: &[u8]) -> Option<EntryCrypt> {
    let (ver, mut p) = vint(rec)?;
    if ver != 0 {
        return None;
    }
    let (cflags, n) = vint(&rec[p..])?;
    p += n;
    if rec.len() < p + 33 {
        return None;
    }
    let lg2_count = rec[p];
    p += 1;
    let salt: [u8; 16] = rec[p..p + 16].try_into().unwrap();
    p += 16;
    let iv: [u8; 16] = rec[p..p + 16].try_into().unwrap();
    p += 16;
    let check = (cflags & 0x01 != 0 && rec.len() >= p + 12)
        .then(|| <[u8; 12]>::try_from(&rec[p..p + 12]).unwrap());
    Some(EntryCrypt::Rar5(Rar5Crypt {
        lg2_count,
        salt,
        iv,
        check,
        tweaked_checksum: cflags & 0x02 != 0,
    }))
}

/// RAR4 `FHD_UNICODE` flag: the file-name field is `asciiFallback` + `\0` +
/// `highByte` + a 2-bit-mode packed UTF-16 stream (WinRAR's custom encoding).
const FHD_UNICODE: u16 = 0x0200;

/// Decode a RAR4 file-name field into UTF-8 bytes. Without the unicode flag
/// (or when the field lacks the `\0` separator) the raw bytes pass through.
/// The 2-bit-mode decoder mirrors the vendored codec's `decode_file_name`.
fn decode_rar4_name(raw: &[u8], flags: u16) -> Vec<u8> {
    if flags & FHD_UNICODE == 0 {
        return raw.to_vec();
    }
    let Some(zero_pos) = raw.iter().position(|&b| b == 0) else {
        return raw.to_vec();
    };
    if zero_pos + 1 >= raw.len() {
        return raw[..zero_pos].to_vec();
    }
    let fallback = &raw[..zero_pos];
    let high_byte = raw[zero_pos + 1];
    let encoded = &raw[zero_pos + 2..];
    let mut pos = 0usize;
    let mut flag_byte = 0u8;
    let mut flag_bits = 0u8;
    let mut dst_pos = 0usize;
    let mut units: Vec<u16> = Vec::new();
    // WinRAR's decoder stops at `MaxDecSize` (NM); without a ceiling the
    // mode-3 run expands up to 129 output units per encoded byte, and each
    // unit costs up to 3 UTF-8 bytes. A ceiling counted per HEADER does not
    // bound the volume: a 70-byte file header whose 38-byte name field is an
    // all-0xFF run decodes to 6 KB of String, RETAINED in the mapper's entry
    // list, so back-to-back headers amplify ~88x and turn a ~100 MB volume
    // into ~9 GB resident from any NZB. Bound the output by the ENCODED field
    // instead. Real names are unaffected: modes 0/1 emit at most one unit per
    // byte, mode 2 one per two, and a legitimate mode-3 run copies from the
    // ASCII fallback, whose length is below `raw.len()`. Amplification is then
    // capped at 3x, matching RAR5.
    const MAX_NAME_UNITS: usize = 2048;
    let cap = MAX_NAME_UNITS.min(raw.len());
    while pos < encoded.len() && units.len() < cap {
        if flag_bits == 0 {
            flag_byte = encoded[pos];
            pos += 1;
            flag_bits = 8;
        }
        let mode = flag_byte >> 6;
        flag_byte <<= 2;
        flag_bits -= 2;
        match mode {
            0 => {
                let Some(&low) = encoded.get(pos) else { return raw.to_vec() };
                pos += 1;
                units.push(u16::from(low));
                dst_pos += 1;
            }
            1 => {
                let Some(&low) = encoded.get(pos) else { return raw.to_vec() };
                pos += 1;
                units.push((u16::from(high_byte) << 8) | u16::from(low));
                dst_pos += 1;
            }
            2 => {
                let Some((&low, &high)) = encoded.get(pos).zip(encoded.get(pos + 1)) else {
                    return raw.to_vec();
                };
                pos += 2;
                units.push((u16::from(high) << 8) | u16::from(low));
                dst_pos += 1;
            }
            _ => {
                let Some(&length_byte) = encoded.get(pos) else { return raw.to_vec() };
                pos += 1;
                let (count, correction, high) = if length_byte & 0x80 != 0 {
                    let Some(&correction) = encoded.get(pos) else { return raw.to_vec() };
                    pos += 1;
                    ((length_byte & 0x7f) as usize + 2, correction, high_byte)
                } else {
                    (length_byte as usize + 2, 0, 0)
                };
                // Clamp the run to the same ceiling - the loop guard above
                // only sees whole iterations, and one run can emit 129 units.
                let count = count.min(cap - units.len());
                for _ in 0..count {
                    let low = fallback.get(dst_pos).copied().unwrap_or(b'?').wrapping_add(correction);
                    units.push((u16::from(high) << 8) | u16::from(low));
                    dst_pos += 1;
                }
            }
        }
    }
    char::decode_utf16(units)
        .map(|u| u.unwrap_or(char::REPLACEMENT_CHARACTER))
        .collect::<String>()
        .into_bytes()
}

/// RAR4 file flag `FHD_SALT`: an 8-byte encryption salt follows the name.
const FHD_SALT: u16 = 0x0400;

/// RAR4 file flag `FHD_ENCRYPTED`.
const FHD_ENCRYPTED: u16 = 0x0004;

/// Lowest `unp_ver` whose encryption is the AES-128 + SHA-1 schedule this
/// crate implements (unrar's `CRYPT_RAR30`; the vendored rars fork draws
/// the same line in `SplitCipher::new`). Below it lie the pre-3.0 ciphers
/// (RAR 1.3/1.5/2.0), which stay on the unrar fallback: they predate the
/// obfuscated-release era by two decades and share no primitives.
const RAR4_AES_MIN_UNP_VER: u8 = 29;

/// Parse one RAR4 block at `a[0]` (= volume offset `base`).
fn parse_block_v4(a: &[u8], base: u64) -> BlockResult {
    parse_block_v4_at(a, base, None)
}

/// Parse one RAR4 block whose (already decrypted, for `-hp`) header bytes
/// start at `h[0]`.
///
/// `hdr_span` is how many bytes the header occupies IN THE VOLUME, which
/// is `hsize` for a plaintext block but `8 + align16(hsize)` for an
/// encrypted one (salt + AES padding) - so it decides where the data area
/// starts and where the next block begins. `None` means "plaintext, use
/// `hsize`", which also tells the parser it may still need more bytes.
fn parse_block_v4_at(h: &[u8], base: u64, hdr_span: Option<u64>) -> BlockResult {
    let a = h;
    if a.len() < 7 {
        return BlockResult::NeedMore;
    }
    let btype = a[2];
    let flags = rd_u16(&a[3..]);
    let hsize = rd_u16(&a[5..]) as usize;
    if hsize < 7 {
        return BlockResult::Corrupt("v4 header size < 7");
    }
    let mut add_size = 0u64;
    if flags & 0x8000 != 0 {
        if a.len() < 11 {
            return BlockResult::NeedMore;
        }
        add_size = rd_u32(&a[7..]) as u64;
    }
    if a.len() < hsize {
        return BlockResult::NeedMore;
    }
    let span = hdr_span.unwrap_or(hsize as u64);
    // NOTE: for file headers with the 0x100 flag, `add_size` here is only
    // the LOW 32 bits - the file branch recomputes `next` with the high
    // half once parsed (a >4 GiB RAR4 store piece would otherwise walk
    // the cursor into the data area and end in a Corrupt fallback).
    let next = base + span + add_size;

    match btype {
        0x73 => {
            // Main header: MHD_PASSWORD (0x0080) = every block AFTER this
            // one is encrypted. The marker and the main header itself stay
            // plaintext (unrar's `ReadHeader15` only decrypts past
            // `SIZEOF_MARKHEAD3`), which is what makes the flag readable at
            // all.
            if flags & 0x0080 != 0 {
                BlockResult::V4EncryptedHeaders { next }
            } else {
                BlockResult::Skip { next, volume_number: None }
            }
        }
        0x74 => {
            // File header. Layout after the 7+4 byte block intro:
            // unp_size u32, host u8, crc u32, time u32, unp_ver u8,
            // method u8, name_size u16, attr u32,
            // [high_pack u32, high_unp u32 if flags & 0x100], name.
            if a.len() < 32 {
                return BlockResult::NeedMore;
            }
            let mut p = 11;
            let mut unp_size = rd_u32(&a[p..]) as u64;
            p += 4; // unp
            p += 1; // host
            // RAR4 stores a plain CRC32 of the unpacked data here - of the
            // PLAINTEXT even on an encrypted entry (unrar checks it after
            // decrypting, and the vendored rars writer stamps
            // `crc32(unpacked)` on the final fragment). Capturing it feeds
            // the final-output verifier so a tampered STORE member (damaged
            // before posting, so outer yEnc/PAR2 verify the archive
            // as-posted) is caught instead of written out as success; for an
            // encrypted entry it is also the ONLY thing that can adjudicate
            // the password, since RAR4 stores no check value.
            let v4_crc = rd_u32(&a[p..]);
            p += 4; // crc
            p += 4; // time
            let unp_ver = a[p];
            p += 1; // unp_ver
            let method = a[p];
            p += 1;
            let name_size = rd_u16(&a[p..]) as usize;
            p += 2;
            p += 4; // attr
            let mut data_len = add_size;
            if flags & 0x0100 != 0 {
                if a.len() < p + 8 {
                    return BlockResult::NeedMore;
                }
                data_len |= (rd_u32(&a[p..]) as u64) << 32;
                unp_size |= (rd_u32(&a[p + 4..]) as u64) << 32;
                p += 8;
            }
            if a.len() < p + name_size || p + name_size > hsize {
                if p + name_size > hsize {
                    return BlockResult::Corrupt("v4 name exceeds header");
                }
                return BlockResult::NeedMore;
            }
            // RAR4 encodes non-ASCII names with the FHD_UNICODE flag (0x0200)
            // as `asciiFallback\0<highByte><2-bit-packed UTF-16>`; a plain
            // UTF-8-lossy decode of the whole field mangles them (and two
            // distinct encoded names could collapse to one). Decode the
            // structure first.
            let name =
                String::from_utf8_lossy(&decode_rar4_name(&a[p..p + name_size], flags)).into_owned();
            p += name_size;
            let encrypted = flags & FHD_ENCRYPTED != 0;
            // The 8-byte encryption salt sits immediately after the name.
            // Absent it, the key schedule runs over the password alone -
            // a legacy shape, but a legal one, so parse the flag rather
            // than requiring a salt.
            let salt: Option<[u8; 8]> = if flags & FHD_SALT != 0 {
                if p + 8 > hsize {
                    return BlockResult::Corrupt("v4 salt exceeds header");
                }
                if a.len() < p + 8 {
                    return BlockResult::NeedMore;
                }
                Some(a[p..p + 8].try_into().unwrap())
            } else {
                None
            };
            // Only RAR 3.0+ encryption has a key schedule here. Older
            // ciphers leave `crypt` empty, which `entry_blocker` reads as
            // "hand to unrar".
            let crypt = (encrypted && unp_ver >= RAR4_AES_MIN_UNP_VER)
                .then_some(EntryCrypt::Rar4(Rar4Crypt { salt }));
            let decryptable = crypt.is_some();
            let is_dir = flags & 0x00E0 == 0x00E0;
            BlockResult::File {
                entry: FileEntry {
                    name,
                    unpacked_size: unp_size,
                    method: if method == 0x30 {
                        Method::Store
                    } else {
                        Method::Compressed
                    },
                    encrypted,
                    crypt,
                    // A zero field reads as "not computed", not as a real
                    // CRC32 of 0: writers leave it zero on pieces they can't
                    // compute a whole-file digest for, and the output gate
                    // treats a present CRC as authoritative - so trusting a 0
                    // would false-demote (deleting the extracted output and
                    // forcing a materialize+unrar) on a perfectly good set.
                    // The only real data hashing to 0 is an empty file, which
                    // has nothing to verify anyway.
                    //
                    // An encrypted entry carries it only when we can actually
                    // decrypt: with no key schedule the set materializes and
                    // unrar owns the verdict, and the value would just be a
                    // plaintext CRC nothing in this process ever computes.
                    // Note this is the WHOLE-FILE plaintext CRC only on the
                    // last fragment (`!split_after`); earlier fragments of a
                    // split encrypted file describe their own volume's packed
                    // bytes, which is why the finish pass reads the tail's.
                    file_crc: (!encrypted || decryptable).then_some(v4_crc).filter(|&c| c != 0),
                    hash: None,
                    is_dir,
                    // RAR4 has no unknown-size flag this parser honors.
                    size_unknown: false,
                    split_before: flags & 0x0001 != 0,
                    split_after: flags & 0x0002 != 0,
                    data_off: base + span,
                    data_len,
                },
                // Full 64-bit data length, not the low-32 `add_size`.
                next: base + span + data_len,
            }
        }
        0x7b => BlockResult::End,
        _ => BlockResult::Skip { next, volume_number: None },
    }
}

/// A RAR4 header is CRC16-checked (`crc32(header[2..end]) & 0xffff`),
/// which is what lets the `-hp` path tell a wrong password from a real
/// header: garbage decrypts to a CRC that misses with probability
/// 1 - 2^-16 per block.
///
/// The covered range stops short of the full header for the two legacy
/// comment shapes, where WinRAR CRCs only the fixed part - mirrored from
/// the vendored rars fork's `header_crc_end`, which is what real archives
/// are known to match.
fn v4_header_crc_ok(h: &[u8]) -> bool {
    let hsize = rd_u16(&h[5..]) as usize;
    if h.len() < hsize {
        return false;
    }
    let btype = h[2];
    let flags = rd_u16(&h[3..]);
    const MHD_COMMENT: u16 = 0x0002;
    const FHD_COMMENT: u16 = 0x0008;
    const FHD_LARGE: u16 = 0x0100;
    let end = match btype {
        // Main header with an old-style archive comment, and the standalone
        // comment block: fixed 13-byte coverage.
        0x73 if flags & MHD_COMMENT != 0 => 13,
        0x75 => 13,
        // File header with an old-style comment: coverage stops after the
        // salt, before the comment area.
        0x74 | 0x7a if flags & FHD_COMMENT != 0 => {
            if h.len() < 32 {
                return false;
            }
            let name_size = rd_u16(&h[28..]) as usize;
            let mut e = 32;
            if flags & FHD_LARGE != 0 {
                e += 8;
            }
            e += name_size;
            if flags & FHD_SALT != 0 {
                e += 8;
            }
            e
        }
        _ => hsize,
    }
    .min(hsize);
    if end < 2 {
        return false;
    }
    (crc32fast::hash(&h[2..end]) & 0xffff) as u16 == rd_u16(h)
}

/// Parse one AES-128-CBC encrypted RAR4 block (`-hp`) at volume offset
/// `base`.
///
/// On-disk shape, per unrar's `Archive::ReadHeader15` and the vendored
/// rars fork's `decrypt_encrypted_header_at`: an 8-byte plaintext salt,
/// then `align16(head_size)` bytes of ciphertext. Each block is its OWN
/// CBC stream restarting from the schedule's IV, so `head_size` has to be
/// read out of the first decrypted block before the rest can be sized.
/// Real archives repeat one salt for every header, which the KDF cache
/// turns into a single key derivation per volume.
fn parse_block_v4_enc(a: &[u8], base: u64, password: &str, volume_size: u64) -> BlockResult {
    if a.len() < 24 {
        return BlockResult::NeedMore;
    }
    let salt: [u8; 8] = a[..8].try_into().unwrap();
    let keys = rarcrypt::derive_keys_v4(password, Some(salt));
    parse_block_v4_enc_with(a, base, &keys, volume_size)
}

/// [`parse_block_v4_enc`] with the key schedule already run.
///
/// Split out because every length and offset below comes from decrypted
/// attacker bytes while the schedule above is fixed-size arithmetic over a
/// password: the fuzz target drives THIS with one throwaway key, so the
/// framing gets millions of executions instead of the ~20/s that 0x40000
/// SHA-1 rounds per input would allow.
fn parse_block_v4_enc_with(
    a: &[u8],
    base: u64,
    keys: &rarcrypt::Rar4Keys,
    volume_size: u64,
) -> BlockResult {
    if a.len() < 24 {
        return BlockResult::NeedMore;
    }
    let aes = rarcrypt::AesKey::Aes128(keys.key);
    let mut first = [0u8; 16];
    first.copy_from_slice(&a[8..24]);
    rarcrypt::cbc_decrypt(&aes, &keys.iv, &mut first);
    let hsize = rd_u16(&first[5..]) as usize;
    let enc_len = (hsize + 15) & !15;
    // Three cheap sanity checks on the decrypted first block BEFORE the
    // header CRC, because the CRC needs `hsize` bytes and a wrong password
    // yields a random `hsize` of up to 64 KB: without them the parser would
    // sit in NeedMore for bytes the volume does not contain, never reaching
    // a verdict, and the extractor would hold spans until the budget blew.
    // With the right password all three hold by construction.
    let plausible = hsize >= 7
        && (0x72..=0x7b).contains(&first[2])
        && (volume_size == 0 || base + 8 + enc_len as u64 <= volume_size);
    if !plausible {
        // Not a header shape at all - so the password is the suspect. Same
        // verdict RAR5's stored check gives, and the finish ladder prompts
        // for a new one instead of shipping anything.
        return BlockResult::BadPassword;
    }
    if a.len() < 8 + enc_len {
        return BlockResult::NeedMore;
    }
    let mut hdr = Vec::with_capacity(enc_len);
    hdr.extend_from_slice(&first);
    hdr.extend_from_slice(&a[24..8 + enc_len]);
    // One stream: the first block is already decrypted, so continue the
    // chain from its ciphertext rather than restarting at the IV.
    let chain: [u8; 16] = a[8..24].try_into().unwrap();
    rarcrypt::cbc_decrypt(&aes, &chain, &mut hdr[16..]);
    hdr.truncate(hsize);
    if !v4_header_crc_ok(&hdr) {
        return BlockResult::BadPassword;
    }
    match parse_block_v4_at(&hdr, base, Some(8 + enc_len as u64)) {
        // Every byte the header declares is already here, so "feed me
        // more" can only mean the header's own fields overrun its
        // `head_size` - malformed, not incomplete. Left as NeedMore the
        // parser would ask for bytes that will never come and the volume
        // would never reach a verdict at all.
        BlockResult::NeedMore => BlockResult::Corrupt("v4 encrypted header overruns its size"),
        other => other,
    }
}

fn merge_interval(list: &mut Vec<(usize, usize)>, mut s: usize, mut e: usize) {
    let mut merged = Vec::with_capacity(list.len() + 1);
    for &(fs, fe) in list.iter() {
        if fe < s || fs > e {
            merged.push((fs, fe));
        } else {
            s = s.min(fs);
            e = e.max(fe);
        }
    }
    merged.push((s, e));
    merged.sort_unstable();
    *list = merged;
}

// ---------------------------------------------------------------------------
// Multi-volume archive: piece base-offset resolution
// ---------------------------------------------------------------------------

/// Base (inner-file) offsets for every parsed piece, resolved in volume
/// order. A piece's base is only known once every piece of the same file
/// Does this on-disk volume need a password? Feeds the file's head
/// through the header parser: encrypted headers (RAR4 MHD_PASSWORD /
/// RAR5 encryption block) or any password-protected file entry (headers
/// readable, data encrypted). Merely-compressed archives return false -
/// those unrar can unpack without a password.
pub fn needs_password(path: &std::path::Path) -> bool {
    let Ok(mut f) = std::fs::File::open(path) else { return false };
    let size = f.metadata().map(|m| m.len()).unwrap_or(0);
    let mut m = VolumeMapper::new(size);
    // Seek-driven so an encrypted entry BEHIND a large plaintext member is
    // still detected (finding 17), not just one in the first 512 KiB.
    feed_headers_incrementally(&mut f, size, &mut m);
    matches!(m.blocker, Some(MapBlocker::EncryptedHeaders))
        || m.entries.iter().any(|e| e.encrypted)
}

/// Are this volume's headers opaque to the streaming mapper even WITH
/// `password` in hand? True says the in-stream path cannot map the set at
/// all, so extracting it means reading the volumes off disk through the
/// rars fork or unrar.
///
/// The shape it exists for is `-hp` (encrypted headers). Both formats now
/// parse on with the right password - RAR5 through its type-4 encryption
/// block, RAR4 through the per-block salt + AES-128 headers - so both
/// answer false and keep their in-stream route. RAR4 `-hp` used to answer
/// TRUE whatever it was handed, because header decryption was
/// unimplemented and the MHD_PASSWORD flag blocked unconditionally.
///
/// Distinct from [`needs_password`], which asks "is a password needed"
/// with none supplied; this asks "is the password we have any use to the
/// streaming path".
pub fn headers_encrypted_to(path: &std::path::Path, password: Option<&str>) -> bool {
    let Ok(mut f) = std::fs::File::open(path) else { return false };
    let size = f.metadata().map(|m| m.len()).unwrap_or(0);
    let mut m = VolumeMapper::with_password(size, password.map(std::sync::Arc::from));
    feed_headers_incrementally(&mut f, size, &mut m);
    matches!(m.blocker, Some(MapBlocker::EncryptedHeaders))
}

/// in earlier volumes has a known length - resolution is re-run as
/// volumes parse (cheap: O(total pieces)).
pub struct ArchiveMap {
    /// (volume, entry) → inner-file base offset.
    pub bases: HashMap<(usize, usize), u64>,
    /// A piece's offset was derived from BOTH neighbours and the two
    /// disagreed. Impossible for a healthy set - the headers contradict
    /// themselves - so the caller demotes rather than writing bytes at
    /// an offset it cannot justify.
    pub contradiction: bool,
}

impl ArchiveMap {
    /// `vols[i]` = the mapper for volume i (in .partNN order).
    ///
    /// A split file has AT MOST ONE piece per volume, and its pieces span
    /// CONSECUTIVE volumes - so a continuation's base in volume K is
    /// resolvable as soon as the same file's piece in volume K-1 has been
    /// parsed, even while K-1's later headers (and its end block, which
    /// lives in the volume's LAST article) are still in flight. Waiting
    /// for volume completeness instead stalled resolution behind every
    /// volume's final article and blew the holds cap on a 79-volume 35 GB
    /// set (holds grew at line rate for the whole download).
    pub fn resolve(vols: &[&VolumeMapper]) -> ArchiveMap {
        let indexed: Vec<(u64, &VolumeMapper)> =
            vols.iter().enumerate().map(|(i, m)| (i as u64, *m)).collect();
        Self::resolve_indexed(&indexed)
    }

    /// Base offsets for every parsed piece, from volumes that need NOT be
    /// a consecutive run - each carries its own volume index and
    /// adjacency is decided per neighbouring pair.
    ///
    /// Resolution is a propagation from two kinds of certain seed:
    ///
    /// - a piece with `!split_before` STARTS its file, so its base is 0;
    /// - a piece with `split_before && !split_after` ENDS its file, so its
    ///   base is `unpacked_size - data_len` - a fact from that one
    ///   volume's own header, needing no other volume at all.
    ///
    /// From any seeded piece the offsets walk BOTH ways along consecutive
    /// parsed volumes carrying the same inner file: forward by adding the
    /// earlier piece's length, backward by subtracting the earlier
    /// piece's own. Repeat to a fixpoint.
    ///
    /// The tail seed is what makes multi-file (season-pack) sets place
    /// under a partial or out-of-order arrival: instead of one run
    /// reaching back to volume 0, each inner file needs only a run
    /// containing its own first or last volume. Forward-only resolution
    /// from volume 0 was why an obfuscated season pack could hold
    /// unplaceable bytes until the whole set had parsed.
    ///
    /// Every base here is DERIVED from a header that actually parsed, so
    /// unlike the arithmetic gate there is no premise to be wrong about
    /// and nothing to withdraw later. A piece reached from both
    /// directions must agree; disagreement means self-contradictory
    /// headers and sets [`ArchiveMap::contradiction`].
    pub fn resolve_indexed(vols: &[(u64, &VolumeMapper)]) -> ArchiveMap {
        let mut bases: HashMap<(usize, usize), u64> = HashMap::new();
        let mut contradiction = false;

        // 1. Seeds.
        for (pos, (_, m)) in vols.iter().enumerate() {
            for (ei, e) in m.entries.iter().enumerate() {
                if e.is_dir {
                    continue;
                }
                if !e.split_before {
                    bases.insert((pos, ei), 0);
                } else if !e.split_after && tail_anchorable(e) {
                    // Checked: a piece longer than the file it ends is a
                    // broken header, not a base.
                    if let Some(b) = e.unpacked_size.checked_sub(e.data_len) {
                        bases.insert((pos, ei), b);
                    }
                }
            }
        }

        // 2. Links between adjacent parsed volumes that continue one
        //    inner file. A split file has at most ONE piece per volume;
        //    a volume naming the same file twice is malformed, so that
        //    name simply does not link (never a guess).
        let mut links: Vec<(usize, usize, usize, usize, u64)> = Vec::new();
        for i in 0..vols.len().saturating_sub(1) {
            if vols[i + 1].0 != vols[i].0 + 1 {
                continue; // not adjacent volumes - no chain across a gap
            }
            let (ma, mb) = (vols[i].1, vols[i + 1].1);
            for (ea_i, ea) in ma.entries.iter().enumerate() {
                if ea.is_dir || !ea.split_after {
                    continue;
                }
                let once_a = ma.entries.iter().filter(|x| !x.is_dir && x.name == ea.name).count();
                if once_a != 1 {
                    continue;
                }
                let Some((eb_i, eb)) = mb
                    .entries
                    .iter()
                    .enumerate()
                    .find(|(_, x)| !x.is_dir && x.name == ea.name)
                else {
                    continue;
                };
                if !eb.split_before {
                    continue;
                }
                let once_b = mb.entries.iter().filter(|x| !x.is_dir && x.name == ea.name).count();
                if once_b != 1 {
                    continue;
                }
                links.push((i, ea_i, i + 1, eb_i, ea.data_len));
            }
        }

        // 3. Propagate to a fixpoint. Sweeping forward then backward in
        //    volume order carries a seed the length of its chain per
        //    iteration, so this converges in a couple of passes rather
        //    than one pass per volume.
        for _ in 0..vols.len().max(1) {
            let mut changed = false;
            let mut step = |from: Option<u64>,
                            to_key: (usize, usize),
                            bases: &mut HashMap<(usize, usize), u64>,
                            contradiction: &mut bool| {
                let Some(want) = from else { return };
                match bases.get(&to_key) {
                    None => {
                        bases.insert(to_key, want);
                        changed = true;
                    }
                    Some(&have) if have != want => *contradiction = true,
                    _ => {}
                }
            };
            for &(pa, ea, pb, eb, len) in links.iter() {
                let a = bases.get(&(pa, ea)).copied();
                step(a.and_then(|b| b.checked_add(len)), (pb, eb), &mut bases, &mut contradiction);
            }
            for &(pa, ea, pb, eb, len) in links.iter().rev() {
                let b = bases.get(&(pb, eb)).copied();
                if let Some(bv) = b {
                    match bv.checked_sub(len) {
                        Some(want) => {
                            step(Some(want), (pa, ea), &mut bases, &mut contradiction)
                        }
                        // The earlier piece would start before the file
                        // does: the two headers cannot both be true.
                        None => contradiction = true,
                    }
                }
            }
            if !changed {
                break;
            }
        }
        ArchiveMap { bases, contradiction }
    }

    /// Arithmetic placement for uniform single-file RAR5 STORE sets:
    /// when every parsed volume carries exactly one piece of one file
    /// and the volume geometry is consistent, volume N's piece base is
    /// computable from N and the geometry alone - every volume is
    /// placeable the moment ITS OWN headers parse, under any arrival
    /// order. This is the obfuscated-remux headline shape that chain
    /// resolution (above) demotes when arrival order keeps the
    /// consecutive-from-0 run short.
    ///
    /// The geometry is NOT "uniform data_len" (the trap that demoted the
    /// first live set this ran against): real archivers keep the VOLUME
    /// size constant, so the data area shrinks by a byte wherever the
    /// main header's volume-number vint grows - at volume 128, again at
    /// 16384 - and volume 0, whose number field is absent entirely,
    /// carries one byte MORE than volumes 1..127. The true invariants,
    /// validated against every parsed volume:
    ///
    ///   data_off(k) == off_base + volnum_field_len(k)
    ///   data_off(k) + data_len(k) == data_end          (non-final k)
    ///
    /// from which any volume's base follows in closed form:
    ///
    ///   D = data_end - off_base                      (= volume 0's dl)
    ///   base(N) = sum of dl(k) for k < N = N*D - S(N)
    ///
    /// with S(N) the total volume-number field bytes across volumes
    /// 0..N-1 ([`volnum_field_bytes_before`]). A set whose non-final
    /// pieces all share one data_len regardless of header size (some
    /// custom packers) does NOT fit this model and stays on the chain
    /// path - business as usual, never a demote.
    ///
    /// `vols` is every parsed mapper of the group, in ANY order. The
    /// distinction between the two failure modes matters to the caller:
    /// [`ArithGate::Shape`] says "not this kind of set" (multi-file,
    /// RAR4, encrypted, unnumbered...) - chain territory - while
    /// [`ArithGate::Numbers`] says the set LOOKS like this shape but its
    /// numbers contradict the premise, so any bytes placed under it are
    /// suspect.
    pub fn resolve_arithmetic(vols: &[&VolumeMapper]) -> ArithGate {
        use ArithGate::{Numbers, Shape};
        if vols.is_empty() {
            return Shape;
        }
        let mut geom: Option<(u64, u64)> = None; // (off_base, data_end) from non-finals
        let mut fin: Option<(u64, u64, u64)> = None; // final (volnum, data_len, data_off)
        let mut total: Option<u64> = None;
        let mut name: Option<&str> = None;
        let mut seen: HashSet<u64> = HashSet::with_capacity(vols.len());
        // Did a parsed volume 0 actually START this file? (Half of the
        // premise proof below.)
        let mut starts_at_zero = false;
        for m in vols {
            if m.version != Some(RarVersion::V5) || m.blocker.is_some() {
                return Shape;
            }
            let Some(vn) = m.volume_number else { return Shape };
            let [e] = m.entries.as_slice() else { return Shape };
            // Encrypted entries (with OR without a usable password) stay
            // on the chain path - the in-stream decrypt machinery was
            // built and verified against chained placement.
            if e.is_dir
                || e.encrypted
                || e.crypt.is_some()
                || e.size_unknown
                || !matches!(e.method, Method::Store)
                || e.unpacked_size == 0
            {
                return Shape;
            }
            match &name {
                None => name = Some(e.name.as_str()),
                Some(n) if *n == e.name => {}
                Some(_) => return Shape,
            }
            // A piece that STARTS anywhere but volume 0 means a second
            // file begins mid-set: multi-file territory, the chain's job.
            if vn > 0 && !e.split_before {
                return Shape;
            }
            match total {
                None => total = Some(e.unpacked_size),
                Some(t) if t == e.unpacked_size => {}
                Some(_) => return Numbers,
            }
            if vn == 0 && e.split_before {
                return Numbers; // a continuation at the archive head
            }
            if vn == 0 {
                starts_at_zero = true;
            }
            if !seen.insert(vn) {
                return Numbers; // duplicate volume number
            }
            // Header-base consistency: this volume's data offset must sit
            // exactly volnum_field_len(vn) past the shared base.
            let Some(off_base) = e.data_off.checked_sub(volnum_field_len(vn)) else {
                return Numbers;
            };
            if e.split_after {
                if e.data_len == 0 {
                    return Shape;
                }
                let Some(dend) = e.data_off.checked_add(e.data_len) else {
                    return Numbers;
                };
                match geom {
                    None => geom = Some((off_base, dend)),
                    Some((ob, de)) if ob == off_base && de == dend => {}
                    Some(_) => return Numbers, // volume geometry contradicts
                }
            } else {
                if let Some(&(ob, _)) = geom.as_ref() {
                    if ob != off_base {
                        return Numbers;
                    }
                }
                if fin.replace((vn, e.data_len, e.data_off)).is_some() {
                    return Numbers; // two declared-final pieces of one file
                }
            }
        }
        // A final parsed before any non-final: its off_base still has to
        // agree once geometry is known - re-check it here (the loop only
        // compared when geom was already set).
        if let (Some((fvn, _, foff)), Some((ob, _))) = (fin, geom) {
            if foff.checked_sub(volnum_field_len(fvn)) != Some(ob) {
                return Numbers;
            }
        }
        let total = total.unwrap();
        // Per-volume capacity D (volume 0's data_len): from geometry, or
        // derived from the final piece when only IT has parsed - the
        // premise fixes base(fvn) == total - fdl, so D must divide out
        // exactly.
        let d = match (geom, fin) {
            (Some((ob, de)), _) => {
                let Some(d) = de.checked_sub(ob) else { return Numbers };
                d
            }
            (None, Some((fvn, fdl, _))) if fvn > 0 => {
                let Some(head) = total.checked_sub(fdl) else { return Numbers };
                let Some(s) = volnum_field_bytes_before(fvn) else { return Numbers };
                let Some(num) = head.checked_add(s) else { return Numbers };
                if num % fvn != 0 {
                    return Numbers;
                }
                let d = num / fvn;
                if d == 0 || fdl > d {
                    return Numbers;
                }
                d
            }
            // Only a volnum-0 piece parsed; D is unused below.
            _ => 0,
        };
        // PROOF that the premise holds, before a single byte is placed on
        // it. The premise is "this file begins at volume 0", and headers
        // establish it exactly two ways: a parsed volume 0 whose piece
        // STARTS the file, or the closure identity against a parsed FINAL
        // piece (base(fvn) == total - fdl). Without one, this is not a
        // shape we may place - and that is `Shape`, not `Numbers`.
        //
        // Both halves matter. Refusing to bet without proof is what stops
        // a season pack's continuation-only group - locally uniform,
        // single-name, single-entry, but with absolute volume numbers and
        // a file that starts far into the set - from being placed at
        // offsets that are simply wrong. And reporting it as a different
        // shape rather than a contradiction is what keeps it streaming:
        // chain resolution places it correctly, so there is nothing to
        // demote.
        //
        // The proof costs nothing against the alternative: the tail seed
        // that chain resolution needs is the SAME fact as closure proof
        // here, so a set that could have been placed eagerly can be
        // placed by propagation at the same moment.
        //
        // The distinction is load-bearing. A group holding only the
        // CONTINUATION volumes of a middle file - a season pack before
        // its per-file groups merge - looks locally uniform, single-name
        // and single-entry, and satisfies every per-volume rule above.
        // What it cannot satisfy is the premise that its file begins at
        // volume 0: its volume numbers are absolute while its file starts
        // far into the set, so the closure identity fails. Reporting that
        // as a contradiction demoted healthy season packs (the whole
        // shape this path exists to keep streaming); reporting it as a
        // different shape costs nothing, because the chain handles it.
        let mut proven = starts_at_zero;
        if let Some((fvn, fdl, _)) = fin {
            if seen.iter().any(|&v| v > fvn) {
                return Shape; // pieces past the declared last volume
            }
            let Some(head) = total.checked_sub(fdl) else {
                return Shape;
            };
            if fvn == 0 {
                if head != 0 {
                    return Shape; // an unsplit volume must hold the whole file
                }
            } else if arith_base(fvn, d) != Some(head) || fdl > d {
                return Shape; // the set does not close from volume 0
            }
            proven = true;
        }
        if !proven {
            return Shape;
        }
        let mut bases = Vec::with_capacity(vols.len());
        for m in vols {
            let e = &m.entries[0];
            let vn = m.volume_number.unwrap();
            let base = if !e.split_before {
                0
            } else if !e.split_after {
                total - e.data_len // final piece; fits by checked_sub above
            } else {
                match arith_base(vn, d) {
                    Some(b) => b,
                    None => return Numbers,
                }
            };
            // A piece landing outside the declared file means the
            // premise (this file starts at volume 0, uniform capacity)
            // does not describe this set - most often a continuation-only
            // group whose absolute volume numbers run far past its own
            // file. Not a contradiction: hand it to the chain.
            if base.checked_add(e.data_len).map_or(true, |end| end > total) {
                return Shape;
            }
            bases.push(base);
        }
        // Volume numbers are distinct and all <= fvn, so a count of
        // fvn + 1 means exactly {0..=fvn}: the complete set, closed.
        // `saturating_add`, like every other arithmetic in this function:
        // `fvn` is a header vint, and a crafted volume number of u64::MAX
        // satisfies every guard above (a zero-length FINAL piece is accepted
        // - the data_len reject lives in the split_after arm). Release wraps
        // to 0 and answers "not closed", which is safe; debug and test builds
        // panicked here while holding the routing lock, poisoning it for the
        // rest of the job.
        let closed = fin.is_some_and(|(fvn, _, _)| seen.len() as u64 == fvn.saturating_add(1));
        ArithGate::Place { bases, closed }
    }
}

/// Bytes the RAR5 main header spends on the volume-number field for
/// volume `vn`: absent on volume 0 (MHD_VOLUME implies "first"), else
/// the vint length of the number - 1 byte through volume 127, 2 through
/// 16383, and so on.
fn volnum_field_len(vn: u64) -> u64 {
    if vn == 0 {
        return 0;
    }
    let mut n = vn;
    let mut l = 0u64;
    while n > 0 {
        n >>= 7;
        l += 1;
    }
    l
}

/// S(N): total volume-number field bytes across volumes 0..N-1 - the
/// closed-form band sum behind `base(N) = N*D - S(N)`.
fn volnum_field_bytes_before(n: u64) -> Option<u64> {
    let mut s = 0u64;
    let mut band_start = 1u64; // volume 0 contributes nothing
    let mut len = 1u64;
    while band_start < n {
        let band_end = if len >= 10 {
            u64::MAX
        } else {
            (1u64 << (7 * len)) - 1
        };
        let hi = band_end.min(n - 1);
        s = s.checked_add((hi - band_start + 1).checked_mul(len)?)?;
        if band_end >= n.saturating_sub(1) {
            break;
        }
        band_start = band_end + 1;
        len += 1;
    }
    Some(s)
}

/// base(N) = N*D - S(N): the inner-file offset where volume N's piece
/// starts, under the constant-volume-size geometry. None on overflow or
/// an impossible (S > N*D) combination - hostile headers fail closed.
fn arith_base(n: u64, d: u64) -> Option<u64> {
    n.checked_mul(d)?.checked_sub(volnum_field_bytes_before(n)?)
}

/// May this piece's base be derived from `unpacked_size - data_len`?
///
/// Only for a plain stored, unencrypted member. For a COMPRESSED entry
/// `data_len` is the packed length while `unpacked_size` is the unpacked
/// one, so the subtraction is meaningless. For an ENCRYPTED one the
/// pieces tile block-padded CIPHER space whose total is `sum(data_len)`
/// and can exceed `unpacked_size` (the finish pass truncates to it), so
/// the same subtraction is wrong - those keep resolving by summing
/// lengths forward, which is correct in cipher space.
fn tail_anchorable(e: &FileEntry) -> bool {
    matches!(e.method, Method::Store)
        && !e.encrypted
        && e.crypt.is_none()
        && !e.size_unknown
        && !e.is_dir
        && e.data_len <= e.unpacked_size
}

/// Outcome of [`ArchiveMap::resolve_arithmetic`].
pub enum ArithGate {
    /// Gate passed: `bases[i]` is the inner-file base offset of
    /// `vols[i]`'s single entry. `closed` means the parsed volumes form
    /// the complete set 0..=last, ending in the declared final piece -
    /// the premise is proven, not just unrefuted.
    Place { bases: Vec<u64>, closed: bool },
    /// Not this shape at all - chain resolution territory.
    Shape,
    /// The shape matched but the numbers contradict the uniform
    /// single-file premise.
    Numbers,
}

// ---------------------------------------------------------------------------
// Fixture writers: minimal store-mode RAR5 + RAR4 encoders. Used by unit
// tests and the end-to-end chaos suite (and eventually by a posting tool).
// ---------------------------------------------------------------------------

#[doc(hidden)]
pub mod fixtures {
    use crate::rarcrypt;

    /// Encode a RAR5 vint.
    fn vint(mut v: u64, out: &mut Vec<u8>) {
        loop {
            let b = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                out.push(b);
                break;
            }
            out.push(b | 0x80);
        }
    }

    /// Header bytes (crc + size vint + header data) for one v5 block.
    /// `extra` is appended as the header's extra area (flag 0x01).
    fn hdr_v5(btype: u64, mut hflags: u64, body: &[u8], extra: &[u8], data_len: u64) -> Vec<u8> {
        let mut hdr = Vec::new();
        if !extra.is_empty() {
            hflags |= 0x01;
        }
        vint(btype, &mut hdr);
        vint(hflags, &mut hdr);
        if !extra.is_empty() {
            vint(extra.len() as u64, &mut hdr);
        }
        if hflags & 0x02 != 0 {
            vint(data_len, &mut hdr);
        }
        hdr.extend_from_slice(body);
        hdr.extend_from_slice(extra);
        let mut sized = Vec::new();
        vint(hdr.len() as u64, &mut sized);
        // CRC covers the header-size vint + header data (spec).
        let mut crc = crc32fast::Hasher::new();
        crc.update(&sized);
        crc.update(&hdr);
        let mut out = Vec::new();
        out.extend_from_slice(&crc.finalize().to_le_bytes());
        out.extend_from_slice(&sized);
        out.extend_from_slice(&hdr);
        out
    }

    fn block_v5(btype: u64, hflags: u64, body: &[u8], data: &[u8], out: &mut Vec<u8>) {
        out.extend_from_slice(&hdr_v5(btype, hflags, body, &[], data.len() as u64));
        out.extend_from_slice(data);
    }

    /// A RAR4 volume whose MAIN HEADER carries MHD_PASSWORD (0x0080),
    /// padded with `pad` bytes of junk standing in for encrypted blocks.
    /// The "a password is required" shape, for probes that ask exactly
    /// that - the junk is not real ciphertext, so a mapper GIVEN a
    /// password rejects it; use [`rar4_volume_enc_headers`] for a set that
    /// actually decrypts.
    pub fn rar4_encrypted_headers(pad: usize) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(super::SIG4);
        out.extend_from_slice(&0u16.to_le_bytes()); // head crc (unchecked)
        out.push(0x73);
        out.extend_from_slice(&0x0080u16.to_le_bytes()); // MHD_PASSWORD
        out.extend_from_slice(&13u16.to_le_bytes());
        out.extend_from_slice(&[0u8; 6]); // reserved
        out.extend(std::iter::repeat(0xA5).take(pad));
        out
    }

    /// One store-mode RAR5 volume holding the given (name, total_size,
    /// piece, split_before, split_after) pieces. No volume-number field
    /// (like a standalone .rar) - use [`rar5_volume_n`] for numbered sets.
    pub fn rar5_volume(pieces: &[(&str, u64, &[u8], bool, bool)]) -> Vec<u8> {
        let with_crc: Vec<_> = pieces
            .iter()
            .map(|&(n, t, p, b, a)| (n, t, p, b, a, None))
            .collect();
        rar5_volume_inner(&with_crc, None)
    }

    /// Numbered multi-volume member (RAR5 volume_number, 0-based).
    pub fn rar5_volume_n(pieces: &[(&str, u64, &[u8], bool, bool)], vol_no: u64) -> Vec<u8> {
        let with_crc: Vec<_> = pieces
            .iter()
            .map(|&(n, t, p, b, a)| (n, t, p, b, a, None))
            .collect();
        rar5_volume_inner(&with_crc, Some(vol_no))
    }

    /// Like [`rar5_volume_n`], with a stored data CRC32 per piece (file
    /// flag 0x04) the way real archivers always write it. Per the RAR5
    /// spec the value is the CRC32 of the whole unpacked file on an
    /// unsplit entry and on the LAST split piece (the one unrar checks),
    /// and of the current volume's packed piece bytes on earlier pieces
    /// (store mode packs 1:1).
    pub fn rar5_volume_n_crc(
        pieces: &[(&str, u64, &[u8], bool, bool, Option<u32>)],
        vol_no: u64,
    ) -> Vec<u8> {
        rar5_volume_inner(pieces, Some(vol_no))
    }

    fn rar5_volume_inner(
        pieces: &[(&str, u64, &[u8], bool, bool, Option<u32>)],
        vol_no: Option<u64>,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(super::SIG5);
        // Main archive header (type 1): archive flags vint; volume sets
        // carry 0x01 (volume) and, past the first volume, 0x02 + number.
        let mut main_body = Vec::new();
        match vol_no {
            Some(0) => vint(0x01, &mut main_body),
            Some(n) => {
                vint(0x03, &mut main_body);
                vint(n, &mut main_body);
            }
            None => vint(0x00, &mut main_body),
        }
        block_v5(1, 0, &main_body, &[], &mut out);
        for &(name, total, piece, before, after, crc) in pieces {
            let mut body = Vec::new();
            // File flags: no mtime, not dir; 0x04 when a data CRC rides.
            vint(if crc.is_some() { 0x04 } else { 0 }, &mut body);
            vint(total, &mut body); // unpacked size
            vint(0, &mut body); // attributes
            if let Some(c) = crc {
                body.extend_from_slice(&c.to_le_bytes());
            }
            vint(0, &mut body); // compression info: method 0 = store
            vint(0, &mut body); // host os
            vint(name.len() as u64, &mut body);
            body.extend_from_slice(name.as_bytes());
            let mut hflags = 0x02; // data area present
            if before {
                hflags |= 0x08;
            }
            if after {
                hflags |= 0x10;
            }
            block_v5(2, hflags, &body, piece, &mut out);
        }
        // End of archive (type 5) with end-flags body (0 = last volume).
        let mut end_body = Vec::new();
        vint(0, &mut end_body);
        block_v5(5, 0, &end_body, &[], &mut out);
        out
    }

    /// HOSTILE fixture: a single-file store RAR5 volume whose file block
    /// DECLARES `declared_data` bytes of data area while only `data` is
    /// really there, and which ends immediately after those real bytes (no
    /// end-of-archive block - the parser would never reach it anyway).
    /// This is the "declared size exceeds what was posted" shape: without
    /// the volume-bounds check the cursor jumps past the volume end, the
    /// EOF rule calls the volume complete, and a mostly-sparse
    /// `unpacked_size`-long file ships as a successful extraction.
    pub fn rar5_volume_oversized(
        name: &str,
        unpacked_size: u64,
        data: &[u8],
        declared_data: u64,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(super::SIG5);
        let mut main_body = Vec::new();
        vint(0x00, &mut main_body);
        block_v5(1, 0, &main_body, &[], &mut out);
        let mut body = Vec::new();
        vint(0, &mut body); // file flags: no CRC
        vint(unpacked_size, &mut body);
        vint(0, &mut body); // attributes
        vint(0, &mut body); // compression info: store
        vint(0, &mut body); // host os
        vint(name.len() as u64, &mut body);
        body.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&hdr_v5(2, 0x02, &body, &[], declared_data));
        out.extend_from_slice(data);
        out
    }

    /// One store-mode RAR4 volume.
    pub fn rar4_volume(pieces: &[(&str, u64, &[u8], bool, bool)]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(super::SIG4);
        // Main header: crc u16 (unchecked by our parser) type 0x73 flags 0 size 13.
        let mh_size = 13u16;
        out.extend_from_slice(&0u16.to_le_bytes());
        out.push(0x73);
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&mh_size.to_le_bytes());
        out.extend_from_slice(&[0u8; 6]); // reserved
        for &(name, total, piece, before, after) in pieces {
            let mut flags: u16 = 0x8000; // add size present
            if before {
                flags |= 0x0001;
            }
            if after {
                flags |= 0x0002;
            }
            let name_b = name.as_bytes();
            let hsize = (7 + 4 + 4 + 1 + 4 + 4 + 1 + 1 + 2 + 4 + name_b.len()) as u16;
            out.extend_from_slice(&0u16.to_le_bytes()); // head crc (unchecked)
            out.push(0x74);
            out.extend_from_slice(&flags.to_le_bytes());
            out.extend_from_slice(&hsize.to_le_bytes());
            out.extend_from_slice(&(piece.len() as u32).to_le_bytes()); // add size
            out.extend_from_slice(&(total as u32).to_le_bytes()); // unp size
            out.push(0); // host
            // Whole-file CRC32 (RAR4 header field). Only a complete, single
            // piece can carry it here - a split piece's real whole-file CRC
            // spans data this call doesn't hold, so leave those 0. The parser
            // reads a 0 field as "not computed" (see `file_crc`), so a split
            // fixture exercises mapping without tripping the output-CRC gate.
            // Real writers put the whole-file CRC on the FINAL fragment
            // (vendor/rars/src/rar15_40/write.rs); a multi-volume test of the
            // gate itself therefore needs a fixture that can set it.
            let crc = if !before && !after { crc32fast::hash(piece) } else { 0 };
            out.extend_from_slice(&crc.to_le_bytes()); // crc
            out.extend_from_slice(&0u32.to_le_bytes()); // time
            out.push(29); // unp_ver
            out.push(0x30); // method: store
            out.extend_from_slice(&(name_b.len() as u16).to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes()); // attr
            out.extend_from_slice(name_b);
            out.extend_from_slice(piece);
        }
        // ENDARC
        out.extend_from_slice(&0u16.to_le_bytes());
        out.push(0x7b);
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&7u16.to_le_bytes());
        out
    }

    // -- encrypted RAR4 fixtures (mirror what the vendored rars writer
    //    emits for `-m0 -p`/`-hp`, which testdata/rar4/ pins against
    //    `unrar t`) --

    /// One inner file encrypted the way RAR4 does it: ONE AES-128-CBC
    /// stream over the whole file from the key schedule's own IV,
    /// zero-padded to 16 at the very end. Volumes carve arbitrary byte
    /// ranges out of `cipher` and repeat the same salt in every header.
    pub struct EncFile4 {
        pub plain_len: u64,
        pub cipher: Vec<u8>,
        pub salt: [u8; 8],
        /// CRC32 of the PLAINTEXT - what a RAR4 header stores, and the
        /// only thing that can adjudicate the password at finish.
        pub crc: u32,
    }

    /// Encrypt `plain` as one RAR4 file stream.
    pub fn encrypt_file_v4(password: &str, plain: &[u8], seed: u8) -> EncFile4 {
        let salt: [u8; 8] = seed16(seed, 7)[..8].try_into().unwrap();
        let keys = rarcrypt::derive_keys_v4(password, Some(salt));
        let mut cipher = plain.to_vec();
        cipher.resize(rarcrypt::align16(plain.len() as u64) as usize, 0);
        rarcrypt::CbcEncStream::new(&rarcrypt::AesKey::Aes128(keys.key), &keys.iv)
            .encrypt(&mut cipher);
        EncFile4 {
            plain_len: plain.len() as u64,
            cipher,
            salt,
            crc: crc32fast::hash(plain),
        }
    }

    type EncPiece4<'a> = (&'a str, &'a EncFile4, std::ops::Range<usize>, bool, bool);

    /// A RAR4 file-header block for one encrypted piece, WITHOUT the data
    /// area. `head_crc` is filled in for real: the `-hp` reader checks it,
    /// and it is what tells a wrong password from a real header.
    fn rar4_enc_file_header(piece: &EncPiece4<'_>) -> Vec<u8> {
        let (name, f, range, before, after) = piece;
        let mut flags: u16 = 0x8000 | 0x0004 | super::FHD_SALT; // add size, encrypted, salt
        if *before {
            flags |= 0x0001;
        }
        if *after {
            flags |= 0x0002;
        }
        let name_b = name.as_bytes();
        let hsize = (32 + name_b.len() + 8) as u16;
        let mut h = Vec::with_capacity(hsize as usize);
        h.extend_from_slice(&0u16.to_le_bytes()); // head crc, patched below
        h.push(0x74);
        h.extend_from_slice(&flags.to_le_bytes());
        h.extend_from_slice(&hsize.to_le_bytes());
        h.extend_from_slice(&(range.len() as u32).to_le_bytes()); // packed
        h.extend_from_slice(&(f.plain_len as u32).to_le_bytes()); // unpacked
        h.push(3); // host os
        // Real writers stamp the WHOLE-FILE plaintext CRC on the final
        // fragment only; earlier fragments describe their own volume's
        // packed bytes (vendor/rars/src/rar15_40/write.rs).
        let crc = if *after { crc32fast::hash(&f.cipher[range.clone()]) } else { f.crc };
        h.extend_from_slice(&crc.to_le_bytes());
        h.extend_from_slice(&0u32.to_le_bytes()); // time
        h.push(29); // unp_ver: RAR 2.9 = the AES-128 schedule
        h.push(0x30); // method: store
        h.extend_from_slice(&(name_b.len() as u16).to_le_bytes());
        h.extend_from_slice(&0u32.to_le_bytes()); // attr
        h.extend_from_slice(name_b);
        h.extend_from_slice(&f.salt);
        let hc = (crc32fast::hash(&h[2..]) & 0xffff) as u16;
        h[..2].copy_from_slice(&hc.to_le_bytes());
        h
    }

    fn rar4_end_block() -> Vec<u8> {
        let mut h = vec![0u8, 0];
        h.push(0x7b);
        h.extend_from_slice(&0u16.to_le_bytes());
        h.extend_from_slice(&7u16.to_le_bytes());
        let hc = (crc32fast::hash(&h[2..]) & 0xffff) as u16;
        h[..2].copy_from_slice(&hc.to_le_bytes());
        h
    }

    fn rar4_main_header(password_flag: bool) -> Vec<u8> {
        let mut h = vec![0u8, 0];
        h.push(0x73);
        h.extend_from_slice(&(if password_flag { 0x0080u16 } else { 0 }).to_le_bytes());
        h.extend_from_slice(&13u16.to_le_bytes());
        h.extend_from_slice(&[0u8; 6]); // reserved
        let hc = (crc32fast::hash(&h[2..]) & 0xffff) as u16;
        h[..2].copy_from_slice(&hc.to_le_bytes());
        h
    }

    /// Encrypted-DATA RAR4 volume (`rar -m0 -p…` shape): plaintext
    /// headers, AES-128-CBC file data.
    pub fn rar4_volume_enc(pieces: &[EncPiece4<'_>]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(super::SIG4);
        out.extend_from_slice(&rar4_main_header(false));
        for p in pieces {
            out.extend_from_slice(&rar4_enc_file_header(p));
            out.extend_from_slice(&p.1.cipher[p.2.clone()]);
        }
        out.extend_from_slice(&rar4_end_block());
        out
    }

    /// Encrypted-HEADER RAR4 volume (`rar -m0 -hp…` shape): the marker and
    /// main header stay plaintext (that is how the MHD_PASSWORD flag is
    /// readable at all), and every block after them is an 8-byte salt
    /// followed by its own AES-128-CBC stream padded to 16.
    pub fn rar4_volume_enc_headers(
        pieces: &[EncPiece4<'_>],
        password: &str,
        seed: u8,
    ) -> Vec<u8> {
        let salt: [u8; 8] = seed16(seed, 8)[..8].try_into().unwrap();
        let keys = rarcrypt::derive_keys_v4(password, Some(salt));
        let aes = rarcrypt::AesKey::Aes128(keys.key);
        let mut out = Vec::new();
        out.extend_from_slice(super::SIG4);
        out.extend_from_slice(&rar4_main_header(true));
        let wrap = |hdr: Vec<u8>, out: &mut Vec<u8>| {
            let mut cipher = hdr;
            cipher.resize(rarcrypt::align16(cipher.len() as u64) as usize, 0);
            rarcrypt::CbcEncStream::new(&aes, &keys.iv).encrypt(&mut cipher);
            out.extend_from_slice(&salt);
            out.extend_from_slice(&cipher);
        };
        for p in pieces {
            wrap(rar4_enc_file_header(p), &mut out);
            out.extend_from_slice(&p.1.cipher[p.2.clone()]);
        }
        wrap(rar4_end_block(), &mut out);
        out
    }

    // -- encrypted RAR5 fixtures (mirror what real `rar -m0 -p/-hp`
    //    emits; the format facts are pinned by the testdata KATs) --

    /// One inner file encrypted the way RAR5 does it: ONE AES-256-CBC
    /// stream over the whole file, zero-padded to 16 at the very end.
    /// Volumes carve arbitrary byte ranges out of `cipher` and repeat the
    /// same (salt, iv, check) in every piece's header.
    pub struct EncFile {
        pub plain_len: u64,
        pub cipher: Vec<u8>,
        pub lg2_count: u8,
        pub salt: [u8; 16],
        pub iv: [u8; 16],
        pub check: [u8; 12],
        /// Plaintext CRC32 written into the file header (flag 0x04) when
        /// `with_crc` is set - exercises the post-decrypt verify path.
        pub crc: u32,
        pub with_crc: bool,
        /// Set the crypt record's tweaked-checksum flag (0x02): the stored
        /// CRC is then treated as untrustworthy for a plain comparison.
        pub tweaked: bool,
        /// Omit the password-check value (crypt flag 0x01 cleared) - the
        /// rare WinRAR "don't store password check" case.
        pub no_check: bool,
        /// The password these parameters were derived from - needed to
        /// re-derive `hash_key` when `tweaked` folds the stored CRC.
        pub password: String,
    }

    /// Deterministic 16 bytes from a seed (fixtures must be reproducible).
    fn seed16(seed: u8, tweak: u8) -> [u8; 16] {
        let mut b = [0u8; 16];
        for (i, x) in b.iter_mut().enumerate() {
            *x = (i as u8)
                .wrapping_mul(37)
                .wrapping_add(seed)
                .wrapping_mul(59)
                .wrapping_add(tweak);
        }
        b
    }

    /// Encrypt `plain` as one RAR5 file stream. `lg2_count` 12 keeps test
    /// KDFs fast; real archives use 15.
    pub fn encrypt_file(password: &str, plain: &[u8], seed: u8) -> EncFile {
        let lg2_count = 12u8;
        let salt = seed16(seed, 1);
        let iv = seed16(seed, 2);
        let keys = rarcrypt::derive_keys(password, &salt, lg2_count).unwrap();
        let mut cipher = plain.to_vec();
        cipher.resize(rarcrypt::align16(plain.len() as u64) as usize, 0);
        rarcrypt::CbcEncStream::new(&keys.aes(), &iv).encrypt(&mut cipher);
        EncFile {
            plain_len: plain.len() as u64,
            cipher,
            lg2_count,
            salt,
            iv,
            check: rarcrypt::make_check(&keys),
            crc: crc32fast::hash(plain),
            with_crc: false,
            tweaked: false,
            no_check: false,
            password: password.to_string(),
        }
    }

    /// The file-encryption extra record (type 0x01) for `f`.
    fn crypt_extra(f: &EncFile) -> Vec<u8> {
        let mut body = Vec::new();
        vint(0x01, &mut body); // record type: encryption
        vint(0, &mut body); // version
        let cflags = if f.no_check { 0 } else { 0x01 } | if f.tweaked { 0x02 } else { 0 };
        vint(cflags, &mut body); // flags: [check value present] [+ tweaked]
        body.push(f.lg2_count);
        body.extend_from_slice(&f.salt);
        body.extend_from_slice(&f.iv);
        if !f.no_check {
            body.extend_from_slice(&f.check);
        }
        let mut out = Vec::new();
        vint(body.len() as u64, &mut out);
        out.extend_from_slice(&body);
        out
    }

    /// (header bytes, data bytes) for every block of an encrypted-data
    /// volume. `pieces` = (name, file, cipher range, split_before,
    /// split_after).
    type EncPiece<'a> = (&'a str, &'a EncFile, std::ops::Range<usize>, bool, bool);

    fn enc_volume_blocks(pieces: &[EncPiece<'_>], vol_no: Option<u64>) -> Vec<(Vec<u8>, Vec<u8>)> {
        let mut blocks = Vec::new();
        let mut main_body = Vec::new();
        match vol_no {
            Some(0) => vint(0x01, &mut main_body),
            Some(n) => {
                vint(0x03, &mut main_body);
                vint(n, &mut main_body);
            }
            None => vint(0x00, &mut main_body),
        }
        blocks.push((hdr_v5(1, 0, &main_body, &[], 0), Vec::new()));
        for (name, f, range, before, after) in pieces {
            let mut body = Vec::new();
            // Real RAR5 writes the WHOLE-FILE checksum on the unsplit
            // entry and on the LAST split piece only; earlier pieces
            // describe their own volume's bytes. Fixtures that stamped
            // the whole-file value on every piece let a head-only
            // lookup pass a test the tail lookup is what actually makes
            // work in the field, so only the tail carries it here.
            let tail = !*after;
            vint(if f.with_crc && tail { 0x04 } else { 0 }, &mut body); // file flags
            vint(f.plain_len, &mut body); // unpacked size
            vint(0, &mut body); // attributes
            if f.with_crc && tail {
                // A tweaked-checksum archive stores the KEYED FOLD of the
                // plaintext CRC32, not the CRC itself (WinRAR's
                // ConvertHashToMAC) - a fixture that stored the bare CRC
                // under a set tweaked flag would be testing a shape no
                // real archive has.
                let stored = if f.tweaked {
                    let keys = rarcrypt::derive_keys(&f.password, &f.salt, f.lg2_count)
                        .expect("fixture KDF count is sane");
                    rarcrypt::mac_crc32(&keys, f.crc)
                } else {
                    f.crc
                };
                body.extend_from_slice(&stored.to_le_bytes());
            }
            vint(0, &mut body); // compression info: store
            vint(0, &mut body); // host os
            vint(name.len() as u64, &mut body);
            body.extend_from_slice(name.as_bytes());
            let mut hflags = 0x02;
            if *before {
                hflags |= 0x08;
            }
            if *after {
                hflags |= 0x10;
            }
            let piece = &f.cipher[range.clone()];
            blocks.push((
                hdr_v5(2, hflags, &body, &crypt_extra(f), piece.len() as u64),
                piece.to_vec(),
            ));
        }
        let mut end_body = Vec::new();
        vint(0, &mut end_body);
        blocks.push((hdr_v5(5, 0, &end_body, &[], 0), Vec::new()));
        blocks
    }

    /// Encrypted-DATA volume (`rar -m0 -p…` shape): plaintext headers,
    /// AES-256-CBC file data.
    pub fn rar5_volume_enc(pieces: &[EncPiece<'_>], vol_no: Option<u64>) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(super::SIG5);
        for (hdr, data) in enc_volume_blocks(pieces, vol_no) {
            out.extend_from_slice(&hdr);
            out.extend_from_slice(&data);
        }
        out
    }

    /// Encrypted-HEADER volume (`rar -m0 -hp…` shape): a plaintext type-4
    /// crypt block, then every header wrapped as 16-byte IV + ciphertext
    /// (padded to 16); file data encrypted as in [`rar5_volume_enc`].
    pub fn rar5_volume_enc_headers(
        pieces: &[EncPiece<'_>],
        vol_no: Option<u64>,
        password: &str,
        seed: u8,
    ) -> Vec<u8> {
        let lg2_count = 12u8;
        let salt = seed16(seed, 3);
        let keys = rarcrypt::derive_keys(password, &salt, lg2_count).unwrap();
        let mut out = Vec::new();
        out.extend_from_slice(super::SIG5);
        let mut crypt_body = Vec::new();
        vint(0, &mut crypt_body); // version: AES-256
        vint(0x01, &mut crypt_body); // flags: check present
        crypt_body.push(lg2_count);
        crypt_body.extend_from_slice(&salt);
        crypt_body.extend_from_slice(&rarcrypt::make_check(&keys));
        out.extend_from_slice(&hdr_v5(4, 0, &crypt_body, &[], 0));
        for (bi, (hdr, data)) in enc_volume_blocks(pieces, vol_no).into_iter().enumerate() {
            let iv = seed16(seed.wrapping_add(bi as u8), 4);
            let mut cipher = hdr;
            cipher.resize(rarcrypt::align16(cipher.len() as u64) as usize, 0);
            rarcrypt::CbcEncStream::new(&keys.aes(), &iv).encrypt(&mut cipher);
            out.extend_from_slice(&iv);
            out.extend_from_slice(&cipher);
            out.extend_from_slice(&data);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(n: usize, seed: u8) -> Vec<u8> {
        (0..n).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed)).collect()
    }

    #[test]
    fn needs_password_on_disk_detection() {
        let dir = std::env::temp_dir().join(format!("nzbkit-rar-pw-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let write = |name: &str, bytes: &[u8]| {
            let p = dir.join(name);
            std::fs::write(&p, bytes).unwrap();
            p
        };
        // Encrypted headers (RAR4 MHD_PASSWORD) → password required.
        assert!(needs_password(&write("enc.rar", &fixtures::rar4_encrypted_headers(64))));
        // Plain store volume → no.
        let store = fixtures::rar4_volume(&[("a.bin", 4, b"data", false, false)]);
        assert!(!needs_password(&write("plain.rar", &store)));
        // Readable headers but the file's data is encrypted: LHD_PASSWORD
        // (0x0004) in the file-header flags (sig 7 + main 13 = block base
        // 20; flags at +3) → password required.
        let mut pwfile = store.clone();
        pwfile[23] |= 0x04;
        assert!(needs_password(&write("pwfile.rar", &pwfile)));
        // Compressed-but-not-encrypted (method byte at block base + 25)
        // must NOT ask for a password - unrar unpacks it alone.
        let mut comp = store.clone();
        comp[45] = 0x33;
        assert!(!needs_password(&write("comp.rar", &comp)));
        // Not a RAR / unreadable → no (nothing to unlock).
        assert!(!needs_password(&write("junk.rar", b"not a rar at all")));
        assert!(!needs_password(&dir.join("missing.rar")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The discriminator the extraction ladder's `-hp` shortcut rests on:
    /// "is the password we hold any use to the STREAMING path". Both
    /// formats now answer the same way - opaque with no password, and
    /// parseable with the right one - so neither is diverted to a disk
    /// read it no longer needs. (RAR4 `-hp` used to answer yes-opaque
    /// whatever it was passed, because header decryption was unimplemented.)
    #[test]
    fn headers_encrypted_to_separates_hp_from_a_usable_password() {
        let dir = std::env::temp_dir().join(format!("nzbkit-hdrenc-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let write = |name: &str, bytes: &[u8]| {
            let p = dir.join(name);
            std::fs::write(&p, bytes).unwrap();
            p
        };
        let rar4 = write("hp4.rar", V4_ENC_HDRS);
        assert!(headers_encrypted_to(&rar4, None));
        assert!(
            !headers_encrypted_to(&rar4, Some(PW)),
            "RAR4 -hp decrypts in-stream now - it must not be diverted to disk"
        );
        // Same rule as RAR5 below: a wrong password is a BadPassword
        // blocker, not an opaque one.
        assert!(!headers_encrypted_to(&rar4, Some("nope")));

        let rar5 = write("hp5.rar", ENC_HDRS);
        assert!(headers_encrypted_to(&rar5, None));
        assert!(
            !headers_encrypted_to(&rar5, Some(PW)),
            "RAR5 -hp decrypts in-stream - it must not be diverted to disk"
        );
        // A wrong password is a BadPassword blocker, not an opaque one:
        // reading the volumes off disk would not help either, so the
        // streaming path keeps it and reports the real reason.
        assert!(!headers_encrypted_to(&rar5, Some("nope")));

        // Nothing encrypted, and a non-archive: never divert.
        let store = fixtures::rar4_volume(&[("a.bin", 4, b"data", false, false)]);
        assert!(!headers_encrypted_to(&write("plain.rar", &store), Some(PW)));
        assert!(!headers_encrypted_to(&write("junk.rar", b"not a rar"), Some(PW)));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Feed a volume to a mapper in shuffled article-sized chunks.
    fn feed_shuffled(m: &mut VolumeMapper, vol: &[u8], art: usize, seed: u64) {
        let mut idx: Vec<usize> = (0..vol.len().div_ceil(art)).collect();
        // Tiny LCG shuffle.
        let mut state = seed;
        for i in (1..idx.len()).rev() {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            idx.swap(i, (state >> 33) as usize % (i + 1));
        }
        for i in idx {
            let s = i * art;
            let e = (s + art).min(vol.len());
            m.feed(s as u64, &vol[s..e]);
        }
    }

    #[test]
    fn v5_single_file_maps_fully() {
        let data = payload(100_000, 7);
        let vol = fixtures::rar5_volume(&[("movie.mkv", 100_000, &data, false, false)]);
        let mut m = VolumeMapper::new(vol.len() as u64);
        assert!(m.feed(0, &vol));
        assert_eq!(m.version, Some(RarVersion::V5));
        assert!(m.complete);
        assert_eq!(m.blocker, None);
        assert_eq!(m.entries.len(), 1);
        let e = &m.entries[0];
        assert_eq!(e.name, "movie.mkv");
        assert_eq!(e.method, Method::Store);
        assert_eq!(e.data_len, 100_000);
        // The data area must be exactly the payload.
        let off = e.data_off as usize;
        assert_eq!(&vol[off..off + 100_000], &data[..]);
        // map_span round-trip.
        let hits = m.map_span(e.data_off + 10, 50);
        assert_eq!(hits, vec![(0, 10, 0, 50)]);
    }

    #[test]
    fn v5_out_of_order_articles() {
        let data = payload(300_000, 3);
        let vol = fixtures::rar5_volume(&[("big.bin", 300_000, &data, false, false)]);
        for seed in 1..6u64 {
            let mut m = VolumeMapper::new(vol.len() as u64);
            feed_shuffled(&mut m, &vol, 7000, seed);
            assert!(m.complete, "seed {seed}");
            assert_eq!(m.entries.len(), 1);
            assert_eq!(m.entries[0].data_len, 300_000);
        }
    }

    #[test]
    fn v5_multi_file_volume() {
        let a = payload(50_000, 1);
        let b = payload(80_000, 2);
        let vol = fixtures::rar5_volume(&[
            ("a.bin", 50_000, &a, false, false),
            ("b.bin", 80_000, &b, false, false),
        ]);
        let mut m = VolumeMapper::new(vol.len() as u64);
        // Feed only the first 4 KB: should parse main + file a's header.
        m.feed(0, &vol[..4096]);
        assert_eq!(m.entries.len(), 1);
        assert!(!m.complete);
        // b's header sits after a's 50 KB data area - feed that region.
        let need = m.mapped_through() as usize;
        m.feed(need as u64, &vol[need..(need + 4096).min(vol.len())]);
        assert_eq!(m.entries.len(), 2);
        assert_eq!(m.entries[1].name, "b.bin");
        let off = m.entries[1].data_off as usize;
        assert_eq!(&vol[off..off + 80_000], &b[..]);
    }

    #[test]
    fn v5_split_series_resolves_bases() {
        let total = payload(250_000, 9);
        let p1 = &total[..100_000];
        let p2 = &total[100_000..200_000];
        let p3 = &total[200_000..];
        let v1 = fixtures::rar5_volume(&[("film.mkv", 250_000, p1, false, true)]);
        let v2 = fixtures::rar5_volume(&[("film.mkv", 250_000, p2, true, true)]);
        let v3 = fixtures::rar5_volume(&[("film.mkv", 250_000, p3, true, false)]);
        let mut m1 = VolumeMapper::new(v1.len() as u64);
        let mut m2 = VolumeMapper::new(v2.len() as u64);
        let mut m3 = VolumeMapper::new(v3.len() as u64);
        m1.feed(0, &v1);
        m2.feed(0, &v2);
        m3.feed(0, &v3);
        let map = ArchiveMap::resolve(&[&m1, &m2, &m3]);
        assert_eq!(map.bases[&(0, 0)], 0);
        assert_eq!(map.bases[&(1, 0)], 100_000);
        assert_eq!(map.bases[&(2, 0)], 200_000);
    }

    #[test]
    fn bases_resolve_from_headers_alone_not_completeness() {
        // Volume 1: only its HEADER bytes fed (end block still in flight -
        // the 35 GB regression: waiting on completeness stalls resolution
        // behind every volume's last article). Volume 2's base must still
        // resolve from vol 1's parsed piece length.
        let total = payload(200_000, 6);
        let v1 = fixtures::rar5_volume_n(&[("m.mkv", 200_000, &total[..120_000], false, true)], 0);
        let v2 = fixtures::rar5_volume_n(&[("m.mkv", 200_000, &total[120_000..], true, false)], 1);
        let mut m1 = VolumeMapper::new(v1.len() as u64);
        m1.feed(0, &v1[..4096]); // header only
        assert!(!m1.complete && m1.entries.len() == 1);
        let mut m2 = VolumeMapper::new(v2.len() as u64);
        m2.feed(0, &v2[..4096]);
        let map = ArchiveMap::resolve(&[&m1, &m2]);
        assert_eq!(map.bases[&(1, 0)], 120_000, "vol2 base from vol1 header");
    }

    #[test]
    fn v5_bases_wait_for_missing_volume() {
        // Three volumes, only the LAST parsed. Its piece ends the file,
        // so its base is `unpacked_size - data_len` from its own header
        // alone - no chain, no neighbours. (This used to assert the
        // opposite: forward-only resolution could place nothing until
        // volume 1 arrived, which is what stalled obfuscated season
        // packs.)
        let total = payload(300_000, 4);
        let v1 = fixtures::rar5_volume(&[("x.bin", 300_000, &total[..100_000], false, true)]);
        let v2 =
            fixtures::rar5_volume(&[("x.bin", 300_000, &total[100_000..200_000], true, true)]);
        let v3 = fixtures::rar5_volume(&[("x.bin", 300_000, &total[200_000..], true, false)]);
        let m1 = VolumeMapper::new(v1.len() as u64); // never fed!
        let m2 = VolumeMapper::new(v2.len() as u64); // never fed!
        let mut m3 = VolumeMapper::new(v3.len() as u64);
        m3.feed(0, &v3);
        let map = ArchiveMap::resolve(&[&m1, &m2, &m3]);
        assert_eq!(map.bases.get(&(2, 0)).copied(), Some(200_000));
        assert!(!map.contradiction);
        // The MIDDLE piece is still unplaceable on its own - it is
        // neither the file's head nor its tail, so it genuinely needs a
        // neighbour. That is the limit the tail seed does not remove.
        let mut m2 = VolumeMapper::new(v2.len() as u64);
        m2.feed(0, &v2);
        let m3_empty = VolumeMapper::new(v3.len() as u64); // never fed!
        let map = ArchiveMap::resolve(&[&m1, &m2, &m3_empty]);
        assert!(map.bases.is_empty(), "{:?}", map.bases);
    }

    /// The tail seed walks BACKWARD: once the final piece is anchored,
    /// each earlier piece of the same file follows from it, so a set
    /// resolves from its end even with volume 0 still missing.
    #[test]
    fn v5_bases_walk_backward_from_the_final_piece() {
        let total = payload(300_000, 6);
        let v1 = fixtures::rar5_volume(&[("x.bin", 300_000, &total[..100_000], false, true)]);
        let v2 =
            fixtures::rar5_volume(&[("x.bin", 300_000, &total[100_000..200_000], true, true)]);
        let v3 = fixtures::rar5_volume(&[("x.bin", 300_000, &total[200_000..], true, false)]);
        let m1 = VolumeMapper::new(v1.len() as u64); // never fed!
        let mut m2 = VolumeMapper::new(v2.len() as u64);
        let mut m3 = VolumeMapper::new(v3.len() as u64);
        m2.feed(0, &v2);
        m3.feed(0, &v3);
        let map = ArchiveMap::resolve(&[&m1, &m2, &m3]);
        assert_eq!(map.bases.get(&(2, 0)).copied(), Some(200_000));
        assert_eq!(map.bases.get(&(1, 0)).copied(), Some(100_000), "backward step");
        assert!(!map.contradiction);
    }

    /// Headers that disagree with themselves: the piece in volume 2 is
    /// reachable forward from volume 1 and backward from volume 3, and
    /// the two answers differ. Nothing may be placed on a guess, so the
    /// map reports the contradiction and the caller demotes.
    #[test]
    fn v5_bases_flag_a_self_contradictory_chain() {
        let total = payload(300_000, 8);
        // Volume 2 claims a piece longer than the gap the other two
        // leave for it.
        let v1 = fixtures::rar5_volume(&[("x.bin", 300_000, &total[..100_000], false, true)]);
        let v2 = fixtures::rar5_volume(&[("x.bin", 300_000, &total[..150_000], true, true)]);
        let v3 = fixtures::rar5_volume(&[("x.bin", 300_000, &total[200_000..], true, false)]);
        let mut ms = Vec::new();
        for v in [&v1, &v2, &v3] {
            let mut m = VolumeMapper::new(v.len() as u64);
            m.feed(0, v);
            ms.push(m);
        }
        let refs: Vec<&VolumeMapper> = ms.iter().collect();
        let map = ArchiveMap::resolve(&refs);
        assert!(map.contradiction, "disagreeing neighbours must be reported");
    }

    #[test]
    fn v4_single_and_split() {
        let data = payload(120_000, 5);
        let vol = fixtures::rar4_volume(&[("old.avi", 120_000, &data, false, false)]);
        let mut m = VolumeMapper::new(vol.len() as u64);
        m.feed(0, &vol);
        assert_eq!(m.version, Some(RarVersion::V4));
        assert!(m.complete);
        assert_eq!(m.entries.len(), 1);
        assert_eq!(m.entries[0].method, Method::Store);
        let off = m.entries[0].data_off as usize;
        assert_eq!(&vol[off..off + 120_000], &data[..]);

        // Split pair.
        let p1 = &data[..60_000];
        let p2 = &data[60_000..];
        let v1 = fixtures::rar4_volume(&[("old.avi", 120_000, p1, false, true)]);
        let v2 = fixtures::rar4_volume(&[("old.avi", 120_000, p2, true, false)]);
        let mut m1 = VolumeMapper::new(v1.len() as u64);
        let mut m2 = VolumeMapper::new(v2.len() as u64);
        m1.feed(0, &v1);
        m2.feed(0, &v2);
        assert!(m1.entries[0].split_after && !m1.entries[0].split_before);
        assert!(m2.entries[0].split_before && !m2.entries[0].split_after);
        let map = ArchiveMap::resolve(&[&m1, &m2]);
        assert_eq!(map.bases[&(1, 0)], 60_000);
    }

    #[test]
    fn compressed_flagged_not_store() {
        // Method bits nonzero → Compressed → blocker NotStore.
        let data = payload(10_000, 8);
        let mut vol = fixtures::rar5_volume(&[("c.bin", 10_000, &data, false, false)]);
        // Patch compression_info in the file header: find the name and walk
        // back… simpler: rebuild via a tweaked writer is overkill - craft by
        // scanning for method vint is brittle. Instead test v4 (fixed
        // layout): method byte 0x33 = compressed.
        let mut v4 = fixtures::rar4_volume(&[("c.bin", 10_000, &data, false, false)]);
        // method byte offset: sig 7 + main 13 + 11 (intro+add) + 4+1+4+4+1 = 49
        let m_off = 7 + 13 + 11 + 14;
        assert_eq!(v4[m_off], 0x30);
        v4[m_off] = 0x33;
        let mut m = VolumeMapper::new(v4.len() as u64);
        m.feed(0, &v4);
        assert_eq!(m.blocker, Some(MapBlocker::NotStore));

        // And RAR5 header corruption is caught by the CRC.
        vol[10] ^= 0xff;
        let mut m5 = VolumeMapper::new(vol.len() as u64);
        m5.feed(0, &vol);
        assert!(matches!(m5.blocker, Some(MapBlocker::Corrupt(_))));
    }

    /// RAR4 >4 GiB store piece: `next` must use the full 64-bit packed
    /// size (add_size + high_pack), not just the low 32 bits - otherwise
    /// the cursor walks into the data area and ends in a Corrupt/NotStore
    /// fallback.
    #[test]
    fn v4_large_piece_advances_cursor_past_full_data_len() {
        // Hand-build a v4 file header claiming a 5 GiB piece (no actual
        // data needed - we only check the returned cursor).
        let name = b"huge.bin";
        let data_len: u64 = 5 << 30; // 5 GiB
        let hsize = (7 + 4 + 4 + 1 + 4 + 4 + 1 + 1 + 2 + 4 + 8 + name.len()) as u16;
        let mut blk = Vec::new();
        blk.extend_from_slice(&0u16.to_le_bytes()); // head crc (unchecked)
        blk.push(0x74);
        blk.extend_from_slice(&(0x8000u16 | 0x0100).to_le_bytes()); // add size + high fields
        blk.extend_from_slice(&hsize.to_le_bytes());
        blk.extend_from_slice(&((data_len & 0xFFFF_FFFF) as u32).to_le_bytes()); // add size lo
        blk.extend_from_slice(&((data_len & 0xFFFF_FFFF) as u32).to_le_bytes()); // unp lo
        blk.push(0); // host
        blk.extend_from_slice(&0u32.to_le_bytes()); // crc
        blk.extend_from_slice(&0u32.to_le_bytes()); // time
        blk.push(29); // unp_ver
        blk.push(0x30); // store
        blk.extend_from_slice(&(name.len() as u16).to_le_bytes());
        blk.extend_from_slice(&0u32.to_le_bytes()); // attr
        blk.extend_from_slice(&((data_len >> 32) as u32).to_le_bytes()); // high_pack
        blk.extend_from_slice(&((data_len >> 32) as u32).to_le_bytes()); // high_unp
        blk.extend_from_slice(name);
        let base = 20u64;
        match parse_block_v4(&blk, base) {
            BlockResult::File { entry, next } => {
                assert_eq!(entry.data_len, data_len);
                assert_eq!(entry.unpacked_size, data_len);
                assert_eq!(next, base + hsize as u64 + data_len, "cursor must skip the FULL piece");
            }
            _ => panic!("expected a file block"),
        }
    }

    /// A RAR4 file header carrying `field` verbatim as its name area and
    /// no data area, so headers pack back to back. `extra_flags` is OR'd
    /// into the block flags (FHD_UNICODE for the packed-name tests).
    fn v4_file_header(field: &[u8], extra_flags: u16) -> Vec<u8> {
        let hsize = (32 + field.len()) as u16;
        let mut blk = Vec::new();
        blk.extend_from_slice(&0u16.to_le_bytes()); // head crc (unchecked)
        blk.push(0x74);
        blk.extend_from_slice(&(0x8000u16 | extra_flags).to_le_bytes()); // add size present
        blk.extend_from_slice(&hsize.to_le_bytes());
        blk.extend_from_slice(&0u32.to_le_bytes()); // add size: no data area
        blk.extend_from_slice(&0u32.to_le_bytes()); // unp size
        blk.push(0); // host
        blk.extend_from_slice(&0u32.to_le_bytes()); // crc
        blk.extend_from_slice(&0u32.to_le_bytes()); // time
        blk.push(29); // unp_ver
        blk.push(0x30); // store
        blk.extend_from_slice(&(field.len() as u16).to_le_bytes());
        blk.extend_from_slice(&0u32.to_le_bytes()); // attr
        blk.extend_from_slice(field);
        blk
    }

    /// Wrap raw blocks in a RAR4 signature + main header + ENDARC.
    fn v4_volume_of(blocks: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(SIG4);
        out.extend_from_slice(&0u16.to_le_bytes()); // main head crc
        out.push(0x73);
        out.extend_from_slice(&0u16.to_le_bytes()); // flags
        out.extend_from_slice(&13u16.to_le_bytes());
        out.extend_from_slice(&[0u8; 6]); // reserved
        out.extend_from_slice(blocks);
        out.extend_from_slice(&0u16.to_le_bytes()); // ENDARC
        out.push(0x7b);
        out.extend_from_slice(&0u16.to_le_bytes());
        out.extend_from_slice(&7u16.to_le_bytes());
        out
    }

    /// A downloaded RAR4 volume must not turn into many times its own size
    /// in resident memory through its FILE NAMES. The packed-unicode
    /// decoder's ceiling used to be counted per HEADER, which a 70-byte
    /// header reaches on its own: 200 of them decoded to ~88x the volume,
    /// so a ~100 MB volume in any NZB meant ~9 GB resident. Legitimate
    /// FHD_UNICODE names must still decode exactly.
    #[test]
    fn v4_unicode_names_cannot_amplify_the_volume() {
        // Hostile: empty ASCII fallback, high byte 0x08, then 36 bytes of
        // 0xFF - every 2-bit mode is 3 (a run), every run is the maximum
        // 129 units, and every unit is a 3-byte UTF-8 character.
        let mut field = vec![0u8, 0x08];
        field.extend_from_slice(&[0xFFu8; 36]);
        let hdr = v4_file_header(&field, FHD_UNICODE);
        assert_eq!(hdr.len(), 70);
        let mut blocks = Vec::new();
        for _ in 0..200 {
            blocks.extend_from_slice(&hdr);
        }
        let vol = v4_volume_of(&blocks);
        let mut m = VolumeMapper::new(vol.len() as u64);
        m.feed(0, &vol);
        assert_eq!(m.entries.len(), 200);
        let decoded: usize = m.entries.iter().map(|e| e.name.len()).sum();
        assert!(
            decoded <= 3 * vol.len(),
            "names decoded to {decoded} bytes from a {}-byte volume",
            vol.len()
        );

        // Good case: a real FHD_UNICODE name, through every mode a writer
        // uses - a mode-3 run copied from the ASCII fallback, a mode-2
        // literal for the non-ASCII character, then a second run.
        let mut good = b"My.Long.Show.S01E01.e.mkv".to_vec();
        good.push(0); // separator
        good.push(0); // high byte
        good.extend_from_slice(&[0xEC, 18, 0xE9, 0x00, 2]);
        let vol = v4_volume_of(&v4_file_header(&good, FHD_UNICODE));
        let mut m = VolumeMapper::new(vol.len() as u64);
        m.feed(0, &vol);
        assert_eq!(m.entries.len(), 1);
        assert_eq!(m.entries[0].name, "My.Long.Show.S01E01.é.mkv");
    }

    /// A stream of back-to-back file headers must stop being mapped rather
    /// than growing the retained entry list at line rate - and it must stop
    /// with NotStore, so the job still materializes its volumes and hands
    /// them to unrar instead of failing outright.
    #[test]
    fn v4_entry_flood_stops_mapping_without_failing_the_job() {
        let hdr = v4_file_header(b"", 0);
        assert_eq!(hdr.len(), 32);
        let mut blocks = Vec::with_capacity(hdr.len() * (MAX_ENTRIES + 50));
        for _ in 0..MAX_ENTRIES + 50 {
            blocks.extend_from_slice(&hdr);
        }
        let vol = v4_volume_of(&blocks);
        let mut m = VolumeMapper::new(vol.len() as u64);
        // Article-sized feeds, so the parse window stays small.
        for s in (0..vol.len()).step_by(4096) {
            let e = (s + 4096).min(vol.len());
            m.feed(s as u64, &vol[s..e]);
        }
        assert_eq!(m.blocker, Some(MapBlocker::NotStore));
        assert!(!m.complete);
        assert!(m.entries.len() <= MAX_ENTRIES, "{} entries retained", m.entries.len());
        // Both mapper preconditions of the extractor's chase attach still
        // say no (RAR5 only, exactly one entry), so this routes to
        // materialize + unrar rather than to a chase worker.
        assert_eq!(m.version, Some(RarVersion::V4));
        assert_ne!(m.entries.len(), 1);

        // A real multi-file store volume is untouched by the cap.
        let a = payload(1_000, 1);
        let b = payload(2_000, 2);
        let c = payload(3_000, 3);
        let ok = fixtures::rar4_volume(&[
            ("a.bin", 1_000, &a, false, false),
            ("b.bin", 2_000, &b, false, false),
            ("c.bin", 3_000, &c, false, false),
        ]);
        let mut m = VolumeMapper::new(ok.len() as u64);
        m.feed(0, &ok);
        assert_eq!(m.blocker, None);
        assert!(m.complete);
        assert_eq!(m.entries.len(), 3);
        assert_eq!(m.entries[2].name, "c.bin");
        let off = m.entries[2].data_off as usize;
        assert_eq!(&ok[off..off + 3_000], &c[..]);
    }

    /// RAR5 extra-area record with a hostile size near 2^64: the record
    /// walk must terminate (the wrapping add mapped the cursor onto
    /// itself - an infinite loop holding the extractor's global lock).
    #[test]
    fn v5_hostile_extra_record_size_terminates() {
        // File header with an extra area whose record size vint is huge.
        let mut extra = Vec::new();
        for _ in 0..9 {
            extra.push(0xFF);
        }
        extra.push(0x7F); // vint ≈ 2^63+ - record "size"
        extra.push(0x01); // record type: file encryption
        let mut body = Vec::new();
        let mut hdr = Vec::new();
        // type 2 (file), flags 0x03 (extra + data), extra size, data size
        fn vint_enc(mut v: u64, out: &mut Vec<u8>) {
            loop {
                let b = (v & 0x7f) as u8;
                v >>= 7;
                if v == 0 {
                    out.push(b);
                    break;
                }
                out.push(b | 0x80);
            }
        }
        vint_enc(2, &mut hdr);
        vint_enc(0x03, &mut hdr);
        vint_enc(extra.len() as u64, &mut hdr); // extra size
        vint_enc(4, &mut hdr); // data size
        vint_enc(0, &mut body); // file flags
        vint_enc(100, &mut body); // unpacked
        vint_enc(0, &mut body); // attrs
        vint_enc(0, &mut body); // comp info: store
        vint_enc(0, &mut body); // host
        vint_enc(4, &mut body); // name len
        body.extend_from_slice(b"x.mk");
        hdr.extend_from_slice(&body);
        hdr.extend_from_slice(&extra);
        let mut sized = Vec::new();
        vint_enc(hdr.len() as u64, &mut sized);
        let mut blk = Vec::new();
        let mut crc = crc32fast::Hasher::new();
        crc.update(&sized);
        crc.update(&hdr);
        blk.extend_from_slice(&crc.finalize().to_le_bytes());
        blk.extend_from_slice(&sized);
        blk.extend_from_slice(&hdr);
        blk.extend_from_slice(b"data");
        // Must return (not spin) - and the hostile record still counts as
        // its declared type (encryption) before the walk stops.
        match parse_block_v5(&blk, 0) {
            BlockResult::File { entry, .. } => assert!(entry.encrypted),
            other => panic!("expected file block, got {}", match other {
                BlockResult::NeedMore => "NeedMore",
                BlockResult::Corrupt(w) => w,
                BlockResult::EncryptedHeaders => "EncryptedHeaders",
                BlockResult::BadPassword => "BadPassword",
                BlockResult::V4EncryptedHeaders { .. } => "V4EncryptedHeaders",
                BlockResult::Crypt { .. } => "Crypt",
                BlockResult::End => "End",
                BlockResult::Skip { .. } => "Skip",
                BlockResult::File { .. } => unreachable!(),
            }),
        }
    }

    /// RAR5 extra-area encryption record whose declared size is SMALLER
    /// than the type vint (rec_size=0). The old guard only checked the
    /// upper bound, so `&hdr[rec_start+tn .. rec_start+rec_size]` had
    /// start > end and panicked. Must parse without panicking.
    #[test]
    fn v5_encryption_record_size_below_type_vint_no_panic() {
        fn vint_enc(mut v: u64, out: &mut Vec<u8>) {
            loop {
                let b = (v & 0x7f) as u8;
                v >>= 7;
                if v == 0 {
                    out.push(b);
                    break;
                }
                out.push(b | 0x80);
            }
        }
        // Extra record: size vint = 0, then type vint = 0x01 (encryption).
        // rec_size (0) < tn (1) is the panic trigger.
        let mut extra = Vec::new();
        vint_enc(0, &mut extra); // rec_size = 0
        vint_enc(0x01, &mut extra); // rec_type = file encryption
        let mut hdr = Vec::new();
        vint_enc(2, &mut hdr); // type 2 = file
        vint_enc(0x03, &mut hdr); // flags: extra + data
        vint_enc(extra.len() as u64, &mut hdr); // extra size
        vint_enc(4, &mut hdr); // data size
        let mut body = Vec::new();
        vint_enc(0, &mut body); // file flags
        vint_enc(100, &mut body); // unpacked
        vint_enc(0, &mut body); // attrs
        vint_enc(0, &mut body); // comp info: store
        vint_enc(0, &mut body); // host
        vint_enc(4, &mut body); // name len
        body.extend_from_slice(b"x.mk");
        hdr.extend_from_slice(&body);
        hdr.extend_from_slice(&extra);
        let mut sized = Vec::new();
        vint_enc(hdr.len() as u64, &mut sized);
        let mut blk = Vec::new();
        let mut crc = crc32fast::Hasher::new();
        crc.update(&sized);
        crc.update(&hdr);
        blk.extend_from_slice(&crc.finalize().to_le_bytes());
        blk.extend_from_slice(&sized);
        blk.extend_from_slice(&hdr);
        blk.extend_from_slice(b"data");
        // The record is malformed, so crypt params stay None, but the flag
        // is set from the record type before the (now guarded) slice.
        match parse_block_v5(&blk, 0) {
            BlockResult::File { entry, .. } => {
                assert!(entry.encrypted);
                assert!(entry.crypt.is_none(), "malformed record must not yield crypt params");
            }
            other => panic!("expected file block, got {}", match other {
                BlockResult::NeedMore => "NeedMore",
                BlockResult::Corrupt(w) => w,
                BlockResult::EncryptedHeaders => "EncryptedHeaders",
                BlockResult::BadPassword => "BadPassword",
                BlockResult::V4EncryptedHeaders { .. } => "V4EncryptedHeaders",
                BlockResult::Crypt { .. } => "Crypt",
                BlockResult::End => "End",
                BlockResult::Skip { .. } => "Skip",
                BlockResult::File { .. } => unreachable!(),
            }),
        }
    }

    #[test]
    fn real_world_encrypted_headers_detected() {
        // Prefix of the real obfuscated release (encrypted headers):
        // signature + block crc 8eb85a8b + hsize 0x21 + type 4.
        let mut prefix = Vec::new();
        prefix.extend_from_slice(SIG5);
        prefix.extend_from_slice(&[0x8e, 0xb8, 0x5a, 0x8b, 0x21, 0x04]);
        prefix.extend_from_slice(&[0u8; 64]);
        let mut m = VolumeMapper::new(4096);
        m.feed(0, &prefix);
        // CRC of our zero-padded fake body won't match, so we accept either
        // blocker - the point is it must NOT parse as mappable store data.
        assert!(m.blocker.is_some());
        assert!(m.entries.is_empty());
    }

    /// A data area declared past the end of the volume must blocker the
    /// mapper, not sail through as a COMPLETE volume. Without the bound
    /// the cursor lands beyond `volume_size`, the next parse sees an
    /// empty window, and the EOF rule declares the volume complete - the
    /// mapper then vouches for bytes that were never posted.
    #[test]
    fn data_area_past_the_volume_end_is_corrupt() {
        let data = payload(4_000, 3);
        let vol = fixtures::rar5_volume_oversized("movie.mkv", 8 << 20, &data, 8 << 20);
        let mut m = VolumeMapper::new(vol.len() as u64);
        feed_shuffled(&mut m, &vol, 700, 5);
        assert!(
            matches!(m.blocker, Some(MapBlocker::Corrupt(_))),
            "expected a Corrupt blocker, got {:?}",
            m.blocker
        );
        assert!(!m.complete, "an overrunning volume must never read complete");
        assert_eq!(m.mapped_through(), m.cursor);
    }

    /// The bound must not fire on a legitimate split set, where every
    /// piece's `data_len` is the PER-VOLUME portion and lands exactly on
    /// the volume end - the same invariant the EOF rule already assumes.
    #[test]
    fn volume_bound_leaves_real_split_sets_alone() {
        let total = payload(300_000, 4);
        let vols = [
            fixtures::rar5_volume_n(&[("f.mkv", 300_000, &total[..100_000], false, true)], 0),
            fixtures::rar5_volume_n(&[("f.mkv", 300_000, &total[100_000..200_000], true, true)], 1),
            fixtures::rar5_volume_n(&[("f.mkv", 300_000, &total[200_000..], true, false)], 2),
        ];
        let mappers: Vec<VolumeMapper> = vols
            .iter()
            .map(|v| {
                let mut m = VolumeMapper::new(v.len() as u64);
                feed_shuffled(&mut m, v, 7000, 6);
                assert!(m.blocker.is_none(), "{:?}", m.blocker);
                assert!(m.complete);
                m
            })
            .collect();
        let refs: Vec<&VolumeMapper> = mappers.iter().collect();
        let am = ArchiveMap::resolve(&refs);
        assert_eq!(am.bases.get(&(0, 0)), Some(&0));
        assert_eq!(am.bases.get(&(1, 0)), Some(&100_000));
        assert_eq!(am.bases.get(&(2, 0)), Some(&200_000));
    }

    #[test]
    fn not_rar_rejected() {
        let mut m = VolumeMapper::new(1000);
        m.feed(0, b"PK\x03\x04 definitely a zip file padding padding");
        assert_eq!(m.blocker, Some(MapBlocker::NotRar));
    }

    // -- encrypted RAR5, validated against REAL `rar 7.23` archives
    //    (testdata/rar5/, password testpw123, payload secret.bin) --

    const PW: &str = "testpw123";
    const ENC_STORE: &[u8] = include_bytes!("../testdata/rar5/enc-store.rar");
    const ENC_HDRS: &[u8] = include_bytes!("../testdata/rar5/enc-hdrs.rar");
    const ENC_V1: &[u8] = include_bytes!("../testdata/rar5/enc-vols.part1.rar");
    const ENC_V2: &[u8] = include_bytes!("../testdata/rar5/enc-vols.part2.rar");
    const ENC_V3: &[u8] = include_bytes!("../testdata/rar5/enc-vols.part3.rar");
    const SECRET: &[u8] = include_bytes!("../testdata/rar5/secret.bin");

    // -- encrypted RAR4, from the vendored rars writer and validated with
    //    the reference decoder (`unrar t -ptestpw123`) before committing;
    //    see testdata/rar4/README.md. Same password, its own payload --

    const V4_ENC_STORE: &[u8] = include_bytes!("../testdata/rar4/enc-store.rar");
    const V4_ENC_HDRS: &[u8] = include_bytes!("../testdata/rar4/enc-hdrs.rar");
    const V4_ENC_V1: &[u8] = include_bytes!("../testdata/rar4/enc-vols.part1.rar");
    const V4_ENC_V2: &[u8] = include_bytes!("../testdata/rar4/enc-vols.part2.rar");
    const V4_ENC_V3: &[u8] = include_bytes!("../testdata/rar4/enc-vols.part3.rar");
    const V4_ENC_HV1: &[u8] = include_bytes!("../testdata/rar4/enc-hdr-vols.part1.rar");
    const V4_ENC_HV2: &[u8] = include_bytes!("../testdata/rar4/enc-hdr-vols.part2.rar");
    const V4_ENC_HV3: &[u8] = include_bytes!("../testdata/rar4/enc-hdr-vols.part3.rar");
    const V4_SECRET: &[u8] = include_bytes!("../testdata/rar4/secret.bin");

    fn mapper_with(pw: Option<&str>, vol: &[u8]) -> VolumeMapper {
        let mut m = VolumeMapper::with_password(
            vol.len() as u64,
            pw.map(std::sync::Arc::from),
        );
        m.feed(0, vol);
        m
    }

    #[test]
    fn real_encrypted_data_archive_maps_with_password() {
        let m = mapper_with(Some(PW), ENC_STORE);
        assert_eq!(m.blocker, None, "encrypted store must stay mappable");
        assert!(m.complete);
        assert_eq!(m.entries.len(), 1);
        let e = &m.entries[0];
        assert_eq!(e.name, "secret.bin");
        assert_eq!(e.method, Method::Store);
        assert!(e.encrypted);
        assert_eq!(e.unpacked_size, SECRET.len() as u64);
        // Ciphertext data area = align16(plaintext).
        assert_eq!(e.data_len, (SECRET.len() as u64 + 15) & !15);
        let c = e.crypt.as_ref().and_then(EntryCrypt::rar5).expect("crypt params parsed");
        assert_eq!(c.lg2_count, 15);
        assert!(c.check.is_some(), "real rar writes a check value");
    }

    #[test]
    fn real_encrypted_data_archive_without_password_blocks() {
        let m = mapper_with(None, ENC_STORE);
        assert_eq!(m.blocker, Some(MapBlocker::EncryptedNoPassword));
        // The entry is still recorded (needs_password relies on it).
        assert!(m.entries.iter().any(|e| e.encrypted));
    }

    #[test]
    fn real_encrypted_data_archive_wrong_password_rejected() {
        let m = mapper_with(Some("nottherightpw"), ENC_STORE);
        assert_eq!(m.blocker, Some(MapBlocker::BadPassword));
    }

    #[test]
    fn real_encrypted_headers_archive_parses_with_password() {
        let m = mapper_with(Some(PW), ENC_HDRS);
        assert_eq!(m.blocker, None, "headers must decrypt");
        assert!(m.complete);
        assert_eq!(m.entries.len(), 1);
        let e = &m.entries[0];
        assert_eq!(e.name, "secret.bin");
        assert!(e.encrypted && e.crypt.is_some());
        // Data must decrypt to the payload: one CBC stream from the
        // entry's IV over its data area.
        let keys = e.crypt.as_ref().unwrap().derive(PW).unwrap();
        let mut data =
            ENC_HDRS[e.data_off as usize..(e.data_off + e.data_len) as usize].to_vec();
        crate::rarcrypt::cbc_decrypt(&keys.aes, &keys.iv, &mut data);
        assert_eq!(&data[..SECRET.len()], SECRET);
    }

    #[test]
    fn real_encrypted_headers_wrong_or_missing_password() {
        let m = mapper_with(None, ENC_HDRS);
        assert_eq!(m.blocker, Some(MapBlocker::EncryptedHeaders));
        assert!(m.entries.is_empty());
        let m = mapper_with(Some("nope"), ENC_HDRS);
        assert_eq!(m.blocker, Some(MapBlocker::BadPassword));
    }

    /// Multi-volume: the crypt record (salt AND iv) repeats verbatim in
    /// every volume - one continuous CBC stream, arbitrary split points,
    /// total ciphertext = align16(unpacked). Everything the extractor's
    /// decrypt-at-finish design rests on, proven against real output.
    #[test]
    fn real_encrypted_volumes_are_one_cbc_stream() {
        let vols = [ENC_V1, ENC_V2, ENC_V3];
        let mut mappers = Vec::new();
        for v in vols {
            let m = mapper_with(Some(PW), v);
            assert_eq!(m.blocker, None);
            assert_eq!(m.entries.len(), 1);
            mappers.push(m);
        }
        let c0 = mappers[0].entries[0].crypt.clone().unwrap();
        let r0 = c0.rar5().unwrap();
        let mut cipher = Vec::new();
        for m in &mappers {
            let e = &m.entries[0];
            // The KEY MATERIAL repeats verbatim - that is what makes the
            // volumes one stream. The tweaked-checksum flag does NOT: real
            // rar sets it only on the piece that carries a checksum, so
            // comparing whole records here would false-fail.
            let c = e.crypt.as_ref().and_then(EntryCrypt::rar5).unwrap();
            assert_eq!((c.salt, c.iv), (r0.salt, r0.iv), "params repeat per volume");
            cipher.push((e.data_off, e.data_len));
        }
        // Split flags chain head → middle → tail.
        assert!(!mappers[0].entries[0].split_before && mappers[0].entries[0].split_after);
        assert!(mappers[1].entries[0].split_before && mappers[1].entries[0].split_after);
        assert!(mappers[2].entries[0].split_before && !mappers[2].entries[0].split_after);
        let mut stream = Vec::new();
        for (i, (off, len)) in cipher.iter().enumerate() {
            stream.extend_from_slice(&vols[i][*off as usize..(*off + *len) as usize]);
        }
        assert_eq!(stream.len() as u64, (SECRET.len() as u64 + 15) & !15);
        let keys = c0.derive(PW).unwrap();
        crate::rarcrypt::cbc_decrypt(&keys.aes, &keys.iv, &mut stream);
        assert_eq!(&stream[..SECRET.len()], SECRET, "reassembled stream decrypts");
    }

    // -- the same ladder for RAR4, against unrar-validated archives --

    /// `rar -m0 -p` RAR4: plaintext headers, AES-128 data. The entry must
    /// stay MAPPABLE (store-shaped, so the one-pass path owns it) and
    /// carry the salt the key schedule needs.
    #[test]
    fn real_v4_encrypted_data_archive_maps_with_password() {
        let m = mapper_with(Some(PW), V4_ENC_STORE);
        assert_eq!(m.blocker, None, "RAR4 encrypted store must stay mappable");
        assert!(m.complete);
        assert_eq!(m.entries.len(), 1);
        let e = &m.entries[0];
        assert_eq!(e.name, "inner.bin");
        assert_eq!(e.method, Method::Store);
        assert!(e.encrypted);
        assert_eq!(e.unpacked_size, V4_SECRET.len() as u64);
        // Ciphertext data area = align16(plaintext), same as RAR5.
        assert_eq!(e.data_len, (V4_SECRET.len() as u64 + 15) & !15);
        assert!(
            matches!(e.crypt, Some(EntryCrypt::Rar4(Rar4Crypt { salt: Some(_) }))),
            "RAR4 crypt params with the header salt, got {:?}",
            e.crypt
        );
        // The stored CRC is the PLAINTEXT's - the only thing that can
        // adjudicate the password once the finish pass has decrypted.
        assert_eq!(e.file_crc, Some(crc32fast::hash(V4_SECRET)));
        // …and the data really is one CBC stream from the derived IV.
        let keys = e.crypt.as_ref().unwrap().derive(PW).unwrap();
        let mut data =
            V4_ENC_STORE[e.data_off as usize..(e.data_off + e.data_len) as usize].to_vec();
        crate::rarcrypt::cbc_decrypt(&keys.aes, &keys.iv, &mut data);
        assert_eq!(&data[..V4_SECRET.len()], V4_SECRET);
    }

    /// No password: the same "keep the volumes, prompt for a key" verdict
    /// RAR5 gets, NOT the unrar-fallback NotStore this used to give.
    #[test]
    fn real_v4_encrypted_data_archive_without_password_blocks() {
        let m = mapper_with(None, V4_ENC_STORE);
        assert_eq!(m.blocker, Some(MapBlocker::EncryptedNoPassword));
        assert!(m.entries.iter().any(|e| e.encrypted));
    }

    /// RAR4 stores no password check, so a wrong password CANNOT be
    /// rejected here - the entry maps and the finish pass adjudicates it
    /// against the plaintext CRC. Mapping it is what keeps the assembled
    /// bytes identical to the posted volumes, so the demote costs nothing.
    #[test]
    fn real_v4_wrong_password_is_not_detectable_before_decrypting() {
        let m = mapper_with(Some("nottherightpw"), V4_ENC_STORE);
        assert_eq!(m.blocker, None);
        let e = &m.entries[0];
        let keys = e.crypt.as_ref().unwrap().derive("nottherightpw").unwrap();
        assert!(
            !e.crypt.as_ref().unwrap().check_verifies(&keys),
            "nothing in RAR4 may report a password as verified"
        );
        // Which is exactly why the CRC gate has to exist: the wrong key
        // produces plausible-looking bytes with a CRC that misses.
        let mut data =
            V4_ENC_STORE[e.data_off as usize..(e.data_off + e.data_len) as usize].to_vec();
        crate::rarcrypt::cbc_decrypt(&keys.aes, &keys.iv, &mut data);
        assert_ne!(crc32fast::hash(&data[..V4_SECRET.len()]), e.file_crc.unwrap());
    }

    /// `rar -m0 -hp` RAR4: every block past the plaintext main header is
    /// `8-byte salt + AES-128-CBC`, and the file DATA carries its own salt
    /// under the same password.
    #[test]
    fn real_v4_encrypted_headers_archive_parses_with_password() {
        let m = mapper_with(Some(PW), V4_ENC_HDRS);
        assert_eq!(m.blocker, None, "RAR4 headers must decrypt");
        assert!(m.complete);
        assert_eq!(m.entries.len(), 1);
        let e = &m.entries[0];
        assert_eq!(e.name, "inner.bin");
        assert!(e.encrypted && e.crypt.is_some());
        assert_eq!(e.method, Method::Store);
        let keys = e.crypt.as_ref().unwrap().derive(PW).unwrap();
        let mut data =
            V4_ENC_HDRS[e.data_off as usize..(e.data_off + e.data_len) as usize].to_vec();
        crate::rarcrypt::cbc_decrypt(&keys.aes, &keys.iv, &mut data);
        assert_eq!(&data[..V4_SECRET.len()], V4_SECRET);
    }

    /// Unlike `-p`, a RAR4 `-hp` set DOES catch a wrong password: the
    /// decrypted header's CRC16 misses. No password at all stays opaque.
    #[test]
    fn real_v4_encrypted_headers_wrong_or_missing_password() {
        let m = mapper_with(None, V4_ENC_HDRS);
        assert_eq!(m.blocker, Some(MapBlocker::EncryptedHeaders));
        assert!(m.entries.is_empty());
        let m = mapper_with(Some("nope"), V4_ENC_HDRS);
        assert_eq!(m.blocker, Some(MapBlocker::BadPassword));
        assert!(m.entries.is_empty(), "no garbage entry may survive");
    }

    /// The multi-volume fact the whole one-pass design rests on, for RAR4:
    /// the salt repeats verbatim in every volume, the pieces concatenate
    /// into ONE AES-128-CBC stream of align16(unpacked) bytes, and the
    /// WHOLE-FILE plaintext CRC rides the LAST piece only.
    #[test]
    fn real_v4_encrypted_volumes_are_one_cbc_stream() {
        for vols in [[V4_ENC_V1, V4_ENC_V2, V4_ENC_V3], [V4_ENC_HV1, V4_ENC_HV2, V4_ENC_HV3]] {
            let mappers: Vec<VolumeMapper> = vols
                .iter()
                .map(|v| {
                    let m = mapper_with(Some(PW), v);
                    assert_eq!(m.blocker, None);
                    assert_eq!(m.entries.len(), 1);
                    m
                })
                .collect();
            let c0 = mappers[0].entries[0].crypt.clone().unwrap();
            let mut cipher = Vec::new();
            for m in &mappers {
                let e = &m.entries[0];
                assert_eq!(e.crypt.as_ref(), Some(&c0), "one salt for the whole set");
                assert_eq!(e.unpacked_size, V4_SECRET.len() as u64);
                cipher.push((e.data_off, e.data_len));
            }
            assert!(!mappers[0].entries[0].split_before && mappers[0].entries[0].split_after);
            assert!(mappers[1].entries[0].split_before && mappers[1].entries[0].split_after);
            assert!(mappers[2].entries[0].split_before && !mappers[2].entries[0].split_after);
            // Only the tail's CRC describes the plaintext; the earlier
            // pieces' fields cover their own volume's packed bytes, which
            // is why the finish pass reads the tail's and not the head's.
            assert_eq!(mappers[2].entries[0].file_crc, Some(crc32fast::hash(V4_SECRET)));
            assert_ne!(mappers[0].entries[0].file_crc, Some(crc32fast::hash(V4_SECRET)));
            let mut stream = Vec::new();
            for (i, (off, len)) in cipher.iter().enumerate() {
                stream.extend_from_slice(&vols[i][*off as usize..(*off + *len) as usize]);
            }
            assert_eq!(stream.len() as u64, (V4_SECRET.len() as u64 + 15) & !15);
            let keys = c0.derive(PW).unwrap();
            crate::rarcrypt::cbc_decrypt(&keys.aes, &keys.iv, &mut stream);
            assert_eq!(&stream[..V4_SECRET.len()], V4_SECRET, "reassembled stream decrypts");
        }
    }

    /// Pre-3.0 RAR ciphers have no key schedule here, so those entries
    /// must keep routing to unrar rather than mapping with no `crypt`.
    #[test]
    fn v4_pre_30_encryption_still_falls_back() {
        let mut vol = V4_ENC_STORE.to_vec();
        // unp_ver lives at header start + 25 (7 sig + 20-byte prologue is
        // the main header; the file header starts at 20).
        let unp_ver = 20 + 24;
        assert_eq!(vol[unp_ver], 29, "fixture layout moved");
        vol[unp_ver] = 20; // RAR 2.0
        let m = mapper_with(Some(PW), &vol);
        assert_eq!(m.blocker, Some(MapBlocker::NotStore));
        let e = &m.entries[0];
        assert!(e.encrypted && e.crypt.is_none());
        assert!(e.file_crc.is_none(), "an undecryptable entry vouches for nothing");
    }

    /// The RAR4 encrypted fixture writer must produce what the real
    /// archives above do: mappable store entries, one CBC stream across
    /// the split, the plaintext CRC on the tail, and `-hp` headers this
    /// parser reads with the password and rejects without it. The e2e
    /// suite posts these, so a drift here would test a shape no archiver
    /// emits.
    #[test]
    fn fixture_writer_v4_encrypted_matches_parser() {
        let plain = payload(40_001, 11);
        let f = fixtures::encrypt_file_v4("pw4!", &plain, 21);
        assert_eq!(f.cipher.len() as u64, (plain.len() as u64 + 15) & !15);
        let (a, n) = (17_003, f.cipher.len());
        let split: [(&str, _, std::ops::Range<usize>, bool, bool); 2] =
            [("a.bin", &f, 0..a, false, true), ("a.bin", &f, a..n, true, false)];
        for headers_encrypted in [false, true] {
            let vols: Vec<Vec<u8>> = split
                .iter()
                .map(|p| {
                    let one = [p.clone()];
                    if headers_encrypted {
                        fixtures::rar4_volume_enc_headers(&one, "pw4!", 3)
                    } else {
                        fixtures::rar4_volume_enc(&one)
                    }
                })
                .collect();
            let mut stream = Vec::new();
            let mut crypt = None;
            for (i, v) in vols.iter().enumerate() {
                let m = mapper_with(Some("pw4!"), v);
                assert_eq!(m.blocker, None, "hp={headers_encrypted} vol={i}");
                assert!(m.complete);
                let e = &m.entries[0];
                assert_eq!(e.method, Method::Store);
                assert!(e.encrypted);
                assert_eq!(e.unpacked_size, plain.len() as u64);
                assert_eq!(e.split_before, i == 1);
                assert_eq!(e.split_after, i == 0);
                let c = e.crypt.clone().unwrap();
                assert_eq!(crypt.get_or_insert(c.clone()), &c, "one salt per set");
                stream.extend_from_slice(
                    &v[e.data_off as usize..(e.data_off + e.data_len) as usize],
                );
                // Only the tail vouches for the plaintext.
                assert_eq!(e.file_crc == Some(f.crc), i == 1);
            }
            let keys = crypt.unwrap().derive("pw4!").unwrap();
            crate::rarcrypt::cbc_decrypt(&keys.aes, &keys.iv, &mut stream);
            assert_eq!(&stream[..plain.len()], &plain[..]);
            if headers_encrypted {
                assert_eq!(
                    mapper_with(None, &vols[0]).blocker,
                    Some(MapBlocker::EncryptedHeaders)
                );
                assert_eq!(
                    mapper_with(Some("wrong"), &vols[0]).blocker,
                    Some(MapBlocker::BadPassword)
                );
            }
        }
    }

    /// Our encrypted fixture writer must round-trip through the parser
    /// exactly like real rar output does (the e2e suite leans on it).
    #[test]
    fn fixture_writer_encrypted_matches_parser() {
        let plain = payload(50_001, 3);
        let f = fixtures::encrypt_file("pw!", &plain, 9);
        assert_eq!(f.cipher.len() as u64, (plain.len() as u64 + 15) & !15);
        let vol = fixtures::rar5_volume_enc(&[("a.bin", &f, 0..f.cipher.len(), false, false)], None);
        let m = mapper_with(Some("pw!"), &vol);
        assert_eq!(m.blocker, None);
        let e = &m.entries[0];
        assert_eq!(e.crypt.as_ref().and_then(EntryCrypt::rar5).unwrap().salt, f.salt);
        // And header-encrypted wrapping parses too.
        let hv = fixtures::rar5_volume_enc_headers(
            &[("a.bin", &f, 0..f.cipher.len(), false, false)],
            None,
            "pw!",
            7,
        );
        let m = mapper_with(Some("pw!"), &hv);
        assert_eq!(m.blocker, None, "encrypted headers from fixture writer");
        assert_eq!(m.entries.len(), 1);
        assert!(m.complete);
        let m = mapper_with(Some("wrong"), &hv);
        assert_eq!(m.blocker, Some(MapBlocker::BadPassword));
    }

    /// The no-password check-value probe: harvest crypt params off an
    /// on-disk archive and rule a candidate in or out without decrypting.
    /// Volume 0's main header carries no volume-number field, so the SAME
    /// pieces produce a file exactly one byte shorter at `vol_no` 0 than at
    /// 1. Pinned here, where the asymmetry originates, because every
    /// multi-volume fixture in the workspace has to compensate for it and
    /// each one was re-deriving it by hand - or, more often, not.
    ///
    /// A store set is "uniform" when the volume FILES are the same size, so
    /// a fixture that splits its payload into equal pieces is NOT uniform:
    /// volume 0 comes out a byte short. That matters because the extractor's
    /// arithmetic gate speculates bases under a uniform premise and demotes
    /// the group when headers contradict it - which made
    /// `nested_inner_par2_repairs_data_damaged_store_layer` a race between
    /// two correct demotion reasons, passing under load and failing on a
    /// slower runner (it reproduced 8 times in 30 on macOS). A fixture that
    /// wants a uniform set gives volume 0 one byte MORE data; one that wants
    /// a non-uniform set can keep equal pieces, which is a legitimate shape
    /// real posters produce.
    ///
    /// If this test fails, the helper's header layout moved and every
    /// multi-volume fixture's geometry needs re-checking.
    #[test]
    fn volume_zero_header_is_one_byte_shorter_than_the_rest() {
        let body = vec![b'x'; 4096];
        let piece = |crc: Option<u32>| {
            vec![("v.bin", 8192u64, &body[..], false, true, crc)]
        };
        let v0 = fixtures::rar5_volume_n_crc(&piece(Some(1)), 0);
        let v1 = fixtures::rar5_volume_n_crc(&piece(Some(1)), 1);
        assert_eq!(
            v1.len(),
            v0.len() + 1,
            "vol 0 must be exactly one byte shorter for the same pieces \
             (got {} at vol 0, {} at vol 1) - every multi-volume fixture's \
             uniformity depends on this",
            v0.len(),
            v1.len()
        );
        // ...so equal pieces are NOT a uniform set, and one extra byte in
        // volume 0 IS - the two facts fixtures actually need.
        let mut long = body.clone();
        long.push(b'x');
        let v0_plus =
            fixtures::rar5_volume_n_crc(&[("v.bin", 8192, &long[..], false, true, Some(1))], 0);
        assert_eq!(v0_plus.len(), v1.len(), "one extra data byte in vol 0 evens the files up");
    }

    #[test]
    fn crypt_probe_verifies_without_decrypt() {
        let dir = std::env::temp_dir().join(format!("nzbkit-cryptprobe-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let write = |name: &str, bytes: &[u8]| {
            let p = dir.join(name);
            std::fs::write(&p, bytes).unwrap();
            p
        };

        // Data-encrypted set: probe reads the first entry's crypt record.
        let f = fixtures::encrypt_file("open-sesame", b"secret payload bytes", 9);
        let vol = fixtures::rar5_volume_enc(&[("s.bin", &f, 0..f.cipher.len(), false, false)], None);
        let probe = crypt_probe(&write("data.rar", &vol)).expect("encrypted set yields a probe");
        assert_eq!(probe.verify("open-sesame"), PwVerdict::Verified);
        assert_eq!(probe.verify("wrong-one"), PwVerdict::Rejected);

        // Header-encrypted set: probe reads the type-4 block before it
        // blocks (no password given to the probe).
        let hv = fixtures::rar5_volume_enc_headers(
            &[("s.bin", &f, 0..f.cipher.len(), false, false)],
            None,
            "hp-secret",
            7,
        );
        let hprobe = crypt_probe(&write("hdr.rar", &hv)).expect("header-crypt yields a probe");
        assert_eq!(hprobe.verify("hp-secret"), PwVerdict::Verified);
        assert_eq!(hprobe.verify("nope"), PwVerdict::Rejected);

        // Check-less set: no stored check to veto with -> Indeterminate,
        // and the auto-unlock path leaves it to a real extraction attempt.
        let mut g = fixtures::encrypt_file("k", b"data here", 4);
        g.no_check = true;
        let g2 = fixtures::rar5_volume_enc(&[("x", &g, 0..g.cipher.len(), false, false)], None);
        let cl = crypt_probe(&write("nocheck.rar", &g2)).expect("still a probe");
        assert_eq!(cl.check, None);
        assert_eq!(cl.verify("k"), PwVerdict::Indeterminate);

        // A plaintext store archive is not probeable at all.
        let plain = fixtures::rar5_volume_n(&[("a.bin", 4, b"data", false, false)], 0);
        assert!(crypt_probe(&write("plain.rar", &plain)).is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }
}

//! Store-mode direct extraction (design: M3): decoded article spans are
//! written straight into the *extracted* files; RAR volumes never touch
//! disk on the happy path.
//!
//! The extractor owns all data-file writing in `get`:
//! - A slot is sniffed at its offset-0 article: RAR signature → mapping
//!   mode; anything else → plain mode (ordinary file, exactly the old
//!   behavior). Pre-sniff spans are held in memory (bounded).
//! - Mapping mode feeds the volume's [`VolumeMapper`]; spans intersecting
//!   known data areas `pwrite` into the inner file at
//!   `piece_base + offset_in_piece`; spans beyond the parsed region are
//!   held until more headers arrive.
//! - Volumes group by their FIRST inner-file name - obfuscation-proof
//!   (subjects lie, archive contents don't). Order within a group comes
//!   from RAR5 volume numbers, falling back to natural name sort
//!   (.partNN.rar, .rar < .r00 < .r01).
//! - Non-split pieces extract immediately (base 0); split continuations
//!   wait for every earlier volume's piece length (base resolution).
//! - Any blocker (compressed, encrypted, corrupt, holds cap) falls the
//!   whole group back to materialized volumes - already-extracted bytes
//!   are reconstructed into the volume files via the map, so nothing is
//!   lost and PAR2 repair sees ordinary files.
//! - [`Extractor::read_at`] serves byte-exact volume reads for the live
//!   verifier's read-back path (header stash + inner-file pread), so
//!   in-stream PAR2 verification of the *volume* blocks works even though
//!   volumes were never written.
//! - Nested store archives (a store-mode RAR whose payload is itself a
//!   store-mode RAR) route through a lazily-created CHILD extractor: each
//!   level-1 inner file becomes a dynamically-allocated child slot, and
//!   the child's own offset-0 sniff classifies it - RAR store magic means
//!   nested mapping (the inner archive never touches disk either), while
//!   anything else goes Plain (a real file, byte-identical to the
//!   single-level output). Read-back and coverage compose by delegation,
//!   so verifier settle, mapped repair, and fallback materialization keep
//!   working unchanged. Depth-capped; any blocker at a nested level
//!   demotes that level to a materialized file, never a failure.
//! - COMPRESSED RAR5 nested archives decompress while their bytes arrive
//!   (the chasing decompressor): the chased slot's spans feed a frontier
//!   buffer, a worker drives the RAR engine's streaming reader over the
//!   group's volumes in order, and extracted members route back through
//!   the same child seam - so store archives below a compressed layer
//!   still stream. Any chase failure demotes to the materialize path.
//! - 7z nested archives extract in-stream via tail prefetch: a child slot
//!   sniffing 7z magic parses the 32-byte start header, asks the promote
//!   hook to front-load the articles carrying the end header (the archive
//!   map lives at the tail), and a worker drives the 7z engine through a
//!   blocking Read+Seek view of the arriving bytes - entries stream into
//!   fresh child slots (the same routing seam). Header-encrypted without
//!   a password, unsupported codecs, budget breach, and missing bytes all
//!   demote to a materialized .7z for the disk post-pass.

use std::collections::{BTreeMap, HashMap};
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, Weak};

use crate::disk::{FileWriter, sanitize_filename};
use crate::rar::{ArchiveMap, EntryCrypt, MapBlocker, Method, RarVersion, VolumeMapper};
use crate::rarcrypt;

// ---------------------------------------------------------------------------
// Encrypted-store streaming: decrypt on the fly while the file is still
// ciphertext, and flip to raw reads once finish() has decrypted it.
// ---------------------------------------------------------------------------

/// Lifecycle of one encrypted output file, shared between the finish()
/// decrypt pass and any live /stream readers.
#[derive(Clone, Copy, PartialEq, Eq)]
enum DecState {
    /// On-disk bytes are AES-256-CBC ciphertext (during/after download,
    /// before the finish decrypt) - readers decrypt on the fly.
    Ciphertext,
    /// A plaintext file has been renamed over the name - readers read raw.
    ///
    /// There is deliberately no third "being decrypted right now" state:
    /// the finish decrypt always writes to its own scratch file and
    /// publishes by rename, so the ciphertext inode is whole and readable
    /// for the entire pass and a reader never has to wait one out.
    Decrypted,
}

struct StreamState {
    state: Mutex<DecState>,
    /// Live on-the-fly-decrypting readers. Their fds stay on the
    /// ciphertext inode across the finish decrypt's publish rename, so
    /// they keep serving correct bytes until the last one drops.
    readers: AtomicUsize,
}

/// Random-access CBC decryptor handed to a /stream reader for an
/// encrypted output file. Holds a live-reader lease (released on drop);
/// while it exists, finish() will temp+rename rather than decrypt the
/// file in place, so the reader's captured fd stays valid.
pub struct StreamCrypt {
    key: [u8; 32],
    iv: [u8; 16],
    /// On-disk ciphertext length = align16(plain_len).
    pub cipher_len: u64,
    /// Plaintext length the reader exposes (Content-Length).
    pub plain_len: u64,
    st: Arc<StreamState>,
}

impl Drop for StreamCrypt {
    fn drop(&mut self) {
        self.st.readers.fetch_sub(1, Ordering::Relaxed);
    }
}

impl StreamCrypt {
    /// The ciphertext byte range that must be on disk to decrypt
    /// plaintext `[pos, pos+n)` - includes the preceding cipher block
    /// (the CBC IV for the first plaintext block, unless at offset 0).
    pub fn covered_bounds(&self, pos: u64, n: u64) -> (u64, u64) {
        let s0 = pos & !15;
        let lo = if s0 == 0 { 0 } else { s0 - 16 };
        let hi = rarcrypt::align16(pos + n).min(self.cipher_len);
        (lo, hi.saturating_sub(lo))
    }

    /// Decrypt plaintext `[pos, pos+out.len())` from the open ciphertext
    /// file. Reads the covering cipher blocks (plus the IV block) itself.
    pub fn decrypt_range(&self, f: &std::fs::File, pos: u64, out: &mut [u8]) -> io::Result<()> {
        use crate::disk::read_exact_at;
        let end = pos + out.len() as u64;
        let s0 = pos & !15;
        let e1 = rarcrypt::align16(end).min(self.cipher_len);
        let iv;
        let mut cipher = vec![0u8; (e1 - s0) as usize];
        if s0 == 0 {
            iv = self.iv;
            read_exact_at(f, &mut cipher, 0)?;
        } else {
            // IV block + range in one pread (contiguous on disk).
            let mut buf = vec![0u8; (e1 - (s0 - 16)) as usize];
            read_exact_at(f, &mut buf, s0 - 16)?;
            iv = buf[..16].try_into().unwrap();
            cipher.copy_from_slice(&buf[16..]);
        }
        rarcrypt::cbc_decrypt(&self.key, &iv, &mut cipher);
        let a = (pos - s0) as usize;
        out.copy_from_slice(&cipher[a..a + out.len()]);
        Ok(())
    }
}

/// Result of [`Extractor::open_stream`].
pub enum StreamOpen {
    /// Not an encrypted output (or already decrypted) - the caller opens
    /// and serves the file raw, exactly as before.
    Plain,
    /// Encrypted output still on disk as ciphertext: serve via `crypt`
    /// over the pre-opened (lock-consistent) `file`.
    Encrypted(std::fs::File, StreamCrypt),
}

// ---------------------------------------------------------------------------
// Plaintext-once (in-stream decrypt): encrypted store entries decrypt at
// article-write time and the ciphertext never touches disk. 1x disk, no
// finish pass, no temp/barrier - see research/encrypted-store-plaintext-
// once-scope-2026-07-26.md. The legacy path (ciphertext at store offsets
// + decrypt_finished) remains selectable via NZBFAST_NO_INSTREAM_DECRYPT.
//
// Every consumer of posted bytes is served without ciphertext on disk
// because CBC is invertible per block: the plaintext on disk is always
// D(wire cipher) - even for wire-DAMAGED regions - so re-encrypting it
// reproduces the posted bytes exactly, damage included. Chain state is
// one 16-byte cipher block, so periodic checkpoints captured from the
// wire make re-encryption seekable.
// ---------------------------------------------------------------------------

/// Chain-checkpoint stride for in-stream decrypted files (multiple of
/// 16). One 16-byte cipher block is kept per stride, bounding the
/// posted-bytes shim's worst-case re-encrypt walk; ~1 MB of checkpoints
/// per 60 GB file.
const CRYPTO_CHUNK: u64 = 1 << 20;

/// Journal-bound facts about an in-stream decrypted file, drained by the
/// caller (`drain_crypto_events`) and written as `E`/`K`/`T` journal
/// lines. Together with the `D` placement records they let a resume run
/// RE-ENCRYPT the on-disk plaintext back into posted volume bytes
/// instead of refetching (phase 2 of plaintext-once): `Params` carries
/// the KDF inputs and IV, `Checkpoint` a chain block per stride so the
/// rebuild can restart across coverage holes, and `TailPad` the final
/// block's beyond-`unp` plaintext without which the last block cannot
/// re-encrypt byte-exactly.
pub enum CryptoJournalEvent {
    Params {
        name: String,
        salt: [u8; 16],
        lg2: u8,
        iv: [u8; 16],
        unp: u64,
        /// Stored password check (8-byte value + 4-byte csum): lets a
        /// resume PROVE the password before re-encrypting anything - a
        /// wrong key would otherwise rebuild garbage posted bytes.
        check: Option<[u8; 12]>,
    },
    Checkpoint {
        name: String,
        off: u64,
        block: [u8; 16],
    },
    TailPad {
        name: String,
        pad: Vec<u8>,
    },
}

/// Event sink shared by every [`CryptoState`] of an extractor chain
/// (children inherit it like the holds budget, so nested encrypted
/// outputs journal through the same drain).
type CryptoEventSink = Arc<Mutex<Vec<CryptoJournalEvent>>>;

/// One encrypted store output being decrypted in-stream. Owned by the
/// level's `Inner` (keyed by output name), shared into `WriteJob`s so
/// the AES work runs outside the routing lock under this state's own
/// per-file mutex.
struct CryptoState {
    key: [u8; 32],
    iv: [u8; 16],
    /// Plaintext length (the head entry's `unpacked_size`).
    unp: u64,
    /// Posted ciphertext length = align16(unp).
    cipher_len: u64,
    /// Stored plaintext CRC32 when checkable (single-piece entry with an
    /// untweaked checksum); verified at finish from the composed runs.
    expect_crc: Option<u32>,
    /// Output name + shared sink for the resume-journal events.
    out_name: String,
    events: CryptoEventSink,
    st: Mutex<CryptoSt>,
}

#[derive(Default)]
struct CryptoSt {
    /// Contiguous ciphertext runs received, keyed by cipher start.
    /// Cipher offsets equal output-file offsets (store mapping), so one
    /// coordinate space serves both views.
    runs: BTreeMap<u64, CryptoRun>,
    /// Chunk boundary c -> cipher block [c-16, c), captured from the
    /// wire as spans stream past. Pure posted bytes; repair refreshes
    /// any it overwrites.
    checkpoints: HashMap<u64, [u8; 16]>,
    /// Plaintext CRC composition (maintained only when expect_crc is
    /// set - otherwise it would be a pure extra pass).
    plain: CrcRuns,
    /// Plaintext of the final cipher block beyond `unp` (the <=15
    /// padding bytes). Never written to disk; required to re-encrypt
    /// the last block byte-exactly.
    tail_pad: Vec<u8>,
    tail_done: bool,
}

/// One contiguous ciphertext run. Plaintext has been written for
/// [p_lo, p_hi) (clipped to `unp` on disk). The run retains only the
/// cipher slivers the seams need:
/// - `head` = cipher [start, p_lo): undecryptable until the predecessor
///   arrives (its last 16 bytes are the chain anchor into p_lo). Empty
///   iff start == 0. For a run too small to decrypt anything
///   (p_lo == p_hi == start), `head` holds the ENTIRE run's cipher.
/// - `tail` = cipher [p_hi - 16, end): the chain block into the tail
///   plus the partial tail block, for extension and the right seam.
///   Empty when nothing is decrypted (head carries everything).
struct CryptoRun {
    end: u64,
    p_lo: u64,
    p_hi: u64,
    head: Vec<u8>,
    tail: Vec<u8>,
}

impl CryptoRun {
    fn decrypted(&self) -> bool {
        self.p_hi > self.p_lo || (self.p_lo == 0 && self.p_hi == 0 && self.head.is_empty())
    }
}

impl CryptoState {
    fn new(
        key: [u8; 32],
        iv: [u8; 16],
        unp: u64,
        expect_crc: Option<u32>,
        out_name: String,
        events: CryptoEventSink,
    ) -> CryptoState {
        CryptoState {
            key,
            iv,
            unp,
            cipher_len: rarcrypt::align16(unp),
            expect_crc,
            out_name,
            events,
            st: Mutex::new(CryptoSt::default()),
        }
    }

    /// Decrypt the full blocks of `cipher` (absolute cipher offset `at`,
    /// 16-aligned), chained from `chain` (= cipher block [at-16, at), or
    /// the IV at offset 0). Writes the plaintext (clipped to unp; final-
    /// block padding goes to tail_pad), extends the CRC runs, captures
    /// checkpoints. Returns the decrypted byte count (a multiple of 16)
    /// - the caller keeps the partial remainder as tail cipher.
    fn advance(
        &self,
        st: &mut CryptoSt,
        w: &FileWriter,
        chain: [u8; 16],
        at: u64,
        cipher: &[u8],
        overwrite_crc: bool,
    ) -> io::Result<u64> {
        debug_assert_eq!(at % 16, 0);
        let full = cipher.len() - cipher.len() % 16;
        if full == 0 {
            return Ok(0);
        }
        // Journal a chain anchor for THIS decrypt boundary: every
        // decrypted region then begins at a journaled K, which is what
        // lets a resume's re-encrypt walk stay inside known-good
        // plaintext instead of marching through a coverage hole.
        self.events.lock().unwrap().push(CryptoJournalEvent::Checkpoint {
            name: self.out_name.clone(),
            off: at,
            block: chain,
        });
        // Checkpoints come from the ciphertext itself, before decrypt-in-
        // place destroys it.
        let mut c = at.next_multiple_of(CRYPTO_CHUNK).max(CRYPTO_CHUNK);
        while c <= at + full as u64 {
            // At an exact CRYPTO_CHUNK boundary the checkpoint's previous
            // block is the caller-supplied chain. `c - 16 - at` used to
            // underflow before its cast to i64 in overflow-checked builds.
            let block: [u8; 16] = match c.checked_sub(16).and_then(|p| p.checked_sub(at)) {
                Some(s) => cipher[s as usize..s as usize + 16].try_into().unwrap(),
                None => chain,
            };
            st.checkpoints.insert(c, block);
            self.events.lock().unwrap().push(CryptoJournalEvent::Checkpoint {
                name: self.out_name.clone(),
                off: c,
                block,
            });
            c += CRYPTO_CHUNK;
        }
        let mut buf = cipher[..full].to_vec();
        rarcrypt::CbcStream::new(&self.key, &chain).decrypt(&mut buf);
        // Clip the on-disk write (and the CRC) to the plaintext length;
        // the padding beyond unp only ever lives in tail_pad.
        let plain_end = (at + full as u64).min(self.unp);
        if plain_end > at {
            let n = (plain_end - at) as usize;
            w.write_at(at, &buf[..n])?;
            if self.expect_crc.is_some() {
                if overwrite_crc {
                    st.plain.overwrite(at, &buf[..n]);
                } else {
                    st.plain.add(at, &buf[..n]);
                }
            }
        }
        if at + full as u64 == self.cipher_len {
            st.tail_pad = buf[(self.unp - at) as usize..].to_vec();
            st.tail_done = true;
            self.events.lock().unwrap().push(CryptoJournalEvent::TailPad {
                name: self.out_name.clone(),
                pad: st.tail_pad.clone(),
            });
        }
        Ok(full as u64)
    }

    /// Build a standalone run for novel cipher `[at, at+cipher.len())`,
    /// decrypting whatever its own bytes allow. Neighbor seams are the
    /// caller's job (`merge_at`).
    fn fresh_run(
        &self,
        st: &mut CryptoSt,
        w: &FileWriter,
        at: u64,
        cipher: &[u8],
    ) -> io::Result<CryptoRun> {
        let end = at + cipher.len() as u64;
        if at == 0 {
            let done = self.advance(st, w, self.iv, 0, cipher, false)?;
            return Ok(if done == 0 {
                CryptoRun { end, p_lo: 0, p_hi: 0, head: cipher.to_vec(), tail: Vec::new() }
            } else {
                CryptoRun {
                    end,
                    p_lo: 0,
                    p_hi: done,
                    head: Vec::new(),
                    tail: cipher[(done - 16) as usize..].to_vec(),
                }
            });
        }
        // First decryptable block needs its full predecessor block, so
        // it starts one block past the first aligned boundary in-range.
        let p_lo = at.next_multiple_of(16) + 16;
        let decryptable = end.min(self.cipher_len).saturating_sub(p_lo);
        if decryptable < 16 {
            return Ok(CryptoRun {
                end,
                p_lo: at,
                p_hi: at,
                head: cipher.to_vec(),
                tail: Vec::new(),
            });
        }
        let chain: [u8; 16] =
            cipher[(p_lo - 16 - at) as usize..(p_lo - at) as usize].try_into().unwrap();
        let done = self.advance(st, w, chain, p_lo, &cipher[(p_lo - at) as usize..], false)?;
        Ok(if done == 0 {
            CryptoRun { end, p_lo: at, p_hi: at, head: cipher.to_vec(), tail: Vec::new() }
        } else {
            CryptoRun {
                end,
                p_lo,
                p_hi: p_lo + done,
                head: cipher[..(p_lo - at) as usize].to_vec(),
                tail: cipher[(p_lo + done - 16 - at) as usize..].to_vec(),
            }
        })
    }

    /// Merge the run ending at `mid` with the run starting at `mid`,
    /// decrypting the seam between their plaintext regions from the
    /// retained cipher slivers. No-op unless both exist.
    fn merge_at(&self, st: &mut CryptoSt, w: &FileWriter, mid: u64) -> io::Result<()> {
        let Some((&ls, _)) = st.runs.range(..mid).next_back() else { return Ok(()) };
        let l_end = st.runs[&ls].end;
        if l_end != mid || !st.runs.contains_key(&mid) {
            return Ok(());
        }
        let left = st.runs.remove(&ls).unwrap();
        let right = st.runs.remove(&mid).unwrap();
        let left_dec = left.p_hi > left.p_lo;
        let merged = if left_dec || ls == 0 {
            // Left can chain forward: from its tail's chain block, or
            // from the IV when it is the (still undecrypted) offset-0
            // run. `glue` = contiguous cipher from the chain point to the
            // end of right's retained bytes (right's whole run when
            // undecrypted, its head seam otherwise).
            let (chain, at, mut glue): ([u8; 16], u64, Vec<u8>) = if left_dec {
                (left.tail[..16].try_into().unwrap(), left.p_hi, left.tail[16..].to_vec())
            } else {
                (self.iv, 0, left.head.clone())
            };
            glue.extend_from_slice(&right.head);
            let done = self.advance(st, w, chain, at, &glue, false)?;
            let p_hi = at + done;
            if right.decrypted() {
                debug_assert_eq!(p_hi, right.p_lo, "seam must land on right's plaintext");
                CryptoRun {
                    end: right.end,
                    p_lo: if left_dec { left.p_lo } else { 0 },
                    p_hi: right.p_hi,
                    head: left.head,
                    tail: right.tail,
                }
            } else if p_hi > at || left_dec {
                // Right was head-only cipher; we decrypted into it. Keep
                // the chain block + remainder as the new tail:
                // glue currently spans [at - chain_len, right.end) where
                // chain_len is 16 for a decrypted left (tail carried it)
                // and 0 for the IV case - normalize via glue_start.
                let glue_start = if left_dec { at - 16 } else { 0 };
                let p_hi = p_hi.max(if left_dec { left.p_hi } else { 0 });
                let (head, tail) = if p_hi > 0 {
                    let mut full = if left_dec {
                        let mut v = left.tail[..16].to_vec();
                        v.extend_from_slice(&glue);
                        v
                    } else {
                        glue
                    };
                    let ts = (p_hi - 16 - glue_start) as usize;
                    full.drain(..ts);
                    (left.head, full)
                } else {
                    // ls == 0 and still nothing decrypted (< one block
                    // total): stay head-only.
                    (glue, Vec::new())
                };
                CryptoRun {
                    end: right.end,
                    p_lo: if left_dec { left.p_lo } else { 0 },
                    p_hi,
                    head,
                    tail,
                }
            } else {
                CryptoRun {
                    end: right.end,
                    p_lo: 0,
                    p_hi: 0,
                    head: glue,
                    tail: Vec::new(),
                }
            }
        } else {
            // Left is a head-only sliver at start > 0: all of its bytes
            // are cipher. Right decrypted: only the seam
            // [p_lo_new, right.p_lo) is missing, and the concatenated
            // slivers cover it. Right undecrypted: full cipher for both
            // is in hand - rebuild as one fresh run.
            let mut combined = left.head.clone();
            combined.extend_from_slice(&right.head);
            if right.decrypted() {
                let p_lo_new = (ls.next_multiple_of(16) + 16).min(right.p_lo);
                if p_lo_new < right.p_lo {
                    let chain: [u8; 16] = combined
                        [(p_lo_new - 16 - ls) as usize..(p_lo_new - ls) as usize]
                        .try_into()
                        .unwrap();
                    let done = self.advance(
                        st,
                        w,
                        chain,
                        p_lo_new,
                        &combined[(p_lo_new - ls) as usize..],
                        false,
                    )?;
                    debug_assert_eq!(p_lo_new + done, right.p_lo);
                    CryptoRun {
                        end: right.end,
                        p_lo: p_lo_new,
                        p_hi: right.p_hi,
                        head: combined[..(p_lo_new - ls) as usize].to_vec(),
                        tail: right.tail,
                    }
                } else {
                    CryptoRun {
                        end: right.end,
                        p_lo: right.p_lo,
                        p_hi: right.p_hi,
                        head: combined,
                        tail: right.tail,
                    }
                }
            } else {
                self.fresh_run(st, w, ls, &combined)?
            }
        };
        st.runs.insert(ls, merged);
        Ok(())
    }

    /// Ingest posted cipher for `[at, at+data.len())` - the in-stream
    /// write path. Duplicate/overlapping re-feeds clip to novel
    /// sub-ranges (posted bytes for a range never change outside repair,
    /// which goes through `patch`).
    fn ingest(&self, w: &FileWriter, at: u64, data: &[u8]) -> io::Result<()> {
        let mut st = self.st.lock().unwrap();
        let st = &mut *st;
        let end = at + data.len() as u64;
        // Novel sub-ranges vs existing runs.
        let mut novel: Vec<(u64, u64)> = Vec::new();
        let mut cur = at;
        for (&s, r) in st.runs.range(..end) {
            let e = r.end;
            if e <= cur {
                continue;
            }
            if s > cur {
                novel.push((cur, s.min(end)));
            }
            cur = cur.max(e);
            if cur >= end {
                break;
            }
        }
        if cur < end {
            novel.push((cur, end));
        }
        for (s, e) in novel {
            let run = self.fresh_run(st, w, s, &data[(s - at) as usize..(e - at) as usize])?;
            st.runs.insert(s, run);
            self.merge_at(st, w, s)?;
            self.merge_at(st, w, e)?;
        }
        Ok(())
    }

    /// Whether the PLAINTEXT for cipher range `[at, at+len)` is fully on
    /// disk (decrypted regions; the final block counts once its padding
    /// is captured, since the `T` record carries it for a resume). This
    /// gates the `D` journal record: a span whose seam slivers are still
    /// RAM-held must not journal - a kill would lose them, and a resume
    /// re-encrypting the zero-filled hole would write garbage posted
    /// bytes for an article the journal claims is restored.
    fn plain_on_disk(&self, at: u64, len: u64) -> bool {
        if len == 0 {
            return true;
        }
        let st = self.st.lock().unwrap();
        let end = at + len;
        if end > self.cipher_len {
            return false;
        }
        let mut cur = at;
        for (_, r) in st.runs.range(..end) {
            if r.p_hi <= cur || r.p_lo > cur {
                continue;
            }
            cur = r.p_hi;
            if cur >= end {
                return true;
            }
        }
        cur >= end
    }

    /// Whether every posted byte of `[at, at+len)` has arrived.
    fn covers(&self, at: u64, len: u64) -> bool {
        if len == 0 {
            return true;
        }
        let st = self.st.lock().unwrap();
        let end = at + len;
        let mut cur = at;
        for (&s, r) in st.runs.range(..end) {
            if r.end <= cur {
                continue;
            }
            if s > cur {
                return false;
            }
            cur = r.end;
            if cur >= end {
                return true;
            }
        }
        cur >= end
    }

    /// [`Self::available`] clipped to `[at, at+len)` - the coverage
    /// answer for verification read-back, in POSTED-byte terms.
    fn intervals(&self, at: u64, len: u64) -> Vec<(u64, u64)> {
        let st = self.st.lock().unwrap();
        let end = at + len;
        let mut out = Vec::new();
        for (&s, r) in st.runs.range(..end) {
            let a = at.max(s);
            let b = end.min(r.end);
            if a < b {
                out.push((a, b));
            }
        }
        out
    }

    /// Whether every posted byte `[0, cipher_len)` has arrived and been
    /// decrypted into one seamless run.
    fn complete(&self) -> bool {
        let st = self.st.lock().unwrap();
        st.runs.len() == 1
            && st
                .runs
                .get(&0)
                .is_some_and(|r| r.end == self.cipher_len && r.p_hi == self.cipher_len)
            && (st.tail_done || self.unp == self.cipher_len)
    }

    /// Finish-time plaintext CRC verdict: Some(true)=verified,
    /// Some(false)=MISMATCH, None=nothing checkable (no stored CRC, or
    /// the file is not complete).
    fn crc_verdict(&self) -> Option<bool> {
        let expected = self.expect_crc?;
        let st = self.st.lock().unwrap();
        let got = st.plain.whole(self.unp)?;
        Some(got == expected)
    }

    /// Repair rewrite of posted cipher `[at, at+data.len())` (mapped
    /// PAR2, via patch_volume_span). Never-seen sub-ranges are ordinary
    /// posted bytes and ingest normally; sub-ranges already decrypted
    /// rewrite coherently: CBC locality means patching cipher block X
    /// changes plaintext at X and X+16 only, so the rewrite re-decrypts
    /// the patched blocks plus the one following block, refreshes the
    /// checkpoints and stash slivers the patch overlaps, and overwrites
    /// the CRC runs (the stale-CRC-across-repair problem CrcRuns solves
    /// for the outer volumes).
    fn patch(&self, w: &FileWriter, at: u64, data: &[u8]) -> io::Result<()> {
        let holes = {
            let mut st = self.st.lock().unwrap();
            self.patch_locked(&mut st, w, at, data)?
        };
        // Ranges nobody had yet are ordinary posted bytes wherever they
        // come from - ingest them (re-locks per range).
        for (s, e) in holes {
            self.ingest(w, s, &data[(s - at) as usize..(e - at) as usize])?;
        }
        Ok(())
    }

    fn patch_locked(
        &self,
        st: &mut CryptoSt,
        w: &FileWriter,
        at: u64,
        data: &[u8],
    ) -> io::Result<Vec<(u64, u64)>> {
        let end = at + data.len() as u64;
        // 1. Splice patch bytes into any stash slivers they overlap -
        // stashes ARE posted bytes and repair redefines posted truth.
        // This runs before the region rewrite so that rewrite's chain
        // reads see the repaired bytes.
        for (&rs, run) in st.runs.iter_mut() {
            let head_at = rs;
            let tail_at = run.p_hi.saturating_sub(16);
            for (seg_at, is_head) in [(head_at, true), (tail_at, false)] {
                let stash = if is_head { &mut run.head } else { &mut run.tail };
                if stash.is_empty() {
                    continue;
                }
                let se = seg_at + stash.len() as u64;
                let lo = at.max(seg_at);
                let hi = end.min(se);
                if lo < hi {
                    stash[(lo - seg_at) as usize..(hi - seg_at) as usize]
                        .copy_from_slice(&data[(lo - at) as usize..(hi - at) as usize]);
                }
            }
        }
        // 2. Rewrite affected plaintext block-coherently. A patched
        // cipher block changes the plaintext at itself and at the block
        // after it, and a patch that ends inside a stash changes the
        // chain into the next decrypted block - one extra block of
        // margin on each side is a superset of every affected block, and
        // rewriting an UNaffected block is a byte-identical no-op.
        let regions: Vec<(u64, u64)> = st
            .runs
            .values()
            .filter(|r| r.p_hi > r.p_lo)
            .map(|r| (r.p_lo, r.p_hi))
            .collect();
        for (p_lo, p_hi) in regions {
            let lo = p_lo.max((at & !15).saturating_sub(16));
            let hi = p_hi.min(end.next_multiple_of(16) + 16).min(self.cipher_len);
            if lo >= hi {
                continue;
            }
            let mut chain = self.iv;
            if lo > 0 {
                self.read_posted_locked(st, w, lo - 16, &mut chain)?;
            }
            let mut fresh = vec![0u8; (hi - lo) as usize];
            self.read_posted_locked(st, w, lo, &mut fresh)?;
            let dlo = at.max(lo);
            let dhi = end.min(hi);
            if dlo < dhi {
                fresh[(dlo - lo) as usize..(dhi - lo) as usize]
                    .copy_from_slice(&data[(dlo - at) as usize..(dhi - at) as usize]);
            }
            self.advance(st, w, chain, lo, &fresh, true)?;
        }
        // 3. Report the never-seen sub-ranges for ingest by the caller.
        let mut holes: Vec<(u64, u64)> = Vec::new();
        let mut cur = at;
        for (&s, r) in st.runs.range(..end) {
            if r.end <= cur {
                continue;
            }
            if s > cur {
                holes.push((cur, s.min(end)));
            }
            cur = cur.max(r.end);
            if cur >= end {
                break;
            }
        }
        if cur < end {
            holes.push((cur, end));
        }
        Ok(holes)
    }

    /// Read POSTED bytes for cipher range `[at, at+out.len())`: seam and
    /// tail slivers come from the retained cipher, decrypted regions are
    /// re-encrypted from the nearest chain anchor (checkpoint, run
    /// anchor, or the IV). Errors if any byte has not arrived.
    fn read_posted(&self, w: &FileWriter, at: u64, out: &mut [u8]) -> io::Result<()> {
        let st = self.st.lock().unwrap();
        self.read_posted_locked(&st, w, at, out)
    }

    fn read_posted_locked(
        &self,
        st: &CryptoSt,
        w: &FileWriter,
        at: u64,
        out: &mut [u8],
    ) -> io::Result<()> {
        let end = at + out.len() as u64;
        if end > self.cipher_len {
            return Err(nofile());
        }
        let mut pos = at;
        while pos < end {
            let (&rs, run) = st.runs.range(..=pos).next_back().ok_or_else(nofile)?;
            if run.end <= pos {
                return Err(nofile());
            }
            let stop = end.min(run.end);
            // Head sliver (or the whole run when undecrypted).
            let head_end = if run.decrypted() { run.p_lo } else { run.end };
            if pos < head_end {
                let take = stop.min(head_end);
                let src = &run.head[(pos - rs) as usize..(take - rs) as usize];
                out[(pos - at) as usize..(take - at) as usize].copy_from_slice(src);
                pos = take;
                continue;
            }
            // Tail sliver: cipher [p_hi - 16, end) is retained verbatim.
            if run.p_hi > run.p_lo && pos >= run.p_hi {
                let tail_at = run.p_hi - 16;
                let take = stop;
                let src = &run.tail[(pos - tail_at) as usize..(take - tail_at) as usize];
                out[(pos - at) as usize..(take - at) as usize].copy_from_slice(src);
                pos = take;
                continue;
            }
            // Decrypted region [p_lo, p_hi): re-encrypt from the nearest
            // anchor at or below the aligned start.
            let want_lo = pos & !15;
            let want_hi = stop.min(run.p_hi).next_multiple_of(16).min(self.cipher_len);
            let (chain, mut cpos): ([u8; 16], u64) = {
                let ck = (want_lo / CRYPTO_CHUNK) * CRYPTO_CHUNK;
                let mut best: Option<(u64, [u8; 16])> = None;
                let mut c = ck;
                while c >= run.p_lo.max(CRYPTO_CHUNK) {
                    if c > run.p_lo
                        && let Some(b) = st.checkpoints.get(&c)
                    {
                        best = Some((c, *b));
                        break;
                    }
                    if c < CRYPTO_CHUNK {
                        break;
                    }
                    c -= CRYPTO_CHUNK;
                }
                match best {
                    Some((c, b)) if c >= run.p_lo => (b, c),
                    _ if run.p_lo == 0 => (self.iv, 0),
                    _ => (run.head[run.head.len() - 16..].try_into().unwrap(), run.p_lo),
                }
            };
            // Walk plaintext from the anchor to the requested window,
            // encrypting as we go; emit the requested slice.
            let mut buf = vec![0u8; 4096.min((want_hi - cpos) as usize).max(16)];
            let mut enc = rarcrypt::CbcEncStream::new(&self.key, &chain);
            while cpos < want_hi {
                let n = buf.len().min((want_hi - cpos) as usize);
                let block = &mut buf[..n];
                self.read_plain_block(st, w, cpos, block)?;
                enc.encrypt(block);
                let lo = cpos.max(pos);
                let hi = (cpos + n as u64).min(stop);
                if lo < hi {
                    out[(lo - at) as usize..(hi - at) as usize]
                        .copy_from_slice(&block[(lo - cpos) as usize..(hi - cpos) as usize]);
                }
                cpos += n as u64;
            }
            pos = stop.min(run.p_hi);
            if pos < stop && pos < run.end {
                continue; // tail sliver of the same run serves the rest
            }
        }
        Ok(())
    }

    /// Plaintext for `[at, at+block.len())` (16-aligned, within the
    /// decrypted region): disk bytes below `unp`, tail padding beyond.
    fn read_plain_block(
        &self,
        st: &CryptoSt,
        w: &FileWriter,
        at: u64,
        block: &mut [u8],
    ) -> io::Result<()> {
        let end = at + block.len() as u64;
        let disk_end = end.min(self.unp);
        if disk_end > at {
            w.read_at(&mut block[..(disk_end - at) as usize], at)?;
        }
        if end > self.unp {
            if !st.tail_done {
                return Err(nofile());
            }
            let pad_off = (at.max(self.unp) - self.unp) as usize;
            let need = (end - at.max(self.unp)) as usize;
            block[(at.max(self.unp) - at) as usize..]
                .copy_from_slice(&st.tail_pad[pad_off..pad_off + need]);
        }
        Ok(())
    }
}

/// Default total bytes of held (not-yet-mappable) spans before a group
/// falls back to materialized volumes. Memory is the cache tier and the
/// header-first scheduling keeps real holds small; this is the safety
/// net. Overridden by the MemBudget slice (`set_holds_cap`).
const HOLDS_DEFAULT_CAP: usize = 2 << 30;

/// Default nesting levels an extractor chain will map. A child created at
/// this depth is built with extraction disabled, so every slot at that
/// level goes Plain (the file materializes - never a hard failure). Real
/// usenet nesting is 2-3 levels; the cap is the DoS backstop against a
/// crafted archive that unpacks to a slightly different archive forever.
/// Configurable via the daemon `nested_max_depth` setting
/// ([`set_nested_depth_cap`]) or the `NZBFAST_NESTED_MAX_DEPTH` env
/// override (tests); resolved by [`nested_depth_cap`].
const NESTED_MAX_DEPTH_DEFAULT: usize = 5;

/// Process-global nested depth cap set from the daemon `nested_max_depth`
/// setting. 0 = unset (fall back to [`NESTED_MAX_DEPTH_DEFAULT`]). Both
/// the in-stream child chain (via the ctor default) and the disk
/// post-pass (nzbfast `extract_nested`) resolve through
/// [`nested_depth_cap`], so a single setting drives both.
static NESTED_MAX_DEPTH_SETTING: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// Daemon knob: set the nested-extraction depth cap (0 clears back to the
/// default). Clamped to >= 1 - a cap of 0 would materialize the OUTER
/// archive and extract nothing.
pub fn set_nested_depth_cap(depth: usize) {
    NESTED_MAX_DEPTH_SETTING.store(depth, std::sync::atomic::Ordering::Relaxed);
}

/// Resolve the effective nested depth cap: the `NZBFAST_NESTED_MAX_DEPTH`
/// env override (tests) wins, then the daemon setting, then the default.
/// Always >= 1.
pub fn nested_depth_cap() -> usize {
    if let Some(n) = std::env::var("NZBFAST_NESTED_MAX_DEPTH")
        .ok()
        .and_then(|s| s.trim().parse::<usize>().ok())
    {
        return n.max(1);
    }
    match NESTED_MAX_DEPTH_SETTING.load(std::sync::atomic::Ordering::Relaxed) {
        0 => NESTED_MAX_DEPTH_DEFAULT,
        n => n.max(1),
    }
}

/// Rollout escape hatch for nested routing, latched at construction.
fn nested_env_off() -> bool {
    nested_env_off_value(std::env::var("NZBFAST_NO_NESTED_ONEPASS").ok().as_deref())
}

/// Pure parse of the escape-hatch value (unit-testable without mutating
/// the process environment under the parallel test runner).
fn nested_env_off_value(v: Option<&str>) -> bool {
    v == Some("1")
}

/// Soak isolation switch for the chasing decompressor alone: with it set,
/// nested routing still runs (store-in-store keeps streaming) but a
/// compressed inner archive demotes to a materialized file exactly as it
/// did before the chase existed. Latched at construction.
fn chase_env_off() -> bool {
    chase_env_off_value(std::env::var("NZBFAST_NO_NESTED_CHASE").ok().as_deref())
}

/// Pure parse of the chase escape-hatch value (same rationale as
/// [`nested_env_off_value`]).
fn chase_env_off_value(v: Option<&str>) -> bool {
    v == Some("1")
}

/// Soak isolation switch for the 7z chase alone (phase 3), mirroring
/// `NZBFAST_NO_NESTED_CHASE`: with it set, an inner .7z demotes to a
/// materialized file exactly as it did before the 7z path existed.
/// Latched at construction.
fn sevenz_env_off() -> bool {
    sevenz_env_off_value(std::env::var("NZBFAST_NO_NESTED_7Z").ok().as_deref())
}

/// Pure parse of the 7z escape-hatch value (same rationale as
/// [`nested_env_off_value`]).
fn sevenz_env_off_value(v: Option<&str>) -> bool {
    v == Some("1")
}

/// Escape hatch for the final-output CRC gate, mirroring the nested
/// gates: with it set, the level-0 store payload ships unverified
/// exactly as before the gate existed. Latched at construction.
fn output_crc_env_off() -> bool {
    output_crc_env_off_value(std::env::var("NZBFAST_NO_OUTPUT_CRC").ok().as_deref())
}

/// Pure parse of the output-CRC escape-hatch value (same rationale as
/// [`nested_env_off_value`]).
fn output_crc_env_off_value(v: Option<&str>) -> bool {
    v == Some("1")
}

/// Article-promotion hook (nested 7z tail prefetch): `(output name,
/// file size, byte spans)` of a file at THIS extractor's level - the
/// daemon wires the root's hook to its seek/promote ladder, which
/// front-loads the pending articles carrying those bytes.
pub type PromoteHook = Arc<dyn Fn(&str, u64, &[(u64, u64)]) + Send + Sync>;

/// Permission to publish decrypted plaintext over the named outputs.
///
/// The finish decrypt turns an encrypted store output from the ciphertext
/// the crash-resume journal recorded into plaintext. Those two facts -
/// "this file has been mutated" and "the journal still claims it is a
/// faithful copy" - must never both be true on disk at once, so the
/// extractor asks first and publishes nothing until the hook returns `Ok`
/// (main.rs wires it to `journal::Journal::invalidate`, which is durable
/// before it returns). Unwired (tests, the CLI re-extract pass), there is
/// no journal to poison and the publish proceeds.
pub type DecryptBarrier = Arc<dyn Fn(&[String]) -> io::Result<()> + Send + Sync>;

/// Held-span accounting shared across the whole extractor CHAIN: a child
/// extractor's holds charge the same budget as its parent's, so a nested
/// post can't balloon RSS to depth x cap. Atomics rather than a field
/// under the routing lock because parent and child each have their own
/// lock; peak reporting is naturally the chain-wide peak.
struct HoldsBudget {
    bytes: AtomicUsize,
    cap: AtomicUsize,
    peak: AtomicUsize,
}

impl HoldsBudget {
    fn new(cap: usize) -> HoldsBudget {
        HoldsBudget {
            bytes: AtomicUsize::new(0),
            cap: AtomicUsize::new(cap),
            peak: AtomicUsize::new(0),
        }
    }

    fn add(&self, n: usize) {
        let now = self.bytes.fetch_add(n, Ordering::Relaxed) + n;
        self.peak.fetch_max(now, Ordering::Relaxed);
    }

    fn sub(&self, n: usize) {
        self.bytes.fetch_sub(n, Ordering::Relaxed);
    }

    fn over(&self) -> bool {
        self.bytes.load(Ordering::Relaxed) > self.cap.load(Ordering::Relaxed)
    }

    fn cap(&self) -> usize {
        self.cap.load(Ordering::Relaxed)
    }

    fn peak(&self) -> usize {
        self.peak.load(Ordering::Relaxed)
    }
}

/// Per-slot budget for spans held while a slot is still unclassified
/// (waiting for its offset-0 sniff). Honest posts fetch each file's first
/// segment within the first round-trips (M3 scheduling), so real holds
/// stay a few articles deep; an NZB with synthesized segment numbering
/// never delivers offset 0 early and would pile the whole file here.
/// A quarter of the holds slice, clamped [4 MB, 64 MB] - far above any
/// legitimate out-of-order depth, far below "the entire download in RAM".
fn unclassified_spill(holds_cap: usize) -> usize {
    (holds_cap / 4).clamp(4 << 20, 64 << 20)
}

/// Strip release-file suffixes down to the shared stem:
/// `x.part01.rar`/`x.r00`/`x.vol000+01.par2`/`x.par2`/`x.rar` → `x`.
pub fn release_stem(name: &str) -> String {
    let lower = name.to_ascii_lowercase();
    let mut end = lower.len();
    let cut = |s: &str, end: usize, f: &dyn Fn(&str) -> Option<usize>| -> usize {
        f(&s[..end]).unwrap_or(end)
    };
    end = cut(&lower, end, &|s| s.strip_suffix(".par2").map(|r| r.len()));
    end = cut(&lower, end, &|s| {
        let vol = s.rfind(".vol")?;
        let tail = &s[vol + 4..];
        // par2cmdline "vol01+02" or range-style "vol001-003".
        let (a, b) = tail.split_once(['+', '-'])?;
        (!a.is_empty()
            && a.bytes().all(|c| c.is_ascii_digit())
            && !b.is_empty()
            && b.bytes().all(|c| c.is_ascii_digit()))
        .then_some(vol)
    });
    end = cut(&lower, end, &|s| s.strip_suffix(".rar").map(|r| r.len()));
    end = cut(&lower, end, &|s| {
        let p = s.rfind(".part")?;
        let tail = &s[p + 5..];
        (!tail.is_empty() && tail.bytes().all(|c| c.is_ascii_digit())).then_some(p)
    });
    end = cut(&lower, end, &|s| {
        let p = s.rfind('.')?;
        let tail = &s[p + 1..];
        (tail.len() >= 2
            && (tail.starts_with('r') || tail.starts_with('s'))
            && tail[1..].bytes().all(|c| c.is_ascii_digit()))
        .then_some(p)
    });
    name[..end].to_string()
}

/// Natural volume order key: `.rar` < `.r00` < `.r01`; `.part1` < `.part2`.
pub fn vol_sort_key(name: &str) -> (u64, String) {
    let lower = name.to_ascii_lowercase();
    if let Some(p) = lower.rfind(".part") {
        let tail = &lower[p + 5..];
        let digits: String = tail.chars().take_while(|c| c.is_ascii_digit()).collect();
        if let Ok(n) = digits.parse::<u64>() {
            return (n, lower.clone());
        }
    }
    if lower.ends_with(".rar") {
        return (0, lower.clone());
    }
    if let Some(p) = lower.rfind('.') {
        let tail = &lower[p + 1..];
        // Old-style continuations roll the letter past .r99: .s00 = 101,
        // .t00 = 201… (each letter is another 10^digits volumes). Keying
        // only 'r' broke base-resolution at the r→s boundary on 100+
        // volume sets.
        if tail.len() >= 2 && (b'r'..=b'z').contains(&tail.as_bytes()[0]) {
            if let Ok(n) = tail[1..].parse::<u64>() {
                let span = 10u64.pow((tail.len() - 1) as u32);
                return ((tail.as_bytes()[0] - b'r') as u64 * span + n + 1, lower.clone());
            }
        }
        // WinRAR numeric volume naming: .001, .002 …
        if tail.len() >= 2 && tail.bytes().all(|c| c.is_ascii_digit()) {
            if let Ok(n) = tail.parse::<u64>() {
                return (n, lower.clone());
            }
        }
    }
    (u64::MAX, lower)
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum SlotMode {
    /// Waiting for the offset-0 article to sniff.
    Unknown,
    /// Ordinary file - write through.
    Plain,
    /// RAR volume in mapping mode.
    Rar,
    /// Compressed RAR5 volume being chased: spans feed the slot's
    /// frontier buffer, the chase worker decodes behind the frontier.
    RarChase,
    /// Inner 7z archive being chased (child slots only): spans feed the
    /// slot's frontier buffer, the 7z worker parses/decodes through a
    /// blocking Read+Seek view (footer first, via tail prefetch).
    SevenZ,
    /// RAR volume after fallback - volume file materialized.
    RarFallback,
    /// Source-protected fallback: the slot's bytes already live in a real
    /// file the caller owns (re-extraction reads volumes off disk), so a
    /// fallback must never materialize - writes are dropped instead.
    Discard,
}

/// Out-of-order CRC32 accumulator over one mapped store piece's data
/// area: disjoint (start → len, crc) runs that coalesce through
/// `crc32_combine` as gaps fill. Re-fed spans (hold drains, fallback-race
/// re-routes) clip to the not-yet-seen sub-ranges - routing is
/// deterministic, so a duplicate span carries identical bytes and
/// first-writer-wins is exact. The one writer that carries DIFFERENT
/// bytes for a range already seen is mapped PAR2 repair; it enters
/// through [`Self::overwrite`], which replaces the overlapped sub-range
/// instead of clipping.
#[derive(Default)]
struct CrcRuns {
    runs: BTreeMap<u64, (u64, u32)>,
    /// Sub-ranges whose composed CRC an `overwrite` had to discard: a
    /// repair span landing mid-run invalidates the whole run, and the
    /// parts outside the span cannot be split back out of the composed
    /// value (that value is entangled with the discarded damaged
    /// bytes). They become gaps to recompute from the routed bytes on
    /// disk at verify time - see [`Self::take_stale_gaps`].
    stale: Vec<(u64, u64)>,
}

impl CrcRuns {
    fn add(&mut self, off: u64, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        let end = off + data.len() as u64;
        // Sub-ranges of [off, end) no existing run covers.
        let mut fresh: Vec<(u64, u64)> = Vec::new();
        let mut cur = off;
        for (&s, &(l, _)) in self.runs.range(..end) {
            let e = s + l;
            if e <= cur {
                continue;
            }
            if s > cur {
                fresh.push((cur, s.min(end)));
            }
            cur = cur.max(e);
            if cur >= end {
                break;
            }
        }
        if cur < end {
            fresh.push((cur, end));
        }
        if fresh.is_empty() {
            return;
        }
        for &(s, e) in &fresh {
            let part = &data[(s - off) as usize..(e - off) as usize];
            self.runs.insert(s, (e - s, crc32fast::hash(part)));
        }
        for &(s, _) in &fresh {
            self.coalesce_at(s);
        }
    }

    /// Repair rewrite (mapped PAR2, via patch_volume_span): replace
    /// `[off, off+data.len())` with the rebuilt bytes' CRC. Plain `add`
    /// clips to unseen sub-ranges - correct for every duplicate-bytes
    /// re-feed, but across a repair it would keep the STALE wire-damage
    /// CRC while the file on disk heals, and the finish gate would then
    /// demote a job that one-passed cleanly. Overlapped runs are
    /// removed first; their sub-ranges outside the span move to
    /// `stale`.
    fn overwrite(&mut self, off: u64, data: &[u8]) {
        if data.is_empty() {
            return;
        }
        let end = off + data.len() as u64;
        let hit: Vec<u64> = self
            .runs
            .range(..end)
            .filter(|&(&s, &(l, _))| s + l > off)
            .map(|(&s, _)| s)
            .collect();
        for s in hit {
            let (l, _) = self.runs.remove(&s).expect("run key just enumerated");
            if s < off {
                self.stale.push((s, off));
            }
            if s + l > end {
                self.stale.push((end, s + l));
            }
        }
        // A pure gap-fill now.
        self.add(off, data);
    }

    /// Drain the stale list into the disjoint sub-ranges still uncovered
    /// by runs (a later add() may have re-covered part of a stale range
    /// with re-fed bytes - those ARE the current disk bytes and need no
    /// recomputation). The caller recomputes each gap from the routed
    /// bytes and feeds it back through [`Self::add_run`]; a gap it
    /// cannot read simply stays a gap, and the piece reads as
    /// unverifiable (skip - today's assurance level).
    fn take_stale_gaps(&mut self) -> Vec<(u64, u64)> {
        let mut stale = std::mem::take(&mut self.stale);
        stale.sort_unstable();
        let mut out: Vec<(u64, u64)> = Vec::new();
        for (s, e) in stale {
            // Merge overlap with the previously emitted range (the list
            // can hold overlapping entries after repeated overwrites).
            let s = match out.last() {
                Some(&(_, pe)) if s < pe => pe,
                _ => s,
            };
            let mut cur = s;
            for (&rs, &(rl, _)) in self.runs.range(..e) {
                let re = rs + rl;
                if re <= cur {
                    continue;
                }
                if rs > cur {
                    out.push((cur, rs.min(e)));
                }
                cur = cur.max(re);
                if cur >= e {
                    break;
                }
            }
            if cur < e {
                out.push((cur, e));
            }
        }
        out
    }

    /// Insert a precomputed run (verify-time recompute of a stale gap;
    /// the caller hashed the bytes incrementally, so they never
    /// materialize here). Gap-fill only: `take_stale_gaps` returns
    /// ranges disjoint from the runs, and anything else is a caller bug
    /// that must not corrupt the composition - overlaps are dropped.
    /// Returns whether the run was taken. A caller holding the bytes (the
    /// verified-article-CRC fast path) must hash and use [`Self::add`] on
    /// false, or the overlapped range silently loses coverage and the
    /// piece never composes - a clean job demoted for want of a CRC.
    #[must_use = "a refused run means the range is still uncovered; hash it and use add()"]
    fn add_run(&mut self, off: u64, len: u64, crc: u32) -> bool {
        if len == 0 {
            return false;
        }
        let end = off + len;
        if self.runs.range(..end).any(|(&s, &(l, _))| s + l > off) {
            return false;
        }
        self.runs.insert(off, (len, crc));
        self.coalesce_at(off);
        true
    }

    /// Merge the run starting at `s` with the neighbours it now touches
    /// (b starts exactly where a ends), looking only at those neighbours.
    ///
    /// The whole-map rebuild this replaces ran once per `add`, which under
    /// out-of-order article arrival is once per article: a 100 MiB volume
    /// completing out of order holds many disjoint runs, so ~150 rebuilds
    /// each allocated a fresh `BTreeMap` and walked every run - and did it
    /// while the routing lock was held. Only the inserted run's immediate
    /// neighbours can newly touch, so this is O(log n + merged) instead.
    ///
    /// A no-op when `s` is absent: `add` inserts several fresh runs and
    /// coalesces each, and an earlier merge may already have absorbed a
    /// later one.
    fn coalesce_at(&mut self, s: u64) {
        if !self.runs.contains_key(&s) {
            return;
        }
        // Fold into the predecessor when it ends exactly here, so the
        // surviving key is the earliest of the merged chain.
        let mut start = s;
        if let Some((&ps, &(pl, pc))) = self.runs.range(..s).next_back() {
            if ps + pl == s {
                let (l, c) = self.runs.remove(&s).expect("key checked above");
                self.runs.insert(ps, (pl + l, crate::yenc_simd::crc32_combine(pc, c, l)));
                start = ps;
            }
        }
        // Absorb successors while they touch.
        while let Some(&(l, c)) = self.runs.get(&start) {
            let Some((&ns, &(nl, nc))) = self.runs.range(start + 1..).next() else {
                break;
            };
            if ns != start + l {
                break;
            }
            self.runs.remove(&ns);
            self.runs.insert(start, (l + nl, crate::yenc_simd::crc32_combine(c, nc, nl)));
        }
    }

    /// The CRC32 of [0, len) once every byte has been seen; None while
    /// gaps remain.
    fn whole(&self, len: u64) -> Option<u32> {
        match self.runs.iter().next() {
            Some((&0, &(l, c))) if l == len && self.runs.len() == 1 => Some(c),
            _ => None,
        }
    }
}

struct Slot {
    mode: SlotMode,
    name: String,
    size: u64,
    /// Pre-sniff / unmappable spans.
    holds: Vec<(u64, Vec<u8>)>,
    /// Bytes held while still Unknown (pre-classification). Bounded by
    /// the per-slot spill: an NZB with synthesized segment numbering
    /// ("segment 1" is not the yEnc offset-0 article - seen live on a
    /// fully-obfuscated 9.6 GB single-file post) would otherwise hold the
    /// entire file in RAM waiting for a sniff that may come last.
    pre_bytes: usize,
    /// Plain-file or materialized-volume writer.
    writer: Option<Arc<FileWriter>>,
    mapper: Option<VolumeMapper>,
    /// Raw header/meta bytes (offset, bytes) kept for reconstruction.
    header_spans: Vec<(u64, Vec<u8>)>,
    /// Canonical group key (the archive's identity), set once entries
    /// parse. Groups start keyed by a volume's first inner-file name and
    /// merge when split pieces prove two keys are one archive.
    group: Option<String>,
    /// Chase attachment (modes RarChase and SevenZ): the slot's
    /// in-flight bytes.
    chase: Option<ChaseSlot>,
    /// 7z chase control (mode SevenZ): the worker and its sink slots.
    sevenz: Option<Arc<SevenZCtl>>,
    /// Entry index → composed CRC32 of the routed piece bytes, for the
    /// finish-time check against the RAR5 header CRC. That check is the
    /// only verifier a store payload has - the download's PAR2 vouches
    /// for the OUTER bytes as posted, damage the poster packed in
    /// included. Nested levels always compose; level 0 composes under
    /// the verify_output_crc gate.
    piece_crcs: HashMap<usize, CrcRuns>,
}

struct Group {
    slots: Vec<usize>,
    /// (slot, entry) → inner-file base offset, rebuilt as mappers progress.
    bases: HashMap<(usize, usize), u64>,
    fallback: bool,
    fallback_reason: Option<String>,
    /// sanitized inner-file name → actual output filename. Output files
    /// are OWNED by their group: another archive in the same NZB reusing
    /// an inner name gets its own (disambiguated) file, and a fallback
    /// deletes only the files listed here - never another group's.
    out_names: HashMap<String, String>,
    /// sanitized inner-file name → CHILD slot, for inner files routed
    /// into the nested child extractor. Group-owned for the same reason
    /// as `out_names`: two archives reusing an inner name must not share
    /// a destination, and a fallback abandons only its own child slots.
    routed: HashMap<String, usize>,
    /// Live chasing decompressor over this group's volumes (compressed
    /// RAR5 inner archive). Cleared at finish once the worker is joined.
    chase: Option<Arc<ChaseCtl>>,
}

pub struct ExtractReport {
    /// Inner files written via direct extraction (name, size).
    pub extracted: Vec<(String, u64)>,
    /// Groups that fell back to materialized volumes (key, why).
    pub fallbacks: Vec<(String, String)>,
    /// Bytes that went through the direct-extraction path.
    pub extracted_bytes: u64,
    /// Extracted files that were AES-decrypted in place at finish
    /// (encrypted RAR5 store sets - no unrar involved).
    pub decrypted: Vec<String>,
}

/// Where one piece of an article's decoded bytes landed on disk: `len`
/// bytes at `file_off` of `file` (a name in the out dir), carrying the
/// volume-view bytes at `vol_off` (article yEnc offset + span offset).
/// The crash-resume journal records these so a later run can rebuild the
/// volume file from wherever the bytes physically went - identity for
/// plain files, translated for direct-extracted inner files.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frag {
    pub file: String,
    pub file_off: u64,
    pub vol_off: u64,
    pub len: u64,
}

/// What [`Extractor::write`] did with a span, for the crash-resume
/// journal. `Placed` means EVERY byte of the article is durably on disk
/// at the recorded fragments - the only state a plain `R` record may
/// describe. `PlacedCrypto` is the same coverage claim for a span that
/// fed an in-stream-decrypted (plaintext-once) file: what is on disk is
/// PLAINTEXT, so it journals as a `D` record that a resume can only
/// honor by re-encrypting through the file's journaled `E`/`K`/`T`
/// facts - an old binary parses `D` as an unknown message-id and simply
/// refetches. Held spans, header bytes retained in memory, and
/// discarded spans return `No`.
pub enum Persist {
    No,
    Placed(Vec<Frag>),
    PlacedCrypto(Vec<Frag>),
}

// ---- Phase 0(b): nested-archive prevalence instrumentation ----
//
// Learn real-world nesting prevalence from live daemons and testers.
// Every nested level processed (an archive INSIDE another archive - depth
// > 0) emits one concise, greppable log line and bumps a process-global
// tally the daemon stats API can surface. A single-layer job (depth 0)
// never reaches this path, so the common case pays nothing. Two paths
// feed the ONE counter set: the in-stream child extractor here (store /
// chase / 7z inners that stream in RAM) and the disk post-pass in nzbfast
// (materialized inners the stream demoted, plus never-streamed shapes
// like RAR4 and resumed jobs).
//
// Counting model (kept consistent across both call sites so a demoted
// inner is never double-counted):
//   * an inner that STAYS in-stream          -> `in_stream` (this crate)
//   * an inner handled by the disk post-pass -> `disk`      (nzbfast)
//   * an in-stream attempt that DEMOTES      -> `demoted` only
// A demoted inner materializes and is then re-extracted by the disk
// post-pass, where it is tallied once under `disk`; the `demoted` bump is
// a diagnostic that records WHY a `disk` line exists. Hence the invariant
// `levels == in_stream + disk`, with `demoted <= disk`.

static NESTED_LEVELS: AtomicU64 = AtomicU64::new(0);
static NESTED_IN_STREAM: AtomicU64 = AtomicU64::new(0);
static NESTED_DEMOTED: AtomicU64 = AtomicU64::new(0);
static NESTED_DISK: AtomicU64 = AtomicU64::new(0);
static NESTED_RAR_STORE: AtomicU64 = AtomicU64::new(0);
static NESTED_RAR_COMPRESSED: AtomicU64 = AtomicU64::new(0);
static NESTED_RAR_ENCRYPTED: AtomicU64 = AtomicU64::new(0);
static NESTED_SEVENZ: AtomicU64 = AtomicU64::new(0);
static NESTED_OTHER: AtomicU64 = AtomicU64::new(0);

// ---------------------------------------------------------------------------
// Archive shape: what the set turned out to BE, published live.
//
// The mappers already learn every fact here the moment a volume's headers
// parse - RAR version, per-entry method, encryption - and the routing
// decisions know whether the bytes are being extracted as they arrive or
// materialized for a disk unpack. None of it used to leave the extractor
// before finish(). The latch below collects it into a small token list
// the daemon can poll mid-download and the dashboard can translate.
//
// Bits are LATCHED, never cleared: a set that starts on the fast path and
// later demotes reads as "partly on disk", which is what actually
// happened. One latch is shared by a whole extractor chain, with nested
// levels writing a separate word, so an inner 7z inside a RAR5 store set
// shows up as "7z inside" rather than overwriting the outer format.
// ---------------------------------------------------------------------------

const SH_RAR4: u32 = 1 << 0;
const SH_RAR5: u32 = 1 << 1;
const SH_7Z: u32 = 1 << 2;
const SH_STORE: u32 = 1 << 3;
const SH_COMPRESSED: u32 = 1 << 4;
const SH_ENCRYPTED: u32 = 1 << 5;
/// Encrypted content that decrypts at write time (plaintext-once) rather
/// than being assembled as ciphertext for the finish pass.
const SH_ENC_INSTREAM: u32 = 1 << 6;
/// At least one inner file was routed to direct extraction.
const SH_ONE_PASS: u32 = 1 << 7;
/// At least one group/slot fell back to volumes on disk.
const SH_MATERIALIZED: u32 = 1 << 8;

/// Shared observation word for one extractor chain (see the section note).
#[derive(Default)]
struct ShapeLatch {
    outer: AtomicU32,
    nested: AtomicU32,
}

impl ShapeLatch {
    fn note(&self, depth: usize, bits: u32) {
        let w = if depth == 0 { &self.outer } else { &self.nested };
        w.fetch_or(bits, Ordering::Relaxed);
    }

    fn snapshot(&self) -> (u32, u32) {
        (
            self.outer.load(Ordering::Relaxed),
            self.nested.load(Ordering::Relaxed),
        )
    }
}

/// What an archive set turned out to be, as an ordered list of stable
/// tokens: format, then how the content is packed, then how it is being
/// unpacked, then what was found inside.
///
/// The tokens are the wire format - the daemon persists them and the
/// dashboard translates them - so they must stay stable. [`Self::display`]
/// renders the English the CLI prints.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveShape {
    tokens: Vec<&'static str>,
}

impl ArchiveShape {
    fn from_bits(outer: u32, nested: u32) -> Option<ArchiveShape> {
        let mut t: Vec<&'static str> = Vec::new();
        if outer & SH_RAR5 != 0 {
            t.push("rar5");
        } else if outer & SH_RAR4 != 0 {
            t.push("rar4");
        } else if outer & SH_7Z != 0 {
            t.push("7z");
        } else {
            // Nothing archive-shaped has been recognized yet (or the job
            // is loose files) - no badge rather than a guess.
            return None;
        }
        match (outer & SH_STORE != 0, outer & SH_COMPRESSED != 0) {
            (true, true) => t.push("mixed"),
            (true, false) => t.push("store"),
            (false, true) => t.push("compressed"),
            (false, false) => {}
        }
        if outer & SH_ENCRYPTED != 0 {
            t.push("encrypted");
        }
        let one_pass = outer & SH_ONE_PASS != 0;
        let on_disk = outer & SH_MATERIALIZED != 0;
        if one_pass && on_disk {
            t.push("mixed-pass");
        } else if on_disk {
            t.push("on-disk");
        } else if one_pass {
            // Legacy encrypted sets assemble ciphertext and unlock in the
            // finish pass; plaintext-once unlocks as the bytes arrive, so
            // it is a plain one-pass set like any other.
            if outer & SH_ENCRYPTED != 0 && outer & SH_ENC_INSTREAM == 0 {
                t.push("unlock-at-end");
            } else {
                t.push("one-pass");
            }
        }
        if nested & SH_7Z != 0 {
            t.push("inner-7z");
        } else if nested & (SH_RAR4 | SH_RAR5) != 0 {
            t.push("inner-rar");
        }
        Some(ArchiveShape { tokens: t })
    }

    pub fn tokens(&self) -> &[&'static str] {
        &self.tokens
    }

    /// The space-separated form carried by the API and the history file.
    pub fn tag(&self) -> String {
        self.tokens.join(" ")
    }

    /// English, for the CLI and as the dashboard's fallback.
    pub fn display(&self) -> String {
        self.tokens
            .iter()
            .map(|t| shape_word(t))
            .collect::<Vec<_>>()
            .join(" · ")
    }
}

/// English for one [`ArchiveShape`] token. Unknown tokens pass through so
/// an older daemon's persisted tag still reads sensibly.
pub fn shape_word(token: &str) -> &str {
    match token {
        "rar5" => "RAR5",
        "rar4" => "RAR4",
        "7z" => "7z",
        "store" => "stored",
        "compressed" => "compressed",
        "mixed" => "mixed",
        "encrypted" => "encrypted",
        "one-pass" => "one-pass",
        "unlock-at-end" => "unlocked at the end",
        "on-disk" => "unpacked after download",
        "mixed-pass" => "partly on disk",
        "inner-7z" => "7z inside",
        "inner-rar" => "RAR inside",
        other => other,
    }
}

/// How a nested inner archive was handled, for [`note_nested_level`].
pub enum NestedDisposition<'a> {
    /// Extracted entirely in-stream - its volumes never touched disk.
    InStream,
    /// An in-stream attempt fell back to materialized volumes; the reason
    /// is the demote cause (a mixed set, a budget breach, a bad CRC, ...).
    Demoted(&'a str),
    /// Handled by the disk post-pass (a demoted inner, or one never
    /// eligible for streaming - RAR4, multipart 7z, a resumed job).
    Disk,
}

/// A snapshot of the nested-prevalence tally, for the stats API.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct NestedPrevalence {
    /// Distinct nested inner archives processed (`in_stream + disk`).
    pub levels: u64,
    pub in_stream: u64,
    pub demoted: u64,
    pub disk: u64,
    pub rar_store: u64,
    pub rar_compressed: u64,
    pub rar_encrypted: u64,
    pub sevenz: u64,
    pub other: u64,
}

/// Record one processed nested level: log a line and bump the tally. Cheap
/// and non-spammy - called once per nested archive at a terminal seam, not
/// per span. `kind` is one of `rar-store` / `rar-compressed` /
/// `rar-encrypted` / `7z` / `other`.
pub fn note_nested_level(depth: usize, kind: &str, disposition: NestedDisposition) {
    let bump_kind = || match kind {
        "rar-store" => &NESTED_RAR_STORE,
        "rar-compressed" => &NESTED_RAR_COMPRESSED,
        "rar-encrypted" => &NESTED_RAR_ENCRYPTED,
        "7z" => &NESTED_SEVENZ,
        _ => &NESTED_OTHER,
    }
    .fetch_add(1, Ordering::Relaxed);
    match disposition {
        NestedDisposition::InStream => {
            NESTED_LEVELS.fetch_add(1, Ordering::Relaxed);
            NESTED_IN_STREAM.fetch_add(1, Ordering::Relaxed);
            bump_kind();
            println!("nested-prevalence: depth={depth} type={kind} stream=in-stream");
        }
        NestedDisposition::Disk => {
            NESTED_LEVELS.fetch_add(1, Ordering::Relaxed);
            NESTED_DISK.fetch_add(1, Ordering::Relaxed);
            bump_kind();
            println!("nested-prevalence: depth={depth} type={kind} stream=disk");
        }
        NestedDisposition::Demoted(reason) => {
            // Diagnostic only - the archive is tallied under `disk` when
            // the post-pass re-extracts the volumes this demote produced.
            NESTED_DEMOTED.fetch_add(1, Ordering::Relaxed);
            println!("nested-prevalence: depth={depth} type={kind} stream=demoted reason=\"{reason}\"");
        }
    }
}

/// Current nested-prevalence tally (process lifetime). Surfaced by the
/// daemon stats API and asserted by the prevalence tests.
pub fn nested_prevalence() -> NestedPrevalence {
    NestedPrevalence {
        levels: NESTED_LEVELS.load(Ordering::Relaxed),
        in_stream: NESTED_IN_STREAM.load(Ordering::Relaxed),
        demoted: NESTED_DEMOTED.load(Ordering::Relaxed),
        disk: NESTED_DISK.load(Ordering::Relaxed),
        rar_store: NESTED_RAR_STORE.load(Ordering::Relaxed),
        rar_compressed: NESTED_RAR_COMPRESSED.load(Ordering::Relaxed),
        rar_encrypted: NESTED_RAR_ENCRYPTED.load(Ordering::Relaxed),
        sevenz: NESTED_SEVENZ.load(Ordering::Relaxed),
        other: NESTED_OTHER.load(Ordering::Relaxed),
    }
}

/// Reset the tally to zero. Test-only: the counters are process-global, so
/// a test that asserts exact counts must isolate itself first.
#[doc(hidden)]
pub fn reset_nested_prevalence() {
    for c in [
        &NESTED_LEVELS,
        &NESTED_IN_STREAM,
        &NESTED_DEMOTED,
        &NESTED_DISK,
        &NESTED_RAR_STORE,
        &NESTED_RAR_COMPRESSED,
        &NESTED_RAR_ENCRYPTED,
        &NESTED_SEVENZ,
        &NESTED_OTHER,
    ] {
        c.store(0, Ordering::Relaxed);
    }
}

/// One deferred pwrite: performed after the routing lock drops.
struct WriteJob {
    writer: Arc<FileWriter>,
    file_off: u64,
    src_start: usize,
    len: usize,
    /// In-stream decrypt state when this span belongs to an encrypted
    /// store entry under plaintext-once: the executor routes the bytes
    /// through [`CryptoState::ingest`]/[`CryptoState::patch`] instead of
    /// a raw pwrite, and the article is never journaled (Persist::No -
    /// what lands on disk is plaintext, not the posted bytes a resume
    /// would copy into volume files).
    crypto: Option<Arc<CryptoState>>,
    repair: bool,
}

/// One deferred child forward from the hot write path: `len` bytes of the
/// caller's span (at `src_start`) go to the child slot the routing map
/// names at DELIVERY time, at `file_off` of the level-1 file - executed
/// after the routing lock drops, exactly like the deferred pwrites (the
/// child takes its own lock and defers its own pwrites; running that
/// under our lock would serialize disk I/O behind routing again). The
/// destination is re-resolved rather than captured: a group merge in the
/// window can displace (and abandon) the slot routing picked.
struct FwdSpan {
    name: String,
    size: u64,
    file_off: u64,
    src_start: usize,
    len: usize,
    /// Mapped-repair rewrite: the bytes may DIFFER from an earlier
    /// delivery of the same range, so the child must overwrite (not
    /// clip) its piece-CRC composition - see [`CrcRuns::overwrite`].
    repair: bool,
}

/// An OWNED child forward, queued by the under-the-lock re-feed paths
/// (drain_holds / reresolve / settle) that cannot call into the child
/// while the lock is held. Delivered by `flush_pending_fwd` once the lock
/// drops; `parent_slot`/`vol_off` let delivery re-route the bytes into a
/// materialized volume if the slot fell back in the meantime.
struct FwdJob {
    parent_slot: usize,
    vol_off: u64,
    name: String,
    size: u64,
    file_off: u64,
    bytes: Vec<u8>,
    /// See [`FwdSpan::repair`].
    repair: bool,
}

/// Where an inner file's bytes go: a real output writer, or a slot of the
/// nested child extractor.
enum Dest {
    Writer(Arc<FileWriter>),
    Child(Arc<Extractor>, usize),
}

// ---------------------------------------------------------------------------
// The chasing decompressor (nested one-pass, phase 2): a COMPRESSED RAR5
// inner archive decompresses while its bytes arrive, instead of demoting
// to a materialized file. Each chased volume feeds a frontier buffer the
// routing path appends to; a chase worker thread drives the RAR engine's
// streaming reader over those buffers in volume order, and its extracted
// member bytes route back through the same seam - a child-extractor slot
// per member - so a store archive UNDER the compressed layer still
// streams. Any failure demotes the group to today's materialize path.
// ---------------------------------------------------------------------------

/// In-flight byte store for one chased volume. Spans arrive in any order;
/// readers see a CONTIGUOUS frontier from offset 0 and block for bytes
/// beyond it (the RAR decode is forward-only, so blocking at the frontier
/// is exactly the chase). Out-of-order spans park in a hole map and fold
/// into the frontier as the gaps fill - a late PAR2-rebuilt block enters
/// like any other span and simply unblocks the reader.
struct FrontierBuffer {
    state: Mutex<FrontierState>,
    arrived: Condvar,
}

#[derive(Default)]
struct FrontierState {
    /// Contiguous bytes from volume offset 0.
    data: Vec<u8>,
    /// Spans beyond the frontier, keyed by start offset.
    pending: BTreeMap<u64, Vec<u8>>,
    /// Declared volume size (the level-1 entry's unpacked size).
    total: u64,
    /// Retained bytes (frontier + pending) - what the holds budget is
    /// charged for.
    stored: usize,
    /// A rewrite arrived whose bytes DIFFERED from what was already
    /// retained for that range. Sticky, and never cleared: see
    /// [`FrontierBuffer::write_span`].
    conflict: bool,
    abort: Option<String>,
}

impl std::fmt::Debug for FrontierBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let st = self.state.lock().unwrap();
        f.debug_struct("FrontierBuffer")
            .field("frontier", &st.data.len())
            .field("pending", &st.pending.len())
            .field("total", &st.total)
            .field("abort", &st.abort)
            .finish()
    }
}

impl FrontierBuffer {
    fn new(total: u64) -> FrontierBuffer {
        FrontierBuffer {
            state: Mutex::new(FrontierState {
                total,
                ..Default::default()
            }),
            arrived: Condvar::new(),
        }
    }

    /// Accept one span (any order, duplicates and overlaps tolerated -
    /// routing may deliver a span twice, always with identical bytes).
    /// Returns the retained-byte total afterwards, for budget accounting.
    ///
    /// The one delivery that is NOT a harmless duplicate is a mapped
    /// repair rewrite ([`FwdSpan::repair`]), whose bytes may legitimately
    /// DIFFER from an earlier delivery of the same range - poster-side
    /// damage where the article CRC passes but the PAR2 block does not.
    /// This used to be dropped without a word for anything at or behind
    /// the frontier, which is precisely the range the chase engine has
    /// already decoded, so the corrected bytes went nowhere and nothing
    /// noticed. Now any differing rewrite OVERWRITES the retained copy
    /// (so a demotion materializes the corrected volume, exactly) and
    /// sets the sticky `conflict` flag, which makes the caller forfeit
    /// the chase. That is the same outcome depth 0 reaches by accident:
    /// `patch_volume_span` refuses a repair on a chased slot, so the
    /// volume demotes to materialized and the disk pass re-extracts it.
    ///
    /// Deliberately NOT `abort()`: the retained bytes have to stay
    /// readable for [`Self::take_spans`] to materialize them.
    fn write_span(&self, offset: u64, bytes: &[u8]) -> usize {
        let mut st = self.state.lock().unwrap();
        if st.abort.is_some() {
            return st.stored;
        }
        let end = (offset + bytes.len() as u64).min(st.total);
        if end <= offset {
            return st.stored;
        }
        let bytes = &bytes[..(end - offset) as usize];
        let frontier = st.data.len() as u64;
        let mut accepted = false;
        let mut differed = false;
        // Whatever we already retain for this range, the newest delivery
        // wins. Checked against the frontier AND the parked spans: the 7z
        // chase peeks at arbitrary offsets, so a parked span can have been
        // read too, and a rewrite of one is no safer to discard.
        if offset < frontier {
            let n = (frontier.min(end) - offset) as usize;
            let dst = &mut st.data[offset as usize..offset as usize + n];
            if *dst != bytes[..n] {
                dst.copy_from_slice(&bytes[..n]);
                differed = true;
            }
        }
        if end > frontier {
            // Start from the last parked span that could reach `offset`.
            let lo = st
                .pending
                .range(..=offset)
                .next_back()
                .map(|(&s, _)| s)
                .unwrap_or(0);
            for (&s, v) in st.pending.range_mut(lo..end) {
                let a = offset.max(s);
                let b = end.min(s + v.len() as u64);
                if a >= b {
                    continue;
                }
                let src = &bytes[(a - offset) as usize..(b - offset) as usize];
                let dst = &mut v[(a - s) as usize..(b - s) as usize];
                if *dst != *src {
                    dst.copy_from_slice(src);
                    differed = true;
                }
            }
        }
        if offset <= frontier {
            if end > frontier {
                st.data.extend_from_slice(&bytes[(frontier - offset) as usize..]);
                accepted = true;
            }
            // Fold parked spans the new frontier now reaches. Their
            // overlap with the frontier was reconciled when they were
            // written, so only the tail is new.
            while let Some((&s, _)) = st.pending.first_key_value() {
                let f = st.data.len() as u64;
                if s > f {
                    break;
                }
                let v = st.pending.remove(&s).unwrap();
                let ve = s + v.len() as u64;
                if ve > f {
                    st.data.extend_from_slice(&v[(f - s) as usize..]);
                }
            }
        } else {
            // Park it; a shorter duplicate at the same start is subsumed
            // (its bytes were just reconciled into the longer one).
            let keep = match st.pending.get(&offset) {
                Some(old) => old.len() < bytes.len(),
                None => true,
            };
            if keep {
                st.pending.insert(offset, bytes.to_vec());
                // Parked spans wake waiters too: the 7z chase reads at
                // arbitrary offsets (the promoted footer far past the
                // frontier), unlike the frontier-sequential RAR reader.
                accepted = true;
            }
        }
        st.conflict |= differed;
        st.stored = st.data.len() + st.pending.values().map(|v| v.len()).sum::<usize>();
        let stored = st.stored;
        drop(st);
        if accepted {
            self.arrived.notify_all();
        }
        stored
    }

    /// Fail the buffer: every blocked (and future) read errors with
    /// `reason`. Cancel path; retained bytes stay readable via
    /// [`Self::take_spans`] for demotion.
    fn abort(&self, reason: &str) {
        let mut st = self.state.lock().unwrap();
        if st.abort.is_none() {
            st.abort = Some(reason.to_string());
        }
        drop(st);
        self.arrived.notify_all();
    }

    /// Did a rewrite land whose bytes differed from what was already
    /// retained? Sticky. The retained record now holds the CORRECTED
    /// bytes, but anything the chase decoded before the rewrite came
    /// from the stale copy, so the caller must forfeit the chase and
    /// materialize instead. See [`Self::write_span`].
    fn conflicted(&self) -> bool {
        self.state.lock().unwrap().conflict
    }

    /// Frontier progress (bytes contiguous from 0) vs the declared total.
    fn is_complete(&self) -> bool {
        let st = self.state.lock().unwrap();
        st.data.len() as u64 >= st.total
    }

    /// Non-blocking volume-view read for the verifier/repair read-back:
    /// serves frontier AND parked bytes, errors if any hole intersects.
    fn peek(&self, off: u64, out: &mut [u8]) -> io::Result<()> {
        let st = self.state.lock().unwrap();
        let mut pos = off;
        let end = off + out.len() as u64;
        let frontier = st.data.len() as u64;
        if pos < frontier {
            let n = (frontier.min(end) - pos) as usize;
            out[..n].copy_from_slice(&st.data[pos as usize..pos as usize + n]);
            pos += n as u64;
        }
        while pos < end {
            // The parked span covering `pos`, if any.
            let hit = st
                .pending
                .range(..=pos)
                .next_back()
                .filter(|&(&s, v)| s + v.len() as u64 > pos);
            let Some((&s, v)) = hit else { return Err(nofile()) };
            let ve = s + v.len() as u64;
            let n = (ve.min(end) - pos) as usize;
            out[(pos - off) as usize..(pos - off) as usize + n]
                .copy_from_slice(&v[(pos - s) as usize..(pos - s) as usize + n]);
            pos += n as u64;
        }
        Ok(())
    }

    /// Present sub-ranges of `[off, off+len)` in volume offsets, merged.
    fn intervals(&self, off: u64, len: u64) -> Vec<(u64, u64)> {
        let st = self.state.lock().unwrap();
        let end = off + len;
        let mut ivs: Vec<(u64, u64)> = Vec::new();
        let frontier = st.data.len() as u64;
        if off < frontier {
            ivs.push((off, frontier.min(end)));
        }
        for (&s, v) in st.pending.range(..end) {
            let a = off.max(s);
            let b = end.min(s + v.len() as u64);
            if a < b {
                ivs.push((a, b));
            }
        }
        ivs.sort_unstable();
        let mut out: Vec<(u64, u64)> = Vec::new();
        for (a, b) in ivs {
            if let Some(last) = out.last_mut()
                && a <= last.1
            {
                last.1 = last.1.max(b);
                continue;
            }
            out.push((a, b));
        }
        out
    }

    /// Consume the retained bytes for demotion: the frontier moves out as
    /// one span, parked spans follow as-is. The buffer is empty after.
    fn take_spans(&self) -> Vec<(u64, Vec<u8>)> {
        let mut st = self.state.lock().unwrap();
        let mut out: Vec<(u64, Vec<u8>)> = Vec::new();
        let data = std::mem::take(&mut st.data);
        if !data.is_empty() {
            out.push((0, data));
        }
        for (s, v) in std::mem::take(&mut st.pending) {
            out.push((s, v));
        }
        st.stored = 0;
        out
    }

    /// Declared total size (the level-N entry's unpacked size).
    fn total(&self) -> u64 {
        self.state.lock().unwrap().total
    }

    /// Blocking RANDOM-ACCESS read for the 7z chase. The trait method
    /// below blocks on the contiguous frontier (the RAR decode is
    /// forward-only); 7z seeks - its footer must be readable long
    /// before the frontier reaches it. Serves the longest available
    /// run at `offset` from frontier or parked bytes, blocks while
    /// `offset` sits in a hole, `Ok(0)` at the declared end, error
    /// after abort.
    fn read_covered_blocking(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut st = self.state.lock().unwrap();
        loop {
            if let Some(reason) = &st.abort {
                return Err(io::Error::other(format!("chase source aborted: {reason}")));
            }
            if offset >= st.total {
                return Ok(0);
            }
            let frontier = st.data.len() as u64;
            if offset < frontier {
                let start = offset as usize;
                let take = buf.len().min(st.data.len() - start);
                buf[..take].copy_from_slice(&st.data[start..start + take]);
                return Ok(take);
            }
            let hit = st
                .pending
                .range(..=offset)
                .next_back()
                .filter(|&(&s, v)| s + v.len() as u64 > offset);
            if let Some((&s, v)) = hit {
                let a = (offset - s) as usize;
                let take = buf.len().min(v.len() - a);
                buf[..take].copy_from_slice(&v[a..a + take]);
                return Ok(take);
            }
            st = self.arrived.wait(st).unwrap();
        }
    }
}

/// Blocking Read+Seek over a chased slot's frontier buffer - the view
/// the 7z engine parses and decodes through. Reads block until the
/// requested bytes arrive (the initial footer reads block only until
/// the promoted tail lands); Seek is pure position arithmetic against
/// the declared size, so seeking never blocks.
struct BlockingSeekReader {
    buf: Arc<FrontierBuffer>,
    pos: u64,
    total: u64,
}

impl io::Read for BlockingSeekReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let n = self.buf.read_covered_blocking(self.pos, out)?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl io::Seek for BlockingSeekReader {
    fn seek(&mut self, pos: io::SeekFrom) -> io::Result<u64> {
        let target = match pos {
            io::SeekFrom::Start(o) => o as i128,
            io::SeekFrom::End(d) => self.total as i128 + d as i128,
            io::SeekFrom::Current(d) => self.pos as i128 + d as i128,
        };
        if target < 0 || target > u64::MAX as i128 {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "seek out of range"));
        }
        self.pos = target as u64;
        Ok(self.pos)
    }
}

/// 7z container magic at offset 0.
const SEVENZ_MAGIC: &[u8] = &[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];

/// Parse the 32-byte 7z start header: `(end-header offset, size)`,
/// CRC-checked - the offsets are relative to byte 32, so the end header
/// (the archive map, which 7z keeps at the TAIL) occupies
/// `[32 + offset, 32 + offset + size)`. None for anything that is not a
/// well-formed single-container start.
fn sevenz_start_header(data: &[u8]) -> Option<(u64, u64)> {
    if data.len() < 32 || !data.starts_with(SEVENZ_MAGIC) {
        return None;
    }
    let crc = u32::from_le_bytes(data[8..12].try_into().unwrap());
    if crc32fast::hash(&data[12..32]) != crc {
        return None;
    }
    let off = u64::from_le_bytes(data[12..20].try_into().unwrap());
    let size = u64::from_le_bytes(data[20..28].try_into().unwrap());
    Some((off, size))
}

/// The RAR engine reads chased volumes through this: block at the
/// frontier, `Ok(0)` only at the declared end, error after abort.
impl rars::BlockingRangeSource for FrontierBuffer {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut st = self.state.lock().unwrap();
        loop {
            if let Some(reason) = &st.abort {
                return Err(io::Error::other(format!("chase source aborted: {reason}")));
            }
            let frontier = st.data.len() as u64;
            if offset < frontier {
                let start = offset as usize;
                let take = buf.len().min(st.data.len() - start);
                buf[..take].copy_from_slice(&st.data[start..start + take]);
                return Ok(take);
            }
            if offset >= st.total {
                return Ok(0);
            }
            st = self.arrived.wait(st).unwrap();
        }
    }

    fn known_len(&self) -> u64 {
        self.state.lock().unwrap().data.len() as u64
    }

    fn total_len(&self) -> Option<u64> {
        Some(self.state.lock().unwrap().total)
    }
}

/// Per-slot chase attachment: the slot's volume bytes live here (instead
/// of holds / a writer) while the chase runs. `charged` is what this
/// buffer currently holds against the shared budget.
struct ChaseSlot {
    buf: Arc<FrontierBuffer>,
    charged: usize,
}

/// One chase = one compressed inner archive (one group): its registered
/// volume buffers, the worker driving the streaming decode, and the
/// bookkeeping the demote path needs to unwind cleanly.
struct ChaseCtl {
    shared: Mutex<ChaseShared>,
    cv: Condvar,
    worker: Mutex<Option<std::thread::JoinHandle<()>>>,
    /// Child-extractor slots the sink opened for extracted members -
    /// abandoned (partial outputs deleted) if the chase demotes.
    sink_slots: Mutex<Vec<usize>>,
    /// Member name -> unpacked size, recorded as each volume parses (the
    /// engine's open callback doesn't carry the size, the headers do).
    sizes: Mutex<HashMap<String, u64>>,
}

#[derive(Default)]
struct ChaseShared {
    /// Volume index -> (buffer, declared volume size).
    vols: BTreeMap<usize, (Arc<FrontierBuffer>, u64)>,
    /// Download over: an index past the registered set means "no more
    /// volumes" rather than "not arrived yet".
    no_more: bool,
    /// Demoted/cancelled: the worker unblocks with an error.
    aborted: bool,
    /// The worker's exit status, set exactly once before it returns.
    outcome: Option<Result<(), String>>,
}

impl ChaseCtl {
    fn new() -> ChaseCtl {
        ChaseCtl {
            shared: Mutex::new(ChaseShared::default()),
            cv: Condvar::new(),
            worker: Mutex::new(None),
            sink_slots: Mutex::new(Vec::new()),
            sizes: Mutex::new(HashMap::new()),
        }
    }

    /// Stop the worker: abort every registered buffer and flag the state
    /// so a wait for an unregistered volume wakes with an error. Join
    /// happens later, off-lock (finish / drop).
    fn abort(&self, reason: &str) {
        let mut st = self.shared.lock().unwrap();
        st.aborted = true;
        for (buf, _) in st.vols.values() {
            buf.abort(reason);
        }
        drop(st);
        self.cv.notify_all();
    }
}

/// One 7z chase = one inner .7z file (one child slot): the slot's
/// in-flight bytes, the worker driving the 7z engine over them, and the
/// bookkeeping the demote path needs to unwind cleanly. Single-file
/// containers only - a multipart `.7z.001` part's end header lies past
/// its own bytes, so multipart sets never attach (v1 limitation: the
/// parts materialize and the disk post-pass joins and extracts them).
struct SevenZCtl {
    buf: Arc<FrontierBuffer>,
    worker: Mutex<Option<std::thread::JoinHandle<()>>>,
    /// Child-extractor slots the sink opened for extracted entries -
    /// abandoned (partial outputs deleted) if the chase demotes.
    sink_slots: Mutex<Vec<usize>>,
    /// The worker's exit status, set exactly once before it returns.
    outcome: Mutex<Option<Result<(), String>>>,
}

/// The chase's routing-seam sink: extracted member bytes stream into a
/// slot of the nested child extractor, whose offset-0 sniff classifies
/// them - a store RAR below the compressed layer keeps streaming, plain
/// payloads land as ordinary files. Writes are sequential from 0.
struct ChaseSink {
    child: Arc<Extractor>,
    slot: usize,
    name: String,
    size: u64,
    pos: u64,
}

impl io::Write for ChaseSink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.child
            .write(self.slot, &self.name, self.size, self.pos, buf)?;
        self.pos += buf.len() as u64;
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Job-wide extraction limits, shared by every level of one nesting
/// chain (like `HoldsBudget`), so a bomb split across nested archives or
/// many inner files can never hand itself a fresh allowance.
///
/// Both numbers default to "no limit", so an `Extractor` built without
/// them behaves exactly as it did before they existed.
#[derive(Debug)]
pub struct Limits {
    /// PREALLOCATION ceiling for inner-file writers. An inner file's
    /// declared `unpacked_size` is an attacker-controlled RAR header
    /// vint, and on Linux preallocation is a real `fallocate` - so a
    /// few-hundred-KB post could reserve the whole volume until the
    /// finish-time gates demoted it. The defensible bound is the NZB's
    /// own posted byte count: a STORE archive cannot legitimately unpack
    /// to more than what was posted. Applied to the RESERVATION only -
    /// never to `FileWriter.size`, which feeds resume truncation and the
    /// reported extracted size (see `disk::preallocate_capped`).
    prealloc_cap: AtomicU64,
    /// Distinct extracted bytes the whole chain may write - the in-stream
    /// half of the decompression-bomb guard the disk/post-pass sinks have
    /// always had. Separate from `prealloc_cap` on purpose: one bounds a
    /// reservation and is deliberately soft (writes past it still
    /// succeed), the other bounds bytes actually landed and is hard.
    budget: Arc<crate::disk::WriteBudget>,
}

impl Limits {
    fn unlimited() -> Limits {
        Limits {
            prealloc_cap: AtomicU64::new(u64::MAX),
            budget: Arc::new(crate::disk::WriteBudget::unlimited()),
        }
    }

    fn prealloc_cap(&self) -> u64 {
        self.prealloc_cap.load(Ordering::Relaxed)
    }
}

pub struct Extractor {
    out_dir: PathBuf,
    enabled: bool,
    /// Crash-resume: open existing files without truncating.
    resume: bool,
    /// Nesting level: 0 = the top-level extractor over the download's
    /// volume slots, +1 per child. A child created AT the depth cap
    /// (`inner.nested_max_depth`) is disabled (everything materializes
    /// Plain).
    depth: usize,
    /// The extractor one level up (dead for the root, and for children
    /// created before the root's [`Self::set_promote_hook`] anchored the
    /// chain). Carries the tail-prefetch promote walk: a child's file
    /// ranges translate level by level up to the root's hook.
    parent: Weak<Extractor>,
    /// What this set turned out to be, shared with every nested level.
    /// Deliberately outside `inner`: the daemon polls it once a second
    /// while the routing lock is the hot path.
    shape: Arc<ShapeLatch>,
    inner: Mutex<Inner>,
}

struct Inner {
    slots: Vec<Slot>,
    groups: HashMap<String, Group>,
    /// Inner-file name → canonical group key. Entries are added when a
    /// split piece links a name to an archive; following the chain maps
    /// any name to the group that owns it.
    alias: HashMap<String, String>,
    /// Extracted inner-file writers, keyed by OUTPUT filename (see
    /// `Group::out_names` for the entry-name → output-name step).
    inner_writers: HashMap<String, Arc<FileWriter>>,
    /// M15: held-span budget, SHARED down the child chain (nested holds
    /// charge the same slice; beyond it groups spill to materialized
    /// volumes).
    budget: Arc<HoldsBudget>,
    /// Preallocation ceiling + extracted-byte budget, SHARED down the
    /// child chain (see [`Limits`]).
    limits: Arc<Limits>,
    /// Output-name claims, SHARED down the child chain so name
    /// disambiguation spans nesting levels (a child's plain file must not
    /// collide with a parent-level output). Leaf lock: only ever taken
    /// with no other lock acquired after it.
    names_taken: Arc<Mutex<std::collections::HashSet<String>>>,
    /// Whether `names_taken` keys are case-folded, i.e. whether the OUTPUT
    /// VOLUME is case-insensitive. Probed once at the root and threaded down
    /// with `names_taken` so every level keys that shared set the same way.
    fold_names: bool,
    /// Lazily-created nested child extractor (level+1 inner files become
    /// its slots).
    child: Option<Arc<Extractor>>,
    /// Child forwards queued by under-the-lock re-feed paths; delivered
    /// by `flush_pending_fwd` after the lock drops.
    pending_fwd: Vec<FwdJob>,
    /// Nested routing gate (env escape hatch / rollout setting). With it
    /// off, level-1 inner files write directly to disk as before the
    /// child path existed.
    nested_on: bool,
    /// Chasing-decompressor gate (`NZBFAST_NO_NESTED_CHASE` / runtime
    /// setter). Off: a compressed inner archive demotes to a
    /// materialized file exactly as before the chase existed.
    chase_on: bool,
    /// 7z-chase gate (`NZBFAST_NO_NESTED_7Z` / runtime setter). Off: an
    /// inner .7z materializes exactly as before the 7z path existed.
    sevenz_on: bool,
    /// Nested depth cap for this chain: the child created AT this depth is
    /// disabled, so the deepest layer materializes (never a hard failure).
    /// Resolved from the daemon setting / env at construction and inherited
    /// unchanged by every child. See [`nested_depth_cap`].
    nested_max_depth: usize,
    /// Final-output CRC gate (`NZBFAST_NO_OUTPUT_CRC` / runtime setter).
    /// On (the default): level 0 composes and checks its store payloads'
    /// header CRCs exactly like the nested levels, so a payload the
    /// poster packed damaged (outer PAR2 accepts it as-posted) demotes
    /// to materialized volumes instead of shipping silently corrupt.
    /// Off: level 0 skips composition and the check, today's behavior.
    verify_output_crc: bool,
    /// Tail-prefetch promote hook, installed on the ROOT only (main.rs
    /// wires it to the seek/promote ladder). Levels below reach it by
    /// walking `parent` and translating ranges as they go.
    promote: Option<PromoteHook>,
    /// Weak self-handle (set by `ensure_child` - only children chase, and
    /// children are always Arc-owned). The chase worker upgrades per
    /// callback so a cancelled extractor can actually drop: its Drop
    /// aborts the buffers and the worker's next upgrade fails.
    self_weak: Weak<Extractor>,
    extracted_bytes: u64,
    /// Fallbacks of slots that never joined a group (blocker before any
    /// entry parsed) - reported alongside group fallbacks.
    slot_fallbacks: Vec<(String, String)>,
    /// Slot bytes come from real files in `out_dir` (re-extraction): a
    /// fallback must never create a slot writer - `FileWriter::create`
    /// truncates, and the slot's name IS the source file being read.
    /// Fallback slots discard instead; the sources are the deliverable.
    protect_sources: bool,
    /// Archive password (M23a plumbing): lets mappers accept RAR5
    /// encrypted headers / encrypted store entries. The ciphertext is
    /// assembled at the usual store offsets and decrypted in one pass at
    /// finish - during the download the inner files hold volume-exact
    /// bytes, so verifier read-back and fallback reconstruction are
    /// untouched by encryption.
    password: Option<std::sync::Arc<str>>,
    /// Per-encrypted-output stream lifecycle (out name → shared state),
    /// created on first /stream open or at the finish decrypt.
    stream_states: HashMap<String, Arc<StreamState>>,
    /// Publish gate for the finish decrypt, inherited by every child (a
    /// nested level's outputs are journal recovery sources too). See
    /// [`DecryptBarrier`].
    decrypt_barrier: Option<DecryptBarrier>,
    /// Plaintext-once gate (see [`CryptoState`]): encrypted store
    /// entries decrypt at write time instead of assembling ciphertext
    /// for the finish pass. `NZBFAST_NO_INSTREAM_DECRYPT=1` restores
    /// the legacy path.
    instream_decrypt: bool,
    /// In-stream decrypt state per OUTPUT name (same key space as
    /// `inner_writers`). Presence marks the file plaintext-on-disk:
    /// posted-bytes readers go through [`CryptoState::read_posted`],
    /// its articles journal as `D` records (restorable only by
    /// re-encryption), and the finish decrypt skips it.
    crypto_files: HashMap<String, Arc<CryptoState>>,
    /// Resume-journal events from every [`CryptoState`] in the chain
    /// (children share it like the holds budget); drained by
    /// [`Extractor::drain_crypto_events`].
    crypto_events: CryptoEventSink,
}

impl Extractor {
    /// `n_slots` = number of slots in the download; `enabled=false` makes
    /// every slot Plain (the pre-M3 behavior, e.g. --no-extract).
    pub fn new(out_dir: &Path, n_slots: usize, enabled: bool) -> Extractor {
        Self::with_resume(out_dir, n_slots, enabled, false)
    }

    /// Plaintext-once override (tests + future daemon setting): pin the
    /// in-stream decrypt gate regardless of the env default. Only
    /// meaningful before the first encrypted span arrives; existing
    /// [`CryptoState`]s are not torn down. Never enables on a resume or
    /// disabled extractor (in-stream mapping is off there anyway).
    pub fn set_instream_decrypt(&self, on: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.instream_decrypt = on && self.enabled && !self.resume;
    }

    /// M15: set the held-span budget slice (spill: materialize volumes).
    /// The budget is shared with any nested children.
    pub fn set_holds_cap(&self, cap: usize) {
        self.inner
            .lock()
            .unwrap()
            .budget
            .cap
            .store(cap.max(8 << 20), Ordering::Relaxed);
    }

    /// Ceiling on how much space an inner-file writer may RESERVE, shared
    /// by every nesting level (see [`Limits::prealloc_cap`]). Pass the
    /// NZB's posted byte count: a store archive cannot legitimately unpack
    /// to more than what was posted, and preallocation past the ceiling is
    /// only an optimisation the writer does without.
    ///
    /// Safe to set at any time - the Arc is shared with children, and it
    /// is read per writer creation.
    pub fn set_prealloc_ceiling(&self, bytes: u64) {
        self.inner
            .lock()
            .unwrap()
            .limits
            .prealloc_cap
            .store(bytes, Ordering::Relaxed);
    }

    /// Cap the DISTINCT extracted bytes this chain may write - the
    /// in-stream half of the decompression-bomb guard (the disk and
    /// post-pass sinks carry their own `BombGuardWriter` with the same
    /// budget). Shared across nesting levels and across every inner file,
    /// so a bomb split over many outputs cannot restart the allowance.
    pub fn set_extract_budget(&self, bytes: u64) {
        self.inner.lock().unwrap().limits.budget.set_limit(bytes);
    }

    /// Extracted bytes charged against [`Self::set_extract_budget`] so far
    /// (whole chain). Test/diagnostic hook.
    pub fn extract_budget_used(&self) -> u64 {
        self.inner.lock().unwrap().limits.budget.used()
    }

    /// Peak held-span bytes across the whole nesting chain - end-of-run
    /// mem summary (M15).
    pub fn holds_peak(&self) -> usize {
        self.inner.lock().unwrap().budget.peak()
    }

    /// Nested-routing gate (see `NZBFAST_NO_NESTED_ONEPASS`, latched at
    /// construction). Set before any span arrives - routing decisions are
    /// deterministic per inner file and must not flip mid-download.
    pub fn set_nested_one_pass(&self, on: bool) {
        self.inner.lock().unwrap().nested_on = on;
    }

    /// Override this chain's nested depth cap (see [`nested_depth_cap`]).
    /// Set before any child is created - the value is read when a span
    /// first descends a level. Clamped to >= 1. Used by the daemon to
    /// apply a live `nested_max_depth` change and by tests for a
    /// deterministic cap without touching the process-global setting.
    pub fn set_nested_max_depth(&self, depth: usize) {
        self.inner.lock().unwrap().nested_max_depth = depth.max(1);
    }

    /// Chasing-decompressor gate (see `NZBFAST_NO_NESTED_CHASE`, latched
    /// at construction). Same set-before-spans discipline as the nested
    /// routing gate.
    pub fn set_nested_chase(&self, on: bool) {
        self.inner.lock().unwrap().chase_on = on;
    }

    /// 7z-chase gate (see `NZBFAST_NO_NESTED_7Z`, latched at
    /// construction). Same set-before-spans discipline as the other
    /// gates.
    pub fn set_nested_sevenz(&self, on: bool) {
        self.inner.lock().unwrap().sevenz_on = on;
    }

    /// Final-output CRC gate (see `NZBFAST_NO_OUTPUT_CRC`, latched at
    /// construction; default on). Same set-before-spans discipline as
    /// the other gates - composition happens as spans route, so a
    /// mid-download flip would leave gaps that read as "unverifiable"
    /// and skip the check.
    pub fn set_verify_output_crc(&self, on: bool) {
        self.inner.lock().unwrap().verify_output_crc = on;
    }

    /// Install the article-promotion hook (nested 7z tail prefetch): the
    /// daemon wires this to its seek/promote ladder, so a child extractor
    /// that classifies an inner .7z can front-load the articles carrying
    /// its end header. Composition runs child -> parent through
    /// [`Self::promote_file`], translating each level's file ranges
    /// through the level above (all-store levels only; a compressed level
    /// in between yields no mapping and the promote is skipped - the
    /// chase reaches those bytes sequentially anyway). Install before any
    /// span arrives, like the gates - it also anchors the chain's root
    /// for the upward walk.
    pub fn set_promote_hook(self: &Arc<Self>, hook: PromoteHook) {
        let mut inner = self.inner.lock().unwrap();
        inner.self_weak = Arc::downgrade(self);
        inner.promote = Some(hook);
    }

    /// Re-extraction mode: slot bytes are fed from real volume files in
    /// `out_dir`, so no fallback may ever materialize a slot writer (it
    /// would truncate the very file being read). Fallback slots discard.
    pub fn set_protect_sources(&self) {
        self.inner.lock().unwrap().protect_sources = true;
    }

    /// Archive password for encrypted RAR5 store sets. Set before any
    /// span is written - mappers capture it at slot classification.
    pub fn set_password(&self, pw: &str) {
        self.inner.lock().unwrap().password = Some(std::sync::Arc::from(pw));
    }

    /// Install the finish-decrypt publish gate (see [`DecryptBarrier`]).
    /// Set it before `finish()`; children created afterwards inherit it,
    /// and children created earlier are updated too, so wiring order at
    /// the call site can't leave a level ungated.
    pub fn set_decrypt_barrier(&self, barrier: DecryptBarrier) {
        let child = {
            let mut inner = self.inner.lock().unwrap();
            inner.decrypt_barrier = Some(barrier.clone());
            inner.child.clone()
        };
        if let Some(c) = child {
            c.set_decrypt_barrier(barrier);
        }
    }

    pub fn with_resume(out_dir: &Path, n_slots: usize, enabled: bool, resume: bool) -> Extractor {
        Self::build(
            out_dir,
            n_slots,
            enabled,
            resume,
            0,
            Weak::new(),
            Arc::new(HoldsBudget::new(HOLDS_DEFAULT_CAP)),
            Arc::new(Limits::unlimited()),
            Arc::new(Mutex::new(Default::default())),
            crate::disk::case_insensitive_dir(out_dir),
            !nested_env_off(),
            !chase_env_off(),
            !sevenz_env_off(),
            nested_depth_cap(),
            !output_crc_env_off(),
            None,
            Arc::new(ShapeLatch::default()),
        )
    }

    /// Full constructor - the public ctors and `ensure_child` both land
    /// here. Children share the parent's holds budget and name claims.
    #[allow(clippy::too_many_arguments)]
    fn build(
        out_dir: &Path,
        n_slots: usize,
        enabled: bool,
        resume: bool,
        depth: usize,
        parent: Weak<Extractor>,
        budget: Arc<HoldsBudget>,
        limits: Arc<Limits>,
        names_taken: Arc<Mutex<std::collections::HashSet<String>>>,
        fold_names: bool,
        nested_on: bool,
        chase_on: bool,
        sevenz_on: bool,
        nested_max_depth: usize,
        verify_output_crc: bool,
        password: Option<std::sync::Arc<str>>,
        shape: Arc<ShapeLatch>,
    ) -> Extractor {
        Extractor {
            out_dir: out_dir.to_path_buf(),
            enabled,
            resume,
            depth,
            parent,
            shape,
            inner: Mutex::new(Inner {
                slots: (0..n_slots).map(|_| Self::new_slot()).collect(),
                groups: HashMap::new(),
                alias: HashMap::new(),
                inner_writers: HashMap::new(),
                budget,
                limits,
                names_taken,
                fold_names,
                child: None,
                pending_fwd: Vec::new(),
                nested_on,
                chase_on,
                sevenz_on,
                nested_max_depth: nested_max_depth.max(1),
                verify_output_crc,
                promote: None,
                self_weak: Weak::new(),
                extracted_bytes: 0,
                slot_fallbacks: Vec::new(),
                protect_sources: false,
                password,
                stream_states: HashMap::new(),
                decrypt_barrier: None,
                // Plaintext-once gate: on for a live (enabled, fresh)
                // extractor unless the env kill-switch restores the
                // legacy ciphertext-then-finish-decrypt path. Resume
                // never maps in-stream, so the flag is moot there.
                instream_decrypt: enabled
                    && !resume
                    && std::env::var("NZBFAST_NO_INSTREAM_DECRYPT").map_or(true, |v| v != "1"),
                crypto_files: HashMap::new(),
                crypto_events: Arc::new(Mutex::new(Vec::new())),
            }),
        }
    }

    /// What this download's archives turned out to be, as far as the
    /// mappers and the routing have got. `None` until something
    /// archive-shaped is recognized (loose files never report a shape).
    ///
    /// Safe to call from any thread at any time - it reads the latch, not
    /// the routing lock - and it is the same answer during the download
    /// and after finish(), so the live badge and the history entry agree.
    pub fn archive_shape(&self) -> Option<ArchiveShape> {
        let (outer, nested) = self.shape.snapshot();
        ArchiveShape::from_bits(outer, nested)
    }

    /// Drain the chain's pending resume-journal crypto events (`E`/`K`/
    /// `T` facts - see [`CryptoJournalEvent`]). The caller writes them to
    /// the journal alongside the `D` placement records.
    pub fn drain_crypto_events(&self) -> Vec<CryptoJournalEvent> {
        let sink = self.inner.lock().unwrap().crypto_events.clone();
        let mut ev = sink.lock().unwrap();
        std::mem::take(&mut *ev)
    }

    /// Whether every plaintext-once fragment of a `PlacedCrypto` span is
    /// physically on disk (seams resolved, tail padding captured). The
    /// journal writer holds `D` records until this turns true - usually
    /// one neighboring article later - because a record for RAM-held
    /// slivers would survive a kill that the bytes did not.
    pub fn crypto_span_on_disk(&self, frags: &[Frag]) -> bool {
        frags.iter().all(|f| match self.find_crypto(&f.file) {
            Some(cs) => cs.plain_on_disk(f.file_off, f.len),
            None => true,
        })
    }

    /// Which fragments of a span landed in plaintext-once files. Rides
    /// into the `D` record so a resume knows which fragments restore by
    /// re-encryption and which are ordinary copies - a crypto fragment
    /// whose facts are missing must fail, never fall through to a copy.
    pub fn crypto_frag_mask(&self, frags: &[Frag]) -> Vec<bool> {
        frags.iter().map(|f| self.find_crypto(&f.file).is_some()).collect()
    }

    fn find_crypto(&self, name: &str) -> Option<Arc<CryptoState>> {
        let inner = self.inner_read();
        if let Some(cs) = inner.crypto_files.get(name) {
            return Some(cs.clone());
        }
        let child = inner.child.clone();
        drop(inner);
        child.and_then(|c| c.find_crypto(name))
    }

    fn new_slot() -> Slot {
        Slot {
            mode: SlotMode::Unknown,
            name: String::new(),
            size: 0,
            holds: Vec::new(),
            pre_bytes: 0,
            writer: None,
            mapper: None,
            header_spans: Vec::new(),
            group: None,
            chase: None,
            sevenz: None,
            piece_crcs: HashMap::new(),
        }
    }

    /// Dynamically add a slot (nested routing: every level-1 inner file
    /// becomes one slot of the child extractor). Returns its index.
    pub fn alloc_slot(&self) -> usize {
        let mut inner = self.inner.lock().unwrap();
        inner.slots.push(Self::new_slot());
        inner.slots.len() - 1
    }

    /// The nested child extractor, created on first use. Shares the holds
    /// budget, the name claims, the password, and the routing gate; a
    /// child AT the depth cap is created disabled, so every deeper file
    /// simply materializes Plain.
    fn ensure_child(&self, inner: &mut Inner) -> Arc<Extractor> {
        if inner.child.is_none() {
            let depth = self.depth + 1;
            let child = Arc::new(Self::build(
                &self.out_dir,
                0,
                depth < inner.nested_max_depth,
                self.resume,
                depth,
                inner.self_weak.clone(),
                inner.budget.clone(),
                inner.limits.clone(),
                inner.names_taken.clone(),
                inner.fold_names,
                inner.nested_on,
                inner.chase_on,
                inner.sevenz_on,
                inner.nested_max_depth,
                inner.verify_output_crc,
                inner.password.clone(),
                // One latch per chain: the child's observations land in
                // the nested word of the same summary the root publishes.
                self.shape.clone(),
            ));
            {
                let mut ci = child.inner.lock().unwrap();
                // The child knows its own Arc (weakly): the chase worker
                // reaches its extractor through this without pinning it.
                ci.self_weak = Arc::downgrade(&child);
                // A nested level decrypts its own encrypted store outputs
                // at ITS finish, and those files are journal recovery
                // sources exactly like the parent's - same gate.
                ci.decrypt_barrier = inner.decrypt_barrier.clone();
                // One event sink per chain: a nested encrypted output's
                // E/K/T records drain through the root exactly like its
                // placements fold into the root's frags.
                ci.crypto_events = inner.crypto_events.clone();
            }
            inner.child = Some(child);
        }
        inner.child.clone().unwrap()
    }

    /// Write one decoded span. `name`/`size` from the yEnc header.
    ///
    /// The global lock covers only routing/mapping decisions - the actual
    /// `pwrite`s run after it drops, so concurrent decoders don't
    /// serialize on disk I/O (measured: the locked-write version capped
    /// `get` ~2 Gbps below the network on London).
    ///
    /// Returns [`Persist::Placed`] with the physical fragments when EVERY
    /// byte of the span is durably on disk after this call - at its final
    /// offset in a plain/materialized file, or translated into an
    /// extracted inner file. Held spans, retained header bytes, and
    /// discards return [`Persist::No`] (their articles refetch on resume).
    pub fn write(
        &self,
        slot: usize,
        name: &str,
        size: u64,
        offset: u64,
        data: &[u8],
    ) -> io::Result<Persist> {
        self.write_impl(slot, name, size, offset, data, false, None)
    }

    /// [`Self::write`] carrying what the decode established about this
    /// article: `article_crc` is the pcrc32 that was present, calculated
    /// and MATCHED, over exactly `data`. Passing it lets a STORE span
    /// that is byte-for-byte this article compose from the verified value
    /// instead of hashing the same bytes a second time. `None` is always
    /// safe and simply hashes.
    pub fn write_verified(
        &self,
        slot: usize,
        name: &str,
        size: u64,
        offset: u64,
        data: &[u8],
        article_crc: Option<u32>,
    ) -> io::Result<Persist> {
        self.write_impl(slot, name, size, offset, data, false, article_crc)
    }

    /// [`Self::write`] with the repair marker: `repair` says this span is
    /// a mapped-repair rewrite (patch_volume_span), whose bytes may
    /// DIFFER from an earlier arrival of the same range. Everything on
    /// disk overwrites naturally; the piece-CRC composition is the one
    /// consumer that must be told, or it keeps the stale pre-repair
    /// value (first-writer-wins) and the finish gate demotes a job whose
    /// output healed cleanly.
    fn write_impl(
        &self,
        slot: usize,
        name: &str,
        size: u64,
        offset: u64,
        data: &[u8],
        repair: bool,
        article_crc: Option<u32>,
    ) -> io::Result<Persist> {
        let mut jobs: Vec<WriteJob> = Vec::new();
        let mut fwd: Vec<FwdSpan> = Vec::new();
        let mut pending: Vec<FwdJob> = Vec::new();
        let mut routed_rar = false;
        {
            let mut g = self.inner.lock().unwrap();
            let inner = &mut *g;
            {
                let s = &mut inner.slots[slot];
                if s.name.is_empty() && !name.is_empty() {
                    s.name = name.to_string();
                }
                if s.size == 0 {
                    s.size = size;
                }
            }

            match inner.slots[slot].mode {
                SlotMode::Unknown => {
                    if !self.enabled {
                        // No mapping possible - no reason to wait for the
                        // offset-0 sniff (crucial on resume, where segment
                        // 1 may never be refetched).
                        inner.slots[slot].mode = SlotMode::Plain;
                        self.plain_job(inner, slot, offset, data, &mut jobs)?;
                        self.drain_holds(inner, slot)?;
                    } else if offset != 0 {
                        inner.budget.add(data.len());
                        inner.slots[slot].pre_bytes += data.len();
                        inner.slots[slot].holds.push((offset, data.to_vec()));
                        let spill =
                            inner.slots[slot].pre_bytes > unclassified_spill(inner.budget.cap());
                        if inner.budget.over() {
                            self.overflow_to_plain(inner)?;
                        } else if spill {
                            // The offset-0 sniff hasn't arrived after this
                            // much of the slot - synthesized segment
                            // numbering can put it anywhere in the queue.
                            // Give up mapping THIS slot: plain writes are
                            // always correct (a real RAR volume simply
                            // materializes on disk, the pre-M3 behavior),
                            // while holding on livelocks the pipeline in
                            // RAM with nothing on disk, in stats, or in
                            // the journal.
                            self.spill_unclassified_slot(inner, slot)?;
                        }
                        return Ok(Persist::No);
                    } else {
                        let is_rar = data.starts_with(b"Rar!\x1a\x07\x01\x00")
                            || data.starts_with(b"Rar!\x1a\x07\x00");
                        if is_rar {
                            inner.slots[slot].mode = SlotMode::Rar;
                            routed_rar = true;
                            let size = inner.slots[slot].size;
                            inner.slots[slot].mapper =
                                Some(VolumeMapper::with_password(size, inner.password.clone()));
                            self.rar_span(
                                inner,
                                slot,
                                offset,
                                data,
                                Some((&mut jobs, &mut fwd)),
                                repair,
                                article_crc,
                            )?;
                        } else if self.try_attach_sevenz(inner, slot, data)? {
                            // Phase 3: an inner .7z gets the tail-prefetch
                            // chase - this span (and everything held) feeds
                            // its frontier buffer.
                            self.shape.note(self.depth, SH_7Z | SH_ONE_PASS);
                            self.chase_span(inner, slot, offset, data)?;
                        } else if inner.protect_sources {
                            // A supposed volume that isn't RAR: writing it
                            // out plain would truncate the source file.
                            let name = inner.slots[slot].name.clone();
                            inner.slot_fallbacks.push((name, "not a RAR volume".to_string()));
                            self.discard_slot(inner, slot);
                            return Ok(Persist::No);
                        } else {
                            if data.starts_with(b"7z\xbc\xaf\x27\x1c") {
                                // A .7z the chase can't take (top level, a
                                // multipart .001, gate off): it lands on
                                // disk for the post-pass, and the badge
                                // should say so rather than say nothing.
                                self.shape.note(self.depth, SH_7Z | SH_MATERIALIZED);
                            }
                            inner.slots[slot].mode = SlotMode::Plain;
                            self.plain_job(inner, slot, offset, data, &mut jobs)?;
                        }
                        self.drain_holds(inner, slot)?;
                    }
                }
                SlotMode::Plain | SlotMode::RarFallback => {
                    self.plain_job(inner, slot, offset, data, &mut jobs)?;
                }
                SlotMode::Rar => {
                    routed_rar = true;
                    self.rar_span(
                        inner,
                        slot,
                        offset,
                        data,
                        Some((&mut jobs, &mut fwd)),
                        repair,
                        article_crc,
                    )?;
                }
                // Chased slot (RAR or 7z): the span feeds the frontier
                // buffer (RAM, budget-charged) - not on disk, so never
                // journalable.
                SlotMode::RarChase | SlotMode::SevenZ => {
                    self.chase_span(inner, slot, offset, data)?
                }
                SlotMode::Discard => return Ok(Persist::No),
            }
            if !fwd.is_empty() || !inner.pending_fwd.is_empty() {
                pending = std::mem::take(&mut inner.pending_fwd);
            }
        }
        for j in &jobs {
            let part = &data[j.src_start..j.src_start + j.len];
            match &j.crypto {
                // The AES runs here, outside the routing lock, under the
                // file's own crypto mutex.
                Some(cs) if j.repair => cs.patch(&j.writer, j.file_off, part)?,
                Some(cs) => cs.ingest(&j.writer, j.file_off, part)?,
                None => j.writer.write_at(j.file_off, part)?,
            }
        }
        // Owned forwards queued by the re-feed paths inside the lock
        // (drain_holds / reresolve) deliver now, then this span's own
        // forwards. Each child call runs lock-free here and returns the
        // child's Persist for the frag composition below.
        if !pending.is_empty() {
            self.deliver_fwd(pending)?;
        }
        let mut fwd_persist: Vec<Persist> = Vec::with_capacity(fwd.len());
        for f in &fwd {
            fwd_persist.push(self.deliver_routed(
                slot,
                offset + f.src_start as u64,
                &f.name,
                f.size,
                f.file_off,
                &data[f.src_start..f.src_start + f.len],
                f.repair,
            )?);
        }
        // The pwrites above ran without the lock. If a fallback flipped
        // this slot meanwhile, its read-back could not see these bytes
        // (interval-gated) and may already have unlinked the inner files
        // the jobs targeted - so the materialized volume is missing this
        // span. Re-route it through the slot's current mode: duplicate
        // writes are harmless, a lost span is silent corruption. The
        // journal skips the article (Persist::No) - its fragments may
        // name just-deleted inner files, and a refetch on resume is the
        // safe outcome for a span that raced a fallback. Forwards to the
        // child already re-resolved their destination in deliver_routed;
        // the whole-span rewrite here duplicates their bytes into the
        // materialized volume, which is harmless (identical offsets,
        // identical bytes).
        if routed_rar && (!jobs.is_empty() || !fwd.is_empty()) {
            let mut g = self.inner.lock().unwrap();
            let inner = &mut *g;
            if matches!(inner.slots[slot].mode, SlotMode::RarFallback) {
                self.plain_span(inner, slot, offset, data)?;
                return Ok(Persist::No);
            }
        }
        // Spans that fed an in-stream-decrypted file journal as `D`
        // records (restore-by-re-encryption), never as `R` - a plain
        // copy of the plaintext into a volume file would rebuild
        // silently corrupt volumes on a downgrade resume.
        let crypto_span = jobs.iter().any(|j| j.crypto.is_some());
        // Journalable only if the queued writes cover the whole span - a
        // span partially held (or with header bytes kept in memory) is not
        // fully on disk and must refetch on resume.
        let mut frags: Vec<Frag> = jobs
            .iter()
            .map(|j| Frag {
                file: j
                    .writer
                    .path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned(),
                file_off: j.file_off,
                vol_off: offset + j.src_start as u64,
                len: j.len as u64,
            })
            .collect();
        // Fold the child placements in: a child frag names a child-level
        // output file (already final for the journal); its vol_off is in
        // the CHILD slot's address space, translated back through the
        // affine forward window. Any child part not fully placed makes
        // the whole article refetch on resume.
        let mut crypto_span = crypto_span;
        for (f, p) in fwd.iter().zip(fwd_persist) {
            let cfrags = match p {
                Persist::No => return Ok(Persist::No),
                Persist::Placed(cfrags) => cfrags,
                // A nested plaintext-once output: the whole article's
                // record must be a D line, since at least one fragment
                // can only restore by re-encryption.
                Persist::PlacedCrypto(cfrags) => {
                    crypto_span = true;
                    cfrags
                }
            };
            for cf in cfrags {
                frags.push(Frag {
                    file: cf.file,
                    file_off: cf.file_off,
                    vol_off: offset + f.src_start as u64 + (cf.vol_off - f.file_off),
                    len: cf.len,
                });
            }
        }
        frags.sort_by_key(|f| f.vol_off);
        let mut covered_to = offset;
        for f in &frags {
            if f.vol_off > covered_to {
                return Ok(Persist::No);
            }
            covered_to = covered_to.max(f.vol_off + f.len);
        }
        if !frags.is_empty() && covered_to >= offset + data.len() as u64 {
            Ok(if crypto_span {
                Persist::PlacedCrypto(frags)
            } else {
                Persist::Placed(frags)
            })
        } else {
            Ok(Persist::No)
        }
    }

    /// Queue a plain write of the whole span (lock held; write happens
    /// after it drops).
    fn plain_job(
        &self,
        inner: &mut Inner,
        slot: usize,
        offset: u64,
        data: &[u8],
        jobs: &mut Vec<WriteJob>,
    ) -> io::Result<()> {
        let w = self.ensure_plain_writer(inner, slot)?;
        jobs.push(WriteJob {
            writer: w,
            file_off: offset,
            src_start: 0,
            len: data.len(),
            crypto: None,
            repair: false,
        });
        Ok(())
    }

    fn ensure_plain_writer(&self, inner: &mut Inner, slot: usize) -> io::Result<Arc<FileWriter>> {
        if inner.slots[slot].writer.is_none() {
            let s = &inner.slots[slot];
            let base = if s.name.is_empty() {
                format!("slot{slot:03}")
            } else {
                s.name.clone()
            };
            let mut fname = sanitize_filename(&base);
            Self::claim_name(inner, slot, &mut fname);
            let path = self.out_dir.join(&fname);
            // The same two bounds as `inner_writer`, and for the same
            // reason: with nested routing on (the default) a group's inner
            // files are forwarded to the CHILD, so a non-archive inner
            // file materializes HERE, at depth > 0, with the slot size the
            // parent forwarded - i.e. the poster's declared
            // `unpacked_size`. At level 0 the slot size comes from the NZB
            // and is below the posted ceiling by construction, so the cap
            // never binds there and preallocation is untouched.
            let size = inner.slots[slot].size;
            let cap = inner.limits.prealloc_cap();
            let w = if self.resume {
                FileWriter::create_resume_capped(&path, size, cap)?
            } else {
                FileWriter::create_capped(&path, size, cap)?
            };
            // Only a NESTED plain file is extraction output. Level 0's
            // plain files are the downloaded volumes themselves, which the
            // disk-path `BombGuardWriter` does not count either.
            let w = if self.depth > 0 {
                w.with_budget(inner.limits.budget.clone())
            } else {
                w
            };
            inner.slots[slot].writer = Some(Arc::new(w));
        }
        Ok(inner.slots[slot].writer.clone().unwrap())
    }

    /// Claim an output filename in the chain-shared set, disambiguating
    /// on collision. Shared with nested children, so a child's plain file
    /// can never silently overwrite (or be overwritten by) another
    /// level's output of the same name.
    fn claim_name(inner: &Inner, slot: usize, out: &mut String) {
        let fold = inner.fold_names;
        let mut names = inner.names_taken.lock().unwrap();
        if names.insert(name_collision_key(fold, out)) {
            return;
        }
        let mut n = 0usize;
        loop {
            let cand = if n == 0 {
                format!("{slot:03}-{out}")
            } else {
                format!("{slot:03}-{n}-{out}")
            };
            if names.insert(name_collision_key(fold, &cand)) {
                *out = cand;
                return;
            }
            n += 1;
        }
    }

    /// Plain write-through under the lock (fallback/drain paths where the
    /// data is locally owned).
    fn plain_span(&self, inner: &mut Inner, slot: usize, offset: u64, data: &[u8]) -> io::Result<()> {
        let w = self.ensure_plain_writer(inner, slot)?;
        w.write_at(offset, data)
    }

    /// Deliver queued child forwards. Never called with the routing lock
    /// held - each job re-resolves its destination in
    /// [`Self::deliver_routed`], so a slot that fell back (or a child
    /// slot a merge displaced) in any window still gets its bytes.
    fn deliver_fwd(&self, pending: Vec<FwdJob>) -> io::Result<()> {
        for j in pending {
            self.deliver_routed(
                j.parent_slot,
                j.vol_off,
                &j.name,
                j.size,
                j.file_off,
                &j.bytes,
                j.repair,
            )?;
        }
        Ok(())
    }

    /// Deliver one routed span to whatever destination the routing map
    /// names NOW, re-resolving under the lock until the write has landed
    /// somewhere still live. Between capture and delivery a group merge
    /// can displace the child slot routing picked and abandon it - a
    /// write into an abandoned slot is silently swallowed while the
    /// span's bytes were already composed into the piece CRCs, so
    /// delivering by stale slot index could let the finish gate vouch
    /// for a hole. The loop is bounded by the number of merges (each
    /// retry means the destination changed again), and duplicate
    /// deliveries land on identical offsets (routing is deterministic),
    /// so retries are harmless. Never called with the routing lock held.
    #[allow(clippy::too_many_arguments)]
    fn deliver_routed(
        &self,
        parent_slot: usize,
        vol_off: u64,
        name: &str,
        size: u64,
        file_off: u64,
        bytes: &[u8],
        repair: bool,
    ) -> io::Result<Persist> {
        enum Target {
            Child(Arc<Extractor>, usize),
            Writer(Arc<FileWriter>),
            Done,
        }
        loop {
            let tgt = {
                let mut g = self.inner.lock().unwrap();
                let inner = &mut *g;
                match inner.slots[parent_slot].mode {
                    SlotMode::Rar => match Self::dest_for(inner, parent_slot, name) {
                        Some(Dest::Child(c, cs)) => Target::Child(c, cs),
                        Some(Dest::Writer(w)) => Target::Writer(w),
                        // The routed entry vanished while the slot still
                        // maps (structurally unexpected): materialize the
                        // slot rather than drop bytes the piece CRCs
                        // already counted.
                        None => {
                            self.fallback_slot_or_group(
                                inner,
                                parent_slot,
                                "routed span lost its destination",
                            )?;
                            if !matches!(inner.slots[parent_slot].mode, SlotMode::Discard) {
                                self.plain_span(inner, parent_slot, vol_off, bytes)?;
                            }
                            Target::Done
                        }
                    },
                    SlotMode::Plain | SlotMode::RarFallback => {
                        self.plain_span(inner, parent_slot, vol_off, bytes)?;
                        Target::Done
                    }
                    // A chase-eligible slot blocks on its FIRST entry, so
                    // it can never have routed a forward while mapped -
                    // nothing to deliver.
                    SlotMode::Unknown
                    | SlotMode::RarChase
                    | SlotMode::SevenZ
                    | SlotMode::Discard => Target::Done,
                }
            };
            match tgt {
                Target::Done => return Ok(Persist::No),
                Target::Writer(w) => {
                    w.write_at(file_off, bytes)?;
                    return Ok(Persist::No);
                }
                Target::Child(c, cs) => {
                    // No article CRC across the boundary: these are mapped
                    // sub-ranges of OUR span, and the child's own article
                    // boundaries are its own.
                    let p = c.write_impl(cs, name, size, file_off, bytes, repair, None)?;
                    let mut g = self.inner.lock().unwrap();
                    let inner = &mut *g;
                    match inner.slots[parent_slot].mode {
                        SlotMode::Rar => {
                            let live = matches!(
                                Self::dest_for(inner, parent_slot, name),
                                Some(Dest::Child(ref c2, cs2)) if Arc::ptr_eq(c2, &c) && cs2 == cs
                            );
                            if live {
                                return Ok(p);
                            }
                            // Displaced mid-delivery - resolve again.
                        }
                        SlotMode::Plain | SlotMode::RarFallback => {
                            self.plain_span(inner, parent_slot, vol_off, bytes)?;
                            return Ok(Persist::No);
                        }
                        _ => return Ok(Persist::No),
                    }
                }
            }
        }
    }

    /// Take and deliver any queued child forwards (public entry points
    /// that may have re-fed holds under the lock call this after it
    /// drops).
    fn flush_pending_fwd(&self) -> io::Result<()> {
        let pending = std::mem::take(&mut self.inner.lock().unwrap().pending_fwd);
        if pending.is_empty() {
            return Ok(());
        }
        self.deliver_fwd(pending)
    }

    /// Mapping-mode span: feed headers, extract mapped parts, hold the
    /// rest. With `sink` set (the hot write path), mapped writes queue as
    /// jobs / child forwards for after the lock; without (drain/fallback
    /// paths), writer writes run inline and child forwards queue as owned
    /// pending jobs (the child cannot be called under our lock).
    fn rar_span(
        &self,
        inner: &mut Inner,
        slot: usize,
        offset: u64,
        data: &[u8],
        sink: Option<(&mut Vec<WriteJob>, &mut Vec<FwdSpan>)>,
        repair: bool,
        article_crc: Option<u32>,
    ) -> io::Result<()> {
        let progressed = inner.slots[slot]
            .mapper
            .as_mut()
            .unwrap()
            .feed(offset, data);
        if progressed {
            // Everything the shape badge reports about the archive itself
            // is known here, the instant the headers parse: the version
            // is a property of the volume, the method and encryption of
            // each entry. Latching only on parse progress keeps this off
            // the per-span path.
            let m = inner.slots[slot].mapper.as_ref().unwrap();
            let mut bits = match m.version {
                Some(RarVersion::V5) => SH_RAR5,
                Some(RarVersion::V4) => SH_RAR4,
                None => 0,
            };
            for e in &m.entries {
                if e.is_dir {
                    continue;
                }
                bits |= match e.method {
                    Method::Store => SH_STORE,
                    Method::Compressed => SH_COMPRESSED,
                };
                if e.encrypted {
                    bits |= SH_ENCRYPTED;
                }
            }
            self.shape.note(self.depth, bits);
        }
        let stashed = self.retain_header_bytes(inner, slot, offset, data);
        // A slot that already carries a blocker takes the blocker's route
        // below instead of this one. Its reason is the specific, actionable
        // one - encrypted headers ask the user for a password, compressed
        // gets a chase - and reporting the budget here in its place turned
        // "this archive needs a password" into a failed job that ran unrar
        // with no password. Deferring cannot leave the budget over: both of
        // those routes release this same charge.
        let blocked = inner.slots[slot].mapper.as_ref().unwrap().blocker.is_some();
        if stashed > 0 && !blocked && inner.budget.over() {
            // The header stash charges the same budget as holds, and it
            // grows on remote data: service blocks (a RAR recovery
            // record) and anything past the end-of-archive marker sit
            // below the parse cursor, so they are kept for the life of
            // the slot - and once the mapper is complete EVERY byte
            // outside a data area lands here. Over the cap the volume
            // materializes, which puts the stash on disk instead of RAM.
            // The reason MUST carry "held-bytes cap": this is that same
            // budget, and both the caller's volume-level remediation and
            // `nested_reason` key off that substring. A novel string
            // would demote the volumes and then ship the job with no
            // payload and exit 0.
            self.fallback_slot_or_group(inner, slot, "held-bytes cap: header stash")?;
            if matches!(inner.slots[slot].mode, SlotMode::Discard) {
                return Ok(());
            }
            return self.plain_span(inner, slot, offset, data);
        }

        if let Some(b) = inner.slots[slot].mapper.as_ref().unwrap().blocker.clone() {
            // A password blocker is the one shape fact no entry scan can
            // reach: nothing parsed, so say "encrypted" from the blocker.
            if matches!(b, MapBlocker::EncryptedHeaders | MapBlocker::BadPassword) {
                self.shape.note(self.depth, SH_ENCRYPTED);
            }
            // Phase 2: a compressed RAR5 inner archive gets a chase
            // instead of a demotion - the slot flips to RarChase, its
            // seen-so-far bytes seed the frontier buffer, and this span
            // (whose header part the parser just consumed) feeds it too.
            if self.try_attach_chase(inner, slot, &b)? {
                return self.chase_span(inner, slot, offset, data);
            }
            self.fallback_slot_or_group(inner, slot, blocker_reason(&b))?;
            if matches!(inner.slots[slot].mode, SlotMode::Discard) {
                return Ok(());
            }
            // The span's bytes reach the volume file via header_spans +
            // holds + extracted read-back inside the fallback; anything in
            // this span not covered there writes through now.
            return self.plain_span(inner, slot, offset, data);
        }

        // Group assignment happens at first-entry parse (inner name),
        // routed through the alias map so a volume whose first entry is a
        // continuation of an already-linked archive joins that group.
        if inner.slots[slot].group.is_none()
            && !inner.slots[slot].mapper.as_ref().unwrap().entries.is_empty()
        {
            let raw = inner.slots[slot].mapper.as_ref().unwrap().entries[0]
                .name
                .clone();
            let key = Self::canon_key(inner, &raw);
            inner.slots[slot].group = Some(key.clone());
            let grp = inner.groups.entry(key.clone()).or_insert_with(|| Group {
                slots: Vec::new(),
                bases: HashMap::new(),
                fallback: false,
                fallback_reason: None,
                out_names: HashMap::new(),
                routed: HashMap::new(),
                chase: None,
            });
            grp.slots.push(slot);
            if grp.fallback {
                // Joined a group that already fell back.
                self.fallback_slot(inner, slot)?;
                if matches!(inner.slots[slot].mode, SlotMode::Discard) {
                    return Ok(());
                }
                return self.plain_span(inner, slot, offset, data);
            }
        }

        if progressed {
            self.link_split_names(inner, slot)?;
            if let Some(key) = inner.slots[slot].group.clone() {
                self.reresolve(inner, &key)?;
            }
        }
        if inner.slots[slot].mode == SlotMode::Rar {
            self.extract_span(inner, slot, offset, data, sink, repair, article_crc)?;
        }
        Ok(())
    }

    /// Keep the parts of a span not covered by any data area (header/meta
    /// bytes below the parse cursor) for byte-exact reconstruction.
    /// Returns the bytes newly stashed; they are charged to the shared
    /// holds budget here and released wherever the stash is dropped.
    fn retain_header_bytes(
        &self,
        inner: &mut Inner,
        slot: usize,
        offset: u64,
        data: &[u8],
    ) -> usize {
        let s = &mut inner.slots[slot];
        let Some(m) = s.mapper.as_ref() else { return 0 };
        let mut covered: Vec<(u64, u64)> = m
            .map_span(offset, data.len() as u64)
            .into_iter()
            .map(|(_, _, span_off, len)| (span_off, span_off + len))
            .collect();
        covered.sort_unstable();
        let mut pos = 0u64;
        let mut keep: Vec<(u64, u64)> = Vec::new();
        for (cs, ce) in covered {
            if cs > pos {
                keep.push((pos, cs));
            }
            pos = pos.max(ce);
        }
        if pos < data.len() as u64 {
            keep.push((pos, data.len() as u64));
        }
        let mut stashed = 0usize;
        for (ks, ke) in keep {
            let abs_s = offset + ks;
            if abs_s >= m.mapped_through() {
                continue; // not header - just not-yet-mapped data
            }
            let abs_e = (offset + ke).min(m.mapped_through());
            if abs_e > abs_s {
                let part = data[ks as usize..(abs_e - offset) as usize].to_vec();
                stashed += part.len();
                s.header_spans.push((abs_s, part));
            }
        }
        inner.budget.add(stashed);
        stashed
    }

    /// Attach the chasing decompressor to a slot whose mapper just hit a
    /// blocker, when the blocker is a compressed RAR5 payload the RAR
    /// engine can stream: the slot flips to `RarChase`, everything it has
    /// seen so far (header stash + holds) seeds a frontier buffer, and
    /// the group's chase worker (spawned on first attach) will pull this
    /// volume at its index. Returns false when ineligible - the caller
    /// then demotes exactly as before the chase existed. Eligible only
    /// when the blocker fired on the archive's FIRST entry: a mixed
    /// store/compressed set has already routed store members, and
    /// re-extracting those through a chase is out of scope.
    fn try_attach_chase(
        &self,
        inner: &mut Inner,
        slot: usize,
        b: &MapBlocker,
    ) -> io::Result<bool> {
        if self.depth == 0
            || !inner.nested_on
            || !inner.chase_on
            || inner.protect_sources
            || !matches!(b, MapBlocker::NotStore)
            || !matches!(inner.slots[slot].mode, SlotMode::Rar)
            || inner.slots[slot].group.is_some()
            || inner.slots[slot].size == 0
            || inner.self_weak.upgrade().is_none()
        {
            return Ok(false);
        }
        let (name, vol_index) = {
            let Some(m) = inner.slots[slot].mapper.as_ref() else {
                return Ok(false);
            };
            if m.version != Some(RarVersion::V5) || m.entries.len() != 1 {
                return Ok(false);
            }
            let e = &m.entries[0];
            // RAR4 never chases (the engine streams RAR5 only), and an
            // encrypted member without a password can't decode anywhere.
            if e.method != Method::Compressed || (e.encrypted && inner.password.is_none()) {
                return Ok(false);
            }
            (e.name.clone(), m.volume_number.unwrap_or(0) as usize)
        };
        let key = Self::canon_key(inner, &name);
        let grp = inner.groups.entry(key.clone()).or_insert_with(|| Group {
            slots: Vec::new(),
            bases: HashMap::new(),
            fallback: false,
            fallback_reason: None,
            out_names: HashMap::new(),
            routed: HashMap::new(),
            chase: None,
        });
        if grp.fallback {
            return Ok(false); // joins the fallback via today's path
        }
        // A healthy group with mapped (non-chased) members claiming this
        // first-entry name is a mixed set - out of scope, demote.
        if grp.chase.is_none() && !grp.slots.is_empty() {
            return Ok(false);
        }
        let fresh = grp.chase.is_none();
        let ctl = grp.chase.clone().unwrap_or_else(|| Arc::new(ChaseCtl::new()));
        {
            let st = ctl.shared.lock().unwrap();
            // A duplicate volume-index claim means the set's ordering is
            // unreliable; an aborted chase accepts no new volumes.
            if st.vols.contains_key(&vol_index) || st.aborted {
                return Ok(false);
            }
        }
        // Commit.
        let size = inner.slots[slot].size;
        let grp = inner.groups.get_mut(&key).unwrap();
        grp.chase = Some(ctl.clone());
        grp.slots.push(slot);
        inner.slots[slot].group = Some(key.clone());
        inner.slots[slot].mode = SlotMode::RarChase;
        let buf = Arc::new(FrontierBuffer::new(size));
        // Seed with everything already seen. The header stash MOVES in
        // (like the holds): the buffer keeps every byte from offset 0
        // for the life of the chase - reads never consume it, and a
        // demotion materializes the volume straight out of it - so a
        // second RAM copy would only double-charge the shared budget
        // that the stash is now billed to. Nothing reads `header_spans`
        // outside `SlotMode::Rar`, which this slot just left.
        let mut stored = 0usize;
        let headers = std::mem::take(&mut inner.slots[slot].header_spans);
        for (off, bytes) in headers {
            inner.budget.sub(bytes.len());
            stored = buf.write_span(off, &bytes);
        }
        let holds = std::mem::take(&mut inner.slots[slot].holds);
        inner.slots[slot].pre_bytes = 0;
        for (off, bytes) in holds {
            inner.budget.sub(bytes.len());
            stored = buf.write_span(off, &bytes);
        }
        inner.budget.add(stored);
        // The stash and the holds can already disagree with each other if
        // a repair landed before the chase attached. Nothing has been
        // decoded yet, so this is the cheap case: never start.
        let seeded_conflict = buf.conflicted();
        inner.slots[slot].chase = Some(ChaseSlot {
            buf: buf.clone(),
            charged: stored,
        });
        {
            let mut st = ctl.shared.lock().unwrap();
            st.vols.insert(vol_index, (buf, size));
        }
        ctl.cv.notify_all();
        if fresh {
            let weak = inner.self_weak.clone();
            let pw = inner.password.clone();
            let ctl2 = ctl.clone();
            let key2 = key.clone();
            let handle = std::thread::Builder::new()
                .name("nzb-chase".into())
                .spawn(move || Self::chase_worker(weak, ctl2, key2, pw))
                .map_err(io::Error::other)?;
            *ctl.worker.lock().unwrap() = Some(handle);
        }
        if seeded_conflict {
            self.fallback_slot_or_group(inner, slot, "repair rewrote chased bytes")?;
            return Ok(true);
        }
        if inner.budget.over() {
            // Same shared budget as the holds cap, so the reason carries
            // the same substring: the caller keys volume-level remediation
            // off "held-bytes cap", and the bare wording this used to have
            // matched nothing, demoting the volumes and then shipping the
            // job with no payload and exit 0.
            self.fallback_slot_or_group(inner, slot, "held-bytes cap: chase memory")?;
        }
        Ok(true)
    }

    /// Route a chased slot's span into its frontier buffer, charging the
    /// shared budget for the retained delta; a breach demotes the whole
    /// group to materialized volumes. A span landing after demotion
    /// writes through the slot's current mode like any late span.
    fn chase_span(&self, inner: &mut Inner, slot: usize, offset: u64, data: &[u8]) -> io::Result<()> {
        let Some(ch) = inner.slots[slot].chase.as_mut() else {
            return match inner.slots[slot].mode {
                SlotMode::Plain | SlotMode::RarFallback => {
                    self.plain_span(inner, slot, offset, data)
                }
                _ => Ok(()),
            };
        };
        let stored = ch.buf.write_span(offset, data);
        let conflicted = ch.buf.conflicted();
        if stored > ch.charged {
            let delta = stored - ch.charged;
            ch.charged = stored;
            inner.budget.add(delta);
        }
        if conflicted {
            // A repair rewrote bytes the chase had already decoded. The
            // buffer now holds the corrected copy, so materializing the
            // volume out of it is exact and the disk pass re-extracts it;
            // carrying on would ship what was decoded from the stale
            // bytes, with every CRC on the path still passing.
            return self.fallback_slot_or_group(inner, slot, "repair rewrote chased bytes");
        }
        if inner.budget.over() {
            // Same shared budget as the holds cap, so the reason carries
            // the same substring: the caller keys volume-level remediation
            // off "held-bytes cap", and the bare wording this used to have
            // matched nothing, demoting the volumes and then shipping the
            // job with no payload and exit 0.
            self.fallback_slot_or_group(inner, slot, "held-bytes cap: chase memory")?;
        }
        Ok(())
    }

    /// The chase worker: drives the RAR engine's volume-sequence
    /// extraction over the group's frontier buffers, in volume order,
    /// decoding behind the arrival frontier. Runs on its own thread; the
    /// extractor is reached weakly so a cancelled job can drop (Drop
    /// aborts the buffers, the next upgrade here fails, the worker
    /// exits). The outcome is recorded for finish() to act on.
    fn chase_worker(
        me: Weak<Extractor>,
        ctl: Arc<ChaseCtl>,
        key: String,
        password: Option<std::sync::Arc<str>>,
    ) {
        let pw: Option<Vec<u8>> = password.map(|p| p.as_bytes().to_vec());
        let result = rars::rar50::extract_volume_sequence_to(
            |index| Self::chase_next_volume(&ctl, index, pw.as_deref()),
            rars::ArchiveReadOptions::with_optional_password(pw.as_deref()),
            |meta| Self::chase_open_sink(&me, &ctl, &key, meta),
        );
        let mut st = ctl.shared.lock().unwrap();
        st.outcome = Some(result.map_err(|e| e.to_string()));
        drop(st);
        ctl.cv.notify_all();
    }

    /// Supply volume `index` to the sequence driver: wait until routing
    /// registers that volume's buffer (volumes classify in any order),
    /// then run the engine's blocking header parse over it - which
    /// returns once the volume has fully arrived. `no_more` (set at
    /// finish) turns a wait into a clean end-of-set.
    fn chase_next_volume(
        ctl: &ChaseCtl,
        index: usize,
        password: Option<&[u8]>,
    ) -> rars::Result<Option<rars::rar50::Archive>> {
        let (buf, len) = {
            let mut st = ctl.shared.lock().unwrap();
            loop {
                if st.aborted {
                    return Err(io::Error::other("chase aborted").into());
                }
                if let Some((buf, len)) = st.vols.get(&index) {
                    break (buf.clone(), *len);
                }
                if st.no_more {
                    return Ok(None);
                }
                st = ctl.cv.wait(st).unwrap();
            }
        };
        let archive = rars::rar50::Archive::parse_stream(
            buf as Arc<dyn rars::BlockingRangeSource>,
            len,
            rars::ArchiveReadOptions::with_optional_password(password),
        )?;
        // Record member sizes: the engine's open callback carries no
        // size, the parsed headers do (split parts repeat the total -
        // first sighting wins).
        {
            let mut sizes = ctl.sizes.lock().unwrap();
            for f in archive.files() {
                sizes
                    .entry(String::from_utf8_lossy(f.name_bytes()).into_owned())
                    .or_insert(f.unpacked_size);
            }
        }
        Ok(Some(archive))
    }

    /// Open the routing-seam sink for one extracted member: a fresh slot
    /// of the nested child extractor, whose offset-0 sniff classifies the
    /// decompressed bytes (store RAR maps on, anything else lands Plain).
    /// The slot is recorded so a demotion can abandon partial outputs.
    fn chase_open_sink(
        me: &Weak<Extractor>,
        ctl: &ChaseCtl,
        key: &str,
        meta: &rars::rar50::ExtractedEntryMeta,
    ) -> rars::Result<Box<dyn io::Write>> {
        if meta.is_directory {
            return Ok(Box::new(io::sink()));
        }
        let Some(ex) = me.upgrade() else {
            return Err(io::Error::other("extractor dropped").into());
        };
        let name = String::from_utf8_lossy(&meta.name).into_owned();
        let size = ctl.sizes.lock().unwrap().get(&name).copied().unwrap_or(0);
        // Liveness check, slot allocation and registration under ONE
        // routing-lock hold: a demotion (chase_teardown drains
        // sink_slots under the same lock) either runs before this - the
        // fallback flag bounces us - or after, and then it sees the slot
        // we just registered. Split apart, a slot allocated after the
        // drain would leak a partial grandchild output.
        let (child, slot) = {
            let mut g = ex.inner.lock().unwrap();
            let inner = &mut *g;
            if inner.groups.get(key).is_none_or(|g| g.fallback) {
                return Err(io::Error::other("chase demoted").into());
            }
            let child = ex.ensure_child(inner);
            let slot = child.alloc_slot();
            ctl.sink_slots.lock().unwrap().push(slot);
            (child, slot)
        };
        Ok(Box::new(ChaseSink {
            child,
            slot,
            name,
            size,
            pos: 0,
        }))
    }

    /// Stop a group's chase (demotion/abandon): the worker unblocks with
    /// errors, and every partial output slot the sink opened is
    /// abandoned in the child so no half-decoded file survives.
    /// Idempotent; the join happens off-lock at finish/drop.
    fn chase_teardown(&self, inner: &mut Inner, ctl: &Arc<ChaseCtl>, reason: &str) {
        ctl.abort(reason);
        if let Some(c) = inner.child.clone() {
            for cs in ctl.sink_slots.lock().unwrap().drain(..) {
                c.abandon_slot(cs);
            }
        }
    }

    /// Attach the 7z chase (phase 3) to a child slot whose offset-0
    /// sniff found 7z magic: parse the start header for the end-header
    /// (footer) range, flip the slot to SevenZ, seed a frontier buffer
    /// with everything held so far, and spawn the worker - which first
    /// asks the chain above to front-load the footer's articles (tail
    /// prefetch), then parses and decodes through a blocking Read+Seek
    /// view as bytes arrive. Returns false when ineligible - the slot
    /// then classifies Plain and materializes exactly as before. A
    /// multipart `.7z.001` part never attaches (its end header lies
    /// past its own bytes - the v1 limitation): the parts materialize
    /// and the disk post-pass joins them.
    fn try_attach_sevenz(&self, inner: &mut Inner, slot: usize, data: &[u8]) -> io::Result<bool> {
        if self.depth == 0
            || !inner.nested_on
            || !inner.sevenz_on
            || inner.protect_sources
            || inner.slots[slot].size == 0
            || inner.self_weak.upgrade().is_none()
        {
            return Ok(false);
        }
        let Some((ho, hs)) = sevenz_start_header(data) else {
            return Ok(false);
        };
        let size = inner.slots[slot].size;
        let tail = 32u64
            .checked_add(ho)
            .and_then(|s| s.checked_add(hs).map(|e| (s, e)));
        let Some((tail_start, tail_end)) = tail else {
            return Ok(false);
        };
        if hs == 0 || tail_end > size {
            return Ok(false);
        }
        // Commit.
        inner.slots[slot].mode = SlotMode::SevenZ;
        let buf = Arc::new(FrontierBuffer::new(size));
        let holds = std::mem::take(&mut inner.slots[slot].holds);
        inner.slots[slot].pre_bytes = 0;
        let mut stored = 0usize;
        for (off, bytes) in holds {
            inner.budget.sub(bytes.len());
            stored = buf.write_span(off, &bytes);
        }
        inner.budget.add(stored);
        // See the RAR attach: held spans that disagree with each other
        // mean a repair already landed, and nothing has decoded yet.
        let seeded_conflict = buf.conflicted();
        inner.slots[slot].chase = Some(ChaseSlot {
            buf: buf.clone(),
            charged: stored,
        });
        let ctl = Arc::new(SevenZCtl {
            buf,
            worker: Mutex::new(None),
            sink_slots: Mutex::new(Vec::new()),
            outcome: Mutex::new(None),
        });
        inner.slots[slot].sevenz = Some(ctl.clone());
        let weak = inner.self_weak.clone();
        let pw = inner.password.clone();
        let ctl2 = ctl.clone();
        let handle = std::thread::Builder::new()
            .name("nzb-7z-chase".into())
            .spawn(move || Self::sevenz_worker(weak, ctl2, slot, (tail_start, tail_end), pw))
            .map_err(io::Error::other)?;
        *ctl.worker.lock().unwrap() = Some(handle);
        if seeded_conflict {
            self.fallback_slot_or_group(inner, slot, "repair rewrote chased bytes")?;
            return Ok(true);
        }
        if inner.budget.over() {
            // Same shared budget as the holds cap, so the reason carries
            // the same substring: the caller keys volume-level remediation
            // off "held-bytes cap", and the bare wording this used to have
            // matched nothing, demoting the volumes and then shipping the
            // job with no payload and exit 0.
            self.fallback_slot_or_group(inner, slot, "held-bytes cap: chase memory")?;
        }
        Ok(true)
    }

    /// The 7z chase worker: front-load the footer, then let the engine
    /// parse the archive map and decode block by block behind the
    /// arrival frontier, each entry streaming into a fresh child slot
    /// (the routing seam - a store RAR inside the 7z keeps streaming).
    /// The extractor is reached weakly so a cancelled job can drop; the
    /// outcome is recorded for finish() to act on, with error wording
    /// the parent's nested-reason fold understands.
    fn sevenz_worker(
        me: Weak<Extractor>,
        ctl: Arc<SevenZCtl>,
        slot: usize,
        tail: (u64, u64),
        password: Option<std::sync::Arc<str>>,
    ) {
        if let Some(ex) = me.upgrade() {
            ex.promote_slot_spans(slot, &[tail]);
        }
        let result = Self::sevenz_run(&me, &ctl, slot, password).map_err(|e| match e {
            sevenz_rust2::Error::PasswordRequired => {
                "inner 7z is encrypted (no password)".to_string()
            }
            sevenz_rust2::Error::MaybeBadPassword(_) => {
                "inner 7z is encrypted (password rejected)".to_string()
            }
            sevenz_rust2::Error::UnsupportedCompressionMethod(m) => {
                format!("inner 7z codec unsupported: {m}")
            }
            e => format!("inner 7z decode failed: {e}"),
        });
        let mut st = ctl.outcome.lock().unwrap();
        *st = Some(result);
    }

    /// The worker's engine drive: parse blocks (the initial footer reads
    /// block only until the promoted tail lands), then decode every
    /// entry in block order through the blocking view. CRC-checked per
    /// entry by the engine.
    fn sevenz_run(
        me: &Weak<Extractor>,
        ctl: &SevenZCtl,
        slot: usize,
        password: Option<std::sync::Arc<str>>,
    ) -> Result<(), sevenz_rust2::Error> {
        let total = ctl.buf.total();
        let src = BlockingSeekReader {
            buf: ctl.buf.clone(),
            pos: 0,
            total,
        };
        let pw = match &password {
            Some(p) => sevenz_rust2::Password::from(&**p),
            None => sevenz_rust2::Password::empty(),
        };
        let mut reader = sevenz_rust2::ArchiveReader::new(src, pw)?;
        reader.for_each_entries(|entry, rd| {
            if entry.is_directory {
                return Ok(true);
            }
            let Some(ex) = me.upgrade() else {
                return Err(io::Error::other("extractor dropped").into());
            };
            // Same single-lock-hold discipline as chase_open_sink: the
            // liveness check and the sink-slot registration must be
            // atomic against a demotion draining sink_slots, or the
            // fresh slot leaks a partial grandchild output.
            let (child, cslot) = {
                let mut g = ex.inner.lock().unwrap();
                let inner = &mut *g;
                if !matches!(inner.slots[slot].mode, SlotMode::SevenZ) {
                    return Err(io::Error::other("7z chase demoted").into());
                }
                let child = ex.ensure_child(inner);
                let cslot = child.alloc_slot();
                ctl.sink_slots.lock().unwrap().push(cslot);
                (child, cslot)
            };
            let mut sink = ChaseSink {
                child,
                slot: cslot,
                name: entry.name.clone(),
                size: entry.size,
                pos: 0,
            };
            io::copy(rd, &mut sink)?;
            Ok(true)
        })
    }

    /// Abandon every partial output slot a 7z chase's sink opened, so
    /// no half-decoded file survives a demotion.
    fn sevenz_abandon_sinks(&self, inner: &mut Inner, ctl: &SevenZCtl) {
        if let Some(c) = inner.child.clone() {
            for cs in ctl.sink_slots.lock().unwrap().drain(..) {
                c.abandon_slot(cs);
            }
        }
    }

    /// Join every 7z chase worker before settling (mirrors
    /// [`Self::chase_finish`]): the download is over, so an incomplete
    /// buffer can never complete - abort it and the blocked worker
    /// unblocks with an error. A failed or panicked worker demotes its
    /// slot to a materialized level-N .7z (the disk post-pass input); a
    /// successful one releases the retained bytes - its outputs already
    /// live in the child chain.
    fn sevenz_finish(&self) -> io::Result<()> {
        let pending: Vec<(usize, Arc<SevenZCtl>)> = {
            let inner = self.inner.lock().unwrap();
            inner
                .slots
                .iter()
                .enumerate()
                .filter_map(|(i, s)| s.sevenz.clone().map(|c| (i, c)))
                .collect()
        };
        for (slot, ctl) in pending {
            if !ctl.buf.is_complete() {
                ctl.buf.abort("bytes never arrived");
            }
            let handle = ctl.worker.lock().unwrap().take();
            if let Some(h) = handle {
                // A worker panic surfaces as a join error and leaves no
                // outcome - handled below as a demotion.
                let _ = h.join();
            }
            let outcome = ctl.outcome.lock().unwrap().clone();
            let mut g = self.inner.lock().unwrap();
            let inner = &mut *g;
            inner.slots[slot].sevenz = None;
            if !matches!(inner.slots[slot].mode, SlotMode::SevenZ) {
                continue; // demoted earlier (budget breach / abandon)
            }
            match outcome {
                Some(Ok(())) => {
                    if let Some(ch) = inner.slots[slot].chase.take() {
                        inner.budget.sub(ch.charged);
                    }
                }
                other => {
                    let why = match other {
                        Some(Err(e)) => e,
                        _ => "7z worker panicked".to_string(),
                    };
                    self.sevenz_abandon_sinks(inner, &ctl);
                    self.fallback_slot_or_group(inner, slot, &why)?;
                }
            }
        }
        Ok(())
    }

    /// Ask the chain above to front-load the outer articles carrying
    /// `spans` of this slot's byte space (7z tail prefetch). A slot's
    /// byte space IS its level-N file's byte space, and that file is an
    /// entry of the parent's groups - so the parent handles it as a
    /// file promote.
    fn promote_slot_spans(&self, slot: usize, spans: &[(u64, u64)]) {
        let Some(p) = self.parent.upgrade() else { return };
        let (name, size) = {
            let inner = self.inner.lock().unwrap();
            (inner.slots[slot].name.clone(), inner.slots[slot].size)
        };
        if name.is_empty() || size == 0 {
            return;
        }
        p.promote_file(&sanitize_filename(&name), size, spans);
    }

    /// Promote byte spans of file `name` (an inner file of one of THIS
    /// extractor's groups): the root hands them to the installed hook
    /// (the daemon's seek/promote ladder resolves them to articles);
    /// a level below the root translates them to its own slot ranges
    /// via [`Self::map_output_range`] and recurses upward - the §3b
    /// map_to_root composition. All-store levels only by construction:
    /// a chased (compressed) level yields no offset mapping, so the
    /// promote quietly stops there. Never called with any routing lock
    /// held; each level takes only its own lock, one at a time.
    fn promote_file(&self, name: &str, size: u64, spans: &[(u64, u64)]) {
        let hook = self.inner.lock().unwrap().promote.clone();
        if let Some(h) = hook {
            h(name, size, spans);
            return;
        }
        let Some(p) = self.parent.upgrade() else { return };
        let mut per_slot: BTreeMap<usize, Vec<(u64, u64)>> = BTreeMap::new();
        for &(s, e) in spans {
            if s >= e {
                continue;
            }
            for (slot, vs, ve, _) in self.map_output_range(name, s, e) {
                if vs < ve {
                    per_slot.entry(slot).or_default().push((vs, ve));
                }
            }
        }
        for (slot, ranges) in per_slot {
            let (sname, ssize) = {
                let inner = self.inner.lock().unwrap();
                (inner.slots[slot].name.clone(), inner.slots[slot].size)
            };
            if sname.is_empty() {
                continue;
            }
            p.promote_file(&sanitize_filename(&sname), ssize, &ranges);
        }
    }

    /// Base offset of (slot, entry) within its inner file: 0 for pieces
    /// that start a file; group-resolved for split continuations.
    fn base_for(inner: &Inner, slot: usize, ei: usize) -> Option<u64> {
        let m = inner.slots[slot].mapper.as_ref()?;
        if !m.entries[ei].split_before {
            return Some(0);
        }
        let key = inner.slots[slot].group.as_ref()?;
        inner.groups.get(key)?.bases.get(&(slot, ei)).copied()
    }

    /// Route the mapped parts of a span into inner files or the nested
    /// child (queued when the caller collects a sink, inline/pending
    /// otherwise); hold the rest.
    fn extract_span(
        &self,
        inner: &mut Inner,
        slot: usize,
        offset: u64,
        data: &[u8],
        mut sink: Option<(&mut Vec<WriteJob>, &mut Vec<FwdSpan>)>,
        repair: bool,
        article_crc: Option<u32>,
    ) -> io::Result<()> {
        let hits = {
            let m = inner.slots[slot].mapper.as_ref().unwrap();
            m.map_span(offset, data.len() as u64)
        };
        // The yEnc decode already computed and CHECKED this article's
        // CRC32 over exactly these bytes. When the article maps to a
        // single STORE data range covering the whole buffer, that value
        // IS the CRC the stored-file composition needs, so the second
        // scan over ~700 KiB is pure waste (measured on a real corpus:
        // 98.75% of STORE payload bytes qualify; the exceptions are the
        // header-bearing first article, the trailing article, volume and
        // member boundaries, and multi-entry spans).
        //
        // Every reuse condition is checked, not assumed: the CRC exists
        // and matched (`article_crc` is None otherwise, including on the
        // bare-LF scalar path and under delegated verification), this is
        // not a repair rewrite (its bytes deliberately DIFFER from what
        // composed earlier), the entry is `checkable` (unencrypted store,
        // not a directory) at the use site, and the range is untouched -
        // `add_run` refuses an overlap and the hash path takes over. A
        // single hit spanning the whole buffer is what makes the mapped
        // range byte-for-byte the decoded output.
        let single_whole_hit = matches!(
            hits.as_slice(),
            [(_, _, 0, len)] if *len == data.len() as u64
        );
        let whole_article = single_whole_hit && !repair && article_crc.is_some();
        let mut covered_end = offset;
        for (ei, piece_off, span_off, len) in hits {
            covered_end = covered_end.max(offset + span_off + len);
            let base = match Self::base_for(inner, slot, ei) {
                Some(b) => b,
                None => {
                    let part = data[span_off as usize..(span_off + len) as usize].to_vec();
                    inner.budget.add(part.len());
                    inner.slots[slot].holds.push((offset + span_off, part));
                    if inner.budget.over() {
                        return self.fallback_slot_or_group(inner, slot, "held-bytes cap");
                    }
                    continue;
                }
            };
            let (name, total, encrypted, checkable) = {
                let m = inner.slots[slot].mapper.as_ref().unwrap();
                let e = &m.entries[ei];
                (
                    e.name.clone(),
                    e.unpacked_size,
                    e.encrypted,
                    matches!(e.method, Method::Store) && !e.encrypted && !e.is_dir,
                )
            };
            // Compose the routed bytes' CRC32 per piece for the
            // finish-time check against the header CRC (encrypted
            // entries have their own post-decrypt check). Nested levels
            // always compose; level 0's PAR2 only vouches for the outer
            // bytes AS POSTED, so the final store payload gets the same
            // treatment under the verify_output_crc gate (default on;
            // `NZBFAST_NO_OUTPUT_CRC=1` restores the skip). A repair
            // span overwrites: its bytes REPLACE a range that may have
            // composed wire-damaged bytes earlier, and clipping it as a
            // duplicate would keep the stale CRC while the file heals.
            if (self.depth > 0 || inner.verify_output_crc) && checkable {
                let part = &data[span_off as usize..(span_off + len) as usize];
                let runs = inner.slots[slot].piece_crcs.entry(ei).or_default();
                if repair {
                    runs.overwrite(piece_off, part);
                } else if !(whole_article && runs.add_run(piece_off, len, article_crc.unwrap())) {
                    // Not the exact-article case, or the range was already
                    // (partly) composed: hash the routed bytes as before.
                    runs.add(piece_off, part);
                }
            }
            match self.route_dest(inner, slot, &name, total, encrypted)? {
                Dest::Writer(w) => {
                    // Plaintext-once: an encrypted store span decrypts at
                    // write time instead of assembling ciphertext for the
                    // finish pass. The state needs the HEAD entry's crypt
                    // parameters; a continuation piece racing its head
                    // volume's headers holds like an unresolved base.
                    let crypto = if encrypted && inner.instream_decrypt {
                        match Self::crypto_for(inner, slot, &name, &w) {
                            Some(cs) => {
                                // Plaintext-once is live for this set:
                                // the badge says "one-pass", not
                                // "unlocked at the end".
                                self.shape.note(self.depth, SH_ENC_INSTREAM);
                                Some(cs)
                            }
                            None => {
                                let part =
                                    data[span_off as usize..(span_off + len) as usize].to_vec();
                                inner.budget.add(part.len());
                                inner.slots[slot].holds.push((offset + span_off, part));
                                if inner.budget.over() {
                                    return self.fallback_slot_or_group(
                                        inner,
                                        slot,
                                        "held-bytes cap",
                                    );
                                }
                                continue;
                            }
                        }
                    } else {
                        None
                    };
                    match sink.as_mut() {
                        Some((jobs, _)) => jobs.push(WriteJob {
                            writer: w,
                            file_off: base + piece_off,
                            src_start: span_off as usize,
                            len: len as usize,
                            crypto,
                            repair,
                        }),
                        // Under-the-lock re-feed (drain_holds/reresolve):
                        // cold path, so the AES here is acceptable.
                        None => {
                            let part = &data[span_off as usize..(span_off + len) as usize];
                            match &crypto {
                                Some(cs) if repair => {
                                    cs.patch(&w, base + piece_off, part)?
                                }
                                Some(cs) => cs.ingest(&w, base + piece_off, part)?,
                                None => w.write_at(base + piece_off, part)?,
                            }
                        }
                    }
                }
                Dest::Child(..) => match sink.as_mut() {
                    Some((_, fwd)) => fwd.push(FwdSpan {
                        name,
                        size: total,
                        file_off: base + piece_off,
                        src_start: span_off as usize,
                        len: len as usize,
                        repair,
                    }),
                    // Under-the-lock re-feed: the child cannot be called
                    // here (it defers pwrites behind its own lock), so
                    // queue an owned copy for flush_pending_fwd. Cold
                    // paths only - the hot write path always has a sink.
                    None => inner.pending_fwd.push(FwdJob {
                        parent_slot: slot,
                        vol_off: offset + span_off,
                        name,
                        size: total,
                        file_off: base + piece_off,
                        bytes: data[span_off as usize..(span_off + len) as usize].to_vec(),
                        repair,
                    }),
                },
            }
            inner.extracted_bytes += len;
        }
        // Anything past the mapped region: hold until headers advance.
        let m = inner.slots[slot].mapper.as_ref().unwrap();
        let span_end = offset + data.len() as u64;
        let unmapped_from = covered_end.max(m.mapped_through()).max(offset);
        if unmapped_from < span_end && !m.complete {
            let part = data[(unmapped_from - offset) as usize..].to_vec();
            inner.budget.add(part.len());
            inner.slots[slot].holds.push((unmapped_from, part));
            if inner.budget.over() {
                return self.fallback_slot_or_group(inner, slot, "held-bytes cap");
            }
        }
        Ok(())
    }

    /// The in-stream decrypt state for entry `name`'s output (keyed by
    /// the writer's on-disk filename), created on first touch from the
    /// HEAD entry's crypt parameters. None while the head volume's
    /// headers have not been seen (the caller holds the span) or when no
    /// usable key exists - the latter cannot normally happen, because an
    /// encrypted entry only maps after the stored password check passed.
    fn crypto_for(
        inner: &mut Inner,
        slot: usize,
        name: &str,
        w: &Arc<FileWriter>,
    ) -> Option<Arc<CryptoState>> {
        let key = w.path.file_name()?.to_string_lossy().into_owned();
        if let Some(cs) = inner.crypto_files.get(&key) {
            return Some(cs.clone());
        }
        // Find the head piece (split_before == false) of this file - it
        // may live in another volume's mapper within the same group.
        let head_of = |m: &VolumeMapper| {
            m.entries
                .iter()
                .find(|e| e.name == name && !e.split_before && e.crypt.is_some())
                .map(|e| (e.crypt.clone().unwrap(), e.unpacked_size, e.file_crc, e.split_after))
        };
        let mut head = inner.slots[slot].mapper.as_ref().and_then(head_of);
        if head.is_none()
            && let Some(gk) = inner.slots[slot].group.clone()
            && let Some(g) = inner.groups.get(&gk)
        {
            for &si in &g.slots {
                if let Some(h) = inner.slots[si].mapper.as_ref().and_then(head_of) {
                    head = Some(h);
                    break;
                }
            }
        }
        let (c, unp, file_crc, split_after) = head?;
        let pw = inner.password.as_ref()?;
        let keys = rarcrypt::derive_keys(pw, &c.salt, c.lg2_count)?;
        // Only a single-piece entry's stored CRC covers the whole
        // plaintext, and a tweaked checksum is keyed - same rules as the
        // legacy finish pass.
        let expect_crc = file_crc.filter(|_| !split_after && !c.tweaked_checksum);
        let cs = Arc::new(CryptoState::new(
            keys.key,
            c.iv,
            unp,
            expect_crc,
            key.clone(),
            inner.crypto_events.clone(),
        ));
        inner.crypto_events.lock().unwrap().push(CryptoJournalEvent::Params {
            name: key.clone(),
            salt: c.salt,
            lg2: c.lg2_count,
            iv: c.iv,
            unp,
            check: c.check,
        });
        inner.crypto_files.insert(key, cs.clone());
        Some(cs)
    }

    /// Read-side lookup: the in-stream decrypt state behind a writer,
    /// if that output is plaintext-once.
    fn crypto_of(inner: &Inner, w: &FileWriter) -> Option<Arc<CryptoState>> {
        let key = w.path.file_name()?.to_string_lossy();
        inner.crypto_files.get(key.as_ref()).cloned()
    }

    /// The destination for `slot`'s view of inner file `name` - decided
    /// once per (group, name) and sticky thereafter, so write-side routing
    /// and read-side delegation always agree. Non-encrypted files route
    /// into the nested child (whose offset-0 sniff classifies them: RAR
    /// store maps on, everything else lands as a plain file, exactly the
    /// single-level output). Encrypted entries stay on the direct writer
    /// path - the ciphertext-at-store-offsets assembly and the finish
    /// decrypt own that lifecycle.
    fn route_dest(
        &self,
        inner: &mut Inner,
        slot: usize,
        name: &str,
        total: u64,
        encrypted: bool,
    ) -> io::Result<Dest> {
        // Group identity is the RAW entry name, not its sanitized form: two
        // distinct archive entries whose names sanitize alike (e.g. "a/b.txt"
        // and "a_b.txt" both -> "a_b.txt") must get SEPARATE child slots and
        // writers, or the second silently overwrites/interleaves the first at
        // offset 0. The same raw name across split volumes still maps to one
        // output (the intended "one inner file, many pieces" case). The
        // sanitized form is used only to derive the on-disk filename, in
        // inner_writer/claim_name.
        // Reaching here means the fast path owns this inner file - its
        // bytes go straight to their destination and the volumes never
        // land. That is what "one-pass" on the badge means.
        self.shape.note(self.depth, SH_ONE_PASS);
        let key = name;
        if let Some(gk) = inner.slots[slot].group.clone() {
            if let Some(&cs) = inner.groups.get(&gk).and_then(|g| g.routed.get(key)) {
                let c = inner.child.clone().expect("routed name without a child");
                return Ok(Dest::Child(c, cs));
            }
            let already_written = inner
                .groups
                .get(&gk)
                .is_some_and(|g| g.out_names.contains_key(key));
            if !already_written && inner.nested_on && !encrypted {
                let child = self.ensure_child(inner);
                let cs = child.alloc_slot();
                inner
                    .groups
                    .get_mut(&gk)
                    .unwrap()
                    .routed
                    .insert(key.to_string(), cs);
                return Ok(Dest::Child(child, cs));
            }
        }
        Ok(Dest::Writer(self.inner_writer(inner, slot, name, total)?))
    }

    /// The output writer for `name` as seen by `slot`'s group. Output
    /// files are group-owned: two archives in one NZB that reuse an inner
    /// filename each get their own file (the second is disambiguated),
    /// instead of interleaving writes into one writer at conflicting
    /// offsets - inner files are not PAR2-covered, so that corruption was
    /// silent and deterministic.
    fn inner_writer(
        &self,
        inner: &mut Inner,
        slot: usize,
        name: &str,
        total: u64,
    ) -> io::Result<Arc<FileWriter>> {
        // Keyed on the RAW name (see route_dest); the sanitized form is only
        // the on-disk filename. Distinct raw names that sanitize alike get
        // distinct writers (claim_name disambiguates the on-disk name).
        let key = name;
        let fname = sanitize_filename(name);
        let gkey = inner.slots[slot].group.clone();
        match &gkey {
            Some(gk) => {
                if let Some(out) = inner.groups.get(gk).and_then(|g| g.out_names.get(key)) {
                    if let Some(w) = inner.inner_writers.get(out) {
                        return Ok(w.clone());
                    }
                }
            }
            None => {
                if let Some(w) = inner.inner_writers.get(&fname) {
                    return Ok(w.clone());
                }
            }
        }
        let mut out = fname.clone();
        Self::claim_name(inner, slot, &mut out);
        let path = self.out_dir.join(&out);
        // `total` is the entry's declared `unpacked_size` - an untrusted
        // header vint. It stays the writer's `size` (resume truncation and
        // the reported extracted size both depend on it) but it does NOT
        // get to reserve the disk: the reservation is capped at the
        // chain's ceiling, and the extracted bytes are charged against the
        // chain's bomb budget. See [`Limits`].
        let cap = inner.limits.prealloc_cap();
        let budget = inner.limits.budget.clone();
        let w = Arc::new(
            if self.resume {
                FileWriter::create_resume_capped(&path, total, cap)?
            } else {
                FileWriter::create_capped(&path, total, cap)?
            }
            .with_budget(budget),
        );
        inner.inner_writers.insert(out.clone(), w.clone());
        if let Some(gk) = gkey {
            if let Some(g) = inner.groups.get_mut(&gk) {
                g.out_names.insert(key.to_string(), out);
            }
        }
        Ok(w)
    }

    /// Resolve `slot`'s view of an inner-file name to its destination -
    /// the read-side mirror of `route_dest`, consulting the group's
    /// routed map first so delegation always agrees with routing.
    fn dest_for(inner: &Inner, slot: usize, entry_name: &str) -> Option<Dest> {
        // Keyed on the RAW name, matching route_dest/inner_writer.
        if let Some(gk) = inner.slots[slot].group.as_ref()
            && let Some(g) = inner.groups.get(gk)
        {
            if let Some(&cs) = g.routed.get(entry_name) {
                return inner.child.clone().map(|c| Dest::Child(c, cs));
            }
            if let Some(out) = g.out_names.get(entry_name) {
                return inner.inner_writers.get(out).cloned().map(Dest::Writer);
            }
        }
        inner.inner_writers.get(&sanitize_filename(entry_name)).cloned().map(Dest::Writer)
    }

    /// Unlink and forget every output file a group owns (fallback: the
    /// bytes were reconstructed into the volume files, and a sparse
    /// half-written "extracted" file would masquerade as output). Only
    /// files in the group's own `out_names` are touched - a file another
    /// group is still extracting is structurally unreachable from here.
    /// Routed inner files are abandoned in the child by the same
    /// ownership argument: the child slots drained here belong to this
    /// group alone.
    fn delete_group_out_files(inner: &mut Inner, key: &str) {
        let (outs, routed): (Vec<String>, Vec<usize>) = match inner.groups.get_mut(key) {
            Some(g) => (
                g.out_names.drain().map(|(_, v)| v).collect(),
                g.routed.drain().map(|(_, v)| v).collect(),
            ),
            None => return,
        };
        for out in outs {
            if let Some(w) = inner.inner_writers.remove(&out) {
                let _ = std::fs::remove_file(&w.path);
                inner.names_taken.lock().unwrap().remove(&name_collision_key(inner.fold_names, &out));
            }
        }
        if let Some(c) = inner.child.clone() {
            for cs in routed {
                c.abandon_slot(cs);
            }
        }
    }

    /// Parent-group fallback support: this routed slot's bytes were (or
    /// will be) reconstructed into the parent's materialized volumes, so
    /// drop everything it produced - holds, its own file, and the group
    /// outputs once every member slot is abandoned - and swallow all
    /// future spans. Silent by design: the parent already reported the
    /// fallback, a child-side entry would double-count it.
    fn abandon_slot(&self, slot: usize) {
        let mut g = self.inner.lock().unwrap();
        let inner = &mut *g;
        if matches!(inner.slots[slot].mode, SlotMode::Discard) {
            return;
        }
        let holds = std::mem::take(&mut inner.slots[slot].holds);
        for (_, bytes) in &holds {
            inner.budget.sub(bytes.len());
        }
        inner.slots[slot].pre_bytes = 0;
        let headers = std::mem::take(&mut inner.slots[slot].header_spans);
        for (_, bytes) in &headers {
            inner.budget.sub(bytes.len());
        }
        inner.slots[slot].piece_crcs = HashMap::new();
        if let Some(ch) = inner.slots[slot].chase.take() {
            inner.budget.sub(ch.charged);
            ch.buf.abort("slot abandoned");
        }
        // An abandoned 7z chase dies with the slot: buffer already
        // aborted above (the worker exits on its next read), and its
        // partial sink outputs go too. The sink-open path re-checks the
        // slot's mode under this lock, so no NEW sink can appear after.
        // The ctl stays in the slot so sevenz_finish / Drop still find
        // and join the worker.
        if let Some(ctl) = inner.slots[slot].sevenz.clone() {
            self.sevenz_abandon_sinks(inner, &ctl);
        }
        // No mapper means finish() sees neither holds nor an incomplete
        // parse here - an abandoned slot must not read as a fallback.
        inner.slots[slot].mapper = None;
        if let Some(w) = inner.slots[slot].writer.take() {
            let _ = std::fs::remove_file(&w.path);
            let name = w
                .path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned();
            inner.names_taken.lock().unwrap().remove(&name_collision_key(inner.fold_names, &name));
        }
        inner.slots[slot].mode = SlotMode::Discard;
        if let Some(key) = inner.slots[slot].group.clone() {
            let all_gone = inner
                .groups
                .get(&key)
                .is_some_and(|g| {
                    g.slots
                        .iter()
                        .all(|&si| matches!(inner.slots[si].mode, SlotMode::Discard))
                });
            if all_gone {
                // The group's chase (if any) dies with its last slot -
                // the worker stops, partial sink outputs go too.
                if let Some(ctl) = inner.groups.get(&key).and_then(|g| g.chase.clone()) {
                    self.chase_teardown(inner, &ctl, "group abandoned");
                }
                Self::delete_group_out_files(inner, &key);
            }
        }
    }

    /// Follow the alias chain from an inner-file name to the canonical
    /// group key that owns it (itself when unlinked).
    fn canon_key(inner: &Inner, name: &str) -> String {
        let mut k = name;
        for _ in 0..64 {
            match inner.alias.get(k) {
                Some(next) if next != k => k = next,
                _ => break,
            }
        }
        k.to_string()
    }

    /// Whole-archive linking. A volume that carries a SPLIT piece of an
    /// inner file proves that file's chain runs through this archive - so
    /// its name belongs to this slot's group, and a group that formed
    /// under that name (the continuation volumes of a multi-file set,
    /// which group by THEIR first entry) is the same archive: merge it.
    /// Without this, a store set holding more than one file splits into a
    /// new group at every file boundary; the continuation group can never
    /// base-resolve, falls back at finish(), and deleted the shared inner
    /// file - silent whole-file loss on a season-pack layout.
    ///
    /// Only split names link: a wholly-contained file (e.g. `sample.mkv`
    /// present in two different archives) is no evidence of shared
    /// identity and must NOT merge two archives.
    fn link_split_names(&self, inner: &mut Inner, slot: usize) -> io::Result<()> {
        let Some(my_raw) = inner.slots[slot].group.clone() else {
            return Ok(());
        };
        let my_key = Self::canon_key(inner, &my_raw);
        let names: Vec<String> = match inner.slots[slot].mapper.as_ref() {
            Some(m) => m
                .entries
                .iter()
                .filter(|e| !e.is_dir && (e.split_before || e.split_after))
                .map(|e| e.name.clone())
                .collect(),
            None => Vec::new(),
        };
        for n in names {
            let other = Self::canon_key(inner, &n);
            if other == my_key {
                continue;
            }
            inner.alias.insert(n, my_key.clone());
            if inner.groups.contains_key(&other) {
                self.merge_groups(inner, &my_key, &other)?;
            }
        }
        Ok(())
    }

    /// Merge group `from` into group `into` (one archive, one group, one
    /// fate). Aliases are flattened so future lookups land on `into`.
    fn merge_groups(&self, inner: &mut Inner, into: &str, from: &str) -> io::Result<()> {
        if into == from || !inner.groups.contains_key(into) {
            return Ok(());
        }
        let Some(old) = inner.groups.remove(from) else {
            return Ok(());
        };
        for v in inner.alias.values_mut() {
            if v == from {
                *v = into.to_string();
            }
        }
        inner.alias.insert(from.to_string(), into.to_string());
        for &si in &old.slots {
            inner.slots[si].group = Some(into.to_string());
        }
        let into_was_fallback = inner.groups[into].fallback;
        let mut displaced: Vec<usize> = Vec::new();
        {
            let g = inner.groups.get_mut(into).unwrap();
            g.slots.extend(old.slots.iter().copied());
            // Bases carry over so a fallback right after the merge can
            // still read back what the moved slots already extracted;
            // reresolve rebuilds them anyway on the next progress.
            g.bases.extend(old.bases);
            for (k, v) in old.out_names {
                g.out_names.entry(k).or_insert(v);
            }
            // Same for routed child slots; when both groups had already
            // routed the same inner name (they were one archive all
            // along), the loser's partial child slot is abandoned so no
            // stray half-file survives the merge.
            for (k, v) in old.routed {
                match g.routed.entry(k) {
                    std::collections::hash_map::Entry::Occupied(_) => displaced.push(v),
                    std::collections::hash_map::Entry::Vacant(e) => {
                        e.insert(v);
                    }
                }
            }
        }
        if let Some(c) = inner.child.clone() {
            for cs in displaced {
                c.abandon_slot(cs);
            }
        }
        if old.fallback && !into_was_fallback {
            let why = old
                .fallback_reason
                .clone()
                .unwrap_or_else(|| "merged into fallen-back group".to_string());
            self.fallback_group(inner, into, &why)?;
        } else if into_was_fallback {
            // The moved slots join the fallback: materialize them, then
            // drop their partial inner files (same contract as
            // fallback_group - the bytes now live in the volumes).
            for si in old.slots {
                self.fallback_slot(inner, si)?;
            }
            Self::delete_group_out_files(inner, into);
        } else {
            self.reresolve(inner, into)?;
        }
        Ok(())
    }

    /// Recompute volume order + split bases for a group; drain any holds
    /// that became mappable.
    ///
    /// Split-continuation bases are only valid over a GAPLESS run of
    /// volumes: resolving `part3` while `part2` is unparsed would assign
    /// part3's piece to part2's offsets. Volume indexes come from RAR5
    /// volume numbers when every member has one, else from the volume
    /// naming (.partNN / .rar,.rNN); resolution walks the sorted list only
    /// while the indexes stay consecutive.
    fn reresolve(&self, inner: &mut Inner, key: &str) -> io::Result<()> {
        let slots = inner.groups[key].slots.clone();
        let all_numbered = slots.iter().all(|&si| {
            inner.slots[si]
                .mapper
                .as_ref()
                .is_some_and(|m| m.volume_number.is_some())
        });
        let mut keyed: Vec<(Option<u64>, (u64, String), usize)> = slots
            .iter()
            .map(|&si| {
                let s = &inner.slots[si];
                let name_key = vol_sort_key(&s.name);
                let idx = if all_numbered {
                    s.mapper.as_ref().unwrap().volume_number
                } else if name_key.0 != u64::MAX {
                    Some(name_key.0)
                } else {
                    None
                };
                (idx, name_key, si)
            })
            .collect();
        keyed.sort();

        // Longest consecutive-index prefix (must have known indexes).
        let mut prefix: Vec<usize> = Vec::new();
        let mut prev: Option<u64> = None;
        for (idx, _, si) in &keyed {
            match (idx, prev) {
                (Some(k), None) => {
                    prefix.push(*si);
                    prev = Some(*k);
                }
                (Some(k), Some(p)) if *k == p + 1 => {
                    prefix.push(*si);
                    prev = Some(*k);
                }
                _ => break,
            }
        }
        let mappers: Vec<&VolumeMapper> = prefix
            .iter()
            .map(|&si| inner.slots[si].mapper.as_ref().unwrap())
            .collect();
        let resolved = ArchiveMap::resolve(&mappers);
        let mut bases = HashMap::new();
        for ((vi, ei), b) in resolved.bases {
            bases.insert((prefix[vi], ei), b);
        }
        inner.groups.get_mut(key).unwrap().bases = bases;

        for si in slots {
            if inner.slots[si].mode == SlotMode::Rar {
                // Full re-feed, not just re-extraction: a held span may
                // carry block-HEADER bytes that arrived while the parse
                // window was elsewhere (the mapper's stash only keeps
                // bytes near its cursor) - without re-feeding, mapping
                // stalls and a healthy group needlessly falls back.
                self.drain_holds(inner, si)?;
            }
        }
        Ok(())
    }

    /// Flush held spans through the slot's current mode.
    fn drain_holds(&self, inner: &mut Inner, slot: usize) -> io::Result<()> {
        let holds = std::mem::take(&mut inner.slots[slot].holds);
        inner.slots[slot].pre_bytes = 0;
        for (off, bytes) in holds {
            inner.budget.sub(bytes.len());
            match inner.slots[slot].mode {
                // No article CRC: a held span is a SUBSET of some earlier
                // article's bytes, re-fed later, so that article's CRC does
                // not describe it.
                SlotMode::Rar => self.rar_span(inner, slot, off, &bytes, None, false, None)?,
                SlotMode::RarChase | SlotMode::SevenZ => {
                    self.chase_span(inner, slot, off, &bytes)?
                }
                SlotMode::Discard => {}
                _ => self.plain_span(inner, slot, off, &bytes)?,
            }
        }
        Ok(())
    }

    /// One Unknown slot exceeded the per-slot pre-classification budget -
    /// flip just that slot to Plain and flush its holds to disk. Same
    /// safety argument as [`Self::overflow_to_plain`], applied before the
    /// GLOBAL cap wedges the whole pipeline on one unsniffable slot.
    fn spill_unclassified_slot(&self, inner: &mut Inner, slot: usize) -> io::Result<()> {
        if !matches!(inner.slots[slot].mode, SlotMode::Unknown) {
            return Ok(());
        }
        if inner.protect_sources {
            let name = inner.slots[slot].name.clone();
            inner
                .slot_fallbacks
                .push((name, "unclassified-holds budget".to_string()));
            self.discard_slot(inner, slot);
            return Ok(());
        }
        inner.slots[slot].mode = SlotMode::Plain;
        self.drain_holds(inner, slot)
    }

    /// Holds cap exceeded before sniffing finished - flip every Unknown
    /// slot to Plain (writes are safe; RAR mapping just won't happen).
    fn overflow_to_plain(&self, inner: &mut Inner) -> io::Result<()> {
        for si in 0..inner.slots.len() {
            if matches!(inner.slots[si].mode, SlotMode::Unknown)
                && !inner.slots[si].holds.is_empty()
            {
                if inner.protect_sources {
                    let name = inner.slots[si].name.clone();
                    inner
                        .slot_fallbacks
                        .push((name, "held-bytes cap".to_string()));
                    self.discard_slot(inner, si);
                    continue;
                }
                inner.slots[si].mode = SlotMode::Plain;
                self.drain_holds(inner, si)?;
            }
        }
        Ok(())
    }

    fn fallback_slot_or_group(
        &self,
        inner: &mut Inner,
        slot: usize,
        reason: &str,
    ) -> io::Result<()> {
        match inner.slots[slot].group.clone() {
            Some(key) => self.fallback_group(inner, &key, reason),
            None => {
                if !matches!(
                    inner.slots[slot].mode,
                    SlotMode::RarFallback | SlotMode::Discard
                ) {
                    // Phase 0(b): a group-less nested inner demotes here (a
                    // 7z - always slot-level - or a RAR that blocked before
                    // forming a group). Emit the `demoted` diagnostic with
                    // the reason BEFORE fallback_slot flips the mode to
                    // RarFallback; the archive itself is tallied under
                    // `disk` when the post-pass re-extracts the materialized
                    // volume, so this is never double-counted. `slot_inner_kind`
                    // returns None for a plain/unclassified slot, so a
                    // demoting non-archive stays silent (no tally bias).
                    if self.depth > 0 {
                        if let Some(kind) = Self::slot_inner_kind(inner, slot) {
                            note_nested_level(
                                self.depth,
                                kind,
                                NestedDisposition::Demoted(reason),
                            );
                        }
                    }
                    let name = inner.slots[slot].name.clone();
                    inner.slot_fallbacks.push((name, reason.to_string()));
                }
                self.fallback_slot(inner, slot)
            }
        }
    }

    /// Materialize every volume of a group and stop mapping it. The
    /// group's partially-extracted inner files are deleted afterwards -
    /// their bytes were reconstructed into the volume files, and a sparse
    /// half-written "extracted" file would masquerade as output.
    fn fallback_group(&self, inner: &mut Inner, key: &str, reason: &str) -> io::Result<()> {
        let grp = inner.groups.get_mut(key).unwrap();
        if grp.fallback {
            return Ok(());
        }
        grp.fallback = true;
        grp.fallback_reason = Some(reason.to_string());
        let members = grp.slots.clone();
        // A chased group tears its chase down FIRST: the worker stops
        // producing and its partial outputs are abandoned, then each
        // member's frontier buffer materializes below.
        if let Some(ctl) = inner.groups.get(key).and_then(|g| g.chase.clone()) {
            self.chase_teardown(inner, &ctl, reason);
        }
        for si in &members {
            self.fallback_slot(inner, *si)?;
        }
        Self::delete_group_out_files(inner, key);
        Ok(())
    }

    /// Source-protected fallback: no writer, no reconstruction - drop the
    /// held bytes (the source file already has them) and swallow all
    /// future spans.
    fn discard_slot(&self, inner: &mut Inner, slot: usize) {
        let holds = std::mem::take(&mut inner.slots[slot].holds);
        inner.slots[slot].pre_bytes = 0;
        for (_, bytes) in &holds {
            inner.budget.sub(bytes.len());
        }
        let headers = std::mem::take(&mut inner.slots[slot].header_spans);
        for (_, bytes) in &headers {
            inner.budget.sub(bytes.len());
        }
        inner.slots[slot].piece_crcs = HashMap::new();
        inner.slots[slot].mode = SlotMode::Discard;
    }

    /// Reconstruct one volume into a real file: header stash + extracted
    /// inner-file bytes + holds; future spans write through.
    fn fallback_slot(&self, inner: &mut Inner, slot: usize) -> io::Result<()> {
        if matches!(
            inner.slots[slot].mode,
            SlotMode::RarFallback | SlotMode::Discard
        ) {
            return Ok(());
        }
        // Every demote route funnels through here (group fallbacks call
        // this per member), so it is the one place the badge has to learn
        // that some of this set is going to disk after all.
        self.shape.note(self.depth, SH_MATERIALIZED);
        if inner.protect_sources {
            self.discard_slot(inner, slot);
            return Ok(());
        }
        // A demoting 7z chase abandons its worker's partial outputs
        // first; the worker itself unblocks on the buffer abort below.
        // The ctl stays IN the slot: sevenz_finish / Drop discover
        // workers by iterating slots that still hold one, so taking it
        // here would leave the thread detached and still copying into
        // abandoned sinks after finish() returned.
        if let Some(ctl) = inner.slots[slot].sevenz.clone() {
            self.sevenz_abandon_sinks(inner, &ctl);
        }
        // A chased slot's complete byte record lives in its frontier
        // buffer (headers, data, parked repair spans - everything since
        // attach was routed there): materialize it directly and SKIP the
        // entry read-back below, whose destinations hold DECODED member
        // bytes for this slot, not volume bytes.
        if let Some(ch) = inner.slots[slot].chase.take() {
            inner.slots[slot].mode = SlotMode::RarFallback;
            ch.buf.abort("demoted to materialized volume");
            for (off, bytes) in ch.buf.take_spans() {
                self.plain_span(inner, slot, off, &bytes)?;
            }
            inner.budget.sub(ch.charged);
            return self.drain_holds(inner, slot);
        }
        inner.slots[slot].mode = SlotMode::RarFallback;
        inner.slots[slot].piece_crcs = HashMap::new();

        // 1. Header bytes. The stash is released up front: a materialized
        // slot answers every read from its volume file, so the RAM copy
        // (and the budget it charges) buys nothing once the bytes are on
        // disk - and the whole stash leaves RAM here either way, so a
        // write error mid-loop must not leave the budget charged for
        // bytes nobody owns any more.
        let headers = std::mem::take(&mut inner.slots[slot].header_spans);
        inner
            .budget
            .sub(headers.iter().map(|(_, b)| b.len()).sum::<usize>());
        for (off, bytes) in &headers {
            self.plain_span(inner, slot, *off, bytes)?;
        }

        // 2. Already-extracted data areas: read back from inner files.
        let pieces: Vec<(String, u64, u64, Option<u64>)> = {
            match inner.slots[slot].mapper.as_ref() {
                Some(m) => m
                    .entries
                    .iter()
                    .enumerate()
                    .map(|(ei, e)| {
                        (
                            e.name.clone(),
                            e.data_off,
                            e.data_len,
                            Self::base_for(inner, slot, ei),
                        )
                    })
                    .collect(),
                None => Vec::new(),
            }
        };
        let mut buf = vec![0u8; 1 << 20];
        for (name, data_off, data_len, base) in pieces {
            let Some(base) = base else { continue };
            // Copy back ONLY ranges the destination has actually written.
            // The files are sparse-preallocated, so a hole preads as
            // zeros - and a decoder whose pwrite is queued but not yet
            // landed (the deferred-write window) would have its span
            // turned into zeros in the materialized volume while the
            // verifier had already passed those blocks from RAM. Skipped
            // ranges stay holes here; the bytes reach the volume either
            // via the article's own write-through (not yet arrived) or
            // via the post-write re-route in `write()` / the forward
            // delivery re-check (in flight).
            match Self::dest_for(inner, slot, &name) {
                // Plaintext-once output: the volume needs POSTED bytes,
                // so read back through the re-encrypt shim (which also
                // serves the seam/tail cipher the disk never held),
                // gated on arrived-cipher intervals.
                Some(Dest::Writer(w)) if Self::crypto_of(inner, &w).is_some() => {
                    let cr = Self::crypto_of(inner, &w).unwrap();
                    for (cs, ce) in cr.intervals(base, data_len) {
                        let mut done = cs;
                        while done < ce {
                            let n = (ce - done).min(buf.len() as u64) as usize;
                            if cr.read_posted(&w, done, &mut buf[..n]).is_err() {
                                break;
                            }
                            self.plain_span(inner, slot, data_off + (done - base), &buf[..n])?;
                            done += n as u64;
                        }
                    }
                }
                Some(Dest::Writer(w)) => {
                    let f = std::fs::File::open(&w.path)?;
                    for (cs, ce) in w.covered_intervals(base, data_len) {
                        let mut done = cs;
                        while done < ce {
                            let n = (ce - done).min(buf.len() as u64) as usize;
                            if crate::disk::read_exact_at(&f, &mut buf[..n], done).is_err() {
                                break;
                            }
                            self.plain_span(inner, slot, data_off + (done - base), &buf[..n])?;
                            done += n as u64;
                        }
                    }
                }
                // Routed file: the child serves its own reconstructible
                // view (it composes headers + its outputs recursively),
                // gated on the same interval discipline.
                Some(Dest::Child(c, cslot)) => {
                    for (cs, ce) in c.covered_intervals(cslot, base, data_len) {
                        let mut done = cs;
                        while done < ce {
                            let n = (ce - done).min(buf.len() as u64) as usize;
                            if c.read_at(cslot, done, &mut buf[..n]).is_err() {
                                break;
                            }
                            self.plain_span(inner, slot, data_off + (done - base), &buf[..n])?;
                            done += n as u64;
                        }
                    }
                }
                None => continue,
            }
        }

        // 3. Held spans flush through the plain path.
        self.drain_holds(inner, slot)
    }

    /// Poison-tolerant lock acquisition for the READ-ONLY accessors
    /// (`read_at` / `covered` / `covered_intervals` / `open_stream` /
    /// `writers_snapshot` / `map_output_range`). The daemon's stream
    /// server and verifier call these concurrently with the decode
    /// threads, so a single panic on a thread holding the routing lock
    /// would otherwise turn every later accessor call into a poison
    /// panic - wedging live /stream and stats reads for the rest of the
    /// job. Recovering the guard here is sound because these paths only
    /// OBSERVE a snapshot: whatever partial mutation the panicking
    /// thread left behind is exactly the state Drop-side recovery
    /// already exposes, a subsequent read cannot make it worse, and
    /// poisoning is purely advisory (no memory safety is at stake - the
    /// worst case is a read that reflects a half-applied routing step,
    /// which the interval/coverage checks already treat as "not there
    /// yet"). Write/mutate paths keep the strict unwrap on purpose: a
    /// poisoned lock there signals state too suspect to EXTEND, and
    /// failing loud beats folding more data into it.
    fn inner_read(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Byte-exact volume read for verifier read-back: headers from the
    /// stash, data areas from the extracted files (or the materialized
    /// volume file after fallback).
    /// True iff `[off, off+len)` of this slot's (volume-view) bytes are
    /// really on disk / in the header stash - a sparse hole would pread
    /// as zeros, so the M15 backfill path must ask first.
    pub fn covered(&self, slot: usize, off: u64, len: usize) -> bool {
        let inner = self.inner_read();
        let s = &inner.slots[slot];
        match s.mode {
            SlotMode::Plain | SlotMode::RarFallback => s
                .writer
                .as_ref()
                .is_some_and(|w| w.covered(off, len as u64)),
            // Chased slot: the frontier buffer is the byte record
            // (frontier + parked out-of-order spans).
            SlotMode::RarChase | SlotMode::SevenZ => s.chase.as_ref().is_some_and(|ch| {
                len == 0 || ch.buf.intervals(off, len as u64) == [(off, off + len as u64)]
            }),
            SlotMode::Rar => {
                let Some(m) = s.mapper.as_ref() else { return false };
                let mut filled = vec![false; len];
                // Held spans count: bytes that arrived but sit parked
                // behind an unparsed header (a lost mid-file entry
                // header leaves everything after it in holds) are real,
                // exact volume bytes - mapped repair must be able to
                // read them to rebuild the header blocks that free them.
                for (hs, bytes) in s.header_spans.iter().chain(&s.holds) {
                    let he = hs + bytes.len() as u64;
                    let qs = off.max(*hs);
                    let qe = (off + len as u64).min(he);
                    if qs < qe {
                        filled[(qs - off) as usize..(qe - off) as usize].fill(true);
                    }
                }
                for (ei, piece_off, span_off, plen) in m.map_span(off, len as u64) {
                    // Soft-skip like read_at: holds may already cover a
                    // range whose base/route is unresolved.
                    let Some(base) = Self::base_for(&inner, slot, ei) else { continue };
                    let ok = match Self::dest_for(&inner, slot, &m.entries[ei].name) {
                        // Plaintext-once file: coverage is in POSTED-byte
                        // terms (arrived cipher), not the plaintext the
                        // writer holds - seams and tail padding live in
                        // the crypto stashes, not on disk.
                        Some(Dest::Writer(w)) => match Self::crypto_of(&inner, &w) {
                            Some(cs) => cs.covers(base + piece_off, plen),
                            None => w.covered(base + piece_off, plen),
                        },
                        Some(Dest::Child(c, cs)) => {
                            c.covered(cs, base + piece_off, plen as usize)
                        }
                        None => false,
                    };
                    if !ok {
                        continue;
                    }
                    filled[span_off as usize..(span_off + plen) as usize].fill(true);
                }
                filled.iter().all(|&f| f)
            }
            // Unclassified slot: pre-sniff holds are exact file bytes.
            SlotMode::Unknown => {
                let mut filled = vec![false; len];
                for (hs, bytes) in &s.holds {
                    let he = hs + bytes.len() as u64;
                    let qs = off.max(*hs);
                    let qe = (off + len as u64).min(he);
                    if qs < qe {
                        filled[(qs - off) as usize..(qe - off) as usize].fill(true);
                    }
                }
                filled.iter().all(|&f| f)
            }
            SlotMode::Discard => false,
        }
    }

    pub fn read_at(&self, slot: usize, off: u64, buf: &mut [u8]) -> io::Result<()> {
        // Plan under the lock (header bytes are memcpy'd right away),
        // pread after releasing it - the mapped-repair path reads
        // thousands of blocks concurrently and must not serialize every
        // disk read behind the extractor lock. Child reads defer the same
        // way; the child plans under its own lock and reads lock-free.
        enum Plan {
            W(Arc<FileWriter>, usize, usize, u64),
            C(Arc<Extractor>, usize, usize, usize, u64),
            /// Plaintext-once output: posted bytes come from the
            /// re-encrypt shim + cipher stashes, not a raw pread.
            X(Arc<CryptoState>, Arc<FileWriter>, usize, usize, u64),
        }
        let mut reads: Vec<Plan> = Vec::new();
        {
            let inner = self.inner_read();
            let s = &inner.slots[slot];
            match s.mode {
                SlotMode::Plain | SlotMode::RarFallback => {
                    let w = s.writer.as_ref().ok_or_else(nofile)?;
                    reads.push(Plan::W(w.clone(), 0, buf.len(), off));
                }
                SlotMode::Rar => {
                    let m = s.mapper.as_ref().ok_or_else(nofile)?;
                    let mut filled = vec![false; buf.len()];
                    // Header stash first, then held spans: bytes parked
                    // behind an unparsed header are exact volume bytes,
                    // and mapped repair reads through here to rebuild
                    // the very header blocks that will free them.
                    for (hs, bytes) in s.header_spans.iter().chain(&s.holds) {
                        let he = hs + bytes.len() as u64;
                        let qs = off.max(*hs);
                        let qe = (off + buf.len() as u64).min(he);
                        if qs < qe {
                            let n = (qe - qs) as usize;
                            buf[(qs - off) as usize..(qs - off) as usize + n].copy_from_slice(
                                &bytes[(qs - hs) as usize..(qs - hs) as usize + n],
                            );
                            filled[(qs - off) as usize..(qs - off) as usize + n].fill(true);
                        }
                    }
                    for (ei, piece_off, span_off, len) in m.map_span(off, buf.len() as u64) {
                        // Unresolved base / unrouted destination is not
                        // fatal by itself: a continuation entry whose
                        // head volume is the very damage under repair
                        // keeps its arrived bytes in holds (served
                        // above) - only a range NOBODY can serve fails.
                        let Some(base) = Self::base_for(&inner, slot, ei) else { continue };
                        match Self::dest_for(&inner, slot, &m.entries[ei].name) {
                            Some(Dest::Writer(w)) => match Self::crypto_of(&inner, &w) {
                                Some(cs) => reads.push(Plan::X(
                                    cs,
                                    w,
                                    span_off as usize,
                                    len as usize,
                                    base + piece_off,
                                )),
                                None => reads.push(Plan::W(
                                    w,
                                    span_off as usize,
                                    len as usize,
                                    base + piece_off,
                                )),
                            },
                            Some(Dest::Child(c, cs)) => reads.push(Plan::C(
                                c,
                                cs,
                                span_off as usize,
                                len as usize,
                                base + piece_off,
                            )),
                            None => continue,
                        }
                        filled[span_off as usize..(span_off + len) as usize].fill(true);
                    }
                    if !filled.iter().all(|&f| f) {
                        return Err(nofile());
                    }
                }
                // Chased slot: byte-exact view straight from the
                // frontier buffer (RAM memcpy - fine under the lock).
                SlotMode::RarChase | SlotMode::SevenZ => {
                    let ch = s.chase.as_ref().ok_or_else(nofile)?;
                    ch.buf.peek(off, buf)?;
                }
                // Unclassified slot: serve from pre-sniff holds when they
                // fully cover the range (see covered_intervals).
                SlotMode::Unknown => {
                    let mut filled = vec![false; buf.len()];
                    for (hs, bytes) in &s.holds {
                        let he = hs + bytes.len() as u64;
                        let qs = off.max(*hs);
                        let qe = (off + buf.len() as u64).min(he);
                        if qs < qe {
                            let n = (qe - qs) as usize;
                            buf[(qs - off) as usize..(qs - off) as usize + n].copy_from_slice(
                                &bytes[(qs - hs) as usize..(qs - hs) as usize + n],
                            );
                            filled[(qs - off) as usize..(qs - off) as usize + n].fill(true);
                        }
                    }
                    if !filled.iter().all(|&f| f) {
                        return Err(nofile());
                    }
                }
                SlotMode::Discard => return Err(nofile()),
            }
        }
        for r in reads {
            match r {
                Plan::W(w, buf_start, len, file_off) => {
                    w.read_at(&mut buf[buf_start..buf_start + len], file_off)?;
                }
                Plan::C(c, cs, buf_start, len, file_off) => {
                    c.read_at(cs, file_off, &mut buf[buf_start..buf_start + len])?;
                }
                Plan::X(cs, w, buf_start, len, file_off) => {
                    cs.read_posted(&w, file_off, &mut buf[buf_start..buf_start + len])?;
                }
            }
        }
        Ok(())
    }

    /// The reconstructible sub-ranges of `[off, off+len)` of a slot's
    /// byte space, in slot offsets: writer intervals for plain and
    /// materialized slots, header stash + destination coverage (writers
    /// and routed children alike, recursively) for mapped ones. The
    /// fallback read-back walks these so a sparse hole or an in-flight
    /// deferred write is never copied as zeros.
    pub fn covered_intervals(&self, slot: usize, off: u64, len: u64) -> Vec<(u64, u64)> {
        let inner = self.inner_read();
        let s = &inner.slots[slot];
        match s.mode {
            SlotMode::Plain | SlotMode::RarFallback => s
                .writer
                .as_ref()
                .map(|w| w.covered_intervals(off, len))
                .unwrap_or_default(),
            SlotMode::RarChase | SlotMode::SevenZ => s
                .chase
                .as_ref()
                .map(|ch| ch.buf.intervals(off, len))
                .unwrap_or_default(),
            SlotMode::Rar => {
                let Some(m) = s.mapper.as_ref() else { return Vec::new() };
                let end = off + len;
                let mut ivs: Vec<(u64, u64)> = Vec::new();
                // Header stash + held spans (see read_at: held bytes are
                // exact volume bytes awaiting a header parse).
                for (hs, bytes) in s.header_spans.iter().chain(&s.holds) {
                    let he = hs + bytes.len() as u64;
                    let a = off.max(*hs);
                    let b = end.min(he);
                    if a < b {
                        ivs.push((a, b));
                    }
                }
                for (ei, piece_off, span_off, plen) in m.map_span(off, len) {
                    let Some(base) = Self::base_for(&inner, slot, ei) else { continue };
                    let file_lo = base + piece_off;
                    let sub = match Self::dest_for(&inner, slot, &m.entries[ei].name) {
                        Some(Dest::Writer(w)) => match Self::crypto_of(&inner, &w) {
                            Some(cs) => cs.intervals(file_lo, plen),
                            None => w.covered_intervals(file_lo, plen),
                        },
                        Some(Dest::Child(c, cs)) => c.covered_intervals(cs, file_lo, plen),
                        None => Vec::new(),
                    };
                    // Translate file-space intervals back to slot space.
                    for (a, b) in sub {
                        ivs.push((off + span_off + (a - file_lo), off + span_off + (b - file_lo)));
                    }
                }
                ivs.sort_unstable();
                let mut out: Vec<(u64, u64)> = Vec::new();
                for (a, b) in ivs {
                    if let Some(last) = out.last_mut()
                        && a <= last.1
                    {
                        last.1 = last.1.max(b);
                        continue;
                    }
                    out.push((a, b));
                }
                out
            }
            // Unclassified slot: pre-sniff holds are exact file bytes at
            // file offsets (a nested child whose offset-0 header is the
            // very damage being repaired sits here).
            SlotMode::Unknown => {
                let end = off + len;
                let mut ivs: Vec<(u64, u64)> = Vec::new();
                for (hs, bytes) in &s.holds {
                    let he = hs + bytes.len() as u64;
                    let a = off.max(*hs);
                    let b = end.min(he);
                    if a < b {
                        ivs.push((a, b));
                    }
                }
                ivs.sort_unstable();
                let mut out: Vec<(u64, u64)> = Vec::new();
                for (a, b) in ivs {
                    if let Some(last) = out.last_mut()
                        && a <= last.1
                    {
                        last.1 = last.1.max(b);
                        continue;
                    }
                    out.push((a, b));
                }
                out
            }
            SlotMode::Discard => Vec::new(),
        }
    }

    /// M2c.1 - patch `[off, off+data.len())` of a mapped slot's VOLUME
    /// view with repaired bytes. Routed through the normal streaming
    /// [`write`] path: a rebuilt block is just late-arriving article
    /// data, so mapped pieces land in the extracted output, envelope
    /// bytes stash like any other header bytes, and - crucially - the
    /// volume parser resumes past what the lost articles interrupted
    /// (e.g. the end-of-archive record in a lost tail article), letting
    /// [`finish`] complete the group instead of falling back. The
    /// caller's whole-file MD5 over [`read_at`] remains the arbiter of
    /// whether the patch actually reconstructed the volume. The span
    /// carries the repair marker down the routing chain: rebuilt bytes
    /// REPLACE a range whose earlier (wire-damaged) arrival may already
    /// sit composed in the piece CRCs, and without the marker the
    /// composition would clip the rewrite as a duplicate and keep the
    /// stale value - demoting, at finish, a job whose output healed
    /// cleanly (see [`CrcRuns::overwrite`]).
    ///
    /// [`write`]: Extractor::write
    /// [`finish`]: Extractor::finish
    /// [`read_at`]: Extractor::read_at
    pub fn patch_volume_span(&self, slot: usize, off: u64, data: &[u8]) -> io::Result<()> {
        let (name, size) = {
            let inner = self.inner.lock().unwrap();
            let s = &inner.slots[slot];
            if !matches!(s.mode, SlotMode::Rar) {
                return Err(nofile());
            }
            (s.name.clone(), s.size)
        };
        // Repair bytes REPLACE a range that may already have composed;
        // reuse is excluded for repair anyway.
        self.write_impl(slot, &name, size, off, data, true, None).map(|_| ())
    }

    /// Every live output writer (extracted inner files + plain files) -
    /// the streaming server picks media files from this and polls their
    /// coverage. (name, writer).
    /// M11 seek support: translate a byte range of an OUTPUT file (a plain
    /// slot file, or an extracted inner file) to the source-volume pieces
    /// that carry it: `(slot, vol_start, vol_end, slot_total_size)`.
    /// Best-effort - only pieces whose group bases have resolved appear;
    /// `slot_total_size` is the volume's decoded size (0 if unknown yet),
    /// which the caller uses to scale offsets onto the article list.
    pub fn map_output_range(&self, name: &str, start: u64, end: u64) -> Vec<(usize, u64, u64, u64)> {
        let inner = self.inner_read();
        // Plain slot file: identity mapping on that slot.
        for (si, s) in inner.slots.iter().enumerate() {
            if let Some(w) = &s.writer {
                let fname = w.path.file_name().unwrap_or_default().to_string_lossy();
                if fname == name {
                    return vec![(si, start.min(w.size), end.min(w.size), w.size)];
                }
            }
        }
        // Extracted inner file: walk every resolved (volume-slot, entry)
        // piece of the archive and clip the requested inner range to it.
        // `bases` is a HashMap - pieces MUST be re-sorted by their output
        // offset, because callers (M11 seek promotion) treat the returned
        // order as the player's read order; unsorted, a range spanning a
        // volume boundary could promote the later volume's articles ahead
        // of the seek point's own.
        let mut pieces: Vec<(u64, (usize, u64, u64, u64))> = Vec::new();
        for g in inner.groups.values() {
            for (&(slot, ei), &base) in &g.bases {
                let Some(m) = inner.slots[slot].mapper.as_ref() else { continue };
                let Some(e) = m.entries.get(ei) else { continue };
                if e.is_dir {
                    continue;
                }
                // Look up by the RAW entry name (route_dest/inner_writer key);
                // the sanitized form is only the on-disk fallback name.
                let out_name = if let Some(&cs) = g.routed.get(&e.name) {
                    // A routed level-1 file is an OUTPUT only when its
                    // child slot went Plain (real file, possibly under a
                    // disambiguated name). Any other mode is still
                    // addressable by the entry name itself - a child
                    // slot's byte space is that file's byte space by
                    // construction, which is what the nested promote
                    // walk (map_to_root composition) asks by. Seek
                    // mapping INTO a nested archive's outputs stays out
                    // of scope for v1 - those fall to the non-mapped
                    // path.
                    match inner.child.as_ref().and_then(|c| c.plain_slot_out_name(cs)) {
                        Some(n) => n,
                        None => sanitize_filename(&e.name),
                    }
                } else {
                    g.out_names
                        .get(&e.name)
                        .cloned()
                        .unwrap_or_else(|| sanitize_filename(&e.name))
                };
                if out_name != name {
                    continue;
                }
                let piece_end = base + e.data_len;
                let s = start.max(base);
                let en = end.min(piece_end);
                if s < en {
                    pieces.push((
                        s,
                        (
                            slot,
                            e.data_off + (s - base),
                            e.data_off + (en - base),
                            inner.slots[slot].size,
                        ),
                    ));
                }
            }
        }
        let mut out: Vec<(usize, u64, u64, u64)> = Vec::new();
        if !pieces.is_empty() {
            pieces.sort_by_key(|(s, _)| *s);
            return pieces.into_iter().map(|(_, p)| p).collect();
        }
        // Deep seek past the parse frontier: bases resolve in volume order
        // behind the download, so a far-forward seek has no resolved piece
        // yet - exactly the case promotion exists for. Estimate instead:
        // volumes are uniform, so scale the inner offset across the
        // group's volume slots (±1 volume of slack; the caller's article
        // ladder adds its own).
        let Some(g) = inner
            .groups
            .iter()
            .find(|(k, g)| {
                sanitize_filename(k) == name || g.out_names.values().any(|v| v == name)
            })
            .map(|(_, g)| g)
        else {
            return out;
        };
        // Any resolved piece gives the per-volume data size + data offset.
        let Some((per_vol, data_off)) = g.bases.keys().find_map(|&(slot, ei)| {
            let e = inner.slots[slot].mapper.as_ref()?.entries.get(ei)?;
            (e.data_len > 0).then_some((e.data_len, e.data_off))
        }) else {
            return out;
        };
        let mut vols: Vec<usize> = g.slots.clone();
        vols.sort_by_key(|&si| vol_sort_key(&inner.slots[si].name));
        for (vi, &si) in vols.iter().enumerate() {
            let vbase = vi as u64 * per_vol;
            let s = start.max(vbase);
            let en = end.min(vbase + per_vol);
            if s < en {
                out.push((
                    si,
                    data_off + (s - vbase),
                    data_off + (en - vbase),
                    inner.slots[si].size,
                ));
            }
        }
        out
    }

    pub fn writers_snapshot(&self) -> Vec<(String, Arc<FileWriter>)> {
        let (mut out, child) = {
            let inner = self.inner_read();
            let mut out: Vec<(String, Arc<FileWriter>)> = inner
                .inner_writers
                .iter()
                .map(|(n, w)| (n.clone(), w.clone()))
                .collect();
            for s in &inner.slots {
                if let Some(w) = &s.writer {
                    out.push((
                        w.path
                            .file_name()
                            .unwrap_or_default()
                            .to_string_lossy()
                            .to_string(),
                        w.clone(),
                    ));
                }
            }
            (out, inner.child.clone())
        };
        // Routed outputs (the common flat case included) live in the
        // child chain - the streaming server must see them.
        if let Some(c) = child {
            out.extend(c.writers_snapshot());
        }
        out
    }

    /// Output filename of a Plain slot (nested seek mapping: a routed
    /// level-1 file whose child slot went Plain IS the output file).
    /// Poison-tolerant like its caller: `map_output_range` calls this on
    /// the CHILD while holding the PARENT lock, so a poisoned child lock
    /// panicking here would poison the parent too and cascade upward.
    fn plain_slot_out_name(&self, slot: usize) -> Option<String> {
        let inner = self.inner_read();
        let s = &inner.slots[slot];
        if !matches!(s.mode, SlotMode::Plain) {
            return None;
        }
        s.writer
            .as_ref()
            .map(|w| w.path.file_name().unwrap_or_default().to_string_lossy().into_owned())
    }

    /// (name, size) of every slot-owned output file - what a PARENT folds
    /// into its report when this extractor is its child: a Plain slot is
    /// a level-N file delivered as-is, a RarFallback slot is a level-N
    /// archive materialized by a nested demotion (today's output either
    /// way).
    fn slot_output_files(&self) -> Vec<(String, u64)> {
        let inner = self.inner.lock().unwrap();
        inner
            .slots
            .iter()
            .filter(|s| matches!(s.mode, SlotMode::Plain | SlotMode::RarFallback))
            .filter_map(|s| {
                s.writer.as_ref().map(|w| {
                    (
                        w.path
                            .file_name()
                            .unwrap_or_default()
                            .to_string_lossy()
                            .into_owned(),
                        w.size,
                    )
                })
            })
            .collect()
    }

    /// Path of the slot's on-disk file (plain/materialized), if any.
    pub fn slot_path(&self, slot: usize) -> Option<PathBuf> {
        let inner = self.inner.lock().unwrap();
        inner.slots[slot].writer.as_ref().map(|w| w.path.clone())
    }

    /// (file name, size) of the slot's on-disk file - what the journal
    /// records as the slot's restore destination.
    pub fn slot_file_info(&self, slot: usize) -> Option<(String, u64)> {
        let inner = self.inner.lock().unwrap();
        inner.slots[slot].writer.as_ref().map(|w| {
            (
                w.path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned(),
                w.size,
            )
        })
    }

    /// Crash resume: adopt `file_name` (already restored on disk by the
    /// journal, `spans` of it trusted) as this slot's plain writer. The
    /// slot classifies Plain immediately - refetched articles write
    /// through, and `covered`/`read_at` serve the restored spans to the
    /// M15b backfill so they hash against the PAR2 block map in-download.
    pub fn seed_slot(
        &self,
        slot: usize,
        file_name: &str,
        size: u64,
        spans: &[(u64, u64)],
    ) -> io::Result<()> {
        let mut g = self.inner.lock().unwrap();
        let inner = &mut *g;
        if inner.slots[slot].writer.is_some() {
            return Ok(());
        }
        let path = self.out_dir.join(file_name);
        let cur = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        // Same reservation ceiling every other writer gets: the journal's
        // `size` came from a slot size the poster declared, so it may not
        // reserve the disk either. `size.max(cur)` stays the writer's
        // `size` (the adopted spans and `s.size` below both read it) - the
        // cap bounds only what is RESERVED, and never below `cur`, so a
        // resumed file keeps every byte it already holds.
        let cap = inner.limits.prealloc_cap();
        let w = Arc::new(FileWriter::create_resume_capped(&path, size.max(cur), cap)?);
        for &(off, len) in spans {
            w.note_written(off, len);
        }
        inner.names_taken.lock().unwrap().insert(name_collision_key(inner.fold_names, file_name));
        let s = &mut inner.slots[slot];
        s.mode = SlotMode::Plain;
        s.name = file_name.to_string();
        s.size = size.max(cur);
        s.writer = Some(w);
        Ok(())
    }

    /// Whether the slot is being direct-extracted (no on-disk volume).
    /// Deliberately does NOT consult routed child slots: verifier settle
    /// and mapped repair read the volume view through [`Self::read_at`],
    /// which delegates per range and fails only for ranges the chain
    /// truly cannot serve - a whole-slot veto here would push a healthy
    /// mapped slot onto the no-writer path (worse than a few bad blocks).
    pub fn is_mapped(&self, slot: usize) -> bool {
        matches!(self.inner.lock().unwrap().slots[slot].mode, SlotMode::Rar)
    }


    /// Open an output file for /stream. For an encrypted store output
    /// still on disk as ciphertext, this returns a [`StreamCrypt`] the
    /// reader decrypts through on the fly (so encrypted releases stream
    /// mid-download, not just after the finish decrypt) and leases a live
    /// reader so finish() will temp+rename instead of mutating in place.
    /// The file is opened HERE, under the lock, so the ciphertext-vs-
    /// plaintext decision can't race the finish rename. Plain files (the
    /// common case) return [`StreamOpen::Plain`] and are opened by the
    /// caller exactly as before.
    pub fn open_stream(&self, out_name: &str) -> StreamOpen {
        // Poison-tolerant (see `inner_read`): this is the /stream read
        // path. Its only mutations are inserting a fresh per-output
        // stream state and bumping its reader count - both self-
        // contained and independent of the routing state a panicking
        // writer could have been mid-mutation on, so serving a read
        // after recovery is as safe as the pure readers above.
        let mut g = self.inner_read();
        let inner = &mut *g;
        // Plaintext-once output: the disk already holds plaintext, so
        // the reader serves raw ranges exactly like any plain file (its
        // coverage answers come from the writer, which only ever holds
        // decrypted bytes).
        if inner.crypto_files.contains_key(out_name) {
            return StreamOpen::Plain;
        }
        let Some((path, crypt, unp)) = Self::locate_encrypted_output(inner, out_name) else {
            // Not one of ours - a nested child may own the name (its
            // encrypted outputs live in its own writer map).
            let child = inner.child.clone();
            drop(g);
            return match child {
                Some(c) => c.open_stream(out_name),
                None => StreamOpen::Plain,
            };
        };
        let aes = inner
            .password
            .as_ref()
            .and_then(|pw| rarcrypt::derive_keys(pw, &crypt.salt, crypt.lg2_count));
        let Some(aes) = aes else {
            // Verified encrypted output with an underivable password
            // shouldn't reach here (the group would have fallen back);
            // serve raw rather than hand out a broken decryptor.
            return StreamOpen::Plain;
        };
        let st = inner
            .stream_states
            .entry(out_name.to_string())
            .or_insert_with(|| {
                Arc::new(StreamState {
                    state: Mutex::new(DecState::Ciphertext),
                    readers: AtomicUsize::new(0),
                })
            })
            .clone();
        let state = *st.state.lock().unwrap();
        match state {
            DecState::Decrypted => StreamOpen::Plain,
            DecState::Ciphertext => match std::fs::File::open(&path) {
                Ok(f) => {
                    st.readers.fetch_add(1, Ordering::Relaxed);
                    StreamOpen::Encrypted(
                        f,
                        StreamCrypt {
                            key: aes.key,
                            iv: crypt.iv,
                            cipher_len: rarcrypt::align16(unp),
                            plain_len: unp,
                            st,
                        },
                    )
                }
                Err(_) => StreamOpen::Plain,
            },
        }
    }

    /// (path, crypt params, unpacked size) of an encrypted head-piece
    /// output file by its output name, in a non-fallback group.
    fn locate_encrypted_output(
        inner: &Inner,
        out_name: &str,
    ) -> Option<(PathBuf, EntryCrypt, u64)> {
        for grp in inner.groups.values() {
            if grp.fallback {
                continue;
            }
            for &si in &grp.slots {
                let Some(m) = inner.slots[si].mapper.as_ref() else { continue };
                for e in &m.entries {
                    if e.is_dir || !e.encrypted || e.split_before {
                        continue;
                    }
                    let Some(c) = &e.crypt else { continue };
                    // out_names is keyed on the RAW name; the sanitized form
                    // is the on-disk fallback (route_dest/inner_writer key).
                    let out = grp
                        .out_names
                        .get(&e.name)
                        .cloned()
                        .unwrap_or_else(|| sanitize_filename(&e.name));
                    if out != out_name {
                        continue;
                    }
                    if let Some(w) = inner.inner_writers.get(&out) {
                        return Some((w.path.clone(), c.clone(), e.unpacked_size));
                    }
                }
            }
        }
        None
    }

    /// PAR2 deobfuscation rename: update the name a future materialization
    /// (or plain-writer creation) will use.
    pub fn rename(&self, slot: usize, new_name: &str) {
        let mut inner = self.inner.lock().unwrap();
        if inner.slots[slot].writer.is_none() {
            inner.slots[slot].name = new_name.to_string();
        }
    }

    /// Force materialization of a slot's group (e.g. PAR2 repair needs the
    /// volume files on disk).
    pub fn materialize(&self, slot: usize) -> io::Result<()> {
        {
            let mut inner = self.inner.lock().unwrap();
            let inner = &mut *inner;
            if matches!(
                inner.slots[slot].mode,
                SlotMode::Rar | SlotMode::RarChase | SlotMode::SevenZ
            ) {
                self.fallback_slot_or_group(inner, slot, "materialized for repair")?;
            }
        }
        self.flush_pending_fwd()
    }

    /// Download over: no more articles can arrive, so a slot still waiting
    /// on its offset-0 sniff will never classify. Flush its held spans to
    /// a plain file so verification read-back and PAR2 repair see the
    /// bytes on disk - a lost head article must cost one article's worth
    /// of repair blocks, not turn the whole target into "missing".
    /// Propagates down the child chain: a routed level-1 file still
    /// waiting on ITS sniff settles Plain the same way (it can still
    /// receive late repair-patch bytes as an ordinary file).
    pub fn settle_unclassified(&self) -> io::Result<()> {
        let child = {
            let mut g = self.inner.lock().unwrap();
            self.overflow_to_plain(&mut g)?;
            g.child.clone()
        };
        self.flush_pending_fwd()?;
        if let Some(c) = child {
            c.settle_unclassified()?;
        }
        Ok(())
    }

    /// End-of-download: settle groups that never finished mapping, flush
    /// stray holds, sync writers, and report. A nested child finishes
    /// BEFORE this level's sync phase - its own settle demotes any
    /// unfinished child slot to a materialized level-1 file (today's
    /// output), and its report folds into ours.
    pub fn finish(&self) -> io::Result<ExtractReport> {
        // Chase workers join FIRST: their sink writes must have landed
        // before the child settles/finishes, and a chase still blocked
        // here (bytes never arrived) aborts and demotes. The 7z workers
        // follow the same contract.
        self.chase_finish()?;
        self.sevenz_finish()?;
        self.settle_groups()?;
        // Settle re-fed holds under the lock; any child forwards it
        // queued must land before the child settles itself.
        self.flush_pending_fwd()?;
        // Every byte is routed now; check nested store payloads against
        // their header CRCs BEFORE the decrypt pass (a demoting group
        // must still materialize exact volume bytes) and before the
        // child finishes (the demote abandons its routed child slots).
        self.verify_inner_crcs()?;
        // The decrypt pass does its own phased locking: the in-place AES
        // I/O over multi-GB files must not hold the routing lock (the
        // daemon's stats/stream calls read through it).
        let mut decrypted = self.decrypt_finished()?;
        let child = self.inner.lock().unwrap().child.clone();
        let child_fold = match &child {
            Some(c) => Some((c.finish()?, c.slot_output_files())),
            None => None,
        };
        let mut g = self.inner.lock().unwrap();
        let inner = &mut *g;

        // A sync failure (ENOSPC/EIO) means buffered pwrites never reached
        // disk - swallowing it here let a job exit 0 with corrupt output
        // and a journal that recorded those articles persisted. Sync
        // everything, then fail loud if anything failed.
        let mut sync_err: Option<io::Error> = None;
        let mut extracted: Vec<(String, u64)> = Vec::new();
        for (name, w) in &inner.inner_writers {
            extracted.push((name.clone(), w.size));
            if let Err(e) = w.sync() {
                sync_err.get_or_insert(e);
            }
        }
        for s in &inner.slots {
            if let Some(w) = &s.writer {
                if let Err(e) = w.sync() {
                    sync_err.get_or_insert(e);
                }
            }
        }
        if let Some(e) = sync_err {
            return Err(e);
        }
        let mut fallbacks: Vec<(String, String)> = inner
            .groups
            .iter()
            .filter(|(_, g)| g.fallback)
            .map(|(s, g)| (s.clone(), g.fallback_reason.clone().unwrap_or_default()))
            .collect();
        fallbacks.extend(inner.slot_fallbacks.iter().cloned());
        // Phase 0(b): one prevalence line per inner archive this level
        // streamed. Runs on THIS level's own groups/slots (self.depth);
        // each child level already reported its own via c.finish() above.
        self.report_nested_prevalence(inner);
        // Fold the child chain in: its slot files (Plain level-1 files
        // and materialized nested demotions) and its own extracted list
        // are all outputs of THIS extraction; its fallbacks are demotions
        // that already produced today's output, reported distinctly so
        // volume-level remediation never keys off them.
        if let Some((crep, cfiles)) = child_fold {
            extracted.extend(crep.extracted);
            extracted.extend(cfiles);
            for (key, why) in crep.fallbacks {
                fallbacks.push((key, nested_reason(&why)));
            }
            decrypted.extend(crep.decrypted);
            decrypted.sort();
        }
        extracted.sort();
        Ok(ExtractReport {
            extracted,
            fallbacks,
            extracted_bytes: inner.extracted_bytes,
            decrypted,
        })
    }

    /// Phase 0(b) prevalence: emit one line per inner archive this level
    /// handled in-stream, with its type and disposition. Nested levels
    /// only (`self.depth > 0`) - a single-layer job's outer archives are
    /// depth 0 and never counted. RAR inners live in `groups` (store and
    /// chase alike; the kind reads off the mapper's first entry, which
    /// survives a demote); an in-stream 7z is a group-less slot in
    /// `SevenZ` mode. A demoted inner is logged `demoted` (with the
    /// reason) and left for the disk post-pass to tally under `disk`, so
    /// it is never counted twice.
    fn report_nested_prevalence(&self, inner: &Inner) {
        if self.depth == 0 {
            return;
        }
        for grp in inner.groups.values() {
            let kind = Self::group_inner_kind(inner, grp);
            match (grp.fallback, grp.fallback_reason.as_deref()) {
                (true, reason) => note_nested_level(
                    self.depth,
                    kind,
                    NestedDisposition::Demoted(reason.unwrap_or("demoted")),
                ),
                (false, _) => {
                    note_nested_level(self.depth, kind, NestedDisposition::InStream)
                }
            }
        }
        // In-stream 7z inners are slot-level (not in `groups`): a slot
        // still in `SevenZ` mode at finish streamed successfully. A
        // demoted 7z is `RarFallback` by now - its `demoted` diagnostic
        // was emitted at the demote site (fallback_slot_or_group, which
        // still sees the `SevenZ` mode), and the materialized volume is
        // tallied under `disk` by the post-pass.
        for s in &inner.slots {
            if matches!(s.mode, SlotMode::SevenZ) && s.group.is_none() {
                note_nested_level(self.depth, "7z", NestedDisposition::InStream);
            }
        }
    }

    /// Classify a single group-less slot for a demote-site prevalence
    /// line, or `None` when it is not a nested archive. Only the three
    /// nested-archive modes count: a plain file, an unclassified span, or
    /// an already-demoted slot returns `None` and stays silent, so a
    /// demoting non-archive never biases the tally. Must be read BEFORE
    /// `fallback_slot` flips the slot to `RarFallback`. `RarChase` slots
    /// always own a group (handled at finish), so a group-less chase mode
    /// is defensive only.
    fn slot_inner_kind(inner: &Inner, slot: usize) -> Option<&'static str> {
        match inner.slots[slot].mode {
            SlotMode::SevenZ => Some("7z"),
            SlotMode::RarChase => Some("rar-compressed"),
            SlotMode::Rar => Some(
                match inner.slots[slot].mapper.as_ref().and_then(|m| m.entries.first()) {
                    Some(e) if e.encrypted || e.crypt.is_some() => "rar-encrypted",
                    Some(e) => match e.method {
                        Method::Store => "rar-store",
                        Method::Compressed => "rar-compressed",
                    },
                    // Mode Rar means it mapped as a store RAR, so this is
                    // effectively unreachable; classify as store rather than
                    // guess a sub-type.
                    None => "rar-store",
                },
            ),
            SlotMode::Unknown
            | SlotMode::Plain
            | SlotMode::RarFallback
            | SlotMode::Discard => None,
        }
    }

    /// Classify a RAR group for the prevalence line from its first mapped
    /// entry - encryption wins (it is the salient blocker), then the
    /// compression method. Reads the mapper, which outlives a demote, so a
    /// fallen-back group still classifies correctly.
    fn group_inner_kind(inner: &Inner, grp: &Group) -> &'static str {
        for si in &grp.slots {
            if let Some(m) = inner.slots[*si].mapper.as_ref() {
                if let Some(e) = m.entries.first() {
                    if e.encrypted || e.crypt.is_some() {
                        return "rar-encrypted";
                    }
                    return match e.method {
                        Method::Store => "rar-store",
                        Method::Compressed => "rar-compressed",
                    };
                }
            }
        }
        "other"
    }

    /// In-stream store-payload CRC gate: a store set whose DATA was
    /// damaged before the poster packed it maps cleanly - the headers
    /// are intact - and would one-pass extract silently corrupt, because
    /// the download's PAR2 vouches for the outer bytes AS POSTED, damage
    /// included, and the extracted payload has no other verifier. RAR5
    /// file headers carry the unpacked data's CRC32; the routing path
    /// composed each piece's CRC as the bytes flowed (see `CrcRuns`),
    /// and the last split piece's header holds the whole-file value -
    /// the same one unrar checks. Any completed file that mismatches
    /// demotes its group to materialized volumes, where the disk
    /// post-pass can run a packed-alongside par2 set (or fail honestly).
    /// Entries whose bytes never fully arrived are skipped - missing
    /// articles are the outer repair ladder's problem, not proof of
    /// pre-packed damage. A header set that does NOT tile its declared
    /// file is a different matter and DEMOTES: tiling is decided purely
    /// from the headers, so a non-tiling set is a broken (or hostile)
    /// archive description, never a delivery gap. Also skipped are
    /// entries this gate cannot speak to at all (compressed, encrypted)
    /// and level-0 entries whose header carries
    /// no CRC (RAR4, encrypted); a NESTED RAR4 store file demotes
    /// instead, because the disk-path unrar is the only CRC check it
    /// will ever meet. The gate itself never errors the extraction: its
    /// only verdict is the demotion, which routes damage to where
    /// unrar/PAR2 can catch it. Nested levels always run the gate;
    /// level 0 (the FINAL extracted output) runs it under the
    /// verify_output_crc setting.
    fn verify_inner_crcs(&self) -> io::Result<()> {
        let mut g = self.inner.lock().unwrap();
        if self.depth == 0 && !g.verify_output_crc {
            return Ok(());
        }
        let inner = &mut *g;
        Self::recompose_repair_gaps(inner);
        let keys: Vec<String> = inner.groups.keys().cloned().collect();
        for key in keys {
            if inner.groups[&key].fallback {
                continue;
            }
            let members: Vec<(usize, usize)> = inner.groups[&key]
                .slots
                .iter()
                .flat_map(|&si| {
                    let n = inner.slots[si].mapper.as_ref().map_or(0, |m| m.entries.len());
                    (0..n).map(move |ei| (si, ei))
                })
                .collect();
            // name → (base, piece len, composed run, last piece's header
            // CRC). Unverifiable pieces poison their whole file, never
            // the group.
            struct Piece {
                base: Option<u64>,
                len: u64,
                total: u64,
                run: Option<u32>,
                hdr: Option<u32>,
                v4: bool,
                /// Entry carries an FHEXTRA_HASH record (e.g. BLAKE2sp) but
                /// no in-stream CRC - integrity data this gate can't compose.
                has_hash: bool,
                /// Unencrypted STORE: the only shape whose bytes this gate
                /// can compose a CRC over at all.
                checkable: bool,
            }
            let mut files: HashMap<String, Vec<Piece>> = HashMap::new();
            for (si, ei) in members {
                let base = Self::base_for(inner, si, ei);
                let s = &inner.slots[si];
                let m = s.mapper.as_ref().unwrap();
                let e = &m.entries[ei];
                if e.is_dir || e.unpacked_size == 0 {
                    continue;
                }
                let checkable = matches!(e.method, Method::Store) && !e.encrypted;
                files.entry(e.name.clone()).or_default().push(Piece {
                    base,
                    len: e.data_len,
                    total: e.unpacked_size,
                    run: s
                        .piece_crcs
                        .get(&ei)
                        .and_then(|r| r.whole(e.data_len))
                        .filter(|_| checkable),
                    hdr: if !e.split_after { e.file_crc } else { None },
                    v4: matches!(m.version, Some(RarVersion::V4)),
                    has_hash: !e.split_after && e.hash.is_some(),
                    checkable,
                });
            }
            for (_name, mut pieces) in files {
                // A member this gate can never speak to (compressed, or
                // encrypted - the decrypt pass owns that check) is not
                // evidence of anything. Unchanged: skip.
                if pieces.iter().any(|p| !p.checkable) {
                    continue;
                }
                pieces.sort_by_key(|p| p.base);
                let total = pieces[0].total;
                // The pieces must tile [0, total) exactly, and the final
                // one must carry the whole-file CRC.
                //
                // Tiling is computed BEFORE the byte-arrival check on
                // purpose: it is a pure HEADER property (base, data_len,
                // unpacked_size), so "the headers do not describe a whole
                // file" is knowable no matter which articles landed, and it
                // is a different failure from "the bytes never arrived".
                // Conflating them let a single well-formed volume declare
                // `unpacked_size` = 64 GiB against a few hundred KB of real
                // store data and ship the preallocated sparse tail as a
                // successful extraction: `run` was Some, `hdr` was None
                // (split_after set), and every demote below was gated on
                // `tiled`, so the file fell out of the gate entirely.
                let mut at = 0u64;
                let tiled = pieces.iter().all(|p| {
                    let ok = p.base == Some(at) && p.total == total;
                    at += p.len;
                    ok
                }) && at == total;
                if !tiled {
                    self.fallback_group(
                        inner,
                        &key,
                        "inner file's headers do not describe a complete file",
                    )?;
                    break;
                }
                // Bytes that never arrived ARE the outer repair ladder's
                // problem, not proof of pre-packed damage - skip, as before.
                if pieces.iter().any(|p| p.run.is_none()) {
                    continue;
                }
                let Some(expected) = pieces.last().and_then(|p| p.hdr) else {
                    // RAR4 file headers carry a CRC32 the mapper does
                    // not consume, so a completed RAR4 store file can
                    // never be verified in-stream. NESTED, that demotes
                    // to materialized volumes - the disk-path unrar
                    // checks the CRC there - instead of clean-passing
                    // the one family this gate cannot see. At level 0
                    // it skips: the output-CRC gate is best-effort
                    // hardening on top of the outer PAR2, and demoting
                    // every RAR4 job to the double-I/O disk path would
                    // regress the common case the gate exists to keep
                    // fast. Files whose bytes never fully arrived still
                    // skip above: missing articles are the outer repair
                    // ladder's problem, not proof of pre-packed damage.
                    // (Everything here tiles - a header set that doesn't
                    // already demoted.)
                    if self.depth > 0 && pieces.iter().any(|p| p.v4) {
                        self.fallback_group(inner, &key, "inner RAR4 file lacks an in-stream CRC")?;
                        break;
                    }
                    // The entry stores an FHEXTRA_HASH digest (BLAKE2sp) in
                    // place of a CRC. This gate composes CRC32 only, so it
                    // cannot verify the hash - but the digest proves the format
                    // INTENDS integrity checking, so silently passing corrupt
                    // (damaged-before-posting) bytes is wrong. Demote to the
                    // disk path, where the unrar codec verifies BLAKE2sp. Rare
                    // enough (most RAR5 writers still emit CRC32) that the
                    // double-I/O cost is acceptable at any depth.
                    if pieces.iter().any(|p| p.has_hash) {
                        self.fallback_group(inner, &key, "inner file carries only a hash the fast path can't verify")?;
                        break;
                    }
                    continue;
                };
                let mut crc = 0u32;
                for p in &pieces {
                    crc = crate::yenc_simd::crc32_combine(crc, p.run.unwrap(), p.len);
                }
                if crc != expected {
                    // No file name in the reason: callers branch on
                    // substrings of it ("password", "compressed"…) and a
                    // hostile inner name must not steer them. The group
                    // key names the archive in every report line.
                    self.fallback_group(inner, &key, "inner file failed its stored CRC")?;
                    break;
                }
            }
        }
        Ok(())
    }

    /// Close the composition holes a mapped repair left behind: an
    /// overwrite that lands mid-run discards the run's composed CRC, and
    /// the run's sub-ranges outside the repair span become stale gaps
    /// (see [`CrcRuns`]). Every such byte is already routed and on
    /// disk - exactly what the composition originally hashed - so
    /// recompute each gap from its destination (inner-file writer, or
    /// the nested child's view; downward child calls under our lock
    /// follow the `covered` precedent) and fold it back in. This keeps
    /// the gate's teeth after a repair: pre-packed damage ELSEWHERE in a
    /// repaired file still mismatches and demotes. A gap that cannot be
    /// read back simply stays a gap - the piece reads as unverifiable
    /// and skips, today's assurance level, never a false pass.
    fn recompose_repair_gaps(inner: &mut Inner) {
        struct Gap {
            slot: usize,
            ei: usize,
            base: u64,
            dest: Dest,
            ranges: Vec<(u64, u64)>,
        }
        let mut jobs: Vec<Gap> = Vec::new();
        for si in 0..inner.slots.len() {
            if !matches!(inner.slots[si].mode, SlotMode::Rar) {
                continue;
            }
            let eis: Vec<usize> = inner.slots[si]
                .piece_crcs
                .iter()
                .filter(|(_, r)| !r.stale.is_empty())
                .map(|(&ei, _)| ei)
                .collect();
            for ei in eis {
                let Some(base) = Self::base_for(inner, si, ei) else { continue };
                let name = match inner.slots[si].mapper.as_ref().and_then(|m| m.entries.get(ei)) {
                    Some(e) => e.name.clone(),
                    None => continue,
                };
                let Some(dest) = Self::dest_for(inner, si, &name) else { continue };
                let ranges = inner.slots[si]
                    .piece_crcs
                    .get_mut(&ei)
                    .expect("entry enumerated above")
                    .take_stale_gaps();
                if !ranges.is_empty() {
                    jobs.push(Gap { slot: si, ei, base, dest, ranges });
                }
            }
        }
        for j in jobs {
            for (gs, ge) in j.ranges {
                let len = ge - gs;
                let covered = match &j.dest {
                    Dest::Writer(w) => w.covered(j.base + gs, len),
                    Dest::Child(c, cs) => c.covered(*cs, j.base + gs, len as usize),
                };
                if !covered {
                    continue;
                }
                // Bounded chunks: a gap can span most of a large file
                // (one coalesced run covered it all before the repair).
                let mut h = crc32fast::Hasher::new();
                let mut buf = vec![0u8; (len as usize).min(4 << 20)];
                let mut pos = gs;
                let mut ok = true;
                while pos < ge {
                    let n = ((ge - pos) as usize).min(buf.len());
                    let read = match &j.dest {
                        Dest::Writer(w) => w.read_at(&mut buf[..n], j.base + pos).is_ok(),
                        Dest::Child(c, cs) => c.read_at(*cs, j.base + pos, &mut buf[..n]).is_ok(),
                    };
                    if !read {
                        ok = false;
                        break;
                    }
                    h.update(&buf[..n]);
                    pos += n as u64;
                }
                if ok && let Some(r) = inner.slots[j.slot].piece_crcs.get_mut(&j.ei) {
                    // `take_stale_gaps` yields ranges disjoint from the
                    // runs and from each other, so this cannot be refused.
                    // If it somehow were, the gap simply stays a gap and
                    // the piece reads as unverifiable (skipped at finish),
                    // which is the safe direction - never a false pass.
                    let taken = r.add_run(gs, len, h.finalize());
                    debug_assert!(taken, "recomposed stale gap overlapped a live run");
                }
            }
        }
    }

    /// Join every chase worker before settling. The download is over, so
    /// a buffer short of its declared size can never complete - abort it
    /// and the blocked worker unblocks with an error. The join is bounded
    /// by construction: after `no_more` + those aborts every blocking
    /// read either has its bytes or errors, so the worker always
    /// terminates (a complete chase just runs its decode out). A failed
    /// or panicked worker demotes its group to materialized volumes; a
    /// successful one releases the retained volume bytes - its outputs
    /// already live in the child chain.
    fn chase_finish(&self) -> io::Result<()> {
        let chases: Vec<(String, Arc<ChaseCtl>)> = {
            let inner = self.inner.lock().unwrap();
            inner
                .groups
                .iter()
                .filter_map(|(k, g)| g.chase.clone().map(|c| (k.clone(), c)))
                .collect()
        };
        for (key, ctl) in chases {
            {
                let mut st = ctl.shared.lock().unwrap();
                st.no_more = true;
                for (buf, _) in st.vols.values() {
                    if !buf.is_complete() {
                        buf.abort("bytes never arrived");
                    }
                }
            }
            ctl.cv.notify_all();
            let handle = ctl.worker.lock().unwrap().take();
            if let Some(h) = handle {
                // A worker panic surfaces as a join error and leaves no
                // outcome - handled below as a demotion, never a
                // propagated panic.
                let _ = h.join();
            }
            let outcome = ctl.shared.lock().unwrap().outcome.clone();
            let mut g = self.inner.lock().unwrap();
            let inner = &mut *g;
            if !inner.groups.contains_key(&key) {
                continue;
            }
            let already_fallback = inner.groups[&key].fallback;
            match &outcome {
                Some(Ok(())) if !already_fallback => {
                    for si in inner.groups[&key].slots.clone() {
                        if let Some(ch) = inner.slots[si].chase.take() {
                            inner.budget.sub(ch.charged);
                        }
                    }
                }
                _ => {
                    if !already_fallback {
                        let why = match &outcome {
                            Some(Err(e)) => format!("chase failed: {e}"),
                            None => "chase worker panicked".to_string(),
                            Some(Ok(())) => unreachable!(),
                        };
                        self.fallback_group(inner, &key, &why)?;
                    }
                }
            }
            if let Some(grp) = inner.groups.get_mut(&key) {
                grp.chase = None;
            }
        }
        Ok(())
    }

    /// Settle groups that never finished mapping and flush stray holds.
    fn settle_groups(&self) -> io::Result<()> {
        let mut g = self.inner.lock().unwrap();
        let inner = &mut *g;
        let keys: Vec<String> = inner.groups.keys().cloned().collect();
        for key in &keys {
            let has_holds = inner.groups[key]
                .slots
                .iter()
                .any(|&si| !inner.slots[si].holds.is_empty());
            let incomplete = inner.groups[key].slots.iter().any(|&si| {
                inner.slots[si]
                    .mapper
                    .as_ref()
                    .is_some_and(|m| !m.complete && m.blocker.is_none())
            });
            if (has_holds || incomplete) && !inner.groups[key].fallback {
                self.fallback_group(inner, key, "incomplete mapping at end of download")?;
            }
        }
        for si in 0..inner.slots.len() {
            if !inner.slots[si].holds.is_empty() {
                if matches!(inner.slots[si].mode, SlotMode::Unknown) {
                    if inner.protect_sources {
                        let name = inner.slots[si].name.clone();
                        inner
                            .slot_fallbacks
                            .push((name, "never classified".to_string()));
                        self.discard_slot(inner, si);
                        continue;
                    }
                    inner.slots[si].mode = SlotMode::Plain;
                }
                self.drain_holds(inner, si)?;
            }
        }

        Ok(())
    }

    /// Decrypt every encrypted store file of the healthy groups. During
    /// the download those files accumulated the archive's AES-256-CBC
    /// ciphertext at plain store offsets (RAR5 encrypts each inner file
    /// as ONE stream across all volumes, so the assembled ciphertext is
    /// contiguous); one sequential CBC pass + truncate to the unpacked
    /// size turns each into the real output, and the plaintext CRC32 is
    /// checked against the header CRC when it isn't tweaked.
    ///
    /// NOTHING is decrypted in place. Every file is written to a fresh
    /// same-directory temp that this pass created with `create_new` (so
    /// the name is provably ours and no archive member can alias it),
    /// sync'd, CRC-checked, cleared by the [`DecryptBarrier`], and only
    /// then published by rename.
    ///
    /// That ordering is the point, not the temp file. These outputs are
    /// what the crash-resume journal's placement records point INTO: a
    /// file that holds plaintext is no longer the ciphertext the journal
    /// describes, and a resume run would copy fragments out of it into
    /// volume files and mark those message ids restored - skipping the
    /// refetch, so without PAR2 the retry grinds on poisoned local bytes
    /// forever while the provider still has every original article. In
    /// place, a kill mid-pass produced exactly that, half plaintext and
    /// half ciphertext, with the journal still vouching for it. So:
    ///
    /// - a failure before a file's barrier call drops its temp and leaves
    ///   its ciphertext byte-exact - the journal is still true for it, so
    ///   resume reads local bytes and fallback can still rebuild volumes;
    /// - the barrier retires that file's claim, durably, before its
    ///   rename - after it the file's articles refetch whether or not the
    ///   rename ever landed;
    /// - a rename either happened or did not; no file is ever a mix.
    ///
    /// Files are independent here, so a mid-batch failure leaves each one
    /// in whichever of those two consistent states it reached; the job
    /// still fails, and the retry does the right thing for both.
    ///
    /// Phased locking: job gathering + pre-flight (coverage, key
    /// derivation) and the per-file ciphertext→plaintext state flip run
    /// under the routing lock; the multi-GB read+write passes run WITHOUT
    /// it (the daemon's stats/stream calls read through that lock -
    /// holding it for a disk pass froze them) and in parallel across
    /// files. Temps also make a live /stream reader free: its fd stays on
    /// the intact ciphertext inode across the publish, so it keeps
    /// decrypting on the fly and never has to wait out the pass.
    ///
    /// Cost of never mutating in place: while this level's extractor is
    /// alive the set is on disk twice. The plaintext replaces the name,
    /// but the ciphertext inode it displaced stays allocated because the
    /// inner `FileWriter` still holds an open fd on it (that writer is the
    /// daemon's live handle for /stream, so it is not ours to close here),
    /// and the blocks come back when the extractor drops at end of job.
    /// The old in-place pass paid 1x. Correctness is worth it - a file
    /// that is half plaintext under a journal that vouches for it is
    /// unrecoverable without PAR2 - but on a tight volume this is the
    /// headroom an encrypted store set now needs.
    fn decrypt_finished(&self) -> io::Result<Vec<String>> {
        struct Job {
            key: String,
            out: String,
            path: PathBuf,
            unp: u64,
            key_bytes: [u8; 32],
            iv: [u8; 16],
            aes_ok: bool,
            covered: bool,
            /// Stored plaintext CRC32 to check after decryption, when the
            /// crypt record's tweaked-checksum flag is clear (a tweaked CRC
            /// is keyed and cannot be compared against a plain CRC32).
            expect_crc: Option<u32>,
        }
        // Scratch from a killed earlier run. This pass is the only thing
        // that creates these names and every write of the job has landed
        // by now, so anything still matching the prefix is dead. Swept
        // before the early returns below: a retry whose group falls back
        // decrypts nothing, and the corpse would otherwise sit in the
        // user's output directory forever (the cleanup walkers skip
        // `.nzbfast*` by design, so nothing else would ever collect it).
        sweep_decrypt_temps(&self.out_dir);
        let mut jobs: Vec<Job> = Vec::new();
        // Plaintext-once files whose posted cipher never fully arrived:
        // their groups fall back exactly like a legacy coverage hole.
        let mut instream_failed: std::collections::HashSet<String> = Default::default();
        // ...and the ones that verified complete: already decrypted on
        // disk, reported alongside the legacy pass's output.
        let mut instream_done: Vec<String> = Vec::new();
        {
            let g = self.inner.lock().unwrap();
            let inner = &*g;
            for (key, grp) in &inner.groups {
                if grp.fallback {
                    continue;
                }
                // One decrypt job per inner file, keyed off its head piece
                // (split_before == false - whose IV starts the stream).
                let mut heads: HashMap<String, (EntryCrypt, u64, String, Option<u32>)> =
                    HashMap::new();
                for &si in &grp.slots {
                    let Some(m) = inner.slots[si].mapper.as_ref() else { continue };
                    for e in &m.entries {
                        if e.is_dir || !e.encrypted || e.split_before {
                            continue;
                        }
                        if let Some(c) = &e.crypt {
                            // out_names is keyed on the RAW name; sanitized is
                            // the on-disk fallback. Key `heads` by raw name too
                            // so distinct raw names get distinct decrypt jobs.
                            let out = grp
                                .out_names
                                .get(&e.name)
                                .cloned()
                                .unwrap_or_else(|| sanitize_filename(&e.name));
                            // Only a single-piece entry's stored CRC covers
                            // the whole plaintext this decrypt pass produces.
                            // Split volumes each carry a per-volume CRC (the
                            // whole-file CRC lives on the last piece, keyed
                            // there), so checking the head's value against the
                            // assembled file would false-fail - leave split
                            // encrypted files to the outer PAR2/yEnc gate.
                            let single_crc = e.file_crc.filter(|_| !e.split_after);
                            heads
                                .entry(e.name.clone())
                                .or_insert((c.clone(), e.unpacked_size, out, single_crc));
                        }
                    }
                }
                for (_fname, (c, unp, out, file_crc)) in heads {
                    let Some(w) = inner.inner_writers.get(&out) else { continue };
                    // Plaintext-once file: already decrypted in-stream.
                    // Verify instead of building a decrypt job - an
                    // incomplete cipher record condemns the group like a
                    // coverage hole would, and a stored-CRC mismatch is
                    // the same hard error the legacy pass raises (posted
                    // archive damaged before posting; the posted bytes
                    // remain reproducible through the shim for fallback).
                    if let Some(cs) = inner.crypto_files.get(&out) {
                        if cs.crc_verdict() == Some(false) {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "encrypted RAR5 file failed its stored CRC after decryption",
                            ));
                        }
                        if unp == 0 || cs.complete() {
                            instream_done.push(out);
                        } else {
                            instream_failed.insert(key.clone());
                        }
                        continue;
                    }
                    let aes = inner
                        .password
                        .as_ref()
                        .and_then(|pw| rarcrypt::derive_keys(pw, &c.salt, c.lg2_count));
                    jobs.push(Job {
                        key: key.clone(),
                        out,
                        path: w.path.clone(),
                        unp,
                        key_bytes: aes.as_ref().map(|k| k.key).unwrap_or([0; 32]),
                        iv: c.iv,
                        aes_ok: aes.is_some(),
                        covered: unp == 0 || w.covered(0, rarcrypt::align16(unp)),
                        // A clear tweaked flag means the stored CRC is a plain
                        // CRC32 of the plaintext (WinRAR's -hp default): verify
                        // it after decryption. Password-check proves the KEY,
                        // not that every ciphertext block survived the wire.
                        expect_crc: file_crc.filter(|_| !c.tweaked_checksum),
                    });
                }
            }
        }
        if jobs.is_empty() && instream_failed.is_empty() {
            instream_done.sort();
            return Ok(instream_done);
        }
        // A group decrypts ALL of its files or NONE: once one file is
        // plaintext, a fallback (which reads inner files back to
        // materialize volumes) would rebuild silently-corrupt volumes -
        // so any pre-flight failure (ciphertext holes, vanished password)
        // condemns the whole group BEFORE any byte changes.
        let mut failed_groups: std::collections::HashSet<String> = jobs
            .iter()
            .filter(|j| !j.aes_ok || !j.covered)
            .map(|j| j.key.clone())
            .collect();
        failed_groups.extend(instream_failed);
        let live: Vec<&Job> = jobs.iter().filter(|j| !failed_groups.contains(&j.key)).collect();
        let total: u64 = live.iter().map(|j| j.unp).sum();
        if !live.is_empty() {
            println!(
                "🔓 decrypting {} file(s) ({:.1} MB)…",
                live.len(),
                total as f64 / 1e6
            );
        }
        // Per-output stream state, under the lock. No file flips to
        // `Decrypting`: the ciphertext inode stays whole and readable for
        // the entire pass, so a reader arriving mid-pass keeps decrypting
        // on the fly and the rename is what moves it to plaintext.
        let states: Vec<Arc<StreamState>> = {
            let mut g = self.inner.lock().unwrap();
            let inner = &mut *g;
            live.iter()
                .map(|j| {
                    inner
                        .stream_states
                        .entry(j.out.clone())
                        .or_insert_with(|| {
                            Arc::new(StreamState {
                                state: Mutex::new(DecState::Ciphertext),
                                readers: AtomicUsize::new(0),
                            })
                        })
                        .clone()
                })
                .collect()
        };
        let barrier = self.inner.lock().unwrap().decrypt_barrier.clone();
        // Reserve every temp up front, outside the lock: a name we cannot
        // claim must abort before any ciphertext is touched, not halfway
        // through the set.
        let mut plans: Vec<(&Job, PathBuf, File, Arc<StreamState>)> = Vec::new();
        let mut reserve_err = None;
        for (j, st) in live.iter().copied().zip(states) {
            match create_decrypt_temp(&self.out_dir) {
                Ok((path, file)) => plans.push((j, path, file, st)),
                Err(e) => {
                    reserve_err = Some(e);
                    break;
                }
            }
        }
        if let Some(e) = reserve_err {
            for (_, tmp, _, _) in &plans {
                let _ = std::fs::remove_file(tmp);
            }
            return Err(e);
        }
        // The disk passes, in parallel (bounded), lock-free.
        let workers = plans.len().min(4).max(1);
        // Files run concurrently and each file shards internally, so the two
        // share one budget. An encrypted set is usually ONE file, which is
        // exactly the case that needs the shards: without them a 60 GB
        // release decrypts on a single core after the download has finished.
        let shards_per_file =
            (std::thread::available_parallelism().map_or(1, |n| n.get()) / workers).max(1);
        let next = AtomicUsize::new(0);
        let done: Mutex<Vec<String>> = Mutex::new(Vec::new());
        let first_err: Mutex<Option<io::Error>> = Mutex::new(None);
        let plans_ref = &plans;
        let barrier_ref = &barrier;
        std::thread::scope(|scope| {
            for _ in 0..workers {
                scope.spawn(|| loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some((j, tmp, wf, st)) = plans_ref.get(i) else { break };
                    // One file's failure condemns the job, so don't burn
                    // disk passes on the rest of the set.
                    if first_err.lock().unwrap().is_some() {
                        let _ = std::fs::remove_file(tmp);
                        continue;
                    }
                    let outcome = decrypt_pass(
                        &j.path,
                        wf,
                        &j.key_bytes,
                        &j.iv,
                        j.unp,
                        j.expect_crc,
                        shards_per_file,
                    )
                    // Plaintext is on disk and verified; now buy the right
                    // to publish it. Until this returns Ok the journal
                    // still describes `j.path` truthfully and must keep
                    // doing so, which is why nothing has touched it yet.
                    .and_then(|()| match barrier_ref {
                        Some(b) => b(std::slice::from_ref(&j.out)),
                        None => Ok(()),
                    })
                    .and_then(|()| {
                        // Publish under the lock, ordered against
                        // open_stream's ciphertext/plaintext choice.
                        let _g = self.inner.lock().unwrap();
                        let r = std::fs::rename(tmp, &j.path);
                        if r.is_ok() {
                            *st.state.lock().unwrap() = DecState::Decrypted;
                        }
                        r
                    });
                    match outcome {
                        Ok(()) => done.lock().unwrap().push(j.out.clone()),
                        Err(e) => {
                            // Nothing was published, so the ciphertext is
                            // byte-exact whichever step failed - drop the
                            // scratch and leave it that way. If the rename
                            // was the failure the claim is already retired,
                            // which just costs the retry a refetch.
                            let _ = std::fs::remove_file(tmp);
                            let mut fe = first_err.lock().unwrap();
                            if fe.is_none() {
                                *fe = Some(e);
                            }
                        }
                    }
                });
            }
        });
        if let Some(e) = first_err.into_inner().unwrap() {
            return Err(e);
        }
        // Renames are metadata: fsync the directory so a power cut can't
        // undo a publish the journal has already stopped vouching for.
        // Best-effort by design - the correctness guarantee comes from the
        // barrier ordering above (after a lost rename the articles refetch
        // either way), and SMB/CIFS NAS mounts reject a directory fsync
        // outright, where failing the job would be pure harm.
        crate::disk::sync_dir(&self.out_dir);
        if !failed_groups.is_empty() {
            let mut g = self.inner.lock().unwrap();
            let inner = &mut *g;
            for key in failed_groups {
                if inner.groups.contains_key(&key) {
                    self.fallback_group(inner, &key, "encrypted data incomplete")?;
                }
            }
        }
        let mut decrypted = done.into_inner().unwrap();
        decrypted.extend(instream_done);
        decrypted.sort();
        Ok(decrypted)
    }
}

impl Drop for Extractor {
    /// Cancel path: a dropped extractor must not leave chase workers
    /// blocked on frontiers that will never fill. Abort every live chase
    /// and join - except from the worker's own thread (a worker holding
    /// the last transient Arc would otherwise join itself; after the
    /// abort it exits on its own anyway).
    fn drop(&mut self) {
        let inner = match self.inner.get_mut() {
            Ok(i) => i,
            Err(p) => p.into_inner(),
        };
        let mut handles = Vec::new();
        for g in inner.groups.values_mut() {
            if let Some(ctl) = g.chase.take() {
                ctl.abort("extractor dropped");
                ctl.shared.lock().unwrap().no_more = true;
                ctl.cv.notify_all();
                if let Some(h) = ctl.worker.lock().unwrap().take() {
                    handles.push(h);
                }
            }
        }
        for s in inner.slots.iter_mut() {
            if let Some(ctl) = s.sevenz.take() {
                ctl.buf.abort("extractor dropped");
                if let Some(h) = ctl.worker.lock().unwrap().take() {
                    handles.push(h);
                }
            }
        }
        for h in handles {
            if h.thread().id() != std::thread::current().id() {
                let _ = h.join();
            }
        }
    }
}

/// Same-directory scratch prefix for the finish decrypt. The leading
/// `.nzbfast` is the established internal-scratch marker (the cleanup
/// walkers and the keep-media-only sweep already skip those names), and
/// pid + counter make each name unique to one pass of one process.
const DEC_TMP_PREFIX: &str = ".nzbfast-dec.";

/// Create the decrypt scratch file for one output. `create_new` is what
/// makes the name provably OURS: it can never adopt a stale file's bytes
/// and never be shared with another process. The reason it matters here is
/// the third one - it can never alias a legitimate archive member, which a
/// deterministic sibling name like `movie.mkv.nzbdec.tmp` could (an archive
/// is free to contain that name, and truncating it would destroy real
/// output). A taken name just bumps the counter.
fn create_decrypt_temp(dir: &Path) -> io::Result<(PathBuf, File)> {
    static SEQ: AtomicUsize = AtomicUsize::new(0);
    let pid = std::process::id();
    for _ in 0..4096 {
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let path = dir.join(format!("{DEC_TMP_PREFIX}{pid}.{n}.tmp"));
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(f) => return Ok((path, f)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "no free decrypt scratch name in the output directory",
    ))
}

/// Remove decrypt scratch left behind by a killed run.
fn sweep_decrypt_temps(dir: &Path) {
    let Ok(rd) = std::fs::read_dir(dir) else { return };
    for e in rd.flatten() {
        if e.file_name().to_string_lossy().starts_with(DEC_TMP_PREFIX) {
            let _ = std::fs::remove_file(e.path());
        }
    }
}

/// One AES-256-CBC pass over the ciphertext at `src` (length =
/// align16(`unp`)): decrypt into the caller's scratch handle `wf` and
/// truncate it to `unp`. `src` is only ever READ - see
/// [`Extractor::decrypt_finished`] for why nothing may mutate it before
/// the journal has stopped vouching for it.
///
/// When `expect_crc` is set (the crypt record's tweaked-checksum flag was
/// clear, so the stored CRC is a plain CRC32 of the plaintext), the
/// decrypted bytes are CRC32'd as they stream past and checked at the end.
/// This catches ciphertext that was damaged before posting - the outer
/// yEnc/PAR2 verify the archive as-posted and the password-check only
/// proves the key, so without this the corrupt plaintext would be written
/// out as success. A mismatch is a hard error, and since it is raised
/// before the scratch is ever published, the ciphertext output survives
/// intact for a fallback or a resume.
fn decrypt_pass(
    src: &Path,
    wf: &File,
    key: &[u8; 32],
    iv: &[u8; 16],
    unp: u64,
    expect_crc: Option<u32>,
    threads: usize,
) -> io::Result<()> {
    let rf = std::fs::File::open(src)?;
    let cipher_len = rarcrypt::align16(unp);
    // One shard per thread, 16-aligned so every shard starts on a cipher
    // block boundary. Below the threshold the extra seeks and the per-shard
    // IV read cost more than the parallelism buys.
    let shards = if cipher_len < DECRYPT_PARALLEL_MIN {
        1
    } else {
        threads.clamp(1, DECRYPT_MAX_SHARDS)
    };
    let crc = if shards <= 1 {
        decrypt_shard(&rf, wf, key, iv, 0, cipher_len, unp, expect_crc.is_some())?
    } else {
        let shard_len = rarcrypt::align16(cipher_len.div_ceil(shards as u64));
        let rf = &rf;
        let parts: Vec<io::Result<(u32, u64)>> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..shards)
                .map(|i| {
                    let start = shard_len * i as u64;
                    let end = (start + shard_len).min(cipher_len);
                    scope.spawn(move || {
                        if start >= end {
                            return Ok((0, 0));
                        }
                        // CBC decryption of a block needs only the
                        // ciphertext block before it, so a shard seeds its
                        // chain from the 16 bytes it starts after.
                        let seed = if start == 0 {
                            *iv
                        } else {
                            let mut prev = [0u8; 16];
                            crate::disk::read_exact_at(rf, &mut prev, start - 16)?;
                            prev
                        };
                        decrypt_shard(rf, wf, key, &seed, start, end, unp, expect_crc.is_some())
                            .map(|c| (c, unp.min(end).saturating_sub(unp.min(start))))
                    })
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });
        // CRC32 composes over concatenation, so the shards fold back into
        // the whole-file CRC in order.
        let mut acc = 0u32;
        for part in parts {
            let (c, plain_len) = part?;
            acc = if plain_len == 0 {
                acc
            } else {
                crate::yenc_simd::crc32_combine(acc, c, plain_len)
            };
        }
        acc
    };
    wf.set_len(unp)?;
    wf.sync_data()?;
    if expect_crc.is_some_and(|expected| crc != expected) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "encrypted RAR5 file failed its stored CRC after decryption",
        ));
    }
    Ok(())
}

/// Ciphertext below this stays on one thread: the shard IV reads and the
/// scattered writes cost more than the parallelism returns.
const DECRYPT_PARALLEL_MIN: u64 = 32 << 20;
/// Ceiling on shards per file. Each holds a 4 MiB scratch buffer, and the
/// pass is read/write bound well before this on any disk a NAS ships with.
const DECRYPT_MAX_SHARDS: usize = 8;

/// Decrypt `[start, end)` of the ciphertext into the same offsets of `wf`,
/// seeded from `iv`. Returns the CRC32 of the plaintext bytes it wrote that
/// lie below `unp` (the 16-byte alignment padding beyond `unp` is not part
/// of the file and never enters the CRC).
#[allow(clippy::too_many_arguments)]
fn decrypt_shard(
    rf: &File,
    wf: &File,
    key: &[u8; 32],
    iv: &[u8; 16],
    start: u64,
    end: u64,
    unp: u64,
    want_crc: bool,
) -> io::Result<u32> {
    use crate::disk::{read_exact_at, write_all_at};
    let mut stream = rarcrypt::CbcStream::new(key, iv);
    let mut hasher = want_crc.then(crc32fast::Hasher::new);
    let mut buf = vec![0u8; 4 << 20]; // 16-aligned chunks
    let mut off = start;
    while off < end {
        let n = (end - off).min(buf.len() as u64) as usize;
        read_exact_at(rf, &mut buf[..n], off)?;
        stream.decrypt(&mut buf[..n]);
        write_all_at(wf, &buf[..n], off)?;
        if let Some(h) = hasher.as_mut() {
            let plain = (unp.saturating_sub(off)).min(n as u64) as usize;
            if plain > 0 {
                h.update(&buf[..plain]);
            }
        }
        off += n as u64;
    }
    Ok(hasher.map_or(0, |h| h.finalize()))
}

fn nofile() -> io::Error {
    io::Error::new(io::ErrorKind::NotFound, "no backing data")
}

/// Collision key for the chain-shared output-name set. On a case-insensitive
/// volume `README` and `readme` name ONE object, so claiming both would let
/// the second `FileWriter::create` (truncating) clobber the first; folding to
/// lowercase makes the second name disambiguate instead. On a case-sensitive
/// volume they are genuinely distinct files, so the exact name is kept and
/// neither gets needlessly renamed.
///
/// `fold` is PROBED from the output volume (`disk::case_insensitive_dir`) and
/// threaded down the chain next to `names_taken`, so every level keys that
/// shared set identically. It is deliberately not `cfg!(target_os)`: the
/// Linux container/NAS build writing to a CIFS/SMB or exFAT share is
/// case-insensitive, and that is precisely the deployment where losing an
/// output file hurts most.
fn name_collision_key(fold: bool, name: &str) -> String {
    if fold {
        name.to_lowercase()
    } else {
        name.to_string()
    }
}

/// Reword a child-level fallback reason for the parent's report. The
/// caller keys VOLUME-level remediation (unrar passes, loose-volume job
/// failure) off substrings of top-level reasons ("compressed",
/// "encrypted"/"password", "held-bytes cap", "incomplete mapping"); a
/// nested demotion has already materialized the level-1 file - exactly
/// the single-level output, which the disk post-pass handles - so its
/// reason must never pattern-match those branches.
fn nested_reason(why: &str) -> String {
    let safe: String = if why.contains("compressed") {
        "inner archive is not store-mode".to_string()
    } else if why.contains("password") || why.contains("encrypted") {
        "inner archive is protected".to_string()
    } else if why.contains("held-bytes cap") {
        "inner holds budget exceeded".to_string()
    } else if why.contains("incomplete mapping") {
        "inner mapping unfinished at end of download".to_string()
    } else {
        why.to_string()
    };
    format!("nested fallback: {safe}")
}

fn blocker_reason(b: &MapBlocker) -> &'static str {
    match b {
        MapBlocker::NotRar => "not a RAR volume",
        MapBlocker::EncryptedHeaders => "encrypted headers (password required)",
        MapBlocker::NotStore => "compressed or encrypted entries",
        MapBlocker::BadPassword => "wrong archive password",
        MapBlocker::Corrupt(w) => w,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rar::fixtures;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("nzbfast-extract-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn payload(n: usize, seed: u8) -> Vec<u8> {
        (0..n)
            .map(|i| (i as u8).wrapping_mul(17).wrapping_add(seed))
            .collect()
    }

    #[test]
    fn vol_sort_key_letter_rollover_and_numeric() {
        let k = |n: &str| vol_sort_key(n).0;
        assert!(k("x.rar") < k("x.r00"));
        assert_eq!(k("x.r00"), 1);
        assert_eq!(k("x.r99"), 100);
        // 100+-volume sets roll the letter: continuity across .r99 → .s00
        // (was u64::MAX, breaking base-resolution at the boundary).
        assert_eq!(k("x.s00"), 101);
        assert_eq!(k("x.t00"), 201);
        // WinRAR numeric volumes order numerically.
        assert!(k("x.001") < k("x.002"));
        // Non-volume extensions stay in the terminal bucket.
        assert_eq!(k("x.srt"), u64::MAX);
        assert_eq!(k("x.mkv"), u64::MAX);
    }

    /// Feed a volume file as shuffled articles through the extractor.
    /// `feed` through the verified-article-CRC entry point. `poison`
    /// offsets the CRC handed over, standing in for a value that does not
    /// describe the bytes - which is what a reuse bug would produce.
    fn feed_verified(
        ex: &Extractor,
        slot: usize,
        name: &str,
        vol: &[u8],
        art: usize,
        seed: u64,
        poison: u32,
    ) {
        let mut idx: Vec<usize> = (0..vol.len().div_ceil(art)).collect();
        let mut state = seed;
        for i in (1..idx.len()).rev() {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            idx.swap(i, (state >> 33) as usize % (i + 1));
        }
        for i in idx {
            let s = i * art;
            let e = (s + art).min(vol.len());
            let crc = crc32fast::hash(&vol[s..e]) ^ poison;
            ex.write_verified(slot, name, vol.len() as u64, s as u64, &vol[s..e], Some(crc))
                .unwrap();
        }
    }

    fn feed(ex: &Extractor, slot: usize, name: &str, vol: &[u8], art: usize, seed: u64) {
        let mut idx: Vec<usize> = (0..vol.len().div_ceil(art)).collect();
        let mut state = seed;
        for i in (1..idx.len()).rev() {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            idx.swap(i, (state >> 33) as usize % (i + 1));
        }
        for i in idx {
            let s = i * art;
            let e = (s + art).min(vol.len());
            ex.write(slot, name, vol.len() as u64, s as u64, &vol[s..e])
                .unwrap();
        }
    }


    #[test]
    fn single_volume_direct_extract() {
        let dir = tmpdir("single");
        let data = payload(200_000, 1);
        let vol = fixtures::rar5_volume(&[("movie.mkv", 200_000, &data, false, false)]);
        let ex = Extractor::new(&dir, 1, true);
        feed(&ex, 0, "v.rar", &vol, 7000, 3);
        let rep = ex.finish().unwrap();
        assert_eq!(rep.extracted, vec![("movie.mkv".to_string(), 200_000)]);
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("movie.mkv")).unwrap(), data);
        // The volume file must NOT exist (one-pass!).
        assert!(!dir.join("v.rar").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// BUG (HIGH): the in-stream extractor reserved an attacker-declared
    /// size. `inner_writer` passes the entry's `unpacked_size` - a RAR
    /// header vint the poster controls - straight to `FileWriter::create`,
    /// which `set_len`s and (on Linux) really `fallocate`s it. The
    /// volume-bounds check does NOT close this in the `split_after`
    /// shape: the writer is created with the inflated declaration DURING
    /// the download and the demote only lands at `finish()`, long after
    /// the blocks are gone.
    ///
    /// The ceiling is the NZB's own posted byte count: a store archive
    /// cannot legitimately unpack to more than what was posted.
    #[test]
    fn an_inflated_unpacked_size_cannot_reserve_past_the_posted_ceiling() {
        let dir = tmpdir("prealloc-cap");
        let data = payload(200_000, 9);
        // 200 KB really posted; the header declares 8 TiB and sets
        // split_after, so nothing demotes until finish().
        const HUGE: u64 = 8 << 40;
        let vol = fixtures::rar5_volume(&[("movie.mkv", HUGE, &data, false, true)]);
        let ex = Extractor::new(&dir, 1, true);
        let posted = vol.len() as u64;
        ex.set_prealloc_ceiling(posted);
        feed(&ex, 0, "x.part1.rar", &vol, 7000, 3);

        // MID-DOWNLOAD - the window the finish-time gates cannot cover.
        let reserved = std::fs::metadata(dir.join("movie.mkv")).unwrap().len();
        assert!(
            reserved <= posted,
            "reserved {reserved} bytes for a {posted}-byte post declaring {HUGE}"
        );
        let _ = ex.finish();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The other half, and the one a wrong fix breaks silently: a
    /// legitimate inner file BIGGER than any single volume must still be
    /// preallocated in full as soon as the first volume identifies it -
    /// the whole point of preallocation is that the extents are reserved
    /// before the rest of the download races other files for them.
    ///
    /// (This is also why the ceiling is the NZB total and not the sum of
    /// the group's slot sizes: group membership accretes as volumes
    /// arrive, so at this point only ONE volume is known.)
    #[test]
    fn a_legitimate_large_inner_file_still_preallocates_in_full() {
        let dir = tmpdir("prealloc-ok");
        let total = payload(500_000, 2);
        let vols: Vec<Vec<u8>> = vec![
            fixtures::rar5_volume(&[("film.mkv", 500_000, &total[..200_000], false, true)]),
            fixtures::rar5_volume(&[("film.mkv", 500_000, &total[200_000..400_000], true, true)]),
            fixtures::rar5_volume(&[("film.mkv", 500_000, &total[400_000..], true, false)]),
        ];
        let posted: u64 = vols.iter().map(|v| v.len() as u64).sum();
        assert!(posted > 500_000);
        let ex = Extractor::new(&dir, 3, true);
        ex.set_prealloc_ceiling(posted);

        feed(&ex, 0, "x.part1.rar", &vols[0], 9000, 12);
        assert_eq!(
            std::fs::metadata(dir.join("film.mkv")).unwrap().len(),
            500_000,
            "a legitimate 500 KB inner file must be reserved in full from the first volume"
        );

        feed(&ex, 1, "x.part2.rar", &vols[1], 9000, 13);
        feed(&ex, 2, "x.part3.rar", &vols[2], 9000, 11);
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(rep.extracted, vec![("film.mkv".to_string(), 500_000)]);
        assert_eq!(std::fs::read(dir.join("film.mkv")).unwrap(), total);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The crash-resume adoption path had the same hole as the writer
    /// paths above: `seed_slot` handed the journal's declared size to an
    /// UNcapped `create_resume`. Same ceiling, same reasoning - and the
    /// legitimate half still reserves in full.
    #[test]
    fn seed_slot_reserves_under_the_ceiling_and_in_full_below_it() {
        let dir = tmpdir("prealloc-seed");
        const HUGE: u64 = 8 << 40;
        const POSTED: u64 = 8_000_000;
        // enabled=false, resume=true: exactly how `main` builds the
        // extractor for a resumed run.
        let ex = Extractor::with_resume(&dir, 2, false, true);
        ex.set_prealloc_ceiling(POSTED);

        ex.seed_slot(0, "inflated.bin", HUGE, &[]).unwrap();
        assert_eq!(
            std::fs::metadata(dir.join("inflated.bin")).unwrap().len(),
            POSTED,
            "a journal size past the posted ceiling must not reserve past it"
        );
        ex.seed_slot(1, "legit.bin", 4_000_000, &[]).unwrap();
        assert_eq!(
            std::fs::metadata(dir.join("legit.bin")).unwrap().len(),
            4_000_000,
            "a legitimate resumed file under the ceiling must still be reserved in full"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The regression this fix must never cause: resume adoption may not
    /// shrink a file below the bytes an earlier run already restored into
    /// it, however small the ceiling.
    #[test]
    fn seed_slot_never_shrinks_the_bytes_a_resume_already_holds() {
        let dir = tmpdir("prealloc-seed-cur");
        let restored = payload(400_000, 3);
        std::fs::write(dir.join("part.bin"), &restored).unwrap();
        let ex = Extractor::with_resume(&dir, 1, false, true);
        ex.set_prealloc_ceiling(1024); // absurdly small on purpose
        ex.seed_slot(0, "part.bin", 8 << 40, &[(0, 400_000)]).unwrap();
        assert_eq!(std::fs::metadata(dir.join("part.bin")).unwrap().len(), 400_000);
        assert_eq!(std::fs::read(dir.join("part.bin")).unwrap(), restored);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// BUG (MEDIUM): the decompression-bomb guard counted bytes only on
    /// the disk and post-pass sinks, so it protected the fallback and not
    /// the in-stream path every download actually takes. The budget is
    /// shared across the whole job - inner files do not each get a fresh
    /// allowance.
    #[test]
    fn the_in_stream_path_is_bounded_by_the_extract_budget() {
        let dir = tmpdir("bomb-instream");
        let a = payload(200_000, 4);
        let b = payload(200_000, 5);
        let vol = fixtures::rar5_volume(&[
            ("one.bin", 200_000, &a, false, false),
            ("two.bin", 200_000, &b, false, false),
        ]);
        let ex = Extractor::new(&dir, 1, true);
        // Room for the first inner file and not the second: a shared
        // budget must refuse, a per-file one would wave both through.
        ex.set_extract_budget(300_000);

        let art = 8192;
        let mut err = None;
        for s in (0..vol.len()).step_by(art) {
            let e = (s + art).min(vol.len());
            if let Err(x) = ex.write(0, "v.rar", vol.len() as u64, s as u64, &vol[s..e]) {
                err = Some(x);
                break;
            }
        }
        let err = err.expect("a 400 KB extract under a 300 KB budget must be refused");
        assert!(err.to_string().contains("decompression bomb"), "{err}");
        assert!(ex.extract_budget_used() > 300_000);
        let _ = ex.finish();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The budget must not fire on a job that merely fits - the guard
    /// exists for bombs, not for large legitimate extracts.
    #[test]
    fn the_extract_budget_never_trips_on_a_job_that_fits() {
        let dir = tmpdir("bomb-fits");
        let data = payload(200_000, 1);
        let vol = fixtures::rar5_volume(&[("movie.mkv", 200_000, &data, false, false)]);
        let ex = Extractor::new(&dir, 1, true);
        ex.set_extract_budget(200_000);
        feed(&ex, 0, "v.rar", &vol, 7000, 3);
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("movie.mkv")).unwrap(), data);
        assert_eq!(ex.extract_budget_used(), 200_000);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn split_volumes_out_of_order() {
        let dir = tmpdir("split");
        let total = payload(500_000, 2);
        let vols: Vec<Vec<u8>> = vec![
            fixtures::rar5_volume(&[("film.mkv", 500_000, &total[..200_000], false, true)]),
            fixtures::rar5_volume(&[("film.mkv", 500_000, &total[200_000..400_000], true, true)]),
            fixtures::rar5_volume(&[("film.mkv", 500_000, &total[400_000..], true, false)]),
        ];
        // Feed volumes interleaved and shuffled - vol 3 first.
        let ex = Extractor::new(&dir, 3, true);
        feed(&ex, 2, "x.part3.rar", &vols[2], 9000, 11);
        feed(&ex, 0, "x.part1.rar", &vols[0], 9000, 12);
        feed(&ex, 1, "x.part2.rar", &vols[1], 9000, 13);
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("film.mkv")).unwrap(), total);
        assert!(!dir.join("x.part1.rar").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A store entry that DECLARES far more data than the volume holds
    /// must never ship as a successful extraction. Before the
    /// volume-bounds check the parse cursor jumped past the volume end,
    /// the EOF rule marked the volume complete, `mapped_through()` went
    /// to u64::MAX (so no tail-hold), the end-of-download settle saw
    /// nothing incomplete, and the CRC gate skipped the file because its
    /// composed run was shorter than the declared piece - leaving a
    /// preallocated, mostly-zero file reported as output with exit 0.
    #[test]
    fn oversized_data_area_never_ships_a_sparse_file() {
        let dir = tmpdir("oversize-a");
        let data = payload(4_000, 5);
        // 4 KB really posted; the header claims 8 MB of data area.
        let vol = fixtures::rar5_volume_oversized("movie.mkv", 8 << 20, &data, 8 << 20);
        let ex = Extractor::new(&dir, 1, true);
        feed(&ex, 0, "v.rar", &vol, 700, 3);
        let rep = ex.finish().unwrap();
        assert!(
            !rep.fallbacks.is_empty(),
            "a volume that overruns itself must demote, got {:?}",
            rep.fallbacks
        );
        assert!(
            !dir.join("movie.mkv").exists(),
            "no sparse output may survive the demote"
        );
        assert!(rep.extracted.iter().all(|(n, _)| n != "movie.mkv"), "{:?}", rep.extracted);
        // The volume itself materialized for the disk path, byte-exact,
        // so unrar gets to fail the job honestly.
        assert_eq!(std::fs::read(dir.join("v.rar")).unwrap(), vol);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Variant B: every per-volume invariant holds (the data area ends
    /// exactly at the volume end, the end-of-archive block is there, the
    /// bytes all arrive) but `split_after` is set on the only piece and
    /// `unpacked_size` is 8 MB against 4 KB of real data. The parser
    /// cannot object - the continuation volume it promises simply never
    /// exists - so the CRC gate has to notice that the header set does
    /// not tile the file it declares. It used to skip: `split_after`
    /// nulled the header CRC, and every demote below was gated on
    /// `tiled`.
    #[test]
    fn split_after_with_oversized_unpacked_size_demotes() {
        let dir = tmpdir("oversize-b");
        let data = payload(4_000, 6);
        let vol = fixtures::rar5_volume(&[("movie.mkv", 8 << 20, &data, false, true)]);
        let ex = Extractor::new(&dir, 1, true);
        feed(&ex, 0, "v.rar", &vol, 700, 4);
        let rep = ex.finish().unwrap();
        assert!(
            !rep.fallbacks.is_empty(),
            "headers that do not cover the file must demote, got {:?}",
            rep.fallbacks
        );
        assert!(
            !dir.join("movie.mkv").exists(),
            "no sparse output may survive the demote"
        );
        assert!(rep.extracted.iter().all(|(n, _)| n != "movie.mkv"), "{:?}", rep.extracted);
        assert_eq!(std::fs::read(dir.join("v.rar")).unwrap(), vol);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The regression that matters most: a REAL multi-volume split set
    /// (per-volume `data_len` well under the declared whole-file
    /// `unpacked_size`, stored CRCs, out-of-order arrival) must still go
    /// through the one-pass path untouched - no demote, byte-exact
    /// output, no volume files left behind.
    #[test]
    fn legitimate_split_set_still_extracts_one_pass() {
        let dir = tmpdir("split-legit");
        let total = payload(500_000, 8);
        let cut = |r: std::ops::Range<usize>| crc32fast::hash(&total[r]);
        let vols = [
            fixtures::rar5_volume_n_crc(
                &[("film.mkv", 500_000, &total[..200_000], false, true, Some(cut(0..200_000)))],
                0,
            ),
            fixtures::rar5_volume_n_crc(
                &[(
                    "film.mkv",
                    500_000,
                    &total[200_000..400_000],
                    true,
                    true,
                    Some(cut(200_000..400_000)),
                )],
                1,
            ),
            // Last piece carries the WHOLE-file CRC, the way real
            // archivers write it - so the composed gate actually runs.
            fixtures::rar5_volume_n_crc(
                &[("film.mkv", 500_000, &total[400_000..], true, false, Some(cut(0..500_000)))],
                2,
            ),
        ];
        let ex = Extractor::new(&dir, 3, true);
        feed(&ex, 2, "x.part3.rar", &vols[2], 9000, 31);
        feed(&ex, 0, "x.part1.rar", &vols[0], 9000, 32);
        feed(&ex, 1, "x.part2.rar", &vols[1], 9000, 33);
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("film.mkv")).unwrap(), total);
        assert!(!dir.join("x.part1.rar").exists());
        assert!(!dir.join("x.part3.rar").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// M2c.1: patch_volume_span heals holes in a mapped volume - data
    /// bytes land in the extracted output, envelope bytes (including an
    /// end-of-archive record that never arrived) re-enter the parser so
    /// finish() completes without a fallback, and read_at serves the
    /// patched view byte-exactly.
    #[test]
    fn patch_volume_span_writes_through_the_mapping() {
        let dir = tmpdir("patch");
        let total = payload(500_000, 9);
        let vols: Vec<Vec<u8>> = vec![
            fixtures::rar5_volume(&[("film.mkv", 500_000, &total[..200_000], false, true)]),
            fixtures::rar5_volume(&[("film.mkv", 500_000, &total[200_000..400_000], true, true)]),
            fixtures::rar5_volume(&[("film.mkv", 500_000, &total[400_000..], true, false)]),
        ];
        let ex = Extractor::new(&dir, 3, true);
        feed(&ex, 0, "x.part1.rar", &vols[0], 9000, 21);
        // Volume 2: a mid-data article lost. Volume 3: the TAIL article
        // lost - it carried the end-of-archive record, so the volume
        // parser stalls there until the patch feeds it back.
        let art = 9000usize;
        let v3_tail = (vols[2].len() - 1) / art * art;
        for (si, v, skip) in [(1usize, &vols[1], 45_000usize), (2, &vols[2], v3_tail)] {
            let mut i = 0;
            while i < v.len() {
                let e = (i + art).min(v.len());
                if i != skip {
                    ex.write(si, &format!("x.part{}.rar", si + 1), v.len() as u64, i as u64, &v[i..e])
                        .unwrap();
                }
                i = e;
            }
        }
        assert!(!ex.covered(1, 45_000, art), "hole really is a hole");
        // Patch the holes with repaired bytes (here: the originals).
        ex.patch_volume_span(1, 45_000, &vols[1][45_000..54_000]).unwrap();
        ex.patch_volume_span(2, v3_tail as u64, &vols[2][v3_tail..]).unwrap();
        // read_at serves both healed volume views byte-exactly…
        for si in [1usize, 2] {
            let mut back = vec![0u8; vols[si].len()];
            ex.read_at(si, 0, &mut back).unwrap();
            assert_eq!(back, vols[si], "volume {si} view healed");
        }
        // …and the parser resumed past the lost tail: no fallback, the
        // extracted output is pristine, no volume ever materialized.
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("film.mkv")).unwrap(), total);
        assert!(!dir.join("x.part2.rar").exists(), "no volume materialized");
        assert!(!dir.join("x.part3.rar").exists(), "no volume materialized");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn obfuscated_names_group_by_inner_file() {
        let dir = tmpdir("obf");
        let total = payload(300_000, 5);
        let v1 = fixtures::rar5_volume_n(&[("real.mkv", 300_000, &total[..150_000], false, true)], 0);
        let v2 = fixtures::rar5_volume_n(&[("real.mkv", 300_000, &total[150_000..], true, false)], 1);
        let ex = Extractor::new(&dir, 2, true);
        // Hash-garbage yEnc names; sorted order of names is WRONG (b < a).
        feed(&ex, 0, "bbbb1234.bin", &v1, 8000, 7);
        feed(&ex, 1, "aaaa9999.bin", &v2, 8000, 8);
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("real.mkv")).unwrap(), total);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// TODO §7 #1 regression: a store set carrying MORE THAN ONE inner
    /// file, with a file boundary inside a middle volume. Volumes group
    /// by their first inner name, so the E02-only continuation volumes
    /// formed a separate group that could never base-resolve; at finish()
    /// that group fell back and deleted E02.mkv - including the head
    /// bytes the healthy group had extracted (its volumes were never
    /// materialized), i.e. deterministic whole-file loss at exit 0.
    #[test]
    fn multi_file_store_set_extracts_across_file_boundary() {
        let dir = tmpdir("multifile");
        let e01 = payload(350_000, 21);
        let e02 = payload(250_000, 22);
        let vols = vec![
            fixtures::rar5_volume_n(&[("E01.mkv", 350_000, &e01[..200_000], false, true)], 0),
            fixtures::rar5_volume_n(
                &[
                    ("E01.mkv", 350_000, &e01[200_000..], true, false),
                    ("E02.mkv", 250_000, &e02[..50_000], false, true),
                ],
                1,
            ),
            fixtures::rar5_volume_n(&[("E02.mkv", 250_000, &e02[50_000..], true, false)], 2),
        ];
        // Obfuscated volume names; feed the continuation-only volume FIRST
        // so its group forms before the boundary volume can link it.
        let ex = Extractor::new(&dir, 3, true);
        feed(&ex, 2, "ccc.bin", &vols[2], 9000, 51);
        feed(&ex, 0, "bbb.bin", &vols[0], 9000, 52);
        feed(&ex, 1, "aaa.bin", &vols[1], 9000, 53);
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(
            rep.extracted,
            vec![
                ("E01.mkv".to_string(), 350_000),
                ("E02.mkv".to_string(), 250_000)
            ]
        );
        assert_eq!(std::fs::read(dir.join("E01.mkv")).unwrap(), e01);
        assert_eq!(std::fs::read(dir.join("E02.mkv")).unwrap(), e02);
        for n in ["bbb.bin", "aaa.bin", "ccc.bin"] {
            assert!(!dir.join(n).exists(), "volume {n} materialized");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Finding 14: two DISTINCT inner entries whose names sanitize to the
    /// same on-disk name ("a/b.txt" -> "a_b.txt" collides with a literal
    /// "a_b.txt") must each get their own output. Keyed on the sanitized
    /// name they shared one writer and the second silently overwrote the
    /// first; keyed on the raw name they land as two disambiguated files.
    #[test]
    fn distinct_names_that_sanitize_alike_dont_share_output() {
        let dir = tmpdir("sanitize-collide");
        let a = payload(120_000, 61);
        let b = payload(90_000, 62);
        let vol = fixtures::rar5_volume(&[
            ("a/b.txt", 120_000, &a, false, false),
            ("a_b.txt", 90_000, &b, false, false),
        ]);
        let ex = Extractor::new(&dir, 1, true);
        feed(&ex, 0, "v.rar", &vol, 7000, 63);
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        // Both payloads must survive intact on disk under two distinct names,
        // never one truncated/interleaved file.
        let landed: Vec<Vec<u8>> = dir_files(&dir)
            .into_iter()
            .map(|n| std::fs::read(dir.join(n)).unwrap())
            .collect();
        assert!(landed.iter().any(|f| f == &a), "first entry's bytes lost");
        assert!(landed.iter().any(|f| f == &b), "second entry's bytes lost");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Finding 15: on a case-insensitive default volume (macOS/Windows)
    /// "README" and "readme" name one filesystem object, so the second
    /// output would truncate the first. The claim key folds case there, so
    /// the second disambiguates and both payloads survive. (On case-
    /// sensitive Linux they are distinct files already; either way both
    /// payloads land intact.)
    #[test]
    fn case_only_name_collision_keeps_both_outputs() {
        let dir = tmpdir("case-collide");
        let a = payload(120_000, 71);
        let b = payload(90_000, 72);
        let vol = fixtures::rar5_volume(&[
            ("README", 120_000, &a, false, false),
            ("readme", 90_000, &b, false, false),
        ]);
        let ex = Extractor::new(&dir, 1, true);
        feed(&ex, 0, "v.rar", &vol, 7000, 73);
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        let landed: Vec<Vec<u8>> = dir_files(&dir)
            .into_iter()
            .map(|n| std::fs::read(dir.join(n)).unwrap())
            .collect();
        assert!(landed.iter().any(|f| f == &a), "README bytes lost");
        assert!(landed.iter().any(|f| f == &b), "readme bytes lost");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Same layout at season-pack scale - six volumes, boundary inside
    /// v3 - driven through every linking path: sequential (the
    /// deterministic-loss order), continuations first (the group forms
    /// before its head volume exists), and boundary volume first (the
    /// alias exists before either neighbor group).
    #[test]
    fn multi_file_store_set_survives_all_feed_orders() {
        let e01 = payload(350_000, 21);
        let e02 = payload(250_000, 22);
        let vols: Vec<Vec<u8>> = vec![
            fixtures::rar5_volume_n(&[("E01.mkv", 350_000, &e01[..100_000], false, true)], 0),
            fixtures::rar5_volume_n(&[("E01.mkv", 350_000, &e01[100_000..200_000], true, true)], 1),
            fixtures::rar5_volume_n(&[("E01.mkv", 350_000, &e01[200_000..300_000], true, true)], 2),
            fixtures::rar5_volume_n(
                &[
                    ("E01.mkv", 350_000, &e01[300_000..], true, false),
                    ("E02.mkv", 250_000, &e02[..50_000], false, true),
                ],
                3,
            ),
            fixtures::rar5_volume_n(&[("E02.mkv", 250_000, &e02[50_000..150_000], true, true)], 4),
            fixtures::rar5_volume_n(&[("E02.mkv", 250_000, &e02[150_000..], true, false)], 5),
        ];
        for (t, order) in [
            [0usize, 1, 2, 3, 4, 5],
            [4, 5, 0, 1, 2, 3],
            [3, 4, 5, 2, 1, 0],
        ]
        .iter()
        .enumerate()
        {
            let dir = tmpdir(&format!("multifile{t}"));
            let ex = Extractor::new(&dir, 6, true);
            for &vi in order {
                let name = format!("obf{:02x}.bin", (vi as u8) ^ 0x5a);
                feed(&ex, vi, &name, &vols[vi], 7000, 40 + vi as u64);
            }
            let rep = ex.finish().unwrap();
            assert!(rep.fallbacks.is_empty(), "order {order:?}: {:?}", rep.fallbacks);
            assert_eq!(
                rep.extracted,
                vec![
                    ("E01.mkv".to_string(), 350_000),
                    ("E02.mkv".to_string(), 250_000)
                ],
                "order {order:?}"
            );
            assert_eq!(std::fs::read(dir.join("E01.mkv")).unwrap(), e01, "order {order:?}");
            assert_eq!(std::fs::read(dir.join("E02.mkv")).unwrap(), e02, "order {order:?}");
            // One-pass: no volume file may exist.
            let files: Vec<String> = std::fs::read_dir(&dir)
                .unwrap()
                .flatten()
                .map(|e| e.file_name().to_string_lossy().to_string())
                .collect();
            assert_eq!(files.len(), 2, "order {order:?}: {files:?}");
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    /// Fallback read-back must skip sparse holes: an unwritten inner-file
    /// region reads back as zeros, and stamping those into the
    /// materialized volume marked the missing range as written -
    /// verification then trusted garbage (the zero-fill half of the
    /// deferred-pwrite race, minus the race).
    #[test]
    fn fallback_readback_skips_unwritten_ranges() {
        let dir = tmpdir("fbholes");
        let data = payload(300_000, 17);
        let vol = fixtures::rar5_volume(&[("f.bin", 300_000, &data, false, false)]);
        let ex = Extractor::new(&dir, 1, true);
        // Feed every article except one mid-data chunk.
        let art = 7000;
        let miss = vol.len() / 2 / art;
        for i in 0..vol.len().div_ceil(art) {
            if i == miss {
                continue;
            }
            let s = i * art;
            let e = (s + art).min(vol.len());
            ex.write(0, "v.rar", vol.len() as u64, s as u64, &vol[s..e])
                .unwrap();
        }
        ex.materialize(0).unwrap();
        let (ms, me) = (miss * art, ((miss + 1) * art).min(vol.len()));
        // The missing article's range must NOT be claimed as written.
        assert!(
            !ex.covered(0, ms as u64, me - ms),
            "hole was stamped into the volume as zeros"
        );
        // Late arrival writes through and completes the volume.
        ex.write(0, "v.rar", vol.len() as u64, ms as u64, &vol[ms..me])
            .unwrap();
        ex.finish().unwrap();
        assert_eq!(std::fs::read(dir.join("v.rar")).unwrap(), vol);
        assert!(!dir.join("f.bin").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Two archives in one NZB that reuse an inner filename must not
    /// share a writer (conflicting-offset interleave, silent since inner
    /// files aren't PAR2-covered) - and must NOT be merged into one group
    /// (the shared name is wholly contained, not split: no archive-chain
    /// evidence).
    #[test]
    fn same_inner_name_across_archives_gets_own_files() {
        let dir = tmpdir("namecollide");
        let film_a = payload(120_000, 31);
        let film_b = payload(140_000, 32);
        let samp_a = payload(30_000, 33);
        let samp_b = payload(40_000, 34);
        let va = fixtures::rar5_volume(&[
            ("filmA.mkv", 120_000, &film_a, false, false),
            ("sample.mkv", 30_000, &samp_a, false, false),
        ]);
        let vb = fixtures::rar5_volume(&[
            ("filmB.mkv", 140_000, &film_b, false, false),
            ("sample.mkv", 40_000, &samp_b, false, false),
        ]);
        let ex = Extractor::new(&dir, 2, true);
        feed(&ex, 0, "a.rar", &va, 8000, 61);
        feed(&ex, 1, "b.rar", &vb, 8000, 62);
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("filmA.mkv")).unwrap(), film_a);
        assert_eq!(std::fs::read(dir.join("filmB.mkv")).unwrap(), film_b);
        // One sample per archive, the second under a disambiguated name.
        let mut samples: Vec<Vec<u8>> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .ends_with("sample.mkv")
            })
            .map(|e| std::fs::read(e.path()).unwrap())
            .collect();
        samples.sort_by_key(|s| s.len());
        assert_eq!(samples.len(), 2, "each archive keeps its own sample");
        assert_eq!(samples[0], samp_a);
        assert_eq!(samples[1], samp_b);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A held span can carry the NEXT file's header bytes while the parse
    /// window is still megabytes behind (stash keeps only bytes near the
    /// cursor). Draining holds must re-FEED the mapper, not just retry
    /// extraction - otherwise mapping stalls and a healthy group falls
    /// back at finish().
    #[test]
    fn held_header_bytes_reach_the_parser_on_drain() {
        let dir = tmpdir("farheader");
        // Data areas > MAX_WIN (4 MiB) so each later header starts
        // outside the parse window of the previous cursor position.
        let f1 = payload(5_100_000, 41);
        let f2 = payload(5_100_000, 42);
        let f3 = payload(4_000, 43);
        let vol = fixtures::rar5_volume(&[
            ("one.bin", 5_100_000, &f1, false, false),
            ("two.bin", 5_100_000, &f2, false, false),
            ("three.bin", 4_000, &f3, false, false),
        ]);
        let art = 65_536;
        let ex = Extractor::new(&dir, 1, true);
        let write_art = |i: usize| {
            let s = i * art;
            let e = (s + art).min(vol.len());
            ex.write(0, "v.rar", vol.len() as u64, s as u64, &vol[s..e]).unwrap();
        };
        let n_arts = vol.len().div_ceil(art);
        // Article 0: sniff + file-1 header → cursor jumps to ~5.1 MB.
        write_art(0);
        // The article carrying file-3's header (~10.2 MB) arrives while
        // the window sits at ~5.1 MB - its bytes miss the stash and the
        // span is held.
        write_art(n_arts - 1);
        // Everything else in order; file-2's header advances the cursor
        // to file-3's header, which now only exists in that held span.
        for i in 1..n_arts - 1 {
            write_art(i);
        }
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("three.bin")).unwrap(), f3);
        assert_eq!(std::fs::read(dir.join("one.bin")).unwrap(), f1);
        assert_eq!(std::fs::read(dir.join("two.bin")).unwrap(), f2);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn plain_files_still_work() {
        let dir = tmpdir("plain");
        let data = payload(50_000, 9);
        let ex = Extractor::new(&dir, 1, true);
        // Not a rar - offset-0 article sniffs plain. Feed out of order.
        ex.write(0, "doc.iso", 50_000, 30_000, &data[30_000..]).unwrap();
        ex.write(0, "doc.iso", 50_000, 0, &data[..30_000]).unwrap();
        ex.finish().unwrap();
        assert_eq!(std::fs::read(dir.join("doc.iso")).unwrap(), data);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn read_at_reconstructs_volume_bytes() {
        let dir = tmpdir("readat");
        let data = payload(150_000, 4);
        let vol = fixtures::rar5_volume(&[("inner.bin", 150_000, &data, false, false)]);
        let ex = Extractor::new(&dir, 1, true);
        feed(&ex, 0, "v.rar", &vol, 6000, 21);
        // Reconstruct arbitrary volume ranges byte-exactly.
        for (off, len) in [(0usize, 64), (5, 200), (100, 149_000), (0, vol.len())] {
            let mut buf = vec![0u8; len.min(vol.len() - off)];
            ex.read_at(0, off as u64, &mut buf).unwrap();
            assert_eq!(&buf[..], &vol[off..off + buf.len()], "range {off}+{len}");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn encrypted_headers_fall_back_to_materialized_volume() {
        let dir = tmpdir("enc");
        // Signature + encryption block type 4 (valid CRC).
        let mut vol = Vec::new();
        vol.extend_from_slice(b"Rar!\x1a\x07\x01\x00");
        let hdr = [0x04u8, 0x00]; // type 4, flags 0
        vol.extend_from_slice(&crc32fast::hash(&hdr).to_le_bytes());
        vol.push(2); // header size vint
        vol.extend_from_slice(&hdr);
        vol.extend_from_slice(&payload(5000, 6)); // opaque encrypted stuff
        let ex = Extractor::new(&dir, 1, true);
        let n = vol.len();
        ex.write(0, "sec.rar", n as u64, 0, &vol[..2000]).unwrap();
        ex.write(0, "sec.rar", n as u64, 2000, &vol[2000..]).unwrap();
        let rep = ex.finish().unwrap();
        assert!(rep.extracted.is_empty());
        // Volume materialized byte-exactly for a future unrar-with-password.
        assert_eq!(std::fs::read(dir.join("sec.rar")).unwrap(), vol);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn protect_sources_happy_path_extracts_normally() {
        let dir = tmpdir("protect-ok");
        let total = payload(300_000, 12);
        let vols = vec![
            fixtures::rar5_volume_n(&[("film.mkv", 300_000, &total[..150_000], false, true)], 0),
            fixtures::rar5_volume_n(&[("film.mkv", 300_000, &total[150_000..], true, false)], 1),
        ];
        let ex = Extractor::new(&dir, 2, true);
        ex.set_protect_sources();
        feed(&ex, 0, "x.part1.rar", &vols[0], 8000, 41);
        feed(&ex, 1, "x.part2.rar", &vols[1], 8000, 42);
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("film.mkv")).unwrap(), total);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The 2026-07 damaged-post bench corruption: re-extraction fed
    /// volumes off disk, hit the holds cap, and the fallback materialized
    /// "volumes" over the very files being read (FileWriter::create
    /// truncates). Protect-sources mode must leave the source files
    /// byte-identical, never create slot writers, and delete any partial
    /// inner file.
    #[test]
    fn protect_sources_fallback_never_touches_source_files() {
        let dir = tmpdir("protect-fb");
        let total = payload(20_000_000, 13);
        let vols = vec![
            fixtures::rar5_volume_n(
                &[("film.mkv", 20_000_000, &total[..10_000_000], false, true)],
                0,
            ),
            fixtures::rar5_volume_n(
                &[("film.mkv", 20_000_000, &total[10_000_000..], true, false)],
                1,
            ),
        ];
        // The volume files exist on disk, as in reextract_dir.
        std::fs::write(dir.join("x.part1.rar"), &vols[0]).unwrap();
        std::fs::write(dir.join("x.part2.rar"), &vols[1]).unwrap();

        let ex = Extractor::new(&dir, 2, true);
        ex.set_protect_sources();
        ex.set_holds_cap(1); // floors at 8 MB - part2's data area exceeds it
        // Sequential in-file order, as reextract_dir feeds. part2 first:
        // its split piece can't base-resolve, so every span holds until
        // the cap trips the group fallback.
        let mut feed_seq = |slot: usize, name: &str, vol: &[u8]| {
            for (i, chunk) in vol.chunks(65_000).enumerate() {
                ex.write(slot, name, vol.len() as u64, (i * 65_000) as u64, chunk)
                    .unwrap();
            }
        };
        feed_seq(1, "x.part2.rar", &vols[1]);
        feed_seq(0, "x.part1.rar", &vols[0]);
        let rep = ex.finish().unwrap();
        assert!(!rep.fallbacks.is_empty(), "expected a holds-cap fallback");

        // Source volumes byte-identical - NOT truncated/rewritten.
        assert_eq!(std::fs::read(dir.join("x.part1.rar")).unwrap(), vols[0]);
        assert_eq!(std::fs::read(dir.join("x.part2.rar")).unwrap(), vols[1]);
        // No slot writers, no half-written inner file masquerading as output.
        assert!(ex.slot_path(0).is_none());
        assert!(ex.slot_path(1).is_none());
        assert!(!dir.join("film.mkv").exists());
        let extra: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .filter(|n| n != "x.part1.rar" && n != "x.part2.rar")
            .collect();
        assert!(extra.is_empty(), "unexpected files: {extra:?}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn protect_sources_non_rar_sniff_discards() {
        let dir = tmpdir("protect-plain");
        let data = payload(50_000, 14);
        std::fs::write(dir.join("doc.bin"), &data).unwrap();
        let ex = Extractor::new(&dir, 1, true);
        ex.set_protect_sources();
        ex.write(0, "doc.bin", 50_000, 0, &data[..30_000]).unwrap();
        ex.write(0, "doc.bin", 50_000, 30_000, &data[30_000..]).unwrap();
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.iter().any(|(_, w)| w.contains("not a RAR")));
        // Source untouched - a plain writer would have truncated it.
        assert_eq!(std::fs::read(dir.join("doc.bin")).unwrap(), data);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Live 2026-07-20 (Seinfeld S08E05, 12,109 segments): synthesized
    /// segment numbering means "segment 1" isn't the yEnc offset-0
    /// article, so the sniff may come LAST - every span piled into
    /// pre-classification holds, nothing reached disk/stats/journal for
    /// the whole run. The per-slot spill must flip the slot Plain and
    /// flush once its held bytes pass the budget, long before offset 0.
    #[test]
    fn unclassified_slot_spills_to_plain_before_sniff() {
        let dir = tmpdir("prespill");
        let data = payload(6_000_000, 9);
        let ex = Extractor::new(&dir, 1, true);
        ex.set_holds_cap(8 << 20); // spill budget = clamp(2M, 4M..) = 4 MB
        let art = 40_000;
        // Everything EXCEPT the offset-0 article, in scrambled order.
        let mut offs: Vec<usize> = (1..data.len().div_ceil(art)).map(|i| i * art).collect();
        let mut state = 77u64;
        for i in (1..offs.len()).rev() {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            offs.swap(i, (state >> 33) as usize % (i + 1));
        }
        for s in offs {
            let e = (s + art).min(data.len());
            ex.write(0, "video.bin", data.len() as u64, s as u64, &data[s..e])
                .unwrap();
        }
        // The slot must have spilled: file on disk BEFORE the sniff, and
        // held bytes bounded by the budget (one article of slack), not
        // the ~6 MB the whole tail would have piled up.
        let path = dir.join("video.bin");
        assert!(path.exists(), "spill never created the plain file");
        assert!(
            ex.holds_peak() <= (4 << 20) + art,
            "holds peaked at {} - slot never spilled",
            ex.holds_peak()
        );
        // Offset 0 arrives dead last; the slot is already Plain.
        ex.write(0, "video.bin", data.len() as u64, 0, &data[..art]).unwrap();
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(&path).unwrap(), data);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Same scramble on a real RAR volume: giving up on the sniff must
    /// still be CORRECT - the volume materializes byte-identical on disk
    /// (in-stream extraction is forfeited, not the data).
    #[test]
    fn unclassified_spill_of_rar_volume_materializes_it() {
        let dir = tmpdir("prespill-rar");
        let data = payload(6_000_000, 10);
        let vol = fixtures::rar5_volume(&[("movie.mkv", 6_000_000, &data, false, false)]);
        let ex = Extractor::new(&dir, 1, true);
        ex.set_holds_cap(8 << 20);
        let art = 40_000;
        let mut offs: Vec<usize> = (1..vol.len().div_ceil(art)).map(|i| i * art).collect();
        let mut state = 78u64;
        for i in (1..offs.len()).rev() {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            offs.swap(i, (state >> 33) as usize % (i + 1));
        }
        for s in offs {
            let e = (s + art).min(vol.len());
            ex.write(0, "v.rar", vol.len() as u64, s as u64, &vol[s..e]).unwrap();
        }
        ex.write(0, "v.rar", vol.len() as u64, 0, &vol[..art]).unwrap();
        ex.finish().unwrap();
        assert_eq!(
            std::fs::read(dir.join("v.rar")).unwrap(),
            vol,
            "materialized volume must be byte-identical"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Volume bytes that belong to no data area - service blocks (a RAR
    /// recovery record) and anything past the end-of-archive marker - go
    /// to the header stash, and once the mapper is complete that is EVERY
    /// remaining byte of the volume. Uncharged, a crafted volume (a tiny
    /// archive plus gigabytes of trailing junk) pinned all of it in RAM
    /// with no spill and no demote. The stash charges the holds budget,
    /// so the volume materializes instead.
    #[test]
    fn trailing_bytes_past_archive_end_are_capped() {
        let dir = tmpdir("hdrcap");
        let data = payload(1_000, 12);
        let mut vol = fixtures::rar5_volume(&[("a.bin", 1_000, &data, false, false)]);
        let archive_end = vol.len();
        vol.extend(payload(12 << 20, 3)); // junk past the end block
        let ex = Extractor::new(&dir, 1, true);
        ex.set_holds_cap(1); // floors at 8 MB
        let art = 64_000;
        let mut s = 0usize;
        while s < vol.len() {
            let e = (s + art).min(vol.len());
            ex.write(0, "v.rar", vol.len() as u64, s as u64, &vol[s..e]).unwrap();
            s = e;
        }
        assert!(
            ex.holds_peak() <= (8 << 20) + art + archive_end,
            "stash peaked at {} - the junk was never charged",
            ex.holds_peak()
        );
        let rep = ex.finish().unwrap();
        // The reason must be one the caller ROUTES: a level-0 demote it
        // does not recognize means loose volumes, no payload, exit 0.
        assert!(
            rep.fallbacks
                .iter()
                .any(|(_, w)| w.contains("held-bytes cap") && !w.starts_with("nested fallback:")),
            "{:?}",
            rep.fallbacks
        );
        // Demoting is not losing: the volume is byte-identical on disk.
        assert_eq!(std::fs::read(dir.join("v.rar")).unwrap(), vol);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn late_fallback_reconstructs_from_extracted() {
        let dir = tmpdir("latefb");
        let data = payload(120_000, 8);
        let vol = fixtures::rar5_volume(&[("f.bin", 120_000, &data, false, false)]);
        let ex = Extractor::new(&dir, 1, true);
        // Feed everything (fully extracted)…
        feed(&ex, 0, "v.rar", &vol, 5000, 31);
        // …then force materialization (as the repair path would).
        ex.materialize(0).unwrap();
        let vpath = ex.slot_path(0).expect("volume materialized");
        assert_eq!(std::fs::read(&vpath).unwrap(), vol, "byte-exact reconstruction");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    // -- archive shape (the live badge's facts) --

    fn shape_of(ex: &Extractor) -> Vec<&'static str> {
        ex.archive_shape().map(|s| s.tokens().to_vec()).unwrap_or_default()
    }

    #[test]
    fn shape_is_empty_until_something_archive_shaped_parses() {
        let dir = tmpdir("shape-none");
        let ex = Extractor::new(&dir, 1, true);
        assert!(ex.archive_shape().is_none(), "nothing fed yet");
        // A loose file is not an archive and must never grow a badge.
        let data = payload(50_000, 9);
        feed(&ex, 0, "notes.txt", &data, 7000, 3);
        ex.finish().unwrap();
        assert!(ex.archive_shape().is_none(), "{:?}", shape_of(&ex));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn shape_reports_rar5_store_one_pass() {
        let dir = tmpdir("shape-store");
        let data = payload(200_000, 1);
        let vol = fixtures::rar5_volume(&[("movie.mkv", 200_000, &data, false, false)]);
        let ex = Extractor::new(&dir, 1, true);
        feed(&ex, 0, "v.rar", &vol, 7000, 3);
        // Known DURING the download, not just at finish - that is the
        // whole point of the live badge.
        assert_eq!(shape_of(&ex), ["rar5", "store", "one-pass"]);
        ex.finish().unwrap();
        assert_eq!(shape_of(&ex), ["rar5", "store", "one-pass"]);
        assert_eq!(
            ex.archive_shape().unwrap().display(),
            "RAR5 · stored · one-pass"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn shape_reports_rar4() {
        let dir = tmpdir("shape-rar4");
        let data = payload(120_000, 4);
        let vol = fixtures::rar4_volume(&[("movie.mkv", 120_000, &data, false, false)]);
        let ex = Extractor::new(&dir, 1, true);
        feed(&ex, 0, "v.rar", &vol, 7000, 3);
        ex.finish().unwrap();
        assert_eq!(shape_of(&ex)[0], "rar4", "{:?}", shape_of(&ex));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn shape_reports_compressed_set_as_unpacked_on_disk() {
        let dir = tmpdir("shape-comp");
        let data = payload(120_000, 2);
        // A compressed entry cannot be mapped at the top level: the
        // volume materializes and the badge has to say so.
        let vol = rar5_compressed_volume("movie.mkv", &data);
        let ex = Extractor::new(&dir, 1, true);
        feed(&ex, 0, "v.rar", &vol, 7000, 3);
        ex.finish().unwrap();
        let sh = shape_of(&ex);
        assert_eq!(sh[0], "rar5", "{sh:?}");
        assert!(sh.contains(&"compressed"), "{sh:?}");
        assert!(sh.contains(&"on-disk"), "{sh:?}");
        assert!(!sh.contains(&"one-pass"), "{sh:?}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn shape_says_one_pass_when_an_encrypted_set_decrypts_in_stream() {
        let dir = tmpdir("shape-enc");
        let plain = payload(200_003, 41);
        let f = fixtures::encrypt_file("hunter2", &plain, 5);
        let vol =
            fixtures::rar5_volume_enc(&[("movie.mkv", &f, 0..f.cipher.len(), false, false)], None);
        let ex = Extractor::new(&dir, 1, true);
        ex.set_password("hunter2");
        feed(&ex, 0, "v.rar", &vol, 7000, 3);
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        // Plaintext-once: nothing is ever stored locked, so this is an
        // ordinary one-pass set that happens to be encrypted.
        assert_eq!(shape_of(&ex), ["rar5", "store", "encrypted", "one-pass"]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn shape_says_unlocked_at_the_end_on_the_legacy_encrypted_path() {
        let dir = tmpdir("shape-enc-legacy");
        let plain = payload(200_003, 41);
        let f = fixtures::encrypt_file("hunter2", &plain, 5);
        let vol =
            fixtures::rar5_volume_enc(&[("movie.mkv", &f, 0..f.cipher.len(), false, false)], None);
        let ex = Extractor::new(&dir, 1, true);
        ex.set_password("hunter2");
        // Ciphertext assembled at store offsets, unlocked by the finish
        // pass - the shape must distinguish it from plaintext-once.
        ex.set_instream_decrypt(false);
        feed(&ex, 0, "v.rar", &vol, 7000, 3);
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(
            shape_of(&ex),
            ["rar5", "store", "encrypted", "unlock-at-end"]
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn shape_says_encrypted_when_the_headers_are_locked() {
        let dir = tmpdir("shape-hdr");
        // Encrypted headers with no password: nothing parses, so the
        // blocker is the only place the fact can come from.
        let vol = fixtures::rar4_encrypted_headers(200_000);
        let ex = Extractor::new(&dir, 1, true);
        feed(&ex, 0, "v.rar", &vol, 7000, 3);
        ex.finish().unwrap();
        let sh = shape_of(&ex);
        assert!(sh.contains(&"encrypted"), "{sh:?}");
        assert!(sh.contains(&"on-disk"), "{sh:?}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn shape_reports_a_top_level_7z_as_unpacked_on_disk() {
        let dir = tmpdir("shape-7z");
        // A top-level .7z never maps in-stream (the chase is nested-only),
        // so it lands on disk for the post-pass. Without the signature
        // sniff the badge would say nothing at all about a 7z release.
        let mut vol = b"7z\xbc\xaf\x27\x1c".to_vec();
        vol.extend_from_slice(&payload(80_000, 6));
        let ex = Extractor::new(&dir, 1, true);
        feed(&ex, 0, "release.7z", &vol, 7000, 3);
        ex.finish().unwrap();
        assert_eq!(shape_of(&ex), ["7z", "on-disk"]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn shape_tag_round_trips_through_the_wire_form() {
        let dir = tmpdir("shape-tag");
        let data = payload(200_000, 1);
        let vol = fixtures::rar5_volume(&[("movie.mkv", 200_000, &data, false, false)]);
        let ex = Extractor::new(&dir, 1, true);
        feed(&ex, 0, "v.rar", &vol, 7000, 3);
        ex.finish().unwrap();
        // The daemon persists exactly this string and the dashboard
        // splits it back apart on whitespace.
        let tag = ex.archive_shape().unwrap().tag();
        assert_eq!(tag, "rar5 store one-pass");
        assert_eq!(
            tag.split(' ').map(shape_word).collect::<Vec<_>>(),
            ["RAR5", "stored", "one-pass"]
        );
        // An unknown token from a newer daemon still reads as itself.
        assert_eq!(shape_word("rar9"), "rar9");
    }

    // -- encrypted RAR5 store sets (native AES decryption) --

    #[test]
    fn encrypted_single_volume_decrypts_in_stream() {
        let dir = tmpdir("enc-single");
        // Non-16-aligned length exercises the end-padding truncate.
        let plain = payload(200_003, 41);
        let f = fixtures::encrypt_file("hunter2", &plain, 5);
        let vol =
            fixtures::rar5_volume_enc(&[("movie.mkv", &f, 0..f.cipher.len(), false, false)], None);
        let ex = Extractor::new(&dir, 1, true);
        ex.set_password("hunter2");
        feed(&ex, 0, "v.rar", &vol, 7000, 3);
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(rep.decrypted, vec!["movie.mkv".to_string()]);
        assert_eq!(rep.extracted, vec![("movie.mkv".to_string(), 200_003)]);
        let out = std::fs::read(dir.join("movie.mkv")).unwrap();
        assert_eq!(out.len(), plain.len(), "padding must be truncated");
        assert_eq!(out, plain);
        assert!(!dir.join("v.rar").exists(), "one-pass: no volume on disk");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Finding 8: an encrypted RAR5 STORE entry with a plain (non-tweaked)
    /// stored CRC must have its DECRYPTED plaintext verified. The password
    /// check proves the key, not that every ciphertext block survived the
    /// wire, so damaged ciphertext (the outer PAR2 vouches for the archive
    /// as-posted) would otherwise decrypt to corrupt plaintext and report
    /// success. With the CRC present, pristine ciphertext succeeds and a
    /// single flipped ciphertext byte fails the extraction loudly.
    #[test]
    fn encrypted_store_verifies_plaintext_crc() {
        let plain = payload(200_003, 47);
        // Pristine: with_crc set, tweaked clear -> plaintext CRC is checked
        // and matches, so extraction succeeds.
        let mut f = fixtures::encrypt_file("hunter2", &plain, 6);
        f.with_crc = true;
        f.tweaked = false;
        let dir = tmpdir("enc-crc-ok");
        let vol =
            fixtures::rar5_volume_enc(&[("movie.mkv", &f, 0..f.cipher.len(), false, false)], None);
        let ex = Extractor::new(&dir, 1, true);
        ex.set_password("hunter2");
        feed(&ex, 0, "v.rar", &vol, 7000, 7);
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("movie.mkv")).unwrap(), plain);
        std::fs::remove_dir_all(&dir).unwrap();

        // Damaged ciphertext, correct password: decryption yields corrupt
        // plaintext whose CRC no longer matches -> hard failure, no clean
        // output. (Before finding 8's fix this returned Ok with corrupt
        // movie.mkv.)
        let mut fbad = fixtures::encrypt_file("hunter2", &plain, 6);
        fbad.with_crc = true;
        fbad.tweaked = false;
        fbad.cipher[80_000] ^= 0x5A;
        let dir = tmpdir("enc-crc-bad");
        let vol = fixtures::rar5_volume_enc(
            &[("movie.mkv", &fbad, 0..fbad.cipher.len(), false, false)],
            None,
        );
        let ex = Extractor::new(&dir, 1, true);
        ex.set_password("hunter2");
        feed(&ex, 0, "v.rar", &vol, 7000, 8);
        let res = ex.finish();
        assert!(res.is_err(), "damaged encrypted plaintext must not succeed");
        let out = dir.join("movie.mkv");
        assert!(
            !out.exists() || std::fs::read(&out).unwrap() != plain,
            "corrupt plaintext must not masquerade as the clean file"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The decrypt pass shards a file across threads, seeding each shard's
    /// CBC chain from the ciphertext block before it and folding the shard
    /// CRCs back with `crc32_combine`. Every shard count must therefore
    /// produce byte-identical plaintext and an identical CRC to the serial
    /// pass - including when `unp` is not 16-aligned, so the tail shard
    /// carries padding that must stay out of the CRC.
    #[test]
    fn decrypt_shards_match_the_serial_pass() {
        // Over DECRYPT_PARALLEL_MIN so the sharded path actually engages,
        // and deliberately not a multiple of 16 or of the shard size.
        let plain = payload((36 << 20) + 7, 91);
        let key = [0x3Cu8; 32];
        let iv = [0x5Au8; 16];
        let mut cipher = plain.clone();
        cipher.resize(rarcrypt::align16(plain.len() as u64) as usize, 0);
        rarcrypt::CbcEncStream::new(&key, &iv).encrypt(&mut cipher);

        let dir = tmpdir("decrypt-shards");
        let src = dir.join("cipher.bin");
        std::fs::write(&src, &cipher).unwrap();
        let expect_crc = crc32fast::hash(&plain);

        for threads in [1usize, 2, 3, 5, 8, 64] {
            let out = dir.join(format!("plain-{threads}.bin"));
            let wf = File::options()
                .create(true)
                .truncate(true)
                .read(true)
                .write(true)
                .open(&out)
                .unwrap();
            decrypt_pass(
                &src,
                &wf,
                &key,
                &iv,
                plain.len() as u64,
                Some(expect_crc),
                threads,
            )
            .unwrap_or_else(|e| panic!("{threads} shards: {e}"));
            drop(wf);
            assert_eq!(
                std::fs::read(&out).unwrap(),
                plain,
                "{threads} shards produced different plaintext"
            );
        }

        // A wrong stored CRC must still be caught on the sharded path: the
        // combine has to reproduce the real whole-file CRC, not just agree
        // with itself.
        let out = dir.join("bad.bin");
        let wf = File::options()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(&out)
            .unwrap();
        let err = decrypt_pass(
            &src,
            &wf,
            &key,
            &iv,
            plain.len() as u64,
            Some(expect_crc ^ 1),
            8,
        );
        assert!(err.is_err(), "sharded pass must still enforce the CRC");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Shard scaling of the finish decrypt, for the low-end story. Run it
    /// with `--ignored --nocapture`, and with `--cfg aes_force_soft` to see
    /// the no-AES-hardware case (some budget ARM NAS SoCs omit the crypto
    /// extensions, and the RAR format leaves no cipher to fall back to).
    #[test]
    #[ignore = "timing bench, not a correctness gate"]
    fn decrypt_shard_scaling_bench() {
        let plain = payload(256 << 20, 13);
        let key = [0x11u8; 32];
        let iv = [0x22u8; 16];
        let mut cipher = plain.clone();
        rarcrypt::CbcEncStream::new(&key, &iv).encrypt(&mut cipher);
        let dir = tmpdir("decrypt-bench");
        let src = dir.join("cipher.bin");
        std::fs::write(&src, &cipher).unwrap();
        let crc = crc32fast::hash(&plain);
        println!("256 MiB encrypted store file");
        for threads in [1usize, 2, 4, 8] {
            let out = dir.join("plain.bin");
            let wf = File::options()
                .create(true)
                .truncate(true)
                .read(true)
                .write(true)
                .open(&out)
                .unwrap();
            let t = std::time::Instant::now();
            decrypt_pass(&src, &wf, &key, &iv, plain.len() as u64, Some(crc), threads).unwrap();
            let el = t.elapsed().as_secs_f64();
            println!(
                "  {threads} shard(s): {el:6.3}s  {:7.1} MB/s",
                (plain.len() as f64 / 1e6) / el
            );
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Finding A8. The finish decrypt replaces an encrypted store output
    /// with its plaintext, and that output is exactly what the
    /// crash-resume journal's placement records point into. Rewriting it
    /// IN PLACE meant a kill mid-pass left the file half plaintext and
    /// half ciphertext while the journal still vouched for it - the resume
    /// run then copied those poisoned bytes into the volume files and
    /// marked the message ids restored, so they were skipped instead of
    /// refetched and, without PAR2, the retry could never converge.
    ///
    /// The guarantee is about ORDERING, so that is what is asserted here:
    /// the publish barrier fires once per output, and at that moment the
    /// output on disk is still byte-exact ciphertext. Every earlier
    /// instant therefore looks identical to a killed process, and the
    /// publish itself is a rename - so no kill can ever observe a mix.
    #[test]
    fn decrypt_publishes_only_after_the_journal_barrier_clears() {
        let dir = tmpdir("enc-barrier");
        let plain = payload(200_003, 51);
        let f = fixtures::encrypt_file("hunter2", &plain, 5);
        let cipher = f.cipher.clone();
        let vol =
            fixtures::rar5_volume_enc(&[("movie.mkv", &f, 0..f.cipher.len(), false, false)], None);
        let ex = Extractor::new(&dir, 1, true);
        ex.set_password("hunter2");
        // This test guards the LEGACY ciphertext+finish-decrypt path
        // (still shipped behind NZBFAST_NO_INSTREAM_DECRYPT).
        ex.set_instream_decrypt(false);
        // The name the old code derived deterministically for its temp. An
        // archive is free to ship a member called this (finding A13), so
        // the pass must not go anywhere near it.
        let decoy = dir.join("movie.mkv.nzbdec.tmp");
        std::fs::write(&decoy, b"a legitimate archive member").unwrap();

        let calls: Arc<Mutex<Vec<Vec<String>>>> = Arc::new(Mutex::new(Vec::new()));
        let seen_at_barrier: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
        {
            let (calls, seen, out) = (calls.clone(), seen_at_barrier.clone(), dir.join("movie.mkv"));
            ex.set_decrypt_barrier(Arc::new(move |names: &[String]| {
                calls.lock().unwrap().push(names.to_vec());
                *seen.lock().unwrap() = std::fs::read(&out).unwrap();
                Ok(())
            }));
        }
        feed(&ex, 0, "v.rar", &vol, 7000, 3);
        let rep = ex.finish().unwrap();

        assert_eq!(rep.decrypted, vec!["movie.mkv".to_string()]);
        assert_eq!(
            *calls.lock().unwrap(),
            vec![vec!["movie.mkv".to_string()]],
            "the journal's claim must be retired for exactly the published output"
        );
        let at_barrier = seen_at_barrier.lock().unwrap().clone();
        assert_eq!(
            &at_barrier[..cipher.len()],
            &cipher[..],
            "the output was mutated before the journal stopped vouching for it"
        );
        assert_eq!(std::fs::read(dir.join("movie.mkv")).unwrap(), plain);
        assert_eq!(
            std::fs::read(&decoy).unwrap(),
            b"a legitimate archive member",
            "an archive member must never be mistaken for decrypt scratch"
        );
        assert!(
            leftover_scratch(&dir).is_empty(),
            "decrypt scratch left behind: {:?}",
            leftover_scratch(&dir)
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Finding A8, the other half: when the journal's claim CANNOT be
    /// retired, nothing may be published. The job fails, and the output is
    /// left byte-exact ciphertext - which is what makes a crash here
    /// recoverable, because the journal is still telling the truth and the
    /// resume run rebuilds the volumes from local bytes with no refetch.
    #[test]
    fn decrypt_publishes_nothing_when_the_barrier_refuses() {
        let dir = tmpdir("enc-barrier-fail");
        let plain = payload(200_003, 52);
        let f = fixtures::encrypt_file("hunter2", &plain, 5);
        let cipher = f.cipher.clone();
        let vol =
            fixtures::rar5_volume_enc(&[("movie.mkv", &f, 0..f.cipher.len(), false, false)], None);
        let ex = Extractor::new(&dir, 1, true);
        ex.set_password("hunter2");
        // This test guards the LEGACY ciphertext+finish-decrypt path
        // (still shipped behind NZBFAST_NO_INSTREAM_DECRYPT).
        ex.set_instream_decrypt(false);
        ex.set_decrypt_barrier(Arc::new(|_: &[String]| {
            Err(io::Error::other("journal is not writable"))
        }));
        feed(&ex, 0, "v.rar", &vol, 7000, 3);

        let err = match ex.finish() {
            Err(e) => e,
            Ok(_) => panic!("publish went ahead without the journal's permission"),
        };
        assert!(err.to_string().contains("journal is not writable"), "{err}");
        let on_disk = std::fs::read(dir.join("movie.mkv")).unwrap();
        assert_eq!(
            &on_disk[..cipher.len()],
            &cipher[..],
            "ciphertext must survive byte-exact so the journal stays true"
        );
        assert!(
            !on_disk.starts_with(&plain[..1024]),
            "plaintext was published without permission"
        );
        assert!(
            leftover_scratch(&dir).is_empty(),
            "decrypt scratch left behind: {:?}",
            leftover_scratch(&dir)
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Decrypt scratch from a killed run is swept, and a failed pass
    /// leaves none of its own - a stale temp must never reach the user's
    /// output directory or the keep-media-only sweep.
    #[test]
    fn stale_decrypt_scratch_is_swept() {
        let dir = tmpdir("enc-scratch");
        let stale = dir.join(format!("{DEC_TMP_PREFIX}999999.7.tmp"));
        std::fs::write(&stale, b"corpse of a killed run").unwrap();
        let plain = payload(70_001, 53);
        let f = fixtures::encrypt_file("pw", &plain, 9);
        let vol = fixtures::rar5_volume_enc(&[("a.bin", &f, 0..f.cipher.len(), false, false)], None);
        let ex = Extractor::new(&dir, 1, true);
        ex.set_password("pw");
        feed(&ex, 0, "v.rar", &vol, 7000, 4);
        ex.finish().unwrap();
        assert!(!stale.exists(), "stale decrypt scratch survived the pass");
        assert!(leftover_scratch(&dir).is_empty());
        assert_eq!(std::fs::read(dir.join("a.bin")).unwrap(), plain);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The aliasing hazard with the decoy arriving the way it actually
    /// does in the wild: as a genuine member of the same download,
    /// written by this very extraction rather than planted beforehand.
    /// The old deterministic `<output>.nzbdec.tmp` name truncated it and
    /// then renamed it away, so a real file silently became the decrypt
    /// scratch. Ported from the parallel isolated-staging fix, whose
    /// scratch-subdirectory approach this file solves with `create_new`.
    #[test]
    fn decrypt_temp_cannot_alias_an_extracted_member() {
        let dir = tmpdir("enc-temp-alias");
        let plain = payload(180_000, 73);
        let f = fixtures::encrypt_file("pw", &plain, 3);
        let enc =
            fixtures::rar5_volume_enc(&[("movie.mkv", &f, 0..f.cipher.len(), false, false)], None);
        // A second, ordinary volume whose member is named exactly like the
        // temp the old code would have derived for movie.mkv.
        let decoy = payload(9_000, 74);
        let bait = fixtures::rar5_volume(&[(
            "movie.mkv.nzbdec.tmp",
            decoy.len() as u64,
            &decoy,
            false,
            false,
        )]);
        let ex = Extractor::new(&dir, 2, true);
        ex.set_password("pw");
        feed(&ex, 0, "a.rar", &enc, 7000, 4);
        feed(&ex, 1, "b.rar", &bait, 3000, 5);
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(rep.decrypted, vec!["movie.mkv".to_string()]);
        assert_eq!(std::fs::read(dir.join("movie.mkv")).unwrap(), plain);
        assert_eq!(
            std::fs::read(dir.join("movie.mkv.nzbdec.tmp")).unwrap(),
            decoy,
            "the decrypt temp overwrote a legitimate member of the same name"
        );
        assert!(leftover_scratch(&dir).is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn leftover_scratch(dir: &Path) -> Vec<String> {
        std::fs::read_dir(dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.starts_with(DEC_TMP_PREFIX))
            .collect()
    }

    /// The real multi-volume shape: ONE CBC stream carved at arbitrary
    /// (non-16-aligned) offsets, same crypt record in every volume, fed
    /// interleaved and out of order.
    #[test]
    fn encrypted_split_volumes_decrypt() {
        let dir = tmpdir("enc-split");
        let plain = payload(500_007, 42);
        let f = fixtures::encrypt_file("s3cret", &plain, 11);
        let n = f.cipher.len();
        let (a, b) = (170_003, 340_006); // deliberately odd split points
        let vols = [
            fixtures::rar5_volume_enc(&[("film.mkv", &f, 0..a, false, true)], Some(0)),
            fixtures::rar5_volume_enc(&[("film.mkv", &f, a..b, true, true)], Some(1)),
            fixtures::rar5_volume_enc(&[("film.mkv", &f, b..n, true, false)], Some(2)),
        ];
        let ex = Extractor::new(&dir, 3, true);
        ex.set_password("s3cret");
        feed(&ex, 2, "x.part3.rar", &vols[2], 9000, 11);
        feed(&ex, 0, "x.part1.rar", &vols[0], 9000, 12);
        feed(&ex, 1, "x.part2.rar", &vols[1], 9000, 13);
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(rep.decrypted, vec!["film.mkv".to_string()]);
        assert_eq!(std::fs::read(dir.join("film.mkv")).unwrap(), plain);
        assert!(!dir.join("x.part1.rar").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Plaintext-once equivalence: the in-stream decrypt path and the
    /// legacy ciphertext+finish-decrypt path must produce byte-identical
    /// output for every arrival order and article size - including
    /// pathological articles smaller than two cipher blocks, where every
    /// span is nothing BUT seams.
    #[test]
    fn instream_decrypt_matches_legacy_across_orders_and_sizes() {
        let plain = payload(120_003, 77);
        let mut f = fixtures::encrypt_file("hunter2", &plain, 21);
        f.with_crc = true; // engage the composed-CRC verify too
        f.tweaked = false;
        let vol =
            fixtures::rar5_volume_enc(&[("movie.mkv", &f, 0..f.cipher.len(), false, false)], None);
        for art in [17usize, 33, 4096, 7000] {
            for seed in [1u64, 2, 3] {
                let mut outs: Vec<Vec<u8>> = Vec::new();
                for instream in [true, false] {
                    let dir = tmpdir(&format!("eqv-{art}-{seed}-{instream}"));
                    let ex = Extractor::new(&dir, 1, true);
                    ex.set_password("hunter2");
                    ex.set_instream_decrypt(instream);
                    feed(&ex, 0, "v.rar", &vol, art, seed);
                    let rep = ex.finish().unwrap();
                    assert!(rep.fallbacks.is_empty(), "art={art} seed={seed}: {:?}", rep.fallbacks);
                    assert_eq!(rep.decrypted, vec!["movie.mkv".to_string()]);
                    outs.push(std::fs::read(dir.join("movie.mkv")).unwrap());
                    assert!(!dir.join("v.rar").exists(), "no volume on disk either way");
                    std::fs::remove_dir_all(&dir).unwrap();
                }
                assert_eq!(outs[0], plain, "in-stream output wrong at art={art} seed={seed}");
                assert_eq!(outs[0], outs[1], "paths diverge at art={art} seed={seed}");
            }
        }
    }

    /// Split encrypted file, in-stream: one CBC stream across three
    /// volumes, volumes fed out of order, seams crossing volume
    /// boundaries.
    #[test]
    fn instream_split_volumes_decrypt() {
        let dir = tmpdir("instream-split");
        let plain = payload(500_007, 42);
        let f = fixtures::encrypt_file("s3cret", &plain, 11);
        let n = f.cipher.len();
        let (a, b) = (170_003, 340_006);
        let vols = [
            fixtures::rar5_volume_enc(&[("film.mkv", &f, 0..a, false, true)], Some(0)),
            fixtures::rar5_volume_enc(&[("film.mkv", &f, a..b, true, true)], Some(1)),
            fixtures::rar5_volume_enc(&[("film.mkv", &f, b..n, true, false)], Some(2)),
        ];
        let ex = Extractor::new(&dir, 3, true);
        ex.set_password("s3cret");
        ex.set_instream_decrypt(true);
        feed(&ex, 2, "x.part3.rar", &vols[2], 4099, 31);
        feed(&ex, 0, "x.part1.rar", &vols[0], 4099, 32);
        feed(&ex, 1, "x.part2.rar", &vols[1], 4099, 33);
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(rep.decrypted, vec!["film.mkv".to_string()]);
        assert_eq!(std::fs::read(dir.join("film.mkv")).unwrap(), plain);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The posted-bytes shim: after an in-stream decrypt, read_at over
    /// the whole volume view must reproduce the POSTED volume
    /// byte-exactly - headers from the stash, data areas re-encrypted
    /// from the plaintext on disk, seam/tail slivers from retained
    /// cipher. This is what PAR2 settle read-back, mapped repair and
    /// fallback all consume.
    #[test]
    fn instream_read_at_reproduces_posted_volume_bytes() {
        let dir = tmpdir("instream-shim");
        // Big enough to cross a checkpoint stride with the small chunk.
        let plain = payload(300_005, 55);
        let f = fixtures::encrypt_file("pw", &plain, 9);
        let vol =
            fixtures::rar5_volume_enc(&[("movie.mkv", &f, 0..f.cipher.len(), false, false)], None);
        let ex = Extractor::new(&dir, 1, true);
        ex.set_password("pw");
        ex.set_instream_decrypt(true);
        feed(&ex, 0, "v.rar", &vol, 7001, 5);
        // Whole-volume round trip.
        let mut got = vec![0u8; vol.len()];
        ex.read_at(0, 0, &mut got).unwrap();
        assert_eq!(got, vol, "shim must reproduce the posted volume");
        // Unaligned interior windows, crossing data-area edges.
        for (off, len) in [(1u64, 31usize), (999, 4097), (150_001, 50_003)] {
            let mut w = vec![0u8; len];
            ex.read_at(0, off, &mut w).unwrap();
            assert_eq!(w, vol[off as usize..off as usize + len], "window {off}+{len}");
        }
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("movie.mkv")).unwrap(), plain);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A file spanning several checkpoint strides: the shim must chain
    /// from the nearest checkpoint (not the file head), deep windows
    /// must reproduce posted bytes, and a repair landing past the first
    /// stride must refresh the checkpoints it crosses.
    #[test]
    fn instream_checkpoints_serve_deep_windows_and_repairs() {
        let dir = tmpdir("instream-ckpt");
        let plain = payload(3_500_003, 91);
        let mut f = fixtures::encrypt_file("hunter2", &plain, 66);
        f.with_crc = true;
        f.tweaked = false;
        let vol =
            fixtures::rar5_volume_enc(&[("movie.mkv", &f, 0..f.cipher.len(), false, false)], None);
        let mut damaged = vol.clone();
        for i in 2_500_000..2_500_048 {
            damaged[i] ^= 0xA7;
        }
        let ex = Extractor::new(&dir, 1, true);
        ex.set_password("hunter2");
        ex.set_instream_decrypt(true);
        feed(&ex, 0, "v.rar", &damaged, 65_536, 14);
        // Deep windows chain from checkpoints, not a multi-MB walk.
        for (off, len) in [(3_200_001u64, 8_192usize), (1_048_570, 64), (2_097_140, 40)] {
            let mut w = vec![0u8; len];
            ex.read_at(0, off, &mut w).unwrap();
            assert_eq!(w, damaged[off as usize..off as usize + len], "window {off}");
        }
        // Repair the damage (crosses nothing aligned on purpose).
        ex.patch_volume_span(0, 2_499_997, &vol[2_499_997..2_500_051]).unwrap();
        let mut got = vec![0u8; vol.len()];
        ex.read_at(0, 0, &mut got).unwrap();
        assert_eq!(got, vol, "healed volume view across strides");
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("movie.mkv")).unwrap(), plain);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Mapped repair on a plaintext-once file: damaged cipher decrypts
    /// to garbage plaintext locally, the patch rewrites the repaired
    /// blocks AND the CBC-adjacent following block, and the stored-CRC
    /// gate passes on the healed plaintext.
    #[test]
    fn instream_patch_heals_damaged_cipher_and_adjacency() {
        let dir = tmpdir("instream-patch");
        let plain = payload(200_003, 61);
        let mut f = fixtures::encrypt_file("hunter2", &plain, 33);
        f.with_crc = true;
        f.tweaked = false;
        let vol =
            fixtures::rar5_volume_enc(&[("movie.mkv", &f, 0..f.cipher.len(), false, false)], None);
        // Damage a mid-data range of the POSTED bytes before feeding -
        // the wire delivered corrupt cipher, exactly what PAR2 repairs.
        let mut damaged = vol.clone();
        for i in 45_000..45_040 {
            damaged[i] ^= 0x5A;
        }
        let ex = Extractor::new(&dir, 1, true);
        ex.set_password("hunter2");
        ex.set_instream_decrypt(true);
        feed(&ex, 0, "v.rar", &damaged, 7000, 8);
        // Repair the damaged span with the true posted bytes (unaligned
        // edges on purpose - the patch window logic must round out).
        ex.patch_volume_span(0, 44_997, &vol[44_997..45_043]).unwrap();
        // The healed volume view must be the pristine posted bytes...
        let mut got = vec![0u8; vol.len()];
        ex.read_at(0, 0, &mut got).unwrap();
        assert_eq!(got, vol, "healed volume view");
        // ...and the plaintext (incl. the adjacency block) must verify.
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("movie.mkv")).unwrap(), plain);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// An incomplete in-stream set falls back to materialized volumes,
    /// and every byte the fallback writes must be the POSTED byte (the
    /// shim rebuilding cipher from plaintext), never plaintext leaking
    /// into a volume file.
    #[test]
    fn instream_incomplete_set_materializes_posted_bytes() {
        let dir = tmpdir("instream-fallback");
        let plain = payload(200_003, 71);
        let f = fixtures::encrypt_file("hunter2", &plain, 44);
        let vol =
            fixtures::rar5_volume_enc(&[("movie.mkv", &f, 0..f.cipher.len(), false, false)], None);
        let ex = Extractor::new(&dir, 1, true);
        ex.set_password("hunter2");
        ex.set_instream_decrypt(true);
        // Feed everything except one mid-file article.
        let art = 7000usize;
        let skip = 91_000usize;
        let mut i = 0;
        while i < vol.len() {
            let e = (i + art).min(vol.len());
            if i != skip {
                ex.write(0, "v.rar", vol.len() as u64, i as u64, &vol[i..e]).unwrap();
            }
            i = e;
        }
        let rep = ex.finish().unwrap();
        assert!(!rep.fallbacks.is_empty(), "incomplete set must fall back");
        let disk = std::fs::read(dir.join("v.rar")).unwrap();
        // Every fed byte materialized must equal the posted byte.
        let mut i = 0;
        while i < vol.len().min(disk.len()) {
            let e = (i + art).min(vol.len()).min(disk.len());
            if i != skip {
                assert_eq!(
                    &disk[i..e],
                    &vol[i..e],
                    "materialized volume must hold posted bytes at {i}"
                );
            }
            i = e;
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Plaintext-once bookkeeping: spans that fed an in-stream-decrypted
    /// file are never journaled (a resume must refetch them - the disk
    /// holds plaintext, not the posted bytes a restore would copy into
    /// volume files), and /stream serves the output as a plain file.
    #[test]
    fn instream_spans_never_journal_and_stream_is_plain() {
        let dir = tmpdir("instream-journal");
        let plain = payload(150_001, 81);
        let f = fixtures::encrypt_file("hunter2", &plain, 55);
        let vol =
            fixtures::rar5_volume_enc(&[("movie.mkv", &f, 0..f.cipher.len(), false, false)], None);
        let ex = Extractor::new(&dir, 1, true);
        ex.set_password("hunter2");
        ex.set_instream_decrypt(true);
        let mut any_placed = false;
        let art = 7000usize;
        let mut i = 0;
        while i < vol.len() {
            let e = (i + art).min(vol.len());
            let p = ex.write(0, "v.rar", vol.len() as u64, i as u64, &vol[i..e]).unwrap();
            if let Persist::Placed(_) = p {
                any_placed = true;
            }
            i = e;
        }
        assert!(
            !any_placed,
            "no article of an in-stream-decrypted file may be journaled"
        );
        assert!(
            matches!(ex.open_stream("movie.mkv"), StreamOpen::Plain),
            "plaintext-once output streams as a plain file"
        );
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("movie.mkv")).unwrap(), plain);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Phase 2 of plaintext-once: a journaled run's D/E/K/T records let a
    /// resume RE-ENCRYPT the on-disk plaintext back into posted volume
    /// bytes. Simulates a kill (drop without finish), then restores and
    /// compares every restored span byte-for-byte against the posted
    /// volume - including the final article, whose last block needs the
    /// journaled tail padding.
    #[test]
    fn instream_journal_restores_posted_bytes_for_resume() {
        let dir = tmpdir("instream-resume");
        let plain = payload(2_300_005, 87); // > 2 checkpoint strides
        let f = fixtures::encrypt_file("hunter2", &plain, 77);
        let vol =
            fixtures::rar5_volume_enc(&[("movie.mkv", &f, 0..f.cipher.len(), false, false)], None);
        let art = 50_000usize;
        let n_arts = vol.len().div_ceil(art);

        // Run 1: journal exactly like main.rs does, "crash" before the
        // last two articles and before finish.
        let (journal, _) = crate::journal::Journal::open(&dir, b"nzb-x").unwrap();
        let mut d_ids: Vec<String> = Vec::new();
        {
            let ex = Extractor::new(&dir, 1, true);
            ex.set_password("hunter2");
            ex.set_instream_decrypt(true);
            // Mirror main.rs: D records park until their span's seam
            // bytes are physically on disk (usually one article later).
            let mut pending: Vec<(String, Vec<Frag>)> = Vec::new();
            for i in 0..n_arts - 2 {
                let s = i * art;
                let e = (s + art).min(vol.len());
                let id = format!("<a{i}@t>");
                let p = ex
                    .write(0, "v.rar", vol.len() as u64, s as u64, &vol[s..e])
                    .unwrap();
                match p {
                    Persist::PlacedCrypto(frags) => pending.push((id, frags)),
                    Persist::Placed(_) => panic!("crypto span must journal as D, not R"),
                    Persist::No => {}
                }
                pending.retain(|(id, frags)| {
                    if ex.crypto_span_on_disk(frags) {
                        let ev = ex.drain_crypto_events();
                        journal.record_crypto_events(&ev);
                        journal.record_placed_crypto(
                            0,
                            id,
                            ex.slot_file_info(0),
                            "v.rar",
                            vol.len() as u64,
                            frags,
                            &ex.crypto_frag_mask(frags),
                        );
                        d_ids.push(id.clone());
                        false
                    } else {
                        true
                    }
                });
            }
            // Killed: dropped without finish. The frontier article's
            // seam never settled, so it must still be parked.
            assert!(!pending.is_empty(), "the frontier span must be unjournaled");
        }
        drop(journal);
        // The plaintext output must exist from run 1.
        assert!(dir.join("movie.mkv").exists());
        assert!(!d_ids.is_empty(), "run 1 recorded D articles");

        // Resume: parse + restore with the password.
        let (_j2, resume) = crate::journal::Journal::open(&dir, b"nzb-x").unwrap();
        assert!(resume.crypto_files.contains_key("movie.mkv"), "E record parsed");
        let restored = crate::journal::restore(&dir, &resume, Some("hunter2"));
        // Every D article restores (its plaintext fully on disk - the
        // skipped articles' seams only affect themselves).
        for id in &d_ids {
            assert!(restored.ids.contains(id), "{id} must restore");
        }
        // And the rebuilt volume bytes are the POSTED bytes.
        let rebuilt = std::fs::read(dir.join("v.rar")).unwrap();
        for seed in &restored.seeds {
            for &(off, len) in &seed.spans {
                assert_eq!(
                    &rebuilt[off as usize..(off + len) as usize],
                    &vol[off as usize..(off + len) as usize],
                    "restored span {off}+{len} must be posted bytes"
                );
            }
        }
        // No password: nothing restores, articles refetch.
        let none = crate::journal::restore(&dir, &resume, None);
        assert!(none.ids.is_empty(), "no password must mean no restores");
        // Wrong password: KDF succeeds but produces the wrong keystream;
        // the checkpoint cross-verify rejects the walk, so nothing is
        // restored (rather than poisoned volumes).
        let wrong = crate::journal::restore(&dir, &resume, Some("wrong"));
        assert!(wrong.ids.is_empty(), "wrong password must not restore: {:?}", wrong.ids.len());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A D record without its E facts (torn journal tail, or a file
    /// whose params line was lost) must refetch, never guess.
    #[test]
    fn journal_d_without_e_refetches() {
        let dir = tmpdir("d-without-e");
        std::fs::write(dir.join("movie.mkv"), payload(64_000, 3)).unwrap();
        let text = "nzbfast-journal v1 d41d8cd98f00b204e9800998ecf8427e\n\
                    S 0 100000 v.rar\n\
                    F 0 movie.mkv\n\
                    D 0 0:0:5000:32768 <a1@t>\n";
        std::fs::write(dir.join(".nzbfast.journal"), text).unwrap();
        // Reparse through the real reader (fingerprint of b"" matches).
        let (_j, resume) = crate::journal::Journal::open(&dir, b"").unwrap();
        let restored = crate::journal::restore(&dir, &resume, Some("pw"));
        assert!(restored.ids.is_empty(), "D without E must refetch");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// `-hp` shape: encrypted headers AND encrypted data.
    #[test]
    fn encrypted_headers_volume_decrypts() {
        let dir = tmpdir("enc-hdrs");
        let plain = payload(150_001, 43);
        let f = fixtures::encrypt_file("pw", &plain, 21);
        let vol = fixtures::rar5_volume_enc_headers(
            &[("obf.bin", &f, 0..f.cipher.len(), false, false)],
            None,
            "pw",
            22,
        );
        let ex = Extractor::new(&dir, 1, true);
        ex.set_password("pw");
        feed(&ex, 0, "0abc123.rar", &vol, 6000, 9);
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(rep.decrypted, vec!["obf.bin".to_string()]);
        assert_eq!(std::fs::read(dir.join("obf.bin")).unwrap(), plain);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Wrong password: the check value rejects it BEFORE any garbage is
    /// written; the volume materializes byte-identical (unrar / retry
    /// with the right password still possible).
    #[test]
    fn encrypted_wrong_password_materializes_volume() {
        let dir = tmpdir("enc-wrongpw");
        let plain = payload(90_000, 44);
        let f = fixtures::encrypt_file("right", &plain, 31);
        let vol =
            fixtures::rar5_volume_enc(&[("a.bin", &f, 0..f.cipher.len(), false, false)], None);
        let ex = Extractor::new(&dir, 1, true);
        ex.set_password("wrong");
        feed(&ex, 0, "v.rar", &vol, 7000, 5);
        let rep = ex.finish().unwrap();
        assert!(
            rep.fallbacks.iter().any(|(_, w)| w.contains("password")),
            "{:?}",
            rep.fallbacks
        );
        assert!(rep.decrypted.is_empty());
        assert_eq!(std::fs::read(dir.join("v.rar")).unwrap(), vol, "byte-exact volume");
        assert!(!dir.join("a.bin").exists(), "no half-written decoy output");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// No password at all: today's behavior - volumes on disk, reason
    /// names encryption.
    #[test]
    fn encrypted_without_password_materializes_volume() {
        let dir = tmpdir("enc-nopw");
        let plain = payload(60_000, 45);
        let f = fixtures::encrypt_file("x", &plain, 33);
        let vol =
            fixtures::rar5_volume_enc(&[("a.bin", &f, 0..f.cipher.len(), false, false)], None);
        let ex = Extractor::new(&dir, 1, true);
        feed(&ex, 0, "v.rar", &vol, 7000, 6);
        let rep = ex.finish().unwrap();
        assert!(
            rep.fallbacks.iter().any(|(_, w)| w.contains("encrypted")),
            "{:?}",
            rep.fallbacks
        );
        assert_eq!(std::fs::read(dir.join("v.rar")).unwrap(), vol);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The committed REAL `rar 7.23` fixtures, driven through the full
    /// extractor: single encrypted volume, encrypted headers, and the
    /// 3-volume split - each must produce the exact payload with no
    /// volume files left behind.
    #[test]
    fn real_rar_fixtures_extract_and_decrypt() {
        let secret = include_bytes!("../testdata/rar5/secret.bin").to_vec();
        let cases: Vec<(&str, Vec<(&str, &[u8])>)> = vec![
            ("store", vec![("enc-store.rar", include_bytes!("../testdata/rar5/enc-store.rar"))]),
            ("hdrs", vec![("enc-hdrs.rar", include_bytes!("../testdata/rar5/enc-hdrs.rar"))]),
            (
                "vols",
                vec![
                    ("enc-vols.part1.rar", include_bytes!("../testdata/rar5/enc-vols.part1.rar")),
                    ("enc-vols.part2.rar", include_bytes!("../testdata/rar5/enc-vols.part2.rar")),
                    ("enc-vols.part3.rar", include_bytes!("../testdata/rar5/enc-vols.part3.rar")),
                ],
            ),
        ];
        for (tag, vols) in cases {
            let dir = tmpdir(&format!("enc-real-{tag}"));
            let ex = Extractor::new(&dir, vols.len(), true);
            ex.set_password("testpw123");
            for (si, (name, bytes)) in vols.iter().enumerate() {
                feed(&ex, si, name, bytes, 1400, 60 + si as u64);
            }
            let rep = ex.finish().unwrap();
            assert!(rep.fallbacks.is_empty(), "{tag}: {:?}", rep.fallbacks);
            assert_eq!(rep.decrypted, vec!["secret.bin".to_string()], "{tag}");
            assert_eq!(std::fs::read(dir.join("secret.bin")).unwrap(), secret, "{tag}");
            for (name, _) in &vols {
                assert!(!dir.join(name).exists(), "{tag}: volume {name} materialized");
            }
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    /// A check-less encrypted archive can't have its password verified
    /// natively (the stored CRC is keyed), so it must fall back to unrar
    /// rather than risk a silent wrong-password decrypt.
    #[test]
    fn encrypted_without_check_falls_back() {
        let dir = tmpdir("enc-nocheck");
        let plain = payload(80_000, 61);
        let mut f = fixtures::encrypt_file("pw", &plain, 7);
        f.no_check = true;
        let vol =
            fixtures::rar5_volume_enc(&[("a.bin", &f, 0..f.cipher.len(), false, false)], None);
        let ex = Extractor::new(&dir, 1, true);
        ex.set_password("pw"); // correct password, but unverifiable
        feed(&ex, 0, "v.rar", &vol, 7000, 5);
        let rep = ex.finish().unwrap();
        assert!(rep.decrypted.is_empty());
        assert!(
            rep.fallbacks.iter().any(|(_, w)| w.contains("encrypted")),
            "{:?}",
            rep.fallbacks
        );
        // Byte-exact volume kept for unrar / a corrected retry.
        assert_eq!(std::fs::read(dir.join("v.rar")).unwrap(), vol);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// On-the-fly stream decryption: while an encrypted file is still
    /// ciphertext on disk (mid-download), `open_stream` hands back a
    /// `StreamCrypt` whose `decrypt_range` yields the exact plaintext for
    /// arbitrary offsets - the basis of streaming encrypted releases
    /// before the finish decrypt runs.
    #[test]
    fn stream_crypt_decrypts_arbitrary_ranges_before_finish() {
        let dir = tmpdir("enc-stream");
        let plain = payload(300_003, 71);
        let f = fixtures::encrypt_file("pw", &plain, 9);
        let vol =
            fixtures::rar5_volume_enc(&[("movie.mkv", &f, 0..f.cipher.len(), false, false)], None);
        let ex = Extractor::new(&dir, 1, true);
        ex.set_password("pw");
        // This test guards the LEGACY ciphertext+finish-decrypt path
        // (still shipped behind NZBFAST_NO_INSTREAM_DECRYPT).
        ex.set_instream_decrypt(false);
        // Feed everything but DON'T finish() - the file is ciphertext.
        feed(&ex, 0, "v.rar", &vol, 7000, 4);
        let StreamOpen::Encrypted(file, crypt) = ex.open_stream("movie.mkv") else {
            panic!("expected an encrypted stream handle");
        };
        assert_eq!(crypt.plain_len, plain.len() as u64);
        // Random-ish ranges, including offset 0, a mid-block start, and
        // the final partial block.
        for &(pos, len) in &[
            (0u64, 100u64),
            (16, 4096),
            (12345, 50000),
            (plain.len() as u64 - 7, 7),
            (100_000, 200_003),
        ] {
            let (lo, clen) = crypt.covered_bounds(pos, len);
            assert!(lo + clen <= crypt.cipher_len);
            let mut out = vec![0u8; len as usize];
            crypt.decrypt_range(&file, pos, &mut out).unwrap();
            assert_eq!(
                out,
                &plain[pos as usize..(pos + len) as usize],
                "range {pos}+{len}"
            );
        }
        // Dropping the handle releases the reader lease; finish then
        // decrypts in place (no live reader) to the same plaintext.
        drop(crypt);
        drop(file);
        let rep = ex.finish().unwrap();
        assert_eq!(rep.decrypted, vec!["movie.mkv".to_string()]);
        assert_eq!(std::fs::read(dir.join("movie.mkv")).unwrap(), plain);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// With a live stream reader attached, finish() must NOT mutate the
    /// file in place: it decrypts to a temp file and renames, so the
    /// reader's captured fd keeps decrypting the intact ciphertext inode
    /// even after the on-disk file becomes plaintext.
    #[test]
    fn finish_temp_renames_while_a_reader_streams() {
        let dir = tmpdir("enc-stream-finish");
        let plain = payload(260_000, 72);
        let f = fixtures::encrypt_file("pw", &plain, 3);
        let vol =
            fixtures::rar5_volume_enc(&[("movie.mkv", &f, 0..f.cipher.len(), false, false)], None);
        let ex = Extractor::new(&dir, 1, true);
        ex.set_password("pw");
        // This test guards the LEGACY ciphertext+finish-decrypt path
        // (still shipped behind NZBFAST_NO_INSTREAM_DECRYPT).
        ex.set_instream_decrypt(false);
        feed(&ex, 0, "v.rar", &vol, 7000, 4);
        let StreamOpen::Encrypted(file, crypt) = ex.open_stream("movie.mkv") else {
            panic!("expected an encrypted stream handle");
        };
        // finish() runs WHILE the reader holds its handle → temp+rename.
        let rep = ex.finish().unwrap();
        assert_eq!(rep.decrypted, vec!["movie.mkv".to_string()]);
        // On-disk file is now plaintext…
        assert_eq!(std::fs::read(dir.join("movie.mkv")).unwrap(), plain);
        // …yet the live reader's fd still reads the ciphertext inode and
        // decrypts correctly (rename kept it alive).
        let mut out = vec![0u8; 40_000];
        crypt.decrypt_range(&file, 90_000, &mut out).unwrap();
        assert_eq!(out, &plain[90_000..130_000]);
        // A NEW open now sees plaintext → raw reads (Plain).
        assert!(matches!(ex.open_stream("movie.mkv"), StreamOpen::Plain));
        drop(crypt);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    // -- nested one-pass: store-in-store via the recursive child --

    fn dir_files(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        v.sort();
        v
    }

    /// Minimal RAR5 volume holding ONE compressed entry - enough for the
    /// child's sniff to classify RAR and its parser to hit the NotStore
    /// blocker. (The shared fixtures only write store mode.)
    fn rar5_compressed_volume(name: &str, data: &[u8]) -> Vec<u8> {
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
        fn block(btype: u64, hflags: u64, body: &[u8], data: &[u8], out: &mut Vec<u8>) {
            let mut hdr = Vec::new();
            vint(btype, &mut hdr);
            vint(hflags, &mut hdr);
            if hflags & 0x02 != 0 {
                vint(data.len() as u64, &mut hdr);
            }
            hdr.extend_from_slice(body);
            let mut sized = Vec::new();
            vint(hdr.len() as u64, &mut sized);
            let mut crc = crc32fast::Hasher::new();
            crc.update(&sized);
            crc.update(&hdr);
            out.extend_from_slice(&crc.finalize().to_le_bytes());
            out.extend_from_slice(&sized);
            out.extend_from_slice(&hdr);
            out.extend_from_slice(data);
        }
        let mut out = Vec::new();
        out.extend_from_slice(b"Rar!\x1a\x07\x01\x00");
        let mut main_body = Vec::new();
        vint(0, &mut main_body);
        block(1, 0, &main_body, &[], &mut out);
        let mut body = Vec::new();
        vint(0, &mut body); // file flags
        vint(data.len() as u64, &mut body); // unpacked size
        vint(0, &mut body); // attributes
        vint(0x80, &mut body); // compression info: method 1 = not store
        vint(0, &mut body); // host os
        vint(name.len() as u64, &mut body);
        body.extend_from_slice(name.as_bytes());
        block(2, 0x02, &body, data, &mut out);
        let mut end_body = Vec::new();
        vint(0, &mut end_body);
        block(5, 0, &end_body, &[], &mut out);
        out
    }

    /// Outer store volumes wrapping a store archive wrapping the final
    /// files: both layers map in one pass - the final files land
    /// byte-exact and NEITHER the outer volumes NOR the intermediate
    /// archive ever exist on disk. Driven across three feed orders
    /// (mirroring `multi_file_store_set_survives_all_feed_orders`).
    #[test]
    fn two_level_store_set_extracts_one_pass() {
        let a = payload(300_000, 81);
        let b = payload(150_000, 82);
        let inner_arch = fixtures::rar5_volume(&[
            ("A.mkv", 300_000, &a, false, false),
            ("B.mkv", 150_000, &b, false, false),
        ]);
        let n = inner_arch.len();
        let (c1, c2) = (n / 3, 2 * n / 3);
        let vols: Vec<Vec<u8>> = vec![
            fixtures::rar5_volume_n(
                &[("inner.rar", n as u64, &inner_arch[..c1], false, true)],
                0,
            ),
            fixtures::rar5_volume_n(
                &[("inner.rar", n as u64, &inner_arch[c1..c2], true, true)],
                1,
            ),
            fixtures::rar5_volume_n(
                &[("inner.rar", n as u64, &inner_arch[c2..], true, false)],
                2,
            ),
        ];
        for (t, order) in [[0usize, 1, 2], [2, 1, 0], [1, 2, 0]].iter().enumerate() {
            let dir = tmpdir(&format!("nested2l{t}"));
            let ex = Extractor::new(&dir, 3, true);
            for &vi in order {
                let name = format!("obf{:02x}.bin", (vi as u8) ^ 0x3c);
                feed(&ex, vi, &name, &vols[vi], 7000, 70 + vi as u64);
            }
            let rep = ex.finish().unwrap();
            assert!(rep.fallbacks.is_empty(), "order {order:?}: {:?}", rep.fallbacks);
            assert_eq!(
                rep.extracted,
                vec![("A.mkv".to_string(), 300_000), ("B.mkv".to_string(), 150_000)],
                "order {order:?}"
            );
            assert_eq!(std::fs::read(dir.join("A.mkv")).unwrap(), a, "order {order:?}");
            assert_eq!(std::fs::read(dir.join("B.mkv")).unwrap(), b, "order {order:?}");
            // One pass: no outer volume, no intermediate archive.
            assert_eq!(
                dir_files(&dir),
                vec!["A.mkv".to_string(), "B.mkv".to_string()],
                "order {order:?}"
            );
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    /// An INNER volume boundary spanning two OUTER volumes: the child's
    /// base for the final file's continuation piece resolves through the
    /// composed cum-chain, with the level-1 volume's bytes arriving via
    /// two different parent slots.
    #[test]
    fn nested_split_chain() {
        let f = payload(400_000, 83);
        let iv1 =
            fixtures::rar5_volume_n(&[("F.mkv", 400_000, &f[..200_000], false, true)], 0);
        let iv2 =
            fixtures::rar5_volume_n(&[("F.mkv", 400_000, &f[200_000..], true, false)], 1);
        let cut = iv2.len() / 2;
        let vols: Vec<Vec<u8>> = vec![
            fixtures::rar5_volume_n(
                &[
                    ("inner.part1.rar", iv1.len() as u64, &iv1, false, false),
                    ("inner.part2.rar", iv2.len() as u64, &iv2[..cut], false, true),
                ],
                0,
            ),
            fixtures::rar5_volume_n(
                &[("inner.part2.rar", iv2.len() as u64, &iv2[cut..], true, false)],
                1,
            ),
        ];
        for (t, order) in [[0usize, 1], [1, 0]].iter().enumerate() {
            let dir = tmpdir(&format!("nestedsplit{t}"));
            let ex = Extractor::new(&dir, 2, true);
            for &vi in order {
                feed(&ex, vi, &format!("zz{vi}.bin"), &vols[vi], 8000, 90 + vi as u64);
            }
            let rep = ex.finish().unwrap();
            assert!(rep.fallbacks.is_empty(), "order {order:?}: {:?}", rep.fallbacks);
            assert_eq!(
                rep.extracted,
                vec![("F.mkv".to_string(), 400_000)],
                "order {order:?}"
            );
            assert_eq!(std::fs::read(dir.join("F.mkv")).unwrap(), f, "order {order:?}");
            assert_eq!(dir_files(&dir), vec!["F.mkv".to_string()], "order {order:?}");
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    #[test]
    fn crc_runs_compose_out_of_order_with_duplicates() {
        let data = payload(50_000, 77);
        let cuts = [0usize, 9_001, 17_000, 17_003, 31_777, 50_000];
        let mut r = CrcRuns::default();
        // Feed the chunks in a scrambled order; completion only at the end.
        for &i in &[3usize, 0, 4, 2] {
            r.add(cuts[i] as u64, &data[cuts[i]..cuts[i + 1]]);
            assert_eq!(r.whole(50_000), None);
        }
        // A duplicate overlapping span (hold re-feed / repair rewrite of a
        // block whose other articles already landed) must not skew the
        // composition: [17_001, 40_000) is already fully covered.
        r.add(17_001, &data[17_001..40_000]);
        assert_eq!(r.whole(50_000), None);
        // A span straddling covered and fresh ranges clips to the gap.
        r.add(5_000, &data[5_000..20_000]);
        assert_eq!(r.whole(50_000), Some(crc32fast::hash(&data)));
        assert_eq!(r.whole(49_999), None, "wrong length must not verify");
    }

    /// Randomized differential against a byte-coverage oracle, for the
    /// local `coalesce_at` merge that replaced the whole-map rebuild.
    /// Rebuilding could not get the STRUCTURE wrong (it re-derived every
    /// run each time); a neighbour-only merge can, so the invariants that
    /// used to hold by construction are asserted here instead: runs stay
    /// disjoint and non-touching, their spans equal the covered byte set,
    /// and a fully covered piece composes to the same CRC as hashing the
    /// buffer whole. Spans are fed in scrambled order with duplicates and
    /// partial overlaps, which is what out-of-order article arrival and
    /// hold re-feeds actually produce.
    #[test]
    fn crc_runs_match_a_byte_oracle_under_random_feeds() {
        const LEN: usize = 40_000;
        let data = payload(LEN, 91);
        // xorshift64*, so the schedule is varied but reproducible. A
        // periodic payload would let unrelated ranges hash alike and hide
        // a mis-composition, hence payload()'s non-repeating bytes.
        let mut rng = 0x2545_F491_4F6C_DD1Du64;
        let mut next = || {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            rng
        };
        for trial in 0..200 {
            let mut runs = CrcRuns::default();
            let mut covered = vec![false; LEN];
            // Enough spans that full coverage is reached most trials, and
            // heavy overlap when it is not.
            for _ in 0..24 {
                let a = (next() as usize) % LEN;
                let b = (next() as usize) % LEN;
                let (s, e) = (a.min(b), a.max(b));
                if s == e {
                    continue;
                }
                runs.add(s as u64, &data[s..e]);
                covered[s..e].iter_mut().for_each(|c| *c = true);

                // The run set is exactly the covered bytes, disjoint and
                // never touching (a touching pair means a missed merge).
                let mut prev_end: Option<u64> = None;
                let mut from_runs = vec![false; LEN];
                for (&rs, &(rl, _)) in &runs.runs {
                    assert!(rl > 0, "trial {trial}: empty run at {rs}");
                    if let Some(pe) = prev_end {
                        assert!(rs > pe, "trial {trial}: run at {rs} touches or overlaps {pe}");
                    }
                    prev_end = Some(rs + rl);
                    from_runs[rs as usize..(rs + rl) as usize]
                        .iter_mut()
                        .for_each(|c| *c = true);
                }
                assert_eq!(from_runs, covered, "trial {trial}: run coverage diverged");

                // Composition is exact exactly when everything is covered.
                match covered.iter().all(|&c| c) {
                    true => assert_eq!(
                        runs.whole(LEN as u64),
                        Some(crc32fast::hash(&data)),
                        "trial {trial}: full coverage composed to the wrong CRC"
                    ),
                    false => assert_eq!(
                        runs.whole(LEN as u64),
                        None,
                        "trial {trial}: an incomplete piece claimed a CRC"
                    ),
                }
            }
        }
    }

    /// Reusing the verified article CRC must compose to exactly what
    /// hashing the routed bytes composes: a clean nested store set still
    /// one-passes with no demotion, in every feed order.
    #[test]
    fn a_reused_article_crc_extracts_the_same_as_hashing() {
        let f = payload(400_000, 86);
        let whole = crc32fast::hash(&f);
        let iv = [
            fixtures::rar5_volume_n_crc(
                &[("F.mkv", 400_000, &f[..150_000], false, true,
                   Some(crc32fast::hash(&f[..150_000])))],
                0,
            ),
            fixtures::rar5_volume_n_crc(
                &[("F.mkv", 400_000, &f[150_000..300_000], true, true,
                   Some(crc32fast::hash(&f[150_000..300_000])))],
                1,
            ),
            fixtures::rar5_volume_n_crc(
                &[("F.mkv", 400_000, &f[300_000..], true, false, Some(whole))],
                2,
            ),
        ];
        let outer = fixtures::rar5_volume(&[
            ("i.part1.rar", iv[0].len() as u64, &iv[0], false, false),
            ("i.part2.rar", iv[1].len() as u64, &iv[1], false, false),
            ("i.part3.rar", iv[2].len() as u64, &iv[2], false, false),
        ]);
        for seed in [11u64, 12, 13] {
            let dir = tmpdir(&format!("reusecrc{seed}"));
            let ex = Extractor::new(&dir, 1, true);
            feed_verified(&ex, 0, "o.rar", &outer, 7000, seed, 0);
            let rep = ex.finish().unwrap();
            assert!(rep.fallbacks.is_empty(), "seed {seed}: {:?}", rep.fallbacks);
            assert_eq!(std::fs::read(dir.join("F.mkv")).unwrap(), f, "seed {seed}");
            assert_eq!(dir_files(&dir), vec!["F.mkv".to_string()], "seed {seed}");
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    /// The reused value must actually REACH the composition, and be the
    /// thing the finish gate judges. A single-level store volume whose
    /// entry carries a real header CRC is the case where the composed
    /// value is actually compared: hand over article CRCs that do not
    /// describe the bytes and the gate has to demote. The payload itself
    /// is intact, so nothing but the passed-in CRC can cause that - and
    /// if the run came out clean, the caller's CRC was being ignored and
    /// the fast path would be vouching for nothing.
    #[test]
    fn a_wrong_article_crc_is_not_taken_on_trust() {
        let f = payload(300_000, 88);
        let vol = fixtures::rar5_volume_n_crc(
            &[("F.mkv", 300_000, &f, false, false, Some(crc32fast::hash(&f)))],
            0,
        );

        // Truthful CRCs: extracts, no demotion.
        let dir = tmpdir("reusecrcok1");
        let ex = Extractor::new(&dir, 1, true);
        feed_verified(&ex, 0, "v.rar", &vol, 7000, 11, 0);
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "clean set demoted: {:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("F.mkv")).unwrap(), f);
        std::fs::remove_dir_all(&dir).unwrap();

        // Same bytes, CRCs that describe nothing: must NOT pass the gate.
        let dir = tmpdir("reusecrcbad");
        let ex = Extractor::new(&dir, 1, true);
        feed_verified(&ex, 0, "v.rar", &vol, 7000, 11, 0x5AA5_5AA5);
        let rep = ex.finish().unwrap();
        assert!(
            !rep.fallbacks.is_empty(),
            "a CRC that describes nothing was accepted as proof the payload is good"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Store inner volumes carrying real header CRCs (last piece = whole
    /// file, earlier pieces = their own bytes, like real archivers write):
    /// intact data one-pass extracts with NO demotion in any feed order -
    /// the in-stream CRC gate must never false-positive on clean sets.
    #[test]
    fn nested_store_with_crcs_extracts_clean() {
        let f = payload(400_000, 86);
        let whole = crc32fast::hash(&f);
        let iv = [
            fixtures::rar5_volume_n_crc(
                &[("F.mkv", 400_000, &f[..150_000], false, true,
                   Some(crc32fast::hash(&f[..150_000])))],
                0,
            ),
            fixtures::rar5_volume_n_crc(
                &[("F.mkv", 400_000, &f[150_000..300_000], true, true,
                   Some(crc32fast::hash(&f[150_000..300_000])))],
                1,
            ),
            fixtures::rar5_volume_n_crc(
                &[("F.mkv", 400_000, &f[300_000..], true, false, Some(whole))],
                2,
            ),
        ];
        let outer = fixtures::rar5_volume(&[
            ("i.part1.rar", iv[0].len() as u64, &iv[0], false, false),
            ("i.part2.rar", iv[1].len() as u64, &iv[1], false, false),
            ("i.part3.rar", iv[2].len() as u64, &iv[2], false, false),
        ]);
        for seed in [11u64, 12, 13] {
            let dir = tmpdir(&format!("nestcrcok{seed}"));
            let ex = Extractor::new(&dir, 1, true);
            feed(&ex, 0, "o.rar", &outer, 7000, seed);
            let rep = ex.finish().unwrap();
            assert!(rep.fallbacks.is_empty(), "seed {seed}: {:?}", rep.fallbacks);
            assert_eq!(std::fs::read(dir.join("F.mkv")).unwrap(), f, "seed {seed}");
            assert_eq!(dir_files(&dir), vec!["F.mkv".to_string()], "seed {seed}");
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    /// The residual gauntlet gap: a store inner set whose DATA was
    /// damaged before packing (headers intact, header CRCs computed over
    /// the original bytes). Mapping succeeds, so without the CRC gate the
    /// corrupt payload would ship silently with rc=0. The gate must
    /// demote the nested level to materialized volumes - byte-exact as
    /// packed, damage included, where a par2 set can reach them - and
    /// delete the corrupt extracted output.
    #[test]
    fn nested_store_data_damage_demotes_on_crc() {
        let f = payload(400_000, 87);
        let whole = crc32fast::hash(&f);
        let mut iv = vec![
            fixtures::rar5_volume_n_crc(
                &[("F.mkv", 400_000, &f[..150_000], false, true,
                   Some(crc32fast::hash(&f[..150_000])))],
                0,
            ),
            fixtures::rar5_volume_n_crc(
                &[("F.mkv", 400_000, &f[150_000..300_000], true, true,
                   Some(crc32fast::hash(&f[150_000..300_000])))],
                1,
            ),
            fixtures::rar5_volume_n_crc(
                &[("F.mkv", 400_000, &f[300_000..], true, false, Some(whole))],
                2,
            ),
        ];
        // Poster damage: flip bytes in the middle of i.part2.rar - deep
        // inside its 150 KB data area, nowhere near the headers.
        let mid = iv[1].len() / 2;
        for b in &mut iv[1][mid..mid + 64] {
            *b ^= 0xA5;
        }
        let outer = fixtures::rar5_volume(&[
            ("i.part1.rar", iv[0].len() as u64, &iv[0], false, false),
            ("i.part2.rar", iv[1].len() as u64, &iv[1], false, false),
            ("i.part3.rar", iv[2].len() as u64, &iv[2], false, false),
        ]);
        let dir = tmpdir("nestcrcbad");
        let ex = Extractor::new(&dir, 1, true);
        feed(&ex, 0, "o.rar", &outer, 7000, 21);
        let rep = ex.finish().unwrap();
        let nested: Vec<_> = rep
            .fallbacks
            .iter()
            .filter(|(_, w)| w.starts_with("nested fallback:"))
            .collect();
        assert_eq!(nested.len(), 1, "{:?}", rep.fallbacks);
        assert!(
            nested[0].1.contains("failed its stored CRC"),
            "{:?}",
            rep.fallbacks
        );
        for (_, w) in &rep.fallbacks {
            assert!(
                !w.contains("compressed")
                    && !w.contains("encrypted")
                    && !w.contains("password")
                    && !w.contains("held-bytes cap")
                    && !w.contains("incomplete mapping"),
                "nested reason leaks a volume-remediation trigger: {w}"
            );
        }
        // The corrupt payload must not masquerade as output; the volumes
        // materialize byte-exact AS PACKED (damage included) so a
        // recovery set can verify and repair them.
        assert!(!dir.join("F.mkv").exists(), "corrupt output survived");
        for (i, v) in iv.iter().enumerate() {
            let p = dir.join(format!("i.part{}.rar", i + 1));
            assert_eq!(&std::fs::read(&p).unwrap(), v, "volume {} not byte-exact", i + 1);
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A nested RAR4 store file now verifies IN-STREAM (finding 9): the v4
    /// parser retains the header CRC, so clean inner data extracts on the
    /// fast path (no demote to a materialized level-1 archive), and
    /// damaged-before-packing data is caught by the composed CRC and
    /// demoted honestly instead of shipping with rc=0.
    #[test]
    fn nested_rar4_store_verifies_in_stream() {
        // Clean inner RAR4: composed CRC matches, one-pass extract, no demote.
        let dir = tmpdir("nest-rar4-gate");
        let data = payload(60_000, 71);
        let v4 = fixtures::rar4_volume(&[("old.avi", 60_000, &data, false, false)]);
        let outer = fixtures::rar5_volume(&[("inner.rar", v4.len() as u64, &v4, false, false)]);
        let ex = Extractor::new(&dir, 1, true);
        feed(&ex, 0, "v.rar", &outer, 5000, 17);
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("old.avi")).unwrap(), data);
        assert!(!dir.join("inner.rar").exists(), "clean inner RAR4 should not materialize");
        std::fs::remove_dir_all(&dir).unwrap();

        // Damaged inner RAR4: header CRC over pristine bytes, data area
        // flipped - the gate must demote, never ship the corrupt payload.
        let dir = tmpdir("nest-rar4-gate-bad");
        let mut v4b = fixtures::rar4_volume(&[("old.avi", 60_000, &data, false, false)]);
        let off = {
            let mut m = crate::rar::VolumeMapper::new(v4b.len() as u64);
            m.feed(0, &v4b);
            m.entries[0].data_off as usize
        };
        for b in &mut v4b[off + 30_000..off + 30_064] {
            *b ^= 0x5A;
        }
        let outer = fixtures::rar5_volume(&[("inner.rar", v4b.len() as u64, &v4b, false, false)]);
        let ex = Extractor::new(&dir, 1, true);
        feed(&ex, 0, "v.rar", &outer, 5000, 29);
        let rep = ex.finish().unwrap();
        assert!(
            rep.fallbacks.iter().any(|(_, w)| w.contains("failed its stored CRC")),
            "{:?}",
            rep.fallbacks
        );
        assert!(!dir.join("old.avi").exists(), "corrupt inner RAR4 payload shipped");
        assert_eq!(std::fs::read(dir.join("inner.rar")).unwrap(), v4b);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The level-0 half of the CRC gate (verify_output_crc, default on):
    /// the FINAL extracted store payload - the one the outer PAR2 only
    /// vouches for as-posted - demotes to a materialized volume when its
    /// composed CRC mismatches the header value. The damaged bytes never
    /// masquerade as clean output; they land byte-exact in the volume
    /// file where the disk path (unrar / a packed-alongside par2 set)
    /// can catch them honestly. finish() itself still succeeds.
    #[test]
    fn output_crc_gate_demotes_damaged_final_store() {
        let f = payload(300_000, 91);
        let pristine_crc = crc32fast::hash(&f);
        let mut damaged = f.clone();
        // Poster damage: the header CRC was computed over the original
        // bytes, the packed data area carries the flipped ones.
        for b in &mut damaged[140_000..140_064] {
            *b ^= 0x5A;
        }
        let vol = fixtures::rar5_volume_n_crc(
            &[("F.mkv", 300_000, &damaged, false, false, Some(pristine_crc))],
            0,
        );
        let dir = tmpdir("outcrcbad");
        let ex = Extractor::new(&dir, 1, true);
        feed(&ex, 0, "o.rar", &vol, 7000, 31);
        let rep = ex.finish().unwrap();
        assert_eq!(rep.fallbacks.len(), 1, "{:?}", rep.fallbacks);
        assert!(
            rep.fallbacks[0].1.contains("failed its stored CRC"),
            "{:?}",
            rep.fallbacks
        );
        assert!(!dir.join("F.mkv").exists(), "corrupt output survived");
        assert_eq!(
            std::fs::read(dir.join("o.rar")).unwrap(),
            vol,
            "volume must materialize byte-exact as packed"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The gate's clean half: a level-0 store payload whose CRC matches
    /// extracts exactly as before - no fallback, no volume on disk, no
    /// behavioral difference beyond the (already-flowing) composition.
    #[test]
    fn output_crc_gate_clean_payload_passes() {
        let f = payload(300_000, 92);
        let vol = fixtures::rar5_volume_n_crc(
            &[("F.mkv", 300_000, &f, false, false, Some(crc32fast::hash(&f)))],
            0,
        );
        let dir = tmpdir("outcrcok");
        let ex = Extractor::new(&dir, 1, true);
        feed(&ex, 0, "o.rar", &vol, 7000, 32);
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("F.mkv")).unwrap(), f);
        assert!(!dir.join("o.rar").exists(), "one-pass: no volume file");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The reversibility contract: with verify_output_crc off (env
    /// escape hatch / setter) the damaged payload ships exactly as
    /// today - clean pass, damaged bytes and all. The env PARSE is
    /// asserted on the pure helper for the same process-global-state
    /// reason as `nested_disabled_by_env`.
    #[test]
    fn output_crc_gate_off_restores_todays_behavior() {
        assert!(output_crc_env_off_value(Some("1")));
        assert!(!output_crc_env_off_value(Some("0")));
        assert!(!output_crc_env_off_value(None));
        let f = payload(300_000, 93);
        let pristine_crc = crc32fast::hash(&f);
        let mut damaged = f.clone();
        for b in &mut damaged[140_000..140_064] {
            *b ^= 0x5A;
        }
        let vol = fixtures::rar5_volume_n_crc(
            &[("F.mkv", 300_000, &damaged, false, false, Some(pristine_crc))],
            0,
        );
        let dir = tmpdir("outcrcoff");
        let ex = Extractor::new(&dir, 1, true);
        assert!(
            ex.inner.lock().unwrap().verify_output_crc,
            "gate must default on"
        );
        ex.set_verify_output_crc(false);
        feed(&ex, 0, "o.rar", &vol, 7000, 33);
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("F.mkv")).unwrap(), damaged);
        assert!(!dir.join("o.rar").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A LEVEL-0 RAR4 store archive now carries its header CRC through to
    /// the output gate (finding 9): the v4 parser retains the whole-file
    /// CRC, so a clean payload verifies IN-STREAM (no demote, no double
    /// I/O) and extracts, while damaged bytes are caught. This closes the
    /// old gap where a top-level RAR4 store output bypassed the gate
    /// entirely and shipped pre-packed damage with rc=0.
    #[test]
    fn output_crc_gate_verifies_level0_rar4() {
        // Clean: composed CRC matches the header, one-pass extract, no demote.
        let dir = tmpdir("outcrc-rar4");
        let data = payload(60_000, 95);
        let v4 = fixtures::rar4_volume(&[("old.avi", 60_000, &data, false, false)]);
        let ex = Extractor::new(&dir, 1, true);
        feed(&ex, 0, "v.rar", &v4, 5000, 19);
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("old.avi")).unwrap(), data);
        assert!(!dir.join("v.rar").exists(), "one-pass: no volume file");
        std::fs::remove_dir_all(&dir).unwrap();

        // Damaged: the header CRC was computed over the pristine bytes, the
        // packed data area carries flipped ones - the gate must demote to a
        // byte-exact materialized volume instead of shipping corrupt output.
        let dir = tmpdir("outcrc-rar4-bad");
        let mut damaged = data.clone();
        for b in &mut damaged[30_000..30_064] {
            *b ^= 0x5A;
        }
        let mut v4b = fixtures::rar4_volume(&[("old.avi", 60_000, &data, false, false)]);
        // Splice the damaged payload in place of the pristine data area,
        // keeping the pristine-derived header CRC.
        let off = {
            let mut m = crate::rar::VolumeMapper::new(v4b.len() as u64);
            m.feed(0, &v4b);
            m.entries[0].data_off as usize
        };
        v4b[off..off + 60_000].copy_from_slice(&damaged);
        let ex = Extractor::new(&dir, 1, true);
        feed(&ex, 0, "v.rar", &v4b, 5000, 23);
        let rep = ex.finish().unwrap();
        assert_eq!(rep.fallbacks.len(), 1, "{:?}", rep.fallbacks);
        assert!(
            rep.fallbacks[0].1.contains("failed its stored CRC"),
            "{:?}",
            rep.fallbacks
        );
        assert!(!dir.join("old.avi").exists(), "corrupt RAR4 output survived");
        assert_eq!(std::fs::read(dir.join("v.rar")).unwrap(), v4b);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Repair-awareness at the CrcRuns level: first-writer-wins is exact
    /// for duplicate re-feeds, but a mapped-repair rewrite carries
    /// DIFFERENT bytes for a range already composed - overwrite must
    /// replace it, orphan the entangled remainder of the run as stale
    /// gaps, and let recomputation (or a re-feed of current bytes)
    /// restore a whole-piece value that reflects the healed file.
    #[test]
    fn crc_runs_overwrite_recomposes_repaired_range() {
        let good = payload(50_000, 78);
        let mut bad = good.clone();
        for b in &mut bad[20_000..20_100] {
            *b ^= 0x5A;
        }
        let mut r = CrcRuns::default();
        // Wire-damaged bytes compose first, as one coalesced run.
        r.add(0, &bad);
        assert_eq!(r.whole(50_000), Some(crc32fast::hash(&bad)));
        // The repair rewrite replaces the damaged range; plain add()
        // would clip it as a duplicate and keep the stale value.
        r.overwrite(19_500, &good[19_500..21_000]);
        assert_eq!(r.whole(50_000), None, "orphaned sub-ranges must gap");
        // A duplicate re-feed of current bytes may re-cover part of a
        // stale range - that part needs no recomputation.
        r.add(0, &good[..10_000]);
        let gaps = r.take_stale_gaps();
        assert_eq!(gaps, vec![(10_000, 19_500), (21_000, 50_000)]);
        for &(s, e) in &gaps {
            assert!(r.add_run(s, e - s, crc32fast::hash(&good[s as usize..e as usize])));
        }
        assert_eq!(r.whole(50_000), Some(crc32fast::hash(&good)));
    }

    /// THE repair regression (level 0): a wire-damaged span routes into
    /// the output unverified, mapped PAR2 repair rewrites the same range
    /// with correct bytes via patch_volume_span, and the file on disk
    /// heals - the output gate must NOT demote on the stale pre-repair
    /// CRC. Fails against a composition that keeps first-writer-wins
    /// across the repair; passes with the repair-aware overwrite +
    /// verify-time recompute.
    #[test]
    fn output_crc_gate_survives_mapped_repair() {
        let f = payload(300_000, 96);
        let vol = fixtures::rar5_volume_n_crc(
            &[("F.mkv", 300_000, &f, false, false, Some(crc32fast::hash(&f)))],
            0,
        );
        // The data area is the payload verbatim: locate the damage range
        // inside it and verify the arithmetic before flipping.
        let data_off = vol.len() - 300_000 - 8;
        let (ds, de) = (data_off + 140_000, data_off + 140_064);
        assert_eq!(&vol[ds..de], &f[140_000..140_064], "fixture layout moved");
        let mut wire = vol.clone();
        for b in &mut wire[ds..de] {
            *b ^= 0x3C;
        }
        let dir = tmpdir("outcrcrepair");
        let ex = Extractor::new(&dir, 1, true);
        feed(&ex, 0, "o.rar", &wire, 7000, 41);
        // Mapped repair rebuilds the damaged range and patches it in.
        ex.patch_volume_span(0, ds as u64, &vol[ds..de]).unwrap();
        let rep = ex.finish().unwrap();
        assert!(
            rep.fallbacks.is_empty(),
            "repaired job must not demote on a stale CRC: {:?}",
            rep.fallbacks
        );
        assert_eq!(std::fs::read(dir.join("F.mkv")).unwrap(), f);
        assert!(!dir.join("o.rar").exists(), "one-pass: no volume file");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The nested twin of the repair regression: the wire damage lands
    /// inside a NESTED store set's data (routed through the child), the
    /// patch re-enters through the parent, and BOTH compositions - the
    /// parent's level-0 entry for the inner archive file and the child's
    /// piece for the payload - must shed their stale values. The
    /// depth>0 half predates the output gate: first-writer-wins across
    /// a repair would false-demote here on its own.
    #[test]
    fn nested_crc_gate_survives_mapped_repair() {
        let f = payload(400_000, 97);
        let whole = crc32fast::hash(&f);
        let iv = [
            fixtures::rar5_volume_n_crc(
                &[("F.mkv", 400_000, &f[..150_000], false, true,
                   Some(crc32fast::hash(&f[..150_000])))],
                0,
            ),
            fixtures::rar5_volume_n_crc(
                &[("F.mkv", 400_000, &f[150_000..300_000], true, true,
                   Some(crc32fast::hash(&f[150_000..300_000])))],
                1,
            ),
            fixtures::rar5_volume_n_crc(
                &[("F.mkv", 400_000, &f[300_000..], true, false, Some(whole))],
                2,
            ),
        ];
        // Outer entries carry CRCs too, so the level-0 gate composes
        // the inner-archive files alongside the child's payload gate.
        let outer = fixtures::rar5_volume_n_crc(
            &[
                ("i.part1.rar", iv[0].len() as u64, &iv[0], false, false,
                 Some(crc32fast::hash(&iv[0]))),
                ("i.part2.rar", iv[1].len() as u64, &iv[1], false, false,
                 Some(crc32fast::hash(&iv[1]))),
                ("i.part3.rar", iv[2].len() as u64, &iv[2], false, false,
                 Some(crc32fast::hash(&iv[2]))),
            ],
            0,
        );
        // Damage 64 bytes of iv[1]'s DATA area as it sits in the outer
        // volume: iv[1] starts at the third RAR5 signature, its data
        // area holds f[150_000..300_000] verbatim before the 8-byte end
        // block. Verify the arithmetic before flipping.
        let sig_at: Vec<usize> = (0..outer.len().saturating_sub(8))
            .filter(|&i| outer[i..].starts_with(b"Rar!\x1a\x07\x01\x00"))
            .collect();
        assert_eq!(sig_at.len(), 4, "outer + three inner signatures");
        let iv1_data = sig_at[2] + (iv[1].len() - 150_000 - 8);
        let (ds, de) = (iv1_data + 70_000, iv1_data + 70_064);
        assert_eq!(&outer[ds..de], &f[220_000..220_064], "fixture layout moved");
        let mut wire = outer.clone();
        for b in &mut wire[ds..de] {
            *b ^= 0x3C;
        }
        let dir = tmpdir("nestcrcrepair");
        let ex = Extractor::new(&dir, 1, true);
        feed(&ex, 0, "o.rar", &wire, 7000, 43);
        ex.patch_volume_span(0, ds as u64, &outer[ds..de]).unwrap();
        let rep = ex.finish().unwrap();
        assert!(
            rep.fallbacks.is_empty(),
            "repaired nested job must not demote on a stale CRC: {:?}",
            rep.fallbacks
        );
        assert_eq!(std::fs::read(dir.join("F.mkv")).unwrap(), f);
        assert_eq!(dir_files(&dir), vec!["F.mkv".to_string()]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The recompute path must keep the gate's teeth: a repaired file
    /// with SEPARATE pre-packed damage (the header CRC never matched the
    /// packed bytes) still demotes after the repair. Dropping the
    /// orphaned runs instead of recomputing them would read this file as
    /// unverifiable and clean-pass the damage the gate exists to catch.
    #[test]
    fn output_crc_gate_still_demotes_prepacked_damage_after_repair() {
        let f = payload(300_000, 98);
        let pristine_crc = crc32fast::hash(&f);
        let mut packed = f.clone();
        // Poster damage at 50k: baked into the posted volume.
        for b in &mut packed[50_000..50_032] {
            *b ^= 0xA5;
        }
        let vol = fixtures::rar5_volume_n_crc(
            &[("F.mkv", 300_000, &packed, false, false, Some(pristine_crc))],
            0,
        );
        let data_off = vol.len() - 300_000 - 8;
        let (ds, de) = (data_off + 140_000, data_off + 140_064);
        assert_eq!(&vol[ds..de], &packed[140_000..140_064], "fixture layout moved");
        // Wire damage at 140k on top; repair rebuilds it as-posted.
        let mut wire = vol.clone();
        for b in &mut wire[ds..de] {
            *b ^= 0x3C;
        }
        let dir = tmpdir("outcrcrepairbad");
        let ex = Extractor::new(&dir, 1, true);
        feed(&ex, 0, "o.rar", &wire, 7000, 47);
        ex.patch_volume_span(0, ds as u64, &vol[ds..de]).unwrap();
        let rep = ex.finish().unwrap();
        assert_eq!(rep.fallbacks.len(), 1, "{:?}", rep.fallbacks);
        assert!(
            rep.fallbacks[0].1.contains("failed its stored CRC"),
            "{:?}",
            rep.fallbacks
        );
        assert!(!dir.join("F.mkv").exists(), "corrupt output survived");
        assert_eq!(
            std::fs::read(dir.join("o.rar")).unwrap(),
            vol,
            "volume must materialize byte-exact as posted (wire damage healed)"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A decode-side panic while holding the routing lock poisons it;
    /// the READ accessors (the daemon's live /stream and stats paths)
    /// must recover the guard and keep serving instead of cascading the
    /// panic into every later call (see `inner_read`). The expected
    /// "panicked at" line this prints is the deliberately-poisoning
    /// helper thread, not a failure.
    #[test]
    fn poisoned_lock_still_serves_read_accessors() {
        let dir = tmpdir("poison");
        let data = payload(60_000, 94);
        let ex = Arc::new(Extractor::new(&dir, 1, true));
        // A plain output file, fully written.
        ex.write(0, "file.bin", data.len() as u64, 0, &data).unwrap();
        // Poison the routing lock: a thread panics while holding it -
        // the decode-worker failure mode.
        let ex2 = ex.clone();
        let h = std::thread::spawn(move || {
            let _g = ex2.inner.lock().unwrap();
            panic!("decode-side panic under the routing lock (expected)");
        });
        assert!(h.join().is_err(), "helper thread must have panicked");
        assert!(ex.inner.is_poisoned(), "lock must be poisoned");
        // Every read accessor still answers from the snapshot.
        assert!(ex.covered(0, 0, data.len()));
        let mut buf = vec![0u8; data.len()];
        ex.read_at(0, 0, &mut buf).unwrap();
        assert_eq!(buf, data);
        assert_eq!(
            ex.covered_intervals(0, 0, data.len() as u64),
            vec![(0, data.len() as u64)]
        );
        assert_eq!(ex.writers_snapshot().len(), 1);
        assert_eq!(
            ex.map_output_range("file.bin", 0, 1000),
            vec![(0, 0, 1000, data.len() as u64)]
        );
        assert!(matches!(ex.open_stream("file.bin"), StreamOpen::Plain));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Compressed inner archive: the child demotes and materializes the
    /// level-1 file intact - exactly the single-level output the disk
    /// post-pass expects - reported as a nested fallback whose wording
    /// must never pattern-match the caller's volume-level remediation
    /// branches. The job itself succeeds.
    #[test]
    fn nested_compressed_inner_demotes() {
        let dir = tmpdir("nestedcomp");
        let junk = payload(120_000, 84);
        let inner_arch = rar5_compressed_volume("F.bin", &junk);
        let outer = fixtures::rar5_volume(&[(
            "inner.rar",
            inner_arch.len() as u64,
            &inner_arch,
            false,
            false,
        )]);
        let ex = Extractor::new(&dir, 1, true);
        feed(&ex, 0, "v.rar", &outer, 7000, 9);
        let rep = ex.finish().unwrap();
        assert_eq!(std::fs::read(dir.join("inner.rar")).unwrap(), inner_arch);
        assert!(!dir.join("v.rar").exists(), "one-pass: no outer volume");
        assert!(
            rep.extracted
                .iter()
                .any(|(n, s)| n == "inner.rar" && *s == inner_arch.len() as u64),
            "{:?}",
            rep.extracted
        );
        let nested: Vec<_> = rep
            .fallbacks
            .iter()
            .filter(|(_, w)| w.starts_with("nested fallback:"))
            .collect();
        assert_eq!(nested.len(), 1, "{:?}", rep.fallbacks);
        for (_, w) in &rep.fallbacks {
            assert!(
                !w.contains("compressed")
                    && !w.contains("encrypted")
                    && !w.contains("password")
                    && !w.contains("held-bytes cap")
                    && !w.contains("incomplete mapping"),
                "nested reason leaks a volume-remediation trigger: {w}"
            );
        }
        assert_eq!(dir_files(&dir), vec!["inner.rar".to_string()]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Phase 0(b): the prevalence tally reflects a known nested fixture. A
    /// store-in-store (outer -> inner.rar -> movie.mkv) streams the inner
    /// payload entirely in RAM, so the depth-1 child logs one in-stream
    /// `rar-store` level and bumps `in_stream` + `rar_store`. Depth 0 (the
    /// outer set) is never counted. The tally is process-global under the
    /// parallel runner, so the assertions are lower-bound deltas, not
    /// absolutes.
    #[test]
    fn nested_prevalence_counts_in_stream_store() {
        let before = nested_prevalence();
        let dir = tmpdir("nestprev");
        let data = payload(90_000, 91);
        let inner_arch =
            fixtures::rar5_volume(&[("movie.mkv", data.len() as u64, &data, false, false)]);
        let outer = fixtures::rar5_volume(&[(
            "inner.rar",
            inner_arch.len() as u64,
            &inner_arch,
            false,
            false,
        )]);
        let ex = Extractor::new(&dir, 1, true);
        feed(&ex, 0, "v.rar", &outer, 7000, 41);
        let rep = ex.finish().unwrap();
        // In-stream store-in-store: the inner payload is produced directly,
        // no volume ever materialized, no fallback.
        assert_eq!(rep.extracted, vec![("movie.mkv".to_string(), data.len() as u64)]);
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        let after = nested_prevalence();
        assert!(
            after.in_stream >= before.in_stream + 1,
            "in_stream did not advance ({} -> {})",
            before.in_stream,
            after.in_stream
        );
        assert!(
            after.rar_store >= before.rar_store + 1,
            "rar_store did not advance ({} -> {})",
            before.rar_store,
            after.rar_store
        );
        assert!(
            after.levels >= before.levels + 1,
            "levels did not advance ({} -> {})",
            before.levels,
            after.levels
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Phase 0(b) false-positive guard: `slot_inner_kind` names only the
    /// three nested-archive modes and stays silent (`None`) for a plain
    /// file, an unclassified span, or an already-demoted slot - so a
    /// demoting non-archive can never emit a `demoted` line and bias the
    /// tally. Deterministic (no counter, no fixture): the whole risk is
    /// this classifier saying "archive" for a non-archive.
    #[test]
    fn slot_inner_kind_ignores_non_archive_slots() {
        let dir = tmpdir("slotkind");
        let ex = Extractor::new(&dir, 1, true);
        let mut g = ex.inner.lock().unwrap();
        let base = g.slots.len();
        for m in [
            SlotMode::Plain,
            SlotMode::Unknown,
            SlotMode::RarFallback,
            SlotMode::Discard,
            SlotMode::SevenZ,
        ] {
            let mut s = Extractor::new_slot();
            s.mode = m;
            g.slots.push(s);
        }
        assert_eq!(Extractor::slot_inner_kind(&g, base), None, "Plain");
        assert_eq!(Extractor::slot_inner_kind(&g, base + 1), None, "Unknown");
        assert_eq!(Extractor::slot_inner_kind(&g, base + 2), None, "RarFallback");
        assert_eq!(Extractor::slot_inner_kind(&g, base + 3), None, "Discard");
        assert_eq!(Extractor::slot_inner_kind(&g, base + 4), Some("7z"), "SevenZ");
        drop(g);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Phase 0(b): a group-less nested inner that DEMOTES (an encrypted 7z
    /// with no password) emits the `demoted` diagnostic at the demote site
    /// - so `demoted` advances while `levels`/`in_stream` do NOT (the
    /// materialized .7z is counted under `disk` by the disk post-pass, not
    /// here). Lower-bound deltas: the tally is process-global.
    #[test]
    fn nested_prevalence_counts_demoted_sevenz() {
        let before = nested_prevalence();
        let f = payload(120_000, 173);
        let arch = sevenz_archive(
            &[("F.bin", &f)],
            Some(vec![
                sevenz_rust2::encoder_options::AesEncoderOptions::new(
                    sevenz_rust2::Password::from("secret"),
                )
                .into(),
            ]),
            false,
        );
        let outer = store_outer("inner.7z", &arch);
        let dir = tmpdir("prev-7z-demote");
        let ex = Extractor::new(&dir, 1, true);
        feed(&ex, 0, "v.rar", &outer, 7000, 51);
        let rep = ex.finish().unwrap();
        // The 7z demoted to a materialized volume, as its own test proves.
        assert!(
            rep.fallbacks.iter().any(|(_, w)| w.starts_with("nested fallback:")),
            "{:?}",
            rep.fallbacks
        );
        let after = nested_prevalence();
        assert!(
            after.demoted >= before.demoted + 1,
            "demoted did not advance ({} -> {})",
            before.demoted,
            after.demoted
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Phase 0(b): the GROUPED demote topology (a multi-volume store set
    /// whose data is CRC-damaged demotes the whole group via the finish-time
    /// CRC gate -> fallback_group) also bumps `demoted` - but through
    /// `report_nested_prevalence`'s groups loop, NOT the demote site. This
    /// is the double-emit-safe counterpart to the group-less 7z demote test
    /// above: the two demote topologies take structurally different emit
    /// paths, and both must count. Lower-bound delta (process-global tally).
    #[test]
    fn nested_prevalence_counts_grouped_demote() {
        let before = nested_prevalence();
        let f = payload(400_000, 177);
        let whole = crc32fast::hash(&f);
        let mut iv = vec![
            fixtures::rar5_volume_n_crc(
                &[("F.mkv", 400_000, &f[..150_000], false, true,
                   Some(crc32fast::hash(&f[..150_000])))],
                0,
            ),
            fixtures::rar5_volume_n_crc(
                &[("F.mkv", 400_000, &f[150_000..300_000], true, true,
                   Some(crc32fast::hash(&f[150_000..300_000])))],
                1,
            ),
            fixtures::rar5_volume_n_crc(
                &[("F.mkv", 400_000, &f[300_000..], true, false, Some(whole))],
                2,
            ),
        ];
        // Poster damage deep in volume 2's data area -> the CRC gate demotes
        // the whole store group at finish.
        let mid = iv[1].len() / 2;
        for b in &mut iv[1][mid..mid + 64] {
            *b ^= 0xA5;
        }
        let outer = fixtures::rar5_volume(&[
            ("i.part1.rar", iv[0].len() as u64, &iv[0], false, false),
            ("i.part2.rar", iv[1].len() as u64, &iv[1], false, false),
            ("i.part3.rar", iv[2].len() as u64, &iv[2], false, false),
        ]);
        let dir = tmpdir("prev-grouped-demote");
        let ex = Extractor::new(&dir, 1, true);
        feed(&ex, 0, "o.rar", &outer, 7000, 57);
        let rep = ex.finish().unwrap();
        assert!(
            rep.fallbacks.iter().any(|(_, w)| w.starts_with("nested fallback:")),
            "{:?}",
            rep.fallbacks
        );
        let after = nested_prevalence();
        assert!(
            after.demoted >= before.demoted + 1,
            "grouped demoted did not advance ({} -> {})",
            before.demoted,
            after.demoted
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A 6-deep store chain: levels 0-4 map through the child chain; the
    /// child AT the depth cap is created disabled, so the level-5 archive
    /// materializes as an ordinary file. No error, no fallback noise. The
    /// cap is a per-chain setting: at a cap of 3 the level-3 archive is
    /// the one left materialized, proving the deepest layer materializes
    /// wherever the cap lands - it is never a hard failure.
    #[test]
    fn nested_depth_cap_materializes() {
        let data = payload(50_000, 85);
        let wrap = |name: &str, inner: &[u8]| {
            fixtures::rar5_volume(&[(name, inner.len() as u64, inner, false, false)])
        };
        // A 6-deep store chain: outer(a1) < a2 < a3 < a4 < a5 < payload.
        // Extracting akN yields ak(N+1); the archive produced AT the cap
        // is the one left materialized.
        let payload_rar = wrap("payload.bin", &data);
        let c5 = wrap("a5.rar", &payload_rar);
        let c4 = wrap("a4.rar", &c5);
        let c3 = wrap("a3.rar", &c4);
        let c2 = wrap("a2.rar", &c3);
        let outer = wrap("a1.rar", &c2);

        // Default cap (5): the level-5 extraction yields a5.rar, whose own
        // (depth-5) child is disabled, so a5.rar = payload_rar materializes.
        let dir = tmpdir("nesteddepth");
        let ex = Extractor::new(&dir, 1, true);
        feed(&ex, 0, "outer.rar", &outer, 7000, 12);
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(rep.extracted, vec![("a5.rar".to_string(), payload_rar.len() as u64)]);
        assert_eq!(std::fs::read(dir.join("a5.rar")).unwrap(), payload_rar);
        assert_eq!(dir_files(&dir), vec!["a5.rar".to_string()]);
        std::fs::remove_dir_all(&dir).unwrap();

        // Configured shallower cap (3): the SAME chain now leaves a3.rar
        // (= c4) materialized - the cap is honoured, still no failure.
        let dir3 = tmpdir("nesteddepth3");
        let ex3 = Extractor::new(&dir3, 1, true);
        ex3.set_nested_max_depth(3);
        feed(&ex3, 0, "outer.rar", &outer, 7000, 12);
        let rep3 = ex3.finish().unwrap();
        assert!(rep3.fallbacks.is_empty(), "{:?}", rep3.fallbacks);
        assert_eq!(rep3.extracted, vec![("a3.rar".to_string(), c4.len() as u64)]);
        assert_eq!(std::fs::read(dir3.join("a3.rar")).unwrap(), c4);
        assert_eq!(dir_files(&dir3), vec!["a3.rar".to_string()]);
        std::fs::remove_dir_all(&dir3).unwrap();
    }

    /// The rollout gates: NZBFAST_NO_NESTED_ONEPASS=1 turns routing off
    /// at construction, and the runtime setter drives the same
    /// `nested_on` flag. With routing off the level-1 archive
    /// materializes exactly as before the nested path existed. The env
    /// PARSE is asserted on the pure helper - actually setting the
    /// process env here would flip the gate for every extractor other
    /// tests construct in the window (process-global state under the
    /// parallel runner), so the behavioral half runs through the setter,
    /// which gates the very same routing decision.
    #[test]
    fn nested_disabled_by_env() {
        // Env latch parse: "1" disables, anything else leaves routing on.
        assert!(nested_env_off_value(Some("1")));
        assert!(!nested_env_off_value(Some("0")));
        assert!(!nested_env_off_value(None));
        let dir = tmpdir("nestedenv");
        let ex = Extractor::new(&dir, 1, true);
        assert!(ex.inner.lock().unwrap().nested_on, "gate must default on");
        ex.set_nested_one_pass(false);

        let data = payload(90_000, 86);
        let inner_arch =
            fixtures::rar5_volume(&[("movie.mkv", data.len() as u64, &data, false, false)]);
        let outer = fixtures::rar5_volume(&[(
            "inner.rar",
            inner_arch.len() as u64,
            &inner_arch,
            false,
            false,
        )]);
        feed(&ex, 0, "v.rar", &outer, 7000, 5);
        let rep = ex.finish().unwrap();
        assert_eq!(
            rep.extracted,
            vec![("inner.rar".to_string(), inner_arch.len() as u64)]
        );
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("inner.rar")).unwrap(), inner_arch);
        assert_eq!(dir_files(&dir), vec!["inner.rar".to_string()]);
        std::fs::remove_dir_all(&dir).unwrap();

        // Same behavior through the runtime setter (daemon rollout knob).
        let dir2 = tmpdir("nestedenv2");
        let ex2 = Extractor::new(&dir2, 1, true);
        ex2.set_nested_one_pass(false);
        feed(&ex2, 0, "v.rar", &outer, 7000, 6);
        let rep2 = ex2.finish().unwrap();
        assert_eq!(
            rep2.extracted,
            vec![("inner.rar".to_string(), inner_arch.len() as u64)]
        );
        assert_eq!(std::fs::read(dir2.join("inner.rar")).unwrap(), inner_arch);
        std::fs::remove_dir_all(&dir2).unwrap();
    }

    // -- nested one-pass phase 2: the chasing decompressor --

    /// Compressed RAR5 single volume built by the vendored RAR engine's
    /// writer - a REAL compressed archive (LZ bitstream, valid CRCs), not
    /// a hand-crafted header shell.
    fn rars_compressed_volume(entries: &[(&str, &[u8])]) -> Vec<u8> {
        use rars::rar50::{CompressedEntry, Rar50Writer, WriterOptions};
        let entries: Vec<CompressedEntry> = entries
            .iter()
            .map(|&(name, data)| CompressedEntry {
                name: name.as_bytes(),
                data,
                mtime: None,
                attributes: 0,
                host_os: 0,
            })
            .collect();
        Rar50Writer::new(WriterOptions::default())
            .compressed_entries(&entries)
            .finish()
            .unwrap()
    }

    /// Compressed RAR5 multi-volume set (one member split across
    /// volumes), capped payload bytes per volume.
    fn rars_compressed_volumes(name: &str, data: &[u8], per_vol: usize) -> Vec<Vec<u8>> {
        use rars::rar50::{CompressedEntry, Rar50VolumeWriter, WriterOptions};
        let entries = [CompressedEntry {
            name: name.as_bytes(),
            data,
            mtime: None,
            attributes: 0,
            host_os: 0,
        }];
        Rar50VolumeWriter::new(WriterOptions::default())
            .compressed_entries(&entries)
            .max_payload_per_volume(per_vol)
            .finish()
            .unwrap()
    }

    /// Half-entropy bytes (xorshift byte, zero byte, ...): compressible
    /// enough that the writer keeps the compressed method, incompressible
    /// enough that the packed stream stays near half the input size -
    /// entropy bounds it from below, so size-driven tests are stable.
    fn noisy(n: usize, seed: u64) -> Vec<u8> {
        let mut s = seed | 1;
        (0..n)
            .map(|i| {
                if i % 2 == 0 {
                    s ^= s << 13;
                    s ^= s >> 7;
                    s ^= s << 17;
                    (s >> 24) as u8
                } else {
                    0
                }
            })
            .collect()
    }

    /// Prove a fixture really is compressed: the store mapper must refuse
    /// it with NotStore (otherwise the test would silently exercise the
    /// phase-1 store path instead of the chase).
    fn assert_not_store(vol: &[u8]) {
        let mut m = VolumeMapper::new(vol.len() as u64);
        m.feed(0, vol);
        assert_eq!(m.blocker, Some(MapBlocker::NotStore), "fixture is not compressed");
    }

    /// A store outer wrapping a COMPRESSED RAR5 inner: the chase engages
    /// (no demotion), the final payload is byte-identical, and neither
    /// the outer volume nor the inner archive ever exists on disk.
    #[test]
    fn chase_compressed_inner_one_pass() {
        let dir = tmpdir("chase1");
        let f = payload(300_000, 91);
        let inner_arch = rars_compressed_volume(&[("F.bin", &f)]);
        assert_not_store(&inner_arch);
        let outer = fixtures::rar5_volume(&[(
            "inner.rar",
            inner_arch.len() as u64,
            &inner_arch,
            false,
            false,
        )]);
        let ex = Extractor::new(&dir, 1, true);
        feed(&ex, 0, "v.rar", &outer, 7000, 9);
        let rep = ex.finish().unwrap();
        // No fallback = the chase ran, it did not demote.
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert!(
            rep.extracted
                .iter()
                .any(|(n, s)| n == "F.bin" && *s == f.len() as u64),
            "{:?}",
            rep.extracted
        );
        assert_eq!(std::fs::read(dir.join("F.bin")).unwrap(), f);
        // One pass: no outer volume, no intermediate archive - ever.
        assert_eq!(dir_files(&dir), vec!["F.bin".to_string()]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Out-of-order arrival with a mid-file gap filled LAST: the chase
    /// worker blocks at the frontier until the gap span lands, then runs
    /// through - proving the frontier buffer's hole tracking and the
    /// blocking read contract end to end.
    #[test]
    fn chase_blocks_at_frontier_until_gap_fills() {
        let dir = tmpdir("chase-gap");
        // noisy: the packed inner archive stays ~150 KB, so the outer
        // really spans many articles and the gap sits mid-bitstream.
        let f = noisy(300_000, 92);
        let inner_arch = rars_compressed_volume(&[("F.bin", &f)]);
        assert_not_store(&inner_arch);
        let outer = fixtures::rar5_volume(&[(
            "inner.rar",
            inner_arch.len() as u64,
            &inner_arch,
            false,
            false,
        )]);
        let art = 999usize; // odd size: gap edges land mid-anything
        let n_arts = outer.len().div_ceil(art);
        let gap = n_arts / 2;
        let ex = Extractor::new(&dir, 1, true);
        // Everything except the gap article, in reverse order (offset 0
        // arrives late, spans park out of order in the frontier buffer).
        for i in (0..n_arts).rev() {
            if i == gap {
                continue;
            }
            let s = i * art;
            let e = (s + art).min(outer.len());
            ex.write(0, "v.rar", outer.len() as u64, s as u64, &outer[s..e])
                .unwrap();
        }
        // The chase is attached and its worker blocked at the gap; fill it.
        let (s, e) = (gap * art, ((gap + 1) * art).min(outer.len()));
        ex.write(0, "v.rar", outer.len() as u64, s as u64, &outer[s..e])
            .unwrap();
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("F.bin")).unwrap(), f);
        assert_eq!(dir_files(&dir), vec!["F.bin".to_string()]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// PAR2 interplay: a rebuilt block re-enters via patch_volume_span ->
    /// routing -> frontier fill, and the blocked chase simply unblocks.
    /// No chase-specific repair code exists - this proves none is needed.
    #[test]
    fn chase_unblocks_on_patched_volume_span() {
        let dir = tmpdir("chase-patch");
        let f = noisy(300_000, 93);
        let inner_arch = rars_compressed_volume(&[("F.bin", &f)]);
        assert_not_store(&inner_arch);
        let outer = fixtures::rar5_volume(&[(
            "inner.rar",
            inner_arch.len() as u64,
            &inner_arch,
            false,
            false,
        )]);
        let art = 1000usize;
        let n_arts = outer.len().div_ceil(art);
        let lost = n_arts / 2;
        let ex = Extractor::new(&dir, 1, true);
        for i in 0..n_arts {
            if i == lost {
                continue;
            }
            let s = i * art;
            let e = (s + art).min(outer.len());
            ex.write(0, "v.rar", outer.len() as u64, s as u64, &outer[s..e])
                .unwrap();
        }
        // "Repair" rebuilds the lost article's bytes and patches them in.
        let (s, e) = (lost * art, ((lost + 1) * art).min(outer.len()));
        ex.patch_volume_span(0, s as u64, &outer[s..e]).unwrap();
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("F.bin")).unwrap(), f);
        assert_eq!(dir_files(&dir), vec!["F.bin".to_string()]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// RAR4 compressed inner: never chases (the engine streams RAR5
    /// only) - demotes to a byte-exact materialized level-1 archive,
    /// today's output, and the job succeeds.
    #[test]
    fn chase_demotes_on_rar4() {
        let dir = tmpdir("chase-rar4");
        let data = payload(60_000, 94);
        let mut v4 = fixtures::rar4_volume(&[("c.bin", 60_000, &data, false, false)]);
        // Flip the fixed-layout method byte to "compressed" (see the
        // rar.rs compressed_flagged_not_store test for the offset math).
        let m_off = 7 + 13 + 11 + 14;
        assert_eq!(v4[m_off], 0x30);
        v4[m_off] = 0x33;
        assert_not_store(&v4);
        let outer = fixtures::rar5_volume(&[(
            "inner.rar",
            v4.len() as u64,
            &v4,
            false,
            false,
        )]);
        let ex = Extractor::new(&dir, 1, true);
        feed(&ex, 0, "v.rar", &outer, 5000, 11);
        let rep = ex.finish().unwrap();
        assert!(
            rep.fallbacks
                .iter()
                .any(|(_, w)| w.starts_with("nested fallback:")),
            "{:?}",
            rep.fallbacks
        );
        assert_eq!(std::fs::read(dir.join("inner.rar")).unwrap(), v4);
        assert_eq!(dir_files(&dir), vec!["inner.rar".to_string()]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Budget breach mid-chase: the retained frontier bytes charge the
    /// SHARED holds budget, and crossing the cap demotes the group to a
    /// materialized level-1 archive - complete and byte-exact, with the
    /// partial chase output deleted, no hang, no leaked worker.
    #[test]
    fn chase_budget_breach_demotes() {
        let dir = tmpdir("chase-budget");
        // ~1.2 MB packed (half-entropy input bounds it near half size).
        let f = noisy(2_400_000, 95);
        let inner_arch = rars_compressed_volume(&[("F.bin", &f)]);
        assert_not_store(&inner_arch);
        assert!(inner_arch.len() > 900_000, "packed too small: {}", inner_arch.len());
        let outer = fixtures::rar5_volume(&[(
            "inner.rar",
            inner_arch.len() as u64,
            &inner_arch,
            false,
            false,
        )]);
        let ex = Extractor::new(&dir, 3, true);
        ex.set_holds_cap(1); // floors at 8 MB
        // Eat most of the budget with two never-classifying slots held
        // just under their per-slot spill (4 MB each at this cap).
        let junk = payload(65_000, 96);
        for slot in [1usize, 2] {
            for i in 0..60u64 {
                ex.write(slot, &format!("dummy{slot}.bin"), 8_000_000, 64_000 + i * 65_000, &junk)
                    .unwrap();
            }
        }
        // Sequential outer feed: the chase attaches at the inner sniff,
        // then its retained bytes push the shared budget over the cap.
        for (i, chunk) in outer.chunks(50_000).enumerate() {
            ex.write(0, "v.rar", outer.len() as u64, (i * 50_000) as u64, chunk)
                .unwrap();
        }
        let rep = ex.finish().unwrap();
        assert!(
            rep.fallbacks
                .iter()
                .any(|(_, w)| w.starts_with("nested fallback:")),
            "{:?}",
            rep.fallbacks
        );
        // The level-1 archive materialized COMPLETE (buffer bytes +
        // post-demote write-through), ready for the disk post-pass.
        assert_eq!(std::fs::read(dir.join("inner.rar")).unwrap(), inner_arch);
        assert!(!dir.join("F.bin").exists(), "partial chase output survived");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Bytes never arrive: finish() aborts the still-blocked chase and
    /// demotes cleanly - no hang, job Ok, the materialized level-1
    /// archive carries everything that DID arrive (the lost article's
    /// range stays an uncovered hole), partial output deleted.
    #[test]
    fn chase_abort_on_finish_with_missing_bytes() {
        let dir = tmpdir("chase-missing");
        let f = noisy(300_000, 97);
        let inner_arch = rars_compressed_volume(&[("F.bin", &f)]);
        assert_not_store(&inner_arch);
        let outer = fixtures::rar5_volume(&[(
            "inner.rar",
            inner_arch.len() as u64,
            &inner_arch,
            false,
            false,
        )]);
        // Locate the outer data area so the withheld article is pure
        // inner-archive bytes.
        let data_off = {
            let mut m = VolumeMapper::new(outer.len() as u64);
            m.feed(0, &outer);
            m.entries[0].data_off as usize
        };
        let art = 1000usize;
        let lost = (data_off / art) + 2; // fully inside the data area
        let (ls, le) = (lost * art, ((lost + 1) * art).min(outer.len()));
        let ex = Extractor::new(&dir, 1, true);
        for i in 0..outer.len().div_ceil(art) {
            if i == lost {
                continue;
            }
            let s = i * art;
            let e = (s + art).min(outer.len());
            ex.write(0, "v.rar", outer.len() as u64, s as u64, &outer[s..e])
                .unwrap();
        }
        let rep = ex.finish().unwrap();
        assert!(
            rep.fallbacks
                .iter()
                .any(|(_, w)| w.starts_with("nested fallback:")),
            "{:?}",
            rep.fallbacks
        );
        assert!(!dir.join("F.bin").exists(), "partial chase output survived");
        // Materialized volume: byte-exact outside the lost range, hole
        // (zeros, uncovered) inside it.
        let got = std::fs::read(dir.join("inner.rar")).unwrap();
        let mut expect = inner_arch.clone();
        expect[ls - data_off..le - data_off].fill(0);
        assert_eq!(got, expect);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A compressed member split across FOUR inner volumes, all wrapped
    /// in one store outer: the sequence driver pulls volume k+1 only
    /// after k, split read-back reaches retained earlier volumes, and
    /// the final payload lands byte-exact with nothing else on disk.
    #[test]
    fn chase_multi_volume_compressed_inner() {
        let f = noisy(300_000, 98);
        let vols = rars_compressed_volumes("F.bin", &f, 50_000);
        assert!(vols.len() >= 3, "want a real multi-volume set, got {}", vols.len());
        for v in &vols {
            assert_not_store(v);
        }
        let pieces: Vec<(String, &Vec<u8>)> = vols
            .iter()
            .enumerate()
            .map(|(i, v)| (format!("inner.part{}.rar", i + 1), v))
            .collect();
        let outer_entries: Vec<(&str, u64, &[u8], bool, bool)> = pieces
            .iter()
            .map(|(n, v)| (n.as_str(), v.len() as u64, v.as_slice(), false, false))
            .collect();
        let outer = fixtures::rar5_volume(&outer_entries);
        // Two feed orders: forward and reverse (later inner volumes'
        // buffers register before the chase can use them).
        for (t, rev) in [false, true].iter().enumerate() {
            let dir = tmpdir(&format!("chase-mv{t}"));
            let ex = Extractor::new(&dir, 1, true);
            let art = 7000usize;
            let n_arts = outer.len().div_ceil(art);
            let order: Vec<usize> = if *rev {
                (0..n_arts).rev().collect()
            } else {
                (0..n_arts).collect()
            };
            for i in order {
                let s = i * art;
                let e = (s + art).min(outer.len());
                ex.write(0, "v.rar", outer.len() as u64, s as u64, &outer[s..e])
                    .unwrap();
            }
            let rep = ex.finish().unwrap();
            assert!(rep.fallbacks.is_empty(), "rev={rev}: {:?}", rep.fallbacks);
            assert_eq!(std::fs::read(dir.join("F.bin")).unwrap(), f, "rev={rev}");
            assert_eq!(dir_files(&dir), vec!["F.bin".to_string()], "rev={rev}");
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    /// Chase + repair at multi-volume scale (the multi-volume extension
    /// of `chase_unblocks_on_patched_volume_span`): a compressed member
    /// split across 3+ inner volumes, wrapped in a TWO-volume store
    /// outer with an inner volume file spanning the outer boundary. One
    /// article is lost inside the packed stream of EACH outer volume;
    /// everything else arrives, then both holes are patched via
    /// patch_volume_span (the mapped-repair re-entry path). The blocked
    /// chase must resume through both fills and complete byte-exact,
    /// with neither an outer volume nor an inner archive on disk.
    #[test]
    fn chase_multi_volume_patched_spans_complete() {
        let dir = tmpdir("chase-mv-patch");
        let f = noisy(300_000, 101);
        let vols = rars_compressed_volumes("F.bin", &f, 50_000);
        assert!(vols.len() >= 3, "want a real multi-volume set, got {}", vols.len());
        for v in &vols {
            assert_not_store(v);
        }
        // Outer vol 1: inner.part1.rar whole + the head of inner.part2.rar;
        // outer vol 2: the rest of inner.part2.rar + the remaining volumes.
        let cut = vols[1].len() / 2;
        let names: Vec<String> = (1..=vols.len())
            .map(|i| format!("inner.part{i}.rar"))
            .collect();
        let o1_entries: Vec<(&str, u64, &[u8], bool, bool)> = vec![
            (names[0].as_str(), vols[0].len() as u64, &vols[0][..], false, false),
            (names[1].as_str(), vols[1].len() as u64, &vols[1][..cut], false, true),
        ];
        let mut o2_entries: Vec<(&str, u64, &[u8], bool, bool)> = vec![(
            names[1].as_str(),
            vols[1].len() as u64,
            &vols[1][cut..],
            true,
            false,
        )];
        for (i, v) in vols.iter().enumerate().skip(2) {
            o2_entries.push((names[i].as_str(), v.len() as u64, v, false, false));
        }
        let outers = [
            fixtures::rar5_volume_n(&o1_entries, 0),
            fixtures::rar5_volume_n(&o2_entries, 1),
        ];
        // Lose one article deep inside each outer volume's first data
        // area - packed LZ bitstream bytes, not envelope.
        let art = 1000usize;
        let lost: Vec<usize> = outers
            .iter()
            .map(|o| {
                let mut m = VolumeMapper::new(o.len() as u64);
                m.feed(0, o);
                let e = &m.entries[0];
                ((e.data_off + e.data_len / 2) / art as u64) as usize
            })
            .collect();
        let ex = Extractor::new(&dir, 2, true);
        for (si, o) in outers.iter().enumerate() {
            for i in 0..o.len().div_ceil(art) {
                if i == lost[si] {
                    continue;
                }
                let s = i * art;
                let e = (s + art).min(o.len());
                ex.write(si, &format!("o.part{}.rar", si + 1), o.len() as u64, s as u64, &o[s..e])
                    .unwrap();
            }
        }
        // "Repair" both holes - rebuilt blocks re-enter through the
        // normal patch path, exactly as mapped PAR2 repair delivers them.
        for (si, o) in outers.iter().enumerate() {
            let (s, e) = (lost[si] * art, ((lost[si] + 1) * art).min(o.len()));
            assert!(!ex.covered(si, s as u64, e - s), "vol {si} hole really is a hole");
            ex.patch_volume_span(si, s as u64, &o[s..e]).unwrap();
        }
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("F.bin")).unwrap(), f);
        assert_eq!(dir_files(&dir), vec!["F.bin".to_string()]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The chase SINK is the routing seam (n-deep): a compressed layer
    /// wrapping a STORE archive - the chase's decompressed output routes
    /// into a child slot, sniffs as RAR, and the store layer below keeps
    /// streaming. Only the innermost payload ever touches disk.
    #[test]
    fn chase_output_store_archive_streams_below() {
        let dir = tmpdir("chase-deep");
        let g = payload(120_000, 99);
        let deep = fixtures::rar5_volume(&[("G.bin", 120_000, &g, false, false)]);
        let inner_arch = rars_compressed_volume(&[("deep.rar", &deep)]);
        assert_not_store(&inner_arch);
        let outer = fixtures::rar5_volume(&[(
            "inner.rar",
            inner_arch.len() as u64,
            &inner_arch,
            false,
            false,
        )]);
        let ex = Extractor::new(&dir, 1, true);
        feed(&ex, 0, "v.rar", &outer, 7000, 13);
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("G.bin")).unwrap(), g);
        // No outer volume, no compressed archive, no store archive.
        assert_eq!(dir_files(&dir), vec!["G.bin".to_string()]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The chase gates: NZBFAST_NO_NESTED_CHASE=1 parses as off, and the
    /// runtime setter drives the same latch - with it off, a compressed
    /// inner demotes to a materialized file exactly as before the chase
    /// existed (nested routing itself stays on). The env PARSE is
    /// asserted on the pure helper for the same parallel-runner reason
    /// as `nested_disabled_by_env`.
    #[test]
    fn chase_disabled_by_env() {
        assert!(chase_env_off_value(Some("1")));
        assert!(!chase_env_off_value(Some("0")));
        assert!(!chase_env_off_value(None));

        let dir = tmpdir("chase-env");
        let f = payload(200_000, 90);
        let inner_arch = rars_compressed_volume(&[("F.bin", &f)]);
        assert_not_store(&inner_arch);
        let outer = fixtures::rar5_volume(&[(
            "inner.rar",
            inner_arch.len() as u64,
            &inner_arch,
            false,
            false,
        )]);
        let ex = Extractor::new(&dir, 1, true);
        assert!(ex.inner.lock().unwrap().chase_on, "gate must default on");
        ex.set_nested_chase(false);
        feed(&ex, 0, "v.rar", &outer, 7000, 15);
        let rep = ex.finish().unwrap();
        assert!(
            rep.fallbacks
                .iter()
                .any(|(_, w)| w.starts_with("nested fallback:")),
            "{:?}",
            rep.fallbacks
        );
        assert_eq!(std::fs::read(dir.join("inner.rar")).unwrap(), inner_arch);
        assert!(!dir.join("F.bin").exists());
        assert_eq!(dir_files(&dir), vec!["inner.rar".to_string()]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Cancel semantics: dropping an extractor mid-chase (job abandoned)
    /// aborts the chase buffers and the worker exits - the drop returns
    /// instead of hanging on a frontier that will never fill.
    #[test]
    fn chase_worker_exits_on_extractor_drop() {
        let dir = tmpdir("chase-drop");
        let f = noisy(300_000, 89);
        let inner_arch = rars_compressed_volume(&[("F.bin", &f)]);
        assert_not_store(&inner_arch);
        let outer = fixtures::rar5_volume(&[(
            "inner.rar",
            inner_arch.len() as u64,
            &inner_arch,
            false,
            false,
        )]);
        let ex = Extractor::new(&dir, 1, true);
        // Just enough for the chase to attach and its worker to block at
        // the frontier - then abandon the job.
        ex.write(0, "v.rar", outer.len() as u64, 0, &outer[..4000])
            .unwrap();
        drop(ex);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// FrontierBuffer contract: out-of-order spans park and fold in as
    /// gaps fill; a blocked reader wakes on exactly the fill; peek and
    /// intervals see parked bytes the blocking reader must not.
    #[test]
    fn frontier_buffer_holes_and_blocking() {
        use rars::BlockingRangeSource as _;
        let buf = Arc::new(FrontierBuffer::new(30));
        // Arrive out of order: [20,30) then [10,20); frontier stays 0.
        buf.write_span(20, &[2u8; 10]);
        buf.write_span(10, &[1u8; 10]);
        assert_eq!(buf.known_len(), 0);
        assert_eq!(buf.intervals(0, 30), vec![(10, 30)]);
        let mut peeked = [0u8; 10];
        buf.peek(15, &mut peeked[..5]).unwrap();
        assert_eq!(&peeked[..5], &[1u8; 5]);
        assert!(buf.peek(5, &mut peeked).is_err(), "hole must not peek");
        // A reader blocks at offset 0 until the head span lands.
        let reader = Arc::clone(&buf);
        let h = std::thread::spawn(move || {
            let mut out = vec![0u8; 30];
            let mut pos = 0usize;
            while pos < 30 {
                let n = reader.read_at(pos as u64, &mut out[pos..]).unwrap();
                assert_ne!(n, 0);
                pos += n;
            }
            out
        });
        std::thread::sleep(std::time::Duration::from_millis(20));
        buf.write_span(0, &[9u8; 10]);
        let mut want = vec![9u8; 10];
        want.extend_from_slice(&[1u8; 10]);
        want.extend_from_slice(&[2u8; 10]);
        assert_eq!(h.join().unwrap(), want);
        assert_eq!(buf.known_len(), 30);
        assert!(buf.is_complete());
        // Duplicates and overlaps are absorbed, never doubled - and an
        // IDENTICAL re-delivery is not a conflict, which is the case the
        // routing layer produces constantly.
        let before = buf.write_span(5, &[9u8; 5]);
        assert_eq!(before, 30);
        assert!(!buf.conflicted(), "identical re-delivery is not a rewrite");
        // Abort wakes a blocked reader with an error.
        let buf2 = Arc::new(FrontierBuffer::new(10));
        let r2 = Arc::clone(&buf2);
        let h2 = std::thread::spawn(move || {
            let mut b = [0u8; 4];
            r2.read_at(0, &mut b)
        });
        std::thread::sleep(std::time::Duration::from_millis(20));
        buf2.abort("test cancel");
        assert!(h2.join().unwrap().is_err());
    }

    /// A mapped repair whose bytes DIFFER from an earlier delivery used to
    /// vanish silently whenever it landed at or behind the frontier - the
    /// exact range the chase engine has already decoded. Pin both halves
    /// of the fix: the conflict is visible to the caller, and the retained
    /// record ends up holding the CORRECTED bytes, because a demotion
    /// materializes the volume straight out of it.
    #[test]
    fn frontier_buffer_flags_a_differing_rewrite() {
        use rars::BlockingRangeSource as _;
        // Wholly behind the frontier.
        let buf = FrontierBuffer::new(30);
        buf.write_span(0, &[1u8; 10]);
        buf.write_span(10, &[2u8; 10]);
        assert_eq!(buf.known_len(), 20);
        assert!(!buf.conflicted());
        buf.write_span(0, &[7u8; 5]);
        assert!(buf.conflicted(), "a differing rewrite must not be dropped");
        let mut got = [0u8; 10];
        buf.peek(0, &mut got).unwrap();
        assert_eq!(&got, &[7, 7, 7, 7, 7, 1, 1, 1, 1, 1], "repair must win");

        // Straddling the frontier: the overlap is reconciled, the tail is
        // appended, and the frontier still advances.
        let buf = FrontierBuffer::new(30);
        buf.write_span(0, &[1u8; 10]);
        buf.write_span(5, &[8u8; 10]);
        assert!(buf.conflicted());
        assert_eq!(buf.known_len(), 15);
        let mut got = [0u8; 15];
        buf.peek(0, &mut got).unwrap();
        assert_eq!(&got[..5], &[1u8; 5]);
        assert_eq!(&got[5..], &[8u8; 10]);

        // Parked, not yet folded. The 7z chase peeks at arbitrary offsets,
        // so a parked span can have been read too.
        let buf = FrontierBuffer::new(30);
        buf.write_span(20, &[3u8; 10]);
        assert_eq!(buf.known_len(), 0);
        assert!(!buf.conflicted());
        buf.write_span(22, &[4u8; 4]);
        assert!(buf.conflicted(), "a parked rewrite must not be dropped");
        let mut got = [0u8; 10];
        buf.peek(20, &mut got).unwrap();
        assert_eq!(&got, &[3, 3, 4, 4, 4, 4, 3, 3, 3, 3]);
        // And the corrected bytes are what a demotion would materialize.
        // An overlapping park is kept as its own span (only a same-start
        // duplicate is subsumed), so what matters is that the copies now
        // AGREE - materializing them in any order lands the same volume.
        let spans = buf.take_spans();
        let covering = spans.iter().find(|(s, _)| *s == 20).expect("span at 20");
        assert_eq!(&covering.1, &[3, 3, 4, 4, 4, 4, 3, 3, 3, 3]);
        for (s, v) in &spans {
            for (i, b) in v.iter().enumerate() {
                let at = (s + i as u64 - 20) as usize;
                assert_eq!(*b, covering.1[at], "copies disagree at {}", s + i as u64);
            }
        }
    }

    /// Invertibility with routing live: `read_at` over outer-volume
    /// ranges returns byte-identical data - outer header regions, the
    /// region carrying the INNER archive's headers (served from the
    /// child's stash), and deep data regions (served from the final
    /// files, two delegation hops down). This is the property verifier
    /// settle and mapped repair stand on.
    #[test]
    fn nested_read_at_reconstructs_outer_volume_bytes() {
        let a = payload(220_000, 87);
        let inner_arch =
            fixtures::rar5_volume(&[("A.mkv", 220_000, &a, false, false)]);
        let n = inner_arch.len();
        let cut = n / 2;
        let vols: Vec<Vec<u8>> = vec![
            fixtures::rar5_volume_n(
                &[("inner.rar", n as u64, &inner_arch[..cut], false, true)],
                0,
            ),
            fixtures::rar5_volume_n(
                &[("inner.rar", n as u64, &inner_arch[cut..], true, false)],
                1,
            ),
        ];
        let dir = tmpdir("nestedreadat");
        let ex = Extractor::new(&dir, 2, true);
        feed(&ex, 0, "x.part1.rar", &vols[0], 6000, 31);
        feed(&ex, 1, "x.part2.rar", &vols[1], 6000, 32);
        // Whole volumes, byte-exact, mid-download (mapped mode).
        for (si, vol) in vols.iter().enumerate() {
            let mut back = vec![0u8; vol.len()];
            ex.read_at(si, 0, &mut back).unwrap();
            assert_eq!(&back, vol, "volume {si} view");
            assert!(ex.covered(si, 0, vol.len()), "volume {si} coverage");
        }
        // Targeted ranges: outer header bytes; the outer data-area start,
        // which carries the inner archive's own headers; straddling and
        // deep data ranges; the tail (end-of-archive record).
        for &(si, off, len) in &[
            (0usize, 0usize, 64usize),
            (0, 8, 120),
            (0, 40, 9000),
            (0, cut / 2, 9000),
            (1, 0, 300),
            (1, 100, 5000),
            (1, vols[1].len() - 4000, 4000),
        ] {
            let mut buf = vec![0u8; len.min(vols[si].len() - off)];
            ex.read_at(si, off as u64, &mut buf).unwrap();
            assert_eq!(
                &buf[..],
                &vols[si][off..off + buf.len()],
                "range slot {si} {off}+{len}"
            );
        }
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("A.mkv")).unwrap(), a);
        assert_eq!(dir_files(&dir), vec!["A.mkv".to_string()]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    // -- nested one-pass: extreme shapes + depth memory accounting --

    /// Every level of a 4-deep store chain carries a required sibling
    /// data file next to the deeper archive: level k holds "docs_k.txt"
    /// plus the level-(k+1) archive, the innermost holding the final
    /// payload. All four siblings and the payload land byte-exact in the
    /// output dir; no archive at ANY level and no volume ever touch
    /// disk. Driven forward and reverse (offset 0 last: every level
    /// classifies off drained holds).
    #[test]
    fn nested_mixed_payload_every_level() {
        let docs: Vec<Vec<u8>> = (0..4u8)
            .map(|k| payload(30_000 + k as usize * 1_000, 0xA0 + k))
            .collect();
        let final_pay = payload(200_000, 0xB1);
        let a3 = fixtures::rar5_volume(&[
            ("docs_3.txt", docs[3].len() as u64, &docs[3], false, false),
            ("payload.bin", final_pay.len() as u64, &final_pay, false, false),
        ]);
        let a2 = fixtures::rar5_volume(&[
            ("docs_2.txt", docs[2].len() as u64, &docs[2], false, false),
            ("a3.rar", a3.len() as u64, &a3, false, false),
        ]);
        let a1 = fixtures::rar5_volume(&[
            ("docs_1.txt", docs[1].len() as u64, &docs[1], false, false),
            ("a2.rar", a2.len() as u64, &a2, false, false),
        ]);
        let outer = fixtures::rar5_volume(&[
            ("docs_0.txt", docs[0].len() as u64, &docs[0], false, false),
            ("a1.rar", a1.len() as u64, &a1, false, false),
        ]);
        let want: Vec<(String, u64)> = vec![
            ("docs_0.txt".to_string(), docs[0].len() as u64),
            ("docs_1.txt".to_string(), docs[1].len() as u64),
            ("docs_2.txt".to_string(), docs[2].len() as u64),
            ("docs_3.txt".to_string(), docs[3].len() as u64),
            ("payload.bin".to_string(), final_pay.len() as u64),
        ];
        for rev in [false, true] {
            let dir = tmpdir(&format!("nestedmix{}", rev as u8));
            let ex = Extractor::new(&dir, 1, true);
            let art = 7000usize;
            let n_arts = outer.len().div_ceil(art);
            let order: Vec<usize> = if rev {
                (0..n_arts).rev().collect()
            } else {
                (0..n_arts).collect()
            };
            for i in order {
                let s = i * art;
                let e = (s + art).min(outer.len());
                ex.write(0, "v.rar", outer.len() as u64, s as u64, &outer[s..e])
                    .unwrap();
            }
            let rep = ex.finish().unwrap();
            assert!(rep.fallbacks.is_empty(), "rev={rev}: {:?}", rep.fallbacks);
            assert_eq!(rep.extracted, want, "rev={rev}");
            for (k, d) in docs.iter().enumerate() {
                assert_eq!(
                    &std::fs::read(dir.join(format!("docs_{k}.txt"))).unwrap(),
                    d,
                    "rev={rev} docs_{k}"
                );
            }
            assert_eq!(std::fs::read(dir.join("payload.bin")).unwrap(), final_pay, "rev={rev}");
            assert_eq!(
                dir_files(&dir),
                vec![
                    "docs_0.txt".to_string(),
                    "docs_1.txt".to_string(),
                    "docs_2.txt".to_string(),
                    "docs_3.txt".to_string(),
                    "payload.bin".to_string(),
                ],
                "rev={rev}"
            );
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    /// Same shape with the level-3 archive COMPRESSED (the chase engages
    /// at depth): it carries its own sibling plus a STORE archive whose
    /// payload keeps streaming below the chase. Store-level siblings,
    /// the chased sibling, and the deepest payload all land byte-exact;
    /// no archive at any level materializes.
    #[test]
    fn nested_mixed_payload_chase_at_depth() {
        let docs: Vec<Vec<u8>> = (0..4u8)
            .map(|k| payload(28_000 + k as usize * 1_000, 0x60 + k))
            .collect();
        let g = payload(150_000, 0x71);
        let deep = fixtures::rar5_volume(&[("G.bin", g.len() as u64, &g, false, false)]);
        let a3 = rars_compressed_volume(&[("docs_3.txt", &docs[3]), ("deep.rar", &deep)]);
        assert_not_store(&a3);
        let a2 = fixtures::rar5_volume(&[
            ("docs_2.txt", docs[2].len() as u64, &docs[2], false, false),
            ("a3.rar", a3.len() as u64, &a3, false, false),
        ]);
        let a1 = fixtures::rar5_volume(&[
            ("docs_1.txt", docs[1].len() as u64, &docs[1], false, false),
            ("a2.rar", a2.len() as u64, &a2, false, false),
        ]);
        let outer = fixtures::rar5_volume(&[
            ("docs_0.txt", docs[0].len() as u64, &docs[0], false, false),
            ("a1.rar", a1.len() as u64, &a1, false, false),
        ]);
        let dir = tmpdir("nestedmixchase");
        let ex = Extractor::new(&dir, 1, true);
        feed(&ex, 0, "v.rar", &outer, 7000, 17);
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        for (k, d) in docs.iter().enumerate() {
            assert_eq!(
                &std::fs::read(dir.join(format!("docs_{k}.txt"))).unwrap(),
                d,
                "docs_{k}"
            );
        }
        assert_eq!(std::fs::read(dir.join("G.bin")).unwrap(), g);
        assert_eq!(
            dir_files(&dir),
            vec![
                "G.bin".to_string(),
                "docs_0.txt".to_string(),
                "docs_1.txt".to_string(),
                "docs_2.txt".to_string(),
                "docs_3.txt".to_string(),
            ]
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// One nested level fanning WIDE: a level-1 archive split across
    /// three outer volumes carries EIGHT sibling files around one deeper
    /// archive - the out_names/name-claim machinery holds up with many
    /// concurrent child slots at depth. Two volume feed orders.
    #[test]
    fn nested_many_siblings_wide() {
        let sibs: Vec<Vec<u8>> = (0..8u8)
            .map(|i| payload(40_000 + i as usize * 3_000, 0xC0 + i))
            .collect();
        let names: Vec<String> = (0..8).map(|i| format!("sib_{i}.dat")).collect();
        let fpay = payload(180_000, 0xD5);
        let deep = fixtures::rar5_volume(&[("final.bin", fpay.len() as u64, &fpay, false, false)]);
        let mut entries: Vec<(&str, u64, &[u8], bool, bool)> = Vec::new();
        for i in 0..4 {
            entries.push((names[i].as_str(), sibs[i].len() as u64, &sibs[i], false, false));
        }
        entries.push(("deep.rar", deep.len() as u64, &deep, false, false));
        for i in 4..8 {
            entries.push((names[i].as_str(), sibs[i].len() as u64, &sibs[i], false, false));
        }
        let inner1 = fixtures::rar5_volume(&entries);
        let n = inner1.len();
        let (c1, c2) = (n / 3, 2 * n / 3);
        let vols: Vec<Vec<u8>> = vec![
            fixtures::rar5_volume_n(
                &[("inner1.rar", n as u64, &inner1[..c1], false, true)],
                0,
            ),
            fixtures::rar5_volume_n(
                &[("inner1.rar", n as u64, &inner1[c1..c2], true, true)],
                1,
            ),
            fixtures::rar5_volume_n(
                &[("inner1.rar", n as u64, &inner1[c2..], true, false)],
                2,
            ),
        ];
        for (t, order) in [[0usize, 1, 2], [2, 0, 1]].iter().enumerate() {
            let dir = tmpdir(&format!("nestedwide{t}"));
            let ex = Extractor::new(&dir, 3, true);
            for &vi in order {
                feed(&ex, vi, &format!("w{vi}.bin"), &vols[vi], 8000, 120 + vi as u64);
            }
            let rep = ex.finish().unwrap();
            assert!(rep.fallbacks.is_empty(), "order {order:?}: {:?}", rep.fallbacks);
            for (i, s) in sibs.iter().enumerate() {
                assert_eq!(
                    &std::fs::read(dir.join(&names[i])).unwrap(),
                    s,
                    "order {order:?} sib {i}"
                );
            }
            assert_eq!(std::fs::read(dir.join("final.bin")).unwrap(), fpay, "order {order:?}");
            let mut want = names.clone();
            want.push("final.bin".to_string());
            want.sort();
            assert_eq!(dir_files(&dir), want, "order {order:?}");
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    /// Depth memory accounting: an 8 MB payload wrapped 1..5 store
    /// levels deep, fed in order - the chain-wide HoldsBudget peak must
    /// stay far under the cap and must NOT grow with depth (each level
    /// is an offset remap, not a buffered copy). A chased compressed
    /// inner at the same scale reports alongside: its frontier retention
    /// charges the same budget and stays bounded by it, not by the
    /// archive size.
    #[test]
    fn nested_depth_holds_peak_bounded() {
        let data = payload(8 << 20, 0x55);
        let art = 65_536usize;
        let mut rows: Vec<(String, usize)> = Vec::new();
        let mut store_peaks: Vec<usize> = Vec::new();
        for depth in 1..=5usize {
            let mut cur =
                fixtures::rar5_volume(&[("payload.bin", data.len() as u64, &data, false, false)]);
            for k in (1..depth).rev() {
                let name = format!("a{k}.rar");
                cur = fixtures::rar5_volume(&[(name.as_str(), cur.len() as u64, &cur, false, false)]);
            }
            // In-order (the honest-post shape) and shuffled (out-of-order
            // arrival forces real held spans at every level).
            for shuffled in [false, true] {
                let dir = tmpdir(&format!("nestedmem{depth}{}", shuffled as u8));
                let ex = Extractor::new(&dir, 1, true);
                if shuffled {
                    feed(&ex, 0, "outer.rar", &cur, art, 200 + depth as u64);
                } else {
                    for (i, chunk) in cur.chunks(art).enumerate() {
                        ex.write(0, "outer.rar", cur.len() as u64, (i * art) as u64, chunk)
                            .unwrap();
                    }
                }
                let rep = ex.finish().unwrap();
                assert!(rep.fallbacks.is_empty(), "depth {depth}: {:?}", rep.fallbacks);
                assert_eq!(
                    std::fs::read(dir.join("payload.bin")).unwrap(),
                    data,
                    "depth {depth}"
                );
                let peak = ex.holds_peak();
                if shuffled {
                    store_peaks.push(peak);
                    rows.push((format!("store x{depth} shuf"), peak));
                } else {
                    rows.push((format!("store x{depth} seq"), peak));
                }
                std::fs::remove_dir_all(&dir).unwrap();
            }
        }
        // Chased compressed inner at the same scale (~8 MB unpacked,
        // half-entropy input keeps the packed stream near half size).
        {
            let f = noisy(8 << 20, 0x99);
            let inner_arch = rars_compressed_volume(&[("F.bin", &f)]);
            assert_not_store(&inner_arch);
            let outer = fixtures::rar5_volume(&[(
                "inner.rar",
                inner_arch.len() as u64,
                &inner_arch,
                false,
                false,
            )]);
            let dir = tmpdir("nestedmemchase");
            let ex = Extractor::new(&dir, 1, true);
            for (i, chunk) in outer.chunks(art).enumerate() {
                ex.write(0, "outer.rar", outer.len() as u64, (i * art) as u64, chunk)
                    .unwrap();
            }
            let rep = ex.finish().unwrap();
            assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
            assert_eq!(std::fs::read(dir.join("F.bin")).unwrap(), f);
            rows.push(("chase 8 MB".to_string(), ex.holds_peak()));
            std::fs::remove_dir_all(&dir).unwrap();
        }
        println!("shape          holds_peak (bytes)");
        for (tag, p) in &rows {
            println!("{tag:<14} {p:>10}");
        }
        for (tag, p) in &rows {
            assert!(*p < 64 << 20, "{tag}: holds peak {p} breaches 64 MB");
        }
        // Not linear in depth: five levels must not retain per-level
        // copies (linear scaling would add ~8 MB of held payload per
        // extra level; the allowance covers shuffle variance only).
        assert!(
            store_peaks[4] <= store_peaks[0] + (2 << 20),
            "peak grows with depth: {store_peaks:?}"
        );
    }

    // -- nested one-pass phase 3: 7z inner archives via tail prefetch --

    /// In-memory 7z container. `methods: None` keeps the writer's LZMA2
    /// default; `solid` packs every entry into ONE block.
    fn sevenz_archive(
        entries: &[(&str, &[u8])],
        methods: Option<Vec<sevenz_rust2::EncoderConfiguration>>,
        solid: bool,
    ) -> Vec<u8> {
        let mut w = sevenz_rust2::ArchiveWriter::new(std::io::Cursor::new(Vec::new())).unwrap();
        if let Some(m) = methods {
            w.set_content_methods(m);
        }
        if solid {
            let ents: Vec<sevenz_rust2::ArchiveEntry> = entries
                .iter()
                .map(|&(n, _)| sevenz_rust2::ArchiveEntry::new_file(n))
                .collect();
            let readers: Vec<sevenz_rust2::SourceReader<&[u8]>> = entries
                .iter()
                .map(|&(_, d)| sevenz_rust2::SourceReader::new(d))
                .collect();
            w.push_archive_entries(ents, readers).unwrap();
        } else {
            for &(n, d) in entries {
                w.push_archive_entry(sevenz_rust2::ArchiveEntry::new_file(n), Some(d))
                    .unwrap();
            }
        }
        w.finish().unwrap().into_inner()
    }

    /// A store RAR5 single volume wrapping one payload file.
    fn store_outer(name: &str, payload: &[u8]) -> Vec<u8> {
        fixtures::rar5_volume(&[(name, payload.len() as u64, payload, false, false)])
    }

    /// A store outer wrapping an LZMA2 7z: both layers stream - the
    /// final payload lands byte-exact and NEITHER the outer volume NOR
    /// the .7z ever exists on disk. Three feed orders, including the
    /// natural one where the promoted tail arrives dead last.
    #[test]
    fn sevenz_inner_extracts_one_pass() {
        let f = payload(300_000, 101);
        let arch = sevenz_archive(&[("F.bin", &f)], None, false);
        let outer = store_outer("inner.7z", &arch);
        let art = 7000usize;
        let n_arts = outer.len().div_ceil(art);
        let orders: Vec<Vec<usize>> = vec![
            (0..n_arts).collect(),                                // tail arrives last
            (0..n_arts).rev().collect(),                          // tail first, sniff last
            (0..n_arts).map(|i| (i * 7 + 3) % n_arts).collect(),  // scrambled
        ];
        for (t, order) in orders.iter().enumerate() {
            let dir = tmpdir(&format!("7z-onepass{t}"));
            let ex = Extractor::new(&dir, 1, true);
            let mut seen = vec![false; n_arts];
            for &i in order {
                if std::mem::replace(&mut seen[i], true) {
                    continue;
                }
                let s = i * art;
                let e = (s + art).min(outer.len());
                ex.write(0, "v.rar", outer.len() as u64, s as u64, &outer[s..e])
                    .unwrap();
            }
            let rep = ex.finish().unwrap();
            assert!(rep.fallbacks.is_empty(), "order {t}: {:?}", rep.fallbacks);
            assert!(
                rep.extracted
                    .iter()
                    .any(|(n, s)| n == "F.bin" && *s == f.len() as u64),
                "order {t}: {:?}",
                rep.extracted
            );
            assert_eq!(std::fs::read(dir.join("F.bin")).unwrap(), f, "order {t}");
            assert_eq!(dir_files(&dir), vec!["F.bin".to_string()], "order {t}");
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    /// The tail-prefetch handle: classifying the inner 7z calls the
    /// installed promote hook with the archive's end-header range, and
    /// the root's output-range map resolves that same range to outer
    /// volume pieces (the composition promote_output_spans runs on) -
    /// whether the tail arrives last naturally or would have been
    /// promoted ahead.
    #[test]
    fn sevenz_tail_promote_hook() {
        let f = payload(220_000, 102);
        let arch = sevenz_archive(&[("F.bin", &f)], None, false);
        let (ho, hs) = sevenz_start_header(&arch).expect("fixture start header");
        let tail = (32 + ho, 32 + ho + hs);
        let outer = store_outer("inner.7z", &arch);
        for (t, forward) in [true, false].iter().enumerate() {
            let dir = tmpdir(&format!("7z-promote{t}"));
            let ex = Arc::new(Extractor::new(&dir, 1, true));
            type Calls = Arc<Mutex<Vec<(String, u64, Vec<(u64, u64)>)>>>;
            let calls: Calls = Default::default();
            let sink = calls.clone();
            ex.set_promote_hook(Arc::new(move |n: &str, s: u64, sp: &[(u64, u64)]| {
                sink.lock().unwrap().push((n.to_string(), s, sp.to_vec()));
            }));
            let art = 6000usize;
            let n_arts = outer.len().div_ceil(art);
            let order: Vec<usize> = if *forward {
                (0..n_arts).collect()
            } else {
                (0..n_arts).rev().collect()
            };
            for i in order {
                let s = i * art;
                let e = (s + art).min(outer.len());
                ex.write(0, "v.rar", outer.len() as u64, s as u64, &outer[s..e])
                    .unwrap();
            }
            let rep = ex.finish().unwrap();
            assert!(rep.fallbacks.is_empty(), "order {t}: {:?}", rep.fallbacks);
            assert_eq!(std::fs::read(dir.join("F.bin")).unwrap(), f, "order {t}");
            let got = calls.lock().unwrap().clone();
            assert_eq!(
                got,
                vec![("inner.7z".to_string(), arch.len() as u64, vec![tail])],
                "order {t}"
            );
            // The main.rs half of the wiring: the hook's (name, range)
            // resolves through map_output_range to outer volume pieces.
            let pieces = ex.map_output_range("inner.7z", tail.0, tail.1);
            assert!(!pieces.is_empty(), "order {t}: tail range must map");
            let span: u64 = pieces.iter().map(|(_, vs, ve, _)| ve - vs).sum();
            assert_eq!(span, hs, "order {t}: mapped span covers the footer");
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    /// n-deep composition (§3b map_to_root): a 7z at depth 2 under a
    /// store RAR - the promote translates the 7z tail through the mid
    /// archive's mapping, so the root hook sees mid.rar ranges; the
    /// payload still lands one-pass.
    #[test]
    fn sevenz_promote_composes_through_levels() {
        let g = payload(150_000, 103);
        let arch = sevenz_archive(&[("G.bin", &g)], None, false);
        let (ho, hs) = sevenz_start_header(&arch).expect("fixture start header");
        let mid = store_outer("deep.7z", &arch);
        let outer = store_outer("mid.rar", &mid);
        // Where the 7z sits inside mid.rar (the translation the promote
        // walk must apply).
        let data_off = {
            let mut m = VolumeMapper::new(mid.len() as u64);
            m.feed(0, &mid);
            m.entries[0].data_off
        };
        let dir = tmpdir("7z-deep-promote");
        let ex = Arc::new(Extractor::new(&dir, 1, true));
        type Calls = Arc<Mutex<Vec<(String, u64, Vec<(u64, u64)>)>>>;
        let calls: Calls = Default::default();
        let sink = calls.clone();
        ex.set_promote_hook(Arc::new(move |n: &str, s: u64, sp: &[(u64, u64)]| {
            sink.lock().unwrap().push((n.to_string(), s, sp.to_vec()));
        }));
        feed(&ex, 0, "v.rar", &outer, 7000, 44);
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("G.bin")).unwrap(), g);
        assert_eq!(dir_files(&dir), vec!["G.bin".to_string()]);
        let got = calls.lock().unwrap().clone();
        assert_eq!(
            got,
            vec![(
                "mid.rar".to_string(),
                mid.len() as u64,
                vec![(data_off + 32 + ho, data_off + 32 + ho + hs)]
            )],
            "tail must translate through the mid archive's mapping"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Solid multi-file 7z (one block, entries decode in sequence
    /// through the same BlockDecoder pass).
    #[test]
    fn sevenz_solid_multi_file_one_pass() {
        let a = payload(180_000, 104);
        let b = payload(90_000, 105);
        let c = payload(40_000, 106);
        let arch = sevenz_archive(&[("A.bin", &a), ("B.bin", &b), ("C.bin", &c)], None, true);
        let outer = store_outer("inner.7z", &arch);
        let dir = tmpdir("7z-solid");
        let ex = Extractor::new(&dir, 1, true);
        feed(&ex, 0, "v.rar", &outer, 7000, 45);
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("A.bin")).unwrap(), a);
        assert_eq!(std::fs::read(dir.join("B.bin")).unwrap(), b);
        assert_eq!(std::fs::read(dir.join("C.bin")).unwrap(), c);
        assert_eq!(
            dir_files(&dir),
            vec!["A.bin".to_string(), "B.bin".to_string(), "C.bin".to_string()]
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Copy-codec 7z (no compression - the block is an offset remap).
    #[test]
    fn sevenz_copy_codec_one_pass() {
        let f = payload(160_000, 107);
        let arch = sevenz_archive(
            &[("F.bin", &f)],
            Some(vec![sevenz_rust2::EncoderConfiguration::new(
                sevenz_rust2::EncoderMethod::COPY,
            )]),
            false,
        );
        let outer = store_outer("inner.7z", &arch);
        let dir = tmpdir("7z-copy");
        let ex = Extractor::new(&dir, 1, true);
        feed(&ex, 0, "v.rar", &outer, 7000, 46);
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("F.bin")).unwrap(), f);
        assert_eq!(dir_files(&dir), vec!["F.bin".to_string()]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Header-encrypted 7z without a password: the worker fails at the
    /// parse, finish demotes, and the .7z materializes byte-exact for
    /// the disk post-pass - reported as a nested fallback whose wording
    /// never pattern-matches volume-level remediation.
    #[test]
    fn sevenz_encrypted_without_password_demotes() {
        let f = payload(120_000, 108);
        let arch = sevenz_archive(
            &[("F.bin", &f)],
            Some(vec![
                sevenz_rust2::encoder_options::AesEncoderOptions::new(
                    sevenz_rust2::Password::from("secret"),
                )
                .into(),
            ]),
            false,
        );
        let outer = store_outer("inner.7z", &arch);
        let dir = tmpdir("7z-encrypted");
        let ex = Extractor::new(&dir, 1, true);
        feed(&ex, 0, "v.rar", &outer, 7000, 47);
        let rep = ex.finish().unwrap();
        let nested: Vec<_> = rep
            .fallbacks
            .iter()
            .filter(|(_, w)| w.starts_with("nested fallback:"))
            .collect();
        assert_eq!(nested.len(), 1, "{:?}", rep.fallbacks);
        for (_, w) in &rep.fallbacks {
            assert!(
                !w.contains("compressed")
                    && !w.contains("encrypted")
                    && !w.contains("password")
                    && !w.contains("held-bytes cap")
                    && !w.contains("incomplete mapping"),
                "nested reason leaks a volume-remediation trigger: {w}"
            );
        }
        assert_eq!(std::fs::read(dir.join("inner.7z")).unwrap(), arch);
        assert!(!dir.join("F.bin").exists(), "no half-decoded output");
        assert_eq!(dir_files(&dir), vec!["inner.7z".to_string()]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Bytes never arrive: finish() aborts the still-blocked 7z worker
    /// and demotes cleanly - no hang, job Ok, the materialized .7z
    /// carries everything that DID arrive (the lost range stays an
    /// uncovered hole), partial output deleted.
    #[test]
    fn sevenz_missing_bytes_demotes() {
        // noisy: the packed 7z stays large enough that a whole article
        // sits inside its bytes.
        let f = noisy(300_000, 109);
        let arch = sevenz_archive(&[("F.bin", &f)], None, false);
        assert!(arch.len() > 10_000, "packed too small: {}", arch.len());
        let outer = store_outer("inner.7z", &arch);
        let data_off = {
            let mut m = VolumeMapper::new(outer.len() as u64);
            m.feed(0, &outer);
            m.entries[0].data_off as usize
        };
        let art = 1000usize;
        let lost = (data_off / art) + 2; // fully inside the 7z bytes
        let (ls, le) = (lost * art, ((lost + 1) * art).min(outer.len()));
        let dir = tmpdir("7z-missing");
        let ex = Extractor::new(&dir, 1, true);
        for i in 0..outer.len().div_ceil(art) {
            if i == lost {
                continue;
            }
            let s = i * art;
            let e = (s + art).min(outer.len());
            ex.write(0, "v.rar", outer.len() as u64, s as u64, &outer[s..e])
                .unwrap();
        }
        let rep = ex.finish().unwrap();
        assert!(
            rep.fallbacks
                .iter()
                .any(|(_, w)| w.starts_with("nested fallback:")),
            "{:?}",
            rep.fallbacks
        );
        assert!(!dir.join("F.bin").exists(), "partial 7z output survived");
        let got = std::fs::read(dir.join("inner.7z")).unwrap();
        let mut expect = arch.clone();
        expect[ls - data_off..le - data_off].fill(0);
        assert_eq!(got, expect);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Budget breach mid-chase: the retained 7z bytes charge the SHARED
    /// holds budget, and crossing the cap demotes to a materialized .7z
    /// - complete and byte-exact, partial output deleted.
    #[test]
    fn sevenz_budget_breach_demotes() {
        let f = noisy(2_400_000, 110);
        let arch = sevenz_archive(&[("F.bin", &f)], None, false);
        assert!(arch.len() > 900_000, "packed too small: {}", arch.len());
        let outer = store_outer("inner.7z", &arch);
        let dir = tmpdir("7z-budget");
        let ex = Extractor::new(&dir, 3, true);
        ex.set_holds_cap(1); // floors at 8 MB
        let junk = payload(65_000, 111);
        for slot in [1usize, 2] {
            for i in 0..60u64 {
                ex.write(slot, &format!("dummy{slot}.bin"), 8_000_000, 64_000 + i * 65_000, &junk)
                    .unwrap();
            }
        }
        for (i, chunk) in outer.chunks(50_000).enumerate() {
            ex.write(0, "v.rar", outer.len() as u64, (i * 50_000) as u64, chunk)
                .unwrap();
        }
        let rep = ex.finish().unwrap();
        assert!(
            rep.fallbacks
                .iter()
                .any(|(_, w)| w.starts_with("nested fallback:")),
            "{:?}",
            rep.fallbacks
        );
        assert_eq!(std::fs::read(dir.join("inner.7z")).unwrap(), arch);
        assert!(!dir.join("F.bin").exists(), "partial 7z output survived");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Multipart `.7z.001` inner set (v1 limitation): the part's start
    /// header points past its own bytes, so the chase declines and the
    /// part materializes Plain - today's output, the disk post-pass
    /// joins and extracts the set.
    #[test]
    fn sevenz_multipart_part_declines_to_materialize() {
        let f = payload(200_000, 112);
        let arch = sevenz_archive(&[("F.bin", &f)], None, false);
        let half = arch.len() / 2;
        let outer = store_outer("inner.7z.001", &arch[..half]);
        let dir = tmpdir("7z-multipart");
        let ex = Extractor::new(&dir, 1, true);
        feed(&ex, 0, "v.rar", &outer, 7000, 48);
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("inner.7z.001")).unwrap(), &arch[..half]);
        assert_eq!(dir_files(&dir), vec!["inner.7z.001".to_string()]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The 7z gates: NZBFAST_NO_NESTED_7Z=1 parses as off, and the
    /// runtime setter drives the same latch - with it off, an inner .7z
    /// materializes exactly as before the 7z path existed (nested
    /// routing itself stays on). The env PARSE is asserted on the pure
    /// helper for the same parallel-runner reason as
    /// `nested_disabled_by_env`.
    #[test]
    fn sevenz_disabled_by_env() {
        assert!(sevenz_env_off_value(Some("1")));
        assert!(!sevenz_env_off_value(Some("0")));
        assert!(!sevenz_env_off_value(None));

        let f = payload(140_000, 113);
        let arch = sevenz_archive(&[("F.bin", &f)], None, false);
        let outer = store_outer("inner.7z", &arch);
        let dir = tmpdir("7z-gate");
        let ex = Extractor::new(&dir, 1, true);
        assert!(ex.inner.lock().unwrap().sevenz_on, "gate must default on");
        ex.set_nested_sevenz(false);
        feed(&ex, 0, "v.rar", &outer, 7000, 49);
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("inner.7z")).unwrap(), arch);
        assert!(!dir.join("F.bin").exists());
        assert_eq!(dir_files(&dir), vec!["inner.7z".to_string()]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Cancel semantics: dropping an extractor mid-7z-chase aborts the
    /// buffer and the worker exits - the drop returns instead of
    /// hanging on bytes that will never arrive.
    #[test]
    fn sevenz_worker_exits_on_extractor_drop() {
        let f = noisy(300_000, 114);
        let arch = sevenz_archive(&[("F.bin", &f)], None, false);
        let outer = store_outer("inner.7z", &arch);
        assert!(outer.len() > 4000, "fixture too small: {}", outer.len());
        let dir = tmpdir("7z-drop");
        let ex = Extractor::new(&dir, 1, true);
        // Enough for the sniff + 7z attach, then abandon the job.
        ex.write(0, "v.rar", outer.len() as u64, 0, &outer[..4000])
            .unwrap();
        drop(ex);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The blocking random-access read the 7z adapter stands on: parked
    /// tail bytes are readable long before the frontier reaches them,
    /// a hole blocks until its span lands, and abort wakes with an
    /// error.
    #[test]
    fn frontier_buffer_random_access_blocking() {
        let buf = Arc::new(FrontierBuffer::new(30));
        buf.write_span(20, &[7u8; 10]);
        // Parked tail serves immediately - no frontier needed.
        let mut out = [0u8; 10];
        assert_eq!(buf.read_covered_blocking(20, &mut out).unwrap(), 10);
        assert_eq!(out, [7u8; 10]);
        // A hole blocks until the covering span arrives.
        let reader = Arc::clone(&buf);
        let h = std::thread::spawn(move || {
            let mut b = [0u8; 5];
            let n = reader.read_covered_blocking(10, &mut b).unwrap();
            (n, b)
        });
        std::thread::sleep(std::time::Duration::from_millis(20));
        buf.write_span(10, &[3u8; 10]);
        let (n, b) = h.join().unwrap();
        assert!(n >= 1 && b[..n] == [3u8; 5][..n]);
        // Past the declared end: clean EOF.
        let mut b = [0u8; 4];
        assert_eq!(buf.read_covered_blocking(30, &mut b).unwrap(), 0);
        // Abort wakes a blocked reader with an error.
        let buf2 = Arc::new(FrontierBuffer::new(10));
        let r2 = Arc::clone(&buf2);
        let h2 = std::thread::spawn(move || {
            let mut b = [0u8; 4];
            r2.read_covered_blocking(0, &mut b)
        });
        std::thread::sleep(std::time::Duration::from_millis(20));
        buf2.abort("test cancel");
        assert!(h2.join().unwrap().is_err());
    }
}

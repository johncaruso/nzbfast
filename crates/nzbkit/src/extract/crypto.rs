//! Encrypted-store crypto: the per-entry AES state machine, the
//! in-stream (plaintext-once) decrypt path with its journal events
//! and chain checkpoints, the legacy finish()-time decrypt pass with
//! its scratch temps and shards, password probing/awaits, and the
//! /stream ciphertext reader.
//!
//! Split out of the 19,920-line `extract.rs` under the TODO 43
//! recipe: a verbatim move, not a redesign.

use super::*;
use crate::sync::MutexExt;

// ---------------------------------------------------------------------------
// Encrypted-store streaming: decrypt on the fly while the file is still
// ciphertext, and flip to raw reads once finish() has decrypted it.
// ---------------------------------------------------------------------------

/// Lifecycle of one encrypted output file, shared between the finish()
/// decrypt pass and any live /stream readers.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum DecState {
    /// On-disk bytes are AES-CBC ciphertext (during/after download,
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

pub(super) struct StreamState {
    pub(super) state: Mutex<DecState>,
    /// Live on-the-fly-decrypting readers. Their fds stay on the
    /// ciphertext inode across the finish decrypt's publish rename, so
    /// they keep serving correct bytes until the last one drops.
    pub(super) readers: AtomicUsize,
}

/// Random-access CBC decryptor handed to a /stream reader for an
/// encrypted output file. Holds a live-reader lease (released on drop);
/// while it exists, finish() will temp+rename rather than decrypt the
/// file in place, so the reader's captured fd stays valid.
pub struct StreamCrypt {
    pub(super) key: rarcrypt::AesKey,
    pub(super) iv: [u8; 16],
    /// On-disk ciphertext length = align16(plain_len).
    pub(crate) cipher_len: u64,
    /// Plaintext length the reader exposes (Content-Length).
    pub plain_len: u64,
    pub(super) st: Arc<StreamState>,
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

/// Chain-checkpoint stride for in-stream decrypted files (multiple of
/// 16). One 16-byte cipher block is kept per stride, bounding the
/// posted-bytes shim's worst-case re-encrypt walk; ~1 MB of checkpoints
/// per 60 GB file.
pub(super) const CRYPTO_CHUNK: u64 = 1 << 20;

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
pub(super) type CryptoEventSink = Arc<Mutex<Vec<CryptoJournalEvent>>>;

/// One encrypted store output being decrypted in-stream. Owned by the
/// level's `Inner` (keyed by output name), shared into `WriteJob`s so
/// the AES work runs outside the routing lock under this state's own
/// How a decrypted file's stored checksum is compared against the CRC32
/// composed from its plaintext (Increment B).
///
/// `hash_key` absent is WinRAR's default: the stored value IS a plain
/// CRC32 of the plaintext. Present means the crypt record set the
/// tweaked-checksum flag (0x02) and the stored value is the keyed fold
/// of that CRC - which the download can still verify, because deriving
/// `hash_key` needs only the password we are decrypting with. Folding
/// the computed CRC and comparing checks the same two things a plain
/// comparison does (the key is right, the plaintext is intact), so a
/// tweaked entry is no longer un-verifiable and no longer has to be
/// handed to unrar.
#[derive(Clone, Copy)]
pub(super) struct CrcGate {
    pub(super) stored: u32,
    pub(super) hash_key: Option<[u8; 32]>,
}

impl CrcGate {
    /// The stored checksum as this gate compares it: plain, or the
    /// keyed fold of `computed`.
    pub(super) fn accepts(&self, computed: u32) -> bool {
        match &self.hash_key {
            None => computed == self.stored,
            Some(hk) => rarcrypt::mac_crc32_with_key(hk, computed) == self.stored,
        }
    }
}

/// Build the gate for an encrypted entry: `None` when nothing is
/// checkable (no stored CRC, or a split entry whose stored CRC covers
/// only the last piece), else plain or keyed per the tweaked flag.
pub(super) fn crc_gate(
    file_crc: Option<u32>,
    c: &EntryCrypt,
    keys: &rarcrypt::EntryKeys,
) -> Option<CrcGate> {
    file_crc.map(|stored| CrcGate {
        stored,
        // RAR4 has no tweaked-checksum flag: its header CRC is always the
        // bare plaintext CRC32, so the gate compares it directly.
        hash_key: c.tweaked_checksum().then_some(keys.hash_key).flatten(),
    })
}

/// per-file mutex.
pub(super) struct CryptoState {
    pub(super) key: rarcrypt::AesKey,
    pub(super) iv: [u8; 16],
    /// Plaintext length (the head entry's `unpacked_size`).
    pub(super) unp: u64,
    /// Posted ciphertext length = align16(unp).
    pub(super) cipher_len: u64,
    /// Stored plaintext checksum when checkable (single-piece entry);
    /// verified at finish from the composed runs, through the keyed fold
    /// when the entry's checksum is tweaked.
    pub(super) expect_crc: Option<CrcGate>,
    /// Output name + shared sink for the resume-journal events.
    pub(super) out_name: String,
    pub(super) events: CryptoEventSink,
    pub(super) st: Mutex<CryptoSt>,
}

#[derive(Default)]
pub(super) struct CryptoSt {
    /// Contiguous ciphertext runs received, keyed by cipher start.
    /// Cipher offsets equal output-file offsets (store mapping), so one
    /// coordinate space serves both views.
    pub(super) runs: BTreeMap<u64, CryptoRun>,
    /// Chunk boundary c -> cipher block [c-16, c), captured from the
    /// wire as spans stream past. Pure posted bytes; repair refreshes
    /// any it overwrites.
    pub(super) checkpoints: HashMap<u64, [u8; 16]>,
    /// Plaintext CRC composition (maintained only when expect_crc is
    /// set - otherwise it would be a pure extra pass).
    pub(super) plain: CrcRuns,
    /// Plaintext of the final cipher block beyond `unp` (the <=15
    /// padding bytes). Never written to disk; required to re-encrypt
    /// the last block byte-exactly.
    pub(super) tail_pad: Vec<u8>,
    pub(super) tail_done: bool,
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
pub(super) struct CryptoRun {
    pub(super) end: u64,
    pub(super) p_lo: u64,
    pub(super) p_hi: u64,
    pub(super) head: Vec<u8>,
    pub(super) tail: Vec<u8>,
}

impl CryptoRun {
    pub(super) fn decrypted(&self) -> bool {
        self.p_hi > self.p_lo || (self.p_lo == 0 && self.p_hi == 0 && self.head.is_empty())
    }
}

impl CryptoState {
    pub(super) fn new(
        key: rarcrypt::AesKey,
        iv: [u8; 16],
        unp: u64,
        expect_crc: Option<CrcGate>,
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
    pub(super) fn advance(
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
        self.events
            .lock()
            .unwrap()
            .push(CryptoJournalEvent::Checkpoint {
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
            self.events
                .lock()
                .unwrap()
                .push(CryptoJournalEvent::Checkpoint {
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
            self.events
                .lock()
                .unwrap()
                .push(CryptoJournalEvent::TailPad {
                    name: self.out_name.clone(),
                    pad: st.tail_pad.clone(),
                });
        }
        Ok(full as u64)
    }

    /// Build a standalone run for novel cipher `[at, at+cipher.len())`,
    /// decrypting whatever its own bytes allow. Neighbor seams are the
    /// caller's job (`merge_at`).
    pub(super) fn fresh_run(
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
                CryptoRun {
                    end,
                    p_lo: 0,
                    p_hi: 0,
                    head: cipher.to_vec(),
                    tail: Vec::new(),
                }
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
        let chain: [u8; 16] = cipher[(p_lo - 16 - at) as usize..(p_lo - at) as usize]
            .try_into()
            .unwrap();
        let done = self.advance(st, w, chain, p_lo, &cipher[(p_lo - at) as usize..], false)?;
        Ok(if done == 0 {
            CryptoRun {
                end,
                p_lo: at,
                p_hi: at,
                head: cipher.to_vec(),
                tail: Vec::new(),
            }
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
    pub(super) fn merge_at(&self, st: &mut CryptoSt, w: &FileWriter, mid: u64) -> io::Result<()> {
        let Some((&ls, _)) = st.runs.range(..mid).next_back() else {
            return Ok(());
        };
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
                (
                    left.tail[..16].try_into().unwrap(),
                    left.p_hi,
                    left.tail[16..].to_vec(),
                )
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
    pub(super) fn ingest(&self, w: &FileWriter, at: u64, data: &[u8]) -> io::Result<()> {
        let mut st = self.st.lock_ok();
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
    pub(super) fn plain_on_disk(&self, at: u64, len: u64) -> bool {
        if len == 0 {
            return true;
        }
        let st = self.st.lock_ok();
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
    pub(super) fn covers(&self, at: u64, len: u64) -> bool {
        if len == 0 {
            return true;
        }
        let st = self.st.lock_ok();
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
    pub(super) fn intervals(&self, at: u64, len: u64) -> Vec<(u64, u64)> {
        let st = self.st.lock_ok();
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
    pub(super) fn complete(&self) -> bool {
        let st = self.st.lock_ok();
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
    pub(super) fn crc_verdict(&self) -> Option<bool> {
        let gate = self.expect_crc?;
        let st = self.st.lock_ok();
        let got = st.plain.whole(self.unp)?;
        Some(gate.accepts(got))
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
    pub(super) fn patch(&self, w: &FileWriter, at: u64, data: &[u8]) -> io::Result<()> {
        let holes = {
            let mut st = self.st.lock_ok();
            self.patch_locked(&mut st, w, at, data)?
        };
        // Ranges nobody had yet are ordinary posted bytes wherever they
        // come from - ingest them (re-locks per range).
        for (s, e) in holes {
            self.ingest(w, s, &data[(s - at) as usize..(e - at) as usize])?;
        }
        Ok(())
    }

    pub(super) fn patch_locked(
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
                let stash = if is_head {
                    &mut run.head
                } else {
                    &mut run.tail
                };
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
    pub(super) fn read_posted(&self, w: &FileWriter, at: u64, out: &mut [u8]) -> io::Result<()> {
        let st = self.st.lock_ok();
        self.read_posted_locked(&st, w, at, out)
    }

    pub(super) fn read_posted_locked(
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
                    _ => (
                        run.head[run.head.len() - 16..].try_into().unwrap(),
                        run.p_lo,
                    ),
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
    pub(super) fn read_plain_block(
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

/// Increment A: how often the candidate-password probe re-runs while
/// slots sit parked. The sidecar carrying the password usually lands
/// within the head round, seconds after the archive blocks; probing on
/// this cadence (piggybacked on span arrivals, off the routing lock)
/// re-keys the mapper while the holds are still small. The hook itself
/// dedupes candidates, so a quiet directory costs a directory scan, not
/// repeated KDFs.
pub(super) const PW_REPROBE_EVERY: std::time::Duration = std::time::Duration::from_millis(750);

/// Same-directory scratch prefix for the finish decrypt. The leading
/// `.nzbfast` is the established internal-scratch marker (the cleanup
/// walkers and the keep-media-only sweep already skip those names), and
/// pid + counter make each name unique to one pass of one process.
pub(super) const DEC_TMP_PREFIX: &str = ".nzbfast-dec.";

/// Create the decrypt scratch file for one output. `create_new` is what
/// makes the name provably OURS: it can never adopt a stale file's bytes
/// and never be shared with another process. The reason it matters here is
/// the third one - it can never alias a legitimate archive member, which a
/// deterministic sibling name like `movie.mkv.nzbdec.tmp` could (an archive
/// is free to contain that name, and truncating it would destroy real
/// output). A taken name just bumps the counter.
pub(super) fn create_decrypt_temp(dir: &Path) -> io::Result<(PathBuf, File)> {
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

/// Gather the resume-journal facts for one finish-decrypted output while
/// `src` still holds the ciphertext (the rename destroys it): the `E`
/// params from the entry's crypt record, a `K` chain checkpoint per
/// [`CRYPTO_CHUNK`] stride read straight off the posted bytes, and the
/// `T` tail pad - the final block's plaintext beyond `unp`, without
/// which that block can never re-encrypt byte-exactly.
///
/// `None` is always safe: the publish notification is simply skipped and
/// a retry refetches, the pre-existing behaviour. That covers RAR4 (its
/// 8-byte salt and SHA-1 schedule do not fit the `E` grammar), a
/// check-less RAR5 set (a resume could never PROVE the password before
/// re-encrypting, so it would refuse these records anyway), and any
/// read error here.
fn collect_decrypt_facts(
    src: &Path,
    crypt: &crate::rar::EntryCrypt,
    out: &str,
    unp: u64,
    key: &rarcrypt::AesKey,
) -> Option<Vec<CryptoJournalEvent>> {
    let c5 = crypt.rar5()?;
    c5.check?;
    let rf = File::open(src).ok()?;
    let cipher_len = rarcrypt::align16(unp);
    let mut evs = vec![CryptoJournalEvent::Params {
        name: out.to_string(),
        salt: c5.salt,
        lg2: c5.lg2_count,
        iv: c5.iv,
        unp,
        check: c5.check,
    }];
    // CBC decryption of a block needs only the cipher block before it,
    // so a checkpoint is a plain 16-byte read - no chain walk.
    let mut off = CRYPTO_CHUNK;
    while off <= cipher_len {
        let mut block = [0u8; 16];
        crate::disk::read_exact_at(&rf, &mut block, off - 16).ok()?;
        evs.push(CryptoJournalEvent::Checkpoint {
            name: out.to_string(),
            off,
            block,
        });
        off += CRYPTO_CHUNK;
    }
    let pad = if unp == cipher_len {
        Vec::new()
    } else {
        // Decrypt the final block once more: the scratch was truncated
        // to `unp`, so its beyond-`unp` plaintext exists nowhere else.
        let mut prev = c5.iv;
        if cipher_len >= 32 {
            crate::disk::read_exact_at(&rf, &mut prev, cipher_len - 32).ok()?;
        }
        let mut last = [0u8; 16];
        crate::disk::read_exact_at(&rf, &mut last, cipher_len - 16).ok()?;
        rarcrypt::CbcStream::new(key, &prev).decrypt(&mut last);
        last[(unp % 16) as usize..].to_vec()
    };
    evs.push(CryptoJournalEvent::TailPad {
        name: out.to_string(),
        pad,
    });
    Some(evs)
}

/// TODO 100 test rig: `NZBFAST_DECRYPT_ENOSPC_ONCE=pre|post` makes the
/// finish decrypt fail ONCE per process with a disk-full error - before
/// any ciphertext is touched (`pre`), or after every publish landed
/// (`post`, the exact journal state an unpack-stage failure after a
/// successful decrypt leaves behind). The daemon retry e2e asserts the
/// second attempt refetches ~nothing.
fn injected_decrypt_enospc(stage: &str) -> Option<io::Error> {
    use std::sync::atomic::AtomicBool;
    static FIRED: AtomicBool = AtomicBool::new(false);
    if std::env::var("NZBFAST_DECRYPT_ENOSPC_ONCE").ok().as_deref() == Some(stage)
        && !FIRED.swap(true, Ordering::Relaxed)
    {
        return Some(io::Error::new(
            io::ErrorKind::StorageFull,
            "injected decrypt disk-full (NZBFAST_DECRYPT_ENOSPC_ONCE)",
        ));
    }
    None
}

/// Remove decrypt scratch left behind by a killed run.
pub(super) fn sweep_decrypt_temps(dir: &Path) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        if e.file_name().to_string_lossy().starts_with(DEC_TMP_PREFIX) {
            let _ = std::fs::remove_file(e.path());
        }
    }
}

/// One AES-CBC pass over the ciphertext at `src` (length =
/// align16(`unp`)): decrypt into the caller's scratch handle `wf` and
/// truncate it to `unp`. `src` is only ever READ - see
/// [`Extractor::decrypt_finished`] for why nothing may mutate it before
/// the journal has stopped vouching for it.
///
/// When `expect_crc` is set, the decrypted bytes are CRC32'd as they
/// stream past and checked at the end - directly against a plain stored
/// CRC32, or through the keyed fold for a tweaked checksum.
/// This catches ciphertext that was damaged before posting - the outer
/// yEnc/PAR2 verify the archive as-posted and the password-check only
/// proves the key, so without this the corrupt plaintext would be written
/// out as success. A mismatch is a hard error, and since it is raised
/// before the scratch is ever published, the ciphertext output survives
/// intact for a fallback or a resume.
pub(super) fn decrypt_pass(
    src: &Path,
    wf: &File,
    key: &rarcrypt::AesKey,
    iv: &[u8; 16],
    unp: u64,
    expect_crc: Option<CrcGate>,
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
    if expect_crc.is_some_and(|gate| !gate.accepts(crc)) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "encrypted RAR file failed its stored CRC after decryption",
        ));
    }
    Ok(())
}

/// Ciphertext below this stays on one thread: the shard IV reads and the
/// scattered writes cost more than the parallelism returns.
pub(super) const DECRYPT_PARALLEL_MIN: u64 = 32 << 20;

/// Ceiling on shards per file. Each holds a 4 MiB scratch buffer, and the
/// pass is read/write bound well before this on any disk a NAS ships with.
pub(super) const DECRYPT_MAX_SHARDS: usize = 8;

/// Decrypt `[start, end)` of the ciphertext into the same offsets of `wf`,
/// seeded from `iv`. Returns the CRC32 of the plaintext bytes it wrote that
/// lie below `unp` (the 16-byte alignment padding beyond `unp` is not part
/// of the file and never enters the CRC).
#[allow(clippy::too_many_arguments)]
pub(super) fn decrypt_shard(
    rf: &File,
    wf: &File,
    key: &rarcrypt::AesKey,
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

/// Every check field the plaintext-once route decision reads, resolved
/// across a whole inner FILE.
///
/// The route is latched per OUTPUT name (`crypto_files`) by whichever
/// fragment asks first, so a decision that reads its check fields off the
/// fragment in front of the writer can latch on a head and disagree with
/// its own tail. See [`Extractor::instream_decrypt_allowed`].
struct FileChecks {
    /// Some piece of the file refuses the plaintext-once route: it is
    /// unencrypted, or its crypt record is RAR4 or check-less (nothing
    /// proves the password before a byte is decrypted), or it states a
    /// plaintext digest this build cannot compute with no CRC32 beside
    /// it (`rar a -htb`, whose output nothing here could adjudicate).
    vetoed: bool,
    /// (slot, entry) of the head piece - `split_before` clear, the record
    /// whose IV starts the stream and which [`Extractor::crypto_for`]
    /// keys the whole file with. `None` while the head volume's headers
    /// are still in flight.
    head: Option<(usize, usize)>,
}

impl Extractor {
    /// Drain the chain's pending resume-journal crypto events (`E`/`K`/
    /// `T` facts - see [`CryptoJournalEvent`]). The caller writes them to
    /// the journal alongside the `D` placement records.
    pub fn drain_crypto_events(&self) -> Vec<CryptoJournalEvent> {
        let sink = self.inner.lock_ok().crypto_events.clone();
        let mut ev = sink.lock_ok();
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
        frags
            .iter()
            .map(|f| self.find_crypto(&f.file).is_some())
            .collect()
    }

    pub(super) fn find_crypto(&self, name: &str) -> Option<Arc<CryptoState>> {
        let inner = self.inner_read();
        if let Some(cs) = inner.crypto_files.get(name) {
            return Some(cs.clone());
        }
        let child = inner.child.clone();
        drop(inner);
        child.and_then(|c| c.find_crypto(name))
    }

    /// Increment A: park a password-blocked slot instead of demoting it,
    /// while the candidate probe may still turn up the password. Returns
    /// true when the span was taken (held); false hands the blocker back
    /// to the demote path unchanged.
    ///
    /// Eligible only when a probe hit could actually rescue the slot:
    /// the hook is installed (root level - children never get one), the
    /// blocker is password-shaped rather than structural, and the
    /// archive carries a WELLFORMED stored check - without one no
    /// candidate can ever verify (that shape needs the tweaked-MAC gate,
    /// Increment B) and awaiting would just burn budget until finish.
    ///
    /// Held spans stay fully live: `read_at`/`covered` serve holds, so
    /// settle read-back and mapped PAR2 repair see the bytes; a repair
    /// span for a parked slot parks BEHIND the original in `holds`, and
    /// the ordered re-feed keeps last-writer-wins intact.
    pub(super) fn try_pw_await(
        &self,
        inner: &mut Inner,
        slot: usize,
        b: &MapBlocker,
        offset: u64,
        data: &[u8],
    ) -> io::Result<bool> {
        if inner.slots[slot].pw_await.is_none() {
            // First span since the blocker fired: decide eligibility once.
            if self.depth != 0
                || inner.pw_probe.is_none()
                || inner.protect_sources
                || !matches!(inner.slots[slot].mode, SlotMode::Rar)
            {
                return Ok(false);
            }
            let probeable = match b {
                // Headers opaque, or the start password failed its check:
                // the type-4 block's params are captured either way.
                // Encrypted store entries with no password at all: the
                // exact shape a found candidate rescues. (Compressed
                // entries return NotStore before the encryption check, so
                // this variant is store-method by construction; a RAR4
                // encrypted entry also lands here but has no RAR5 crypt
                // params, which the wellformed-check gate below filters.)
                MapBlocker::EncryptedHeaders
                | MapBlocker::BadPassword
                | MapBlocker::EncryptedNoPassword => true,
                // "Compressed or encrypted entries": only the encrypted
                // STORE flavor is rescuable - a password makes it
                // mappable. A compressed entry stays blocked with the
                // password in hand, so it goes to the chase/demote path.
                MapBlocker::NotStore => inner.slots[slot].mapper.as_ref().is_some_and(|m| {
                    m.entries
                        .last()
                        .is_some_and(|e| e.encrypted && matches!(e.method, Method::Store))
                }),
                _ => return Ok(false),
            };
            let has_check = probeable
                && inner.slots[slot]
                    .mapper
                    .as_ref()
                    .and_then(|m| m.crypt_probe_params())
                    .and_then(|p| p.check)
                    .is_some_and(|c| crate::rarcrypt::check_is_wellformed(&c));
            if !has_check {
                return Ok(false);
            }
            inner.slots[slot].pw_await = Some(blocker_reason(b));
            inner.pw_probe_due = true;
        }
        // Park the span. The header-region part of it is already in the
        // stash (retain_header_bytes ran before the blocker arm), so that
        // overlap is briefly double-charged - headers only, released with
        // whichever copy drops first, and both the fallback materialize
        // and a re-keyed re-parse tolerate the duplicate bytes.
        inner.budget.add(data.len());
        inner.slots[slot]
            .holds
            .push((offset, HoldSpan::Ram(data.to_vec())));
        // Parked ciphertext is cold until a probe hit or finish, so it
        // pages to scratch beyond a small window instead of riding RAM
        // to the holds cap (see `pw_await_spill`). A probe hit re-feeds
        // paged spans off disk through `reclaim_span`, and the finish
        // demote materializes them into volumes the same way.
        if inner.budget.len() > pw_await_spill(inner.budget.cap()) {
            self.page_pw_holds(inner, slot);
        }
        if inner.budget.over() && !self.page_out_holds(inner) {
            // Same arbiter as every other hold. Demote with the ORIGINAL
            // blocker's reason so the finish ladder's remediation (the
            // "encrypted"/"password" keying) is exactly what it would
            // have been without the wait.
            let reason = inner.slots[slot].pw_await.take().unwrap();
            self.fallback_slot_or_group(inner, slot, reason)?;
        }
        Ok(true)
    }

    /// Run the candidate probe for parked slots, off the routing lock
    /// (the hook does PBKDF2 work). `force` ignores the re-probe cadence
    /// - the finish path's last chance, when every sidecar has landed.
    /// On a hit the password applies under the lock and the parked slots
    /// re-key; the re-feeds may queue child forwards, so this flushes
    /// them like every other public entry point that re-feeds holds.
    pub(super) fn flush_pw_probe(&self, force: bool) -> io::Result<()> {
        let (hook, probes) = {
            let mut g = self.inner.lock_ok();
            let inner = &mut *g;
            let Some(hook) = inner.pw_probe.clone() else {
                return Ok(());
            };
            let due = force
                || inner.pw_probe_due
                || inner
                    .pw_probe_last
                    .is_none_or(|t| t.elapsed() >= PW_REPROBE_EVERY);
            if !due {
                return Ok(());
            }
            let mut probes: Vec<crate::rar::CryptProbe> = Vec::new();
            for s in &inner.slots {
                if s.pw_await.is_none() {
                    continue;
                }
                if let Some(p) = s.mapper.as_ref().and_then(|m| m.crypt_probe_params()) {
                    // One salt per archive; a multi-set job contributes
                    // one probe per distinct salt.
                    if !probes.contains(&p) {
                        probes.push(p);
                    }
                }
            }
            if probes.is_empty() {
                return Ok(());
            }
            inner.pw_probe_due = false;
            inner.pw_probe_last = Some(std::time::Instant::now());
            (hook, probes)
        };
        for p in &probes {
            if let Some(pw) = hook(p) {
                self.apply_probed_password(&pw)?;
                self.flush_pending_fwd()?;
                break;
            }
        }
        Ok(())
    }

    /// A probe candidate VERIFIED against some parked archive: install
    /// it and re-key every parked slot whose own stored check accepts it
    /// (two encrypted sets in one job may want different passwords - the
    /// others keep waiting for a later candidate). Re-keying is a fresh
    /// mapper plus a re-feed of everything retained; the parse runs
    /// exactly as if the password had been known at classification.
    pub(super) fn apply_probed_password(&self, pw: &str) -> io::Result<()> {
        let mut g = self.inner.lock_ok();
        let inner = &mut *g;
        inner.password = Some(std::sync::Arc::from(pw));
        for slot in 0..inner.slots.len() {
            if inner.slots[slot].pw_await.is_none() {
                continue;
            }
            let verified = inner.slots[slot]
                .mapper
                .as_ref()
                .and_then(|m| m.crypt_probe_params())
                .is_some_and(|p| p.verify(pw) == crate::rar::PwVerdict::Verified);
            if !verified {
                continue;
            }
            inner.slots[slot].pw_await = None;
            let size = inner.slots[slot].size;
            inner.slots[slot].mapper =
                Some(VolumeMapper::with_password(size, inner.password.clone()));
            // Feed the stash back through the keyed mapper. Uncharge
            // first: the re-parse re-stashes whatever is still header
            // (and maps the rest), so leaving the old charge would
            // double-bill every stashed byte.
            let headers = std::mem::take(&mut inner.slots[slot].header_spans);
            for (off, span) in headers {
                let bytes = Self::reclaim_span(inner, span)?;
                self.rar_span(inner, slot, off, &bytes, None, false, None)?;
            }
            self.drain_holds(inner, slot)?;
            println!(
                "🔑 candidate password unlocked {} in-stream",
                inner.slots[slot].name
            );
        }
        Ok(())
    }

    /// Finish-time resolution for Increment A: one forced probe (every
    /// sidecar is on disk by now), then any slot still parked demotes
    /// with its original blocker reason - the exact outcome the await
    /// deferred, so the report and the ladder see nothing new.
    pub(super) fn resolve_pw_awaits(&self) -> io::Result<()> {
        self.flush_pw_probe(true)?;
        {
            let mut g = self.inner.lock_ok();
            let inner = &mut *g;
            for slot in 0..inner.slots.len() {
                if let Some(reason) = inner.slots[slot].pw_await.take() {
                    self.fallback_slot_or_group(inner, slot, reason)?;
                }
            }
        }
        self.flush_pending_fwd()
    }

    /// May this encrypted entry decrypt at WRITE time (plaintext-once),
    /// or must it assemble ciphertext for the finish pass?
    ///
    /// Only when the file's stored check verifies the password. Without
    /// that proof (a check-less set, or one whose check is malformed and
    /// so vetoes nothing) a wrong password would write plaintext-shaped
    /// garbage straight into the output file, and the group could no
    /// longer materialize its volumes - the inner file is supposed to BE
    /// the volume bytes, and it would hold decrypted-with-the-wrong-key
    /// noise instead. Assembling ciphertext keeps the bytes identical to
    /// the posted volumes, so `decrypt_finished` can adjudicate against
    /// the whole-file checksum and, on a miss, demote with nothing lost.
    ///
    /// ONE ANSWER PER FILE, and never veto-then-allow. `crypto_files`
    /// caches the route by OUTPUT name and the first fragment to ask
    /// latches it for the whole file, so fragments that disagree would
    /// route half an output each way - and a half-plaintext file cannot
    /// be turned back into byte-exact volumes by the fallback shim. Two
    /// rules keep that unreachable:
    ///
    /// 1. Every check field consulted here is resolved across the whole
    ///    file by [`FileChecks`], which walks every mapped piece in the
    ///    group. None is read off the fragment in front of the writer.
    ///    Only the tail piece carries the whole-file checks, so reading
    ///    them off a head answered "allowed" for a split hash-only set
    ///    (Codex sweep 12 Aug F2) - and the same trap waits for any
    ///    per-file check field added later.
    /// 2. An output that already holds bytes with no `CryptoState`
    ///    behind it holds CIPHERTEXT, and may never latch plaintext-once
    ///    afterwards. Rule 1 makes the fields agree; rule 2 is what makes
    ///    a MIXED output impossible even where they cannot. It covers
    ///    what rule 1 does not: the live password cell, which a
    ///    mid-download re-key can flip from veto to allow under a file
    ///    already assembling ciphertext, and whatever the next field
    ///    turns out to be.
    ///
    /// What the two rules do NOT buy is the same ROUTE in every arrival
    /// order: a fact that has not arrived cannot veto, so a head mapped
    /// alone may latch plaintext-once for a file whose tail would have
    /// refused, and the same set fed tail-first assembles ciphertext.
    /// Both routes are whole-file, both are adjudicated by
    /// `decrypt_finished`, and both reach the same published bytes.
    /// Route identity would mean holding every encrypted span until the
    /// last volume mapped, which is not a trade this path can make
    /// (TODO 158 item 2).
    pub(super) fn instream_decrypt_allowed(
        inner: &Inner,
        slot: usize,
        ei: usize,
        w: &FileWriter,
    ) -> bool {
        // Rule 2, and first because it is the cheapest test here and the
        // only one that still holds for a check field this function does
        // not know about yet. Bytes under an output with no crypto state
        // are ciphertext: the plaintext-once writes all go through one.
        //
        // TWO halves. The route latch is the authoritative one: it is
        // stamped at enqueue under the routing lock, where the decision
        // is actually made. The written() counter lags it - pwrites run
        // after the lock drops, so a routed-but-unwritten ciphertext
        // job was invisible here, and a span arriving in that window
        // (a live password candidate landing mid-file) latched
        // plaintext-once over it: a mixed output (Codex sweep 13 Aug
        // C1). The counter stays as the belt - it is what covers
        // resume, where bytes from a prior run sit under an output the
        // latch never saw.
        if w.path.file_name().is_some_and(|k| {
            inner
                .ciphertext_files
                .contains(k.to_string_lossy().as_ref())
        }) {
            return false;
        }
        if w.written() > 0 {
            return false;
        }
        let Some(pw) = inner.password.as_ref() else {
            return false;
        };
        let Some(m) = inner.slots[slot].mapper.as_ref() else {
            return false;
        };
        let Some(e) = m.entries.get(ei) else {
            return false;
        };
        let f = Self::file_checks(inner, slot, &e.name);
        if f.vetoed {
            return false;
        }
        // The head piece's record is what `crypto_for` keys the whole
        // stream with, so the head's check is the one that has to verify.
        // While the head volume's headers are still in flight there is
        // nothing to latch onto at all: `crypto_for` returns None and the
        // span holds, which is what stops a continuation piece from
        // committing the file to a route its head never answered for.
        let Some((si, hi)) = f.head else {
            return true;
        };
        let Some(c) = inner.slots[si]
            .mapper
            .as_ref()
            .and_then(|m| m.entries.get(hi))
            .and_then(|e| e.crypt.as_ref())
        else {
            return false;
        };
        // One derive, for the head alone, because this runs per SPAN:
        // RAR4's schedule is 0x40000 SHA-1 rounds, and while the cache
        // makes a repeat cheap, an archive with a fresh salt per piece
        // would pay it again and again under the routing lock. RAR4 never
        // reaches this line - the format stores no check value, so
        // `file_checks` vetoes it and `decrypt_finished` adjudicates the
        // set against the header's plaintext CRC32, the recoverable route
        // a check-less RAR5 set takes for exactly the same reason.
        c.derive(pw).is_some_and(|keys| c.check_verifies(&keys))
    }

    /// Resolve [`FileChecks`] for inner file `name` over `slot`'s group.
    ///
    /// Every mapped piece is consulted, because the whole-file checks
    /// live on the tail piece alone and the answer has to be the same for
    /// every fragment of the file - see the caller. Pieces that have not
    /// arrived yet cannot contribute, which is why `decrypt_finished`
    /// re-asks once the set is complete.
    ///
    /// The digest veto is per PIECE (a piece stating a digest and no
    /// CRC32 of its own), not `any digest && no CRC32 anywhere`: the
    /// group-wide form let a head's CRC32 excuse a tail that says
    /// "BLAKE2sp, no CRC32", which is the disagreement this whole walk
    /// exists to refuse. A piece carrying both - the `rar a -htb` set
    /// that also stores a CRC32 - is fully adjudicable and still routes
    /// one-pass.
    fn file_checks(inner: &Inner, slot: usize, name: &str) -> FileChecks {
        let mut out = FileChecks {
            vetoed: false,
            head: None,
        };
        let mut scan = |si: usize, m: &VolumeMapper| {
            for (ei, e) in m.entries.iter().enumerate() {
                if e.name != name || e.is_dir {
                    continue;
                }
                let checked = e.encrypted
                    && e.crypt
                        .as_ref()
                        .and_then(|c| c.rar5())
                        .is_some_and(|r5| r5.check.is_some());
                // An FHEXTRA_HASH digest (BLAKE2sp, `rar a -htb`) with no
                // CRC32 beside it has nothing the finish pass can
                // adjudicate: `crc_gate` returns None, so `crc_verdict` is
                // None rather than Some(false), and the plaintext is
                // published with NO integrity check at all.
                // `verify_inner_crcs` already refuses the unencrypted twin
                // of this shape for the same reason - its gate is `Store
                // && !encrypted`, so an encrypted entry never reached it.
                // Assembling ciphertext instead costs nothing: the volumes
                // stay byte-exact and can still materialize, and the disk
                // path verifies the BLAKE2sp properly
                // (`verify_integrity_with_keys`). nzbkit has no BLAKE2sp of
                // its own, so verifying in place is not an option here.
                let uncheckable = e.hash.is_some() && e.file_crc.is_none();
                out.vetoed |= !checked || uncheckable;
                if !e.split_before && out.head.is_none() {
                    out.head = Some((si, ei));
                }
            }
        };
        match inner.slots[slot]
            .group
            .as_ref()
            .and_then(|gk| inner.groups.get(gk))
        {
            Some(g) => {
                for &si in &g.slots {
                    if let Some(m) = inner.slots[si].mapper.as_ref() {
                        scan(si, m);
                    }
                }
            }
            None => {
                if let Some(m) = inner.slots[slot].mapper.as_ref() {
                    scan(slot, m);
                }
            }
        }
        out
    }

    pub(super) fn crypto_for(
        inner: &mut Inner,
        slot: usize,
        ei: usize,
        w: &Arc<FileWriter>,
    ) -> Option<Arc<CryptoState>> {
        // Borrowed lookup first: the state exists for every span after
        // the first, and owning the key cost a String per encrypted span.
        let key = w.path.file_name()?.to_string_lossy();
        if let Some(cs) = inner.crypto_files.get(key.as_ref()) {
            return Some(cs.clone());
        }
        let key = key.into_owned();
        let name = Self::entry_name(inner, slot, ei);
        // The head piece (split_before == false) of this file - it may
        // live in another volume's mapper within the same group. Found by
        // the SAME walk the route gate uses, so the record that keys the
        // stream is the record whose check the gate verified; a slot-first
        // preference here and a group-order one there could pick two
        // different heads for one output.
        let (c, unp, file_crc, split_after) =
            Self::file_checks(inner, slot, name)
                .head
                .and_then(|(si, hi)| {
                    let e = inner.slots[si].mapper.as_ref()?.entries.get(hi)?;
                    Some((e.crypt.clone()?, e.unpacked_size, e.file_crc, e.split_after))
                })?;
        let pw = inner.password.as_ref()?;
        let keys = c.derive(pw)?;
        // Plaintext-once requires a pre-decrypt password proof, which only
        // RAR5's stored check can give (`instream_decrypt_allowed` gates
        // every caller on it), so the resume journal's `E` record can
        // safely assume RAR5 parameters here.
        let r5 = c.rar5()?;
        // Only a single-piece entry's stored CRC covers the whole
        // plaintext. A tweaked checksum is keyed rather than useless -
        // the gate folds the computed CRC before comparing (Increment
        // B), same rules as the legacy finish pass.
        let expect_crc = crc_gate(file_crc.filter(|_| !split_after), &c, &keys);
        let cs = Arc::new(CryptoState::new(
            keys.aes.clone(),
            keys.iv,
            unp,
            expect_crc,
            key.clone(),
            inner.crypto_events.clone(),
        ));
        inner
            .crypto_events
            .lock()
            .unwrap()
            .push(CryptoJournalEvent::Params {
                name: key.clone(),
                salt: r5.salt,
                lg2: r5.lg2_count,
                iv: r5.iv,
                unp,
                check: r5.check,
            });
        inner.crypto_files.insert(key, cs.clone());
        Some(cs)
    }

    /// Read-side lookup: the in-stream decrypt state behind a writer,
    /// if that output is plaintext-once.
    pub(super) fn crypto_of(inner: &Inner, w: &FileWriter) -> Option<Arc<CryptoState>> {
        let key = w.path.file_name()?.to_string_lossy();
        inner.crypto_files.get(key.as_ref()).cloned()
    }

    /// (path, crypt params, unpacked size) of an encrypted head-piece
    /// output file by its output name, in a non-fallback group.
    pub(super) fn locate_encrypted_output(
        inner: &Inner,
        out_name: &str,
    ) -> Option<(PathBuf, EntryCrypt, u64)> {
        for grp in inner.groups.values() {
            if grp.fallback {
                continue;
            }
            for &si in &grp.slots {
                let Some(m) = inner.slots[si].mapper.as_ref() else {
                    continue;
                };
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

    /// Decrypt every encrypted store file of the healthy groups. During
    /// the download those files accumulated the archive's AES-CBC
    /// ciphertext at plain store offsets (both formats encrypt each inner
    /// file as ONE stream across all volumes, so the assembled ciphertext
    /// is contiguous); one sequential CBC pass + truncate to the unpacked
    /// size turns each into the real output, and the plaintext CRC32 is
    /// checked against the header CRC when it isn't tweaked.
    ///
    /// For RAR4 that CRC check is not belt-and-braces but the ONLY
    /// adjudicator there is: the format stores no password check, so every
    /// RAR4 job arrives here `verified: false` and publishes nothing the
    /// checksum has not accepted.
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
    /// - a rename either happened or did not; no file is ever a mix;
    /// - after a LANDED rename the [`DecryptPublish`] notification hands
    ///   the journal this file's crypt facts, so its retired placements
    ///   republish as plaintext-restorable `D` records - a later failure
    ///   in the same job (another file, the nested pass) then costs the
    ///   retry a local re-encrypt, not a refetch of a finished file
    ///   (TODO 100).
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
    pub(super) fn decrypt_finished(&self) -> io::Result<Vec<String>> {
        struct Job {
            key: String,
            out: String,
            path: PathBuf,
            unp: u64,
            key_bytes: Option<rarcrypt::AesKey>,
            iv: [u8; 16],
            covered: bool,
            /// Stored plaintext checksum to check after decryption -
            /// plain, or folded through the entry's keyed MAC when the
            /// crypt record set the tweaked-checksum flag.
            expect_crc: Option<CrcGate>,
            /// The entry's crypt record, kept whole for the publish
            /// notification: the resume journal's `E` line needs the
            /// RAR5-shaped KDF inputs, not just the derived key.
            crypt: EntryCrypt,
            /// Did the entry's stored check VERIFY the password before
            /// any byte was decrypted? False for a check-less (or
            /// malformed-check) set, which the mapper now admits on the
            /// promise that this pass adjudicates it: such a job must
            /// carry a checksum gate, and a gate it fails demotes the
            /// group instead of failing the whole download - the
            /// password is simply the wrong one, and the ciphertext (=
            /// the volume bytes) is untouched.
            verified: bool,
            /// The entry states a plaintext digest (FHEXTRA_HASH) and NO
            /// CRC32 - `rar a -htb`. There is nothing this pass can check
            /// such an output against, so it never publishes one; see the
            /// demotion filter below.
            hash_only: bool,
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
            let g = self.inner.lock_ok();
            let inner = &*g;
            for (key, grp) in &inner.groups {
                if grp.fallback {
                    continue;
                }
                // One decrypt job per inner file, keyed off its head piece
                // (split_before == false - whose IV starts the stream).
                let mut heads: HashMap<String, (EntryCrypt, u64, String, Option<u32>, bool)> =
                    HashMap::new();
                // The WHOLE-FILE checksum lives on the entry's LAST piece
                // (`split_after == false`) - per the RAR5 spec, earlier
                // pieces carry only their own volume's bytes. The head
                // loop below therefore cannot see it for a split file,
                // which is why a multi-volume encrypted set used to have
                // no verifiable checksum at all. By finish every volume
                // has arrived, so the tail is simply here to be read.
                let mut tail_crcs: HashMap<&str, u32> = HashMap::new();
                // ...and, from the same piece, whether the entry states a
                // digest instead of a CRC32. Read off the TAIL for the same
                // reason: the whole-file checks live there.
                let mut tail_hash_only: std::collections::HashSet<&str> = Default::default();
                for &si in &grp.slots {
                    let Some(m) = inner.slots[si].mapper.as_ref() else {
                        continue;
                    };
                    for e in &m.entries {
                        if e.is_dir || !e.encrypted {
                            continue;
                        }
                        if !e.split_after {
                            match e.file_crc {
                                Some(crc) => {
                                    tail_crcs.insert(e.name.as_str(), crc);
                                }
                                None if e.hash.is_some() => {
                                    tail_hash_only.insert(e.name.as_str());
                                }
                                None => {}
                            }
                        }
                    }
                }
                for &si in &grp.slots {
                    let Some(m) = inner.slots[si].mapper.as_ref() else {
                        continue;
                    };
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
                            // The checksum that covers the whole plaintext
                            // this pass produces: the entry's own when it is
                            // unsplit, else its tail piece's (collected
                            // above). Using the head's value on a split file
                            // would false-fail - it describes only that
                            // volume's bytes.
                            let whole_crc = tail_crcs.get(e.name.as_str()).copied();
                            let hash_only =
                                whole_crc.is_none() && tail_hash_only.contains(e.name.as_str());
                            heads.entry(e.name.clone()).or_insert((
                                c.clone(),
                                e.unpacked_size,
                                out,
                                whole_crc,
                                hash_only,
                            ));
                        }
                    }
                }
                for (_fname, (c, unp, out, file_crc, hash_only)) in heads {
                    let Some(w) = inner.inner_writers.get(&out) else {
                        continue;
                    };
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
                                "encrypted RAR file failed its stored CRC after decryption",
                            ));
                        }
                        // The hash-only backstop, and the only ORDER-
                        // INDEPENDENT place to put it.
                        // `instream_decrypt_allowed` resolves its check
                        // fields across the whole file, but a fact that has
                        // not arrived cannot veto: only the TAIL fragment
                        // carries the whole-file checks, so a head mapped
                        // alone reads `hash: None, file_crc: None`, answers
                        // "allowed" and latches the plaintext-once route
                        // for the whole file (`crypto_files` caches by
                        // output name, first decision wins). Whether that
                        // happens therefore depends on which volume is
                        // mapped first, and without this the head-first
                        // order published plaintext with no integrity
                        // verdict at all. By finish every volume is mapped,
                        // so `hash_only` is the truth: demote exactly as an
                        // incomplete cipher record does, and the shim
                        // reproduces the posted bytes for the fallback
                        // (Codex sweep 12 Aug F2). The route may still
                        // differ by arrival order; what it may never be is
                        // MIXED, which is the gate's own contract.
                        if unp > 0 && hash_only {
                            instream_failed.insert(key.clone());
                        } else if unp == 0 || cs.complete() {
                            instream_done.push(out);
                        } else {
                            instream_failed.insert(key.clone());
                        }
                        continue;
                    }
                    let aes = inner.password.as_ref().and_then(|pw| c.derive(pw));
                    jobs.push(Job {
                        key: key.clone(),
                        out,
                        path: w.path.clone(),
                        unp,
                        key_bytes: aes.as_ref().map(|k| k.aes.clone()),
                        // RAR5 stores the IV in the header; RAR4 derives it
                        // with the key, so it comes off the key material.
                        iv: aes.as_ref().map(|k| k.iv).unwrap_or([0; 16]),
                        covered: unp == 0 || w.covered(0, rarcrypt::align16(unp)),
                        // Verify the plaintext after decryption: a clear
                        // tweaked flag stores a plain CRC32 (WinRAR's -hp
                        // default), a set one stores its keyed fold, and the
                        // gate handles both. Password-check proves the KEY,
                        // not that every ciphertext block survived the wire.
                        expect_crc: aes.as_ref().and_then(|k| crc_gate(file_crc, &c, k)),
                        verified: aes.as_ref().is_some_and(|k| c.check_verifies(k)),
                        hash_only,
                        crypt: c,
                    });
                }
            }
        }
        if jobs.is_empty() && instream_failed.is_empty() {
            instream_done.sort();
            return Ok(instream_done);
        }
        if let Some(e) = injected_decrypt_enospc("pre") {
            return Err(e);
        }
        // A group decrypts ALL of its files or NONE: once one file is
        // plaintext, a fallback (which reads inner files back to
        // materialize volumes) would rebuild silently-corrupt volumes -
        // so any pre-flight failure (ciphertext holes, vanished password)
        // condemns the whole group BEFORE any byte changes.
        let mut failed_groups: std::collections::HashSet<String> = jobs
            .iter()
            // An unverified password with nothing to check the plaintext
            // against can never be adjudicated: decrypting would publish
            // bytes no one has vouched for. Demote instead - the volumes
            // materialize and the disk path (which validates the password
            // itself) takes over, exactly where the mapper used to send
            // this set the moment it saw a missing check.
            //
            // `hash_only` is the same rule for the shape that DOES have a
            // plaintext check we cannot compute. `instream_decrypt_allowed`
            // diverts a `rar a -htb` entry (BLAKE2sp, no CRC32) here
            // explicitly so "the disk path verifies the BLAKE2sp properly"
            // - but nothing demoted it, so it arrived `verified = true,
            // expect_crc = None`, sailed past the filter above, and
            // published plaintext with NO integrity check. A verified RAR5
            // password proves the KEY, never that every ciphertext block
            // survived the wire: damage one before the yEnc/PAR2 pass and
            // every outer check agrees while the payload is corrupt (Codex
            // sweep 12 Aug F2). rars checks the keyed digest on the disk
            // path (`verify_integrity_with_keys`), which is the verdict
            // this pass has no BLAKE2sp of its own to reach. A zero-length
            // entry has no plaintext to check and must not drag its group
            // to disk over it.
            .filter(|j| {
                j.key_bytes.is_none()
                    || !j.covered
                    || (!j.verified && j.expect_crc.is_none())
                    || (j.hash_only && j.unp > 0)
            })
            .map(|j| j.key.clone())
            .collect();
        failed_groups.extend(instream_failed);
        let live: Vec<&Job> = jobs
            .iter()
            .filter(|j| !failed_groups.contains(&j.key))
            .collect();
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
            let mut g = self.inner.lock_ok();
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
        let (barrier, publish) = {
            let g = self.inner.lock_ok();
            (g.decrypt_barrier.clone(), g.decrypt_publish.clone())
        };
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
        let workers = plans.len().clamp(1, 4);
        // Files run concurrently and each file shards internally, so the two
        // share one budget. An encrypted set is usually ONE file, which is
        // exactly the case that needs the shards: without them a 60 GB
        // release decrypts on a single core after the download has finished.
        let shards_per_file =
            (std::thread::available_parallelism().map_or(1, |n| n.get()) / workers).max(1);
        let next = AtomicUsize::new(0);
        let done: Mutex<Vec<String>> = Mutex::new(Vec::new());
        let first_err: Mutex<Option<io::Error>> = Mutex::new(None);
        // Groups an unverified password turned out to be wrong for (a
        // checksum miss after the decrypt pass) - demoted below rather
        // than failing the job. See the outcome match.
        let late_failed: Mutex<std::collections::HashSet<String>> = Default::default();
        let plans_ref = &plans;
        let barrier_ref = &barrier;
        let publish_ref = &publish;
        std::thread::scope(|scope| {
            for _ in 0..workers {
                scope.spawn(|| {
                    loop {
                        let i = next.fetch_add(1, Ordering::Relaxed);
                        let Some((j, tmp, wf, st)) = plans_ref.get(i) else {
                            break;
                        };
                        // One file's failure condemns the job, so don't burn
                        // disk passes on the rest of the set.
                        if first_err.lock_ok().is_some() {
                            let _ = std::fs::remove_file(tmp);
                            continue;
                        }
                        let mut facts: Option<Vec<CryptoJournalEvent>> = None;
                        let outcome = decrypt_pass(
                            &j.path,
                            wf,
                            j.key_bytes
                                .as_ref()
                                .expect("pre-flight dropped keyless jobs"),
                            &j.iv,
                            j.unp,
                            j.expect_crc,
                            shards_per_file,
                        )
                        // Plaintext is on disk and verified; now buy the right
                        // to publish it. Until this returns Ok the journal
                        // still describes `j.path` truthfully and must keep
                        // doing so, which is why nothing has touched it yet.
                        .and_then(|()| {
                            // The resume facts come off `j.path` NOW - it
                            // still holds the ciphertext, and the rename
                            // below destroys it. Soft-fail by design: no
                            // facts just means the retirement stands and a
                            // retry refetches this file.
                            if publish_ref.is_some() {
                                facts = collect_decrypt_facts(
                                    &j.path,
                                    &j.crypt,
                                    &j.out,
                                    j.unp,
                                    j.key_bytes
                                        .as_ref()
                                        .expect("pre-flight dropped keyless jobs"),
                                );
                            }
                            match barrier_ref {
                                Some(b) => b(std::slice::from_ref(&j.out)),
                                None => Ok(()),
                            }
                        })
                        .and_then(|()| {
                            // Publish under the lock, ordered against
                            // open_stream's ciphertext/plaintext choice.
                            let _g = self.inner.lock_ok();
                            let r = std::fs::rename(tmp, &j.path);
                            if r.is_ok() {
                                *st.state.lock_ok() = DecState::Decrypted;
                            }
                            r
                        });
                        match outcome {
                            Ok(()) => {
                                // Published: hand the resume facts over so
                                // the journal can republish this file's
                                // placements as plaintext-restorable `D`
                                // records (TODO 100 - a LATER failure in
                                // this job must not cost the retry a
                                // refetch of a file that is already done).
                                if let (Some(p), Some(evs)) = (publish_ref, &facts) {
                                    p(&j.out, evs);
                                }
                                done.lock_ok().push(j.out.clone())
                            }
                            Err(e) => {
                                // Nothing was published, so the ciphertext is
                                // byte-exact whichever step failed - drop the
                                // scratch and leave it that way. If the rename
                                // was the failure the claim is already retired,
                                // which just costs the retry a refetch.
                                let _ = std::fs::remove_file(tmp);
                                // A checksum miss on an UNVERIFIED password is
                                // not a damaged download - it is the wrong
                                // password, on a set whose header offered no way
                                // to say so earlier. Demote that group (volumes
                                // materialize, the disk path re-tries with the
                                // password itself) rather than failing the whole
                                // job, which is what a verified set's mismatch
                                // still means: bytes that were damaged before
                                // posting.
                                if !j.verified && e.kind() == io::ErrorKind::InvalidData {
                                    late_failed.lock_ok().insert(j.key.clone());
                                } else {
                                    let mut fe = first_err.lock_ok();
                                    if fe.is_none() {
                                        *fe = Some(e);
                                    }
                                }
                            }
                        }
                    }
                });
            }
        });
        if let Some(e) = first_err.into_inner().unwrap() {
            return Err(e);
        }
        // Wrong-password groups join the demotion set before it is applied.
        let late_failed = late_failed.into_inner().unwrap();
        failed_groups.extend(late_failed.iter().cloned());
        // Renames are metadata: fsync the directory so a power cut can't
        // undo a publish the journal has already stopped vouching for.
        // Best-effort by design - the correctness guarantee comes from the
        // barrier ordering above (after a lost rename the articles refetch
        // either way), and SMB/CIFS NAS mounts reject a directory fsync
        // outright, where failing the job would be pure harm.
        crate::disk::sync_dir(&self.out_dir);
        if !failed_groups.is_empty() {
            let mut g = self.inner.lock_ok();
            let inner = &mut *g;
            for key in failed_groups {
                if inner.groups.contains_key(&key) {
                    // Two very different demotes reach here, and the reason
                    // is what the user reads. A late CRC miss on a password
                    // nothing could verify up front (every RAR4 set, and a
                    // check-less RAR5 one) is a WRONG PASSWORD on a complete
                    // download - "incomplete" would send the reader hunting
                    // for articles that all arrived. Both keep the
                    // "encrypted" substring the finish ladder routes on.
                    let why = if late_failed.contains(&key) {
                        "encrypted data failed its checksum (wrong password)"
                    } else {
                        "encrypted data incomplete"
                    };
                    self.fallback_group(inner, &key, why)?;
                }
            }
        }
        let mut decrypted = done.into_inner().unwrap();
        decrypted.extend(instream_done);
        decrypted.sort();
        if let Some(e) = injected_decrypt_enospc("post") {
            return Err(e);
        }
        Ok(decrypted)
    }
}

#[cfg(test)]
#[path = "crypto_tests.rs"]
mod crypto_tests;

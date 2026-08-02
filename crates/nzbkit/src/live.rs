//! Live in-stream PAR2 verification (design: M2 - the one-pass pipeline).
//!
//! Decoded article buffers are hashed against the PAR2 block checksums
//! *while the download runs*, so verification finishes with the last
//! article and clean sets never trigger a post-download verify pass.
//!
//! Design:
//! - The par2 main packet is scheduled first; [`LiveVerifier`] starts in
//!   `Waiting` and is [`activate`](LiveVerifier::activate)d mid-download as
//!   soon as its packets parse. Until then articles just record their
//!   yEnc name and capture the first 16 KiB (for obfuscation matching).
//! - NZB slots are matched to PAR2 files lazily - by exact/sanitized name
//!   first, then by md5-16k (obfuscated posts lie in subjects but not in
//!   their bytes).
//! - Blocks fully contained in one decoded span are hashed straight from
//!   the decode buffer - zero copies, no disk involvement. Blocks that
//!   straddle article boundaries accumulate in bounded per-file partial
//!   buffers (at most one boundary block per adjacent-article pair is ever
//!   alive; a cap converts pathological orderings into read-back work
//!   instead of unbounded memory).
//! - Anything not verified in-stream (spans decoded before activation,
//!   partials whose neighbor article never arrived, missing articles) is
//!   settled by [`finish_slot`](LiveVerifier::finish_slot) with targeted
//!   `pread`s of exactly those blocks - usually straight from page cache,
//!   and usually zero blocks on the happy path.
//!
//! Hashing happens *outside* the per-slot lock: `on_data` claims work under
//! the lock, hashes lock-free, then records results. MD5 is the throughput
//! floor (~0.6 GB/s/core), so concurrent decode workers must not serialize.
//! [`set_fast_verify`](LiveVerifier::set_fast_verify) lifts that floor by
//! claiming in-stream blocks on the IFSC CRC32 alone (TODO §10) - settle
//! read-back and the no-IFSC whole-file check always keep full MD5.

use crate::sync::{MutexExt, RwLockExt};
use std::collections::HashMap;
use std::io;
use std::path::Path;
use std::sync::{Arc, Mutex, RwLock};

use md5::{Digest, Md5};

use crate::par2::{BlockCheck, Par2Error, Par2Set};

/// Default GLOBAL cap on bytes held in partial (boundary) block buffers,
/// across ALL slots. Beyond it, new partials are abandoned to the settle
/// read-back path instead of allocated. This must be global: a per-file
/// cap multiplied by hundreds of volume slots was the linear RSS term
/// measured on big jobs (5 GB @ 87 GB → 25.8 GB @ 190 GB). Overridden by
/// the MemBudget slice (`with_partials_cap`).
const PARTIAL_BYTES_DEFAULT_CAP: usize = 256 * 1024 * 1024;
/// First-16-KiB capture used for md5_16k matching of obfuscated posts.
const HEAD_LEN: usize = 16384;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BlockState {
    /// Not yet verified (in-stream hashing hasn't covered it).
    Pending,
    Ok,
    Bad,
}

/// A boundary block accumulating bytes from more than one article.
struct Partial {
    /// Real bytes of this block (final block may be shorter than block_size).
    buf: Vec<u8>,
    /// Filled intervals within `buf`, sorted + merged.
    filled: Vec<(usize, usize)>,
}

impl Partial {
    fn new(len: usize) -> Partial {
        Partial {
            buf: vec![0; len],
            filled: Vec::with_capacity(2),
        }
    }

    fn fill(&mut self, at: usize, bytes: &[u8]) {
        self.buf[at..at + bytes.len()].copy_from_slice(bytes);
        let (mut s, mut e) = (at, at + bytes.len());
        // Merge into the sorted interval list.
        let mut merged = Vec::with_capacity(self.filled.len() + 1);
        for &(fs, fe) in &self.filled {
            if fe < s || fs > e {
                merged.push((fs, fe));
            } else {
                s = s.min(fs);
                e = e.max(fe);
            }
        }
        merged.push((s, e));
        merged.sort_unstable();
        self.filled = merged;
    }

    fn complete(&self) -> bool {
        self.filled == [(0, self.buf.len())]
    }
}

/// B1: a boundary block held as per-fragment CRC32s instead of bytes.
/// CRC32 composes over concatenation (`crc32_combine`), so fragments can
/// arrive in any order and merge whenever neighbors touch - ~24 bytes per
/// fragment against a block-sized buffer. Only valid when the block will
/// be claimed on CRC alone (fast/lean verify - the default); full-MD5
/// mode keeps byte buffers because MD5 cannot be composed.
///
/// This erases the partials RSS term entirely in default mode - the term
/// that grew linearly on big jobs (25.8 GB at 190 GB pre-cap) and that at
/// the 256 MB MemBudget floor forced constant spill → settle read-back on
/// exactly the boxes with the slowest disks. When the PAR2 block size
/// exceeds the article size, EVERY block straddles articles and the old
/// buffers approached a full copy of the in-flight file.
struct CrcParts {
    /// (start, end, crc32 of that range) - sorted, non-overlapping,
    /// adjacent entries eagerly merged.
    parts: Vec<(usize, usize, u32)>,
}

impl CrcParts {
    fn new() -> CrcParts {
        CrcParts {
            parts: Vec::with_capacity(2),
        }
    }

    /// Merge a fragment. Returns false on overlap with an existing part -
    /// impossible for decoder-fresh spans (each article is fed once), so
    /// the caller treats it as "this block can't be tracked losslessly"
    /// and abandons the block to settle read-back.
    fn insert(&mut self, s: usize, e: usize, crc: u32) -> bool {
        let at = self.parts.partition_point(|&(ps, _, _)| ps < s);
        if at > 0 && self.parts[at - 1].1 > s {
            return false;
        }
        if at < self.parts.len() && self.parts[at].0 < e {
            return false;
        }
        self.parts.insert(at, (s, e, crc));
        // Merge with the right neighbor, then the left (order matters for
        // index stability; combine() appends the RIGHT part's crc).
        if at + 1 < self.parts.len() && self.parts[at].1 == self.parts[at + 1].0 {
            let (rs, re, rc) = self.parts.remove(at + 1);
            let _ = rs;
            let p = &mut self.parts[at];
            p.2 = crate::yenc_simd::crc32_combine(p.2, rc, (re - p.1) as u64);
            p.1 = re;
        }
        if at > 0 && self.parts[at - 1].1 == self.parts[at].0 {
            let (_, e2, c2) = self.parts.remove(at);
            let p = &mut self.parts[at - 1];
            p.2 = crate::yenc_simd::crc32_combine(p.2, c2, (e2 - p.1) as u64);
            p.1 = e2;
        }
        true
    }

    /// CRC of the whole block's real bytes once every fragment landed.
    fn complete(&self, blen: usize) -> Option<u32> {
        match self.parts.as_slice() {
            [(0, e, crc)] if *e == blen => Some(*crc),
            _ => None,
        }
    }
}

/// A boundary block in flight: bytes (full-MD5 mode) or fragment CRCs
/// (fast/lean mode).
enum PartialBuf {
    Bytes(Partial),
    Crc(CrcParts),
}

/// How the backfill pass must re-feed one slot's pre-activation spans -
/// the public half of [`Src`], returned by
/// [`LiveVerifier::take_pre_spans`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PreSpanSrc {
    /// This run decoded every span and each may claim as strongly as a
    /// fresh one - the pcrc32 passed, or lean mode owns the weaker
    /// contract. Feed via [`LiveVerifier::on_data_backfill`].
    Backfill,
    /// Crash resume seeded some, or a span arrived with no wire CRC
    /// behind it - feed via [`LiveVerifier::on_data_from_disk`].
    Disk,
}

/// Where a span came from - decides claim strength (see on_data_inner).
#[derive(Clone, Copy, PartialEq)]
enum Src {
    /// Decoder-fresh, article CRC passed.
    Fresh,
    /// Decoder-fresh, article CRC deliberately skipped (lean mode).
    Lean,
    /// Re-read from disk in THIS run, of bytes this process decoded with a
    /// passing yEnc pcrc32 (the M15b backfill of pre-activation spans).
    /// Claims exactly as strongly as `Fresh`: same two CRC32 layers, and
    /// under fast verify a fresh span's disk copy is never checked either.
    /// [`LiveVerifier::take_pre_spans`] is the gate that keeps that true -
    /// a slot whose pre-activation spans were not all wire-CRC'd is routed
    /// to `Disk` instead (unless lean owns them).
    Rehash,
    /// Read back from disk with nothing in this run vouching for the bytes
    /// (settle, crash resume) - never claims CRC-only.
    Disk,
}

struct SlotState {
    /// yEnc-header name (authoritative once seen; NZB subjects lie).
    name: Option<String>,
    /// First min(16 KiB, file) bytes for md5_16k matching - articles arrive
    /// out of order, so this fills interval-wise like a boundary block.
    head: Option<Partial>,
    /// yEnc-declared file size (caps head capture for small files).
    file_size: u64,
    /// Index into the active set's `files` once matched.
    file: Option<usize>,
    /// One entry per PAR2 block once matched.
    blocks: Vec<BlockState>,
    partials: HashMap<usize, PartialBuf>,
    /// Bytes held by `PartialBuf::Bytes` entries only - CRC entries are
    /// ~free and exempt from the global partials budget.
    partial_bytes: usize,
    /// Spans decoded before PAR2 activation (offset, len) - metadata only.
    /// The backfill pass re-feeds them from disk once the set is live, so
    /// settle read-back shrinks toward zero (M15b).
    pre_spans: Vec<(u64, u32)>,
    /// Some of `pre_spans` were seeded by crash resume (or otherwise came
    /// off disk), so nothing in this run vouches for those bytes at all -
    /// the whole slot's backfill drops to the full-MD5 disk path rather
    /// than trying to tell the two apart.
    resume_seeded: bool,
    /// Some of `pre_spans` were decoded without a wire CRC covering them (a
    /// pcrc-absent article, or lean's skipped article CRCs). Same reason as
    /// `resume_seeded` - offsets are all `pre_spans` hold, so the backfill
    /// re-feeds a slot under ONE source - but lean may still claim these
    /// CRC-only, so the two flags stay apart (see `take_pre_spans`).
    pre_unvouched: bool,
    /// Matching was attempted and failed permanently (name + head both
    /// exhausted) - avoids rescanning every article.
    unmatchable: bool,
    /// Blocks verified in-stream (for the zero-read-back accounting).
    live_ok: u64,
    live_bad: u64,
}

enum Plan {
    /// Par2 main not yet parsed; slots record names/heads only.
    Waiting,
    Active(Active),
    /// No PAR2 in this NZB - verification off.
    Off,
}

struct Active {
    set: Arc<Par2Set>,
    /// file idx → slot that claimed it (one slot per PAR2 file). Its own
    /// mutex: matching happens while holding a slot lock, and two slots
    /// must not race a claim.
    claimed: Mutex<Vec<Option<usize>>>,
}

/// Result of settling one slot at completion time.
#[derive(Debug)]
pub struct SlotReport {
    pub par2_name: Option<String>,
    pub total_blocks: usize,
    pub bad_blocks: Vec<usize>,
    /// Blocks verified in-stream from decode buffers.
    pub live_blocks: u64,
    /// Blocks that needed the read-back fallback.
    pub readback_blocks: u64,
    /// File length per PAR2 (0 if unmatched).
    pub length: u64,
}

impl SlotReport {
    pub fn all_ok(&self) -> bool {
        self.par2_name.is_some() && self.bad_blocks.is_empty()
    }
}

pub struct LiveVerifier {
    plan: RwLock<Plan>,
    slots: Vec<Mutex<SlotState>>,
    /// Run-wide counters for the dashboard's verify lane (M14h).
    live_ok_total: std::sync::atomic::AtomicU64,
    live_bad_total: std::sync::atomic::AtomicU64,
    /// M15 global partial-buffer accounting (bytes, across all slots).
    partials_cap: usize,
    partials_used: std::sync::atomic::AtomicUsize,
    partials_peak: std::sync::atomic::AtomicUsize,
    /// Blocks pushed to settle read-back because the budget was full.
    partials_spilled: std::sync::atomic::AtomicU64,
    /// Fast verify (TODO §10): claim in-stream blocks on the IFSC CRC32
    /// alone, skipping the MD5 pass - MD5 is the compute floor
    /// (~0.8 GB/s/core vs 10+ for hw CRC), and every in-stream span
    /// already passed its yEnc pcrc32 in the decoder. Settle read-back
    /// and the no-IFSC whole-file check keep full MD5 hashing either way.
    fast: std::sync::atomic::AtomicBool,
    /// M32 lean mode: CRC-only claims allowed for untrusted spans too
    /// (article CRCs are being skipped upstream). See [`Self::set_lean`].
    lean: std::sync::atomic::AtomicBool,
}

impl LiveVerifier {
    pub fn new(n_slots: usize) -> LiveVerifier {
        Self::with_partials_cap(n_slots, PARTIAL_BYTES_DEFAULT_CAP)
    }

    /// M15: cap partial-block memory at `cap` bytes GLOBALLY (a MemBudget
    /// slice). Overflow degrades to settle read-back, never fails.
    pub fn with_partials_cap(n_slots: usize, cap: usize) -> LiveVerifier {
        LiveVerifier {
            plan: RwLock::new(Plan::Waiting),
            live_ok_total: Default::default(),
            live_bad_total: Default::default(),
            partials_cap: cap.max(1 << 20),
            partials_used: Default::default(),
            partials_peak: Default::default(),
            partials_spilled: Default::default(),
            fast: Default::default(),
            lean: Default::default(),
            slots: (0..n_slots)
                .map(|_| {
                    Mutex::new(SlotState {
                        name: None,
                        head: None,
                        file_size: 0,
                        file: None,
                        blocks: Vec::new(),
                        partials: HashMap::new(),
                        partial_bytes: 0,
                        pre_spans: Vec::new(),
                        resume_seeded: false,
                        pre_unvouched: false,
                        unmatchable: false,
                        live_ok: 0,
                        live_bad: 0,
                    })
                })
                .collect(),
        }
    }

    /// Declare that no PAR2 set will ever arrive (NZB has none).
    pub fn set_off(&self) {
        *self.plan.write_ok() = Plan::Off;
    }

    /// Enable/disable fast verify (CRC32-only in-stream claims). Flip
    /// before articles flow; blocks already claimed keep their verdict.
    pub fn set_fast_verify(&self, on: bool) {
        self.fast.store(on, std::sync::atomic::Ordering::Relaxed);
    }

    /// M32 "lean" mode (opt-in, slow-CPU boost): CRC-only claims are
    /// allowed even for spans the decoder did NOT vouch for - the
    /// caller is skipping article CRCs on PAR2-covered slots, so the
    /// block CRC32 is the single in-stream integrity layer. Settle
    /// read-back and repair remain the final authority. Only
    /// meaningful with fast verify on.
    pub fn set_lean(&self, on: bool) {
        self.lean.store(on, std::sync::atomic::Ordering::Relaxed);
    }

    /// Seed a slot's name when no article will ever flow through it (crash
    /// resume: fully-completed slots refetch nothing, but matching still
    /// needs a name). A later yEnc name would win only if none is set -
    /// call this exclusively for slots with zero pending articles.
    pub fn set_name_hint(&self, slot: usize, name: &str) {
        let mut s = self.slots[slot].lock_ok();
        if s.name.is_none() && !name.is_empty() {
            s.name = Some(name.to_string());
        }
    }

    /// Parse + adopt the recovery set. Call once, when the par2 main
    /// file(s) finish downloading. Returns the parsed set for the caller's
    /// own use (repair planning, reporting).
    pub fn activate(&self, inputs: &[&[u8]]) -> Result<Arc<Par2Set>, Par2Error> {
        let set = Arc::new(pick_set(inputs)?);
        let claimed = Mutex::new(vec![None; set.files.len()]);
        *self.plan.write_ok() = Plan::Active(Active {
            set: set.clone(),
            claimed,
        });
        Ok(set)
    }

    /// M32 perf: true when this slot's bytes will be FULLY verified
    /// without the article CRC - the set is active, the slot is matched
    /// to a PAR2 file, and fast verify is OFF (every claim is full
    /// block MD5). Callers may then skip the yEnc pcrc32 pass, feeding
    /// spans as untrusted. Under fast verify this must stay false: the
    /// CRC-only claim's justification IS the passed pcrc32.
    pub fn delegates_integrity(&self, slot: usize) -> bool {
        // Fast mode blocks delegation - UNLESS lean mode explicitly
        // opted into single-CRC32 in-stream integrity.
        if self.fast.load(std::sync::atomic::Ordering::Relaxed)
            && !self.lean.load(std::sync::atomic::Ordering::Relaxed)
        {
            return false;
        }
        if !matches!(&*self.plan.read_ok(), Plan::Active(_)) {
            return false;
        }
        self.slots[slot].lock_ok().file.is_some()
    }

    pub fn set(&self) -> Option<Arc<Par2Set>> {
        match &*self.plan.read_ok() {
            Plan::Active(a) => Some(a.set.clone()),
            _ => None,
        }
    }

    /// Feed one decoded article span. `name`/`file_size` come from the yEnc
    /// header; `offset` is the file offset of `data`. Call after the bytes
    /// are written (read-back must be able to see them). ONLY for
    /// decoder-fresh spans (the yEnc pcrc32 just passed): fast verify may
    /// claim their blocks CRC-only. Bytes re-read from disk go through
    /// [`on_data_backfill`](Self::on_data_backfill) (this run's own
    /// pre-activation spans) or
    /// [`on_data_from_disk`](Self::on_data_from_disk) (everything else).
    pub fn on_data(&self, slot: usize, name: &str, file_size: u64, offset: u64, data: &[u8]) {
        self.on_data_inner(slot, name, file_size, offset, data, Src::Fresh);
    }

    /// [`on_data`](Self::on_data) for spans whose bytes came back off disk
    /// with nothing in this run vouching for them (settle read-back,
    /// crash-resume seeds). They always take the full MD5+CRC block check -
    /// fast verify never thins the resume path's protection.
    pub fn on_data_from_disk(
        &self,
        slot: usize,
        name: &str,
        file_size: u64,
        offset: u64,
        data: &[u8],
    ) {
        self.on_data_inner(slot, name, file_size, offset, data, Src::Disk);
    }

    /// M15b backfill: a span re-read from disk in THIS run, recorded as a
    /// pre-activation span while the plan was `Waiting` (by
    /// [`on_data`](Self::on_data), or by
    /// [`on_data_unverified`](Self::on_data_unverified) in lean mode).
    /// Trust equals a fresh span's - the wire CRC layer happened, and fast
    /// verify already claims fresh blocks without ever reading their disk
    /// copy - so boundary fragments compose as CRC parts (B1) instead of
    /// forcing block-sized byte buffers. Feeding these through
    /// [`on_data_from_disk`](Self::on_data_from_disk) instead re-created
    /// the exact partials-RSS term B1 removed: with a PAR2 block bigger
    /// than the partials budget every backfilled block spilled straight
    /// back to settle read-back.
    ///
    /// Only for spans this run produced: crash-resume seeds stay on the
    /// disk path. Whether a pcrc-absent article may ride here is lean
    /// mode's call, not this function's - lean owns that trade, and
    /// [`take_pre_spans`](Self::take_pre_spans) is the single gate that
    /// decides it. Call this only with the source `take_pre_spans` handed
    /// back; it is what tells the routes apart.
    pub fn on_data_backfill(
        &self,
        slot: usize,
        name: &str,
        file_size: u64,
        offset: u64,
        data: &[u8],
    ) {
        self.on_data_inner(slot, name, file_size, offset, data, Src::Rehash);
    }

    /// A decoder-fresh span no wire CRC covered: the article CRC was
    /// deliberately skipped (delegation under lean), or the article
    /// carried no pcrc32 at all. Distinct from
    /// [`Self::on_data_from_disk`] so settle read-backs keep their
    /// full-MD5 contract while lean spans may claim CRC-only. Only lean
    /// unlocks that claim - a pcrc-absent article takes full MD5 in
    /// default fast mode, live and through the backfill alike.
    pub fn on_data_unverified(
        &self,
        slot: usize,
        name: &str,
        file_size: u64,
        offset: u64,
        data: &[u8],
    ) {
        self.on_data_inner(slot, name, file_size, offset, data, Src::Lean);
    }

    fn on_data_inner(
        &self,
        slot: usize,
        name: &str,
        file_size: u64,
        offset: u64,
        data: &[u8],
        src: Src,
    ) {
        let plan = self.plan.read_ok();
        let mut s = self.slots[slot].lock_ok();

        if s.name.is_none() && !name.is_empty() {
            s.name = Some(name.to_string());
        }
        if s.file_size == 0 {
            s.file_size = file_size;
        }

        let active = match &*plan {
            Plan::Active(a) => a,
            Plan::Off => return,
            Plan::Waiting => {
                s.capture_head(offset, data);
                // Record how weakly the span may be claimed once the M15b
                // backfill re-feeds it: `pre_spans` are offsets only, so
                // the whole slot comes back under one source. Without this
                // the round trip through disk LAUNDERS trust - a
                // pcrc-absent article (Src::Lean in default fast mode,
                // denied a CRC-only claim below) would return as
                // Src::Rehash and be claimed on the block CRC32 alone.
                match src {
                    Src::Fresh | Src::Rehash => {}
                    Src::Lean => s.pre_unvouched = true,
                    // Nothing in this run vouches at all: same standing as
                    // a crash-resume seed.
                    Src::Disk => s.resume_seeded = true,
                }
                s.pre_spans.push((offset, data.len() as u32));
                return;
            }
        };

        if s.file.is_none() {
            s.capture_head(offset, data);
            if s.unmatchable || !s.try_match(slot, active) {
                return;
            }
        }

        let fi = s.file.unwrap();
        let file = &active.set.files[fi];
        let bs = active.set.block_size as usize;
        if file.blocks.is_empty() || bs == 0 {
            return; // no IFSC - finish_slot settles via whole-file MD5
        }

        // Clamp the span to the PAR2 length (yEnc padding beyond it is noise).
        let len = (data.len() as u64).min(file.length.saturating_sub(offset)) as usize;
        if len == 0 {
            return;
        }
        let data = &data[..len];
        let span = offset as usize..offset as usize + len;

        // Claim work under the lock, hash outside it. Fast/lean spans
        // (decided below, same condition as the check fn) route boundary
        // blocks through CRC-parts (B1): no bytes are held, so nothing
        // counts against the partials budget and no spill can happen.
        // Src::Lean reaches here in two cases: lean mode is on (its documented
        // single-CRC32 contract), OR the article carried no pcrc32 in default
        // fast mode (main.rs routes crc_checked=false to Src::Lean). The latter
        // must NOT make a CRC-only claim - with no wire CRC to vouch for it a
        // single block CRC32 would be its only integrity, half the two-CRC
        // guarantee fast mode promises. Gate Lean on lean actually being on so
        // a pcrc-absent article falls to full MD5 (both claim and check below).
        // Src::Rehash rides with Fresh: same run, only a round trip through
        // our own writer in between. Its pcrc32 passed too, EXCEPT where
        // lean mode routed a pcrc-absent article here - lean makes that
        // trade knowingly, and take_pre_spans is where it is made.
        let crc_claims = self.fast.load(std::sync::atomic::Ordering::Relaxed)
            && (matches!(src, Src::Fresh | Src::Rehash)
                || (matches!(src, Src::Lean)
                    && self.lean.load(std::sync::atomic::Ordering::Relaxed)));
        let first_block = span.start / bs;
        let last_block = (span.end - 1) / bs;
        let mut full: Vec<usize> = Vec::new(); // hash straight from `data`
        let mut ready: Vec<(usize, Vec<u8>)> = Vec::new(); // completed byte partials
        let mut crc_jobs: Vec<(usize, usize, usize)> = Vec::new(); // (bi, os, oe)
        for bi in first_block..=last_block.min(file.blocks.len() - 1) {
            if s.blocks[bi] != BlockState::Pending {
                continue;
            }
            let bstart = bi * bs;
            let blen = block_len(file.length, bs, bi);
            let bend = bstart + blen;
            if span.start <= bstart && bend <= span.end {
                full.push(bi);
                continue;
            }
            // Boundary block: track the overlapping fragment.
            let os = span.start.max(bstart);
            let oe = span.end.min(bend);
            match s.partials.get_mut(&bi) {
                Some(PartialBuf::Crc(_)) if !crc_claims => {
                    // Mixed trust: this fragment has no wire CRC vouching
                    // for it (a disk read-back, or a pcrc-absent article in
                    // default fast mode), and the parts already held are
                    // CRCs, not bytes - so a composed block CRC32 would be
                    // this block's ONLY integrity layer. Gate on crc_claims
                    // rather than Src::Disk alone: whatever makes a span
                    // unable to claim CRC-only makes it unable to lend its
                    // bytes to someone else's CRC-only claim.
                    // Abandon to settle read-back (which always full-MD5s).
                    s.partials.remove(&bi);
                    self.partials_spilled
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                Some(PartialBuf::Crc(_)) => crc_jobs.push((bi, os, oe)),
                Some(PartialBuf::Bytes(p)) => {
                    // Byte-mode block (created under full-MD5 or by a disk
                    // span): keep filling bytes whatever this span's mode.
                    p.fill(os - bstart, &data[os - span.start..oe - span.start]);
                    if p.complete() {
                        let Some(PartialBuf::Bytes(p)) = s.partials.remove(&bi) else {
                            unreachable!()
                        };
                        s.partial_bytes -= p.buf.len();
                        self.partials_used
                            .fetch_sub(p.buf.len(), std::sync::atomic::Ordering::Relaxed);
                        ready.push((bi, p.buf));
                    }
                }
                None if crc_claims => {
                    s.partials.insert(bi, PartialBuf::Crc(CrcParts::new()));
                    crc_jobs.push((bi, os, oe));
                }
                None => {
                    // GLOBAL budget check (M15): the sum across every slot
                    // stays under the cap, whatever the volume count.
                    // Reserve-then-check so concurrent slots can't both
                    // pass a load() and overshoot the cap together.
                    use std::sync::atomic::Ordering;
                    let prev = self.partials_used.fetch_add(blen, Ordering::Relaxed);
                    if prev + blen > self.partials_cap {
                        self.partials_used.fetch_sub(blen, Ordering::Relaxed);
                        self.partials_spilled.fetch_add(1, Ordering::Relaxed);
                        continue; // leave Pending → read-back at finish
                    }
                    self.partials_peak.fetch_max(prev + blen, Ordering::Relaxed);
                    s.partial_bytes += blen;
                    let mut p = Partial::new(blen);
                    p.fill(os - bstart, &data[os - span.start..oe - span.start]);
                    // A single span can't complete a boundary block it
                    // just created (some other article owns the rest).
                    s.partials.insert(bi, PartialBuf::Bytes(p));
                }
            }
        }
        let set = active.set.clone();
        drop(s);
        drop(plan);

        // Lock-free hashing. Fast verify applies only to trusted spans -
        // ones straight out of a decoder that already enforced the yEnc
        // pcrc32, so the CRC-only claim keeps two independent CRC32
        // layers. Disk-fed spans (backfill, crash-resume) always hash in
        // full: no wire CRC vouches for them.
        // Fresh spans: pcrc passed, CRC-only claim justified. Lean
        // spans: the caller opted into single-CRC32 in-stream integrity
        // (only sent when lean is on). Disk spans (settle read-back)
        // ALWAYS full-MD5 - lean does not weaken that contract.
        // (`crc_claims` above is the same condition - boundary fragments
        // of such spans were queued as CRC jobs.)
        let check = if crc_claims {
            check_block_crc
        } else {
            check_block
        };
        let file = &set.files[fi];
        let mut results: Vec<(usize, bool)> = Vec::with_capacity(full.len() + ready.len());
        for bi in full {
            let bstart = bi * bs;
            let blen = block_len(file.length, bs, bi);
            let rel = bstart - span.start;
            let ok = check(&file.blocks[bi], bs, &data[rel..rel + blen]);
            results.push((bi, ok));
        }
        // Completed byte partials ALWAYS take full MD5, regardless of what
        // THIS span may claim. A byte partial exists only because some
        // fragment of the block arrived without a wire CRC (the `None` arm
        // allocates bytes exactly when `crc_claims` is false), and the span
        // that happens to finish a block says nothing about the ones that
        // started it - a disk-fed fragment completed by a fresh article
        // would otherwise be claimed on the block CRC32 alone.
        for (bi, buf) in ready {
            let ok = check_block(&file.blocks[bi], bs, &buf);
            results.push((bi, ok));
        }
        // B1: fragment CRCs, also outside the lock (hardware CRC is fast,
        // but a block-sized fragment is still real work at 2 cores).
        let crc_frags: Vec<(usize, usize, usize, u32)> = crc_jobs
            .into_iter()
            .map(|(bi, os, oe)| {
                let crc = crc32fast::hash(&data[os - span.start..oe - span.start]);
                (bi, os, oe, crc)
            })
            .collect();

        if !results.is_empty() || !crc_frags.is_empty() {
            use std::sync::atomic::Ordering;
            let mut s = self.slots[slot].lock_ok();
            let record = |s: &mut SlotState, bi: usize, ok: bool| {
                if s.blocks[bi] == BlockState::Pending {
                    s.blocks[bi] = if ok { BlockState::Ok } else { BlockState::Bad };
                    if ok {
                        s.live_ok += 1;
                        self.live_ok_total.fetch_add(1, Ordering::Relaxed);
                    } else {
                        s.live_bad += 1;
                        self.live_bad_total.fetch_add(1, Ordering::Relaxed);
                    }
                }
            };
            for (bi, ok) in results {
                record(&mut s, bi, ok);
            }
            for (bi, os, oe, crc) in crc_frags {
                if s.blocks[bi] != BlockState::Pending {
                    // Raced: another span (one containing the whole block)
                    // already settled it - drop the stale partial.
                    s.partials.remove(&bi);
                    continue;
                }
                let Some(PartialBuf::Crc(parts)) = s.partials.get_mut(&bi) else {
                    continue; // vanished (mixed-trust abandon) - stays Pending
                };
                let bstart = bi * bs;
                if !parts.insert(os - bstart, oe - bstart, crc) {
                    // Overlapping re-feed - can't compose CRCs losslessly.
                    s.partials.remove(&bi);
                    self.partials_spilled.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                let blen = block_len(file.length, bs, bi);
                if let Some(crc_data) = parts.complete(blen) {
                    // IFSC checksums cover the block zero-padded to bs.
                    let final_crc = if blen < bs {
                        crate::yenc_simd::crc32_zeros(crc_data, (bs - blen) as u64)
                    } else {
                        crc_data
                    };
                    s.partials.remove(&bi);
                    record(&mut s, bi, final_crc == file.blocks[bi].crc32);
                }
            }
        }
    }

    /// Crash resume: register spans a previous run already persisted (and
    /// the journal restored) as pre-activation spans. The M15b backfill
    /// then reads them from disk once the set activates and verifies
    /// their blocks against the PAR2 block map - restored bytes are
    /// trusted only after they hash clean (settle read-back backstops
    /// anything the backfill couldn't reach).
    pub fn seed_pre_spans(&self, slot: usize, spans: &[(u64, u64)]) {
        let mut s = self.slots[slot].lock_ok();
        s.resume_seeded = true;
        for &(off, len) in spans {
            let (mut off, mut len) = (off, len);
            while len > 0 {
                let n = len.min(u32::MAX as u64);
                s.pre_spans.push((off, n as u32));
                off += n;
                len -= n;
            }
        }
    }

    /// Drain the spans a slot decoded before activation (coalesced,
    /// sorted) for the backfill pass, with the source the re-read bytes
    /// must be fed under: [`PreSpanSrc::Backfill`] when this run decoded
    /// every one of them under a passing pcrc32, [`PreSpanSrc::Disk`] when
    /// crash resume seeded any (see [`Self::seed_pre_spans`]) or any span
    /// came in with no wire CRC covering it.
    ///
    /// Lean is the one mode that keeps unvouched spans on the backfill
    /// route: it is exactly the mode where a span the decoder did not
    /// vouch for may still be claimed CRC-only, so the disk round trip
    /// hands back no more trust than the span had live.
    pub fn take_pre_spans(&self, slot: usize) -> (Vec<(u64, u64)>, PreSpanSrc) {
        let mut s = self.slots[slot].lock_ok();
        let lean = self.lean.load(std::sync::atomic::Ordering::Relaxed);
        let how = if s.resume_seeded || (s.pre_unvouched && !lean) {
            PreSpanSrc::Disk
        } else {
            PreSpanSrc::Backfill
        };
        let mut spans = std::mem::take(&mut s.pre_spans);
        drop(s);
        spans.sort_unstable();
        let mut out: Vec<(u64, u64)> = Vec::new();
        for (off, len) in spans {
            let (off, len) = (off, len as u64);
            match out.last_mut() {
                Some((_, e)) if off <= *e && off + len > *e => *e = off + len,
                Some((_, e)) if off + len <= *e => {}
                _ => out.push((off, off + len)),
            }
        }
        (out.into_iter().map(|(s, e)| (s, e - s)).collect(), how)
    }

    /// (peak partial-buffer bytes, blocks spilled to read-back) - the
    /// end-of-run memory summary (M15).
    pub fn partials_stats(&self) -> (usize, u64) {
        use std::sync::atomic::Ordering;
        (
            self.partials_peak.load(Ordering::Relaxed),
            self.partials_spilled.load(Ordering::Relaxed),
        )
    }

    /// (blocks verified in-stream so far, of which bad) - dashboard gauge.
    pub fn live_counts(&self) -> (u64, u64) {
        use std::sync::atomic::Ordering;
        (
            self.live_ok_total.load(Ordering::Relaxed)
                + self.live_bad_total.load(Ordering::Relaxed),
            self.live_bad_total.load(Ordering::Relaxed),
        )
    }

    /// Settle a slot when all its articles are terminal: read back every
    /// still-pending block from `path` (None if no file was ever created)
    /// and return the verdict. Returns None when no PAR2 file matched this
    /// slot (nothing to verify against).
    pub fn finish_slot(&self, slot: usize, path: Option<&Path>) -> Option<SlotReport> {
        match path {
            Some(p) => self.finish_slot_from(slot, ReadAt::Path(p)),
            None => self.finish_slot_from(slot, ReadAt::Missing),
        }
    }

    /// [`finish_slot`](Self::finish_slot) with a generic byte source - for
    /// direct-extracted RAR volumes the "file" is reconstructed on demand
    /// (header stash + extracted-file pread) instead of read from disk.
    pub fn finish_slot_from(&self, slot: usize, src: ReadAt<'_>) -> Option<SlotReport> {
        let plan = self.plan.read_ok();
        let active = match &*plan {
            Plan::Active(a) => a,
            _ => return None,
        };
        let mut s = self.slots[slot].lock_ok();
        // Last-chance match (e.g. every article of the slot arrived before
        // activation, so on_data never ran while Active).
        if s.file.is_none() && !s.unmatchable {
            s.try_match(slot, active);
        }
        let fi = s.file?;
        let file = &active.set.files[fi];
        let bs = active.set.block_size as usize;

        // Drop leftover partials - their blocks read back below. Return
        // their bytes to the global budget (M15).
        s.partials.clear();
        self.partials_used
            .fetch_sub(s.partial_bytes, std::sync::atomic::Ordering::Relaxed);
        s.partial_bytes = 0;

        let mut bad: Vec<usize> = Vec::new();
        let mut readback = 0u64;

        if file.blocks.is_empty() {
            // No IFSC: whole-file MD5 is the only check.
            let ok = src_md5(&src, file.length).is_ok_and(|md5| md5 == file.md5);
            return Some(SlotReport {
                par2_name: Some(file.name.clone()),
                total_blocks: 0,
                bad_blocks: if ok { Vec::new() } else { vec![0] },
                live_blocks: 0,
                readback_blocks: 1,
                length: file.length,
            });
        }

        let pending: Vec<usize> = s
            .blocks
            .iter()
            .enumerate()
            .filter(|(_, st)| **st == BlockState::Pending)
            .map(|(i, _)| i)
            .collect();
        if !pending.is_empty() {
            let f = match &src {
                ReadAt::Path(p) => std::fs::File::open(p).ok(),
                _ => None,
            };
            // One block-sized buffer per slot was `block_size` resident, and
            // the caller settles slots on up to 12 threads: the accepted wire
            // block size runs to 256 MiB, so a small, valid PAR2 metadata set
            // naming a dozen targets with one pending block each asked for
            // ~3 GiB at once. Bounded above 8 MiB, where the block is read
            // and hashed in chunks instead (`read_block_chunked`); at or
            // below it - every real-world set - the single-buffer path with
            // its CRC-before-MD5 short circuit is unchanged.
            const READBACK_CHUNK: usize = 8 << 20;
            let mut buf = vec![0u8; bs.min(READBACK_CHUNK)];
            for bi in pending {
                readback += 1;
                let blen = block_len(file.length, bs, bi);
                let ok = if bs <= READBACK_CHUNK {
                    let got = match (&src, &f) {
                        (ReadAt::Path(_), Some(f)) => {
                            crate::disk::read_exact_at(f, &mut buf[..blen], (bi * bs) as u64)
                                .is_ok()
                        }
                        (ReadAt::Reader(r), _) => r((bi * bs) as u64, &mut buf[..blen]).is_ok(),
                        _ => false,
                    };
                    got && check_block(&file.blocks[bi], bs, &buf[..blen])
                } else {
                    read_block_chunked(&src, f.as_ref(), (bi * bs) as u64, blen, &mut buf)
                        .is_some_and(|check| check.finish(&file.blocks[bi], bs))
                };
                s.blocks[bi] = if ok { BlockState::Ok } else { BlockState::Bad };
            }
        }
        for (bi, st) in s.blocks.iter().enumerate() {
            if *st == BlockState::Bad {
                bad.push(bi);
            }
        }
        Some(SlotReport {
            par2_name: Some(file.name.clone()),
            total_blocks: file.blocks.len(),
            bad_blocks: bad,
            live_blocks: s.live_ok + s.live_bad,
            readback_blocks: readback,
            length: file.length,
        })
    }

    /// PAR2 files no slot claimed (files entirely absent from the NZB or
    /// whose every article vanished before a name could be learned).
    pub fn unclaimed_files(&self) -> Vec<String> {
        match &*self.plan.read_ok() {
            Plan::Active(a) => a
                .claimed
                .lock()
                .unwrap()
                .iter()
                .enumerate()
                .filter(|(_, c)| c.is_none())
                .map(|(i, _)| a.set.files[i].name.clone())
                .collect(),
            _ => Vec::new(),
        }
    }
}

impl SlotState {
    fn head_want(&self) -> usize {
        if self.file_size > 0 {
            (self.file_size as usize).min(HEAD_LEN)
        } else {
            HEAD_LEN
        }
    }

    fn capture_head(&mut self, offset: u64, data: &[u8]) {
        let want = self.head_want();
        if want == 0 || offset as usize >= want {
            return;
        }
        let head = self.head.get_or_insert_with(|| Partial::new(want));
        if head.buf.len() != want {
            // file_size learned after the first capture changed `want`;
            // restart (rare, only when the very first article lacked a size).
            *head = Partial::new(want);
        }
        if head.complete() {
            return;
        }
        let off = offset as usize;
        let end = (off + data.len()).min(want);
        if end > off {
            head.fill(off, &data[..end - off]);
        }
    }

    /// Try to claim a PAR2 file for this slot. Name match first, md5-16k
    /// second. Requires `self.file.is_none()`.
    fn try_match(&mut self, slot: usize, active: &Active) -> bool {
        let files = &active.set.files;
        let mut claimed = active.claimed.lock_ok();

        if let Some(name) = &self.name {
            let sname = crate::disk::sanitize_filename(name);
            for (fi, f) in files.iter().enumerate() {
                if claimed[fi].is_some() {
                    continue;
                }
                if f.name == *name
                    || f.name.eq_ignore_ascii_case(name)
                    || crate::disk::sanitize_filename(&f.name) == sname
                {
                    claimed[fi] = Some(slot);
                    self.file = Some(fi);
                    self.blocks = vec![BlockState::Pending; f.blocks.len()];
                    return true;
                }
            }
        }
        // md5-16k fallback (obfuscated names).
        let want = self.head_want();
        if want > 0
            && self
                .head
                .as_ref()
                .is_some_and(|h| h.buf.len() == want && h.complete())
        {
            let head_md5: [u8; 16] = Md5::digest(&self.head.as_ref().unwrap().buf).into();
            for (fi, f) in files.iter().enumerate() {
                if claimed[fi].is_some() || f.length.min(HEAD_LEN as u64) != want as u64 {
                    continue;
                }
                if f.md5_16k == head_md5 {
                    claimed[fi] = Some(slot);
                    self.file = Some(fi);
                    self.blocks = vec![BlockState::Pending; f.blocks.len()];
                    return true;
                }
            }
            // Head is complete and matched nothing: if the name also failed,
            // this slot will never match (nfo/sfv/sample files).
            if self.name.is_some() {
                self.unmatchable = true;
            }
        }
        false
    }
}

/// Real (unpadded) length of block `bi` of a `length`-byte file.
fn block_len(length: u64, bs: usize, bi: usize) -> usize {
    let start = (bi * bs) as u64;
    ((length - start.min(length)) as usize).min(bs)
}

/// Hash `bytes` (the real bytes of one block, zero-padded to `block_size`
/// per spec) and compare with the IFSC checksums. MD5 + CRC32 must both
/// match - identical semantics to `par2::verify_file_blocks`. CRC32 runs
/// first: hardware CRC is ~13× faster than MD5, so a mismatching (damaged)
/// block never pays for the MD5 pass.
pub fn check_block(check: &BlockCheck, block_size: usize, bytes: &[u8]) -> bool {
    if !check_block_crc(check, block_size, bytes) {
        return false;
    }
    let mut md5 = Md5::new();
    md5.update(bytes);
    pad_to(block_size, bytes.len(), |z| md5.update(z));
    <[u8; 16]>::from(md5.finalize()) == check.md5
}

/// CRC32-only block check - the fast-verify hot path. The caller must only
/// use this for bytes that already carry an independent integrity check
/// (in-stream spans passed their yEnc pcrc32 in the decoder); a false
/// accept then requires corruption that survives two independent CRC32s
/// over differently-aligned spans.
pub fn check_block_crc(check: &BlockCheck, block_size: usize, bytes: &[u8]) -> bool {
    debug_assert!(bytes.len() <= block_size);
    let mut crc = crc32fast::Hasher::new();
    crc.update(bytes);
    pad_to(block_size, bytes.len(), |z| crc.update(z));
    crc.finalize() == check.crc32
}

/// [`check_block`] fed in pieces, for a block too big to hold at once.
///
/// Both digests run together, so the CRC-before-MD5 short circuit is gone -
/// which is why the caller only uses this above the chunking threshold, where
/// holding the whole block is the larger cost by far.
struct StreamedBlock {
    crc: crc32fast::Hasher,
    md5: Md5,
    len: usize,
}

impl StreamedBlock {
    fn new() -> Self {
        Self {
            crc: crc32fast::Hasher::new(),
            md5: Md5::new(),
            len: 0,
        }
    }

    fn update(&mut self, bytes: &[u8]) {
        self.crc.update(bytes);
        self.md5.update(bytes);
        self.len += bytes.len();
    }

    /// Pad to `block_size` per spec and compare both digests.
    fn finish(mut self, check: &BlockCheck, block_size: usize) -> bool {
        // O(log n) through the padding rather than hashing it: the padding on
        // a 256 MiB block is itself most of a block.
        if crate::yenc_simd::crc32_zeros(self.crc.finalize(), (block_size - self.len) as u64)
            != check.crc32
        {
            return false;
        }
        pad_to(block_size, self.len, |z| self.md5.update(z));
        <[u8; 16]>::from(self.md5.finalize()) == check.md5
    }
}

/// Read one block through `buf` in `buf.len()` pieces, hashing as it goes.
/// `None` if any read failed - a block that cannot be read is damage.
fn read_block_chunked(
    src: &ReadAt<'_>,
    file: Option<&std::fs::File>,
    base: u64,
    blen: usize,
    buf: &mut [u8],
) -> Option<StreamedBlock> {
    let mut check = StreamedBlock::new();
    let mut done = 0usize;
    while done < blen {
        let n = (blen - done).min(buf.len());
        let ok = match (src, file) {
            (ReadAt::Path(_), Some(f)) => {
                crate::disk::read_exact_at(f, &mut buf[..n], base + done as u64).is_ok()
            }
            (ReadAt::Reader(r), _) => r(base + done as u64, &mut buf[..n]).is_ok(),
            _ => false,
        };
        if !ok {
            return None;
        }
        check.update(&buf[..n]);
        done += n;
    }
    Some(check)
}

/// Feed `block_size - len` zero-padding bytes to a hasher, chunk-wise.
fn pad_to(block_size: usize, len: usize, mut update: impl FnMut(&[u8])) {
    const ZEROS: [u8; 4096] = [0; 4096];
    let mut rem = block_size - len;
    while rem > 0 {
        let n = rem.min(ZEROS.len());
        update(&ZEROS[..n]);
        rem -= n;
    }
}

/// A source of file bytes for read-back settling.
pub enum ReadAt<'a> {
    /// No backing data at all (file never created).
    Missing,
    /// An ordinary file on disk.
    Path(&'a Path),
    /// Reconstructed bytes (direct-extracted volumes): read `buf.len()`
    /// bytes at the given offset.
    #[allow(clippy::type_complexity)]
    Reader(&'a (dyn Fn(u64, &mut [u8]) -> io::Result<()> + Sync)),
}

/// Streaming whole-file MD5 (for IFSC-less sets).
fn src_md5(src: &ReadAt<'_>, expect_len: u64) -> io::Result<[u8; 16]> {
    let mut md5 = Md5::new();
    match src {
        ReadAt::Missing => Err(io::Error::new(io::ErrorKind::NotFound, "no data")),
        ReadAt::Path(path) => {
            use std::io::Read;
            let mut f = std::fs::File::open(path)?;
            if f.metadata()?.len() != expect_len {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "length mismatch",
                ));
            }
            let mut buf = vec![0u8; 1 << 20];
            loop {
                let n = f.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                md5.update(&buf[..n]);
            }
            Ok(md5.finalize().into())
        }
        ReadAt::Reader(r) => {
            let mut buf = vec![0u8; 1 << 20];
            let mut off = 0u64;
            while off < expect_len {
                let n = ((expect_len - off) as usize).min(buf.len());
                r(off, &mut buf[..n])?;
                md5.update(&buf[..n]);
                off += n as u64;
            }
            Ok(md5.finalize().into())
        }
    }
}

/// Parse par2 inputs into one set. If the inputs mix recovery sets (an NZB
/// carrying several releases), fall back to parsing each input alone and
/// keep the set describing the most files.
pub fn pick_set(inputs: &[&[u8]]) -> Result<Par2Set, Par2Error> {
    match Par2Set::parse(inputs) {
        Ok(set) => Ok(set),
        Err(Par2Error::MixedRecoverySets) => inputs
            .iter()
            .filter_map(|i| Par2Set::parse(&[i]).ok())
            .max_by_key(|s| s.files.len())
            .ok_or(Par2Error::NoMainPacket),
        Err(e) => Err(e),
    }
}

/// Files/blocks needed for repair planning, computed from slot reports.
#[derive(Debug, Default)]
pub struct DamageSummary {
    pub bad_blocks: usize,
    pub damaged_files: Vec<String>,
}

pub fn summarize_damage<'a>(reports: impl Iterator<Item = &'a SlotReport>) -> DamageSummary {
    let mut d = DamageSummary::default();
    for r in reports {
        if !r.bad_blocks.is_empty() {
            d.bad_blocks += r.bad_blocks.len();
            if let Some(n) = &r.par2_name {
                d.damaged_files.push(n.clone());
            }
        }
    }
    d
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pre-activation spans are re-fed by the M15b backfill under ONE
    /// source per slot, so a span no wire CRC covered must not come back
    /// as a fresh-strength `Rehash` claim - the disk round trip would
    /// otherwise hand a pcrc-absent article a CRC32-only verdict.
    #[test]
    fn unvouched_pre_spans_take_the_disk_backfill() {
        let data = [7u8; 4096];
        let v = LiveVerifier::new(3);
        v.set_fast_verify(true);

        // Every span wire-CRC'd: the CRC-parts backfill route stands.
        v.on_data(0, "a.bin", 8192, 0, &data);
        v.on_data(0, "a.bin", 8192, 4096, &data);
        assert_eq!(v.take_pre_spans(0).1, PreSpanSrc::Backfill);

        // One pcrc-absent article taints the slot in default fast mode.
        v.on_data(1, "b.bin", 8192, 0, &data);
        v.on_data_unverified(1, "b.bin", 8192, 4096, &data);
        assert_eq!(v.take_pre_spans(1).1, PreSpanSrc::Disk);

        // Lean owns the weaker contract, so its own spans keep the route.
        v.set_lean(true);
        v.on_data_unverified(2, "c.bin", 8192, 0, &data);
        assert_eq!(v.take_pre_spans(2).1, PreSpanSrc::Backfill);
    }
}

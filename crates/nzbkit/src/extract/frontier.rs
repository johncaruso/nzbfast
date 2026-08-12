//! The frontier buffer: the arriving-bytes window a chase worker
//! reads through - holes, blocking reads, the drop-behind trim, and
//! the differing-rewrite tripwire.
//!
//! Split out of the 19,920-line `extract.rs` under the TODO 43
//! recipe: a verbatim move, not a redesign.

use super::*;
use crate::sync::MutexExt;

/// In-flight byte store for one chased volume. Spans arrive in any order;
/// readers see a CONTIGUOUS frontier from offset 0 and block for bytes
/// beyond it (the RAR decode is forward-only, so blocking at the frontier
/// is exactly the chase). Out-of-order spans park in a hole map and fold
/// into the frontier as the gaps fill - a late PAR2-rebuilt block enters
/// like any other span and simply unblocks the reader.
pub(super) struct FrontierBuffer {
    pub(super) state: Mutex<FrontierState>,
    pub(super) arrived: Condvar,
    /// §94 B: when Some, reads only serve bytes below the slot's
    /// verified-block watermark - the chase decode consumes nothing the
    /// PAR2 set has not vouched for, so a repair can never rewrite
    /// consumed bytes. None = ungated (no set, unclaimed slot, feature
    /// off): behavior is exactly the pre-gate code.
    gate: Option<(std::sync::Arc<crate::live::VerifyGate>, usize)>,
    /// The chain's holds scratch, when this buffer may page cold spans
    /// out of RAM ([`Self::page_cold`] - the terminally-stalled-chase
    /// spill). None (the 7z/zip chases, tests): nothing ever pages and
    /// every path behaves exactly as before paging existed.
    scratch: Option<Arc<HoldsScratch>>,
}

#[derive(Default)]
pub(super) struct FrontierState {
    /// Volume offset of `data[0]`. Zero until a drop-behind trim moves
    /// it; past that point the bytes below it are no longer in RAM (the
    /// trim spilled them into the slot's own archive file, which is
    /// where a demotion would have put them anyway). Reads below it
    /// fail here and are served by the caller from that file.
    pub(super) base: u64,
    /// Contiguous bytes from volume offset `base`.
    pub(super) data: Vec<u8>,
    /// Spans beyond the frontier, keyed by start offset.
    pub(super) pending: BTreeMap<u64, Vec<u8>>,
    /// Spans paged out to the holds scratch (start offset -> scratch
    /// region offset + length), disjoint among themselves. Created only
    /// by [`FrontierBuffer::page_cold`] on a chase stalled behind
    /// terminally-missing articles; bytes here always AGREE with any
    /// overlapping RAM copy (write_span reconciles every delivery), so
    /// duplicated coverage is harmless everywhere it can arise.
    pub(super) paged: BTreeMap<u64, (u64, usize)>,
    /// Sum of paged span lengths - the scratch live-count this buffer
    /// still owes (released per span on read-back, remainder on Drop).
    pub(super) paged_bytes: usize,
    /// Declared volume size (the level-1 entry's unpacked size).
    pub(super) total: u64,
    /// Retained RAM bytes (frontier + pending; paged spans excluded) -
    /// what the holds budget is charged for.
    pub(super) stored: usize,
    /// A rewrite arrived whose bytes DIFFERED from what was already
    /// retained for that range. Sticky, and never cleared: see
    /// [`FrontierBuffer::write_span`].
    pub(super) conflict: bool,
    pub(super) abort: Option<String>,
}

impl FrontierState {
    /// One past the last byte of the contiguous RAM run, in VOLUME
    /// offsets - where `data` ends. Appends, folds and the drop-behind
    /// trim all work on this edge.
    pub(super) fn frontier_ram(&self) -> u64 {
        self.base + self.data.len() as u64
    }

    /// One past the last contiguously-COVERED byte from `base`, in
    /// volume offsets: the RAM run extended through any paged and
    /// parked spans that continue it without a hole. This is the
    /// "arrived" edge - completeness and `known_len` read it, and the
    /// blocking readers can serve every byte below it (paged ones via
    /// pread).
    pub(super) fn frontier(&self) -> u64 {
        let mut f = self.frontier_ram();
        loop {
            let paged = self
                .paged
                .range(..=f)
                .next_back()
                .map(|(&s, &(_, len))| s + len as u64)
                .filter(|&e| e > f);
            let pending = self
                .pending
                .range(..=f)
                .next_back()
                .map(|(&s, v)| s + v.len() as u64)
                .filter(|&e| e > f);
            match paged.max(pending) {
                Some(e) => f = e,
                None => return f,
            }
        }
    }

    /// The paged span covering `pos`, if any: `(start, region offset,
    /// length)`.
    fn paged_at(&self, pos: u64) -> Option<(u64, u64, usize)> {
        self.paged
            .range(..=pos)
            .next_back()
            .filter(|&(&s, &(_, len))| s + len as u64 > pos)
            .map(|(&s, &(off, len))| (s, off, len))
    }
}

impl std::fmt::Debug for FrontierBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let st = self.state.lock_ok();
        f.debug_struct("FrontierBuffer")
            .field("base", &st.base)
            .field("frontier", &st.frontier())
            .field("pending", &st.pending.len())
            .field("paged", &st.paged.len())
            .field("total", &st.total)
            .field("abort", &st.abort)
            .finish()
    }
}

impl FrontierBuffer {
    /// Ungated construction. Production callers all attach the §94 B
    /// watermark gate via [`Self::new_gated`], so this survives for the
    /// tests, which exercise the buffer without a verify pipeline.
    #[cfg(test)]
    pub(super) fn new(total: u64) -> FrontierBuffer {
        Self::new_gated(total, None, None)
    }

    /// Construction with an optional §94 B watermark gate attached, and
    /// an optional holds scratch that arms [`Self::page_cold`].
    pub(super) fn new_gated(
        total: u64,
        gate: Option<(std::sync::Arc<crate::live::VerifyGate>, usize)>,
        scratch: Option<Arc<HoldsScratch>>,
    ) -> FrontierBuffer {
        FrontierBuffer {
            state: Mutex::new(FrontierState {
                total,
                ..Default::default()
            }),
            arrived: Condvar::new(),
            gate,
            scratch,
        }
    }

    /// The §94 B serving limit: bytes at or past this offset are not yet
    /// PAR2-vouched and must not reach the decode. Ungated = MAX.
    fn gate_limit(&self) -> u64 {
        match &self.gate {
            Some((g, slot)) => g.watermark(*slot),
            None => u64::MAX,
        }
    }

    /// Park briefly for a watermark advance past `offset`. Bounded so a
    /// gate-blocked reader still observes buffer abort/demote (which
    /// notify [`Self::arrived`], not the gate) on its next loop pass.
    fn gate_wait(&self, offset: u64) {
        if let Some((g, slot)) = &self.gate {
            g.wait_past(*slot, offset, std::time::Duration::from_millis(100));
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
    pub(super) fn write_span(&self, offset: u64, bytes: &[u8]) -> usize {
        let mut st = self.state.lock_ok();
        if st.abort.is_some() {
            return st.stored;
        }
        let end = (offset + bytes.len() as u64).min(st.total);
        if end <= offset {
            return st.stored;
        }
        let bytes = &bytes[..(end - offset) as usize];
        let base = st.base;
        let frontier = st.frontier_ram();
        let mut accepted = false;
        let mut differed = false;
        // Whatever we already retain for this range, the newest delivery
        // wins. Checked against the frontier AND the parked spans: the 7z
        // chase peeks at arbitrary offsets, so a parked span can have been
        // read too, and a rewrite of one is no safer to discard.
        //
        // The sub-range below `base` is not ours to reconcile - it is on
        // disk, not in `data`. `below_base()` reports it and the caller
        // fixes the file and forfeits; here it is simply skipped, which
        // is why the clip is to `base` and not to `offset`.
        if offset < frontier && end > base {
            let a = offset.max(base);
            let n = (frontier.min(end) - a) as usize;
            let di = (a - base) as usize;
            let si = (a - offset) as usize;
            let dst = &mut st.data[di..di + n];
            if *dst != bytes[si..si + n] {
                dst.copy_from_slice(&bytes[si..si + n]);
                differed = true;
            }
        }
        // Paged spans reconcile too - a delivery overlapping one is
        // either a routing duplicate (identical bytes; the paged copy
        // stands and this part of the span need not be re-retained) or
        // a repair rewrite. Scratch regions are write-once, so a
        // differing rewrite UN-PAGES the region: the corrected copy
        // parks in RAM, where a demotion materializes it exactly, and
        // the sticky conflict below forfeits the chase like any other
        // rewrite. A scratch READ error also flags the conflict: the
        // copies cannot be proven to agree, and the demote's own
        // read-back will surface the I/O error as the job failure.
        if !st.paged.is_empty() && end > base {
            let overlapping: Vec<(u64, u64, usize)> = {
                let lo = st
                    .paged
                    .range(..=offset)
                    .next_back()
                    .map(|(&s, _)| s)
                    .unwrap_or(0);
                st.paged
                    .range(lo..end)
                    .filter(|&(&s, &(_, len))| s + len as u64 > offset && s < end)
                    .map(|(&s, &(off, len))| (s, off, len))
                    .collect()
            };
            for (s, po, len) in overlapping {
                let a = offset.max(s);
                let b = end.min(s + len as u64);
                let mut have = vec![0u8; (b - a) as usize];
                let Some(sc) = self.scratch.as_ref() else {
                    debug_assert!(false, "paged span with no scratch");
                    differed = true;
                    continue;
                };
                if sc.read(po + (a - s), &mut have).is_err() {
                    differed = true;
                    continue;
                }
                let src = &bytes[(a - offset) as usize..(b - offset) as usize];
                if have == src {
                    continue;
                }
                // Read the whole region back BEFORE releasing it (the
                // idle truncate must never beat a read), apply the
                // rewrite, and re-park the corrected bytes in RAM.
                let mut whole = vec![0u8; len];
                if sc.read(po, &mut whole).is_err() {
                    differed = true;
                    continue;
                }
                whole[(a - s) as usize..(b - s) as usize].copy_from_slice(src);
                st.paged.remove(&s);
                st.paged_bytes -= len;
                sc.release(len);
                match st.pending.get_mut(&s) {
                    // A longer same-start park subsumes the region; the
                    // corrected bytes overwrite its copy so every
                    // retained record agrees.
                    Some(old) if old.len() >= whole.len() => {
                        old[..whole.len()].copy_from_slice(&whole);
                    }
                    _ => {
                        st.pending.insert(s, whole);
                    }
                }
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
                // The append stops where paged coverage begins: those
                // bytes are already on scratch (reconciled above), and
                // the extended `frontier()` walks straight through them.
                let stop = if st.paged_at(frontier).is_some() {
                    frontier
                } else {
                    st.paged
                        .range(frontier..end)
                        .next()
                        .map(|(&s, _)| s)
                        .unwrap_or(end)
                };
                if stop > frontier {
                    st.data.extend_from_slice(
                        &bytes[(frontier - offset) as usize..(stop - offset) as usize],
                    );
                    accepted = true;
                }
                if end > stop {
                    // The remainder past a paged region parks - unless
                    // the region covers it entirely, in which case it is
                    // a pure duplicate of scratch bytes.
                    let covered = st
                        .paged_at(stop)
                        .is_some_and(|(s, _, len)| s + len as u64 >= end);
                    let keep = !covered
                        && match st.pending.get(&stop) {
                            Some(old) => old.len() < (end - stop) as usize,
                            None => true,
                        };
                    if keep {
                        st.pending
                            .insert(stop, bytes[(stop - offset) as usize..].to_vec());
                        accepted = true;
                    }
                }
            }
            // Fold parked spans the new frontier now reaches. Their
            // overlap with the frontier was reconciled when they were
            // written, so only the tail is new.
            while let Some((&s, _)) = st.pending.first_key_value() {
                let f = st.frontier_ram();
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
            // (its bytes were just reconciled into the longer one), and
            // a span one paged region wholly covers is a duplicate of
            // scratch bytes and stays off RAM.
            let covered = st
                .paged_at(offset)
                .is_some_and(|(s, _, len)| s + len as u64 >= end);
            let keep = !covered
                && match st.pending.get(&offset) {
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
    pub(super) fn abort(&self, reason: &str) {
        let mut st = self.state.lock_ok();
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
    pub(super) fn conflicted(&self) -> bool {
        self.state.lock_ok().conflict
    }

    /// Force the forfeit from outside: used when a span lands below the
    /// trim point, where the buffer cannot compare it against anything
    /// because those bytes are on disk rather than in `data`.
    pub(super) fn mark_conflict(&self) {
        self.state.lock_ok().conflict = true;
    }

    /// Frontier progress (bytes contiguous from 0, trimmed prefix
    /// included - those bytes arrived, they just live on disk now) vs
    /// the declared total.
    pub(super) fn is_complete(&self) -> bool {
        let st = self.state.lock_ok();
        st.frontier() >= st.total
    }

    /// Non-blocking volume-view read for the verifier/repair read-back:
    /// serves frontier, parked AND paged bytes (the last via pread),
    /// errors if any hole intersects. A trimmed prefix reads as a hole -
    /// those bytes are on disk, and the slot-level read splits the
    /// request at [`Self::base`] before getting here.
    pub(super) fn peek(&self, off: u64, out: &mut [u8]) -> io::Result<()> {
        let st = self.state.lock_ok();
        let mut pos = off;
        let end = off + out.len() as u64;
        if pos < st.base {
            return Err(nofile());
        }
        let frontier = st.frontier_ram();
        if pos < frontier {
            let n = (frontier.min(end) - pos) as usize;
            let di = (pos - st.base) as usize;
            out[..n].copy_from_slice(&st.data[di..di + n]);
            pos += n as u64;
        }
        while pos < end {
            // The parked span covering `pos`, if any.
            let hit = st
                .pending
                .range(..=pos)
                .next_back()
                .filter(|&(&s, v)| s + v.len() as u64 > pos);
            if let Some((&s, v)) = hit {
                let ve = s + v.len() as u64;
                let n = (ve.min(end) - pos) as usize;
                out[(pos - off) as usize..(pos - off) as usize + n]
                    .copy_from_slice(&v[(pos - s) as usize..(pos - s) as usize + n]);
                pos += n as u64;
                continue;
            }
            if let Some((s, po, len)) = st.paged_at(pos) {
                let se = s + len as u64;
                let n = (se.min(end) - pos) as usize;
                let sc = self.scratch.as_ref().ok_or_else(nofile)?;
                sc.read(
                    po + (pos - s),
                    &mut out[(pos - off) as usize..(pos - off) as usize + n],
                )?;
                pos += n as u64;
                continue;
            }
            return Err(nofile());
        }
        Ok(())
    }

    /// Present sub-ranges of `[off, off+len)` in volume offsets, merged.
    /// A trimmed prefix is absent here by construction; the slot-level
    /// coverage adds the archive file's own intervals for it.
    pub(super) fn intervals(&self, off: u64, len: u64) -> Vec<(u64, u64)> {
        let st = self.state.lock_ok();
        let end = off + len;
        let mut ivs: Vec<(u64, u64)> = Vec::new();
        let frontier = st.frontier_ram();
        let lo = off.max(st.base);
        if lo < frontier && lo < end {
            ivs.push((lo, frontier.min(end)));
        }
        for (&s, v) in st.pending.range(..end) {
            let a = off.max(s);
            let b = end.min(s + v.len() as u64);
            if a < b {
                ivs.push((a, b));
            }
        }
        for (&s, &(_, plen)) in st.paged.range(..end) {
            let a = off.max(s);
            let b = end.min(s + plen as u64);
            if a < b {
                ivs.push((a, b));
            }
        }
        merge_intervals(ivs)
    }

    /// Consume the retained bytes for demotion: the frontier moves out as
    /// one span AT ITS OWN OFFSET, parked spans follow as-is. The buffer
    /// is empty after. A trimmed prefix is not here and does not need to
    /// be: the trim already wrote it to the very file this demotion
    /// materializes into. Test-only: the production demote goes through
    /// [`Self::pop_span`], which also reads paged spans back one at a
    /// time instead of re-inflating the whole set.
    #[cfg(test)]
    pub(super) fn take_spans(&self) -> Vec<(u64, Vec<u8>)> {
        let mut st = self.state.lock_ok();
        debug_assert!(st.paged.is_empty(), "take_spans on a paged buffer");
        let mut out: Vec<(u64, Vec<u8>)> = Vec::new();
        let base = st.base;
        let data = std::mem::take(&mut st.data);
        if !data.is_empty() {
            out.push((base, data));
        }
        for (s, v) in std::mem::take(&mut st.pending) {
            out.push((s, v));
        }
        st.stored = 0;
        out
    }

    /// Consume one retained span for demotion: the contiguous frontier
    /// first (at its own offset), then each paged span - read back off
    /// the scratch with a single pread and released - then the parked
    /// spans. `None` once the buffer is empty. One span in RAM at a
    /// time, which is what keeps a demote of a mostly-paged set from
    /// re-inflating it; a scratch read error deliberately fails the
    /// caller rather than demoting short, because the demote path needs
    /// exactly these bytes to materialize the volume.
    pub(super) fn pop_span(&self) -> io::Result<Option<(u64, Vec<u8>)>> {
        let mut st = self.state.lock_ok();
        if !st.data.is_empty() {
            let base = st.base;
            let data = std::mem::take(&mut st.data);
            st.stored = st.pending.values().map(|v| v.len()).sum::<usize>();
            return Ok(Some((base, data)));
        }
        if let Some((&s, &(po, len))) = st.paged.iter().next() {
            let sc = self
                .scratch
                .as_ref()
                .ok_or_else(|| io::Error::other("paged span with no scratch"))?
                .clone();
            let mut b = vec![0u8; len];
            // Read BEFORE release: the idle truncate must never beat a
            // read of a region a span still references.
            sc.read(po, &mut b)?;
            st.paged.remove(&s);
            st.paged_bytes -= len;
            sc.release(len);
            return Ok(Some((s, b)));
        }
        if let Some((s, v)) = st.pending.pop_first() {
            st.stored = st.data.len() + st.pending.values().map(|v| v.len()).sum::<usize>();
            return Ok(Some((s, v)));
        }
        st.stored = 0;
        Ok(None)
    }

    /// Declared total size (the level-N entry's unpacked size).
    pub(super) fn total(&self) -> u64 {
        self.state.lock_ok().total
    }

    /// Volume offset of the first byte still in RAM. Everything below it
    /// has been trimmed out to the slot's archive file.
    pub(super) fn base(&self) -> u64 {
        self.state.lock_ok().base
    }

    /// Bytes currently held in RAM - what the holds budget is charged
    /// for. Re-read after a trim to give the budget its bytes back.
    pub(super) fn stored(&self) -> usize {
        self.state.lock_ok().stored
    }

    /// One past the last contiguous byte, in volume offsets.
    #[cfg(test)]
    pub(super) fn frontier(&self) -> u64 {
        self.state.lock().unwrap().frontier()
    }

    /// Drop-behind: release the frontier bytes below `watermark` and hand
    /// them back so the caller can spill them into the slot's archive
    /// file. Returns `(offset, bytes)` of what left RAM, or None if there
    /// was nothing to release.
    ///
    /// `watermark` is the lowest offset the decode engine may still ask
    /// for - the READ frontier, not decode progress: MT-LZMA2 prefetches
    /// tens of MB ahead of what it has decoded, so trimming to decode
    /// position would take bytes the prefetcher still wants. Parked spans
    /// are untouched by construction: they all sit ABOVE the frontier.
    ///
    /// Nothing is trimmed while a conflict is pending - that buffer is
    /// about to demote and `take_spans` is the only thing left to run.
    ///
    /// `min_release` is what makes this affordable. The release is a
    /// `Vec::drain` from the front, so it memmoves whatever is still
    /// live; refusing to trim for less than a worthwhile chunk bounds
    /// that work to a constant per arriving byte. It also answers the
    /// case trimming cannot fix - arrivals running far ahead of decode,
    /// where the live window IS the cap - by declining, which demotes.
    pub(super) fn trim_to(&self, watermark: u64, min_release: u64) -> Option<(u64, Vec<u8>)> {
        let mut st = self.state.lock_ok();
        if st.conflict || st.abort.is_some() {
            return None;
        }
        // The RAM frontier, deliberately: only `data` leaves through a
        // trim. A paged span below the watermark is already off RAM and
        // stays on the scratch until the demote or Drop releases it.
        let cut = watermark.min(st.frontier_ram());
        if cut < st.base + min_release.max(1) {
            return None;
        }
        let n = (cut - st.base) as usize;
        let out = st.data.drain(..n).collect::<Vec<u8>>();
        let at = st.base;
        st.base = cut;
        st.stored = st.data.len() + st.pending.values().map(|v| v.len()).sum::<usize>();
        Some((at, out))
    }

    /// Proactive spill for a chase stalled behind terminally-missing
    /// articles: move up to `need` cold RAM bytes to the holds scratch.
    /// Parked spans go first, newest (highest) offsets first - they are
    /// cold by construction, the forward-only RAR reader cannot reach a
    /// parked span until its gap fills. With `include_data` the tail of
    /// the contiguous run pages too (a volume the engine has not
    /// reached, or is wholly past); the paged span continues coverage
    /// exactly where `data` now ends, so `frontier()` and the blocking
    /// readers see the same bytes, just served by pread. Returns the
    /// bytes that left RAM; the caller re-reads `stored()` and settles
    /// the budget, the same contract as the drop-behind trim. A scratch
    /// refusal (ceiling, dead) just stops - whatever stayed in RAM keeps
    /// riding the cap arbiter exactly as before this spill existed.
    pub(super) fn page_cold(&self, cap: u64, mut need: usize, include_data: bool) -> usize {
        let Some(sc) = self.scratch.as_ref() else {
            return 0;
        };
        let mut st = self.state.lock_ok();
        // A conflicted or aborted buffer is about to demote; leave its
        // spans where the demote expects them.
        if st.conflict || st.abort.is_some() {
            return 0;
        }
        let mut moved = 0usize;
        let starts: Vec<u64> = st.pending.keys().rev().copied().collect();
        for s in starts {
            if need == 0 {
                break;
            }
            let len = st.pending[&s].len();
            if len < HOLDS_PAGE_MIN {
                continue;
            }
            let e = s + len as u64;
            // Overlap with an existing paged region: fully covered means
            // an agreeing duplicate that re-parked - drop the RAM copy,
            // no I/O. A same-start longer span replaces the shorter
            // region below. Any other partial overlap stays in RAM:
            // paged regions are kept DISJOINT (every covering lookup is
            // a single `range(..=pos).next_back()`), and these shapes
            // are rare re-delivery leftovers, not the pile.
            //
            // `range(..e)` finds the greatest paged key BELOW the span's
            // end, which can start above `s` - a repair span mapped at a
            // PAR2 block boundary reaches under a region paged at an
            // article boundary. Covered means covered at BOTH ends
            // (`ps <= s`): without that test the prefix `[s, ps)` is in
            // no map, no scratch region and no file, and dropping the
            // RAM copy loses bytes that had already arrived.
            let overlap = st
                .paged
                .range(..e)
                .next_back()
                .map(|(&ps, &(_, plen))| (ps, plen))
                .filter(|&(ps, plen)| ps + plen as u64 > s);
            match overlap {
                Some((ps, plen)) if ps <= s && ps + plen as u64 >= e => {
                    st.pending.remove(&s);
                    moved += len;
                    need = need.saturating_sub(len);
                    continue;
                }
                Some((ps, _)) if ps != s => continue,
                _ => {}
            }
            let v = st.pending.remove(&s).unwrap();
            let Some(off) = sc.append(&v, cap) else {
                st.pending.insert(s, v);
                break;
            };
            if let Some(&(_, old_len)) = st.paged.get(&s) {
                // The same-start shorter region is subsumed (bytes
                // agree; the longer copy covers it).
                debug_assert!(old_len < v.len());
                st.paged_bytes -= old_len;
                sc.release(old_len);
            }
            st.paged_bytes += v.len();
            moved += v.len();
            need = need.saturating_sub(v.len());
            st.paged.insert(s, (off, v.len()));
        }
        if include_data && need >= HOLDS_PAGE_MIN && !st.data.is_empty() {
            let take = st.data.len().min(need);
            let data_end = st.base + st.data.len() as u64;
            let at = data_end - take as u64;
            // A paged region overlapping the tail (a fold ran through
            // one): leave the tail resident rather than create
            // overlapping regions - same disjointness rule as above.
            let overlap = st
                .paged
                .range(..data_end)
                .next_back()
                .is_some_and(|(&ps, &(_, plen))| ps + plen as u64 > at);
            if take >= HOLDS_PAGE_MIN && !overlap {
                let cut = st.data.len() - take;
                let tail = st.data.split_off(cut);
                match sc.append(&tail, cap) {
                    Some(off) => {
                        st.paged_bytes += tail.len();
                        moved += tail.len();
                        st.paged.insert(at, (off, tail.len()));
                    }
                    None => {
                        // Refused: put the tail back where it was.
                        st.data.extend_from_slice(&tail);
                    }
                }
            }
        }
        st.stored = st.data.len() + st.pending.values().map(|v| v.len()).sum::<usize>();
        moved
    }

    /// Blocking RANDOM-ACCESS read for the 7z chase. The trait method
    /// below blocks on the contiguous frontier (the RAR decode is
    /// forward-only); 7z seeks - its footer must be readable long
    /// before the frontier reaches it. Serves the longest available
    /// run at `offset` from frontier or parked bytes, blocks while
    /// `offset` sits in a hole, `Ok(0)` at the declared end, error
    /// after abort.
    pub(super) fn read_covered_blocking(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut st = self.state.lock_ok();
        loop {
            if let Some(reason) = &st.abort {
                return Err(io::Error::other(format!("chase source aborted: {reason}")));
            }
            if offset >= st.total {
                return Ok(0);
            }
            // Behind the trim point: those bytes went to disk and the
            // engine promised never to come back for them. A read here
            // means the promise broke (BCJ2 is the only shape that
            // would, and it is refused a trim up front), so fail loudly
            // - the chase forfeits and the archive materializes, which
            // is cheap because most of it is already written.
            if offset < st.base {
                return Err(io::Error::other(format!(
                    "chase source read {offset} behind the trim point {}",
                    st.base
                )));
            }
            // §94 B: nothing at or past the verified watermark may reach
            // the decode. Blocked-by-gate is a different wait from
            // blocked-by-arrival: the bytes are here, the vouching is
            // not - park on the gate (bounded) and re-run every check.
            let lim = self.gate_limit();
            if offset >= lim {
                drop(st);
                self.gate_wait(offset);
                st = self.state.lock_ok();
                continue;
            }
            let frontier = st.frontier_ram();
            if offset < frontier {
                let start = (offset - st.base) as usize;
                let take = buf
                    .len()
                    .min(st.data.len() - start)
                    .min((lim - offset) as usize);
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
                let take = buf.len().min(v.len() - a).min((lim - offset) as usize);
                buf[..take].copy_from_slice(&v[a..a + take]);
                return Ok(take);
            }
            if let Some((s, po, len)) = st.paged_at(offset) {
                let take = buf
                    .len()
                    .min(len - (offset - s) as usize)
                    .min((lim - offset) as usize);
                let sc = self
                    .scratch
                    .as_ref()
                    .ok_or_else(|| io::Error::other("paged span with no scratch"))?;
                sc.read(po + (offset - s), &mut buf[..take])?;
                return Ok(take);
            }
            st = self.arrived.wait(st).unwrap();
        }
    }
}

impl Drop for FrontierBuffer {
    /// A buffer dropped with paged spans still in it (a successful
    /// chase, an abandoned slot) hands their scratch live-count back so
    /// the file can truncate; the regions themselves were write-once
    /// and need no other unwind.
    fn drop(&mut self) {
        let st = self
            .state
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if st.paged_bytes > 0
            && let Some(sc) = &self.scratch
        {
            sc.release(st.paged_bytes);
            st.paged_bytes = 0;
            st.paged.clear();
        }
    }
}

/// The RAR engine reads chased volumes through this: block at the
/// frontier, `Ok(0)` only at the declared end, error after abort.
impl rars::BlockingRangeSource for FrontierBuffer {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut st = self.state.lock_ok();
        loop {
            if let Some(reason) = &st.abort {
                return Err(io::Error::other(format!("chase source aborted: {reason}")));
            }
            // The RAR chase never trims (the rars reader's access
            // pattern has not been measured the way the 7z one has), so
            // `base` is always 0 here - but read it rather than assume
            // it, so the day that changes this fails instead of serving
            // the wrong bytes.
            if offset < st.base {
                return Err(io::Error::other(format!(
                    "chase source read {offset} behind the trim point {}",
                    st.base
                )));
            }
            // §94 B: same gate as `read_covered_blocking` - the decode
            // may only consume PAR2-vouched bytes.
            let lim = self.gate_limit();
            if offset >= lim && offset < st.total {
                drop(st);
                self.gate_wait(offset);
                st = self.state.lock_ok();
                continue;
            }
            let frontier = st.frontier_ram();
            if offset < frontier {
                let start = (offset - st.base) as usize;
                let take = buf
                    .len()
                    .min(st.data.len() - start)
                    .min((lim - offset) as usize);
                buf[..take].copy_from_slice(&st.data[start..start + take]);
                return Ok(take);
            }
            if offset >= st.total {
                return Ok(0);
            }
            // Beyond the RAM run the coverage may continue through
            // paged spans (served by pread) and the parked spans that
            // follow them. The reader is forward-only, so it can only
            // arrive here through contiguous coverage - serving a
            // parked span early is strictly more bytes, never wrong
            // ones (identical-delivery reconciliation holds for every
            // retained copy).
            if let Some((s, po, len)) = st.paged_at(offset) {
                let take = buf
                    .len()
                    .min(len - (offset - s) as usize)
                    .min((lim - offset) as usize);
                let sc = self
                    .scratch
                    .as_ref()
                    .ok_or_else(|| io::Error::other("paged span with no scratch"))?;
                sc.read(po + (offset - s), &mut buf[..take])?;
                return Ok(take);
            }
            let hit = st
                .pending
                .range(..=offset)
                .next_back()
                .filter(|&(&s, v)| s + v.len() as u64 > offset);
            if let Some((&s, v)) = hit {
                let a = (offset - s) as usize;
                let take = buf.len().min(v.len() - a).min((lim - offset) as usize);
                buf[..take].copy_from_slice(&v[a..a + take]);
                return Ok(take);
            }
            st = self.arrived.wait(st).unwrap();
        }
    }

    fn known_len(&self) -> u64 {
        let st = self.state.lock_ok();
        st.frontier()
    }

    fn total_len(&self) -> Option<u64> {
        Some(self.state.lock_ok().total)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extract::testutil::tmpdir;

    fn pat(off: usize, n: usize) -> Vec<u8> {
        (off..off + n).map(|i| (i % 251) as u8).collect()
    }

    /// The stalled-chase cold spill end to end at the buffer level:
    /// parked spans and the contiguous tail page to scratch, coverage
    /// stays whole (intervals, peek, completeness), a forward reader
    /// runs the volume out through preads once the gap fills, and a
    /// demotion pops every span back byte-exact with the scratch
    /// live-count fully drained.
    #[test]
    fn stall_paging_serves_paged_spans_and_pops_them_back() {
        use rars::BlockingRangeSource as _;
        let dir = tmpdir("frontier-paged");
        let sc = Arc::new(HoldsScratch::new(&dir));
        let buf = FrontierBuffer::new_gated(40_000, None, Some(sc.clone()));
        buf.write_span(0, &pat(0, 10_000)); // contiguous run
        buf.write_span(20_000, &pat(20_000, 10_000)); // parks
        buf.write_span(30_000, &pat(30_000, 10_000)); // parks
        assert_eq!(buf.stored(), 30_000);
        let moved = buf.page_cold(1 << 20, usize::MAX, true);
        assert_eq!(moved, 30_000, "both parks and the data tail must page");
        assert_eq!(buf.stored(), 0);
        // Coverage is intact, just served differently.
        assert_eq!(
            buf.intervals(0, 40_000),
            vec![(0, 10_000), (20_000, 40_000)]
        );
        let mut got = vec![0u8; 10_000];
        buf.peek(25_000, &mut got).unwrap();
        assert_eq!(got, pat(25_000, 10_000), "peek must pread across regions");
        assert!(!buf.is_complete());
        // The gap fills (a retry or a repair landing late): coverage
        // completes and the forward-only reader streams the whole
        // volume, paged regions served by pread.
        buf.write_span(10_000, &pat(10_000, 10_000));
        assert!(buf.is_complete(), "paged coverage must count as arrived");
        let mut out = vec![0u8; 40_000];
        let mut pos = 0usize;
        while pos < 40_000 {
            let n = buf.read_at(pos as u64, &mut out[pos..]).unwrap();
            assert_ne!(n, 0, "reader starved at {pos} despite full coverage");
            pos += n;
        }
        assert_eq!(out, pat(0, 40_000));
        // Demotion consumes one span at a time, byte-exact.
        let mut mat = vec![0u8; 40_000];
        let mut popped = 0;
        while let Some((off, bytes)) = buf.pop_span().unwrap() {
            mat[off as usize..off as usize + bytes.len()].copy_from_slice(&bytes);
            popped += 1;
        }
        assert!(popped >= 3, "expected data + paged spans, got {popped}");
        assert_eq!(mat, pat(0, 40_000));
        assert_eq!(sc.st().live, 0, "scratch live must drain with the pops");
        drop(buf);
        sc.cleanup();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Deliveries overlapping a paged region reconcile exactly like RAM
    /// copies: an identical duplicate is absorbed without re-inflating
    /// RAM or flagging anything, and a DIFFERING rewrite un-pages the
    /// region with the correction applied and trips the sticky conflict
    /// - the demote must materialize the corrected bytes.
    #[test]
    fn paged_span_rewrites_reconcile_and_conflict() {
        let dir = tmpdir("frontier-paged-rw");
        let sc = Arc::new(HoldsScratch::new(&dir));
        let buf = FrontierBuffer::new_gated(30_000, None, Some(sc.clone()));
        buf.write_span(10_000, &[3u8; 10_000]);
        assert_eq!(buf.page_cold(1 << 20, usize::MAX, false), 10_000);
        assert_eq!(buf.stored(), 0);
        buf.write_span(10_000, &[3u8; 10_000]);
        assert!(!buf.conflicted(), "an identical duplicate is not a rewrite");
        assert_eq!(buf.stored(), 0, "an agreeing duplicate re-inflated RAM");
        buf.write_span(12_000, &[3u8; 1_000]);
        assert!(!buf.conflicted());
        assert_eq!(buf.stored(), 0);
        buf.write_span(12_000, &[9u8; 1_000]);
        assert!(buf.conflicted(), "a differing rewrite must not be dropped");
        let mut want = vec![3u8; 10_000];
        want[2_000..3_000].fill(9);
        let mut got = vec![0u8; 10_000];
        buf.peek(10_000, &mut got).unwrap();
        assert_eq!(got, want, "the corrected copy is what a demote ships");
        let mut mat = vec![0u8; 10_000];
        while let Some((off, bytes)) = buf.pop_span().unwrap() {
            let at = (off - 10_000) as usize;
            mat[at..at + bytes.len()].copy_from_slice(&bytes);
        }
        assert_eq!(mat, want);
        assert_eq!(sc.st().live, 0);
        drop(buf);
        sc.cleanup();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A parked span reaching UNDER a paged region keeps its uncovered
    /// prefix. `page_cold` finds the overlap with `range(..e).next_back()`
    /// - the greatest paged key below the span's END - so the region it
    /// finds can start above the span's start, which is what a repair
    /// span mapped at a PAR2 block boundary looks like against a region
    /// paged at an article boundary. Treating that as "fully covered"
    /// dropped the prefix into no map, no file and no scratch region:
    /// the frontier could never pass it, and a demote materialized a
    /// volume with a hole at bytes that had already arrived.
    #[test]
    fn page_cold_keeps_the_prefix_a_paged_region_does_not_cover() {
        let dir = tmpdir("frontier-paged-prefix");
        let sc = Arc::new(HoldsScratch::new(&dir));
        let buf = FrontierBuffer::new_gated(30_000, None, Some(sc.clone()));
        // A span parks above the frontier and pages out.
        buf.write_span(10_000, &pat(10_000, 10_000));
        assert_eq!(buf.page_cold(1 << 20, usize::MAX, false), 10_000);
        assert_eq!(buf.stored(), 0);
        // A later delivery starts BELOW the paged region and ends inside
        // it: nothing covers [5_000, 10_000), so it parks whole.
        buf.write_span(5_000, &pat(5_000, 10_000));
        assert_eq!(buf.stored(), 10_000);
        // The next spill pass must not mistake it for a duplicate.
        buf.page_cold(1 << 20, usize::MAX, false);
        assert!(!buf.conflicted(), "the bytes agree - no rewrite happened");
        buf.write_span(0, &pat(0, 5_000));
        assert_eq!(
            buf.frontier(),
            20_000,
            "coverage must run through the prefix"
        );
        let mut got = vec![0u8; 20_000];
        buf.peek(0, &mut got).unwrap();
        assert_eq!(got, pat(0, 20_000), "the prefix bytes must still be there");
        let mut mat = vec![0u8; 20_000];
        while let Some((off, bytes)) = buf.pop_span().unwrap() {
            mat[off as usize..off as usize + bytes.len()].copy_from_slice(&bytes);
        }
        assert_eq!(mat, pat(0, 20_000), "a demote must materialize every byte");
        assert_eq!(sc.st().live, 0);
        drop(buf);
        sc.cleanup();
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// §94 B: a gated buffer serves only PAR2-vouched bytes. Bytes are
    /// PRESENT past the watermark and must still not reach the decode -
    /// serves clamp at the limit, and a fully-advanced gate releases
    /// the rest. Ungated buffers (every other test here) are the teeth
    /// proving the pre-gate behavior is untouched.
    #[test]
    fn gated_reads_clamp_at_the_verified_watermark() {
        let gate = crate::live::VerifyGate::new(1);
        gate.engage(0);
        let buf = FrontierBuffer::new_gated(30, Some((gate.clone(), 0)), None);
        buf.write_span(0, &[7u8; 30]);
        // Watermark 10: a 16-byte read at 0 serves exactly 10.
        gate.advance(0, 10);
        let mut out = [0u8; 16];
        let n = buf.read_covered_blocking(0, &mut out).unwrap();
        assert_eq!(n, 10, "serve clamps at the watermark");
        // A read AT the watermark parks; an advance releases it.
        let b2 = std::sync::Arc::new(buf);
        let (b3, g3) = (b2.clone(), gate.clone());
        let t = std::thread::spawn(move || {
            let mut out = [0u8; 32];
            b3.read_covered_blocking(10, &mut out).unwrap()
        });
        std::thread::sleep(std::time::Duration::from_millis(50));
        g3.advance(0, u64::MAX);
        assert_eq!(t.join().unwrap(), 20, "advance releases the rest");
        // An aborted buffer must not strand a gate-blocked reader.
        let gate2 = crate::live::VerifyGate::new(1);
        gate2.engage(0);
        let b4 = std::sync::Arc::new(FrontierBuffer::new_gated(30, Some((gate2, 0)), None));
        b4.write_span(0, &[1u8; 30]);
        let b5 = b4.clone();
        let t = std::thread::spawn(move || {
            let mut out = [0u8; 8];
            b5.read_covered_blocking(0, &mut out)
        });
        std::thread::sleep(std::time::Duration::from_millis(50));
        b4.abort("test abort");
        assert!(
            t.join().unwrap().is_err(),
            "abort must reach a gate-blocked reader"
        );
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

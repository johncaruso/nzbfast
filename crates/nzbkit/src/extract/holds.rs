//! Pre-sniff holds and their relief valve: the held-bytes budget,
//! the scratch file held spans page to when the cap is hit, the
//! drain that replays held bytes into the parser, and the spill of
//! never-classified slots to plain files.
//!
//! Split out of the 19,920-line `extract.rs` under the TODO 43
//! recipe: a verbatim move, not a redesign.

use super::*;
use crate::sync::MutexExt;

/// Default total bytes of held (not-yet-mappable) spans before a group
/// falls back to materialized volumes. Memory is the cache tier and the
/// header-first scheduling keeps real holds small; this is the safety
/// net. Overridden by the MemBudget slice (`set_holds_cap`).
pub(super) const HOLDS_DEFAULT_CAP: usize = 2 << 30;

/// Held-span accounting shared across the whole extractor CHAIN: a child
/// extractor's holds charge the same budget as its parent's, so a nested
/// post can't balloon RSS to depth x cap. Atomics rather than a field
/// under the routing lock because parent and child each have their own
/// lock; peak reporting is naturally the chain-wide peak.
pub(super) struct HoldsBudget {
    pub(super) bytes: AtomicUsize,
    pub(super) cap: AtomicUsize,
    pub(super) peak: AtomicUsize,
}

impl HoldsBudget {
    pub(super) fn new(cap: usize) -> HoldsBudget {
        HoldsBudget {
            bytes: AtomicUsize::new(0),
            cap: AtomicUsize::new(cap),
            peak: AtomicUsize::new(0),
        }
    }

    pub(super) fn add(&self, n: usize) {
        let now = self.bytes.fetch_add(n, Ordering::Relaxed) + n;
        self.peak.fetch_max(now, Ordering::Relaxed);
    }

    pub(super) fn sub(&self, n: usize) {
        self.bytes.fetch_sub(n, Ordering::Relaxed);
    }

    pub(super) fn over(&self) -> bool {
        self.bytes.load(Ordering::Relaxed) > self.cap.load(Ordering::Relaxed)
    }

    pub(super) fn cap(&self) -> usize {
        self.cap.load(Ordering::Relaxed)
    }

    pub(super) fn peak(&self) -> usize {
        self.peak.load(Ordering::Relaxed)
    }

    pub(super) fn len(&self) -> usize {
        self.bytes.load(Ordering::Relaxed)
    }
}

/// One held span's bytes: in RAM (charging [`HoldsBudget`]) or paged out
/// to the chain's scratch file (charging [`HoldsScratch`]). Paging is the
/// budget-breach relief valve: the span keeps its slot MAPPED - it stays
/// visible to `covered`/`read_at` and re-feeds on drain exactly like a RAM
/// span, with one pread - so a set that would have demoted on the cap
/// still extracts one-pass.
pub(super) enum HoldSpan {
    Ram(Vec<u8>),
    Paged { off: u64, len: usize },
}

impl HoldSpan {
    pub(super) fn len(&self) -> usize {
        match self {
            HoldSpan::Ram(b) => b.len(),
            HoldSpan::Paged { len, .. } => *len,
        }
    }
}

/// Same-directory scratch prefix for paged held spans. Like
/// [`DEC_TMP_PREFIX`], the leading `.nzbfast` keeps the cleanup walkers
/// and the keep-media-only sweep off it, and pid + counter make each name
/// unique to one run of one process.
pub(super) const HOLDS_TMP_PREFIX: &str = ".nzbfast-holds.";

/// Remove holds scratch left behind by a killed run. Root construction
/// only - a child sweeping would unlink the root's live file.
pub(super) fn sweep_holds_scratch(dir: &Path) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        if e.file_name()
            .to_string_lossy()
            .starts_with(HOLDS_TMP_PREFIX)
        {
            let _ = std::fs::remove_file(e.path());
        }
    }
}

/// The chain's held-span scratch file, shared root-to-children like the
/// [`HoldsBudget`] it relieves. Created lazily on first page; regions are
/// append-only and WRITE-ONCE (a region is never rewritten while any
/// span references it), which is what makes the deferred preads in
/// `read_at` safe off the routing lock. Space reclaim is deliberately
/// crude: when nothing live remains and no reader is pinned, the cursor
/// resets and the file truncates - bounding the drain/re-hold/re-page
/// ping-pong without a free-list.
///
/// EVERY piece of mutable state (file, cursor, live, pins) lives under
/// the one `state` mutex, on purpose. "Under the routing lock" is not a
/// synchronization boundary here: the scratch is CHAIN-shared while
/// routing locks are per-level, so a parent release and a child append
/// run concurrently. An earlier draft kept `live`/`pins` as Relaxed
/// atomics checked partly outside the mutex - the 31 Jul race audit
/// found a reachable interleaving where a reader pin born inside
/// `release`'s check-to-truncate window was ignored and a planned pread
/// read truncated (or reused) bytes. Every path that touches this state
/// is cold (paging, drains, planning a paged read), so the mutex costs
/// nothing and makes the gates sequentially consistent by construction.
pub(super) struct HoldsScratch {
    pub(super) dir: PathBuf,
    pub(super) state: Mutex<ScratchState>,
    /// Bytes ever paged (diagnostics/tests; monotonic).
    pub(super) paged_total: AtomicU64,
    /// Hard ceiling on the append cursor. 0 = auto (4x the holds RAM cap,
    /// resolved at page time so a later `set_holds_cap` is respected).
    pub(super) cap: AtomicU64,
    /// Latched on any scratch I/O error: paging is off for the rest of
    /// the run and every breach demotes exactly as before paging existed.
    pub(super) dead: AtomicBool,
    /// First-engage log line, once per run.
    pub(super) announced: AtomicBool,
}

pub(super) struct ScratchState {
    /// Lazily-created file. The `Arc` is what a deferred read plan
    /// carries out from under the locks.
    pub(super) file: Option<Arc<(PathBuf, File)>>,
    /// Append cursor; resets to 0 when idle (live == 0, pins == 0).
    pub(super) cursor: u64,
    /// Bytes of live paged spans - every `HoldSpan::Paged` anywhere in
    /// the chain holds exactly one charge here. Nonzero blocks the idle
    /// reset, so a referenced region is never overwritten or truncated.
    pub(super) live: u64,
    /// Readers holding deferred pread plans (pinned at plan time,
    /// released after the preads land). Nonzero blocks the idle reset,
    /// protecting a planned region whose span has since been released.
    pub(super) pins: usize,
}

impl HoldsScratch {
    pub(super) fn new(dir: &Path) -> HoldsScratch {
        HoldsScratch {
            dir: dir.to_path_buf(),
            state: Mutex::new(ScratchState {
                file: None,
                cursor: 0,
                live: 0,
                pins: 0,
            }),
            paged_total: AtomicU64::new(0),
            cap: AtomicU64::new(0),
            dead: AtomicBool::new(false),
            announced: AtomicBool::new(false),
        }
    }

    /// Poison-tolerant state lock: the readers/releasers must keep
    /// working after some other thread panicked mid-scratch (same
    /// argument as [`Extractor::inner_read`]).
    pub(super) fn st(&self) -> std::sync::MutexGuard<'_, ScratchState> {
        self.state.lock_ok()
    }

    /// Append one span's bytes; `cap` is the effective ceiling (the
    /// caller resolves auto). Returns the region offset, or None when the
    /// ceiling refuses (caller demotes with today's reason) - an I/O
    /// error additionally latches the scratch dead.
    pub(super) fn append(&self, bytes: &[u8], cap: u64) -> Option<u64> {
        if self.dead.load(Ordering::Relaxed) {
            return None;
        }
        let mut st = self.st();
        if st.file.is_none() {
            match Self::create(&self.dir) {
                Ok(pf) => st.file = Some(Arc::new(pf)),
                Err(_) => {
                    self.dead.store(true, Ordering::Relaxed);
                    return None;
                }
            }
        }
        // Idle reset: nothing live and nobody reading - every byte below
        // the cursor is dead, so reuse the space.
        if st.live == 0 && st.pins == 0 {
            st.cursor = 0;
        }
        if st.cursor.saturating_add(bytes.len() as u64) > cap {
            return None;
        }
        let f = st.file.as_ref().unwrap().clone();
        if crate::disk::write_all_at(&f.1, bytes, st.cursor).is_err() {
            self.dead.store(true, Ordering::Relaxed);
            return None;
        }
        let off = st.cursor;
        st.cursor += bytes.len() as u64;
        st.live += bytes.len() as u64;
        self.paged_total
            .fetch_add(bytes.len() as u64, Ordering::Relaxed);
        Some(off)
    }

    pub(super) fn create(dir: &Path) -> io::Result<(PathBuf, File)> {
        static SEQ: AtomicUsize = AtomicUsize::new(0);
        let pid = std::process::id();
        for _ in 0..4096 {
            let n = SEQ.fetch_add(1, Ordering::Relaxed);
            let path = dir.join(format!("{HOLDS_TMP_PREFIX}{pid}.{n}.tmp"));
            match std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(f) => return Ok((path, f)),
                // PermissionDenied too: on classic-delete-semantics
                // Windows (pre-1903, FAT/exFAT, SMB) a swept-but-still-
                // open stale file is delete-pending, and create_new on
                // that name reports ERROR_ACCESS_DENIED rather than
                // AlreadyExists - advance to the next seq instead of
                // latching paging dead for the whole run.
                Err(e)
                    if matches!(
                        e.kind(),
                        io::ErrorKind::AlreadyExists | io::ErrorKind::PermissionDenied
                    ) =>
                {
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "no free holds scratch name in the output directory",
        ))
    }

    /// The file handle for deferred reads, cloned out at plan time (pin
    /// first - see `ScratchState::pins`).
    pub(super) fn handle(&self) -> Option<Arc<(PathBuf, File)>> {
        self.st().file.clone()
    }

    /// Read a paged region back (drain paths, under some routing lock).
    pub(super) fn read(&self, off: u64, buf: &mut [u8]) -> io::Result<()> {
        let f = self
            .handle()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "holds scratch file missing"))?;
        crate::disk::read_exact_at(&f.1, buf, off)
    }

    /// Transfer a rebind's live charge in (see `rebind_subranges`): the
    /// subrange keeps referencing its region, so the region's protection
    /// must be added BEFORE the original span's `release` subtracts.
    pub(super) fn add_live(&self, len: usize) {
        self.st().live += len as u64;
    }

    /// A paged span was consumed (drained, discarded, abandoned). When
    /// the last live byte goes and no reader is pinned, the file
    /// truncates - space back, handle and name kept for a later page.
    /// Both gates read under the state mutex: a pin is taken under this
    /// same mutex, so a reader that planned before we got here is always
    /// visible (the earlier outside-the-mutex pins check was the race
    /// the 31 Jul audit caught).
    pub(super) fn release(&self, len: usize) {
        let mut st = self.st();
        st.live -= len as u64;
        if st.live == 0 && st.pins == 0 {
            st.cursor = 0;
            if let Some(f) = st.file.as_ref() {
                let _ = f.1.set_len(0);
            }
        }
    }

    /// Root finish/Drop: unlink the scratch NAME but keep the handle, so
    /// a straggler read of a still-paged span (a healthy group's header
    /// stash outlives settle) is served through the open file until the
    /// extractor drops. The disk space goes with the last handle; the
    /// construction-time sweep covers a killed run.
    pub(super) fn cleanup(&self) {
        let st = self.st();
        if let Some(f) = st.file.as_ref() {
            let _ = std::fs::remove_file(&f.0);
        }
    }
}

/// Spans smaller than this stay in RAM at page time - not worth the
/// syscall, and tiny spans are exactly the ones about to resolve.
pub(super) const HOLDS_PAGE_MIN: usize = 4 * 1024;

/// Reader pin over the holds scratch: taken (under the state mutex) when
/// `read_at` plans a pread of a paged span, released after the pread
/// lands. While any pin is held the scratch never resets its cursor or
/// truncates, so a planned region stays byte-stable off the locks.
pub(super) struct ScratchPin(Option<Arc<HoldsScratch>>);

impl ScratchPin {
    pub(super) fn none() -> ScratchPin {
        ScratchPin(None)
    }

    pub(super) fn pin(&mut self, sc: &Arc<HoldsScratch>) {
        if self.0.is_none() {
            sc.st().pins += 1;
            self.0 = Some(sc.clone());
        }
    }
}

impl Drop for ScratchPin {
    fn drop(&mut self) {
        if let Some(sc) = &self.0 {
            sc.st().pins -= 1;
        }
    }
}

/// `NZBFAST_NO_HOLDS_PAGE=1` restores the pre-paging behavior: every
/// budget breach demotes. Split for testability like the chase gates.
pub(super) fn holds_page_env_off_value(v: Option<&str>) -> bool {
    v == Some("1")
}

pub(super) fn holds_page_env_off() -> bool {
    holds_page_env_off_value(std::env::var("NZBFAST_NO_HOLDS_PAGE").ok().as_deref())
}

/// Per-slot budget for spans held while a slot is still unclassified
/// (waiting for its offset-0 sniff). Honest posts fetch each file's first
/// segment within the first round-trips (M3 scheduling), so real holds
/// stay a few articles deep; an NZB with synthesized segment numbering
/// never delivers offset 0 early and would pile the whole file here.
/// A quarter of the holds slice, floored at 4 MB.
///
/// The ceiling scales with the budget on purpose - it used to be a flat
/// 64 MB, and that flat number was a 3x I/O bug on damaged jobs
/// (bench settle round, 11 Aug 2026, a big-RAM desktop against five
/// real backbones): one RAR volume whose offset-0
/// article ran late spilled to Plain at 64 MB against a 7.7 GB holds
/// slice, and a damaged-but-unmapped file makes `try_mapped_repair`
/// decline the WHOLE set - every volume then materialized for a
/// disk-fed repair + re-extract pass (~18 GB of disk traffic for a
/// 6.5 GB post, at 96% free budget). A box with gigabytes of holds
/// room should ride out a late sniff; a small-RAM box keeps today's
/// early spill because its budget slice is small, and a global breach
/// still pages to scratch (or demotes) exactly as before.
pub(super) fn unclassified_spill(holds_cap: usize) -> usize {
    (holds_cap / 4).max(4 << 20)
}

/// Chain-wide RAM window for spans parked while a password probe may
/// still rescue their slot (`pw_await`). Parked ciphertext is cold by
/// construction - nothing reads it until a probe hit or finish - so it
/// must not ride RAM up to the holds cap: a header-encrypted set with
/// no password parks its ENTIRE payload, and on a big-RAM box the 45%
/// budget slice let a 1.6 GB set sit fully resident (the 2026-08-10
/// bench's peak-RSS outlier). The 64 MB ceiling is deliberate and must
/// scale with NOTHING: unlike a late-sniff hold, paging parked spans
/// never costs the set its one-pass rescue (a probe hit re-feeds them
/// from scratch), so a bigger budget buys no reason to keep more of
/// them resident.
pub(super) fn pw_await_spill(holds_cap: usize) -> usize {
    (holds_cap / 4).clamp(4 << 20, 64 << 20)
}

/// Chain-wide RAM window for a chased RAR set once the job has articles
/// with TERMINAL verdicts (430 everywhere, out of retention, transport
/// dead). The sequential decode wedges at the first unfillable gap, so
/// every frontier byte beyond it is as cold as parked ciphertext - the
/// pw_await argument exactly - yet it used to ride RAM to the holds cap:
/// 45% of a big box's budget let a damaged 3.5 GB compressed set sit
/// fully resident for the whole download (the 11 Aug 2026 soak's RSS
/// stair). Beyond this window the cold spans page to the holds scratch
/// ([`Extractor::page_stalled_chase`]); a gap that later fills (retry,
/// PAR2 repair) reads them back through the frontier buffer's paged
/// serving, and a demote materializes volumes from scratch byte-exact.
/// Same deliberate non-scaling ceiling as [`pw_await_spill`], for the
/// same reason: paging cold chase bytes never costs the set anything
/// but preads on the rescue path, so a bigger budget buys no reason to
/// keep more of them resident.
pub(super) fn chase_stall_spill(holds_cap: usize) -> usize {
    (holds_cap / 4).clamp(4 << 20, 64 << 20)
}

impl Extractor {
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

    /// Holds-paging gate (see `NZBFAST_NO_HOLDS_PAGE`, latched at
    /// construction; default on). Same set-before-spans discipline as the
    /// other gates. Off: a holds-budget breach demotes exactly as before
    /// paging existed.
    pub fn set_holds_paging(&self, on: bool) {
        self.inner.lock_ok().holds_page_on = on;
    }

    /// Hard ceiling on the held-span scratch file, shared down the chain
    /// like the RAM cap it relieves. Unset (0) means auto: 4x the holds
    /// RAM cap, resolved at page time. The daemon wires a free-space-
    /// aware value here next to `set_extract_budget`. Exceeding the
    /// ceiling demotes with the same "held-bytes cap" reasons as a RAM
    /// breach with paging off.
    pub fn set_holds_scratch_cap(&self, bytes: u64) {
        self.inner
            .lock()
            .unwrap()
            .scratch
            .cap
            .store(bytes, Ordering::Relaxed);
    }

    /// Bytes ever paged to the holds scratch (whole chain; monotonic).
    /// Test/diagnostic hook.
    pub fn holds_paged_total(&self) -> u64 {
        self.inner
            .lock()
            .unwrap()
            .scratch
            .paged_total
            .load(Ordering::Relaxed)
    }

    /// Bytes of live paged spans right now. Test/diagnostic hook.
    pub fn holds_paged_live(&self) -> u64 {
        let scratch = self.inner.lock_ok().scratch.clone();

        scratch.st().live
    }

    /// Peak held-span bytes across the whole nesting chain - end-of-run
    /// mem summary (M15).
    pub fn holds_peak(&self) -> usize {
        self.inner.lock_ok().budget.peak()
    }

    /// Budget-breach relief: move RAM-held spans - holds and header
    /// stash alike, every slot - out to the chain's scratch file until
    /// the budget sits at half its cap. Returns whether the budget is
    /// back under the cap; `false` (gate off, ceiling refused, scratch
    /// dead, or the remaining RAM belongs to spans this pass cannot
    /// touch - a chase frontier, sub-4K slivers, another level's holds)
    /// sends the caller down the exact demote it performs today, with
    /// the same reason string.
    pub(super) fn page_out_holds(&self, inner: &mut Inner) -> bool {
        if !inner.holds_page_on {
            return false;
        }
        let budget = inner.budget.clone();
        let scratch = inner.scratch.clone();
        // Auto ceiling: 4x the RAM cap, resolved per pass so a later
        // set_holds_cap is respected and an explicit ceiling wins.
        let cap = match scratch.cap.load(Ordering::Relaxed) {
            0 => 4 * budget.cap() as u64,
            c => c,
        };
        let low_water = budget.cap() / 2;
        let mut paged_any = false;
        'outer: for si in 0..inner.slots.len() {
            let s = &mut inner.slots[si];
            for store in [&mut s.holds, &mut s.header_spans] {
                for (_, span) in store.iter_mut() {
                    let HoldSpan::Ram(bytes) = span else { continue };
                    if bytes.len() < HOLDS_PAGE_MIN {
                        continue;
                    }
                    let Some(off) = scratch.append(bytes, cap) else {
                        // Ceiling or scratch death: whatever is still in
                        // RAM stays there; the verdict below demotes.
                        break 'outer;
                    };
                    let len = bytes.len();
                    budget.sub(len);
                    *span = HoldSpan::Paged { off, len };
                    paged_any = true;
                    if budget.bytes.load(Ordering::Relaxed) <= low_water {
                        break 'outer;
                    }
                }
            }
        }
        if paged_any && !scratch.announced.swap(true, Ordering::Relaxed) {
            println!("💾 held spans over the RAM cap - paging to scratch, set stays one-pass");
        }
        !budget.over()
    }

    /// Page password-parked slots' RAM spans to scratch, down to the
    /// [`pw_await_spill`] window. Unlike [`Self::page_out_holds`] this
    /// is not budget-breach relief - parked ciphertext goes to disk
    /// long before the cap, keeping a password-less set's resident
    /// footprint at the window instead of the payload. A refusal (gate
    /// off, ceiling, scratch death) leaves spans in RAM, where the cap
    /// arbiter still stands exactly as before.
    ///
    /// `first` is the slot that just parked: it is walked before the
    /// others, newest span first, so the steady state (budget hovering
    /// at the window) pages exactly the arriving span and stops -
    /// without that ordering, every park rescans the thousands of
    /// already-paged spans of a large set, and the per-article cost
    /// goes quadratic in the payload.
    pub(super) fn page_pw_holds(&self, inner: &mut Inner, first: usize) {
        if !inner.holds_page_on {
            return;
        }
        let budget = inner.budget.clone();
        let scratch = inner.scratch.clone();
        let cap = match scratch.cap.load(Ordering::Relaxed) {
            0 => 4 * budget.cap() as u64,
            c => c,
        };
        let window = pw_await_spill(budget.cap());
        let mut paged_any = false;
        let order: Vec<usize> = std::iter::once(first)
            .chain((0..inner.slots.len()).filter(|&si| si != first))
            .collect();
        'outer: for si in order {
            if inner.slots[si].pw_await.is_none() {
                continue;
            }
            let s = &mut inner.slots[si];
            for store in [&mut s.holds, &mut s.header_spans] {
                for (_, span) in store.iter_mut().rev() {
                    let HoldSpan::Ram(bytes) = span else { continue };
                    if bytes.len() < HOLDS_PAGE_MIN {
                        continue;
                    }
                    let Some(off) = scratch.append(bytes, cap) else {
                        break 'outer;
                    };
                    let len = bytes.len();
                    budget.sub(len);
                    *span = HoldSpan::Paged { off, len };
                    paged_any = true;
                    if budget.len() <= window {
                        break 'outer;
                    }
                }
            }
        }
        if paged_any && !scratch.announced.swap(true, Ordering::Relaxed) {
            println!("🔒 spans parked for a password are paging to scratch");
        }
    }

    /// Take one held span's bytes back into RAM, releasing whichever
    /// store held them (budget for RAM, scratch live-count for paged -
    /// read BEFORE release, so an idle truncate can never beat the
    /// pread). The caller feeds them onward; a re-hold re-charges as a
    /// fresh RAM span. Routing lock held.
    pub(super) fn reclaim_span(inner: &Inner, span: HoldSpan) -> io::Result<Vec<u8>> {
        match span {
            HoldSpan::Ram(b) => {
                inner.budget.sub(b.len());
                Ok(b)
            }
            HoldSpan::Paged { off, len } => {
                let mut b = vec![0u8; len];
                inner.scratch.read(off, &mut b)?;
                inner.scratch.release(len);
                Ok(b)
            }
        }
    }

    /// Drop-only release (discard/abandon paths): uncharge a held span
    /// without a read-back.
    pub(super) fn uncharge_span(inner: &Inner, span: &HoldSpan) {
        match span {
            HoldSpan::Ram(b) => inner.budget.sub(b.len()),
            HoldSpan::Paged { len, .. } => inner.scratch.release(*len),
        }
    }

    /// Flush held spans through the slot's current mode.
    ///
    /// Runs with `refeed_active` raised: the under-lock write sites
    /// report every plain placement into `late_placements`, which is
    /// how an article that was parked whole (Persist::Held) still gets
    /// its journal record once its bytes land. Saved/restored, not
    /// set/cleared - drains nest (reresolve firing inside a feed).
    pub(super) fn drain_holds(&self, inner: &mut Inner, slot: usize) -> io::Result<()> {
        let prev = inner.refeed_active;
        inner.refeed_active = true;
        let r = self.drain_holds_feed(inner, slot);
        inner.refeed_active = prev;
        r
    }

    fn drain_holds_feed(&self, inner: &mut Inner, slot: usize) -> io::Result<()> {
        let holds = std::mem::take(&mut inner.slots[slot].holds);
        inner.slots[slot].pre_bytes = 0;
        for (off, span) in holds {
            // A paged span reads back but is NOT released until after the
            // feed: whatever the feed re-holds is a subrange of these very
            // bytes, and rebinding those to the still-valid scratch region
            // (below) is what keeps a drain cycle from re-appending the
            // same bytes - unbounded churn would eat the scratch ceiling
            // on exactly the big-transient-window sets paging exists for.
            let (bytes, paged_at) = match span {
                HoldSpan::Ram(b) => {
                    inner.budget.sub(b.len());
                    (b, None)
                }
                HoldSpan::Paged { off: po, len } => {
                    let mut b = vec![0u8; len];
                    inner.scratch.read(po, &mut b)?;
                    (b, Some((po, len)))
                }
            };
            let held_before = inner.slots[slot].holds.len();
            let stash_before = inner.slots[slot].header_spans.len();
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
            if let Some((po, len)) = paged_at {
                Self::rebind_subranges(inner, slot, held_before, stash_before, off, po, &bytes);
                inner.scratch.release(len);
            }
        }
        Ok(())
    }

    /// After re-feeding a PAGED span, point any re-held subrange of it
    /// back at its scratch region instead of a fresh RAM copy: the
    /// region is write-once and still live (released only after this
    /// runs, so the live-count never falsely hits zero), and the re-held
    /// bytes are subslices of the bytes read from it. Pure accounting -
    /// no new appends, no I/O - which is what bounds the drain/re-hold
    /// ping-pong at one scratch write per unique byte.
    ///
    /// The subslice premise is CHECKED, not assumed: a re-entrant drain
    /// (reresolve firing inside the feed) can repopulate the vectors and
    /// stale the `*_before` indices, and a repair span parked behind the
    /// original may overlap the fed range with DIFFERENT bytes -
    /// rebinding either would silently swap its bytes for the region's.
    /// An entry only rebinds when its bytes equal the fed slice at its
    /// offset; anything else stays in RAM with its charge (correct,
    /// just unpaged until the next breach).
    pub(super) fn rebind_subranges(
        inner: &mut Inner,
        slot: usize,
        held_before: usize,
        stash_before: usize,
        fed_off: u64,
        po: u64,
        fed: &[u8],
    ) {
        let budget = inner.budget.clone();
        let scratch = inner.scratch.clone();
        let s = &mut inner.slots[slot];
        for (vec, from) in [
            (&mut s.holds, held_before),
            (&mut s.header_spans, stash_before),
        ] {
            for (ho, hs) in vec.iter_mut().skip(from) {
                let HoldSpan::Ram(b) = hs else { continue };
                let Some(rel) = ho.checked_sub(fed_off) else {
                    continue;
                };
                let rel = rel as usize;
                let Some(end) = rel.checked_add(b.len()) else {
                    continue;
                };
                if end > fed.len() || fed[rel..end] != b[..] {
                    continue;
                }
                scratch.add_live(b.len());
                budget.sub(b.len());
                *hs = HoldSpan::Paged {
                    off: po + rel as u64,
                    len: b.len(),
                };
            }
        }
    }

    /// One Unknown slot exceeded the per-slot pre-classification budget -
    /// flip just that slot to Plain and flush its holds to disk. Same
    /// safety argument as [`Self::overflow_to_plain`], applied before the
    /// GLOBAL cap wedges the whole pipeline on one unsniffable slot.
    pub(super) fn spill_unclassified_slot(&self, inner: &mut Inner, slot: usize) -> io::Result<()> {
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
    pub(super) fn overflow_to_plain(&self, inner: &mut Inner) -> io::Result<()> {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rar::fixtures;

    use crate::extract::testutil::*;

    /// Holds paging (the budget-breach relief valve, default ON): the
    /// same neither-end-parsed window that demotes with paging off pages
    /// to scratch instead and the set still extracts one-pass,
    /// byte-exact - no volume ever touches disk, and the scratch file
    /// itself is gone after finish.
    #[test]
    fn paged_holds_keep_a_tight_budget_set_one_pass() {
        let inner = "late2.mkv";
        let (data, vols, names) = uniform_store_set(inner, 300_000, 44, 200_000, 31);
        let mut order = shuffled_zero_last(vols.len(), 0xC0FFEE);
        let tail = vols.len() - 1;
        let at = order.iter().position(|&v| v == tail).unwrap();
        order.remove(at);
        order.insert(order.len() - 1, tail);
        let dir = tmpdir("holds-paged-onepass");
        let ex = Extractor::new(&dir, vols.len(), true);
        ex.set_holds_cap(8 << 20);
        for &vi in &order {
            feed(&ex, vi, &names[vi], &vols[vi], 9000, 70 + vi as u64);
        }
        assert!(ex.holds_paged_total() > 0, "paging never engaged");
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join(inner)).unwrap(), data);
        for n in &names {
            assert!(!dir.join(n).exists(), "volume {n} materialized");
        }
        // Close the scratch handle before asserting the name is gone:
        // finish() unlinks with the handle deliberately open, and on
        // classic-delete-semantics filesystems (pre-1903 Windows, SMB)
        // the name stays listed until last close.
        drop(ex);
        // Only the payload survives - the scratch must not outlive finish.
        assert_eq!(dir_files(&dir), vec![inner.to_string()]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Mapped PAR2 repair sees paged spans: bytes parked behind an
    /// unresolvable base page out under the cap, and `covered`/`read_at`
    /// still serve them byte-exactly - repair reads through exactly these
    /// paths to rebuild the blocks that free the holds. The set then
    /// completes one-pass once the neighbours land.
    #[test]
    fn mapped_repair_reads_a_paged_span() {
        let dir = tmpdir("holds-paged-readat");
        let total = payload(30_000_000, 13);
        let vols = [
            fixtures::rar5_volume_n(
                &[("film.mkv", 30_000_000, &total[..7_000_000], false, true)],
                0,
            ),
            fixtures::rar5_volume_n(
                &[(
                    "film.mkv",
                    30_000_000,
                    &total[7_000_000..22_000_000],
                    true,
                    true,
                )],
                1,
            ),
            fixtures::rar5_volume_n(
                &[("film.mkv", 30_000_000, &total[22_000_000..], true, false)],
                2,
            ),
        ];
        let ex = Extractor::new(&dir, 3, true);
        ex.set_holds_cap(1); // floors at 8 MB - part2's data area exceeds it
        let feed_seq = |slot: usize, name: &str, vol: &[u8]| {
            for (i, chunk) in vol.chunks(65_000).enumerate() {
                ex.write(slot, name, vol.len() as u64, (i * 65_000) as u64, chunk)
                    .unwrap();
            }
        };
        // Middle volume first: a middle piece is neither its file's head
        // nor its tail, so nothing resolves its base and the whole data
        // area holds - and pages.
        feed_seq(1, "x.part2.rar", &vols[1]);
        assert!(ex.holds_paged_total() > 0, "paging never engaged");
        // A mid-volume range that can only live in (paged) holds now.
        let (off, len) = (5_000_000u64, 200_000usize);
        assert!(ex.covered(1, off, len), "paged span invisible to covered");
        let mut got = vec![0u8; len];
        ex.read_at(1, off, &mut got).unwrap();
        assert_eq!(&got[..], &vols[1][off as usize..off as usize + len]);
        // The whole volume reconstructs too (headers + RAM + paged spans).
        let mut whole = vec![0u8; vols[1].len()];
        ex.read_at(1, 0, &mut whole).unwrap();
        assert_eq!(whole, vols[1]);
        // With the neighbours fed, the paged spans drain into place and
        // the set finishes one-pass.
        feed_seq(0, "x.part1.rar", &vols[0]);
        feed_seq(2, "x.part3.rar", &vols[2]);
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("film.mkv")).unwrap(), total);
        // Handle closed before the name-absence check (delete-pending
        // filesystems keep the unlinked name listed until last close).
        drop(ex);
        assert_eq!(dir_files(&dir), vec!["film.mkv".to_string()]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The scratch has a hard ceiling of its own: exceeding it demotes
    /// with the SAME "held-bytes cap" reason as a RAM breach with paging
    /// off. The finish ladder keys volume-level remediation off that
    /// substring, so the wording is load-bearing - a novel string would
    /// demote the volumes and then ship the job with no payload, exit 0.
    #[test]
    fn scratch_ceiling_demotes_with_the_unchanged_reason() {
        let dir = tmpdir("holds-paged-ceiling");
        let total = payload(30_000_000, 13);
        let vols = [
            fixtures::rar5_volume_n(
                &[("film.mkv", 30_000_000, &total[..7_000_000], false, true)],
                0,
            ),
            fixtures::rar5_volume_n(
                &[(
                    "film.mkv",
                    30_000_000,
                    &total[7_000_000..22_000_000],
                    true,
                    true,
                )],
                1,
            ),
            fixtures::rar5_volume_n(
                &[("film.mkv", 30_000_000, &total[22_000_000..], true, false)],
                2,
            ),
        ];
        let ex = Extractor::new(&dir, 3, true);
        ex.set_holds_cap(1); // floors at 8 MB
        ex.set_holds_scratch_cap(2 << 20); // far below part2's window
        let feed_seq = |slot: usize, name: &str, vol: &[u8]| {
            for (i, chunk) in vol.chunks(65_000).enumerate() {
                ex.write(slot, name, vol.len() as u64, (i * 65_000) as u64, chunk)
                    .unwrap();
            }
        };
        feed_seq(1, "x.part2.rar", &vols[1]);
        feed_seq(0, "x.part1.rar", &vols[0]);
        feed_seq(2, "x.part3.rar", &vols[2]);
        let rep = ex.finish().unwrap();
        assert!(ex.holds_paged_total() > 0, "paging never engaged");
        assert!(
            rep.fallbacks
                .iter()
                .any(|(_, w)| w.contains("held-bytes cap") && !w.starts_with("nested fallback:")),
            "{:?}",
            rep.fallbacks
        );
        // Demoting is not losing: every volume byte-exact on disk, and
        // the scratch gone with the demote (its spans all drained).
        for (vi, vol) in vols.iter().enumerate() {
            assert_eq!(
                &std::fs::read(dir.join(format!("x.part{}.rar", vi + 1))).unwrap(),
                vol,
                "volume {vi}"
            );
        }
        // Handle closed before the name-absence check (delete-pending
        // filesystems keep the unlinked name listed until last close).
        drop(ex);
        assert!(
            !dir_files(&dir)
                .iter()
                .any(|n| n.starts_with(HOLDS_TMP_PREFIX)),
            "scratch left behind: {:?}",
            dir_files(&dir)
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The paging gate: NZBFAST_NO_HOLDS_PAGE=1 parses as off (asserted
    /// on the pure helper for the parallel-runner reason the chase gates
    /// established); the runtime setter drives the same latch and is
    /// exercised by the paging-off legs above.
    #[test]
    fn holds_paging_env_parse() {
        assert!(holds_page_env_off_value(Some("1")));
        assert!(!holds_page_env_off_value(Some("0")));
        assert!(!holds_page_env_off_value(None));
    }

    /// The scratch's reader-pin contract, pinned directly (the 31 Jul
    /// race audit's finding was a gate that consulted `pins` outside
    /// the state mutex): a pin taken at plan time must block BOTH
    /// reclaim gates - the release-side truncate and the append-side
    /// cursor reset - for a planned pread of a since-released region,
    /// and must stop blocking once dropped.
    #[test]
    fn scratch_pin_blocks_idle_reclaim() {
        let dir = tmpdir("scratch-pin");
        let sc = Arc::new(HoldsScratch::new(&dir));
        let payload = b"exact bytes a planned pread must still see";
        let off = sc.append(payload, 1 << 20).expect("first append");
        // A reader plans: pin, then the span is consumed (released)
        // before the pread lands - the exact window of the race.
        let mut pin = ScratchPin::none();
        pin.pin(&sc);
        sc.release(payload.len());
        // live == 0, but the pin blocks the truncate: the planned pread
        // still sees the bytes...
        let mut buf = vec![0u8; payload.len()];
        sc.read(off, &mut buf).unwrap();
        assert_eq!(&buf, payload);
        // ...and a new append must not reset the cursor onto the
        // planned region either.
        let off2 = sc.append(b"XXXX", 1 << 20).expect("append under pin");
        assert_ne!(off2, off, "cursor reset under a live pin");
        sc.read(off, &mut buf).unwrap();
        assert_eq!(&buf, payload, "planned region overwritten under a live pin");
        // Pin dropped and everything released: the idle reset may fire.
        drop(pin);
        sc.release(4);
        let off3 = sc.append(b"YYYY", 1 << 20).expect("append after idle");
        assert_eq!(off3, 0, "idle reset never fired once unpinned");
        sc.release(4);
        sc.cleanup();
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
            ex.write(0, "v.rar", vol.len() as u64, s as u64, &vol[s..e])
                .unwrap();
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
        ex.write(0, "video.bin", data.len() as u64, 0, &data[..art])
            .unwrap();
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
            ex.write(0, "v.rar", vol.len() as u64, s as u64, &vol[s..e])
                .unwrap();
        }
        ex.write(0, "v.rar", vol.len() as u64, 0, &vol[..art])
            .unwrap();
        ex.finish().unwrap();
        assert_eq!(
            std::fs::read(dir.join("v.rar")).unwrap(),
            vol,
            "materialized volume must be byte-identical"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The unclassified ceiling scales with the holds budget (the
    /// 11 Aug 2026 settle-round 3x-I/O bug): a RAR volume whose
    /// offset-0 article runs late must NOT spill to Plain at a flat
    /// 64 MB while the budget has gigabytes free - it holds, sniffs on
    /// the late head, and the set still extracts one-pass with no
    /// volume file ever touching disk. The small-budget spill is
    /// pinned by `unclassified_slot_spills_to_plain_before_sniff`
    /// above, which is the degradation this must not disturb.
    #[test]
    fn a_late_sniff_on_a_big_budget_holds_instead_of_spilling() {
        let dir = tmpdir("latesniff-bigbudget");
        let inner = "movie.mkv";
        // Bigger than the old flat 64 MB ceiling, far under cap/4.
        let data = payload(72 << 20, 11);
        let vol = fixtures::rar5_volume(&[(inner, (72 << 20) as u64, &data, false, false)]);
        let ex = Extractor::new(&dir, 1, true);
        ex.set_holds_cap(1 << 30); // spill budget = max(256 MB, 4 MB)
        let art = 256 * 1024;
        let n = vol.len().div_ceil(art);
        // Every article except offset-0, reversed - the whole volume
        // piles into pre-classification holds.
        for i in (1..n).rev() {
            let s = i * art;
            let e = (s + art).min(vol.len());
            ex.write(0, "v.rar", vol.len() as u64, s as u64, &vol[s..e])
                .unwrap();
        }
        assert!(
            ex.holds_peak() > 64 << 20,
            "fixture lost its teeth: holds peaked at {} - the old flat \
             ceiling was never exceeded",
            ex.holds_peak()
        );
        assert!(
            !dir.join("v.rar").exists(),
            "slot spilled to Plain under a nearly-empty budget"
        );
        // The head arrives dead last: sniff, map, drain, one-pass.
        ex.write(0, "v.rar", vol.len() as u64, 0, &vol[..art])
            .unwrap();
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join(inner)).unwrap(), data);
        assert!(
            !dir.join("v.rar").exists(),
            "volume materialized despite the late sniff arriving"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The spill budget's shape, pinned directly: floor for small
    /// slices, scaling (not a flat 64 MB) above it.
    #[test]
    fn unclassified_spill_scales_with_the_budget() {
        assert_eq!(unclassified_spill(8 << 20), 4 << 20); // floor
        assert_eq!(unclassified_spill(256 << 20), 64 << 20);
        assert_eq!(unclassified_spill(1 << 30), 256 << 20); // past the old flat ceiling
        // The field shape: 45% of a 16 GiB budget held a 64 MB window.
        let field_holds = (16u64 << 30) as usize / 100 * 45;
        assert!(unclassified_spill(field_holds) > 1 << 30);
    }

    /// The stalled-chase window's shape, pinned directly: floored for
    /// small slices, and NEVER scaling past 64 MB - a bigger budget
    /// buys no reason to keep cold frontier bytes resident (the same
    /// deliberate ceiling as `pw_await_spill`).
    #[test]
    fn chase_stall_spill_window_shape() {
        assert_eq!(chase_stall_spill(8 << 20), 4 << 20); // floor
        assert_eq!(chase_stall_spill(256 << 20), 64 << 20);
        assert_eq!(chase_stall_spill(16 << 30), 64 << 20); // the field shape
    }

    /// TODO 100 follow-up: an article that arrives before the offset-0
    /// sniff establishes the store mapper parks whole (`Persist::Held`)
    /// and its bytes land only when the sniff arrives and the holds
    /// drain, INSIDE the extractor. Those drained writes must surface
    /// through `drain_late_placements`, or the journal writer has
    /// nothing to record and every crash/ENOSPC resume refetches
    /// fully-written payload articles - seen as nondeterministically
    /// missing `R` records in the §100 e2e.
    #[test]
    fn held_then_drained_articles_surface_their_placements() {
        let dir = tmpdir("holds-late-placements");
        let inner = "movie.mkv";
        let data = payload(600_000, 9);
        let vol = fixtures::rar5_volume(&[(inner, 600_000, &data, false, false)]);
        let art = 100_000usize;
        let n = vol.len().div_ceil(art);
        let ex = Extractor::new(&dir, 1, true);
        // Every article except offset-0, in reverse: no sniff yet, so
        // each parks whole and must say so.
        let mut held: Vec<(u64, u64)> = Vec::new();
        for i in (1..n).rev() {
            let s = i * art;
            let e = ((i + 1) * art).min(vol.len());
            match ex
                .write(0, "v.rar", vol.len() as u64, s as u64, &vol[s..e])
                .unwrap()
            {
                Persist::Held(frags) => {
                    assert!(frags.is_empty(), "a pre-sniff hold has nothing on disk");
                    held.push((s as u64, (e - s) as u64));
                }
                _ => panic!("article {i} arrived pre-sniff and must park as Held"),
            }
        }
        assert!(
            ex.drain_late_placements().is_empty(),
            "nothing has drained - nothing may be reported"
        );
        // The offset-0 article: the sniff maps the volume and the drain
        // writes every held payload byte into the inner file.
        ex.write(0, "v.rar", vol.len() as u64, 0, &vol[..art])
            .unwrap();
        let late = ex.drain_late_placements();
        assert!(
            late.iter().all(|(slot, f)| *slot == 0 && f.file == inner),
            "store payload places into the inner file: {late:?}"
        );
        // Every held article lying fully inside the data area (the last
        // one also carries the end-of-archive block, which legitimately
        // never lands in an output file) must now be fully covered.
        let covered = |off: u64, len: u64| {
            let mut iv: Vec<(u64, u64)> = late
                .iter()
                .map(|(_, f)| (f.vol_off, f.vol_off + f.len))
                .filter(|&(s, e)| s >= off && e <= off + len)
                .collect();
            iv.sort_unstable();
            let mut to = off;
            for (s, e) in iv {
                if s > to {
                    return false;
                }
                to = to.max(e);
            }
            to >= off + len
        };
        let mut payload_articles = 0;
        for &(off, len) in held.iter().filter(|&&(o, l)| o + l < vol.len() as u64) {
            assert!(
                covered(off, len),
                "held article at {off}+{len} drained fully but its placement \
                 was not reported"
            );
            payload_articles += 1;
        }
        assert!(payload_articles >= 3, "fixture geometry lost its teeth");
        // A second drain reports nothing new, and the set still
        // finishes one-pass, byte-exact.
        assert!(ex.drain_late_placements().is_empty());
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join(inner)).unwrap(), data);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

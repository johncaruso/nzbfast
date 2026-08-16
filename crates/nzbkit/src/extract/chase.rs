//! The RAR volume chase: attaching a posted multi-volume set to a chase
//! controller, the worker that walks volume to volume, the spans it
//! writes, and the teardown/finish bookkeeping.
//!
//! Split out of the 19,920-line `extract.rs` under the TODO 43 recipe:
//! a verbatim move of the methods, not a redesign.

use super::*;
use crate::sync::MutexExt;

impl Extractor {
    /// Mapping-mode span: feed headers, extract mapped parts, hold the
    /// rest. With `sink` set (the hot write path), mapped writes queue as
    /// jobs / child forwards for after the lock; without (drain/fallback
    /// paths), writer writes run inline and child forwards queue as owned
    /// pending jobs (the child cannot be called under our lock).
    pub(super) fn rar_span(
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
                // The identity fact in the same header: the whole-file
                // CRC32 of an inner file, which is an exact key into the
                // open release databases (see `srrdb`). Encrypted
                // entries are skipped - RAR5 may tweak the stored CRC so
                // it cannot fingerprint the plaintext, and a header-
                // encrypted archive never reaches here at all, which is
                // precisely the `-hp` case the oracle cannot serve.
                if let (false, Some(crc)) = (e.encrypted, e.file_crc) {
                    self.shape.note_crc(&e.name, crc);
                }
            }
            self.shape.note(self.depth, bits);
        }
        let stashed = self.retain_header_bytes(inner, slot, offset, data);
        // Header bytes parked in RAM hold this article's record exactly
        // like a data hold does: report the span Held (same refeed
        // exclusion as the hold-push sites) so the article parks instead
        // of dropping to Persist::No. It completes if the stash ever
        // lands on disk - the fallback reconstruction surfaces identity
        // placements for it - and an article whose stash stays in RAM
        // just refetches on resume, which was its record before too.
        if stashed > 0 && !inner.refeed_active {
            inner.span_held = true;
        }
        // A slot that already carries a blocker takes the blocker's route
        // below instead of this one. Its reason is the specific, actionable
        // one - encrypted headers ask the user for a password, compressed
        // gets a chase - and reporting the budget here in its place turned
        // "this archive needs a password" into a failed job that ran unrar
        // with no password. Deferring cannot leave the budget over: both of
        // those routes release this same charge.
        let blocked = inner.slots[slot].mapper.as_ref().unwrap().blocker.is_some();
        if stashed > 0 && !blocked && inner.budget.over() && !self.page_out_holds(inner) {
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
            // Increment A: a password-shaped blocker with the candidate
            // probe installed parks instead of demoting - the password
            // may be sitting in a sidecar of this very NZB, and a
            // Verified hit re-keys the mapper with every byte still in
            // RAM. A miss resolves through the exact demote below, at
            // budget pressure or at finish.
            if self.try_pw_await(inner, slot, &b, offset, data)? {
                return Ok(());
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
            && !inner.slots[slot]
                .mapper
                .as_ref()
                .unwrap()
                .entries
                .is_empty()
        {
            let raw = inner.slots[slot].mapper.as_ref().unwrap().entries[0]
                .name
                .clone();
            let key = Self::canon_key(inner, &raw);
            inner.slots[slot].group = Some(key.clone());
            let grp = inner.groups.entry(key.clone()).or_insert_with(|| Group {
                slots: Vec::new(),
                bases: HashMap::new(),
                resolve_stamp: None,
                arith_provisional: HashMap::new(),
                arith_ever: false,
                fallback: false,
                fallback_reason: None,
                out_names: HashMap::new(),
                routed: HashMap::new(),
                routed_plain: HashMap::new(),
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
        } else if matches!(inner.slots[slot].mode, SlotMode::RarFallback) {
            // The reresolve above demoted this very group (arithmetic
            // premise contradicted by the parse progression THIS span
            // caused). The fallback drained the holds and read back the
            // extracted bytes, but the current span is in neither -
            // write it through, same as the blocker routes above (the
            // already-stashed header part rewrites identical bytes).
            self.plain_span(inner, slot, offset, data)?;
        }
        Ok(())
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
    /// re-extracting those through a chase is out of scope. (An
    /// all-compressed multi-entry archive is NOT excluded by the
    /// single-entry check below: the blocker fires on the first parsed
    /// entry, so exactly one entry exists at attach time, and the
    /// sequence driver then decodes every member through its own sink.)
    ///
    /// Runs at depth 0 too (the top-level analogue of TODO 37 step 1):
    /// a POSTED compressed RAR chases, its decoded members land in the
    /// level-1 child and promote to the root output - the same rails
    /// nested chases have always used. Nothing about the engine is
    /// depth-specific; the old guard predated the root promote wiring.
    ///
    /// A set larger than the holds cap no longer has to demote: the
    /// engine decodes split members incrementally and publishes how much
    /// of each volume it is finished with, and [`Self::rar_trim_set`]
    /// releases those bytes into the volumes' own files under budget
    /// pressure. What still demotes is a set whose ARRIVALS run so far
    /// ahead of the decode that the live window alone fills the cap -
    /// trimming declines there, and declining is how it says so.
    fn try_attach_chase(&self, inner: &mut Inner, slot: usize, b: &MapBlocker) -> io::Result<bool> {
        if (self.depth == 0 && !inner.top_chase_on)
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
        let (name, vol_index, v4) = {
            let Some(m) = inner.slots[slot].mapper.as_ref() else {
                return Ok(false);
            };
            let v4 = match m.version {
                Some(RarVersion::V5) => false,
                Some(RarVersion::V4) => true,
                None => return Ok(false),
            };
            if m.entries.len() != 1 {
                return Ok(false);
            }
            let e = &m.entries[0];
            // An encrypted member without a password can't decode anywhere.
            if e.method != Method::Compressed || (e.encrypted && inner.password.is_none()) {
                return Ok(false);
            }
            // RAR4 headers carry no volume number; the set's order lives in
            // the volume NAMES (.rar < .r00 < .r01, .partNN). RAR5's header
            // number is authoritative and survives renames, so it stays
            // preferred there.
            let vol_index = if v4 {
                Self::v4_vol_index(&inner.slots[slot].name)
            } else {
                m.volume_number.unwrap_or(0) as usize
            };
            (e.name.clone(), vol_index, v4)
        };
        let key = Self::canon_key(inner, &name);
        let grp = inner.groups.entry(key.clone()).or_insert_with(|| Group {
            slots: Vec::new(),
            bases: HashMap::new(),
            resolve_stamp: None,
            arith_provisional: HashMap::new(),
            arith_ever: false,
            fallback: false,
            fallback_reason: None,
            out_names: HashMap::new(),
            routed: HashMap::new(),
            routed_plain: HashMap::new(),
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
        let ctl = grp
            .chase
            .clone()
            .unwrap_or_else(|| Arc::new(ChaseCtl::new(v4)));
        // A set whose volumes disagree on the RAR family is not a set.
        if ctl.v4 != v4 {
            return Ok(false);
        }
        {
            let st = ctl.shared.lock_ok();
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
        let buf = Arc::new(FrontierBuffer::new_gated(
            size,
            inner.verify_gate.clone().map(|g| (g, slot)),
            // Arms the stalled-chase cold spill (RAR chases only - the
            // forward-only reader is what makes "beyond the gap" cold).
            Some(inner.scratch.clone()),
            Some(inner.self_weak.clone()),
        ));
        // §156.1: a terminal verdict that landed before this attach
        // still marks the volume it doomed.
        if inner.slots[slot].article_lost {
            buf.mark_lost();
        }
        // Seed with everything already seen. The header stash MOVES in
        // (like the holds): the buffer keeps every byte from offset 0
        // for the life of the chase - reads never consume it, and a
        // demotion materializes the volume straight out of it - so a
        // second RAM copy would only double-charge the shared budget
        // that the stash is now billed to. Nothing reads `header_spans`
        // outside `SlotMode::Rar`, which this slot just left.
        let mut stored = 0usize;
        let headers = std::mem::take(&mut inner.slots[slot].header_spans);
        let holds = std::mem::take(&mut inner.slots[slot].holds);
        inner.slots[slot].pre_bytes = 0;
        // Both stashes are OUT of the slot now, so a reclaim that fails
        // (a scratch read error) must uncharge everything it did not
        // read: dropping the rest frees the memory but leaves the budget
        // - and the scratch reservation - charged for it.
        let mut rest = headers.into_iter().chain(holds);
        let mut failed = None;
        for (off, span) in rest.by_ref() {
            match Self::reclaim_span(inner, span) {
                Ok(bytes) => stored = buf.write_span(off, &bytes),
                Err(e) => {
                    failed = Some(e);
                    break;
                }
            }
        }
        if let Some(e) = failed {
            for (_, span) in rest {
                Self::uncharge_span(inner, &span);
            }
            return Err(e);
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
            let mut st = ctl.shared.lock_ok();
            st.vols.insert(vol_index, ChaseVol { buf, size, slot });
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
            *ctl.worker.lock_ok() = Some(handle);
        }
        if seeded_conflict {
            self.fallback_slot_or_group(inner, slot, "repair rewrote chased bytes")?;
            return Ok(true);
        }
        if inner.budget.over() {
            // A volume joining a chase already in flight: the engine may
            // be far past earlier volumes, so try the drop-behind before
            // giving up on the whole set.
            self.rar_trim_set(inner, &ctl)?;
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
    pub(super) fn chase_span(
        &self,
        inner: &mut Inner,
        slot: usize,
        offset: u64,
        data: &[u8],
    ) -> io::Result<()> {
        // Anything below the trim point is not the buffer's to reconcile
        // - it is already in the archive file. A late span there is
        // either a routing re-feed (which cannot happen after a trim:
        // re-feeds all land at classification) or a PAR2 repair rewrite,
        // and we cannot tell cheaply. So take the safe reading: write it
        // to the file, where it OVERWRITES whatever the trim spilled, and
        // force the forfeit below - the engine may already have decoded
        // from the stale copy. Same shape and same direction as the
        // conflict guard, which is what actually fires here.
        //
        // Unreachable in practice: `patch_volume_span` refuses a SevenZ
        // slot outright, and at depth 0 the caller materializes a chased
        // slot before repair runs at all.
        let trimmed = inner.slots[slot]
            .chase
            .as_ref()
            .map(|ch| (ch.buf.clone(), ch.buf.base()));
        if let Some((buf, base)) = trimmed
            && offset < base
        {
            let n = ((base - offset) as usize).min(data.len());
            buf.mark_conflict();
            self.plain_span(inner, slot, offset, &data[..n])?;
        }
        let Some(ch) = inner.slots[slot].chase.as_mut() else {
            return match inner.slots[slot].mode {
                SlotMode::Plain | SlotMode::RarFallback => {
                    self.plain_span(inner, slot, offset, data)
                }
                // Still a chase mode but the chase is gone means finish()
                // already took it on success, so this span goes nowhere -
                // and the conflict check that would catch a differing
                // rewrite lives on the chase we no longer have. Nothing in
                // this crate reaches it (the daemon is strictly download ->
                // repair -> finish), but that sequencing is a caller
                // contract, so assert rather than trust it.
                _ => {
                    debug_assert!(
                        false,
                        "span for slot {slot} arrived after finish() took its chase - \
                         a differing rewrite here would go undetected"
                    );
                    Ok(())
                }
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
            return self.chase_forfeit(inner, slot, "repair rewrote chased bytes");
        }
        // Proactive cold spill: a RAR chase WEDGED behind an unfillable
        // gap is holding bytes nothing can decode - as cold as parked
        // ciphertext - so they page to the holds scratch beyond a small
        // window instead of riding RAM to the cap (the 11 Aug 2026 soak
        // held a whole damaged 3.5 GB set resident this way). §156.1:
        // the wedge test is what arms this, not the verdict alone - a
        // healthy chase that merely shares a job with a lost article
        // used to skim its entire pile through scratch and pread it
        // straight back (527 MB of doubled I/O on the A/B's 614 MB
        // set). A gap that does fill later (retry, repair) reads paged
        // spans straight back through the frontier buffer; a demote
        // materializes from them byte-exact. The paging itself runs on
        // the detached pager (§156.3b) - this path holds the extractor
        // lock, and the pass does disk I/O.
        if inner.lost_articles.load(Ordering::Relaxed)
            && inner.slots[slot].sevenz.is_none()
            && inner.budget.len() > chase_stall_spill(inner.budget.cap())
            && let Some(ctl) = Self::rar_chase_of(inner, slot)
            && Self::chase_first_doomed(&ctl).is_some()
            && let Some(me) = inner.self_weak.upgrade()
        {
            me.wake_pager();
        }
        if inner.budget.over() {
            // Drop-behind first: an archive whose decode is keeping up
            // has a long prefix nobody will read again, and releasing it
            // is what lets a container larger than the cap stream at all.
            if let Some(ctl) = inner.slots[slot].sevenz.clone() {
                self.sevenz_trim_set(inner, &ctl)?;
            } else if let Some(ctl) = Self::rar_chase_of(inner, slot) {
                self.rar_trim_set(inner, &ctl)?;
            }
        }
        if inner.budget.over() {
            // Same shared budget as the holds cap, so the reason carries
            // the same substring: the caller keys volume-level remediation
            // off "held-bytes cap", and the bare wording this used to have
            // matched nothing, demoting the volumes and then shipping the
            // job with no payload and exit 0.
            self.chase_forfeit(inner, slot, "held-bytes cap: chase memory")?;
        }
        Ok(())
    }
    /// Bytes the RAR chase drop-behind has spilled out of RAM, this
    /// extractor and every child below it. A chased set that finishes
    /// with a nonzero count here is one that only fit because of the
    /// drop-behind.
    pub fn chase_trimmed_bytes(&self) -> u64 {
        let (own, child) = {
            let inner = self.inner_read();
            (inner.chase_trimmed, inner.child.clone())
        };
        own + child.map_or(0, |c| c.chase_trimmed_bytes())
    }
    /// Bytes chased volumes are holding in RAM right now, this extractor
    /// and every child below it - what the drop-behind is keeping down.
    pub fn chase_retained_bytes(&self) -> usize {
        let (own, child) = {
            let inner = self.inner_read();
            (
                inner
                    .slots
                    .iter()
                    .filter_map(|s| s.chase.as_ref().map(|ch| ch.charged))
                    .sum::<usize>(),
                inner.child.clone(),
            )
        };
        own + child.map_or(0, |c| c.chase_retained_bytes())
    }
    /// Volumes the RAR engine has said it is wholly finished with, over
    /// every live chase in this extractor and its children. What the
    /// drop-behind is allowed to release, and the only honest way to
    /// watch a chase keep up with its arrivals.
    pub fn chase_consumed_volumes(&self) -> usize {
        let (groups, child) = {
            let inner = self.inner_read();
            (
                inner
                    .groups
                    .values()
                    .filter_map(|g| g.chase.clone())
                    .collect::<Vec<_>>(),
                inner.child.clone(),
            )
        };
        let own: usize = groups
            .iter()
            .map(|ctl| {
                ctl.low_water
                    .lock_ok()
                    .values()
                    .filter(|&&at| at == u64::MAX)
                    .count()
            })
            .sum();
        own + child.map_or(0, |c| c.chase_consumed_volumes())
    }
    /// Report a TERMINAL article verdict for `slot`: that slot's bytes
    /// will never all arrive from the wire (a 430 on every provider, an
    /// article outside retention, a dead transport). Sticky and
    /// idempotent; the chain-wide flag arms the arrival-path and
    /// reader-path wedge checks, and the SLOT mark (§156.1) is what
    /// makes the trigger honest: only volumes that can actually contain
    /// the hole are marked, so a healthy chase that merely shares the
    /// job with the loss never pages. The immediate pass here matters
    /// because verdicts typically land AFTER the pile has built (retries
    /// exhaust last), and a set already wedged at its hole sees no
    /// further spans to re-arm from. A later repair (or a rescheduled
    /// fetch) that fills the gap resumes the decode straight off the
    /// paged bytes.
    pub fn note_article_lost(&self, slot: usize) {
        {
            let mut g = self.inner.lock_ok();
            let inner = &mut *g;
            inner.lost_articles.store(true, Ordering::Relaxed);
            Self::mark_slot_lost(inner, slot);
        }
        // §156.3b: the pass does disk I/O - it runs with the extractor
        // lock RELEASED (this is the decode consumer thread, which does
        // its own pwrites anyway), taking it back only for the short
        // per-volume guard and budget settles.
        self.run_stalled_page_pass();
    }

    /// §156.1: sticky terminal-loss mark for one slot, propagated to
    /// wherever the hole can actually live. A chased slot marks its own
    /// frontier buffer. A mapped volume's hole lands in whichever inner
    /// files its group routed to the child, so every routed child slot
    /// is marked (the group IS the archive containing the hole; finer
    /// than that would need the article's byte offset, which the caller
    /// does not have). Routes created after the verdict pick the mark up
    /// at the routing site, chases attached after it at the attach site.
    pub(super) fn mark_slot_lost(inner: &mut Inner, slot: usize) {
        if slot >= inner.slots.len() || std::mem::replace(&mut inner.slots[slot].article_lost, true)
        {
            return;
        }
        if let Some(ch) = inner.slots[slot].chase.as_ref() {
            ch.buf.mark_lost();
        }
        if let Some(g) = inner.slots[slot]
            .group
            .as_ref()
            .and_then(|gk| inner.groups.get(gk))
            && let Some(child) = inner.child.clone()
        {
            for cs in g.routed.values().copied().collect::<Vec<_>>() {
                child.mark_child_slot_lost(cs);
            }
        }
    }

    /// [`Self::mark_slot_lost`] across a nesting boundary: the parent
    /// calls this holding its own lock (parent-then-child is the
    /// established order - the read planners do the same).
    pub(super) fn mark_child_slot_lost(&self, slot: usize) {
        let mut g = self.inner.lock_ok();
        Self::mark_slot_lost(&mut g, slot);
    }

    /// §156.1 wedge test for one chase: the LOWEST volume that is
    /// terminally wedged - marked lost, coverage stopped short - if
    /// any. The decode is strictly volume-ordered, so every byte beyond
    /// that volume's frontier is provably cold: the engine cannot reach
    /// it until the hole fills, wherever the engine currently is. That
    /// is the whole narrowing - a chase none of whose volumes hold an
    /// unfillable hole returns None here and never pages, however many
    /// terminal verdicts the rest of the job collects. Volumes BELOW
    /// the doomed one stay warm (the engine is still coming for them),
    /// which `page_wedged_chase` enforces with this index.
    pub(super) fn chase_first_doomed(ctl: &Arc<ChaseCtl>) -> Option<usize> {
        let vols: Vec<(usize, Arc<FrontierBuffer>)> = {
            let st = ctl.shared.lock_ok();
            st.vols.iter().map(|(&i, v)| (i, v.buf.clone())).collect()
        };
        vols.into_iter()
            .find(|(_, b)| b.terminally_wedged())
            .map(|(i, _)| i)
    }

    /// Coalesced wake for the stalled-chase pager: a detached thread
    /// that runs [`Self::run_stalled_page_pass`] until no wake is
    /// pending, then exits. Callers hold arbitrary locks - this is
    /// atomics and a spawn, nothing more. Reached weakly from the
    /// blocking readers so a cancelled extractor can drop; the thread's
    /// next upgrade fails and it exits.
    pub(super) fn wake_pager(self: &Arc<Self>) {
        self.pager_armed.store(true, Ordering::Release);
        if self.pager_active.swap(true, Ordering::AcqRel) {
            return;
        }
        let me = Arc::downgrade(self);
        let spawned = std::thread::Builder::new()
            .name("nzb-stall-pager".into())
            .spawn(move || {
                loop {
                    let Some(ex) = me.upgrade() else { return };
                    if !ex.pager_armed.swap(false, Ordering::AcqRel) {
                        ex.pager_active.store(false, Ordering::Release);
                        // A wake racing this shutdown saw `active` still
                        // set and returned; re-take the slot ourselves.
                        if ex.pager_armed.load(Ordering::Acquire)
                            && !ex.pager_active.swap(true, Ordering::AcqRel)
                        {
                            continue;
                        }
                        return;
                    }
                    ex.run_stalled_page_pass();
                }
            });
        if spawned.is_err() {
            self.pager_active.store(false, Ordering::Release);
        }
    }

    /// One stalled-chase paging pass over this extractor and its chain:
    /// page every chase that is terminally wedged (§156.1) while the
    /// shared budget sits past the [`chase_stall_spill`] window. Takes
    /// no lock across any I/O; safe to run concurrently with itself
    /// (`page_cold` commits re-verify, and a lost race just releases
    /// the orphaned scratch region).
    pub(super) fn run_stalled_page_pass(&self) {
        let (armed, chases, child) = {
            let inner = self.inner.lock_ok();
            (
                inner.holds_page_on && inner.lost_articles.load(Ordering::Relaxed),
                inner
                    .groups
                    .values()
                    .filter_map(|g| g.chase.clone())
                    .collect::<Vec<_>>(),
                inner.child.clone(),
            )
        };
        if armed {
            for ctl in chases {
                if let Some(doom) = Self::chase_first_doomed(&ctl) {
                    self.page_wedged_chase(&ctl, doom);
                }
            }
        }
        if let Some(c) = child {
            c.run_stalled_page_pass();
        }
    }

    /// The chase controller driving this slot's group, if any.
    fn rar_chase_of(inner: &Inner, slot: usize) -> Option<Arc<ChaseCtl>> {
        let key = inner.slots[slot].group.as_ref()?;
        inner.groups.get(key)?.chase.clone()
    }
    /// Drop-behind trim for a chased RAR set: release the bytes the
    /// engine has read past, writing them into each volume's own archive
    /// file on the way out.
    ///
    /// Same bargain as the 7z trim it copies, for the same reasons.
    /// Spilling into THAT file rather than a temp one is what keeps the
    /// demote path free: a demotion materializes the volume at exactly
    /// these offsets, so the spill is not a cost paid against demotion -
    /// it IS demotion, done early and in pieces. `fallback_slot` then
    /// writes only what is still in RAM and finds the rest on disk; a
    /// chase that SUCCEEDS deletes the partial file in `chase_finish`,
    /// because the payload came out the other way.
    ///
    /// The watermark is the engine's own promise (see
    /// `rars::rar50::extract_volume_sequence_to_with_progress`): nothing
    /// at or below it will be read again. Before the engine has said
    /// anything a volume's watermark is 0 and nothing trims, which is why
    /// there is no arming step here - unlike 7z, whose watermark is a raw
    /// reader position that starts at EOF.
    pub(super) fn rar_trim_set(&self, inner: &mut Inner, ctl: &Arc<ChaseCtl>) -> io::Result<()> {
        if !inner.rar_trim_on {
            return Ok(());
        }
        // Every volume, not just the one whose span breached the budget:
        // arrivals typically run on a LATER volume than the one the
        // engine is decoding, so the bytes worth releasing belong to a
        // different slot entirely.
        let volumes: Vec<(Arc<FrontierBuffer>, usize, u64)> = {
            let st = ctl.shared.lock_ok();
            let low = ctl.low_water.lock_ok();
            st.vols
                .iter()
                .map(|(index, vol)| {
                    (
                        vol.buf.clone(),
                        vol.slot,
                        low.get(index).copied().unwrap_or(0),
                    )
                })
                .collect()
        };
        for (buf, slot, watermark) in volumes {
            self.rar_trim_volume(inner, slot, &buf, watermark)?;
        }
        Ok(())
    }
    fn rar_trim_volume(
        &self,
        inner: &mut Inner,
        slot: usize,
        buf: &Arc<FrontierBuffer>,
        watermark: u64,
    ) -> io::Result<()> {
        if watermark == 0 {
            return Ok(());
        }
        // The slot must still be chased, and still be chasing THIS
        // buffer: a demote takes the chase out of the slot, and a
        // registration this ctl no longer owns is not ours to spill.
        match inner.slots[slot].chase.as_ref() {
            Some(ch) if Arc::ptr_eq(&ch.buf, buf) => {}
            _ => return Ok(()),
        }
        // Half the cap: bounds the drain's memmove to a constant amount
        // of work per arriving byte, since two trims cannot be closer
        // together than that many bytes of arrival. A volume the engine
        // is wholly past is released regardless of size - it is finished
        // with, and holding it buys nothing.
        let min_release = if watermark >= buf.total() {
            1
        } else {
            (inner.budget.cap() / 2) as u64
        };
        let Some((at, bytes)) = buf.trim_to(watermark, min_release) else {
            return Ok(());
        };
        inner.chase_trimmed += bytes.len() as u64;
        self.plain_span(inner, slot, at, &bytes)?;
        let now = buf.stored();
        let released = match inner.slots[slot].chase.as_mut() {
            Some(ch) => {
                let delta = ch.charged.saturating_sub(now);
                ch.charged = now;
                delta
            }
            None => 0,
        };
        inner.budget.sub(released);
        Ok(())
    }
    /// Page a WEDGED RAR chase's cold frontier bytes to the holds
    /// scratch, until the shared budget sits back at the
    /// [`chase_stall_spill`] window. Volumes walk in DESCENDING index -
    /// the farthest-ahead arrivals are the coldest - and within one, the
    /// buffer pages parked spans (never engine-readable until their gap
    /// fills) before anything else. `doom` (the lowest volume holding
    /// an unfillable hole, from [`Self::chase_first_doomed`]) is the
    /// coldness boundary: contiguous runs page only beyond it, volumes
    /// below it are skipped wholesale unless the engine is wholly past
    /// them. Budget bookkeeping is the drop-behind trim's exact
    /// contract: re-read `stored()` and release the delta. A scratch
    /// refusal leaves the rest in RAM, where the cap arbiter stands
    /// exactly as before this spill existed.
    ///
    /// §156.3b: runs with NO caller-held locks. The extractor lock is
    /// taken per volume for the guard and the budget settle only - the
    /// paging I/O in between holds neither it nor (see `page_cold`) the
    /// buffer's own state lock. The predecessor held the extractor lock
    /// across the whole pass, disk writes included, so a pool teardown
    /// sealing thousands of ids stalled every slot's deliveries behind
    /// scratch I/O.
    fn page_wedged_chase(&self, ctl: &Arc<ChaseCtl>, doom: usize) {
        let (budget, scratch) = {
            let inner = self.inner.lock_ok();
            (inner.budget.clone(), inner.scratch.clone())
        };
        // Auto ceiling: 4x the RAM cap, resolved per pass so a later
        // set_holds_cap is respected and an explicit ceiling wins.
        let cap = match scratch.cap.load(Ordering::Relaxed) {
            0 => 4 * budget.cap() as u64,
            c => c,
        };
        let window = chase_stall_spill(budget.cap());
        // The coldness boundary is `doom`, the lowest volume with an
        // unfillable hole (§156.1): everything beyond its frontier is
        // unreachable until the hole fills. Volumes below it are warm -
        // the engine is still coming for them - and stay untouched,
        // except ones the engine is wholly PAST, whose leftovers page
        // like any cold bytes. Inside the doomed volume only the parked
        // pile beyond its hole pages, never its contiguous run (the
        // engine will still decode up to the hole).
        let volumes: Vec<(Arc<FrontierBuffer>, usize, bool)> = {
            let st = ctl.shared.lock_ok();
            let low = ctl.low_water.lock_ok();
            st.vols
                .iter()
                .filter_map(|(&index, vol)| {
                    let past = low.get(&index) == Some(&u64::MAX);
                    (index >= doom || past)
                        .then(|| (vol.buf.clone(), vol.slot, index > doom || past))
                })
                .collect()
        };
        let mut paged_any = false;
        for (buf, slot, cold_data) in volumes.into_iter().rev() {
            let need = budget.len().saturating_sub(window);
            if need == 0 {
                break;
            }
            // The slot must still be chasing THIS buffer (same guard as
            // the trim): a demote takes the chase out of the slot.
            {
                let inner = self.inner.lock_ok();
                match inner.slots[slot].chase.as_ref() {
                    Some(ch) if Arc::ptr_eq(&ch.buf, &buf) => {}
                    _ => continue,
                }
            }
            if buf.page_cold(cap, need, cold_data) == 0 {
                continue;
            }
            paged_any = true;
            // Settle only while the slot still owns this buffer: a
            // demote in the window has already released its full charge
            // and drained the spans, so touching it again would
            // double-release.
            let mut g = self.inner.lock_ok();
            let inner = &mut *g;
            if let Some(ch) = inner.slots[slot].chase.as_mut()
                && Arc::ptr_eq(&ch.buf, &buf)
            {
                let now = buf.stored();
                let delta = ch.charged.saturating_sub(now);
                ch.charged = now;
                budget.sub(delta);
            }
        }
        if paged_any && !scratch.announced.swap(true, Ordering::Relaxed) {
            println!("🧊 archive decode blocked on missing articles - paging to scratch");
        }
    }

    /// Give up on whatever CONTAINER this slot belongs to.
    ///
    /// A 7z slot is one part of a container, and a byte split has no
    /// useful half - so a part failing is the container failing, and the
    /// demote has to take every member with it. Routing these two
    /// forfeits through the single-slot path instead was a silent
    /// data-loss bug, not just untidy: `fallback_slot` drains the
    /// container's WHOLE sink list (every member shares one ctl), so the
    /// payload output was deleted while the other members stayed in
    /// `SevenZ` mode with the set un-aborted. The worker then read on
    /// from parts nobody had touched, wrote into a slot that had become
    /// `Discard` (which swallows writes), and returned `Ok` - at which
    /// point `sevenz_finish` took the survivors' success path, dropped
    /// their retained bytes and unlinked their spilled prefixes. Output
    /// directory: one orphaned `.7z.002`, no payload, exit 0.
    pub(super) fn chase_forfeit(
        &self,
        inner: &mut Inner,
        slot: usize,
        reason: &str,
    ) -> io::Result<()> {
        match inner.slots[slot].sevenz.clone() {
            Some(ctl) => self.sevenz_fallback_set(inner, &ctl, reason),
            None => self.fallback_slot_or_group(inner, slot, reason),
        }
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
        // Drop-behind: the engine says how much of each volume it will
        // never read again, and routing releases those bytes on budget
        // pressure (`rar_trim_set`). Recording only - the trim itself
        // needs the extractor lock, which this thread must never take
        // while a blocking volume read could be holding a buffer.
        let mark = |index: usize, offset: u64| {
            let mut low = ctl.low_water.lock_ok();
            let at = low.entry(index).or_insert(0);
            *at = (*at).max(offset);
        };
        let result = if ctl.v4 {
            rars::rar15_40::extract_volume_sequence_to_with_progress(
                |index| Self::chase_next_volume_v4(&ctl, index, pw.as_deref()),
                crate::mem::rar_read_options(pw.as_deref()),
                |meta| Self::chase_open_sink(&me, &ctl, &key, &meta.name, meta.is_directory),
                mark,
            )
        } else {
            rars::rar50::extract_volume_sequence_to_with_progress(
                |index| Self::chase_next_volume(&ctl, index, pw.as_deref()),
                crate::mem::rar_read_options(pw.as_deref()),
                |meta| Self::chase_open_sink(&me, &ctl, &key, &meta.name, meta.is_directory),
                mark,
            )
        };
        let mut st = ctl.shared.lock_ok();
        st.outcome = Some(result.map_err(|e| e.to_string()));
        drop(st);
        ctl.cv.notify_all();
    }
    /// Natural 0-based volume index from a RAR4 volume NAME. Old-style
    /// naming is already 0-based (`.rar` then `.r00`, `.r01`, rolling to
    /// `.s00`…); `.partNN.rar` and bare-numeric `.001` naming start at 1,
    /// so those shift down by one.
    fn v4_vol_index(name: &str) -> usize {
        let lower = name.to_ascii_lowercase();
        if let Some(p) = lower.rfind(".part") {
            let tail = &lower[p + 5..];
            let digits: String = tail.chars().take_while(|c| c.is_ascii_digit()).collect();
            if let Ok(n) = digits.parse::<u64>() {
                return (n.saturating_sub(1)) as usize;
            }
        }
        if let Some(p) = lower.rfind('.') {
            let tail = &lower[p + 1..];
            if tail.len() >= 2
                && tail.bytes().all(|c| c.is_ascii_digit())
                && let Ok(n) = tail.parse::<u64>()
            {
                return (n.saturating_sub(1)) as usize;
            }
        }
        crate::extract::vol_sort_key(name).0 as usize
    }
    /// [`Self::chase_next_volume`], RAR4 family: same wait, the
    /// `rar15_40` blocking parse.
    fn chase_next_volume_v4(
        ctl: &ChaseCtl,
        index: usize,
        password: Option<&[u8]>,
    ) -> rars::Result<Option<rars::rar15_40::Archive>> {
        let (buf, len) = {
            let mut st = ctl.shared.lock_ok();
            loop {
                if st.aborted {
                    return Err(io::Error::other("chase aborted").into());
                }
                if let Some(vol) = st.vols.get(&index) {
                    break (vol.buf.clone(), vol.size);
                }
                if st.no_more {
                    return Ok(None);
                }
                st = ctl.cv.wait(st).unwrap();
            }
        };
        let archive = rars::rar15_40::Archive::parse_stream(
            buf as Arc<dyn rars::BlockingRangeSource>,
            len,
            crate::mem::rar_read_options(password),
        )?;
        {
            let mut sizes = ctl.sizes.lock_ok();
            for f in archive.files() {
                sizes
                    .entry(String::from_utf8_lossy(&f.name).into_owned())
                    .or_insert(f.unp_size);
            }
        }
        Ok(Some(archive))
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
            let mut st = ctl.shared.lock_ok();
            loop {
                if st.aborted {
                    return Err(io::Error::other("chase aborted").into());
                }
                if let Some(vol) = st.vols.get(&index) {
                    break (vol.buf.clone(), vol.size);
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
            crate::mem::rar_read_options(password),
        )?;
        // Record member sizes: the engine's open callback carries no
        // size, the parsed headers do (split parts repeat the total -
        // first sighting wins).
        {
            let mut sizes = ctl.sizes.lock_ok();
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
        member_name: &[u8],
        is_directory: bool,
    ) -> rars::Result<Box<dyn io::Write>> {
        if is_directory {
            return Ok(Box::new(io::sink()));
        }
        let Some(ex) = me.upgrade() else {
            return Err(io::Error::other("extractor dropped").into());
        };
        let name = String::from_utf8_lossy(member_name).into_owned();
        let size = ctl.sizes.lock_ok().get(&name).copied().unwrap_or(0);
        // Liveness check, slot allocation and registration under ONE
        // routing-lock hold: a demotion (chase_teardown drains
        // sink_slots under the same lock) either runs before this - the
        // fallback flag bounces us - or after, and then it sees the slot
        // we just registered. Split apart, a slot allocated after the
        // drain would leak a partial grandchild output.
        let (child, slot) = {
            let mut g = ex.inner.lock_ok();
            let inner = &mut *g;
            if inner.groups.get(key).is_none_or(|g| g.fallback) {
                return Err(io::Error::other("chase demoted").into());
            }
            let child = ex.ensure_child(inner);
            let slot = child.alloc_slot();
            ctl.sink_slots.lock_ok().push(slot);
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
    pub(super) fn chase_teardown(&self, inner: &mut Inner, ctl: &Arc<ChaseCtl>, reason: &str) {
        ctl.abort(reason);
        if let Some(c) = inner.child.clone() {
            for cs in ctl.sink_slots.lock_ok().drain(..) {
                c.abandon_slot(cs);
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
    pub(super) fn chase_finish(&self) -> io::Result<()> {
        let chases: Vec<(String, Arc<ChaseCtl>)> = {
            let inner = self.inner.lock_ok();
            inner
                .groups
                .iter()
                .filter_map(|(k, g)| g.chase.clone().map(|c| (k.clone(), c)))
                .collect()
        };
        for (key, ctl) in chases {
            {
                let mut st = ctl.shared.lock_ok();
                st.no_more = true;
                for vol in st.vols.values() {
                    if !vol.buf.is_complete() {
                        vol.buf.abort("bytes never arrived");
                    }
                }
            }
            ctl.cv.notify_all();
            let handle = ctl.worker.lock_ok().take();
            if let Some(h) = handle {
                // A worker panic surfaces as a join error and leaves no
                // outcome - handled below as a demotion, never a
                // propagated panic.
                let _ = h.join();
            }
            let outcome = ctl.shared.lock_ok().outcome.clone();
            let mut g = self.inner.lock_ok();
            let inner = &mut *g;
            if !inner.groups.contains_key(&key) {
                continue;
            }
            let already_fallback = inner.groups[&key].fallback;
            match &outcome {
                Some(Ok(())) if !already_fallback => {
                    for si in inner.groups[&key].slots.clone() {
                        let Some(ch) = inner.slots[si].chase.take() else {
                            // Not a chased volume. A group can pick up a
                            // MAPPED member by name (`rar_span`'s group
                            // assignment), and that slot's file, if it has
                            // one, is not ours to delete.
                            continue;
                        };
                        inner.budget.sub(ch.charged);
                        // A drop-behind trim may have spilled a prefix
                        // into this volume's own file on the way past.
                        // The payload came out the other way, so that
                        // file is a truncated volume nobody wants -
                        // leaving it beside the payload would look like a
                        // second, broken download (and would break the
                        // one-pass promise that no archive ever lands on
                        // disk). Same cleanup `sevenz_finish` does.
                        Self::drop_slot_file(inner, si);
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
}

/// Which container format a `SlotMode::SevenZ` chase is actually
/// driving. The chase machinery (frontier buffers, the one-part/N-part
/// set, tail promote, trim, demote, finish joining) is format-agnostic;
/// only the worker parsing the container differs - so zip rides the 7z
/// mode rather than re-teaching a new mode to every `is_mapped` seam
/// (the six TODO-37 findings all lived in those seams). This tag is
/// what keeps the user-facing words honest: the demote prefix, the
/// badge kind and the finish diagnostics read it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum ChaseFormat {
    SevenZ,
    Zip,
}

impl ChaseFormat {
    pub(super) fn noun(self) -> &'static str {
        match self {
            ChaseFormat::SevenZ => "7z",
            ChaseFormat::Zip => "zip",
        }
    }
}

/// Per-slot chase attachment: the slot's volume bytes live here (instead
/// of holds / a writer) while the chase runs. `charged` is what this
/// buffer currently holds against the shared budget.
pub(super) struct ChaseSlot {
    pub(super) buf: Arc<FrontierBuffer>,
    pub(super) charged: usize,
}

/// One chase = one compressed inner archive (one group): its registered
/// volume buffers, the worker driving the streaming decode, and the
/// bookkeeping the demote path needs to unwind cleanly.
pub(super) struct ChaseCtl {
    pub(super) shared: Mutex<ChaseShared>,
    pub(super) cv: Condvar,
    /// Drop-behind watermarks published by the RAR engine: volume index
    /// -> the lowest offset it may still ask for, `u64::MAX` once it is
    /// finished with the volume entirely. Its own lock because the engine
    /// writes it from the decode thread while routing reads it under the
    /// extractor lock; taking `shared` for that would put the extractor
    /// lock ahead of the one every blocking volume wait holds.
    pub(super) low_water: Mutex<BTreeMap<usize, u64>>,
    pub(super) worker: Mutex<Option<std::thread::JoinHandle<()>>>,
    /// Child-extractor slots the sink opened for extracted members -
    /// abandoned (partial outputs deleted) if the chase demotes.
    pub(super) sink_slots: Mutex<Vec<usize>>,
    /// Member name -> unpacked size, recorded as each volume parses (the
    /// engine's open callback doesn't carry the size, the headers do).
    pub(super) sizes: Mutex<HashMap<String, u64>>,
    /// RAR family of this set: `true` drives the `rar15_40` engine, `false`
    /// the `rar50` one. Fixed at attach; a slot of the other family never
    /// joins (mixed families are not a set).
    pub(super) v4: bool,
}

/// One registered volume of a chased set.
pub(super) struct ChaseVol {
    pub(super) buf: Arc<FrontierBuffer>,
    /// Declared volume size (the level-N entry's unpacked size).
    pub(super) size: u64,
    /// The slot holding this volume - the drop-behind trim spills into
    /// its archive file, and adjusts its budget charge.
    pub(super) slot: usize,
}

#[derive(Default)]
pub(super) struct ChaseShared {
    /// Volume index -> its buffer, size and slot.
    pub(super) vols: BTreeMap<usize, ChaseVol>,
    /// Download over: an index past the registered set means "no more
    /// volumes" rather than "not arrived yet".
    pub(super) no_more: bool,
    /// Demoted/cancelled: the worker unblocks with an error.
    pub(super) aborted: bool,
    /// The worker's exit status, set exactly once before it returns.
    pub(super) outcome: Option<Result<(), String>>,
}

impl ChaseCtl {
    pub(super) fn new(v4: bool) -> ChaseCtl {
        ChaseCtl {
            shared: Mutex::new(ChaseShared::default()),
            cv: Condvar::new(),
            low_water: Mutex::new(BTreeMap::new()),
            worker: Mutex::new(None),
            sink_slots: Mutex::new(Vec::new()),
            sizes: Mutex::new(HashMap::new()),
            v4,
        }
    }

    /// Stop the worker: abort every registered buffer and flag the state
    /// so a wait for an unregistered volume wakes with an error. Join
    /// happens later, off-lock (finish / drop).
    pub(super) fn abort(&self, reason: &str) {
        let mut st = self.shared.lock_ok();
        st.aborted = true;
        for vol in st.vols.values() {
            vol.buf.abort(reason);
        }
        drop(st);
        self.cv.notify_all();
    }
}

/// The chase's routing-seam sink: extracted member bytes stream into a
/// slot of the nested child extractor, whose offset-0 sniff classifies
/// them - a store RAR below the compressed layer keeps streaming, plain
/// payloads land as ordinary files. Writes are sequential from 0.
pub(super) struct ChaseSink {
    pub(super) child: Arc<Extractor>,
    pub(super) slot: usize,
    pub(super) name: String,
    pub(super) size: u64,
    pub(super) pos: u64,
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

#[cfg(test)]
#[path = "chase_tests.rs"]
mod chase_tests;

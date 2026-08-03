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
        ));
        // Seed with everything already seen. The header stash MOVES in
        // (like the holds): the buffer keeps every byte from offset 0
        // for the life of the chase - reads never consume it, and a
        // demotion materializes the volume straight out of it - so a
        // second RAM copy would only double-charge the shared budget
        // that the stash is now billed to. Nothing reads `header_spans`
        // outside `SlotMode::Rar`, which this slot just left.
        let mut stored = 0usize;
        let headers = std::mem::take(&mut inner.slots[slot].header_spans);
        for (off, span) in headers {
            let bytes = Self::reclaim_span(inner, span)?;
            stored = buf.write_span(off, &bytes);
        }
        let holds = std::mem::take(&mut inner.slots[slot].holds);
        inner.slots[slot].pre_bytes = 0;
        for (off, span) in holds {
            let bytes = Self::reclaim_span(inner, span)?;
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
mod tests {
    use super::*;
    use crate::rar::fixtures;

    use crate::extract::testutil::*;

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

    /// §94 B: a GATED chase parks until the verified watermark covers
    /// what it wants to decode, then completes byte-exact. The gate is
    /// driven by hand here exactly as the verifier drives it (engage at
    /// claim, advance as blocks verify) - the extractor-side contract is
    /// what this pins: gated buffers wait, wake on advance, and the
    /// result is indistinguishable from an ungated run.
    #[test]
    fn gated_chase_waits_for_verification_then_completes() {
        let dir = tmpdir("chase-gate");
        let f = payload(300_000, 96);
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
        let gate = crate::live::VerifyGate::new(1);
        ex.set_verify_gate(gate.clone());
        gate.engage(0); // the verifier claimed slot 0
        feed(&ex, 0, "v.rar", &outer, 7000, 9);
        // The chase worker is parked at watermark 0 with every byte
        // already in the frontier. Release it the way verification
        // does: an advance to the volume midpoint, then full.
        let total = outer.len() as u64;
        let g = gate.clone();
        let t = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(120));
            g.advance(0, total / 2);
            std::thread::sleep(std::time::Duration::from_millis(120));
            g.advance(0, u64::MAX);
        });
        let rep = ex.finish().unwrap();
        t.join().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("F.bin")).unwrap(), f);
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

    /// A RAR4 inner whose "compressed" member is a lying method byte over
    /// store bytes: the chase attaches (RAR4 chases now), the decode
    /// fails, and the group demotes to a byte-exact materialized level-1
    /// archive - the job still succeeds with today's output.
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
        let outer = fixtures::rar5_volume(&[("inner.rar", v4.len() as u64, &v4, false, false)]);
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
        assert!(
            inner_arch.len() > 900_000,
            "packed too small: {}",
            inner_arch.len()
        );
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
                ex.write(
                    slot,
                    &format!("dummy{slot}.bin"),
                    8_000_000,
                    64_000 + i * 65_000,
                    &junk,
                )
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

    /// Three junk slots holding the shared holds budget down to about
    /// `headroom` bytes of slack, without any of them crossing the
    /// per-slot unclassified spill (a quarter of the cap, floored at
    /// 4 MB) that would send them to disk instead.
    fn eat_budget_to(ex: &Extractor, first_slot: usize, headroom: usize, seed: u8) {
        const CAP: usize = 8 << 20; // set_holds_cap(1) floors here
        const CHUNK: usize = 65_000;
        let want = CAP.saturating_sub(headroom);
        let per_slot = want.div_ceil(3);
        let chunks = per_slot / CHUNK;
        assert!(
            per_slot < 4 << 20,
            "a junk slot would spill instead of holding: {per_slot}"
        );
        let junk = payload(CHUNK, seed);
        for slot in first_slot..first_slot + 3 {
            for i in 0..chunks as u64 {
                ex.write(
                    slot,
                    &format!("dummy{slot}.bin"),
                    8_000_000,
                    64_000 + i * CHUNK as u64,
                    &junk,
                )
                .unwrap();
            }
        }
    }

    /// The posted compressed set the drop-behind tests share: payload,
    /// volumes and volume names.
    ///
    /// The member has to clear 4 MiB - `should_stream_decode`'s bar, and
    /// therefore the incremental split path's - and encoding it is slow
    /// enough (tens of seconds in a debug build) that the three tests
    /// build it once between them.
    fn chase_volume_set() -> &'static (Vec<u8>, Vec<Vec<u8>>, Vec<String>) {
        static SET: std::sync::OnceLock<(Vec<u8>, Vec<Vec<u8>>, Vec<String>)> =
            std::sync::OnceLock::new();
        SET.get_or_init(|| {
            let f = noisy(5 << 20, 140);
            let vols = rars_compressed_volumes("F.bin", &f, 200_000);
            assert!(vols.len() >= 8, "want many volumes, got {}", vols.len());
            for v in &vols {
                assert_not_store(v);
            }
            let names = (0..vols.len())
                .map(|i| format!("release.part{}.rar", i + 1))
                .collect();
            (f, vols, names)
        })
    }

    /// THE test that defines the drop-behind: a posted compressed set
    /// whose retained bytes are several times the budget headroom chases
    /// all the way to completion, byte-exact, with nothing left on disk -
    /// because the engine keeps saying which volumes it is finished with
    /// and routing keeps releasing them into the volumes' own files.
    ///
    /// Before the incremental split decode this shape could only demote:
    /// the split member decoded at its FINISH fragment, so every volume
    /// had to be retained until the last one landed.
    #[test]
    fn chase_over_cap_multi_volume_set_trims_and_streams() {
        let dir = tmpdir("chase-trim-stream");
        let (f, vols, names) = chase_volume_set();
        let packed: usize = vols.iter().map(|v| v.len()).sum();
        let headroom = 3 * vols[0].len();
        assert!(
            packed > 4 * headroom,
            "the set must be well past the headroom or the test proves nothing: \
             {packed} vs {headroom}"
        );

        let ex = Arc::new(Extractor::new(&dir, vols.len() + 3, true));
        ex.anchor();
        ex.set_holds_cap(1); // floors at 8 MB
        eat_budget_to(&ex, vols.len(), headroom, 141);
        let trimmed = feed_chase_volumes_paced(&ex, names, vols, 7000, 2);
        let rep = ex.finish().unwrap();

        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert!(
            trimmed > 0,
            "nothing was ever trimmed - the test proved nothing"
        );
        assert_eq!(&std::fs::read(dir.join("F.bin")).unwrap(), f);
        // The payload plus the budget-eating junk slots, and nothing
        // else: no volume, and no spilled prefix of one.
        let mut want = vec!["F.bin".to_string()];
        want.extend((0..3).map(|i| format!("dummy{}.bin", vols.len() + i)));
        want.sort();
        assert_eq!(
            dir_files(&dir),
            want,
            "a spilled volume survived the successful chase"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The same set with the trim gated OFF demotes, exactly as it did
    /// before drop-behind existed. Two things at once: the escape hatch
    /// works, and the test above is measuring the trim rather than a
    /// budget that was never tight.
    #[test]
    fn chase_over_cap_multi_volume_set_demotes_with_the_trim_off() {
        assert!(rar_trim_env_off_value(Some("1")));
        assert!(!rar_trim_env_off_value(Some("0")));
        assert!(!rar_trim_env_off_value(None));

        let dir = tmpdir("chase-trim-off");
        let (_, vols, names) = chase_volume_set();
        let headroom = 3 * vols[0].len();

        let ex = Arc::new(Extractor::new(&dir, vols.len() + 3, true));
        ex.anchor();
        ex.set_holds_cap(1);
        ex.set_rar_trim(false);
        eat_budget_to(&ex, vols.len(), headroom, 143);
        for (index, vol) in vols.iter().enumerate() {
            feed(&ex, index, &names[index], vol, 7000, 33 + index as u64);
        }
        let rep = ex.finish().unwrap();

        assert!(
            rep.fallbacks
                .iter()
                .any(|(_, w)| w.contains("held-bytes cap: chase memory")),
            "{:?}",
            rep.fallbacks
        );
        assert_eq!(ex.chase_trimmed_bytes(), 0, "the gate did not hold");
        // Every volume materialized COMPLETE, ready for the disk pass.
        for (index, vol) in vols.iter().enumerate() {
            assert_eq!(
                &std::fs::read(dir.join(&names[index])).unwrap(),
                vol,
                "{}",
                names[index]
            );
        }
        assert!(!dir.join("F.bin").exists(), "partial chase output survived");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The demote path stays free ACROSS a trim, and the PAR2 case the
    /// plan calls out: a repair rewrite landing BELOW the trim point.
    ///
    /// Those bytes are on disk, not in the buffer, so nothing can compare
    /// them - the buffer takes the rewrite as a forfeit, the file takes
    /// the corrected bytes, and the disk ladder re-extracts. Trimming and
    /// demote-to-volumes are not exclusive, because the trim spills into
    /// the volume's OWN file: what a demotion would have written, written
    /// early. So the materialized volume is byte-identical to what was
    /// posted, trimmed prefix and all.
    #[test]
    fn chase_patch_below_the_trim_point_forfeits_and_materializes_repaired() {
        let dir = tmpdir("chase-trim-patch");
        let (_, vols, names) = chase_volume_set();
        let headroom = 3 * vols[0].len();

        let ex = Arc::new(Extractor::new(&dir, vols.len() + 3, true));
        ex.anchor();
        ex.set_holds_cap(1);
        eat_budget_to(&ex, vols.len(), headroom, 145);
        // Feed every volume but the last, so the chase is still live
        // (and trimmed) when the rewrite lands.
        let live = vols.len() - 1;
        let trimmed = feed_chase_volumes_paced(&ex, names, &vols[..live], 7000, 2);
        assert!(trimmed > 0, "nothing was trimmed - the test proved nothing");
        let base = ex.inner.lock_ok().slots[0]
            .chase
            .as_ref()
            .map_or(0, |ch| ch.buf.base());
        assert!(base > 0, "volume 0 was never trimmed: base {base}");

        // A repair rewriting a range the chase consumed AND released:
        // different bytes, wholly below the trim point.
        let mut stale = vols[0][..(base as usize).min(vols[0].len())].to_vec();
        for b in stale.iter_mut() {
            *b ^= 0xff;
        }
        ex.write(0, &names[0], vols[0].len() as u64, 0, &stale)
            .unwrap();
        // ...then the truth, and the last volume.
        ex.write(
            0,
            &names[0],
            vols[0].len() as u64,
            0,
            &vols[0][..stale.len()],
        )
        .unwrap();
        feed(&ex, live, &names[live], &vols[live], 7000, 99);

        let rep = ex.finish().unwrap();
        assert!(
            rep.fallbacks.iter().any(|(_, w)| w.contains("rewrote")),
            "a rewrite over trimmed bytes must forfeit, and say why: {:?}",
            rep.fallbacks
        );
        // Byte-exact against what was posted: the spilled prefix, the
        // bytes still in RAM, and the corrected rewrite on top.
        for (index, vol) in vols.iter().enumerate() {
            assert_eq!(
                &std::fs::read(dir.join(&names[index])).unwrap(),
                vol,
                "{}",
                names[index]
            );
        }
        assert!(!dir.join("F.bin").exists(), "partial chase output survived");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The conflict forfeit, end to end through `write` - the trigger the
    /// buffer-level tests do not exercise.
    ///
    /// The story is the one the guard exists for: an article arrives whose
    /// own CRC passes but whose bytes are wrong, the chase decodes them,
    /// and only then does PAR2 rebuild the range and deliver a DIFFERING
    /// copy. Carrying on would ship what was decoded from the stale bytes
    /// with every checksum on the path still passing, so the rewrite must
    /// forfeit the chase. The retained record ends up holding the repaired
    /// bytes, so the materialized volume is byte-exact and the disk pass
    /// re-extracts it.
    #[test]
    fn chase_differing_rewrite_forfeits_and_materializes_repaired() {
        let dir = tmpdir("chase-rewrite");
        let f = noisy(2_400_000, 121);
        let inner_arch = rars_compressed_volume(&[("F.bin", &f)]);
        assert_not_store(&inner_arch);
        let outer = fixtures::rar5_volume(&[(
            "inner.rar",
            inner_arch.len() as u64,
            &inner_arch,
            false,
            false,
        )]);
        // Well past the outer headers, so the damaged chunk lands in the
        // inner payload the chase is decoding, not in the mapping.
        const BAD: usize = 10;
        const STEP: usize = 50_000;
        assert!(
            outer.len() > (BAD + 4) * STEP,
            "outer too small: {}",
            outer.len()
        );

        let ex = Extractor::new(&dir, 1, true);
        for (i, chunk) in outer.chunks(STEP).enumerate() {
            let off = (i * STEP) as u64;
            if i == BAD {
                // Passes its own CRC, still wrong.
                let mut stale = chunk.to_vec();
                for b in stale.iter_mut() {
                    *b ^= 0xff;
                }
                ex.write(0, "v.rar", outer.len() as u64, off, &stale)
                    .unwrap();
                continue;
            }
            ex.write(0, "v.rar", outer.len() as u64, off, chunk)
                .unwrap();
        }
        // The repair lands after the chase has already consumed the range.
        let fixed = &outer[BAD * STEP..(BAD + 1) * STEP];
        ex.write(0, "v.rar", outer.len() as u64, (BAD * STEP) as u64, fixed)
            .unwrap();

        let rep = ex.finish().unwrap();
        let reasons: Vec<&str> = rep.fallbacks.iter().map(|(_, w)| w.as_str()).collect();
        assert!(
            reasons.iter().any(|w| w.contains("rewrote")),
            "the forfeit must be reported, and say why: {reasons:?}"
        );
        // Byte-exact against the REPAIRED archive: the later delivery won,
        // so nothing decoded from the stale copy survived into the output.
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
        assert!(
            vols.len() >= 3,
            "want a real multi-volume set, got {}",
            vols.len()
        );
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

    /// A store outer wrapping a COMPRESSED RAR4 (RAR 2.9/3.x) inner: the
    /// chase engages through the `rar15_40` engine, the payload lands
    /// byte-identical, and neither the outer volume nor the inner archive
    /// ever exists on disk.
    #[test]
    fn chase_compressed_rar4_inner_one_pass() {
        let dir = tmpdir("chase-v4");
        let f = payload(300_000, 191);
        let inner_arch = rars_v4_compressed_volume(&[("F.bin", &f)]);
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
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("F.bin")).unwrap(), f);
        assert_eq!(dir_files(&dir), vec!["F.bin".to_string()]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A compressed RAR4 member split across volumes, both naming
    /// schemes: `.partNN.rar` (1-based, shifts down) and old-style
    /// `.rar`/`.r00`/`.r01` (already 0-based) - the volume index comes
    /// from the NAME for RAR4, so both must sequence correctly, forward
    /// and reverse arrival.
    #[test]
    fn chase_multi_volume_compressed_rar4_inner() {
        let f = noisy(300_000, 198);
        let vols = rars_v4_compressed_volumes("F.bin", &f, 50_000);
        assert!(
            vols.len() >= 3,
            "want a real multi-volume set, got {}",
            vols.len()
        );
        for v in &vols {
            assert_not_store(v);
        }
        let naming: [Box<dyn Fn(usize) -> String>; 2] = [
            Box::new(|i| format!("inner.part{}.rar", i + 1)),
            Box::new(|i| {
                if i == 0 {
                    "inner.rar".to_string()
                } else {
                    format!("inner.r{:02}", i - 1)
                }
            }),
        ];
        for (scheme, name_of) in naming.iter().enumerate() {
            let pieces: Vec<(String, &Vec<u8>)> = vols
                .iter()
                .enumerate()
                .map(|(i, v)| (name_of(i), v))
                .collect();
            let outer_entries: Vec<(&str, u64, &[u8], bool, bool)> = pieces
                .iter()
                .map(|(n, v)| (n.as_str(), v.len() as u64, v.as_slice(), false, false))
                .collect();
            let outer = fixtures::rar5_volume(&outer_entries);
            for (t, rev) in [false, true].iter().enumerate() {
                let dir = tmpdir(&format!("chase-v4mv{scheme}{t}"));
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
                assert!(
                    rep.fallbacks.is_empty(),
                    "scheme={scheme} rev={rev}: {:?}",
                    rep.fallbacks
                );
                assert_eq!(
                    std::fs::read(dir.join("F.bin")).unwrap(),
                    f,
                    "scheme={scheme} rev={rev}"
                );
                assert_eq!(
                    dir_files(&dir),
                    vec!["F.bin".to_string()],
                    "scheme={scheme} rev={rev}"
                );
                std::fs::remove_dir_all(&dir).unwrap();
            }
        }
    }

    /// Encrypted (-p) compressed RAR4, split across volumes: the chase
    /// decrypts through the rar15_40 engine's own sequential cipher (a
    /// salt per member, key derived once per member on the WORKER thread,
    /// never in the mapper - the §RAR4 KDF-DoS rule), payload byte-exact,
    /// one pass.
    #[test]
    fn chase_encrypted_compressed_rar4_inner_one_pass() {
        let f = noisy(300_000, 199);
        let vols = rars_v4_encrypted_volumes("F.bin", &f, 60_000, "chasepw", false);
        assert!(vols.len() >= 2, "want a split set, got {}", vols.len());
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
        let dir = tmpdir("chase-v4enc");
        let ex = Extractor::new(&dir, 1, true);
        ex.set_password("chasepw");
        feed(&ex, 0, "v.rar", &outer, 7000, 13);
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("F.bin")).unwrap(), f);
        assert_eq!(dir_files(&dir), vec!["F.bin".to_string()]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The -hp shape: RAR4 with ENCRYPTED HEADERS. The mapper needs the
    /// password to enumerate entries at all; past that the chase drives
    /// the same engine (parse_stream decrypts headers per block).
    #[test]
    fn chase_header_encrypted_compressed_rar4_inner() {
        let f = noisy(200_000, 201);
        let vols = rars_v4_encrypted_volumes("F.bin", &f, 80_000, "hppw", true);
        // A password-less mapper must see nothing but EncryptedHeaders -
        // that both proves the -hp shape and stands in for
        // assert_not_store, which cannot read a method byte it cannot
        // decrypt.
        for v in &vols {
            let mut m = crate::rar::VolumeMapper::new(v.len() as u64);
            m.feed(0, v);
            assert_eq!(m.blocker, Some(crate::rar::MapBlocker::EncryptedHeaders));
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
        let dir = tmpdir("chase-v4hp");
        let ex = Extractor::new(&dir, 1, true);
        ex.set_password("hppw");
        feed(&ex, 0, "v.rar", &outer, 7000, 17);
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("F.bin")).unwrap(), f);
        assert_eq!(dir_files(&dir), vec!["F.bin".to_string()]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Encrypted RAR4 with NO password available: the chase must not
    /// attach (nothing can decode anywhere) - the set demotes to
    /// byte-exact materialized volumes, today's output.
    #[test]
    fn chase_encrypted_rar4_without_password_demotes() {
        let f = noisy(120_000, 203);
        let vol = rars_v4_encrypted_volume("F.bin", &f, "nopw");
        let outer =
            fixtures::rar5_volume(&[("inner.rar", vol.len() as u64, vol.as_slice(), false, false)]);
        let dir = tmpdir("chase-v4enc-nopw");
        let ex = Extractor::new(&dir, 1, true);
        feed(&ex, 0, "v.rar", &outer, 5000, 19);
        let rep = ex.finish().unwrap();
        assert!(
            rep.fallbacks
                .iter()
                .any(|(_, w)| w.starts_with("nested fallback:")),
            "{:?}",
            rep.fallbacks
        );
        assert_eq!(std::fs::read(dir.join("inner.rar")).unwrap(), vol);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// TOP-LEVEL chase (the RAR analogue of TODO 37 step 1): a POSTED
    /// compressed RAR5 - no store wrapper - chases at depth 0, its
    /// payload promotes to the root output, and neither the volume nor
    /// any intermediate archive ever exists on disk. Three arrival
    /// orders, mirroring the 7z twin.
    #[test]
    fn top_level_compressed_rar_chases_one_pass() {
        let f = payload(300_000, 131);
        let arch = rars_compressed_volume(&[("F.bin", &f)]);
        assert_not_store(&arch);
        let art = 7000usize;
        let n_arts = arch.len().div_ceil(art);
        let orders: Vec<Vec<usize>> = vec![
            (0..n_arts).collect(),
            (0..n_arts).rev().collect(),
            (0..n_arts).map(|i| (i * 7 + 3) % n_arts).collect(),
        ];
        for (t, order) in orders.iter().enumerate() {
            let dir = tmpdir(&format!("rar-top-onepass{t}"));
            let ex = Arc::new(Extractor::new(&dir, 1, true));
            ex.anchor();
            let mut seen = vec![false; n_arts];
            for &i in order {
                if std::mem::replace(&mut seen[i], true) {
                    continue;
                }
                let s = i * art;
                let e = (s + art).min(arch.len());
                ex.write(0, "release.rar", arch.len() as u64, s as u64, &arch[s..e])
                    .unwrap();
            }
            let rep = ex.finish().unwrap();
            assert!(rep.fallbacks.is_empty(), "order {t}: {:?}", rep.fallbacks);
            assert_eq!(std::fs::read(dir.join("F.bin")).unwrap(), f, "order {t}");
            assert_eq!(dir_files(&dir), vec!["F.bin".to_string()], "order {t}");
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    /// The multi-volume shape at depth 0: each volume of a posted
    /// compressed set is its own top-level file (own slot, own name),
    /// registering with the group's chase at its header volume number.
    /// Forward and reverse volume-arrival orders.
    #[test]
    fn top_level_compressed_rar_multivolume_chases_one_pass() {
        let f = noisy(300_000, 132);
        let vols = rars_compressed_volumes("F.bin", &f, 50_000);
        assert!(
            vols.len() >= 3,
            "want a real multi-volume set, got {}",
            vols.len()
        );
        for v in &vols {
            assert_not_store(v);
        }
        for (t, rev) in [false, true].iter().enumerate() {
            let dir = tmpdir(&format!("rar-top-mv{t}"));
            let ex = Arc::new(Extractor::new(&dir, vols.len(), true));
            ex.anchor();
            let order: Vec<usize> = if *rev {
                (0..vols.len()).rev().collect()
            } else {
                (0..vols.len()).collect()
            };
            for &vi in &order {
                feed(
                    &ex,
                    vi,
                    &format!("release.part{}.rar", vi + 1),
                    &vols[vi],
                    7000,
                    33 + vi as u64,
                );
            }
            let rep = ex.finish().unwrap();
            assert!(rep.fallbacks.is_empty(), "rev={rev}: {:?}", rep.fallbacks);
            assert_eq!(std::fs::read(dir.join("F.bin")).unwrap(), f, "rev={rev}");
            assert_eq!(dir_files(&dir), vec!["F.bin".to_string()], "rev={rev}");
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    /// The kill switch restores the pre-lift behaviour exactly: gate
    /// off, a posted compressed RAR materializes byte-exact with the
    /// NotStore demote reason and no partial output. Also pins the env
    /// parse ("1" and nothing else).
    #[test]
    fn top_level_chase_gate_off_materializes() {
        assert!(top_chase_env_off_value(Some("1")));
        assert!(!top_chase_env_off_value(Some("0")));
        assert!(!top_chase_env_off_value(None));
        let f = noisy(300_000, 133);
        let arch = rars_compressed_volume(&[("F.bin", &f)]);
        assert_not_store(&arch);
        let dir = tmpdir("rar-top-gateoff");
        let ex = Arc::new(Extractor::new(&dir, 1, true));
        ex.anchor();
        ex.set_top_level_chase(false);
        feed(&ex, 0, "release.rar", &arch, 7000, 34);
        let rep = ex.finish().unwrap();
        assert!(
            rep.fallbacks
                .iter()
                .any(|(_, w)| w.contains("compressed or encrypted entries")),
            "{:?}",
            rep.fallbacks
        );
        assert_eq!(std::fs::read(dir.join("release.rar")).unwrap(), arch);
        assert!(!dir.join("F.bin").exists(), "gate off must not stream");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A depth-0 chase over the holds cap demotes cleanly: the volume
    /// materializes COMPLETE for the unrar ladder (whose "held-bytes
    /// cap" keying the reason carries), and no partial payload survives.
    /// This is the pre-lift exit path, reached through the chase.
    #[test]
    fn top_level_chase_budget_breach_demotes_to_volume() {
        let f = noisy(2_400_000, 134);
        let arch = rars_compressed_volume(&[("F.bin", &f)]);
        assert_not_store(&arch);
        assert!(arch.len() > 900_000, "packed too small: {}", arch.len());
        let dir = tmpdir("rar-top-budget");
        let ex = Arc::new(Extractor::new(&dir, 3, true));
        ex.anchor();
        ex.set_holds_cap(1); // floors at 8 MB
        let junk = payload(65_000, 135);
        for slot in [1usize, 2] {
            for i in 0..60u64 {
                ex.write(
                    slot,
                    &format!("dummy{slot}.bin"),
                    8_000_000,
                    64_000 + i * 65_000,
                    &junk,
                )
                .unwrap();
            }
        }
        for (i, chunk) in arch.chunks(50_000).enumerate() {
            ex.write(
                0,
                "release.rar",
                arch.len() as u64,
                (i * 50_000) as u64,
                chunk,
            )
            .unwrap();
        }
        let rep = ex.finish().unwrap();
        assert!(
            rep.fallbacks
                .iter()
                .any(|(_, w)| w.contains("held-bytes cap: chase memory")),
            "{:?}",
            rep.fallbacks
        );
        assert_eq!(std::fs::read(dir.join("release.rar")).unwrap(), arch);
        assert!(!dir.join("F.bin").exists(), "partial chase output survived");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Encrypted + compressed at depth 0: with the password set the
    /// chase attaches (the gate admits an encrypted compressed entry
    /// when `inner.password` is some) and the worker decrypts through
    /// `rar_read_options` - byte-exact payload, no volume on disk.
    /// Without a password the same set must demote and materialize:
    /// nothing can decode it anywhere, and a partial output would be
    /// garbage. First test of the chase's decrypt path at ANY depth.
    #[test]
    fn top_level_encrypted_compressed_rar_chases_one_pass() {
        use rars::rar50::{EncryptedCompressedEntry, Rar50VolumeWriter, WriterOptions};
        let f = noisy(300_000, 137);
        let mut features = rars::FeatureSet::store_only();
        features.file_encryption = true;
        let opts = WriterOptions::new(rars::ArchiveVersion::Rar50, features);
        let vols = Rar50VolumeWriter::new(opts)
            .encrypted_compressed_entries(&[EncryptedCompressedEntry {
                name: b"F.bin",
                data: &f,
                mtime: None,
                attributes: 0,
                host_os: 0,
                password: b"hunter2",
            }])
            .max_payload_per_volume(50_000)
            .finish()
            .unwrap();
        assert!(
            vols.len() >= 3,
            "want a real multi-volume set, got {}",
            vols.len()
        );
        for v in &vols {
            assert_not_store(v);
        }
        // Password in hand: one-pass.
        let dir = tmpdir("rar-top-enccomp");
        let ex = Arc::new(Extractor::new(&dir, vols.len(), true));
        ex.anchor();
        ex.set_password("hunter2");
        for (vi, vol) in vols.iter().enumerate() {
            feed(
                &ex,
                vi,
                &format!("release.part{}.rar", vi + 1),
                vol,
                7000,
                60 + vi as u64,
            );
        }
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("F.bin")).unwrap(), f);
        assert_eq!(dir_files(&dir), vec!["F.bin".to_string()]);
        std::fs::remove_dir_all(&dir).unwrap();
        // No password: demote, volumes materialize byte-exact.
        let dir = tmpdir("rar-top-enccomp-nopw");
        let ex = Arc::new(Extractor::new(&dir, vols.len(), true));
        ex.anchor();
        for (vi, vol) in vols.iter().enumerate() {
            feed(
                &ex,
                vi,
                &format!("release.part{}.rar", vi + 1),
                vol,
                7000,
                70 + vi as u64,
            );
        }
        let rep = ex.finish().unwrap();
        assert!(!rep.fallbacks.is_empty(), "no-password set must demote");
        for (vi, vol) in vols.iter().enumerate() {
            assert_eq!(
                std::fs::read(dir.join(format!("release.part{}.rar", vi + 1))).unwrap(),
                *vol,
                "volume {vi} must materialize byte-exact"
            );
        }
        assert!(!dir.join("F.bin").exists(), "no partial decrypt output");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A resumed run never chases at the top level (twin of the 7z
    /// pin): the disabled extractor materializes the volume untouched
    /// for the disk path.
    #[test]
    fn top_level_chase_never_runs_on_a_resumed_run() {
        let f = noisy(200_000, 136);
        let arch = rars_compressed_volume(&[("F.bin", &f)]);
        assert_not_store(&arch);
        let dir = tmpdir("rar-top-resume");
        let ex = Arc::new(Extractor::with_resume(&dir, 1, false, true));
        ex.anchor();
        feed(&ex, 0, "release.rar", &arch, 7000, 55);
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("release.rar")).unwrap(), arch);
        assert_eq!(dir_files(&dir), vec!["release.rar".to_string()]);
        std::fs::remove_dir_all(&dir).unwrap();
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
        assert!(
            vols.len() >= 3,
            "want a real multi-volume set, got {}",
            vols.len()
        );
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
            (
                names[0].as_str(),
                vols[0].len() as u64,
                &vols[0][..],
                false,
                false,
            ),
            (
                names[1].as_str(),
                vols[1].len() as u64,
                &vols[1][..cut],
                false,
                true,
            ),
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
                ex.write(
                    si,
                    &format!("o.part{}.rar", si + 1),
                    o.len() as u64,
                    s as u64,
                    &o[s..e],
                )
                .unwrap();
            }
        }
        // "Repair" both holes - rebuilt blocks re-enter through the
        // normal patch path, exactly as mapped PAR2 repair delivers them.
        for (si, o) in outers.iter().enumerate() {
            let (s, e) = (lost[si] * art, ((lost[si] + 1) * art).min(o.len()));
            assert!(
                !ex.covered(si, s as u64, e - s),
                "vol {si} hole really is a hole"
            );
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
}

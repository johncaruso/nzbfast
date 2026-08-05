//! The worker tasks get_with_progress spawns: decode consumers, the
//! rate ticker, the deadlock watchdog, the speculative recovery
//! prefetch, and the par-race experiment (TODO 106 phase 2.1, cuts
//! 1-2). Bodies are verbatim moves from the orchestrator; each fn's
//! parameter list is exactly the clone set its spawn site used to
//! build.

use crate::*;
use std::path::Path;
use tracing::info;

/// Plaintext-once (`D`) journal record parked until its seam bytes are
/// on disk: (slot, article id, name, size, frags).
pub(super) type PendingD = (usize, String, String, u64, Vec<nzbkit::extract::Frag>);

/// One decode consumer's dependency set - exactly the clone list its
/// spawn site builds (TODO 106 phase 2.1, cut 1). The destructure at
/// the top of [`decode_consumer_loop`] keeps the body identical to its
/// pre-extraction text, so the diff is a move, not a rewrite.
pub(super) struct DecodeCtx {
    pub(super) rx: Arc<std::sync::Mutex<tokio::sync::mpsc::Receiver<nzbkit::pool::FetchOutcome>>>,
    pub(super) pending_d: Arc<std::sync::Mutex<Vec<PendingD>>>,
    pub(super) pool: Arc<nzbkit::pool::BufPool>,
    pub(super) out_pool: Arc<nzbkit::pool::BufPool>,
    pub(super) slots: Vec<Arc<FileSlot>>,
    pub(super) id_to_slot: crate::unpack::IdSlots,
    pub(super) seek_names: Arc<SeekCtl>,
    pub(super) decoded_bytes: Arc<AtomicU64>,
    pub(super) fetch_done: Arc<AtomicU64>,
    pub(super) decode_errors: Arc<AtomicU64>,
    pub(super) retention_excluded: Arc<AtomicU64>,
    pub(super) missing_430: Arc<AtomicU64>,
    pub(super) transport_failed: Arc<AtomicU64>,
    pub(super) transport_sample: Arc<std::sync::Mutex<Option<String>>>,
    pub(super) decode_error_sample: Arc<std::sync::Mutex<Option<String>>>,
    pub(super) verifier: Arc<nzbkit::live::LiveVerifier>,
    pub(super) extractor: Arc<nzbkit::extract::Extractor>,
    pub(super) shape_said: Arc<std::sync::atomic::AtomicBool>,
    pub(super) par2_outstanding: Arc<std::sync::atomic::AtomicUsize>,
    pub(super) journal: Arc<nzbkit::journal::Journal>,
    pub(super) backfill: Arc<std::sync::Mutex<Option<tokio::task::JoinHandle<u64>>>>,
    pub(super) sniff: Arc<SniffCtl>,
    pub(super) queue_ctl: Arc<nzbkit::pool::QueueControl>,
    pub(super) rt: tokio::runtime::Handle,
    pub(super) throttle_mbps: Option<f64>,
    pub(super) throttle_t0: Instant,
}

/// Everything one decode consumer thread does: drain outcome batches
/// off the shared channel, yEnc-decode, write through the extractor,
/// feed the verifier, keep the journal and the PAR2 activation race
/// honest. Runs on a dedicated OS thread - decode + pwrite + verify
/// are synchronous CPU/disk work, and inline on tokio workers they
/// starve the socket reactor on 2-4 core boxes (see the spawn site).
pub(super) fn decode_consumer_loop(ctx: DecodeCtx) {
    use nzbkit::pool::FetchOutcome;
    let DecodeCtx {
        rx,
        pending_d,
        pool,
        out_pool,
        slots,
        id_to_slot,
        seek_names,
        decoded_bytes,
        fetch_done,
        decode_errors,
        retention_excluded,
        missing_430,
        transport_failed,
        transport_sample,
        decode_error_sample,
        verifier,
        extractor,
        shape_said,
        par2_outstanding,
        journal,
        backfill,
        sniff,
        queue_ctl,
        rt,
        throttle_mbps,
        throttle_t0,
    } = ctx;
    loop {
        // Drain a batch per lock hold: the futex wake + context
        // switch of a blocking_recv handoff is per-batch, not
        // per-article - at loopback article rates (8k+/s) the
        // per-article version tripled sys time on 2 CPUs. At NAS
        // rates the batch is 1 and behavior is identical.
        let mut batch: Vec<FetchOutcome> = Vec::with_capacity(8);
        {
            let mut rx = rx.lock_ok();
            if let Some(first) = rx.blocking_recv() {
                batch.push(first);
                while batch.len() < 8 {
                    match rx.try_recv() {
                        Ok(o) => batch.push(o),
                        Err(_) => break,
                    }
                }
            }
        }
        if batch.is_empty() {
            break; // channel closed and drained
        }
        for outcome in batch {
            match outcome {
                FetchOutcome::Done { id, raw } => {
                    let Some(&(sidx, nbytes)) = id_to_slot.get(&id) else {
                        pool.give(raw);
                        continue;
                    };
                    let (sidx, nbytes) = (sidx as usize, nbytes as u64);
                    // This article is now accounted for,
                    // whatever the decode below makes of it.
                    fetch_done.fetch_add(nbytes, Ordering::Relaxed);
                    let slot = &slots[sidx];
                    let mut out = out_pool.take();
                    // M32 perf: once live verify (full-MD5 mode) has
                    // matched this slot to a PAR2 file, the article
                    // CRC is a redundant pass over bytes the verifier
                    // hashes anyway - skip it and feed the span
                    // untrusted. First article per slot (and every
                    // article under fast verify / no PAR2) keeps it.
                    let delegated = verifier.delegates_integrity(sidx);
                    match nzbkit::yenc_simd::decode_into_integrity(&raw, &mut out, !delegated) {
                        Ok((dec, integrity)) => {
                            let crc_checked = integrity.crc_checked;
                            let name = if dec.name.is_empty() {
                                slot.hint.clone()
                            } else {
                                dec.name.clone()
                            };
                            // Issue #14: the offset-0 article of a
                            // payload-classified slot decoding to
                            // the PAR2 packet magic identifies
                            // recovery data with certainty (nothing
                            // else starts with it). Reclassify NOW,
                            // before the scheduler fetches any more
                            // of the volume.
                            if !slot.is_par2()
                                && dec.offset() == 0
                                && out.starts_with(nzbkit::par2::MAGIC)
                            {
                                reclassify_sniffed_par2(
                                    &sniff,
                                    &slots,
                                    sidx,
                                    &out,
                                    dec.file_size,
                                    &queue_ctl,
                                    &id_to_slot,
                                    &par2_outstanding,
                                );
                            }
                            // BEFORE the write: the offset-0 probe
                            // fires from inside write_verified and
                            // promotes by this yEnc name - on an
                            // obfuscated set the hint-keyed lookup
                            // alone would miss it.
                            if !slot.is_par2() {
                                seek_names.note_slot_name(sidx, &name);
                            }
                            match extractor.write_verified(
                                sidx,
                                &name,
                                dec.file_size,
                                dec.offset(),
                                &out,
                                // The checked pcrc32 over exactly these
                                // bytes: a STORE span that is this whole
                                // article composes from it instead of
                                // hashing them again.
                                integrity.verified_article_crc,
                            ) {
                                Err(e) => {
                                    eprintln!("write {name}: {e}");
                                    decode_error_sample
                                        .lock_ok()
                                        .get_or_insert_with(|| format!("write {name}: {e}"));
                                    decode_errors.fetch_add(1, Ordering::Relaxed);
                                    slot.errors.fetch_add(1, Ordering::Relaxed);
                                }
                                Ok(persist) => {
                                    match &persist {
                                        nzbkit::extract::Persist::Placed(frags) => {
                                            if slot.is_par2_main {
                                                journal.record(&id);
                                            } else {
                                                journal.record_placed(
                                                    sidx,
                                                    &id,
                                                    extractor.slot_file_info(sidx),
                                                    &name,
                                                    dec.file_size,
                                                    frags,
                                                );
                                            }
                                        }
                                        // Plaintext-once span: parked
                                        // until its seam slivers are on
                                        // disk (usually one neighboring
                                        // article later) - a D record for
                                        // RAM-held bytes would survive a
                                        // kill the bytes did not.
                                        nzbkit::extract::Persist::PlacedCrypto(frags) => {
                                            pending_d.lock_ok().push((
                                                sidx,
                                                id.clone(),
                                                name.clone(),
                                                dec.file_size,
                                                frags.clone(),
                                            ));
                                        }
                                        nzbkit::extract::Persist::No => {}
                                    }
                                    // Flush every parked D whose bytes
                                    // have settled; E/K/T facts go first
                                    // so the records they support are
                                    // never orphaned.
                                    {
                                        let mut pd = pending_d.lock_ok();
                                        if !pd.is_empty() {
                                            let ev = extractor.drain_crypto_events();
                                            journal.record_crypto_events(&ev);
                                            pd.retain(|(sidx, id, name, size, frags)| {
                                                if extractor.crypto_span_on_disk(frags) {
                                                    journal.record_placed_crypto(
                                                        *sidx,
                                                        id,
                                                        extractor.slot_file_info(*sidx),
                                                        name,
                                                        *size,
                                                        frags,
                                                        &extractor.crypto_frag_mask(frags),
                                                    );
                                                    false
                                                } else {
                                                    true
                                                }
                                            });
                                        }
                                    }
                                    decoded_bytes.fetch_add(out.len() as u64, Ordering::Relaxed);
                                    if let Some(mbps) = throttle_mbps {
                                        let target = decoded_bytes.load(Ordering::Relaxed) as f64
                                            / (mbps * 1e6);
                                        let actual = throttle_t0.elapsed().as_secs_f64();
                                        if target > actual {
                                            // Dedicated thread: a plain sleep
                                            // stalls only this decoder.
                                            std::thread::sleep(std::time::Duration::from_secs_f64(
                                                (target - actual).min(0.25),
                                            ));
                                        }
                                    }
                                    if slot.is_par2() {
                                        // Par2 main (or the sniffed in-stream
                                        // bootstrap): mirror the bytes in memory
                                        // for mid-download set activation. A
                                        // sniffed slot WITHOUT a capture is a
                                        // deferred volume - its stragglers are
                                        // recovery data, not payload, and stay
                                        // out of the verifier.
                                        //
                                        // `off` is the article's declared yEnc
                                        // `begin - 1`, clamped only to >= 1 -
                                        // never to the file size. Unlike the
                                        // extractor's disk path (a sparse
                                        // write_all_at at a huge offset costs no
                                        // RAM), this resize ZERO-FILLS real
                                        // memory, so one article declaring
                                        // begin=10^15 in a file whose name merely
                                        // contains ".par2" allocated a petabyte
                                        // and aborted the daemon. A main .par2
                                        // packet is small; cap the mirror well
                                        // above any real one and drop the rest -
                                        // an oversized "main" packet is not a
                                        // set we could have activated anyway.
                                        let mut cap = slot.capture.lock_ok();
                                        if let Some(buf) = cap.as_mut() {
                                            let off = dec.offset() as usize;
                                            let end = off.saturating_add(out.len());
                                            if end <= MAX_PAR2_CAPTURE {
                                                if buf.len() < end {
                                                    buf.resize(end, 0);
                                                }
                                                buf[off..end].copy_from_slice(&out);
                                            }
                                        }
                                    } else if crc_checked {
                                        verifier.on_data(
                                            sidx,
                                            &dec.name,
                                            dec.file_size,
                                            dec.offset(),
                                            &out,
                                        );
                                    } else {
                                        // CRC skipped (or absent): not
                                        // decoder-vouched. Full MD5
                                        // under delegation; CRC-only
                                        // under lean (its contract).
                                        verifier.on_data_unverified(
                                            sidx,
                                            &dec.name,
                                            dec.file_size,
                                            dec.offset(),
                                            &out,
                                        );
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("decode error ({id}): {e}");
                            decode_error_sample
                                .lock_ok()
                                .get_or_insert_with(|| format!("decode error: {e}"));
                            decode_errors.fetch_add(1, Ordering::Relaxed);
                            slot.errors.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    out_pool.give(out);
                    pool.give(raw);
                    if slot.remaining.fetch_sub(1, Ordering::AcqRel) == 1 {
                        if extractor.is_mapped(sidx) {
                            let shape = match extractor.archive_shape() {
                                Some(sh) if !shape_said.swap(true, Ordering::Relaxed) => {
                                    format!(" [{}]", sh.display())
                                }
                                _ => String::new(),
                            };
                            println!("  ✔ {} → extracting in-stream{shape}", slot.hint);
                        } else if extractor.is_chased(sidx) {
                            // A chased slot may own a file since
                            // drop-behind trimming - but it is a
                            // partial spill, not a finished download,
                            // and announcing it as one is a lie.
                            println!("  ✔ {} → extracting in-stream", slot.hint);
                        } else if let Some(p) = extractor.slot_path(sidx) {
                            println!(
                                "  ✔ {}",
                                p.file_name().unwrap_or_default().to_string_lossy()
                            );
                        }
                        // A sniffed bootstrap volume owes the
                        // activation counter a completion just
                        // like a static par2-main slot does;
                        // deferred sniffed slots do not.
                        if (slot.is_par2_main || (slot.is_par2() && sniff.note_completed(sidx)))
                            && maybe_activate_par2(
                                &slots,
                                &verifier,
                                &par2_outstanding,
                                &sniff,
                                &queue_ctl,
                                &extractor,
                            )
                        {
                            let v = verifier.clone();
                            let ex = extractor.clone();
                            let sl = slots.clone();
                            let n = slots.len();
                            *backfill.lock_ok() = Some(rt.spawn_blocking(move || {
                                let flags: Vec<bool> = sl.iter().map(|s| s.is_par2()).collect();
                                backfill_pre_activation(&v, &ex, n, &flags)
                            }));
                        }
                    }
                }
                FetchOutcome::Missing { id, cause } => {
                    match cause {
                        nzbkit::pool::MissingCause::Retention => {
                            retention_excluded.fetch_add(1, Ordering::Relaxed);
                        }
                        nzbkit::pool::MissingCause::Gone => {
                            missing_430.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                    if let Some(&(sidx, nbytes)) = id_to_slot.get(&id) {
                        let sidx = sidx as usize;
                        // Terminal is terminal: an article
                        // that will never arrive still ends
                        // the fetch's responsibility for it,
                        // and leaving it out would hold the
                        // bar short of 100% on every damaged
                        // set while repair ran.
                        fetch_done.fetch_add(nbytes as u64, Ordering::Relaxed);
                        slots[sidx].missing.fetch_add(1, Ordering::Relaxed);
                        if slots[sidx].remaining.fetch_sub(1, Ordering::AcqRel) == 1
                            && (slots[sidx].is_par2_main
                                || (slots[sidx].is_par2() && sniff.note_completed(sidx)))
                            && maybe_activate_par2(
                                &slots,
                                &verifier,
                                &par2_outstanding,
                                &sniff,
                                &queue_ctl,
                                &extractor,
                            )
                        {
                            let v = verifier.clone();
                            let ex = extractor.clone();
                            let sl = slots.clone();
                            let n = slots.len();
                            *backfill.lock_ok() = Some(rt.spawn_blocking(move || {
                                let flags: Vec<bool> = sl.iter().map(|s| s.is_par2()).collect();
                                backfill_pre_activation(&v, &ex, n, &flags)
                            }));
                        }
                    }
                }
                FetchOutcome::Failed { id, error } => {
                    transport_failed.fetch_add(1, Ordering::Relaxed);
                    transport_sample.lock_ok().get_or_insert(error);
                    if let Some(&(sidx, nbytes)) = id_to_slot.get(&id) {
                        let sidx = sidx as usize;
                        // Terminal is terminal: an article
                        // that will never arrive still ends
                        // the fetch's responsibility for it,
                        // and leaving it out would hold the
                        // bar short of 100% on every damaged
                        // set while repair ran.
                        fetch_done.fetch_add(nbytes as u64, Ordering::Relaxed);
                        slots[sidx].missing.fetch_add(1, Ordering::Relaxed);
                        if slots[sidx].remaining.fetch_sub(1, Ordering::AcqRel) == 1
                            && (slots[sidx].is_par2_main
                                || (slots[sidx].is_par2() && sniff.note_completed(sidx)))
                            && maybe_activate_par2(
                                &slots,
                                &verifier,
                                &par2_outstanding,
                                &sniff,
                                &queue_ctl,
                                &extractor,
                            )
                        {
                            let v = verifier.clone();
                            let ex = extractor.clone();
                            let sl = slots.clone();
                            let n = slots.len();
                            *backfill.lock_ok() = Some(rt.spawn_blocking(move || {
                                let flags: Vec<bool> = sl.iter().map(|s| s.is_par2()).collect();
                                backfill_pre_activation(&v, &ex, n, &flags)
                            }));
                        }
                    }
                }
            }
        }
    }
}

// Live rate ticker (2 s), driven by the consumer-side decoded counter.
// Missing-article churn shows too: a mostly-taken-down post decodes
// nothing while the pool grinds through 430s, and without the count
// that phase is indistinguishable from a hard stall (seen live on a
// 12k-segment post that flatlined at "0.0 MB/s" for minutes).
pub(super) fn spawn_rate_ticker(
    ticker_bytes: Arc<AtomicU64>,
    ticker_slots: Vec<Arc<FileSlot>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut last = 0u64;
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(2));
        tick.tick().await;
        loop {
            tick.tick().await;
            let now = ticker_bytes.load(Ordering::Relaxed);
            let missing: usize = ticker_slots
                .iter()
                .map(|s| s.missing.load(Ordering::Relaxed))
                .sum();
            let miss = if missing > 0 {
                format!("  ({missing} missing)")
            } else {
                String::new()
            };
            println!(
                "  … {:>7.1} MB/s ({:.2} Gbps)  written {:.2} GB{miss}",
                (now - last) as f64 / 2e6,
                (now - last) as f64 * 8.0 / 2e9,
                now as f64 / 1e9
            );
            last = now;
        }
    })
}

// Deadlock watchdog. A pool bug that leaves an article non-terminal
// wedges the whole job AFTER its bytes are downloaded: fetch_all_multi
// never returns, silently, until something external kills it (seen on
// a 190 GB low-memory run - 3 h frozen, download complete, no output).
// Pausing aborts the transfer rather than freezing it, so a job that
// is neither decoding NOR resolving articles, with segments still
// outstanding, is unambiguously the deadlock. When that holds, dump
// the pool state and abort: the stuck slot's blocks then fall into
// PAR2 repair (usually recovered) or fail loud, and the journal makes
// either outcome resume cleanly.
//
// BOTH signals, because decoded bytes alone do not mean "alive". An
// article that goes terminally Missing decodes nothing, and a post
// that is wholly gone decodes NOTHING AT ALL, for however long it
// takes to ask every server for every article - so a dead post is
// byte-frozen by definition while the pool works through its queue
// perfectly. Watching bytes alone, the watchdog aborted exactly that
// (31 Jul, live: a 30-day-old dead post killed mid-ladder, then
// reported as a fault on the user's own machine with most of its
// articles never requested). `remaining` counts down on Hit, Missing
// AND Failed, so it moves whenever the pool resolves anything by any
// route: it is the liveness signal a refusal-only run still has. A
// genuine wedge freezes both, and still fires.
pub(super) fn spawn_deadlock_watchdog(
    decoded: Arc<AtomicU64>,
    slots: Vec<Arc<FileSlot>>,
    qc: Arc<nzbkit::pool::QueueControl>,
    abort_flag: Arc<std::sync::atomic::AtomicBool>,
    stalled: Arc<std::sync::atomic::AtomicBool>,
) -> tokio::task::JoinHandle<()> {
    let secs: u64 = std::env::var("NZBFAST_STALL_ABORT_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(180);
    // Poll several times per stall window (bounded 1..=15 s) so a short
    // override fires promptly in tests and production stays low-churn.
    let poll = (secs / 4).clamp(1, 15);
    tokio::spawn(async move {
        let outstanding_now = |sl: &[Arc<FileSlot>]| -> usize {
            sl.iter().map(|s| s.remaining.load(Ordering::Relaxed)).sum()
        };
        let mut last = decoded.load(Ordering::Relaxed);
        let mut last_outstanding = outstanding_now(&slots);
        let mut frozen = 0u64;
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(poll)).await;
            if abort_flag.load(Ordering::Relaxed) {
                return;
            }
            let now = decoded.load(Ordering::Relaxed);
            let outstanding = outstanding_now(&slots);
            if now != last || outstanding != last_outstanding {
                last = now;
                last_outstanding = outstanding;
                frozen = 0;
                continue;
            }
            frozen += poll;
            if frozen >= secs && outstanding > 0 {
                eprintln!(
                    "⚠ download stalled: no decode progress AND no article \
                     resolved for {frozen}s with {outstanding} segment(s) still \
                     outstanding - the connection pool has wedged. Dumping state \
                     and aborting; the journal keeps what landed, PAR2 fills any \
                     gap, and a retry resumes."
                );
                qc.dump_state();
                stalled.store(true, Ordering::Relaxed);
                qc.abort();
                return;
            }
        }
    })
}

// M2c.5 speculative recovery prefetch: the moment ANY article goes
// terminally Missing/Failed, damage is certain - fetch the smallest
// recovery volume on a tiny side pool (1 conn/server; the main pool
// owns the provider grants) so the post-settle exact-fit pass starts
// with recovery blocks already on disk. The daemon gates this via
// hub.spec_prefetch (off when a quota is configured - mirrors the
// sidecar-prefetch guard); CLI runs opt out with
// NZBFAST_NO_SPEC_PREFETCH=1. Risk is bounded to one small volume of
// possibly-wasted bytes. Skipped when the set bootstraps from a
// volume (one is already inbound) or the NZB ships no volumes.
#[allow(clippy::too_many_arguments)]
pub(super) fn spawn_spec_prefetch(
    allowed: bool,
    has_main: bool,
    nzb: &Arc<Nzb>,
    servers: &[(ServerConfig, nzbkit::pool::PoolConfig)],
    slots: &[Arc<FileSlot>],
    out_dir: &Path,
    buf_pool: &Arc<nzbkit::pool::BufPool>,
    prefetched: &Arc<std::sync::Mutex<Vec<(usize, Vec<PathBuf>)>>>,
    prefetch_stop: &Arc<std::sync::atomic::AtomicBool>,
) -> Option<tokio::task::JoinHandle<()>> {
    use nzbkit::pool::ArticleReq;
    use std::collections::HashMap;
    let target = (allowed && has_main)
        .then(|| {
            nzb.files
                .iter()
                .enumerate()
                .filter(|(_, f)| f.kind() == FileKind::Par2Volume)
                .min_by_key(|(_, f)| f.bytes())
                .map(|(fi, f)| (fi, f.bytes()))
        })
        .flatten();
    target.map(|_| {
        // Smallest-first ladder of every recovery volume: (fi, reqs,
        // declared/estimated slice count). The watcher escalates one
        // rung at a time while the missing count outruns the blocks
        // already prefetched - missing articles are CERTAIN damage,
        // so cover for the observed count is never wasted bytes.
        let mut ladder: Vec<(usize, Vec<ArticleReq>, HashMap<String, usize>, usize, u64)> =
            nzb.files
                .iter()
                .enumerate()
                .filter(|(_, f)| f.kind() == FileKind::Par2Volume)
                .map(|(fi, f)| {
                    let age_days = nzb_age_days(f.date);
                    let mut reqs = Vec::new();
                    let mut idm = HashMap::new();
                    for seg in &f.segments {
                        let b = format!("<{}>", seg.message_id);
                        idm.insert(b.clone(), fi);
                        reqs.push(ArticleReq {
                            id: b,
                            age_days,
                            part: seg.number,
                        });
                    }
                    let name = f.filename_hint().unwrap_or(&f.subject);
                    // Conservative when the name doesn't declare a
                    // count: claim 1 so escalation keeps going rather
                    // than stopping on an inflated estimate.
                    let count = vol_count_from_name(name).unwrap_or(1);
                    (fi, reqs, idm, count, f.bytes())
                })
                .collect();
        ladder.sort_by_key(|(_, _, _, _, bytes)| *bytes);
        let side_servers = side_pool_servers(servers);
        let slots2 = slots.to_vec();
        let out2 = out_dir.to_path_buf();
        let bp = buf_pool.clone();
        let vol_cap = volume_prealloc_cap(nzb);
        let pre = prefetched.clone();
        let stop = prefetch_stop.clone();
        tokio::spawn(async move {
            let mut covered = 0usize;
            let mut ladder = ladder;
            loop {
                if stop.load(Ordering::Acquire) {
                    return; // network phase over - settle takes it from here
                }
                let miss: usize =
                    slots2.iter().map(|s| s.missing.load(Ordering::Relaxed)).sum();
                if miss > covered {
                    // Exact-fit rung: the smallest unfetched volume
                    // covering the whole deficit (else the biggest
                    // left) - the pure smallest-first ladder
                    // over-fetched ~2x once the damage count ran
                    // ahead of the rungs.
                    let deficit = miss - covered;
                    if ladder.is_empty() {
                        return; // every volume already prefetched
                    }
                    let at = ladder
                        .iter()
                        .position(|(_, _, _, count, _)| *count >= deficit)
                        .unwrap_or(ladder.len() - 1);
                    let (fi, reqs, idm, count, bytes) = ladder.remove(at);
                    info!(
                        target: "repair",
                        "{miss} article(s) terminally missing - prefetching recovery volume ({:.1} MB) alongside the download",
                        bytes as f64 / 1e6
                    );
                    match fetch_volume_articles(&side_servers, reqs, idm, &out2, &bp, vol_cap)
                        .await
                    {
                        Ok((0, paths)) if !paths.is_empty() => {
                            covered += count.max(1);
                            pre.lock_ok().push((fi, paths));
                        }
                        Ok((failures, paths)) if !paths.is_empty() => {
                            // A PARTIAL volume: some articles failed.
                            // Recording its file index would strike the
                            // WHOLE volume off the post-settle fetch
                            // list while its missing slices can never
                            // be refetched - a repairable job then
                            // reports a false shortfall. Leave it
                            // unrecorded and uncredited: the next rung
                            // runs now, and the post-settle ladder can
                            // still fetch this volume in full.
                            info!(
                                target: "repair",
                                "that volume landed partially ({failures} article \
                                 failure(s)) - leaving it fetchable and trying the next rung"
                            );
                        }
                        Ok(_) => {
                            // Not one byte of that volume landed (every
                            // article failed, or it was unwritable).
                            // Claiming its blocks as covered would stall
                            // escalation, and recording the file index
                            // would strike it off the post-settle fetch
                            // list - so do neither and try the next rung.
                            info!(
                                target: "repair",
                                "that volume produced no file - trying the next one"
                            );
                        }
                        Err(e) => {
                            info!(
                                target: "repair",
                                "speculative prefetch failed ({e}) - the post-settle fetch covers it"
                            );
                            return;
                        }
                    }
                    continue; // re-check immediately - miss may have grown
                }
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            }
        })
    })
}

// PAR2-race experiment (dark, NZBFAST_PAR_RACE=1): once the set is
// active, if the recovery blocks already on hand cover the WORST
// CASE of every still-queued payload article being abandoned - with
// 2x margin - and the line is slow enough that the remainder is
// >30 s away, cancel the queued stragglers and let repair finish
// the job: the math beats the network. Conservative on every axis:
// on-hand is the activation count plus prefetched volumes counted
// off disk; per-article damage is the whole-block ceiling plus one
// (the block its edges straddle); in-flight articles are untouched
// (`cancel` only removes QUEUED work) and resolve normally. The
// articles removed get no pool outcome, so this owns the accounting
// exactly as a sniff deferral does: remaining down, abandoned up,
// fetch_done credited. Settle needs no new damage arithmetic - the
// final read-back finds the absent blocks and the repair self-proves
// by re-reading the whole set (the invariant this leans on).
// Fires at most once per run.
#[allow(clippy::too_many_arguments)]
pub(super) fn spawn_par_race(
    slots: &[Arc<FileSlot>],
    verifier: &Arc<nzbkit::live::LiveVerifier>,
    queue_ctl: &Arc<nzbkit::pool::QueueControl>,
    prefetch_stop: &Arc<std::sync::atomic::AtomicBool>,
    prefetched: &Arc<std::sync::Mutex<Vec<(usize, Vec<PathBuf>)>>>,
    fetch_done: &Arc<AtomicU64>,
    decoded_bytes: &Arc<AtomicU64>,
    slot_file: &[usize],
    nzb: &Arc<Nzb>,
) -> Option<tokio::task::JoinHandle<()>> {
    std::env::var("NZBFAST_PAR_RACE")
        .is_ok_and(|v| v == "1")
        .then(|| {
            let slots2 = slots.to_vec();
            let verifier2 = verifier.clone();
            let queue_ctl2 = queue_ctl.clone();
            let stop = prefetch_stop.clone();
            let pre = prefetched.clone();
            let fetch_done2 = fetch_done.clone();
            let bytes_now = decoded_bytes.clone();
            let slot_file2 = slot_file.to_vec();
            let nzb2 = nzb.clone();
            tokio::spawn(async move {
                use std::collections::{HashMap, HashSet, VecDeque};
                let mut win: VecDeque<(std::time::Instant, u64)> = VecDeque::new();
                loop {
                    if stop.load(Ordering::Acquire) {
                        return; // network phase over - settle owns it now
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    let Some(set) = verifier2.set() else { continue };
                    // Rolling 10 s decode-rate window.
                    let now = std::time::Instant::now();
                    win.push_back((now, bytes_now.load(Ordering::Relaxed)));
                    while win
                        .front()
                        .is_some_and(|(t, _)| now.duration_since(*t).as_secs() > 10)
                    {
                        win.pop_front();
                    }
                    let (Some(&(t0, b0)), Some(&(t1, b1))) = (win.front(), win.back()) else {
                        continue;
                    };
                    let span = t1.duration_since(t0).as_secs_f64();
                    if span < 8.0 {
                        continue;
                    }
                    let rate = b1.saturating_sub(b0) as f64 / span;
                    // Candidates: payload slots with unresolved articles.
                    let block = set.block_size.max(1) as usize;
                    let mut want: HashSet<String> = HashSet::new();
                    let mut bytes_of: HashMap<String, (usize, u64)> = HashMap::new();
                    let mut out_bytes = 0u64;
                    let mut out_blocks = 0usize;
                    for (sidx, s) in slots2.iter().enumerate() {
                        let rem = s.remaining.load(Ordering::Relaxed);
                        if s.is_par2() || rem == 0 {
                            continue;
                        }
                        let f = &nzb2.files[slot_file2[sidx]];
                        let per = (f.bytes() / f.segments.len().max(1) as u64).max(1);
                        out_bytes += rem as u64 * per;
                        out_blocks += rem * ((per as usize).div_ceil(block) + 1);
                        for seg in &f.segments {
                            let b = format!("<{}>", seg.message_id);
                            bytes_of.insert(b.clone(), (sidx, seg.bytes));
                            want.insert(b);
                        }
                    }
                    if want.is_empty() {
                        continue;
                    }
                    // The line must be slow enough that repair clearly
                    // wins; a healthy line finishes the remainder before
                    // any repair could start its verify pass.
                    let eta = if rate > 0.0 {
                        out_bytes as f64 / rate
                    } else {
                        f64::INFINITY
                    };
                    if eta < 30.0 {
                        continue;
                    }
                    // Damage ceiling if every unresolved article is lost:
                    // the queued ones we would cancel plus the already
                    // bad or terminally missing.
                    let (_, live_bad) = verifier2.live_counts();
                    let missing_arts: usize = slots2
                        .iter()
                        .filter(|s| !s.is_par2())
                        .map(|s| s.missing.load(Ordering::Relaxed))
                        .sum();
                    let per_art_blocks =
                        ((out_bytes / want.len().max(1) as u64) as usize).div_ceil(block) + 1;
                    let damage_ceiling =
                        out_blocks + live_bad as usize + missing_arts * per_art_blocks;
                    let mut on_hand = set.recovery_blocks_seen;
                    for (_, paths) in pre.lock_ok().iter() {
                        for p in paths {
                            if let Ok(bytes) = std::fs::read(p) {
                                on_hand += nzbkit::par2repair::recovery_slice_locators(
                                    &bytes,
                                    &set.recovery_set_id,
                                )
                                .into_iter()
                                .filter(|(_, _, len)| *len == block)
                                .count();
                            }
                        }
                    }
                    if on_hand < damage_ceiling.saturating_mul(2) {
                        continue;
                    }
                    // Race. Cancel is best-effort under queue contention
                    // (bounded try_lock) - same retry shape as the sniff
                    // deferral.
                    let mut removed = Vec::new();
                    for attempt in 0..3 {
                        removed = queue_ctl2.cancel(&want);
                        if !removed.is_empty() {
                            break;
                        }
                        if attempt < 2 {
                            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
                        }
                    }
                    if removed.is_empty() {
                        continue; // everything already in flight or done
                    }
                    let mut freed = 0u64;
                    for id in &removed {
                        if let Some(&(sidx, b)) = bytes_of.get(id) {
                            slots2[sidx].remaining.fetch_sub(1, Ordering::AcqRel);
                            slots2[sidx].abandoned.fetch_add(1, Ordering::Relaxed);
                            freed += b;
                        }
                    }
                    // No outcome will ever arrive for these - settle the
                    // bar here, exactly like a sniff deferral.
                    fetch_done2.fetch_add(freed, Ordering::Relaxed);
                    info!(
                        target: "repair",
                        "par-race: abandoned {} queued straggler article(s) ({:.1} MB) - \
                         {on_hand} recovery blocks on hand cover the {damage_ceiling}-block \
                         worst case at 2x, and repair beats the ~{eta:.0}s fetch remainder",
                        removed.len(),
                        freed as f64 / 1e6,
                    );
                    return;
                }
            })
        })
}

/// Wind the network phase down: stop the side tasks, join the decode
/// consumers off the reactor, flush the final D records, stop the
/// ticker and watchdog, honor user abort and graceful pause (bailing
/// DROPS net_done, which the daemon reads as network-drained), signal
/// net_done, re-read the late-attach password, and await the M15b
/// backfill. Returns the elapsed network time and the effective
/// password for the disk tail.
#[allow(clippy::too_many_arguments)]
pub(super) async fn drain_network(
    prefetch_stop: &Arc<std::sync::atomic::AtomicBool>,
    spec_prefetch_task: Option<tokio::task::JoinHandle<()>>,
    par_race_task: Option<tokio::task::JoinHandle<()>>,
    consumers: Vec<std::thread::JoinHandle<()>>,
    pending_d: &Arc<std::sync::Mutex<Vec<PendingD>>>,
    extractor: &Arc<nzbkit::extract::Extractor>,
    journal: &Arc<nzbkit::journal::Journal>,
    t0: Instant,
    ticker: tokio::task::JoinHandle<()>,
    watchdog: tokio::task::JoinHandle<()>,
    stalled: &Arc<std::sync::atomic::AtomicBool>,
    abort_flag: &Arc<std::sync::atomic::AtomicBool>,
    queue_ctl: &Arc<nzbkit::pool::QueueControl>,
    note_activity: &(dyn Fn(&'static str) + Sync),
    net_done: Option<tokio::sync::oneshot::Sender<()>>,
    hub: &Option<Arc<StreamHub>>,
    stream_owner: &str,
    password: Option<String>,
    backfill: &Arc<std::sync::Mutex<Option<tokio::task::JoinHandle<u64>>>>,
) -> Result<(std::time::Duration, Option<String>)> {
    // Network phase over: stop a still-waiting watcher, and let a
    // mid-fetch prefetch finish before settle harvests the directory.
    prefetch_stop.store(true, Ordering::Release);
    if let Some(t) = spec_prefetch_task {
        let _ = t.await;
    }
    if let Some(t) = par_race_task {
        let _ = t.await;
    }
    // Decode threads exit when the channel closes (fetch dropped tx).
    // Join off the reactor - thread::join blocks.
    let _ = tokio::task::spawn_blocking(move || {
        for c in consumers {
            let _ = c.join();
        }
    })
    .await;
    // Final D-record flush: seams that closed after the last article's
    // own flush pass settle now; anything still RAM-held refetches on
    // resume, which is exactly the truthful record.
    {
        let mut pd = pending_d.lock_ok();
        if !pd.is_empty() {
            let ev = extractor.drain_crypto_events();
            journal.record_crypto_events(&ev);
            pd.retain(|(sidx, id, name, size, frags)| {
                if extractor.crypto_span_on_disk(frags) {
                    journal.record_placed_crypto(
                        *sidx,
                        id,
                        extractor.slot_file_info(*sidx),
                        name,
                        *size,
                        frags,
                        &extractor.crypto_frag_mask(frags),
                    );
                    false
                } else {
                    true
                }
            });
        }
    }
    let elapsed = t0.elapsed();
    ticker.abort();
    watchdog.abort();
    if stalled.load(Ordering::Relaxed) {
        println!(
            "  ⚠ recovered from a stalled pool by aborting the tail - \
             verifying and repairing what landed"
        );
    }
    // User cancelled: skip settle/repair/extract on the partial data.
    // The journal keeps what landed - a later retry resumes from it.
    // (Bailing drops net_done, which the daemon reads as network-drained.)
    if abort_flag.load(Ordering::Relaxed) {
        anyhow::bail!("stopped by user");
    }
    // Graceful pause: the pool admitted no new work and let every in-flight
    // article finish and journal, so a resume re-fetches only the unstarted
    // queue - nothing here is wasted. Park it like an abort (skip settle),
    // but say so: this is a clean wind-down, not a cancel.
    if queue_ctl.is_draining() {
        anyhow::bail!("paused (drained in-flight; queue kept for resume)");
    }
    // Network drained: everything from here is disk/CPU. Tell the daemon
    // so the next queued download can start soaking the line now.
    //
    // The token moves FIRST, and it is what the queue row's status is
    // read from - so by the time the daemon can act on the signal and
    // start the next download, this job has already stopped calling
    // itself a download. Announced here rather than at the verify pass
    // below because the settle read-back, the backfill join and the
    // deferred-payload sweep in between are all part of checking what
    // landed; leaving the token on "fetching" for them is what made a
    // finished transfer read as "downloading, 100%, 0 MB/s" for minutes.
    note_activity("verifying");
    if let Some(tx) = net_done {
        let _ = tx.send(());
    }
    // M24 late attach (C1): a password set via mode=set_password while
    // this job downloaded. The `password` binding above was resolved at
    // start; without this re-read the whole disk tail (re-extraction,
    // recovery-record repair, the unrar ladder, the nested pass) ran with
    // the stale None, parked the job as password_required, and the very
    // password the user had already supplied sat unread until a manual
    // retry. Late wins over captured: a user re-typing mid-download is
    // correcting the one the job started with.
    let password: Option<String> = hub
        .as_ref()
        .and_then(|h| h.late_password_for(stream_owner))
        .or(password);
    // Any pre-activation spans the backfill is still hashing belong to
    // this tail - wait so settle sees final block states (M15b).
    let bf = backfill.lock_ok().take();
    if let Some(h) = bf
        && let Ok(fed) = h.await
        && fed > 0
    {
        println!(
            "  » backfilled {:.1} MB of pre-activation spans during download",
            fed as f64 / 1e6
        );
    }
    Ok((elapsed, password))
}

/// The fetch-outcome channel, the shared progress/error counters and
/// first-error samples, the slow-disk consumer throttle, the M15b
/// backfill cell, and the runtime handle the decode threads use for
/// spawn_blocking. Field names match the local bindings the inline
/// code used.
pub(super) struct Counters {
    pub(super) tx: tokio::sync::mpsc::Sender<nzbkit::pool::FetchOutcome>,
    pub(super) rx: Arc<std::sync::Mutex<tokio::sync::mpsc::Receiver<nzbkit::pool::FetchOutcome>>>,
    pub(super) decoded_bytes: Arc<AtomicU64>,
    pub(super) decode_errors: Arc<AtomicU64>,
    pub(super) retention_excluded: Arc<AtomicU64>,
    pub(super) missing_430: Arc<AtomicU64>,
    pub(super) transport_failed: Arc<AtomicU64>,
    pub(super) transport_sample: Arc<std::sync::Mutex<Option<String>>>,
    pub(super) decode_error_sample: Arc<std::sync::Mutex<Option<String>>>,
    pub(super) throttle_mbps: Option<f64>,
    pub(super) throttle_t0: Instant,
    pub(super) backfill: Arc<std::sync::Mutex<Option<tokio::task::JoinHandle<u64>>>>,
    pub(super) rt: tokio::runtime::Handle,
}

pub(super) fn build_counters(
    budget: &nzbkit::mem::MemBudget,
    progress: Option<Arc<AtomicU64>>,
    hub: &Option<Arc<StreamHub>>,
    resume_have_bytes: u64,
) -> Counters {
    use nzbkit::pool::FetchOutcome;
    // B2: channel depth scales with the budget - a fixed 256 held up to
    // ~200 MB of raw articles OUTSIDE the budget, more than a small
    // box's entire allowance. See MemBudget::channel_depth.
    let (tx, rx) = tokio::sync::mpsc::channel::<FetchOutcome>(budget.channel_depth());
    // Consumers are dedicated OS threads (A6, constrained-CPU): decode +
    // pwrite + verify are all synchronous CPU/disk work, and running them
    // inline on tokio workers starves the socket reactor on 2-4 core
    // boxes (every worker stuck in MD5/pwrite → TCP reads stall →
    // throughput craters). A std Mutex around the receiver is fine
    // between OS threads: the handoff is microseconds against ~800 KB
    // of decode work per article, and no async scheduler hop is involved.
    let rx = Arc::new(std::sync::Mutex::new(rx));
    // The daemon shares this counter to report live queue progress.
    let decoded_bytes = progress.unwrap_or_else(|| Arc::new(AtomicU64::new(0)));
    // Publish what the journal already holds, so the queue row can add
    // it to this counter and pick the bar up where the last run left it.
    // A resume that stopped at 62% otherwise re-drew from 0 and climbed
    // back, which reads as "it started over" however loudly the copy
    // says nothing is re-downloaded - and is what a good share of the
    // reports of a lost journal actually are.
    //
    // Beside the counter rather than added INTO it, deliberately. This
    // one is every consumer's idea of "bytes off the wire this run": the
    // quota ledger bills it, history divides it by network seconds, the
    // resulting average feeds `best_rate_bps` (the stall watchdog's
    // reference for what the line can do), the CLI ticker differences it
    // per 2 s, and the daemon's rolling speed window differences it per
    // sample. Crediting 40 GB of already-downloaded articles into it in
    // one instant would answer all six of those with a number no line
    // has ever run at. The reader that wants "how much of this release
    // is on disk" adds the two; nothing else has to know.
    //
    // The figure is the NZB's encoded segment size, where a fetched
    // article credits its decoded length - so the seeded stretch of the
    // bar runs a few percent generous against an encoded denominator
    // that the fetched stretch runs a few percent shy of. Squaring those
    // two ends is audit #15's job; the percentage is clamped, so neither
    // can overshoot the bar.
    if let Some(h) = &hub {
        h.resume_seeded.store(resume_have_bytes, Ordering::Relaxed);
    }
    let decode_errors = Arc::new(AtomicU64::new(0));
    // Segments the pool never asked anyone for: outside every configured
    // server's retention window. Reported by cause in the failure summary
    // - to the user these were indistinguishable from real takedowns.
    let retention_excluded = Arc::new(AtomicU64::new(0));
    // The other two loss ledgers the failure summary reads. A real 430
    // verdict and a transport failure demand opposite responses (the
    // post is dead vs the provider flaked), yet both used to land in the
    // same per-slot "missing" count - a flaky provider read as a
    // takedown, all the way to the indexer failure report.
    let missing_430 = Arc::new(AtomicU64::new(0));
    let transport_failed = Arc::new(AtomicU64::new(0));
    // First error of each kind, verbatim, for the failure summary to
    // quote - the counter alone says nothing a bug report can act on.
    let transport_sample: Arc<std::sync::Mutex<Option<String>>> = Default::default();
    let decode_error_sample: Arc<std::sync::Mutex<Option<String>>> = Default::default();
    // Test knob: cap the consumer (decode+write) stage to N MB/s to
    // simulate a slow disk. The correct systemic response - proven by the
    // backpressure test - is that the bounded channel fills, workers stop
    // reading sockets, TCP windows close, and providers slow to match,
    // with RSS flat. Async sleep, so pool I/O tasks stay unstarved.
    let throttle_mbps: Option<f64> = std::env::var("NZBFAST_THROTTLE_WRITE_MBPS")
        .ok()
        .and_then(|v| v.parse().ok());
    if let Some(m) = throttle_mbps {
        println!("⚠ consumer throttle active: {m} MB/s (slow-disk simulation)");
    }
    let throttle_t0 = Instant::now();

    // M15b backfill: filled by whichever consumer wins the activation
    // race; awaited (and reported) before the settle pass.
    let backfill: Arc<std::sync::Mutex<Option<tokio::task::JoinHandle<u64>>>> =
        Arc::new(std::sync::Mutex::new(None));
    // NOTE: the par2 flags for the M15b backfill are computed AT ACTIVATION
    // TIME from the slots themselves (not snapshotted here): the in-stream
    // sniff can flip a slot to recovery data long after this point.

    // Handle for the two par2-activation spawn_blocking sites below -
    // decode threads are plain OS threads with no implicit runtime context.
    let rt = tokio::runtime::Handle::current();
    Counters {
        tx,
        rx,
        decoded_bytes,
        decode_errors,
        retention_excluded,
        missing_430,
        transport_failed,
        transport_sample,
        decode_error_sample,
        throttle_mbps,
        throttle_t0,
        backfill,
        rt,
    }
}

/// Spawn the decode-consumer fleet: one dedicated OS thread per
/// decoder (capped at the core count - more is pure scheduler churn,
/// measured on the 2-CPU cgroup rig), each running
/// [`decode_consumer_loop`] over a DecodeCtx built from these shared
/// handles. Returns the join handles and the shared pending-D cell the
/// drain pass flushes.
#[allow(clippy::too_many_arguments)]
pub(super) fn spawn_decode_consumers(
    decoders: usize,
    rx: &Arc<std::sync::Mutex<tokio::sync::mpsc::Receiver<nzbkit::pool::FetchOutcome>>>,
    buf_pool: &Arc<nzbkit::pool::BufPool>,
    out_pool: &Arc<nzbkit::pool::BufPool>,
    slots: &[Arc<FileSlot>],
    id_to_slot: &crate::unpack::IdSlots,
    seek_names: &Arc<SeekCtl>,
    decoded_bytes: &Arc<AtomicU64>,
    fetch_done: &Arc<AtomicU64>,
    decode_errors: &Arc<AtomicU64>,
    retention_excluded: &Arc<AtomicU64>,
    missing_430: &Arc<AtomicU64>,
    transport_failed: &Arc<AtomicU64>,
    transport_sample: &Arc<std::sync::Mutex<Option<String>>>,
    decode_error_sample: &Arc<std::sync::Mutex<Option<String>>>,
    verifier: &Arc<nzbkit::live::LiveVerifier>,
    extractor: &Arc<nzbkit::extract::Extractor>,
    shape_said: &Arc<std::sync::atomic::AtomicBool>,
    par2_outstanding: &Arc<std::sync::atomic::AtomicUsize>,
    journal: &Arc<nzbkit::journal::Journal>,
    backfill: &Arc<std::sync::Mutex<Option<tokio::task::JoinHandle<u64>>>>,
    sniff: &Arc<SniffCtl>,
    queue_ctl: &Arc<nzbkit::pool::QueueControl>,
    rt: &tokio::runtime::Handle,
    throttle_mbps: Option<f64>,
    throttle_t0: Instant,
) -> (
    Vec<std::thread::JoinHandle<()>>,
    Arc<std::sync::Mutex<Vec<PendingD>>>,
) {
    let mut consumers = Vec::new();
    // Plaintext-once D records parked until their seam bytes settle on
    // disk (see the PlacedCrypto arm below). Shared across the decode
    // threads; leftovers at join time simply refetch on resume.
    let pending_d: Arc<std::sync::Mutex<Vec<PendingD>>> = Default::default();
    // More decode threads than cores is pure scheduler churn (measured on
    // the 2-CPU cgroup rig): the default 4 stands on big metal, small
    // boxes get one per core.
    let n_decoders = decoders
        .max(1)
        .min(std::thread::available_parallelism().map_or(usize::MAX, |n| n.get()));
    for i in 0..n_decoders {
        let ctx = DecodeCtx {
            rx: rx.clone(),
            pending_d: pending_d.clone(),
            pool: buf_pool.clone(),
            out_pool: out_pool.clone(),
            slots: slots.to_vec(),
            id_to_slot: id_to_slot.clone(),
            seek_names: seek_names.clone(),
            decoded_bytes: decoded_bytes.clone(),
            fetch_done: fetch_done.clone(),
            decode_errors: decode_errors.clone(),
            retention_excluded: retention_excluded.clone(),
            missing_430: missing_430.clone(),
            transport_failed: transport_failed.clone(),
            transport_sample: transport_sample.clone(),
            decode_error_sample: decode_error_sample.clone(),
            verifier: verifier.clone(),
            extractor: extractor.clone(),
            shape_said: shape_said.clone(),
            par2_outstanding: par2_outstanding.clone(),
            journal: journal.clone(),
            backfill: backfill.clone(),
            sniff: sniff.clone(),
            queue_ctl: queue_ctl.clone(),
            rt: rt.clone(),
            throttle_mbps,
            throttle_t0,
        };
        let thread = std::thread::Builder::new()
            .name(format!("decode-{i}"))
            .spawn(move || decode_consumer_loop(ctx))
            .expect("spawn decode thread");
        consumers.push(thread);
    }
    (consumers, pending_d)
}

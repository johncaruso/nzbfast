//! Index upkeep, either side of the scan loop itself (which stays in
//! `serve/tasks.rs` with the download worker): deferred VACUUM
//! compaction, the instant-watch hook that offers fresh arrivals to the
//! watchlist, the tip watcher, and the oracle sampler.
//!
//! The common discipline here is that none of it may cost the user a
//! download - the compactor waits for a genuinely idle moment, and the
//! samplers sit out entirely while anything is fetching.
//!
//! Split out of `serve/tasks.rs` whole (TODO 106) - the code is verbatim,
//! only visibility changed (and one `super::daemon::` path, which now
//! sits one module deeper, spelled from the crate root).

use super::*;

/// M34: deferred compaction. Deleting rows does not shrink a SQLite
/// file - the pages go on the free list and the file stays the size
/// it grew to - so reclaiming the disk the size cap just promised
/// needs a VACUUM. VACUUM exclusive-locks and rewrites the WHOLE
/// database, which is exactly the thing that must never interrupt a
/// scan pass or a download, so it is not run where the prune raises
/// the flag. This loop waits for a genuinely idle moment instead:
/// nothing downloading, nothing scanning, and room on the volume for
/// the rebuild. If any of that fails it stays deferred and tries
/// again a minute later - a compact that never happens costs disk,
/// a compact that runs at the wrong time costs the user their
/// download.
#[cfg(feature = "indexer")]
pub(in crate::serve) fn spawn_index_compact(
    daemon: &Arc<Daemon>,
    index_pass_gate: &Arc<tokio::sync::Mutex<()>>,
) {
    let d = daemon.clone();
    let index_pass_gate = index_pass_gate.clone();
    // Not `index_db` - the scan-loop task above owns that binding now.
    let db = daemon.index_db.clone();
    tokio::spawn(async move {
        // Rate-limit the "no room" line: this ticks every minute and
        // a small NAS volume can stay full for days.
        let mut last_moan = std::time::Instant::now()
            .checked_sub(std::time::Duration::from_secs(7200))
            .unwrap_or_else(std::time::Instant::now);
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            // `compact_pending` is sticky, so a prune that raised it
            // just before the indexer was switched off would still
            // rewrite a multi-GB file - the loudest disk work there
            // is, on behalf of a feature that is now off. It stays
            // raised and runs if the indexer comes back; to get the
            // space back instead, the off state offers to delete the
            // database outright.
            if !d.compact_pending.load(Ordering::Relaxed) || d.indexer_off() {
                continue;
            }
            let Ok(_index_pass) = index_pass_gate.try_lock() else {
                continue;
            };
            // A stat, but on whatever volume holds the index - demote
            // the worker like every other sync fs touch on a tokio task.
            let db_bytes = crate::persist::blocking_db(|| {
                std::fs::metadata(&db).map(|m| m.len()).unwrap_or(0)
            });
            // §95: which of the two paths this database can take, read
            // BEFORE the verdict because it decides whether the volume
            // needs room for a second copy. A fresh install has been
            // incremental since `Index::open` created it; an existing
            // one is still in SQLite's default mode and needs one full
            // rewrite to get there.
            let style = d
                .with_index(|ix| ix.compact_style().ok())
                .unwrap_or(nzbkit::index::CompactStyle::FullRewrite);
            let verdict = compact_verdict(
                true,
                !d.scan_progress.lock_ok().is_empty(),
                // This argument is `downloading`, and a true answer
                // yields Busy("a download is running"). The pause
                // PREDICATE is not that question and gets it wrong in
                // both directions: with pause-on-download switched off
                // it reads false during a job, so a multi-GB VACUUM
                // could start mid-download on the same volume; and with
                // the indexer manually paused it reads true forever, so
                // compaction never runs at exactly the moment it is
                // safest. compact_pending is sticky, so that second one
                // defers silently and permanently.
                //
                // Count jobs in flight rather than reading started_at,
                // which goes None between queued jobs while the
                // pipeline is still busy.
                d.index_jobs_active.load(Ordering::Acquire) > 0,
                db_bytes,
                crate::persist::blocking_db(|| {
                    free_bytes(db.parent().unwrap_or(std::path::Path::new(".")))
                }),
                style == nzbkit::index::CompactStyle::FullRewrite,
            );
            match verdict {
                CompactVerdict::NotNeeded | CompactVerdict::Busy(_) => continue,
                CompactVerdict::NoRoom { need, free } => {
                    if last_moan.elapsed() >= std::time::Duration::from_secs(3600) {
                        last_moan = std::time::Instant::now();
                        info!(
                            target: "index",
                            "compact deferred: rebuilding the {:.0} MB index needs \
                             ~{:.0} MB free and the volume has {:.0} MB - the pruned rows \
                             are gone, the file just hasn't shrunk yet",
                            db_bytes as f64 / (1u64 << 20) as f64,
                            need as f64 / (1u64 << 20) as f64,
                            free as f64 / (1u64 << 20) as f64,
                        );
                    }
                    continue;
                }
                CompactVerdict::Go => {}
            }
            // Clear the flag BEFORE the rewrite: if a prune lands
            // while this runs it re-raises it and we come back,
            // whereas clearing afterwards would swallow that request.
            d.compact_pending.store(false, Ordering::Relaxed);
            let d2 = d.clone();
            let path = db.clone();
            // The verdict above answers "is a download running?" a
            // moment BEFORE the rewrite starts, and the rewrite then
            // holds `index_pass_gate` - which is exactly what a
            // starting download waits on - for its whole duration.
            // A job that arrives in between sits in `Downloading`
            // making no progress and logging nothing until the
            // VACUUM ends: measured, a 175 MB index blocks a waiter
            // for ~0.5 s, so the multi-GB indexes this feature exists
            // for block it for minutes.
            //
            // So take an interrupt handle before handing the
            // connection to the blocking thread, and abort the
            // rewrite the moment a job appears. VACUUM is one
            // transaction: aborting leaves the file exactly as it
            // was, and `compact_pending` brings us back a minute
            // later. The user's rule is that compaction never
            // interrupts a download - the same rule has to hold when
            // the download turns up second.
            if style == nzbkit::index::CompactStyle::Chunked {
                chunked_compact(&d, &db).await;
                continue;
            }
            info!(
                target: "index",
                "compacting the {:.0} MB index in one pass to enable incremental \
                 reclaim - this one cannot be cut short for a download, later ones can",
                db_bytes as f64 / (1u64 << 20) as f64,
            );
            // Armed inside the blocking closure, under the guard that
            // runs the VACUUM - see MaintenanceArm. A handle taken here
            // and used later belongs to a connection an unrelated
            // writer may hold by then.
            let arm = Arc::new(crate::serve::daemon::MaintenanceArm::default());
            let done = Arc::new(AtomicBool::new(false));
            let watch = {
                let jobs = d.index_jobs_active.clone();
                let done = done.clone();
                let arm = arm.clone();
                tokio::spawn(abort_compact_when_job_starts(jobs, done, move || {
                    arm.abort();
                }))
            };
            // VACUUM is a long synchronous rewrite - it belongs on a
            // blocking thread, not on an async worker.
            let done2 = done.clone();
            let arm2 = arm.clone();
            let outcome = tokio::task::spawn_blocking(move || {
                let before = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
                let ok = d2
                    .with_index(|ix| {
                        if !arm2.arm(ix.interrupt_handle()) {
                            // A download started before we got the
                            // guard: do not begin the rewrite at all.
                            done2.store(true, Ordering::Release);
                            return None;
                        }
                        let r = ix.compact();
                        arm2.disarm();
                        // Inside the closure, so the flag is set
                        // while this thread still holds the index
                        // lock: the watcher can never see "running"
                        // for a connection somebody else has already
                        // started using.
                        done2.store(true, Ordering::Release);
                        r.ok()
                    })
                    .is_some();
                let after = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
                if ok {
                    info!(
                        target: "index",
                        "compacted at idle - {:.0} MB reclaimed",
                        before.saturating_sub(after) as f64 / (1u64 << 20) as f64
                    );
                } else {
                    d2.compact_pending.store(true, Ordering::Relaxed);
                }
                ok
            })
            .await;
            done.store(true, Ordering::Release);
            // Distinguish the two failures in the log. "Compact
            // failed" for a rewrite we deliberately aborted would
            // send the user looking for a broken database.
            if matches!(watch.await, Ok(true)) {
                info!(
                    target: "index",
                    "compact stood down for a download - the index will \
                     shrink at the next idle moment"
                );
            } else if matches!(outcome, Ok(false)) {
                warn!(target: "index", "compact failed - will retry when idle");
            }
        }
    });
}

/// §95: reclaim the freed pages in bounded chunks, stopping the moment
/// a download appears.
///
/// This is the whole point of the incremental mode. The VACUUM path
/// above can only ASK to stop - `sqlite3_interrupt` is read from the
/// VDBE, so it never reaches the rewrite's `sqlite3BtreeCopyFile` tail -
/// and measured on a 1.16 GB index, a job that arrived as the rewrite
/// started waited the full 4.8 s and every abort that did land threw
/// away all 580 MB of reclaim. Here the check is between chunks, where
/// nothing is running, so standing down is immediate and everything
/// reclaimed so far is already committed and truncated.
///
/// It stays on one blocking thread for the whole loop, but takes the
/// shared index connection PER CHUNK: scan passes are already excluded
/// for the whole iteration by `index_pass_gate` (they use scratch
/// connections and rendezvous on the gate, never this mutex), so the
/// only threads the mutex holds off are the write-side HTTP handlers -
/// wall admin edits, pre_assign, kv writes - and parking those for a
/// multi-minute pass is the 2 Aug wedge shape all over again. Between
/// chunks the mutex is free, so an admin edit waits one chunk (~100 ms),
/// not the whole compaction.
#[cfg(feature = "indexer")]
async fn chunked_compact(d: &Arc<Daemon>, db: &std::path::Path) {
    let d2 = d.clone();
    let jobs = d.index_jobs_active.clone();
    let path = db.to_path_buf();
    let outcome = tokio::task::spawn_blocking(move || {
        let before = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        let mut chunks = 0u64;
        let mut stood_down = false;
        let ran = (|| {
            let mut left = d2.with_index(|ix| ix.freelist_pages().ok())?;
            while left > 0 {
                // Between chunks: nothing is running, so this
                // needs no interrupt and cannot be ignored.
                if jobs.load(Ordering::Acquire) > 0 {
                    stood_down = true;
                    break;
                }
                let now_left = d2.with_index(|ix| ix.compact_chunk(COMPACT_CHUNK_PAGES).ok())?;
                chunks += 1;
                // A chunk that reclaimed nothing means the freelist
                // is not shrinking - pages pinned by something we
                // cannot move. Without this the loop would spin on
                // them forever, holding the gate it is meant to
                // release.
                if now_left >= left {
                    break;
                }
                left = now_left;
            }
            Some(())
        })()
        .is_some();
        let after = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        (ran, stood_down, chunks, before.saturating_sub(after))
    })
    .await;
    let Ok((ran, stood_down, chunks, freed)) = outcome else {
        d.compact_pending.store(true, Ordering::Relaxed);
        return;
    };
    if !ran {
        // Re-raise the sticky flag or "will retry" is a lie: nothing
        // else raises it until some future eviction happens to, and an
        // index that stays under its cap never evicts again.
        d.compact_pending.store(true, Ordering::Relaxed);
        warn!(target: "index", "compact failed - will retry when idle");
        return;
    }
    let mb = freed as f64 / (1u64 << 20) as f64;
    if stood_down {
        // Unlike the VACUUM path, this is not "nothing happened": the
        // chunks that did run are committed and the file is already
        // shorter. Say so, or the next line the user reads implies the
        // work was wasted.
        d.compact_pending.store(true, Ordering::Relaxed);
        info!(
            target: "index",
            "compact stood down for a download after {chunks} chunks - {mb:.0} MB \
             reclaimed and kept, the rest at the next idle moment"
        );
    } else {
        info!(target: "index", "compacted at idle - {mb:.0} MB reclaimed");
    }
}

/// §74: install (or clear) the arrival watch on an index handle. Kept
/// beside `install_live_ingest_policy` and called from the same places
/// for the same reason: the shared handle is republished after every
/// full scan pass, so neither closure survives one.
///
/// `None` clears it, which is what an install with no watchlist - or the
/// setting switched off - must do, or a handle would keep journalling
/// hits nobody will ever drain.
#[cfg(feature = "indexer")]
pub(in crate::serve) fn install_instant_watch(
    ix: &mut nzbkit::index::Index,
    matcher: Option<crate::watchlist::InstantMatcher>,
) {
    ix.set_watch_names(
        matcher
            .map(|m| Box::new(move |name: &str| m.wants(name)) as Box<dyn Fn(&str) -> bool + Send>),
    );
}

/// §74: react to what the arrival watch caught in one batch.
///
/// Complete releases wake the watchlist pass immediately. Incomplete ones
/// are held for a short re-check instead: a post seen seconds after it
/// went up is usually still going up, and the watchlist only ever
/// considers complete releases. Nothing here decides anything about a
/// release - the pass does that, with the whole ladder - so the worst a
/// wrong call costs is a wasted look or a minute of latency.
#[cfg(feature = "indexer")]
pub(in crate::serve) fn instant_arrivals(
    d: &Arc<Daemon>,
    hits: Vec<nzbkit::index::WatchHit>,
    dropped: u32,
    now: i64,
) {
    if dropped > 0 {
        // Said out loud rather than swallowed: this is the one place
        // instant coverage is knowingly given up, and it must not look
        // like "nothing arrived".
        info!(
            target: "watch",
            "{dropped} arrival(s) past the instant journal's cap - \
             they wait for the next regular check"
        );
    }
    if hits.is_empty() {
        return;
    }
    let mut ready: Vec<String> = Vec::new();
    {
        let mut pending = d.instant_pending.lock_ok();
        for h in hits {
            if h.complete {
                pending.remove(&h.id);
                ready.push(h.name);
            } else {
                // First sighting wins: the clock this starts is what
                // expires the entry back to the periodic pass, and
                // re-stamping it on every batch of a large post would
                // keep it alive for as long as the post kept growing.
                pending.entry(h.id).or_insert(now);
            }
        }
    }
    if !ready.is_empty() {
        let names = ready.join(", ");
        if d.instant_kick(&ready, now) {
            info!(target: "watch", "arrived: {names} - checking the watchlist now");
        }
    }
}

/// TODO 110: how long a background sampler stands down from a host
/// whose connect was refused because the account's slots are full.
///
/// The samplers redial on their own tick - the tip watcher's default is
/// 20 s - so without this a provider at its cap was asked again three
/// times a minute, all night. The slots in question clear on another
/// machine's schedule (a laptop shutting down, a seedbox finishing, a
/// multi-WAN route settling), never on the next tick. Fifteen minutes
/// matches the full scan interval, whose passes cover the same groups
/// the cooled-down watcher is skipping, so the cost is latency only.
#[cfg(feature = "indexer")]
const SAMPLER_CAP_COOLDOWN: std::time::Duration = std::time::Duration::from_secs(900);

/// Should a background sampler stop redialling this server for a while
/// after this connect error, and if so for how long?
///
/// Two refusal shapes qualify:
///
/// * a Capacity-classified AUTHINFO refusal ("too many connections",
///   "max simultaneous IP addresses") on ANY server - the account is
///   fine, its slots are simply full, and a retry every tick is
///   exactly the hammering providers punish;
/// * a Permanent-classified refusal against a server whose source
///   addresses are declared (or known) tight - the shape where an
///   address cap answers with the same 502 wording as a bad password
///   (`max_source_ips` set low, or the [`caps_source_ips`] hostname
///   list). On a lax server that stays a credential error and keeps
///   the loud per-tick warn, because cooling it down would hide a
///   typo for fifteen minutes at a time.
///
/// Everything else (unreachable, TLS, timeout) keeps the existing
/// retry-next-tick behavior: those are what a flaky network produces,
/// and the next tick genuinely may succeed.
///
/// [`caps_source_ips`]: nzbkit::config::caps_source_ips
#[cfg(feature = "indexer")]
pub(in crate::serve) fn sampler_cap_cooldown(
    err: &nzbkit::nntp::NntpError,
    server: &nzbkit::config::ServerConfig,
) -> Option<std::time::Duration> {
    use nzbkit::nntp::{AuthRefusal, NntpError};
    match err {
        NntpError::AuthFailed {
            kind: AuthRefusal::Capacity,
            ..
        } => Some(SAMPLER_CAP_COOLDOWN),
        NntpError::AuthFailed {
            kind: AuthRefusal::Permanent,
            ..
        } if server.source_ips_are_tight() => Some(SAMPLER_CAP_COOLDOWN),
        _ => None,
    }
}

/// Tip watcher: the short loop that tracks only what is NEW at the
/// head of each group.
///
/// A full scan pass is two legs - the forward tip (~20k articles) and
/// a 200,000-article backward history deepen - and the interval
/// (default 900 s) does not start until BOTH have finished. So the
/// part that matters for "something just arrived" was riding on the
/// schedule of the part that does not: measured on the live daemon,
/// ~90% of every pass is backfill, and a new post waited up to a
/// quarter of an hour to become visible.
///
/// This loop does the forward leg alone, on its own short interval,
/// over ONE connection reused across ticks. That matters more than it
/// looks: a full pass builds and tears down a connection per worker
/// per group (~33 TLS handshakes at turbo fan-out), which is fine
/// every 15 minutes and ruinous every 20 seconds. When nothing has
/// arrived a whole tick costs one GROUP command per group.
///
/// It never competes with the full pass: a group the scan loop is
/// currently working is skipped, so only one of the two ever advances
/// a given group's high-water mark. Anything the watcher does not
/// reach (a group far behind, or a tick that runs out of budget) is
/// simply picked up by the next pass, exactly as before - the mark
/// only ever advances over a contiguous prefix, so falling behind
/// costs latency, never coverage.
#[cfg(feature = "indexer")]
pub(in crate::serve) fn spawn_tip_watcher(
    daemon: &Arc<Daemon>,
    config: &std::path::Path,
    index_pass_gate: &Arc<tokio::sync::Mutex<()>>,
) {
    let config = config.to_path_buf();
    let daemon2 = daemon.clone();
    let index_pass_gate = index_pass_gate.clone();
    tokio::spawn(async move {
        // A lone connection wants big OVER ranges - per-request
        // server latency, not bandwidth, is what costs (the full
        // scanner measures 82-95k hdr/s on 100k ranges against
        // 31-54k/s on 10k ones).
        const TIP_CHUNK: u64 = 20_000;
        // Further behind than this and catching up is the full
        // pass's job, not ours: it fans out over ~10 connections and
        // will cover the gap far faster than one connection can.
        const TIP_HANDOFF: u64 = 500_000;
        // A8: one connection per PRIMARY host - groups can have
        // different chosen primaries, and a mark is only valid
        // against the server whose numbering built it. With one
        // provider this degenerates to the single connection it
        // always was.
        let mut conns: std::collections::HashMap<String, nzbkit::nntp::Connection> =
            Default::default();
        // TODO 110: hosts cooling down after a slots-full refusal -
        // see `sampler_cap_cooldown`. Keyed like `conns`.
        let mut cooldown: std::collections::HashMap<String, Instant> = Default::default();
        let mut group_cursor = 0usize;
        loop {
            let every = daemon2.index_tip_secs.load(Ordering::Relaxed);
            let groups = daemon2.index_groups.lock_ok().clone();
            if every == 0 || groups.is_empty() {
                // Off, or nothing to watch - drop the connections
                // rather than hold them open for nothing.
                for (_, c) in conns.drain() {
                    c.quit().await;
                }
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                continue;
            }
            // Stand down entirely while a full pass is in flight.
            // Skipping just the group being scanned is not enough:
            // both write the same SQLite file, and a 200k-article
            // deepen leg plus this loop's ingest overran the 10 s
            // busy timeout and failed a whole group's scan with
            // "database is locked". The full pass is the faster
            // catch-up anyway, so there is nothing to add here while
            // it runs.
            if daemon2.indexing_pause_reason().is_some() {
                for (_, c) in conns.drain() {
                    c.quit().await;
                }
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                continue;
            }
            if daemon2.scan_active.load(Ordering::Relaxed) {
                tokio::time::sleep(std::time::Duration::from_secs(every.min(5))).await;
                continue;
            }
            let index_pass = index_pass_gate.lock().await;
            if daemon2.indexing_pause_reason().is_some() {
                drop(index_pass);
                for (_, c) in conns.drain() {
                    c.quit().await;
                }
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                continue;
            }
            let gates = daemon2.index_gates.lock_ok().1.clone();
            let cats = daemon2.custom_categories.read_ok().clone();
            // §74: the watchlist, compiled into the cheap name test the
            // ingest below runs over each arriving release. Rebuilt every
            // tick rather than cached behind a generation counter: it is
            // a handful of string normalisations against a list a person
            // typed, once per tick, and a stale matcher would silently
            // stop reacting to an item the user just added.
            let matcher = daemon2.instant_matcher();
            let mut fresh = 0u32;
            // Set when a group still had articles waiting as the
            // tick ended - see the nap below.
            let mut behind = false;
            // The tick bounds itself by TIME, not by an article
            // count. A fixed count cannot work: measured live,
            // alt.binaries.boneless alone posts ~900 articles/s, so
            // a 20k-per-tick cap pinned the watcher at 100% duty
            // cycle and permanently ~20k behind - it never caught
            // up, and had no headroom for a slow tick. A deadline
            // tracks whatever the group actually does and still
            // guarantees the loop keeps to its own interval.
            let deadline = Instant::now() + std::time::Duration::from_secs(every.min(30));
            'groups: for offset in 0..groups.len() {
                let g = &groups[(group_cursor + offset) % groups.len()];
                // A8: follow the group's chosen primary - the full
                // pass persists its marks key. Absent = the group was
                // never scanned; seeding needs the backfill count and
                // max-age bisection only the full pass knows, so
                // leave it alone.
                let Some(pkey) = daemon2.with_index(|ix| ix.kv_get(&format!("scan_primary:{g}")))
                else {
                    continue;
                };
                let mark = daemon2
                    .with_index(|ix| Some(ix.high_water(g, &pkey)))
                    .unwrap_or(0);
                if mark == 0 {
                    continue;
                }
                if !conns.contains_key(&pkey) {
                    // TODO 110: still cooling down from a slots-full
                    // refusal - skip quietly, the full pass covers it.
                    if cooldown.get(&pkey).is_some_and(|&t| Instant::now() < t) {
                        continue;
                    }
                    // The key names a server the config may have
                    // dropped since the pass; skip until the next
                    // pass re-chooses.
                    let Some(server) = crate::find_scan_server(&config, &pkey) else {
                        continue;
                    };
                    match nzbkit::nntp::Connection::connect(&server).await {
                        Ok((c, _)) => {
                            cooldown.remove(&pkey);
                            conns.insert(pkey.clone(), c);
                        }
                        Err(e) => match sampler_cap_cooldown(&e, &server) {
                            Some(cd) => {
                                cooldown.insert(pkey.clone(), Instant::now() + cd);
                                warn!(
                                    target: "tip",
                                    "{}: {e} - the account's slots are in use \
                                     elsewhere; tip watch resumes in {} min \
                                     (full scan passes still cover the group)",
                                    server.host,
                                    cd.as_secs() / 60
                                );
                                continue;
                            }
                            None => {
                                warn!(target: "tip", "{}: connect: {e}", server.host);
                                continue;
                            }
                        },
                    }
                }
                let c = conns.get_mut(&pkey).expect("connected above");
                let high = match c.group(g).await {
                    Ok(info) => info.high,
                    // A dropped idle connection looks exactly like
                    // this; reconnect on the next tick.
                    Err(_) => {
                        conns.remove(&pkey);
                        continue;
                    }
                };
                if high <= mark || high - mark > TIP_HANDOFF {
                    continue;
                }
                let mut lo = mark.saturating_add(1);
                while lo <= high && Instant::now() < deadline {
                    if daemon2.indexing_pause_reason().is_some() {
                        for (_, c) in conns.drain() {
                            c.quit().await;
                        }
                        break 'groups;
                    }
                    let hi = lo.saturating_add(TIP_CHUNK - 1).min(high);
                    let Some(c) = conns.get_mut(&pkey) else { break };
                    let entries = match c.over(lo, hi).await {
                        Ok(es) => es,
                        Err(_) => {
                            conns.remove(&pkey);
                            break;
                        }
                    };
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs() as i64)
                        .unwrap_or(0);
                    let gates = gates.clone();
                    let cats = cats.clone();
                    let matcher = matcher.clone();
                    let done = daemon2.with_index_mut(|ix| {
                        // Gates are a live setting, so they are
                        // re-installed each time rather than once at
                        // startup. No gates configured = a closure
                        // that admits everything, which is what the
                        // absence of a gate means anyway.
                        install_live_ingest_policy(ix, gates, cats);
                        // §74: same re-install discipline for the
                        // arrival watch, and for the same reason - the
                        // handle is republished after every full pass.
                        install_instant_watch(ix, matcher);
                        let n = ix.ingest(g, &entries, now).ok()?;
                        // The mark moves only with the rows: an
                        // ingest that failed must not claim the
                        // range.
                        ix.set_high_water(g, &pkey, hi).ok()?;
                        // Drained inside the same lock hold: these are
                        // this batch's arrivals, and leaving them for
                        // later would mix them with the next one's.
                        Some((n, ix.take_watch_hits()))
                    });
                    let Some((_, (hits, dropped))) = done else {
                        break;
                    };
                    instant_arrivals(&daemon2, hits, dropped, now);
                    fresh += (hi - lo + 1) as u32;
                    lo = hi.saturating_add(1);
                }
                if lo <= high {
                    behind = true;
                }
            }
            // Every group leads one tick in turn. A sustained backlog
            // in groups[0] can consume the global deadline, but it can
            // no longer starve every quiet group behind it forever.
            group_cursor = (group_cursor + 1) % groups.len();
            if fresh > 0 && daemon2.index_maintenance_ok() {
                // Fresh posts need `titles` rows before the enricher
                // will look at them, and the wall sorts newest-first
                // - so this is what makes an arriving card get its
                // poster in seconds rather than at the next pass.
                let seeded = daemon2
                    .with_index(|ix| ix.seed_missing_titles(2, 200).ok())
                    .unwrap_or(0);
                info!(
                    target: "tip",
                    "{fresh} new headers{}",
                    if seeded > 0 {
                        format!(", {seeded} titles queued for artwork")
                    } else {
                        String::new()
                    }
                );
            }
            // The interval is how often to CHECK for arrivals, not
            // a throttle on ingesting them. Sleeping it out while a
            // group still had a backlog halved the loop's capacity -
            // measured against alt.binaries.boneless (~900
            // articles/s) that left it permanently ~47k articles
            // behind. Catching up gets a short nap instead, so busy
            // groups get continuous service and quiet ones stay
            // cheap.
            let nap = if behind { 1 } else { every };
            drop(index_pass);
            // Same stand-down as the oracle sampler: once the daemon
            // has been download-idle past the release timeout, hold
            // a session only for the pass that uses it. The steady
            // state here is one GROUP and one empty OVER per tick,
            // so the socket is idle for essentially the whole
            // interval while occupying an account slot - and against
            // a provider capping source IPs, the account.
            //
            // Skipped while `behind`, where the nap is 1 s and the
            // loop is genuinely working: reconnecting between
            // one-second catch-up passes would be churn, and a
            // backlog means the account is in use by this host
            // anyway.
            if !behind && !conns.is_empty() {
                // Config once, not once per held session: the map is
                // keyed by the index's server key, and resolving
                // each key through `find_scan_server` would re-read
                // the file every time.
                let cfg_now = nzbkit::config::Config::load(&config).ok();
                let release: Vec<String> = conns
                    .keys()
                    .filter(|k| {
                        cfg_now.as_ref().is_some_and(|c| {
                            c.servers
                                .iter()
                                .find(|s| nzbkit::index::Index::server_key(&s.host) == **k)
                                .is_some_and(|s| !daemon2.sampler_may_hold(s))
                        })
                    })
                    .cloned()
                    .collect();
                for k in release {
                    if let Some(c) = conns.remove(&k) {
                        c.quit().await;
                    }
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(nap)).await;
        }
    });
}

/// M29: idle STAT sampler - probes indexed releases' articles on one
/// spare connection per enabled server and feeds the availability
/// ledger, stalest-verdict release first. Throttled: `oracle_sample`
/// = STATs/hour/server (live setting, default 300; 0 disables). Sits
/// out whole ticks while a download is active so it never competes
/// for account connection slots.
#[cfg(feature = "indexer")]
pub(in crate::serve) fn spawn_oracle_sampler(daemon: &Arc<Daemon>, config: &std::path::Path) {
    let config = config.to_path_buf();
    let d = daemon.clone();
    tokio::spawn(async move {
        let mut conns: std::collections::HashMap<String, nzbkit::nntp::Connection> =
            Default::default();
        // TODO 110: same stand-down as the tip watcher's, same reason.
        let mut cooldown: std::collections::HashMap<String, Instant> = Default::default();
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            let rate = d.oracle_sample.load(Ordering::Relaxed);
            // The ledger it feeds is a table in the index database
            // and the releases it probes are indexed ones, so the
            // master switch takes this with it. Same `conns.clear()`
            // as the other stand-down arms: an idle session held
            // open against a provider is the account's slot, not
            // ours.
            if rate == 0
                || d.offline.load(Ordering::Relaxed)
                || d.indexer_off()
                || d.started_at.lock_ok().is_some()
            {
                // Offline joins the existing stand-down arms, which
                // already drop the map rather than hold sessions
                // open - dropping a Connection closes its socket, so
                // this is the hang-up, not just a bookkeeping reset.
                conns.clear();
                continue;
            }
            // Per-tick budget: ceil(rate/60) STATs per server - the
            // default 300/h probes 5 articles of one release a minute.
            let budget = (rate as usize).div_ceil(60);
            let servers: Vec<nzbkit::config::ServerConfig> =
                match nzbkit::config::Config::load(&config) {
                    Ok(c) => c.servers.into_iter().filter(|s| s.enabled).collect(),
                    Err(_) => continue,
                };
            if servers.is_empty() {
                continue;
            }
            conns.retain(|h, _| servers.iter().any(|s| &s.host == h));
            let picked = d.with_index(|ix| {
                let (id, grp, posted) = ix.oracle_pick(1).ok()?.into_iter().next()?;
                let ids = ix.oracle_msgids(id, budget).ok()?;
                Some((id, grp, posted, ids))
            });
            let Some((rid, grp, posted, ids)) = picked else {
                continue;
            };
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|t| t.as_secs() as i64)
                .unwrap_or(0);
            // Stamp first: even a failed probe rotates the pick, so
            // one bad release can't pin the sampler forever.
            d.with_index(|ix| ix.oracle_mark(rid, now).ok());
            if ids.is_empty() {
                continue;
            }
            let family = nzbkit::oracle::group_family(&grp);
            let bucket = nzbkit::oracle::age_bucket(((now - posted).max(0) / 86_400) as u32);
            let mut samples: Vec<nzbkit::oracle::Sample> = Vec::new();
            for s in &servers {
                if !conns.contains_key(&s.host) {
                    if cooldown.get(&s.host).is_some_and(|&t| Instant::now() < t) {
                        continue;
                    }
                    match nzbkit::nntp::Connection::connect(s).await {
                        Ok((c, _)) => {
                            cooldown.remove(&s.host);
                            conns.insert(s.host.clone(), c);
                        }
                        Err(e) => {
                            match sampler_cap_cooldown(&e, s) {
                                Some(cd) => {
                                    cooldown.insert(s.host.clone(), Instant::now() + cd);
                                    warn!(
                                        target: "oracle",
                                        "{}: {e} - the account's slots are in \
                                         use elsewhere; sampling this server \
                                         resumes in {} min",
                                        s.host,
                                        cd.as_secs() / 60
                                    );
                                }
                                None => warn!(target: "oracle", "{}: connect: {e}", s.host),
                            }
                            continue;
                        }
                    }
                }
                let conn = conns.get_mut(&s.host).expect("just inserted");
                let probe = async {
                    for id in &ids {
                        conn.send_stat(id).await?;
                    }
                    conn.flush().await?;
                    let (mut hits, mut misses) = (0u64, 0u64);
                    for _ in &ids {
                        match conn.read_stat().await? {
                            true => hits += 1,
                            false => misses += 1,
                        }
                    }
                    Ok::<(u64, u64), nzbkit::nntp::NntpError>((hits, misses))
                };
                match tokio::time::timeout(std::time::Duration::from_secs(20), probe).await {
                    Ok(Ok((hits, misses))) => samples.push(nzbkit::oracle::Sample {
                        host: s.host.clone(),
                        family: family.clone(),
                        bucket,
                        hits,
                        misses,
                    }),
                    other => {
                        if let Ok(Err(e)) = other {
                            warn!(target: "oracle", "{}: STAT: {e}", s.host);
                        }
                        // Desynced or mute - reconnect next tick.
                        conns.remove(&s.host);
                    }
                }
            }
            if !samples.is_empty() {
                d.with_index(|ix| ix.oracle_ingest(&samples, now).ok());
            }
            // Give the slots back between ticks, per server, once
            // the daemon has been download-idle past that server's
            // release timeout. This sampler probes ~5 articles a
            // minute: holding the socket for the other 59-odd
            // seconds occupies one of the account's connections -
            // and on a provider limiting source addresses, one of
            // its one or two address slots - permanently, for a few
            // hundred milliseconds of work. Reconnecting costs five
            // round-trips a minute, which is nothing against a
            // sampler already throttled to 300 STATs an hour.
            //
            // Per server so a strict provider cannot make this churn
            // reconnects against a lax one sharing nothing with it.
            for s in &servers {
                if !d.sampler_may_hold(s)
                    && let Some(c) = conns.remove(&s.host)
                {
                    c.quit().await;
                }
            }
        }
    });
}

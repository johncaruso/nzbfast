//! The idle-server prefetch sidecar: a secondary download that runs on
//! ONLY the servers the active job leaves idle, so the next job is already
//! partly on disk when the runner gets to it.
//!
//! Moved out of job.rs bodily (TODO 106) as a SIBLING of `job` rather than
//! a child, so `pub(super)` still means "pub in serve" and no call site
//! moved - the runner (`tasks.rs`), the slow-job watchdog
//! (`tasks/stall.rs`) and `Daemon::sidecar` all reach these by the names
//! they always used.

use super::*;

/// A secondary download running on ONLY the servers the active job
/// leaves idle (their copies of its articles keep 430ing). Its own hub
/// gives it independent abort control and pool stats; its writes land in
/// the job's normal out_dir + journal, so however it ends - completion,
/// abort at active-job end, or "these servers don't have it either" -
/// nothing is lost: the eventual primary run resumes from the journal.
pub struct Sidecar {
    pub nzo_id: String,
    /// `pub(crate)`: [`crate::StreamHub`] is crate-private, and the
    /// field follows it (Q5, as with [`Job::health`]).
    pub(crate) hub: Arc<crate::StreamHub>,
    /// Decoded bytes so far (dashboard shows prefetch progress).
    pub progress: Arc<AtomicU64>,
    /// Pre-armed cancel: the pipeline installs its own abort flag into
    /// the hub only once it starts - this one is checked by the task
    /// BEFORE that, so a stop can never miss the install window.
    pub cancelled: Arc<std::sync::atomic::AtomicBool>,
    pub task: tokio::task::JoinHandle<()>,
    /// True when this sidecar runs on connections BORROWED from servers
    /// busy on the active job (no healthy idle server existed). An idle
    /// sidecar suppresses the defer verdict - the idle capacity is
    /// already on the next job, so demoting the slow one buys nothing.
    /// A borrowed sidecar claims no idle capacity, so that reasoning
    /// does not apply and the watchdog stays armed.
    pub borrowed: bool,
}

/// Abort the sidecar (if any) and wait for it to wind down. Called by
/// the runner at every primary-job end - the next pick may be the very
/// job the sidecar holds open, and two pipelines must never share an
/// out_dir or a server's connection budget. The abort is re-fired on a
/// short interval because the pipeline installs its hub abort/queue-ctl
/// handles asynchronously after launch.
///
/// This waits for the DOWNLOAD only. A sidecar that completed its job
/// hands the post-processing tail to a task of its own (see
/// `spawn_sidecar`), so the queue never waits on a move to a NAS.
pub(super) async fn stop_sidecar(d: &Arc<Daemon>) {
    let sc = d.sidecar.lock_ok().take();
    if let Some(mut sc) = sc {
        d.note_event(
            "sidecar",
            "early start wound down - the main queue takes over",
        );
        sc.cancelled.store(true, Ordering::Relaxed);
        loop {
            if let Some(f) = sc.hub.abort.lock_ok().as_ref() {
                f.store(true, Ordering::Relaxed);
            }
            if let Some(c) = sc.hub.queue_ctl.lock_ok().as_ref() {
                c.abort();
            }
            // A timeout means the handles are not installed yet - re-fire.
            if tokio::time::timeout(std::time::Duration::from_millis(250), &mut sc.task)
                .await
                .is_ok()
            {
                break;
            }
        }
    }
}

/// Launch the idle-server prefetch pipeline for `job` (see Sidecar).
///
/// `fleet` is the host set the sidecar may download on:
/// - `borrow == false`: the idle hosts. The exclusion list is every host
///   that IS serving the active job plus exhausted block accounts and
///   auth-refused hosts - the sidecar may only touch idle capacity.
/// - `borrow == true`: healthy BUSY hosts, used when no healthy idle
///   server exists (the 31 Jul soak state: the only idle server
///   auth-refused, and cross-job tail-overlap simply never engaged -
///   49 s line-idle of a 144 s queue vs ~2% healthy). Each host stays in
///   the sidecar's fleet but its pool is capped (hub.host_conn_caps) to
///   a 1-2 connection slice sized into the headroom between the active
///   job's fleet and the provider cap, so the next job's tail-overlap
///   engages without starving the active job. When there is no headroom
///   (the active fleet already fills the account limit) the single
///   borrowed connection may be capacity-refused; the sidecar's own pool
///   answers 481s by yielding, never hammering (see AuthState in
///   nzbkit::pool), and picks the slot up as the active job's tail
///   releases it - which is exactly when tail-overlap wants it.
pub(super) fn spawn_sidecar(
    d: &Arc<Daemon>,
    config: &Path,
    job: &Arc<Mutex<Job>>,
    fleet: &[String],
    deltas: &[(String, u64)],
    budget: nzbkit::mem::MemBudget,
    borrow: bool,
) {
    let (nzo_id, nzb_path, out_dir, password) = {
        let g = job.lock_ok();
        (
            g.nzo_id.clone(),
            g.nzb_path.clone(),
            g.out_dir.clone(),
            g.password.clone(),
        )
    };
    let total: u64 = deltas.iter().map(|(_, b)| b).sum();
    let cfg_loaded = nzbkit::config::Config::load(config).ok();
    let block: std::collections::HashSet<String> = cfg_loaded
        .as_ref()
        .map(|c| {
            c.servers
                .iter()
                .filter(|s| {
                    s.block_bytes
                        .is_some_and(|b| b > 0 && d.block_spent(&s.host) >= b)
                })
                .map(|s| s.host.clone())
                .collect()
        })
        .unwrap_or_default();
    // Servers the active job's pool has recorded a refusal for (bad
    // credential or connection/IP cap) moved no bytes, so the busy-host
    // test below never catches them - but they are dead weight, not idle
    // capacity, and the sidecar must not build its fleet on them. The
    // pool clears the note on the next successful connect, so a cap that
    // lifts re-qualifies the host for the NEXT spawn.
    let refused: std::collections::HashSet<String> = d
        .hub
        .pool_live
        .lock()
        .unwrap()
        .as_ref()
        .map(|l| {
            l.servers
                .iter()
                .filter(|s| s.refusal.lock_ok().is_some())
                .map(|s| s.host.clone())
                .collect()
        })
        .unwrap_or_default();
    // The caller filters too, but enforcement must not depend on it.
    let fleet: Vec<String> = fleet
        .iter()
        .filter(|h| !refused.contains(*h) && !block.contains(*h))
        .cloned()
        .collect();
    if fleet.is_empty() {
        return;
    }
    // The borrowed slice per host: the provider cap (config `connections`
    // - "we typically use far fewer") minus the active job's fleet is
    // free headroom; take up to 2 connections of it so active + sidecar
    // never overcount the account limit. With zero headroom, take 1 and
    // let the pool's capacity-refusal handling wait it out (doc above).
    let caps: std::collections::HashMap<String, usize> = if borrow {
        let global = d.connections.load(Ordering::Relaxed).max(1);
        fleet
            .iter()
            .filter_map(|h| {
                let acct = cfg_loaded
                    .as_ref()?
                    .servers
                    .iter()
                    .find(|s| &s.host == h)?
                    .connections
                    .max(1) as usize;
                let headroom = acct.saturating_sub(global.min(acct));
                Some((h.clone(), headroom.clamp(1, 2)))
            })
            .collect()
    } else {
        Default::default()
    };
    // A borrowed host without a computed cap (config unreadable, or the
    // host vanished from it) must not join the fleet at all - an
    // uncapped "borrow" would be a full second fleet on a busy server.
    // Narrowed BEFORE the exclusion list is built, so a dropped host
    // falls back into it (it is busy) instead of slipping through both.
    let fleet: Vec<String> = if borrow {
        let kept: Vec<String> = fleet.into_iter().filter(|h| caps.contains_key(h)).collect();
        if kept.is_empty() {
            return;
        }
        kept
    } else {
        fleet
    };
    let mut excl: Vec<String> = deltas
        .iter()
        .filter(|(_, b)| (*b as f64) >= total as f64 * 0.01)
        // Borrow mode deliberately keeps its (busy) fleet hosts in.
        .filter(|(h, _)| !(borrow && fleet.contains(h)))
        .map(|(h, _)| h.clone())
        .collect();
    excl.extend(block);
    excl.extend(refused);
    let hub = Arc::new(crate::StreamHub::default());
    *hub.excluded_hosts.lock_ok() = excl;
    *hub.host_conn_caps.lock_ok() = caps.clone();
    // §96.5: a block host with bytes left may serve the sidecar, but
    // its remaining budget rides along, so a block that runs out
    // mid-prefetch releases the server there and then, same as on the
    // main job. (The ledger is read at spawn: a main job spending the
    // same host concurrently is not re-subtracted mid-run, so the
    // bound is per-fleet, not global - the exclusion lists above keep
    // that overlap to the borrow path.)
    *hub.host_byte_budgets.lock_ok() = cfg_loaded
        .as_ref()
        .map(|c| {
            c.servers
                .iter()
                .filter_map(|s| {
                    let b = s.block_bytes.filter(|b| *b > 0)?;
                    let left = b.saturating_sub(d.block_spent(&s.host));
                    (left > 0).then(|| (s.host.clone(), left))
                })
                .collect()
        })
        .unwrap_or_default();
    // M29 3d: the idle-server prefetch is real availability signal too.
    // The primary job's OracleSink lives on the daemon hub; this sidecar
    // runs on a FRESH hub, so without its own sink every 222/430 it sees
    // was silently dropped. Give it one and drain it when it winds down.
    *hub.oracle.lock_ok() = Some(Arc::new(nzbkit::oracle::OracleSink::default()));
    let progress = Arc::new(AtomicU64::new(0));
    let cancelled = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut sc_guard = d.sidecar.lock_ok();
    if sc_guard.is_some() {
        return; // raced another spawn - keep the first
    }
    if borrow {
        let slice: Vec<String> = fleet
            .iter()
            .map(|h| format!("{h} x{}", caps.get(h).copied().unwrap_or(1)))
            .collect();
        info!(
            target: "prefetch",
            "{nzo_id} borrowing connection(s) from busy server(s) {} while the active job downloads (no healthy idle server)",
            slice.join(", ")
        );
        d.note_event(
            "sidecar",
            "next job started early on connections borrowed from busy servers",
        );
    } else {
        info!(
            target: "prefetch",
            "{nzo_id} starting on idle server(s) {} while the active job downloads",
            fleet.join(", ")
        );
        d.note_event("sidecar", "next job started early on idle servers");
    }
    let eat_ok = job.lock_ok().eat_volumes_ok;
    let task = {
        let d = d.clone();
        let config = config.to_path_buf();
        let job = job.clone();
        let hub = hub.clone();
        let progress = progress.clone();
        let cancelled = cancelled.clone();
        let nzo_id = nzo_id.clone();
        let connections = d.connections.load(Ordering::Relaxed).max(1);
        let window = d.window.load(Ordering::Relaxed).max(1);
        let decoders = d.decoders.load(Ordering::Relaxed).max(1);
        let fast_verify = d.fast_verify.load(Ordering::Relaxed);
        let verify_lean = d.verify_lean.load(Ordering::Relaxed);
        let par_cleanup = d.par_cleanup.load(Ordering::Relaxed);
        tokio::spawn(async move {
            let t0 = Instant::now();
            let res = if cancelled.load(Ordering::Relaxed) {
                Err(anyhow::anyhow!("cancelled before start"))
            } else {
                crate::get_with_progress(
                    &config,
                    &nzb_path,
                    &out_dir,
                    connections,
                    window,
                    decoders,
                    fast_verify,
                    verify_lean,
                    false,
                    par_cleanup,
                    password,
                    // The sidecar prefetches ANOTHER job; its consent
                    // travels with that job's record, not this one's.
                    eat_ok,
                    Some(progress.clone()),
                    Some(hub.clone()),
                    &nzo_id,
                    None,
                    budget,
                )
                .await
            };
            // Bill what moved to the per-server usage history either way
            // (block accounts must see every byte).
            let per: Vec<(String, u64)> = hub
                .pool_live
                .lock()
                .unwrap()
                .as_ref()
                .map(|l| {
                    l.servers
                        .iter()
                        .map(|s| (s.host.clone(), s.bytes.load(Ordering::Relaxed)))
                        .collect()
                })
                .unwrap_or_default();
            d.add_usage(&per);
            // M29 3d: fold the sidecar's per-article hit/430 outcomes into
            // the availability ledger, exactly as the primary job does at
            // net-drain. Partial/cancelled runs still carry real signal.
            #[cfg(feature = "indexer")]
            if let Some(sink) = hub.oracle.lock_ok().take() {
                let samples = sink.drain();
                if !samples.is_empty() {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|t| t.as_secs() as i64)
                        .unwrap_or(0);
                    d.with_index(|ix| ix.oracle_ingest(&samples, now).ok());
                }
            }
            match res {
                Ok(()) => {
                    // The whole job fit on the idle servers - it's done.
                    {
                        let mut g = job.lock_ok();
                        g.state = JobState::Completed;
                        g.fetched = true;
                        g.downloaded_bytes = progress.load(Ordering::Relaxed);
                        g.elapsed_secs = t0.elapsed().as_secs_f64();
                        g.finished_at = Some(Instant::now());
                        g.finished_unix = Some(unix_now());
                    }
                    info!(
                        target: "prefetch",
                        "{nzo_id} completed entirely on {}",
                        if borrow {
                            "borrowed connections"
                        } else {
                            "idle servers"
                        }
                    );
                    d.note_event(
                        "sidecar",
                        if borrow {
                            "early start finished the whole job on borrowed connections"
                        } else {
                            "early start finished the whole job on idle servers"
                        },
                    );
                    // A sidecar completion is a completion: it owes the
                    // job the same tail the runner gives one (hand-over,
                    // unlock, junk sweep, rename, move), and it must run
                    // before the pp-script and history see the job.
                    //
                    // On its OWN task, because the runner awaits this one
                    // (stop_sidecar) at every primary-job end before it may
                    // pick the next: a tail that copies the payload to a NAS
                    // would hold the whole queue for the length of that copy.
                    // Nothing here needs the sidecar's abort handles - the
                    // download is over and its connections are gone.
                    let d2 = d.clone();
                    tokio::spawn(async move {
                        finalize_completed(&d2, &job).await;
                        d2.run_post_job_hooks(&job);
                        d2.park(job);
                    });
                }
                Err(e) => {
                    // A restricted attempt, not a verdict - the job stays
                    // queued and its journal keeps everything landed.
                    info!(target: "prefetch", "{nzo_id} stopped: {e} (progress kept in the journal)");
                }
            }
            let mut g = d.sidecar.lock_ok();
            if g.as_ref().is_some_and(|s| s.nzo_id == nzo_id) {
                *g = None;
            }
        })
    };
    *sc_guard = Some(Sidecar {
        nzo_id,
        hub,
        progress,
        cancelled,
        task,
        borrowed: borrow,
    });
}

//! §129 perf lane: the post-processing lane.
//!
//! The download worker used to hold the slot hostage to the PREVIOUS
//! job's tail: `prev_tail.await` meant job N+1's drain could not hand
//! the line to job N+2 until job N's repair/unpack/move finished, so
//! consecutive damaged or compressed jobs serialized completely (the
//! 8 Aug 2026 queue-continuity and profiling rounds are the
//! evidence). This module generalizes "at most one outstanding tail the
//! worker eventually blocks on" into a bounded lane the worker never
//! blocks on, except for honest backpressure.
//!
//! Contract, in one sentence: a job's ticket is in the lane if and only
//! if the job sits in the queue list as `Finishing` - tickets enter at
//! net-drain (where `net_done` fires today, AFTER the worker's
//! singleton accounting) and leave only via `park`.
//!
//! What the lane does NOT do: touch anything inside `get_with_progress`.
//! The engine's own tail (settle, repair, unpack, the §100 journal
//! handshake, §101's gates) keeps its exact ordering because it lives
//! inside the fetch task, which [`run_tail`] merely awaits from a
//! different place than the old inline closure did.
//!
//! Kill-switch: `NZBFAST_POSTPROC_INLINE=1` forces width 1 AND
//! worker-blocking submission - byte-for-byte the old scheduling
//! envelope, kept as a bisection tool.

use super::*;
use std::sync::atomic::AtomicUsize;

/// Everything the old inline tail closure captured, as a named ticket.
/// The worker builds it between `net_rx` and lane submission, after the
/// per-job accounting that must read the hub singletons before the next
/// job resets them (quota, usage, reliability, oracle drain, the
/// verifier/extractor snapshots).
pub(super) struct PostprocTicket {
    pub(super) job: Arc<Mutex<Job>>,
    /// The running engine task - settle, repair, unpack, nested pass
    /// all happen inside it. The lane awaits it; nothing reorders it.
    pub(super) fetch: tokio::task::JoinHandle<Result<()>>,
    /// Snapshotted pre-handoff: still THIS job's, even after the next
    /// job swaps the hub's slot.
    pub(super) verifier: Option<Arc<nzbkit::live::LiveVerifier>>,
    pub(super) shaper: Option<Arc<nzbkit::extract::Extractor>>,
    pub(super) log_mark: u64,
    pub(super) dl_bytes: u64,
    pub(super) dl_secs: f64,
    pub(super) on_disk_bytes: u64,
    pub(super) index_job_guard: IndexJobGuard,
}

/// The bounded lane. Width says how many tails may RUN at once; the
/// backpressure threshold (`saturated`, at 2x width of running plus
/// waiting tickets) is what keeps a fast line over a slow disk honest -
/// the worker stops picking new jobs with a stated reason instead of
/// filling the disk with undone unpacks.
pub(super) struct PostprocLane {
    d: Arc<Daemon>,
    width: usize,
    inline: bool,
    /// RUN permits (fair FIFO): a submitted ticket waits here until a
    /// lane slot frees. Admission order is submission order.
    slots: Arc<tokio::sync::Semaphore>,
    /// Tickets submitted and not yet parked (running + waiting).
    backlog: Arc<AtomicUsize>,
}

impl PostprocLane {
    pub(super) fn new(d: Arc<Daemon>) -> Self {
        let inline = std::env::var("NZBFAST_POSTPROC_INLINE").is_ok_and(|v| v == "1");
        let width = if inline {
            1
        } else {
            (d.postproc_jobs.load(Ordering::Relaxed) as usize).clamp(1, 4)
        };
        if inline {
            info!(
                target: "lane",
                "NZBFAST_POSTPROC_INLINE=1 - post-processing runs inline \
                 (width 1, the worker blocks on each tail)"
            );
        }
        PostprocLane {
            d,
            width,
            inline,
            slots: Arc::new(tokio::sync::Semaphore::new(width)),
            backlog: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub(super) fn backlog(&self) -> usize {
        self.backlog.load(Ordering::Relaxed)
    }

    /// The backpressure bound: running + waiting at twice the width.
    pub(super) fn cap(&self) -> usize {
        self.width * 2
    }

    pub(super) fn saturated(&self) -> bool {
        self.backlog() >= self.cap()
    }

    /// Hand one finished download's tail to the lane. Marks the job
    /// `Finishing` (the moment it stops being a download) and returns
    /// immediately - unless the inline kill-switch is set, in which
    /// case this awaits the whole tail like the old scheduler did.
    pub(super) async fn submit(&self, t: PostprocTicket) {
        {
            let mut j = t.job.lock_ok();
            j.state = JobState::Finishing;
            // §129 4a: the per-stage transition the schema promises -
            // the download is done, the tail (verify remainder, unlock,
            // rename, move, scripts) begins.
            self.d.life_emit(
                "job.finishing",
                json!({
                    "nzo_id": j.nzo_id,
                    "name": j.name,
                    "category": j.category,
                }),
            );
        }
        // Coalesced: a crash before the debounced write lands restores
        // the job from an OLDER snapshot, which the wildcard state arm
        // reads as Queued either way, and the journal replays the
        // network phase for free. What the deferral buys is not writing
        // a 14,500-job file four times per completion (issue #38).
        self.d.save_queue_soon();
        self.backlog.fetch_add(1, Ordering::Relaxed);
        let d = self.d.clone();
        let slots = self.slots.clone();
        let ticket = BacklogTicket {
            backlog: self.backlog.clone(),
            cap: self.cap(),
            d: self.d.clone(),
        };
        let job = t.job.clone();
        // The outer task is the per-job supervisor: it owns the lane
        // slot, catches a panicked tail (the inner JoinHandle surfaces
        // it) and guarantees the job record cannot vanish - only `park`
        // removes it from the queue list, and every arm below ends in
        // `park`.
        let supervisor = tokio::spawn(async move {
            // The count comes down when the ticket drops, wherever that
            // happens - end of this body, a panic in the crashed-tail
            // arm, the semaphore expect, or the task being dropped at
            // shutdown. The slot permit is already RAII; a decrement
            // that ran only on the happy path leaked once per panicked
            // park, and cap() leaks left saturated() true over an idle
            // daemon until restart.
            let _ticket = ticket;
            let _slot = slots
                .acquire_owned()
                .await
                .expect("the lane semaphore is never closed");
            let tail = tokio::spawn(run_tail(d.clone(), t));
            if let Err(e) = tail.await {
                file_crashed_tail(&job, &e);
                d.run_post_job_hooks(&job);
                d.park(job);
            }
        });
        if self.inline {
            let _ = supervisor.await;
        }
    }
}

/// One unit of lane backlog, paid back on Drop.
///
/// The withdraw-the-hold half lives here too: the guard loop re-reads
/// `saturated()` only once a second, so clearing where the lane drains
/// takes the stale "waiting for post-processing to catch up" sentence
/// off the screen sooner. Re-read rather than reason from fetch_sub's
/// return: a submit may have raced in behind us, and the fresher number
/// is the honest one. `clear_postproc_hold` checks the KIND, so a disk
/// or quota hold raised in between survives.
struct BacklogTicket {
    backlog: Arc<AtomicUsize>,
    cap: usize,
    d: Arc<Daemon>,
}

impl Drop for BacklogTicket {
    fn drop(&mut self) {
        self.backlog.fetch_sub(1, Ordering::Relaxed);
        if self.backlog.load(Ordering::Relaxed) < self.cap {
            self.d.clear_postproc_hold();
        }
    }
}

impl Daemon {
    /// Stop the recovery-volume side-fetches of every named job.
    ///
    /// The delete arms already tombstone a `Finishing` job and rely on
    /// the tombstone making its tail a no-op at `park` - correct for the
    /// filing, silent about the network. A damaged set's repair pulls
    /// parity over its own small pool, and that fetch has no share of
    /// `hub.abort`: those handles belong to whatever is DOWNLOADING now
    /// (see `owns_hub`), which since the lane is routinely a different
    /// job. So a deleted job went on asking a provider for volumes
    /// nobody would read, for as long as the retry ladder took.
    ///
    /// Only the network is stopped. A repair already patching bytes runs
    /// to its end and parks - cutting it mid-write would leave a
    /// half-patched file behind, and the tombstone makes the outcome a
    /// no-op either way.
    ///
    /// Unknown ids are silently skipped: a queued job that never ran, a
    /// CLI run, a job already parked.
    pub(super) fn cancel_tail_fetches(&self, hit: impl Fn(&str) -> bool) {
        for (id, c) in self.hub.tail_cancel.lock_ok().iter() {
            if hit(id) {
                info!(target: "lane", "{id}: stopping recovery fetches - the job was deleted");
                c.cancel();
            }
        }
    }

    /// Drop the lane's backpressure hold, and only that one.
    ///
    /// `queue_hold` is one slot shared by every reason the runner can
    /// stop picking (disk, postproc, quota), so a blind `= None` here
    /// would erase a min-free hold raised while a tail was finishing and
    /// leave the header claiming downloads are running. Kind-checked
    /// under the same lock the write takes, so there is no window
    /// between the test and the clear.
    pub(super) fn clear_postproc_hold(&self) {
        let mut h = self.queue_hold.lock_ok();
        if h.as_ref().is_some_and(|(kind, _, _)| kind == "postproc") {
            *h = None;
        }
    }
}

/// The lane task panicked (or was cancelled by a dying runtime): file
/// the job Failed with the journal untouched, so a user retry re-runs
/// the tail from what is on disk. Same contract `finalize_completed`
/// already keeps for its inner `spawn_blocking`.
fn file_crashed_tail(job: &Arc<Mutex<Job>>, e: &tokio::task::JoinError) {
    warn!(target: "lane", "post-processing task died: {e}");
    let mut j = job.lock_ok();
    j.state = JobState::Failed;
    j.fail_message = crate::with_build(
        "post-processing crashed (internal error) - retry the job to re-run it".to_string(),
    );
    j.finished_at = Some(Instant::now());
    j.finished_unix = Some(unix_now());
}

/// The tail itself: a verbatim move of the worker's old inline closure
/// (tasks.rs `run_worker`), with the captured state read off the ticket.
/// Runs settle-result filing, the suspended/park-on-full-disk arms,
/// verdict + stats onto the record, `finalize_completed`, hooks, `park`.
pub(super) async fn run_tail(d2: Arc<Daemon>, t: PostprocTicket) {
    let PostprocTicket {
        job: job2,
        fetch,
        verifier,
        shaper,
        log_mark,
        dl_bytes,
        dl_secs,
        on_disk_bytes,
        index_job_guard,
    } = t;
    let _index_job_guard = index_job_guard;
    let res = match fetch.await {
        Ok(r) => r,
        Err(e) => Err(anyhow::anyhow!("download task panicked: {e}")),
    };
    // The download is over: hand the operating system back
    // every output file descriptor before anything else runs.
    //
    // `Extractor::finish` deliberately KEEPS its writers open
    // (see `park_outputs`), and the hub leaves the extractor
    // installed until the NEXT job starts - so on an idle
    // daemon a finished job's handles are held indefinitely.
    // On unix an unlinked file with a live descriptor keeps
    // its blocks, and unlinking those files is exactly what
    // happens after a download: cleanup deletes the volumes,
    // then an *arr imports the release and removes the
    // folder. The space never came back, the folder would not
    // delete over a share that cannot remove an open file,
    // and restarting the daemon was the only cure (reported
    // on Unraid, 2 Aug). A FAILED or paused job holds its
    // partial volumes open just as long, so this sits above
    // every exit path below rather than in the completed arm.
    //
    // Parking, not clearing: the extractor stays installed,
    // so the shape/CRC latch below and `writers_snapshot`
    // keep working. Nothing that serves bytes needs these
    // handles - `serve_range` opens the path itself, and a
    // finished job streams from disk through
    // `find_completed_media` - and the sweeps and renames in
    // `finalize_completed` are happier with them closed.
    if let Some(ex) = &shaper
        && let Err(e) = ex.park_outputs()
    {
        warn!(target: "cleanup", "could not release the output handles: {e}");
    }
    // M23e: a pause aborted this job - put it back in the
    // queue (not history) so resume continues it from the
    // journal. If it somehow completed despite the abort,
    // fall through and file it normally.
    let was_suspended = {
        let g = job2.lock_ok();
        g.suspended && !g.tombstone
    };
    if was_suspended && res.is_err() {
        {
            let mut j = job2.lock_ok();
            j.state = JobState::Queued;
            j.suspended = false;
            // What is on disk, not what this run fetched:
            // the queue row reports its percentage from this
            // while paused, and a job paused twice would
            // otherwise report only the second stint. It was
            // not recorded here at all - a paused row read
            // 0% with the full size still to go, which is
            // the exact reading that has users deleting a
            // job whose journal is intact.
            j.downloaded_bytes = on_disk_bytes;
            info!(
                target: "pause",
                "{} parked back in the queue ({:.2} GB already on disk)",
                j.nzo_id,
                on_disk_bytes as f64 / 1e9
            );
        }
        d2.save_queue();
        return;
    }
    job2.lock_ok().suspended = false;
    // Mid-download disk full: park under the min-free hold
    // instead of failing - see `park_on_full_disk`.
    if park_on_full_disk(&d2, &job2, res.as_ref().err(), on_disk_bytes).await {
        return;
    }
    let demoted = {
        let mut j = job2.lock_ok();
        match &res {
            Ok(_) => {
                j.state = JobState::Completed;
                j.fetched = true;
            }
            Err(e) => {
                j.state = JobState::Failed;
                j.fail_message = e.to_string();
                // TODO §77: fold the pre-flight sample into
                // the failure evidence. "It was already
                // short when you added it" and "it rotted
                // out from under the download" call for
                // different things - a replacement from the
                // indexer versus a retry - and after the
                // fact nothing else can tell them apart.
                //
                // APPENDED, never prefixed: `fail_kind`, the
                // *arr health mapping and the diag tests all
                // key on the opening clause, exactly as the
                // segment census does in `incomplete_reason`.
                if let Some(h) = j.health.as_ref()
                    && crate::serve::fail_kind(&j.fail_message).post_unavailable()
                    && let Some(clause) = crate::health::failure_clause(h)
                {
                    j.fail_message.push_str(&clause);
                }
                // A disk that filled up during the unpack is
                // the one failure where the fix is entirely
                // in the user's hands and the cost of the
                // retry is near zero: the spent-volume sweep
                // only removes volumes after a SUCCESSFUL
                // extraction, so the downloaded parts are
                // still on disk and mode=retry resumes from
                // the article journal without re-fetching a
                // byte. Say so, with the amount to free -
                // the extracted payload is roughly the size
                // of the set. APPENDED, same rule as the
                // health clause above.
                // Not for the mid-download halt: its verdict
                // already says the fetch resumes from the
                // journal, and "only the unpack re-runs"
                // would be flatly wrong for it.
                if crate::serve::disk_full_failure(&j.fail_message)
                    && !crate::serve::disk_full_mid_download(&j.fail_message)
                {
                    let clause = format!(
                        "; free about {:.1} GB on that disk and hit Retry - the downloaded archive parts are kept, so nothing is re-downloaded and only the unpack re-runs",
                        j.total_bytes as f64 / 1e9
                    );
                    j.fail_message.push_str(&clause);
                }
                // Keep the console block that explains the
                // one-liner. Failures are where a user
                // needs the log MOST and where it is least
                // likely to still be there when they look.
                j.fail_detail = crate::fail_detail_snapshot(log_mark);
            }
        }
        j.downloaded_bytes = dl_bytes;
        j.elapsed_secs = dl_secs;
        // A verdict only where something actually verified.
        // `live_counts()` is (ok + bad, bad): no verifier at
        // all (par2-less post) and a verifier that mapped
        // nothing (the resume case) both check zero blocks,
        // and neither is evidence the payload is clean. Keep
        // an earlier run's verdict rather than overwriting it
        // with "unknown" - a retry that maps nothing in
        // stream must not erase what the first pass proved.
        let (checked, bad) = verifier.as_ref().map_or((0, 0), |v| v.live_counts());
        if checked > 0 {
            j.bad_blocks = Some(bad);
            j.verify_blocks = checked;
        }
        // Latch the shape for history. Keep whatever a
        // previous run learned if this one recognized
        // nothing (a resume maps nothing in-stream, and
        // reporting "no archive" for a retried RAR5 set
        // would be a downgrade, not an update).
        if let Some(tag) = shaper.as_ref().and_then(|e| e.archive_shape()) {
            j.archive_shape = tag.tag();
        }
        // Same latch-don't-downgrade rule, same reason:
        // a resumed run maps nothing in-stream, and the
        // headers this key came from are not on disk to
        // read again.
        if let Some((_, crc)) = shaper.as_ref().and_then(|e| e.inner_crc()) {
            j.inner_crc = crc;
        }
        j.finished_at = Some(Instant::now());
        j.finished_unix = Some(unix_now());
        // A demotion only HAPPENED if the watchdog's abort
        // actually took the download down. When the flag
        // loses the race with the finish line the job is a
        // plain completion: it gets its hooks below, and
        // park files it to history (clearing the flag)
        // instead of re-queueing a finished release.
        res.is_err() && j.demote
    };
    // Feed the watchdog's reference: every job's average
    // network rate is an observed "the line can do this"
    // sample (short bursts are too noisy to count).
    if dl_secs >= 0.5 && dl_bytes > 0 {
        let avg = (dl_bytes as f64 / dl_secs) as u64;
        d2.best_rate_bps.fetch_max(avg, Ordering::Relaxed);
    }
    finalize_completed(&d2, &job2).await;
    // A watchdog demotion is not a completion - no
    // script and no notification; park() requeues it
    // deferred.
    if !demoted {
        d2.run_post_job_hooks(&job2);
    }
    d2.park(job2);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_daemon(name: &str, f: impl FnOnce(&Arc<Daemon>)) {
        let dir = std::env::temp_dir().join(format!("nzbfast-lane-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let d = crate::serve::testutil::test_daemon(&dir);
        f(&d);
        drop(d);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The delete arms reach the right job's recovery fetches and only
    /// that job's. The registry is keyed by owning nzo_id precisely
    /// because the hub's own abort handles are not - aiming a cancel at
    /// the wrong job is the hazard `owns_hub` exists for, and this
    /// registry must not reintroduce it under a new name.
    #[test]
    fn cancel_tail_fetches_hits_the_named_owner_only() {
        with_daemon("cancel", |d| {
            let mine = Arc::new(crate::repair::SideCancel::new());
            let other = Arc::new(crate::repair::SideCancel::new());
            {
                let mut m = d.hub.tail_cancel.lock_ok();
                m.insert("SABnzbd_nzo_mine".to_string(), mine.clone());
                m.insert("SABnzbd_nzo_other".to_string(), other.clone());
            }
            d.cancel_tail_fetches(|id| id == "SABnzbd_nzo_mine");
            assert!(mine.is_cancelled(), "the deleted job's fetches stop");
            assert!(
                !other.is_cancelled(),
                "a job nobody deleted keeps fetching - this is the owns_hub hazard"
            );

            // An id with no registration (a queued job that never ran, a
            // job already parked) is skipped, never a panic.
            d.cancel_tail_fetches(|id| id == "SABnzbd_nzo_ghost");

            // "all" reaches everything, which is what a delete-all asks
            // for.
            d.cancel_tail_fetches(|_| true);
            assert!(other.is_cancelled());
        });
    }

    /// The drain-side clear is kind-scoped. `queue_hold` is one slot for
    /// every guard, so the interesting case is not "does it clear its
    /// own" but "does it leave the others alone" - a tail parking while
    /// the disk guard holds the queue must not report the queue running.
    #[test]
    fn clear_postproc_hold_takes_only_its_own_kind() {
        with_daemon("hold", |d| {
            *d.queue_hold.lock_ok() = Some(("postproc".into(), 4.0, 4.0));
            d.clear_postproc_hold();
            assert!(d.queue_hold.lock_ok().is_none(), "its own hold clears");

            *d.queue_hold.lock_ok() = Some(("disk".into(), 1.5, 20.0));
            d.clear_postproc_hold();
            assert_eq!(
                d.queue_hold.lock_ok().as_ref().map(|(k, ..)| k.clone()),
                Some("disk".to_string()),
                "a min-free hold raised while a tail finished must survive"
            );

            *d.queue_hold.lock_ok() = Some(("quota".into(), 50.0, 50.0));
            d.clear_postproc_hold();
            assert_eq!(
                d.queue_hold.lock_ok().as_ref().map(|(k, ..)| k.clone()),
                Some("quota".to_string()),
                "so must a quota hold"
            );

            // Nothing held: still a no-op, never a panic.
            *d.queue_hold.lock_ok() = None;
            d.clear_postproc_hold();
            assert!(d.queue_hold.lock_ok().is_none());
        });
    }
}

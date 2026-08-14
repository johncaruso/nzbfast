//! How a job stops running (TODO 106 code motion out of daemon.rs).
//!
//! One subject end to end: whether a failure will re-arm itself
//! (`will_auto_retry`), the failure report the queue row and the *arr
//! see (`report_failure`), aborting a prefetch sidecar that was serving
//! it (`poke_sidecar`), quarantining payload a delete must not silently
//! destroy (`note_delete_kept`/`save_delete_kept`), parking the job into
//! history (`park`, the big one), noticing the queue has gone quiet
//! (`note_queue_idle`) and persisting the give-up ledger
//! (`save_giveup`).
//!
//! A second `impl Daemon` in a child module of `daemon`, on the
//! daemon_index shape, for the same reasons as daemon_persist.rs -
//! including `pub(super)` becoming `pub(in crate::serve)`, which is what
//! the ORIGINAL visibility meant here and what every existing call site
//! across serve/ still needs.

use super::*;

impl Daemon {
    /// Will [`park`](Daemon::park) arm an M32 automatic retry for this
    /// job? See [`auto_retry_eligible`], which both this and the hook
    /// planner share so they cannot drift (they already did once - see
    /// [`fail_kind`]).
    pub(in crate::serve) fn will_auto_retry(&self, job: &Arc<Mutex<Job>>) -> bool {
        let secs = self.auto_retry_secs.load(Ordering::Relaxed);
        auto_retry_eligible(&job.lock_ok(), secs)
    }

    /// Tell the indexer this download failed, and queue the replacement
    /// it offers - NZBGet's FailureLink, natively.
    ///
    /// An indexer that sends `X-DNZB-Failure` is offering two things at
    /// one URL: a failure report (which is how it learns a post is dead,
    /// and how the next person is spared it) and, in the response body,
    /// another NZB for the same title. `failure_link` chooses how far to
    /// go: "report" sends the report and stops, "regrab" also queues what
    /// comes back. Off by default - it tells a third party what failed
    /// for you, which is a reasonable thing to want and not a reasonable
    /// default.
    ///
    /// A 404, an empty body, or anything that isn't XML means the
    /// indexer has nothing else, which is the ordinary outcome and not an
    /// error. Blocking: call from the blocking pool.
    pub(in crate::serve) fn report_failure(&self, job: &Arc<Mutex<Job>>) {
        let mode = self.failure_link.lock_ok().clone();
        if mode == "off" {
            return;
        }
        let (link, depth, name, cat, priority, pp, password) = {
            let j = job.lock_ok();
            // A job the user DELETED owes the outside world nothing, and
            // least of all a dead-post report for a post that is not dead.
            if j.state != JobState::Failed || j.tombstone || j.failure_link.is_empty() {
                return;
            }
            // Only a post-unavailability failure is news the indexer can
            // act on. A full disk, a permission error or an unpack that
            // fell over says nothing about the post - reporting it marks
            // a healthy release dead for every other user of that indexer
            // and, under `regrab`, spends bandwidth replacing it.
            if !fail_kind(&j.fail_message).post_unavailable() {
                info!(
                    target: "failurelink",
                    "{}: not reported - {} is a local fault, not a dead post",
                    j.name, j.fail_message
                );
                return;
            }
            if !failure_link_allowed(&j.failure_link, &j.failure_host, j.failure_https) {
                warn!(
                    target: "failurelink",
                    "{}: refusing {} - it does not point back at {} (the indexer that supplied it)",
                    j.name,
                    // The X-DNZB-Failure endpoint is the indexer's own URL and
                    // carries its key - and this line fires exactly on a host
                    // mismatch, which in practice is an indexer serving the
                    // link from a CDN alias with ?apikey= attached. stdout is
                    // not private (logtee mirrors it into mode=log, the
                    // JSON-RPC log methods and `docker logs`), so redact here
                    // like the accept path below already does.
                    redact_url_creds(&j.failure_link),
                    if j.failure_host.is_empty() {
                        "the origin"
                    } else {
                        &j.failure_host
                    }
                );
                return;
            }
            let (cat, priority, password) = replacement_inherits(&j);
            (
                j.failure_link.clone(),
                j.failure_depth,
                j.name.clone(),
                cat,
                priority,
                // The pp the failed job's add asked for: the replacement
                // is the same request re-made, so the pre-queue hook
                // sees the same mode.
                j.sab_pp,
                password,
            )
        };
        let regrab = may_regrab(&mode, depth);
        if mode == "regrab" && !regrab {
            info!(target: "failurelink", "{name}: {depth} replacements already tried - reporting only");
        }
        // In `report` mode the report IS the GET: nothing reads the
        // response, a 404 counts as success, and there is no reason to
        // pull a body down (let alone a large one) only to drop it.
        let fetched = match if regrab {
            fetch_url(&link).map(Some)
        } else {
            ping_url(&link)
        } {
            Ok(f) => f,
            // 404 is the indexer saying "nothing else for that title".
            Err(e) => {
                let s = e.to_string();
                if s.contains("404") {
                    info!(target: "failurelink", "{name}: reported, no other release available");
                } else {
                    // Same reason as the watch leg above: the X-DNZB-Failure
                    // endpoint is the indexer's own URL and carries the key.
                    warn!(target: "failurelink", "{name}: {}", redact_url_creds(&s));
                }
                return;
            }
        };
        let Some(fetched) = fetched else {
            info!(target: "failurelink", "{name}: failure reported to the indexer");
            return;
        };
        if !is_nzb_body(&fetched.bytes) {
            info!(target: "failurelink", "{name}: reported, no other release available");
            return;
        }
        // Our category, always: it selects the output subfolder, the
        // library flag and the move-completed destination, so taking the
        // one out of the (untrusted) response would let the indexer pick
        // which of the user's destinations the payload lands in.
        match self.enqueue_fetched(
            &fetched,
            &format!("{name}.nzb"),
            &cat,
            priority,
            pp,
            password.as_deref(),
            depth + 1,
            // A failure-link replacement inherits nothing useful from the
            // failed job, but "we picked this for you" is worth saying.
            "failure-link",
            false,
        ) {
            Ok(id) => info!(target: "failurelink", "{name}: queued a replacement ({id})"),
            Err(e) => warn!(target: "failurelink", "{name}: replacement was not usable: {e}"),
        }
    }

    /// Abort of the prefetch sidecar when a user op removes or pauses the
    /// job it holds (sync handler contexts - the task winds down on its
    /// own; the runner's stop_sidecar await covers pipeline handover).
    ///
    /// Fires inline and then RE-FIRES until the sidecar is actually gone,
    /// for the same reason suspend_matching does: `get_with_progress`
    /// installs the hub's abort and queue-ctl handles asynchronously after
    /// launch, so a single signal that lands in the gap finds both slots
    /// empty and no-ops. `cancelled` is not a safety net there either - the
    /// task reads it once, before the transfer starts, and is then parked
    /// inside the pipeline with nothing left to re-check it.
    ///
    /// That gap was reachable and it lost data-plane work: deleting a job
    /// mid-prefetch removed it from the queue and kept it out of history
    /// (both correct) while the transfer ran to completion, spending
    /// provider quota on a job the user had explicitly deleted and leaving
    /// the finished files in the output directory. Caught by
    /// `jsonrpc_delete_stops_a_prefetching_job`, which failed on
    /// "the delete did not stop the prefetch" roughly 1 run in 40 in
    /// release - the whole reason that assertion exists.
    pub(in crate::serve) fn poke_sidecar(self: &Arc<Self>, hit: impl Fn(&str) -> bool) {
        // Inline first, so the transfer is already stopping by the time the
        // delete/pause API call returns.
        let Some(id) = self.fire_sidecar_abort(&hit) else {
            return;
        };
        let d = self.clone();
        std::thread::spawn(move || {
            // Bounded like the pause re-fire: 60 s is far longer than the
            // handles take to attach, and the loop exits the moment the
            // sidecar slot is empty or holds a different job.
            for _ in 0..240 {
                std::thread::sleep(std::time::Duration::from_millis(250));
                if d.fire_sidecar_abort(&|s: &str| s == id).is_none() {
                    return;
                }
            }
        });
    }

    /// One abort signal at the current sidecar, if `hit` accepts it.
    /// Returns the nzo_id it fired at, or None when there is nothing to
    /// fire at - which is how the re-fire loop above knows to stop.
    fn fire_sidecar_abort(&self, hit: &impl Fn(&str) -> bool) -> Option<String> {
        let sc = self.sidecar.lock_ok();
        let sc = sc.as_ref().filter(|s| hit(&s.nzo_id))?;
        sc.cancelled.store(true, Ordering::Relaxed);
        if let Some(f) = sc.hub.abort.lock_ok().as_ref() {
            f.store(true, Ordering::Relaxed);
        }
        if let Some(c) = sc.hub.queue_ctl.lock_ok().as_ref() {
            c.abort();
        }
        Some(sc.nzo_id.clone())
    }

    /// Record a delete that removed the RECORD but not the FILES, for the
    /// dashboard's kept-files notice.
    ///
    /// Every delete-with-files path ends here on a [`FilesGone::Kept`],
    /// and the reason is the same one each time: the user asked for
    /// recoverable deletes, no Trash would take the path, and we now
    /// leave the download alone rather than destroying it (70990f19).
    /// That was the right call and it opened this hole - the queue row or
    /// history row goes regardless, so the only handle the user had on a
    /// folder that is still sitting there is the thing the delete removed,
    /// and a `warn!` in a log they will never open is not telling them.
    ///
    /// The path is the replacement handle, which is why it is stored
    /// rather than the id: they cannot open a record that no longer
    /// exists, but they can go and look at the folder.
    pub(in crate::serve) fn note_delete_kept(&self, name: &str, path: &std::path::Path, why: &str) {
        {
            let mut k = self.delete_kept.lock_ok();
            let path = path.display().to_string();
            // One entry per path. A bulk history sweep over a shared season
            // folder refuses once per record, and a dozen identical rows
            // would bury the one thing the notice has to say.
            if k.iter().any(|(_, p, _, _)| *p == path) {
                return;
            }
            k.push_back((name.to_string(), path, why.to_string(), unix_now()));
            while k.len() > 12 {
                k.pop_front();
            }
        }
        self.save_delete_kept();
    }

    /// Persist the kept-files notices to `.spool/delete-kept.json`.
    ///
    /// This ring is not a moment that scrolls past like the ones beside
    /// it - it is the REPLACEMENT handle on a folder whose history row
    /// was just deleted, and it stays on screen until dismissed. Held
    /// only in memory it did not survive a restart, which includes the
    /// auto-updater's own restart and `restart_daemon` from the settings
    /// UI: the row was already gone, so the user was left with the exact
    /// state the notice exists to prevent - a folder still eating disk,
    /// named by nothing anywhere. The deferred `park()` refusal has no
    /// response to ride back on at all, so for that path this is the
    /// only channel there is.
    pub(in crate::serve) fn save_delete_kept(&self) {
        let path = self.spool.join("delete-kept.json");
        // The lock is held ACROSS the write, not just around a snapshot.
        // Snapshotting and then writing lets two writers land in the
        // opposite order to the states they carry: a refusal snapshots
        // [X, Y] and is preempted, the user dismisses X and its write of
        // [Y] completes, then the first write lands [X, Y] - and the next
        // restart resurrects the notice the user just cleared, which is
        // the one thing persisting the dismissal exists to prevent.
        // Safe to hold: `write_atomic` takes no other lock of ours, and
        // this mutex is a leaf (never acquired while queue/history are
        // held - both delete arms record after dropping them).
        let kept = self.delete_kept.lock_ok();
        if let Ok(text) = serde_json::to_string_pretty(&*kept) {
            let _ = crate::persist::write_atomic(&path, text.as_bytes());
        }
    }

    /// Park a finished job in history (NZBGet-style: failures are parked,
    /// not lost - mode=retry sends them back through the queue and the
    /// journal resumes from what already landed).
    pub(in crate::serve) fn park(&self, job: Arc<Mutex<Job>>) {
        /// Was this held row held against the job that just failed?
        ///
        /// The `dupe_key` filter alone asks "same title", which is what
        /// `smart` admission judges on and is therefore the same
        /// question there. Under `dupe_scope = "exact"` it is NOT: a
        /// different release of the same episode is admitted and runs,
        /// so its failure promoted rows held against a still-completed
        /// original (Codex sweep K). An empty `held_for` is a row from
        /// before the field existed and keeps the old behaviour.
        fn held_against(g: &Job, failed_id: &str) -> bool {
            g.held_for.is_empty() || g.held_for == failed_id
        }
        let (id, failed, key, demote) = {
            let g = job.lock_ok();
            (
                g.nzo_id.clone(),
                g.state == JobState::Failed,
                g.dupe_key.clone(),
                g.demote,
            )
        };
        // The active-download delete deferred its file removal to here: by
        // now the fetch has drained and no writer can recreate the dir. A
        // tombstoned job is dropped (not filed to history), so its spooled
        // .nzb is dead weight too - remove it (history retry keeps its own).
        {
            // Snapshot what the removal needs, then RELEASE the guard
            // before touching the filesystem. Recursive deletion of a
            // whole release is slow (and on a hung NAS, unbounded), and
            // the queue -> job lock order means anyone walking the queue
            // - save_queue, pick_job, the API - would park behind this
            // one job's mutex for the duration. The job is terminal and
            // its fetch has drained, so nothing rewrites these fields
            // between the snapshot and the removal.
            let (del, gone_nzb) = {
                let g = job.lock_ok();
                let del = g.del_on_drop.then(|| {
                    (
                        delete_tail(&g, || self.job_suffix(filed_stem(&g))),
                        g.out_dir.clone(),
                        filed_stem(&g).to_string(),
                        g.filed,
                    )
                });
                (del, g.tombstone.then(|| g.nzb_path.clone()))
            };
            if let Some((tail, out_dir, stem, filed)) = del {
                // The user pressed delete-with-files on a LIVE download
                // and this is where it finally happens, long after the
                // request answered - so a refusal here has no response
                // left to ride back on, and the notice is the only way it
                // reaches them at all.
                if let FilesGone::Kept(why) = remove_job_files(&out_dir, &stem, filed, &tail) {
                    self.note_delete_kept(&stem, &out_dir, &why);
                }
                // The other end of the reservation the delete took when
                // it set this flag: the directory is only safe to hand
                // out once its files are actually gone.
                self.reserved.lock_ok().remove(&out_dir);
            }
            if let Some(nzb) = gone_nzb {
                let _ = std::fs::remove_file(&nzb);
            }
        }
        // The job's queue-row activity dies with the row.
        self.hub.activity.lock_ok().remove(&id);
        // §129: so does its recovery-fetch cancel handle. Same key, same
        // place, same reason - the tail is over, and neither map may
        // outgrow the queue.
        self.hub.tail_cancel.lock_ok().remove(&id);
        // Read LIVE, not from the snapshot above: everything between the two
        // is unlocked, and file removal is slow. A queue or JSON-RPC delete
        // landing in that window used to be decided against a stale
        // `tombstone == false`, so the deleted job was requeued (demote arm),
        // filed into history, or had an alternative promoted for a cancel the
        // user had just made. Every terminal branch below re-reads it.
        let tombstone = job.lock_ok().tombstone;
        // Watchdog demotion: back into the queue (deferred, at the end)
        // instead of history - the abort was ours, not a failure. The
        // journal keeps everything already landed, so the eventual rerun
        // fetches only what's still missing.
        // `!tombstone`: a deleted job stays deleted. Both flags together is
        // an ordinary race - the slow-job watchdog demotes at T, the user (or
        // an *arr) deletes at T+ε - and the demote arm used to win, pushing
        // the just-deleted job back onto the queue with its payload removed
        // and its spooled .nzb already unlinked above. It then reappeared in
        // the *arr, ran, and failed.
        // `failed`: the demotion only counts if its abort actually took the
        // download down. The watchdog's abort can lose the race with the
        // finish line - it once fired at a job whose network had already
        // drained (see the runner's stand-down at net-drain) - and a stale
        // flag on a job that went on to COMPLETE must not send it back
        // through the queue: post-processing has renamed its directory by
        // now, so the "rerun" was a full second download of a finished
        // release into the renamed folder (the 31 Jul queue soak).
        if demote_requeues(demote, tombstone, failed) {
            {
                let mut g = job.lock_ok();
                g.state = JobState::Queued;
                g.fail_message.clear();
                // The evidence goes with the verdict it explained - a
                // re-queued job that fails again captures its own.
                g.fail_detail.clear();
                g.finished_at = None;
                g.finished_unix = None;
                g.demote = false;
                g.deferred = true;
                g.defer_count += 1;
            }
            // §158.7: the row leaves and rejoins the queue under ONE hold
            // of the lock. It used to be dropped near the top of `park` and
            // pushed back here, and a demoted job has no history copy to
            // fall back on, so any other thread's save inside that gap
            // published a queue.json while NO store held the record. The
            // coalescing saver widened that: the write now happens on the
            // saver thread, off a live queue this park had already emptied.
            {
                let mut q = self.queue.lock_ok();
                q.retain(|j| j.lock_ok().nzo_id != id);
                q.push_back(job);
            }
            self.save_queue_soon();
            return;
        }
        // §158 item 1: claim the queue -> history move before ANY of it is
        // durable, so every copy this park writes carries the higher
        // `move_seq` and the queue.json rewrite at the end is the only
        // write left holding the lower one. A kill between them leaves a
        // stale nonterminal queue row beside the terminal history one, and
        // the counter is what tells `load_queue` that the history copy is
        // where the job was heading rather than where it happened to be.
        //
        // Ahead of `park_prewrite`, not beside the `history_upsert` lower
        // down: §158.7 made the prewrite the FIRST durable history write,
        // so stamping after it filed an unstamped row and left the tear
        // reading as a tie. The demote arm has already returned by here,
        // so a requeued job is never stamped; a tombstoned one is stamped
        // and dropped, which is inert because it reaches neither store.
        moveseq::stamp_move(&job);
        // Q2: from the prewrite until the record is filed into
        // `self.history` below, its only durable copy is the disk row the
        // prewrite is about to append - and `history_compact` snapshots
        // MEMORY. The guard keeps the id registered for the whole
        // interval so a concurrent compaction ("Save queue" runs one on
        // a live daemon) carries the disk row into its snapshot instead
        // of erasing it.
        let _inflight = self.hist_inflight_begin(&id);
        // §158.7: the DESTINATION store FIRST, before the row leaves the
        // live queue - `park_prewrite` carries the why, and the demote arm
        // above is why it has to know about the tombstone.
        let filed_early = self.park_prewrite(&job, tombstone);
        self.queue.lock_ok().retain(|j| j.lock_ok().nzo_id != id);
        // The harness's window: the row has just left the queue and every
        // store write park still owes is ahead of it.
        #[cfg(test)]
        super::storecut::park_gap(self);
        if demote {
            // The flag outlived a download that finished anyway (or a
            // tombstone). Scrub it before the record reaches history, or a
            // later retry of this job carries it back here and the arm
            // above requeues that retry's park unconditionally.
            job.lock_ok().demote = false;
        }
        // M32: a FIRST failure with missing articles gets ONE
        // automatic retry after a cooldown - propagation lag is a real
        // cause of missing articles that clears on its own, and the
        // journal makes the rerun fetch only what's still missing. Only
        // transient shapes qualify: password and takedown verdicts don't.
        //
        // The predicate itself is `will_auto_retry`, shared with
        // `run_post_job_hooks` so the report/re-grab side and the
        // duplicate promotion below agree with what actually happens here.
        let armed_auto_retry = self.will_auto_retry(&job);
        if armed_auto_retry {
            let secs = self.auto_retry_secs.load(Ordering::Relaxed);
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            // What we are waiting FOR decides both the delay and what
            // to call it. Propagation filling in missing articles takes
            // real time; a pool that stalled on this machine has nothing
            // to wait for at all, and the old copy told the user to sit
            // out 20 minutes for a propagation that was never the
            // problem.
            let kind = fail_kind(&job.lock_ok().fail_message);
            let (secs, why, token) = match kind {
                FailKind::Transport => (
                    secs.min(SHORT_RETRY_SECS),
                    "connection trouble, not missing articles - retrying shortly",
                    RETRY_WHY_TRANSPORT,
                ),
                _ => (
                    secs,
                    "articles missing - propagation may fill them",
                    RETRY_WHY_PROPAGATION,
                ),
            };
            {
                let mut g = job.lock_ok();
                g.auto_retry_at = Some(now + secs);
                // Beside the stamp, because the delay above was chosen
                // from it: the drawer says "2 minutes, because this was
                // the link and not the post" in the user's own language,
                // which needs the reason as a token and not as this
                // English log line.
                g.auto_retry_why = Some(token.to_string());
            }
            info!(
                target: "retry",
                "{id}: {why}; automatic retry in {} min \
                 (resumes from the journal; only the gaps will be refetched)",
                secs.div_ceil(60)
            );
        }
        // Re-read once more: the demote arm above returns, so this is the
        // first point the history/promotion decisions are actually taken.
        let tombstone = job.lock_ok().tombstone;
        // §96.3: feed the per-target give-up breaker. Here because this
        // is where a failure becomes FINAL - a tombstone owes nobody
        // anything and an armed auto-retry means the story continues.
        if !tombstone {
            self.giveup_note_outcome(&job, armed_auto_retry);
        }
        if !tombstone {
            // C: hand the owed move over only once the record is IN
            // history - the mover looks the job up there, and it runs
            // on its own worker so this park (and the runner tail
            // behind it) never waits on a NAS copy.
            let owes_move = job.lock_ok().move_pending;
            self.history.lock_ok().push(job.clone());
            // §129 1a/1b: the record reaches its own store the moment it
            // reaches history, and the lifecycle event replaces the
            // dashboard's snapshot-diff toast inference. Then retention,
            // which is a no-op unless the optional knobs are set.
            let _ = self.history_upsert(std::slice::from_ref(&job));
            self.life_emit_parked(&job);
            self.history_enforce_retention();
            if owes_move {
                self.mover_enqueue(&job);
            }
        } else if filed_early {
            // §158.7: a delete landed INSIDE this park, after
            // `park_prewrite`. The job is dropped rather than filed, so
            // bury the row it already wrote or the next boot replays a
            // history record for the job the user cancelled.
            self.history_tombstone(std::slice::from_ref(&id));
        }
        // The original failed → promote its best held ALTERNATIVE (M14f).
        // Not while an automatic retry is armed: the original is coming
        // back through the queue in minutes, and starting the alternative
        // now downloads the same title twice. And not for a tombstone: the
        // "failure" there is the abort the user's own delete fired, so
        // promoting would start downloading the very title they cancelled.
        if failed
            && !tombstone
            && !armed_auto_retry
            && let Some(key) = key
        {
            // BEST, not first. Breaking at the first match promoted
            // whichever alternative happened to be added earliest, so
            // a 720p held before a 2160p won and the 2160p stayed
            // parked for good - the user ended up with the worst copy
            // of the three while two better ones sat in the queue.
            // Rank them the way the watchlist ranks candidates, so
            // "best" means the same thing in both places.
            // Collect the held candidates under the queue lock (a few
            // Arc + name clones), then rank them AFTER it is released:
            // parse_release is real parsing work, and running it under
            // the lock scaled with the number of held duplicates while
            // every API request waited (issue #38 follow-up).
            let candidates: Vec<(Arc<Mutex<Job>>, String)> = self
                .queue
                .lock_ok()
                .iter()
                .filter_map(|j| {
                    let g = j.lock_ok();
                    (g.priority == -3
                        && g.dupe_key.as_ref() == Some(&key)
                        && g.paused
                        && held_against(&g, &id))
                    .then(|| (j.clone(), g.name.clone()))
                })
                .collect();
            let mut best: Option<(u32, &Arc<Mutex<Job>>)> = None;
            for (j, name) in &candidates {
                let rank = crate::watchlist::quality_rank(&crate::wall::parse_release(name));
                // Ties keep the earlier-added one, which is the
                // old behaviour and is as good a tiebreak as any.
                if best.is_none_or(|(r, _)| rank > r) {
                    best = Some((rank, j));
                }
            }
            if let Some((rank, j)) = best {
                let mut g = j.lock_ok();
                // Re-check now that the queue lock has been dropped and
                // retaken a world away: a delete landing in the gap sets
                // tombstone, and promoting a just-deleted alternative
                // would start downloading the very title the user
                // cancelled.
                if g.priority == -3
                    && g.dupe_key.as_ref() == Some(&key)
                    && g.paused
                    && !g.tombstone
                    && held_against(&g, &id)
                {
                    g.paused = false;
                    g.priority = 0;
                    info!(
                        target: "queue",
                        "{} promoted (best held duplicate of failed {id}, rank {rank})",
                        g.nzo_id
                    );
                }
            }
        }
        // Coalesced: the record is already durable in history.jsonl (the
        // upsert above), and load_queue resolves a torn queue/history
        // pair in history's favour - the debounced rewrite only drops
        // the queue row.
        self.save_queue_soon();
        self.note_queue_idle();
    }

    /// §129 4a: `queue.idle`, if the queue has just become idle. Idle =
    /// nothing downloading or finishing and nothing unpaused waiting; a
    /// held ALTERNATIVE (paused by design) does not keep the queue
    /// "busy". The latch makes it a transition, said once until the next
    /// add or pick re-arms it.
    ///
    /// Every way the last runnable job can leave calls this, not just
    /// `park`. Deleting the last queued job and pausing the last
    /// runnable one both make the queue idle without a park, and until
    /// the 10 Aug sweep (M3) neither said so - the subscriber that
    /// starts a media scan or spins a disk down when the queue empties
    /// simply never heard about those two.
    pub(in crate::serve) fn note_queue_idle(&self) {
        // Latch already set = idle is already announced and nothing has
        // re-armed it, so the CAS below cannot succeed and the answer to
        // the walk is moot - return rather than take 15,000 job locks
        // under the queue lock to learn that (issue #38 residue). This
        // can only suppress an emit the CAS would have refused anyway:
        // "said once until re-armed" is decided by the latch, and the
        // walk was only ever evidence for the arming edge.
        if self.queue_idle_latch.load(Ordering::Relaxed) {
            return;
        }
        let idle = !self.queue.lock_ok().iter().any(|j| {
            let g = j.lock_ok();
            matches!(g.state, JobState::Downloading | JobState::Finishing)
                || (g.state == JobState::Queued && !g.paused)
        });
        if idle
            && self
                .queue_idle_latch
                .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            self.life_emit("queue.idle", json!({}));
        }
    }

    /// Persist the give-up counters (small, changes rarely - every
    /// terminal outcome of an automated grab at most).
    /// Persist the give-up counters (small, changes rarely - every
    /// terminal outcome of an automated grab at most).
    ///
    /// Snapshot AND write under one hold of the state lock. `write_atomic`
    /// publishes through a uniquely named temp file, so two savers that
    /// snapshot in one order can rename in the other: a tripped snapshot
    /// that stalled behind a "Try again" reset could land last and
    /// restore the trip at the next restart, with the UI still saying
    /// reset (M14, 10 Aug sweep). Holding the lock across the write
    /// costs nothing here - this file is a few hundred bytes and is
    /// written at most once per terminal grab.
    pub(in crate::serve) fn save_giveup(&self) {
        let path = self.spool.join("giveup-state.json");
        let st = self.giveup.lock_ok();
        if let Ok(text) = serde_json::to_string_pretty(&*st) {
            let _ = crate::persist::write_atomic(&path, text.as_bytes());
        }
    }
}

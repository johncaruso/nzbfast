//! The queue on disk: `.spool/queue.json` out and back again (TODO 106
//! code motion out of daemon.rs).
//!
//! One subject in two halves - `save_queue` serializes queue + history
//! under its own IO lock, `load_queue` restores them at startup and
//! re-floors the id counter so a restored record can never have its id
//! handed out twice.
//!
//! A second `impl Daemon` in a child module of `daemon`, on the
//! daemon_index shape, for the same reasons as daemon_retry.rs -
//! including `pub(super)` becoming `pub(in crate::serve)`.

use super::*;

impl Daemon {
    /// Persist queue + history to `.spool/queue.json` so a daemon restart
    /// doesn't forget the job list. Only the record is at stake: the NZB
    /// itself already lives in the spool, and each out_dir's article
    /// journal makes a resumed download fetch only what's still missing.
    /// Called after every mutation, once the queue/history locks are
    /// released. Best-effort like save_setting: a failed write must never
    /// take down a live daemon.
    ///
    /// Returns whether the record actually landed. Almost every caller is
    /// right to ignore that - the job is live in memory either way. The watch
    /// poller is not: it deletes the user's original .nzb once the job is
    /// accepted, so it needs to know the acceptance survived a restart.
    pub(in crate::serve) fn save_queue(&self) -> bool {
        // API requests run on a worker pool - serialize the writes so two
        // mutations can't interleave bytes in the file. Take the IO lock
        // BEFORE snapshotting: if the snapshot were built first, a slow
        // encoder (T1) could grab the lock after a later mutation (T2)
        // already wrote its fresher snapshot, then overwrite it with stale
        // state and lose T2's change across restart. Snapshotting under the
        // lock makes the last writer also the one holding the newest state.
        static IO: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _g = IO.lock_ok();
        let jobs: Vec<Value> = self
            .queue
            .lock_ok()
            .iter()
            .map(|j| job_json(&j.lock_ok()))
            .collect();
        // §129 1a: history is NOT here any more. It lives in its own
        // append-only store (`histstore.rs`), written by the sites that
        // actually change it - park, delete, retry, recategorize, the
        // unlock/mover bookkeeping - so an unlimited history stops
        // costing every queue mutation an O(all-time) rewrite.
        let v = json!({
            "next_id": self.next_id.load(Ordering::Relaxed),
            "queue": jobs,
        });
        // The dashboard's change handle, bumped WITH the write: a queue
        // change that should survive restart comes through here, so the
        // revision sees it by construction.
        self.queue_rev.fetch_add(1, Ordering::Relaxed);
        let path = self.spool.join("queue.json");
        match serde_json::to_string_pretty(&v) {
            Ok(text) => match crate::persist::write_atomic(&path, text.as_bytes()) {
                Ok(()) => true,
                Err(e) => {
                    error!(target: "queue", "persist {}: {e}", path.display());
                    false
                }
            },
            Err(e) => {
                error!(target: "queue", "serialize: {e}");
                false
            }
        }
    }

    /// Reload `.spool/queue.json` at startup, re-creating the Job records.
    /// Wall-clock floor (seconds since the Unix epoch) for the RESTORED
    /// id allocator. The snapshot's `next_id` can be stale when the run
    /// that allocated past it could not persist (disk full at enqueue),
    /// and those already-issued ids carry permanent stream tokens - so
    /// a restore must never let allocation fall back behind real time.
    /// Only applied on restore: a fresh daemon with no state keeps its
    /// small ids (and has no earlier run to collide with unless
    /// persistence never worked at all, which startup now warns about).
    fn id_floor() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// A job that was Downloading when the daemon stopped comes back
    /// Queued, so the scheduler restarts it and its journal resumes the
    /// transfer.
    pub(in crate::serve) fn load_queue(&self) {
        // Before anything reads a job's out_dir: put back a download that
        // an interrupted replace left in limbo.
        recover_interrupted_publishes(&self.out_dir());
        let path = self.spool.join("queue.json");
        // A torn/corrupt file falls back to the .bak of the last good
        // parse - never "start empty" and let the next save_queue make
        // the loss permanent.
        // §129 1a: history has its own store now. Replay it FIRST so the
        // legacy-migration merge below can prefer the newer layout when
        // both name an id (a crash between the split's two writes).
        let (stored_hist, wants_compaction) = self.history_replay();
        let (v, mut legacy_hist) = match crate::persist::load_json_with_backup(&path) {
            Some(v) => {
                let legacy = v
                    .get("history")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                (Some(v), legacy)
            }
            None => (None, Vec::new()),
        };
        // Records already living in history.jsonl win over their legacy
        // queue.json copies - the split happened, then something wrote
        // history.jsonl, then the queue.json rewrite was lost.
        legacy_hist.retain(|r| {
            r.get("nzo_id")
                .and_then(Value::as_str)
                .is_none_or(|id| !stored_hist.iter().any(|j| j.nzo_id == id))
        });
        let migrating = !legacy_hist.is_empty();
        let queue_arr = v
            .as_ref()
            .and_then(|v| v.get("queue"))
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let (queued, from_file) = restore_records(&queue_arr, &legacy_hist);
        // `from_file` is the legacy history records plus any terminal
        // records restore_records routed OUT of the queue array
        // (interrupted post-processing). Order for the final Vec, oldest
        // first: legacy array, then the store's records, then the routed
        // ones (they finished last, mid-shutdown). A routed record whose
        // park already reached history.jsonl before the crash keeps the
        // store's copy.
        let legacy_ids: std::collections::HashSet<String> = legacy_hist
            .iter()
            .filter_map(|r| r.get("nzo_id").and_then(Value::as_str))
            .map(str::to_string)
            .collect();
        let (legacy_part, routed): (Vec<Job>, Vec<Job>) = from_file
            .into_iter()
            .partition(|j| legacy_ids.contains(&j.nzo_id));
        let routed: Vec<Job> = routed
            .into_iter()
            .filter(|j| !stored_hist.iter().any(|s| s.nzo_id == j.nzo_id))
            .collect();
        let routed_any = !routed.is_empty();
        let mut history = legacy_part;
        history.extend(stored_hist);
        history.extend(routed);
        // Cross-store reconciliation. A queue -> history move is two
        // independent durable writes - park appends and fsyncs the terminal
        // history row, then `save_queue` rewrites queue.json without it -
        // and a kill between them leaves the SAME nzo_id in both files. The
        // queue copy is nonterminal (Finishing), `job_wire` restores a
        // nonterminal row as Queued, and nothing deduplicated the two: the
        // job then showed as Queued AND Failed, and the queued copy
        // downloaded the whole release again (Codex sweep 12 Aug F1).
        //
        // History wins. It is the store that was written FIRST on that path
        // and it holds the terminal verdict, so its record is the newer
        // fact; the queue row is a snapshot the rewrite never got to
        // replace. The two history -> queue paths (retry, library-stream
        // activation) are ordered to agree with this rule: they save the
        // queue BEFORE tombstoning, so their torn state is "still in
        // history", which this resolves the same way - back in history,
        // retryable, never lost and never running twice.
        //
        // `routed` above is the same rule applied to records restore_records
        // moved out of the queue array; this covers the ones it leaves in
        // it, which is the case that could still run.
        let hist_ids: std::collections::HashSet<&str> =
            history.iter().map(|j| j.nzo_id.as_str()).collect();
        let before = queued.len();
        let queued: Vec<Job> = queued
            .into_iter()
            .filter(|j| !hist_ids.contains(j.nzo_id.as_str()))
            .collect();
        if queued.len() != before {
            warn!(
                target: "queue",
                "{} queued record(s) were also in history - a restart caught a \
                 queue/history move half-written; keeping the history copy",
                before - queued.len()
            );
        }
        let (nq, nh) = (queued.len(), history.len());
        for job in queued {
            self.register_cat(&job.category);
            self.queue.lock_ok().push_back(Arc::new(Mutex::new(job)));
        }
        for job in history {
            self.register_cat(&job.category);
            self.history.lock_ok().push(Arc::new(Mutex::new(job)));
        }
        let v = match v {
            Some(v) => v,
            None => {
                // No queue.json at all, but maybe a history store.
                if wants_compaction {
                    self.history_compact();
                }
                self.history_enforce_retention();
                if nh > 0 {
                    info!(target: "queue", "restored {nh} history jobs");
                }
                return;
            }
        };
        if let Some(n) = v.get("next_id").and_then(Value::as_u64) {
            // Never reuse an id - SABnzbd clients key on nzo_id uniqueness,
            // and stream tokens are H(secret, nzo_id): a reused id would
            // hand a previous job's permanent capability URL to a NEW job.
            // The persisted allocator alone cannot guarantee that (the
            // snapshot write is best-effort and an enqueue whose snapshot
            // failed already returned its id and token), so the wall-clock
            // floor below keeps allocations ahead of any earlier run's
            // even when its snapshots never landed.
            let cur = self.next_id.load(Ordering::Relaxed);
            self.next_id
                .store(n.max(cur).max(Self::id_floor()), Ordering::Relaxed);
        }
        // The one-time split, and the store's own housekeeping. Compact
        // FIRST (it writes every live record, so migrated and routed
        // rows land in history.jsonl), then rewrite queue.json without
        // its history array - in that order, so a crash between the two
        // duplicates records into both files (deduped above on the next
        // boot) rather than losing them from both.
        if migrating || routed_any || wants_compaction {
            self.history_compact();
        }
        if migrating {
            self.save_queue();
            info!(
                target: "queue",
                "history moved out of queue.json into its own store ({} records)",
                nh
            );
        }
        self.history_enforce_retention();
        if nq + nh > 0 {
            info!(target: "queue", "restored {nq} queued + {nh} history jobs");
        }
    }
}

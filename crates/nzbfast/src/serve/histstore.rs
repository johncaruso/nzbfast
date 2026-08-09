//! §129 phase 1a: history's own store.
//!
//! History used to ride inside `queue.json`, which `save_queue` rewrote
//! wholesale - queue AND every history record, pretty-printed, fsync'd,
//! under one process-wide mutex - on every mutation anywhere in the
//! daemon. With history now UNLIMITED by default (a product ruling),
//! that made every pause/add/delete an O(all-time) disk write. The store
//! here splits history into `.spool/history.jsonl`, one compact
//! `job_json` line per record, append-only:
//!
//!  * a job PARKING appends its record;
//!  * the rare history MUTATIONS (recategorize, unlock, mover
//!    bookkeeping...) append a fresh line for the same nzo_id - the
//!    LAST line for an id wins on replay;
//!  * a delete (or a retry/stream pulling the record back into the
//!    queue) appends a tombstone line `{"nzo_id": ..., "deleted": true}`.
//!
//! Replay tolerates a torn tail (a crash mid-append costs at most that
//! one line) and compacts the file - one line per live record - when
//! more than half the lines are dead. `queue.json` keeps `next_id` +
//! the live queue only; a legacy file still carrying a "history" array
//! is read once and split (see `Daemon::load_queue`).
//!
//! Revision discipline: every write here bumps `history_rev`, which is
//! what `mode=dashboard` hands to clients so an unchanged history costs
//! an atomic load instead of a payload. Bumping at the persistence seam
//! is deliberate - a history change that should survive a restart MUST
//! come through here, so the seam sees every change by construction.

use super::*;
use std::io::Write as _;

impl Daemon {
    pub(super) fn history_store_path(&self) -> PathBuf {
        self.spool.join("history.jsonl")
    }

    /// Append pre-serialized lines and bump the revision. One fsync per
    /// call, not per line; callers batch. Best-effort like save_queue -
    /// a failed write must never take down a live daemon - but logged,
    /// because a silent miss here is a history row lost across restart.
    fn history_append(&self, lines: &[String]) -> bool {
        if lines.is_empty() {
            return true;
        }
        // Same discipline as save_queue's IO lock: two workers appending
        // must not interleave bytes. A separate lock - history appends
        // must not queue behind full queue.json rewrites.
        static IO: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _g = IO.lock_ok();
        let path = self.history_store_path();
        // 0600 on unix, for the same reason `persist::write_atomic`
        // does it: these rows are daemon-private and carry credentials.
        // A history record serializes the job's archive `password`
        // (job_wire.rs), its local paths and its identity metadata, and
        // this file is created by plain append - so under the ordinary
        // 022 umask it landed 0644 and stayed world-readable for the
        // life of the store, since compaction (which does go through
        // the private path) may not run for weeks. `mode` applies only
        // to creation, so an existing file keeps whatever it has.
        let mut opts = std::fs::OpenOptions::new();
        opts.create(true).append(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let r = opts.open(&path).and_then(|mut f| {
            let mut buf = String::with_capacity(lines.iter().map(|l| l.len() + 1).sum());
            for l in lines {
                buf.push_str(l);
                buf.push('\n');
            }
            f.write_all(buf.as_bytes())?;
            f.sync_all()
        });
        let ok = match r {
            Ok(()) => true,
            Err(e) => {
                error!(target: "queue", "history store {}: {e}", path.display());
                false
            }
        };
        self.history_rev.fetch_add(1, Ordering::Relaxed);
        ok
    }

    /// Persist the CURRENT state of history records that changed: one
    /// fresh line each, last-wins on replay. Callers pass the records
    /// AFTER mutating them, with no history/job locks held. Returns
    /// whether the write landed (recategorize reports durability).
    pub(super) fn history_upsert(&self, jobs: &[Arc<Mutex<Job>>]) -> bool {
        let lines: Vec<String> = jobs
            .iter()
            .map(|j| job_json(&j.lock_ok()).to_string())
            .collect();
        self.history_append(&lines)
    }

    /// Upsert ONLY when the record is currently in history. The mover
    /// and unlock tasks mutate a job they hold an Arc to, and by the
    /// time they persist, a delete may have pulled it out - appending
    /// then would resurrect the record at the next boot. (A queue job
    /// must never reach the store either; replay would mint a phantom
    /// history row for it.)
    pub(super) fn history_upsert_if_present(&self, job: &Arc<Mutex<Job>>) {
        let present = self.history.lock_ok().iter().any(|j| Arc::ptr_eq(j, job));
        if present {
            let _ = self.history_upsert(std::slice::from_ref(job));
        }
    }

    /// Persist removals: tombstone lines. For a record leaving history
    /// for good (delete) AND for one moving back into the queue (retry,
    /// stream) - in both cases the id must stop replaying into history;
    /// the queue arm of `save_queue` carries the latter onward.
    pub(super) fn history_tombstone(&self, ids: &[String]) {
        let lines: Vec<String> = ids
            .iter()
            .map(|id| json!({"nzo_id": id, "deleted": true}).to_string())
            .collect();
        self.history_append(&lines);
    }

    /// Rewrite the store as exactly the live records, atomically. Called
    /// at load when replay found more garbage than live rows, and after
    /// the one-time migration out of queue.json. Never on the serve
    /// path - history garbage accrues at human speed.
    pub(super) fn history_compact(&self) {
        let lines: Vec<String> = self
            .history
            .lock_ok()
            .iter()
            .map(|j| job_json(&j.lock_ok()).to_string())
            .collect();
        let mut buf = String::with_capacity(lines.iter().map(|l| l.len() + 1).sum());
        for l in &lines {
            buf.push_str(l);
            buf.push('\n');
        }
        let path = self.history_store_path();
        if let Err(e) = crate::persist::write_atomic(&path, buf.as_bytes()) {
            error!(target: "queue", "history compact {}: {e}", path.display());
        }
        self.history_rev.fetch_add(1, Ordering::Relaxed);
    }

    /// Replay `.spool/history.jsonl` into Job records, oldest first.
    /// Returns `(records, wants_compaction)`.
    ///
    /// Last line wins per nzo_id; tombstones remove; a torn or garbled
    /// line is skipped (the crash window is the file's own tail, and one
    /// lost append is the worst case the format permits). Order is
    /// first-APPEND order per id - an upsert refreshes a record's
    /// contents, not its age - matching the Vec the daemon serves
    /// newest-last.
    pub(super) fn history_replay(&self) -> (Vec<Job>, bool) {
        let path = self.history_store_path();
        // Read BYTES and decode per line. `read_to_string` rejects the
        // whole file on one invalid UTF-8 byte, and a crash mid-append
        // can tear the tail through the middle of a multi-byte
        // character - a foreign-language release name is all it takes.
        // That turned a recoverable one-line loss into "the history is
        // empty", permanently: nothing rewrites the bad byte, so every
        // later start read empty too, and the per-line tolerance below -
        // which exists for exactly this - never got to run.
        let Ok(raw) = std::fs::read(&path) else {
            return (Vec::new(), false);
        };
        let mut order: Vec<String> = Vec::new();
        let mut live: std::collections::HashMap<String, Job> = std::collections::HashMap::new();
        let mut lines = 0usize;
        for chunk in raw.split(|b| *b == b'\n') {
            let Ok(line) = std::str::from_utf8(chunk) else {
                warn!(
                    target: "queue",
                    "history store: skipping a line with invalid UTF-8"
                );
                continue;
            };
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            lines += 1;
            let Ok(v) = serde_json::from_str::<Value>(line) else {
                // A torn tail parses as garbage exactly once; anything
                // mid-file was already fsync'd whole, so noise here is
                // worth a line in the log.
                warn!(target: "queue", "history store: skipping an unreadable line");
                continue;
            };
            let Some(id) = v.get("nzo_id").and_then(Value::as_str).map(str::to_string) else {
                continue;
            };
            if v.get("deleted").and_then(Value::as_bool).unwrap_or(false) {
                live.remove(&id);
                order.retain(|o| *o != id);
                continue;
            }
            let Some(mut job) = job_from_json(&v) else {
                continue;
            };
            // `finalizing` is a LIVE flag: it says a post-processing tail
            // is running right now, and nothing is running after a
            // restart. A record appended while it was raised - the
            // password-unlock path upserts twice inside its
            // ClearFinalizing scope, and the guard only clears the
            // in-memory copy - comes back permanently marked busy, and
            // every consumer refuses it forever: history delete (the
            // WHOLE request, so "Clear completed" stops working),
            // change_cat, retry, the owed move, retention. A wrong
            // password is worse - `password_required && finalizing`
            // refuses every further unlock attempt, so the job can never
            // be opened again. The legacy `restore_records` this replaced
            // cleared it on load and said so; §129's store lost that, so
            // clear it here, whichever write path persisted the stale
            // true.
            job.finalizing = false;
            if !live.contains_key(&id) {
                order.push(id.clone());
            }
            live.insert(id, job);
        }
        let records: Vec<Job> = order
            .into_iter()
            .filter_map(|id| live.remove(&id))
            .collect();
        // More dead lines than live rows: worth a rewrite once loaded.
        let wants_compaction = lines > records.len().saturating_mul(2).max(64);
        (records, wants_compaction)
    }
}

/// §129 1b: one discrete lifecycle event, sequence-numbered so a client
/// can ask "everything since N" instead of diffing snapshots. Ring
/// bounded at [`LIFE_RING`]; a client whose cursor has fallen off the
/// tail is told to reseed (`events_reset`), never replayed stale toasts.
pub(super) const LIFE_RING: usize = 512;

impl Daemon {
    /// Emit one lifecycle event. `payload` carries the kind-specific
    /// keys; `seq`/`kind`/`at` are stamped here.
    pub(super) fn life_emit(&self, kind: &str, mut payload: Value) {
        let seq = self.life_seq.fetch_add(1, Ordering::Relaxed) + 1;
        let at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        if let Some(o) = payload.as_object_mut() {
            o.insert("seq".into(), json!(seq));
            o.insert("kind".into(), json!(kind));
            o.insert("at".into(), json!(at));
        }
        let mut ring = self.life_events.lock_ok();
        if ring.len() >= LIFE_RING {
            ring.pop_front();
        }
        ring.push_back(payload);
    }

    /// Everything after `since`, plus whether that cursor already fell
    /// off the ring's tail (reseed signal). "No cursor at all" (a fresh
    /// page's first poll) is the CALLER's case - it omits the param and
    /// never reaches here - so a numeric cursor, zero included, means
    /// "I have seen everything up to here": a daemon whose first-ever
    /// event lands after the page opened must deliver it to a client
    /// holding cursor 0, not swallow it as a replay guard.
    pub(super) fn life_since(&self, since: u64) -> (Vec<Value>, bool) {
        let ring = self.life_events.lock_ok();
        let oldest = ring
            .front()
            .and_then(|e| e["seq"].as_u64())
            .unwrap_or_else(|| self.life_seq.load(Ordering::Relaxed) + 1);
        // A gap between the cursor and the oldest retained event means
        // events were lost to the ring bound: say so instead of quietly
        // skipping them.
        let reset = since + 1 < oldest;
        let events: Vec<Value> = ring
            .iter()
            .filter(|e| e["seq"].as_u64().unwrap_or(0) > since)
            .cloned()
            .collect();
        (if reset { Vec::new() } else { events }, reset)
    }

    /// The park-side emitter: the one place a job becomes history, so
    /// the one place "it finished" becomes an event. Locked; call with
    /// no locks held.
    pub(super) fn life_emit_parked(&self, job: &Arc<Mutex<Job>>) {
        let g = job.lock_ok();
        match g.state {
            JobState::Failed => self.life_emit(
                "job.failed",
                json!({
                    "nzo_id": g.nzo_id,
                    "name": g.name,
                    "category": g.category,
                    "fail_message": g.fail_message,
                    "auto_retry_at": g.auto_retry_at,
                    // A Failed row can be asking for a password too (the
                    // in-stream probe saw an encrypted set); the client's
                    // password chime keys off this.
                    "locked": g.password_required,
                }),
            ),
            _ => self.life_emit(
                "job.completed",
                json!({
                    "nzo_id": g.nzo_id,
                    "name": g.name,
                    "category": g.category,
                    // The completed-but-locked split the toast rules need.
                    "locked": g.password_required,
                    "moved_to": if g.out_dir.starts_with(self.out_dir()) {
                        String::new()
                    } else {
                        g.out_dir.to_string_lossy().into_owned()
                    },
                }),
            ),
        }
    }

    /// §129 D5: the optional retention knobs, both 0 = unlimited (the
    /// default; unlimited SHIPS by ruling). Applied at park and at load.
    /// Count cap drops oldest-first regardless of state; the age cap
    /// only ever drops Completed rows (a Failed row is a pending
    /// decision, not a memory). Rows mid-move/unlock are never touched.
    pub(super) fn history_enforce_retention(&self) {
        let keep_count = self.history_keep_count.load(Ordering::Relaxed) as usize;
        let keep_days = self.history_keep_days.load(Ordering::Relaxed);
        if keep_count == 0 && keep_days == 0 {
            return;
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let mut doomed: Vec<String> = Vec::new();
        let mut spooled: Vec<PathBuf> = Vec::new();
        {
            let mut h = self.history.lock_ok();
            let moving = self.moving.lock_ok();
            let untouchable = |g: &Job| g.finalizing || moving.contains(&g.nzo_id);
            if keep_days > 0 {
                let cutoff = now - (keep_days as i64) * 86_400;
                h.retain(|j| {
                    let g = j.lock_ok();
                    let old = g.state == JobState::Completed
                        && g.finished_unix.is_some_and(|t| t < cutoff);
                    if old && !untouchable(&g) {
                        doomed.push(g.nzo_id.clone());
                        spooled.push(g.nzb_path.clone());
                        false
                    } else {
                        true
                    }
                });
            }
            if keep_count > 0 && h.len() > keep_count {
                let mut excess = h.len() - keep_count;
                // Oldest first = front of the Vec.
                h.retain(|j| {
                    if excess == 0 {
                        return true;
                    }
                    let g = j.lock_ok();
                    if untouchable(&g) {
                        return true;
                    }
                    doomed.push(g.nzo_id.clone());
                    spooled.push(g.nzb_path.clone());
                    excess -= 1;
                    false
                });
            }
        }
        // The RECORD retires; the payload on disk is the user's. Only
        // the spooled .nzb (kept for retry, and retry needs a record)
        // goes with it.
        for p in spooled {
            let _ = std::fs::remove_file(&p);
        }
        if !doomed.is_empty() {
            info!(
                target: "queue",
                "history retention: dropped {} old record(s) (keep_count {}, keep_days {})",
                doomed.len(),
                keep_count,
                keep_days
            );
            self.history_tombstone(&doomed);
        }
    }
}

#[cfg(test)]
mod store_tests {
    use crate::serve::testutil::test_daemon;

    fn tmp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("nzbfast-hist-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// A torn multi-byte tail costs ONE row, not the whole history.
    ///
    /// Replay used to `read_to_string` the file before its per-line
    /// recovery, so a crash that tore an append through the middle of a
    /// character - a foreign-language release name is enough - made the
    /// entire history read as empty. Nothing ever rewrote the bad byte,
    /// so it stayed empty across every later restart, and the documented
    /// per-line tolerance never got to run.
    #[test]
    fn a_torn_utf8_tail_costs_one_row_not_the_history() {
        let dir = tmp("torn");
        let d = test_daemon(&dir);
        let path = d.history_store_path();

        // The fields `job_from_json` insists on, and nothing else.
        let row = |id: &str, name: &str| {
            format!(
                r#"{{"nzo_id":"{id}","name":"{name}","out_dir":"/tmp/o","nzb_path":"/tmp/n.nzb","state":"Completed"}}"#
            )
        };
        let mut bytes = Vec::new();
        bytes.extend_from_slice(row("a1", "Ordinary.Release").as_bytes());
        bytes.push(b'\n');
        // A name with real multi-byte characters, written whole.
        bytes.extend_from_slice(row("a2", "Æon.Flux.Æ").as_bytes());
        bytes.push(b'\n');
        // ...and a third append that died mid-character: the leading
        // byte of a 2-byte sequence with its continuation byte missing.
        bytes.extend_from_slice(
            br#"{"nzo_id":"a3","out_dir":"/tmp/o","nzb_path":"/tmp/n.nzb","state":"Completed","name":"Tor"#,
        );
        bytes.push(0xC3);

        std::fs::write(&path, &bytes).unwrap();
        let (jobs, _) = d.history_replay();
        let ids: Vec<String> = jobs.iter().map(|j| j.nzo_id.clone()).collect();
        assert_eq!(
            ids,
            ["a1", "a2"],
            "a torn tail took the whole history with it"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The append-only store is created private. It carries the job's
    /// archive password, its local paths and its identity metadata, and
    /// plain `OpenOptions` under the usual 022 umask left it 0644 -
    /// readable by every local account until a compaction (which does go
    /// through the private path) happened to run.
    #[cfg(unix)]
    #[test]
    fn a_fresh_history_store_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tmp("mode");
        let d = test_daemon(&dir);
        assert!(d.history_append(&[r#"{"nzo_id":"a1","name":"x"}"#.to_string()]));
        let mode = std::fs::metadata(d.history_store_path())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "history store is group/world readable");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

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

/// ONE publication lock for `history.jsonl`: every append, tombstone and
/// the compacting rewrite take it.
///
/// Same discipline as save_queue's IO lock (two workers appending must
/// not interleave bytes), and a separate lock so history appends do not
/// queue behind full queue.json rewrites - but it covers the REWRITE
/// too, which it did not until the 10 Aug sweep (H3). Compaction
/// snapshots the live rows and renames a replacement over the file; an
/// append that landed after that snapshot was published into the file
/// the rename then replaced, and the transition - a park, an upsert, a
/// delete's tombstone - was simply gone at the next boot. The lock makes
/// snapshot-and-publish indivisible against the appenders, so a
/// concurrent transition is either inside the snapshot or appended after
/// the rename, never lost between them.
static HIST_IO: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Test seam: a barrier `history_compact` trips between snapshotting the
/// live rows and publishing the replacement.
///
/// The H3 regression is a two-thread ordering, and a sleep-based test
/// either misses the window or goes flaky. Parking the compaction
/// exactly in the gap lets the test hold it open and prove what an
/// appender does there - which, with the lock in place, is wait.
#[cfg(test)]
pub(super) static COMPACT_BARRIER: std::sync::Mutex<Option<Arc<std::sync::Barrier>>> =
    std::sync::Mutex::new(None);

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
        let _g = HIST_IO.lock_ok();
        self.history_write_locked(lines)
    }

    /// The append itself, with [`HIST_IO`] ALREADY held. Split out so a
    /// caller that must decide something under the same lock (the
    /// present-check in `history_upsert_if_present`) can do so without
    /// dropping it between the decision and the write.
    fn history_write_locked(&self, lines: &[String]) -> bool {
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
    ///
    /// The check and the append happen under ONE hold of [`HIST_IO`],
    /// which is what makes the guard true rather than likely: the check
    /// used to drop the history lock before serializing, and a delete
    /// that removed the row and appended its tombstone in that window
    /// left the stale upsert as the LAST line for the id - replay then
    /// resurrected exactly the record this guard exists to bury (H6,
    /// 10 Aug sweep). A delete either finishes first (the check sees the
    /// record gone and writes nothing) or waits here for the lock and
    /// tombstones after (the tombstone stays last).
    pub(super) fn history_upsert_if_present(&self, job: &Arc<Mutex<Job>>) {
        let _g = HIST_IO.lock_ok();
        if !self.history.lock_ok().iter().any(|j| Arc::ptr_eq(j, job)) {
            return;
        }
        let line = job_json(&job.lock_ok()).to_string();
        self.history_write_locked(&[line]);
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
    /// at load when replay found more garbage than live rows, after the
    /// one-time migration out of queue.json - and by "Save queue", the
    /// remedy the durability errors name, which is a LIVE daemon with
    /// appenders running. Returns whether the rewrite landed: the remedy
    /// has to be able to report that it did not.
    ///
    /// Snapshot and publish both happen under [`HIST_IO`]; see the lock's
    /// own note for what an unsynchronised rewrite cost.
    pub(super) fn history_compact(&self) -> bool {
        let _g = HIST_IO.lock_ok();
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
        #[cfg(test)]
        {
            let barrier = COMPACT_BARRIER.lock_ok().clone();
            if let Some(b) = barrier {
                b.wait();
            }
        }
        let path = self.history_store_path();
        let ok = match crate::persist::write_atomic(&path, buf.as_bytes()) {
            Ok(()) => true,
            Err(e) => {
                error!(target: "queue", "history compact {}: {e}", path.display());
                false
            }
        };
        self.history_rev.fetch_add(1, Ordering::Relaxed);
        ok
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

/// §129 4a: the event schema's version, stamped on every event.
/// Additive payload keys never bump it; renaming or removing a key, or
/// changing what one means, does. Consumers must ignore unknown keys
/// and unknown kinds - the dashboard's if/else-if chain and the webhook
/// filter both already do.
pub(super) const LIFE_SCHEMA_VERSION: u32 = 1;

impl Daemon {
    /// Emit one lifecycle event. `payload` carries the kind-specific
    /// keys; `seq`/`kind`/`at`/`schema_version` are stamped here.
    /// Sequence allocation and ring insertion happen under ONE hold of
    /// the ring lock, and `life_seq` is only ever advanced there. They
    /// used to be separate: the counter went up first, then hooks were
    /// offered, then the ring lock was taken - so a poll landing in that
    /// window read a ring WITHOUT the event and a cursor that already
    /// counted it, and the client, which adopts the returned cursor,
    /// filtered that event out forever (M1, 10 Aug sweep). Two emitters
    /// racing could also push [2, 1] and break `front()` being the
    /// numerically oldest, which is what `life_since` reads to decide
    /// whether a client has fallen off the tail.
    pub(super) fn life_emit(&self, kind: &str, mut payload: Value) {
        let at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let published = {
            let mut ring = self.life_events.lock_ok();
            let seq = self.life_seq.fetch_add(1, Ordering::Relaxed) + 1;
            if let Some(o) = payload.as_object_mut() {
                o.insert("seq".into(), json!(seq));
                o.insert("kind".into(), json!(kind));
                o.insert("at".into(), json!(at));
                o.insert("schema_version".into(), json!(LIFE_SCHEMA_VERSION));
            }
            if ring.len() >= LIFE_RING {
                ring.pop_front();
            }
            ring.push_back(payload.clone());
            payload
        };
        // §129 4a: offer the event to the webhook dispatcher - a
        // try-send that can neither block nor fail the emitter. AFTER
        // publication now, and outside the ring lock: a dispatcher that
        // is behind must not hold the emitter's lock, and the event is
        // already visible to pollers by the time it is offered.
        self.hooks_offer(&published);
    }

    /// Everything after `since`, plus whether that cursor already fell
    /// off the ring's tail (reseed signal). "No cursor at all" (a fresh
    /// page's first poll) is the CALLER's case - it omits the param and
    /// never reaches here - so a numeric cursor, zero included, means
    /// "I have seen everything up to here": a daemon whose first-ever
    /// event lands after the page opened must deliver it to a client
    /// holding cursor 0, not swallow it as a replay guard.
    /// The cursor a client with no cursor at all should adopt: the last
    /// PUBLISHED sequence, read under the ring lock like `life_since`
    /// reads it, so a fresh page cannot start out already past an event
    /// that is mid-publication (M1's shape, from the other end).
    pub(super) fn life_cursor(&self) -> u64 {
        let _ring = self.life_events.lock_ok();
        self.life_seq.load(Ordering::Relaxed)
    }

    /// Returns `(events, reset, cursor)`. The cursor is read under the
    /// SAME ring lock the events are read under, and is what the client
    /// must adopt: answering with the atomic's current value instead
    /// reintroduced M1's gap from the reader's side, since an event
    /// published between this call and that load would be counted by the
    /// cursor and absent from the batch.
    pub(super) fn life_since(&self, since: u64) -> (Vec<Value>, bool, u64) {
        let ring = self.life_events.lock_ok();
        let cursor = self.life_seq.load(Ordering::Relaxed);
        let oldest = ring
            .front()
            .and_then(|e| e["seq"].as_u64())
            .unwrap_or(cursor + 1);
        // A gap between the cursor and the oldest retained event means
        // events were lost to the ring bound: say so instead of quietly
        // skipping them.
        //
        // A cursor AHEAD of this daemon's sequence is the other reseed
        // case: a tab that was open across a restart still holds the old
        // boot's numbering, and every event of the new boot reads as
        // already-seen (M2, 10 Aug sweep). Numbering is per-boot, so
        // "impossible cursor" means "different boot" - reseed.
        let reset = since + 1 < oldest || since > cursor;
        let events: Vec<Value> = ring
            .iter()
            .filter(|e| e["seq"].as_u64().unwrap_or(0) > since)
            .cloned()
            .collect();
        (if reset { Vec::new() } else { events }, reset, cursor)
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
            _ => {
                // §129 4a: a completed job that needed repair announces
                // the repair as its own kind first - the schema's
                // job.repaired - then completes. Same derivation the
                // notify router uses for its "repaired" token.
                let repaired = g.bad_blocks.unwrap_or(0) > 0;
                if repaired {
                    self.life_emit(
                        "job.repaired",
                        json!({
                            "nzo_id": g.nzo_id,
                            "name": g.name,
                            "category": g.category,
                            "bad_blocks": g.bad_blocks.unwrap_or(0),
                        }),
                    );
                }
                self.life_emit(
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
                        // §129 4a additive keys (schema v1): what the job
                        // was, whether it repaired, and the archive shape
                        // the one-pass engine unpacked ("" = plain files)
                        // - job.extracted's answer lives here, extraction
                        // being integral to the download rather than a
                        // stage of its own.
                        "bytes": g.total_bytes,
                        "repaired": repaired,
                        "archive_shape": g.archive_shape,
                    }),
                );
            }
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
    use super::*;
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

    /// One record, filed in history, for the concurrency tests below.
    fn filed(d: &Arc<Daemon>, id: &str) -> Arc<Mutex<Job>> {
        let v = json!({
            "nzo_id": id, "name": format!("Release.{id}"),
            "out_dir": "/tmp/o", "nzb_path": "/tmp/n.nzb", "state": "Completed",
        });
        let job = Arc::new(Mutex::new(job_from_json(&v).expect("job")));
        d.history.lock_ok().push(job.clone());
        job
    }

    /// A compaction running beside live appends must not lose one.
    ///
    /// `history_compact` used to snapshot the rows and rename its
    /// replacement over `history.jsonl` with no lock at all, while
    /// appends went to the file it was about to replace. Every
    /// transition that landed in that window - a park, a recategorize, a
    /// delete's tombstone - was simply absent at the next boot, and
    /// "Save queue", the remedy the durability errors name, calls the
    /// compaction on a LIVE daemon (H3, 10 Aug sweep).
    #[test]
    fn a_compaction_cannot_erase_a_concurrent_append() {
        let dir = tmp("compact-race");
        let d = test_daemon(&dir);
        filed(&d, "seed");
        assert!(d.history_compact());

        // Hold the compaction open in the exact gap: snapshot taken,
        // replacement not yet renamed into place.
        let gate = Arc::new(std::sync::Barrier::new(2));
        *super::COMPACT_BARRIER.lock_ok() = Some(gate.clone());
        let compactor = {
            let d = d.clone();
            std::thread::spawn(move || assert!(d.history_compact()))
        };
        gate.wait();

        // A park lands here: the record joins history and is appended to
        // the store. The snapshot the compaction is holding predates it.
        let appender = {
            let d = d.clone();
            std::thread::spawn(move || {
                let job = filed(&d, "parked-in-the-gap");
                assert!(d.history_upsert(std::slice::from_ref(&job)));
            })
        };
        // Long enough that an UNSERIALIZED append would have reached the
        // file the rename is about to replace. With the lock it simply
        // waits for the rename, which is the whole point.
        std::thread::sleep(std::time::Duration::from_millis(50));
        compactor.join().unwrap();
        appender.join().unwrap();
        *super::COMPACT_BARRIER.lock_ok() = None;

        let (rows, _) = d.history_replay();
        assert!(
            rows.iter().any(|j| j.nzo_id == "parked-in-the-gap"),
            "the compaction published its stale snapshot over a live \
             append: {:?}",
            rows.iter().map(|j| &j.nzo_id).collect::<Vec<_>>()
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A deleted record stays deleted, whatever a concurrent upsert is
    /// doing.
    ///
    /// `history_upsert_if_present` checked membership, dropped the lock,
    /// and only then serialized and appended. A delete landing in that
    /// window removed the row and wrote its tombstone FIRST, so the
    /// stale upsert became the last line for the id and replay brought
    /// the record back - exactly the resurrection the helper exists to
    /// prevent (H6, 10 Aug sweep).
    #[test]
    fn an_upsert_cannot_resurrect_a_deleted_record() {
        let dir = tmp("resurrect");
        for round in 0..40 {
            let d = test_daemon(&dir);
            let _ = std::fs::remove_file(d.history_store_path());
            let job = filed(&d, "victim");
            assert!(d.history_upsert(std::slice::from_ref(&job)));

            let deleter = {
                let d = d.clone();
                std::thread::spawn(move || {
                    d.history
                        .lock_ok()
                        .retain(|j| j.lock_ok().nzo_id != "victim");
                    d.history_tombstone(&["victim".to_string()]);
                })
            };
            // The mover's shape: mutate the record it holds an Arc to,
            // then persist it.
            job.lock_ok().name = format!("Renamed.{round}");
            d.history_upsert_if_present(&job);
            deleter.join().unwrap();

            let (rows, _) = d.history_replay();
            assert!(
                !rows.iter().any(|j| j.nzo_id == "victim"),
                "round {round}: the deleted record came back"
            );
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Every emitted event reaches a client that keeps polling with the
    /// cursor it was handed.
    ///
    /// Allocation, ring insertion and the published cursor used to be
    /// three separate steps: a poll could see the counter already
    /// advanced and the ring not yet pushed, hand back that cursor, and
    /// the client - which adopts whatever it is given - filtered the
    /// event out forever (M1, 10 Aug sweep).
    #[test]
    fn no_event_can_slip_between_the_ring_and_the_cursor() {
        let dir = tmp("life-race");
        let d = test_daemon(&dir);
        const N: u64 = 300;
        let emitters: Vec<_> = (0..3)
            .map(|w| {
                let d = d.clone();
                std::thread::spawn(move || {
                    for i in 0..N / 3 {
                        d.life_emit("job.completed", json!({"w": w, "i": i}));
                    }
                })
            })
            .collect();
        // The dashboard's loop: ask for everything since the cursor the
        // last answer gave, and adopt the new one unconditionally.
        let mut cursor = 0u64;
        let mut seen: std::collections::HashSet<u64> = std::collections::HashSet::new();
        while cursor < N {
            let (events, reset, next) = d.life_since(cursor);
            assert!(!reset, "the ring is far larger than this test's traffic");
            for e in events {
                seen.insert(e["seq"].as_u64().unwrap());
            }
            cursor = next;
        }
        for h in emitters {
            h.join().unwrap();
        }
        let (events, _, _) = d.life_since(cursor);
        for e in events {
            seen.insert(e["seq"].as_u64().unwrap());
        }
        let missed: Vec<u64> = (1..=N).filter(|s| !seen.contains(s)).collect();
        assert!(missed.is_empty(), "a poller never saw events {missed:?}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A cursor from the PREVIOUS boot asks for a reseed.
    ///
    /// Sequence numbers restart at zero with the daemon, so a tab that
    /// slept through a restart came back holding a number no event of
    /// this boot will ever exceed: every new event read as already-seen,
    /// and the client adopted the lower cursor without ever being told
    /// it had missed anything (M2, 10 Aug sweep).
    #[test]
    fn a_cursor_from_a_previous_boot_forces_a_reseed() {
        let dir = tmp("life-boot");
        let d = test_daemon(&dir);
        d.life_emit("job.completed", json!({}));
        let (events, reset, cursor) = d.life_since(50);
        assert!(reset, "an impossible cursor must ask for a reseed");
        assert!(events.is_empty(), "a reseed replays nothing");
        assert_eq!(cursor, 1);
        // ...and a cursor this boot could have issued is served normally.
        let (events, reset, _) = d.life_since(0);
        assert!(!reset);
        assert_eq!(events.len(), 1);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The queue going idle without a park still says so.
    ///
    /// `queue.idle` was evaluated only from `Daemon::park`, so deleting
    /// the last queued job or pausing the last runnable one made the
    /// queue idle in silence (M3, 10 Aug sweep). The latch keeps it a
    /// transition: said once, and not again until something re-arms it.
    #[test]
    fn an_idle_queue_is_announced_once_per_transition() {
        let dir = tmp("idle");
        let d = test_daemon(&dir);
        // Armed the way an add arms it, with nothing runnable left.
        d.queue_idle_latch
            .store(false, std::sync::atomic::Ordering::Relaxed);
        d.note_queue_idle();
        d.note_queue_idle();
        let (events, _, _) = d.life_since(0);
        let idle: Vec<&Value> = events
            .iter()
            .filter(|e| e["kind"] == "queue.idle")
            .collect();
        assert_eq!(idle.len(), 1, "{events:?}");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

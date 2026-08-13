//! `Daemon::enqueue` - the whole add path from NZB bytes to a queued (or
//! parked) job - moved out bodily under the size gate (TODO 106). A child
//! module of `daemon`, same shape as daemon_index, so `Daemon`'s private
//! fields and daemon.rs's private types stay in scope exactly as they
//! were inline. `super` now means `daemon`, not `serve`, so the method's
//! old pub(super) is spelled pub(in crate::serve) to keep its original
//! visibility.

use super::*;

impl Daemon {
    /// `pp` is the post-processing mode the CALLER requested (0-3, None
    /// = none named). The pre-queue hook receives it - SAB's contract
    /// hands the script the requested pp - but it is RECORDED on the
    /// job afterwards by `record_add_params`, which fills only what the
    /// hook did not already answer.
    pub(in crate::serve) fn enqueue(
        &self,
        nzb_bytes: &[u8],
        name: &str,
        category: &str,
        priority: i32,
        pp: Option<i64>,
        password: Option<&str>,
        origin: &str,
        allow_dupe: bool,
    ) -> Result<String> {
        let n = self.next_id.fetch_add(1, Ordering::Relaxed);
        let nzo_id = format!("SABnzbd_nzo_nzbfast{n}");
        let nzb = nzbkit::nzb::Nzb::parse(nzb_bytes)?;
        let mut stem = name.trim_end_matches(".nzb").to_string();
        // Archive password: an explicit param (SAB API) wins; the
        // `Name{{password}}` convention comes OFF the display name either
        // way (and the output folder - never leak a password into the
        // filesystem); the NZB's own <meta type="password"> is the
        // fallback (the engine would find it again at download time -
        // capturing it here surfaces has_password to the UI).
        let mut password: Option<String> = password.filter(|p| !p.is_empty()).map(str::to_string);
        // All three name conventions - {{pw}}, password=pw, {pw} - are
        // recognized and stripped (crate::smart::name_password).
        if let Some((pw, clean)) = crate::smart::name_password(&stem) {
            password.get_or_insert(pw);
            stem = clean;
        }
        if password.is_none() {
            password = nzb.password().map(str::to_string);
        }
        // Zip-packed post, spotted from the NZB's own file list before a
        // single byte is fetched. We cannot unpack one, so saying it here
        // costs the user a click instead of a download. Name-shaped
        // evidence only - an obfuscated container has no name to read, and
        // guessing from a subject line would cry wolf on ordinary posts.
        let zip_packed = nzb
            .files
            .iter()
            .filter_map(|f| f.filename_hint())
            .any(nzbkit::zip::name_is_zip_shaped);
        if zip_packed {
            info!(
                target: "queue",
                "{nzo_id} looks zip-packed - store and deflate zips unpack \
                 natively, an encrypted one too when the job has a password; an \
                 exotic codec will arrive packed"
            );
        }
        let total_bytes = nzb.eager_bytes();
        // M23 Smart Folders: the first matching rule can retarget the
        // category (= out_root subfolder) and request TV filing.
        let mut category = category.to_string();
        let mut tv_sort = false;
        let mut smart_rule = String::new();
        if let Some(r) =
            crate::smart::first_match(&self.smart_folders.lock_ok(), &stem, total_bytes)
        {
            if !r.category.is_empty() {
                category = r.category.clone();
            }
            tv_sort = r.tv_sort;
            // Kept on the job: "why is this in Films?" is answerable only
            // by the rule that decided it, and the rule list is editable.
            smart_rule = r.name.clone();
            info!(
                target: "smart",
                "rule {:?} matched {stem:?} → category {:?}{}",
                r.name,
                category,
                if tv_sort { " + TV filing" } else { "" }
            );
        }
        // `category` (the `cat=` request param) and `stem` (from the NZB
        // name / `nzbname`) are untrusted and must never escape out_root:
        // an absolute component replaces the base, and `..` is resolved by
        // the OS at create/remove time - a crafted name plus a delete call
        // could otherwise write to, or recursively delete, an arbitrary
        // directory (bug sweep). Force each to a single contained path
        // component before it ever touches the filesystem.
        if !category.is_empty() {
            category = nzbkit::disk::sanitize_filename(&category);
        }
        // §129 4a: consult the pre-queue hook - rename, recategorize,
        // reprioritize, pick pp/script, or reject - before anything is
        // published. Before the spool write (a rename names the spool
        // file), before the add lock (a slow script must never
        // serialize concurrent adds), and demoted via blocking_db
        // (enqueue is reachable from tokio tasks). Fail-open by
        // contract - see serve/prequeue.rs.
        let mut priority = priority;
        let mut hook_pp = None;
        let mut hook_script = String::new();
        let mut hook_reject = None;
        if self.pre_queue_script.lock_ok().is_some() {
            let mut groups: Vec<String> = Vec::new();
            for f in &nzb.files {
                for g in &f.groups {
                    if !groups.contains(g) {
                        groups.push(g.clone());
                    }
                }
            }
            let verdict = crate::persist::blocking_db(|| {
                self.run_pre_queue(
                    &nzo_id,
                    origin,
                    &stem,
                    pp,
                    &category,
                    priority,
                    total_bytes,
                    &groups,
                )
            });
            if let Some(v) = verdict {
                if !v.accept {
                    hook_reject = Some("rejected by the pre-queue script".to_string());
                }
                if let Some(n) = v.name {
                    stem = n;
                }
                if let Some(c) = v.category {
                    category = nzbkit::disk::sanitize_filename(&c);
                }
                if let Some(p) = v.priority {
                    // The hook's priority is an EXPLICIT one: it also
                    // suppresses the category default fill below.
                    priority = p;
                }
                hook_pp = v.pp;
                hook_script = v.script.unwrap_or_default();
            }
        }
        // Named after the release as well as the job id. A folder of
        // SABnzbd_nzo_nzbfast<n>.nzb files could not be matched to
        // anything a user had ever seen; the id stays first so the name
        // is still unique and sortable, and old jobs are unaffected
        // because nzb_path is persisted per job.
        let spool_path = self
            .spool
            .join(format!("{nzo_id}-{}.nzb", safe_spool_stem(&stem)));
        // Atomic: a resume re-parses this file; it must never be torn.
        crate::persist::write_atomic(&spool_path, nzb_bytes)?;
        // §129 2b: the category's default priority fills an add that
        // did not name one (-100, SAB's "default"). An explicit
        // priority - including -2 add-paused - always wins.
        if priority == SAB_DEFAULT_PRIORITY
            && let Some(p) = self
                .cat_meta
                .lock_ok()
                .get(&category)
                .and_then(|m| m.priority)
        {
            priority = p;
        }
        let dir_stem = nzbkit::disk::sanitize_filename(&stem);
        let base_out_dir = self.base_out_dir(&category, &dir_stem);
        // Two DIFFERENT NZBs whose names sanitize to the same stem and carry
        // no dupe_key (no SxxEyy/year marker - e.g. software or music posts)
        // are not caught by the M14f duplicate hold below, so they would
        // share one out_dir. Their pipelines deliberately overlap (A's tail
        // repairs/extracts while B's net leg runs), so B's journal + volume
        // writers truncate the files A is still reading → both corrupt. Give
        // a colliding job its own directory.
        //
        // A COMPLETED job's payload claims its directory too. Treating it as
        // inert meant a re-add reused the folder and the very first decoded
        // span truncated the previous, good result - which was then gone for
        // nothing if the replacement failed on missing articles, a password
        // or ENOSPC. The re-add downloads under its own name and takes over
        // the canonical directory only once it has verified (`replaces`,
        // published by `publish_over_previous`). A FAILED job's leftovers are
        // junk and are still reused in place, so retrying a flaky post does
        // not climb .2, .3, .4.
        // From here to the queue push is one transaction. Choosing a
        // directory and deciding "not a duplicate" are both reads of
        // state this job is about to change, and neither is published
        // until the push, so without the lock two concurrent adds of one
        // release agree on everything and then collide.
        let publish = self.add_lock.lock_ok();
        // dir_claim stats the output volume (`p.exists()`), which can be
        // a network share, and enqueue is reachable from tokio tasks
        // (watchlist watcher, RSS poller) - demote the worker around it.
        let (out_dir, replaces) = crate::persist::blocking_db(|| {
            choose_out_dir(&base_out_dir, &dir_stem, &|p| self.dir_claim(p))
        });
        self.register_cat(&category);
        // M14f duplicate check: same identity already queued, running, or
        // successfully completed → hold this one as an ALTERNATIVE
        // (paused, Duplicate priority). It auto-promotes if the original
        // fails; PROPERs always download.
        //
        // `allow_dupe` is the user having been ASKED and said yes (the
        // wall's confirmation). It suppresses the hold, not the key: the
        // job still carries its identity, so everything downstream that
        // reasons about duplicates keeps working.
        let key = dupe_key(&stem);
        let collision = if allow_dupe {
            None
        } else {
            self.dupe_collision(&stem)
        };
        let duplicate = collision.is_some();
        // §129 2d: what a duplicate add becomes is the user's call now.
        // "pause" is the M14f hold; "discard" refuses the add outright;
        // "fail" files it straight to history as Failed (the *arr
        // contract: a failed grab triggers their own search for a
        // different release, where a silently held one just sits).
        let dupe_action = self.dupe_action.lock_ok().clone();
        if let Some(c) = &collision
            && dupe_action == "discard"
            // A hook REJECT outranks the duplicates setting: the job is
            // about to file to history with the hook's reason.
            && hook_reject.is_none()
        {
            drop(publish);
            // The spool copy was written above; a refused add must not
            // leave it behind.
            let _ = std::fs::remove_file(&spool_path);
            info!(
                target: "queue",
                "refused {stem:?} - duplicate of {} ({}, {}), and duplicates \
                 are set to be discarded",
                c.name, c.nzo_id, c.where_
            );
            anyhow::bail!(
                "duplicate of {:?} ({}) - discarded; the duplicates setting \
                 decides this",
                c.name,
                c.where_
            );
        }
        // Late-pick groundwork: was the runner free to take this job the
        // moment it lands? Only then does a slow pick mean the runner was
        // starved (the fixed inline-SQLite bug held picks back 38 s)
        // rather than the job simply waiting its turn.
        let runner_idle = self.started_at.lock_ok().is_none()
            && !self.paused.load(std::sync::atomic::Ordering::Relaxed)
            && !self.queue.lock_ok().iter().any(|j| {
                let g = j.lock_ok();
                g.state == JobState::Queued && !g.paused
            });
        // C4-4: the accepted NZB is a (name, payload message-id set)
        // pairing for the identity substrate - recorded after the job
        // publishes, below.
        let pairing_name = stem.clone();
        let job = Arc::new(Mutex::new(Job {
            origin: origin.to_string(),
            nzo_id: nzo_id.clone(),
            name: stem,
            nzb_sha: nzb_sha(nzb_bytes),
            finalizing: false,
            nzb_path: spool_path,
            category: category.clone(),
            state: JobState::Queued,
            total_bytes,
            out_dir,
            fail_message: String::new(),
            fail_detail: String::new(),
            finished_at: None,
            finished_unix: None,
            // SAB priority -2 means "add paused", -100 means "the default".
            priority: enqueue_priority(priority, duplicate),
            paused: duplicate || priority == -2,
            queued_at: Some(Instant::now()),
            queued_unix: Some(unix_now()),
            idle_at_add: runner_idle,
            // Stamped by `enqueue_fetched` when the NZB came from a URL
            // and the indexer sent an X-DNZB-Failure header.
            failure_link: String::new(),
            failure_host: String::new(),
            failure_https: false,
            failure_depth: 0,
            identify: String::new(),
            media: None,
            media_rejudge: false,
            retries: 0,
            dupe_key: key,
            // WHICH row this one is an alternative OF - see `Job::held_for`.
            held_for: collision
                .as_ref()
                .map(|c| c.nzo_id.clone())
                .unwrap_or_default(),
            library: self.library_cats.lock_ok().contains(&category),
            fetched: false,
            tombstone: false,
            del_on_drop: false,
            suspended: false,
            downloaded_bytes: 0,
            elapsed_secs: 0.0,
            deferred: false,
            defer_reason: String::new(),
            defer_count: 0,
            demote: false,
            bad_blocks: None,
            verify_blocks: 0,
            tv_sort,
            smart_rule,
            filed: false,
            filed_suffix: None,
            filed_title: None,
            filed_base: None,
            password,
            password_required: false,
            eat_volumes_ok: false,
            zip_packed,
            unpack_blocked_by: String::new(),
            move_split: String::new(),
            move_failed: String::new(),
            move_attempts: 0,
            move_pending: false,
            // A fresh job has never crossed between the two stores.
            move_seq: 0,
            archive_shape: String::new(),
            inner_crc: 0,
            identity_name: String::new(),
            identity_imdb: String::new(),
            identity_src: String::new(),
            auto_retry_at: None,
            auto_retry_why: None,
            pp_params: Vec::new(),
            sab_pp: hook_pp,
            script_override: hook_script,
            replaces,
            // §77: filled in by the health prober on its next idle tick.
            // Deliberately not probed inline here - enqueue is called
            // from the HTTP handler, the watch folder and the RSS
            // poller, and none of them may block on a network round trip
            // to every configured server.
            health: None,
            // Counted at completion by the post-processing sweeps.
            cleaned_files: 0,
            cleaned_par2: 0,
            cleaned_trash: false,
        }));
        // §129 4a: a pre-queue REJECT files to history as Failed with
        // the reason - the dupe_action="fail" shape verbatim, so the
        // *arr contract (a failed grab means "search for another
        // release") and retry-from-history both hold. The spool .nzb
        // stays; a retry does not re-run the hook (SAB semantics).
        if let Some(why) = hook_reject {
            {
                let mut g = job.lock_ok();
                g.state = JobState::Failed;
                g.paused = false;
                g.priority = 0;
                g.fail_message = why;
                g.finished_at = Some(Instant::now());
                g.finished_unix = Some(unix_now());
            }
            self.history.lock_ok().push(job.clone());
            drop(publish);
            info!(
                target: "prequeue",
                "{nzo_id} filed to history as FAILED - rejected by the pre-queue \
                 script"
            );
            // §158.7: the DESTINATION store first, then the queue
            // snapshot. This job was never queued, so `save_queue` writes
            // a queue.json that does not carry it either way - which is
            // exactly what made the old order lossy rather than merely
            // odd. A kill (or an ENOSPC) between the two writes left the
            // record in NEITHER file: queue.json never had it and
            // history.jsonl did not have it yet, so the spooled .nzb sat
            // on disk named by no record anywhere and the *arr that
            // submitted it was never told the grab failed. Ordered this
            // way the torn state is "in history only", which is the whole
            // truth for a job that never reached the queue. Nothing here
            // depends on the queue write running first; all it carries of
            // this job is the id-allocator bump, and the restore's
            // wall-clock floor already covers an allocator bump that
            // never landed.
            let _ = self.history_upsert(std::slice::from_ref(&job));
            self.save_queue();
            self.life_emit_parked(&job);
            self.history_enforce_retention();
            return Ok(nzo_id);
        }
        // §129 2d, dupe_action = "fail": the job never queues - it files
        // straight to history as Failed, through the same seam every
        // history mutation uses (history_upsert beside save_queue), and
        // emits the job.failed lifecycle event a real failure would.
        // Retry from history remains the escape hatch: the spool .nzb
        // is in place and retry asks the duplicates question afresh.
        if let Some(c) = &collision
            && dupe_action == "fail"
        {
            {
                let mut g = job.lock_ok();
                g.state = JobState::Failed;
                g.paused = false;
                g.priority = 0;
                g.fail_message = format!(
                    "duplicate of {:?} ({}) - failed; the duplicates setting decides this",
                    c.name, c.where_
                );
                g.finished_at = Some(Instant::now());
                g.finished_unix = Some(unix_now());
            }
            self.history.lock_ok().push(job.clone());
            drop(publish);
            info!(
                target: "queue",
                "{nzo_id} filed to history as FAILED - duplicate of {} ({}), and \
                 duplicates are set to fail",
                c.name, c.nzo_id
            );
            // §158.7: the destination store first, for the reason
            // spelled out on the pre-queue REJECT arm above - this job
            // never queued either, so a kill between the two writes used
            // to lose it from both files.
            let _ = self.history_upsert(std::slice::from_ref(&job));
            self.save_queue();
            self.life_emit_parked(&job);
            self.history_enforce_retention();
            return Ok(nzo_id);
        }
        // §129 4a: the add joins the event ring and the queue in one
        // step, announced BEFORE the job is visible to anything that
        // could start it. Every add path funnels through here, so this
        // one emit covers all fourteen of them.
        //
        // The queue lock is what makes the ordering a guarantee rather
        // than a race: `pick_job` scans under this same lock, so a
        // runner that sees this job necessarily acquired the lock after
        // we released it, and its job.started is therefore behind our
        // job.added on the ring. Emitting AFTER the push instead let a
        // fast pick outrun a slow `save_queue` - a 16-way-loaded box put
        // job.started on the ring at seq 1, 54 ms ahead of the job.added
        // for the same nzo_id, which is a webhook consumer watching a
        // job start before it exists. The idle latch re-arms inside the
        // same window for the same reason: an idle sweep between the
        // push and a later store could emit a queue.idle that this add
        // has already invalidated.
        //
        // Deadlock-safe by lock order: the ring, the webhook channel and
        // the target list are leaves taken under the queue lock, and no
        // path takes them the other way round. The cost is that the
        // event now precedes `save_queue` rather than following it, so a
        // crash in that window loses a job a consumer was told about -
        // the same window every other reader of the add already had,
        // since the queue was live to the API at exactly this point.
        self.queue_idle_latch.store(false, Ordering::Relaxed);
        {
            let mut q = self.queue.lock_ok();
            self.life_emit(
                "job.added",
                json!({
                    "nzo_id": nzo_id,
                    "name": pairing_name,
                    "category": category,
                    "priority": enqueue_priority(priority, duplicate),
                    "origin": origin,
                    "total_bytes": total_bytes,
                    "duplicate": duplicate,
                    "paused": duplicate || priority == -2,
                }),
            );
            q.push_back(job);
        }
        // Published: the directory and the identity are now visible to
        // every other adder.
        drop(publish);
        if duplicate {
            info!(target: "queue", "added {nzo_id} as ALTERNATIVE (duplicate held)");
        } else {
            info!(target: "queue", "added {nzo_id}");
        }
        self.save_queue();
        // After the add is published and saved, never on its critical
        // path: a contended index costs this pairing, not the add.
        self.record_nzb_pairing(&pairing_name, origin, &nzb);
        Ok(nzo_id)
    }
}

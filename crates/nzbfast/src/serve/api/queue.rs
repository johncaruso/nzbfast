use super::super::*;
use super::ApiCtx;

pub(in crate::serve) fn dispatch(
    d: &Arc<Daemon>,
    req: &mut tiny_http::Request,
    params: &std::collections::HashMap<String, String>,
    mode: &str,
    ctx: &ApiCtx<'_>,
    api_body: &mut Option<Vec<u8>>,
) -> Option<Value> {
    Some(match mode {
        "pause" => {
            // pause&value=<minutes> = SAB's timed pause. value2=now
            // forces the immediate abort; default is a graceful
            // wind-down (finish in-flight, keep the queue for resume).
            let mins = params
                .get("value")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            let graceful = params.get("value2").map(|v| v != "now").unwrap_or(true);
            timed_pause(d, mins, graceful);
            json!({"status": true})
        }
        "resume" => {
            // Deliberately does NOT clear offline any more.
            //
            // It used to, and the reasoning was sound at the time:
            // with nothing gating the download loop, leaving the flag
            // set while the queue ran would have every job fail
            // against a provider we had promised not to touch. That
            // premise is gone - the loop now refuses to start a job
            // while offline - and what was left was the last way a
            // remote client could put the operator back on their
            // provider without asking. An *arr sends resume as a
            // matter of course; going offline is a confirmed,
            // persisted act meaning "my account is free for another
            // machine". A routine resume must not undo it.
            //
            // So resume means what it says: unpause the queue. The
            // queue then sits still, visibly Offline, until someone
            // presses online. `mode=online` is the one that
            // reconnects, and it is one click.
            d.paused.store(false, Ordering::Relaxed);
            d.pause_gen.fetch_add(1, Ordering::Relaxed);
            *d.pause_until.lock_ok() = None;
            persist_pause(d);
            json!({"status": true})
        }
        // The instant sibling of the idle-release timeout: hang
        // up everything now, so the account is usable from
        // another machine without waiting one out.
        "offline" | "online" => {
            let want = mode == "offline";
            d.set_offline(want);
            json!({"status": true, "offline": want})
        }
        // M23d: airdate calendar - episodes of watched shows
        // from a week back to three weeks out, joined with what
        // the watcher has grabbed. String compares work because
        // dates are ISO "YYYY-MM-DD".
        "watch_calendar" => {
            use crate::watchlist as wl;
            let days = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|t| (t.as_secs() / 86_400) as i64)
                .unwrap_or(0);
            let civil_str = |d: i64| {
                let (y, m, dd) = civil_from_days(d);
                format!("{y:04}-{m:02}-{dd:02}")
            };
            let (today, lo, hi) = (civil_str(days), civil_str(days - 7), civil_str(days + 21));
            let items = d.watchlist.lock_ok().clone();
            let st = d.watch_state.lock_ok().clone();
            let mut entries: Vec<(String, String, Value)> = Vec::new();
            for item in items.iter().filter(|i| i.enabled && i.kind == "tv") {
                let key = format!("eplist:{}", crate::wall::norm_title(&item.title));
                let eps: Vec<crate::wall::EpInfo> = d
                    .with_index_read(|ix| ix.kv_get(&key))
                    .and_then(|s| serde_json::from_str::<Value>(&s).ok())
                    .and_then(|v| serde_json::from_value(v["episodes"].clone()).ok())
                    .unwrap_or_default();
                for ep in eps {
                    if ep.airdate.is_empty()
                        || ep.airdate < lo
                        || ep.airdate > hi
                        || !wl::in_range_spec(&item.seasons, ep.season)
                        || !wl::in_range_spec(&item.episodes, ep.episode)
                    {
                        continue;
                    }
                    // A season pack covers this episode too, so
                    // the calendar asks what the slot EFFECTIVELY
                    // has - otherwise a season grabbed as one
                    // pack drew a calendar of empty ticks.
                    let have =
                        wl::covering(&st.slots, item.id, &wl::episode_slot(ep.season, ep.episode))
                            .map(|s| s.quality.clone());
                    entries.push((
                        ep.airdate.clone(),
                        item.title.clone(),
                        json!({
                            "title": item.title, "season": ep.season,
                            "episode": ep.episode, "name": ep.name,
                            "airdate": ep.airdate,
                            "aired": ep.airdate <= today,
                            "have": have,
                            // TVmaze sends a synopsis for
                            // essentially every aired episode and
                            // we used to discard all of them, so
                            // "what is this one" had no answer.
                            "summary": ep.summary,
                            "runtime": ep.runtime,
                        }),
                    ));
                }
            }
            entries.sort_by(|a, b| (&a.0, &a.1).cmp(&(&b.0, &b.1)));
            json!({
                "today": today,
                "entries": entries.into_iter().map(|(_, _, v)| v).collect::<Vec<_>>(),
            })
        }
        // M23: run a watchlist pass immediately (after an edit,
        // or just impatience).
        "watchlist_check_now" => {
            d.watch_now.notify_one();
            json!({"status": true})
        }
        // M23: items with what's been grabbed for each - the
        // dashboard's per-row status line.
        "watchlist_status" => {
            let items = d.watchlist.lock_ok().clone();
            let st = d.watch_state.lock_ok().clone();
            let out: Vec<Value> = items
                .iter()
                .map(|it| {
                    let prefix = format!("{}:", it.id);
                    let mut slots: Vec<(String, Value)> = st
                        .slots
                        .iter()
                        .filter(|(k, _)| k.starts_with(&prefix))
                        .map(|(k, s)| {
                            let slot = k[prefix.len()..].to_string();
                            let upgrading = st.pending.iter().any(|p| &p.slot == k);
                            (
                                slot.clone(),
                                json!({
                                    "slot": slot, "quality": s.quality,
                                    "stem": s.stem, "nzo_id": s.nzo_id,
                                    "grabbed_at": s.grabbed_at,
                                    "upgrading": upgrading,
                                }),
                            )
                        })
                        .collect();
                    slots.sort_by(|a, b| b.0.cmp(&a.0)); // newest episode first
                    json!({
                        "id": it.id,
                        "slots": slots.into_iter().map(|(_, v)| v).collect::<Vec<_>>(),
                        // §74: the last grab this item got because the
                        // release ARRIVED, not because a pass came round.
                        // Absent until one happens - the dashboard shows
                        // the line only when there is something true to
                        // say.
                        "instant": st.instant.get(&it.id.to_string()),
                    })
                })
                .collect();
            // Is the instant path armed at all right now? The badge is a
            // claim about what will happen, so it has to read the same
            // two switches the arrival hooks do: the feature's own, and
            // the indexer that produces the arrivals.
            json!({
                "items": out,
                "instant_on": d.watchlist_instant.load(Ordering::Relaxed) && !d.indexer_off(),
            })
        }
        // Recategorize a QUEUED job. The NZBGet facade has had
        // this as `GroupSetCategory` since M26 and the SAB side
        // only ever had the history-item form, so which client
        // type the user picked decided whether it worked.
        //
        // Nothing has been written yet, so unlike the history
        // form this moves no files - it re-derives the output
        // directory under the new category, which is exactly what
        // a retry does.
        "change_cat" => {
            let id = params.get("value").cloned().unwrap_or_default();
            let cat = params.get("value2").cloned().unwrap_or_default();
            let cat = cat.trim().trim_matches('*').trim().to_string();
            // Untrusted: a single contained path component, the
            // same guard as enqueue and the history form.
            let cat = if cat.is_empty() {
                cat
            } else {
                nzbkit::disk::sanitize_filename(&cat)
            };
            // Three phases, and they have to stay three: picking
            // the new directory goes through `dir_claim`, which
            // locks the queue itself, so computing it while
            // holding that lock deadlocks the daemon.
            //
            // Queued, stated positively. `!= Downloading` also
            // matched a job that had just finished and was still
            // in the queue waiting for `park` to file it - the
            // state flip and the queue removal are not one step.
            // Re-deriving out_dir for a job whose bytes are
            // already on disk points its history entry at a
            // directory the files were never written to, and the
            // caller is told `true` for a move nothing performed.
            // Held, deferred and duplicate jobs are all Queued,
            // so none of them lose the ability to be refiled.
            let target = d.queue.lock_ok().iter().find_map(|j| {
                let g = j.lock_ok();
                (g.nzo_id == id && g.state == JobState::Queued)
                    .then(|| (j.clone(), g.name.clone(), g.category.clone()))
            });
            match target {
                // Not queued - it may already be in history. A
                // download in the wrong category used to be
                // unfixable the moment it finished, which is
                // exactly when people notice.
                None => history_change_cat(d, &id, &cat),
                // Already there: don't re-derive, or the job's own
                // directory reads as taken and the name climbs .2.
                Some((_, _, current)) if current == cat => json!({"status": true}),
                Some((job, name, _)) => {
                    // Choosing a directory and publishing it have to be ONE
                    // transaction, under the same lock `add` uses: between
                    // the `dir_claim` probe below and the assignment, this
                    // job still names its OLD directory, so a concurrent
                    // add reads the new one as Free and takes it - two jobs
                    // writing one folder, which is the hole the 2 Aug sweep
                    // closed for `add` and this path never joined.
                    //
                    // Scoped to this arm on purpose: `history_change_cat`
                    // takes `add_lock` itself, and it is not reentrant.
                    // Taken with no queue/history/job lock held - `add_lock`
                    // sits above all three, and `dir_claim` locks every job
                    // in both lists.
                    let _publish = d.add_lock.lock_ok();
                    let (dir, _) =
                        refile_out_dir(&d.out_root.read_ok().clone(), &cat, &name, &|p| {
                            d.dir_claim(p)
                        });
                    {
                        let mut g = job.lock_ok();
                        g.category = cat.clone();
                        g.out_dir = dir;
                    }
                    d.register_cat(&cat);
                    d.save_queue();
                    json!({"status": true})
                }
            }
        }
        "retry" => {
            let id = params.get("value").cloned().unwrap_or_default();
            // The *arrs adopt the returned nzo_id as the new
            // tracking id (SAB may reissue; we keep it stable).
            json!({"status": d.retry(&id), "nzo_id": id})
        }
        // M24: attach an archive password to a job. Queued jobs
        // use it at completion; a history job flagged
        // password_required gets an immediate background unlock
        // attempt (+ pending TV filing once the video appears).
        "set_password" => {
            let id = params.get("value").cloned().unwrap_or_default();
            let pw = params.get("password").cloned().unwrap_or_default();
            if pw.is_empty() {
                json!({"status": false, "error": "empty password"})
            } else {
                let hit = |j: &&Arc<Mutex<Job>>| j.lock_ok().nzo_id == id;
                let found = d
                    .queue
                    .lock()
                    .unwrap()
                    .iter()
                    .find(hit)
                    .cloned()
                    .or_else(|| d.history.lock_ok().iter().find(hit).cloned());
                match found {
                    None => json!({"status": false, "error": "unknown nzo_id"}),
                    Some(job) => {
                        let (locked, out_dir, name, cat, tv, nzb) = {
                            let mut j = job.lock_ok();
                            j.password = Some(pw.clone());
                            (
                                j.password_required,
                                j.out_dir.clone(),
                                j.name.clone(),
                                j.category.clone(),
                                j.tv_sort,
                                j.nzb_path.clone(),
                            )
                        };
                        // C1: the job may be DOWNLOADING right now.
                        // Its task captured j.password once at start,
                        // so hand the live run this one through the
                        // hub cell too - the finish tail re-reads it
                        // (network drain + fallback ladder) and
                        // unlocks in THIS run instead of parking the
                        // job as password_required for a manual
                        // retry. Owner-tagged; a job that finishes
                        // between this write and the tail's read
                        // just parks exactly as it did before.
                        if d.active_stream.lock_ok().as_deref() == Some(id.as_str()) {
                            *d.hub.late_password.lock_ok() = Some((id.clone(), pw.clone()));
                        }
                        if locked {
                            let d2 = d.clone();
                            let job2 = job.clone();
                            // Mark the job busy for the whole task.
                            // unlock + finalize_names rewrite out_dir
                            // for many seconds on a large encrypted
                            // set, and history_change_cat's only
                            // interlock is this flag - without it a
                            // category change moves the directory out
                            // from under the running extractor, and
                            // the two then race to write j.out_dir
                            // with whichever lands second winning.
                            job.lock_ok().finalizing = true;
                            tokio::task::spawn_blocking(move || {
                                // Cleared on EVERY exit below,
                                // including the unlock-failed path,
                                // or a wrong password would wedge the
                                // job as permanently finalizing.
                                struct ClearFinalizing(Arc<Mutex<Job>>);
                                impl Drop for ClearFinalizing {
                                    fn drop(&mut self) {
                                        if let Ok(mut j) = self.0.lock() {
                                            j.finalizing = false;
                                        }
                                    }
                                }
                                let _clear = ClearFinalizing(job2.clone());
                                if crate::smart::unlock(&out_dir, &pw) {
                                    let post_year = match post_year_of(&nzb) {
                                        0 => crate::identify::current_year(),
                                        y => y,
                                    };
                                    let done = d2.finalize_names(
                                        &out_dir,
                                        &FinalizeJob {
                                            name: &name,
                                            cat: &cat,
                                            tv_sort: tv,
                                            post_year,
                                        },
                                    );
                                    let mut j = job2.lock_ok();
                                    j.password_required = false;
                                    if j.fail_message == "password required to unpack" {
                                        j.fail_message.clear();
                                    }
                                    if !done.identify.is_empty() {
                                        j.identify = done.identify;
                                    }
                                    if let Some(dest) = done.moved {
                                        j.filed = j.tv_sort && is_season_dir(&dest);
                                        // The suffix and episode title
                                        // filing just used, kept for
                                        // the delete that will need
                                        // them later.
                                        j.filed_suffix = j.filed.then_some(done.suffix);
                                        j.filed_title = j.filed.then_some(done.filed_title);
                                        j.out_dir = dest;
                                    }
                                    drop(j);
                                    d2.save_queue();
                                } else {
                                    let mut j = job2.lock_ok();
                                    j.fail_message = "password did not unlock the archive".into();
                                    drop(j);
                                    d2.save_queue();
                                    info!(target: "unlock", "{name:?}: password did not unlock");
                                }
                            });
                            json!({"status": true, "unpacking": true})
                        } else {
                            d.save_queue();
                            json!({"status": true})
                        }
                    }
                }
            }
        }
        // M14h: live pool + pipeline stats of the active download -
        // the overlapping-lanes view no sequential client can draw.
        "stats" => {
            let servers: Vec<Value> = d
                .hub
                .pool_live
                .lock()
                .unwrap()
                .as_ref()
                .map(|l| {
                    l.servers
                        .iter()
                        .map(|s| {
                            json!({
                                "host": s.host,
                                "budget": s.budget,
                                "connected": s.connected.load(Ordering::Relaxed),
                                "bytes": s.bytes.load(Ordering::Relaxed),
                                // This-run article dispatches + 430s so the UI can
                                // explain an idle provider: 0 conns with missing==tried
                                // means it doesn't have this content (430'd it all),
                                // not that it's broken.
                                "tried": s.articles_tried.load(Ordering::Relaxed),
                                "missing": s.articles_missing.load(Ordering::Relaxed),
                                // §35: why this server contributed
                                // nothing, in its own words. A user
                                // with one expired provider was
                                // paying for it on every download
                                // with nothing anywhere saying so.
                                "refused": s.refusal.lock_ok().as_ref().map(|r| {
                                    json!({"permanent": r.permanent, "line": r.line})
                                }),
                                // Lifetime completion% (reliability
                                // ledger) for the Providers card.
                                "completion_pct": d.reliability(&s.host).map(|(t, m)| {
                                    100.0 * (t.saturating_sub(m)) as f64 / t as f64
                                }),
                            })
                        })
                        .collect()
                })
                .unwrap_or_default();
            let (vdone, vbad, vtotal) = d
                .hub
                .verifier
                .lock()
                .unwrap()
                .as_ref()
                .map(|v| {
                    let (done, bad) = v.live_counts();
                    let total: u64 = v
                        .set()
                        .map(|s| s.files.iter().map(|f| f.blocks.len() as u64).sum())
                        .unwrap_or(0);
                    (done, bad, total)
                })
                .unwrap_or((0, 0, 0));
            let files: Vec<Value> = d
                .hub
                .extractor
                .lock()
                .unwrap()
                .as_ref()
                .map(|(_owner, ex)| {
                    let mut ws = ex.writers_snapshot();
                    ws.sort_by_key(|(_, w)| std::cmp::Reverse(w.size));
                    ws.into_iter()
                        .take(12)
                        .map(|(name, w)| {
                            json!({
                                "name": name,
                                "size": w.size,
                                "written": w.written(),
                            })
                        })
                        .collect()
                })
                .unwrap_or_default();
            // Host resources for the dashboard's combined chart -
            // one getrusage + task_info + statvfs per poll, no
            // sampling thread. CPU% is % of ALL cores (0-100),
            // from the cpu-time delta since the previous poll;
            // sub-500 ms re-polls (a second open dashboard) reuse
            // the last reading instead of amplifying noise.
            let cpu_pct = {
                let now = Instant::now();
                let cpu = nzbkit::mem::cpu_time_secs().unwrap_or(0.0);
                let ncpu = std::thread::available_parallelism().map_or(1, |n| n.get()) as f64;
                let mut prev = d.cpu_sample.lock_ok();
                match *prev {
                    Some((t0, _, last)) if now.duration_since(t0).as_secs_f64() < 0.5 => last,
                    Some((t0, c0, _)) => {
                        let wall = now.duration_since(t0).as_secs_f64();
                        let pct = ((cpu - c0) / wall / ncpu * 100.0).clamp(0.0, 100.0);
                        *prev = Some((now, cpu, pct));
                        pct
                    }
                    None => {
                        *prev = Some((now, cpu, 0.0));
                        0.0
                    }
                }
            };
            let (disk_free, disk_total) = disk_stat_walk(&d.out_dir()).unwrap_or((0, 0));
            // Phase 0(b) nested-archive prevalence (process lifetime):
            // how often nested layers appear, of what inner type, and
            // whether they streamed or demoted - real-world data for
            // future nested-format priorities.
            let nested_prevalence = {
                let np = nzbkit::extract::nested_prevalence();
                json!({
                    "levels": np.levels,
                    "in_stream": np.in_stream,
                    "demoted": np.demoted,
                    "disk": np.disk,
                    "rar_store": np.rar_store,
                    "rar_compressed": np.rar_compressed,
                    "rar_encrypted": np.rar_encrypted,
                    "sevenz": np.sevenz,
                    "other": np.other,
                })
            };
            json!({
                "active": d.started_at.lock_ok().is_some(),
                "downloaded": d.progress.load(Ordering::Relaxed),
                "total": d.active_total.load(Ordering::Relaxed),
                "servers": servers,
                "verify": {"blocks_done": vdone, "blocks_bad": vbad, "blocks_total": vtotal},
                "files": files,
                "host": {
                    "cpu_pct": (cpu_pct * 10.0).round() / 10.0,
                    "rss_bytes": nzbkit::mem::dashboard_rss().unwrap_or(0),
                    "rss_peak_bytes": nzbkit::mem::peak_rss().unwrap_or(0),
                    "rss_budget": d.mem_budget_total,
                    "disk_free_bytes": disk_free,
                    "disk_total_bytes": disk_total,
                    // Cumulative engine disk writes - the client
                    // derives a live write rate from the deltas.
                    "disk_write_bytes": nzbkit::disk::bytes_written(),
                },
                "nested_prevalence": nested_prevalence,
            })
        }
        "addfile" => {
            // Multipart body: extract the first file part.
            let boundary = req
                .headers()
                .iter()
                .find(|h| h.field.equiv("Content-Type"))
                .and_then(|h| {
                    h.value
                        .as_str()
                        .split("boundary=")
                        .nth(1)
                        .map(|b| b.trim_matches('"').to_string())
                });
            // Generous: an NZB for a 190 GB job is tens of MB.
            // The form pre-read above may already hold the body.
            let raw = api_body
                .take()
                .unwrap_or_else(|| read_body_capped(req.as_reader(), 256 << 20));
            match boundary.and_then(|b| multipart_file(&raw, &b)) {
                Some((fname, bytes)) => {
                    // Sonarr and Radarr send the release name in
                    // `nzbname` on addfile as well as addurl, and
                    // only addurl was reading it - so the job took
                    // its name from the multipart filename, which
                    // for a Prowlarr-proxied grab is a numeric id.
                    // `origin_of` has meanwhile been treating the
                    // presence of this very parameter as the "an
                    // *arr sent this" signal.
                    let fname = params
                        .get("nzbname")
                        .map(|s| s.trim())
                        .filter(|s| !s.is_empty())
                        .map(str::to_string)
                        .unwrap_or(fname);
                    let cat = params.get("cat").cloned().unwrap_or_default();
                    let cat = if cat == "*" { String::new() } else { cat };
                    let pw = params.get("password").map(String::as_str);
                    // stream=1: watch-while-downloading add - Force
                    // priority (starts next even while paused) and
                    // the response carries the player-handoff links.
                    let stream = params.get("stream").map(String::as_str) == Some("1");
                    let prio = if stream { 2 } else { param_priority(params) };
                    let origin = api_origin(ctx.ua_hdr, origin_of(params));
                    match d.enqueue(&bytes, &fname, &cat, prio, pw, &origin, false) {
                        Ok(id) if stream => json!({
                            "status": true, "nzo_ids": [id],
                            "m3u": format!("http://{}/m3u/{id}{}", ctx.host_hdr, ctx.key_q),
                            "stream": format!("http://{}/stream/{id}?t={}", ctx.host_hdr, d.stream_token(&id)),
                        }),
                        Ok(id) => json!({"status": true, "nzo_ids": [id]}),
                        Err(e) => json!({"status": false, "error": e.to_string()}),
                    }
                }
                None => json!({"status": false, "error": "no nzb file in request"}),
            }
        }
        "addurl" => {
            let url = params.get("name").cloned().unwrap_or_default();
            let cat = params.get("cat").cloned().unwrap_or_default();
            let cat = if cat == "*" { String::new() } else { cat };
            let name = params
                .get("nzbname")
                .cloned()
                .unwrap_or_else(|| url.rsplit('/').next().unwrap_or("download.nzb").to_string());
            let pw = params.get("password").cloned();
            let stream = params.get("stream").map(String::as_str) == Some("1");
            let prio = if stream { 2 } else { param_priority(params) };
            let origin = api_origin(ctx.ua_hdr, origin_of(params));
            match fetch_url(&url) {
                Ok(f) => {
                    match d.enqueue_fetched(&f, &name, &cat, prio, pw.as_deref(), 0, &origin, false)
                    {
                        Ok(id) if stream => json!({
                            "status": true, "nzo_ids": [id],
                            "m3u": format!("http://{}/m3u/{id}{}", ctx.host_hdr, ctx.key_q),
                            "stream": format!("http://{}/stream/{id}?t={}", ctx.host_hdr, d.stream_token(&id)),
                        }),
                        Ok(id) => json!({"status": true, "nzo_ids": [id]}),
                        Err(e) => json!({"status": false, "error": e.to_string()}),
                    }
                }
                Err(e) => json!({"status": false, "error": e.to_string()}),
            }
        }
        // NZBLNK: a link with no NZB behind it. The German and
        // Dutch boards hand out `nzblnk:?h=…` instead of a file
        // because the posting is obfuscated - there is nothing
        // to link to until somebody has scanned the group - and
        // the client is expected to resolve the header itself.
        //
        // We own both halves already, so the ladder is short and
        // in cost order:
        //   1. our own header index, which needs no network at
        //      all and can emit the NZB from stored segment ids;
        //   2. the user's configured indexers over the M35
        //      client, under the same daily budgets and backoff
        //      every other pull search obeys.
        // Deliberately NOT in the add-only key's allowlist: rung
        // 2 spends the user's indexer quota, which an add-only
        // credential has no business doing.
        //
        // `p` becomes the job password, so the existing
        // password-chain unlock opens the archive without the
        // user pasting it anywhere; `t` becomes the job name.
        "addnzblnk" => {
            // `link` is ours; `name` is where addurl puts its
            // URL, so a caller that treats the two modes alike
            // still works.
            let raw = params
                .get("link")
                .or_else(|| params.get("name"))
                .cloned()
                .unwrap_or_default();
            match nzbkit::nzblnk::parse(&raw) {
                // `reason` is the stable, machine-readable half:
                // the dashboard says these two in the user's own
                // language rather than echoing English back.
                Err(e) => {
                    json!({"status": false, "reason": "badlink", "error": e.to_string()})
                }
                Ok(l) => {
                    let cat = params.get("cat").cloned().unwrap_or_default();
                    let cat = if cat == "*" { String::new() } else { cat };
                    let prio = param_priority(params);
                    let dupe_ok = params.get("dupe_ok").map(String::as_str) == Some("1");
                    let pw = (!l.password.is_empty()).then(|| l.password.clone());
                    resolve_nzblnk(d, &l, &cat, prio, pw.as_deref(), dupe_ok)
                }
            }
        }
        // Delete a rejected watch-folder file by NAME. Only files
        // currently in the failed set can be deleted - the name is
        // matched against tracked paths, never joined to a path,
        // so it can't reach anything else on disk.
        "watch_failed_delete" => {
            let name = params.get("value").cloned().unwrap_or_default();
            let path = d
                .watch_failed
                .lock()
                .unwrap()
                .keys()
                .find(|p| p.file_name().is_some_and(|f| f.to_string_lossy() == name))
                .cloned();
            match path {
                None => json!({"status": false, "error": "no such rejected file"}),
                Some(p) => match std::fs::remove_file(&p) {
                    Ok(()) => {
                        d.watch_failed.lock_ok().remove(&p);
                        info!(target: "watch", "deleted rejected {name}");
                        json!({"status": true})
                    }
                    Err(e) => json!({"status": false, "error": e.to_string()}),
                },
            }
        }
        "queue" => {
            let value = params.get("value").cloned().unwrap_or_default();
            let hit_id = |id: &str| value == "all" || value.split(',').any(|v| v == id);
            let hit = |j: &Arc<Mutex<Job>>| hit_id(&j.lock_ok().nzo_id);
            match params.get("name").map(String::as_str) {
                Some("delete") => {
                    // A deleted job's prefetch sidecar must stop
                    // writing to its directory.
                    d.poke_sidecar(hit_id);
                    let del_files = params.get("del_files").map(String::as_str) == Some("1");
                    let mut stopped_active = false;
                    let mut q = d.queue.lock_ok();
                    let before = q.len();
                    q.retain(|j| {
                        if hit(j) {
                            let mut g = j.lock_ok();
                            let active = g.state == JobState::Downloading;
                            if active {
                                // The pipeline is running - mark it
                                // for silent drop and abort below.
                                // park() drops the record and removes
                                // its spooled .nzb.
                                g.tombstone = true;
                                stopped_active = true;
                            } else {
                                // Non-active: the record is gone for
                                // good, so its spooled NZB is dead
                                // weight (retry only applies to
                                // history). Remove it now.
                                //
                                // Tombstoned all the same. A queued
                                // job can still be RUNNING in the
                                // prefetch sidecar, and the poke
                                // above only stops a download that
                                // has not finished: an Ok already on
                                // its way to the tail would otherwise
                                // unlock, rename, file into the TV
                                // library, move to the destination
                                // folder, run the pp-script and park
                                // the deleted job into history. The
                                // flag makes that tail a no-op.
                                g.tombstone = true;
                                let _ = std::fs::remove_file(&g.nzb_path);
                            }
                            if del_files {
                                if active || g.finalizing {
                                    // Writers are still live; removing
                                    // now just lets the next positioned
                                    // write recreate the files and
                                    // orphan them. Defer to park(),
                                    // which runs after the fetch drains.
                                    //
                                    // `finalizing` matters for the same
                                    // reason and is NOT covered by
                                    // `active`: a Completed job whose
                                    // post-processing (unlock, rename,
                                    // TV filing, NAS move) is still
                                    // running has left Downloading, so
                                    // this used to take the else arm and
                                    // remove_dir_all the very directory
                                    // the mover was reading from - half
                                    // deleting a tree under it, or
                                    // deleting an emptied source while
                                    // the payload sat at the destination
                                    // with no record left to delete it
                                    // by. park() already implements the
                                    // deferral and is always reached for
                                    // a finalizing job (its tail holds
                                    // its own Arc and parks after
                                    // finalize_completed), so the files
                                    // still go. Deferring on `finalizing`
                                    // only, not on every non-active
                                    // state: a never-run Queued job has
                                    // no tail, so park would never fire
                                    // and its files would never be
                                    // removed at all.
                                    g.del_on_drop = true;
                                } else {
                                    let tail = delete_tail(&g, || d.job_suffix(filed_stem(&g)));
                                    remove_job_files(&g.out_dir, filed_stem(&g), g.filed, &tail);
                                }
                            }
                            false
                        } else {
                            true
                        }
                    });
                    let removed = q.len() < before;
                    drop(q);
                    // Only the job that OWNS the hub may fire its
                    // abort. `state == Downloading` is NOT that
                    // test: job N stays Downloading through its
                    // whole post-network tail while job N+1 is
                    // already on the wire and owns hub.abort /
                    // hub.queue_ctl (they are overwritten per job
                    // and carry no owner tag), so deleting N during
                    // its tail aborted N+1 - a healthy, unrelated
                    // download. N+1 then failed permanently (a
                    // Local fail_kind is not `transient()`, so no
                    // auto-retry) and fired its pp-script, failure
                    // notification and failure re-grab on a good
                    // release, while N was never stopped at all
                    // (its abort flag was last read long before).
                    // `active_stream` is the owner - the watchdog
                    // was already fixed to steer by it, for exactly
                    // this hazard.
                    if stopped_active && d.owns_hub(hit_id) {
                        if let Some(f) = d.hub.abort.lock_ok().as_ref() {
                            f.store(true, Ordering::Relaxed);
                        }
                        if let Some(c) = d.hub.queue_ctl.lock_ok().as_ref() {
                            c.abort();
                        }
                        info!(target: "queue", "active download stopped by user");
                    }
                    if removed {
                        d.save_queue();
                    }
                    json!({"status": removed})
                }
                Some(op @ ("pause" | "resume")) => {
                    if op == "pause" {
                        // Pausing a job also stops its prefetch.
                        d.poke_sidecar(hit_id);
                    }
                    let mut n = 0;
                    for j in d.queue.lock_ok().iter().filter(|j| hit(j)) {
                        j.lock_ok().paused = op == "pause";
                        n += 1;
                    }
                    // The flag alone only takes effect when a job
                    // next enters the queue. Pausing the item that
                    // was ACTUALLY downloading left it running at
                    // full speed while this answered success and
                    // the queue kept showing it as Downloading -
                    // so an nzb360 tap to free bandwidth did
                    // nothing at all. Wind the transfer down too.
                    if op == "pause" && n > 0 {
                        d.suspend_matching(true, |g| hit_id(&g.nzo_id));
                    }
                    if n > 0 {
                        d.save_queue();
                    }
                    json!({"status": n > 0})
                }
                // SAB parity: mode=queue&name=switch&value=<nzo_id>
                // &value2=<index> moves the item to that queue
                // position (the dashboard's drag-to-reorder). Order
                // only breaks ties within a priority - pick_job
                // still runs Force/High first - and the active
                // download can't be moved.
                Some("switch") => {
                    let pos: usize = params
                        .get("value2")
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(0);
                    let mut q = d.queue.lock_ok();
                    let from = q.iter().position(|j| j.lock_ok().nzo_id == value);
                    match from {
                        Some(i) if q[i].lock_ok().state != JobState::Downloading => {
                            let job = q.remove(i).unwrap();
                            // A manual reorder reasserts the
                            // user's order - the watchdog's
                            // deferral no longer applies, and
                            // neither does §77's health sink. The
                            // health VERDICT stays: it is what the
                            // servers said, and the row goes on
                            // saying it.
                            {
                                let mut g = job.lock_ok();
                                g.deferred = false;
                                if let Some(h) = g.health.as_mut() {
                                    h.waived = true;
                                }
                            }
                            let to = pos.min(q.len());
                            q.insert(to, job);
                            drop(q);
                            d.save_queue();
                            json!({"status": true, "position": to})
                        }
                        Some(_) => json!({
                            "status": false,
                            "error": "cannot move the active download"
                        }),
                        None => {
                            json!({"status": false, "error": "unknown nzo_id"})
                        }
                    }
                }
                Some("priority") => {
                    // SAB's priority dropdown has a "Default" entry
                    // and sends the -100 sentinel for it, so it has
                    // to be resolved here too - storing the sentinel
                    // would sort the job below Low while every
                    // client labelled it Normal. (-2, "add paused",
                    // is only meaningful on an ADD and is left
                    // exactly as it was.)
                    let prio: i32 = match params
                        .get("value2")
                        .and_then(|v| super::super::sabcompat::parse_priority_token(v))
                        .unwrap_or(0)
                    {
                        SAB_DEFAULT_PRIORITY => 0,
                        p => p,
                    };
                    let mut n = 0;
                    for j in d.queue.lock_ok().iter().filter(|j| hit(j)) {
                        let mut g = j.lock_ok();
                        g.priority = prio;
                        // Explicit priority overrides a watchdog
                        // deferral - and §77's health sink, which is an
                        // advisory guess and does not get to argue with
                        // an order the user has just given.
                        g.deferred = false;
                        if let Some(h) = g.health.as_mut() {
                            h.waived = true;
                        }
                        n += 1;
                    }
                    if n > 0 {
                        d.save_queue();
                    }
                    json!({"status": n > 0, "position": -1})
                }
                _ => queue_json(d, params),
            }
        }
        "history" => {
            let value = params.get("value").cloned().unwrap_or_default();
            let find = |id: &str| {
                d.history
                    .lock()
                    .unwrap()
                    .iter()
                    .find(|j| j.lock_ok().nzo_id == id)
                    .cloned()
            };
            match params.get("name").map(String::as_str) {
                // Open the finished item on the DAEMON's machine
                // (the normal local setup): value2 "folder" reveals
                // the download dir, "file" opens the largest media
                // file in the OS default player.
                Some("open") => {
                    let what = params.get("value2").map(String::as_str).unwrap_or("folder");
                    match find(&value) {
                        None => json!({"status": false, "error": "unknown nzo_id"}),
                        Some(job) => {
                            let dir = job.lock_ok().out_dir.clone();
                            let target = if what == "file" {
                                largest_media_file(&dir).unwrap_or_else(|| dir.clone())
                            } else {
                                dir.clone()
                            };
                            json!({"status": os_open(&target), "path": target.to_string_lossy()})
                        }
                    }
                }
                // Re-categorize: move the files to the new
                // category's folder and update the record.
                Some("set_cat") => {
                    let cat = params.get("value2").cloned().unwrap_or_default();
                    let cat = cat.trim().trim_matches('*').trim().to_string();
                    // Untrusted: keep it a single contained path
                    // component so the rename target can't escape
                    // out_root (bug sweep - same class as enqueue).
                    let cat = if cat.is_empty() {
                        cat
                    } else {
                        nzbkit::disk::sanitize_filename(&cat)
                    };
                    // One implementation with change_cat's history
                    // leg. This used to rename under the download
                    // root only - ignoring the completed-move
                    // destinations, failing across filesystems
                    // (fs::rename cannot cross onto a NAS), and
                    // never persisting - so a recategorized job
                    // forgot its category on restart.
                    history_change_cat(d, &value, &cat)
                }
                Some("delete") => {
                    let del_files = params.get("del_files").map(String::as_str) == Some("1");
                    // A recategorize is moving one of these payloads on
                    // disk right now. It snapshotted the record before
                    // the move and writes `out_dir` back afterwards, so
                    // deleting the record (and its files) underneath
                    // leaves the moved data orphaned at a destination
                    // nothing names, or half-deleted across both
                    // folders. Refuse for the whole request rather than
                    // silently skipping one id of a batch.
                    let busy: Vec<String> = {
                        let m = d.moving.lock_ok();
                        value
                            .split(',')
                            .map(str::trim)
                            .filter(|s| m.contains(*s))
                            .map(str::to_string)
                            .collect()
                    };
                    if !busy.is_empty() {
                        return Some(json!({"status": false,
                            "error": format!(
                                "{} is having its files moved right now - try again when it settles",
                                busy.join(", "))}));
                    }
                    // Snapshot the queue's directories BEFORE the
                    // history lock: they are claimants too, and
                    // taking the two locks in this order everywhere
                    // is what keeps them from deadlocking.
                    let queue_dirs: Vec<PathBuf> = d
                        .queue
                        .lock()
                        .unwrap()
                        .iter()
                        .map(|j| j.lock_ok().out_dir.clone())
                        .collect();
                    let mut h = d.history.lock_ok();
                    let before = h.len();
                    let records: Vec<DeleteRecord> = h
                        .iter()
                        .map(|j| {
                            let g = j.lock_ok();
                            DeleteRecord {
                                nzo_id: g.nzo_id.clone(),
                                state: g.state,
                                out_dir: g.out_dir.clone(),
                                filed: g.filed,
                                locked: g.password_required,
                            }
                        })
                        .collect();
                    // Decided in one pass over the WHOLE list, so
                    // the "somebody else still lives here" test sees
                    // the records that survive rather than the ones
                    // about to go (see plan_history_delete).
                    let plan = plan_history_delete(&records, &value, &queue_dirs);
                    for (j, p) in h.iter().zip(&plan) {
                        if !p.doomed {
                            continue;
                        }
                        let g = j.lock_ok();
                        // The record is being deleted for good -
                        // its spooled .nzb (kept until now for
                        // retry) is now dead weight.
                        let _ = std::fs::remove_file(&g.nzb_path);
                        if del_files {
                            if p.may_remove_files {
                                let tail = delete_tail(&g, || d.job_suffix(filed_stem(&g)));
                                remove_job_files(&g.out_dir, filed_stem(&g), g.filed, &tail);
                            } else {
                                // A verified re-download published
                                // over this record's directory and
                                // lives there now. Removing the
                                // record is right; removing the
                                // files would destroy the newer job.
                                info!(
                                    target: "history",
                                    "{}: record removed, files kept - {} \
                                             belongs to another job now",
                                    g.nzo_id,
                                    g.out_dir.display()
                                );
                            }
                        }
                    }
                    // By id, not by position: nzo_ids are unique,
                    // and a positional retain would be one refactor
                    // away from deleting the wrong record.
                    let doomed: std::collections::HashSet<&str> = records
                        .iter()
                        .zip(&plan)
                        .filter(|(_, p)| p.doomed)
                        .map(|(r, _)| r.nzo_id.as_str())
                        .collect();
                    h.retain(|j| !doomed.contains(j.lock_ok().nzo_id.as_str()));
                    // A bulk sweep needs to say how much it swept:
                    // "Cleared." over a list that still has rows in
                    // it is indistinguishable from a no-op. `status`
                    // keeps its old meaning for every existing
                    // caller (SAB clients included).
                    let count = before - h.len();
                    drop(h);
                    if count > 0 {
                        d.save_queue();
                    }
                    json!({"status": count > 0, "removed": count})
                }
                _ => history_json(d, params),
            }
        }
        _ => return None,
    })
}

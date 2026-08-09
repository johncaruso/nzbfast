//! Unit tests for serve/daemon.rs (TODO 106 phase 3): the helpers the
//! serve/mod.rs test module does not already cover, exercised against
//! the in-memory `test_daemon` fixture where a Daemon is needed.

use super::*;

fn with_daemon(name: &str, f: impl FnOnce(&Arc<Daemon>)) {
    let dir = std::env::temp_dir().join(format!("nzbfast-dmn-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let d = super::super::testutil::test_daemon(&dir);
    f(&d);
    drop(d);
    let _ = std::fs::remove_dir_all(&dir);
}

fn jv(id: &str, name: &str, extra: serde_json::Value) -> Arc<Mutex<Job>> {
    let mut v = serde_json::json!({
        "nzo_id": id, "name": name, "nzb_path": "/tmp/x.nzb",
        "out_dir": format!("/tmp/out/{id}"), "state": "Queued",
    });
    if let Some(m) = extra.as_object() {
        for (k, val) in m {
            v[k] = val.clone();
        }
    }
    Arc::new(Mutex::new(job_from_json(&v).expect("job_from_json")))
}

// -- find_job (pure) --------------------------------------------------------

#[test]
fn find_job_first_match_wins_and_clones_the_arc() {
    let a = jv("id-a", "first", serde_json::json!({}));
    let b = jv("id-a", "second", serde_json::json!({}));
    let c = jv("id-c", "third", serde_json::json!({}));
    let list = [a.clone(), b, c];

    let empty: Vec<Arc<Mutex<Job>>> = Vec::new();
    assert!(find_job(empty.iter(), "id-a").is_none());
    assert!(find_job(list.iter(), "id-x").is_none());

    let got = find_job(list.iter(), "id-a").expect("match");
    assert_eq!(got.lock_ok().name, "first", "duplicate ids: first wins");
    assert!(Arc::ptr_eq(&got, &a), "same Arc, cloned not copied");

    assert_eq!(
        find_job(list.iter(), "id-c").unwrap().lock_ok().name,
        "third"
    );
}

// -- OpenedLog gaps (mod.rs already covers coalesce/expiry/bounds) ----------

#[cfg(feature = "indexer")]
#[test]
fn opened_log_trim_is_a_noop_at_or_below_the_cap() {
    let mut m: std::collections::HashMap<String, i64> = std::collections::HashMap::new();
    for i in 0..10 {
        m.insert(format!("k{i}"), i);
    }
    OpenedLog::trim(&mut m);
    assert_eq!(m.len(), 10, "well below the cap: untouched");

    let mut full: std::collections::HashMap<String, i64> = std::collections::HashMap::new();
    for i in 0..OPENED_MAX_ENTRIES {
        full.insert(format!("k{i}"), i as i64);
    }
    OpenedLog::trim(&mut full);
    assert_eq!(
        full.len(),
        OPENED_MAX_ENTRIES,
        "exactly at the cap: untouched"
    );
}

#[cfg(feature = "indexer")]
#[test]
fn opened_log_trim_drops_oldest_to_exactly_the_cap() {
    let mut m: std::collections::HashMap<String, i64> = std::collections::HashMap::new();
    for i in 0..(OPENED_MAX_ENTRIES + 7) {
        m.insert(format!("k{i}"), i as i64);
    }
    OpenedLog::trim(&mut m);
    assert_eq!(m.len(), OPENED_MAX_ENTRIES);
    for i in 0..7 {
        assert!(!m.contains_key(&format!("k{i}")), "oldest {i} dropped");
    }
    assert!(m.contains_key("k7"));
    assert!(m.contains_key(&format!("k{}", OPENED_MAX_ENTRIES + 6)));
}

#[cfg(feature = "indexer")]
#[test]
fn opened_log_expire_keeps_age_exactly_at_the_window() {
    let mut log = OpenedLog::default();
    let now = 1_700_000_000i64;
    let window = 100i64;
    log.titles.insert("t:edge".into(), now - window);
    log.titles.insert("t:past".into(), now - window - 1);
    log.releases.insert(1, now - window);
    log.releases.insert(2, now - window - 1);
    log.expire(now, window);
    assert!(log.titles.contains_key("t:edge"), "age == window is kept");
    assert!(!log.titles.contains_key("t:past"));
    assert!(log.releases.contains_key(&1));
    assert!(!log.releases.contains_key(&2));
}

// -- pause-reason ladders ---------------------------------------------------

#[cfg(feature = "indexer")]
#[test]
fn indexing_pause_reason_precedence_ladder() {
    with_daemon("idxreason", |d| {
        d.index_enabled.store(false, Ordering::Relaxed);
        d.index_paused.store(true, Ordering::Relaxed);
        d.index_pause_on_download.store(true, Ordering::Relaxed);
        d.index_jobs_active.store(1, Ordering::Release);
        d.queue
            .lock_ok()
            .push_back(jv("q1", "job", serde_json::json!({})));

        d.offline.store(true, Ordering::Relaxed);
        assert_eq!(
            d.indexing_pause_reason(),
            Some("offline"),
            "offline beats all"
        );

        d.offline.store(false, Ordering::Relaxed);
        assert_eq!(
            d.indexing_pause_reason(),
            Some("off"),
            "disabled beats paused"
        );

        d.index_enabled.store(true, Ordering::Relaxed);
        assert_eq!(d.indexing_pause_reason(), Some("paused"));

        d.index_paused.store(false, Ordering::Relaxed);
        assert_eq!(d.indexing_pause_reason(), Some("downloading"), "active job");

        d.index_jobs_active.store(0, Ordering::Release);
        assert_eq!(
            d.indexing_pause_reason(),
            Some("downloading"),
            "a queued runnable job counts before the runner picks it"
        );

        d.queue.lock_ok().clear();
        assert_eq!(d.indexing_pause_reason(), None);

        // With pause-on-download off, neither active nor queued work holds.
        d.index_pause_on_download.store(false, Ordering::Relaxed);
        d.index_jobs_active.store(1, Ordering::Release);
        d.queue
            .lock_ok()
            .push_back(jv("q2", "job2", serde_json::json!({})));
        assert_eq!(d.indexing_pause_reason(), None);
    });
}

#[cfg(feature = "indexer")]
#[test]
fn spot_pause_reason_same_shape_reads_index_paused() {
    with_daemon("spotreason", |d| {
        d.spot_enabled.store(false, Ordering::Relaxed);
        d.index_paused.store(true, Ordering::Relaxed);
        d.index_pause_on_download.store(true, Ordering::Relaxed);
        d.index_jobs_active.store(1, Ordering::Release);

        d.offline.store(true, Ordering::Relaxed);
        assert_eq!(d.spot_pause_reason(), Some("offline"));

        d.offline.store(false, Ordering::Relaxed);
        assert_eq!(d.spot_pause_reason(), Some("off"));

        d.spot_enabled.store(true, Ordering::Relaxed);
        // The spot leg honors the INDEX pause switch.
        assert_eq!(d.spot_pause_reason(), Some("paused"));

        d.index_paused.store(false, Ordering::Relaxed);
        assert_eq!(d.spot_pause_reason(), Some("downloading"));

        d.index_jobs_active.store(0, Ordering::Release);
        d.queue
            .lock_ok()
            .push_back(jv("q1", "job", serde_json::json!({})));
        assert_eq!(d.spot_pause_reason(), Some("downloading"));

        d.queue.lock_ok().clear();
        assert_eq!(d.spot_pause_reason(), None);
    });
}

#[cfg(feature = "indexer")]
#[test]
fn index_db_wanted_when_either_switch_is_on() {
    with_daemon("dbwanted", |d| {
        d.index_enabled.store(false, Ordering::Relaxed);
        d.spot_enabled.store(false, Ordering::Relaxed);
        assert!(!d.index_db_wanted());
        d.index_enabled.store(true, Ordering::Relaxed);
        assert!(d.index_db_wanted());
        d.index_enabled.store(false, Ordering::Relaxed);
        d.spot_enabled.store(true, Ordering::Relaxed);
        assert!(d.index_db_wanted());
    });
}

#[cfg(feature = "indexer")]
#[test]
fn predb_feed_needs_both_switches() {
    with_daemon("predbon", |d| {
        d.predb_enabled.store(true, Ordering::Relaxed);
        d.index_enabled.store(false, Ordering::Relaxed);
        assert!(!d.predb_feed_on());
        d.index_enabled.store(true, Ordering::Relaxed);
        assert!(d.predb_feed_on());
        d.predb_enabled.store(false, Ordering::Relaxed);
        assert!(!d.predb_feed_on());
    });
}

#[test]
fn queue_has_runnable_wants_queued_and_unpaused() {
    with_daemon("runnable", |d| {
        assert!(!d.queue_has_runnable(), "empty queue");
        d.queue
            .lock_ok()
            .push_back(jv("a", "a", serde_json::json!({"paused": true})));
        assert!(!d.queue_has_runnable(), "paused does not count");
        d.queue
            .lock_ok()
            .push_back(jv("b", "b", serde_json::json!({"state": "Completed"})));
        assert!(!d.queue_has_runnable(), "non-Queued does not count");
        d.queue
            .lock_ok()
            .push_back(jv("c", "c", serde_json::json!({})));
        assert!(d.queue_has_runnable());
    });
}

#[cfg(feature = "indexer")]
#[test]
fn index_maintenance_needs_no_reason_and_no_active_job() {
    with_daemon("maint", |d| {
        d.index_enabled.store(false, Ordering::Relaxed);
        d.index_paused.store(false, Ordering::Relaxed);
        d.index_pause_on_download.store(false, Ordering::Relaxed);
        assert!(!d.index_maintenance_ok(), "indexing off is a reason");

        d.index_enabled.store(true, Ordering::Relaxed);
        assert!(d.index_maintenance_ok());

        // A job in flight blocks maintenance even when the pause-on-download
        // preference is off and the reason ladder answers None.
        d.index_jobs_active.store(1, Ordering::Release);
        assert_eq!(d.indexing_pause_reason(), None);
        assert!(!d.index_maintenance_ok());
        d.index_jobs_active.store(0, Ordering::Release);
        assert!(d.index_maintenance_ok());
    });
}

// -- pick_job / held_as_duplicate -------------------------------------------

#[test]
fn pick_job_priority_desc_then_fifo() {
    with_daemon("pickjob", |d| {
        assert!(d.pick_job(false).is_none(), "empty queue");

        {
            let mut q = d.queue.lock_ok();
            q.push_back(jv("n1", "normal-1", serde_json::json!({"priority": 0})));
            q.push_back(jv("n2", "normal-2", serde_json::json!({"priority": 0})));
            q.push_back(jv("hi", "high", serde_json::json!({"priority": 1})));
            q.push_back(jv(
                "hp",
                "high-paused",
                serde_json::json!({"priority": 5, "paused": true}),
            ));
        }
        let got = d.pick_job(false).expect("pick");
        assert_eq!(got.lock_ok().nzo_id, "hi", "highest runnable priority wins");

        d.queue.lock_ok().retain(|j| j.lock_ok().nzo_id != "hi");
        let got = d.pick_job(false).expect("pick");
        assert_eq!(got.lock_ok().nzo_id, "n1", "FIFO within a priority");

        // Per-job pause always holds a job back, whatever its priority.
        d.queue.lock_ok().retain(|j| {
            let g = j.lock_ok();
            g.nzo_id == "hp"
        });
        assert!(d.pick_job(false).is_none());
    });
}

#[test]
fn pick_job_force_runs_through_a_queue_pause() {
    with_daemon("pickforce", |d| {
        {
            let mut q = d.queue.lock_ok();
            q.push_back(jv("n1", "normal", serde_json::json!({"priority": 1})));
            q.push_back(jv("f1", "forced", serde_json::json!({"priority": 2})));
        }
        assert_eq!(
            d.pick_job(true).expect("pick").lock_ok().nzo_id,
            "f1",
            "only Force (2) runs while the queue is paused"
        );
        d.queue.lock_ok().retain(|j| j.lock_ok().nzo_id != "f1");
        assert!(d.pick_job(true).is_none());
        assert!(d.pick_job(false).is_some());
    });
}

#[test]
fn pick_job_deferred_runs_only_when_nothing_else_can() {
    with_daemon("pickdefer", |d| {
        {
            let mut q = d.queue.lock_ok();
            q.push_back(jv(
                "df",
                "slow",
                serde_json::json!({"priority": 5, "deferred": true}),
            ));
            q.push_back(jv("ok", "fresh", serde_json::json!({"priority": 0})));
        }
        assert_eq!(
            d.pick_job(false).expect("pick").lock_ok().nzo_id,
            "ok",
            "deferred loses to any runnable job regardless of priority"
        );
        d.queue.lock_ok().retain(|j| j.lock_ok().nzo_id == "df");
        assert_eq!(d.pick_job(false).expect("pick").lock_ok().nzo_id, "df");
    });
}

#[test]
fn held_as_duplicate_requires_pause_and_dupe_priority() {
    with_daemon("dupe", |d| {
        {
            let mut q = d.queue.lock_ok();
            q.push_back(jv(
                "held",
                "held",
                serde_json::json!({"paused": true, "priority": DUPE_PRIORITY}),
            ));
            q.push_back(jv(
                "justpaused",
                "p",
                serde_json::json!({"paused": true, "priority": 0}),
            ));
            q.push_back(jv(
                "justdupe",
                "d",
                serde_json::json!({"paused": false, "priority": DUPE_PRIORITY}),
            ));
        }
        assert!(d.held_as_duplicate("held"));
        assert!(!d.held_as_duplicate("justpaused"));
        assert!(!d.held_as_duplicate("justdupe"));
        assert!(!d.held_as_duplicate("absent"));
    });
}

/// §129 2d: the dupe_action setting decides what a duplicate add
/// becomes - held (default), refused, or filed to history as Failed -
/// and allow_dupe (the wall's asked-and-said-yes) bypasses all three.
#[test]
fn dupe_action_discard_and_fail_change_what_a_duplicate_becomes() {
    with_daemon("dupeact", |d| {
        let nzb = |seg: &str| {
            format!(
                "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\
                 <file poster=\"x\" date=\"0\" subject=\"&quot;a.bin&quot; yEnc (1/1)\">\
                 <groups><group>g</group></groups><segments>\
                 <segment bytes=\"1000\" number=\"1\">{seg}@x</segment>\
                 </segments></file></nzb>"
            )
        };
        let add = |seg: &str, name: &str, allow: bool| {
            d.enqueue(nzb(seg).as_bytes(), name, "", -100, None, "test", allow)
        };
        // A name with a derivable identity (SxxEyy) so dupe_key exists.
        add("one", "Show.S01E02.1080p.nzb", false).unwrap();
        // Default: held paused as an ALTERNATIVE.
        let held = add("two", "Show.S01E02.720p.nzb", false).unwrap();
        assert!(d.held_as_duplicate(&held));
        // discard: the add is refused and nothing joins the queue.
        *d.dupe_action.lock_ok() = "discard".into();
        let e = add("three", "Show.S01E02.2160p.nzb", false).unwrap_err();
        assert!(e.to_string().contains("discarded"), "{e}");
        assert_eq!(d.queue.lock_ok().len(), 2);
        // fail: filed straight to history as Failed; queue untouched.
        *d.dupe_action.lock_ok() = "fail".into();
        let failed = add("four", "Show.S01E02.480p.nzb", false).unwrap();
        assert_eq!(d.queue.lock_ok().len(), 2);
        {
            let h = d.history.lock_ok();
            let j = h
                .iter()
                .find(|j| j.lock_ok().nzo_id == failed)
                .expect("filed to history")
                .clone();
            let g = j.lock_ok();
            assert_eq!(g.state, JobState::Failed);
            assert!(g.fail_message.contains("duplicate"), "{}", g.fail_message);
        }
        // allow_dupe bypasses whatever the setting says.
        let ok = add("five", "Show.S01E02.HDR.nzb", true).unwrap();
        assert!(!d.held_as_duplicate(&ok));
        assert_eq!(d.queue.lock_ok().len(), 3);
    });
}

/// §129 2b: real per-category behavior - the category's default
/// priority fills a default add (explicit wins), its dir renames the
/// subfolder (contained, sanitized), and script resolution runs
/// job-override, then category, then global.
#[test]
fn cat_meta_priority_dir_and_script_apply() {
    with_daemon("catmeta", |d| {
        use super::CatMeta;
        d.cat_meta.lock_ok().insert(
            "tv".into(),
            CatMeta {
                dir: "series/current".into(),
                priority: Some(1),
                script: "/scripts/tv.py".into(),
            },
        );
        // dir: the category's subfolder is renamed, nested, contained.
        let base = d.base_out_dir("tv", "job");
        assert_eq!(base, d.out_dir().join("series").join("current").join("job"));
        // A traversal in the meta dir cannot escape the root.
        d.cat_meta.lock_ok().get_mut("tv").unwrap().dir = "../../evil".into();
        assert_eq!(
            d.base_out_dir("tv", "job"),
            d.out_dir().join("evil").join("job")
        );
        d.cat_meta.lock_ok().get_mut("tv").unwrap().dir = "series/current".into();
        // No meta = the old shape, untouched.
        assert_eq!(
            d.base_out_dir("movies", "job"),
            d.out_dir().join("movies").join("job")
        );
        assert_eq!(d.base_out_dir("", "job"), d.out_dir().join("job"));

        // priority: fills the default, loses to an explicit one.
        let nzb = "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\
                   <file poster=\"x\" date=\"0\" subject=\"&quot;a.bin&quot; yEnc (1/1)\">\
                   <groups><group>g</group></groups><segments>\
                   <segment bytes=\"1000\" number=\"1\">cm1@x</segment>\
                   </segments></file></nzb>";
        let id = d
            .enqueue(
                nzb.as_bytes(),
                "Alpha.2026.nzb",
                "tv",
                -100,
                None,
                "test",
                false,
            )
            .unwrap();
        let nzb2 = nzb.replace("cm1@x", "cm2@x");
        let id2 = d
            .enqueue(
                nzb2.as_bytes(),
                "Beta.2026.nzb",
                "tv",
                -1,
                None,
                "test",
                false,
            )
            .unwrap();
        {
            let q = d.queue.lock_ok();
            let prio = |id: &str| {
                q.iter()
                    .find(|j| j.lock_ok().nzo_id == *id)
                    .map(|j| j.lock_ok().priority)
                    .unwrap()
            };
            assert_eq!(prio(&id), 1, "category default fills a default add");
            assert_eq!(prio(&id2), -1, "an explicit priority wins");
        }

        // script resolution order.
        let job = d
            .queue
            .lock_ok()
            .iter()
            .find(|j| j.lock_ok().nzo_id == id)
            .cloned()
            .unwrap();
        assert_eq!(
            d.resolve_script(&job),
            Some(std::path::PathBuf::from("/scripts/tv.py")),
            "category script beats the (unset) global"
        );
        *d.script.lock_ok() = Some(std::path::PathBuf::from("/scripts/global.py"));
        job.lock_ok().category = "movies".into();
        assert_eq!(
            d.resolve_script(&job),
            Some(std::path::PathBuf::from("/scripts/global.py")),
            "no category script falls back to the global one"
        );
        job.lock_ok().script_override = "/scripts/mine.py".into();
        assert_eq!(
            d.resolve_script(&job),
            Some(std::path::PathBuf::from("/scripts/mine.py")),
            "the job's own script= wins"
        );
        job.lock_ok().script_override = "None".into();
        assert_eq!(
            d.resolve_script(&job),
            None,
            "script=None means none at all"
        );

        // record_add_params: pp + script land on the job. A bare name
        // is what a SAB client sends back from mode=get_scripts, so it
        // resolves through known_scripts to the real path - stored
        // verbatim it became a cwd-relative path that ran nothing.
        d.record_add_params(&id, Some("1"), Some("tv.py"), false);
        {
            let g = job_by(d, &id);
            let g = g.lock_ok();
            assert_eq!(g.sab_pp, Some(1));
            assert_eq!(g.script_override, "/scripts/tv.py");
        }
        // ...and known_scripts is exactly what get_scripts offers:
        // global + per-category, deduped by basename, global first.
        let names: Vec<String> = d.known_scripts().into_iter().map(|(n, _)| n).collect();
        assert_eq!(names, ["global.py", "tv.py"]);
        // An unknown name is a logged compatibility note, never a
        // stored override - the category/global ladder stays in charge.
        d.record_add_params(&id, None, Some("ghost.py"), false);
        assert_eq!(job_by(d, &id).lock_ok().script_override, "/scripts/tv.py");
        // A path-bearing value is operator intent and stays as written.
        d.record_add_params(&id, None, Some("/elsewhere/mine.py"), false);
        assert_eq!(
            job_by(d, &id).lock_ok().script_override,
            "/elsewhere/mine.py"
        );
        // ...but ONLY for a full-key caller. `addfile`/`addurl` are on
        // the add-only allowlist and `resolve_script` hands
        // `script_override` straight to `Command::new` on the job tail,
        // so accepting a path here let the NZB key - which ships to
        // browser push extensions - choose which program the daemon
        // runs. The previous override must survive untouched: refusing
        // must not become a way to CLEAR someone else's setting.
        d.record_add_params(&id, None, Some("/tmp/pwn.sh"), true);
        assert_eq!(
            job_by(d, &id).lock_ok().script_override,
            "/elsewhere/mine.py",
            "an add-only credential may not choose the program to run"
        );
        // A configured name is still fine on the add-only key: it can
        // only select something the operator already installed.
        d.record_add_params(&id, None, Some("tv.py"), true);
        assert_eq!(job_by(d, &id).lock_ok().script_override, "/scripts/tv.py");
        // SAB's own null still suppresses the whole ladder.
        d.record_add_params(&id, None, Some("None"), false);
        assert_eq!(job_by(d, &id).lock_ok().script_override, "None");
        assert_eq!(d.resolve_script(&job_by(d, &id)), None);
    });
}

fn job_by(d: &Arc<Daemon>, id: &str) -> Arc<Mutex<Job>> {
    d.queue
        .lock_ok()
        .iter()
        .find(|j| j.lock_ok().nzo_id == id)
        .cloned()
        .unwrap()
}

// -- instant kick -----------------------------------------------------------

#[cfg(feature = "indexer")]
#[test]
fn instant_kick_dedupes_hints_and_caps_from_the_front() {
    with_daemon("kickhint", |d| {
        // max 0 = unmetered, so this test is about the hint list alone.
        d.watchlist_instant_max.store(0, Ordering::Relaxed);
        assert!(!d.instant_kick(&[], 1000), "empty names never wake");

        let names: Vec<String> = vec!["a".into(), "b".into()];
        assert!(d.instant_kick(&names, 1000));
        let again: Vec<String> = vec!["b".into(), "c".into()];
        assert!(d.instant_kick(&again, 1001));
        assert_eq!(*d.instant_hint.lock_ok(), vec!["a", "b", "c"], "dedupe");

        d.instant_hint.lock_ok().clear();
        let flood: Vec<String> = (0..300).map(|i| format!("n{i}")).collect();
        assert!(d.instant_kick(&flood, 1002));
        let hint = d.instant_hint.lock_ok();
        assert_eq!(hint.len(), 256, "HINT_CAP");
        assert_eq!(hint[0], "n44", "drained from the front (oldest)");
        assert_eq!(hint[255], "n299");
    });
}

#[cfg(feature = "indexer")]
#[test]
fn instant_kick_rate_limit_refuses_without_touching_hints() {
    with_daemon("kicklimit", |d| {
        d.watchlist_instant_max.store(1, Ordering::Relaxed);
        let a: Vec<String> = vec!["a".into()];
        let b: Vec<String> = vec!["b".into()];
        assert!(d.instant_kick(&a, 5000));
        assert!(!d.instant_kick(&b, 5001), "allowance for the hour is spent");
        assert_eq!(*d.instant_hint.lock_ok(), vec!["a"], "refusal adds no hint");
        // A new hour restores the allowance.
        assert!(d.instant_kick(&b, 5000 + 3_600));
    });
}

// -- event ring / speed ceiling ---------------------------------------------

#[test]
fn event_ring_caps_at_256_dropping_oldest_and_lists_newest_first() {
    with_daemon("events", |d| {
        for i in 0..300 {
            d.note_event("pause", format!("e{i}"));
        }
        assert_eq!(d.events.lock_ok().len(), 256);

        let all = d.recent_events(1000);
        assert_eq!(all.len(), 256);
        assert_eq!(all[0].detail, "e299", "newest first");
        assert_eq!(all[255].detail, "e44", "oldest 44 dropped");

        let two = d.recent_events(2);
        assert_eq!(two.len(), 2, "limit honored");
        assert_eq!(two[0].detail, "e299");
        assert_eq!(two[1].detail, "e298");
    });
}

#[test]
fn speed_ceiling_notes_changes_only_and_names_the_source() {
    with_daemon("ceiling", |d| {
        d.set_speed_ceiling_from(1_000_000, "schedule");
        assert_eq!(d.speed_ceiling.load(Ordering::Relaxed), 1_000_000);
        assert_eq!(*d.limit_source.lock_ok(), "schedule");
        let ev = d.recent_events(1);
        assert_eq!(ev[0].kind, "limit");
        assert_eq!(ev[0].detail, "speed limit set to 1.0 MB/s by the schedule");

        // Re-applying the number in force is not a change.
        d.set_speed_ceiling_from(1_000_000, "schedule");
        assert_eq!(d.recent_events(10).len(), 1);

        d.set_speed_ceiling_from(0, "api");
        assert_eq!(
            d.recent_events(1)[0].detail,
            "speed limit removed by an API client"
        );

        d.set_speed_ceiling(2_000_000);
        assert_eq!(d.recent_events(1)[0].detail, "speed limit set to 2.0 MB/s");
        assert_eq!(*d.limit_source.lock_ok(), "user");
    });
}

// -- stream token / cat list / rename style ---------------------------------

#[test]
fn stream_token_is_deterministic_32_char_lowercase_hex() {
    with_daemon("token", |d| {
        let t1 = d.stream_token("SABnzbd_nzo_1");
        let t2 = d.stream_token("SABnzbd_nzo_1");
        let t3 = d.stream_token("SABnzbd_nzo_2");
        assert_eq!(t1, t2, "deterministic per nzo_id");
        assert_ne!(t1, t3, "different jobs, different tokens");
        assert_eq!(t1.len(), 32);
        assert!(
            t1.chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    });
}

#[test]
fn cat_list_is_sorted_star_filtered_comma_joined() {
    with_daemon("catlist", |d| {
        {
            let mut cats = d.cats.lock_ok();
            cats.clear();
            for c in ["tv", "*", "movies", "books"] {
                cats.insert(c.to_string());
            }
        }
        assert_eq!(d.cat_list(), "books, movies, tv");
    });
}

#[test]
fn rename_style_mirrors_every_toggle() {
    with_daemon("style", |d| {
        let flags: [(
            &std::sync::atomic::AtomicBool,
            fn(&crate::wall::NameStyle) -> bool,
        ); 8] = [
            (&d.rename_resolution, |s| s.resolution),
            (&d.rename_vcodec, |s| s.video_codec),
            (&d.rename_acodec, |s| s.audio_codec),
            (&d.rename_source, |s| s.source),
            (&d.rename_group, |s| s.group),
            (&d.rename_year_parens, |s| s.year_parens),
            (&d.rename_quality_brackets, |s| s.quality_brackets),
            (&d.rename_extra_words, |s| s.extra_words),
        ];
        for (atomic, _) in &flags {
            atomic.store(false, Ordering::Relaxed);
        }
        for (i, (atomic, read)) in flags.iter().enumerate() {
            atomic.store(true, Ordering::Relaxed);
            let s = d.rename_style();
            assert!(read(&s), "toggle {i} sets its mirrored field");
            for (j, (_, other)) in flags.iter().enumerate() {
                assert_eq!(other(&s), i == j, "toggle {i} flips exactly field {j}");
            }
            atomic.store(false, Ordering::Relaxed);
        }
    });
}

#[test]
fn job_suffix_is_empty_with_auto_rename_off() {
    with_daemon("suffix", |d| {
        d.auto_rename.store(false, Ordering::Relaxed);
        assert_eq!(d.job_suffix("Movie.2020.1080p.x264-GRP"), "");

        d.auto_rename.store(true, Ordering::Relaxed);
        d.rename_resolution.store(true, Ordering::Relaxed);
        for a in [
            &d.rename_vcodec,
            &d.rename_acodec,
            &d.rename_source,
            &d.rename_group,
            &d.rename_quality_brackets,
        ] {
            a.store(false, Ordering::Relaxed);
        }
        assert_eq!(d.job_suffix("Movie.2020.1080p.x264-GRP"), " 1080p");
    });
}

// -- indexer accounts / tri-state -------------------------------------------

#[test]
fn enabled_indexers_counts_only_enabled_and_drives_the_tri_state() {
    with_daemon("tristate", |d| {
        let mk = |name: &str, enabled: bool| crate::newznab::IndexerConfig {
            name: name.into(),
            url: "http://indexer.test".into(),
            apikey: String::new(),
            enabled,
            priority: 0,
            hits_per_day: 0,
            grabs_per_day: 0,
        };
        d.watchlist_external_set.store(false, Ordering::Relaxed);
        assert_eq!(d.enabled_indexers(), 0);
        assert!(!d.watchlist_external_on(), "unset + no accounts = off");

        d.indexers.lock_ok().push(mk("a", false));
        assert_eq!(d.enabled_indexers(), 0);
        assert!(!d.watchlist_external_on());

        d.indexers.lock_ok().push(mk("b", true));
        assert_eq!(d.enabled_indexers(), 1);
        assert!(d.watchlist_external_on(), "unset + an account = on");

        // An explicit answer wins over the fallback in both directions.
        d.watchlist_external_set.store(true, Ordering::Relaxed);
        d.watchlist_external.store(false, Ordering::Relaxed);
        assert!(!d.watchlist_external_on());
        d.watchlist_external.store(true, Ordering::Relaxed);
        d.indexers.lock_ok().clear();
        assert!(d.watchlist_external_on());
    });
}

// -- evict policy / predb config --------------------------------------------

#[cfg(feature = "indexer")]
#[test]
fn evict_policy_unknown_order_falls_back_to_ladder() {
    with_daemon("evict", |d| {
        *d.index_evict_order.lock_ok() = "bogus".to_string();
        *d.index_evict_kinds.lock_ok() = vec!["movie".to_string()];
        let p = d.evict_policy();
        assert!(matches!(p.order, nzbkit::index::EvictOrder::Ladder));
        assert_eq!(p.kinds, vec!["movie".to_string()]);

        *d.index_evict_order.lock_ok() = "largest".to_string();
        assert!(matches!(
            d.evict_policy().order,
            nzbkit::index::EvictOrder::Largest
        ));
    });
}

#[cfg(feature = "indexer")]
#[test]
fn predb_irc_config_parses_every_address_form() {
    with_daemon("predbcfg", |d| {
        let cfg_for = |server: &str| {
            *d.predb_server.lock_ok() = server.to_string();
            d.predb_irc_config()
        };
        let c = cfg_for("irc.example.net");
        assert_eq!(c.host, "irc.example.net");
        assert_eq!(c.port, nzbkit::predb::DEFAULT_PORT);

        let c = cfg_for("irc.example.net:7000");
        assert_eq!((c.host.as_str(), c.port), ("irc.example.net", 7000));

        let c = cfg_for("[2001:db8::1]");
        assert_eq!(c.host, "2001:db8::1");
        assert_eq!(c.port, nzbkit::predb::DEFAULT_PORT);

        let c = cfg_for("[2001:db8::1]:7000");
        assert_eq!((c.host.as_str(), c.port), ("2001:db8::1", 7000));

        // Non-numeric port: the WHOLE raw string stays the host.
        let c = cfg_for("irc.example.net:junk");
        assert_eq!(c.host, "irc.example.net:junk");
        assert_eq!(c.port, nzbkit::predb::DEFAULT_PORT);

        let c = cfg_for("");
        assert_eq!(c.host, nzbkit::predb::DEFAULT_HOST);
        assert_eq!(c.port, nzbkit::predb::DEFAULT_PORT);

        *d.predb_channels.lock_ok() = " #pre , ,#spam,  ".to_string();
        *d.predb_nick.lock_ok() = "nick".to_string();
        let c = d.predb_irc_config();
        assert_eq!(c.channels, vec!["#pre".to_string(), "#spam".to_string()]);
        assert_eq!(c.nick, "nick");
        assert!(c.tls);
    });
}

// -- usage / reliability ledgers --------------------------------------------

#[test]
fn usage_ledger_accumulates_and_skips_zero_entries() {
    with_daemon("usage", |d| {
        assert_eq!(d.usage_lifetime("s1.example"), 0);
        d.add_usage(&[("s1.example".into(), 100), ("s2.example".into(), 0)]);
        assert_eq!(d.usage_lifetime("s1.example"), 100);
        assert_eq!(d.usage_lifetime("s2.example"), 0, "zero bytes never billed");
        d.add_usage(&[("s1.example".into(), 50)]);
        assert_eq!(d.usage_lifetime("s1.example"), 150);
        assert!(d.spool.join("usage.json").exists(), "persisted to spool");
    });
}

#[test]
fn reliability_ledger_accumulates_and_answers_none_untried() {
    with_daemon("reliability", |d| {
        assert_eq!(d.reliability("s1.example"), None);

        // All-zero report: skipped wholesale, ledger never created.
        d.add_reliability(&[("s1.example".into(), 0, 0)]);
        assert_eq!(d.reliability("s1.example"), None);

        d.add_reliability(&[("s1.example".into(), 10, 2), ("s2.example".into(), 0, 0)]);
        assert_eq!(d.reliability("s1.example"), Some((10, 2)));
        assert_eq!(d.reliability("s2.example"), None, "tried == 0 skipped");

        d.add_reliability(&[("s1.example".into(), 5, 1)]);
        assert_eq!(d.reliability("s1.example"), Some((15, 3)));
    });
}

// -- paths ------------------------------------------------------------------

#[test]
fn base_out_dir_skips_the_category_level_when_empty() {
    with_daemon("baseout", |d| {
        let root = d.out_dir();
        assert_eq!(
            d.base_out_dir("", "Some.Release"),
            root.join("Some.Release")
        );
        assert_eq!(
            d.base_out_dir("tv", "Some.Release"),
            root.join("tv").join("Some.Release")
        );
    });
}

#[test]
fn working_state_paths_hang_off_spool_and_index_db() {
    with_daemon("paths", |d| {
        assert_eq!(d.bench_history_path(), d.spool.join("bench_history.json"));
        assert!(d.out_dir().ends_with("out"));
        #[cfg(feature = "indexer")]
        {
            assert_eq!(d.opened_path(), d.spool.join("index-opened.json"));
            assert_eq!(
                d.groups_cache_path(),
                d.index_db.with_file_name("groups.tsv")
            );
            assert_eq!(
                d.groupstats_cache_path(),
                d.index_db.with_file_name("groupstats.tsv")
            );
        }
    });
}

// -- idle clock / sampler hold ----------------------------------------------

#[cfg(feature = "indexer")]
#[test]
fn download_idle_for_is_none_while_a_job_runs() {
    with_daemon("idlefor", |d| {
        let idle = d.download_idle_for().expect("idle since boot");
        assert!(idle < std::time::Duration::from_secs(60));
        *d.started_at.lock_ok() = Some(std::time::Instant::now());
        assert!(d.download_idle_for().is_none());
    });
}

#[cfg(feature = "indexer")]
#[test]
fn sampler_holds_unless_idle_past_the_release_timeout() {
    with_daemon("sampler", |d| {
        let server = |secs: serde_json::Value| -> nzbkit::config::ServerConfig {
            serde_json::from_value(serde_json::json!({
                "host": "news.example.net", "idle_release_secs": secs,
            }))
            .expect("server config")
        };
        // Some(0) = no release policy: always hold.
        assert!(d.sampler_may_hold(&server(serde_json::json!(0))));

        // A running download holds whatever the policy says.
        *d.started_at.lock_ok() = Some(std::time::Instant::now());
        assert!(d.sampler_may_hold(&server(serde_json::json!(3600))));

        // Idle for ~0 s, timeout 3600 s: still holding.
        *d.started_at.lock_ok() = None;
        assert!(d.sampler_may_hold(&server(serde_json::json!(3600))));

        // Idle past the timeout: borrow per tick instead.
        if let Some(past) =
            std::time::Instant::now().checked_sub(std::time::Duration::from_secs(7200))
        {
            *d.last_download_end.lock_ok() = past;
            assert!(!d.sampler_may_hold(&server(serde_json::json!(3600))));
            assert!(
                d.sampler_may_hold(&server(serde_json::json!(0))),
                "0 still holds"
            );
        }
    });
}

// -- auto-retry / tail phase ------------------------------------------------

#[test]
fn will_auto_retry_wants_the_cooldown_armed_and_a_transient_failure() {
    with_daemon("autoretry", |d| {
        let failed = jv(
            "f1",
            "f1",
            serde_json::json!({"state": "Failed", "fail_message": "download incomplete: 3 articles missing"}),
        );
        assert!(!d.will_auto_retry(&failed), "secs == 0: feature off");

        d.auto_retry_secs.store(600, Ordering::Relaxed);
        assert!(d.will_auto_retry(&failed));

        let retried = jv(
            "f2",
            "f2",
            serde_json::json!({"state": "Failed", "fail_message": "download incomplete", "retries": 1}),
        );
        assert!(!d.will_auto_retry(&retried), "one automatic retry only");

        let gone = jv(
            "f3",
            "f3",
            serde_json::json!({"state": "Failed", "fail_message": "post is gone"}),
        );
        assert!(!d.will_auto_retry(&gone), "Gone is not transient");

        let done = jv("f4", "f4", serde_json::json!({"state": "Completed"}));
        assert!(!d.will_auto_retry(&done));
    });
}

#[test]
fn tail_phase_maps_hub_activity_to_sab_vocabulary() {
    with_daemon("tailphase", |d| {
        assert_eq!(d.tail_phase("nzo1"), None, "no activity recorded");
        d.hub
            .activity
            .lock_ok()
            .insert("nzo1".to_string(), "verifying");
        d.hub
            .activity
            .lock_ok()
            .insert("nzo2".to_string(), "repairing");
        d.hub
            .activity
            .lock_ok()
            .insert("nzo3".to_string(), "extracting");
        d.hub
            .activity
            .lock_ok()
            .insert("nzo4".to_string(), "assembling");
        assert_eq!(d.tail_phase("nzo1"), Some("Verifying"));
        assert_eq!(d.tail_phase("nzo2"), Some("Repairing"));
        assert_eq!(d.tail_phase("nzo3"), Some("Extracting"));
        assert_eq!(d.tail_phase("nzo4"), None, "unmapped phases stay quiet");
        assert_eq!(d.tail_phase("nzo9"), None);
    });
}

// -- owned key sets ----------------------------------------------------------

#[cfg(feature = "indexer")]
#[test]
fn owned_dupe_keys_take_all_of_queue_but_only_completed_history() {
    with_daemon("dupekeys", |d| {
        d.queue
            .lock_ok()
            .push_back(jv("q1", "q1", serde_json::json!({"dupe_key": "k-queued"})));
        d.queue
            .lock_ok()
            .push_back(jv("q2", "q2", serde_json::json!({})));
        d.history.lock_ok().push(jv(
            "h1",
            "h1",
            serde_json::json!({"state": "Completed", "dupe_key": "k-done"}),
        ));
        d.history.lock_ok().push(jv(
            "h2",
            "h2",
            serde_json::json!({"state": "Failed", "dupe_key": "k-failed"}),
        ));
        let set = d.owned_dupe_keys();
        assert!(set.contains("k-queued"));
        assert!(set.contains("k-done"));
        assert!(!set.contains("k-failed"), "failed history is not owned");
        assert_eq!(set.len(), 2, "keyless jobs contribute nothing");
    });
}

#[cfg(feature = "indexer")]
#[test]
fn owned_title_keys_parse_names_and_drop_empty_keys() {
    with_daemon("titlekeys", |d| {
        let queued = "The.Show.S01E01.720p.WEB.x264-ABC";
        let done = "Some.Movie.2021.1080p.BluRay.x264-XYZ";
        let failed = "Other.Film.2019.720p.WEB.x264-QQQ";
        d.queue
            .lock_ok()
            .push_back(jv("q1", queued, serde_json::json!({})));
        d.queue
            .lock_ok()
            .push_back(jv("q2", "", serde_json::json!({})));
        d.history
            .lock_ok()
            .push(jv("h1", done, serde_json::json!({"state": "Completed"})));
        d.history
            .lock_ok()
            .push(jv("h2", failed, serde_json::json!({"state": "Failed"})));

        let set = d.owned_title_keys();
        let key = |n: &str| crate::wall::parse_release(n).key;
        assert!(set.contains(&key(queued)));
        assert!(set.contains(&key(done)));
        assert!(!set.contains(&key(failed)), "failed history is not owned");
        // The parser never emits a bare empty key (a blank name still
        // parses to the kind prefix), so the drop guard stays defensive.
        assert!(!set.contains(""));
        assert!(
            !key("").is_empty(),
            "even a blank name keys to its kind prefix"
        );
        assert!(set.contains(&key("")));
        assert_eq!(set.len(), 3);
    });
}

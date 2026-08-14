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

/// Every reason either ladder can produce has to have a phrase of its
/// own. The scan legs print `pause_phrase(reason)` and nothing else, so
/// a reason word added to the ladders without one falls through to the
/// generic arm and the log goes back to saying nothing - which is the
/// whole 11 Aug 2026 failure, arrived at from the other direction.
#[cfg(feature = "indexer")]
#[test]
fn every_pause_reason_has_its_own_phrase() {
    let mut seen: Vec<(&str, &str)> = Vec::new();
    with_daemon("pausephrase", |d| {
        d.index_pause_on_download.store(true, Ordering::Relaxed);
        // Walk both ladders top to bottom, collecting what they say.
        let ladder: [(&str, &dyn Fn(&Arc<Daemon>)); 4] = [
            ("offline", &|d: &Arc<Daemon>| {
                d.offline.store(true, Ordering::Relaxed)
            }),
            ("off", &|d: &Arc<Daemon>| {
                d.offline.store(false, Ordering::Relaxed);
                d.index_enabled.store(false, Ordering::Relaxed);
                d.spot_enabled.store(false, Ordering::Relaxed);
            }),
            ("paused", &|d: &Arc<Daemon>| {
                d.index_enabled.store(true, Ordering::Relaxed);
                d.spot_enabled.store(true, Ordering::Relaxed);
                d.index_paused.store(true, Ordering::Relaxed);
            }),
            ("downloading", &|d: &Arc<Daemon>| {
                d.index_paused.store(false, Ordering::Relaxed);
                d.index_jobs_active.store(1, Ordering::Release);
            }),
        ];
        for (want, set) in ladder {
            set(d);
            assert_eq!(d.indexing_pause_reason(), Some(want));
            assert_eq!(d.spot_pause_reason(), Some(want));
            let phrase = Daemon::pause_phrase(want);
            assert_ne!(
                phrase, "standing down",
                "{want} fell through to the generic arm"
            );
            seen.push((want, phrase));
        }
    });
    for (i, (reason, phrase)) in seen.iter().enumerate() {
        assert!(
            !seen[..i].iter().any(|(_, p)| p == phrase),
            "{reason} shares a phrase with an earlier reason: {phrase}"
        );
    }
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
            d.enqueue(
                nzb(seg).as_bytes(),
                name,
                "",
                -100,
                None,
                None,
                "test",
                allow,
            )
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

/// #41: dupe_scope = "exact" narrows what collides. A different release
/// of the same episode (an *arr quality upgrade) is not a duplicate and
/// downloads normally; a re-add of the same release name still is, even
/// across separator styles. "smart" (the default) keeps the identity
/// match - pinned above.
#[test]
fn dupe_scope_exact_lets_a_different_release_of_the_same_episode_through() {
    with_daemon("dupescope", |d| {
        let nzb = |seg: &str| {
            format!(
                "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\
                 <file poster=\"x\" date=\"0\" subject=\"&quot;a.bin&quot; yEnc (1/1)\">\
                 <groups><group>g</group></groups><segments>\
                 <segment bytes=\"1000\" number=\"1\">{seg}@x</segment>\
                 </segments></file></nzb>"
            )
        };
        let add = |seg: &str, name: &str| {
            d.enqueue(
                nzb(seg).as_bytes(),
                name,
                "",
                -100,
                None,
                None,
                "test",
                false,
            )
        };
        *d.dupe_scope.lock_ok() = "exact".into();
        add("one", "Show.S01E02.1080p.WEB-DL.x264-Poke.nzb").unwrap();
        // Same episode, different release: not a duplicate under "exact".
        let upgrade = add("two", "Show.S01E02.1080p.HEVC.x265-MeGusta.nzb").unwrap();
        assert!(!d.held_as_duplicate(&upgrade));
        // Same release re-sent, different separators: still caught.
        let resend = add("three", "Show S01E02 1080p WEB-DL x264-Poke.nzb").unwrap();
        assert!(d.held_as_duplicate(&resend));
        // Back to "smart": identity collides again.
        *d.dupe_scope.lock_ok() = "smart".into();
        let held = add("four", "Show.S01E02.2160p.nzb").unwrap();
        assert!(d.held_as_duplicate(&held));
    });
}

/// Codex sweep K, 13 Aug 2026: admission and promotion asked different
/// questions. Under `dupe_scope = "exact"` a different release of the
/// same episode is admitted and runs; when it failed, `park` promoted
/// held rows by the shared EPISODE key - including one held against a
/// completed original that is still sitting in history. The user got a
/// second copy of something they already had.
#[test]
fn an_exact_mode_failure_does_not_release_another_releases_hold() {
    with_daemon("dupe-promote", |d| {
        let nzb = |seg: &str| {
            format!(
                "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\
                 <file poster=\"x\" date=\"0\" subject=\"&quot;a.bin&quot; yEnc (1/1)\">\
                 <groups><group>g</group></groups><segments>\
                 <segment bytes=\"1000\" number=\"1\">{seg}@x</segment>\
                 </segments></file></nzb>"
            )
        };
        let add = |seg: &str, name: &str| {
            d.enqueue(
                nzb(seg).as_bytes(),
                name,
                "",
                -100,
                None,
                None,
                "test",
                false,
            )
            .unwrap()
        };
        *d.dupe_scope.lock_ok() = "exact".into();
        // A: completed, in history.
        let a = add("k1", "Show.S05E05.1080p.WEB-DL.x264-Poke.nzb");
        let ja = d.queue_job(&a).unwrap();
        {
            let mut g = ja.lock_ok();
            g.state = JobState::Completed;
        }
        d.queue.lock_ok().retain(|j| j.lock_ok().nzo_id != a);
        d.history.lock_ok().push(ja);

        // B: a DIFFERENT release of the same episode - admitted under
        // exact, and it runs.
        let b = add("k2", "Show.S05E05.2160p.HEVC.x265-MeGusta.nzb");
        assert!(!d.held_as_duplicate(&b));
        // C: a re-send of A's release - held, against A.
        let c = add("k3", "Show S05E05 1080p WEB-DL x264-Poke.nzb");
        assert!(d.held_as_duplicate(&c));

        // B fails. Its failure says nothing about A, which is still
        // completed, so C must stay held.
        let jb = d.queue_job(&b).unwrap();
        {
            let mut g = jb.lock_ok();
            g.state = JobState::Failed;
        }
        d.park(jb);
        assert!(
            d.held_as_duplicate(&c),
            "C was held against a COMPLETED original, not against B"
        );
        assert!(
            d.history
                .lock_ok()
                .iter()
                .any(|j| j.lock_ok().nzo_id == a && j.lock_ok().state == JobState::Completed),
            "the original is still completed"
        );
    });
}

/// Codex sweep J, 13 Aug 2026: the exact identity was built with an
/// ASCII-only filter, so every non-Latin letter became a space. Two
/// DIFFERENT CJK titles sharing a tag tail reduced to the same key and
/// the second was held as a duplicate of the first, while a wholly
/// non-ASCII name reduced to the empty string - no identity at all, so
/// a genuine re-send of it was admitted as new.
#[test]
fn exact_identity_keeps_non_ascii_titles_apart() {
    with_daemon("dupe-unicode", |d| {
        let nzb = |seg: &str| {
            format!(
                "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\
                 <file poster=\"x\" date=\"0\" subject=\"&quot;a.bin&quot; yEnc (1/1)\">\
                 <groups><group>g</group></groups><segments>\
                 <segment bytes=\"1000\" number=\"1\">{seg}@x</segment>\
                 </segments></file></nzb>"
            )
        };
        let add = |seg: &str, name: &str| {
            d.enqueue(
                nzb(seg).as_bytes(),
                name,
                "",
                -100,
                None,
                None,
                "test",
                false,
            )
            .unwrap()
        };
        *d.dupe_scope.lock_ok() = "exact".into();
        let first = add("u1", "電影甲.2024.1080p.WEB-DL.x264-GRP.nzb");
        assert!(!d.held_as_duplicate(&first));
        // A different film, same year and tags: not the same release.
        let other = add("u2", "電影乙.2024.1080p.WEB-DL.x264-GRP.nzb");
        assert!(
            !d.held_as_duplicate(&other),
            "distinct titles must not share an exact identity"
        );
        // …and the same one re-sent IS caught, which needs the name to
        // have had a nonempty identity in the first place.
        let all_cjk = add("u3", "電影丙.nzb");
        assert!(!d.held_as_duplicate(&all_cjk));
        let resend = add("u4", "電影丙.nzb");
        assert!(
            d.held_as_duplicate(&resend),
            "an all-letter non-ASCII name must still have an identity"
        );
    });
}

/// §129 4a: an add announces itself on the event ring BEFORE the job
/// can be picked, so no consumer ever sees a job start before it
/// exists. The runner picks under the queue lock (`pick_job`), which is
/// the lock `enqueue` emits under - a picker spinning as fast as it can
/// must still land behind the job.added. Regression: the emit used to
/// sit after the push and after `save_queue`, and a loaded box really
/// did put job.started on the ring first (seq 1, 54 ms early).
#[test]
fn an_add_is_on_the_event_ring_before_the_job_can_be_picked() {
    with_daemon("addbeforepick", |d| {
        let picker = {
            let d = d.clone();
            std::thread::spawn(move || {
                // Stands in for the runner's pick arm: spin on pick_job
                // and emit job.started the moment one appears, the same
                // order tasks.rs uses (claim the job, then emit).
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
                while std::time::Instant::now() < deadline {
                    if let Some(j) = d.pick_job(false) {
                        let mut g = j.lock_ok();
                        g.state = JobState::Downloading;
                        d.life_emit("job.started", serde_json::json!({"nzo_id": g.nzo_id}));
                        return true;
                    }
                    std::thread::yield_now();
                }
                false
            })
        };
        let nzb = "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\
                   <file poster=\"x\" date=\"0\" subject=\"&quot;a.bin&quot; yEnc (1/1)\">\
                   <groups><group>g</group></groups><segments>\
                   <segment bytes=\"1000\" number=\"1\">ord1@x</segment>\
                   </segments></file></nzb>";
        d.enqueue(
            nzb.as_bytes(),
            "Order.Test.nzb",
            "",
            0,
            None,
            None,
            "test",
            false,
        )
        .expect("enqueue");
        assert!(picker.join().expect("picker thread"), "nothing was picked");

        let ring: Vec<(String, u64)> = d
            .life_events
            .lock_ok()
            .iter()
            .map(|e| {
                (
                    e["kind"].as_str().unwrap_or_default().to_string(),
                    e["seq"].as_u64().unwrap_or(0),
                )
            })
            .collect();
        let at = |kind: &str| {
            ring.iter()
                .position(|(k, _)| k == kind)
                .unwrap_or_else(|| panic!("no {kind} on the ring: {ring:?}"))
        };
        let (added, started) = (at("job.added"), at("job.started"));
        assert!(added < started, "job.started outran job.added: {ring:?}");
        // Ring order and seq order are the same claim; a fix that
        // reserved a seq early but pushed late would break this half.
        assert!(
            ring[added].1 < ring[started].1,
            "seq out of order: {ring:?}"
        );
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
                nzb_name: None,
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
        // (§129 4a: record_add_params FILLS, never clobbers - at add
        // time these fields are empty unless the pre-queue hook set
        // them, and the hook outranks the request. Clear the values the
        // resolve_script cases above planted.)
        {
            let g = job_by(d, &id);
            let mut g = g.lock_ok();
            g.script_override = String::new();
            g.sab_pp = None;
        }
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
        // (Also the fill-only rule doing its other job: refusing can
        // never become a way to CLEAR an existing override.)
        d.record_add_params(&id, None, Some("ghost.py"), false);
        assert_eq!(job_by(d, &id).lock_ok().script_override, "/scripts/tv.py");
        // §129 4a: fill-only in general - once set (at add time that
        // means the pre-queue hook set it), the request's own script=
        // does not displace it. The hook outranks the request, SAB
        // pre-queue semantics.
        d.record_add_params(&id, None, Some("/elsewhere/mine.py"), false);
        assert_eq!(
            job_by(d, &id).lock_ok().script_override,
            "/scripts/tv.py",
            "a planted override survives the request's script="
        );
        let clear = || job_by(d, &id).lock_ok().script_override = String::new();
        // A path-bearing value is operator intent and stays as written.
        clear();
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
        clear();
        d.record_add_params(&id, None, Some("tv.py"), true);
        assert_eq!(job_by(d, &id).lock_ok().script_override, "/scripts/tv.py");
        // SAB's own null still suppresses the whole ladder.
        clear();
        d.record_add_params(&id, None, Some("None"), false);
        assert_eq!(job_by(d, &id).lock_ok().script_override, "None");
        assert_eq!(d.resolve_script(&job_by(d, &id)), None);
    });
}

/// A job that never reached the QUEUE still keeps the add's `pp=` and
/// `script=`.
///
/// A pre-queue reject and dupe_action="fail" both answer the add with an
/// id and file the record straight to history, and `record_add_params`
/// searched the queue alone - so those two paths dropped the caller's
/// post-processing parameters on the floor. The record is what a History
/// retry brings back, so it has to carry them (M15, 10 Aug sweep).
#[test]
fn add_params_reach_a_job_that_went_straight_to_history() {
    with_daemon("addparams-history", |d| {
        let job = jv("hist-1", "Rejected.Release", serde_json::json!({}));
        {
            let mut g = job.lock_ok();
            g.state = JobState::Failed;
            g.fail_message = "rejected by the pre-queue script".into();
        }
        d.history.lock_ok().push(job.clone());

        d.record_add_params("hist-1", Some("2"), Some("/scripts/mine.py"), false);
        {
            let g = job.lock_ok();
            assert_eq!(g.sab_pp, Some(2), "pp= was lost on the history path");
            assert_eq!(g.script_override, "/scripts/mine.py");
        }
        // ...and it reached the store, not just the in-memory record.
        let stored = std::fs::read_to_string(d.history_store_path()).unwrap_or_default();
        assert!(
            stored.contains("/scripts/mine.py"),
            "the history record was not persisted: {stored:?}"
        );
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

#[test]
fn scoreboard_reference_prefers_the_named_account_and_never_falls_through() {
    with_daemon("sbref", |d| {
        let mk = |name: &str, enabled: bool| crate::newznab::IndexerConfig {
            name: name.into(),
            url: "https://geek.test".into(),
            apikey: "k1".into(),
            enabled,
            priority: 0,
            hits_per_day: 0,
            grabs_per_day: 0,
        };
        // Nothing configured at all: the ask-the-user message.
        assert!(d.scoreboard_reference().is_err());

        // Manual pair only - the pre-existing shape still works.
        *d.scoreboard_url.lock_ok() = "https://manual.test".into();
        *d.scoreboard_key.lock_ok() = Some("mk".into());
        assert_eq!(
            d.scoreboard_reference(),
            Ok(("https://manual.test".into(), "mk".into()))
        );

        // A named account wins over the manual pair, key included.
        d.indexers.lock_ok().push(mk("geek", true));
        *d.scoreboard_source.lock_ok() = "geek".into();
        assert_eq!(
            d.scoreboard_reference(),
            Ok(("https://geek.test".into(), "k1".into()))
        );

        // Disabled or deleted, the named pick is an ERROR - never a
        // silent fall-through to the manual pair, and never traffic to
        // an account the user turned off.
        d.indexers.lock_ok()[0].enabled = false;
        assert!(d.scoreboard_reference().unwrap_err().contains("turned off"));
        d.indexers.lock_ok().clear();
        assert!(
            d.scoreboard_reference()
                .unwrap_err()
                .contains("no longer in your indexer list")
        );
    });
}

/// The confirm lane's stats card mirrors `corr_confirm_reference`'s
/// verdict as four DISTINCT states: the picker deliberately keeps a
/// vanished account listed, so present-and-enabled, disabled, deleted
/// and empty must each be tellable apart - a card that only knows
/// "string present" says "0 of 24 checks used" while every tick is
/// refused.
#[test]
fn corr_confirm_source_state_tells_the_four_states_apart() {
    with_daemon("ccfstate", |d| {
        let mk = |name: &str, enabled: bool| crate::newznab::IndexerConfig {
            name: name.into(),
            url: "https://geek.test".into(),
            apikey: "k1".into(),
            enabled,
            priority: 0,
            hits_per_day: 0,
            grabs_per_day: 0,
        };
        // Empty pick.
        assert_eq!(d.corr_confirm_source_state(), "none");
        assert!(d.corr_confirm_reference().is_err());

        // Present and enabled.
        d.indexers.lock_ok().push(mk("geek", true));
        *d.corr_confirm_source.lock_ok() = "geek".into();
        assert_eq!(d.corr_confirm_source_state(), "ok");
        assert!(d.corr_confirm_reference().is_ok());

        // Turned off: the string is still there, the state is not ok.
        d.indexers.lock_ok()[0].enabled = false;
        assert_eq!(d.corr_confirm_source_state(), "disabled");
        assert!(
            d.corr_confirm_reference()
                .unwrap_err()
                .contains("turned off")
        );

        // Deleted: distinct from turned off.
        d.indexers.lock_ok().clear();
        assert_eq!(d.corr_confirm_source_state(), "missing");
        assert!(
            d.corr_confirm_reference()
                .unwrap_err()
                .contains("no longer in your indexer list")
        );
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

/// §96.5: a refill restarts the block-used counter without rewinding
/// the lifetime ledger - the ledger also answers the history totals
/// and `jobs_ever`, so the two must be able to disagree.
#[test]
fn block_refill_restarts_the_counter_but_never_the_ledger() {
    with_daemon("blockbase", |d| {
        d.add_usage(&[("blk.example".into(), 700)]);
        assert_eq!(d.block_spent("blk.example"), 700);
        d.block_refilled("blk.example");
        assert_eq!(
            d.block_spent("blk.example"),
            0,
            "refill restarts the counter"
        );
        assert_eq!(
            d.usage_lifetime("blk.example"),
            700,
            "the lifetime ledger is never rewound"
        );
        d.add_usage(&[("blk.example".into(), 300)]);
        assert_eq!(d.block_spent("blk.example"), 300);
        assert_eq!(d.usage_lifetime("blk.example"), 1000);
        // Persisted: the base must survive a restart or the refill
        // un-happens the next time the daemon loads usage.json.
        let disk = crate::persist::load_json_with_backup(&d.spool.join("usage.json")).unwrap();
        assert_eq!(
            disk.get("block_base")
                .and_then(|b| b.get("blk.example"))
                .and_then(|v| v.as_u64()),
            Some(700)
        );
    });
}

/// §96.5: the mid-job usage flush bills only the delta since the last
/// call, at any cadence - so the periodic tick and the net-drain call
/// can both run without double-billing a paid block.
#[test]
fn flush_run_usage_delta_bills_and_never_double_bills() {
    with_daemon("usageflush", |d| {
        let sc: nzbkit::config::ServerConfig =
            serde_json::from_str(r#"{"host":"blk.example"}"#).unwrap();
        let live =
            nzbkit::pool::LiveStats::for_servers(&[(sc, nzbkit::pool::PoolConfig::default())]);
        live.servers[0].bytes.store(500, Ordering::Relaxed);
        *d.hub.pool_live.lock_ok() = Some(live.clone());
        d.flush_run_usage();
        assert_eq!(d.usage_lifetime("blk.example"), 500);
        d.flush_run_usage();
        assert_eq!(
            d.usage_lifetime("blk.example"),
            500,
            "an unmoved counter must bill nothing"
        );
        live.servers[0].bytes.store(800, Ordering::Relaxed);
        d.flush_run_usage(); // the net-drain call is this same helper
        assert_eq!(d.usage_lifetime("blk.example"), 800);
        // Job boundary: pool cleared first, then the high-water map -
        // a flush tick in that gap sees no pool and bills nothing.
        *d.hub.pool_live.lock_ok() = None;
        d.run_usage_flushed.lock_ok().clear();
        d.flush_run_usage();
        assert_eq!(d.usage_lifetime("blk.example"), 800);
    });
}

/// §129 4c: the second empty state must not come back once a job has
/// run. Clearing history is the case that broke a naive "is the queue
/// empty right now" check, so the sticky term is asserted on its own -
/// with the queue and history both empty, which is exactly the state a
/// user who cleared everything is in.
#[test]
fn jobs_ever_is_sticky_across_a_cleared_history() {
    with_daemon("jobsever", |d| {
        assert!(!d.jobs_ever(), "a fresh install has never downloaded");
        // A completed download bills the lifetime bucket...
        d.add_usage(&[("s1.example".into(), 4096)]);
        assert!(d.jobs_ever(), "billed bytes say a job has run");
        // ...and the bucket outlives an emptied queue and history.
        d.queue.lock_ok().clear();
        d.history.lock_ok().clear();
        assert!(
            d.jobs_ever(),
            "clearing history must not send a working install back to onboarding"
        );
    });
}

/// The other half: a job that failed before it billed a single byte
/// still ends the empty state, because it is in history.
#[test]
fn jobs_ever_answers_off_history_alone() {
    with_daemon("jobsever-hist", |d| {
        assert!(!d.jobs_ever());
        let j = crate::serve::tests_jobs::job(serde_json::json!({
            "nzo_id": "abc", "name": "Some.Show.S01E01", "nzb_path": "/spool/a.nzb",
            "state": "Failed", "out_dir": "/dl/a",
        }));
        d.history
            .lock_ok()
            .push(std::sync::Arc::new(std::sync::Mutex::new(j)));
        assert!(d.jobs_ever(), "a failed job never bills usage, but it ran");
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

/// A job's out_dir is the absolute path baked in from the download-folder
/// setting when it was ADDED. If the user later points the download folder
/// somewhere else (or a settings.json is carried between machines where the
/// old path no longer exists), `retry` must re-download into the CURRENT
/// folder - not re-run the job forever at the stale, possibly-dead path.
/// Field repro 9 Aug: out_dir was changed to a mounted path, yet retry kept
/// targeting the old /Volumes/... one and failed with the same error.
#[test]
fn retry_reresolves_a_stale_baked_out_dir_to_the_current_download_folder() {
    with_daemon("retry-staleroot", |d| {
        let old_root = d.out_dir();
        let tmp = old_root.parent().expect("tempdir").to_path_buf();
        let new_root = tmp.join("newout");
        std::fs::create_dir_all(&new_root).unwrap();

        // A Failed history job whose out_dir sits under the OLD root, exactly
        // as enqueue would have built it (root / category / stem).
        let old_dir = old_root.join("movies").join("Some.Movie.2024");
        d.history.lock_ok().push(jv(
            "SABnzbd_nzo_stale",
            "Some.Movie.2024",
            serde_json::json!({
                "out_dir": old_dir.to_string_lossy(),
                "category": "movies",
                "state": "Failed",
                "fail_message": "boom",
            }),
        ));

        // The user changes the download folder AFTER the job was added.
        *d.out_root.write_ok() = new_root.clone();

        assert!(d.retry("SABnzbd_nzo_stale"), "retry accepted");

        // Left history, landed in the queue, re-aimed at the CURRENT root.
        assert!(
            !d.history
                .lock_ok()
                .iter()
                .any(|j| j.lock_ok().nzo_id == "SABnzbd_nzo_stale"),
            "the record left history"
        );
        let q = d.queue.lock_ok();
        let j = q
            .iter()
            .find(|j| j.lock_ok().nzo_id == "SABnzbd_nzo_stale")
            .expect("re-queued")
            .clone();
        let g = j.lock_ok();
        assert!(
            g.out_dir.starts_with(&new_root),
            "retry must target the CURRENT download folder, got {}",
            g.out_dir.display()
        );
        assert!(
            !g.out_dir.starts_with(&old_root),
            "retry must not reuse the stale baked path {}",
            g.out_dir.display()
        );
        // Nothing is on disk at the new folder, so progress starts from zero.
        assert_eq!(g.downloaded_bytes, 0);
        assert_eq!(g.state, JobState::Queued);
    });
}

/// TODO 143: a scan pass publishing its connection must leave
/// `index_migrated` SET.
///
/// The flag answers "has a read-write open run the migrations", and
/// `index_read_checked` sends every query down `with_index`'s UNBOUNDED
/// wait on the write mutex while it is false - the startup-shaped moment
/// when nothing holds a long lock. The other four writers of that mutex
/// only set it on the branch where THEY open the connection
/// (`guard.is_none()`), so once a pass has published one, that branch
/// never runs again and the flag stayed false for the life of the
/// process: the read-only pool became dead code and the 28 Jul / 2 Aug
/// wedges were reopened on every install whose scan loop published
/// before the first `with_index` call.
///
/// http_wedge pins the symptom end to end. This pins the seam, because
/// that suite only caught it once Spotnet went default-on and gave its
/// groupless fixture a pass to publish from - a test whose config is
/// unrepresentative is how this stayed green while production wedged.
#[cfg(feature = "indexer")]
#[test]
fn a_published_scan_connection_marks_the_index_migrated() {
    with_daemon("published", |d| {
        d.index_enabled.store(true, Ordering::Relaxed);
        // A scan pass opens its OWN connection - migrations run there -
        // and hands it over. Nothing has called with_index yet, which is
        // the ordering that made this invisible.
        let era = d.index_era();
        let fresh = nzbkit::index::Index::open(&d.index_db).expect("scan pass open");
        d.publish_index(era, fresh);
        assert!(
            d.index.lock_ok().is_some(),
            "precondition: the pass's connection is the published one"
        );
        assert!(
            d.index_migrated.load(Ordering::Acquire),
            "a published connection has run the migrations, so queries \
             must use the read pool rather than the write mutex"
        );
    });
}

/// The other half of the same rule: an ordinary failed retry whose out_dir
/// is STILL under the current download folder keeps its own directory (and
/// so its journal and its progress). The stale-path re-resolution above must
/// not disturb the common case.
#[test]
fn retry_keeps_an_out_dir_that_is_still_under_the_current_root() {
    with_daemon("retry-liveroot", |d| {
        let keep = d.out_dir().join("movies").join("Keep.Me.2024");
        d.history.lock_ok().push(jv(
            "SABnzbd_nzo_keep",
            "Keep.Me.2024",
            serde_json::json!({
                "out_dir": keep.to_string_lossy(),
                "category": "movies",
                "state": "Failed",
                "downloaded_bytes": 4096,
            }),
        ));

        assert!(d.retry("SABnzbd_nzo_keep"), "retry accepted");

        let q = d.queue.lock_ok();
        let g = q
            .iter()
            .find(|j| j.lock_ok().nzo_id == "SABnzbd_nzo_keep")
            .expect("re-queued")
            .clone();
        let g = g.lock_ok();
        assert_eq!(
            g.out_dir, keep,
            "an under-root retry keeps its own folder in place"
        );
        // Its journal is intact at that folder, so its progress is kept.
        assert_eq!(g.downloaded_bytes, 4096);
    });
}

/// The indexer-confirm lane end to end against a mock newznab, with
/// the suggestion created by the REAL correlation machinery (seeded
/// pre + dark scanned row + catchup walk - the design's own worked
/// example numbers). Round one: the listing matches, its NZB
/// msgid-joins at quorum, the row gains the pre title as a proven
/// msgid-set name and the suggestion settles 'confirmed'. Round two:
/// a second suggestion's NZB joins nothing - stamped out, nothing
/// named, and the suggestion left standing rather than falsely
/// settled.
#[cfg(feature = "indexer")]
#[test]
fn an_indexer_confirmed_suggestion_becomes_a_proven_name() {
    use nzbkit::predb::{PreKind, PreLine};
    with_daemon("corrconfirm", |d| {
        d.index_enabled
            .store(true, std::sync::atomic::Ordering::Relaxed);
        let seed = |ix: &mut nzbkit::index::Index, stem: &str, tag: &str, title: &str| {
            let entries: Vec<nzbkit::nntp::OverEntry> = (1..=3u64)
                .map(|n| nzbkit::nntp::OverEntry {
                    number: n,
                    subject: format!(r#""{stem}" yEnc ({n}/3)"#),
                    from: "p@x".into(),
                    message_id: format!("<{tag}{n}@test>"),
                    bytes: 1_666_666_666,
                    date: 4_600,
                })
                .collect();
            ix.ingest("alt.binaries.x264", &entries, 5_000).unwrap();
            ix.predb_store(
                &[PreLine {
                    kind: PreKind::New,
                    title: title.into(),
                    category: "X264-HD".into(),
                    size: 4_900_000_000,
                    date: 1_000,
                    source: "PRE".into(),
                    ..Default::default()
                }],
                5_000,
            )
            .unwrap();
        };
        const TITLE: &str = "Test.Release.2026.1080p.WEB.H264-GRP";
        d.with_index_mut(|ix| {
            seed(ix, "x7Pq9RtK2mVb8NcJ4wZs", "cc", TITLE);
            let (_, suggested, _) = ix.predb_corr_backlog(400, 0, false, 6_200).unwrap();
            assert_eq!(suggested, 1, "the real scorer suggested the pairing");
            let picks = ix.corr_confirm_pick(5).unwrap();
            assert_eq!(picks.len(), 1);
            assert_eq!(picks[0].1, TITLE);
            Some(())
        })
        .unwrap();

        // Mock newznab: request 1 = the search, request 2 = the NZB.
        // Connection: close forces a fresh connection per request so
        // the accept loop sees each one.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let nzb_ids: std::sync::Arc<std::sync::Mutex<Vec<&'static str>>> =
            std::sync::Arc::new(std::sync::Mutex::new(vec!["cc1", "cc2", "cc3"]));
        let ids2 = nzb_ids.clone();
        let server = std::thread::spawn(move || {
            use std::io::{Read, Write};
            for stream in listener.incoming().take(4) {
                let mut s = stream.unwrap();
                let mut buf = [0u8; 4096];
                let n = s.read(&mut buf).unwrap_or(0);
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let body = if req.contains("t=search") {
                    format!(
                        r#"<?xml version="1.0"?><rss><channel>
<item><title>Test.Release.2026.1080p.WEB.H264-GRP</title><guid>g1</guid>
<enclosure url="http://127.0.0.1:{port}/nzb" length="4900000000" type="application/x-nzb"/>
</item></channel></rss>"#
                    )
                } else {
                    let ids = ids2.lock().unwrap().clone();
                    let segs: String = ids
                        .iter()
                        .enumerate()
                        .map(|(i, id)| {
                            format!(
                                r#"<segment bytes="1666666666" number="{}">{id}@test</segment>"#,
                                i + 1
                            )
                        })
                        .collect();
                    format!(
                        r#"<?xml version="1.0"?><nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
<file poster="p@x" date="4600" subject="&quot;x&quot; yEnc (1/3)">
<groups><group>alt.binaries.x264</group></groups>
<segments>{segs}</segments></file></nzb>"#
                    )
                };
                let _ = write!(
                    s,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
            }
        });

        d.indexers.lock_ok().push(crate::newznab::IndexerConfig {
            name: "mock".into(),
            url: format!("http://127.0.0.1:{port}"),
            apikey: "k".into(),
            enabled: true,
            priority: 0,
            hits_per_day: 0,
            grabs_per_day: 0,
        });
        *d.corr_confirm_source.lock_ok() = "mock".into();
        // Both switches: the confirm lane is a child of correlation
        // and stands down whenever the parent is off.
        d.predb_corr_enabled
            .store(true, std::sync::atomic::Ordering::Relaxed);
        d.corr_confirm_enabled
            .store(true, std::sync::atomic::Ordering::Relaxed);

        assert!(super::tasks::corr_confirm_once(d), "budget was spent");
        d.with_index(|ix| {
            let r = &ix.search("x7Pq9RtK2mVb8NcJ4wZs", 5).unwrap()[0];
            assert_eq!(r.pre_title, TITLE, "the join named the row");
            let stats = ix.predb_corr_stats().unwrap();
            let confirmed = stats
                .iter()
                .find(|(k, _)| k == "confirmed")
                .map(|(_, v)| *v)
                .unwrap_or(0);
            assert_eq!(confirmed, 1, "the suggestion settled confirmed");
            assert!(
                ix.corr_confirm_pick(5).unwrap().is_empty(),
                "checked once, never again"
            );
            Some(())
        })
        .unwrap();

        // Round two: a fresh suggestion whose fetched NZB shares no
        // message-ids with the row - the join must find nothing.
        const TITLE2: &str = "Other.Show.S01E05.1080p.WEB.H264-GRP";
        d.with_index_mut(|ix| {
            seed(ix, "q2Wm8VbN5xKj3RtY7pLc", "dd", TITLE2);
            // The backlog cursor parked below round one's rows; a seed
            // generation bump is production's own re-open mechanism.
            ix.kv_set("predb_seed_gen", "test2").unwrap();
            let (_, suggested, _) = ix.predb_corr_backlog(400, 0, false, 6_300).unwrap();
            assert_eq!(suggested, 1);
            Some(())
        })
        .unwrap();
        *nzb_ids.lock().unwrap() = vec!["ee1", "ee2", "ee3"];
        assert!(
            super::tasks::corr_confirm_once(d),
            "budget spent on the miss too"
        );
        d.with_index(|ix| {
            let r = &ix.search("q2Wm8VbN5xKj3RtY7pLc", 5).unwrap()[0];
            assert_eq!(r.pre_title, "", "no join, no name");
            assert!(
                ix.corr_confirm_pick(5).unwrap().is_empty(),
                "stamped regardless"
            );
            Some(())
        })
        .unwrap();
        drop(server);
    });
}

/// C4-4 (§131 identity substrate): an accepted NZB is a (name, payload
/// message-id set) pairing. When its payload ids are rows the scanner
/// holds, the add records a MsgidSet claim against them, provenance-
/// tagged with the add's origin - and a sub-quorum overlap records
/// nothing, because a single message-id can be seeded.
#[cfg(feature = "indexer")]
#[test]
fn an_accepted_nzb_pairs_its_msgids_onto_scanned_rows() {
    with_daemon("nzbpair", |d| {
        d.index_enabled
            .store(true, std::sync::atomic::Ordering::Relaxed);
        // Two dark scanned rows, three articles each.
        d.with_index_mut(|ix| {
            let row = |stem: &str, tag: &str| -> Vec<nzbkit::nntp::OverEntry> {
                (1..=3u64)
                    .map(|n| nzbkit::nntp::OverEntry {
                        number: n,
                        subject: format!(r#""{stem}.part1.rar" yEnc ({n}/3)"#),
                        from: "p@x".into(),
                        message_id: format!("<{tag}{n}@test>"),
                        bytes: 1000,
                        date: 1_700_000_000,
                    })
                    .collect()
            };
            ix.ingest("a.b.dark", &row("jumbled77aa", "pair"), 1_700_000_001)
                .ok()?;
            ix.ingest("a.b.dark", &row("jumbled77bb", "sub"), 1_700_000_001)
                .ok()
        })
        .expect("seed index");
        let nzb = |ids: &[&str]| {
            let segs: String = ids
                .iter()
                .enumerate()
                .map(|(i, id)| {
                    format!(
                        r#"<segment bytes="1000" number="{}">{id}@test</segment>"#,
                        i + 1
                    )
                })
                .collect();
            format!(
                "<?xml version=\"1.0\"?><nzb><file poster=\"x\" date=\"0\" \
                 subject=\"&quot;a.bin&quot; yEnc (1/{})\"><groups><group>g</group>\
                 </groups><segments>{segs}</segments></file></nzb>",
                ids.len()
            )
        };
        // All three of the first row's ids: quorum, claim recorded.
        d.enqueue(
            nzb(&["pair1", "pair2", "pair3"]).as_bytes(),
            "Real.Show.S01E01.1080p-GRP.nzb",
            "",
            -100,
            None,
            None,
            "watch",
            false,
        )
        .unwrap();
        // Only two of the second row's: under quorum, nothing recorded.
        d.enqueue(
            nzb(&["sub1", "sub2"]).as_bytes(),
            "Wrong.Name.S09E09.720p-BAD.nzb",
            "",
            -100,
            None,
            None,
            "watch",
            true,
        )
        .unwrap();
        let (paired, sub) = d
            .with_index(|ix| {
                let rid = |posted: &str| {
                    ix.release_ids_by_stem(posted)
                        .unwrap()
                        .first()
                        .copied()
                        .expect("seeded row")
                };
                let paired = ix.name_claims(rid("jumbled77aa.part1.rar")).unwrap();
                let sub = ix.name_claims(rid("jumbled77bb.part1.rar")).unwrap();
                Some((paired, sub))
            })
            .expect("index open");
        assert_eq!(paired.len(), 1, "{paired:?}");
        let (name, tier, _key, source, _at) = &paired[0];
        assert_eq!(name, "Real.Show.S01E01.1080p-GRP");
        assert_eq!(tier, "msgid-set");
        assert_eq!(source, "nzb-watch");
        assert!(sub.is_empty(), "sub-quorum must record nothing: {sub:?}");
    });
}

/// The restart window the 10 Aug audit flagged: the stats cache is
/// empty until the first successful read, and a scan batch can hold the
/// write connection from the moment the daemon comes up - index_stats
/// answered (0,0,0,0) and the dashboard told whoever loaded the page
/// that a populated index was empty. The pooled read-only connections
/// run concurrently with that writer, so a busy write lock must not
/// read as an empty index.
#[cfg(feature = "indexer")]
#[test]
fn index_stats_answer_from_the_read_pool_while_the_writer_is_busy() {
    with_daemon("statsro", |d| {
        d.index_enabled.store(true, Ordering::Relaxed);
        // Create the database (and run migrations) through the write
        // connection, exactly as startup's first ingest would.
        d.with_index(|_ix| Some(())).expect("index open");
        assert!(
            d.index_stats_cache.lock_ok().is_none(),
            "precondition: no successful stats read has seeded the cache"
        );
        // A scan batch owns the write connection for the whole window.
        let _writer = d.index.lock_ok();
        let snap = d
            .index_stats_snapshot()
            .expect("the read pool serves figures while the writer is busy");
        assert!(
            snap.2 > 0,
            "a busy write lock must not read as an empty index: {snap:?}"
        );
        // And the answer seeds the cache for the next busy poll.
        assert_eq!(*d.index_stats_cache.lock_ok(), Some(snap));
    });
}

/// The residue of the window above: write lock busy, cache cold, and
/// the read pool cannot help either (here: the database file does not
/// exist yet, so a read-only open fails). The one honest answer is "no
/// figures yet" - None, which the API forwards as stats_cold - never
/// zeros dressed up as a count.
#[cfg(feature = "indexer")]
#[test]
fn index_stats_answer_cold_not_zero_when_no_read_path_is_available() {
    with_daemon("statscold", |d| {
        d.index_enabled.store(true, Ordering::Relaxed);
        assert!(d.index_stats_cache.lock_ok().is_none());
        let _writer = d.index.lock_ok();
        assert_eq!(
            d.index_stats_snapshot(),
            None,
            "an unreadable index must answer cold, not empty"
        );
        // Cold answers must not seed the cache: the next poll should
        // try the real read paths again, not replay the placeholder.
        assert!(d.index_stats_cache.lock_ok().is_none());
    });
}

fn outage(host: &str, secs: u64, kind: &'static str) -> ServerOutage {
    ServerOutage {
        host: host.to_string(),
        since_ms: 1_000,
        secs,
        kind,
        detail: "the server's own words".into(),
    }
}

/// The queue row names a dead provider only when the job is actually
/// stuck behind it, and only once the outage has outlived the window.
///
/// Both gates earn their keep. Without the stall gate, a job pulling at
/// full line speed from server A would put a red "no connection" line on
/// its own row because a backup B nobody needed is out - an alarm on a
/// row that is working. Without the window, every capacity bounce and
/// every ordinary redial would flicker one.
#[test]
fn a_row_names_a_dead_server_only_when_it_is_stuck_behind_it() {
    // Window default is 60 s; keep the test independent of the env knob.
    let win = server_down_secs();
    let long = outage("news.example", win + 5, "unreachable");
    let brief = outage("news.example", win.saturating_sub(1), "unreachable");

    assert!(
        row_outage(false, std::slice::from_ref(&long)).is_none(),
        "a healthy row must stay quiet about a dead backup"
    );
    assert!(
        row_outage(true, std::slice::from_ref(&brief)).is_none(),
        "an outage inside the window is a redial, not news"
    );
    let (tok, o) =
        row_outage(true, std::slice::from_ref(&long)).expect("stuck and past the window");
    assert_eq!(tok, "server_unreachable");
    assert_eq!(o.host, "news.example");
    assert!(row_outage(true, &[]).is_none());
}

/// The three causes are three tokens, because they are three different
/// things for the user to do: wait, wait for a slot, or go fix a
/// password. One "server down" phrase would have flattened them.
#[test]
fn each_outage_cause_gets_its_own_token() {
    let win = server_down_secs() + 1;
    for (kind, want) in [
        ("unreachable", "server_unreachable"),
        ("capacity", "server_capacity"),
        ("refused", "server_refused"),
    ] {
        let o = [outage("h", win, kind)];
        assert_eq!(row_outage(true, &o).expect("reported").0, want, "{kind}");
    }
}

/// Worst first: with two providers out, the row reports the one that has
/// been out longest, because that is the one least likely to come back
/// on its own.
#[test]
fn the_longest_outage_is_the_one_the_row_reports() {
    let win = server_down_secs();
    // `server_outages` sorts longest-first; `row_outage` trusts that.
    let os = [
        outage("old.example", win + 600, "unreachable"),
        outage("new.example", win + 1, "capacity"),
    ];
    assert_eq!(
        row_outage(true, &os).expect("reported").1.host,
        "old.example"
    );
}

// -- §158 item 7: neither store holds the record -----------------------------

/// A second Daemon over the same spool directory, restored from whatever
/// is on disk RIGHT NOW. The restart half of the crash harness: the
/// assertions below are made against bytes a torn write actually left,
/// not against a fixture written to match somebody's belief about it.
fn restart(d: &Arc<Daemon>) -> Arc<Daemon> {
    let dir = d.spool.parent().expect("spool has a parent").to_path_buf();
    let d2 = super::super::testutil::test_daemon(&dir);
    d2.load_queue();
    d2
}

fn one_file_nzb(seg: &str) -> String {
    format!(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\
         <file poster=\"x\" date=\"0\" subject=\"&quot;a.bin&quot; yEnc (1/1)\">\
         <groups><group>g</group></groups><segments>\
         <segment bytes=\"1000\" number=\"1\">{seg}@x</segment>\
         </segments></file></nzb>"
    )
}

fn stored_next_id(d: &Arc<Daemon>) -> u64 {
    crate::persist::load_json_with_backup(&d.spool.join("queue.json"))
        .and_then(|v| v.get("next_id").and_then(Value::as_u64))
        .expect("queue.json carries next_id")
}

/// §158: a duplicate add with duplicates set to "fail" never joins the
/// queue - it files straight to history - so its record reaches disk
/// through TWO writes that are not one transaction. The record's own
/// store goes first; `save_queue` runs second and carries nothing of this
/// job but the id-allocator bump.
///
/// Cut between them, which is what a kill or an ENOSPC does there. The
/// old order wrote the queue snapshot first, so the write that survived
/// the cut was the one with no trace of the job in it and the record was
/// lost from BOTH files - the spooled .nzb left on disk named by nothing,
/// and the *arr that submitted it never told the grab had failed.
#[test]
fn a_never_queued_rejection_survives_a_kill_between_its_two_store_writes() {
    with_daemon("lostboth-fail", |d| {
        let add = |seg: &str, name: &str| {
            d.enqueue(
                one_file_nzb(seg).as_bytes(),
                name,
                "",
                -100,
                None,
                None,
                "test",
                false,
            )
        };
        // The original, so the next add collides with it. A name with a
        // derivable identity (SxxEyy), or there is no dupe_key to match on.
        add("one", "Show.S03E04.1080p.nzb").expect("the original add");
        *d.dupe_action.lock_ok() = "fail".into();
        let before = stored_next_id(d);

        // One more durable store write lands; the process dies before the
        // next one.
        super::super::storecut::arm_cut(1);
        let failed = add("two", "Show.S03E04.720p.nzb").expect("the duplicate add");
        super::super::storecut::disarm();

        let after = stored_next_id(d);
        assert!(
            d.queue
                .lock_ok()
                .iter()
                .all(|j| j.lock_ok().nzo_id != failed),
            "the rejected job must never have been queued"
        );

        // What a restart finds.
        let d2 = restart(d);
        assert!(
            d2.history
                .lock_ok()
                .iter()
                .any(|j| j.lock_ok().nzo_id == failed),
            "the rejected record was lost from BOTH stores"
        );
        // ...and the cut has to have actually landed inside the pair, or
        // the assertion above proves nothing: `save_queue` persists the id
        // allocator, so a stale next_id is the receipt that it never ran.
        assert_eq!(
            after, before,
            "the second write was supposed to be cut - this harness is not \
             exercising the window"
        );
    });
}

/// §158: `park` moves a record the other way, and its window is a RACE
/// rather than a kill - every queue mutation in the daemon calls
/// `save_queue`, so any other thread saving between the row leaving the
/// live queue and history.jsonl gaining it publishes a queue.json the
/// record is no longer in while no store holds it at all.
///
/// The window is a few hundred microseconds, so the harness runs that
/// save from inside it rather than racing for it, and then cuts every
/// write park still had to make.
#[test]
fn a_park_survives_a_racing_queue_save_in_its_window() {
    with_daemon("lostboth-park", |d| {
        let job = jv("nzo-park-1", "Parked.Release", serde_json::json!({}));
        d.queue.lock_ok().push_back(job.clone());
        assert!(d.save_queue(), "the queue snapshot the park starts from");
        {
            let mut g = job.lock_ok();
            g.state = JobState::Completed;
            g.finished_unix = Some(1);
        }

        super::super::storecut::on_park_gap(|d| {
            assert!(d.save_queue(), "the racing save must land");
            // ...and the process dies there: nothing park writes after
            // this point reaches disk.
            super::super::storecut::arm_cut(0);
        });
        d.park(job);
        super::super::storecut::disarm();

        let queued = std::fs::read_to_string(d.spool.join("queue.json")).unwrap_or_default();
        assert!(
            !queued.contains("nzo-park-1"),
            "the racing save was supposed to publish a queue without the row - \
             this harness is not exercising the window"
        );

        let d2 = restart(d);
        assert!(
            d2.history
                .lock_ok()
                .iter()
                .any(|j| j.lock_ok().nzo_id == "nzo-park-1"),
            "the parked record was lost from BOTH stores"
        );
        assert!(
            d2.queue.lock_ok().is_empty(),
            "and it must not come back as a queued job as well"
        );
    });
}

/// The other end of the same reorder: a delete landing INSIDE a park,
/// after its durable history row went down. The job is dropped rather
/// than filed, so the row it already wrote has to be buried - or the
/// early write would resurrect, at the next boot, exactly the job the
/// user cancelled.
#[test]
fn a_delete_inside_the_park_window_buries_the_row_park_already_wrote() {
    with_daemon("lostboth-park-del", |d| {
        let job = jv("nzo-park-2", "Cancelled.Release", serde_json::json!({}));
        d.queue.lock_ok().push_back(job.clone());
        assert!(d.save_queue());
        {
            let mut g = job.lock_ok();
            g.state = JobState::Completed;
            g.finished_unix = Some(1);
        }

        let tombstoned = job.clone();
        super::super::storecut::on_park_gap(move |_| {
            tombstoned.lock_ok().tombstone = true;
        });
        d.park(job);
        super::super::storecut::disarm();

        assert!(
            d.history.lock_ok().is_empty(),
            "a tombstoned job is dropped, not filed"
        );
        let d2 = restart(d);
        assert!(
            d2.history.lock_ok().is_empty(),
            "the early history row outlived the delete that cancelled it"
        );
    });
}

// -- issue #38 follow-up: queue-lock hold at 14,500 jobs ---------------------

/// Manual perf probe for the large-queue lock work, NOT a CI assertion -
/// it prints timings and asserts only that the snapshot is complete.
/// Run it by hand:
///
///   cargo test -p nzbfast --bin nzbfast save_queue_lock_hold \
///     -- --ignored --nocapture
///
/// Phase 1 reproduces the shape save_queue had before the fix (every
/// job serialized UNDER the queue lock); phase 2 is the shipped shape
/// (Arc snapshot under the lock, serialization after). Phases 3-4 put
/// numbers on the residue walks: pick_job (runnable and all-paused) and
/// note_queue_idle (arming edge, then latched). A contender
/// thread hammers the queue lock throughout and reports the worst
/// single acquire wait it saw in each phase - that wait is exactly what
/// an API request or the dashboard felt at issue #38's queue size.
#[test]
#[ignore = "manual perf probe: prints timings, run with --ignored --nocapture"]
fn save_queue_lock_hold_at_15k_jobs() {
    with_daemon("15k-bench", |d| {
        const N: usize = 15_000;
        {
            let mut q = d.queue.lock_ok();
            for i in 0..N {
                q.push_back(jv(
                    &format!("SABnzbd_nzo_bench{i:05}"),
                    &format!("Some.Release.S01E{:02}.1080p.WEB.H264-GRP.{i}", i % 99),
                    serde_json::json!({
                        "total_bytes": 4_000_000_000u64,
                        "downloaded_bytes": 1_234_567u64,
                        "category": "tv",
                    }),
                ));
            }
        }
        fn contend(d: &Arc<Daemon>, run: impl FnOnce()) -> (std::time::Duration, u64) {
            let stop = Arc::new(AtomicBool::new(false));
            let worst = Arc::new(AtomicU64::new(0));
            let (d2, stop2, worst2) = (d.clone(), stop.clone(), worst.clone());
            let contender = std::thread::spawn(move || {
                while !stop2.load(Ordering::Relaxed) {
                    let t = Instant::now();
                    drop(d2.queue.lock_ok());
                    worst2.fetch_max(t.elapsed().as_micros() as u64, Ordering::Relaxed);
                    std::thread::sleep(std::time::Duration::from_micros(200));
                }
            });
            let t = Instant::now();
            run();
            let took = t.elapsed();
            stop.store(true, Ordering::Relaxed);
            contender.join().expect("contender");
            (took, worst.load(Ordering::Relaxed))
        }
        // Phase 1: the pre-fix shape, serialization under the queue lock.
        let mut n_old = 0;
        let (old_took, old_worst) = contend(&d.clone(), || {
            let q = d.queue.lock_ok();
            let jobs: Vec<Value> = q.iter().map(|j| job_json(&j.lock_ok())).collect();
            n_old = jobs.len();
        });
        // Phase 2: the shipped save_queue, four times over - what one
        // completion used to cost in file rewrites.
        let (new_took, new_worst) = contend(&d.clone(), || {
            for _ in 0..4 {
                assert!(d.save_queue(), "save_queue failed");
            }
        });
        assert_eq!(n_old, N);
        // Phase 3: pick_job over 15k runnable jobs, x8 - the argmax walk
        // the download worker runs every 500 ms while polling.
        let (pick_took, pick_worst) = contend(&d.clone(), || {
            for _ in 0..8 {
                assert!(d.pick_job(false).is_some(), "pick on a runnable queue");
            }
        });
        // Everything from here on wants the all-paused queue: pick_job's
        // every-job continue, and the only shape where note_queue_idle's
        // any() cannot exit on the first job.
        {
            let q = d.queue.lock_ok();
            for j in q.iter() {
                j.lock_ok().paused = true;
            }
        }
        let (pickp_took, pickp_worst) = contend(&d.clone(), || {
            for _ in 0..8 {
                assert!(d.pick_job(false).is_none(), "all paused picks nothing");
            }
        });
        // Phase 4: note_queue_idle on the arming edge (latch clear) -
        // the full walk that actually earns its emit. Then x100 with the
        // latch already set: what every park/delete on an already-idle
        // queue pays. The fast path answers from the latch alone, so
        // this leg no longer touches the queue lock at all.
        d.queue_idle_latch.store(false, Ordering::Relaxed);
        let (idle_took, idle_worst) = contend(&d.clone(), || d.note_queue_idle());
        let (latched_took, latched_worst) = contend(&d.clone(), || {
            for _ in 0..100 {
                d.note_queue_idle();
            }
        });
        println!(
            "15k-queue probe:\n\
             \x20 old shape (serialize under queue lock, x1): {old_took:?}, \
             worst contender lock wait {old_worst} us\n\
             \x20 new save_queue x4 (full write to disk):     {new_took:?}, \
             worst contender lock wait {new_worst} us\n\
             \x20 pick_job x8, 15k runnable:                  {pick_took:?}, \
             worst contender lock wait {pick_worst} us\n\
             \x20 pick_job x8, 15k all paused:                {pickp_took:?}, \
             worst contender lock wait {pickp_worst} us\n\
             \x20 note_queue_idle, arming edge (full walk):   {idle_took:?}, \
             worst contender lock wait {idle_worst} us\n\
             \x20 note_queue_idle x100, latch already set:    {latched_took:?}, \
             worst contender lock wait {latched_worst} us"
        );
    });
}

/// The latched note_queue_idle answers from the latch ALONE - route
/// assertion for the issue #38 residue fix, in the lock-placement-oracle
/// style: hold the queue lock and call it. The fast path returns without
/// ever wanting the lock; the pre-fix shape walks every job under it and
/// parks here forever, which the recv timeout turns into a clean failure.
#[test]
fn latched_note_queue_idle_never_takes_the_queue_lock() {
    with_daemon("idle-latched-route", |d| {
        d.queue
            .lock_ok()
            .push_back(jv("SABnzbd_nzo_r1", "Held.Release", serde_json::json!({})));
        d.queue_idle_latch.store(true, Ordering::Relaxed);
        let _q = d.queue.lock_ok();
        let (tx, rx) = std::sync::mpsc::channel();
        let d2 = d.clone();
        std::thread::spawn(move || {
            d2.note_queue_idle();
            let _ = tx.send(());
        });
        rx.recv_timeout(std::time::Duration::from_secs(10)).expect(
            "note_queue_idle with the latch set must answer from the \
             latch, not the queue walk",
        );
    });
}

/// The arming edge's empty scan and its latch CAS share one hold of the
/// queue lock, and an enqueue cannot publish between them (Codex sweep
/// 14 Aug M3). The pre-fix shape dropped the queue guard after the scan:
/// removal of a last job A leaves the queue empty, an add of B re-arms
/// the latch and publishes job.added, and A's notifier - holding a scan
/// from before B existed - then CASes and announces queue.idle over a
/// runnable job, with the latch left set so B's own genuine idle edge
/// could be swallowed too. The seam pins the notifier in exactly that
/// window; a real enqueue must sit out the window, land after the emit,
/// and leave the latch re-armed.
#[test]
fn an_enqueue_cannot_interleave_into_the_idle_scan_cas_window() {
    with_daemon("idle-aba", |d| {
        // The shape the removal of a last job leaves behind: latch
        // re-armed (false), queue empty.
        d.queue_idle_latch.store(false, Ordering::Relaxed);
        let entered = Arc::new(std::sync::Barrier::new(2));
        let released = Arc::new(std::sync::Barrier::new(2));
        *super::daemon_park::IDLE_CAS_BARRIER.lock_ok() = Some((entered.clone(), released.clone()));
        let notifier = {
            let d = d.clone();
            std::thread::spawn(move || d.note_queue_idle())
        };
        // The notifier has scanned the empty queue and is pinned before
        // its CAS. Disarm the seam so nothing else trips it.
        entered.wait();
        *super::daemon_park::IDLE_CAS_BARRIER.lock_ok() = None;

        // Now the add of B, on its own thread - the interleaving's
        // other half.
        let (tx, rx) = std::sync::mpsc::channel();
        let adder = {
            let d = d.clone();
            std::thread::spawn(move || {
                let nzb = "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\
                     <file poster=\"x\" date=\"0\" subject=\"&quot;b.bin&quot; yEnc (1/1)\">\
                     <groups><group>g</group></groups><segments>\
                     <segment bytes=\"1000\" number=\"1\">b1@x</segment>\
                     </segments></file></nzb>";
                d.enqueue(
                    nzb.as_bytes(),
                    "B.Release.nzb",
                    "",
                    -100,
                    None,
                    None,
                    "test",
                    false,
                )
                .expect("enqueue");
                let _ = tx.send(());
            })
        };
        // Route assertion, not a clock: the add must be waiting on the
        // queue lock the notifier holds, so it cannot complete while
        // the window is open. The timeout only bounds how long we watch
        // for something that must never happen.
        assert!(
            rx.recv_timeout(std::time::Duration::from_millis(300))
                .is_err(),
            "an enqueue published inside the scan-to-CAS window"
        );
        released.wait();
        notifier.join().expect("notifier");
        rx.recv_timeout(std::time::Duration::from_secs(10))
            .expect("the add completes once the notifier's hold ends");
        adder.join().expect("adder");

        // The serialized order is one the queue really passed through:
        // idle (it WAS empty), then the add.
        let (events, _, _) = d.life_since(0);
        let pos = |k: &str| {
            events
                .iter()
                .position(|e| e["kind"] == k)
                .unwrap_or_else(|| panic!("no {k} event in {events:?}"))
        };
        assert!(
            pos("queue.idle") < pos("job.added"),
            "queue.idle announced over a runnable job: {events:?}"
        );
        assert!(
            !d.queue_idle_latch.load(Ordering::Relaxed),
            "the add must leave the latch re-armed"
        );
        // ...so B's own genuine departure still gets its edge.
        d.queue.lock_ok().clear();
        d.note_queue_idle();
        let (events, _, _) = d.life_since(0);
        let idles = events.iter().filter(|e| e["kind"] == "queue.idle").count();
        assert_eq!(idles, 2, "exactly one idle edge per transition: {events:?}");
    });
}

// -- the exit path closes the index -----------------------------------------

/// The wind-down must hand the index's write-ahead log back and close
/// the database.
///
/// SQLite deletes the -wal and -shm when the last connection closes, and
/// checkpoints on the way. The daemon never reached that: it leaves by
/// `process::exit` or `exec`, neither of which runs a destructor, so
/// every stop it has ever made left the whole log on disk. Measured on
/// the live daemon 14 Aug 2026 - SIGTERM, process gone, port free, and a
/// 28.1 GiB `index.db-wal` plus a 6.9 MiB `-shm` still sitting beside a
/// 39 GiB database, for the next start to recover.
///
/// The whole wind-down runs here, not just the index step, because the
/// wiring is half the fix: this ran to completion for a year without
/// touching the index at all.
#[cfg(feature = "indexer")]
#[test]
fn the_wind_down_hands_back_the_index_write_ahead_log() {
    with_daemon("windwal", |d| {
        d.index_enabled.store(true, Ordering::Relaxed);
        // Opened and written through the daemon's own accessor, so this
        // is the connection the exit has to find and close. Before the
        // runtime exists: `with_index` runs its SQLite work through
        // `block_in_place` when there is one.
        d.with_index(|ix| ix.kv_set("shutdown_probe", "written").ok())
            .expect("the index must open");
        let wal = d.index_db.with_extension("db-wal");
        let shm = d.index_db.with_extension("db-shm");
        assert!(
            wal.metadata().map(|m| m.len()).unwrap_or(0) > 0,
            "fixture left no write-ahead log - the assertions below would prove nothing"
        );

        let rt = tokio::runtime::Runtime::new().expect("runtime");
        wind_down(d, rt.handle(), "test wind-down");

        assert!(
            !wal.exists(),
            "the wind-down left {} behind - the index was never closed, so \
             the next start pays a recovery pass over the whole log",
            wal.display()
        );
        assert!(!shm.exists(), "the wind-down left {} behind", shm.display());
        // Closed, not merely emptied: what was in the log is in the
        // database file.
        let reopened = nzbkit::index::Index::open(&d.index_db).expect("reopen");
        assert_eq!(
            reopened.kv_get("shutdown_probe").as_deref(),
            Some("written"),
            "the checkpoint dropped the committed rows"
        );
        drop(reopened);
    });
}

/// ...and nothing reopens it behind the close. A status poll or an *arr
/// query arriving in the last moments of the wind-down would otherwise
/// lazily open a fresh connection, and the daemon would exit with a new
/// -wal and -shm on disk after all.
#[cfg(feature = "indexer")]
#[test]
fn an_exiting_daemon_does_not_reopen_the_index() {
    with_daemon("windreopen", |d| {
        d.index_enabled.store(true, Ordering::Relaxed);
        d.exiting.store(true, Ordering::Relaxed);

        assert!(
            d.with_index(|ix| ix.kv_get("anything")).is_none(),
            "an exiting daemon answered from the index instead of declining"
        );
        assert!(
            !d.index_db.exists(),
            "an exiting daemon created {} on its way out",
            d.index_db.display()
        );
    });
}

/// The watch-failed strip rides the revisioned queue payload, so every
/// mutation of the map must move `queue_rev` - an idle dashboard skips
/// the payload while `client_q == qrev`, and an entry removed without a
/// bump renders forever: its delete button answers "no such rejected
/// file" for a row the daemon dropped long ago (reported 14 Aug 2026;
/// the third instance of the payload-rider trap after the update banner
/// and set_limit). No-op mutations must NOT bump, or every 5 s watch
/// pass would re-send the payload to every idle tab.
#[test]
fn watch_failed_mutations_move_the_queue_rev() {
    with_daemon("wfrev", |d| {
        let dir = std::env::temp_dir().join(format!("nzbfast-wfrev-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let present = dir.join("present.nzb");
        std::fs::write(&present, b"x").unwrap();
        let gone = dir.join("gone.nzb");
        let rev = || d.queue_rev.load(Ordering::Relaxed);
        let val = |s: &str| (1u64, 2u64, s.to_string(), String::new());

        let r0 = rev();
        assert!(d.watch_failed_insert(present.clone(), val("truncated")));
        assert_eq!(rev(), r0 + 1, "a fresh insert must bump");
        assert!(
            !d.watch_failed_insert(present.clone(), val("truncated")),
            "re-inserting the identical row is the every-pass no-op"
        );
        assert_eq!(rev(), r0 + 1, "the no-op re-insert must not bump");
        assert!(d.watch_failed_insert(present.clone(), val("kept")));
        assert_eq!(rev(), r0 + 2, "a changed value must bump");

        d.watch_failed_remove(&gone);
        assert_eq!(rev(), r0 + 2, "removing an absent row must not bump");
        d.watch_failed_remove(&present);
        assert_eq!(rev(), r0 + 3, "a real removal must bump");

        d.watch_failed_insert(present.clone(), val("truncated"));
        d.watch_failed_insert(gone.clone(), val("truncated"));
        let r1 = rev();
        d.watch_failed_prune_missing();
        assert_eq!(rev(), r1 + 1, "pruning a vanished file must bump");
        assert!(
            d.watch_failed.lock_ok().contains_key(&present),
            "pruning must keep entries whose file is still on disk"
        );
        d.watch_failed_prune_missing();
        assert_eq!(rev(), r1 + 1, "an empty prune must not bump");
        let _ = std::fs::remove_dir_all(&dir);
    });
}

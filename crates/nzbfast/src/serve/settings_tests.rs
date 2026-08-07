//! Unit tests for `serve::settings` (§106 phase 3): the pure shaping
//! helpers, the settings-table invariants, and the `set_*` validators
//! driven against the in-memory Daemon fixture. No sockets, no network.

use super::super::testutil::test_daemon;
use super::*;

/// House temp-dir pattern, with Drop cleanup so a failing assertion
/// still removes the directory.
struct TmpDir(PathBuf);

impl TmpDir {
    fn new(name: &str) -> TmpDir {
        let p = std::env::temp_dir().join(format!("nzbfast-set-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        TmpDir(p)
    }
}

impl Drop for TmpDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn daemon_in(name: &str) -> (TmpDir, Arc<Daemon>) {
    let t = TmpDir::new(name);
    let d = test_daemon(&t.0);
    (t, d)
}

// ---- annotate_patterns -------------------------------------------------

#[test]
fn annotate_patterns_leaves_non_arrays_alone() {
    let obj = json!({"match": "("});
    assert_eq!(annotate_patterns(obj.clone()), obj);
    assert_eq!(annotate_patterns(json!("plain")), json!("plain"));
    assert_eq!(annotate_patterns(Value::Null), Value::Null);
}

#[test]
fn annotate_patterns_flags_only_bad_rules() {
    let out = annotate_patterns(json!([
        {"match": "foo", "not_match": "bar"},
        {"match": "(", "not_match": ".*"},
        {"match": 7},
        {},
        "not an object",
    ]));
    let out = out.as_array().unwrap();
    // Ok verdicts are omitted entirely, so a clean rule is untouched.
    assert_eq!(out[0], json!({"match": "foo", "not_match": "bar"}));
    assert_eq!(out[1]["match_verdict"], json!("literal"));
    assert_eq!(out[1]["not_verdict"], json!("matches_everything"));
    // Non-string and missing patterns are treated as "", which is Ok.
    assert!(out[2].get("match_verdict").is_none());
    assert!(out[2].get("not_verdict").is_none());
    assert_eq!(out[3], json!({}));
    // A non-object entry passes through unchanged.
    assert_eq!(out[4], json!("not an object"));
}

// ---- rules_save_warning ------------------------------------------------

/// #18 save-time warning: fires only for the two rules settings, only on
/// patterns that will not compile, and never panics on the shapes the
/// API can hand it (empty clear, malformed JSON that apply already
/// rejected, non-object entries).
#[test]
fn rules_save_warning_names_the_rule_and_carries_the_engine_error() {
    let rules = r#"[{"name":"animes","match":"*anime*"},{"match":"1080p","not_match":"[a-"}]"#;
    let w = rules_save_warning("smart_folders", rules).expect("must warn");
    assert!(w.contains("\"animes\"") && w.contains("*anime*"), "{w}");
    assert!(w.contains("rule 2") && w.contains("[a-"), "{w}");
    assert!(
        w.contains("repetition"),
        "the engine's reason must ride along: {w}"
    );

    // Valid-but-dangerous compiles say nothing at save time; the row
    // annotation carries those (a deliberate last-rule catch-all would
    // otherwise toast on every re-save).
    assert_eq!(
        rules_save_warning("smart_folders", r#"[{"match":".*"}]"#),
        None
    );
    assert_eq!(
        rules_save_warning("smart_folders", r#"[{"match":"!*"}]"#),
        None
    );
    // Only the two rules settings are judged, and junk never panics.
    assert_eq!(rules_save_warning("watchlist", rules), None);
    assert_eq!(rules_save_warning("smart_folders", ""), None);
    assert_eq!(rules_save_warning("smart_folders", "not json"), None);
    assert_eq!(
        rules_save_warning("smart_folders", r#"["not an object", 7]"#),
        None
    );
    // The custom-category editor rides the same engine.
    let cats = r#"[{"slug":"a","name":"Anime","match":"*anime*","base":"tv"}]"#;
    let w = rules_save_warning("custom_categories", cats).expect("cats must warn");
    assert!(w.contains("\"Anime\""), "{w}");
}

// ---- shape_only / path_str ---------------------------------------------

#[test]
fn shape_only_counts_chars_not_bytes() {
    assert_eq!(shape_only(""), "(empty)");
    assert_eq!(shape_only("abc"), "(3 chars, not logged)");
    // 4 chars but 5 bytes: the count must be characters.
    assert_eq!(shape_only("über"), "(4 chars, not logged)");
}

#[test]
fn path_str_maps_none_to_empty() {
    assert_eq!(path_str(&None), "");
    assert_eq!(path_str(&Some(PathBuf::from("/a/b"))), "/a/b");
}

// ---- the settings table -------------------------------------------------

#[test]
fn settings_table_names_are_unique_and_nonempty() {
    let mut seen = std::collections::HashSet::new();
    for s in settings() {
        assert!(!s.name.is_empty(), "a settings row has an empty name");
        assert!(seen.insert(s.name), "duplicate settings row {:?}", s.name);
    }
    assert!(setting("history_rows").is_some());
    assert!(setting("no_such_setting_ever").is_none());
}

// ---- numeric validators -------------------------------------------------

#[test]
fn set_index_gapfill_validates_and_stores() {
    let (_t, d) = daemon_in("gapfill");
    d.index_gapfill.store(7, Ordering::Relaxed);
    let e = set_index_gapfill(&d, "index_gapfill", "x").unwrap_err();
    assert!(e.contains("not a number"), "{e}");
    let e = set_index_gapfill(&d, "index_gapfill", "101").unwrap_err();
    assert!(e.contains("0-100"), "{e}");
    assert_eq!(d.index_gapfill.load(Ordering::Relaxed), 7);
    assert_eq!(
        set_index_gapfill(&d, "index_gapfill", "50").unwrap(),
        (true, json!(50))
    );
    assert_eq!(d.index_gapfill.load(Ordering::Relaxed), 50);
}

#[test]
fn set_bench_interval_validates_and_stores() {
    let (_t, d) = daemon_in("bench");
    d.bench_interval.store(3, Ordering::Relaxed);
    let e = set_bench_interval(&d, "bench_interval", "x").unwrap_err();
    assert!(e.contains("not a number"), "{e}");
    let e = set_bench_interval(&d, "bench_interval", "721").unwrap_err();
    assert!(e.contains("0-720"), "{e}");
    assert_eq!(d.bench_interval.load(Ordering::Relaxed), 3);
    assert_eq!(
        set_bench_interval(&d, "bench_interval", "12").unwrap(),
        (true, json!(12))
    );
    assert_eq!(d.bench_interval.load(Ordering::Relaxed), 12);
}

#[test]
fn set_history_rows_rejects_out_of_range() {
    let (_t, d) = daemon_in("histrows");
    d.history_rows.store(30, Ordering::Relaxed);
    for bad in ["0", "201"] {
        let e = set_history_rows(&d, "history_rows", bad).unwrap_err();
        assert!(e.contains("1-200"), "{e}");
    }
    assert_eq!(d.history_rows.load(Ordering::Relaxed), 30);
    assert_eq!(
        set_history_rows(&d, "history_rows", "25").unwrap(),
        (true, json!(25))
    );
    assert_eq!(d.history_rows.load(Ordering::Relaxed), 25);
}

#[test]
fn set_out_umask_octal_range_and_empty_clear() {
    let (_t, d) = daemon_in("umask");
    d.out_umask.store(0o11, Ordering::Relaxed);
    for bad in ["9x", "1777"] {
        let e = set_out_umask(&d, "out_umask", bad).unwrap_err();
        assert!(e.contains("octal"), "{e}");
    }
    assert_eq!(d.out_umask.load(Ordering::Relaxed), 0o11);
    // Empty is the documented way back to "process umask": u32::MAX.
    assert_eq!(
        set_out_umask(&d, "out_umask", "").unwrap(),
        (true, json!(""))
    );
    assert_eq!(d.out_umask.load(Ordering::Relaxed), u32::MAX);
    assert_eq!(
        set_out_umask(&d, "out_umask", "022").unwrap(),
        (true, json!("022"))
    );
    assert_eq!(d.out_umask.load(Ordering::Relaxed), 0o22);
}

#[test]
fn set_spot_backfill_rejects_and_clamps() {
    let (_t, d) = daemon_in("spotbf");
    d.spot_backfill.store(5_000, Ordering::Relaxed);
    let e = set_spot_backfill(&d, "spot_backfill", "x").unwrap_err();
    assert!(e.contains("expected a number"), "{e}");
    assert_eq!(d.spot_backfill.load(Ordering::Relaxed), 5_000);
    assert_eq!(
        set_spot_backfill(&d, "spot_backfill", "10").unwrap(),
        (true, json!(1_000))
    );
    assert_eq!(
        set_spot_backfill(&d, "spot_backfill", "9999999").unwrap(),
        (true, json!(1_000_000))
    );
    assert_eq!(
        set_spot_backfill(&d, "spot_backfill", "50000").unwrap(),
        (true, json!(50_000))
    );
    assert_eq!(d.spot_backfill.load(Ordering::Relaxed), 50_000);
}

// ---- word-list validators -----------------------------------------------

#[test]
fn set_verify_mode_moves_the_flag_pair() {
    let (_t, d) = daemon_in("verify");
    d.fast_verify.store(true, Ordering::Relaxed);
    d.verify_lean.store(true, Ordering::Relaxed);
    let e = set_verify_mode(&d, "verify_mode", "warp").unwrap_err();
    assert!(e.contains("full, fast, or lean"), "{e}");
    assert!(d.fast_verify.load(Ordering::Relaxed));
    assert!(d.verify_lean.load(Ordering::Relaxed));
    for (mode, fast, lean) in [
        ("full", false, false),
        ("fast", true, false),
        ("lean", true, true),
    ] {
        assert_eq!(
            set_verify_mode(&d, "verify_mode", mode).unwrap(),
            (true, json!(mode))
        );
        assert_eq!(d.fast_verify.load(Ordering::Relaxed), fast, "{mode}");
        assert_eq!(d.verify_lean.load(Ordering::Relaxed), lean, "{mode}");
    }
    // The echo is the trimmed word.
    assert_eq!(
        set_verify_mode(&d, "verify_mode", " fast ").unwrap(),
        (true, json!("fast"))
    );
}

#[test]
fn set_quota_period_accepts_both_cases() {
    let (_t, d) = daemon_in("quotap");
    d.quota_period.store(b'd', Ordering::Relaxed);
    let e = set_quota_period(&d, "quota_period", "w").unwrap_err();
    assert!(e.contains("d or m"), "{e}");
    assert_eq!(d.quota_period.load(Ordering::Relaxed), b'd');
    assert_eq!(
        set_quota_period(&d, "quota_period", "M").unwrap(),
        (true, json!("m"))
    );
    assert_eq!(d.quota_period.load(Ordering::Relaxed), b'm');
    assert_eq!(
        set_quota_period(&d, "quota_period", "d").unwrap(),
        (true, json!("d"))
    );
    assert_eq!(d.quota_period.load(Ordering::Relaxed), b'd');
}

#[test]
fn set_password_prompt_lowercases_and_rejects() {
    let (_t, d) = daemon_in("pwprompt");
    *d.password_prompt.lock_ok() = "done".to_string();
    let e = set_password_prompt(&d, "password_prompt", "sometimes").unwrap_err();
    assert!(e.contains("now, done or never"), "{e}");
    assert_eq!(*d.password_prompt.lock_ok(), "done");
    assert_eq!(
        set_password_prompt(&d, "password_prompt", "NOW").unwrap(),
        (true, json!("now"))
    );
    assert_eq!(*d.password_prompt.lock_ok(), "now");
}

#[test]
fn set_failure_link_word_list() {
    let (_t, d) = daemon_in("faillink");
    *d.failure_link.lock_ok() = "off".to_string();
    let e = set_failure_link(&d, "failure_link", "bogus").unwrap_err();
    assert!(e.contains("off, report or regrab"), "{e}");
    assert_eq!(*d.failure_link.lock_ok(), "off");
    assert_eq!(
        set_failure_link(&d, "failure_link", "regrab").unwrap(),
        (true, json!("regrab"))
    );
    assert_eq!(*d.failure_link.lock_ok(), "regrab");
}

#[test]
fn set_update_url_requires_http_or_empty() {
    let (_t, d) = daemon_in("updurl");
    *d.update_url.lock_ok() = "https://known.invalid/u.json".to_string();
    let e = set_update_url(&d, "update_url", "ftp://mirror").unwrap_err();
    assert!(e.contains("http(s)"), "{e}");
    assert_eq!(*d.update_url.lock_ok(), "https://known.invalid/u.json");
    assert_eq!(
        set_update_url(&d, "update_url", "https://example.invalid/m.json").unwrap(),
        (true, json!("https://example.invalid/m.json"))
    );
    assert_eq!(*d.update_url.lock_ok(), "https://example.invalid/m.json");
    // Empty disables checks and is allowed.
    assert_eq!(
        set_update_url(&d, "update_url", "").unwrap(),
        (true, json!(""))
    );
    assert_eq!(*d.update_url.lock_ok(), "");
}

#[test]
fn set_predb_server_shape_checks_and_default_fallback() {
    let (_t, d) = daemon_in("predbsrv");
    assert_eq!(
        set_predb_server(&d, "predb_server", "irc.example.net:7000").unwrap(),
        (true, json!("irc.example.net:7000"))
    );
    let e = set_predb_server(&d, "predb_server", "bad host").unwrap_err();
    assert!(e.contains("host or host:port"), "{e}");
    let e = set_predb_server(&d, "predb_server", "host:xx").unwrap_err();
    assert!(e.contains("port number"), "{e}");
    assert_eq!(*d.predb_server.lock_ok(), "irc.example.net:7000");
    // Empty falls back to the built-in default host.
    let (live, echo) = set_predb_server(&d, "predb_server", "").unwrap();
    assert!(live);
    assert_eq!(echo, json!(nzbkit::predb::DEFAULT_HOST));
    assert_eq!(*d.predb_server.lock_ok(), nzbkit::predb::DEFAULT_HOST);
}

#[test]
fn set_ui_locale_membership_and_empty_auto() {
    let (_t, d) = daemon_in("uilocale");
    *d.ui_locale.lock_ok() = "en".to_string();
    let e = set_ui_locale(&d, "ui_locale", "xx").unwrap_err();
    assert!(e.contains("ui_locale: one of"), "{e}");
    assert_eq!(*d.ui_locale.lock_ok(), "en");
    assert_eq!(
        set_ui_locale(&d, "ui_locale", "DE").unwrap(),
        (true, json!("de"))
    );
    assert_eq!(*d.ui_locale.lock_ok(), "de");
    assert_eq!(
        set_ui_locale(&d, "ui_locale", "").unwrap(),
        (true, json!(""))
    );
    assert_eq!(*d.ui_locale.lock_ok(), "");
}

#[cfg(feature = "indexer")]
#[test]
fn set_index_evict_order_membership() {
    let (_t, d) = daemon_in("evictord");
    *d.index_evict_order.lock_ok() = "ladder".to_string();
    let e = set_index_evict_order(&d, "index_evict_order", "sideways").unwrap_err();
    assert!(e.contains("index_evict_order"), "{e}");
    assert_eq!(*d.index_evict_order.lock_ok(), "ladder");
    assert_eq!(
        set_index_evict_order(&d, "index_evict_order", "Oldest").unwrap(),
        (true, json!("oldest"))
    );
    assert_eq!(*d.index_evict_order.lock_ok(), "oldest");
}

#[cfg(feature = "indexer")]
#[test]
fn set_index_evict_kinds_validates_and_dedups() {
    let (_t, d) = daemon_in("evictkinds");
    let e = set_index_evict_kinds(&d, "index_evict_kinds", "movie,junk").unwrap_err();
    assert!(e.contains("unknown kind"), "{e}");
    assert_eq!(
        set_index_evict_kinds(&d, "index_evict_kinds", "Movie, tv, movie").unwrap(),
        (true, json!(["movie", "tv"]))
    );
    assert_eq!(*d.index_evict_kinds.lock_ok(), vec!["movie", "tv"]);
}

// ---- JSON-blob validators -----------------------------------------------

#[test]
fn set_custom_categories_rejects_bad_json_and_bad_slugs() {
    let (_t, d) = daemon_in("customcats");
    let e = set_custom_categories(&d, "custom_categories", "not json").unwrap_err();
    assert!(e.contains("custom_categories:"), "{e}");
    // Valid JSON but a slug validate() refuses (uppercase).
    let e = set_custom_categories(&d, "custom_categories", r#"[{"slug":"TV","match":"x"}]"#)
        .unwrap_err();
    assert!(e.contains("custom_categories:"), "{e}");
    assert!(d.custom_categories.read_ok().is_empty());
    d.reclassify_pending.store(false, Ordering::Relaxed);
    let (live, _) = set_custom_categories(
        &d,
        "custom_categories",
        r#"[{"slug":"anime","match":"anime"}]"#,
    )
    .unwrap();
    assert!(live);
    assert_eq!(d.custom_categories.read_ok().len(), 1);
    assert!(d.reclassify_pending.load(Ordering::Relaxed));
}

#[test]
fn set_prefer_quality_rejects_unknown_values() {
    let (_t, d) = daemon_in("prefq");
    let e = set_prefer_quality(&d, "prefer_quality", r#"{"res":"999p"}"#).unwrap_err();
    assert!(e.contains("prefer_quality:"), "{e}");
    assert_eq!(d.quality_prefs.lock_ok().res, "");
    let (live, echo) =
        set_prefer_quality(&d, "prefer_quality", r#"{"res":"1080p","vcodec":"x265"}"#).unwrap();
    assert!(live);
    assert_eq!(echo["res"], json!("1080p"));
    assert_eq!(d.quality_prefs.lock_ok().res, "1080p");
    assert_eq!(d.quality_prefs.lock_ok().vcodec, "x265");
}

#[test]
fn set_arr_instances_validates_kind_and_url() {
    let (_t, d) = daemon_in("arrinst");
    let e = set_arr_instances(&d, "arr_instances", "not json").unwrap_err();
    assert!(e.contains("arr_instances:"), "{e}");
    let e = set_arr_instances(
        &d,
        "arr_instances",
        r#"[{"name":"a","kind":"lidarr","url":"http://x","apikey":"k"}]"#,
    )
    .unwrap_err();
    assert!(e.contains("sonarr or radarr"), "{e}");
    let e = set_arr_instances(
        &d,
        "arr_instances",
        r#"[{"name":"a","kind":"sonarr","url":"example.com","apikey":"k"}]"#,
    )
    .unwrap_err();
    assert!(e.contains("http"), "{e}");
    assert!(d.arr_instances.lock_ok().is_empty());
    let good = r#"[{"name":"a","kind":"sonarr","url":"http://localhost:8989","apikey":"k"}]"#;
    let (live, _) = set_arr_instances(&d, "arr_instances", good).unwrap();
    assert!(live);
    assert_eq!(d.arr_instances.lock_ok().len(), 1);
    // A blank apikey on a round-trip keeps the stored key.
    let blanked = r#"[{"name":"a","kind":"sonarr","url":"http://localhost:8989","apikey":""}]"#;
    set_arr_instances(&d, "arr_instances", blanked).unwrap();
    assert_eq!(d.arr_instances.lock_ok()[0].apikey, "k");
}

#[test]
fn json_list_setters_reject_bad_json() {
    let (_t, d) = daemon_in("jsonlists");
    let e = set_feeds(&d, "feeds", "{bad").unwrap_err();
    assert!(e.contains("feeds:"), "{e}");
    let e = set_watchlist(&d, "watchlist", "[{").unwrap_err();
    assert!(e.contains("watchlist:"), "{e}");
    let e = set_smart_folders(&d, "smart_folders", "nope").unwrap_err();
    assert!(e.contains("smart_folders:"), "{e}");
}

#[test]
fn set_categories_keeps_the_builtin_floor() {
    let (_t, d) = daemon_in("cats");
    let (live, echo) = set_categories(&d, "categories", "Anime, *, , tv").unwrap();
    assert!(live);
    let cats = d.cats.lock_ok().clone();
    for c in DEFAULT_CATS {
        assert!(cats.contains(*c), "builtin {c} was dropped");
    }
    assert!(cats.contains("Anime"));
    // The echo is the display list, which hides the "*" wildcard.
    assert_eq!(echo, json!(d.cat_list()));
    assert!(!d.cat_list().contains('*'));
    // All-dots names cannot survive sanitising as themselves: they come
    // back as the "unnamed" placeholder rather than an error or a
    // path-escaping component.
    set_categories(&d, "categories", "...").unwrap();
    assert!(d.cats.lock_ok().contains("unnamed"));
}

// ---- clamp behaviors ----------------------------------------------------

#[test]
fn set_watch_interval_secs_clamps_1_to_3600() {
    let (_t, d) = daemon_in("watchint");
    assert_eq!(
        set_watch_interval_secs(&d, "watch_interval_secs", "0").unwrap(),
        (true, json!(1))
    );
    assert_eq!(d.watch_interval_secs.load(Ordering::Relaxed), 1);
    assert_eq!(
        set_watch_interval_secs(&d, "watch_interval_secs", "99999").unwrap(),
        (true, json!(3600))
    );
    assert_eq!(d.watch_interval_secs.load(Ordering::Relaxed), 3600);
}

#[test]
fn set_watchlist_instant_max_caps_at_3600() {
    let (_t, d) = daemon_in("instmax");
    assert_eq!(
        set_watchlist_instant_max(&d, "watchlist_instant_max", "5000").unwrap(),
        (true, json!(3600))
    );
    assert_eq!(d.watchlist_instant_max.load(Ordering::Relaxed), 3600);
    assert_eq!(
        set_watchlist_instant_max(&d, "watchlist_instant_max", "7").unwrap(),
        (true, json!(7))
    );
    assert_eq!(d.watchlist_instant_max.load(Ordering::Relaxed), 7);
}

#[test]
fn set_arr_giveup_threshold_caps_at_1000() {
    let (_t, d) = daemon_in("giveupthr");
    let e = set_arr_giveup_threshold(&d, "arr_giveup_threshold", "x").unwrap_err();
    assert!(e.contains("not a number"), "{e}");
    assert_eq!(
        set_arr_giveup_threshold(&d, "arr_giveup_threshold", "5000").unwrap(),
        (true, json!(1000))
    );
    assert_eq!(d.arr_giveup_threshold.load(Ordering::Relaxed), 1000);
}

#[test]
fn set_index_tip_secs_zero_off_else_floor_5() {
    let (_t, d) = daemon_in("tipsecs");
    assert_eq!(
        set_index_tip_secs(&d, "index_tip_secs", "0").unwrap(),
        (true, json!(0))
    );
    assert_eq!(d.index_tip_secs.load(Ordering::Relaxed), 0);
    assert_eq!(
        set_index_tip_secs(&d, "index_tip_secs", "3").unwrap(),
        (true, json!(5))
    );
    assert_eq!(d.index_tip_secs.load(Ordering::Relaxed), 5);
    assert_eq!(
        set_index_tip_secs(&d, "index_tip_secs", "60").unwrap(),
        (true, json!(60))
    );
    assert_eq!(d.index_tip_secs.load(Ordering::Relaxed), 60);
}

// ---- apply_setting end to end -------------------------------------------

#[test]
fn apply_setting_tells_unknown_from_read_only() {
    let (_t, d) = daemon_in("applymisc");
    let e = apply_setting(&d, "no_such_thing", "1").unwrap_err();
    assert!(e.contains("unsupported config item"), "{e}");
    let e = apply_setting(&d, "config_path", "/x").unwrap_err();
    assert!(e.contains("is read-only"), "{e}");
    // And a plain arm still routes through: history_rows lands live.
    assert_eq!(
        apply_setting(&d, "history_rows", "42").unwrap(),
        (true, json!(42))
    );
    assert_eq!(d.history_rows.load(Ordering::Relaxed), 42);
}

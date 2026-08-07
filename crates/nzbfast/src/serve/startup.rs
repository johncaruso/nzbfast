//! Everything serve() does before and around the bind: restoring the
//! persisted runtime state, seeding the Daemon's settings-backed fields,
//! taking the listener, the single-instance lock, the core task spawns
//! and the ready banner.
//!
//! The startup CALL ORDER is load-bearing (first_run_apikey before the
//! bind, the bind before the banner) - these functions were lifted out of
//! serve() without reordering anything, and must stay that way.
//!
//! Split out of serve/mod.rs by TODO 106 phase 4 - the code is verbatim,
//! only visibility changed.

use super::*;

pub(super) fn restore_runtime_state(
    daemon: &Arc<Daemon>,
    settings_path: &Path,
    _spool: &Path,
    _config: &Path,
    speedlimit: &Option<String>,
) -> Result<()> {
    // Bring back the job records a previous run persisted (Downloading
    // reverts to Queued inside load_queue - the download restarts and its
    // journal skips what already landed).
    daemon.load_queue();

    // M23 Smart Folders + cleanup rules: UI-managed live settings that
    // exist only in settings.json (no CLI flag), parsed here because
    // they need the daemon to exist.
    {
        let saved = load_settings(settings_path);
        if let Some(v) = saved.get("smart_folders") {
            match serde_json::from_value::<Vec<crate::smart::Rule>>(v.clone()) {
                Ok(list) => *daemon.smart_folders.lock_ok() = list,
                Err(e) => warn!(target: "smart", "ignoring saved smart_folders: {e}"),
            }
        }
        if let Some(v) = saved.get("cleanup_exts") {
            match serde_json::from_value::<Vec<String>>(v.clone()) {
                Ok(list) => *daemon.cleanup_exts.lock_ok() = list,
                Err(e) => warn!(target: "cleanup", "ignoring saved cleanup_exts: {e}"),
            }
        }
        // SAB/NZBGet-parity passwords file. A saved path (adopted from a
        // competitor import, or user-set) wins; empty/absent = the
        // default next to the config.
        if let Some(p) = saved
            .get("password_file")
            .and_then(Value::as_str)
            .filter(|p| !p.trim().is_empty())
        {
            *daemon.password_file.lock_ok() = PathBuf::from(p.trim());
        }
        // One-shot migration: the short-lived `unpack_passwords` LIST
        // setting (shipped and replaced the same day) seeds the file,
        // but never overwrites one that already has content - the file
        // is the operator's now.
        if let Some(list) = saved
            .get("unpack_passwords")
            .and_then(|v| serde_json::from_value::<Vec<String>>(v.clone()).ok())
            .filter(|l| !l.is_empty())
        {
            let path = daemon.password_file.lock_ok().clone();
            if !path.exists() {
                let body = list.join("\n") + "\n";
                if let Err(e) = crate::persist::write_atomic(&path, body.as_bytes()) {
                    warn!(target: "unlock", "could not migrate unpack_passwords to {}: {e}", path.display());
                } else {
                    info!(target: "unlock", "moved {} saved password(s) into {}", list.len(), path.display());
                }
            }
        }
        // Make sure the file exists so "where do passwords go" has one
        // answer: the path the settings page shows. 0600 like every
        // credential-bearing file (write_atomic's mode).
        {
            let path = daemon.password_file.lock_ok().clone();
            if !path.exists()
                && let Err(e) = crate::persist::write_atomic(&path, b"")
            {
                warn!(target: "unlock", "could not create {}: {e}", path.display());
            }
            // Mirror for the in-stream probe (it holds a hub, not the
            // daemon).
            *daemon.hub.unpack_password_file.lock_ok() = Some(path);
        }
        if let Some(m) = saved.get("password_prompt").and_then(Value::as_str)
            && matches!(m, "now" | "done" | "never")
        {
            *daemon.password_prompt.lock_ok() = m.to_string();
        }
        // TODO 101: the mode is read by the unpack ladder through
        // `eatvol`, so mirror it whether it was saved or defaulted -
        // same shape as fast_par below. Nothing is ever eaten under the
        // "off" default, so a mirror of the default is a no-op that
        // keeps the two stores from drifting.
        if let Some(m) = saved
            .get("unpack_eat_volumes")
            .and_then(Value::as_str)
            .and_then(crate::eatvol::EatMode::parse)
        {
            *daemon.unpack_eat_volumes.lock_ok() = m.as_str().to_string();
        }
        crate::eatvol::set_mode(
            crate::eatvol::EatMode::parse(&daemon.unpack_eat_volumes.lock_ok().clone())
                .unwrap_or_default(),
        );
        if let Some(on) = saved.get("par_cleanup").and_then(Value::as_bool) {
            daemon.par_cleanup.store(on, Ordering::Relaxed);
        }
        if let Some(on) = saved.get("watch_keep_nzb").and_then(Value::as_bool) {
            daemon.watch_keep_nzb.store(on, Ordering::Relaxed);
        }
        if let Some(on) = saved.get("fast_par").and_then(Value::as_bool) {
            daemon.fast_par.store(on, Ordering::Relaxed);
        }
        // Mirror into the repair library whether saved or defaulted
        // (NZBFAST_NTT in the environment still overrides it there).
        nzbkit::par2repair::set_fast_par_enabled(daemon.fast_par.load(Ordering::Relaxed));
        if let Some(on) = saved.get("prefer_external_unrar").and_then(Value::as_bool) {
            daemon.prefer_external_unrar.store(on, Ordering::Relaxed);
        }
        // Same shape as fast_par: mirrored whether saved or defaulted
        // (NZBFAST_NO_NATIVE_UNRAR in the environment still forces it on
        // inside nzbkit).
        nzbkit::extract::set_prefer_external_unrar(
            daemon.prefer_external_unrar.load(Ordering::Relaxed),
        );
        // TODO 24D user categories: validated on save, but re-validated
        // here so a hand-edited settings.json can't smuggle a reserved
        // or duplicate slug into the classifier.
        if let Some(v) = saved.get("custom_categories") {
            match serde_json::from_value::<Vec<nzbkit::categories::CustomCategory>>(v.clone()) {
                Ok(mut list) => {
                    // A slug that only became reserved in a LATER release
                    // must not cost the user every OTHER category they set
                    // up: validation rejects the list as a whole, and the
                    // Err arm below discards all of it.
                    let renamed = nzbkit::categories::migrate_reserved_slugs(&mut list);
                    for (from, to) in &renamed {
                        info!(
                            target: "cats",
                            "category slug {from:?} is now a built-in kind - renamed \
                             to {to:?} so your other categories still load"
                        );
                    }
                    if !renamed.is_empty() {
                        save_settings(settings_path, &[("custom_categories", json!(&list))]);
                    }
                    match nzbkit::categories::validate(&list) {
                        Ok(()) => *daemon.custom_categories.write_ok() = list,
                        Err(e) => warn!(target: "cats", "ignoring saved custom_categories: {e}"),
                    }
                }
                Err(e) => warn!(target: "cats", "ignoring saved custom_categories: {e}"),
            }
        }
        // What the user asked the indexer to look for, and how much of
        // that has already been turned into scanned groups. Both are
        // read here rather than applied: applying needs the provider's
        // group list, which the startup path below fetches.
        if let Some(v) = saved.get("index_interests").and_then(Value::as_str) {
            *daemon.index_interests.lock_ok() = crate::interests::parse(v).join(",");
        }
        if let Some(v) = saved.get("index_interests_applied").and_then(Value::as_str) {
            *daemon.index_interests_applied.lock_ok() = v.to_string();
        }
        match saved.get("index_interest_groups") {
            Some(v) => {
                if let Ok(groups) = serde_json::from_value::<Vec<String>>(v.clone()) {
                    *daemon.index_interest_groups.lock_ok() = groups;
                }
            }
            // No provenance recorded: this install predates the key. Without
            // a backfill, `owned` stays empty forever, `reconcile` finds
            // nothing removable, and unticking a preset silently removes
            // NOTHING. It does not self-heal either - re-ticking skips a
            // group that is already present, so it never enters next_owned
            // and the next untick fails the same way. The only escape was
            // hand-editing index_groups.
            //
            // Reconstruct it the only honest way available: the groups the
            // applied presets resolve to, intersected with what is actually
            // being indexed. A group the user added by hand is therefore
            // never claimed as preset-owned, which is the direction that
            // errs toward keeping their groups rather than deleting them.
            None => {
                let applied = daemon.index_interests_applied.lock_ok().clone();
                let keys = crate::interests::parse(&applied);
                if !keys.is_empty() {
                    let have = daemon.index_groups.lock_ok().clone();
                    let owned = crate::interests::backfill_owned(&keys, &have);
                    if !owned.is_empty() {
                        info!(
                            target: "interests",
                            "recorded {} preset-owned group(s) for an install \
                             that predates provenance tracking",
                            owned.len()
                        );
                        save_settings(settings_path, &[("index_interest_groups", json!(&owned))]);
                        *daemon.index_interest_groups.lock_ok() = owned;
                    }
                }
            }
        }
        if let Some(v) = saved.get("failure_link").and_then(Value::as_str)
            && matches!(v, "off" | "report" | "regrab")
        {
            *daemon.failure_link.lock_ok() = v.to_string();
        }
        if let Some(v) = saved.get("notify_targets") {
            match serde_json::from_value::<Vec<crate::notify::Target>>(v.clone()) {
                Ok(list) => *daemon.notify_targets.lock_ok() = list,
                Err(e) => warn!(target: "notify", "ignoring saved notify_targets: {e}"),
            }
        }
        // §96.3 give-up breaker: the threshold, the *arr instances it may
        // act on, and the counters a previous run accumulated.
        if let Some(n) = saved.get("arr_giveup_threshold").and_then(Value::as_u64) {
            daemon.arr_giveup_threshold.store(n, Ordering::Relaxed);
        }
        if let Some(v) = saved.get("arr_instances") {
            match serde_json::from_value::<Vec<giveup::ArrInstance>>(v.clone()) {
                Ok(list) => *daemon.arr_instances.lock_ok() = list,
                Err(e) => warn!(target: "giveup", "ignoring saved arr_instances: {e}"),
            }
        }
        let giveup_path = daemon.spool.join("giveup-state.json");
        if let Some(v) = crate::persist::load_json_with_backup(&giveup_path) {
            match serde_json::from_value(v) {
                Ok(s) => *daemon.giveup.lock_ok() = s,
                Err(e) => warn!(target: "giveup", "ignoring {}: {e}", giveup_path.display()),
            }
        }
        // The kept-files notices outlive the process on purpose: each one
        // names a folder whose history row is gone, so losing them at a
        // restart leaves the payload on disk with nothing anywhere
        // pointing at it. See `Daemon::save_delete_kept`.
        let kept_path = daemon.spool.join("delete-kept.json");
        if let Some(v) = crate::persist::load_json_with_backup(&kept_path) {
            match serde_json::from_value(v) {
                Ok(k) => *daemon.delete_kept.lock_ok() = k,
                Err(e) => warn!(target: "queue", "ignoring {}: {e}", kept_path.display()),
            }
        }
        if let Some(v) = saved.get("ui_locale").and_then(Value::as_str) {
            *daemon.ui_locale.lock_ok() = v.to_string();
        }
        if let Some(v) = saved.get("wall_hide_adult").and_then(Value::as_bool) {
            daemon.wall_hide_adult.store(v, Ordering::Relaxed);
        }
        if let Some(v) = saved.get("auto_connections").and_then(Value::as_bool) {
            daemon.auto_connections.store(v, Ordering::Relaxed);
        }
        if let Some(v) = saved.get("auto_defer").and_then(Value::as_bool) {
            daemon.auto_defer.store(v, Ordering::Relaxed);
        }
        if let Some(v) = saved.get("post_health").and_then(Value::as_bool) {
            daemon.post_health.store(v, Ordering::Relaxed);
        }
        if let Some(v) = saved.get("post_health_defer").and_then(Value::as_bool) {
            daemon.post_health_defer.store(v, Ordering::Relaxed);
        }
        if let Some(v) = saved.get("auto_prefetch").and_then(Value::as_bool) {
            daemon.auto_prefetch.store(v, Ordering::Relaxed);
        }
        if let Some(v) = saved.get("oracle_route").and_then(Value::as_bool) {
            daemon.oracle_route.store(v, Ordering::Relaxed);
        }
        for (key, field) in [
            ("race_stragglers", &daemon.race_stragglers),
            ("adaptive_timeouts", &daemon.adaptive_timeouts),
            ("auto_rename", &daemon.auto_rename),
            ("identity_lookup", &daemon.identity_lookup),
            ("rename_resolution", &daemon.rename_resolution),
            ("rename_vcodec", &daemon.rename_vcodec),
            ("rename_acodec", &daemon.rename_acodec),
            ("rename_source", &daemon.rename_source),
            ("rename_group", &daemon.rename_group),
            ("rename_year_parens", &daemon.rename_year_parens),
            ("rename_quality_brackets", &daemon.rename_quality_brackets),
            ("rename_extra_words", &daemon.rename_extra_words),
            ("rename_identify", &daemon.rename_identify),
            ("rename_episode_titles", &daemon.rename_episode_titles),
            ("history_color_names", &daemon.history_color_names),
            ("media_chip_color", &daemon.media_chip_color),
            ("shape_chip_color", &daemon.shape_chip_color),
            ("rename_junk", &daemon.rename_junk),
            ("rename_media_only", &daemon.rename_media_only),
        ] {
            if let Some(v) = saved.get(key).and_then(Value::as_bool) {
                field.store(v, Ordering::Relaxed);
            }
        }
        // NOTE: a saved `auto_update` from pre-1.0.5 is deliberately
        // IGNORED - self-update was removed in 1.0.5 (notify-only).
        if let Some(v) = saved.get("update_checks").and_then(Value::as_bool) {
            daemon.update_checks.store(v, Ordering::Relaxed);
        }
        // The anti-rollback ratchet. Restored as-is: a hand-edited value
        // can only ever make this install FUSSIER about what it accepts
        // (once enforcement lands), never more permissive, so there is
        // nothing to validate or clamp here.
        if let Some(v) = saved.get("update_serial_seen").and_then(Value::as_u64) {
            daemon.update_serial_seen.store(v, Ordering::Relaxed);
        }
        if let Some(v) = saved.get("unit_bits").and_then(Value::as_bool) {
            daemon.unit_bits.store(v, Ordering::Relaxed);
        }
        // Saved empty string is meaningful: the user disabled update checks.
        if let Some(v) = saved.get("update_url").and_then(Value::as_str) {
            *daemon.update_url.lock_ok() = v.to_string();
        }
        if let Some(v) = saved.get("index_scan_par").and_then(Value::as_u64) {
            daemon
                .index_scan_par
                .store(v.clamp(1, 8), Ordering::Relaxed);
        }
        if let Some(v) = saved.get("index_tip_secs").and_then(Value::as_u64) {
            daemon
                .index_tip_secs
                .store(if v == 0 { 0 } else { v.max(5) }, Ordering::Relaxed);
        }
        if let Some(v) = saved.get("watch_interval_secs").and_then(Value::as_u64) {
            daemon
                .watch_interval_secs
                .store(v.clamp(1, 3600), Ordering::Relaxed);
        }
        if let Some(v) = saved.get("delete_to_trash").and_then(Value::as_bool) {
            crate::smart::set_delete_to_trash(v);
        }
        if let Some(s) = saved.get("cleanup_delete_mode").and_then(Value::as_str) {
            // Mirror the live setter (set_cleanup_delete_mode): lowercase
            // first, and never let an unparseable value fall through in
            // silence - the process default is Follow, which can resolve
            // to permanent deletion, and a typo in a hand-edited
            // settings.json must not silently select that. Trash is the
            // recoverable stand-in until the value is fixed.
            match crate::smart::CleanupMode::parse(&s.to_ascii_lowercase()) {
                Some(m) => crate::smart::set_cleanup_mode(m),
                None => {
                    eprintln!(
                        "⚠ settings.json: unknown cleanup_delete_mode {s:?} - \
                         use follow, trash or delete; treating it as \"trash\" \
                         (recoverable) until it is corrected"
                    );
                    crate::smart::set_cleanup_mode(crate::smart::CleanupMode::Trash);
                }
            }
        }
        // Nested-extraction depth cap shared by the in-stream child chain
        // and the disk post-pass (a process-global in nzbkit). Clamp 1..=64:
        // real nesting is 2-3 levels, the ceiling is a DoS backstop.
        if let Some(v) = saved.get("nested_max_depth").and_then(Value::as_u64) {
            nzbkit::extract::set_nested_depth_cap(v.clamp(1, 64) as usize);
        }
        // No create/writable check at startup: a NAS that is down at
        // boot must not wipe the setting - the move path degrades to
        // leave-in-place on its own.
        if let Some(v) = saved.get("move_completed").and_then(Value::as_str)
            && !v.is_empty()
        {
            *daemon.move_completed.write_ok() = Some(PathBuf::from(v));
        }
        if let Some(v) = saved.get("move_completed_cats").and_then(Value::as_str)
            && let Ok(list) = parse_cat_dests(v)
        {
            *daemon.move_completed_cats.write_ok() = list;
        }
        if let Some(v) = saved.get("categories").and_then(Value::as_str) {
            let mut set = daemon.cats.lock_ok();
            for name in v.split(',').map(str::trim).filter(|n| !n.is_empty()) {
                let clean = nzbkit::disk::sanitize_filename(name);
                if !clean.is_empty() {
                    set.insert(clean);
                }
            }
        }
        if let Some(v) = saved.get("oracle_sample").and_then(Value::as_u64) {
            daemon.oracle_sample.store(v.min(3600), Ordering::Relaxed);
        }
        if let Some(v) = saved.get("index_deepen").and_then(Value::as_u64) {
            daemon.index_deepen.store(v, Ordering::Relaxed);
        }
        if let Some(v) = saved.get("index_coverage").and_then(Value::as_bool) {
            daemon.index_coverage.store(v, Ordering::Relaxed);
        }
        // Present in settings.json == the user answered the question, so
        // the stored value wins over the indexers-configured default.
        if let Some(v) = saved.get("watchlist_external").and_then(Value::as_bool) {
            daemon.watchlist_external.store(v, Ordering::Relaxed);
            daemon.watchlist_external_set.store(true, Ordering::Relaxed);
        }
        if let Some(v) = saved.get("watchlist_instant").and_then(Value::as_bool) {
            daemon.watchlist_instant.store(v, Ordering::Relaxed);
        }
        if let Some(v) = saved.get("watchlist_instant_max").and_then(Value::as_u64) {
            daemon
                .watchlist_instant_max
                .store(v.min(3600) as u32, Ordering::Relaxed);
        }
        if let Some(v) = saved.get("index_gapfill").and_then(Value::as_u64) {
            daemon.index_gapfill.store(v.min(100), Ordering::Relaxed);
        }
        #[cfg(feature = "indexer")]
        if let Some(v) = saved.get("predb_max_rows").and_then(Value::as_u64) {
            daemon.predb_max_rows.store(
                v.clamp(
                    predb_seed::PREDB_MAX_ROWS_MIN,
                    predb_seed::PREDB_MAX_ROWS_MAX,
                ),
                Ordering::Relaxed,
            );
        }
        if let Some(v) = saved.get("predb_seed_days").and_then(Value::as_u64) {
            daemon
                .predb_seed_days
                .store(v.clamp(1, 366), Ordering::Relaxed);
        }
        if let Some(v) = saved.get("script_timeout_secs").and_then(Value::as_u64) {
            daemon.script_timeout.store(v, Ordering::Relaxed);
        }
        if let Some(v) = saved.get("history_rows").and_then(Value::as_u64)
            && (1..=200).contains(&v)
        {
            daemon.history_rows.store(v, Ordering::Relaxed);
        }
        if let Some(v) = saved.get("bench_interval").and_then(Value::as_u64) {
            daemon.bench_interval.store(v, Ordering::Relaxed);
        }
    }

    if let Some(v) = &speedlimit {
        let bps = parse_size(v)
            .ok_or_else(|| anyhow::anyhow!("--speedlimit: bad size {v:?} (e.g. 4M, 500K, 0)"))?;
        daemon.set_speed_ceiling(bps);
        if bps > 0 {
            info!(target: "config", "speedlimit {:.1} KB/s", bps as f64 / 1e3);
        }
    }

    // A pause the user set is part of the state a restart has to land in,
    // the same as the queue itself. Before the scheduler below, which may
    // overrule it.
    restore_pause(daemon, &load_settings(settings_path));

    // `docker stop`, `systemctl stop`, a Ctrl-C in a terminal: all of
    // them are a request to stop, and until now none of them reached the
    // wind-down the tray's Quit item has always had (issue #13).
    install_shutdown_signals(daemon);
    Ok(())
}

pub(super) fn seed_index_retention(settings_path: &Path) -> std::sync::atomic::AtomicBool {
    std::sync::atomic::AtomicBool::new(
        load_settings(settings_path)
            .get("index_retention")
            .and_then(Value::as_bool)
            .unwrap_or(true),
    )
}

pub(super) fn seed_index_pause_on_download(settings_path: &Path) -> std::sync::atomic::AtomicBool {
    std::sync::atomic::AtomicBool::new(
        load_settings(settings_path)
            .get("index_pause_on_download")
            .and_then(Value::as_bool)
            .unwrap_or(true),
    )
}

pub(super) fn seed_index_paused(settings_path: &Path) -> std::sync::atomic::AtomicBool {
    std::sync::atomic::AtomicBool::new(
        load_settings(settings_path)
            .get("index_paused")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    )
}

pub(super) fn seed_predb_enabled(settings_path: &Path) -> std::sync::atomic::AtomicBool {
    std::sync::atomic::AtomicBool::new(
        load_settings(settings_path)
            .get("predb_enabled")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    )
}

pub(super) fn seed_predb_server(settings_path: &Path) -> Mutex<String> {
    Mutex::new(
        load_settings(settings_path)
            .get("predb_server")
            .and_then(Value::as_str)
            .filter(|s| !s.trim().is_empty())
            .unwrap_or(nzbkit::predb::DEFAULT_HOST)
            .to_string(),
    )
}

pub(super) fn seed_predb_channels(settings_path: &Path) -> Mutex<String> {
    Mutex::new(
        load_settings(settings_path)
            .get("predb_channels")
            .and_then(Value::as_str)
            .filter(|s| !s.trim().is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| nzbkit::predb::DEFAULT_CHANNELS.join(",")),
    )
}

pub(super) fn seed_predb_nick(settings_path: &Path) -> Mutex<String> {
    Mutex::new(
        load_settings(settings_path)
            .get("predb_nick")
            .and_then(Value::as_str)
            .filter(|s| !s.trim().is_empty())
            .unwrap_or(nzbkit::predb::DEFAULT_NICK)
            .to_string(),
    )
}

pub(super) fn seed_predb_corr_enabled(settings_path: &Path) -> std::sync::atomic::AtomicBool {
    std::sync::atomic::AtomicBool::new(
        load_settings(settings_path)
            .get("predb_corr_enabled")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    )
}

pub(super) fn seed_predb_corr_auto(settings_path: &Path) -> std::sync::atomic::AtomicBool {
    std::sync::atomic::AtomicBool::new(
        load_settings(settings_path)
            .get("predb_corr_auto")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    )
}

pub(super) fn seed_spot_enabled(settings_path: &Path) -> std::sync::atomic::AtomicBool {
    std::sync::atomic::AtomicBool::new(
        load_settings(settings_path)
            .get("spot_enabled")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    )
}

pub(super) fn seed_spot_groups(settings_path: &Path) -> Mutex<Vec<String>> {
    Mutex::new(
        load_settings(settings_path)
            .get("spot_groups")
            .and_then(Value::as_array)
            .map(|a| {
                a.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect()
            })
            .unwrap_or_else(|| vec!["free.pt".to_string()]),
    )
}

pub(super) fn seed_spot_backfill(settings_path: &Path) -> AtomicU64 {
    AtomicU64::new(
        load_settings(settings_path)
            .get("spot_backfill")
            .and_then(Value::as_u64)
            .unwrap_or(50_000)
            .clamp(1_000, 1_000_000),
    )
}

pub(super) fn seed_index_max_bytes(settings_path: &Path) -> AtomicU64 {
    AtomicU64::new(
        load_settings(settings_path)
            .get("index_max_bytes")
            .and_then(Value::as_u64)
            .unwrap_or(0),
    )
}

pub(super) fn seed_index_evict(settings_path: &Path) -> std::sync::atomic::AtomicBool {
    std::sync::atomic::AtomicBool::new(
        load_settings(settings_path)
            .get("index_evict")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    )
}

#[cfg(feature = "indexer")]
pub(super) fn seed_index_evict_order(settings_path: &Path) -> Mutex<String> {
    Mutex::new(
        load_settings(settings_path)
            .get("index_evict_order")
            .and_then(Value::as_str)
            // A hand-edited settings.json can hold anything; keep
            // the invariant that this field is always valid.
            .filter(|s| parse_evict_order(s).is_some())
            .unwrap_or("ladder")
            .to_string(),
    )
}

#[cfg(feature = "indexer")]
pub(super) fn seed_index_evict_kinds(settings_path: &Path) -> Mutex<Vec<String>> {
    Mutex::new(
        load_settings(settings_path)
            .get("index_evict_kinds")
            .and_then(|v| match v {
                // save_setting persists the parsed Vec<String>; the
                // comma string is accepted too so a hand-written
                // settings.json works.
                Value::Array(a) => Some(
                    a.iter()
                        .filter_map(Value::as_str)
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                Value::String(s) => Some(s.clone()),
                _ => None,
            })
            .and_then(|s| parse_evict_kinds(&s).ok())
            .unwrap_or_default(),
    )
}

#[cfg(feature = "indexer")]
pub(super) fn seed_index_gates(
    settings_path: &Path,
    index_gates: Option<crate::gates::Gates>,
) -> Mutex<(String, Option<crate::gates::Gates>)> {
    Mutex::new((
        load_settings(settings_path)
            .get("index_gates")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string(),
        index_gates,
    ))
}

pub(super) fn seed_line_speed(settings_path: &Path) -> AtomicU64 {
    AtomicU64::new(
        load_settings(settings_path)
            .get("line_speed")
            .and_then(Value::as_u64)
            .unwrap_or(0),
    )
}

pub(super) fn seed_auto_retry_secs(_settings_path: &Path, auto_retry_mins: u64) -> AtomicU64 {
    AtomicU64::new(
        std::env::var("NZBFAST_AUTO_RETRY_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(auto_retry_mins * 60),
    )
}

pub(super) fn seed_quality_prefs(settings_path: &Path) -> Mutex<crate::watchlist::QualityPrefs> {
    Mutex::new(
        load_settings(settings_path)
            .get("prefer_quality")
            .and_then(|v| crate::watchlist::QualityPrefs::from_value(v).ok())
            .unwrap_or_default(),
    )
}

pub(super) fn seed_stream_secret(settings_path: &Path) -> String {
    {
        let saved = load_settings(settings_path)
            .get("stream_secret")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_string);
        match saved {
            Some(s) => s,
            None => {
                let s = fresh_secret();
                // Playback URLs minted from this secret are advertised
                // as permanent (expires: null, library .strm files), a
                // promise only a PERSISTED secret can keep - a restart
                // regenerates it and 401s every URL handed out under
                // the lost one. Say so loudly when the write fails;
                // the daemon still runs (best-effort settings policy).
                if !save_settings(settings_path, &[("stream_secret", json!(&s))]) {
                    eprintln!(
                        "⚠ could not persist the stream secret to {} - playback and \
                         .strm links minted this run will stop working after a \
                         restart (fix the settings directory to make them durable)",
                        settings_path.display()
                    );
                }
                s
            }
        }
    }
}

pub(super) fn seed_omdb_key(settings_path: &Path) -> Mutex<Option<String>> {
    Mutex::new(
        load_settings(settings_path)
            .get("omdb_key")
            .and_then(Value::as_str)
            .map(str::to_string)
            .filter(|k| !k.is_empty()),
    )
}

#[cfg(feature = "indexer")]
pub(super) fn resolve_index_enabled(settings_path: &Path, index_groups: &[String]) -> bool {
    let saved = load_settings(settings_path);
    match saved.get("index_enabled").and_then(Value::as_bool) {
        Some(v) => v,
        None => {
            let configured = !index_groups.is_empty()
                || saved
                    .get("index_interests")
                    .and_then(Value::as_str)
                    .is_some_and(|s| !s.trim().is_empty());
            //
            // Deliberately NOT written back to settings.json. The
            // derivation is stable (it re-runs identically every
            // start), the first touch of the switch in the UI saves
            // a real answer that wins from then on, and startup
            // writes to that file are their own hazard - the
            // first-run API key mint keys off which keys are in it
            // (see SETUP_ANSWER_KEYS).
            if configured {
                info!(
                    target: "index",
                    "indexing is on for the groups this install already had; \
                     it is a switch now (Settings → Indexing) and new installs start off"
                );
            }
            configured
        }
    }
}

pub(super) fn take_listener(bind: &str, port: u16) -> Result<tiny_http::Server> {
    // Take the listener HERE: after the API key is settled, and before the
    // first thing that writes to the data directory.
    //
    // The bind used to sit at the very end of startup, thousands of lines
    // below, so a daemon that could not have its port had already created
    // `.spool` and written settings.json before it found out. Those writes
    // are not incidental clutter - they ARE the "is this a fresh install?"
    // answer that `legacy_rename_punctuation` reads above.
    // A failed start therefore converted the directory from "fresh" to
    // "existing", and the NEXT start read the converted answer.
    //
    // That was a live flake, not a theoretical one: the daemon suites
    // spawn on an OS-assigned port and relaunch when they lose it to a
    // parallel test, so under `cargo test --workspace`
    // `obfuscated_event_release_keeps_its_words` filed its download as
    // `Formula1 (2026) ... [2160p]` - the pre-upgrade punctuation shape -
    // because attempt 1's corpse told attempt 2 it was an upgrade. Nothing
    // about the failure looked like a port problem. For a user the same
    // ordering meant `nzbfast serve --port <taken>` left a half-initialised
    // data directory behind.
    //
    // WHY HERE AND NOT EARLIER. The port is final from `apply_saved_settings`
    // onwards (settings.json wins over the CLI), so this could sit further
    // up - but it must not. `first_run_apikey` above is the gate that
    // REFUSES to start on an empty or unreadable key file, and binding
    // before it would turn a lost port into a bind error where an operator
    // (and firstrun_key.rs) expects to be told the credential is broken.
    // Binding after it also means the listener never exists before the
    // credential does, so there is no window in which tiny_http's accept
    // thread is up without an API key behind it. The one thing a failed
    // bind can still leave is the minted key file, which is harmless: it
    // feeds neither `legacy_rename_punctuation` nor anything else that
    // decides fresh-vs-existing, and the next start correctly reuses it -
    // and MintDisclosure is armed above, so exactly this exit is the one
    // that tells the user the key exists.
    //
    // runtime.json is NOT written here: it stays down by the banner. Its
    // invariant is "the listener exists AND the file appears before the
    // readiness banner" - both still hold with the bind up here - and it
    // needs the daemon's launcher token, which is only constructed below.
    tiny_http::Server::http((bind, port)).map_err(|e| anyhow::anyhow!("bind {bind}:{port}: {e}"))
}

pub(super) fn acquire_serve_lock(spool: &Path, config: &Path) -> Result<Option<std::fs::File>> {
    // ONE daemon per data directory. Two daemons sharing one - the
    // classic shape is an old container still running while its
    // replacement starts on another port - trade last-writer-wins
    // clobbers of settings.json and the queue, each overwriting the
    // other's state on every save with nothing on screen to say so. An
    // OS advisory lock, so it dies with the process and there is no
    // stale-lock state to recover from.
    //
    // Placement: after `spool_dir`, whose migration logic treats an
    // empty new spool as a placeholder to remove - a lock file created
    // inside it earlier would read as a completed migration. After the
    // bind, so a daemon that merely lost its port still exits through
    // the bind error and writes nothing (pinned by
    // a_daemon_that_loses_its_port_writes_nothing). And before the
    // Daemon is constructed, ahead of every runtime writer.
    //
    // Only a HELD lock refuses. A filesystem that cannot lock at all
    // (some network mounts) carries on silently: refusing there would
    // brick every NAS install that survives today, to close a race it
    // cannot even detect.
    Ok(
        match std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(spool.join("serve.lock"))
        {
            Ok(f) => {
                // A restart is allowed to overlap itself: launchers and
                // deploy scripts start the replacement while the old
                // process is still tearing down, and the lock is released
                // at its death, not at any earlier point. So a held lock
                // gets a few seconds to clear before it is treated as a
                // genuinely concurrent daemon.
                let mut verdict = f.try_lock();
                for _ in 0..25 {
                    match verdict {
                        Err(std::fs::TryLockError::WouldBlock) => {
                            std::thread::sleep(std::time::Duration::from_millis(120));
                            verdict = f.try_lock();
                        }
                        _ => break,
                    }
                }
                match verdict {
                    Ok(()) => Some(f),
                    Err(std::fs::TryLockError::WouldBlock) => {
                        let dir = config.parent().unwrap_or(config);
                        anyhow::bail!(
                            "another nzbfast daemon is already serving from {} - two daemons \
                         sharing one data directory overwrite each other's settings and \
                         queue, so this one is stopping. Stop the other daemon first; an \
                         old container or launcher still running is the usual cause. To \
                         run several daemons on purpose, give each its own --config.",
                            dir.display()
                        );
                    }
                    Err(std::fs::TryLockError::Error(_)) => None,
                }
            }
            Err(_) => None,
        },
    )
}

pub(super) fn spawn_core_tasks(
    daemon: &Arc<Daemon>,
    config: &Path,
    settings_path: &Path,
    schedule: &Option<PathBuf>,
    feeds: &Option<PathBuf>,
    #[cfg(feature = "indexer")] index_db: &Path,
    mem_budget: nzbkit::mem::MemBudget,
) -> Result<()> {
    tasks::spawn_scheduler(daemon, settings_path, schedule)?;

    tasks::spawn_watch_folder(daemon);

    tasks::spawn_memory_trim(daemon);

    tasks::spawn_auto_speed(daemon, config);

    #[cfg(feature = "indexer")]
    tasks::spawn_group_catalog(daemon, config);

    // Full scans, the tip watcher and VACUUM all write the same SQLite
    // file. A shared pass gate makes the exclusion two-way: checking an
    // atomic once did not stop a tip OVER already in flight from returning
    // and writing after a full pass began.
    let index_pass_gate = Arc::new(tokio::sync::Mutex::new(()));

    #[cfg(feature = "indexer")]
    tasks::spawn_index_scan(daemon, config, index_db, &index_pass_gate);

    #[cfg(feature = "indexer")]
    tasks::spawn_index_compact(daemon, &index_pass_gate);

    // The pre feed: the IRC listener and its database writer (both inert
    // unless the user has switched the feature on) - see tasks.rs.
    #[cfg(feature = "indexer")]
    tasks::spawn_predb_feed(daemon);

    #[cfg(feature = "indexer")]
    tasks::spawn_tip_watcher(daemon, config, &index_pass_gate);

    #[cfg(feature = "indexer")]
    tasks::spawn_oracle_sampler(daemon, config);

    tasks::spawn_health_prober(daemon, config);

    tasks::spawn_rss_poller(daemon, settings_path, feeds)?;

    tasks::spawn_watchlist_watcher(daemon, settings_path);

    tasks::spawn_download_worker(daemon, config, &index_pass_gate, mem_budget);

    tasks::spawn_library_recheck(daemon, config);

    // §76: the queue-row quality chip - reads the running job's own
    // container header so the row can say what the file IS, and warn
    // when that contradicts the name it was posted under.
    tasks::spawn_media_prober(daemon);

    tasks::spawn_slow_job_watchdog(daemon, config, mem_budget);
    tasks::spawn_live_tuner(daemon, config);
    super::linkpeak::spawn(daemon);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(super) fn announce_ready(
    daemon: &Arc<Daemon>,
    settings_path: &Path,
    bind: &str,
    port: u16,
    minted_key: &Option<(String, PathBuf)>,
    mint_disclosure: &mut MintDisclosure,
    open: bool,
) {
    // HTTP API on a blocking thread. The listener itself was taken at the
    // top of startup (see the bind note beside spool_dir); this is where
    // we start answering on it, and where readiness is announced.
    // Written only once the listener EXISTS, so its presence means this
    // daemon really did get the port (see `write_runtime_file`) - and
    // BEFORE the banner, because the banner is what everything else
    // treats as the readiness signal. Printing first left a window in
    // which a launcher (or a test harness) saw "nzbfast is running",
    // went looking for runtime.json, and found nothing: the handshake
    // then silently degraded to the no-token path, which is exactly the
    // permissive arm. The listener is already bound here, so nothing
    // about the file's meaning changes.
    write_runtime_file(settings_path, port, &daemon.launcher_token);
    println!("nzbfast is running - open the dashboard at  http://localhost:{port}/");
    println!("(SABnzbd-compatible API for Sonarr/Radarr at  http://localhost:{port}/api)");
    if let Some((key, keyfile)) = &minted_key {
        // Printed exactly once, on the first run that generated it. It is
        // the credential the user must paste into Sonarr/Radarr, so it
        // goes right under the dashboard URL rather than into the startup
        // scrollback above.
        // Deliberately small. Nothing here is a task: the key was
        // generated for the user, the dashboard link above already
        // carries it, and Settings can show it again whenever they get
        // round to Sonarr. A boxed banner reserving a third of the first
        // screen made a step that asks nothing read like a step that
        // asks something, which is the opposite of true. The value still
        // gets printed, because a headless first run has nowhere else to
        // read it from.
        println!();
        println!("  API key: {key}");
        println!(
            "  Set up automatically. Sonarr/Radarr need it; Settings → Security \
             can show it again or make a new one."
        );
        let _ = keyfile;
        println!();
        // The key has been shown; the failure-path disclosure would now
        // be noise.
        mint_disclosure.disarm();
    }
    if daemon.apikey.lock_ok().is_none() {
        // No API key → every request is treated as fully authorized (bug
        // sweep). Make the exposure impossible to miss; logtee mirrors
        // this into the dashboard log as well.
        eprintln!(
            "⚠ SECURITY: no apikey is set - the API on {bind}:{port} is OPEN to every host that \
             can reach this machine. Any device on your network, or a web page you visit (CSRF), \
             can add or delete jobs and change settings. Set an API key in Settings, or firewall \
             the port, unless this box is on a fully trusted network."
        );
    }
    if open {
        open_dashboard(port, minted_key.as_ref().map(|(k, _)| k.clone()));
    }
}

/// Issue #9: a fresh-install mint with a non-empty download root means
/// the config directory most likely moved - say so, loudly, once.
pub(super) fn warn_if_config_moved(minted_key: &Option<(String, PathBuf)>, out_root: &Path) {
    if minted_key.is_some() {
        let prior_use = out_root.join(".spool").exists()
            || std::fs::read_dir(out_root)
                .map(|mut entries| entries.next().is_some())
                .unwrap_or(false);
        if prior_use {
            eprintln!(
                "⚠ starting as a NEW install (nothing in the config directory), but the \
                 download folder {} is not empty. If you had settings before - servers, \
                 paths, an API key - nothing deleted them: nzbfast is most likely reading \
                 a different config directory than your previous install used. Docker and \
                 NAS users: compare the /config volume mapping with the old container's. \
                 The manual has the recovery steps, under Troubleshooting (/manual in the \
                 dashboard). If this really is a new install, carry on - nothing is wrong.",
                out_root.display()
            );
        }
    }
}

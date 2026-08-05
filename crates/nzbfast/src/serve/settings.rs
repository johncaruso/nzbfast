use super::*;

/// Everything `get_config` needs to read the live daemon, so a table row
/// can be a plain `fn` pointer instead of a closure over locals.
pub(super) struct ConfigCtx<'a> {
    pub(super) d: &'a Arc<Daemon>,
    pub(super) cfg_path: &'a std::path::Path,
}

/// How a setting's value reaches the settings UI.
pub(super) enum Expose {
    /// Read straight off the live daemon by this function, under the
    /// row's own name. This is what builds `get_config`'s block.
    Config(fn(&ConfigCtx) -> Value),
    /// In the block, but assembled by `get_config` itself out of values
    /// it has already computed (the masked server list, the
    /// restart-pending diff). Declared here only so the drift check
    /// still sees it.
    Assembled,
    /// Writable but never echoed back: credentials (the UI learns only
    /// that one is stored, via a `has_*` row) and the SAB-compatible
    /// one-shot actions, which have no stored value to show.
    Hidden,
}

/// What the `[config]` line may print as this setting's new value.
pub(super) enum Log {
    /// A switch, a number, a path, a plain word or a list of them:
    /// nothing that can carry a credential, so print it verbatim.
    Plain,
    /// A credential. Never printed.
    Masked,
    /// Structured and credential-bearing: a notify target's `url` IS its
    /// bearer token for Discord/ntfy/Gotify, so kinds and counts only.
    Targets,
    /// A feed url essentially always embeds the indexer's `apikey=`, so
    /// the log gets the count and nothing else.
    Feeds,
    /// M35 indexer entries carry a per-site `apikey` field: count only.
    Indexers,
    /// Everything else: how big it was, and nothing about what was in
    /// it. The default, so the next credential-bearing setting someone
    /// adds cannot silently reopen the log.
    Shape,
}

/// One row per setting the config API knows about.
///
/// THIS IS THE LIST. It used to be three of them kept in step by hand -
/// a logging allowlist, the `apply_setting` match, and one enormous
/// `json!` literal in `get_config` - and a setting left out of any one
/// failed silently: no error, the setting simply did nothing.
/// `get_config`'s settings block is now BUILT from this table so a row
/// cannot go missing from it, `log_value` takes its rule from here, and
/// `apply_setting`'s fallthrough can tell a declared row with no writer
/// apart from a name nobody ever declared. The one edge left - the match
/// itself, which cannot be generated without rewriting a hundred
/// hand-written validators - is held to the table by
/// `apply_arms_match_the_table`.
///
/// One surface stays outside the table on purpose: `apply_saved_settings`
/// maps saved JSON onto launch options BEFORE a Daemon exists, so it can
/// share no shape with rows that read live daemon state. That leg is
/// pinned behaviourally instead, by `settings_survive_a_restart` in
/// tests/settings_catalogue.rs.
///
/// The rows carry the API's persisted key names verbatim. Renaming one
/// is a settings.json migration, not an edit here.
pub(super) struct Setting {
    pub(super) name: &'static str,
    pub(super) expose: Expose,
    pub(super) write: Write,
    pub(super) log: Log,
}

/// What `mode=config&name=<row>` does with this row.
#[derive(PartialEq)]
pub(super) enum Write {
    /// `apply_setting` has an arm for it, which validates the value,
    /// applies it live where it can, and returns what to persist.
    /// `apply_arms_match_the_table` holds this to the source.
    Setting,
    /// Accepted by `mode=config`, but intercepted before `apply_setting`
    /// ever sees it: an action, not a stored value.
    Action,
    /// Reported to the UI; there is nothing to set.
    No,
}

/// Shorthand for the common shape: live-readable, writable, safe to log.
pub(super) const fn rw(name: &'static str, read: fn(&ConfigCtx) -> Value) -> Setting {
    Setting {
        name,
        expose: Expose::Config(read),
        write: Write::Setting,
        log: Log::Plain,
    }
}

/// Readable and writable, but the value is a blob we only log the size of.
/// Tell the editor what each rule's pattern will actually do (#18).
///
/// Both `match` and `but not` ride `nzbkit::categories::pat_match`, which
/// never fails - a pattern that will not compile silently becomes a
/// literal keyword search, and one that compiles to "match anything"
/// silently claims the whole queue. Neither is visible in the rules
/// editor, so a broken rule looks exactly like one that has not fired.
///
/// Computed on the READ path and attached here rather than stored on
/// `Rule` / `CustomCategory`: those two structs are the persisted shape in
/// settings.json, and a field that only ever describes the value would be
/// written back into the file. The editors rebuild their payload from the
/// row inputs and send only the keys they own (saveSmart / saveCats in
/// dashboard.html), so these never echo back - the same read-only-sibling
/// contract `feed_health` uses.
///
/// `PatternVerdict::Ok` is left off entirely: an absent key is the normal
/// case, and shipping `"ok"` on every rule of every install would be pure
/// payload for the reading that means "nothing to say".
fn annotate_patterns(v: Value) -> Value {
    use nzbkit::categories::{PatternVerdict, pat_verdict};
    let Value::Array(rules) = v else { return v };
    Value::Array(
        rules
            .into_iter()
            .map(|mut rule| {
                for (field, out) in [("match", "match_verdict"), ("not_match", "not_verdict")] {
                    let pat = rule.get(field).and_then(Value::as_str).unwrap_or("");
                    let verdict = pat_verdict(pat);
                    if verdict != PatternVerdict::Ok
                        && let Some(obj) = rule.as_object_mut()
                    {
                        obj.insert(out.into(), json!(verdict));
                    }
                }
                rule
            })
            .collect(),
    )
}

pub(super) const fn rw_opaque(name: &'static str, read: fn(&ConfigCtx) -> Value) -> Setting {
    Setting {
        name,
        expose: Expose::Config(read),
        write: Write::Setting,
        log: Log::Shape,
    }
}

/// Reported to the UI, but there is nothing to set.
pub(super) const fn ro(name: &'static str, read: fn(&ConfigCtx) -> Value) -> Setting {
    Setting {
        name,
        expose: Expose::Config(read),
        write: Write::No,
        log: Log::Plain,
    }
}

/// Paths and the control port.
pub(super) const PATHS: &[Setting] = &[
    rw("port", |c| json!(c.d.port)),
    rw("out_dir", |c| json!(c.d.out_dir().to_string_lossy())),
    rw("move_completed", |c| {
        json!(
            c.d.move_completed
                .read()
                .unwrap()
                .as_ref()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default()
        )
    }),
    rw("move_completed_cats", |c| {
        json!(fmt_cat_dests(&c.d.move_completed_cats.read_ok()))
    }),
    rw("categories", |c| json!(c.d.cat_list())),
    rw("watch", |c| json!(path_str(&c.d.watch_dir.lock_ok()))),
    rw("watch_interval_secs", |c| {
        json!(c.d.watch_interval_secs.load(Ordering::Relaxed))
    }),
    rw(
        "delete_to_trash",
        |_| json!(crate::smart::delete_to_trash()),
    ),
    rw("script", |c| json!(path_str(&c.d.script.lock_ok()))),
    rw("script_timeout_secs", |c| {
        json!(c.d.script_timeout.load(Ordering::Relaxed))
    }),
    #[cfg(feature = "indexer")]
    rw("index_db", |c| json!(c.d.index_db.to_string_lossy())),
    ro("config_path", |c| json!(c.cfg_path.to_string_lossy())),
    ro("settings_path", |c| {
        json!(c.d.settings_path.to_string_lossy())
    }),
];

/// The download engine.
pub(super) const DOWNLOAD: &[Setting] = &[
    rw("connections", |c| {
        json!(c.d.connections.load(Ordering::Relaxed))
    }),
    rw("window", |c| json!(c.d.window.load(Ordering::Relaxed))),
    rw("decoders", |c| json!(c.d.decoders.load(Ordering::Relaxed))),
    rw("fast_verify", |c| {
        json!(c.d.fast_verify.load(Ordering::Relaxed))
    }),
    rw("verify_mode", |c| {
        json!(match (
            c.d.fast_verify.load(Ordering::Relaxed),
            c.d.verify_lean.load(Ordering::Relaxed),
        ) {
            (false, _) => "full",
            (true, false) => "fast",
            (true, true) => "lean",
        })
    }),
    rw("min_free", |c| json!(c.d.min_free.load(Ordering::Relaxed))),
    // #20. Echoed as the octal STRING it was typed as, empty when off,
    // so the field shows back what the guides print rather than a
    // decimal nobody recognises.
    rw("out_umask", |c| {
        let m = c.d.out_umask.load(Ordering::Relaxed);
        json!(if m <= 0o777 {
            format!("{m:03o}")
        } else {
            String::new()
        })
    }),
    rw("auto_retry_mins", |c| {
        json!(c.d.auto_retry_secs.load(Ordering::Relaxed) / 60)
    }),
    rw("quota", |c| json!(c.d.quota.load(Ordering::Relaxed))),
    rw("quota_period", |c| {
        json!((c.d.quota_period.load(Ordering::Relaxed) as char).to_string())
    }),
    rw("nested_max_depth", |_| {
        json!(nzbkit::extract::nested_depth_cap())
    }),
    // The saved override (0/absent = auto); the resolved budget is
    // mem_budget_total.
    rw("mem_limit", |c| {
        json!(
            load_settings(&c.d.settings_path)
                .get("mem_limit")
                .and_then(Value::as_u64)
                .unwrap_or(0)
        )
    }),
    ro("mem_budget_total", |c| json!(c.d.mem_budget_total)),
];

/// Speed, scheduling and the auto-tuners.
pub(super) const SPEED: &[Setting] = &[
    rw("speedlimit", |c| {
        json!(c.d.speed_ceiling.load(Ordering::Relaxed))
    }),
    rw("line_speed", |c| {
        json!(c.d.line_speed.load(Ordering::Relaxed))
    }),
    rw("auto_speed", |c| {
        json!(c.d.auto_speed.load(Ordering::Relaxed))
    }),
    rw("auto_defer", |c| {
        json!(c.d.auto_defer.load(Ordering::Relaxed))
    }),
    rw("post_health", |c| {
        json!(c.d.post_health.load(Ordering::Relaxed))
    }),
    rw("post_health_defer", |c| {
        json!(c.d.post_health_defer.load(Ordering::Relaxed))
    }),
    rw("wall_hide_adult", |c| {
        json!(c.d.wall_hide_adult.load(Ordering::Relaxed))
    }),
    rw("auto_connections", |c| {
        json!(c.d.auto_connections.load(Ordering::Relaxed))
    }),
    ro("conntune", |c| {
        serde_json::to_value(crate::conntune::load(c.cfg_path)).unwrap_or_else(|_| json!({}))
    }),
    // The tuner's line-speed verdict (empty = fine or unjudged) -
    // written by the probe loop, shown near the line-speed setting.
    ro("tune_hint", |c| json!(c.d.tune_hint.lock_ok().clone())),
    rw("auto_prefetch", |c| {
        json!(c.d.auto_prefetch.load(Ordering::Relaxed))
    }),
    rw("race_stragglers", |c| {
        json!(c.d.race_stragglers.load(Ordering::Relaxed))
    }),
    rw("adaptive_timeouts", |c| {
        json!(c.d.adaptive_timeouts.load(Ordering::Relaxed))
    }),
    rw("oracle_route", |c| {
        json!(c.d.oracle_route.load(Ordering::Relaxed))
    }),
    rw("oracle_sample", |c| {
        json!(c.d.oracle_sample.load(Ordering::Relaxed))
    }),
    rw("bench_interval", |c| {
        json!(c.d.bench_interval.load(Ordering::Relaxed))
    }),
    // Free-form text; only its size reaches the log.
    rw_opaque("schedule", |c| json!(c.d.schedule_text.lock_ok().clone())),
];

/// Auto-rename, and how a finished download is labelled.
pub(super) const RENAME: &[Setting] = &[
    rw("auto_rename", |c| {
        json!(c.d.auto_rename.load(Ordering::Relaxed))
    }),
    rw("identity_lookup", |c| {
        json!(c.d.identity_lookup.load(Ordering::Relaxed))
    }),
    rw("rename_resolution", |c| {
        json!(c.d.rename_resolution.load(Ordering::Relaxed))
    }),
    rw("rename_vcodec", |c| {
        json!(c.d.rename_vcodec.load(Ordering::Relaxed))
    }),
    rw("rename_acodec", |c| {
        json!(c.d.rename_acodec.load(Ordering::Relaxed))
    }),
    rw("rename_source", |c| {
        json!(c.d.rename_source.load(Ordering::Relaxed))
    }),
    rw("rename_group", |c| {
        json!(c.d.rename_group.load(Ordering::Relaxed))
    }),
    rw("rename_year_parens", |c| {
        json!(c.d.rename_year_parens.load(Ordering::Relaxed))
    }),
    rw("rename_quality_brackets", |c| {
        json!(c.d.rename_quality_brackets.load(Ordering::Relaxed))
    }),
    rw("rename_extra_words", |c| {
        json!(c.d.rename_extra_words.load(Ordering::Relaxed))
    }),
    rw("rename_identify", |c| {
        json!(c.d.rename_identify.load(Ordering::Relaxed))
    }),
    rw("rename_episode_titles", |c| {
        json!(c.d.rename_episode_titles.load(Ordering::Relaxed))
    }),
    rw("rename_junk", |c| {
        json!(c.d.rename_junk.load(Ordering::Relaxed))
    }),
    rw("rename_media_only", |c| {
        json!(c.d.rename_media_only.load(Ordering::Relaxed))
    }),
    rw("history_rows", |c| {
        json!(c.d.history_rows.load(Ordering::Relaxed))
    }),
    rw("history_color_names", |c| {
        json!(c.d.history_color_names.load(Ordering::Relaxed))
    }),
    rw("media_chip_color", |c| {
        json!(c.d.media_chip_color.load(Ordering::Relaxed))
    }),
    rw("shape_chip_color", |c| {
        json!(c.d.shape_chip_color.load(Ordering::Relaxed))
    }),
];

/// The indexer and the library scanner.
pub(super) const INDEXING: &[Setting] = &[
    // The master switch. Everything else in this table is inert while it
    // is off, and the UI hides the lot - so it is read first by both.
    #[cfg(feature = "indexer")]
    rw("index_enabled", |c| {
        json!(c.d.index_enabled.load(Ordering::Relaxed))
    }),
    // Spotnet: its own switch, not a sub-option of the one above.
    #[cfg(feature = "indexer")]
    rw("spot_enabled", |c| {
        json!(c.d.spot_enabled.load(Ordering::Relaxed))
    }),
    rw("spot_groups", |c| json!(c.d.spot_groups.lock_ok().clone())),
    rw("spot_backfill", |c| {
        json!(c.d.spot_backfill.load(Ordering::Relaxed))
    }),
    rw("library_cats", |c| {
        json!(c.d.library_cats.lock_ok().clone())
    }),
    rw("library_recheck_secs", |c| {
        json!(c.d.library_recheck_secs.load(Ordering::Relaxed))
    }),
    rw("index_groups", |c| {
        json!(c.d.index_groups.lock_ok().clone())
    }),
    #[cfg(feature = "indexer")]
    rw("index_interests", |c| {
        json!(c.d.index_interests.lock_ok().clone())
    }),
    // Written by the setup wizard to record that the interests it
    // collected have been turned into groups. No UI field reads it back.
    Setting {
        name: "index_interests_applied",
        expose: Expose::Hidden,
        write: Write::Setting,
        log: Log::Plain,
    },
    rw("index_interval_secs", |c| {
        json!(c.d.index_interval_secs.load(Ordering::Relaxed))
    }),
    rw("index_scan_par", |c| {
        json!(c.d.index_scan_par.load(Ordering::Relaxed))
    }),
    rw("index_tip_secs", |c| {
        json!(c.d.index_tip_secs.load(Ordering::Relaxed))
    }),
    rw("index_backfill", |c| {
        json!(c.d.index_backfill.load(Ordering::Relaxed))
    }),
    rw("index_deepen", |c| {
        json!(c.d.index_deepen.load(Ordering::Relaxed))
    }),
    rw("index_coverage", |c| {
        json!(c.d.index_coverage.load(Ordering::Relaxed))
    }),
    rw("index_gapfill", |c| {
        json!(c.d.index_gapfill.load(Ordering::Relaxed))
    }),
    rw("group_desc_isc", |c| {
        json!(c.d.group_desc_isc.load(Ordering::Relaxed))
    }),
    rw("index_max_age_secs", |c| {
        json!(c.d.index_max_age_secs.load(Ordering::Relaxed))
    }),
    rw("index_retention", |c| {
        json!(c.d.index_retention.load(Ordering::Relaxed))
    }),
    rw("index_pause_on_download", |c| {
        json!(c.d.index_pause_on_download.load(Ordering::Relaxed))
    }),
    rw("index_paused", |c| {
        json!(c.d.index_paused.load(Ordering::Relaxed))
    }),
    // M34 size cap. Bytes, not a SAB-style string: the UI formats, the
    // API parses.
    rw("index_max_bytes", |c| {
        json!(c.d.index_max_bytes.load(Ordering::Relaxed))
    }),
    rw("index_evict", |c| {
        json!(c.d.index_evict.load(Ordering::Relaxed))
    }),
    #[cfg(feature = "indexer")]
    rw("index_evict_order", |c| {
        json!(c.d.index_evict_order.lock_ok().clone())
    }),
    #[cfg(feature = "indexer")]
    rw("index_evict_kinds", |c| {
        json!(c.d.index_evict_kinds.lock_ok().clone())
    }),
    #[cfg(feature = "indexer")]
    rw("index_gates", |c| {
        json!(c.d.index_gates.lock_ok().0.clone())
    }),
    // Pre feed. Off by default; the other three are inert while it is.
    rw("predb_enabled", |c| {
        json!(c.d.predb_enabled.load(Ordering::Relaxed))
    }),
    rw("predb_server", |c| {
        json!(c.d.predb_server.lock_ok().clone())
    }),
    rw("predb_channels", |c| {
        json!(c.d.predb_channels.lock_ok().clone())
    }),
    rw("predb_nick", |c| json!(c.d.predb_nick.lock_ok().clone())),
    // Phase 2 correlation - two separate switches on purpose. Hearing
    // pre lines (above) is harmless; INFERRING names from timing+size
    // is a policy, and applying one without a click is a second policy.
    rw("predb_corr_enabled", |c| {
        json!(c.d.predb_corr_enabled.load(Ordering::Relaxed))
    }),
    rw("predb_corr_auto", |c| {
        json!(c.d.predb_corr_auto.load(Ordering::Relaxed))
    }),
    // Capacity, not policy: how many pre rows to keep, and how far back
    // a seed import reaches when it is not told.
    #[cfg(feature = "indexer")]
    rw("predb_max_rows", |c| {
        json!(c.d.predb_max_rows.load(Ordering::Relaxed))
    }),
    #[cfg(feature = "indexer")]
    rw("predb_seed_days", |c| {
        json!(c.d.predb_seed_days.load(Ordering::Relaxed))
    }),
];

/// Automation: what gets grabbed, sorted and announced.
pub(super) const AUTOMATION: &[Setting] = &[
    rw("prefer_quality", |c| c.d.quality_prefs.lock_ok().to_json()),
    // Every feed url essentially always embeds the indexer's `apikey=`.
    //
    // §G: each entry also carries what its last poll did (last_poll,
    // last_error, items_seen). Merged in here rather than shipped as a
    // second keyed list on purpose - a separate block would have to
    // repeat the feed url to say which feed it described, and that url
    // is the credential. These are read-only additions: `saveFeeds`
    // rebuilds the list from the row inputs, so nothing echoes back, and
    // the persisted settings.json shape is unchanged (the writer
    // serialises FeedConfig, which has no idea these exist).
    Setting {
        name: "feeds",
        expose: Expose::Config(|c| {
            let feeds = c.d.feeds.lock_ok().clone();
            let health = c.d.feed_health.lock_ok();
            Value::Array(
                feeds
                    .iter()
                    .map(|f| {
                        let mut v = serde_json::to_value(f).unwrap_or_else(|_| json!({}));
                        if let (Some(m), Some(h)) = (v.as_object_mut(), health.get(&f.url)) {
                            m.insert("last_poll".into(), json!(h.last_poll));
                            m.insert("last_error".into(), json!(h.last_error));
                            m.insert("items_seen".into(), json!(h.items_seen));
                        }
                        v
                    })
                    .collect(),
            )
        }),
        write: Write::Setting,
        log: Log::Feeds,
    },
    // M35 pull-search indexers. The apikey never round-trips: the UI
    // learns `has_key`, and the writer merges a blank key back onto the
    // stored one (the server-password convention), so an edit in the
    // dashboard cannot leak or erase a key.
    Setting {
        name: "indexers",
        expose: Expose::Config(|c| {
            Value::Array(
                c.d.indexers
                    .lock()
                    .unwrap()
                    .iter()
                    .map(|i| {
                        json!({
                            "name": i.name,
                            "url": i.url,
                            "enabled": i.enabled,
                            "priority": i.priority,
                            "hits_per_day": i.hits_per_day,
                            "grabs_per_day": i.grabs_per_day,
                            "has_key": !i.apikey.is_empty(),
                        })
                    })
                    .collect(),
            )
        }),
        write: Write::Setting,
        log: Log::Indexers,
    },
    rw_opaque("watchlist", |c| {
        serde_json::to_value(&*c.d.watchlist.lock_ok()).unwrap_or(json!([]))
    }),
    // The EFFECTIVE answer, not the raw bool: the dashboard checkbox has
    // to show what the watcher will actually do, and while the user has
    // not answered that is derived from whether any indexer exists.
    rw("watchlist_external", |c| json!(c.d.watchlist_external_on())),
    rw("watchlist_instant", |c| {
        json!(c.d.watchlist_instant.load(Ordering::Relaxed))
    }),
    rw("watchlist_instant_max", |c| {
        json!(c.d.watchlist_instant_max.load(Ordering::Relaxed))
    }),
    rw_opaque("smart_folders", |c| {
        annotate_patterns(serde_json::to_value(&*c.d.smart_folders.lock_ok()).unwrap_or(json!([])))
    }),
    rw("custom_categories", |c| {
        annotate_patterns(
            serde_json::to_value(&*c.d.custom_categories.read_ok()).unwrap_or(json!([])),
        )
    }),
    rw("cleanup_exts", |c| {
        json!(c.d.cleanup_exts.lock_ok().clone())
    }),
    // SAB/NZBGet-parity passwords file. Only the PATH and a count reach
    // the UI - the contents are credentials, edited in the file itself
    // (the has_password/notify-token contract).
    rw("password_file", |c| {
        json!(c.d.password_file.lock_ok().to_string_lossy())
    }),
    ro("password_file_count", |c| {
        json!(c.d.read_unpack_passwords().len())
    }),
    rw("password_prompt", |c| {
        json!(c.d.password_prompt.lock_ok().clone())
    }),
    rw("unpack_eat_volumes", |c| {
        json!(c.d.unpack_eat_volumes.lock_ok().clone())
    }),
    rw("par_cleanup", |c| {
        json!(c.d.par_cleanup.load(Ordering::Relaxed))
    }),
    rw("watch_keep_nzb", |c| {
        json!(c.d.watch_keep_nzb.load(Ordering::Relaxed))
    }),
    rw("fast_par", |c| json!(c.d.fast_par.load(Ordering::Relaxed))),
    rw("prefer_external_unrar", |c| {
        json!(c.d.prefer_external_unrar.load(Ordering::Relaxed))
    }),
    // Never the token itself: it is the Plex token / Jellyfin API key /
    // Kodi `user:password`, and get_config is a read anyone with the key
    // can make from a browser. Same contract as has_password/has_apikey -
    // the UI learns only that one is stored. The config writer merges a
    // blank token back onto the saved one, so a round-trip through the
    // dashboard cannot erase it. A target's `url` IS its bearer token for
    // Discord/ntfy/Gotify, so the log gets kinds and counts only.
    //
    // §G: `last_send` is what this target's last delivery did. The
    // OUTCOME travels; the key it is stored under (which embeds the url)
    // never does - the row is matched by position in this list, which is
    // the same list the UI renders from.
    Setting {
        name: "notify_targets",
        expose: Expose::Config(|c| {
            let targets = c.d.notify_targets.lock_ok().clone();
            let health = c.d.notify_health.lock_ok();
            Value::Array(
                targets
                    .iter()
                    .map(|t| {
                        json!({
                            "name": t.name,
                            "kind": t.kind,
                            "url": t.url,
                            "body": t.body,
                            "enabled": t.enabled,
                            "on_failure": t.on_failure,
                            "category": t.category,
                            "has_token": !t.token.is_empty(),
                            "last_send": health.get(&crate::notify::target_key(t)),
                        })
                    })
                    .collect(),
            )
        }),
        write: Write::Setting,
        log: Log::Targets,
    },
    rw("failure_link", |c| {
        json!(c.d.failure_link.lock_ok().clone())
    }),
    // §96.3 give-up breaker: distinct failed releases per target before
    // it is unmonitored. 0 = off, the default.
    rw("arr_giveup_threshold", |c| {
        json!(c.d.arr_giveup_threshold.load(Ordering::Relaxed))
    }),
    // The *arr instances the breaker may act on. The apikey is a
    // credential: only `has_key` crosses back to the UI, and the writer
    // merges a blank key onto the stored one - the notify_targets
    // contract.
    Setting {
        name: "arr_instances",
        expose: Expose::Config(|c| {
            Value::Array(
                c.d.arr_instances
                    .lock_ok()
                    .iter()
                    .map(|i| {
                        json!({
                            "name": i.name,
                            "kind": i.kind,
                            "url": i.url,
                            "enabled": i.enabled,
                            "has_key": !i.apikey.is_empty(),
                        })
                    })
                    .collect(),
            )
        }),
        write: Write::Setting,
        log: Log::Targets,
    },
];

/// The dashboard itself, and update checking.
pub(super) const INTERFACE: &[Setting] = &[
    rw("update_checks", |c| {
        json!(c.d.update_checks.load(Ordering::Relaxed))
    }),
    rw("unit_bits", |c| {
        json!(c.d.unit_bits.load(Ordering::Relaxed))
    }),
    rw("update_url", |c| json!(c.d.update_url.lock_ok().clone())),
    rw("ui_locale", |c| json!(c.d.ui_locale.lock_ok().clone())),
];

/// Credentials. Set-only: the UI is told a key EXISTS, never what it is.
pub(super) const KEYS: &[Setting] = &[
    Setting {
        name: "apikey",
        expose: Expose::Hidden,
        write: Write::Setting,
        log: Log::Masked,
    },
    Setting {
        name: "nzbkey",
        expose: Expose::Hidden,
        write: Write::Setting,
        log: Log::Masked,
    },
    Setting {
        name: "omdb_key",
        expose: Expose::Hidden,
        write: Write::Setting,
        log: Log::Masked,
    },
    ro("has_apikey", |c| json!(c.d.apikey.lock_ok().is_some())),
    ro("has_nzbkey", |c| json!(c.d.nzbkey.lock_ok().is_some())),
    ro("has_omdb", |c| json!(c.d.omdb_key.lock_ok().is_some())),
];

/// Rows `get_config` fills in itself, plus the SAB-compatible actions
/// that go through `mode=config` without being settings at all.
pub(super) const RUNTIME: &[Setting] = &[
    // The usenet servers, secrets masked - built alongside the
    // first-run signal that says whether any exist yet.
    Setting {
        name: "servers",
        expose: Expose::Assembled,
        write: Write::No,
        log: Log::Plain,
    },
    Setting {
        name: "servers_configured",
        expose: Expose::Assembled,
        write: Write::No,
        log: Log::Plain,
    },
    // Saved-but-not-yet-applied values for the restart-only settings.
    Setting {
        name: "pending",
        expose: Expose::Assembled,
        write: Write::No,
        log: Log::Plain,
    },
    // SAB parity: `config&name=set_pause&value=<minutes>`. Handled
    // before apply_setting ever sees it, and stores nothing.
    Setting {
        name: "set_pause",
        expose: Expose::Hidden,
        write: Write::Action,
        log: Log::Plain,
    },
];

/// The table, in the order the settings UI lays the cards out.
pub(super) const SETTING_GROUPS: &[&[Setting]] = &[
    PATHS, DOWNLOAD, SPEED, RENAME, INDEXING, AUTOMATION, INTERFACE, KEYS, RUNTIME,
];

pub(super) fn settings() -> impl Iterator<Item = &'static Setting> {
    SETTING_GROUPS.iter().copied().flatten()
}

pub(super) fn setting(name: &str) -> Option<&'static Setting> {
    settings().find(|s| s.name == name)
}

/// What the `[config]` line may print as a setting's new value.
///
/// stdout is not private here: logtee mirrors it into the dashboard log
/// ring (`mode=log`, and the JSON-RPC `log`/`loadlog` methods) - the pane
/// users screenshot into support threads - as well as journald and
/// `docker logs`. Several settings carry credentials inside an otherwise
/// innocuous-looking value: a notify target's `url` IS its bearer token
/// for Discord/ntfy/Gotify, its `token` is a Plex token or a Kodi
/// `user:password`, and a feed url essentially always embeds the
/// indexer's `apikey=`. `notify.rs` already holds the line that a webhook
/// url must never reach the log; this keeps the config write to the same
/// rule.
///
/// Default-deny by design: the rule comes from the setting's row in
/// [`SETTING_GROUPS`], and a name with no row at all gets a shape
/// summary, not its value - so the next credential-bearing setting
/// someone adds cannot silently reopen this.
pub(super) fn log_value(name: &str, v: &str) -> String {
    match setting(name).map(|s| &s.log) {
        Some(Log::Plain) => v.to_string(),
        // Straight credentials.
        Some(Log::Masked) => "•••".to_string(),
        // Structured, credential-bearing: kinds and counts only, no urls.
        Some(Log::Targets) => match serde_json::from_str::<Vec<Value>>(v) {
            Ok(ts) => {
                let mut kinds: Vec<&str> = ts
                    .iter()
                    .map(|t| t.get("kind").and_then(Value::as_str).unwrap_or("?"))
                    .collect();
                kinds.sort_unstable();
                kinds.dedup();
                if kinds.is_empty() {
                    format!("{} targets", ts.len())
                } else {
                    format!("{} targets ({})", ts.len(), kinds.join(", "))
                }
            }
            Err(_) => shape_only(v),
        },
        Some(Log::Feeds) => match serde_json::from_str::<Vec<Value>>(v) {
            Ok(f) => format!("{} feeds", f.len()),
            Err(_) => shape_only(v),
        },
        Some(Log::Indexers) => match serde_json::from_str::<Vec<Value>>(v) {
            Ok(f) => format!("{} indexers", f.len()),
            Err(_) => shape_only(v),
        },
        Some(Log::Shape) | None => shape_only(v),
    }
}

/// An optional path setting as the UI wants it: the path, or "" for unset.
pub(super) fn path_str(p: &Option<PathBuf>) -> String {
    p.as_ref()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// The settings block `get_config` hands the UI, built by walking the
/// table rather than by one enormous `json!` literal. Every
/// [`Expose::Config`] row contributes its live value under its own name;
/// the [`Expose::Assembled`] rows are filled in by the caller, which has
/// already computed them.
pub(super) fn config_block(ctx: &ConfigCtx) -> serde_json::Map<String, Value> {
    let mut map = serde_json::Map::new();
    for s in settings() {
        if let Expose::Config(read) = s.expose {
            map.insert(s.name.to_string(), read(ctx));
        }
    }
    map
}

/// How big it was, and nothing about what was in it.
pub(super) fn shape_only(v: &str) -> String {
    if v.is_empty() {
        "(empty)".to_string()
    } else {
        format!("({} chars, not logged)", v.chars().count())
    }
}

fn set_speedlimit(
    d: &Arc<Daemon>,
    name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    let size = || parse_size(v).ok_or_else(|| format!("{name}: bad size (e.g. 4M, 10G, 0 = off)"));
    Ok({
        // SAB-compatible semantics (remote apps send percentages):
        // bare number ≤ 100 = PERCENT of the configured line speed
        // (100 = unlimited); anything else = absolute bytes/sec
        // (with or without K/M/G suffix), our native convention.
        let t = v.trim();
        let bps = match t.parse::<u64>() {
            Ok(0) => 0, // 0 = unlimited, both conventions
            Ok(pct) if pct <= 100 => {
                if pct >= 100 {
                    0
                } else {
                    let line = d.line_speed.load(Ordering::Relaxed);
                    if line == 0 {
                        return Err(
                            "percentage limits need a Line speed (Settings → Speed & scheduling)"
                                .into(),
                        );
                    }
                    line * pct / 100
                }
            }
            _ => size()?,
        };
        d.set_speed_ceiling(bps);
        (true, json!(bps))
    })
}

fn set_auto_speed(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    let flag = || v == "1" || v.eq_ignore_ascii_case("true");
    Ok({
        let on = flag();
        d.auto_speed.store(on, Ordering::Relaxed);
        if !on {
            // Hand the wheel back: rate returns to the ceiling.
            d.hub.rate.set(d.speed_ceiling.load(Ordering::Relaxed));
        }
        (true, json!(on))
    })
}

fn set_update_url(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        let t = v.trim();
        if !t.is_empty() && !(t.starts_with("http://") || t.starts_with("https://")) {
            return Err("update_url: must be http(s), or empty to disable checks".into());
        }
        *d.update_url.lock_ok() = t.to_string();
        (true, json!(t))
    })
}

fn set_ui_locale(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        // §5 i18n daemon default. Empty = auto (each browser follows
        // its own language). The value is injected into served HTML,
        // so only known tags pass.
        let t = v.trim().to_ascii_lowercase();
        if !t.is_empty() && !UI_LOCALES.contains(&t.as_str()) {
            // List derived from UI_LOCALES so it can't drift as locales are added.
            return Err(format!(
                "ui_locale: one of {} - or empty for auto",
                UI_LOCALES.join(", ")
            ));
        }
        *d.ui_locale.lock_ok() = t.clone();
        (true, json!(t))
    })
}

fn set_index_gapfill(
    d: &Arc<Daemon>,
    name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    let uint = || {
        v.trim()
            .parse::<u64>()
            .map_err(|_| format!("{name}: not a number"))
    };
    Ok({
        // A8: incomplete releases re-hunted per pass; 0 = off.
        let n = uint()?;
        if n > 100 {
            return Err("index_gapfill: 0-100 releases per pass".into());
        }
        d.index_gapfill.store(n, Ordering::Relaxed);
        (true, json!(n))
    })
}

fn set_bench_interval(
    d: &Arc<Daemon>,
    name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    let uint = || {
        v.trim()
            .parse::<u64>()
            .map_err(|_| format!("{name}: not a number"))
    };
    Ok({
        // Hours between scheduled system benchmarks; 0 = off.
        let h = uint()?;
        if h > 720 {
            return Err("bench_interval: 0-720 hours".into());
        }
        d.bench_interval.store(h, Ordering::Relaxed);
        (true, json!(h))
    })
}

fn set_auto_prefetch(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    let flag = || v == "1" || v.eq_ignore_ascii_case("true");
    Ok({
        let on = flag();
        d.auto_prefetch.store(on, Ordering::Relaxed);
        if !on {
            // Turning it off also stops a running sidecar.
            d.poke_sidecar(|_| true);
        }
        (true, json!(on))
    })
}

fn set_race_stragglers(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    let flag = || v == "1" || v.eq_ignore_ascii_case("true");
    Ok({
        // The pool reads the persisted value per job, so this
        // applies from the NEXT download; the atomic is the
        // settings API's live mirror.
        let on = flag();
        d.race_stragglers.store(on, Ordering::Relaxed);
        (true, json!(on))
    })
}

fn set_history_rows(
    d: &Arc<Daemon>,
    name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    let uint = || {
        v.trim()
            .parse::<u64>()
            .map_err(|_| format!("{name}: not a number"))
    };
    Ok({
        // 0 would render an empty card that looks broken; the upper
        // bound is what one page can show before it is a scroll job.
        let n = uint()?;
        if !(1..=200).contains(&n) {
            return Err("history_rows: 1-200".into());
        }
        d.history_rows.store(n, Ordering::Relaxed);
        (true, json!(n))
    })
}

fn set_connections(
    d: &Arc<Daemon>,
    name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    let uint = || {
        v.trim()
            .parse::<u64>()
            .map_err(|_| format!("{name}: not a number"))
    };
    Ok({
        let n = uint()?.clamp(1, 999) as usize;
        d.connections.store(n, Ordering::Relaxed);
        // Raising this number has to be able to beat a stored
        // auto-tune knee, or it is a control that does nothing: a
        // v1.0.14 tester set 22, then 24, restarted, tried a fresh
        // NZB, and every job still ran at the knee of 6 the tuner
        // had measured once. A knee is a measurement taken UNDER a
        // ceiling, so a higher ceiling retires it pending a
        // re-probe. Lowering the number changes nothing here -
        // min(configured, knee) already handles that direction.
        crate::conntune::reopen_for_install(&d.cfg_path, n);
        (true, json!(n))
    })
}

fn set_fast_verify(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    let flag = || v == "1" || v.eq_ignore_ascii_case("true");
    Ok({
        let on = flag();
        d.fast_verify.store(on, Ordering::Relaxed);
        if !on {
            // Full verify supersedes lean - no article-CRC skipping.
            d.verify_lean.store(false, Ordering::Relaxed);
        }
        // This arm moves BOTH fields, so it has to persist both. The
        // caller saves only the key it was handed, and at launch
        // apply_saved_settings applies fast_verify FIRST and then
        // verify_mode, which sets the pair again - so a stale
        // verify_mode left in settings.json reverts this write on
        // every restart, and an install that once chose lean comes
        // back lean after the user asked for full. Read verify_lean
        // after the stores above, never before.
        let mode = match (on, d.verify_lean.load(Ordering::Relaxed)) {
            (false, _) => "full",
            (true, false) => "fast",
            (true, true) => "lean",
        };
        save_setting(&d.settings_path, "verify_mode", json!(mode));
        (true, json!(on))
    })
}

fn set_verify_mode(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        let (fast, lean) = match v.trim() {
            "full" => (false, false),
            "fast" => (true, false),
            "lean" => (true, true),
            _ => return Err("verify_mode must be full, fast, or lean".into()),
        };
        d.fast_verify.store(fast, Ordering::Relaxed);
        d.verify_lean.store(lean, Ordering::Relaxed);
        (true, json!(v.trim()))
    })
}

fn set_out_umask(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        // Empty clears it, which is the documented way back to
        // "whatever the process umask gives" - the state every
        // install starts in.
        let v = v.trim();
        if v.is_empty() {
            d.out_umask.store(u32::MAX, Ordering::Relaxed);
            return Ok((true, json!("")));
        }
        // Octal, and range-checked. A umask outside 0-0777 is not a
        // stricter setting, it is a typo: `0o1000` would wrap into
        // mode bits that mean setuid rather than permission.
        let m = u32::from_str_radix(v, 8)
            .ok()
            .filter(|m| *m <= 0o777)
            .ok_or("out_umask must be an octal umask like 002 or 022")?;
        d.out_umask.store(m, Ordering::Relaxed);
        (true, json!(format!("{m:03o}")))
    })
}

fn set_auto_retry_mins(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        let m = v
            .trim()
            .parse::<u64>()
            .map_err(|_| "auto_retry_mins must be a number")?;
        d.auto_retry_secs.store(m * 60, Ordering::Relaxed);
        (true, json!(m))
    })
}

fn set_quota_period(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        let p = match v.trim() {
            "d" | "D" => b'd',
            "m" | "M" => b'm',
            _ => return Err("quota_period must be d or m".into()),
        };
        d.quota_period.store(p, Ordering::Relaxed);
        (true, json!((p as char).to_string()))
    })
}

fn set_watch(d: &Arc<Daemon>, _name: &str, v: &str) -> std::result::Result<(bool, Value), String> {
    Ok({
        let p = v.trim();
        if !p.is_empty() {
            let _ = std::fs::create_dir_all(p);
        }
        *d.watch_dir.lock_ok() = (!p.is_empty()).then(|| PathBuf::from(p));
        (true, json!(p))
    })
}

fn set_schedule(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        let text = v.trim().to_string();
        if text.is_empty() {
            d.schedule.lock_ok().clear();
            d.schedule_text.lock_ok().clear();
        } else {
            let entries = parse_schedule(&text).map_err(|e| e.to_string())?;
            // Re-evaluate the week immediately, exactly like startup:
            // if the new schedule implies paused/limited NOW, apply it.
            let (paused, limit) = effective_state(&entries, local_minute_of_week());
            // Through the one mutator, so this route cancels a pending
            // timed pause too. Otherwise identical: the pause leg
            // already wound the transfer down here.
            if let Some(p) = paused {
                apply_action(
                    d,
                    if p {
                        SchedAction::Pause
                    } else {
                        SchedAction::Resume
                    },
                );
            }
            if let Some(l) = limit {
                d.set_speed_ceiling_from(l, "schedule");
            }
            *d.schedule.lock_ok() = entries;
            *d.schedule_text.lock_ok() = text.clone();
        }
        (true, json!(text))
    })
}

fn set_library_cats(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        let cats: Vec<String> = v
            .split(',')
            .map(str::trim)
            .filter(|c| !c.is_empty())
            .map(str::to_string)
            .collect();
        *d.library_cats.lock_ok() = cats.clone();
        (true, json!(cats))
    })
}

fn set_index_groups(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        let groups: Vec<String> = v
            .split(',')
            .map(str::trim)
            .filter(|g| !g.is_empty())
            .map(str::to_string)
            .collect();
        *d.index_groups.lock_ok() = groups.clone();
        (true, json!(groups))
    })
}

#[cfg(feature = "indexer")]
fn set_index_interests(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        // Comma list of interest keys (crate::interests). Unknown
        // keys are dropped, not rejected: the stored value must
        // survive a downgrade, and the failure direction that
        // matters is "indexed something nobody asked for".
        let keys = crate::interests::parse(v);
        let norm = keys.join(",");
        *d.index_interests.lock_ok() = norm.clone();
        // Resolve now if the catalogue is already here; otherwise
        // apply_interests asks for one and the fetch applies it.
        apply_interests(d);
        (true, json!(norm))
    })
}

fn set_delete_to_trash(
    _d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    let flag = || v == "1" || v.eq_ignore_ascii_case("true");
    Ok({
        // Cleanup deletes go to the Trash so a wrong guess by the
        // junk heuristics is recoverable. On by default on macOS and
        // Windows, where the Trash is a place the user can see and
        // empty; off by default on Linux, where it is not - see
        // `trash_suits_this_platform`. Off means a permanent delete.
        let on = flag();
        crate::smart::set_delete_to_trash(on);
        (true, json!(on))
    })
}

fn set_watch_interval_secs(
    d: &Arc<Daemon>,
    name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    let uint = || {
        v.trim()
            .parse::<u64>()
            .map_err(|_| format!("{name}: not a number"))
    };
    Ok({
        // The filesystem watcher already makes a local drop instant,
        // so this is the fallback rate for shares it cannot see.
        // Floored at 1 s: below that it is a directory listing per
        // frame for no gain, since the watcher covers the fast case.
        let n = uint()?.clamp(1, 3600);
        d.watch_interval_secs.store(n, Ordering::Relaxed);
        d.watch_scan_now.notify_one();
        (true, json!(n))
    })
}

fn set_index_tip_secs(
    d: &Arc<Daemon>,
    name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    let uint = || {
        v.trim()
            .parse::<u64>()
            .map_err(|_| format!("{name}: not a number"))
    };
    Ok({
        // 0 = off. Otherwise floor at 5 s: the tick costs one GROUP
        // command per group when nothing has arrived, but there is
        // no reason to spin faster than posts appear.
        let n = uint()?;
        let n = if n == 0 { 0 } else { n.max(5) };
        d.index_tip_secs.store(n, Ordering::Relaxed);
        (true, json!(n))
    })
}

fn set_nested_max_depth(
    _d: &Arc<Daemon>,
    name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    let uint = || {
        v.trim()
            .parse::<u64>()
            .map_err(|_| format!("{name}: not a number"))
    };
    Ok({
        // Depth cap for nested (RAR/7z-in-archive) extraction, shared
        // by the in-stream child chain and the disk post-pass. At the
        // cap the deepest layer materializes - never a failed job.
        // Applies to downloads started after the change.
        let n = uint()?.clamp(1, 64);
        nzbkit::extract::set_nested_depth_cap(n as usize);
        (true, json!(n))
    })
}

fn set_predb_enabled(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        let on = v == "1" || v.eq_ignore_ascii_case("true");
        let was = d.predb_enabled.swap(on, Ordering::Relaxed);
        if on != was {
            // The listener polls this flag; say what changed rather
            // than leaving an outbound connection to appear in
            // somebody's firewall log unexplained.
            *d.predb_status.lock_ok() = String::new();
            if on {
                info!(
                    target: "predb",
                    "pre feed ON - connecting to {} and listening on {}",
                    d.predb_server.lock_ok(),
                    d.predb_channels.lock_ok()
                );
            } else {
                info!(target: "predb", "pre feed off - the connection closes and nothing is fetched");
            }
        }
        (true, json!(on))
    })
}

fn set_predb_corr_enabled(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        let on = v == "1" || v.eq_ignore_ascii_case("true");
        let was = d.predb_corr_enabled.swap(on, Ordering::Relaxed);
        if on != was {
            info!(
                target: "predb",
                "correlation {} - obfuscated posts {} suggested names from pre timing+size",
                if on { "ON" } else { "off" },
                if on { "get" } else { "no longer get" }
            );
        }
        (true, json!(on))
    })
}

fn set_predb_corr_auto(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        let on = v == "1" || v.eq_ignore_ascii_case("true");
        let was = d.predb_corr_auto.swap(on, Ordering::Relaxed);
        if on != was {
            info!(
                target: "predb",
                "auto-apply {} - strong unique correlations {}",
                if on { "ON" } else { "off" },
                if on {
                    "become display names without a click (revocable, never renames files)"
                } else {
                    "stay suggestions"
                }
            );
        }
        (true, json!(on))
    })
}

#[cfg(feature = "indexer")]
fn set_predb_max_rows(
    d: &Arc<Daemon>,
    name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    let uint = || {
        v.trim()
            .parse::<u64>()
            .map_err(|_| format!("{name}: not a number"))
    };
    Ok({
        // Clamped rather than rejected: this is a capacity knob, and
        // a number outside the sane range is a typo, not a request.
        let n = uint()?.clamp(
            super::predb_seed::PREDB_MAX_ROWS_MIN,
            super::predb_seed::PREDB_MAX_ROWS_MAX,
        );
        d.predb_max_rows.store(n, Ordering::Relaxed);
        info!(target: "predb", "feed table capped at {n} pre row(s)");
        (true, json!(n))
    })
}

fn set_predb_server(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        // `host` or `host:port`. Validated only for shape: the set of
        // networks carrying a relay is not ours to enumerate.
        let s = v.trim().to_string();
        if s.contains(char::is_whitespace) {
            return Err("predb_server: expected a host or host:port".into());
        }
        if let Some((_, port)) = s.rsplit_once(':')
            && port.parse::<u16>().is_err()
        {
            return Err("predb_server: the part after ':' must be a port number".into());
        }
        *d.predb_server.lock_ok() = if s.is_empty() {
            nzbkit::predb::DEFAULT_HOST.to_string()
        } else {
            s.clone()
        };
        (true, json!(d.predb_server.lock_ok().clone()))
    })
}

fn set_predb_channels(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        let chans: Vec<String> = v
            .split(',')
            .map(str::trim)
            .filter(|c| !c.is_empty())
            // A channel name may not contain a space, a comma or a
            // control character - a malformed one would be sent
            // verbatim in a JOIN, which is the one place this client
            // writes to somebody else's server.
            .map(|c| {
                c.chars()
                    .filter(|ch| !ch.is_whitespace() && !ch.is_control() && *ch != ',')
                    .collect::<String>()
            })
            .filter(|c| !c.is_empty())
            .collect();
        let joined = if chans.is_empty() {
            nzbkit::predb::DEFAULT_CHANNELS.join(",")
        } else {
            chans.join(",")
        };
        *d.predb_channels.lock_ok() = joined.clone();
        (true, json!(joined))
    })
}

fn set_predb_nick(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        // Nick charset per RFC 2812, minus the leading-digit rule
        // (the random suffix is appended, so the base only has to be
        // safe). Empty falls back to the default rather than sending
        // a bare suffix.
        let n: String = v
            .trim()
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || "[]\\`_^{|}-".contains(*c))
            .take(12)
            .collect();
        let n = if n.is_empty() {
            nzbkit::predb::DEFAULT_NICK.to_string()
        } else {
            n
        };
        *d.predb_nick.lock_ok() = n.clone();
        (true, json!(n))
    })
}

fn set_index_paused(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        let on = v == "1" || v.eq_ignore_ascii_case("true");
        d.index_paused.store(on, Ordering::Relaxed);
        // Resuming should not wait out the rest of the interval -
        // the user just asked for it.
        if !on {
            d.scan_now.notify_one();
        }
        (true, json!(on))
    })
}

#[cfg(feature = "indexer")]
fn set_index_enabled(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        let on = v == "1" || v.eq_ignore_ascii_case("true");
        d.index_enabled.store(on, Ordering::Relaxed);
        if on {
            // Switching on mid-run: turn any interests the wizard
            // recorded into groups (a no-op if that already
            // happened) and scan straight away rather than after a
            // full interval of an empty wall.
            apply_interests(d);
            d.scan_now.notify_one();
            info!(target: "index", "indexer switched on");
        } else {
            // Order matters: stop the workers reaching for the
            // database before closing it, so the next `with_index`
            // cannot re-open what we just dropped. The atomic above
            // is what both of those read.
            d.close_index();
            info!(target: "index", "indexer switched off - nothing is scanned, fetched or stored");
        }
        (true, json!(on))
    })
}

#[cfg(feature = "indexer")]
fn set_spot_enabled(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        let on = v == "1" || v.eq_ignore_ascii_case("true");
        d.spot_enabled.store(on, Ordering::Relaxed);
        if on {
            // Same reasoning as the indexer switch: scan now rather
            // than after a full interval of an empty list.
            d.scan_now.notify_one();
            info!(target: "spots", "Spotnet spots switched on");
        } else {
            // A no-op while the indexer still wants the database.
            d.close_index();
            info!(target: "spots", "Spotnet spots switched off - no spot group is scanned");
        }
        (true, json!(on))
    })
}

fn set_spot_groups(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        let groups: Vec<String> = v
            .split(&[',', ' ', '\n'][..])
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        *d.spot_groups.lock_ok() = groups.clone();
        d.scan_now.notify_one();
        (true, json!(groups))
    })
}

fn set_spot_backfill(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        // A first pass walks back this many articles; later passes
        // resume from the high-water mark, so this only ever costs
        // once per group. Capped: free.pt holds ~4.4M articles and
        // asking for all of them is minutes of OVER for spots that
        // are years stale.
        let n: u64 = v
            .trim()
            .parse()
            .map_err(|_| "spot_backfill: expected a number".to_string())?;
        let n = n.clamp(1_000, 1_000_000);
        d.spot_backfill.store(n, Ordering::Relaxed);
        (true, json!(n))
    })
}

#[cfg(feature = "indexer")]
fn set_index_evict_order(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        let o = v.trim().to_ascii_lowercase();
        if parse_evict_order(&o).is_none() {
            return Err(format!(
                "index_evict_order: expected one of {}",
                EVICT_ORDERS.join(", ")
            ));
        }
        *d.index_evict_order.lock_ok() = o.clone();
        (true, json!(o))
    })
}

#[cfg(feature = "indexer")]
fn set_index_evict_kinds(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        // Restriction list, not an exclusion list: empty = every
        // kind may be evicted. Validated because a typo would
        // restrict eviction to a kind no row carries, leaving a cap
        // that silently never frees a byte.
        let kinds = parse_evict_kinds(v).map_err(|e| format!("index_evict_kinds: {e}"))?;
        *d.index_evict_kinds.lock_ok() = kinds.clone();
        (true, json!(kinds))
    })
}

fn set_index_evict(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        // The one switch that lets the daemon delete indexed rows on
        // its own. Default OFF and it stays off until the user says
        // otherwise - see the field doc on Daemon::index_evict.
        let on = v == "1" || v.eq_ignore_ascii_case("true");
        d.index_evict.store(on, Ordering::Relaxed);
        if on {
            let cap = d.index_max_bytes.load(Ordering::Relaxed);
            info!(
                target: "index",
                "automatic eviction ON{}",
                if cap == 0 {
                    " - but index_max_bytes is 0 (unlimited), so nothing will be evicted"
                        .to_string()
                } else {
                    format!(" - cap {:.0} MB", cap as f64 / (1u64 << 20) as f64)
                }
            );
        }
        (true, json!(on))
    })
}

#[cfg(feature = "indexer")]
fn set_index_gates(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        let text = v.trim().to_string();
        let parsed = if text.is_empty() {
            None
        } else {
            Some(crate::gates::Gates::from_json(&text).map_err(|e| format!("gates: {e}"))?)
        };
        *d.index_gates.lock_ok() = (text.clone(), parsed);
        (true, json!(text))
    })
}

fn set_apikey(d: &Arc<Daemon>, _name: &str, v: &str) -> std::result::Result<(bool, Value), String> {
    Ok({
        let k = v.trim().to_string();
        *d.apikey.lock_ok() = (!k.is_empty()).then(|| k.clone());
        // settings.json and the key file are both siblings of the
        // config (see settings_file / first_run_apikey).
        let keyfile = d.settings_path.with_file_name("apikey");
        if k.is_empty() {
            match std::fs::remove_file(&keyfile) {
                Ok(()) => {
                    info!(target: "config", "apikey cleared - removed {}", keyfile.display())
                }
                // Nothing to remove: the key came from --apikey, a
                // hand-written settings.json, or a container env.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                // Best-effort, as everywhere else in here: never fail
                // a live setting on an IO error. But say so - the key
                // WILL come back on the next start, and a silent
                // failure here is the exact bug being fixed.
                Err(e) => warn!(
                    target: "settings",
                    "⚠ cleared the API key but could not remove {} ({e}) - it will be read \
                     back on the next start. Delete that file to stay keyless.",
                    keyfile.display()
                ),
            }
        } else {
            // Setting a key puts the file BACK. Clearing removes it,
            // so clear-then-rekey used to leave settings.json keyed
            // and no key file at all - which the daemon itself does
            // not mind (settings.json wins at load, and
            // first_run_apikey only reads the file when no key is
            // set, so the duplicate is harmless), but the container
            // entrypoint reads the file to decide whether an
            // established install is about to publish the control
            // API keyless. With the file gone it refused to start,
            // and the container could not be restarted at all.
            //
            // Best-effort like the removal above: never fail a live
            // setting on an IO error, but do say so.
            if let Err(e) = crate::persist::write_atomic(&keyfile, k.as_bytes()) {
                warn!(
                    target: "settings",
                    "⚠ set the API key but could not write {} ({e}) - the key itself is \
                     live and saved in Settings; a container may refuse to restart until \
                     that file can be written.",
                    keyfile.display()
                );
            }
        }
        (true, if k.is_empty() { Value::Null } else { json!(k) })
    })
}

fn set_feeds(d: &Arc<Daemon>, _name: &str, v: &str) -> std::result::Result<(bool, Value), String> {
    Ok({
        // JSON array of {url, interval_secs, category, rules}; the
        // poller picks the new list up on its next 30 s pass.
        let text = v.trim();
        let list: Vec<crate::rss::FeedConfig> = if text.is_empty() {
            Vec::new()
        } else {
            serde_json::from_str(text).map_err(|e| format!("feeds: {e}"))?
        };
        let persist = serde_json::to_value(&list).unwrap_or(json!([]));
        *d.feeds.lock_ok() = list;
        (true, persist)
    })
}

fn set_indexers(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        // M35: JSON array of newznab::IndexerConfig. A blank apikey
        // in an entry keeps the stored key of the same-named entry
        // (get_config never echoes keys, so the UI round-trips
        // blanks); renaming an entry and blanking its key in the
        // same edit drops the key, which is the honest reading.
        let text = v.trim();
        let mut list: Vec<crate::newznab::IndexerConfig> = if text.is_empty() {
            Vec::new()
        } else {
            serde_json::from_str(text).map_err(|e| format!("indexers: {e}"))?
        };
        {
            let cur = d.indexers.lock_ok();
            for i in list.iter_mut() {
                i.name = i.name.trim().to_string();
                i.url = i.url.trim().to_string();
                if i.apikey.is_empty()
                    && let Some(old) = cur.iter().find(|o| o.name == i.name)
                {
                    i.apikey = old.apikey.clone();
                }
            }
        }
        let mut seen = std::collections::HashSet::new();
        for i in &list {
            if i.name.is_empty() || i.url.is_empty() {
                return Err("indexers: every entry needs a name and a URL".into());
            }
            if !(i.url.starts_with("http://") || i.url.starts_with("https://")) {
                return Err(format!("indexers: {}: the URL must be http(s)", i.name));
            }
            if !seen.insert(i.name.clone()) {
                return Err(format!("indexers: duplicate name {}", i.name));
            }
        }
        let persist = serde_json::to_value(&list).unwrap_or(json!([]));
        *d.indexers.lock_ok() = list;
        (true, persist)
    })
}

fn set_watchlist_external(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    let flag = || v == "1" || v.eq_ignore_ascii_case("true");
    Ok({
        // M35 phase 2: let the watcher ask the user's indexer
        // accounts for wanted items. Each item then spends at most
        // one search per WATCH_EXT_INTERVAL_SECS, and per-indexer
        // daily budgets still apply on top.
        //
        // M35b: writing here is the user ANSWERING, which pins the
        // value against the indexers-configured default - including
        // an explicit off, which must survive adding an indexer.
        d.watchlist_external.store(flag(), Ordering::Relaxed);
        d.watchlist_external_set.store(true, Ordering::Relaxed);
        (true, json!(d.watchlist_external.load(Ordering::Relaxed)))
    })
}

fn set_watchlist_instant(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    let flag = || v == "1" || v.eq_ignore_ascii_case("true");
    Ok({
        // §74: grab a watched release as it ARRIVES rather than at
        // the next periodic pass. Nothing to arm or disarm here - the
        // arrival hooks read the flag each time - and with the
        // built-in indexer off there are no arrivals to react to, so
        // this is inert rather than wrong on an index-less install.
        d.watchlist_instant.store(flag(), Ordering::Relaxed);
        (true, json!(d.watchlist_instant.load(Ordering::Relaxed)))
    })
}

fn set_watchlist_instant_max(
    d: &Arc<Daemon>,
    name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    let uint = || {
        v.trim()
            .parse::<u64>()
            .map_err(|_| format!("{name}: not a number"))
    };
    Ok({
        // §74: instant passes per hour, 0 = no limit. Capped well
        // above any sane value rather than validated tightly: over
        // the ceiling the periodic pass still grabs everything a
        // minute later, so a silly number costs churn, not downloads.
        let n = uint()?.min(3600) as u32;
        d.watchlist_instant_max.store(n, Ordering::Relaxed);
        (true, json!(n))
    })
}

fn set_watchlist(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        // JSON array of watchlist::WatchItem; an edit wakes the
        // watcher so adds are checked against the index at once.
        let text = v.trim();
        let list: Vec<crate::watchlist::WatchItem> = if text.is_empty() {
            Vec::new()
        } else {
            serde_json::from_str(text).map_err(|e| format!("watchlist: {e}"))?
        };
        let persist = serde_json::to_value(&list).unwrap_or(json!([]));
        *d.watchlist.lock_ok() = list;
        d.watch_now.notify_one();
        (true, persist)
    })
}

fn set_smart_folders(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        // M23: JSON array of rules; every enqueue from now on runs
        // through the new list (first match wins).
        let text = v.trim();
        let list: Vec<crate::smart::Rule> = if text.is_empty() {
            Vec::new()
        } else {
            serde_json::from_str(text).map_err(|e| format!("smart_folders: {e}"))?
        };
        let persist = serde_json::to_value(&list).unwrap_or(json!([]));
        *d.smart_folders.lock_ok() = list;
        (true, persist)
    })
}

fn set_password_file(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        // Path to the SAB/NZBGet-compatible passwords file (one per
        // line). Empty resets to the default next to the config.
        // Created immediately if missing so the path the UI shows
        // is never a dangling promise; contents are read fresh per
        // unlock, so this is live.
        let p = v.trim();
        let path = if p.is_empty() {
            d.cfg_path.with_file_name("passwords.txt")
        } else {
            std::path::PathBuf::from(p)
        };
        if !path.exists() {
            crate::persist::write_atomic(&path, b"")
                .map_err(|e| format!("password_file: cannot create {}: {e}", path.display()))?;
        }
        *d.password_file.lock_ok() = path.clone();
        *d.hub.unpack_password_file.lock_ok() = Some(path.clone());
        (true, json!(path.to_string_lossy()))
    })
}

fn set_password_prompt(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        // now | done | never - what the dashboard does when an
        // archive turns out passworded ("never" also changes the
        // completion shape: left packed, no failure text).
        let m = v.trim().to_ascii_lowercase();
        if !matches!(m.as_str(), "now" | "done" | "never") {
            return Err("password_prompt must be now, done or never".into());
        }
        *d.password_prompt.lock_ok() = m.clone();
        (true, json!(m))
    })
}

fn set_unpack_eat_volumes(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        // TODO 101. off | low_disk | always. Live: the decision is
        // taken per job, at the moment its disk unpack is about to
        // start, so a change here applies to the very next unpack -
        // including one already downloading.
        let m = v.trim().to_ascii_lowercase();
        let Some(mode) = crate::eatvol::EatMode::parse(&m) else {
            return Err("unpack_eat_volumes must be off, low_disk or always".into());
        };
        *d.unpack_eat_volumes.lock_ok() = mode.as_str().to_string();
        crate::eatvol::set_mode(mode);
        (true, json!(mode.as_str()))
    })
}

fn set_fast_par(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    let flag = || v == "1" || v.eq_ignore_ascii_case("true");
    Ok({
        // "Fast PAR mode": heavy repairs take the NTT syndrome path.
        // Live - the flag is read per repair. NZBFAST_NTT in the
        // daemon's environment overrides it inside nzbkit.
        let on = flag();
        d.fast_par.store(on, Ordering::Relaxed);
        nzbkit::par2repair::set_fast_par_enabled(on);
        (true, json!(on))
    })
}

fn set_prefer_external_unrar(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    let flag = || v == "1" || v.eq_ignore_ascii_case("true");
    Ok({
        // Live for any unpack that has not started: the disk-path
        // engine choice reads it per unpack, the top-level RAR
        // chase latches it per job. No daemon restart needed.
        let on = flag();
        d.prefer_external_unrar.store(on, Ordering::Relaxed);
        nzbkit::extract::set_prefer_external_unrar(on);
        (true, json!(on))
    })
}

fn set_custom_categories(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        // TODO 24D: JSON array of user categories (slug, name, match
        // rules, base behavior). Validated as a whole - a reserved or
        // duplicate slug rejects the save. On change the scan loop
        // runs a chunked re-classification pass over stored rows.
        let text = v.trim();
        let list: Vec<nzbkit::categories::CustomCategory> = if text.is_empty() {
            Vec::new()
        } else {
            serde_json::from_str(text).map_err(|e| format!("custom_categories: {e}"))?
        };
        nzbkit::categories::validate(&list).map_err(|e| format!("custom_categories: {e}"))?;
        let persist = serde_json::to_value(&list).unwrap_or(json!([]));
        *d.custom_categories.write_ok() = list;
        d.reclassify_pending.store(true, Ordering::Relaxed);
        (true, persist)
    })
}

fn set_failure_link(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        // off | report | regrab. See Daemon::report_failure.
        let m = v.trim().to_ascii_lowercase();
        if !matches!(m.as_str(), "off" | "report" | "regrab") {
            return Err("failure_link must be off, report or regrab".into());
        }
        *d.failure_link.lock_ok() = m.clone();
        (true, json!(m))
    })
}

fn set_prefer_quality(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        // {"res":"2160p","vcodec":"x265","acodec":"Atmos","hdr":"DV"},
        // any field omitted or "" meaning no opinion. Validated here
        // so a typo is a visible error rather than a preference that
        // silently never matches anything.
        let p = crate::watchlist::QualityPrefs::from_json(v)
            .map_err(|e| format!("prefer_quality: {e}"))?;
        let stored = p.to_json();
        *d.quality_prefs.lock_ok() = p;
        (true, stored)
    })
}

fn set_notify_targets(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        // JSON array of media servers / webhooks told about every
        // finished job. Applies to the next completion.
        let text = v.trim();
        let mut list: Vec<crate::notify::Target> = if text.is_empty() {
            Vec::new()
        } else {
            serde_json::from_str(text).map_err(|e| format!("notify_targets: {e}"))?
        };
        // get_config never hands the token back (it is a credential),
        // so the dashboard - which rebuilds this whole list from the
        // DOM and replaces it wholesale - submits a blank one for
        // every unchanged row. Blank means KEEP: carry the stored
        // token forward. Matched on (kind, url, name), not on
        // position: rows get reordered and deleted between the load
        // and the save, and an index match would hand one target's
        // credential to another.
        {
            let old = d.notify_targets.lock_ok().clone();
            merge_notify_tokens(&mut list, &old);
        }
        let persist = serde_json::to_value(&list).unwrap_or(json!([]));
        *d.notify_targets.lock_ok() = list;
        (true, persist)
    })
}

fn set_arr_giveup_threshold(
    d: &Arc<Daemon>,
    name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    let uint = || {
        v.trim()
            .parse::<u64>()
            .map_err(|_| format!("{name}: not a number"))
    };
    Ok({
        // §96.3: distinct failed releases per target before the
        // give-up fires. 0 = off. Capped loosely - a huge value is a
        // breaker that never trips, which is just "off" spelt long.
        let n = uint()?.min(1000);
        d.arr_giveup_threshold.store(n, Ordering::Relaxed);
        (true, json!(n))
    })
}

fn set_arr_instances(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        // §96.3: JSON array of {name, kind, url, apikey, enabled}.
        // Validated as a whole - a typo'd kind would otherwise be an
        // instance the breaker silently never acts on.
        let text = v.trim();
        let mut list: Vec<super::giveup::ArrInstance> = if text.is_empty() {
            Vec::new()
        } else {
            serde_json::from_str(text).map_err(|e| format!("arr_instances: {e}"))?
        };
        for i in &list {
            if !matches!(i.kind.as_str(), "sonarr" | "radarr") {
                return Err(format!(
                    "arr_instances: kind must be sonarr or radarr, not {:?}",
                    i.kind
                ));
            }
            let u = i.url.trim();
            if !(u.starts_with("http://") || u.starts_with("https://")) {
                return Err("arr_instances: url must start with http:// or https://".into());
            }
        }
        // get_config never hands the apikey back, so a UI that
        // round-trips the list submits a blank one for every
        // unchanged row. Blank means KEEP: carried forward from the
        // stored instance at the same (kind, url), or failing that
        // the same (kind, name) - correcting a typo'd host must not
        // throw the key away.
        {
            let old = d.arr_instances.lock_ok().clone();
            for i in list.iter_mut().filter(|i| i.apikey.is_empty()) {
                if let Some(o) = old
                    .iter()
                    .find(|o| o.kind == i.kind && o.url == i.url)
                    .or_else(|| old.iter().find(|o| o.kind == i.kind && o.name == i.name))
                {
                    i.apikey = o.apikey.clone();
                }
            }
        }
        let persist = serde_json::to_value(&list).unwrap_or(json!([]));
        *d.arr_instances.lock_ok() = list;
        (true, persist)
    })
}

fn set_port(d: &Arc<Daemon>, name: &str, v: &str) -> std::result::Result<(bool, Value), String> {
    let uint = || {
        v.trim()
            .parse::<u64>()
            .map_err(|_| format!("{name}: not a number"))
    };
    Ok({
        let p = uint()?;
        if !(1..=65535).contains(&p) {
            return Err("port must be 1-65535".into());
        }
        // Refused, not silently ignored: saving a port this
        // installation will never bind is how a container ends up
        // unreachable through its published mapping with the UI still
        // claiming the change took.
        if d.port_locked {
            return Err(
                "this installation's port is set by how it was started (a container's \
                     published port, or the Synology package's own setting), so it can't be \
                     changed here. Change it where the port is published instead."
                    .into(),
            );
        }
        (false, json!(p))
    })
}

fn set_out_dir(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        let p = v.trim();
        if p.is_empty() {
            return Err("out_dir can't be empty".into());
        }
        let path = PathBuf::from(p);
        // Create it if missing so a hand-typed path isn't a dead setting,
        // and fail loudly if we can't - better than silently pointing the
        // downloads at a folder that won't accept them.
        std::fs::create_dir_all(&path).map_err(|e| format!("can't use {p}: {e}"))?;
        if !path_writable(&path) {
            return Err(format!("{p} is not writable"));
        }
        // LIVE: the next enqueue builds its job directory from here. The
        // spool (queue journal / usage / art) was fixed at startup and
        // deliberately does NOT move, so in-flight state is never stranded.
        *d.out_root.write_ok() = path;
        (true, json!(p))
    })
}

fn set_move_completed(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        // M33: post-completion destination (NAS share etc.). Empty
        // clears it - downloads then stay under out_dir.
        let p = v.trim();
        if p.is_empty() {
            *d.move_completed.write_ok() = None;
            (true, json!(""))
        } else {
            let path = PathBuf::from(p);
            require_absolute_dest(&path)?;
            std::fs::create_dir_all(&path).map_err(|e| format!("can't use {p}: {e}"))?;
            if !path_writable(&path) {
                return Err(format!("{p} is not writable"));
            }
            if same_dir(&path, &d.out_root.read_ok()) {
                return Err(
                    "move_completed is the download folder itself - nothing to move".into(),
                );
            }
            *d.move_completed.write_ok() = Some(path);
            (true, json!(p))
        }
    })
}

fn set_move_completed_cats(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        // M33 v2: "tv=/NAS/TV, movies=/NAS/Movies". Empty clears.
        let list = parse_cat_dests(v)?;
        for (_, path) in &list {
            let p = path.display();
            require_absolute_dest(path)?;
            std::fs::create_dir_all(path).map_err(|e| format!("can't use {p}: {e}"))?;
            if !path_writable(path) {
                return Err(format!("{p} is not writable"));
            }
            // The global destination has always been refused when it
            // is the download folder; the per-category ones were not
            // checked at all, and they reach the same move_tree.
            if same_dir(path, &d.out_root.read_ok()) {
                return Err(format!(
                    "{p} is the download folder itself - nothing to move"
                ));
            }
        }
        let echo = fmt_cat_dests(&list);
        *d.move_completed_cats.write_ok() = list;
        (true, json!(echo))
    })
}

fn set_categories(
    d: &Arc<Daemon>,
    _name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    Ok({
        // "tv, movies, sonarr". The built-ins are a floor, not a
        // starting point: a client already configured against one
        // must not stop resolving because the list was edited.
        // Each name is sanitised to the single path component it
        // becomes under the download root.
        let mut set: std::collections::BTreeSet<String> =
            DEFAULT_CATS.iter().map(|s| s.to_string()).collect();
        for raw in v.split(',') {
            let name = raw.trim();
            if name.is_empty() || name == "*" {
                continue;
            }
            let clean = nzbkit::disk::sanitize_filename(name);
            if clean.is_empty() {
                return Err(format!("{name:?} is not a usable category name"));
            }
            set.insert(clean);
        }
        *d.cats.lock_ok() = set;
        (true, json!(d.cat_list()))
    })
}

pub(super) fn apply_setting(
    d: &Arc<Daemon>,
    name: &str,
    v: &str,
) -> std::result::Result<(bool, Value), String> {
    let uint = || {
        v.trim()
            .parse::<u64>()
            .map_err(|_| format!("{name}: not a number"))
    };
    let size = || parse_size(v).ok_or_else(|| format!("{name}: bad size (e.g. 4M, 10G, 0 = off)"));
    let flag = || v == "1" || v.eq_ignore_ascii_case("true");
    Ok(match name {
        "speedlimit" => set_speedlimit(d, name, v)?,
        "line_speed" => {
            let b = size()?;
            d.line_speed.store(b, Ordering::Relaxed);
            (true, json!(b))
        }
        "auto_speed" => set_auto_speed(d, name, v)?,
        "auto_defer" => {
            let on = flag();
            d.auto_defer.store(on, Ordering::Relaxed);
            (true, json!(on))
        }
        "post_health" => {
            let on = flag();
            d.post_health.store(on, Ordering::Relaxed);
            (true, json!(on))
        }
        "post_health_defer" => {
            let on = flag();
            d.post_health_defer.store(on, Ordering::Relaxed);
            (true, json!(on))
        }
        "wall_hide_adult" => {
            let on = flag();
            d.wall_hide_adult.store(on, Ordering::Relaxed);
            (true, json!(on))
        }
        "auto_connections" => {
            let on = flag();
            d.auto_connections.store(on, Ordering::Relaxed);
            (true, json!(on))
        }
        "update_checks" => {
            let on = flag();
            d.update_checks.store(on, Ordering::Relaxed);
            (true, json!(on))
        }
        "unit_bits" => {
            let on = flag();
            d.unit_bits.store(on, Ordering::Relaxed);
            (true, json!(on))
        }
        "update_url" => set_update_url(d, name, v)?,
        "ui_locale" => set_ui_locale(d, name, v)?,
        "index_deepen" => {
            // Articles of history added per scan pass; 0 = off.
            let n = uint()?;
            d.index_deepen.store(n, Ordering::Relaxed);
            (true, json!(n))
        }
        "index_coverage" => {
            // A8: scan the other backbones' tips too (their own marks).
            d.index_coverage.store(flag(), Ordering::Relaxed);
            (true, json!(d.index_coverage.load(Ordering::Relaxed)))
        }
        "index_gapfill" => set_index_gapfill(d, name, v)?,
        "bench_interval" => set_bench_interval(d, name, v)?,
        "auto_prefetch" => set_auto_prefetch(d, name, v)?,
        "race_stragglers" => set_race_stragglers(d, name, v)?,
        "adaptive_timeouts" => {
            // Same per-job read as race_stragglers: applies from the
            // NEXT download; the atomic is the live mirror.
            let on = flag();
            d.adaptive_timeouts.store(on, Ordering::Relaxed);
            (true, json!(on))
        }
        "oracle_route" => {
            // Applies from the NEXT download (the snapshot is installed at
            // job launch).
            d.oracle_route.store(flag(), Ordering::Relaxed);
            (true, json!(d.oracle_route.load(Ordering::Relaxed)))
        }
        "auto_rename" => {
            let on = flag();
            d.auto_rename.store(on, Ordering::Relaxed);
            (true, json!(on))
        }
        "identity_lookup" => {
            let on = flag();
            d.identity_lookup.store(on, Ordering::Relaxed);
            (true, json!(on))
        }
        "rename_resolution" => {
            let on = flag();
            d.rename_resolution.store(on, Ordering::Relaxed);
            (true, json!(on))
        }
        "rename_vcodec" => {
            let on = flag();
            d.rename_vcodec.store(on, Ordering::Relaxed);
            (true, json!(on))
        }
        "rename_acodec" => {
            let on = flag();
            d.rename_acodec.store(on, Ordering::Relaxed);
            (true, json!(on))
        }
        "rename_source" => {
            let on = flag();
            d.rename_source.store(on, Ordering::Relaxed);
            (true, json!(on))
        }
        "rename_group" => {
            let on = flag();
            d.rename_group.store(on, Ordering::Relaxed);
            (true, json!(on))
        }
        "rename_year_parens" => {
            let on = flag();
            d.rename_year_parens.store(on, Ordering::Relaxed);
            (true, json!(on))
        }
        "rename_quality_brackets" => {
            let on = flag();
            d.rename_quality_brackets.store(on, Ordering::Relaxed);
            (true, json!(on))
        }
        "rename_extra_words" => {
            let on = flag();
            d.rename_extra_words.store(on, Ordering::Relaxed);
            (true, json!(on))
        }
        "rename_identify" => {
            let on = flag();
            d.rename_identify.store(on, Ordering::Relaxed);
            (true, json!(on))
        }
        "rename_episode_titles" => {
            let on = flag();
            d.rename_episode_titles.store(on, Ordering::Relaxed);
            (true, json!(on))
        }
        "script_timeout_secs" => {
            let n: u64 = v.trim().parse().map_err(|_| {
                "script_timeout_secs: a number of seconds, 0 = no limit".to_string()
            })?;
            d.script_timeout.store(n, Ordering::Relaxed);
            (true, json!(n))
        }
        "history_rows" => set_history_rows(d, name, v)?,
        "history_color_names" => {
            let on = flag();
            d.history_color_names.store(on, Ordering::Relaxed);
            (true, json!(on))
        }
        "media_chip_color" => {
            let on = flag();
            d.media_chip_color.store(on, Ordering::Relaxed);
            (true, json!(on))
        }
        "shape_chip_color" => {
            let on = flag();
            d.shape_chip_color.store(on, Ordering::Relaxed);
            (true, json!(on))
        }
        "rename_junk" => {
            let on = flag();
            d.rename_junk.store(on, Ordering::Relaxed);
            (true, json!(on))
        }
        "rename_media_only" => {
            let on = flag();
            d.rename_media_only.store(on, Ordering::Relaxed);
            (true, json!(on))
        }
        "connections" => set_connections(d, name, v)?,
        "window" => {
            let n = uint()?.clamp(1, 64) as usize;
            d.window.store(n, Ordering::Relaxed);
            (true, json!(n))
        }
        "decoders" => {
            let n = uint()?.clamp(1, 128) as usize;
            d.decoders.store(n, Ordering::Relaxed);
            (true, json!(n))
        }
        "fast_verify" => set_fast_verify(d, name, v)?,
        // M32 verify_mode = full | fast | lean. Lean is the slow-CPU
        // boost: like fast, but per-article yEnc CRCs are also skipped
        // once PAR2 covers a file, so in-stream corruption detection
        // rests on the PAR2 block CRC32 alone (one CRC32 layer instead
        // of two - a corrupt article is caught slightly later, at its
        // block, and with single-CRC32 confidence). End-of-job
        // verification and repair are unchanged; PAR2-less downloads
        // keep article CRCs automatically. Applies from the NEXT job.
        "verify_mode" => set_verify_mode(d, name, v)?,
        "out_umask" => set_out_umask(d, name, v)?,
        "min_free" => {
            let b = size()?;
            d.min_free.store(b, Ordering::Relaxed);
            (true, json!(b))
        }
        "auto_retry_mins" => set_auto_retry_mins(d, name, v)?,
        "quota" => {
            let b = size()?;
            d.quota.store(b, Ordering::Relaxed);
            (true, json!(b))
        }
        "quota_period" => set_quota_period(d, name, v)?,
        "watch" => set_watch(d, name, v)?,
        "script" => {
            let p = v.trim();
            *d.script.lock_ok() = (!p.is_empty()).then(|| PathBuf::from(p));
            (true, json!(p))
        }
        "schedule" => set_schedule(d, name, v)?,
        "library_cats" => set_library_cats(d, name, v)?,
        "library_recheck_secs" => {
            let n = uint()?.max(60);
            d.library_recheck_secs.store(n, Ordering::Relaxed);
            (true, json!(n))
        }
        "index_groups" => set_index_groups(d, name, v)?,
        #[cfg(feature = "indexer")]
        "index_interests" => set_index_interests(d, name, v)?,
        "index_interests_applied" => {
            // Internal bookkeeping, persisted so a restart does not
            // re-apply interests over groups the user has since pruned.
            *d.index_interests_applied.lock_ok() = v.trim().to_string();
            (true, json!(v.trim()))
        }
        "index_interval_secs" => {
            let n = uint()?.max(30);
            d.index_interval_secs.store(n, Ordering::Relaxed);
            (true, json!(n))
        }
        "index_scan_par" => {
            let n = uint()?.clamp(1, 8);
            d.index_scan_par.store(n, Ordering::Relaxed);
            (true, json!(n))
        }
        "delete_to_trash" => set_delete_to_trash(d, name, v)?,
        "watch_interval_secs" => set_watch_interval_secs(d, name, v)?,
        "index_tip_secs" => set_index_tip_secs(d, name, v)?,
        "nested_max_depth" => set_nested_max_depth(d, name, v)?,
        "oracle_sample" => {
            // M29: idle STAT budget, STATs/hour/server (0 = off).
            let n = uint()?.min(3600);
            d.oracle_sample.store(n, Ordering::Relaxed);
            (true, json!(n))
        }
        "index_backfill" => {
            let n = uint()?;
            d.index_backfill.store(n, Ordering::Relaxed);
            (true, json!(n))
        }
        "index_max_age_secs" => {
            let n = uint()?;
            d.index_max_age_secs.store(n, Ordering::Relaxed);
            (true, json!(n))
        }
        "group_desc_isc" => {
            let on = v == "1" || v.eq_ignore_ascii_case("true");
            d.group_desc_isc.store(on, Ordering::Relaxed);
            (true, json!(on))
        }
        "index_retention" => {
            let on = v == "1" || v.eq_ignore_ascii_case("true");
            d.index_retention.store(on, Ordering::Relaxed);
            (true, json!(on))
        }
        "index_pause_on_download" => {
            let on = v == "1" || v.eq_ignore_ascii_case("true");
            d.index_pause_on_download.store(on, Ordering::Relaxed);
            (true, json!(on))
        }
        "predb_enabled" => set_predb_enabled(d, name, v)?,
        "predb_corr_enabled" => set_predb_corr_enabled(d, name, v)?,
        "predb_corr_auto" => set_predb_corr_auto(d, name, v)?,
        #[cfg(feature = "indexer")]
        "predb_max_rows" => set_predb_max_rows(d, name, v)?,
        #[cfg(feature = "indexer")]
        "predb_seed_days" => {
            // The source's own paging depth is the real ceiling; 366 is
            // just the point past which asking is pointless.
            let n = uint()?.clamp(1, 366);
            d.predb_seed_days.store(n, Ordering::Relaxed);
            (true, json!(n))
        }
        "predb_server" => set_predb_server(d, name, v)?,
        "predb_channels" => set_predb_channels(d, name, v)?,
        "predb_nick" => set_predb_nick(d, name, v)?,
        "index_paused" => set_index_paused(d, name, v)?,
        #[cfg(feature = "indexer")]
        "index_enabled" => set_index_enabled(d, name, v)?,
        #[cfg(feature = "indexer")]
        "spot_enabled" => set_spot_enabled(d, name, v)?,
        "spot_groups" => set_spot_groups(d, name, v)?,
        "spot_backfill" => set_spot_backfill(d, name, v)?,
        // M34 size cap. Four settings, and only the last of them can
        // delete anything - see index_evict.
        "index_max_bytes" => {
            // SAB-style sizes, same as min_free/quota: "20G", "500M",
            // bare bytes. 0 = unlimited, the default.
            let n = size()?;
            d.index_max_bytes.store(n, Ordering::Relaxed);
            (true, json!(n))
        }
        #[cfg(feature = "indexer")]
        "index_evict_order" => set_index_evict_order(d, name, v)?,
        #[cfg(feature = "indexer")]
        "index_evict_kinds" => set_index_evict_kinds(d, name, v)?,
        "index_evict" => set_index_evict(d, name, v)?,
        #[cfg(feature = "indexer")]
        "index_gates" => set_index_gates(d, name, v)?,
        // Clearing a key persists NULL, not "". save_setting REMOVES a
        // null key, so "cleared" means "stop overriding" - the --apikey
        // flag or the default applies again on the next launch. Storing
        // "" instead made the empty string win over an explicit --apikey
        // forever, with no way back through the API: every restart read
        // the blank back and unauthenticated the daemon.
        //
        // The deliberate consequence: while --apikey is passed you cannot
        // turn auth OFF from the dashboard - you drop the flag. That is
        // the right precedence for a credential.
        //
        // Removing the key from settings.json is only half of "keyless"
        // though: first_run_apikey ALSO reads the minted key file beside
        // the config, and reading it back is what makes a key stable
        // across restarts. So clearing here without touching that file
        // left the daemon keyless until the next restart and then keyed
        // again, with nothing on screen to explain it. Delete the file
        // too, so the user's choice actually survives.
        //
        // Deleted, not blanked: the empty-file branch in first_run_apikey
        // deliberately refuses to mint a replacement and warns loudly
        // every boot, which is the right answer to a file someone
        // truncated by hand but pure noise for a choice made in the
        // dashboard. With the file gone, the same function falls through
        // to its first-run test, sees the settings file we are about to
        // write (and the running install's spool), and leaves the daemon
        // keyless - silently, which is what was asked for.
        "apikey" => set_apikey(d, name, v)?,
        "nzbkey" => {
            let k = v.trim().to_string();
            *d.nzbkey.lock_ok() = (!k.is_empty()).then(|| k.clone());
            (true, if k.is_empty() { Value::Null } else { json!(k) })
        }
        // Same shape as apikey/nzbkey above: clearing it persists NULL, so
        // save_setting REMOVES the key and the launch-time default applies
        // again. Storing "" made the empty string a saved OVERRIDE that won
        // on every later start, with no way back through the API.
        "omdb_key" => {
            let k = v.trim().to_string();
            *d.omdb_key.lock_ok() = (!k.is_empty()).then(|| k.clone());
            (true, if k.is_empty() { Value::Null } else { json!(k) })
        }
        "feeds" => set_feeds(d, name, v)?,
        "indexers" => set_indexers(d, name, v)?,
        "watchlist_external" => set_watchlist_external(d, name, v)?,
        "watchlist_instant" => set_watchlist_instant(d, name, v)?,
        "watchlist_instant_max" => set_watchlist_instant_max(d, name, v)?,
        "watchlist" => set_watchlist(d, name, v)?,
        "smart_folders" => set_smart_folders(d, name, v)?,
        "cleanup_exts" => {
            // M23: comma list of extensions ("par2, sfv, srr, url").
            let list = crate::smart::parse_ext_list(v);
            *d.cleanup_exts.lock_ok() = list.clone();
            (true, json!(list))
        }
        "password_file" => set_password_file(d, name, v)?,
        "password_prompt" => set_password_prompt(d, name, v)?,
        "unpack_eat_volumes" => set_unpack_eat_volumes(d, name, v)?,
        "par_cleanup" => {
            let on = flag();
            d.par_cleanup.store(on, Ordering::Relaxed);
            (true, json!(on))
        }
        "watch_keep_nzb" => {
            // Live: the watch loop reads it per pickup.
            let on = flag();
            d.watch_keep_nzb.store(on, Ordering::Relaxed);
            (true, json!(on))
        }
        "fast_par" => set_fast_par(d, name, v)?,
        "prefer_external_unrar" => set_prefer_external_unrar(d, name, v)?,
        "custom_categories" => set_custom_categories(d, name, v)?,
        "failure_link" => set_failure_link(d, name, v)?,
        "prefer_quality" => set_prefer_quality(d, name, v)?,
        "notify_targets" => set_notify_targets(d, name, v)?,
        "arr_giveup_threshold" => set_arr_giveup_threshold(d, name, v)?,
        "arr_instances" => set_arr_instances(d, name, v)?,
        // Restart-only: bound/opened at startup. Persisted now, applied
        // on the next launch.
        "mem_limit" => {
            let b = size()?; // 0 = automatic sizing
            (false, json!(b))
        }
        "port" => set_port(d, name, v)?,
        "out_dir" => set_out_dir(d, name, v)?,
        "move_completed" => set_move_completed(d, name, v)?,
        "move_completed_cats" => set_move_completed_cats(d, name, v)?,
        "categories" => set_categories(d, name, v)?,
        "index_db" => {
            let p = v.trim();
            if p.is_empty() {
                return Err("index_db can't be empty".into());
            }
            (false, json!(p))
        }
        // Three different failures used to arrive here looking identical.
        // The table tells them apart: a row that says it is read-only, a
        // row someone declared and then forgot to write an arm for (our
        // bug, and the one that used to fail silently), and a name that
        // was simply never a setting.
        _ => {
            return Err(match setting(name) {
                Some(s) if s.write != Write::Setting => format!("{name} is read-only"),
                Some(_) => format!(
                    "{name} is declared in the settings table but apply_setting has no arm \
                     for it - that is a bug, please report it"
                ),
                None => format!("unsupported config item {name}"),
            });
        }
    })
}

/// [`apply_setting`] and its persistence as ONE transaction.
///
/// An API key lives in three places - the live mutex, the sibling `apikey`
/// file, and `settings.json` - and `apply_setting` writes the first two while
/// the CALLER writes the third. Two authenticated clients rotating the key at
/// once could therefore interleave as
///
/// ```text
/// A: live/keyfile = A ; B: live/keyfile = B ; B: settings = B ; A: settings = A
/// ```
///
/// with both answering success. The live key is B, `settings.json` says A, and
/// settings wins at load - so the key the user just pasted into Sonarr stops
/// working at the next restart, with nothing in the logs. Credential changes
/// take the transaction lock so the three stores can never disagree; every
/// other setting is a single value and needs no ordering.
pub(super) fn apply_and_save(
    d: &Arc<Daemon>,
    name: &str,
    v: &str,
) -> std::result::Result<(bool, bool), String> {
    static CREDENTIAL_TX: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _tx = matches!(name, "apikey" | "nzbkey")
        // A poisoned lock here would mean a panic mid-rotation; the data it
        // guards is the ordering, not an invariant a panic can corrupt.
        .then(|| CREDENTIAL_TX.lock_ok());
    let (live, persist) = apply_setting(d, name, v)?;
    // The write result is the only signal that the change is DURABLE, and
    // it used to be dropped: on a full disk or a read-only settings dir
    // the live key became B and B was returned as a success while
    // settings.json and the key file still held A, so the next restart
    // silently reverted and the client's stored key stopped working.
    //
    // Reported, deliberately NOT raised as an Err. `apply_setting` has
    // already moved the live value (and, for apikey, the key file), so a
    // caller that reads this as outright failure would keep using the OLD
    // key against a daemon that no longer accepts it - worse than the bug.
    // The honest answer is "it worked, but it is not durable".
    let saved = save_settings(&d.settings_path, &[(name, persist)]);
    if !saved {
        warn!(
            target: "settings",
            "⚠ {name} is live now but could not be written to {} - it reverts to \
             the stored value on the next start",
            d.settings_path.display()
        );
    }
    Ok((live, saved))
}

#[cfg(test)]
#[path = "settings_tests.rs"]
mod settings_tests;

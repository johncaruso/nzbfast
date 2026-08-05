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
        // The whole install in one downloadable file: everything a
        // moved or lost config directory takes with it (settings.json,
        // the config file with its servers, both keys). get_config
        // masks credentials by design; this deliberately does NOT -
        // its purpose is rebuilding the install, so it carries the
        // provider passwords exactly as stored (obfuscated, not
        // encrypted) and the API key. The UI labels the file
        // accordingly.
        //
        // AUTHORISATION: full key only, same reasoning as apikey_show
        // below - this must never join add_only, and must never accept
        // the bootstrap path.
        "backup_export" => {
            let read_json = |p: &std::path::Path| {
                std::fs::read(p)
                    .ok()
                    .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
                    .unwrap_or_else(|| json!({}))
            };
            let apikey_file = std::fs::read_to_string(ctx.cfg_path.with_file_name("apikey"))
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty());
            info!(target: "config", "settings backup exported to an authenticated caller");
            json!({
                "status": true,
                "backup": {
                    "nzbfast_backup": 1,
                    "version": env!("CARGO_PKG_VERSION"),
                    "config": read_json(ctx.cfg_path),
                    "settings": read_json(&ctx.cfg_path.with_file_name("settings.json")),
                    "apikey_file": apikey_file,
                }
            })
        }
        // The other half: write a backup_export bundle back over this
        // install's stores. Accepts the export exactly as downloaded
        // (the whole response) or just its inner "backup" object.
        //
        // Files only, no live apply: the point of a restore is the
        // NEXT start, and pretending to apply a whole install's
        // settings to a running daemon piecemeal is how the files and
        // the live state end up disagreeing. The response says a
        // restart is required, and the dashboard offers it - anything
        // the running daemon saves in between would overwrite the
        // restored files, so restarting promptly is the whole advice.
        // Full-key gated (never add_only): this writes the
        // post-processing script path among everything else.
        "backup_import" => {
            if req.method() != &tiny_http::Method::Post {
                json!({"status": false, "error": "POST required"})
            } else {
                let raw = api_body.take().unwrap_or_default();
                let parsed = serde_json::from_slice::<Value>(&raw).ok();
                let bundle = parsed.as_ref().and_then(|v| {
                    if v.get("nzbfast_backup").is_some() {
                        Some(v)
                    } else {
                        v.get("backup")
                            .filter(|b| b.get("nzbfast_backup").is_some())
                    }
                });
                match bundle {
                    None => json!({
                        "status": false,
                        "error": "not an nzbfast backup file",
                    }),
                    Some(b) => {
                        let mut failed: Vec<String> = Vec::new();
                        let mut write_store = |path: &std::path::Path, v: &Value| {
                            let text = serde_json::to_string_pretty(v).unwrap_or_default();
                            if crate::persist::write_atomic(path, text.as_bytes()).is_err() {
                                failed.push(path.display().to_string());
                            }
                        };
                        if let Some(cfg) = b.get("config").filter(|v| v.is_object()) {
                            write_store(ctx.cfg_path, cfg);
                        }
                        if let Some(s) = b.get("settings").filter(|v| v.is_object()) {
                            write_store(&ctx.cfg_path.with_file_name("settings.json"), s);
                        }
                        // An explicit null is a fact, not a gap: the export
                        // writes `apikey_file: null` when the source install
                        // is keyless, so restoring it onto a KEYED
                        // destination has to remove that key. Leaving the
                        // sibling file behind meant the old key came back at
                        // the next restart (startup reads the keyfile), which
                        // is not "this install now matches the backup".
                        // A backup with no `apikey_file` member at all is
                        // from before the field existed and says nothing -
                        // that one is left alone.
                        match b.get("apikey_file") {
                            Some(Value::String(k)) if !k.trim().is_empty() => {
                                if crate::persist::write_atomic(
                                    &ctx.cfg_path.with_file_name("apikey"),
                                    k.trim().as_bytes(),
                                )
                                .is_err()
                                {
                                    failed.push("apikey".into());
                                }
                            }
                            Some(_) => {
                                let keyfile = ctx.cfg_path.with_file_name("apikey");
                                if let Err(e) = std::fs::remove_file(&keyfile)
                                    && e.kind() != std::io::ErrorKind::NotFound
                                {
                                    failed.push("apikey".into());
                                }
                            }
                            None => {}
                        }
                        if failed.is_empty() {
                            info!(target: "config", "settings backup restored - restart to apply");
                            json!({"status": true, "restart_required": true})
                        } else {
                            json!({
                                "status": false,
                                "error": format!("could not write: {}", failed.join(", ")),
                            })
                        }
                    }
                }
            }
        }
        // Show the caller the key they already have, so setting up
        // Sonarr later does not mean digging through %LOCALAPPDATA%
        // or the browser's URL bar. get_config deliberately masks
        // every credential, and that masking must stay: this is a
        // separate, deliberate act with its own name in the log.
        //
        // AUTHORISATION: nothing extra is needed here, and that is
        // the point worth stating. `mode` is not in the `add_only`
        // list, so reaching this line already required `full` -
        // i.e. the API key ITSELF. The add-only NZB key cannot get
        // here, which matters: it exists to let a script submit
        // NZBs without gaining control, and handing it the API key
        // would silently promote it to exactly that. Do not add
        // "apikey_show" to add_only, and do not accept the
        // bootstrap path here (it proves possession of the NZB key,
        // not the API key).
        "apikey_show" => {
            let k = d.apikey.lock_ok().clone();
            info!(target: "config", "apikey revealed to an authenticated caller");
            json!({
                "status": true,
                // Null, not "", so the UI can tell "no key set on
                // this install" from "a key that is empty".
                "apikey": k,
                "nzbkey": d.nzbkey.lock_ok().clone(),
            })
        }
        // Mint a replacement. Routed through the same apply_setting
        // arm as a hand-typed key so persistence, replay and the
        // masked logging are identical - a second write path for a
        // credential is how the two drift.
        "apikey_new" => match credential_mutation_allowed(req) {
            Err(why) => json!({"status": false, "error": why}),
            Ok(()) => match random_apikey() {
                // Live state, key file and settings.json in one ordered
                // transaction (see `apply_and_save`) - persisting
                // separately let two rotations leave the three
                // disagreeing, and the loser's key came back on restart.
                // Still `status: true` with the key when the write
                // failed: the daemon IS on the new key now, so a page
                // that refused to adopt it would lock itself out.
                // `saved: false` is the durability signal.
                Some(k) => match apply_and_save(d, "apikey", &k) {
                    Ok((_, saved)) => {
                        info!(target: "config", "apikey regenerated");
                        json!({ "status": true, "apikey": k, "saved": saved })
                    }
                    Err(e) => json!({ "status": false, "error": e }),
                },
                None => json!({
                    "status": false,
                    "error": "could not read OS entropy for a new key",
                }),
            },
        },
        // Mint (or rotate) the add-only NZB key. Same shape and same
        // full-key gate as apikey_new: the NZB key must not be able to
        // rotate itself, or a leaked one could lock the owner's push
        // tools out. Revealing it rides apikey_show, which already
        // returns both keys.
        "nzbkey_new" => match credential_mutation_allowed(req) {
            Err(why) => json!({"status": false, "error": why}),
            Ok(()) => match random_apikey() {
                Some(k) => match apply_and_save(d, "nzbkey", &k) {
                    Ok((_, saved)) => {
                        info!(target: "config", "nzbkey regenerated");
                        json!({ "status": true, "nzbkey": k, "saved": saved })
                    }
                    Err(e) => json!({ "status": false, "error": e }),
                },
                None => json!({
                    "status": false,
                    "error": "could not read OS entropy for a new key",
                }),
            },
        },
        "get_config" => {
            let cats: Vec<Value> = d.cats.lock_ok().iter()
                        .map(|c| json!({"name": c, "dir": if c == "*" { "" } else { c.as_str() }, "priority": -100, "pp": "", "script": "None"}))
                        .collect();
            // Usenet servers with SECRETS MASKED: the UI only ever
            // learns whether a password exists, never its value.
            let servers: Vec<Value> = nzbkit::config::Config::load(ctx.cfg_path)
                .map(|c| {
                    c.servers
                        .iter()
                        .map(|s| {
                            // What the unset idle-release fields
                            // resolve to right now, so the UI can
                            // show the effective policy without
                            // duplicating the rule.
                            let rel = s.idle_release_policy();
                            json!({
                                "host": s.host,
                                "port": s.port,
                                "tls": s.tls,
                                "username": s.username.clone().unwrap_or_default(),
                                "has_password": s.password.is_some(),
                                "connections": s.connections,
                                "level": s.level,
                                "group": s.group.clone().unwrap_or_default(),
                                "retention_days": s.retention_days,
                                "block_bytes": s.block_bytes.unwrap_or(0),
                                "block_used": d.usage_lifetime(&s.host),
                                "enabled": s.enabled,
                                "warm_pool": s.warm_pool,
                                "idle_release_secs": s.idle_release_secs,
                                "idle_keep": s.idle_keep,
                                "max_source_ips": s.max_source_ips,
                                "idle_release_effective": {
                                    "secs": rel.after.map(|d| d.as_secs()).unwrap_or(0),
                                    "keep": rel.keep,
                                    "tight_ips": s.source_ips_are_tight(),
                                },
                                // Lifetime article completion% from
                                // the reliability ledger (null until
                                // a job has finished on this host).
                                "completion_pct": d.reliability(&s.host).map(|(t, m)| {
                                    100.0 * (t.saturating_sub(m)) as f64 / t as f64
                                }),
                                // Article tries behind completion_pct: the UI gates
                                // the "poor completion" verdict on sample size, and
                                // uses each server's share of tries to tell a primary
                                // (asked for ~everything) from a fill (only asked for
                                // the gaps others 430'd - low completion is by design).
                                "tried": d.reliability(&s.host).map(|(t, _)| t),
                            })
                        })
                        .collect()
                })
                .unwrap_or_default();
            // Restart-pending: for settings that only take effect on
            // restart, report the value SAVED to settings.json when it
            // differs from the value the daemon is running now. The UI
            // shows the live value in the field plus a "→ X after
            // restart" note, so a saved-but-not-yet-applied change is
            // never invisible. (Live settings can't diverge like this;
            // mem_limit already surfaces its saved value directly.)
            let staged = load_settings(&d.settings_path);
            let mut pending = serde_json::Map::new();
            let active_port = json!(d.port);
            if let Some(v) = staged.get("port")
                && v != &active_port
            {
                pending.insert("port".into(), v.clone());
            }
            let active_db = json!(d.index_db.to_string_lossy());
            if let Some(v) = staged.get("index_db")
                && v != &active_db
            {
                pending.insert("index_db".into(), v.clone());
            }
            // The settings block itself: every row of the table
            // that exposes a value, plus the three the table
            // declares but leaves to us because they are built
            // from what we just computed above.
            let mut nzbfast = config_block(&ConfigCtx {
                d,
                cfg_path: ctx.cfg_path,
            });
            // First-run signal: the dashboard shows a welcome card
            // until a server exists.
            nzbfast.insert("servers_configured".into(), json!(!servers.is_empty()));
            nzbfast.insert("servers".into(), json!(servers));
            nzbfast.insert("pending".into(), Value::Object(pending));
            json!({
                "config": {
                    // The sorting/retention block is what Sonarr/Radarr
                    // Test() probes: all sorting off (an EMPTY *_categories
                    // list means "applies to every category", so the enable
                    // flags must be 0) and history kept forever.
                    "misc": {"complete_dir": d.out_dir().to_string_lossy(),
                             "enable_tv_sorting": 0, "tv_categories": [],
                             "enable_movie_sorting": 0, "movie_categories": [],
                             "enable_date_sorting": 0, "date_categories": [],
                             "pre_check": 0, "history_retention": "",
                             "history_retention_option": "all",
                             "history_retention_number": 0},
                    "sorters": [],
                    "categories": cats,
                    "servers": [],
                    // Everything the settings UI edits, in one
                    // block. Values reflect the LIVE daemon state,
                    // and every key in it comes from the settings
                    // table - see `config_block`.
                    "nzbfast": Value::Object(nzbfast),
                }
            })
        }
        "get_cats" => {
            json!({"categories": d.cats.lock_ok().iter().cloned().collect::<Vec<_>>()})
        }
        // The post-processing script list a remote app fills its
        // per-job dropdown from. We run one global script, so the
        // honest answer is None plus that script if it is set -
        // an empty list makes a client show no dropdown at all.
        "get_scripts" => {
            let mut scripts = vec![json!("None")];
            if let Some(name) = d
                .script
                .lock()
                .unwrap()
                .as_ref()
                .and_then(|p| p.file_name())
                .map(|s| s.to_string_lossy().into_owned())
            {
                scripts.push(json!(name));
            }
            json!({"scripts": scripts})
        }
        // Settings UI + SAB-compatible live config. Sizes are
        // absolute only ("4M", "500K", bare bytes/sec; 0 =
        // unlimited) - no SAB-style percentage values. Every
        // successful set persists to settings.json so it also
        // applies on the next launch.
        "config" => {
            // A setting whose value is a JSON blob (watchlist,
            // feeds, notify targets, smart folders) outgrows the
            // 8 KB request line long before it outgrows anything
            // else, and the query-string form is then rejected
            // with a 414. Accept the same name/value pair in a
            // POST body; the GET form stays for the documented
            // SAB-compatible `mode=config` parity.
            let posted = if req.method() == &tiny_http::Method::Post {
                let raw = api_body.take().unwrap_or_default();
                serde_json::from_slice::<Value>(&raw).ok()
            } else {
                None
            };
            let from_body = |k: &str| {
                posted
                    .as_ref()
                    .and_then(|b| b.get(k))
                    .and_then(Value::as_str)
                    .map(str::to_string)
            };
            let name = from_body("name").or_else(|| params.get("name").cloned());
            let value = from_body("value").or_else(|| params.get("value").cloned());
            // The bootstrap hatch authorised exactly ONE setting, and
            // it decided that from the `name` in the QUERY string -
            // but the body wins two lines up. Without this check a
            // holder of the add-only NZB key could present
            // `?mode=config&name=apikey` to pass the gate and then
            // write `{"name":"script"}` in the body: an add-only
            // credential escalating to arbitrary config, and from
            // there to code execution, because `script` is run on the
            // job tail and `addfile` is itself add-only. Refuse with
            // the same phrase the gate uses, so nothing downstream
            // learns that the request got this far.
            if ctx.bootstrap_apikey && name.as_deref() != Some("apikey") {
                return Some(json!({
                    "status": false,
                    "error": "API Key Incorrect",
                    "nzbfast": env!("CARGO_PKG_VERSION"),
                }));
            }
            match (name.as_deref(), value.as_deref()) {
                (Some("set_pause"), Some(v)) => {
                    // SAB parity: config&name=set_pause&value=<minutes>.
                    timed_pause(d, v.parse().unwrap_or(0), true);
                    json!({"status": true})
                }
                (Some(name), Some(v)) => match apply_and_save(d, name, v) {
                    Ok((live, saved)) => {
                        info!(
                            target: "config",
                            "{name} → {}{}{}",
                            log_value(name, v),
                            if live { "" } else { " (applies after restart)" },
                            if saved {
                                ""
                            } else {
                                " (NOT SAVED - reverts on restart)"
                            }
                        );
                        // The path, but only when the write FAILED: "it
                        // could not be written to disk" is not actionable
                        // without knowing which disk. On the success path
                        // it would just be the daemon volunteering its
                        // filesystem layout to every API caller.
                        json!({"status": true, "live": live, "saved": saved,
                        "path": if saved { Value::Null } else {
                            json!(d.settings_path.to_string_lossy())
                        }})
                    }
                    Err(e) => json!({"status": false, "error": e}),
                },
                _ => json!({"status": false, "error": "config needs name and value"}),
            }
        }
        // Server editor (settings UI). POST bodies so credentials
        // never ride in a query string. Writes go through the
        // setup-wizard helpers → same config.local.json shape;
        // downloads load the config per job, so changes apply
        // from the next download without a restart.
        // M19: import servers from other downloaders' configs.
        // Probe well-known SABnzbd + NZBGet locations (or an
        // explicit value=<path>) and report what's importable.
        "import_probe" => {
            let mut cands: Vec<Value> = Vec::new();
            let mut paths: Vec<(String, PathBuf)> = Vec::new();
            if let Some(p) = params.get("value").filter(|p| !p.is_empty()) {
                let kind = if p.ends_with(".ini") {
                    "sabnzbd"
                } else {
                    "nzbget"
                };
                paths.push((kind.into(), PathBuf::from(p)));
            } else {
                let near: Vec<&std::path::Path> = ctx.cfg_path.parent().into_iter().collect();
                if let Some(p) = nzbkit::config::sabnzbd_ini_path(&near) {
                    paths.push(("sabnzbd".into(), p));
                }
                for p in nzbget_conf_paths() {
                    paths.push(("nzbget".into(), p));
                }
            }
            for (kind, path) in paths {
                let Ok(text) = read_import_config(&path) else {
                    continue;
                };
                let servers = if kind == "sabnzbd" {
                    nzbkit::config::parse_sabnzbd_ini(&text).unwrap_or_default()
                } else {
                    nzbkit::config::parse_nzbget_conf(&text)
                };
                if servers.is_empty() {
                    continue;
                }
                cands.push(json!({
                    "kind": kind,
                    "path": path.to_string_lossy(),
                    "servers": servers.iter().map(|s| json!({
                        "host": s.host,
                        "username": s.username.clone().unwrap_or_default(),
                        "connections": s.connections,
                        "level": s.level,
                    })).collect::<Vec<_>>(),
                }));
            }
            json!({"status": true, "candidates": cands})
        }
        // Merge one probed config's servers into ours (dupes by
        // host+username skipped; nothing existing is touched).
        "import_apply" => {
            let path = params.get("value").cloned().unwrap_or_default();
            let kind = params.get("value2").cloned().unwrap_or_default();
            match read_import_config(std::path::Path::new(&path)) {
                Err(e) => json!({"status": false, "error": format!("{path}: {e}")}),
                Ok(text) => {
                    let incoming = if kind == "sabnzbd" || path.ends_with(".ini") {
                        nzbkit::config::parse_sabnzbd_ini(&text).unwrap_or_default()
                    } else {
                        nzbkit::config::parse_nzbget_conf(&text)
                    };
                    let _cfg = crate::setup::config_write_lock();
                    let mut servers = current_servers(ctx.cfg_path);
                    let have: std::collections::HashSet<(String, String)> = servers
                        .iter()
                        .map(|s| {
                            (
                                s.get("host")
                                    .and_then(Value::as_str)
                                    .unwrap_or("")
                                    .to_lowercase(),
                                s.get("username")
                                    .and_then(Value::as_str)
                                    .unwrap_or("")
                                    .to_lowercase(),
                            )
                        })
                        .collect();
                    // Both competitors also name an archive-passwords
                    // file (SAB `[misc] password_file`, NZBGet
                    // `UnpackPassFile`). Importing their setup imports
                    // that too - but only while OUR file is still
                    // empty, so a list the user already curated here is
                    // never abandoned by a re-import.
                    let pw_adopted = {
                        let key_val = if kind == "sabnzbd" || path.ends_with(".ini") {
                            crate::import_sab::sab_ini_value(&text, "password_file")
                        } else {
                            crate::import_sab::nzbget_conf_value(&text, "UnpackPassFile")
                        };
                        key_val
                            .filter(|p| std::path::Path::new(p).is_file())
                            .filter(|_| d.read_unpack_passwords().is_empty())
                            .and_then(|p| match apply_and_save(d, "password_file", &p) {
                                Ok(_) => {
                                    info!(target: "import", "adopted archive passwords file {p}");
                                    Some(p)
                                }
                                Err(e) => {
                                    warn!(target: "import", "could not adopt passwords file {p}: {e}");
                                    None
                                }
                            })
                    };
                    let (mut added, mut skipped) = (0, 0);
                    for s in incoming {
                        let key = (
                            s.host.to_lowercase(),
                            s.username.clone().unwrap_or_default().to_lowercase(),
                        );
                        if have.contains(&key) {
                            skipped += 1;
                            continue;
                        }
                        if let Ok(v) = serde_json::to_value(&s) {
                            servers.push(v);
                            added += 1;
                        }
                    }
                    if added == 0 {
                        json!({"status": true, "added": 0, "skipped": skipped,
                               "password_file": pw_adopted})
                    } else {
                        match crate::setup::write_servers(ctx.cfg_path, &servers) {
                            Ok(()) => {
                                info!(
                                    target: "import",
                                    "{added} server(s) from {path} ({skipped} already present)"
                                );
                                json!({"status": true, "added": added, "skipped": skipped,
                                       "password_file": pw_adopted})
                            }
                            Err(e) => json!({"status": false, "error": e.to_string()}),
                        }
                    }
                }
            }
        }
        _ => return None,
    })
}

/// May this request ROTATE a credential?
///
/// Minting a key is the one mutation that can lock the owner OUT, which
/// makes it reachable-by-accident in a way nothing else here is. On a
/// deliberately keyless install (`NZBFAST_OPEN=1`, or a legacy one that
/// predates first-run key minting) the gateway's `(None, None) => true`
/// arm authorises everything, so a hostile page the user happens to
/// visit could navigate to `/api?mode=nzbkey_new` on their LAN address:
/// the browser sends the request, the daemon mints a key, and the
/// same-origin policy stops the page ever reading it. The install is now
/// `(None, Some(unknown))`, which is exactly the state that turns full
/// access off - the owner is locked out of their own daemon by a key
/// nobody has.
///
/// Two gates, because neither is sufficient alone:
///
/// - **POST.** Kills the drive-by NAVIGATION - an `<img>`, an iframe, a
///   redirect, a typed link. A cross-site FORM can still POST, hence:
/// - **Same-site.** `Sec-Fetch-Site` (every browser since 2023 sends it
///   on every request) must say the request did not come from another
///   site, and an `Origin`, when present, must match the `Host` we were
///   asked on. Both are checked only WHEN PRESENT: curl, the *arr
///   clients and every script send neither, and those callers have to
///   keep working - the point is to stop a BROWSER being used as a
///   confused deputy, not to invent an authentication scheme.
fn credential_mutation_allowed(req: &tiny_http::Request) -> Result<(), String> {
    if req.method() != &tiny_http::Method::Post {
        return Err("POST required to create a key".into());
    }
    let hv = |name: &'static str| {
        req.headers()
            .iter()
            .find(|h| h.field.equiv(name))
            .map(|h| h.value.as_str().trim().to_string())
            .filter(|v| !v.is_empty())
    };
    // "none" is a user-typed URL or a bookmark; "same-origin" is our own
    // dashboard. "cross-site" and "same-site" are both somebody else's
    // page - a sibling subdomain is not this daemon.
    if let Some(site) = hv("Sec-Fetch-Site")
        && !matches!(site.to_ascii_lowercase().as_str(), "same-origin" | "none")
    {
        return Err("a key can only be created from nzbfast's own pages".into());
    }
    // Compare HOSTS, not whole URLs: the dashboard may be reached over
    // http or https through a reverse proxy, and the scheme the browser
    // reports is not the scheme we were spoken to on.
    if let Some(origin) = hv("Origin") {
        let host_of = |s: &str| {
            s.rsplit_once("//")
                .map_or(s, |(_, rest)| rest)
                .split('/')
                .next()
                .unwrap_or_default()
                .to_ascii_lowercase()
        };
        let asked = hv("Host").unwrap_or_default().to_ascii_lowercase();
        if host_of(&origin) != asked {
            return Err("a key can only be created from nzbfast's own pages".into());
        }
    }
    Ok(())
}

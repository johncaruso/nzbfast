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
        // `version` stays the SAB-compat string (the *arrs
        // feature-gate on it); `nzbfast` is our real release
        // version, which is what the UI shows. `beta` is the
        // between-releases build serial (build.rs, from
        // packaging/beta-serial.txt) - "" on a real release.
        // KEPT OUT of `nzbfast` itself: the update check and
        // every wrapper parse that field as a bare semver.
        "version" => {
            let mut v = json!({
                "version": SAB_VERSION,
                "nzbfast": env!("CARGO_PKG_VERSION"),
                "beta": env!("NZBFAST_BETA"),
            });
            // Same handshake as the keyless refusal above answers,
            // for a keyless install (where this arm IS what a
            // wrapper's probe reaches).
            if let Some(proof) =
                launcher_proof(&d.launcher_token, params.get("hs").map(String::as_str))
            {
                v["hs_proof"] = json!(proof);
            }
            v
        }
        // §36: does parking connections help THIS server's link?
        // Measures time-to-usable-connection fresh vs claimed,
        // paired and alternated, and reports the interval that
        // decided it. Inconclusive resolves to OFF - a link we
        // cannot separate is one where the pool earns nothing.
        // Benchmarking whole downloads was tried and abandoned:
        // 60 paired reps over two hours on a real link still
        // could not separate the arms.
        "warm_bench" => {
            let host = params.get("host").cloned().unwrap_or_default();
            let server = nzbkit::config::Config::load(ctx.cfg_path)
                .ok()
                .and_then(|c| c.servers.iter().find(|s| s.host == host).cloned());
            match server {
                None => json!({"status": false, "error": "no such server"}),
                Some(server) => {
                    // block_on + a hard ceiling, like the
                    // test-server and sysbench handlers: a
                    // black-holed host must not wedge the API
                    // thread. One connect per fresh-first pair and
                    // two per warm-first pair, each already
                    // bounded, so this only trips on a host that
                    // is pathologically slow rather than dead.
                    let r = tokio::runtime::Handle::current().block_on(async {
                        tokio::time::timeout(
                            std::time::Duration::from_secs(120),
                            nzbkit::warmbench::measure(&server, nzbkit::warmbench::PAIRS),
                        )
                        .await
                    });
                    match r {
                        Err(_) => json!({
                            "status": false,
                            "error": "timed out measuring this server"
                        }),
                        Ok(r) => json!({
                            "status": true,
                            "host": host,
                            "verdict": match r.verdict {
                                nzbkit::warmbench::Verdict::Worthwhile => "worthwhile",
                                nzbkit::warmbench::Verdict::NoMeasurableBenefit => "none",
                                nzbkit::warmbench::Verdict::Failed => "failed",
                            },
                            "recommend_on": r.recommends_on(),
                            "samples": r.samples,
                            "fresh_ms": r.fresh_ms,
                            "warm_ms": r.warm_ms,
                            "saved_ms": r.saved_ms,
                            "ci_low_ms": r.ci_low_ms,
                            "ci_high_ms": r.ci_high_ms,
                            "detail": r.detail,
                        }),
                    }
                }
            }
        }
        // In-UI log viewer: last N captured stdout/stderr lines.
        "log" => {
            let n: usize = params
                .get("value")
                .and_then(|v| v.parse().ok())
                .unwrap_or(200);
            json!({
                "lines": nzbkit::logtee::tail(n.min(2000)),
                "capturing": nzbkit::logtee::active(),
            })
        }
        // M18b: per-provider data-usage history (UTC days).
        "usage" => {
            json!({"days": Value::Object(d.usage.lock_ok().clone())})
        }
        // Reveal a configured folder in the OS file manager, for
        // the 📂 buttons beside the path settings.
        //
        // Resolved by KEY from our own config - deliberately never
        // from a path supplied by the caller, which would make this
        // an open-anything-on-the-host endpoint. `script` is a file,
        // so its containing folder is opened.
        "open_dir" => {
            let key = params.get("value").map(String::as_str).unwrap_or("");
            // Containing folder of a file setting. Absolutised
            // first: parent() of a bare relative name is "", which
            // exists() rejects and reads as a nonsense error.
            let parent_of = |p: &std::path::Path| -> Option<PathBuf> {
                let abs = if p.is_absolute() {
                    p.to_path_buf()
                } else {
                    std::env::current_dir().ok()?.join(p)
                };
                abs.parent().map(|x| x.to_path_buf())
            };
            let target: Option<PathBuf> = match key {
                "out_dir" => Some(d.out_dir().clone()),
                "move_completed" => d.move_completed.read_ok().clone(),
                "watch" => d.watch_dir.lock_ok().clone(),
                "script" => d.script.lock_ok().as_ref().and_then(|p| parent_of(p)),
                "password_file" => parent_of(&d.password_file.lock_ok()),
                "index_db" => parent_of(&d.index_db),
                "config" => parent_of(&d.settings_path),
                _ => None,
            };
            // Report the absolute path - "scratchdl" tells the user
            // nothing about which folder actually opened.
            let target = target.map(|p| p.canonicalize().unwrap_or(p));
            match target {
                None => json!({"status": false, "error": format!("{key} is not set")}),
                Some(p) if !p.exists() => json!({
                    "status": false,
                    "error": format!("{} does not exist yet", p.to_string_lossy()),
                }),
                Some(p) => json!({"status": os_open(&p), "path": p.to_string_lossy()}),
            }
        }
        // Directory browser for the path settings - so the download
        // folder (or watch folder, script, index db) can be picked
        // off ANY mounted drive without typing a path.
        //
        // Unlike `open_dir`, this necessarily takes a caller-supplied
        // path, so it is deliberately kept READ-ONLY: it returns only
        // entry NAMES and a dir/file flag - never file contents, sizes
        // or anything else - and it is behind the full API key (the
        // whole `body` match is). The only write it permits is
        // `fs_mkdir` (one new subfolder), which the download-setup
        // flow needs. That is the same trust level the dashboard
        // already has (it can set the download dir to any path and
        // run post-processing scripts).
        "fs_list" => {
            let want_files = params.get("fmode").map(String::as_str) == Some("file");
            let raw = params.get("path").map(String::as_str).unwrap_or("");
            // Empty path → start where the user is now: the current
            // download root, so "here's where it points today" needs
            // no typing.
            let start = if raw.is_empty() {
                d.out_dir()
                    .canonicalize()
                    .unwrap_or_else(|_| d.out_dir().clone())
            } else {
                PathBuf::from(raw)
            };
            let mut dir = if start.is_absolute() {
                start
            } else {
                std::env::current_dir().unwrap_or_default().join(start)
            };
            // A file path browses its containing folder.
            if dir.is_file()
                && let Some(p) = dir.parent()
            {
                dir = p.to_path_buf();
            }
            let dir = dir.canonicalize().unwrap_or(dir);
            match std::fs::read_dir(&dir) {
                Err(e) => json!({
                    "status": false,
                    "path": dir.to_string_lossy(),
                    "error": format!("{}: {e}", dir.to_string_lossy()),
                }),
                Ok(rd) => {
                    let mut entries: Vec<(bool, String)> = rd
                        .flatten()
                        .filter_map(|e| {
                            let name = e.file_name().to_string_lossy().to_string();
                            if name.starts_with('.') {
                                return None; // hide dotfiles, like most pickers
                            }
                            let is_dir = e.file_type().map(|t| t.is_dir()).unwrap_or(false);
                            (is_dir || want_files).then_some((is_dir, name))
                        })
                        .collect();
                    // Folders first, then case-insensitive by name.
                    entries.sort_by(|a, b| {
                        b.0.cmp(&a.0)
                            .then_with(|| a.1.to_lowercase().cmp(&b.1.to_lowercase()))
                    });
                    let entries: Vec<Value> = entries
                        .into_iter()
                        .map(|(is_dir, name)| json!({"name": name, "dir": is_dir}))
                        .collect();
                    json!({
                        "status": true,
                        "path": dir.to_string_lossy(),
                        "parent": dir.parent().map(|p| p.to_string_lossy().to_string()),
                        "writable": path_writable(&dir),
                        "entries": entries,
                        "roots": fs_roots(&d.out_dir()),
                    })
                }
            }
        }
        // Create ONE subfolder under an existing directory (the "New
        // folder" button - needed to make a downloads dir on a fresh
        // drive). Name is a single component; separators and ".." are
        // rejected so it can never escape the parent.
        "fs_mkdir" => {
            let parent = params.get("path").map(String::as_str).unwrap_or("");
            let name = params.get("value").map(|s| s.trim()).unwrap_or("");
            if parent.is_empty()
                || name.is_empty()
                || name == ".."
                || name.contains('/')
                || name.contains('\\')
            {
                json!({"status": false, "error": "invalid folder name"})
            } else {
                let target = PathBuf::from(parent).join(name);
                match std::fs::create_dir(&target) {
                    Ok(()) => json!({"status": true, "path": target.to_string_lossy()}),
                    Err(e) => json!({"status": false, "error": e.to_string()}),
                }
            }
        }
        // M22: near-automatic phone access - every address this
        // daemon answers on, for the Remote access card + QRs.
        "remote_info" => {
            let port = d.port;
            let mut urls: Vec<Value> = Vec::new();
            // The address the browser ACTUALLY reached us on (Host
            // header) is authoritative - it works by definition, and
            // unlike interface auto-detection it stays correct behind
            // Docker/NAT/reverse proxies, where local_addr() would be a
            // container bridge IP (172.17.x) no other device can reach.
            let host_only = ctx
                .host_hdr
                .rsplit_once(':')
                .map(|(h, _)| h)
                .unwrap_or(ctx.host_hdr);
            let is_loopback = matches!(
                host_only.trim_start_matches('[').trim_end_matches(']'),
                "localhost" | "127.0.0.1" | "::1"
            );
            let containerized = std::path::Path::new("/.dockerenv").exists();
            if !ctx.host_hdr.is_empty() && !is_loopback {
                urls.push(json!({"kind": "connected",
                            "url": format!("http://{}/", ctx.host_hdr),
                            "label": "Wi-Fi / same network"}));
            } else {
                // Reached via localhost - auto-detect a shareable LAN
                // IP (bare metal only; a container would just detect
                // its own bridge address). No packet is sent.
                let lan = std::net::UdpSocket::bind("0.0.0.0:0").ok().and_then(|s| {
                    s.connect("8.8.8.8:53").ok()?;
                    s.local_addr().ok()
                });
                if let Some(a) = lan {
                    urls.push(json!({"kind": "lan",
                                "url": format!("http://{}:{port}/", a.ip()),
                                "label": "Wi-Fi / same network"}));
                }
            }
            // mDNS name - phones resolve .local natively. Skipped in a
            // container, where `hostname` is the container name, not
            // the host's - that .local would not resolve on the LAN.
            if !containerized && let Ok(out) = std::process::Command::new("hostname").output() {
                let mut h = String::from_utf8_lossy(&out.stdout).trim().to_string();
                if !h.is_empty() {
                    if !h.ends_with(".local") {
                        h = format!("{}.local", h.trim_end_matches(".local"));
                    }
                    urls.push(json!({"kind": "mdns",
                                    "url": format!("http://{h}:{port}/"),
                                    "label": "Name on your network"}));
                }
            }
            // Tailscale (CGNAT 100.64/10): if present, this URL
            // works from ANYWHERE the phone is on the tailnet -
            // the zero-port-forwarding external answer.
            let ts = std::net::UdpSocket::bind("0.0.0.0:0")
                .ok()
                .and_then(|s| {
                    s.connect("100.100.100.100:53").ok()?;
                    s.local_addr().ok()
                })
                .map(|a| a.ip())
                .filter(|ip| match ip {
                    std::net::IpAddr::V4(v) => {
                        let o = v.octets();
                        o[0] == 100 && (64..128).contains(&o[1])
                    }
                    _ => false,
                });
            if let Some(ip) = ts {
                urls.push(json!({"kind": "tailscale",
                            "url": format!("http://{ip}:{port}/"),
                            "label": "Tailscale - works from anywhere"}));
            }
            json!({"urls": urls, "port": port,
                        "has_apikey": d.apikey.lock_ok().is_some()})
        }
        // QR for any of the above (SVG, currentColor).
        "qr" => {
            let url = params.get("value").cloned().unwrap_or_default();
            match qrcodegen::QrCode::encode_text(&url, qrcodegen::QrCodeEcc::Medium) {
                Err(_) => json!({"status": false, "error": "text too long"}),
                Ok(qr) => {
                    let n = qr.size();
                    let mut p = String::new();
                    for y in 0..n {
                        for x in 0..n {
                            if qr.get_module(x, y) {
                                p.push_str(&format!("M{x},{y}h1v1h-1z"));
                            }
                        }
                    }
                    json!({"svg": format!(
                        "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"-2 -2 {v} {v}\" shape-rendering=\"crispEdges\"><path d=\"{p}\" fill=\"currentColor\"/></svg>",
                        v = n + 4
                    )})
                }
            }
        }
        // Fire one notification target now, so a wrong token or
        // a typo'd port is found here rather than by a library
        // that quietly never rescans. Takes the row being edited,
        // NOT the saved list - the point is to try it before
        // saving it.
        //
        // POST-only, like `shutdown`: it sends a request the
        // caller chose to a URL the caller chose and hands back
        // the status plus the remote's error body, which is a
        // usable port scanner if any page you visit can fire it
        // with an <img> or a link prefetch. The echoed body stays
        // - a Discord or ntfy 400 explains itself only in its
        // body, and the caller already holds the API key.
        "notify_test" => {
            if req.method() != &tiny_http::Method::Post {
                json!({"status": false, "error": "POST required"})
            } else {
                // From the BODY, with `&value=` kept only for callers
                // that already had it (Codex sweep 2, 3 Aug MH1). The
                // target carries a webhook token and a custom body
                // template, and a POST is not private when its
                // parameters ride the query string - reverse proxies log
                // that line, and so does the browser. Being a POST was
                // never the point: it exists so a page you merely visit
                // cannot fire this with an <img>.
                let raw = api_body
                    .take()
                    .filter(|b| !b.is_empty())
                    .and_then(|b| {
                        serde_json::from_slice::<Value>(&b)
                            .ok()
                            .and_then(|v| v.get("target").cloned())
                            .map(|t| t.to_string())
                    })
                    .or_else(|| params.get("value").cloned())
                    .unwrap_or_default();
                match serde_json::from_str::<crate::notify::Target>(&raw) {
                    Err(e) => json!({"status": false, "error": format!("bad target: {e}")}),
                    Ok(mut t) => {
                        // The token is never handed back to the
                        // UI, so an unchanged row tests with a
                        // blank one. Borrow the stored token for
                        // the matching target, exactly as
                        // server_test borrows a saved password.
                        if t.token.is_empty()
                            && let Some(prev) =
                                d.notify_targets.lock_ok().iter().find(|p| {
                                    p.kind == t.kind && p.url == t.url && p.name == t.name
                                })
                        {
                            t.token = prev.token.clone();
                        }
                        // §G: a Test IS a delivery, so it updates the
                        // row's last-send line too. Without this a user
                        // who fixed a token and tested it successfully
                        // still had a red "last send failed" sitting on
                        // the row until the next download finished.
                        let r = crate::notify::test(&t);
                        d.notify_health.lock_ok().insert(
                            crate::notify::target_key(&t),
                            crate::notify::Outcome {
                                at: unix_now(),
                                code: *r.as_ref().unwrap_or(&0),
                                error: r.as_ref().err().cloned().unwrap_or_default(),
                                test: true,
                            },
                        );
                        match r {
                            Ok(code) => json!({"status": true, "code": code}),
                            Err(e) => json!({"status": false, "error": e}),
                        }
                    }
                }
            }
        }
        // SAB remote-app surface: harmless acks + real stats.
        //
        // This used to be a permanent `[]`, so the conditions a
        // user most needs to see - no server configured, the
        // queue held on low disk, a job sitting waiting for a
        // password - were invisible to every client that has a
        // warnings pane, which is all of them.
        "warnings" => json!({"warnings": sab_warnings(d, ctx.cfg_path)}),
        // What the mobile remotes poll instead of `fullstatus`.
        // Same numbers, plus the warning count they badge.
        "status" => {
            let warns = sab_warnings(d, ctx.cfg_path);
            let free = free_bytes(&d.out_dir()).unwrap_or(0) as f64 / 1e9;
            json!({"status": {
                "uptime": "0",
                "color_scheme": "",
                "version": SAB_VERSION,
                "paused": d.paused.load(Ordering::Relaxed),
                "pause_int": pause_int(d),
                "have_warnings": warns.len().to_string(),
                "warnings": warns,
                "diskspace1": format!("{free:.2}"),
                "diskspace1_norm": format!("{free:.1} G"),
                "speedlimit_abs": d.hub.rate.get().to_string(),
                "complete_dir": d.out_dir().to_string_lossy(),
                "completedir": d.out_dir().to_string_lossy(),
                "cache_art": "0",
                "cache_size": "0 B",
                "finishaction": Value::Null,
                "servers": [],
            }})
        }
        // SAB's own mode=restart restarts SABnzbd. We ack it and do
        // NOTHING: Sonarr, Radarr and the SAB remote apps call it,
        // and bouncing the daemon underneath them is not what any of
        // them mean by it. Our real restart is mode=restart_daemon,
        // deliberately a name no SAB client will ever send.
        "restart" => json!({"status": true}),
        // Real shutdown (the native wrappers' clean-quit path):
        // persist the queue, park in-flight transfers (they resume
        // from the journal on next start), ack, then exit once the
        // response has flushed. POST-only so a stray GET (link
        // prefetch, curl tab-complete) can't kill the daemon.
        "shutdown" => {
            if req.method() != &tiny_http::Method::Post {
                json!({"status": false, "error": "POST required"})
            } else {
                // Same wind-down SIGTERM now takes (issue #13) -
                // this path used to exit without closing the
                // provider's sessions either, it just did it
                // where nobody was measuring.
                let d = d.clone();
                let rt = tokio::runtime::Handle::current();
                std::thread::spawn(move || {
                    // Let the JSON answer reach the caller first.
                    std::thread::sleep(std::time::Duration::from_millis(500));
                    wind_down_and_exit(&d, &rt, "api shutdown");
                });
                json!({"status": true})
            }
        }
        // Restart in place: persist, then replace this process with
        // a fresh copy of the same command line.
        //
        // Worth having because the settings UI says "applies after
        // restart" in several places and, until now, offered no way
        // to do that short of a terminal.
        //
        // Unix only, and deliberately so. `exec` replaces the
        // process image, which is the one restart that cannot race
        // itself for the listening port - a spawn-then-exit would
        // have the new process trying to bind while the old one
        // still holds it. Windows has no exec; its tray already has
        // a Restart item, and the honest answer is better than a
        // button that half works.
        "restart_daemon" => {
            if req.method() != &tiny_http::Method::Post {
                json!({"status": false, "error": "POST required"})
            } else if !cfg!(unix) {
                json!({"status": false, "error": "restart-unsupported"})
            } else {
                // Capture the command line BEFORE anything else: on
                // failure we have to be able to say what we tried.
                let exe = std::env::current_exe().ok();
                let args: Vec<std::ffi::OsString> = std::env::args_os().skip(1).collect();
                let cwd = std::env::current_dir().ok();
                match exe {
                    None => json!({
                        "status": false,
                        "error": "could not find our own executable",
                    }),
                    Some(exe) => {
                        let d = d.clone();
                        let rt = tokio::runtime::Handle::current();
                        std::thread::spawn(move || {
                            // Let the JSON answer reach the browser
                            // before the process image is replaced.
                            std::thread::sleep(std::time::Duration::from_millis(400));
                            // Sockets are CLOEXEC, so exec drops
                            // every provider session as abruptly
                            // as a kill does - and the replacement
                            // process then reopens the pool into an
                            // account that still counts them
                            // (issue #13). Hand them back first -
                            // but never at the cost of the restart
                            // itself, so a failure here still
                            // re-execs.
                            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                wind_down(&d, &rt, "api restart")
                            }));
                            restart_in_place(&exe, &args, cwd.as_deref());
                        });
                        json!({"status": true})
                    }
                }
            }
        }
        "fullstatus" => json!({"status": {
            "uptime": "0",
            "color_scheme": "",
            "version": SAB_VERSION,
            "paused": d.paused.load(Ordering::Relaxed),
            // Sonarr/Radarr resolve a relative complete_dir via
            // "completedir" (no underscore); keep both spellings.
            "complete_dir": d.out_dir().to_string_lossy(),
            "completedir": d.out_dir().to_string_lossy(),
        }}),
        "sysbench" => {
            let now = epoch_secs();
            match measure_system(d, ctx.cfg_path, &tokio::runtime::Handle::current()) {
                Err(e) => {
                    d.bench_append(json!({"ts": now, "source": "manual", "error": e.clone()}));
                    json!({"status": false, "error": e})
                }
                Ok(v) => {
                    d.bench_last.store(now, Ordering::Relaxed);
                    d.bench_append(json!({
                        "ts": now, "source": "manual",
                        "network_gbps": v.network_gbps,
                        "compute_gbps": v.compute_gbps,
                        "disk_gbps": v.disk_gbps,
                        "expected_gbps": v.expected_gbps,
                        "bottleneck": v.bottleneck,
                    }));
                    serde_json::to_value(&v).unwrap_or(json!({"status": false}))
                }
            }
        }
        // Update checker: force a check now. Notify-only - there
        // is no apply/install path; the banner links to the
        // download page.
        "update_check" => match check_update(d) {
            Err(e) => json!({"status": false, "error": e}),
            Ok(m) => json!({
                "status": true,
                "current": env!("CARGO_PKG_VERSION"),
                "available": m.as_ref().and_then(|v| v.get("version")).cloned(),
                "manifest": m,
            }),
        },
        // Scheduled-benchmark history (manual + scheduled runs).
        "bench_history" => json!({
            "history": d.bench_history(),
            "interval": d.bench_interval.load(Ordering::Relaxed),
            "last": d.bench_last.load(Ordering::Relaxed),
        }),
        _ => return None,
    })
}

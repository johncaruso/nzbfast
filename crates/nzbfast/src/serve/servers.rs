//! The server list the settings UI edits: reading what is on disk (or
//! what an imported SABnzbd/NZBGet config resolves to), normalising one
//! submitted server, and the watch-folder signature helpers beside it.
//!
//! Split out of serve/mod.rs by TODO 106 phase 4 - the code is verbatim,
//! only visibility changed.

use super::*;

/// Current server list as JSON values ready for editing. Prefers the
/// literal config.local.json contents (preserves keys the UI doesn't
/// know, e.g. rcvbuf); falls back to whatever the engine loader resolves
/// (e.g. a SABnzbd ini) so the first UI edit MATERIALIZES those servers
/// into config.local.json instead of silently dropping them.
pub(super) fn current_servers(cfg_path: &std::path::Path) -> Vec<Value> {
    let raw = crate::setup::read_servers(cfg_path);
    if !raw.is_empty() {
        return raw;
    }
    nzbkit::config::Config::load(cfg_path)
        .map(|c| {
            c.servers
                .iter()
                .filter_map(|s| serde_json::to_value(s).ok())
                .collect()
        })
        .unwrap_or_default()
}

/// Merge an incoming UI server object over an existing one (if any):
/// a blank password keeps the stored secret (secrets never round-trip
/// through the UI), cleared optional fields are removed (matching the
/// setup wizard's output), numbers are clamped sane.
/// Well-known NZBGet config locations, per platform.
pub(super) fn nzbget_conf_paths() -> Vec<PathBuf> {
    let mut out = Vec::new();
    #[cfg(windows)]
    for var in ["APPDATA", "LOCALAPPDATA"] {
        if let Ok(base) = std::env::var(var) {
            out.push(
                std::path::Path::new(&base)
                    .join("NZBGet")
                    .join("nzbget.conf"),
            );
        }
    }
    #[cfg(not(windows))]
    {
        if let Ok(home) = std::env::var("HOME") {
            let home = std::path::Path::new(&home);
            #[cfg(target_os = "macos")]
            out.push(home.join("Library/Application Support/NZBGet/nzbget.conf"));
            out.push(home.join(".nzbget"));
            out.push(home.join(".config/nzbget/nzbget.conf"));
        }
        out.push(PathBuf::from("/etc/nzbget.conf"));
        out.push(PathBuf::from("/config/nzbget.conf")); // docker convention
    }
    out.retain(|p| p.is_file());
    out
}

pub(super) fn normalized_server(
    existing: Option<&Value>,
    incoming: &Value,
) -> std::result::Result<Value, String> {
    let host = incoming
        .get("host")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    if host.is_empty() {
        return Err("server needs a host".into());
    }
    let mut o = existing
        .cloned()
        .filter(Value::is_object)
        .unwrap_or_else(|| json!({}));
    let ob = o.as_object_mut().expect("filtered to object above");
    ob.insert("host".into(), json!(host));
    let port = incoming
        .get("port")
        .and_then(Value::as_u64)
        .filter(|p| (1..=65535).contains(p))
        .unwrap_or(563);
    ob.insert("port".into(), json!(port));
    ob.insert(
        "tls".into(),
        json!(incoming.get("tls").and_then(Value::as_bool).unwrap_or(true)),
    );
    ob.insert(
        "connections".into(),
        json!(
            incoming
                .get("connections")
                .and_then(Value::as_u64)
                .map_or(8, |c| c.clamp(1, 999))
        ),
    );
    // Absent means false, and the key is dropped rather than written
    // false: this file is hand-edited by people, and a lock the user
    // never asked for should not appear in it.
    match incoming.get("pin_connections").and_then(Value::as_bool) {
        Some(true) => {
            ob.insert("pin_connections".into(), json!(true));
        }
        _ => {
            ob.remove("pin_connections");
        }
    }
    for key in ["username", "group"] {
        match incoming.get(key).and_then(Value::as_str).map(str::trim) {
            Some("") => {
                ob.remove(key);
            }
            Some(v) => {
                ob.insert(key.into(), json!(v));
            }
            None => {}
        }
    }
    if let Some(p) = incoming.get("password").and_then(Value::as_str)
        && !p.is_empty()
    {
        // Obfuscated like every other writer of this field. The
        // dashboard was the ONLY one that wasn't - the setup wizard
        // and both the SAB and NZBGet importers all call this - and
        // Settings -> Servers is the only add-server path that exists
        // on Docker, Synology and Windows, so the majority install
        // kept its provider password in cleartext in config.local.json
        // for the life of the install. That defeats the stated point
        // of obf1: these files end up in screenshots, forum posts and
        // bug reports. Idempotent on an already-prefixed value, and
        // ServerConfig's de_secret decodes before connect, so
        // server_test is unaffected. MUST land with the reveal fix
        // below or reveal starts returning obf1 blobs for everyone.
        ob.insert("password".into(), json!(nzbkit::config::obfuscate(p)));
    }
    for key in ["level", "retention_days", "block_bytes"] {
        match incoming.get(key).and_then(Value::as_u64) {
            Some(0) => {
                ob.remove(key);
            }
            Some(v) => {
                ob.insert(key.into(), json!(v));
            }
            None => {}
        }
    }
    // §36: per-server connection pooling, off unless asked for. Removed
    // rather than written false so the config file stays clean and the
    // serde default keeps meaning "off".
    match incoming.get("warm_pool").and_then(Value::as_bool) {
        Some(true) => {
            ob.insert("warm_pool".into(), json!(true));
        }
        Some(false) => {
            ob.remove("warm_pool");
        }
        None => {}
    }
    // Idle release, all three optional. An empty field means "not set",
    // which is NOT the same as 0 - 0 seconds is the deliberate "hold
    // them open" answer for an install that is the account's only
    // consumer, while unset means "derive it from the provider". So an
    // absent or blank value REMOVES the key rather than writing a zero,
    // or clearing the box would silently pin the old behaviour.
    for k in ["idle_release_secs", "idle_keep", "max_source_ips"] {
        match incoming.get(k) {
            Some(Value::Number(n)) if n.as_u64().is_some() => {
                ob.insert(k.into(), json!(n.as_u64().unwrap_or(0)));
            }
            // Blank string from a cleared form field, or an explicit
            // null: back to derived.
            Some(Value::Null) | Some(Value::String(_)) | None => {
                if incoming.get(k).is_some() {
                    ob.remove(k);
                }
            }
            Some(_) => return Err(format!("{k}: not a number")),
        }
    }
    Ok(o)
}

/// (mtime secs, len) of a watch-folder candidate - the signature the
/// poller settles on - or None when it cannot be measured.
///
/// `std::fs::metadata` and NOT the DirEntry's: a DirEntry measures the
/// link itself, and a symlinked .nzb then reports the link's own fixed
/// size and mtime while `read` follows it to a target still being
/// written. The signature would never change, so the file would read as
/// settled on the second pass whatever the writer was doing.
///
/// None means "not settled": a path we cannot stat is one the read two
/// steps later is unlikely to manage either, so the guard costs nothing
/// by failing closed - and failing OPEN would let two consecutive stat
/// errors compare equal and ingest a half-written file.
pub(super) fn watch_sig(p: &std::path::Path) -> Option<(u64, u64)> {
    let m = std::fs::metadata(p).ok()?;
    let mtime = m
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        // MILLISECONDS, not seconds. The signature's whole job is to tell
        // "nobody has written to this since I last looked" from "a copy is
        // still in flight", and at one-second resolution two samples taken
        // a few hundred ms apart are identical BY CONSTRUCTION - which is
        // exactly the comparison the filesystem-notify path now makes.
        .map_or(0, |dur| dur.as_millis() as u64);
    Some((mtime, m.len()))
}

/// Does this look like a WHOLE nzb, rather than one a copy is still
/// writing?
///
/// The watcher used to answer that question purely by timing: same size
/// and mtime one five-second pass later, therefore finished. That is a
/// heuristic, and it is the reason detection cost 5-10 s - two passes had
/// to elapse before anything could be ingested.
///
/// A finished nzb ends with its closing tag, so truncation is DIRECTLY
/// observable and needs no waiting at all. This is strictly stronger than
/// the timing rule for the case that rule exists to catch: a half-written
/// file still parses (the XML reader just stops at the last whole
/// `<file>`), so stillness could never prove completeness, but a missing
/// `</nzb>` proves incompleteness outright.
///
/// Deliberately NOT the only gate: an nzb that is gzipped, or written by
/// something that omits the closing tag, would never pass, so the caller
/// keeps the stability rule as the fallback. This only lets an obviously
/// complete file skip the wait.
pub(super) fn nzb_looks_complete(bytes: &[u8]) -> bool {
    // Trailing whitespace is normal; anything else after </nzb> is not
    // our business. Scan a bounded tail so a huge nzb costs nothing.
    let tail = &bytes[bytes.len().saturating_sub(256)..];
    let end = tail
        .iter()
        .rposition(|b| !b.is_ascii_whitespace())
        .map_or(0, |i| i + 1);
    tail[..end].ends_with(b"</nzb>")
}

/// Armed the moment a first run mints an API key, disarmed once the
/// banner has SHOWN that key. Anything that bails in between - the bind
/// is the measured case (fresh dir + held port: attempt 1 dies below the
/// print, the launcher's retry then takes the reuse path and never
/// prints either) - would otherwise exit holding a credential the user
/// has never seen, reachable only via Settings on a daemon that will not
/// start. Drop-based so every `?` between mint and banner is covered
/// without threading the failure through ~3k lines of startup; the
/// happy-path print itself is deliberately NOT moved (it belongs under
/// the dashboard URL, where a new user is looking - see the banner).
pub(super) struct MintDisclosure(pub(super) Option<PathBuf>);

impl MintDisclosure {
    pub(super) fn disarm(&mut self) {
        self.0 = None;
    }
}

impl Drop for MintDisclosure {
    fn drop(&mut self) {
        if let Some(keyfile) = &self.0 {
            eprintln!(
                "⚠ startup failed AFTER this first run created an API key. The key is saved \
                 at {} and the next start will reuse it; Sonarr/Radarr and the dashboard \
                 will need it (Settings → Security can show it once the daemon is up).",
                keyfile.display()
            );
        }
    }
}

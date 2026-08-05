//! nzbfastd (design: M5): queue daemon + SABnzbd-compatible API subset,
//! so Sonarr/Radarr/Prowlarr work day one.
//!
//! Endpoints (JSON): mode=version, get_config, queue, history, addfile
//! (multipart), queue&name=delete. One download runs at a time at full
//! pipeline speed; a watch folder is polled for new .nzb files.

use crate::{MutexExt, RwLockExt};
use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use anyhow::Result;
use serde_json::{Value, json};
use tracing::{error, info, warn};

mod job;
pub use job::*;

/// Default for the "fast par mode" setting (`fast_par`). ON since
/// 2026-07-31: the verify-failure fold retry makes wrong
/// output impossible to ship, the trip-breaker and this setting cover
/// live disable, and the RAM/cgroup-scaled retention budget in nzbkit
/// gates small machines onto the fold up front - which together
/// superseded the planned corpus-variety soak. A saved `fast_par` in
/// settings.json still wins over this default. The value lives in
/// nzbkit (it initializes the process-global flag there) so the CLI
/// repair path shares this default without a startup call.
pub use nzbkit::par2repair::FAST_PAR_DEFAULT;

mod daemon;
use daemon::*;

mod giveup;
#[cfg(feature = "indexer")]
pub(crate) mod predb_seed;
mod tasks;

mod api;

#[cfg(test)]
mod testutil;

pub struct ServeOpts {
    pub port: u16,
    /// Listen address for the dashboard + API. Default "0.0.0.0" (all
    /// interfaces) and it stays that way deliberately: the product is
    /// routinely run on a NAS or a headless box with Sonarr/Radarr and
    /// the phone remote on OTHER hosts, so a loopback default would
    /// break the normal deployment for everybody in exchange for less
    /// protection than the API key itself provides. Operators who want
    /// the narrow bind can now ask for it (`--bind 127.0.0.1`).
    pub bind: String,
    /// Open the dashboard in a browser once the listener is up.
    pub open: bool,
    pub apikey: Option<String>,
    pub nzbkey: Option<String>,
    pub out_root: PathBuf,
    pub watch: Option<PathBuf>,
    pub script: Option<PathBuf>,
    pub connections: usize,
    pub window: usize,
    pub decoders: usize,
    /// PAR2 fast verify (TODO §10): claim in-stream blocks by CRC32 only
    /// (each article's yEnc CRC already passed); settle read-back and
    /// disk-fed spans keep full MD5. Default ON - bench-validated 2.9×
    /// on CPU-bound boxes (a quick-verify default).
    pub fast_verify: bool,
    /// M32 lean verify (slow-CPU boost, see verify_mode setting).
    pub verify_lean: bool,
    /// M14i: categories whose jobs are metadata-only library entries.
    pub library_cats: Vec<String>,
    /// Re-verify interval for parked library jobs (seconds).
    pub library_recheck_secs: u64,
    /// Pause new jobs while free space on out_root is below this (bytes).
    pub min_free: Option<u64>,
    /// Permissions for finished downloads, as a umask (#20). None =
    /// off, which is the default and today's behaviour.
    pub out_umask: Option<u32>,
    /// M32: minutes before the one automatic retry of a job that failed
    /// with missing articles (0 = off; default 20).
    pub auto_retry_mins: u64,
    /// Sample each job's articles with STAT before downloading, and fail
    /// it up front when the post cannot possibly complete. The CLI has
    /// had `--preflight` since M2; the daemon never offered it, so a
    /// wholly dead post was discovered the slow way - the 31 Jul Silo
    /// job spent six minutes and 0 bytes to reach a verdict a two-second
    /// sample gives. Off by default: it costs a round of STATs on every
    /// job, including the overwhelming majority that are perfectly fine.
    /// `settings.json` only - deliberately not in the dashboard, which
    /// would need the string in all 21 UI locales for a switch aimed at
    /// people whose provider is shedding posts.
    pub preflight: bool,
    /// Byte budget per quota period; new jobs wait for the next period
    /// once it's spent (Force-priority jobs bypass).
    pub quota: Option<u64>,
    /// 'd' (daily, UTC midnight) or 'm' (monthly, 1st 00:00 UTC).
    pub quota_period: char,
    /// M14k: RSS feed config file (see rss.rs for format).
    pub feeds: Option<PathBuf>,
    /// M14g2: initial download speed cap (e.g. "4M"; 0/absent = unlimited).
    pub speedlimit: Option<String>,
    /// M14g2: time-of-week schedule file (see parse_schedule).
    pub schedule: Option<PathBuf>,
    /// M14g3: RTT-governed auto speed (yield to other household traffic).
    pub auto_speed: bool,
    /// M15: pipeline cache-tier budget (see nzbkit::mem).
    pub mem_budget: nzbkit::mem::MemBudget,
    /// M12: index database path (newznab facade + dashboard browse).
    #[cfg(feature = "indexer")]
    pub index_db: PathBuf,
    /// M12: groups to OVER-scan continuously (empty = no scanning).
    #[cfg(feature = "indexer")]
    pub index_groups: Vec<String>,
    #[cfg(feature = "indexer")]
    pub index_interval_secs: u64,
    /// Articles to backfill on a group's first scan.
    #[cfg(feature = "indexer")]
    pub index_backfill: u64,
    /// Fetch newsgroup descriptions from ISC as well as the provider.
    pub group_desc_isc: bool,
    /// Only index posts newer than this (seconds; 0 = off). Overrides
    /// the backfill count on a first scan via Date bisection.
    #[cfg(feature = "indexer")]
    pub index_max_age_secs: u64,
    /// Ingest gates for the scanner (kind/year/res/language/title/size).
    #[cfg(feature = "indexer")]
    pub index_gates: Option<crate::gates::Gates>,
}

/// Dashboard-saved settings live in `settings.json` next to the server
/// config (config.local.json). Flat {key: value} map holding ONLY keys
/// the user changed in the UI; on launch those override the matching CLI
/// flags, so a UI change survives restarts without touching launch
/// scripts. Delete the file (or a key) to fall back to the flags.
/// Settings keys the `nzbfast setup` wizard writes BEFORE the daemon has
/// ever run - it is a separate process, so its answers land in
/// settings.json ahead of first start.
///
/// They must not read as "an existing install" to the first-run API key
/// test: a user who answered "index sport" in the wizard would otherwise
/// get an unkeyed daemon, which is the exact hole that test exists to
/// close.
const SETUP_ANSWER_KEYS: &[&str] = &["index_interests"];

/// Does settings.json hold anything beyond the wizard's own answers?
///
/// Only a file that is NOTHING BUT wizard answers reads as a first run.
/// A missing file is not this function's case (the caller's `exists`
/// test covers it), and an EMPTY object is deliberately "existing": it
/// carries no wizard answer to explain itself, so the old rule - the
/// file exists, therefore the install has run - is the safe reading.
/// Anything unparseable is existing too: never mint a key over a state
/// file we cannot read.
fn settings_beyond_setup_answers(path: &std::path::Path) -> bool {
    let Ok(bytes) = std::fs::read(path) else {
        return false;
    };
    match serde_json::from_slice::<Value>(&bytes) {
        Ok(Value::Object(map)) => {
            map.is_empty() || map.keys().any(|k| !SETUP_ANSWER_KEYS.contains(&k.as_str()))
        }
        Ok(_) => true,
        Err(_) => true,
    }
}

fn settings_file(config: &std::path::Path) -> PathBuf {
    config.with_file_name("settings.json")
}

/// The two rename-punctuation toggles replaced hard-coded ON behavior.
/// Fresh installs ship them OFF, but an upgrade with no saved key must
/// retain the old shape: history cleanup recomputes a filed episode's
/// suffix, and silently changing it would orphan every pre-upgrade
/// bracketed file. Wizard-only settings are still a fresh install.
fn legacy_rename_punctuation(
    config: &std::path::Path,
    out_root: &std::path::Path,
    settings: &std::path::Path,
) -> bool {
    settings_beyond_setup_answers(settings)
        || config.with_file_name(".spool").exists()
        || out_root.join(".spool").exists()
}

/// Where daemon state lives: queue + history, the usage ledger, watchlist
/// memory, RSS seen-ids, benchmark history, the poster-art cache and a
/// copy of each job's NZB.
///
/// Beside the config, NOT under the download directory. It used to be
/// `<downloads>/.spool`, sitting among finished downloads where it reads
/// as leftover clutter - and a leading dot hides nothing on Windows - so
/// users tidying up watched files deleted the daemon's entire state.
/// Tying it to the config also stops it being stranded when the download
/// directory is repointed from the dashboard.
///
/// An existing spool migrates once, on the first launch after the move.
/// Config and downloads are routinely on different filesystems - separate
/// volume mounts are the norm under Docker - so this cannot be a rename.
///
/// It is staged instead: copy the whole old spool to a sibling of the new
/// location, fsync it, then ONE atomic rename publishes it, and only then is
/// the old directory removed. Nothing touches the old spool until the new one
/// is complete.
///
/// It used to `move_tree`, which deletes each file as soon as its copy is
/// durable. A failure partway (ENOSPC, EIO, permissions) therefore left
/// `queue.json` at the new location and the rest at the old one, and this
/// function then returned the OLD path - where the queue was now missing, so
/// the daemon started empty and saved an empty queue over it. The next
/// restart saw a non-empty new directory, switched to it, and resurrected the
/// stale queue that had been copied before the failure. Both restarts were
/// self-consistent and both were wrong.
///
/// That is also why `new.exists()` is now trustworthy as "already migrated":
/// the new path only ever appears via the final rename, so it cannot be a
/// half-copy. An EMPTY `new` is the one exception, and it is not a migration
/// at all - see the `remove_dir` below.
fn spool_dir(config: &std::path::Path, out_root: &std::path::Path) -> PathBuf {
    let new = config.with_file_name(".spool");
    let old = out_root.join(".spool");
    if old == new || !old.exists() {
        return new;
    }
    // An empty `new` is a placeholder, not a migration: something created
    // the directory without any state in it (a packaging step, a first run
    // interrupted between mkdir and the first save), and returning it would
    // start the daemon on an empty queue while the real one sat in `old`.
    // `remove_dir` refuses a non-empty directory, so this can only ever drop
    // an empty one, and the migration below then runs as it should.
    // Decide by what the directory CONTAINS, not by whether it can be
    // removed. `remove_dir` also fails on EACCES/EPERM, and on Windows for
    // an empty directory someone still holds a handle to - and reading that
    // failure as "a real migrated spool" is not a harmless mistake: it sends
    // the user's actual queue at `old` off to legacy-spool/ and starts the
    // daemon on the empty `new`, which then SAVES that empty queue over it.
    // An unreadable `new` is treated as occupied, which is the safe way to
    // be wrong: it declines to migrate rather than moving live state aside.
    let new_is_empty = match std::fs::read_dir(&new) {
        Ok(mut rd) => rd.next().is_none(),
        Err(_) if new.exists() => false,
        Err(_) => true,
    };
    if new.exists() && !new_is_empty {
        // A real, migrated spool. Whatever is still at `old` is the residue
        // of that move, and it is sitting in the user's download folder.
        retire_legacy_spool(&old, &new);
        return new;
    }
    // Empty placeholder: drop it so the migration below can publish into
    // its place. A failure here is not fatal - the rename simply lands on
    // an existing empty directory, or the migration declines.
    if new.exists() {
        let _ = std::fs::remove_dir(&new);
    }
    // Beside `new`, so the publishing rename is same-filesystem and atomic.
    let staging = config.with_file_name(".spool.migrating");
    let _ = std::fs::remove_dir_all(&staging); // abandoned by an earlier crash
    let staged = crate::smart::copy_tree(&old, &staging)
        .and_then(|()| std::fs::rename(&staging, &new))
        .and_then(|()| {
            // Persist the new directory entry before we delete the source.
            crate::smart::sync_dir(new.parent().unwrap_or(&new))
        });
    match staged {
        Ok(()) => {
            let _ = std::fs::remove_dir_all(&old);
            info!(
                target: "spool",
                "moved daemon state out of the download directory: {} → {}",
                old.display(),
                new.display()
            );
            new
        }
        Err(e) => {
            let _ = std::fs::remove_dir_all(&staging);
            warn!(
                target: "spool",
                "could not move daemon state to {} ({e}) - continuing to use {} \
                 (unchanged; the move will be retried next start)",
                new.display(),
                old.display()
            );
            old
        }
    }
}

/// Clear away a `<downloads>/.spool` that outlived the move to the data dir.
///
/// `spool_dir` used to return the moment the new location existed, which is
/// right for the LIVE path and wrong for the old directory. Two ways it
/// survives the migration: the first version of that migration deleted each
/// file as it copied, so any failure partway left the remainder behind; and
/// even the staged version's closing `remove_dir_all` is best-effort, which
/// on Windows one open handle (a scanner, an Explorer preview) is enough to
/// defeat. Either way the leftover then sat in the user's own download
/// folder forever, and un-hidden - only the path `spool_dir` RETURNS is ever
/// passed to `hide_from_user` - reading exactly like junk we forgot to clean
/// up. It is the residue, not the state: this is a tester report, not a
/// theory.
///
/// It is dead by definition here (`new` exists and is non-empty, so the
/// daemon has been running off it, and every file below is a stale copy of
/// something already migrated). It is still not deleted. It moves inside the
/// live spool as `legacy-spool/`, out of the download folder but recoverable,
/// and the log says where it went and that it can be deleted. One volume - the
/// usual case, `%LOCALAPPDATA%` and `Downloads` both on C: - makes that a free
/// rename; only a genuinely separate downloads volume pays for a copy.
fn retire_legacy_spool(old: &std::path::Path, new: &std::path::Path) {
    // First, and regardless of everything below: a leftover we fail to move
    // should at least stop being visible on Windows, where the leading dot
    // means nothing. Cheap, and it covers every failure path at once.
    nzbkit::disk::hide_from_user(old);
    let Some(dest) = free_legacy_spool_path(new) else {
        return;
    };
    let moved = std::fs::rename(old, &dest).is_ok()
        || match crate::smart::copy_tree(old, &dest) {
            // Separate volumes. The source goes only once the copy is whole.
            Ok(()) => std::fs::remove_dir_all(old).is_ok(),
            Err(e) => {
                // Leave nothing half-copied claiming to be the retired state.
                let _ = std::fs::remove_dir_all(&dest);
                warn!(
                    target: "spool",
                    "leftover daemon state at {} could not be retired ({e}); \
                     it is unused and safe to delete",
                    old.display()
                );
                false
            }
        };
    if moved {
        info!(
            target: "spool",
            "retired leftover daemon state from the download folder: {} → {} \
             (unused; safe to delete)",
            old.display(),
            dest.display()
        );
    }
}

/// A free `legacy-spool` name inside the live spool. Suffixed rather than
/// merged, because two leftovers are two separate installs' residue and
/// mixing them would produce a directory that never existed.
fn free_legacy_spool_path(new: &std::path::Path) -> Option<PathBuf> {
    (0..100u32).find_map(|n| {
        let p = match n {
            0 => new.join("legacy-spool"),
            n => new.join(format!("legacy-spool-{n}")),
        };
        (!p.exists()).then_some(p)
    })
}

/// Fresh random hex secret without a rand dependency: RandomState is
/// OS-entropy-seeded, and the sha256 mix of several instances plus
/// pid/time is plenty for a stream-URL capability secret.
fn fresh_secret() -> String {
    use sha2::Digest as _;
    use std::hash::{BuildHasher as _, Hasher as _};
    let mut h = sha2::Sha256::new();
    for i in 0u64..4 {
        let mut hs = std::collections::hash_map::RandomState::new().build_hasher();
        hs.write_u64(i);
        h.update(hs.finish().to_le_bytes());
    }
    h.update(std::process::id().to_le_bytes());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    h.update(now.as_nanos().to_le_bytes());
    format!("{:x}", h.finalize())[..32].to_string()
}

/// M29: JSON verdict for one release - "ok"/"maybe"/"gone", or null when
/// the ledger is too thin (or oracle context unavailable).
#[cfg(feature = "indexer")]
fn oracle_verdict_json(
    ocx: &Option<(nzbkit::oracle::Snapshot, Vec<String>)>,
    grp: &str,
    first_posted: i64,
    now: i64,
) -> Value {
    let Some((snap, bbs)) = ocx else {
        return Value::Null;
    };
    // Undated release: age is unknown, not "20000 days old". Emit no
    // verdict rather than reading it out of the wrong (ancient) bucket.
    if first_posted <= 0 {
        return Value::Null;
    }
    let age = ((now - first_posted).max(0) / 86_400) as u32;
    match snap.verdict(bbs, &nzbkit::oracle::group_family(grp), age) {
        Some(v) => json!(v.as_str()),
        None => Value::Null,
    }
}

fn load_settings(path: &std::path::Path) -> serde_json::Map<String, Value> {
    // Backup-aware: a torn settings.json loads the .bak of the last good
    // parse instead of {} - otherwise the next save_setting would erase
    // every other setting.
    crate::persist::load_json_with_backup(path)
        .and_then(|v| v.as_object().cloned())
        .unwrap_or_default()
}

/// Persist several related settings in one atomic rewrite. `Value::Null`
/// removes a key. Returning false lets multi-step live state avoid
/// recording a completion marker that never reached disk.
fn save_settings(path: &std::path::Path, values: &[(&str, Value)]) -> bool {
    update_settings(path, |map| {
        for (key, v) in values {
            if v.is_null() {
                map.remove(*key);
            } else {
                map.insert((*key).to_string(), v.clone());
            }
        }
    })
}

/// Union two comma-separated category lists, in the settings file's own
/// shape. Order is stable (on-disk entries first, then anything new) so
/// a registration that adds nothing rewrites the same bytes.
fn merge_cat_list(on_disk: &str, mine: &str) -> String {
    let mut all: Vec<&str> = Vec::new();
    for c in on_disk.split(',').chain(mine.split(',')).map(str::trim) {
        if !c.is_empty() && !all.contains(&c) {
            all.push(c);
        }
    }
    all.join(", ")
}

/// The read-modify-write behind [`save_settings`], with the modify step
/// left to the caller. Use this when the new value DEPENDS on what is
/// already on disk: `f` runs inside the same critical section as the
/// read and the write, so it sees the current file rather than a
/// snapshot taken before some other worker's save.
fn update_settings(
    path: &std::path::Path,
    f: impl FnOnce(&mut serde_json::Map<String, Value>),
) -> bool {
    // API requests are handled on a worker pool - serialize the
    // read-modify-write so concurrent saves can't drop each other's keys.
    static IO: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _g = IO.lock_ok();
    let mut map = load_settings(path);
    f(&mut map);
    match serde_json::to_string_pretty(&Value::Object(map)) {
        Ok(text) => {
            if let Err(e) = crate::persist::write_atomic(path, text.as_bytes()) {
                error!(target: "settings", "write {}: {e}", path.display());
                false
            } else {
                true
            }
        }
        Err(e) => {
            error!(target: "settings", "serialize: {e}");
            false
        }
    }
}

/// Persist one UI-changed setting. Best-effort: a failed write must never
/// take down a live daemon.
fn save_setting(path: &std::path::Path, key: &str, v: Value) {
    let _ = save_settings(path, &[(key, v)]);
}

/// A fresh API key: 24 bytes of OS entropy as 48 lowercase hex chars -
/// the same shape and strength the container entrypoint mints, and the
/// shape every `apikey=` comparison in here already handles.
///
/// Deliberately NOT `fresh_secret()`: that mixes `RandomState` instances,
/// which are seeded once per thread and then bumped by a counter, so its
/// outputs are related. Good enough for a stream capability URL that
/// lives for one session; not good enough for the credential guarding
/// the whole control API.
fn random_apikey() -> Option<String> {
    let mut buf = [0u8; 24];
    getrandom::getrandom(&mut buf).ok()?;
    Some(hex::encode(buf))
}

/// `runtime.json`, beside `settings.json`: how a LAUNCHER tells this
/// daemon apart from anything else that answers on the port.
///
/// The Mac wrapper and the Windows tray probe a port without a key (they
/// must: sending it would hand the key, and with it `mode=server_secret`,
/// to whatever bound the port first) and identify us from the reply
/// alone. But an unauthenticated product string is not identity - any
/// local process can print it, and on a shared desktop a second account
/// can bind an unprivileged loopback port before we do, then receive the
/// stored key on the next dashboard open.
///
/// So the wrapper reads a secret only OUR user can read, and the daemon
/// proves it holds the same one: `mode=version&hs=<nonce>` answers with
/// `hs_proof = sha256(token:nonce)`. The token never crosses the wire in
/// either direction, so sending the challenge to an impostor tells it
/// nothing, and a wrapper that gets no proof (or a wrong one) knows not
/// to hand over the key.
///
/// `pid` is recorded for diagnostics and for a spawning wrapper that
/// wants to bind its attach to the exact child it started. The file is
/// 0600 through [`crate::persist::write_atomic`] (LocalAppData and
/// Application Support are already user-only on the other two), and
/// rewritten on every start, so a stale one from a crashed run is
/// replaced rather than trusted - and the port it names is checked too.
fn write_runtime_file(settings_path: &std::path::Path, port: u16, token: &str) {
    let path = settings_path.with_file_name("runtime.json");
    let body = json!({
        "pid": std::process::id(),
        "port": port,
        "token": token,
        "version": env!("CARGO_PKG_VERSION"),
    });
    // Best-effort, like every other state write here: a daemon that cannot
    // write it still runs, and the wrappers fall back to the old
    // reply-shape check (which is what an older daemon gives them anyway).
    if let Err(e) = crate::persist::write_atomic(
        &path,
        serde_json::to_string(&body).unwrap_or_default().as_bytes(),
    ) {
        eprintln!(
            "⚠ could not write {} ({e}) - the desktop wrapper will fall back to \
             identifying this daemon by its reply alone",
            path.display()
        );
    }
}

/// The launcher-handshake answer for a challenge, or None if the caller
/// did not send one.
///
/// The nonce is bounded and charset-checked before it is hashed: it lands
/// in a JSON response and comes from an unauthenticated caller.
fn launcher_proof(token: &str, nonce: Option<&str>) -> Option<String> {
    use sha2::{Digest, Sha256};
    if token.is_empty() {
        return None; // see the mint site: no token, no answer
    }
    let nonce = nonce
        .filter(|n| (8..=128).contains(&n.len()) && n.bytes().all(|b| b.is_ascii_alphanumeric()))?;
    let mut h = Sha256::new();
    h.update(token.as_bytes());
    h.update(b":");
    h.update(nonce.as_bytes());
    Some(hex::encode(h.finalize()))
}

/// First-run API key generation, for every launcher including the
/// container. The Docker entrypoint used to carry a second copy of this
/// (same file, same path, same resolution order); it now only pre-flights
/// the cases where the fallbacks below would leave a published port
/// keyless, and refuses to start instead (packaging/docker-entrypoint.sh).
///
/// Until now only Docker did this. systemd, launchd, homebrew services,
/// NzbFast.app, the tray and a bare `nzbfast serve` all started keyless
/// on 0.0.0.0, where the auth computation's `(None, None) => true` arm
/// makes every request fully authorized: anything on the LAN - or any
/// web page the user happens to visit, since the SAB-compatible API is
/// all GETs with no Origin check - could read the provider password back
/// in cleartext (`mode=server_secret`), point the post-processing script
/// at a program of its choice (`mode=config&name=script`), delete the
/// queue with its files, and shut the daemon down. Minting the key here
/// instead of in five launcher scripts covers every launcher at once.
///
/// Resolution order mirrors the container:
///   1. `--apikey` (or a dashboard-saved apikey) -> use it, untouched.
///   2. `NZBFAST_OPEN=1`                         -> deliberately keyless.
///   3. a previously generated key file          -> reuse it, so the key
///      is stable across restarts.
///   4. a FIRST run and none of the above        -> generate, persist, and
///      return it so the caller can print it once, prominently.
///
/// (4) is the load-bearing case, and its gate is deliberately narrow. An
/// install that is ALREADY running keyless must never have a key appear
/// underneath it: that would break the user's configured Sonarr/Radarr
/// and phone remotes on a restart they never connected to a config
/// change, with no error that points at the cause. So "first run" here
/// means the install has never completed a run at all - no dashboard
/// settings file AND no daemon spool. The config file itself is NOT part
/// of the test: the setup wizard writes it before the first `serve`, so a
/// fresh install has one.
///
/// Every signal is read from the DATA DIRECTORY, and only from there. The
/// download root is NOT a first-run signal, and must never be added as
/// one - it was, as belt and braces, and it was a security regression:
///
///   * A reinstall wipes the data dir but deliberately keeps downloads
///     (the uninstaller asks separately and defaults to keeping them). A
///     `.spool` left in the download root by an install from days earlier
///     then made a genuinely fresh install look established, so no key was
///     minted and the daemon came up open on 0.0.0.0. On Windows that is
///     invisible: no console, and the dashboard's log panel is unix-only.
///   * The test it was meant to strengthen cannot be strengthened this
///     way, because a credential can only live in `settings.json` or the
///     `apikey` file, and both are in the data dir. A spool in the
///     download root is evidence that downloads once happened there, not
///     evidence that a key is in use.
///
/// The pre-migration spool location is still honoured everywhere it
/// matters - `spool_dir` migrates it a few lines into `serve` - and a real
/// legacy install is still recognised here, by its data-dir settings file.
///
/// What to tell someone whose API key file is unusable.
///
/// Carried by both the console error and, on Windows, the tray's own
/// message box - the tray user never sees a console, and the generic
/// "stopped unexpectedly, try Restart" it used to show was worse than
/// nothing: restarting fails identically every time, forever.
///
/// `MARKER` is what the tray greps the log for. Keep them in step.
pub const KEYLESS_MARKER: &str = "nzbfast cannot start: API key file";

fn keyless_help(keyfile: &std::path::Path, what: &str) -> String {
    format!(
        "{KEYLESS_MARKER} {what}.\n\n\
         Your API key is what stops other machines on your network from \
         controlling nzbfast, so it will not start without one. Nothing \
         has been downloaded twice, and nothing has been lost: the queue, \
         history and settings are untouched.\n\n\
         File: {}\n\n\
         Pick whichever fits:\n\
         1. If you know your key (it is in Sonarr/Radarr under this \
            download client), put it back in that file on one line.\n\
         2. If you do not, DELETE the file and start nzbfast again. It \
            creates a new key and shows it to you. You will then need to \
            paste the new key into Sonarr, Radarr or any other app that \
            connects to nzbfast.\n\
         3. Only if this machine is not reachable by anyone else, set \
            NZBFAST_OPEN=1 to run with no key at all.\n\n\
         An empty file usually means the disk filled up or the machine \
         lost power while the file was being written.",
        keyfile.display()
    )
}

/// Returns `Some((key, keyfile))` only when a key was newly generated.
fn first_run_apikey(
    opts: &mut ServeOpts,
    settings_path: &std::path::Path,
    config: &std::path::Path,
) -> Result<Option<(String, PathBuf)>> {
    // Normalise `--apikey ""` (and whitespace) to "no key given" FIRST.
    // Left as Some(""), it short-circuited every check below AND
    // suppressed the open-API banner, because `d.apikey` was not None -
    // then `ct_eq("", "")` authorised `?apikey=`. That was a quieter
    // fail-open than the ones this function exists to close. Empty
    // values from settings.json were already filtered this way.
    if opts.apikey.as_deref().is_some_and(|k| k.trim().is_empty()) {
        opts.apikey = None;
    }
    if opts.apikey.is_some() {
        return Ok(None); // explicit operator choice wins
    }
    if std::env::var("NZBFAST_OPEN").is_ok_and(|v| v == "1") {
        return Ok(None); // deliberately keyless, e.g. behind another auth layer
    }
    let keyfile = config.with_file_name("apikey");
    match std::fs::read_to_string(&keyfile) {
        // Reuse a key we minted earlier. Stable across restarts, which is
        // the whole point - the *arrs hold it.
        Ok(k) if !k.trim().is_empty() => {
            opts.apikey = Some(k.trim().to_string());
            return Ok(None);
        }
        // Present but empty or unreadable. Never continue keyless: the
        // default listener is 0.0.0.0 and `None` grants full control API
        // access, including provider-secret reads and config writes.
        // Refusing startup preserves the old credential and makes the
        // operator repair the explicit fault instead of silently failing
        // open.
        // The wording matters more than usual here: this is the only
        // message a user gets, it appears at the one moment the app will
        // not start, and the previous version named three remedies
        // without saying what any of them would cost. "Restore the key"
        // is not advice to someone whose key file just went empty - they
        // do not have it to restore. So: say what happened, say why we
        // stop, then give the options in the order most people want them,
        // each with its consequence attached.
        Ok(_) => {
            anyhow::bail!("{}", keyless_help(&keyfile, "is empty"));
        }
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
            anyhow::bail!(
                "{}",
                keyless_help(&keyfile, &format!("could not be read ({e})"))
            );
        }
        Err(_) => {} // no key file at all - fall through to the first-run test
    }
    // Data-dir signals ONLY. `opts.out_root` (the download root) must not
    // join this test - see the note above; a leftover spool there survives
    // an uninstall and would suppress minting on a fresh install.
    let spool = config.with_file_name(".spool");
    if spool.exists() || settings_beyond_setup_answers(settings_path) {
        // An existing install. Leave it EXACTLY as it was - EXCEPT when
        // the settings store itself failed to load. A key set in the
        // dashboard is written to settings.json and NOWHERE else (the
        // config handler only touches the keyfile to delete it), so an
        // unreadable or torn settings.json drops that key, load_settings
        // degrades to an empty map, and the daemon comes up wide open on
        // the default 0.0.0.0 listener. Same uid-change and torn-write
        // causes the keyfile branch above guards against, same answer.
        // The container entrypoint has refused this for a while; the
        // native launchers did not.
        if opts.apikey.is_none() && crate::persist::json_store_unreadable(settings_path) {
            anyhow::bail!(
                "{} could not be read, and any API key saved in Settings lives there; \
                 refusing to start the control API without authentication. Restore it \
                 (a .bak or .corrupt sibling may hold it), pass --apikey, or set \
                 NZBFAST_OPEN=1 to run deliberately keyless",
                settings_path.display()
            );
        }
        return Ok(None);
    }
    let key = match random_apikey() {
        Some(k) => k,
        None => anyhow::bail!(
            "could not read OS entropy for an API key; refusing to start the control API \
             without authentication"
        ),
    };
    // Persist first, so the key the user is about to paste into Sonarr
    // survives the next restart. write_atomic creates it 0600 on unix and
    // fsyncs before the rename, so a crash cannot leave a torn key.
    //
    // If it cannot be stored we still USE it for this session rather than
    // falling back to open: the daemon is then keyed (safe) but the key
    // changes on the next start, which the message says outright. On a
    // first run nothing has been wired up yet, so an unstable key costs
    // far less than an open control API.
    if let Err(e) = crate::persist::write_atomic(&keyfile, key.as_bytes()) {
        eprintln!(
            "⚠ generated an API key but could not save it to {} ({e}) - it will CHANGE on the \
             next start. Set one in Settings, or pass --apikey, to make it stick.",
            keyfile.display()
        );
    }
    opts.apikey = Some(key.clone());
    Ok(Some((key, keyfile)))
}

/// Install the daemon's live ingest policy on an Index connection. The
/// shared tip connection is reopened after full scans, so neither custom
/// classification nor its gate closure can be assumed to survive.
#[cfg(feature = "indexer")]
fn install_live_ingest_policy(
    ix: &mut nzbkit::index::Index,
    gates: Option<crate::gates::Gates>,
    cats: Vec<nzbkit::categories::CustomCategory>,
) {
    let gate_cats = cats.clone();
    ix.set_gate(Box::new(move |stem| {
        gates
            .as_ref()
            .is_none_or(|g| g.allows_with(stem, &gate_cats))
    }));
    ix.set_custom(cats);
}

/// A `cat=` value the wall/browse APIs may filter on: a built-in kind or
/// a custom-category slug (lowercase alnum + '-'). The filter is a bound
/// SQL parameter, so this is a shape check, not a security boundary - an
/// unknown slug simply matches no rows.
#[cfg(feature = "indexer")]
fn is_kind_slug(k: &str) -> bool {
    !k.is_empty()
        && k.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// Parse "500M"/"10G"/"1.5T" (SAB-style size strings) to bytes.
pub fn parse_size(s: &str) -> Option<u64> {
    let s = s.trim();
    // BITS when the user says bits, and this is not a nicety: every ISP
    // on earth advertises a line in megaBITS, so "900M" in the Line
    // speed box is what a person with a 900 Mbps connection types - and
    // it was read as 900 MB/s, eight times their actual line. The tuner
    // then scored a perfectly good 37 MB/s as "4% of your line" (field
    // report, 4 Aug).
    //
    // Nothing existing changes meaning: every suffixed form below is
    // REJECTED by this function today (only a bare 900M or 1G parses at
    // all), so this can only turn a refusal into a number. A bare
    // magnitude stays BYTES, because that is what it has always meant
    // here and 29 call sites depend on it - the disk and cache settings
    // are not secretly about bits.
    let s = s
        .strip_suffix("/s")
        .or_else(|| s.strip_suffix("/S"))
        .unwrap_or(s)
        .trim_end();
    // Case matters exactly where the convention says it does: `b` is
    // bits, `B` is bytes. The spelled-out forms are case-insensitive
    // because nobody typing "Mbps" means anything else.
    let lower = s.to_ascii_lowercase();
    let (s, bits) = if let Some(rest) = lower
        .strip_suffix("bits")
        .or_else(|| lower.strip_suffix("bit"))
        .or_else(|| lower.strip_suffix("bps"))
    {
        (&s[..rest.len()], true)
    } else if let Some(rest) = s.strip_suffix('b') {
        (rest, true)
    } else if let Some(rest) = s.strip_suffix('B') {
        (rest, false)
    } else {
        (s, false)
    };
    let s = s.trim_end();
    let (num, mult) = match s.chars().last()? {
        'k' | 'K' => (&s[..s.len() - 1], 1e3),
        'm' | 'M' => (&s[..s.len() - 1], 1e6),
        'g' | 'G' => (&s[..s.len() - 1], 1e9),
        't' | 'T' => (&s[..s.len() - 1], 1e12),
        _ => (s, 1.0),
    };
    let v: f64 = num.trim().parse().ok()?;
    let bytes = if bits { v * mult / 8.0 } else { v * mult };
    (v >= 0.0).then_some(bytes as u64)
}

/// (free, total) bytes of the filesystem holding `path`.
#[cfg(all(unix, not(target_os = "macos")))]
fn disk_stat(path: &std::path::Path) -> Option<(u64, u64)> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
    (unsafe { libc::statvfs(c.as_ptr(), &mut s) } == 0).then(|| {
        (
            s.f_bavail as u64 * s.f_frsize as u64,
            s.f_blocks as u64 * s.f_frsize as u64,
        )
    })
}
/// macOS carries statvfs block counts in a 32-bit `fsblkcnt_t`, so a
/// volume past 2^32 blocks (16 TiB at APFS's 4 KiB) wraps and we read a
/// number reduced modulo that: a 22 TB drive measures 4.4 TB, and free
/// can come out LARGER than total. Everything downstream believes it -
/// the dashboard, the SAB/nzbget diskspace fields the *arrs read, the
/// min-free guard, and the extraction bomb budget, which then aborts a
/// healthy unpack as a "decompression bomb" on a disk with terabytes
/// spare. statfs(2) reports the same counts in uint64_t fields, and its
/// f_bsize is the same allocation block size, so ask it instead.
#[cfg(target_os = "macos")]
fn disk_stat(path: &std::path::Path) -> Option<(u64, u64)> {
    use std::os::unix::ffi::OsStrExt;
    let c = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut s: libc::statfs = unsafe { std::mem::zeroed() };
    (unsafe { libc::statfs(c.as_ptr(), &mut s) } == 0)
        .then(|| (s.f_bavail * s.f_bsize as u64, s.f_blocks * s.f_bsize as u64))
}
/// Windows has no statvfs. GetDiskFreeSpaceExW takes a directory (a
/// file path fails, which the ancestor walk in `free_bytes` absorbs by
/// stepping up) and answers per-volume, including for UNC shares and
/// mounted folders - so a download dir on a mapped NAS is measured on
/// the NAS, not on C:.
///
/// "Free" is bytes-available-TO-THE-CALLER, the statvfs f_bavail
/// analogue: under a disk quota that is the number the guard must use,
/// since it's what this process can actually write.
#[cfg(windows)]
fn disk_stat(path: &std::path::Path) -> Option<(u64, u64)> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    // An interior NUL would silently truncate the path and measure the
    // wrong volume; reject rather than answer about somewhere else.
    if wide.contains(&0) {
        return None;
    }
    wide.push(0);
    let (mut free, mut total) = (0u64, 0u64);
    let ok =
        unsafe { GetDiskFreeSpaceExW(wide.as_ptr(), &mut free, &mut total, std::ptr::null_mut()) };
    (ok != 0).then_some((free, total))
}
#[cfg(not(any(unix, windows)))]
fn disk_stat(_path: &std::path::Path) -> Option<(u64, u64)> {
    None
}

/// Free bytes of the filesystem that holds - or will hold - `path`.
///
/// `statvfs` needs a path that EXISTS, and the output directory often
/// doesn't yet: first run before anything has been downloaded, a
/// per-category subfolder created at job time, or (the dangerous one) a
/// NAS mount point whose share isn't mounted. A bare `disk_stat` returns
/// None there, and None silently DISABLES the min-free guard - the
/// download then fills the very disk the guard was set up to protect.
/// The filesystem that will hold `path` is the one holding its nearest
/// existing ancestor, so fall back to asking that.
pub(crate) fn free_bytes(path: &std::path::Path) -> Option<u64> {
    disk_stat_walk(path).map(|(free, _)| free)
}

/// (free, total) of the filesystem that holds - or will hold - `path`,
/// via the same nearest-existing-ancestor walk. The dashboard and the
/// NZBGet-compat status report went through bare `disk_stat` instead
/// and turned "directory not created yet" into "0 MB free on disk" -
/// which the *arrs read as a full disk.
pub(crate) fn disk_stat_walk(path: &std::path::Path) -> Option<(u64, u64)> {
    let mut p = path;
    loop {
        if let Some(stat) = disk_stat(p) {
            return Some(stat);
        }
        p = match p.parent() {
            // A relative path runs out of ancestors at ""; the cwd is the
            // filesystem it resolves against.
            Some(q) if q.as_os_str().is_empty() => std::path::Path::new("."),
            Some(q) => q,
            None => return None,
        };
        if p == std::path::Path::new(".") {
            return disk_stat(p);
        }
    }
}

/// Downloaded-bytes ledger for the quota window, persisted in the spool
/// so restarts don't forget a spent budget.
struct QuotaLedger {
    path: PathBuf,
    period: char,
    start: u64,
    bytes: u64,
}

impl QuotaLedger {
    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// Start of the current period (UTC midnight / 1st of month).
    fn period_start(period: char) -> u64 {
        let now = Self::now();
        let day = 86_400;
        match period {
            'm' => {
                // Days since epoch → walk back to day-of-month 1. Epoch
                // was a Thursday, Jan 1 1970; use civil-from-days math.
                let days = now / day;
                let dom = civil_from_days(days as i64).2 as u64; // 1-based
                (days - (dom - 1)) * day
            }
            _ => now / day * day,
        }
    }

    fn open(spool: &std::path::Path, period: char) -> Self {
        let path = spool.join("quota.json");
        let mut led = QuotaLedger {
            path,
            period,
            start: Self::period_start(period),
            bytes: 0,
        };
        // Opened from the download runner's tick, which is a tokio task:
        // the read (and the .bak refresh it may write) is disk IO that
        // must not run undemoted on a worker thread.
        if let Some(v) =
            crate::persist::blocking_db(|| crate::persist::load_json_with_backup(&led.path))
        {
            let start = v["start"].as_u64().unwrap_or(0);
            if start == led.start {
                led.bytes = v["bytes"].as_u64().unwrap_or(0);
            }
        }
        led
    }

    /// Roll the window if a new period began; returns bytes spent so far.
    fn spent(&mut self) -> u64 {
        let cur = Self::period_start(self.period);
        if cur != self.start {
            self.start = cur;
            self.bytes = 0;
            self.save();
        }
        self.bytes
    }

    fn add(&mut self, n: u64) {
        self.spent();
        self.bytes += n;
        self.save();
    }

    fn save(&self) {
        let _ = crate::persist::write_atomic(
            &self.path,
            json!({"start": self.start, "bytes": self.bytes})
                .to_string()
                .as_bytes(),
        );
    }
}

/// (year, month, day) from days-since-epoch - Howard Hinnant's civil
/// calendar algorithm, used for monthly quota rollover.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Open the dashboard in the user's default browser, shortly after the
/// listener is up (a small delay lets the accept loop start so the first
/// request doesn't race the bind). Best-effort - failures are ignored.
/// `key` is Some only on the run that MINTED it: the page adopts it into
/// localStorage and strips it from the address bar, so the first
/// double-click launch lands on a working dashboard instead of a prompt
/// for a credential the user has never seen (the .app and the Windows
/// installer send the banner to a log file nobody opens). A key already
/// in the browser needs no help, so it is never re-sent.
fn open_dashboard(port: u16, key: Option<String>) {
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(500));
        let q = key.map(|k| format!("?apikey={k}")).unwrap_or_default();
        let url = format!("http://localhost:{port}/{q}");
        #[cfg(target_os = "macos")]
        let mut cmd = {
            let mut c = std::process::Command::new("open");
            c.arg(&url);
            c
        };
        #[cfg(target_os = "windows")]
        let mut cmd = {
            let mut c = std::process::Command::new("cmd");
            c.args(["/C", "start", "", &url]);
            c
        };
        #[cfg(all(unix, not(target_os = "macos")))]
        let mut cmd = {
            let mut c = std::process::Command::new("xdg-open");
            c.arg(&url);
            c
        };
        let _ = cmd
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();
    });
}

/// Overlay dashboard-saved settings (settings.json) onto the launch
/// flags: a value once changed in the UI wins on every later launch,
/// until its key is deleted from the file.
fn apply_saved_settings(opts: &mut ServeOpts, path: &std::path::Path) {
    let saved = load_settings(path);
    if saved.is_empty() {
        return;
    }
    info!(target: "settings", "applying saved settings from {}", path.display());
    let s = |k: &str| saved.get(k).and_then(Value::as_str);
    let n = |k: &str| saved.get(k).and_then(Value::as_u64);
    let b = |k: &str| saved.get(k).and_then(Value::as_bool);
    let list = |k: &str| {
        saved.get(k).and_then(Value::as_array).map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
    };
    let opt_path = |v: &str| (!v.is_empty()).then(|| PathBuf::from(v));
    // Range-checked exactly as the settings writer checks it: this file
    // can be hand-edited, and `as u16` would silently turn a typo'd
    // 70000 into 4464 - a port nothing expects and the mac wrapper (which
    // validates 1-65535 before it connects) can never find. An
    // out-of-range value is ignored, keeping the CLI or default port.
    if let Some(v) = n("port").filter(|v| (1..=65535).contains(v)) {
        // Unless the launcher owns the port. The API refuses to save one
        // in that case, so this only fires for a file carried over from a
        // desktop install or hand-edited - and honouring it would move the
        // listener away from a published mapping, a healthcheck or DSM's
        // Open button, with nothing in the UI to explain where it went.
        if port_locked() {
            if v as u16 != opts.port {
                info!(
                    target: "settings",
                    "ignoring saved port {v}: this installation's port is set by \
                     how it was started ({}). Change the published/mapped port instead.",
                    opts.port
                );
            }
        } else {
            opts.port = v as u16;
        }
    }
    if let Some(v) = s("bind").filter(|v| !v.is_empty()) {
        opts.bind = v.to_string();
    }
    if let Some(v) = s("out_dir").filter(|v| !v.is_empty()) {
        opts.out_root = PathBuf::from(v);
    }
    if let Some(v) = s("watch") {
        opts.watch = opt_path(v);
    }
    if let Some(v) = s("script") {
        opts.script = opt_path(v);
    }
    if let Some(v) = n("connections") {
        opts.connections = (v as usize).max(1);
    }
    if let Some(v) = n("window") {
        opts.window = (v as usize).max(1);
    }
    if let Some(v) = n("decoders") {
        opts.decoders = (v as usize).max(1);
    }
    if let Some(v) = b("fast_verify") {
        opts.fast_verify = v;
    }
    if let Some(v) = s("verify_mode") {
        match v {
            "full" => (opts.fast_verify, opts.verify_lean) = (false, false),
            "fast" => (opts.fast_verify, opts.verify_lean) = (true, false),
            "lean" => (opts.fast_verify, opts.verify_lean) = (true, true),
            _ => {}
        }
    }
    if let Some(v) = n("min_free") {
        // `Some(0)`, NOT None: 0 is the user saying OFF, and the launch
        // default is non-zero (MIN_FREE_DEFAULT). Collapsing a saved 0
        // into "nothing was saved" handed those installs the default
        // back on every restart, which is the one answer the person who
        // typed 0 had ruled out.
        opts.min_free = Some(v);
    }
    if let Some(v) = n("auto_retry_mins") {
        opts.auto_retry_mins = v;
    }
    // Stored as the octal STRING the user typed ("002"), because that is
    // what every guide about this prints and what the field shows back.
    // Parsed here exactly as the settings writer parses it; anything else
    // is ignored and the install keeps its current behaviour rather than
    // silently adopting a mode nobody chose.
    if let Some(v) = s("out_umask") {
        opts.out_umask = if v.trim().is_empty() {
            None
        } else {
            u32::from_str_radix(v.trim(), 8)
                .ok()
                .filter(|m| *m <= 0o777)
        };
    }
    if let Some(v) = b("preflight") {
        opts.preflight = v;
    }
    if let Some(v) = n("quota") {
        opts.quota = (v > 0).then_some(v);
    }
    if let Some(v) = s("quota_period").and_then(|v| v.chars().next()) {
        opts.quota_period = v;
    }
    if let Some(v) = n("speedlimit") {
        opts.speedlimit = Some(v.to_string()); // parse_size takes bare bytes
    }
    if let Some(v) = b("auto_speed") {
        opts.auto_speed = v;
    }
    if let Some(v) = list("library_cats") {
        opts.library_cats = v;
    }
    if let Some(v) = n("library_recheck_secs") {
        opts.library_recheck_secs = v.max(1);
    }
    #[cfg(feature = "indexer")]
    if let Some(v) = s("index_db").filter(|v| !v.is_empty()) {
        opts.index_db = PathBuf::from(v);
    }
    #[cfg(feature = "indexer")]
    if let Some(v) = list("index_groups") {
        opts.index_groups = v;
    }
    #[cfg(feature = "indexer")]
    if let Some(v) = n("index_interval_secs") {
        opts.index_interval_secs = v;
    }
    #[cfg(feature = "indexer")]
    if let Some(v) = n("index_backfill") {
        opts.index_backfill = v;
    }
    if let Some(v) = b("group_desc_isc") {
        opts.group_desc_isc = v;
    }
    if let Some(v) = s("apikey") {
        opts.apikey = (!v.is_empty()).then(|| v.to_string());
    }
    if let Some(v) = s("nzbkey") {
        opts.nzbkey = (!v.is_empty()).then(|| v.to_string());
    }
    if let Some(v) = n("mem_limit") {
        opts.mem_budget = if v > 0 {
            nzbkit::mem::MemBudget::with_total(v)
        } else {
            nzbkit::mem::MemBudget::auto()
        };
    }
    #[cfg(feature = "indexer")]
    if let Some(v) = n("index_max_age_secs") {
        opts.index_max_age_secs = v;
    }
    #[cfg(feature = "indexer")]
    if let Some(v) = s("index_gates") {
        opts.index_gates = if v.trim().is_empty() {
            None
        } else {
            match crate::gates::Gates::from_json(v) {
                Ok(g) => Some(g),
                Err(e) => {
                    warn!(target: "settings", "ignoring saved index_gates: {e}");
                    opts.index_gates.take()
                }
            }
        };
    }
    // "schedule" and "feeds" (JSON text) are handled in serve(): they
    // need parsing and the daemon to exist.
}

/// Apply one settings-UI change to the running daemon. Returns
/// `(applied_live, persist_value)` - `persist_value` is what lands in
/// settings.json under `name`. `applied_live = false` marks the few
/// settings that only take effect on the next launch.
/// Where the update checker looks for the release manifest. GitHub's
/// /releases/latest/download/ path always serves the newest release's
/// signed manifest over its CDN, no auth. The manifest is ed25519-signed
/// and hard-verified against the baked-in key, so the origin is untrusted
/// anyway - controlling it (or a MITM) cannot forge an update. Overridable
/// via the live update_url setting; unreachable = silently up to date.
const DEFAULT_UPDATE_URL: &str =
    "https://github.com/nzbfast/nzbfast/releases/latest/download/latest.json";

/// ed25519 public key that every accepted update manifest must be signed
/// with. The private half is held offline by the release manager and never
/// touches the repo, a build server, or the update origin - so controlling
/// the update origin (the GitHub account, or a MITM position) is
/// NOT enough to push code: an attacker would also need the offline signing
/// key. sha256 in the manifest only proves the payload matches the manifest;
/// this proves the manifest itself is ours. Rotate by generating a new pair
/// (examples/update_sign.rs `keygen`) and shipping a build with the new key
/// BEFORE signing the next release with the new private key.
const UPDATE_PUBKEY_HEX: &str = "863349474b98569e9a00d06ad3a7385f564b76aed97a7ff60fca713b9c4731ba";

/// Verify a detached ed25519 signature (hex, 64 bytes) over the exact
/// manifest bytes using [`UPDATE_PUBKEY_HEX`]. Any failure - unparseable
/// key, bad signature length, or a signature that does not verify - is a
/// hard refusal: an unsigned or wrongly-signed manifest is treated as
/// hostile, never as "up to date".
fn verify_manifest_sig(manifest: &[u8], sig_hex: &[u8]) -> Result<(), String> {
    verify_with_key(UPDATE_PUBKEY_HEX, manifest, sig_hex)
}

/// Signature check against an explicit hex public key. Split out from
/// [`verify_manifest_sig`] so tests can exercise the exact verification
/// path with an ephemeral key, without needing the production private key.
fn verify_with_key(pubkey_hex: &str, manifest: &[u8], sig_hex: &[u8]) -> Result<(), String> {
    use ed25519_dalek::{Signature, VerifyingKey};
    let key_raw: [u8; 32] = hex::decode(pubkey_hex)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or("update key is malformed")?;
    let vk = VerifyingKey::from_bytes(&key_raw).map_err(|e| format!("update key: {e}"))?;
    let sig_txt = std::str::from_utf8(sig_hex).map_err(|_| "signature file is not text")?;
    let sig_raw: [u8; 64] = hex::decode(sig_txt.trim())
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or("signature is not 64 hex-encoded bytes")?;
    let sig = Signature::from_bytes(&sig_raw);
    vk.verify_strict(manifest, &sig)
        .map_err(|_| "manifest signature does not verify - refusing update".to_string())
}

/// Dotted-numeric version compare: is `remote` newer than `local`?
/// Non-numeric fragments compare as 0 ("4.6.0-beta" == "4.6.0").
fn version_newer(remote: &str, local: &str) -> bool {
    let parse = |s: &str| -> Vec<u64> {
        s.trim_start_matches(['v', 'V'])
            .split(['.', '-'])
            .map(|p| p.parse::<u64>().unwrap_or(0))
            .collect()
    };
    let (r, l) = (parse(remote), parse(local));
    for i in 0..r.len().max(l.len()) {
        let (a, b) = (
            r.get(i).copied().unwrap_or(0),
            l.get(i).copied().unwrap_or(0),
        );
        if a != b {
            return a > b;
        }
    }
    false
}

/// GET a small update-channel resource (manifest or its signature) into
/// memory. Capped at 1 MiB - both are tiny; a huge body is a sign the URL
/// is wrong, not a real manifest.
fn fetch_update_resource(url: &str) -> std::result::Result<Vec<u8>, String> {
    // GitHub's stable manifest URL (/releases/latest/download/...)
    // redirects TWICE - repo → tagged asset → CDN. Without an explicit
    // redirect budget the chain isn't followed to the end and the body
    // arrives empty ("expected value at line 1 column 1").
    // Through the SSRF guard like every other outbound fetch. `update_url` is
    // an operator-settable value (and settable by anyone at all on a keyless
    // install), and this was the one fetch path that dialled a raw agent - so
    // it reached exactly the cloud-metadata and link-local addresses
    // `is_forbidden_fetch_ip` exists to block, on a 6-hourly repeating loop,
    // and returned the transport error verbatim as a reachability oracle.
    let resp = ssrf_safe_agent(10, 15)
        .get(url)
        .call()
        .map_err(|e| format!("{e}"))?;
    use std::io::Read as _;
    let mut body = Vec::new();
    resp.into_reader()
        .take(1024 * 1024)
        .read_to_end(&mut body)
        .map_err(|e| format!("read: {e}"))?;
    Ok(body)
}

/// Fetch a manifest AND its detached `.sig`, verify the signature against
/// the embedded key, and only then parse the JSON. An unreachable manifest
/// surfaces as a distinct error so the caller can stay quiet about it
/// (default channel, no site yet); a manifest that is present but unsigned
/// or wrongly signed is a LOUD refusal - that is the attack we care about.
fn fetch_manifest(url: &str) -> std::result::Result<Value, String> {
    let body = fetch_update_resource(url).map_err(|e| format!("update check: {e}"))?;
    // Signature lives beside the manifest: latest.json -> latest.json.sig.
    let sig_url = format!("{url}.sig");
    let sig = fetch_update_resource(&sig_url)
        .map_err(|e| format!("update manifest is unsigned (no {sig_url}: {e}) - refusing"))?;
    verify_manifest_sig(&body, &sig)?;
    serde_json::from_slice(&body).map_err(|e| format!("update manifest: {e}"))
}

/// Record the `serial` of a signature-verified manifest, advancing the
/// local anti-rollback ratchet.
///
/// The attack this exists for: an attacker who can serve stale bytes -
/// a MITM, a cache, a hostile mirror, a stuck CDN edge - replays an OLD
/// but genuinely-signed manifest. Every signature checks out, because it
/// really was ours. Version comparison alone does not catch it either:
/// the client simply never learns a newer release exists and sits on a
/// version with known bugs indefinitely. The defence is a value inside
/// the SIGNED body that only ever goes up, plus the highest one seen
/// kept locally, so a replayed manifest is recognisable as older than
/// something this machine has already been told about.
///
/// Deliberately clock-free. The serial is compared only against our own
/// stored value, never against the local time, so a machine with a wrong
/// clock cannot lock itself out of updates - which is why this is a
/// serial and not a `not_before`.
///
/// **This build does not refuse anything.** It records, and it warns on a
/// regression so we can see in the field whether serials are actually
/// monotonic before any release depends on it. See `update_serial_seen`.
fn note_manifest_serial(d: &Arc<Daemon>, m: &Value) {
    use std::sync::atomic::Ordering;
    let seen = d.update_serial_seen.load(Ordering::Relaxed);
    match serial_ratchet(seen, m) {
        SerialStep::Advance(serial) => {
            d.update_serial_seen.store(serial, Ordering::Relaxed);
            save_setting(&d.settings_path, "update_serial_seen", json!(serial));
        }
        SerialStep::Regressed { got, seen } => warn!(
            target: "update",
            "manifest serial {got} is older than {seen}, already seen from this \
             channel - a stale or replayed manifest. NOT refused: this build only records \
             serials, it does not enforce them yet."
        ),
        SerialStep::Hold => {}
    }
}

/// What a manifest's serial should do to the stored ratchet value. Split
/// out from [`note_manifest_serial`] so the decision can be tested without
/// building a whole `Daemon`, the same way [`verify_with_key`] is.
#[derive(Debug, PartialEq)]
enum SerialStep {
    /// Higher than anything seen: store and persist it.
    Advance(u64),
    /// Lower than what we have seen. The replay signal - reported, and in
    /// this build nothing more than reported.
    Regressed { got: u64, seen: u64 },
    /// Unchanged, absent, or unusable: leave the stored value alone.
    Hold,
}

fn serial_ratchet(seen: u64, m: &Value) -> SerialStep {
    // A missing serial means a manifest predating the serial rollout, which
    // is normal during it. Crucially it must HOLD rather than clear: if an
    // absent serial reset the ratchet, replaying a pre-serial manifest would
    // become the way to disarm this defence and re-open rollback.
    //
    // `as_u64` also does the validation - a string "999999", a float, or a
    // negative number all yield None and hold. That matters in the other
    // direction too: coercing junk into a huge serial would pin an install
    // above every real release it will ever be offered.
    let Some(serial) = m.get("serial").and_then(Value::as_u64) else {
        return SerialStep::Hold;
    };
    if serial < seen {
        SerialStep::Regressed { got: serial, seen }
    } else if serial == seen {
        SerialStep::Hold // steady state: same manifest as last check, no write
    } else {
        SerialStep::Advance(serial)
    }
}

fn check_update(d: &Arc<Daemon>) -> std::result::Result<Option<Value>, String> {
    let url = d.update_url.lock_ok().clone();
    if url.is_empty() {
        return Ok(None);
    }
    let m: Value = fetch_manifest(&url)?;
    // Before the version comparison, and on EVERY verified manifest rather
    // than only on ones advertising an upgrade: the steady-state manifest
    // (same version as ours) is what establishes the ratchet floor, and it
    // is the one a replay attack has to beat.
    note_manifest_serial(d, &m);
    let remote = m
        .get("version")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    if !remote.is_empty() && version_newer(&remote, env!("CARGO_PKG_VERSION")) {
        *d.update_manifest.lock_ok() = Some(m.clone());
        Ok(Some(m))
    } else {
        *d.update_manifest.lock_ok() = None;
        Ok(None)
    }
}

/// Where the update banner sends users. Hard-coded on purpose: the
/// manifest supplies only a version string, never a link, so a
/// compromised update channel cannot redirect anyone. Self-update was
/// removed in 1.0.5 (notify-only) - there is no code that downloads or
/// replaces the running binary.
const DOWNLOAD_URL: &str = "https://github.com/nzbfast/nzbfast/releases/latest";

/// True when a native wrapper (Mac .app / Windows installer) owns this
/// binary: it sets NZBFAST_BUNDLED=1 at spawn.
fn bundled_install() -> bool {
    std::env::var("NZBFAST_BUNDLED").is_ok_and(|v| v == "1")
}

/// True when we are running inside a container image.
///
/// Deliberately NOT `bundled_install()`: the Mac .app and the Windows
/// tray set NZBFAST_BUNDLED=1 too, and telling a Mac user to open
/// Container Manager would be nonsense. The runtime's own marker files
/// are the signal, and they are the only one that works for the images
/// already in the field - an env var we add to the entrypoint today only
/// exists after the update it is meant to explain how to install.
/// Cached: the answer cannot change while the process runs, and this is
/// read on every queue poll (once a second per open dashboard).
fn container_install() -> bool {
    static IN_CONTAINER: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *IN_CONTAINER.get_or_init(|| {
        std::path::Path::new("/.dockerenv").exists()              // Docker
            || std::path::Path::new("/run/.containerenv").exists() // Podman
            // Escape hatch for runtimes that drop neither marker file,
            // and the only way to exercise the container UI off a NAS.
            || std::env::var("NZBFAST_CONTAINER").is_ok_and(|v| v == "1")
    })
}

/// True when the LAUNCHER owns the listening port and the dashboard must
/// not move it.
///
/// A saved `port` otherwise beats the `--port` flag on every later start,
/// which is right for a desktop or a plain CLI install and wrong
/// everywhere the port is baked in somewhere we cannot reach:
///
/// - a container publishes `6789:6789` and healthchecks that port, so an
///   internal move makes the service unreachable AND unhealthy;
/// - the Synology package bakes `adminport` at install time, so a move
///   takes the listener away from DSM's own Open button;
/// - a fixed system service or firewall rule has the same shape.
///
/// Detected from the environment rather than inferred from
/// `container_install()`: an operator running the image with
/// `--network host` and no published mapping legitimately owns their own
/// port, and the entrypoint knows which case it is. The images and the
/// SPK set it; nothing else does.
fn port_locked() -> bool {
    static LOCKED: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *LOCKED.get_or_init(|| std::env::var("NZBFAST_PORT_LOCKED").is_ok_and(|v| v == "1"))
}

fn epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Fetch the full newsgroup catalogue from the primary server: LIST
/// ACTIVE (mandatory) + LIST NEWSGROUPS (optional descriptions - many
/// binary providers reject it, which just means blank descriptions).
/// Where ISC publishes the community's newsgroup descriptions: about
/// 45,000 of them, refreshed hourly, one `group<TAB>description` per line.
#[cfg(feature = "indexer")]
const ISC_NEWSGROUPS_URL: &str = "https://ftp.isc.org/pub/usenet/CONFIG/newsgroups";

/// Cap on the descriptions file. It is around 3 MB; this is a ceiling on
/// a fetch from a host we do not control, not a size estimate.
#[cfg(feature = "indexer")]
const ISC_MAX_BYTES: u64 = 32 * 1024 * 1024;

/// Fetch the ISC newsgroup descriptions.
///
/// Opt-in, and off by default, because it is the daemon's only outbound
/// request to a host that is not the user's news provider. It exists
/// because most binary providers answer LIST NEWSGROUPS with nothing at
/// all - measured on a real provider, 0 of 111,330 groups came back with
/// a description - which leaves the browser's search matching names only.
///
/// Goes through the SSRF-guarded agent like every other outbound fetch.
#[cfg(feature = "indexer")]
fn fetch_isc_descriptions() -> std::result::Result<Vec<(String, String)>, String> {
    let resp = ssrf_safe_agent(3, 30)
        .get(ISC_NEWSGROUPS_URL)
        .call()
        .map_err(|e| format!("ISC descriptions: {e}"))?;
    // Bytes, then a lossy decode. The file is decades old and is NOT
    // valid UTF-8 - read_to_string on it fails outright with "stream did
    // not contain valid UTF-8", which is how this was found. Group names
    // are ASCII; only the odd description carries a stray Latin-1 byte,
    // and a replacement character in one description is a fair trade for
    // the other 45,000.
    let mut raw = Vec::new();
    use std::io::Read as _;
    resp.into_reader()
        .take(ISC_MAX_BYTES)
        .read_to_end(&mut raw)
        .map_err(|e| format!("ISC descriptions: {e}"))?;
    let body = String::from_utf8_lossy(&raw);
    let out: Vec<(String, String)> = body
        .lines()
        .filter_map(|l| {
            // Tab-separated, but the file has historically used runs of
            // whitespace too, so split on the first whitespace span.
            let (name, desc) = l.split_once(|c: char| c.is_whitespace())?;
            let desc = desc.trim();
            // "?" is the file's placeholder for "no description".
            if name.is_empty() || desc.is_empty() || desc == "?" {
                return None;
            }
            Some((name.to_string(), desc.to_string()))
        })
        .collect();
    if out.is_empty() {
        return Err("ISC descriptions: no usable lines".into());
    }
    Ok(out)
}

#[cfg(feature = "indexer")]
async fn fetch_group_catalog(
    config: &Path,
    prev: Option<&crate::groups::Catalog>,
    isc: bool,
) -> std::result::Result<crate::groups::Catalog, String> {
    let server = crate::load_server(config).map_err(|e| e.to_string())?;
    let (mut conn, _) = nzbkit::nntp::Connection::connect(&server)
        .await
        .map_err(|e| e.to_string())?;
    let active = conn.list_active().await.map_err(|e| e.to_string())?;
    let mut descs = conn.list_newsgroups().await.unwrap_or_default();
    conn.quit().await;
    if active.is_empty() {
        return Err("server returned an empty group list".into());
    }
    if isc {
        // ISC goes FIRST and the provider's own list is appended on top.
        // Catalog::build collects these into a HashMap, so the last entry
        // for a name wins - which has to be the user's own server, since
        // it is authoritative about what it actually carries.
        match tokio::task::spawn_blocking(fetch_isc_descriptions).await {
            Ok(Ok(mut merged)) => {
                info!(target: "groups", "ISC descriptions: {} fetched", merged.len());
                // Drop the provider's non-descriptions FIRST. Some servers
                // answer LIST NEWSGROUPS by echoing each group's own name
                // back as its description; Catalog::build already discards
                // those as junk, but because the provider list is applied
                // last they would first overwrite every real ISC entry.
                // Measured: without this, 45,006 fetched descriptions
                // produced a catalogue with zero.
                descs.retain(|(n, d)| !d.eq_ignore_ascii_case(n));
                merged.extend(descs);
                descs = merged;
            }
            Ok(Err(e)) => info!(target: "groups", "{e}"),
            Err(e) => info!(target: "groups", "ISC descriptions: {e}"),
        }
    }
    Ok(crate::groups::Catalog::build(
        epoch_secs() as i64,
        active,
        descs,
        prev,
    ))
}

/// How many of a group's newest articles one sample covers. 200 is
/// enough for a stable mean and a usable content mix, and small enough
/// that a sample is one quick OVER rather than a scan.
#[cfg(feature = "indexer")]
const GROUP_SAMPLE_N: u64 = 200;

/// How far back the rate baseline reaches, widened until it spans at
/// least an hour. A quiet group is answered by the first step; the
/// busiest groups on a big provider need the last one.
#[cfg(feature = "indexer")]
const RATE_BASELINE_STEPS: &[u64] = &[50_000, 1_000_000, 20_000_000];

/// Sample one group: select it, pull OVER across its newest articles,
/// and reduce that to a profile. One connection, one round trip, closed
/// immediately - this must never compete with the download pool.
#[cfg(feature = "indexer")]
async fn sample_one_group(
    config: &Path,
    group: &str,
    posts: u64,
) -> std::result::Result<crate::groupstats::GroupStats, String> {
    let server = crate::load_server(config).map_err(|e| e.to_string())?;
    let (mut conn, _) = nzbkit::nntp::Connection::connect(&server)
        .await
        .map_err(|e| e.to_string())?;
    let info = conn.group(group).await.map_err(|e| e.to_string())?;
    // An empty group has nothing to sample. Also guards the subtraction
    // below, where high < GROUP_SAMPLE_N is the common case for a quiet
    // group and must not wrap.
    if info.high == 0 || info.high < info.low {
        conn.quit().await;
        return Ok(crate::groupstats::GroupStats {
            sampled_at: epoch_secs() as i64,
            ..Default::default()
        });
    }
    let from = info.high.saturating_sub(GROUP_SAMPLE_N).max(info.low);
    let entries = conn
        .over(from, info.high)
        .await
        .map_err(|e| e.to_string())?;
    let mut stats =
        crate::groupstats::GroupStats::from_sample(epoch_secs() as i64, posts, &entries);

    // Second, tiny probe far back in the article range, purely to date a
    // wide baseline for the posting rate. The newest-200 window spans
    // seconds on a busy group, which is unusable as a divisor; this turns
    // the rate into an honest "N articles between these two dates".
    //
    // The step has to ADAPT, because "far back" is a property of the
    // group, not a constant: 50k articles is weeks on a quiet group and
    // about a minute on alt.binaries.teevee, which is why a fixed
    // baseline measured nothing at all on the busiest group tested.
    // Widen until the baseline spans an hour, or until we run out of
    // group. Two extra round trips at worst, and only for the fast ones.
    for step in RATE_BASELINE_STEPS {
        let back = info.high.saturating_sub(*step).max(info.low);
        if back >= from {
            break; // the sample already covers this far back
        }
        // A few articles, not one: any individual number may be missing.
        let Ok(old) = conn.over(back, back.saturating_add(20).min(from)).await else {
            break;
        };
        let Some(oldest) = old.iter().map(|e| e.date).filter(|d| *d > 0).min() else {
            continue;
        };
        stats.set_rate_from_baseline(info.high.saturating_sub(back), oldest);
        if stats.per_day > 0.0 {
            break; // the baseline was wide enough to be a measurement
        }
        if back == info.low {
            break; // no more group to reach back into
        }
    }
    conn.quit().await;
    Ok(stats)
}

/// Sample `group` in the background unless a sample is already in flight
/// for it. Returns whether THIS call started one.
///
/// Per-group single-flight rather than one global flag: opening two rows
/// in the browser should sample both, but opening the same row twice
/// should not go to the provider twice.
#[cfg(feature = "indexer")]
fn kick_group_sample(d: &Arc<Daemon>, config: PathBuf, group: String, posts: u64) -> bool {
    {
        let mut inflight = d.group_sampling.lock_ok();
        if !inflight.insert(group.clone()) {
            return false;
        }
    }
    let d = d.clone();
    tokio::spawn(async move {
        // Hard ceiling: a black-holed provider must not pin an entry in
        // the in-flight set forever, which would make that group
        // permanently unsampleable until a restart.
        let res = match tokio::time::timeout(
            std::time::Duration::from_secs(45),
            sample_one_group(&config, &group, posts),
        )
        .await
        {
            Err(_) => Err("timed out".to_string()),
            Ok(r) => r,
        };
        match res {
            Ok(stats) => {
                let next = {
                    let cur = d.group_stats.lock_ok().clone();
                    let mut m = (*cur).clone();
                    m.map.insert(group.clone(), stats);
                    Arc::new(m)
                };
                if let Err(e) = next.save(&d.groupstats_cache_path()) {
                    info!(target: "groups", "sample cache write failed: {e}");
                }
                *d.group_stats.lock_ok() = next;
            }
            Err(e) => info!(target: "groups", "sample of {group} failed: {e}"),
        }
        d.group_sampling.lock_ok().remove(&group);
    });
    true
}

/// A release stem reduced to something safe and recognisable as part of a
/// spool filename. Deliberately strict: this string reaches the
/// filesystem, so anything that is not plainly a name character becomes a
/// dash, and the result is length-capped so a long release name plus the
/// job id cannot approach a path limit.
fn safe_spool_stem(stem: &str) -> String {
    let mut out = String::with_capacity(48);
    for c in stem.chars() {
        if out.chars().count() >= 60 {
            break;
        }
        if c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_' {
            out.push(c);
        } else if !out.ends_with('-') {
            out.push('-');
        }
    }
    // Never a leading dot (hidden file) and never an empty stem.
    let out = out.trim_matches(['-', '.'].as_slice()).to_string();
    if out.is_empty() { "job".into() } else { out }
}

/// Which caller an API-added job came from. The *arrs and the dashboard
/// both post to addfile, so the distinguishing evidence is the SAB API
/// key parameters the *arrs send and the browser does not.
fn origin_of(params: &std::collections::HashMap<String, String>) -> &'static str {
    if params.contains_key("nzbname") || params.get("mode").map(String::as_str) == Some("addurl") {
        return "arr";
    }
    "dashboard"
}

/// Name the client behind an API call from its User-Agent, or `None`.
///
/// Every automation that adds jobs leads its UA with a standard product
/// token - `Sonarr/4.0.19.2979 (macos 10.0)`, `Radarr/6.3.0.10514
/// (macos 10.0)`, `nzb360/...` - so taking the substring before the
/// first `/` or space names clients we have never heard of, for free. A
/// hardcoded list of known names would only ever name the ones we
/// thought of, so the list stays out of the classifier and is used for
/// display only.
///
/// The UA is attacker-controlled, and the name is persisted into
/// `queue.json` and rendered in the drawer. Sanitising to `[a-z0-9-]`
/// with a 24-char cap right here, at the point of classification, is the
/// whole defence - nothing downstream re-checks it.
///
/// `None` for a browser (any `mozilla` token, which covers our own
/// dashboard's upload) and for a UA that leaves nothing usable. Callers
/// fall back to the parameter heuristic, so behaviour is unchanged for
/// everyone who does not identify themselves.
fn api_client(user_agent: &str) -> Option<String> {
    let token: String = user_agent
        .trim_start()
        .split(['/', ' '])
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase()
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .take(24)
        .collect();
    if token.is_empty() || token == "mozilla" {
        return None;
    }
    Some(token)
}

/// Origin to record for an API-added job: `arr:<client>` when the caller
/// named itself, else `fallback`.
///
/// The `prefix:detail` shape is the one `rss:<feed-url>` already uses, so
/// nothing needs a new `Job` field or a `queue.json` migration: records
/// written before this keep plain `arr` and still render.
fn api_origin(user_agent: &str, fallback: &str) -> String {
    match api_client(user_agent) {
        Some(client) => format!("arr:{client}"),
        None => fallback.to_string(),
    }
}

/// Delete spool NZBs that no job refers to any more.
///
/// The spool copy is written BEFORE `save_queue()` records the job, so a
/// crash between the two orphans the file permanently and nothing ever
/// looked for it. Metadata-only "library" jobs keep theirs by design and
/// are indistinguishable from an orphan by name alone, which is exactly
/// why this works from the live set of referenced paths rather than from
/// any naming rule.
///
/// Only files whose name looks like ours are considered, and only ones
/// older than a grace period, so a job being enqueued right now (spool
/// written, not yet in the queue) cannot be swept out from under itself.
#[cfg(feature = "indexer")]
fn sweep_orphan_spool_nzbs(d: &Arc<Daemon>) -> usize {
    const GRACE_SECS: u64 = 3600;
    let referenced: std::collections::HashSet<PathBuf> = d
        .queue
        .lock()
        .unwrap()
        .iter()
        .chain(d.history.lock_ok().iter())
        .map(|j| j.lock_ok().nzb_path.clone())
        .collect();
    let Ok(rd) = std::fs::read_dir(&d.spool) else {
        return 0;
    };
    let now = std::time::SystemTime::now();
    let mut removed = 0;
    for e in rd.flatten() {
        let path = e.path();
        if path.extension().and_then(|x| x.to_str()) != Some("nzb") {
            continue;
        }
        let Some(stem) = path.file_name().and_then(|x| x.to_str()) else {
            continue;
        };
        if !stem.starts_with("SABnzbd_nzo_nzbfast") {
            continue; // not one of ours: leave it entirely alone
        }
        if referenced.contains(&path) {
            continue;
        }
        let old = e
            .metadata()
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| now.duration_since(t).ok())
            .is_some_and(|age| age.as_secs() > GRACE_SECS);
        if old && std::fs::remove_file(&path).is_ok() {
            removed += 1;
        }
    }
    if removed > 0 {
        info!(target: "spool", "removed {removed} orphaned NZB(s) no job referred to");
    }
    removed
}

/// Replace this process with a fresh copy of the same command line.
///
/// `exec` does not return on success: the kernel swaps the image and the
/// new binary starts from main with our pid. That is what makes this safe
/// for a network daemon - there is no window in which two processes both
/// want the port. The listening socket is closed for us because Rust
/// opens sockets CLOEXEC.
///
/// Note it picks up a REPLACED binary on disk, so this doubles as
/// "restart onto the version I just installed".
///
/// If exec fails there is nothing sensible left to do: the queue is
/// already persisted and the daemon is paused, so exiting is closer to
/// the user's intent (they asked for a restart) than carrying on in a
/// half-stopped state. Whatever supervises us - Docker, systemd, the
/// tray - brings it back.
#[cfg(unix)]
fn restart_in_place(
    exe: &std::path::Path,
    args: &[std::ffi::OsString],
    cwd: Option<&std::path::Path>,
) {
    use std::os::unix::process::CommandExt as _;
    let mut cmd = std::process::Command::new(exe);
    cmd.args(args);
    if let Some(d) = cwd {
        cmd.current_dir(d);
    }
    // exec replaces the image without running any exit handler, so the
    // log tee has to be drained here or the last lines before a restart
    // die in its pipe.
    nzbkit::logtee::drain();
    let err = cmd.exec(); // only returns on failure
    error!(
        target: "restart",
        "could not re-exec {}: {err} - exiting instead",
        exe.display()
    );
    std::process::exit(1);
}

#[cfg(not(unix))]
fn restart_in_place(
    _exe: &std::path::Path,
    _args: &[std::ffi::OsString],
    _cwd: Option<&std::path::Path>,
) {
    // Unreachable: the handler refuses restart off Unix before spawning.
    warn!(target: "restart", "not supported on this platform");
}

/// Groups profiled per hourly tick by the background pass.
///
/// The content and freshness filters can only see profiled groups, so
/// this governs how quickly those filters become useful. 150 an hour
/// covers the ~2000 groups worth profiling inside a day or so, and costs
/// a few minutes of one sequential connection per hour, only while idle.
#[cfg(feature = "indexer")]
const SAMPLE_BUDGET_PER_TICK: usize = 150;

/// Below this many profiles the install counts as unprofiled, and the
/// first-run burst runs. An established install is far above it (the
/// steady pass alone reaches ~2000 within a day), so it never bursts.
#[cfg(feature = "indexer")]
const BURST_PROFILE_TARGET: usize = 500;

/// Hard bound 1: samples the burst may start in one process lifetime.
/// This is a bound on ATTEMPTS, not on successes, so a provider that
/// fails or times out every sample is contacted a bounded number of
/// times and then dropped back to the hourly pass. At the >=1s spacing
/// below, this is also a floor of ~25 minutes on how long it can last.
#[cfg(feature = "indexer")]
const BURST_MAX_SAMPLES: usize = 1_500;

/// Hard bound 2: wall-clock window from daemon start. Covers the cases
/// the sample bound cannot - no provider configured, no group catalogue
/// yet, or a catalogue so small that the burst finishes it and would
/// otherwise sit in its short tick forever.
#[cfg(feature = "indexer")]
const BURST_WINDOW_SECS: u64 = 60 * 60;

/// Seconds between burst ticks. Short, because a burst tick that finds
/// nothing to do (the catalogue has not been fetched yet, which is the
/// normal state for the first minute of a first run) should retry soon
/// rather than an hour later.
#[cfg(feature = "indexer")]
const BURST_TICK_SECS: u64 = 60;

/// Should the fresh-install profile burst run?
///
/// All three conditions are load-bearing, and the two bounds exist
/// because the first one alone would let a permanently-unprofilable
/// install (bad credentials, a provider that rejects OVER) retry at the
/// burst cadence forever, which is the ban-shaped traffic the pool's
/// reconnect pacing was written to stop.
#[cfg(feature = "indexer")]
fn should_burst_profiles(profiled: usize, burst_samples: usize, since_start_secs: u64) -> bool {
    profiled < BURST_PROFILE_TARGET
        && burst_samples < BURST_MAX_SAMPLES
        && since_start_secs < BURST_WINDOW_SECS
}

#[cfg(all(test, feature = "indexer"))]
mod group_burst_tests {
    use super::{
        BURST_MAX_SAMPLES, BURST_PROFILE_TARGET, BURST_WINDOW_SECS, should_burst_profiles,
    };

    /// The gate this whole feature turns on: a fresh install bursts, an
    /// install that already has profiles never does. The second half is
    /// the one that matters - bursting on an established install means
    /// re-profiling groups that are already known, at a cadence the
    /// provider has no reason to tolerate.
    #[test]
    fn bursts_only_while_the_profile_cache_is_empty() {
        assert!(
            should_burst_profiles(0, 0, 0),
            "a brand new install must burst"
        );
        assert!(
            should_burst_profiles(BURST_PROFILE_TARGET - 1, 0, 0),
            "just under the target still counts as unprofiled"
        );
        assert!(
            !should_burst_profiles(BURST_PROFILE_TARGET, 0, 0),
            "at the target the steady hourly pass takes over"
        );
        assert!(
            !should_burst_profiles(2_000, 0, 0),
            "an established install must never burst"
        );
    }

    /// Both bounds are hard: an install that stays empty because every
    /// sample fails must still stop bursting. Without these it would
    /// retry at the burst cadence for as long as the daemon runs.
    #[test]
    fn an_install_that_never_fills_still_stops_bursting() {
        assert!(
            !should_burst_profiles(0, BURST_MAX_SAMPLES, 0),
            "the sample budget must stop a burst that fills nothing"
        );
        assert!(
            !should_burst_profiles(0, 0, BURST_WINDOW_SECS),
            "the wall-clock window must stop a burst that samples nothing"
        );
        assert!(
            should_burst_profiles(0, BURST_MAX_SAMPLES - 1, BURST_WINDOW_SECS - 1),
            "one short of either bound is still inside the window"
        );
    }
}

/// Fill in sampled profiles for the groups a user is most likely to look
/// at: the ones they already scan, then the busiest binary groups.
/// Returns how many samples this pass started.
///
/// Sequential. One connection at a time is gentle, but a provider account
/// has a hard connection limit and the download pool is entitled to all
/// of it, so the steady pass stands down entirely while anything is
/// downloading rather than risking a rejected connection on the hot path.
///
/// `burst` lifts only the idle gate, and only for the fresh-install
/// window (see `should_burst_profiles`). A brand new install whose first
/// action is to queue something would otherwise profile nothing at all
/// while it downloads, which is exactly when the user is first looking at
/// the content and "still active" filters. It stays one sample at a time,
/// and spaces them further apart while the pool is busy, so the extra
/// load is a single connection opened every few seconds - not a new
/// concurrency tier.
#[cfg(feature = "indexer")]
async fn sample_top_groups(d: &Arc<Daemon>, config: &Path, burst: bool) -> usize {
    if !burst && d.started_at.lock_ok().is_some() {
        return 0; // downloading: the pool owns the connections
    }
    let Some(cat) = d.group_catalog.lock_ok().clone() else {
        return 0;
    };
    let now = epoch_secs() as i64;
    let subscribed: std::collections::HashSet<String> =
        d.index_groups.lock_ok().iter().cloned().collect();

    // Subscribed first, then busiest-binary. `posts` rides along because
    // it is what turns a mean article size into an estimated group size.
    let mut want: Vec<(String, u64)> = cat
        .groups
        .iter()
        .filter(|g| subscribed.contains(&g.name))
        .map(|g| (g.name.clone(), g.posts))
        .collect();
    let mut busiest: Vec<&crate::groups::CatGroup> = cat
        .groups
        .iter()
        .filter(|g| crate::groups::is_binary(&g.name) && !subscribed.contains(&g.name))
        .collect();
    busiest.sort_by_key(|b| std::cmp::Reverse(b.posts));
    want.extend(
        busiest
            .into_iter()
            .take(2_000)
            .map(|g| (g.name.clone(), g.posts)),
    );

    let mut done = 0usize;
    for (name, posts) in want {
        if done >= SAMPLE_BUDGET_PER_TICK {
            break;
        }
        // Re-check per group: a download may have started mid-pass, and
        // an already-fresh profile costs nothing to skip.
        let downloading = d.started_at.lock_ok().is_some();
        if downloading && !burst {
            return done;
        }
        if !d.group_stats.lock_ok().is_stale(&name, now) {
            continue;
        }
        if !kick_group_sample(d, config.to_path_buf(), name, posts) {
            continue; // already in flight from an on-demand request
        }
        done += 1;
        // Space them out. This is housekeeping, not a job - and when the
        // pool is downloading through the same account, housekeeping that
        // yields: five times the gap, so the burst is a trickle beside it.
        let gap = if downloading { 5 } else { 1 };
        tokio::time::sleep(std::time::Duration::from_secs(gap)).await;
    }
    if done > 0 {
        info!(target: "groups", "sampling {done} group profiles in the background");
    }
    done
}

/// Turn the user's chosen interests into scanned groups, once.
///
/// Called when the setting changes, at startup, and whenever a
/// catalogue fetch lands - because at first run there is no catalogue
/// yet: the wizard runs before the daemon has ever spoken to the
/// provider, so "sport" cannot be resolved to group names at the moment
/// it is chosen. The choice is recorded either way and applied when the
/// group list arrives.
///
/// Three properties this has to keep, all of them the point of the
/// feature:
///  * nothing is subscribed for an empty interest string - there is no
///    fallback list;
///  * a group the user removed by hand does not come back (the applied
///    marker makes this one-shot per change);
///  * only groups the provider actually carries are subscribed, so a
///    preset can never point the scan loop at a name that will never
///    answer.
#[cfg(feature = "indexer")]
fn apply_interests(d: &Arc<Daemon>) {
    let want = d.index_interests.lock_ok().clone();
    if want == *d.index_interests_applied.lock_ok() {
        return;
    }
    let keys = crate::interests::parse(&want);
    let was = crate::interests::parse(&d.index_interests_applied.lock_ok().clone());
    // Switching an interest OFF has to stop scanning what switching it on
    // started, or the only way back would be to edit the group list by
    // hand - and not having to know newsgroup names is the point.
    let dropped_keys: Vec<String> = was.iter().filter(|k| !keys.contains(k)).cloned().collect();
    let stale = crate::interests::groups(&dropped_keys);
    let still_wanted = crate::interests::groups(&keys);
    let stale: Vec<String> = stale
        .into_iter()
        .filter(|g| !still_wanted.iter().any(|w| w == g))
        .collect();
    if keys.is_empty() && stale.is_empty() {
        // "Nothing" is a real answer, and recording it stops this from
        // being reconsidered on every catalogue refresh.
        if save_settings(
            &d.settings_path,
            &[("index_interests_applied", json!(&want))],
        ) {
            *d.index_interests_applied.lock_ok() = want;
        }
        return;
    }
    // Removal needs no catalogue - the names are known either way - but
    // ADDING does, so a still-catalogue-less daemon takes the removal now
    // and leaves the marker for the fetch to finish.
    let cat = d.group_catalog.lock_ok().clone();
    if cat.is_none() && !keys.is_empty() {
        if !stale.is_empty() {
            let have = d.index_groups.lock_ok().clone();
            let owned = d.index_interest_groups.lock_ok().clone();
            let (groups, next_owned, dropped, _) =
                crate::interests::reconcile(&have, &owned, &stale, &[]);
            if dropped > 0
                && save_settings(
                    &d.settings_path,
                    &[
                        ("index_groups", json!(&groups)),
                        ("index_interest_groups", json!(&next_owned)),
                    ],
                )
            {
                *d.index_groups.lock_ok() = groups;
                *d.index_interest_groups.lock_ok() = next_owned;
            }
        }
        return;
    }
    let resolved = match &cat {
        Some(c) => {
            let carried: std::collections::HashSet<&str> =
                c.groups.iter().map(|g| g.name.as_str()).collect();
            crate::interests::resolve(&keys, |g| carried.contains(g))
        }
        None => Vec::new(),
    };
    let have = d.index_groups.lock_ok().clone();
    let owned = d.index_interest_groups.lock_ok().clone();
    let (groups, next_owned, dropped, added) =
        crate::interests::reconcile(&have, &owned, &stale, &resolved);
    // Groups, provenance and completion marker are one persisted state
    // transition. Writing the marker first used to make a crash or second
    // write failure suppress this choice forever on restart.
    if !save_settings(
        &d.settings_path,
        &[
            ("index_groups", json!(&groups)),
            ("index_interest_groups", json!(&next_owned)),
            ("index_interests_applied", json!(&want)),
        ],
    ) {
        return;
    }
    *d.index_groups.lock_ok() = groups;
    *d.index_interest_groups.lock_ok() = next_owned;
    *d.index_interests_applied.lock_ok() = want.clone();
    if added == 0 && dropped == 0 {
        return;
    }
    info!(
        target: "groups",
        "interests ({}): {added} group(s) added, {dropped} removed",
        if want.is_empty() { "none" } else { &want },
    );
    if added > 0 {
        d.scan_now.notify_one();
    }
}

/// Start a background catalogue fetch unless one is already running
/// (single-flight). Returns whether THIS call started it.
#[cfg(feature = "indexer")]
fn kick_group_fetch(d: &Arc<Daemon>, config: PathBuf) -> bool {
    if d.group_fetching.swap(true, Ordering::SeqCst) {
        return false;
    }
    let d = d.clone();
    tokio::spawn(async move {
        let prev = d.group_catalog.lock_ok().clone();
        let isc = d.group_desc_isc.load(Ordering::Relaxed);
        match fetch_group_catalog(&config, prev.as_deref(), isc).await {
            Ok(cat) => {
                if let Err(e) = cat.save(&d.groups_cache_path()) {
                    info!(target: "groups", "catalogue cache write failed: {e}");
                }
                let new_count = cat
                    .groups
                    .iter()
                    .filter(|g| g.first_seen == cat.fetched_at)
                    .count();
                info!(
                    target: "groups",
                    "catalogue fetched: {} groups ({} with descriptions, {} newly created)",
                    cat.groups.len(),
                    cat.groups.iter().filter(|g| !g.desc.is_empty()).count(),
                    new_count,
                );
                *d.group_fetch_err.lock_ok() = None;
                *d.group_catalog.lock_ok() = Some(Arc::new(cat));
                // First run orders these the other way round: the user
                // picks interests in the wizard, before this daemon has
                // ever seen a group list. This is where that choice
                // becomes a scan list.
                apply_interests(&d);
            }
            Err(e) => {
                info!(target: "groups", "catalogue fetch failed: {e}");
                *d.group_fetch_err.lock_ok() = Some(e);
            }
        }
        d.group_fetching.store(false, Ordering::SeqCst);
    });
    true
}

/// The newsgroup every diagnostic probe (system bench, connection ladder,
/// pool burst, diversity sweep) selects to find sample articles with: big,
/// busy, and carried by every provider.
///
/// Deliberately a constant and NOT `ServerConfig.group`. That field is a
/// MIRROR LABEL - servers sharing it are backbone twins, and the pool uses
/// it to dedup 430s across them - and the dashboard collects it as freeform
/// text ("Backbone group"). Sent as an NNTP GROUP argument it answers 411,
/// which the probes reported as a 0.00 Gbps network or a failed sweep.
const PROBE_GROUP: &str = "alt.binaries.boneless";

/// One full system measurement (compute + disk + live network probe on
/// the first configured server). Shared by the mode=sysbench handler and
/// the scheduled-benchmark loop - both run on plain threads, hence the
/// runtime handle for the async probe. A failed probe must SAY SO -
/// collapsing errors to 0.0 Gbps used to yield "expected max 0.00,
/// network is your limit", which is worse than useless.
fn measure_system(
    d: &Arc<Daemon>,
    cfg_path: &std::path::Path,
    rt: &tokio::runtime::Handle,
) -> std::result::Result<nzbkit::sysbench::SystemReport, String> {
    let compute = nzbkit::sysbench::compute(128);
    let disk = nzbkit::sysbench::disk_write(&d.out_dir(), 512).unwrap_or(0.0);
    // Every enabled server, at the connection counts downloads actually
    // use - NOT a fixed 8, and NOT just the first server.
    //
    // A single Usenet connection is worth tens of Mbps, so eight of them
    // measure a few hundred Mbps whatever the line is capable of (issue
    // #12). And one server's figure reads far below what several
    // accounts deliver together - the reporter's five providers do 3x
    // what their first one shows alone (issue #12, round 2). SABnzbd's
    // own test pulls from a CDN over HTTP and measures the line, not the
    // providers; ours is the number that predicts a real download.
    let servers: Vec<_> = nzbkit::config::Config::load(cfg_path)
        .map(|c| c.servers.into_iter().filter(|s| s.enabled).collect())
        .unwrap_or_default();
    if servers.is_empty() {
        return Err("no servers configured".into());
    }
    let conns_total: usize = servers
        .iter()
        .map(|s| (s.connections as usize).clamp(1, 100))
        .sum::<usize>()
        .min(200);
    // The card names what the figure came from; keep it locale-neutral
    // (the note around it is translated, this string is substituted in).
    let hosts = {
        let names: Vec<&str> = servers.iter().map(|s| s.host.as_str()).take(3).collect();
        let mut h = names.join(", ");
        if servers.len() > 3 {
            h.push_str(", …");
        }
        h
    };
    let probed = (hosts.clone(), conns_total);
    // Hard cap: a black-holed connect must not wedge the caller
    // (it did, via the Run button, on a filtered uplink).
    let net = rt.block_on(async {
        match tokio::time::timeout(
            std::time::Duration::from_secs(45),
            nzbkit::sysbench::network_probe_multi(&servers, PROBE_GROUP, 8),
        )
        .await
        {
            Err(_) => Err(format!(
                "network probe timed out ({hosts}: slow link or filtered port?)"
            )),
            Ok(Err(e)) => Err(format!("network probe ({hosts}): {e}")),
            Ok(Ok((g, per_server))) => {
                let billed: Vec<(String, u64)> = servers
                    .iter()
                    .zip(&per_server)
                    .map(|(s, &b)| (s.host.clone(), b))
                    .collect();
                d.add_usage(&billed);
                Ok(g)
            }
        }
    })?;
    let mut v = nzbkit::sysbench::verdict(net, &compute, disk);
    (v.network_host, v.network_conns) = probed;
    Ok(v)
}

mod settings;
use settings::*;

/// M23d: keep TVmaze episode lists (with airdates) cached for watched
/// shows - the "coming up" calendar's data. One kv blob per show
/// (`eplist:<norm title>`), refreshed every 12 h; "show not found" is
/// cached too so unknown titles aren't re-queried every minute. Runs on
/// the watcher's blocking thread, so the network calls are fine here.
#[cfg(feature = "indexer")]
fn watch_calendar_refresh(d: &Arc<Daemon>) {
    let items = d.watchlist.lock_ok().clone();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|t| t.as_secs() as i64)
        .unwrap_or(0);
    for item in items.iter().filter(|i| i.enabled && i.kind == "tv") {
        let key = format!("eplist:{}", crate::wall::norm_title(&item.title));
        let fresh = d
            .with_index(|ix| ix.kv_get(&key))
            .and_then(|s| serde_json::from_str::<Value>(&s).ok())
            .and_then(|v| v["fetched"].as_i64())
            .is_some_and(|t| now - t < 12 * 3600);
        if fresh {
            continue;
        }
        let show_id = crate::wall::tvmaze_lookup(&item.title).map(|m| m.tmdb_id);
        let eps = show_id
            .map(crate::wall::tvmaze_episodes)
            .unwrap_or_default();
        info!(
            target: "watch",
            "episode list for {}: {} episodes{}",
            item.title,
            eps.len(),
            if show_id.is_none() {
                " (show not found on TVmaze)"
            } else {
                ""
            }
        );
        let blob = json!({"fetched": now, "show_id": show_id, "episodes": eps}).to_string();
        d.with_index(|ix| ix.kv_set(&key, &blob).ok());
    }
}

/// One M23 watcher pass: settle pending upgrade-deletes, then match
/// every enabled watch item against the index and grab / upgrade.
/// Where a watchlist candidate came from: our own index, or one of the
/// user's third-party indexer accounts (M35 phase 2). Everything
/// between finding it and deciding on it is identical - only the fetch
/// differs, and only an external one costs a metered grab.
enum CandSrc {
    #[cfg(feature = "indexer")]
    Local(i64),
    External {
        url: String,
        indexer: String,
    },
}

/// Default cadence for the watchlist's external leg: how long an item
/// waits between spending one search on the user's indexer accounts.
///
/// The watcher itself runs every 60 s, and a third-party account is
/// metered per DAY (a free tier can be 100 searches), so the watcher's
/// own tempo is not a safe tempo to query at. Twice a day per item
/// keeps a 20-item watchlist at ~40 searches/day even before budgets.
const WATCH_EXT_INTERVAL_SECS: i64 = 12 * 60 * 60;

/// §74: default ceiling on instant watchlist passes per hour.
///
/// Sized against what a watchlist actually wants, not against what a
/// group can post: a busy evening on a watched show is a handful of
/// arrivals, and six of them an hour is already generous. Everything
/// over the line waits for the periodic pass a minute later, so the only
/// thing a low ceiling costs is the seconds.
pub(super) const INSTANT_MAX_DEFAULT: u32 = 6;

/// Free space the queue keeps in hand by default: new jobs wait below
/// it, and the header says which floor is holding them.
///
/// It used to be 0, which is to say there was no protection at all
/// unless the operator went looking for the setting. That is how a
/// tester's disk reached 1.8 GB free (3 Aug): the download itself fits,
/// so nothing objects, and the machine is the thing that suffers - a
/// full disk tears settings writes, starves the OS, and fails the
/// unpack that was going to need the room anyway.
///
/// 2 GB, not more: this is a floor against a disk hitting ZERO, not a
/// per-job forecast (the queue row does that, and it counts the
/// extraction). High enough that macOS and Windows keep working, low
/// enough that a NAS deliberately run near full is not held hostage -
/// and it is one field away from 0, which now MEANS off and survives a
/// restart.
pub(super) const MIN_FREE_DEFAULT: u64 = 2_000_000_000;

/// §74: how long a matched-but-incomplete arrival keeps its short
/// re-check before it is handed back to the periodic pass. A post still
/// going up is the normal case at +6 s; one that has not finished ten
/// minutes later is either enormous or in trouble, and either way the
/// periodic pass is the right owner. NEVER read as "the post is dead" -
/// missing articles are not evidence of that.
#[cfg(feature = "indexer")]
pub(super) const INSTANT_PENDING_SECS: i64 = 10 * 60;

/// §74: cadence of that re-check.
#[cfg(feature = "indexer")]
pub(super) const INSTANT_RECHECK_SECS: u64 = 30;

fn watchlist_pass(d: &Arc<Daemon>) {
    use crate::watchlist as wl;
    let items = d.watchlist.lock_ok().clone();
    // §74: the arrivals that woke this pass, if it was woken by one.
    // Taken, not read: a name only earns the "grabbed as it arrived"
    // record once, and a later periodic pass grabbing the same release
    // (because the instant one declined it, or was rate-limited) is not
    // an instant grab and must not claim to be.
    let arrived: Vec<String> = std::mem::take(&mut *d.instant_hint.lock_ok());
    // 24D: every stem the watcher looks at goes through the SAME
    // classify pass as ingest, so a custom-category item sees the kind
    // and identity key the index stored - and a built-in item never
    // grabs a release a category has claimed.
    let cats = d.custom_categories.read_ok().clone();
    let classify = |stem: &str| nzbkit::categories::classify(stem, &cats);
    // The watcher owns this state: it's only ever mutated here, so
    // working on a clone and writing back at the end is race-free.
    let mut state = d.watch_state.lock_ok().clone();
    // Bundle D: the skip reasons describe THIS pass, so the previous
    // pass's are cleared rather than accumulated - an item that is no
    // longer being declined must stop saying it is.
    state.skips.clear();
    let mut dirty = false;
    let unix_now = || {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|t| t.as_secs() as i64)
            .unwrap_or(0)
    };

    // 1. Pending upgrade-deletes: the replacement download's fate
    // decides. Completed → the superseded version goes; Failed or
    // user-deleted → fall back to the version we already have.
    let pending = std::mem::take(&mut state.pending);
    for p in pending {
        let in_queue = d
            .queue
            .lock()
            .unwrap()
            .iter()
            .any(|j| j.lock_ok().nzo_id == p.new_nzo);
        if in_queue {
            state.pending.push(p);
            continue;
        }
        let hist = d
            .history
            .lock()
            .unwrap()
            .iter()
            .find(|j| j.lock_ok().nzo_id == p.new_nzo)
            .cloned();
        match hist.map(|j| j.lock_ok().state) {
            Some(JobState::Completed) => {
                // The superseded copy is usually a COMPLETED history
                // entry, but can still be sitting in the queue (paused,
                // or the upgrade overtook it). Never touch one that's
                // actively downloading.
                // Mid-download is not "gone" - it is "not yet". Excluding
                // it here found nothing in history either (the job is
                // still in the queue), and the pending entry was taken at
                // the top of this loop and never pushed back, so the
                // delete_old the user asked for was dropped on the floor:
                // the superseded copy finished later and its files sat on
                // disk forever with nothing reporting it. Keep the entry
                // and settle it on a later pass instead.
                // `finalizing` is live for the same reason Downloading
                // is, and it is NOT covered by it: a Completed job whose
                // post-processing (unlock, rename, TV filing, NAS move)
                // is still running has already left Downloading, so this
                // took the delete path below and removed the files out
                // from under the mover - half-deleting a tree it was
                // reading, or deleting the emptied source while the
                // payload sat at the destination with no record left to
                // delete it by. The queue-delete path has had this
                // deferral since the 3 Aug sweep; watch settlement
                // walked straight past it. Settle on a later pass, the
                // way a still-downloading predecessor already does.
                let old_busy = d.queue.lock_ok().iter().any(|j| {
                    let g = j.lock_ok();
                    g.nzo_id == p.old_nzo && (g.state == JobState::Downloading || g.finalizing)
                });
                if old_busy {
                    info!(
                        target: "watch",
                        "upgrade landed, but the superseded {} is still \
                         downloading or being unpacked - deleting it once it settles",
                        p.prev_stem
                    );
                    state.pending.push(p);
                    continue;
                }
                let queued_old = {
                    let mut q = d.queue.lock_ok();
                    let pos = q.iter().position(|j| {
                        let g = j.lock_ok();
                        g.nzo_id == p.old_nzo && g.state != JobState::Downloading && !g.finalizing
                    });
                    pos.and_then(|i| q.remove(i))
                };
                if let Some(job) = queued_old {
                    let (dir, nzb, name, filed, tail) = {
                        let g = job.lock_ok();
                        // The tail is the SUPERSEDED release's own, as
                        // FILED, so a filed delete cannot reach the upgrade
                        // that has just landed in the same season folder
                        // under the same episode base.
                        let t = delete_tail(&g, || d.job_suffix(filed_stem(&g)));
                        (
                            g.out_dir.clone(),
                            g.nzb_path.clone(),
                            filed_stem(&g).to_string(),
                            g.filed,
                            t,
                        )
                    };
                    if let FilesGone::Kept(why) = remove_job_files(&dir, &name, filed, &tail) {
                        d.note_delete_kept(&name, &dir, &why);
                    }
                    let _ = std::fs::remove_file(&nzb);
                    d.save_queue();
                    info!(
                        target: "watch",
                        "upgrade landed - dropped queued {} ({})",
                        p.prev_stem, p.old_nzo
                    );
                }
                let old = d
                    .history
                    .lock()
                    .unwrap()
                    .iter()
                    .find(|j| j.lock_ok().nzo_id == p.old_nzo)
                    .cloned();
                // A history row can be busy too: a password unlock marks
                // the record `finalizing` while it extracts, renames and
                // moves on disk. Same deferral as the queue side above.
                if old.as_ref().is_some_and(|j| j.lock_ok().finalizing) {
                    info!(
                        target: "watch",
                        "upgrade landed, but the superseded {} is being unlocked - \
                         deleting it once it settles",
                        p.prev_stem
                    );
                    state.pending.push(p);
                    continue;
                }
                if let Some(job) = old {
                    let (dir, nzb, name, filed, tail) = {
                        let g = job.lock_ok();
                        // Same as above: this is the SUPERSEDED release's
                        // own filed tail, and the replacement's files do
                        // not carry it.
                        let t = delete_tail(&g, || d.job_suffix(filed_stem(&g)));
                        (
                            g.out_dir.clone(),
                            g.nzb_path.clone(),
                            filed_stem(&g).to_string(),
                            g.filed,
                            t,
                        )
                    };
                    let outcome = remove_job_files(&dir, &name, filed, &tail);
                    if let FilesGone::Kept(why) = &outcome {
                        d.note_delete_kept(&name, &dir, why);
                    }
                    let _ = std::fs::remove_file(&nzb);
                    d.history
                        .lock()
                        .unwrap()
                        .retain(|j| j.lock_ok().nzo_id != p.old_nzo);
                    d.save_queue();
                    // Asked of the REMOVAL, not of the settings. This
                    // read the two globals and inferred a fate from them,
                    // which is a promise the globals cannot make: on 4 Aug
                    // a 14 GB download was reported "went to the Trash" -
                    // the setting was on, nothing had latched
                    // unresponsive - while it had been destroyed outright,
                    // because the backend returned Ok on a volume whose
                    // Trash is not usable. `Removed::Trashed` is now only
                    // reported when the file was FOUND in a Trash
                    // afterwards, so "trash" here is a checked claim.
                    // A refused delete is the third state: the files are
                    // still there, so neither "went to the Trash" nor
                    // "was deleted" is true of them.
                    let fate = match &outcome {
                        FilesGone::Kept(_) => "kept",
                        FilesGone::Yes(crate::smart::Removed::Trashed) => "trash",
                        FilesGone::Yes(crate::smart::Removed::Gone) => "gone",
                    };
                    info!(
                        target: "watch",
                        "upgrade landed - superseded {} ({}) - {}",
                        p.prev_stem,
                        p.old_nzo,
                        match fate {
                            "trash" => "its files went to the Trash",
                            "kept" => "its record went, its files are still on disk",
                            _ => "its files were deleted",
                        }
                    );
                    // Narrate it where the user looks: a completed
                    // download and its history row just disappeared, and
                    // two log lines were the only witnesses. Same ring
                    // pattern as watch_picked - queue_json carries it,
                    // an open dashboard toasts it.
                    {
                        let mut wu = d.watch_upgraded.lock_ok();
                        wu.push_back((
                            p.new_stem.clone(),
                            p.prev_stem.clone(),
                            p.prev_quality.clone(),
                            fate.to_string(),
                            unix_now(),
                        ));
                        while wu.len() > 8 {
                            wu.pop_front();
                        }
                    }
                }
                dirty = true;
            }
            Some(JobState::Failed) | None => {
                // (None = the user deleted the replacement mid-flight.)
                //
                // Revert EVERY slot the upgrade claimed, not only the
                // primary. The Upgrade arm wrote the new job into each
                // slot a multi-episode release covers, while
                // `PendingDelete` carries prev_* for one slot - so after
                // a failed double-episode upgrade the extra slots still
                // named the failed job, and step 1b below then EMPTIED
                // them, even though the superseded release's files still
                // cover that episode. A later standalone candidate scored
                // as a fresh grab and re-downloaded an episode the user
                // already had on disk; the history-adopt net cannot catch
                // it, because the old job's dupe_key names the FIRST
                // episode only.
                let claimed: Vec<String> = state
                    .slots
                    .iter()
                    .filter(|(k, s)| **k == p.slot || s.nzo_id == p.new_nzo)
                    .map(|(k, _)| k.clone())
                    .collect();
                for k in &claimed {
                    if let Some(slot) = state.slots.get_mut(k) {
                        slot.rank = p.prev_rank;
                        slot.stem = p.prev_stem.clone();
                        slot.quality = p.prev_quality.clone();
                        slot.nzo_id = p.old_nzo.clone();
                        if !slot.failed.contains(&p.new_stem) {
                            slot.failed.push(p.new_stem.clone());
                        }
                    }
                }
                info!(
                    target: "watch",
                    "upgrade lost - keeping {} across {} slot(s)",
                    p.prev_stem,
                    claimed.len()
                );
                dirty = true;
            }
            Some(_) => state.pending.push(p),
        }
    }

    // 1b. Reconcile slots against the download's REAL outcome. Slots
    // were recorded at enqueue time and never revisited (the only revert
    // path was the pending-upgrade machinery, gated on delete_old), so a
    // dead post permanently read "have it" - the episode was never
    // re-grabbed while the calendar showed ✓. A Failed grab records its
    // stem in the never-retry list and empties the slot; a user-deleted
    // one just empties it (a deliberate delete is not a dead post).
    {
        let keys: Vec<String> = state.slots.keys().cloned().collect();
        for key in keys {
            if state.pending.iter().any(|p| p.slot == key) {
                continue; // the pending logic above owns this slot
            }
            let nzo = state.slots[&key].nzo_id.clone();
            if nzo.is_empty() {
                continue; // already emptied - waiting for a new candidate
            }
            let in_queue = d
                .queue
                .lock()
                .unwrap()
                .iter()
                .any(|j| j.lock_ok().nzo_id == nzo);
            if in_queue {
                continue;
            }
            let hstate = d
                .history
                .lock()
                .unwrap()
                .iter()
                .find(|j| j.lock_ok().nzo_id == nzo)
                .map(|j| j.lock_ok().state);
            let s = state.slots.get_mut(&key).unwrap();
            match hstate {
                Some(JobState::Failed) => {
                    // A genuinely failed grab: remember the dead stem so we
                    // don't re-pick it, and free the slot for another
                    // release.
                    let stem = s.stem.clone();
                    if !s.failed.contains(&stem) {
                        s.failed.push(stem);
                    }
                    info!(
                        target: "watch",
                        "grab of {} failed - slot freed for another release",
                        s.stem
                    );
                    s.nzo_id.clear();
                    s.stem.clear();
                    s.quality.clear();
                    s.rank = 0;
                    dirty = true;
                }
                // Vanished from BOTH queue and history with no Failed record.
                // This fires when the user clears/prunes history (or Sonarr-
                // style auto-pruning does), NOT just a mid-flight delete -
                // and the two are indistinguishable here. Emptying the slot
                // made step 2 re-Grab it, re-downloading every long-completed
                // watchlist episode whose history row was pruned. Treat a
                // vanished job as "still had": leave the slot intact so a
                // pruned history never triggers a mass re-download. (A user
                // who truly wants it again can re-add the item.)
                None => continue,
                _ => continue, // Completed (or still post-processing)
            }
        }
    }

    // §96.3: snapshot the give-up breaker once per pass. A tripped
    // target's candidates are skipped below - that skip IS the
    // watchlist's "unmonitor", and it keeps the one-grab-path invariant:
    // nothing new decides, the pass just declines dead content.
    let giveup_threshold = d.arr_giveup_threshold.load(Ordering::Relaxed).min(1000) as u32;
    let giveup = d.giveup.lock_ok().clone();

    // 2. Match the index against each enabled item.
    for item in items.iter().filter(|i| i.enabled) {
        let min = wl::threshold_rank(&item.min_quality);
        let target = wl::threshold_rank(&item.target_quality);
        // Best complete candidate per slot (episode / the movie).
        struct Cand {
            rank: u32,
            bytes: u64,
            src: CandSrc,
            stem: String,
            quality: String,
            /// When the post itself went up (unix, 0 = unknown) - only
            /// used to say how far behind the post an instant grab was.
            posted: i64,
        }
        #[cfg(feature = "indexer")]
        let hits = d
            .with_index(|ix| ix.search(&item.title, 1000).ok())
            .unwrap_or_default();
        let mut best: std::collections::HashMap<String, Cand> = std::collections::HashMap::new();
        let now_unix = unix_now();
        #[cfg(feature = "indexer")]
        for r in hits.iter().filter(|r| r.complete) {
            // Matched on the name the release is KNOWN by: a
            // watchlist entry can never match an obfuscated stem, and
            // the whole point of a pre hit is that we now have the
            // string it would have matched all along.
            let name = r.display_name();
            let p = classify(name);
            if !wl::matches(item, name, &p) {
                continue;
            }
            // M32: per-item age window - skip too-fresh
            // (still propagating) and too-stale (repost) candidates.
            //
            // Deliberately AFTER the match test, which it used to
            // precede: the search is a fuzzy title query, so most hits
            // belong to some other title, and recording an age skip
            // against every one of them would report the window
            // rejecting posts this item never wanted. The cost is
            // classifying the age-rejected minority, which is small
            // beside the hits that reach here anyway.
            if !wl::age_ok(item, r.first_posted, now_unix) {
                wl::note_skip(&mut state.skips, item.id, "age");
                continue;
            }
            // §96.3: the give-up breaker has concluded this target is
            // not obtainable - stop pursuing it (any release of it).
            if giveup.tripped(&p, giveup_threshold) {
                wl::note_skip(&mut state.skips, item.id, "giveup");
                continue;
            }
            let Some(slot) = wl::slot_of(item, &p) else {
                continue;
            };
            // Exclude posts this slot already tried and lost (dead/DMCA'd):
            // a failed top-ranked release would otherwise still win `best`,
            // and the later `failed.contains` check skipped the whole SLOT
            // rather than that one candidate - so the next-best HEALTHY
            // release was never considered and the episode never downloaded.
            // Dropping failed stems here lets the best NON-failed post win.
            let skey = wl::state_key(item.id, &slot);
            if state
                .slots
                .get(&skey)
                .is_some_and(|s| s.failed.iter().any(|f| f == name))
            {
                continue;
            }
            let cand = Cand {
                rank: wl::quality_rank(&p),
                bytes: r.total_bytes,
                src: CandSrc::Local(r.id),
                stem: name.to_string(),
                quality: crate::wall::quality_label(&p),
                posted: r.first_posted,
            };
            match best.entry(slot) {
                std::collections::hash_map::Entry::Vacant(e) => {
                    e.insert(cand);
                }
                std::collections::hash_map::Entry::Occupied(mut e) => {
                    // Same rank → prefer the bigger post (better bitrate).
                    if (cand.rank, cand.bytes) > (e.get().rank, e.get().bytes) {
                        e.insert(cand);
                    }
                }
            }
        }
        // M35 phase 2: ask the user's indexer accounts for this item, on
        // its own slow cadence, and let anything they offer compete as
        // an ordinary candidate. This is the one path that spends a
        // metered third-party account without a click, so it is fenced
        // by WATCH_EXT_INTERVAL_SECS and the per-indexer daily budgets
        // rather than by being off - a watchlist that cannot see
        // obfuscated posts and will not ask the accounts that CAN sees
        // nothing at all. An explicit off still wins, always.
        // Results run through the SAME classify /
        // matches / slot_of / age_ok pipeline as local rows, so quality
        // ranking, the failed-stem memory and every decide() rule apply
        // unchanged - an external candidate is just a candidate.
        if d.watchlist_external_on() {
            let due = state
                .ext_checked
                .get(&item.id)
                .is_none_or(|last| now_unix - *last >= WATCH_EXT_INTERVAL_SECS);
            if due {
                state.ext_checked.insert(item.id, now_unix);
                dirty = true;
                let (ext, gated) = watchlist_external_candidates(d, item);
                // The budget and backoff gates are the reason a "search
                // my indexer accounts" item can go quiet for a day with
                // nothing anywhere saying so - manual search has always
                // shown these notes, the watchlist swallowed them.
                if let Some(reason) = gated {
                    wl::note_skip(&mut state.skips, item.id, &reason);
                }
                for r in ext {
                    let p = classify(&r.title);
                    if !wl::matches(item, &r.title, &p) {
                        continue;
                    }
                    // §96.3: same give-up skip as the local leg - an
                    // external candidate for a dead target would spend
                    // third-party allowance re-proving it.
                    if giveup.tripped(&p, giveup_threshold) {
                        wl::note_skip(&mut state.skips, item.id, "giveup");
                        continue;
                    }
                    if !wl::age_ok(item, r.posted, now_unix) {
                        wl::note_skip(&mut state.skips, item.id, "age");
                        continue;
                    }
                    let Some(slot) = wl::slot_of(item, &p) else {
                        continue;
                    };
                    let skey = wl::state_key(item.id, &slot);
                    if state
                        .slots
                        .get(&skey)
                        .is_some_and(|s| s.failed.contains(&r.title))
                    {
                        continue;
                    }
                    let cand = Cand {
                        rank: wl::quality_rank(&p),
                        bytes: r.size,
                        src: CandSrc::External {
                            url: r.link,
                            indexer: r.indexer,
                        },
                        posted: r.posted,
                        stem: r.title,
                        quality: crate::wall::quality_label(&p),
                    };
                    match best.entry(slot) {
                        std::collections::hash_map::Entry::Vacant(e) => {
                            e.insert(cand);
                        }
                        std::collections::hash_map::Entry::Occupied(mut e) => {
                            // STRICTLY better only: a local copy wins
                            // every tie, because grabbing it costs no
                            // third-party allowance.
                            if (cand.rank, cand.bytes) > (e.get().rank, e.get().bytes) {
                                e.insert(cand);
                            }
                        }
                    }
                }
            }
        }
        // M23e season packs: a bare-season post fills every episode of
        // its season at once, which is the efficient way to get a season
        // and a wasteful way to get the last two episodes of one. Judge
        // each pack candidate against what this item already holds, and
        // drop the ones that lose - see `wl::pack_eligible`.
        let pack_cands: Vec<(String, u32, u32)> = best
            .iter()
            .filter_map(|(k, c)| {
                wl::slot_parts(k).and_then(|(s, e)| e.is_none().then_some((k.clone(), s, c.rank)))
            })
            .collect();
        if !pack_cands.is_empty() {
            let cand_slots: Vec<String> = best.keys().cloned().collect();
            for (key, season, rank) in pack_cands {
                // The index only shows what has been POSTED, so on its
                // own it cannot say how much of a season is missing. The
                // calendar's cached episode list can, when there is one
                // - read here rather than up front because a pack
                // candidate is rare and this is a database round trip.
                let listed = aired_episodes(d, item, season);
                let st = wl::season_state(item, season, &state.slots, &cand_slots, &listed);
                if !wl::pack_eligible(item, season, rank, st) {
                    info!(
                        target: "watch",
                        "{}: season {season} pack skipped ({} of {} in-scope \
                         episode(s) already grabbed) - collecting single episodes instead",
                        item.title, st.have, st.known
                    );
                    best.remove(&key);
                }
            }
        }
        // Packs first, then the rest in a stable order: a season's pack
        // has to be settled BEFORE the single episodes it covers, or
        // whichever the hash map happened to yield first would win and
        // the same index could grab a pack one pass and singles the next.
        let mut ordered: Vec<(String, Cand)> = best.into_iter().collect();
        ordered.sort_by(|a, b| {
            wl::is_pack_slot(&b.0)
                .cmp(&wl::is_pack_slot(&a.0))
                .then_with(|| a.0.cmp(&b.0))
        });
        for (slot, c) in ordered {
            let key = wl::state_key(item.id, &slot);
            // An upgrade is already in flight for this slot - one at a time.
            if state.pending.iter().any(|p| p.slot == key) {
                continue;
            }
            let own = state.slots.get(&key);
            if own.is_some_and(|s| s.stem == c.stem || s.failed.contains(&c.stem)) {
                continue;
            }
            // What this slot effectively HAS: its own grab, or the season
            // pack covering it. An emptied slot (failed/deleted grab)
            // keeps its never-retry list but counts as having nothing.
            let cur = wl::covering(&state.slots, item.id, &slot);
            let cur_rank = cur.map(|s| s.rank);
            let prev_failed = own.map(|s| s.failed.clone()).unwrap_or_default();
            match wl::decide(cur_rank, c.rank, min, target, item.upgrade) {
                wl::Decision::Skip => {}
                wl::Decision::Grab => {
                    // §4b: join against history first. Slot state can lag
                    // reality (rebuilt state file, RSS/manual grabs), and
                    // relying on the duplicate-hold as the net piled
                    // dupe-held junk rows into the queue EVERY pass while
                    // the episode sat Completed in history. Adopt the
                    // completed copy as this slot instead of re-grabbing.
                    if let Some((h_name, h_nzo)) = completed_in_history(d, &c.stem)
                        // ...but only a copy that actually FILLS this slot.
                        // The join is on dupe_key, a separate text parser
                        // from the classified identity used for slots, and
                        // where the two disagree the mismatch is silent and
                        // permanent: the slot records a download the user
                        // never asked for, `cur_rank` is now set, and every
                        // later pass Skips. The event itself never
                        // downloads and nothing says so. Reading the reach
                        // off the completed release's own name is the same
                        // check `upgrade_supersedes_all` makes.
                        .filter(|(h_name, _)| covered_slots(item, &classify(h_name)).contains(&key))
                    {
                        let hp = classify(&h_name);
                        let h_rank = wl::quality_rank(&hp);
                        // completed_in_history joins on the quality-AGNOSTIC
                        // dupe_key, so the history copy can be BELOW the
                        // user's min_quality floor (e.g. an old 480p when the
                        // floor is 720p). Adopting it as the slot would then
                        // Skip forever with upgrade=false - the release the
                        // floor demands never downloads. Only adopt a copy
                        // that meets the floor; otherwise fall through and
                        // grab the candidate (which already passed decide).
                        if h_rank >= min {
                            info!(
                                target: "watch",
                                "{}: already in history as {} - adopted, not re-grabbed",
                                item.title, h_name
                            );
                            let slot_val = wl::Slot {
                                rank: h_rank,
                                stem: h_name,
                                quality: crate::wall::quality_label(&hp),
                                nzo_id: h_nzo,
                                grabbed_at: unix_now(),
                                failed: prev_failed.clone(),
                            };
                            // A double episode owns every slot it covers.
                            for extra in wl::extra_slots(item, &hp) {
                                claim_extra_slot(
                                    &mut state.slots,
                                    wl::state_key(item.id, &extra),
                                    &slot_val,
                                );
                            }
                            state.slots.insert(key, slot_val);
                            dirty = true;
                            continue;
                        }
                        info!(
                            target: "watch",
                            "{}: history copy {} is below min_quality - grabbing {} instead",
                            item.title, h_name, c.stem
                        );
                    }
                    if let Some(nzo) = watchlist_grab(d, &c.src, &c.stem, &item.category, false) {
                        info!(target: "watch", "{}: grabbed {} ({})", item.title, c.stem, c.quality);
                        note_instant(&mut state, &arrived, item.id, &c.stem, c.posted, unix_now());
                        let cp = classify(&c.stem);
                        let slot_val = wl::Slot {
                            rank: c.rank,
                            stem: c.stem,
                            quality: c.quality,
                            nzo_id: nzo,
                            grabbed_at: unix_now(),
                            failed: prev_failed,
                        };
                        // A double episode owns every slot it covers, so
                        // a standalone E02 alt is never re-grabbed.
                        for extra in wl::extra_slots(item, &cp) {
                            claim_extra_slot(
                                &mut state.slots,
                                wl::state_key(item.id, &extra),
                                &slot_val,
                            );
                        }
                        state.slots.insert(key, slot_val);
                        dirty = true;
                    }
                }
                wl::Decision::Upgrade => {
                    // `prev` is what this slot HAD, which for an episode
                    // can be the season pack covering it rather than a
                    // grab of its own. Everything below reads the right
                    // thing off it either way: the log line names the
                    // copy being beaten, and the delete is gated on
                    // whether the replacement reaches as far as that
                    // copy did - which a single episode never does
                    // against a pack, so the pack is never deleted for
                    // one better episode.
                    let prev = cur.cloned().unwrap();
                    if let Some(nzo) = watchlist_grab(d, &c.src, &c.stem, &item.category, true) {
                        info!(
                            target: "watch",
                            "{}: upgrading {} → {} ({})",
                            item.title, prev.quality, c.quality, c.stem
                        );
                        note_instant(&mut state, &arrived, item.id, &c.stem, c.posted, unix_now());
                        // The upgrade itself always stands; only the
                        // DELETE is held back, and only when this
                        // replacement does not reach as far as the
                        // download it supersedes. Held back, the old
                        // copy simply stays, exactly as it does for a
                        // delete_old=false item.
                        let cp = classify(&c.stem);
                        if item.delete_old
                            && upgrade_supersedes_all(item, &state, &prev, &cp, &cats)
                        {
                            state.pending.push(wl::PendingDelete {
                                slot: key.clone(),
                                new_nzo: nzo.clone(),
                                new_stem: c.stem.clone(),
                                old_nzo: prev.nzo_id.clone(),
                                prev_rank: prev.rank,
                                prev_stem: prev.stem.clone(),
                                prev_quality: prev.quality.clone(),
                            });
                        }
                        let slot_val = wl::Slot {
                            rank: c.rank,
                            stem: c.stem,
                            quality: c.quality,
                            nzo_id: nzo,
                            grabbed_at: unix_now(),
                            // This slot's OWN never-retry list, not
                            // `prev`'s: when prev is the season pack,
                            // its dead stems belong to the pack slot.
                            failed: prev_failed,
                        };
                        // A double-episode upgrade owns every slot it covers,
                        // exactly like the Grab and adopt arms. Without this
                        // the secondary slot (e.g. s01e02 of an S01E01E02
                        // upgrade) stayed empty and a standalone E02 was later
                        // grabbed as a duplicate of content already had.
                        for extra in wl::extra_slots(item, &cp) {
                            claim_extra_slot(
                                &mut state.slots,
                                wl::state_key(item.id, &extra),
                                &slot_val,
                            );
                        }
                        state.slots.insert(key, slot_val);
                        dirty = true;
                    }
                }
            }
        }
    }

    if dirty {
        let path = d.spool.join("watchlist-state.json");
        if let Ok(text) = serde_json::to_string_pretty(&state) {
            let _ = crate::persist::write_atomic(&path, text.as_bytes());
        }
    }
    *d.watch_state.lock_ok() = state;
}

/// §74: record a grab as INSTANT when the release being grabbed is one
/// of the arrivals that woke this pass.
///
/// The test is the name, not the timing: a pass woken by an arrival also
/// grabs whatever else it finds along the way, and calling those instant
/// too would turn the record into "a pass ran recently". Nothing reads
/// this back - it exists so the watchlist can show that the feature did
/// something, and so the tests can tell the two paths apart.
fn note_instant(
    state: &mut crate::watchlist::WatchState,
    arrived: &[String],
    item_id: u64,
    stem: &str,
    posted: i64,
    now: i64,
) {
    if !arrived.iter().any(|a| a == stem) {
        return;
    }
    let lag = if posted > 0 { (now - posted).max(0) } else { 0 };
    info!(target: "watch", "grabbed {stem} {lag}s after it was posted");
    state.instant.insert(
        item_id.to_string(),
        crate::watchlist::InstantGrab {
            stem: stem.to_string(),
            at: now,
            lag,
        },
    );
}

/// Episodes of one season that have ALREADY AIRED, from the calendar's
/// cached TVmaze episode list (M23d) - the denominator the season-pack
/// decision needs and the index cannot supply, since the index only
/// knows what somebody posted.
///
/// Unaired episodes are excluded deliberately: counting them would make
/// every part-way season look mostly missing, and a pack posted two
/// episodes in would then always look like the better buy. Empty when
/// there is no cached list (an unwatched title, a show TVmaze does not
/// have, a first pass before the refresh) - `pack_eligible` reads that
/// as "nobody knows", not as "nothing exists".
#[cfg_attr(not(feature = "indexer"), allow(unused_variables))]
fn aired_episodes(d: &Arc<Daemon>, item: &crate::watchlist::WatchItem, season: u32) -> Vec<u32> {
    if item.kind != "tv" {
        return Vec::new();
    }
    let days = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|t| (t.as_secs() / 86_400) as i64)
        .unwrap_or(0);
    let (y, m, dd) = civil_from_days(days);
    let today = format!("{y:04}-{m:02}-{dd:02}");
    #[cfg(feature = "indexer")]
    let key = format!("eplist:{}", crate::wall::norm_title(&item.title));
    #[cfg(feature = "indexer")]
    let eps: Vec<crate::wall::EpInfo> = d
        .with_index(|ix| ix.kv_get(&key))
        .and_then(|s| serde_json::from_str::<Value>(&s).ok())
        .and_then(|v| serde_json::from_value(v["episodes"].clone()).ok())
        .unwrap_or_default();
    // Slim build: no index, so no cached episode list to consult.
    #[cfg(not(feature = "indexer"))]
    let eps: Vec<crate::wall::EpInfo> = Vec::new();
    eps.iter()
        .filter(|e| e.season == season && !e.airdate.is_empty() && e.airdate <= today)
        .map(|e| e.episode)
        .collect()
}

/// Every slot of `item` a release fills: the one it places in, plus the
/// extra episodes of a multi-episode post. This is how far a download
/// reaches, read off the release itself, so it stays true however the
/// slot map has since been rewritten. Empty when the release does not
/// place in this item at all.
fn covered_slots(item: &crate::watchlist::WatchItem, p: &crate::wall::Parsed) -> Vec<String> {
    let Some(primary) = crate::watchlist::slot_of(item, p) else {
        return Vec::new();
    };
    std::iter::once(primary)
        .chain(crate::watchlist::extra_slots(item, p))
        .map(|s| crate::watchlist::state_key(item.id, &s))
        .collect()
}

/// May an upgrade delete the download it supersedes? Only when the
/// replacement reaches every slot the old download did.
///
/// A double-episode post is written into every episode slot it fills, so
/// it is the only copy of those episodes too, and deleting it for one
/// slot's upgrade takes the others with it - leaving the watchlist
/// believing it still has an episode whose files are gone. Reach comes
/// off each release's own stem, not off the slot map: the matching loop
/// rewrites that map as it goes, so with both episodes of a double
/// upgrading in one pass a map scan finds the first slot already
/// replaced and reads the second as unshared. The map is still consulted
/// for anything ELSE pointing at the old job - two watchlist items that
/// adopted the same completed download.
///
/// A like-for-like double upgrade (S01E01E02 720p → the same 1080p)
/// reaches both slots and so still deletes: the new job covers
/// everything the old one did.
fn upgrade_supersedes_all(
    item: &crate::watchlist::WatchItem,
    state: &crate::watchlist::WatchState,
    prev: &crate::watchlist::Slot,
    new_p: &crate::wall::Parsed,
    cats: &[nzbkit::categories::CustomCategory],
) -> bool {
    let new_reach = covered_slots(item, new_p);
    covered_slots(item, &nzbkit::categories::classify(&prev.stem, cats))
        .iter()
        .all(|k| new_reach.contains(k))
        && state
            .slots
            .iter()
            .all(|(k, s)| s.nzo_id != prev.nzo_id || new_reach.contains(k))
}

/// A Completed history entry with the same series/movie identity as
/// `stem` (dupe-key join): (job name, nzo_id).
fn completed_in_history(d: &Arc<Daemon>, stem: &str) -> Option<(String, String)> {
    let key = dupe_key(stem)?;
    d.history.lock_ok().iter().find_map(|j| {
        let g = j.lock_ok();
        (g.state == JobState::Completed && g.dupe_key.as_deref() == Some(key.as_str()))
            .then(|| (g.name.clone(), g.nzo_id.clone()))
    })
}

/// Synthesize the NZB for an indexed release and enqueue it. `promote`
/// lifts the M14f duplicate hold: an intentional upgrade IS a duplicate
/// of the completed original, that's the point.
fn watchlist_grab(
    d: &Arc<Daemon>,
    src: &CandSrc,
    stem: &str,
    category: &str,
    promote: bool,
) -> Option<String> {
    // A local candidate is served out of our own index; an external one
    // is fetched from the indexer that offered it, which is also what
    // spends that account's daily grab allowance. The external path
    // goes through enqueue_fetched so a watchlist grab gets the same
    // X-DNZB failure-link handling a hand-clicked one does.
    let nzo = match src {
        #[cfg(feature = "indexer")]
        CandSrc::Local(id) => {
            let xml = d.with_index(|ix| ix.make_nzb(*id).ok())?;
            d.enqueue(
                xml.as_bytes(),
                stem,
                category,
                -100,
                None,
                "watchlist",
                false,
            )
        }
        CandSrc::External { url, indexer } => {
            {
                let mut rt = d.indexer_rt.lock_ok();
                rt.usage.roll(unix_now());
                let cfg = d
                    .indexers
                    .lock()
                    .unwrap()
                    .iter()
                    .find(|i| &i.name == indexer)
                    .cloned();
                if cfg.is_some_and(|c| !rt.usage.grab_allowed(&c)) {
                    warn!(target: "watch", "{indexer}: daily grab budget reached - {stem} not grabbed");
                    return None;
                }
            }
            let fetched = match fetch_url(url) {
                Ok(f) => f,
                Err(e) => {
                    // redact_url_creds: fetch_url names the URL it failed
                    // on, and here that is the indexer's enclosure link,
                    // which carries the user's account apikey. logtee
                    // mirrors stdout/stderr into the dashboard log, so an
                    // unscrubbed line is not merely "in a file on the NAS".
                    warn!(
                        target: "watch",
                        "fetching {stem} from {indexer}: {}",
                        redact_url_creds(&e.to_string())
                    );
                    return None;
                }
            };
            let r = d.enqueue_fetched(&fetched, stem, category, -100, None, 0, "watchlist", false);
            if r.is_ok() {
                let mut rt = d.indexer_rt.lock_ok();
                rt.usage.count_grab(indexer);
                drop(rt);
                save_indexer_usage(d);
            }
            r
        }
    };
    match nzo {
        Ok(nzo) => {
            if promote {
                {
                    let q = d.queue.lock_ok();
                    if let Some(j) = q.iter().find(|j| j.lock_ok().nzo_id == nzo) {
                        let mut g = j.lock_ok();
                        if g.priority == -3 {
                            g.priority = 0;
                            g.paused = false;
                        }
                    }
                }
                d.save_queue();
            }
            Some(nzo)
        }
        Err(e) => {
            warn!(target: "watch", "enqueue {stem}: {e}");
            None
        }
    }
}

/// One external search on behalf of a watchlist item, tagged with the
/// indexer each result came from.
struct ExtCand {
    title: String,
    link: String,
    size: u64,
    posted: i64,
    indexer: String,
}

/// Ask every enabled, in-budget indexer about one watchlist item.
///
/// Deliberately free-text on the item's title: a watchlist entry is
/// something the user typed, and carries no imdb/tvdb id to be precise
/// with. A movie item pins its year, which is what disambiguates a
/// remake. Season/episode are NOT sent - one search per item per
/// cadence has to cover every wanted episode, and `slot_of` sorts the
/// results out afterwards anyway.
///
/// Returns the candidates plus, when this leg asked NOBODY, the reason
/// the gates gave - bundle D: those were bare `continue`s, so an item
/// whose indexers were all out of daily allowance looked exactly like
/// one nothing had been posted for.
fn watchlist_external_candidates(
    d: &Arc<Daemon>,
    item: &crate::watchlist::WatchItem,
) -> (Vec<ExtCand>, Option<String>) {
    let list: Vec<crate::newznab::IndexerConfig> = d
        .indexers
        .lock()
        .unwrap()
        .iter()
        .filter(|i| i.enabled)
        .cloned()
        .collect();
    if list.is_empty() {
        return (Vec::new(), None);
    }
    let mut runnable = Vec::new();
    // Per-indexer, and named: "your indexers are out of allowance" is a
    // different sentence from "NZBGeek is", and with three accounts
    // configured only the second one is actionable.
    let (mut spent, mut backed_off) = (Vec::new(), Vec::new());
    {
        let mut rt = d.indexer_rt.lock_ok();
        rt.usage.roll(unix_now());
        let now = Instant::now();
        for i in list {
            if rt.penalty_until.get(&i.name).is_some_and(|t| *t > now) {
                backed_off.push(i.name.clone());
                continue;
            }
            if !rt.usage.hit_allowed(&i) {
                spent.push(i.name.clone());
                continue;
            }
            rt.usage.count_hit(&i.name);
            runnable.push(i);
        }
    }
    if runnable.is_empty() {
        // Budget leads: an exhausted daily allowance lasts until
        // midnight and is the one the user can do something about,
        // where a rate-limit backoff clears itself in minutes.
        let gated = if !spent.is_empty() {
            Some(format!("indexer_budget:{}", spent.join(", ")))
        } else if !backed_off.is_empty() {
            Some(format!("indexer_backoff:{}", backed_off.join(", ")))
        } else {
            None
        };
        return (Vec::new(), gated);
    }
    save_indexer_usage(d);
    let q = match (item.kind.as_str(), item.year) {
        ("movie", Some(y)) => format!("{} {y}", item.title),
        _ => item.title.clone(),
    };
    let query = crate::newznab::SearchQuery {
        q,
        cats: cat_for_kind(&item.kind)
            .map(|c| vec![c])
            .unwrap_or_default(),
        limit: 100,
        ..Default::default()
    };
    let mut out = Vec::new();
    // The watcher already runs off the queue's critical path, so a
    // plain scoped fan-out is fine here; each call carries the shared
    // agent's 15 s ceiling.
    let results: Vec<_> = std::thread::scope(|s| {
        let handles: Vec<_> = runnable
            .iter()
            .map(|i| {
                let query = query.clone();
                s.spawn(move || (i.name.clone(), indexer_search_one(i, &query)))
            })
            .collect();
        handles.into_iter().filter_map(|h| h.join().ok()).collect()
    });
    let mut asked_ok = 0usize;
    let mut refused: Vec<String> = Vec::new();
    for (name, r) in results {
        match r {
            Ok(items) => {
                asked_ok += 1;
                for it in items {
                    out.push(ExtCand {
                        title: it.title,
                        link: it.link,
                        size: it.size,
                        posted: it.posted,
                        indexer: name.clone(),
                    });
                }
            }
            Err(e) => {
                if matches!(e, crate::newznab::NewznabError::Limit(..)) {
                    d.indexer_rt
                        .lock()
                        .unwrap()
                        .penalty_until
                        .insert(name.clone(), Instant::now() + INDEXER_LIMIT_BACKOFF);
                }
                refused.push(name.clone());
                // Never fatal: the item simply has no external candidate
                // this pass, and the local index still decides.
                warn!(target: "watch", "{name}: {e}");
            }
        }
    }
    // Every account we did ask refused us. Same class of silence as the
    // gates above and reported the same way; a leg that partly answered
    // says nothing, because the answer is what the item wanted.
    let gated = (asked_ok == 0 && !refused.is_empty())
        .then(|| format!("indexer_error:{}", refused.join(", ")));
    (out, gated)
}

/// Current server list as JSON values ready for editing. Prefers the
/// literal config.local.json contents (preserves keys the UI doesn't
/// know, e.g. rcvbuf); falls back to whatever the engine loader resolves
/// (e.g. a SABnzbd ini) so the first UI edit MATERIALIZES those servers
/// into config.local.json instead of silently dropping them.
fn current_servers(cfg_path: &std::path::Path) -> Vec<Value> {
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
fn nzbget_conf_paths() -> Vec<PathBuf> {
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

fn normalized_server(
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
fn watch_sig(p: &std::path::Path) -> Option<(u64, u64)> {
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
fn nzb_looks_complete(bytes: &[u8]) -> bool {
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
struct MintDisclosure(Option<PathBuf>);

impl MintDisclosure {
    fn disarm(&mut self) {
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

fn restore_runtime_state(
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

fn seed_index_retention(settings_path: &Path) -> std::sync::atomic::AtomicBool {
    std::sync::atomic::AtomicBool::new(
        load_settings(settings_path)
            .get("index_retention")
            .and_then(Value::as_bool)
            .unwrap_or(true),
    )
}

fn seed_index_pause_on_download(settings_path: &Path) -> std::sync::atomic::AtomicBool {
    std::sync::atomic::AtomicBool::new(
        load_settings(settings_path)
            .get("index_pause_on_download")
            .and_then(Value::as_bool)
            .unwrap_or(true),
    )
}

fn seed_index_paused(settings_path: &Path) -> std::sync::atomic::AtomicBool {
    std::sync::atomic::AtomicBool::new(
        load_settings(settings_path)
            .get("index_paused")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    )
}

fn seed_predb_enabled(settings_path: &Path) -> std::sync::atomic::AtomicBool {
    std::sync::atomic::AtomicBool::new(
        load_settings(settings_path)
            .get("predb_enabled")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    )
}

fn seed_predb_server(settings_path: &Path) -> Mutex<String> {
    Mutex::new(
        load_settings(settings_path)
            .get("predb_server")
            .and_then(Value::as_str)
            .filter(|s| !s.trim().is_empty())
            .unwrap_or(nzbkit::predb::DEFAULT_HOST)
            .to_string(),
    )
}

fn seed_predb_channels(settings_path: &Path) -> Mutex<String> {
    Mutex::new(
        load_settings(settings_path)
            .get("predb_channels")
            .and_then(Value::as_str)
            .filter(|s| !s.trim().is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| nzbkit::predb::DEFAULT_CHANNELS.join(",")),
    )
}

fn seed_predb_nick(settings_path: &Path) -> Mutex<String> {
    Mutex::new(
        load_settings(settings_path)
            .get("predb_nick")
            .and_then(Value::as_str)
            .filter(|s| !s.trim().is_empty())
            .unwrap_or(nzbkit::predb::DEFAULT_NICK)
            .to_string(),
    )
}

fn seed_predb_corr_enabled(settings_path: &Path) -> std::sync::atomic::AtomicBool {
    std::sync::atomic::AtomicBool::new(
        load_settings(settings_path)
            .get("predb_corr_enabled")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    )
}

fn seed_predb_corr_auto(settings_path: &Path) -> std::sync::atomic::AtomicBool {
    std::sync::atomic::AtomicBool::new(
        load_settings(settings_path)
            .get("predb_corr_auto")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    )
}

fn seed_spot_enabled(settings_path: &Path) -> std::sync::atomic::AtomicBool {
    std::sync::atomic::AtomicBool::new(
        load_settings(settings_path)
            .get("spot_enabled")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    )
}

fn seed_spot_groups(settings_path: &Path) -> Mutex<Vec<String>> {
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

fn seed_spot_backfill(settings_path: &Path) -> AtomicU64 {
    AtomicU64::new(
        load_settings(settings_path)
            .get("spot_backfill")
            .and_then(Value::as_u64)
            .unwrap_or(50_000)
            .clamp(1_000, 1_000_000),
    )
}

fn seed_index_max_bytes(settings_path: &Path) -> AtomicU64 {
    AtomicU64::new(
        load_settings(settings_path)
            .get("index_max_bytes")
            .and_then(Value::as_u64)
            .unwrap_or(0),
    )
}

fn seed_index_evict(settings_path: &Path) -> std::sync::atomic::AtomicBool {
    std::sync::atomic::AtomicBool::new(
        load_settings(settings_path)
            .get("index_evict")
            .and_then(Value::as_bool)
            .unwrap_or(false),
    )
}

#[cfg(feature = "indexer")]
fn seed_index_evict_order(settings_path: &Path) -> Mutex<String> {
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
fn seed_index_evict_kinds(settings_path: &Path) -> Mutex<Vec<String>> {
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
fn seed_index_gates(
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

fn seed_line_speed(settings_path: &Path) -> AtomicU64 {
    AtomicU64::new(
        load_settings(settings_path)
            .get("line_speed")
            .and_then(Value::as_u64)
            .unwrap_or(0),
    )
}

fn seed_auto_retry_secs(_settings_path: &Path, auto_retry_mins: u64) -> AtomicU64 {
    AtomicU64::new(
        std::env::var("NZBFAST_AUTO_RETRY_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(auto_retry_mins * 60),
    )
}

fn seed_quality_prefs(settings_path: &Path) -> Mutex<crate::watchlist::QualityPrefs> {
    Mutex::new(
        load_settings(settings_path)
            .get("prefer_quality")
            .and_then(|v| crate::watchlist::QualityPrefs::from_value(v).ok())
            .unwrap_or_default(),
    )
}

fn seed_stream_secret(settings_path: &Path) -> String {
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
                save_setting(settings_path, "stream_secret", json!(&s));
                s
            }
        }
    }
}

fn seed_omdb_key(settings_path: &Path) -> Mutex<Option<String>> {
    Mutex::new(
        load_settings(settings_path)
            .get("omdb_key")
            .and_then(Value::as_str)
            .map(str::to_string)
            .filter(|k| !k.is_empty()),
    )
}

#[cfg(feature = "indexer")]
fn resolve_index_enabled(settings_path: &Path, index_groups: &[String]) -> bool {
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

fn take_listener(bind: &str, port: u16) -> Result<tiny_http::Server> {
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

fn acquire_serve_lock(spool: &Path, config: &Path) -> Result<Option<std::fs::File>> {
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

fn spawn_core_tasks(
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
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn announce_ready(
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
fn warn_if_config_moved(minted_key: &Option<(String, PathBuf)>, out_root: &Path) {
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

pub async fn serve(config: PathBuf, mut opts: ServeOpts) -> Result<()> {
    reset_embedded_stop();
    // First thing: capture our own stdout/stderr so the dashboard's log
    // viewer sees the whole session, startup lines included.
    nzbkit::logtee::install();
    let settings_path = settings_file(&config);
    apply_saved_settings(&mut opts, &settings_path);
    // Secure-by-default on a genuinely new install (and ONLY there - see
    // first_run_apikey). Printed once, prominently, next to the listener
    // banner below, which is where a new user is looking.
    let minted_key = first_run_apikey(&mut opts, &settings_path, &config)?;
    // A key minted THIS RUN must be disclosed even if startup dies before
    // the banner (see MintDisclosure).
    let mut mint_disclosure =
        MintDisclosure(minted_key.as_ref().map(|(_, keyfile)| keyfile.clone()));
    // One explanation, printed at the moment it is true. A minted key
    // means the data directory read as brand new; a download root already
    // in use says the more likely story is an EXISTING install whose
    // config directory moved out from under it - a recreated container
    // reading an empty /config, a relative bind mount run from a
    // different directory, a fresh appdata path. From here everything
    // behaves like a first run, and without this line the user's next
    // stop is a bug report titled "all my settings are gone" (issue #9's
    // field report, verbatim).
    //
    // A warning ONLY. The download root must never join the
    // fresh-vs-existing decision itself - that was tried, and it was a
    // security regression (see first_run_apikey). Nothing here changes
    // what was minted or decided.
    warn_if_config_moved(&minted_key, &opts.out_root);
    // Saved settings may have overridden the CLI budget; republish so the
    // repair paths use the same figure the rest of the daemon does.
    nzbkit::mem::set_process_budget(opts.mem_budget);
    let ServeOpts {
        group_desc_isc: _,
        port,
        bind,
        open,
        apikey,
        nzbkey,
        out_root,
        watch,
        script,
        connections,
        window,
        decoders,
        fast_verify,
        verify_lean,
        min_free,
        out_umask,
        auto_retry_mins,
        preflight,
        quota,
        quota_period,
        feeds,
        speedlimit,
        schedule,
        auto_speed,
        library_cats,
        library_recheck_secs,
        mem_budget,
        #[cfg(feature = "indexer")]
        index_db,
        #[cfg(feature = "indexer")]
        index_groups,
        #[cfg(feature = "indexer")]
        index_interval_secs,
        #[cfg(feature = "indexer")]
        index_backfill,
        #[cfg(feature = "indexer")]
        index_max_age_secs,
        #[cfg(feature = "indexer")]
        index_gates,
    } = opts;
    let legacy_rename_punctuation = legacy_rename_punctuation(&config, &out_root, &settings_path);
    // The indexer's master switch, and the one migration it needs.
    //
    // A saved value always wins - that is the user's answer. With NO
    // saved value we are either a fresh install (off: see the field's
    // doc comment) or an install from before the switch existed, and
    // those two are told apart by whether anything was ever chosen to
    // index. Groups here already carry settings.json and the config file
    // (see the settings merge above), so a CLI `--index-groups` or a
    // hand-written config counts too - starting a daemon that was
    // explicitly pointed at groups and then not scanning them would be
    // the same surprise as the upgrade case.
    #[cfg(not(feature = "indexer"))]
    let index_enabled = false;
    #[cfg(feature = "indexer")]
    let index_enabled = resolve_index_enabled(&settings_path, &index_groups);
    // Resolved once: every spool path below must agree, or a migrated
    // daemon reads half its state from the old location.
    // ABSOLUTE from here on. Sonarr reads `misc.complete_dir` out of
    // get_config to learn where this client puts files, and a relative
    // path means nothing to another process - different cwd, often a
    // different container or host - so it reports "Remote Path Mapping"
    // while the downloads themselves land perfectly, because WE resolve
    // it against our own cwd. That is exactly the shape of the v1.0.9
    // report: right folder, wrong error. SABnzbd always answers absolute.
    //
    // Resolved rather than canonicalized: the directory may not exist
    // yet on a first run, and canonicalize() fails on a missing path.
    let out_root = if out_root.is_absolute() {
        out_root
    } else {
        std::env::current_dir()
            .map(|c| c.join(&out_root))
            .unwrap_or(out_root)
    };
    let server = take_listener(&bind, port)?;
    let spool = spool_dir(&config, &out_root);
    // Windows has no dotfile convention, so `.spool` is plainly visible
    // wherever it lands - including inside the user's download folder on
    // an install that predates the data-dir move. Create it up front so
    // there is something to set the attribute ON: every other writer
    // makes it implicitly via create_dir_all of a child, which would
    // leave the hide to lose a race it cannot see.
    let _ = std::fs::create_dir_all(&spool);
    nzbkit::disk::hide_from_user(&spool);
    let _serve_lock = acquire_serve_lock(&spool, &config)?;
    let daemon = Arc::new(Daemon {
        hub: Arc::new(crate::StreamHub::default()),
        paused: std::sync::atomic::AtomicBool::new(false),
        offline: std::sync::atomic::AtomicBool::new(false),
        paused_by_offline: std::sync::atomic::AtomicBool::new(false),
        queue: Mutex::new(VecDeque::new()),
        history: Mutex::new(Vec::new()),
        add_lock: Mutex::new(()),
        moving: Mutex::new(std::collections::HashSet::new()),
        reserved: Mutex::new(std::collections::HashSet::new()),
        progress: Arc::new(AtomicU64::new(0)),
        active_total: AtomicU64::new(0),
        active_dl: Mutex::new(None),
        started_at: Mutex::new(None),
        last_download_end: Mutex::new(Instant::now()),
        stall_since: Mutex::new(None),
        playback_disk: Mutex::new(std::collections::HashMap::new()),
        next_id: AtomicU64::new(1),
        out_root: std::sync::RwLock::new(out_root.clone()),
        move_completed: std::sync::RwLock::new(None),
        move_completed_cats: std::sync::RwLock::new(Vec::new()),
        spool: spool.clone(),
        cfg_path: config.clone(),
        cats: Mutex::new(DEFAULT_CATS.iter().map(|s| s.to_string()).collect()),
        port,
        // A failed mint leaves an EMPTY token, and `launcher_proof` then
        // answers a challenge with sha256(":nonce") - a value any process
        // could compute. Refuse to answer at all instead: the wrappers
        // treat "no proof" as "an older daemon" and fall back, which is
        // strictly better than a proof anyone can forge.
        launcher_token: random_apikey().unwrap_or_default(),
        port_locked: port_locked(),
        library_cats: Mutex::new(library_cats),
        active_stream: Mutex::new(None),
        #[cfg(feature = "indexer")]
        index_db: index_db.clone(),
        #[cfg(feature = "indexer")]
        index: Mutex::new(None),
        #[cfg(feature = "indexer")]
        index_read: IndexReadPool::default(),
        #[cfg(feature = "indexer")]
        index_read_warned: AtomicU64::new(0),
        #[cfg(feature = "indexer")]
        index_migrated: std::sync::atomic::AtomicBool::new(false),
        #[cfg(feature = "indexer")]
        index_stats_cache: Mutex::new(None),
        auto_speed: std::sync::atomic::AtomicBool::new(auto_speed),
        preflight: std::sync::atomic::AtomicBool::new(preflight),
        auto_connections: std::sync::atomic::AtomicBool::new(true),
        wall_hide_adult: std::sync::atomic::AtomicBool::new(true),
        auto_defer: std::sync::atomic::AtomicBool::new(true),
        post_health: std::sync::atomic::AtomicBool::new(true),
        post_health_defer: std::sync::atomic::AtomicBool::new(false),
        auto_prefetch: std::sync::atomic::AtomicBool::new(true),
        race_stragglers: std::sync::atomic::AtomicBool::new(true),
        adaptive_timeouts: std::sync::atomic::AtomicBool::new(true),
        oracle_route: std::sync::atomic::AtomicBool::new(false),
        index_deepen: AtomicU64::new(200_000),
        index_coverage: std::sync::atomic::AtomicBool::new(true),
        index_gapfill: AtomicU64::new(4),
        bench_interval: AtomicU64::new(0),
        bench_last: AtomicU64::new(0),
        update_manifest: Mutex::new(None),
        update_serial_seen: std::sync::atomic::AtomicU64::new(0),
        // Notify-only: finding a newer version raises the dashboard
        // banner and nothing else - the daemon never replaces its own
        // binary (the self-update code was removed in 1.0.5; the
        // manifest itself is still ed25519-verified before the banner
        // trusts it). ON by default so users hear about releases; turn
        // it off here (or empty update_url) and the daemon never
        // phones the manifest at all.
        update_checks: std::sync::atomic::AtomicBool::new(true),
        unit_bits: std::sync::atomic::AtomicBool::new(false),
        update_url: Mutex::new(DEFAULT_UPDATE_URL.to_string()),
        ui_locale: Mutex::new(String::new()),
        sidecar: Mutex::new(None),
        media_rejudge: Mutex::new(Vec::new()),
        best_rate_bps: AtomicU64::new(0),
        speed_ceiling: AtomicU64::new(0),
        mem_budget_total: mem_budget.total,
        feeds: Mutex::new(Vec::new()),
        feed_health: Mutex::new(Default::default()),
        last_refusals: Mutex::new(Default::default()),
        events: Mutex::new(Default::default()),
        indexers: Mutex::new(Vec::new()),
        watchlist_external: std::sync::atomic::AtomicBool::new(false),
        watchlist_external_set: std::sync::atomic::AtomicBool::new(false),
        indexer_rt: Mutex::new(IndexerRuntime::default()),
        // §74: on by default and inert without the indexer - see the
        // field. Saved settings replay over these below.
        watchlist_instant: AtomicBool::new(true),
        watchlist_instant_max: std::sync::atomic::AtomicU32::new(INSTANT_MAX_DEFAULT),
        #[cfg(feature = "indexer")]
        instant_kicks: Mutex::new(std::collections::VecDeque::new()),
        #[cfg(feature = "indexer")]
        instant_pending: Mutex::new(std::collections::HashMap::new()),
        instant_hint: Mutex::new(Vec::new()),
        nzblnk_recent: Mutex::new(std::collections::VecDeque::new()),
        smart_folders: Mutex::new(Vec::new()),
        par_cleanup: AtomicBool::new(true),
        // OFF unless asked for: an install that says nothing keeps
        // exactly the modes it has today (#20).
        out_umask: std::sync::atomic::AtomicU32::new(out_umask.unwrap_or(u32::MAX)),
        fast_par: AtomicBool::new(FAST_PAR_DEFAULT),
        prefer_external_unrar: AtomicBool::new(false),
        cleanup_exts: Mutex::new(Vec::new()),
        password_file: Mutex::new(config.with_file_name("passwords.txt")),
        password_prompt: Mutex::new("done".to_string()),
        unpack_eat_volumes: Mutex::new("off".to_string()),
        // Loaded from settings.json below (next to smart_folders); the
        // reclassify flag starts set so startup reconciles the stored
        // rows against the current config exactly once (the index stamps
        // the config fingerprint, so an unchanged config is a no-op).
        custom_categories: std::sync::RwLock::new(Vec::new()),
        reclassify_pending: std::sync::atomic::AtomicBool::new(true),
        // Auto-rename defaults: on, with resolution in the name; codecs /
        // source / group off; junk sweep on; keep-media-only off. Saved
        // settings replay over these below.
        identity_lookup: std::sync::atomic::AtomicBool::new(true),
        auto_rename: std::sync::atomic::AtomicBool::new(true),
        rename_resolution: std::sync::atomic::AtomicBool::new(true),
        rename_vcodec: std::sync::atomic::AtomicBool::new(false),
        rename_acodec: std::sync::atomic::AtomicBool::new(false),
        rename_source: std::sync::atomic::AtomicBool::new(false),
        rename_group: std::sync::atomic::AtomicBool::new(false),
        rename_year_parens: std::sync::atomic::AtomicBool::new(legacy_rename_punctuation),
        rename_quality_brackets: std::sync::atomic::AtomicBool::new(legacy_rename_punctuation),
        rename_extra_words: std::sync::atomic::AtomicBool::new(true),
        rename_identify: std::sync::atomic::AtomicBool::new(true),
        // Off by default, alone among the rename sub-settings: it
        // changes filenames an existing install already wrote, and an
        // *arr's import matcher is reading those. See the field docs.
        rename_episode_titles: std::sync::atomic::AtomicBool::new(false),
        history_rows: AtomicU64::new(10),
        history_color_names: std::sync::atomic::AtomicBool::new(true),
        ladder_live: Mutex::new(None),
        ladder_busy: std::sync::atomic::AtomicBool::new(false),
        ladder_cancel: std::sync::atomic::AtomicBool::new(false),
        media_chip_color: std::sync::atomic::AtomicBool::new(true),
        shape_chip_color: std::sync::atomic::AtomicBool::new(true),
        rename_junk: std::sync::atomic::AtomicBool::new(true),
        rename_media_only: std::sync::atomic::AtomicBool::new(false),
        #[cfg(feature = "indexer")]
        index_max_age_secs: AtomicU64::new(index_max_age_secs),
        #[cfg(not(feature = "indexer"))]
        index_max_age_secs: AtomicU64::new(0),
        // Retention defaults ON: if a user bothered to set a max-age
        // window they almost always want the DB to hold ~that window,
        // not hoard everything older. Off = ingest-gate-only (the
        // pre-M31 behavior), toggle in Settings (persists across
        // restarts like the other live settings).
        index_retention: seed_index_retention(&settings_path),
        index_pause_on_download: seed_index_pause_on_download(&settings_path),
        index_paused: seed_index_paused(&settings_path),
        index_enabled: std::sync::atomic::AtomicBool::new(index_enabled),
        // Pre feed: OFF unless the user has explicitly saved it on. A
        // missing key, a null, or a non-bool all land here - there is no
        // path that opens an outbound IRC connection by accident.
        predb_enabled: seed_predb_enabled(&settings_path),
        predb_server: seed_predb_server(&settings_path),
        predb_channels: seed_predb_channels(&settings_path),
        predb_nick: seed_predb_nick(&settings_path),
        #[cfg(feature = "indexer")]
        predb_pending: Mutex::new(Vec::new()),
        predb_status: Mutex::new(String::new()),
        // Correlation: same explicit-opt-in contract as the feed. Both
        // default OFF; a missing key never turns an inference engine on.
        predb_corr_enabled: seed_predb_corr_enabled(&settings_path),
        predb_corr_auto: seed_predb_corr_auto(&settings_path),
        #[cfg(feature = "indexer")]
        predb_max_rows: std::sync::atomic::AtomicU64::new(predb_seed::PREDB_MAX_ROWS_DEFAULT),
        #[cfg(not(feature = "indexer"))]
        predb_max_rows: std::sync::atomic::AtomicU64::new(250_000),
        #[cfg(feature = "indexer")]
        predb_seed_days: std::sync::atomic::AtomicU64::new(predb_seed::PREDB_SEED_DAYS_DEFAULT),
        #[cfg(not(feature = "indexer"))]
        predb_seed_days: std::sync::atomic::AtomicU64::new(180),
        #[cfg(feature = "indexer")]
        predb_seed_running: std::sync::atomic::AtomicBool::new(false),
        #[cfg(feature = "indexer")]
        predb_seed_status: Mutex::new(String::new()),
        // Spots are new, so there is no existing-install case to seed
        // from: nobody has one running today. Straight off until asked.
        spot_enabled: seed_spot_enabled(&settings_path),
        spot_groups: seed_spot_groups(&settings_path),
        spot_backfill: seed_spot_backfill(&settings_path),
        #[cfg(feature = "indexer")]
        index_generation: AtomicU64::new(0),
        index_jobs_active: Arc::new(AtomicUsize::new(0)),
        // M34 size cap. UI-only settings (no CLI flags), read straight
        // off settings.json like index_retention above.
        index_max_bytes: seed_index_max_bytes(&settings_path),
        // OFF unless the user has explicitly saved it on. A missing key,
        // a null, or a non-bool all land here - there is no path that
        // turns deletion on by accident.
        index_evict: seed_index_evict(&settings_path),
        #[cfg(feature = "indexer")]
        index_evict_order: seed_index_evict_order(&settings_path),
        #[cfg(not(feature = "indexer"))]
        index_evict_order: Mutex::new("ladder".to_string()),
        #[cfg(feature = "indexer")]
        index_evict_kinds: seed_index_evict_kinds(&settings_path),
        #[cfg(not(feature = "indexer"))]
        index_evict_kinds: Mutex::new(Vec::new()),
        #[cfg(feature = "indexer")]
        compact_pending: std::sync::atomic::AtomicBool::new(false),
        #[cfg(feature = "indexer")]
        last_auto_trim: std::sync::Mutex::new(None),
        #[cfg(feature = "indexer")]
        index_opened: Mutex::new(
            crate::persist::load_json_with_backup(&spool.join("index-opened.json"))
                .and_then(|v| serde_json::from_value::<OpenedLog>(v).ok())
                .unwrap_or_default(),
        ),
        #[cfg(feature = "indexer")]
        index_gates: seed_index_gates(&settings_path, index_gates),
        line_speed: seed_line_speed(&settings_path),
        tune_hint: Mutex::new(String::new()),
        cpu_sample: Mutex::new(None),
        speed_win: Mutex::new(VecDeque::new()),
        usage: Mutex::new(
            crate::persist::load_json_with_backup(&spool.join("usage.json"))
                .and_then(|v| v.as_object().cloned())
                .unwrap_or_default(),
        ),
        pause_until: Mutex::new(None),
        pause_gen: AtomicU64::new(0),
        connections: std::sync::atomic::AtomicUsize::new(connections.max(1)),
        window: std::sync::atomic::AtomicUsize::new(window.max(1)),
        decoders: std::sync::atomic::AtomicUsize::new(decoders.max(1)),
        fast_verify: std::sync::atomic::AtomicBool::new(fast_verify),
        verify_lean: std::sync::atomic::AtomicBool::new(verify_lean),
        min_free: AtomicU64::new(min_free.unwrap_or(MIN_FREE_DEFAULT)),
        queue_hold: std::sync::Mutex::new(None),
        pause_source: std::sync::Mutex::new("user"),
        limit_source: std::sync::Mutex::new("user"),
        auto_retry_secs: seed_auto_retry_secs(&settings_path, auto_retry_mins),
        quota: AtomicU64::new(quota.unwrap_or(0)),
        quota_period: std::sync::atomic::AtomicU8::new(if quota_period == 'm' {
            b'm'
        } else {
            b'd'
        }),
        watch_dir: Mutex::new(watch),
        watch_keep_nzb: AtomicBool::new(false),
        watch_failed: Mutex::new(std::collections::HashMap::new()),
        watch_picked: Mutex::new(std::collections::VecDeque::new()),
        auto_retried: Mutex::new(std::collections::VecDeque::new()),
        giveup_tripped: Mutex::new(std::collections::VecDeque::new()),
        watch_upgraded: Mutex::new(std::collections::VecDeque::new()),
        delete_kept: Mutex::new(std::collections::VecDeque::new()),
        auth_fails: Mutex::new(std::collections::HashMap::new()),
        #[cfg(feature = "indexer")]
        enrich_hot: Mutex::new(std::collections::VecDeque::new()),
        #[cfg(feature = "indexer")]
        group_catalog: Mutex::new(None),
        #[cfg(feature = "indexer")]
        group_fetching: std::sync::atomic::AtomicBool::new(false),
        #[cfg(feature = "indexer")]
        group_fetch_err: Mutex::new(None),
        #[cfg(feature = "indexer")]
        group_stats: Mutex::new(Arc::new(crate::groupstats::StatsCache::default())),
        #[cfg(feature = "indexer")]
        group_sampling: Mutex::new(std::collections::HashSet::new()),
        group_desc_isc: std::sync::atomic::AtomicBool::new(opts.group_desc_isc),
        script: Mutex::new(script),
        script_timeout: AtomicU64::new(3600),
        notify_targets: Mutex::new(Vec::new()),
        notify_health: Mutex::new(Default::default()),
        failure_link: Mutex::new("off".to_string()),
        quality_prefs: seed_quality_prefs(&settings_path),
        apikey: Mutex::new(apikey),
        nzbkey: Mutex::new(nzbkey),
        stream_secret: seed_stream_secret(&settings_path),
        omdb_key: seed_omdb_key(&settings_path),
        library_recheck_secs: AtomicU64::new(library_recheck_secs.max(1)),
        #[cfg(feature = "indexer")]
        index_groups: Mutex::new(index_groups),
        #[cfg(not(feature = "indexer"))]
        index_groups: Mutex::new(Vec::new()),
        index_interests: Mutex::new(String::new()),
        index_interests_applied: Mutex::new(String::new()),
        index_interest_groups: Mutex::new(Vec::new()),
        #[cfg(feature = "indexer")]
        index_interval_secs: AtomicU64::new(index_interval_secs),
        #[cfg(not(feature = "indexer"))]
        index_interval_secs: AtomicU64::new(900),
        #[cfg(feature = "indexer")]
        index_backfill: AtomicU64::new(index_backfill),
        #[cfg(not(feature = "indexer"))]
        index_backfill: AtomicU64::new(20000),
        scan_now: tokio::sync::Notify::new(),
        #[cfg(feature = "indexer")]
        scan_deep: AtomicU64::new(0),
        #[cfg(feature = "indexer")]
        scan_progress: Mutex::new(Vec::new()),
        index_scan_par: AtomicU64::new(3),
        scan_active: std::sync::atomic::AtomicBool::new(false),
        index_tip_secs: AtomicU64::new(20),
        watch_interval_secs: AtomicU64::new(5),
        watch_scan_now: tokio::sync::Notify::new(),
        oracle_sample: AtomicU64::new(300),
        schedule: Mutex::new(Vec::new()),
        schedule_text: Mutex::new(String::new()),
        watchlist: Mutex::new(Vec::new()),
        watch_state: Mutex::new(Default::default()),
        watch_now: tokio::sync::Notify::new(),
        arr_giveup_threshold: AtomicU64::new(0),
        arr_instances: Mutex::new(Vec::new()),
        giveup: Arc::new(Mutex::new(Default::default())),
        settings_path: settings_path.clone(),
        #[cfg(feature = "indexer")]
        taste_cache: Mutex::new(None),
    });

    restore_runtime_state(&daemon, &settings_path, &spool, &config, &speedlimit)?;

    spawn_core_tasks(
        &daemon,
        &config,
        &settings_path,
        &schedule,
        &feeds,
        #[cfg(feature = "indexer")]
        &index_db,
        mem_budget,
    )?;

    // M13: metadata enrichment worker. With a TMDB key (config tmdb_key
    // or TMDB_API_KEY env) it uses TMDB; WITHOUT one it still runs,
    // keyless, via TVmaze (tv) + Wikidata/Wikipedia (movies) - TMDB
    // declines API applications for NZB tooling, so keyless is the normal
    // path. iTunes used to serve movies; Apple removed that endpoint.
    // Network stays on this thread - never the API's.
    #[cfg(feature = "indexer")]
    let tmdb_key = nzbkit::config::Config::load(&config)
        .ok()
        .and_then(|c| c.tmdb_key)
        .or_else(|| std::env::var("TMDB_API_KEY").ok())
        .filter(|k| !k.is_empty());
    #[cfg(feature = "indexer")]
    tasks::spawn_enrichment_workers(&daemon, &tmdb_key);

    tasks::spawn_update_checker(&daemon);

    tasks::spawn_scheduled_bench(&daemon, &config);

    tasks::spawn_auto_connections(&daemon, &config);

    announce_ready(
        &daemon,
        &settings_path,
        &bind,
        port,
        &minted_key,
        &mut mint_disclosure,
        open,
    );
    #[cfg(feature = "indexer")]
    http::spawn_http_workers(server, daemon.clone(), config.clone(), tmdb_key.clone());
    #[cfg(not(feature = "indexer"))]
    http::spawn_http_workers(server, daemon.clone(), config.clone());

    park_for_embedded_stop().await;
    // Returning drops our Arc<server>; the workers drop theirs within one
    // HTTP_IDLE_TICK (they poll the stop flag between accepts), and the
    // last drop closes the listener so the port is free to rebind.
    Ok(())
}

/// A leftover stop request from a previous embedded run (see
/// `request_stop`) must not fell the next one: called first thing in
/// [`serve`], before anything can wait on the flag.
fn reset_embedded_stop() {
    STOP_REQUESTED.store(false, std::sync::atomic::Ordering::SeqCst);
}

/// Park until an embedded host asks for an in-process stop. The CLI
/// daemon never does - its stop paths (signals, tray Quit) exit the
/// process - so for it this parks forever, exactly as before.
async fn park_for_embedded_stop() {
    loop {
        stop_notify().notified().await;
        // Load, never consume: the HTTP workers read this same flag to
        // wind up after serve() returns; it resets at the next entry.
        if STOP_REQUESTED.load(std::sync::atomic::Ordering::SeqCst) {
            break;
        }
    }
}

/// One tick of the HTTP workers' accept wait. Long enough to cost
/// nothing (8 workers waking twice a second), short enough that an
/// embedded stop releases the listener promptly.
const HTTP_IDLE_TICK: std::time::Duration = std::time::Duration::from_millis(500);

/// Set by [`request_stop`], consumed by [`serve`]'s park loop and polled
/// by the HTTP workers between accepts. Reset at serve() entry so a stop
/// request from a previous embedded run cannot fell the next one.
static STOP_REQUESTED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn stop_notify() -> &'static tokio::sync::Notify {
    static N: std::sync::OnceLock<tokio::sync::Notify> = std::sync::OnceLock::new();
    N.get_or_init(tokio::sync::Notify::new)
}

/// In-process stop for embedded builds (the iOS staticlib, where exec
/// and process exit are not available): [`serve`] returns instead of
/// parking and the HTTP workers wind up, closing the listener. This is
/// NOT the graceful wind-down the signal path runs - the embedded host
/// stops the tokio runtime after serve() returns, which is what cancels
/// the background tasks. Safe to call before or more than once per
/// serve(): a permit is held until consumed and the flag is re-checked.
// dead_code: only the embedded crate root (lib.rs, `ffi` feature) has a
// caller; the CLI daemon stops by process exit. The module compiles
// under both roots, so the bin build sees this as dead.
#[allow(dead_code)]
pub fn request_stop() {
    STOP_REQUESTED.store(true, std::sync::atomic::Ordering::SeqCst);
    stop_notify().notify_one();
}

mod http;
mod stream;
use stream::*;

/// Wrong keys tolerated from one address inside [`AUTH_FAIL_WINDOW`] before
/// it is refused outright. Generous: a misconfigured *arr retries a handful
/// of times, and locking that out helps nobody.
const AUTH_FAIL_THRESHOLD: u32 = 10;
/// How long the failure count is remembered. Also the block duration - the
/// count resets by simply going quiet, so there is no permanent lockout and
/// no state to unstick.
const AUTH_FAIL_WINDOW: std::time::Duration = std::time::Duration::from_secs(60);
/// Ceiling on tracked addresses, so the map itself cannot be the attack.
const AUTH_FAIL_MAX_TRACKED: usize = 4096;

impl Daemon {
    /// Record a rejected API key and decide whether this address has had
    /// enough. `true` = refuse without doing any further work.
    ///
    /// Deliberately refuses FAST rather than sleeping. The obvious throttle
    /// is a delay before answering, but responses are written on the small
    /// shared worker pool, so a delay is exactly the worker-occupancy problem
    /// a slowloris exploits - it would harden the key and hand over the
    /// dashboard. Refusing immediately costs an attacker the same round trip
    /// and costs us nothing.
    ///
    /// Returns false (allow) when the address is unknown or the table is
    /// full: failing open on *accounting* is fine, the key check itself still
    /// has to pass.
    fn note_auth_failure(&self, addr: Option<std::net::IpAddr>, what: &str) -> bool {
        note_auth_failure_in(&self.auth_fails, addr, what)
    }
}

/// The accounting itself, split out from `Daemon` so it can be tested
/// without standing up a whole daemon.
fn note_auth_failure_in(
    table: &Mutex<std::collections::HashMap<std::net::IpAddr, (u32, Instant)>>,
    addr: Option<std::net::IpAddr>,
    what: &str,
) -> bool {
    {
        let Some(ip) = addr else { return false };
        let now = Instant::now();
        let mut fails = table.lock_ok();
        if fails.len() >= AUTH_FAIL_MAX_TRACKED {
            fails.retain(|_, (_, seen)| now.duration_since(*seen) < AUTH_FAIL_WINDOW);
            if fails.len() >= AUTH_FAIL_MAX_TRACKED {
                return false;
            }
        }
        let entry = fails.entry(ip).or_insert((0, now));
        if now.duration_since(entry.1) >= AUTH_FAIL_WINDOW {
            *entry = (0, now);
        }
        entry.0 += 1;
        let count = entry.0;
        // Log the first, then only on crossing, so a flood cannot be used to
        // fill the disk through the log.
        if count == 1 {
            warn!(target: "auth", "rejected key for {what} from {ip}");
        } else if count == AUTH_FAIL_THRESHOLD {
            warn!(
                target: "auth",
                "{count} rejected keys from {ip} in under {}s - refusing it for {}s",
                AUTH_FAIL_WINDOW.as_secs(),
                AUTH_FAIL_WINDOW.as_secs()
            );
        }
        count >= AUTH_FAIL_THRESHOLD
    }
}

/// The client address of a request, when the transport knows one.
fn peer_ip(req: &tiny_http::Request) -> Option<std::net::IpAddr> {
    req.remote_addr().map(|a| a.ip())
}

/// Constant-time-ish string equality for the stream token - a plain ==
/// short-circuits on the first differing byte.
fn ct_eq(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .fold(0u8, |acc, (x, y)| acc | (x ^ y))
            == 0
}

/// Issue #4: the API key may ride a header instead of the query string,
/// which keeps it out of reverse-proxy access logs, browser history and
/// outbound Referer headers - the leak paths of a `?apikey=` URL on an
/// internet-published install. `X-Api-Key: <key>` (the *arr convention)
/// or `Authorization: Bearer <key>` (what auth proxies inject). The
/// query string still wins when both are present and stays supported
/// forever - Sonarr/Radarr and plain links can only do URLs.
fn header_apikey(req: &tiny_http::Request) -> Option<String> {
    let hv = |name: &'static str| {
        req.headers()
            .iter()
            .find(|h| h.field.equiv(name))
            .map(|h| h.value.as_str().trim().to_string())
            .filter(|v| !v.is_empty())
    };
    hv("X-Api-Key").or_else(|| {
        hv("Authorization").and_then(|v| {
            // RFC 7235: the scheme token is case-insensitive. Matching
            // only the two spellings we happened to think of rejected a
            // compliant `BEARER <key>` from an auth proxy that
            // normalizes headers.
            let (scheme, rest) = v.split_once(' ')?;
            scheme
                .eq_ignore_ascii_case("bearer")
                .then(|| rest.trim().to_string())
                .filter(|s| !s.is_empty())
        })
    })
}

fn parse_query(q: &str) -> std::collections::HashMap<String, String> {
    q.split('&')
        .filter_map(|kv| {
            let (k, v) = kv.split_once('=')?;
            Some((k.to_string(), urldecode(v)))
        })
        .collect()
}

/// [`parse_query`] for a REQUEST BODY, bounded the way `multipart_fields`
/// is and for exactly the same reason.
///
/// A query string is bounded by tiny_http's header limit before it ever
/// reaches `parse_query`. A body is not: the /api pre-drain reads up to
/// `API_BODY_MAX` (256 MiB) BEFORE authenticating, so a form of that size
/// full of tiny `k=` pairs turned into tens of millions of live `String`
/// allocations - several GB of resident set, from an unauthenticated
/// request, decided long before the 403. The multipart sibling has
/// carried these two caps since it was written; the form path beside it
/// never got them.
///
/// Same figures as `multipart_fields`: 256 fields, 4096 bytes a value.
/// Every real caller is far inside both - the largest legitimate body
/// field is an NZB, which arrives as a multipart FILE part, not here.
fn parse_form_body(q: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    for kv in q.split('&') {
        if out.len() >= 256 {
            break;
        }
        let Some((k, v)) = kv.split_once('=') else {
            continue;
        };
        if k.is_empty() || k.len() > 256 || v.len() > 4096 {
            continue;
        }
        out.push((k.to_string(), urldecode(v)));
    }
    out
}

fn urldecode(s: &str) -> String {
    let mut out = Vec::new();
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if i + 3 <= b.len() => {
                let hex = std::str::from_utf8(&b[i + 1..i + 3]).unwrap_or("");
                if let Ok(v) = u8::from_str_radix(hex, 16) {
                    out.push(v);
                    i += 3;
                } else {
                    out.push(b[i]);
                    i += 1;
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// A multipart part's header block is a handful of short ASCII lines
/// (Content-Disposition with a name/filename, maybe a Content-Type).
/// Bounding it BEFORE decoding matters more than usual here: this runs
/// pre-authentication on a body of up to 256 MiB, and
/// `String::from_utf8_lossy` expands each invalid byte to a 3-byte
/// replacement character - so one part whose "header" is the whole body
/// used to allocate ~3x the body on top of it (Codex H8). 8 KiB is far
/// past any legitimate filename.
const MAX_PART_HEADER: usize = 8 << 10;

/// Extract (filename, bytes) of the first file part in a multipart body.
fn multipart_file(body: &[u8], boundary: &str) -> Option<(String, Vec<u8>)> {
    if !valid_boundary(boundary) {
        return None;
    }
    let delim = format!("--{boundary}");
    let mut found = None;
    for_each_split(body, delim.as_bytes(), |part| {
        let Some(hdr_end) = find_bytes(part, b"\r\n\r\n") else {
            return true; // preamble/epilogue segments have no header block
        };
        if hdr_end > MAX_PART_HEADER {
            return true; // attacker-sized header: never decode it
        }
        let headers = String::from_utf8_lossy(&part[..hdr_end]);
        if let Some(fn_pos) = headers.find("filename=\"") {
            let rest = &headers[fn_pos + 10..];
            let fname = rest.split('"').next().unwrap_or("upload.nzb").to_string();
            let mut content = &part[hdr_end + 4..];
            // Strip the trailing \r\n before the next boundary.
            if content.ends_with(b"\r\n") {
                content = &content[..content.len() - 2];
            }
            found = Some((fname, content.to_vec()));
            return false;
        }
        true
    });
    found
}

/// Extract (name, value) of every NON-file field of a multipart body -
/// the parts carrying no `filename=`. SAB-compat: browser addons send
/// api parameters (mode, apikey, cat, nzbname) this way on POST. Values
/// keep multipart's trailing-CRLF strip; anything file-sized is skipped
/// - a parameter is short, and treating a mis-labelled upload as one
/// would copy megabytes into a HashMap key nobody reads.
fn multipart_fields(body: &[u8], boundary: &str) -> Vec<(String, String)> {
    if !valid_boundary(boundary) {
        return Vec::new();
    }
    let delim = format!("--{boundary}");
    let mut out: Vec<(String, String)> = Vec::new();
    for_each_split(body, delim.as_bytes(), |part| {
        // A form carrying thousands of fields is not a form. This runs
        // before authentication, on a body of up to 256 MiB, so the
        // parser's own working set has to be bounded by something other
        // than the attacker's segment count.
        if out.len() >= 256 {
            return false;
        }
        let Some(hdr_end) = find_bytes(part, b"\r\n\r\n") else {
            return true; // preamble/epilogue segments have no header block
        };
        if hdr_end > MAX_PART_HEADER {
            return true; // attacker-sized header: never decode it
        }
        let headers = String::from_utf8_lossy(&part[..hdr_end]);
        if headers.contains("filename=\"") {
            return true; // the file part is multipart_file's business
        }
        let Some(np) = headers.find("name=\"") else {
            return true;
        };
        let name = headers[np + 6..]
            .split('"')
            .next()
            .unwrap_or("")
            .to_string();
        if name.is_empty() {
            return true;
        }
        let mut content = &part[hdr_end + 4..];
        if content.ends_with(b"\r\n") {
            content = &content[..content.len() - 2];
        }
        if content.len() > 4096 {
            return true;
        }
        out.push((name, String::from_utf8_lossy(content).into_owned()));
        true
    });
    out
}

/// Minimal magic-number sniff for user-supplied poster bytes (M21
/// wall_art): JPEG / PNG / GIF / WebP. Anything else is refused before
/// it can land in the art cache.
#[cfg(feature = "indexer")]
fn looks_image(b: &[u8]) -> bool {
    b.starts_with(&[0xFF, 0xD8, 0xFF])
        || b.starts_with(&[0x89, b'P', b'N', b'G'])
        || b.starts_with(b"GIF8")
        || (b.len() >= 12 && b.starts_with(b"RIFF") && &b[8..12] == b"WEBP")
}

/// Split `hay` on `needle`, calling `f` with each segment; stops early
/// when `f` returns false.
///
/// Deliberately not the `Vec<&[u8]>` this replaced. That vector was the
/// multipart parser's amplifier: one fat pointer per delimiter, 16 bytes
/// on 64-bit, so a body made of nothing but delimiters turned a 256 MiB
/// read into roughly 2 GiB of Vec on top of it - allocated before
/// authentication, and outside the body budget that bounds the read
/// itself. Iterating costs a constant.
fn for_each_split<'a>(hay: &'a [u8], needle: &[u8], mut f: impl FnMut(&'a [u8]) -> bool) {
    // An empty needle matches everywhere: `find_bytes` returns Some(0)
    // for every position and the walk never advances. Callers reject
    // empty boundaries before this, but the primitive must not depend
    // on that.
    if needle.is_empty() {
        f(hay);
        return;
    }
    let mut start = 0;
    while let Some(pos) = find_bytes(&hay[start..], needle) {
        if !f(&hay[start..start + pos]) {
            return;
        }
        start += pos + needle.len();
    }
    f(&hay[start..]);
}

/// Is this a multipart boundary we will parse at all?
///
/// RFC 2046 puts a boundary at 1-70 characters of a restricted set. The
/// length bound is what matters here: an EMPTY boundary - which
/// `Content-Type: multipart/form-data; boundary=` supplies, and which
/// nothing legitimate sends - makes the delimiter `--`, so a body of
/// repeated hyphens splits into a segment every two bytes.
fn valid_boundary(b: &str) -> bool {
    !b.is_empty() && b.len() <= 70 && !b.contains('\r') && !b.contains('\n')
}

/// The multipart boundary in a `Content-Type`, or None when the header
/// does not carry a usable one.
///
/// ONE copy, because there were three and they disagreed. The parameter
/// NAME is case-insensitive like the media type around it, but the
/// VALUE is a literal delimiter that has to keep its case - so the
/// position is found in a lowercased copy and the text is cut from the
/// original. The gateway learned that in Codex sweep 2's H1 while the
/// two handler-side copies stayed case-sensitive, which left `Boundary=`
/// parsing at the gateway (fields merged, auth decided) and failing in
/// the handler (no file part at all).
///
/// [`valid_boundary`] is applied here rather than by callers: an empty
/// `boundary=` makes the delimiter `--`, so a body of hyphens splits
/// once every two bytes. Nothing legitimate sends one, and refusing it
/// at the source means no caller can forget to.
fn multipart_boundary(ctype: &str) -> Option<String> {
    let at = ctype.to_ascii_lowercase().find("boundary=")? + "boundary=".len();
    // The value ends at the parameter separator, not at the end of the
    // header. Taking the rest of the line swept up whatever followed:
    // an ordinary `boundary="----abc"; charset=UTF-8` became
    // `----abc"; charset=UTF-8` (the leading quote trimmed, the trailing
    // one buried mid-string), which appears nowhere in the body. The
    // split then found no delimiter, so the upload's file part was
    // silently dropped as "no nzb file in request" - and a caller whose
    // apikey travelled in the body had it stop being found at all,
    // presenting a content-type problem as an authentication failure,
    // which is the hardest possible thing to support.
    //
    // Cut from the ORIGINAL, so the delimiter keeps its case; `at` is
    // valid there because the needle is ASCII and lowercasing does not
    // move byte offsets for it.
    let rest = ctype[at..].trim_start();
    let value = match rest.strip_prefix('"') {
        // Quoted: to the closing quote. A quoted value may legally hold
        // characters that would otherwise end the parameter.
        Some(q) => q.split('"').next().unwrap_or_default(),
        None => rest.split(';').next().unwrap_or_default().trim_end(),
    };
    Some(value.to_string()).filter(|b| valid_boundary(b))
}

fn find_bytes(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn json_resp(v: Value) -> tiny_http::Response<std::io::Cursor<Vec<u8>>> {
    let data = v.to_string().into_bytes();
    tiny_http::Response::from_data(data).with_header(
        tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap(),
    )
}

/// May a scan pass that began at `pass_era` hand its freshly-opened
/// connection to the daemon, given the current `era` and switch state?
///
/// Both conditions, because they fail differently. A stale era means the
/// database itself was replaced (wiped) under the pass, so the
/// connection points at a file nobody wants back. `!enabled` means no
/// source wants the database any more - the user switched the last one
/// off during the pass: the era may well still match - switching off
/// does bump it, but a pass could equally have started while off - and
/// "closed" has to stay closed.
#[cfg(feature = "indexer")]
fn may_publish_index(era: u64, pass_era: u64, enabled: bool) -> bool {
    era == pass_era && enabled
}

mod sabcompat;
use sabcompat::*;

/// Run a child to completion with a deadline, draining its pipes.
///
/// `Command::output()` has no timeout, so a post-processing script that
/// hung held its `spawn_blocking` thread for the life of the daemon, and
/// one per completed job after that. Returns `(None, _)` when the
/// deadline was hit and the child killed; `secs == 0` waits forever,
/// which is what someone running a multi-hour transcode wants.
///
/// stderr is drained by its own thread rather than polled: a child that
/// fills the 64 KB pipe buffer blocks on the write, so waiting on the
/// process alone would turn any chatty script into a timeout. stdout is
/// drained too, and thrown away - nothing reads it, and a script that
/// prints for a living should not be able to spend the daemon's memory
/// proving it.
///
/// Only the LAST [`SCRIPT_ERR_TAIL`] bytes of stderr are kept. The whole
/// stream used to accumulate in a `String`, so an accidental
/// `while true; do echo …; done` grew the daemon until it died - well
/// before any deadline could stop it.
///
/// Two things the deadline has to survive, both of them ordinary
/// post-script shapes rather than hostile ones:
///
///  - A script that backgrounds work (`transcode & `) and exits. The
///    descendant INHERITS stdout/stderr, so the pipes stay open after
///    the direct child is gone and a `join` on the drain threads blocked
///    until the descendant finished. That join ran on the daemon's
///    blocking pool, one leaked worker per completed job, and the pool
///    is finite. The drains are therefore never joined - they are given
///    a short grace and then abandoned, holding nothing but a bounded
///    ring.
///  - The same script when the deadline expires. `Child::kill` signals
///    the direct child alone, so on unix the child is given its own
///    process group and the whole group is signalled. Windows keeps the
///    single-process kill (a job object is the equivalent, and is a
///    bigger change than this fix warrants).
fn run_capped(
    mut cmd: std::process::Command,
    secs: u64,
) -> std::io::Result<(Option<std::process::ExitStatus>, String)> {
    use std::process::Stdio;
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // Own process group, so the deadline can reach what the script
    // spawned. Inherited by every descendant that does not deliberately
    // leave it.
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        cmd.process_group(0);
    }
    let mut child = cmd.spawn()?;
    let tail = Arc::new(Mutex::new(BoundedTail::default()));
    // Detached on purpose: see the doc comment. Each thread owns its pipe
    // and exits when the last writer closes it, whenever that is.
    if let Some(r) = child.stdout.take() {
        std::thread::spawn(move || drain_to_nowhere(r));
    }
    if let Some(r) = child.stderr.take() {
        let tail = tail.clone();
        std::thread::spawn(move || drain_into(r, &tail));
    }
    let deadline = (secs > 0).then(|| Instant::now() + std::time::Duration::from_secs(secs));
    let status = loop {
        if let Some(st) = child.try_wait()? {
            break Some(st);
        }
        if deadline.is_some_and(|d| Instant::now() >= d) {
            #[cfg(unix)]
            unsafe {
                // Negative pid = the whole group. The direct child is
                // killed by the same signal, so no separate kill needed;
                // fall back to it if the group send fails.
                if libc::kill(-(child.id() as i32), libc::SIGKILL) != 0 {
                    let _ = child.kill();
                }
            }
            #[cfg(not(unix))]
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    };
    // The child is gone; its own writes are already in the ring or in
    // flight. A short grace collects the tail end without waiting on any
    // descendant that may still hold the pipe open.
    std::thread::sleep(std::time::Duration::from_millis(50));
    let stderr = tail.lock_ok().tail_text();
    Ok((status, stderr))
}

/// How much of a script's stderr is worth keeping. Enough for a stack
/// trace or a usage message, which is all the log line quotes.
const SCRIPT_ERR_TAIL: usize = 8 << 10;

/// The last [`SCRIPT_ERR_TAIL`] bytes written to it, and nothing else.
#[derive(Default)]
struct BoundedTail {
    buf: std::collections::VecDeque<u8>,
    dropped: usize,
}

impl BoundedTail {
    fn push(&mut self, bytes: &[u8]) {
        self.buf.extend(bytes);
        while self.buf.len() > SCRIPT_ERR_TAIL {
            self.buf.pop_front();
            self.dropped += 1;
        }
    }

    /// The kept tail as text, prefixed with what was dropped. Not a
    /// `Display` impl: this is a lossy read-out of a byte ring for one
    /// log line, not a rendering of the value.
    fn tail_text(&self) -> String {
        let text =
            String::from_utf8_lossy(&self.buf.iter().copied().collect::<Vec<u8>>()).into_owned();
        if self.dropped == 0 {
            text
        } else {
            // Say what was cut, or a truncated trace reads as the whole
            // story - the interesting line may be the one that went.
            format!("[…{} earlier bytes dropped…]{text}", self.dropped)
        }
    }
}

fn drain_into(mut r: impl std::io::Read, tail: &Mutex<BoundedTail>) {
    let mut buf = [0u8; 8192];
    while let Ok(n) = r.read(&mut buf) {
        if n == 0 {
            return;
        }
        tail.lock_ok().push(&buf[..n]);
    }
}

fn drain_to_nowhere(mut r: impl std::io::Read) {
    let mut buf = [0u8; 8192];
    while matches!(r.read(&mut buf), Ok(n) if n > 0) {}
}

/// A person's headshot URL, or "" when the cache does not hold one.
///
/// Empty is normal and not an error: the headshot lane fetches lazily,
/// and the cache evicts under its cap, so the UI must always be able to
/// fall back to initials.
#[cfg(feature = "indexer")]
fn person_photo_url(art_dir: &std::path::Path, id: i64) -> String {
    let f = crate::wall::person_art_name(id);
    if art_dir.join(&f).is_file() {
        format!("/art/{f}")
    } else {
        Default::default()
    }
}

/// Is `n` a name the unauthenticated /art/ route may join onto the art
/// directory? Only our own `art_name()` output, which is flat ASCII.
///
/// The sanitize round-trip is what keeps a Windows reserved DOS device
/// name out: "CON" is all alphanumerics, so the character class alone
/// lets it through, and `art_root.join("CON")` then opens the console
/// device rather than a file. The read never returns (a hidden console
/// has nobody to type EOF into), so it holds one of the few HTTP worker
/// threads for the life of the process. Real art names carry a "m_"/"t_"
/// key prefix, so none of them can be a device name.
#[cfg(feature = "indexer")]
fn art_name_ok(n: &str) -> bool {
    !n.is_empty()
        && !n.contains("..")
        && n.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
        && nzbkit::disk::sanitize_filename_for(n, true) == n
}

/// M28: poster-grid thumbnail - fit inside 342×513 (the TMDB w342
/// aspect), JPEG q80. ~20 KB out of a multi-MB source; None on decode
/// failure (the route then 404s and the client falls back to full art).
#[cfg(feature = "indexer")]
fn make_thumb(src: &[u8]) -> Option<Vec<u8>> {
    let img = image::load_from_memory(src).ok()?;
    // Some providers (TVmaze mediums) already serve small posters -
    // never upscale, and never "shrink" into a bigger file.
    if img.width() <= 342 {
        return Some(src.to_vec());
    }
    let img = image::DynamicImage::ImageRgb8(img.thumbnail(342, 513).to_rgb8());
    let mut out = Vec::new();
    img.write_with_encoder(image::codecs::jpeg::JpegEncoder::new_with_quality(
        &mut out, 80,
    ))
    .ok()?;
    Some(if out.len() < src.len() {
        out
    } else {
        src.to_vec()
    })
}

/// SAB's `nzo_ids` selector: a client naming specific ids gets exactly
/// those rows, with no start/limit window applied. Sonarr reconciles a
/// download weeks after the grab; an id hidden behind `limit=60` reads
/// as "gone" and wedges its tracking, so direct selection must bypass
/// pagination the way real SABnzbd's does.
fn nzo_ids_param(
    params: &std::collections::HashMap<String, String>,
) -> Option<std::collections::HashSet<String>> {
    let raw = params.get("nzo_ids")?;
    let set: std::collections::HashSet<String> = raw
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    (!set.is_empty()).then_some(set)
}

/// start/limit pagination over already-built slots (SAB semantics: both
/// optional; limit 0 = everything).
fn paginate(slots: Vec<Value>, params: &std::collections::HashMap<String, String>) -> Vec<Value> {
    let start: usize = params
        .get("start")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let limit: usize = params
        .get("limit")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let it = slots.into_iter().skip(start);
    if limit == 0 {
        it.collect()
    } else {
        it.take(limit).collect()
    }
}

/// SSRF guard for server-side fetches of user/attacker-supplied URLs
/// (addurl, /watch, poster-from-URL).
///
/// Scope is deliberate: this is a SELF-HOSTED app whose normal job is to
/// talk to indexers on loopback and the LAN (Prowlarr/nzbhydra, or
/// nzbfast's own newznab endpoint), and to be reached over Tailscale
/// (CGNAT 100.64/10). Blocking those would break the common single-box /
/// single-LAN topology. So loopback, RFC1918 and CGNAT are ALLOWED.
///
/// What is refused is the class that is never a legitimate fetch target
/// and is the high-value SSRF prize: the cloud-metadata endpoint and the
/// rest of link-local (169.254/16, fe80::/10), plus unspecified/broadcast.
/// That kills instance-credential theft on AWS/GCP/Azure without breaking
/// local indexers.
pub(crate) fn is_forbidden_fetch_ip(ip: std::net::IpAddr) -> bool {
    use std::net::{IpAddr, Ipv4Addr};
    match ip {
        IpAddr::V4(a) => {
            a.is_link_local()   // 169.254/16, incl. 169.254.169.254 metadata
                || a.is_unspecified() // 0.0.0.0
                || a.is_broadcast()
                || a.octets()[0] == 0 // 0.0.0.0/8 "this network"
                // Alibaba Cloud metadata lives at 100.100.100.200, which is
                // INSIDE the 100.64/10 CGNAT range we otherwise allow for
                // Tailscale - block just that host.
                || a == Ipv4Addr::new(100, 100, 100, 200)
        }
        IpAddr::V6(a) => {
            if let Some(v4) = a.to_ipv4_mapped() {
                return is_forbidden_fetch_ip(IpAddr::V4(v4));
            }
            let s = a.segments();
            a.is_unspecified()
                || (s[0] & 0xffc0) == 0xfe80 // link-local fe80::/10
                // AWS IPv6 IMDS is fd00:ec2::/32, inside the fc00::/7 ULA
                // range we otherwise allow for v6 LANs - block that block.
                || (s[0] == 0xfd00 && s[1] == 0x0ec2)
        }
    }
}

/// ureq resolver that refuses to hand back any internal address. Because
/// ureq connects to exactly the SocketAddrs returned here (no second
/// lookup), this closes the DNS-rebinding window AND re-checks on every
/// redirect hop, since each hop resolves through it.
struct SsrfGuardResolver;
impl ureq::Resolver for SsrfGuardResolver {
    fn resolve(&self, netloc: &str) -> std::io::Result<Vec<std::net::SocketAddr>> {
        use std::net::ToSocketAddrs;
        let addrs: Vec<std::net::SocketAddr> = netloc.to_socket_addrs()?.collect();
        if addrs.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "no address",
            ));
        }
        if addrs.iter().any(|a| is_forbidden_fetch_ip(a.ip())) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!("refusing to fetch an internal address ({netloc})"),
            ));
        }
        Ok(addrs)
    }
}

/// An agent whose every connection (initial + each redirect) is filtered
/// through the SSRF guard. Use for ANY fetch of a user/attacker-supplied
/// URL. `redirects` is capped by the caller.
pub(crate) fn ssrf_safe_agent(redirects: u32, timeout_secs: u64) -> ureq::Agent {
    ureq::AgentBuilder::new()
        .resolver(SsrfGuardResolver)
        .redirects(redirects)
        .timeout(std::time::Duration::from_secs(timeout_secs))
        .build()
}

/// The ONE outbound HTTP agent the wall enricher shares (plan §4 C2).
///
/// In ureq the Agent *is* the connection pool, so `ureq::get(...)` -
/// which builds a throwaway agent per call - reconnects and re-does the
/// TLS handshake for every single request. The enricher makes several
/// requests per title (search, entity, summary, art) and runs over
/// thousands of titles a scan, all to a handful of hosts, so it was
/// paying a full handshake where a pooled connection costs nothing.
///
/// One agent, kept for the process's life, and callers still set their
/// own per-request `.timeout()` - which is why a single shared agent can
/// serve a 10 s metadata lookup and a 120 s dataset download alike.
///
/// It carries the SSRF resolver for the same reason the NZB fetcher
/// does: these hosts are ours today, but user-supplied sources are the
/// stated direction for this code, and a pool that guards by default
/// cannot be forgotten later.
pub(crate) fn shared_enrich_agent() -> ureq::Agent {
    static AGENT: std::sync::OnceLock<ureq::Agent> = std::sync::OnceLock::new();
    AGENT.get_or_init(|| ssrf_safe_agent(4, 30)).clone()
}

/// An NZB fetched by URL, plus what the indexer said about it in the
/// response headers.
pub struct Fetched {
    pub bytes: Vec<u8>,
    /// `X-DNZB-Failure`: where to report this download failing, and where
    /// the indexer hands back a replacement NZB for the same title. See
    /// [`Daemon::report_failure`].
    pub failure_link: String,
    /// Host of the URL that was REQUESTED (not the last redirect hop):
    /// the only host `failure_link` may point back at. See
    /// [`Daemon::report_failure`].
    pub host: String,
    /// Was the REQUESTED url https? A failure link may not downgrade the
    /// scheme it was handed over. See [`failure_link_allowed`].
    pub https: bool,
    /// `X-DNZB-Category`, when the indexer sends one. Parsed, but never
    /// used to route a download: the category picks the output subfolder,
    /// the library flag and the move-completed destination, and those are
    /// the user's choice, not the responding server's. Kept (and
    /// asserted on) so the header parse stays covered if a future caller
    /// has a legitimate use for it.
    #[allow(dead_code)]
    pub category: String,
}

/// One `X-DNZB-*` header, trimmed, or empty.
fn dnzb(resp: &ureq::Response, name: &str) -> String {
    resp.header(name).unwrap_or_default().trim().to_string()
}

/// The failure-report link out of the two spellings in the wild.
/// `X-DNZB-Failure` is what indexers actually send (it is the header
/// NZBGet's own FailureLink reads, via the `*DNZB:Failure` parameter);
/// `X-DNZB-FailureLink` is what the feature is usually CALLED, and a few
/// indexers send that name instead. The canonical one wins, and a header
/// present but blank counts as absent.
fn pick_failure_link(canonical: &str, alias: &str) -> String {
    if canonical.is_empty() {
        alias.to_string()
    } else {
        canonical.to_string()
    }
}

/// The host of an http(s) URL, lowercased, without userinfo and without
/// the port - or empty when there isn't one. Deliberately port-blind: an
/// indexer that serves NZBs on :9117 and reports failures on :9118 is
/// still the same machine, and the check is about WHOSE server we call,
/// not which socket.
///
/// Hand-rolled because the daemon has no URL crate. It parses less than a
/// real one, and everything it cannot parse comes back empty, which fails
/// the origin match - the safe direction.
fn url_host(url: &str) -> String {
    let rest = match url.split_once("://") {
        Some((scheme, rest))
            if scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https") =>
        {
            rest
        }
        _ => return String::new(),
    };
    // Authority ends at the first '/', '?' or '#'.
    let auth = rest.split(['/', '?', '#']).next().unwrap_or("");
    // `user:pass@host` - the LAST '@' separates them, so a password
    // containing '@' cannot smuggle a fake host in front of the real one.
    let hostport = match auth.rsplit_once('@') {
        Some((_, h)) => h,
        None => auth,
    };
    // `[::1]:8080` - the bracketed literal is the host; a bare IPv6 with
    // no brackets is not a legal authority and drops out as empty below.
    let host = if let Some(end) = hostport.find(']') {
        if hostport.starts_with('[') {
            &hostport[..=end]
        } else {
            ""
        }
    } else {
        hostport.split(':').next().unwrap_or("")
    };
    host.to_ascii_lowercase()
}

/// May this job's `failure_link` be called? Only when it points back at
/// the host that supplied it. The link arrives in a RESPONSE HEADER from
/// whatever server answered the NZB fetch, and the daemon then calls it
/// from inside the user's network with an SSRF guard that permits
/// loopback and RFC1918 (LAN indexers are the normal case). Binding it to
/// the origin keeps that concession from becoming "any indexer can aim
/// the daemon at any address on your LAN".
///
/// Same host is necessary but not sufficient: an https origin may not be
/// handed an http link. The daemon's own indexer apikey rides in that
/// query string, and "the same indexer, in the clear" is a different
/// party to anything on the path between here and it.
fn failure_link_allowed(link: &str, origin_host: &str, origin_https: bool) -> bool {
    // Both sides come out of `url_host`, so this is a comparison of
    // normalized hosts. An empty origin (an NZB the user uploaded, or a
    // record written before this field existed) matches nothing.
    let h = url_host(link);
    if h.is_empty() || h != origin_host {
        return false;
    }
    // Byte compare, not `&link[..8]`: the link comes out of a response
    // header, and slicing a str at a byte index that lands inside a
    // multi-byte character panics.
    !origin_https || link.len() >= 8 && link.as_bytes()[..8].eq_ignore_ascii_case(b"https://")
}

/// Does this response body carry a replacement NZB? Indexers answer 200
/// with a human "nothing found" page at least as often as they answer
/// with XML, so the body decides and the status does not. Same test
/// FailureLink applies.
fn is_nzb_body(bytes: &[u8]) -> bool {
    bytes.starts_with(b"<?xml")
}

/// What a re-grabbed replacement inherits from the job it stands in for:
/// `(category, priority, password)`.
///
/// All three used to be dropped on the floor (`cat` fell back to the
/// indexer's own `X-DNZB-Category`, priority was a hardcoded 0, password
/// a hardcoded None), which meant: a Force job's replacement queued at
/// Normal behind work the user had deprioritized; a passworded release's
/// replacement downloaded in full and then failed extraction for a
/// password the daemon was holding (the name-convention fallback cannot
/// recover it - by then `name` is the stem AFTER `smart::name_password`
/// stripped the marker); and the responding server, not the user, chose
/// the output subfolder, the library flag and the move-completed
/// destination.
///
/// Priority is clamped at Normal: a held duplicate carries -3, which is a
/// "parked, do not run" marker, not a speed.
fn replacement_inherits(j: &Job) -> (String, i32, Option<String>) {
    (j.category.clone(), j.priority.max(0), j.password.clone())
}

/// May we queue a replacement right now - the mode asks for one, and this
/// chain has not already spent its allowance?
fn may_regrab(mode: &str, depth: u8) -> bool {
    mode == "regrab" && depth < FAILURE_REGRAB_MAX
}

/// Ceiling on a fetched NZB. Every caller of [`fetch_url`] - the RSS
/// poller, `/watch`, `addurl`, the failure-link re-grab - takes its URL
/// from somewhere the user does not fully control, and none of them has
/// an opt-in for "this one is allowed to be huge", so the old 256 MB was
/// a quarter of a gigabyte of RAM available to anything that can answer a
/// request.
///
/// 64 MB, not the "a few MB" an NZB usually is: a real 4K remux triple
/// feature off the bench farm measures 23.7 MB of XML, and obfuscated
/// message-ids inflate that further, so the headroom is deliberate. This
/// is a runaway-response guard, not a size policy. An uploaded file goes
/// through addfile, which keeps its own (much larger) body cap.
const FETCH_MAX_BYTES: u64 = 64 * 1024 * 1024;

/// The bit of [`fetch_url`] both it and [`ping_url`] share: scheme check,
/// SSRF-guarded GET, and the indexer headers off the response.
fn fetch_head(url: &str) -> Result<(ureq::Response, String, String)> {
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        anyhow::bail!("addurl: unsupported url {url}");
    }
    // Release assets redirect to a CDN host; follow the whole chain, but
    // every hop is SSRF-filtered so a public URL can't 302 into 127.0.0.1
    // or 169.254.169.254.
    let resp = ssrf_safe_agent(10, 60).get(url).call()?;
    let failure_link = pick_failure_link(
        &dnzb(&resp, "X-DNZB-Failure"),
        &dnzb(&resp, "X-DNZB-FailureLink"),
    );
    let category = dnzb(&resp, "X-DNZB-Category");
    Ok((resp, failure_link, category))
}

fn fetch_url(url: &str) -> Result<Fetched> {
    use std::io::Read;
    let (resp, failure_link, category) = fetch_head(url)?;
    // Refuse an oversized body BEFORE reading it, when the server was
    // honest enough to declare one; the take() below is the backstop for
    // when it wasn't.
    if let Some(len) = resp
        .header("Content-Length")
        .and_then(|l| l.trim().parse::<u64>().ok())
        && len > FETCH_MAX_BYTES
    {
        anyhow::bail!("{url}: {len} bytes is too large for an NZB");
    }
    let mut bytes = Vec::new();
    resp.into_reader()
        .take(FETCH_MAX_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > FETCH_MAX_BYTES {
        anyhow::bail!("{url}: response is too large for an NZB");
    }
    // The host we ASKED for, deliberately - not resp.get_url(), which is
    // the last hop of the redirect chain. Otherwise an indexer (or
    // anything that can answer for it) launders an arbitrary origin by
    // bouncing the fetch through one redirect.
    Ok(Fetched {
        bytes,
        failure_link,
        host: url_host(url),
        https: url.starts_with("https://"),
        category,
    })
}

/// GET a URL for its SIDE EFFECT only, and never read the body.
///
/// `failure_link` in `report` mode: the report IS the request, nothing
/// inspects what comes back, and a 404 is a normal answer. Returning
/// `Ok(None)` keeps the caller's one error arm (which is where the 404
/// handling lives) doing the work for both modes.
fn ping_url(url: &str) -> Result<Option<Fetched>> {
    fetch_head(url)?;
    Ok(None)
}

/// M35 pull-search runtime state, one lock for all of it: the caps
/// cache, the per-day usage counters, limit backoffs, and the
/// token->result cache. The result cache is the security seam: an
/// external result's NZB link embeds the user's indexer apikey, so the
/// browser only ever sees an opaque token and `indexer_grab` will fetch
/// exactly the URLs a search stored - never one the client supplies.
#[derive(Default)]
struct IndexerRuntime {
    /// M35 phase 2: what each indexer's `t=caps` said, so an id search
    /// is only ever sent to a site that advertises the parameter. A
    /// FAILED probe is cached too (as None) - an indexer that cannot
    /// answer caps must not be re-probed on every keystroke-driven
    /// search - just for much less time than a success.
    ///
    /// Keyed by [`IndexerConfig::identity`] - the far end - and NOT by
    /// name: caps describe a site and an account, while the name is a
    /// label the user edits, reuses and types into unsaved drafts.
    /// See that method for what keying on the name cost.
    ///
    /// [`IndexerConfig::identity`]: crate::newznab::IndexerConfig::identity
    caps: std::collections::HashMap<String, (Instant, Option<crate::newznab::Caps>)>,
    /// Indexers backing off after a limit error, by name. The name is
    /// right here: a budget/backoff belongs to the configured ENTRY the
    /// user set limits on, and only a saved entry ever runs a search.
    penalty_until: std::collections::HashMap<String, Instant>,
    usage: crate::newznab::Usage,
    #[cfg(feature = "indexer")]
    results: std::collections::HashMap<String, IndexerHit>,
    /// Insertion order, for capping `results`.
    #[cfg(feature = "indexer")]
    order: std::collections::VecDeque<String>,
}

/// One cached external search result, grabbable by token.
#[cfg(feature = "indexer")]
#[derive(Clone)]
struct IndexerHit {
    url: String,
    title: String,
    indexer: String,
    at: Instant,
}

/// How far back the `addnzblnk` rate gate looks.
const NZBLNK_WINDOW: std::time::Duration = std::time::Duration::from_secs(60);
/// Link resolutions allowed per window before the endpoint refuses. A
/// person clicking board links does a handful a minute; a page in a loop
/// does not stop.
const NZBLNK_MAX: usize = 20;
/// ...and how many of those may reach the user's indexers. Lower,
/// because this is the threshold that guards a metered account rather
/// than our own CPU. Past it the ladder still runs, local-only.
const NZBLNK_EXTERNAL_MAX: usize = 6;

/// A grab token stays valid this long after its search.
#[cfg(feature = "indexer")]
const INDEXER_HIT_TTL: std::time::Duration = std::time::Duration::from_secs(30 * 60);

/// How long a pull search will wait for an xREL slot before giving up on
/// the id enrichment. Their search budget is 2 calls per 5 s, so a
/// second search inside that window finds the bucket empty - and a
/// search that returns its releases a beat sooner without an IMDb id is
/// a better answer than one that returns everything late.
#[cfg(feature = "indexer")]
const XREL_UI_WAIT: std::time::Duration = std::time::Duration::from_millis(400);
/// Ceiling on cached external results across all searches.
#[cfg(feature = "indexer")]
const INDEXER_HIT_CAP: usize = 5000;
/// Ceiling on one search/caps response body. A 100-item page of XML is
/// well under 1 MB; 8 MB is runaway-response territory, same idea as
/// [`FETCH_MAX_BYTES`].
const INDEXER_BODY_MAX: u64 = 8 * 1024 * 1024;
/// How long a limit error (daily quota, HTTP 429) parks an indexer.
const INDEXER_LIMIT_BACKOFF: std::time::Duration = std::time::Duration::from_secs(60 * 60);
/// How long a successful `t=caps` answer stays fresh. Capabilities
/// change when a site is upgraded, which is rare.
#[cfg(feature = "indexer")]
const INDEXER_CAPS_TTL: std::time::Duration = std::time::Duration::from_secs(24 * 60 * 60);
/// How long a FAILED caps probe is remembered. Short, because the cause
/// is usually transient (the site was down), but not zero, because the
/// alternative is a caps request in front of every search.
#[cfg(feature = "indexer")]
const INDEXER_CAPS_FAIL_TTL: std::time::Duration = std::time::Duration::from_secs(10 * 60);

/// The one agent every pull-search call goes out through: SSRF-guarded
/// like every other daemon fetch, 15 s ceiling per call so a dead
/// indexer costs one timeout, not a wedged search.
fn shared_indexer_agent() -> ureq::Agent {
    static AGENT: std::sync::OnceLock<ureq::Agent> = std::sync::OnceLock::new();
    AGENT.get_or_init(|| ssrf_safe_agent(4, 15)).clone()
}

/// GET one indexer API URL, capped. Transport-level limit answers (a
/// real HTTP 429/503) map to `Limit` here; protocol errors ship as
/// HTTP 200 XML and are the caller's `parse_error` pass.
/// Blank the `apikey=` value anywhere in a string. A transport error's
/// Display carries the URL it failed on, and that URL carries the user's
/// key - which then rode into a toast, a rendered error row and anything
/// the user pasted into a bug report. M35's contract is that the key
/// never reaches a browser or a log, so it is scrubbed at the one choke
/// point every indexer error passes through.
fn redact_apikey(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(p) = rest.find("apikey=") {
        out.push_str(&rest[..p + "apikey=".len()]);
        out.push_str("***");
        // The value runs to the next query separator or to whatever ends
        // the URL inside a longer sentence.
        let tail = &rest[p + "apikey=".len()..];
        let end = tail
            .find(|c: char| c == '&' || c == '#' || c.is_whitespace())
            .unwrap_or(tail.len());
        rest = &tail[end..];
    }
    out.push_str(rest);
    out
}

/// Cut every URL in a message down to `scheme://host`, dropping userinfo,
/// path and query.
///
/// [`redact_apikey`] guards the SEARCH path, where we built the URL and
/// therefore know the credential is spelled `apikey=`. The GRAB path has
/// no such guarantee: the NZB link comes out of the indexer's own XML,
/// and sites spell their credential `apikey`, `api_key`, `r`, `i`, or
/// put it in the path. Blanking one parameter name there is a guess.
/// The host is the only part of such a URL worth showing a user anyway -
/// it names who failed - so everything after it goes.
pub(crate) fn redact_url_creds(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    // Whichever scheme comes first, when both appear.
    while let Some(p) = match (rest.find("http://"), rest.find("https://")) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    } {
        out.push_str(&rest[..p]);
        let url = &rest[p..];
        let scheme_len = if url.starts_with("https://") { 8 } else { 7 };
        // The authority ends at the first path/query/fragment character,
        // or at whatever ends the URL inside a longer sentence.
        let after = &url[scheme_len..];
        let end = after
            .find(|c: char| c == '/' || c == '?' || c == '#' || c.is_whitespace())
            .unwrap_or(after.len());
        let authority = &after[..end];
        // Userinfo (user:pass@host) is a credential too.
        let host = authority.rsplit('@').next().unwrap_or(authority);
        out.push_str(&url[..scheme_len]);
        out.push_str(host);
        // Anything else attached to the URL is dropped, up to whitespace.
        let tail = &after[end..];
        let stop = tail.find(char::is_whitespace).unwrap_or(tail.len());
        if stop > 0 {
            out.push_str("/...");
        }
        rest = &tail[stop..];
    }
    out.push_str(rest);
    out
}

fn indexer_fetch(url: &str) -> std::result::Result<String, crate::newznab::NewznabError> {
    use crate::newznab::NewznabError;
    use std::io::Read as _;
    let resp = match shared_indexer_agent().get(url).call() {
        Ok(r) => r,
        Err(ureq::Error::Status(code @ (429 | 503), _)) => {
            return Err(NewznabError::Limit(code, format!("HTTP {code}")));
        }
        Err(ureq::Error::Status(code, _)) => {
            return Err(NewznabError::Api(code, format!("HTTP {code}")));
        }
        Err(e) => return Err(NewznabError::Api(0, redact_apikey(&e.to_string()))),
    };
    let mut bytes = Vec::new();
    resp.into_reader()
        .take(INDEXER_BODY_MAX + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| NewznabError::Api(0, redact_apikey(&e.to_string())))?;
    if bytes.len() as u64 > INDEXER_BODY_MAX {
        return Err(NewznabError::Api(0, "response too large".into()));
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

/// One search against one indexer.
fn indexer_search_one(
    cfg: &crate::newznab::IndexerConfig,
    q: &crate::newznab::SearchQuery,
) -> std::result::Result<Vec<crate::newznab::SearchResult>, crate::newznab::NewznabError> {
    let body = indexer_fetch(&crate::newznab::search_url(cfg, q))?;
    if let Some(e) = crate::newznab::parse_error(&body) {
        return Err(e);
    }
    Ok(crate::newznab::parse_results(&body))
}

/// This indexer's caps, from the cache when fresh, else probed. A probe
/// failure caches None (briefly) and the caller then plans a plain
/// free-text search, so caps trouble degrades the search rather than
/// failing it.
///
/// Only called when a query actually carries an id worth planning
/// around: a plain free-text search needs no caps at all, and must not
/// pay for a probe.
#[cfg(feature = "indexer")]
fn indexer_caps_cached(
    d: &Daemon,
    cfg: &crate::newznab::IndexerConfig,
) -> Option<crate::newznab::Caps> {
    let id = cfg.identity();
    if let Some((at, caps)) = d.indexer_rt.lock_ok().caps.get(&id) {
        let ttl = if caps.is_some() {
            INDEXER_CAPS_TTL
        } else {
            INDEXER_CAPS_FAIL_TTL
        };
        if at.elapsed() < ttl {
            return caps.clone();
        }
    }
    let got = indexer_caps_one(cfg).ok();
    d.indexer_rt
        .lock()
        .unwrap()
        .caps
        .insert(id, (Instant::now(), got.clone()));
    got
}

/// One `t=caps` against one indexer, with a sanity check that the far
/// end is a Newznab API at all (a parked domain answers 200 with HTML,
/// which parses to an all-default Caps).
fn indexer_caps_one(
    cfg: &crate::newznab::IndexerConfig,
) -> std::result::Result<crate::newznab::Caps, crate::newznab::NewznabError> {
    let body = indexer_fetch(&crate::newznab::caps_url(cfg))?;
    if let Some(e) = crate::newznab::parse_error(&body) {
        return Err(e);
    }
    let caps = crate::newznab::parse_caps(&body);
    if !caps.search && caps.server.is_empty() && caps.categories.is_empty() {
        return Err(crate::newznab::NewznabError::Api(
            0,
            "not a newznab API (no caps)".into(),
        ));
    }
    Ok(caps)
}

/// Persist the day's hit/grab counters; best-effort, tiny file.
/// Persist the day's indexer hit/grab counters.
///
/// The snapshot and the write are ONE critical section, and the write is
/// atomic. Both matter, and neither used to hold: the clone happened
/// under the runtime lock, the lock was then released, and a bare
/// `fs::write` followed. Two concurrent grabs could therefore snapshot 1
/// and 2 and land in that order or the other, so the file could end up
/// recording 1 after 2 was already counted - and a same-day restart
/// reloads whatever is on disk, handing back budget the user's paid
/// account had already spent. The bare write could also leave a
/// half-truncated file that reloads as no counters at all.
fn save_indexer_usage(d: &Daemon) {
    // Separate from indexer_rt: this is held across file I/O, and
    // indexer_rt is on the search path.
    static IO: std::sync::Mutex<()> = std::sync::Mutex::new(());
    let _g = IO.lock_ok();
    let u = d.indexer_rt.lock_ok().usage.clone();
    if let Ok(b) = serde_json::to_vec(&u)
        && let Err(e) = crate::persist::write_atomic(&d.spool.join("indexer-usage.json"), &b)
    {
        warn!(target: "indexer", "could not persist usage counters: {e}");
    }
}

/// Turn one parsed NZBLNK into a queued job, or say why not.
///
/// The ladder is our own index first (free, offline, and it can emit the
/// NZB straight from the segment ids the scan stored) and the user's
/// configured indexers second (one API hit each, under the same daily
/// budgets and limit backoff the pull search obeys).
///
/// A local hit that is INCOMPLETE does not short-circuit the ladder: a
/// synthesized NZB missing parts downloads and then fails repair, so the
/// indexers get their turn first and the partial release is only used
/// when nothing else answered - with a note saying so, because "queued,
/// and we already know parts are missing" is not the same promise as
/// "queued".
fn resolve_nzblnk(
    d: &Daemon,
    l: &nzbkit::nzblnk::NzbLnk,
    cat: &str,
    prio: i32,
    password: Option<&str>,
    dupe_ok: bool,
) -> serde_json::Value {
    let mut notes: Vec<serde_json::Value> = Vec::new();

    // ---- The rate gate. ---------------------------------------------
    // Two thresholds off one sliding window, because the two things a
    // loop can spend are not equally scarce. Local resolution costs CPU
    // (rung 3 of find_by_header is an unindexed scan); asking the
    // indexers costs the user's metered account. So the cheap half stays
    // available far longer than the expensive one, and passing the
    // second threshold DEGRADES to local-only rather than failing - a
    // link our own index can answer is answered.
    let recent = {
        let mut q = d.nzblnk_recent.lock_ok();
        let now = Instant::now();
        while q
            .front()
            .is_some_and(|t| now.duration_since(*t) > NZBLNK_WINDOW)
        {
            q.pop_front();
        }
        if q.len() >= NZBLNK_MAX {
            return json!({"status": false, "reason": "toofast",
                "error": "too many links at once - wait a moment and try again"});
        }
        q.push_back(now);
        q.len()
    };
    let may_ask_indexers = recent <= NZBLNK_EXTERNAL_MAX;

    // ---- Rung 1: our own header index. ------------------------------
    // Ranking, strongest first: complete beats partial, a release in a
    // group the link named beats one somewhere else, then size. `>` and
    // not `>=`, so ties keep find_by_header's own ordering (exact stem
    // ahead of a filename match).
    #[cfg(feature = "indexer")]
    let rank = |r: &nzbkit::index::Release| {
        (
            r.complete,
            l.groups.is_empty() || l.groups.iter().any(|g| g.eq_ignore_ascii_case(&r.grp)),
            r.total_bytes,
        )
    };
    // with_index_read on both index calls: this is an interactive
    // handler, and rung 3 of find_by_header is a table scan. On the
    // read-write connection a catch-up ingest or maintenance pass would
    // park the paste for as long as it holds the mutex (measured at 62s
    // for wall2 before the read-only connection existed).
    #[cfg(feature = "indexer")]
    let local = d.with_index_read(|ix| {
        let mut best: Option<nzbkit::index::Release> = None;
        for r in ix.find_by_header(&l.header, 8).ok()? {
            if best.as_ref().is_none_or(|b| rank(&r) > rank(b)) {
                best = Some(r);
            }
        }
        best
    });
    #[cfg(feature = "indexer")]
    let queue_local = |r: &nzbkit::index::Release,
                       partial: bool,
                       notes: &Vec<serde_json::Value>| {
        let xml = match d.with_index_read(|ix| ix.make_nzb(r.id).ok()) {
            Some(x) => x,
            None => {
                return json!({"status": false, "error": "the index could not rebuild that post"});
            }
        };
        let name = if l.title.is_empty() {
            r.stem.clone()
        } else {
            l.title.clone()
        };
        match d.enqueue(
            xml.as_bytes(),
            &name,
            cat,
            prio,
            password,
            "nzblnk",
            dupe_ok,
        ) {
            Ok(nzo) => {
                // Same protection a wall grab gets: the row this job came
                // from must survive the index size cap.
                d.touch_opened_release(r.id);
                json!({"status": true, "nzo_ids": [nzo], "name": name, "via": "index",
                       "partial": partial, "notes": notes})
            }
            Err(e) => json!({"status": false, "error": e.to_string()}),
        }
    };
    #[cfg(feature = "indexer")]
    if let Some(r) = local.as_ref().filter(|r| r.complete) {
        return queue_local(r, false, &notes);
    }
    #[cfg(feature = "indexer")]
    if local.is_some() {
        notes.push(json!({"index": "found the post, but parts are still missing"}));
    }

    // ---- Rung 2: the user's indexers, over the M35 client. -----------
    // A header is free text, so this is a plain `t=search` - no caps
    // probe (an id-less query never needs one) and no category filter,
    // because an obfuscated release name tells nobody what it is.
    let list: Vec<crate::newznab::IndexerConfig> = if may_ask_indexers {
        d.indexers
            .lock()
            .unwrap()
            .iter()
            .filter(|i| i.enabled)
            .cloned()
            .collect()
    } else {
        notes.push(json!({"indexers":
            "skipped: too many link lookups just now, so only the local index was searched"}));
        Vec::new()
    };
    let mut runnable = Vec::new();
    {
        let mut rt = d.indexer_rt.lock_ok();
        rt.usage.roll(unix_now());
        let now = Instant::now();
        for i in list {
            if rt.penalty_until.get(&i.name).is_some_and(|t| *t > now) {
                notes.push(json!({"indexer": i.name,
                    "skipped": "backing off after a limit error"}));
            } else if !rt.usage.hit_allowed(&i) {
                notes.push(json!({"indexer": i.name, "skipped": "daily API budget reached"}));
            } else {
                rt.usage.count_hit(&i.name);
                runnable.push(i);
            }
        }
    }
    if !runnable.is_empty() {
        save_indexer_usage(d);
    }
    let query = crate::newznab::SearchQuery {
        q: l.header.clone(),
        limit: 100,
        ..Default::default()
    };
    let outcomes: Vec<_> = std::thread::scope(|s| {
        let handles: Vec<_> = runnable
            .into_iter()
            .map(|i| {
                let query = query.clone();
                s.spawn(move || {
                    let r = indexer_search_one(&i, &query);
                    (i, r)
                })
            })
            .collect();
        handles.into_iter().filter_map(|h| h.join().ok()).collect()
    });
    // A header identifies ONE posting, so this picks a single winner
    // rather than building a result list: a title that actually contains
    // the header beats one that merely matched some token of it, then
    // indexer priority, then the newest upload.
    let norm = |s: &str| {
        s.to_ascii_lowercase()
            .replace(['.', '_', '-'], " ")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
    };
    let want = norm(&l.header);
    let mut best: Option<(u8, i32, i64, crate::newznab::SearchResult, String)> = None;
    {
        let mut rt = d.indexer_rt.lock_ok();
        let now = Instant::now();
        for (cfg, outcome) in outcomes {
            match outcome {
                Ok(items) => {
                    for item in items {
                        let k = (
                            u8::from(!norm(&item.title).contains(&want)),
                            cfg.priority,
                            -item.posted,
                        );
                        if best.as_ref().is_none_or(|b| k < (b.0, b.1, b.2)) {
                            best = Some((k.0, k.1, k.2, item, cfg.name.clone()));
                        }
                    }
                }
                Err(e) => {
                    if matches!(e, crate::newznab::NewznabError::Limit(..)) {
                        rt.penalty_until
                            .insert(cfg.name.clone(), now + INDEXER_LIMIT_BACKOFF);
                    }
                    notes.push(json!({"indexer": cfg.name, "error": e.to_string()}));
                }
            }
        }
    }
    if let Some((_, _, _, item, indexer)) = best {
        let allowed = {
            let mut rt = d.indexer_rt.lock_ok();
            rt.usage.roll(unix_now());
            d.indexers
                .lock()
                .unwrap()
                .iter()
                .find(|i| i.name == indexer)
                .is_none_or(|c| rt.usage.grab_allowed(c))
        };
        if !allowed {
            notes.push(json!({"indexer": indexer, "skipped": "daily grab budget reached"}));
        } else {
            let name = if l.title.is_empty() {
                item.title.clone()
            } else {
                l.title.clone()
            };
            match fetch_url(&item.link)
                .map_err(|e| e.to_string())
                .and_then(|f| {
                    d.enqueue_fetched(&f, &name, cat, prio, password, 0, "nzblnk", dupe_ok)
                        .map_err(|e| e.to_string())
                }) {
                Ok(nzo) => {
                    d.indexer_rt.lock_ok().usage.count_grab(&indexer);
                    save_indexer_usage(d);
                    return json!({"status": true, "nzo_ids": [nzo], "name": name,
                                  "via": indexer, "partial": false, "notes": notes});
                }
                // The NZB link itself failed. Not fatal to the ladder -
                // a partial local copy may still be better than nothing.
                //
                // redact_url_creds: fetch_url names the URL it failed on,
                // and that URL is the enclosure link out of the indexer's
                // XML, which carries the user's account credential. This
                // string goes straight into the dashboard's notes.
                Err(e) => notes.push(json!({"indexer": indexer, "error": redact_url_creds(&e)})),
            }
        }
    }

    // ---- Last resort: the partial local hit, honestly labelled. ------
    #[cfg(feature = "indexer")]
    if let Some(r) = local.as_ref() {
        return queue_local(r, true, &notes);
    }
    json!({"status": false, "reason": "notfound", "notes": notes,
           "error": "nothing found for that link - the post may be too new to be indexed, \
                     or too old to still be on your server"})
}

/// Process-wide in-flight request-body budget (28 Jul sweep finding):
/// 8 HTTP workers x the 256 MB per-request cap could hold ~2 GB of
/// half-read uploads at once - enough to OOM a memory-clamped container
/// - and `addfile` accepts the add-only tier, so the exposure does not
/// need the admin key. Every `read_body_capped_hold` reserves here as its
/// body grows and releases when the read completes; a reader that would
/// push the total past the cap WAITS for another body to finish -
/// except a sole reader, which may take everything alone, so one
/// huge-NZB upload still works on a box whose whole budget is smaller
/// than the per-request cap. A deliberately slow uploader therefore
/// stalls OTHER large uploads rather than eating RAM - it already
/// pinned a worker thread either way, and blocked-and-small beats
/// admitted-and-huge. Sized from the process memory budget at first use
/// (serve() publishes that before the listener exists).
struct BodyBudget {
    cap: u64,
    /// How long a blocked holder waits per round. A field rather than the
    /// constant so the tests can drive many rounds in milliseconds - the
    /// overshoot bound below is a statement about what happens over MANY
    /// rounds, and a test that takes 5 s each to make the point would not
    /// be written.
    wait: std::time::Duration,
    cur: std::sync::Mutex<Reserved>,
    cv: std::sync::Condvar,
}

/// In-flight reserved bytes, plus the ticket of every body currently
/// holding some. Tickets are handed out in arrival order and the LOWEST
/// live one is the body allowed to finish (see [`BodyBudget::grow`]).
#[derive(Default)]
struct Reserved {
    bytes: u64,
    next_ticket: u64,
    live: std::collections::BTreeSet<u64>,
}

/// One body's claim on the pool: the bytes it holds and its place in the
/// queue. Carried by the reader for the length of its read.
#[derive(Default)]
struct Hold {
    bytes: u64,
    ticket: Option<u64>,
}

/// How long a blocked holder waits before re-checking. Purely a
/// belt-and-braces re-read of the predicate now - forward progress comes
/// from the oldest-holder rule, not from this expiring - so it no longer
/// has to be tuned against anything.
const BODY_BUDGET_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

static BODY_BUDGET: std::sync::OnceLock<BodyBudget> = std::sync::OnceLock::new();

fn body_budget() -> &'static BodyBudget {
    BODY_BUDGET.get_or_init(|| {
        BodyBudget::new((nzbkit::mem::process_budget().total / 4).clamp(64 << 20, 512 << 20))
    })
}

impl BodyBudget {
    fn new(cap: u64) -> BodyBudget {
        BodyBudget::with_wait(cap, BODY_BUDGET_WAIT)
    }

    fn with_wait(cap: u64, wait: std::time::Duration) -> BodyBudget {
        BodyBudget {
            cap,
            wait,
            cur: std::sync::Mutex::new(Reserved::default()),
            cv: std::sync::Condvar::new(),
        }
    }

    /// Reserve `more` bytes for `h`. Blocks while OTHER bodies have the
    /// pool exhausted.
    ///
    /// A waiter that already holds bytes cannot be made to wait forever:
    /// its own reservation is part of the total everyone else is queued
    /// behind, and it only releases when its read loop ENDS - so two
    /// bodies that together reach the cap would each block on a condvar
    /// only the other could signal, wedging every HTTP worker behind
    /// them. (`read_body_capped_hold` reserves before each read, so even a
    /// reader that has hit its own `take` limit - one line from breaking
    /// out and releasing - parks here first.)
    ///
    /// The way out is to name ONE body that may always proceed: the
    /// oldest live holder. It runs to its own per-request `take` cap,
    /// releases, and the next-oldest inherits the right - so the pool
    /// always drains, and the total is bounded by `cap` plus that single
    /// over-runner's per-request cap.
    ///
    /// This replaces a timeout-based escape that let ANY holder through
    /// after a wait in which nothing was released. That looked equally
    /// deadlock-free and was not bounded: the grant repeated every round,
    /// for every holder, so a set of stalled uploads ratcheted the pool
    /// upward by a chunk each per wait - 8 MiB per 5 s with the HTTP
    /// worker count, walking back to the multi-gigabyte figure this
    /// budget exists to prevent. It needed no credentials beyond the
    /// add-only tier `addfile` accepts. Found by Codex on the 31 Jul
    /// sweep; `stalled_holders_cannot_ratchet_the_pool_upward` is the
    /// regression test, and it reached 7x the cap in 600 ms against the
    /// old rule.
    fn grow(&self, h: &mut Hold, more: u64) {
        let mut cur = self.cur.lock_ok();
        // Join the queue on first contact, so arrival order is the order
        // bodies started reading rather than the order they blocked.
        let ticket = *h.ticket.get_or_insert_with(|| {
            let t = cur.next_ticket;
            cur.next_ticket += 1;
            cur.live.insert(t);
            t
        });
        loop {
            let others = cur.bytes - h.bytes;
            // Sole reader, or it fits: the ordinary cases.
            if others == 0 || cur.bytes + more <= self.cap {
                break;
            }
            // The designated finisher. Only ever one body, and only while
            // it is the oldest thing in the pool.
            if cur.live.first() == Some(&ticket) {
                break;
            }
            cur = self.cv.wait_timeout(cur, self.wait).unwrap().0;
        }
        cur.bytes += more;
        h.bytes += more;
    }

    fn release(&self, h: Hold) {
        let Some(ticket) = h.ticket else { return };
        {
            let mut cur = self.cur.lock_ok();
            cur.bytes -= h.bytes;
            cur.live.remove(&ticket);
        }
        // Always: dropping out of `live` can promote a new finisher even
        // when this body held nothing.
        self.cv.notify_all();
    }
}

/// RAII form of a body's budget claim: the reservation lives exactly as
/// long as this guard. The read used to release its claim at the end of
/// the READ, before the body was parsed - so the parse phase (and a body
/// retained for later arms, like the pre-auth form buffer) sat entirely
/// outside the budget, and concurrent workers could each hold a full
/// 256 MiB body "for free" while parsing (Codex H8). Callers that keep
/// the bytes keep the guard beside them.
///
/// Since Codex sweep 2's H1 the /api pre-read covers EVERY post, so this
/// window now spans dispatch for bodies that used to be read (and
/// released) inside a handler - an untyped or `text/plain` POST among
/// them. The extra exposure is bounded by [`api_body_cap`], which gives
/// those [`API_BODY_DEFAULT`] rather than the ceiling, so it is ~1 MiB
/// per worker; the modes that can hold the ceiling open through dispatch
/// (addfile, wall_art) already did so through the old form path.
struct BodyHold(Option<Hold>);
impl Drop for BodyHold {
    fn drop(&mut self) {
        if let Some(h) = self.0.take() {
            body_budget().release(h);
        }
    }
}

/// Largest body a POST to `/api` may carry, when nothing more specific
/// is known: the ceiling every endpoint that takes a whole NZB needs.
const API_BODY_MAX: u64 = 256 << 20;

/// The cap for an /api POST that names no size-hungry mode. Generous
/// enough for any JSON settings blob (the watchlist, feeds, notify
/// targets and *arr instances all live well inside it) and far below
/// the ceiling.
const API_BODY_DEFAULT: u64 = 1 << 20;

/// How large a body each `/api` mode is allowed to send.
///
/// The gateway reads every POST body before authorizing (see the
/// pre-read at the front controller), so this is where the endpoint's
/// real limit has to be applied - the handlers' own capped-read
/// fallbacks are unreachable now, and a flat ceiling would let a
/// nominal 1 MiB endpoint buffer and parse 256 MiB (Codex sweep 2,
/// 3 Aug M1).
///
/// Only the modes that legitimately carry bulk are listed; everything
/// else takes [`API_BODY_DEFAULT`]. Erring large costs memory on a
/// request that was going to be refused anyway; erring small breaks a
/// real upload, so anything that can carry an NZB, an archive of them,
/// or an image is at the ceiling.
/// Each figure is the cap the handler itself already declared, so this
/// changes no endpoint's real limit - it moves the decision to the only
/// place that still runs.
fn api_body_cap(mode: &str) -> u64 {
    match mode {
        // A whole NZB, or a multipart batch of them.
        "addfile" => API_BODY_MAX,
        // A settings backup archive.
        "backup_import" => 8 << 20,
        // Poster/fanart upload.
        "wall_art" => 10 << 20,
        _ => API_BODY_DEFAULT,
    }
}

/// Read a request body with a hard size cap, returning the budget claim
/// alongside the bytes so the caller can keep the reservation alive
/// through parsing.
///
/// The cap exists because no single POST may balloon the daemon's RSS -
/// tiny_http hands us the raw reader and nothing upstream bounds it. A
/// body that hits the cap comes back truncated and fails its parse,
/// which surfaces as the normal bad-request error for that endpoint.
fn read_body_capped_hold(r: impl std::io::Read, cap: u64) -> (Vec<u8>, BodyHold) {
    use std::io::Read as _;
    let budget = body_budget();
    let mut hold = Hold::default();
    let mut raw = Vec::new();
    let mut r = r.take(cap);
    // Chunked so the reservation tracks the body as it arrives instead
    // of front-loading the worst case: a 30 KB NZB reserves one chunk,
    // not 256 MB. Accounting is by bytes read (Vec spare capacity is
    // bounded by one doubling and not worth modelling).
    const CHUNK: u64 = 1 << 20;
    loop {
        budget.grow(&mut hold, CHUNK);
        // Error handling matches the pre-budget behavior: a broken read
        // returns whatever arrived (the parsers judge it).
        match (&mut r).take(CHUNK).read_to_end(&mut raw) {
            Ok(n) if n as u64 == CHUNK => continue,
            _ => break,
        }
    }
    // `r.take(cap)` is what bounds the one body the pool may let past its
    // cap: the designated finisher can over-run by its own per-request
    // limit and no more.
    (raw, BodyHold(Some(hold)))
}

/// Read a candidate SABnzbd/NZBGet config for import. The path is
/// caller-supplied, so refuse non-regular files (/dev/zero, FIFOs) and
/// anything implausibly large before slurping it into RAM.
fn read_import_config(path: &std::path::Path) -> std::io::Result<String> {
    const CAP: u64 = 4 * 1024 * 1024;
    let meta = std::fs::metadata(path)?;
    if !meta.is_file() || meta.len() > CAP {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "not a config file",
        ));
    }
    std::fs::read_to_string(path)
}

/// Open a path with the OS default handler ON THE DAEMON'S MACHINE (the
/// dashboard's Play / Show-in-folder actions - the normal local setup).
fn os_open(path: &std::path::Path) -> bool {
    #[cfg(target_os = "macos")]
    let mut cmd = std::process::Command::new("open");
    #[cfg(all(unix, not(target_os = "macos")))]
    let mut cmd = std::process::Command::new("xdg-open");
    // Windows: explorer, NOT `cmd /C start` - cmd re-parses its command
    // line, so metacharacters (&, ^, %) in a path would execute. These
    // paths derive from release names, which arrive in NZBs.
    #[cfg(windows)]
    let mut cmd = std::process::Command::new("explorer");
    cmd.arg(path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .is_ok()
}

/// Can the daemon actually write into this directory? Shown next to the
/// download-folder picker so the user learns a chosen location is
/// read-only BEFORE a download fails there.
fn path_writable(p: &std::path::Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        match std::ffi::CString::new(p.as_os_str().as_bytes()) {
            Ok(c) => (unsafe { libc::access(c.as_ptr(), libc::W_OK) }) == 0,
            Err(_) => false,
        }
    }
    #[cfg(not(unix))]
    {
        p.metadata()
            .map(|m| !m.permissions().readonly())
            .unwrap_or(false)
    }
}

/// A move destination has to be an absolute path.
///
/// `create_dir_all` is perfectly happy to make a relative one, and it
/// lands under the daemon's WORKING DIRECTORY: `/var/lib/nzbfast` under
/// the systemd unit, the container's workdir under Docker, and wherever
/// the launcher happened to be otherwise. Typing `movies/anime` into the
/// settings field therefore created a real directory, passed
/// `path_writable`, passed the `same_dir` check against the download
/// folder, and was stored - and finished downloads were then moved into
/// a folder the user never chose and would not think to look in.
///
/// Refusing is deliberately preferred over resolving it against
/// something ourselves. Every candidate base is a guess (the download
/// root? the config's directory? the home directory?), and a
/// destination the user cannot predict is worse than an error that says
/// what was expected.
///
/// This applies to the MOVE destinations only. `out_dir` and `watch` are
/// left alone on purpose: both are passed relative by the CLI's own
/// defaults (`--out downloads`, `--watch watch`), so cwd-relative is
/// their documented behaviour rather than a trap.
fn require_absolute_dest(p: &std::path::Path) -> Result<(), String> {
    if p.is_absolute() {
        return Ok(());
    }
    Err(format!(
        "{} is a relative path - give the full path to the folder, \
         starting from the top of the drive",
        p.display()
    ))
}

/// M33 v2: parse the per-category destination list ("tv=/NAS/TV,
/// movies=/NAS/Movies"; comma or semicolon separated; empty = none).
/// Category names get the same sanitizing the enqueue path applies, so
/// a rule here always matches the folder the job actually used.
fn parse_cat_dests(v: &str) -> Result<Vec<(String, PathBuf)>, String> {
    let mut out: Vec<(String, PathBuf)> = Vec::new();
    for item in v.split([',', ';']) {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        let Some((cat, path)) = item.split_once('=') else {
            return Err(format!("{item:?} is not category=path"));
        };
        let cat = nzbkit::disk::sanitize_filename(cat.trim());
        let path = path.trim();
        if cat.is_empty() || path.is_empty() {
            return Err(format!("{item:?} is not category=path"));
        }
        if out.iter().any(|(c, _)| *c == cat) {
            return Err(format!("category {cat:?} listed twice"));
        }
        out.push((cat, PathBuf::from(path)));
    }
    Ok(out)
}

/// Inverse of [`parse_cat_dests`] - the canonical echo/persist form.
fn fmt_cat_dests(list: &[(String, PathBuf)]) -> String {
    list.iter()
        .map(|(c, p)| format!("{c}={}", p.display()))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Quick-access roots for the directory browser: home, the current
/// download folder, and every mounted volume/drive - the whole point being
/// to reach a *second* drive without knowing its path.
fn fs_roots(cur_download: &std::path::Path) -> Value {
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/"));
    // Mobile targets have no volume enumeration arm below: the app
    // sandbox is the whole visible filesystem, so `roots` never grows.
    #[cfg_attr(any(target_os = "ios", target_os = "android"), allow(unused_mut))]
    let mut roots = vec![
        json!({"name": "Home", "path": home.to_string_lossy()}),
        json!({"name": "Current downloads", "path": cur_download.to_string_lossy()}),
    ];
    #[cfg(target_os = "macos")]
    {
        roots.push(json!({"name": "Macintosh HD", "path": "/"}));
        // Every mounted volume, external drives included.
        if let Ok(rd) = std::fs::read_dir("/Volumes") {
            for e in rd.flatten() {
                let name = e.file_name().to_string_lossy().to_string();
                if !name.starts_with('.') {
                    roots.push(
                        json!({"name": name, "path": e.path().to_string_lossy(), "drive": true}),
                    );
                }
            }
        }
    }
    #[cfg(target_os = "linux")]
    {
        roots.push(json!({"name": "Filesystem", "path": "/"}));
        // /media/<user>/<label> and /mnt/<label> are the usual mount points.
        for base in ["/media", "/mnt"] {
            if let Ok(rd) = std::fs::read_dir(base) {
                for e in rd.flatten() {
                    let p = e.path();
                    if !p.is_dir() {
                        continue;
                    }
                    // /media nests one level deeper (per-user).
                    if base == "/media" {
                        if let Ok(inner) = std::fs::read_dir(&p) {
                            for i in inner.flatten() {
                                if i.path().is_dir() {
                                    roots.push(json!({"name": i.file_name().to_string_lossy(), "path": i.path().to_string_lossy(), "drive": true}));
                                }
                            }
                        }
                    } else {
                        roots.push(json!({"name": e.file_name().to_string_lossy(), "path": p.to_string_lossy(), "drive": true}));
                    }
                }
            }
        }
    }
    #[cfg(windows)]
    {
        for letter in b'A'..=b'Z' {
            let drive = format!("{}:\\", letter as char);
            if std::path::Path::new(&drive).exists() {
                roots.push(json!({"name": drive.clone(), "path": drive, "drive": true}));
            }
        }
    }
    Value::Array(roots)
}

/// Largest media file under `dir` (one level of subdirs too - extraction
/// can nest a release folder).
fn largest_media_file(dir: &std::path::Path) -> Option<PathBuf> {
    const EXTS: [&str; 6] = [".mkv", ".mp4", ".avi", ".m4v", ".ts", ".wmv"];
    let mut best: Option<(u64, PathBuf)> = None;
    let mut consider = |p: PathBuf| {
        let l = p
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_ascii_lowercase();
        if EXTS.iter().any(|x| l.ends_with(x))
            && let Ok(md) = p.metadata()
            && best.as_ref().is_none_or(|(sz, _)| md.len() > *sz)
        {
            best = Some((md.len(), p));
        }
    };
    for entry in std::fs::read_dir(dir).ok()?.flatten() {
        let p = entry.path();
        if p.is_dir() {
            for sub in std::fs::read_dir(&p).ok().into_iter().flatten().flatten() {
                consider(sub.path());
            }
        } else {
            consider(p);
        }
    }
    best.map(|(_, p)| p)
}

/// Change the category of a job that already finished: relabel the
/// history entry and, when the payload sits in a folder of its own, move
/// that folder to where the new category would have put it - the
/// per-category override first, then the global completed destination,
/// then the download root, mirroring `relocate_completed`'s ladder.
///
/// A Failed job moves too - retry reuses `out_dir` when it is free, so
/// the article journal travels with the partial payload and the rerun
/// both resumes AND completes into the right place - but only under the
/// download root: the completed-move destinations are for finished
/// payloads, not in-progress state. One case relabels WITHOUT moving,
/// said out loud in the reply: a TV-filed job, whose files are
/// interleaved with other jobs' in a shared Show/Season folder, so
/// moving `out_dir` would drag innocent siblings along. The move
/// happens with no locks held - `move_tree` on a NAS is seconds, and
/// the queue must not stall behind it.
fn history_change_cat(d: &Daemon, id: &str, cat: &str) -> Value {
    let target = d.history.lock_ok().iter().find_map(|j| {
        let g = j.lock_ok();
        (g.nzo_id == id).then(|| {
            (
                j.clone(),
                g.state,
                g.category.clone(),
                g.out_dir.clone(),
                g.filed,
                g.finalizing,
            )
        })
    });
    let Some((job, state, current, out_dir, filed, finalizing)) = target else {
        return json!({"status": false,
            "error": "no job with that nzo_id (a job still downloading keeps its category until it finishes)"});
    };
    if finalizing {
        return json!({"status": false,
            "error": "post-processing is still running for this job - try again when it settles"});
    }
    if current == cat {
        return json!({"status": true});
    }
    // Claim the job for the duration. `finalizing` above is a snapshot
    // and stops being true the moment it is read; this is a live marker
    // retry and delete both consult, so nothing can pull the record out
    // from under a move that has already started. Dropped on EVERY exit
    // below, including the early error returns.
    struct MoveClaim<'a>(&'a Daemon, String);
    impl Drop for MoveClaim<'_> {
        fn drop(&mut self) {
            self.0.moving.lock_ok().remove(&self.1);
        }
    }
    if !d.moving.lock_ok().insert(id.to_string()) {
        return json!({"status": false,
            "error": "this job's files are already being moved - try again when it settles"});
    }
    let _claim = MoveClaim(d, id.to_string());
    // The snapshot above happened BEFORE the claim went up, so re-verify
    // both of its gates now that it has: a delete that slipped into the
    // window has already removed the record (deleting files this move
    // would race), and a password unlock that slipped in has raised
    // `finalizing` (it checks `moving` only after raising, so exactly
    // one of the two proceeds). Checked before any filesystem work.
    if !d.history.lock_ok().iter().any(|j| Arc::ptr_eq(j, &job)) {
        return json!({"status": false,
            "error": "no job with that nzo_id (it was removed just now)"});
    }
    if job.lock_ok().finalizing {
        return json!({"status": false,
            "error": "post-processing is still running for this job - try again when it settles"});
    }
    let mut split_error: Option<String> = None;
    // Nothing on disk to move: relabel and stop. Otherwise move_tree fails
    // (read_dir on a missing source is ENOENT) and the category could never
    // be corrected at all - for a job whose pre-flight verdict failed it
    // before out_dir was ever created, a folder the user tidied by hand, or
    // a move_completed share that is not mounted right now. Worse, every
    // attempt left a stray empty category directory behind, because
    // move_tree's first act is create_dir_all(dst.parent()). Relabelling is
    // the one part that needs no filesystem work, so do just that.
    let source_missing = !filed && !out_dir.is_dir();
    let moved = if !filed && !source_missing {
        let base = if state == JobState::Completed {
            let cat_root = d
                .move_completed_cats
                .read()
                .unwrap()
                .iter()
                .find(|(c, _)| *c == cat)
                .map(|(_, p)| p.clone());
            match (cat_root, d.move_completed.read_ok().clone()) {
                // The override IS that category's root - no repeated component.
                (Some(root), _) => root,
                (None, Some(root)) if !cat.is_empty() => root.join(cat),
                (None, Some(root)) => root,
                (None, None) if !cat.is_empty() => d.out_dir().join(cat),
                (None, None) => d.out_dir(),
            }
        } else if cat.is_empty() {
            d.out_dir()
        } else {
            d.out_dir().join(cat)
        };
        // Pick a free name rather than merging blind. The queued-job arm
        // goes through refile_out_dir with dir_claim, and retry does the
        // same, for the reason its comment gives: re-using a claimed
        // directory would put two live jobs in it. Without this, re-adding
        // the same NZB under another category (which claims the folder while
        // held as a duplicate) and then recategorising the finished one
        // merges a whole payload into the claimed directory - and both
        // history records then name it, so plan_history_delete marks each as
        // the other's claimant and "Remove and delete files" silently
        // refuses for both, leaving a folder undeletable from the UI.
        let stem = out_dir
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        // Under the same lock the enqueue and retry paths pick THEIR
        // directories with, and reserved before the lock goes: a free
        // name is only free until somebody takes it, and no record will
        // name this one until the move below finishes.
        struct Reservation<'a>(&'a Daemon, PathBuf);
        impl Drop for Reservation<'_> {
            fn drop(&mut self) {
                self.0.reserved.lock_ok().remove(&self.1);
            }
        }
        let dest = {
            let _publish = d.add_lock.lock_ok();
            let dest = choose_out_dir(&base.join(&stem), &stem, &|p| d.dir_claim(p)).0;
            d.reserved.lock_ok().insert(dest.clone());
            dest
        };
        let _reservation = Reservation(d, dest.clone());
        // Same aliasing guard as relocate_completed: a dest that IS the
        // current folder through case or symlinks must not self-merge.
        let same = dest == out_dir
            || matches!((dest.canonicalize(), out_dir.canonicalize()),
                        (Ok(a), Ok(b)) if a == b);
        if same {
            None
        } else {
            // Count first: move_tree's same-filesystem merge moves entry by
            // entry and propagates the first error, so a failure can leave
            // the payload split across both folders. Without this the whole
            // failure is indistinguishable from "nothing happened".
            let before = file_count(&out_dir);
            match crate::smart::move_tree(&out_dir, &dest) {
                Ok(()) => {
                    info!(target: "move", "recategorized → {}", dest.display());
                    Some(dest)
                }
                Err(e) => {
                    // Same split detection relocate_completed does. A
                    // partial move is the ordinary Windows case: the
                    // whole-directory rename is refused while a child is
                    // open, the merge path runs, and it stops at the open
                    // file having already moved the siblings.
                    let moved_some = file_count(&out_dir) < before;
                    error!(
                        target: "move",
                        "{} → {}: {e}\n[move] {}",
                        out_dir.display(),
                        dest.display(),
                        if moved_some {
                            format!(
                                "the payload is now SPLIT - some files moved before this \
                                 failed. Check both {} and {} before deleting either.",
                                out_dir.display(),
                                dest.display()
                            )
                        } else {
                            format!(
                                "nothing moved - the download is still at {}",
                                out_dir.display()
                            )
                        }
                    );
                    if moved_some {
                        // The files that moved exist nowhere else, so the
                        // record has to follow the bytes even though the
                        // call failed - leaving it on the half-emptied
                        // source points the dashboard, a later delete and
                        // the *arr import at a folder they have left.
                        // Reported as a failure below, after the state is
                        // updated, so the user is told rather than shown a
                        // success over a split payload.
                        split_error = Some(format!(
                            "the files are now SPLIT between {} and {} because the move \
                             failed part way ({e}). Check both before deleting either.",
                            out_dir.display(),
                            dest.display()
                        ));
                        Some(dest)
                    } else {
                        // Nothing moved: leave the category alone too. A
                        // label saying "movies" over files still sitting in
                        // tv/ is a lie that outlives the error message.
                        return json!({"status": false,
                            "error": format!("could not move the files: {e}")});
                    }
                }
            }
        }
    } else {
        None
    };
    // Commit under the history lock, against a record that is still the
    // one we snapshotted. The `moving` marker keeps retry and delete
    // off this job, but the check is cheap and it is the last chance to
    // notice that the record went somewhere else - a job the user
    // deleted just before the marker went up, say. Writing `out_dir`
    // into a detached Arc would point nothing at the bytes we just
    // moved, and `save_queue` would not persist it either.
    {
        let h = d.history.lock_ok();
        if !h.iter().any(|j| Arc::ptr_eq(j, &job)) {
            let where_ = moved.clone().unwrap_or_else(|| out_dir.clone());
            return json!({"status": false,
                "error": format!(
                    "the history entry was removed while its files were being moved - \
                     they are now at {}",
                    where_.display()),
                "path": where_.to_string_lossy()});
        }
        let mut g = job.lock_ok();
        g.category = cat.to_string();
        if let Some(p) = &moved {
            g.out_dir = p.clone();
        }
        // UX §18: a recategorize that stopped part way leaves the
        // payload in two directories, and `out_dir` has just followed
        // the bytes that made it. The error below tells whoever pressed
        // the button, once - it was the ONLY witness, and it does not
        // survive a page reload. Record the source the way the
        // completion path records it, so the row keeps warning and a
        // later delete has something to reach the other half by.
        //
        // SET, never cleared: a job that was already split by its
        // completion move still is - this relocation only touched
        // `out_dir`, and the source half it knows about is untouched.
        if split_error.is_some() {
            g.move_split = out_dir.to_string_lossy().to_string();
        }
    }
    d.register_cat(cat);
    d.save_queue();
    // Reported only now: the record above had to be updated first so it
    // points at where the bytes actually are, but the caller must still be
    // told this failed rather than shown a success over a split payload.
    if let Some(msg) = split_error {
        return json!({"status": false,
            "error": msg,
            "path": moved.map(|p| p.to_string_lossy().to_string())});
    }
    let note = if filed {
        "relabeled only: the files were filed into a shared TV folder and stayed there"
    } else {
        ""
    };
    // `path` is what the dashboard's toast names; kept even when nothing
    // moved so the message can still say where the files live.
    let path = moved.clone().unwrap_or(out_dir);
    json!({"status": true,
           "moved": moved.map(|p| p.to_string_lossy().to_string()),
           "path": path.to_string_lossy(),
           "note": note})
}

fn history_json(d: &Daemon, params: &std::collections::HashMap<String, String>) -> Value {
    let h = d.history.lock_ok();
    let failed_only = params.get("failed_only").map(String::as_str) == Some("1");
    let cat_filter = params
        .get("category")
        .filter(|c| !c.is_empty() && *c != "*");
    let ids = nzo_ids_param(params);
    let slots: Vec<Value> = h
        .iter()
        .rev()
        .filter_map(|j| {
            let j = j.lock_ok();
            // §91: selected and rendered under ONE lock on the record.
            // Taking it twice - once to test the filter, again to build
            // the row - let the two see different states: a Failed job
            // whose auto-retry cooldown came due between them is pulled
            // back out of history and reset to Queued, so `failed_only=1`
            // answered with a row saying `"status": "Queued"` and an
            // empty `fail_kind` / `fail_action`. An *arr asking for
            // failures is entitled to get only failures back, and the
            // remedy keys it reads to act on one must be there.
            if (failed_only && j.state != JobState::Failed)
                || !cat_filter.is_none_or(|c| j.category == *c)
                || !ids.as_ref().is_none_or(|s| s.contains(j.nzo_id.as_str()))
            {
                return None;
            }
            // Truth-audit I: what this download is CALLED on disk, when
            // that is not what it was posted as. A de-obfuscation rename
            // left the history row saying "a4f9c2e1" and the folder
            // saying "Example.Movie.2019.1080p-GRP", with nothing
            // anywhere connecting the two - so a user who went looking
            // for their download could not tell which folder was it.
            // Empty when the two agree, so the drawer shows the row only
            // when there is something to reconcile.
            let filed_as = {
                let disk = if j.filed {
                    // A TV-filed job's directory is the SHARED season
                    // folder, so its name says nothing about this
                    // episode. The stem the episode files were written
                    // under is the answer.
                    j.filed_base.clone().unwrap_or_else(|| j.name.clone())
                } else {
                    j.out_dir
                        .file_name()
                        .map(|s| s.to_string_lossy().into_owned())
                        .unwrap_or_default()
                };
                if disk == j.name { String::new() } else { disk }
            };
            // ...and whether `move_completed` put the payload somewhere
            // the download folder does not contain. The completion toast
            // announced a finished download and said nothing about the
            // files having gone to a NAS. Empty for everything still
            // under the download root.
            let moved_to = if j.out_dir.starts_with(d.out_dir()) {
                String::new()
            } else {
                j.out_dir.to_string_lossy().into_owned()
            };
            Some(json!({
                "nzo_id": j.nzo_id,
                "name": j.name,
                "nzb_name": format!("{}.nzb", j.name),
                "origin": j.origin,
                "nzb_path": j.nzb_path.to_string_lossy(),
                "category": if j.category.is_empty() { "*" } else { &j.category },
                "status": match j.state { JobState::Completed => "Completed", JobState::Failed => "Failed", _ => "Queued" },
                "fail_message": j.fail_message,
                "fail_detail": j.fail_detail,
                // This failure was a full disk, decided by the same
                // matcher the NZBGet SPACE verdict uses. Its own key so
                // the drawer can pair the row with the LIVE free-space
                // number instead of string-matching a sentence: the fix
                // is entirely in the user's hands, and Retry re-runs
                // just the unpack (the article journal re-fetches
                // nothing while the volumes are intact).
                "disk_full": j.state == JobState::Failed && disk_full_failure(&j.fail_message),
                // What the retry actually needs FREE, which is not the
                // set size: the volumes are already on the disk, so the
                // room owed is the extracted payload - and, for an
                // ENCRYPTED set, the finish decrypt's temp copy beside
                // it as well. The drawer used to gate its Retry button
                // on `bytes` alone and would have lit it up one whole
                // payload too early on exactly the shape that hit this
                // (RAR5 encrypted, a tester, 2 Aug).
                "space_needed": unpack_space_needed(0, j.total_bytes, &j.archive_shape),
                // The failure classifier as a token, so the drawer can
                // say what to DO per kind - and suppress Retry for the
                // two kinds the daemon itself knows retrying cannot fix
                // (gone, preflight). Empty on anything not Failed.
                "fail_kind": if j.state == JobState::Failed {
                    fail_kind_token(fail_kind(&j.fail_message))
                } else {
                    ""
                },
                // M32: when the daemon has already scheduled its own
                // retry, say so - the user was shown a hard failure and
                // then watched the row silently resurrect. Unix seconds,
                // null when no retry is armed.
                "auto_retry_at": j.auto_retry_at,
                // ...and WHAT it is waiting for ("transport" or
                // "propagation"), which is also why the cooldown is the
                // length it is. Null when no retry is armed.
                "auto_retry_why": j.auto_retry_why,
                // The sub-cause inside the message, for the ONE remedy
                // button the drawer offers beside the reason. Two
                // failures can share a fail_kind and need opposite next
                // moves - see `fail_hint`. Empty on anything not Failed.
                "fail_hint": if j.state == JobState::Failed {
                    fail_hint(&j.fail_message)
                } else {
                    ""
                },
                // ...and the single action that answers it. One key so
                // the page never has to re-derive the rule, and so the
                // rule itself is testable.
                "fail_action": if j.state == JobState::Failed {
                    fail_action(
                        fail_kind(&j.fail_message),
                        fail_hint(&j.fail_message),
                        &j.fail_message,
                        j.password_required,
                    )
                } else {
                    ""
                },
                "retry": j.retries,
                // This job came out of the local index rather than from
                // an NZB the user holds. It matters on a failure: a
                // "gone" verdict here means the post rotted out of the
                // library, nothing was ever written to disk, and the
                // copy must not talk about resuming what downloaded.
                "library": j.library,
                "duplicate_key": j.dupe_key.as_deref().unwrap_or(""),
                "storage": j.out_dir.to_string_lossy(),
                "path": j.out_dir.to_string_lossy(),
                "bytes": j.total_bytes,
                "size": format!("{:.1} MB", j.total_bytes as f64 / API_MB),
                // Stats (0 until a download actually ran): bytes ÷ secs
                // is the average network speed for this job.
                "downloaded_bytes": j.downloaded_bytes,
                "elapsed_secs": (j.elapsed_secs * 10.0).round() / 10.0,
                // SAB's native key for "when did this finish", unix
                // seconds. 0 for spool entries that predate
                // `finished_unix` - clients treat that as "unknown",
                // never as 1970.
                "completed": j.finished_unix.unwrap_or(0),
                // NULL when nothing verified this download (no PAR2 in
                // the post, or a resume that mapped no block) - the
                // dashboard says "not verified" for that and keeps it
                // out of the clean count. A number is a real verdict,
                // and `verify_blocks` is how many blocks produced it.
                "bad_blocks": j.bad_blocks,
                "verify_blocks": j.verify_blocks,
                // M24: the value never leaves the daemon - only the facts.
                "password_required": j.password_required,
                "has_password": j.password.is_some(),
                // Completed, but something in it is still packed. SAB has
                // no field for "succeeded with a caveat", so the archive
                // NAME rides in its own key (the dashboard composes the
                // sentence in the user's own language) while an English
                // one goes in the SAB-native `script_line` - the single
                // free-text slot a Completed history item has, and one
                // existing clients already surface beside the status.
                "unpack_blocked_by": j.unpack_blocked_by,
                // UX §18: the move to the completed folder stopped part
                // way and the payload is in TWO directories - this one
                // and `storage`. Its own key beside `unpack_blocked_by`
                // and for the same reason: SAB has no "succeeded with a
                // caveat", so the PATH rides here and the dashboard
                // composes the sentence in the user's own language.
                // Empty on everything that moved whole or never moved.
                "move_split": j.move_split,
                "archive_shape": j.archive_shape,
                // §76: the same quality chip the queue row carries,
                // latched during the download and kept. Another additive
                // key - a client that does not know it ignores it.
                "media": j.media,
                // What an identity oracle said this release is, beside
                // the name it was posted under. Additive keys: `name`
                // stays exactly what every SAB client already matches
                // on, and a client that does not know these ignores
                // them.
                "identity_name": j.identity_name,
                "identity_imdb": j.identity_imdb,
                "identity_src": j.identity_src,
                "filed_as": filed_as,
                // The Smart Folder rule that chose its category, same
                // reason: "why is this in Films?" is answerable only by
                // the rule that decided it.
                "smart_rule": j.smart_rule,
                "moved_to": moved_to,
                // What the post-processing sweeps removed from this
                // job's directory, and whether the deletes were
                // recoverable when they ran. Additive keys; zero means
                // no drawer line.
                "cleaned_files": j.cleaned_files,
                "cleaned_par2": j.cleaned_par2,
                "cleaned_trash": j.cleaned_trash,
                // ...and when no oracle could name it, what synthesised
                // naming made of the payload: the file's own facts, then
                // the shortlist. English, and deliberately so - film
                // titles are not ours to translate, and the runtimes and
                // codecs in it are not words. See Job::identify.
                "identify": j.identify,
                "script_line": if j.unpack_blocked_by.is_empty() {
                    String::new()
                } else {
                    format!(
                        "{} could not be unpacked: it is damaged, encrypted, or uses \
                         a compression method this build does not carry. The verified \
                         archive is in the output folder.",
                        j.unpack_blocked_by
                    )
                },
            }))
        })
        .collect();
    let n = slots.len();
    // Direct id selection bypasses the start/limit window (SAB semantics).
    let slots = if ids.is_some() {
        slots
    } else {
        paginate(slots, params)
    };
    json!({"history": {"slots": slots, "noofslots": n}})
}

// ---------------------------------------------------------------------------
// M14g: time-of-week scheduler (parse_size lives with the other guards
// near ServeOpts)
// ---------------------------------------------------------------------------

const WEEK_MINUTES: u32 = 7 * 24 * 60;

#[derive(Debug, Clone, Copy, PartialEq)]
enum SchedAction {
    Pause,
    Resume,
    SpeedLimit(u64),
}

#[derive(Debug, Clone)]
struct SchedEntry {
    /// Mon=0 .. Sun=6.
    days: [bool; 7],
    /// Minutes after midnight (UTC).
    minute: u32,
    action: SchedAction,
}

impl SchedEntry {
    /// Does this entry fire at exactly minute-of-week `mow`?
    fn fires_at(&self, mow: u32) -> bool {
        self.days[(mow / 1440) as usize] && self.minute == mow % 1440
    }
}

/// Current UTC time as a minute-of-week (Mon 00:00 = 0 .. Sun 23:59 = 10079).
fn utc_minute_of_week() -> u32 {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let day = ((secs / 86_400 + 3) % 7) as u32; // epoch day 0 was a Thursday
    day * 1440 + (secs % 86_400 / 60) as u32
}

/// Minute-of-week (0 = Monday 00:00) in the machine's LOCAL timezone -
/// people schedule around their own nights, not UTC's. Falls back to UTC
/// where localtime isn't available.
fn local_minute_of_week() -> u32 {
    #[cfg(unix)]
    {
        let t = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as libc::time_t;
        let mut tm: libc::tm = unsafe { std::mem::zeroed() };
        if !unsafe { libc::localtime_r(&t, &mut tm) }.is_null() {
            let day = (tm.tm_wday as u32 + 6) % 7; // tm_wday: 0 = Sunday
            return day * 1440 + tm.tm_hour as u32 * 60 + tm.tm_min as u32;
        }
    }
    utc_minute_of_week()
}

/// "mon-fri", "sat,sun", "all", or any comma list of names/ranges
/// ("mon,wed-fri"). Ranges may wrap ("sat-mon").
fn parse_days(s: &str) -> Option<[bool; 7]> {
    const NAMES: [&str; 7] = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"];
    let day = |n: &str| {
        NAMES
            .iter()
            .position(|x| *x == n.trim().to_ascii_lowercase())
    };
    let mut out = [false; 7];
    if s.trim().eq_ignore_ascii_case("all") {
        return Some([true; 7]);
    }
    for part in s.split(',') {
        match part.split_once('-') {
            Some((a, b)) => {
                let (mut i, j) = (day(a)?, day(b)?);
                loop {
                    out[i] = true;
                    if i == j {
                        break;
                    }
                    i = (i + 1) % 7;
                }
            }
            None => out[day(part)?] = true,
        }
    }
    Some(out)
}

/// Parse a schedule file: a JSON array of
/// `{"days": "mon-fri", "time": "23:30", "action": "pause"|"resume"|
///   "speedlimit", "value": "4M"}` (value only for speedlimit; sizes as
/// per `parse_size`, or a bare JSON number of bytes/sec).
fn parse_schedule(json: &str) -> Result<Vec<SchedEntry>> {
    let v: Value = serde_json::from_str(json)?;
    let arr = v
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("schedule must be a JSON array"))?;
    arr.iter()
        .enumerate()
        .map(|(i, e)| {
            let bad = |what: &str| anyhow::anyhow!("entry {i}: {what}");
            let days = parse_days(e.get("days").and_then(Value::as_str).unwrap_or("all"))
                .ok_or_else(|| bad("bad days"))?;
            let time = e
                .get("time")
                .and_then(Value::as_str)
                .ok_or_else(|| bad("missing time"))?;
            let (h, m) = time
                .split_once(':')
                .ok_or_else(|| bad("time must be HH:MM"))?;
            let (h, m): (u32, u32) = (
                h.parse().map_err(|_| bad("bad hour"))?,
                m.parse().map_err(|_| bad("bad minute"))?,
            );
            if h >= 24 || m >= 60 {
                return Err(bad("time out of range"));
            }
            let action = match e.get("action").and_then(Value::as_str) {
                Some("pause") => SchedAction::Pause,
                Some("resume") => SchedAction::Resume,
                Some("speedlimit") => {
                    let val = e
                        .get("value")
                        .ok_or_else(|| bad("speedlimit needs value"))?;
                    let bps = match val {
                        Value::Number(n) => n.as_u64(),
                        Value::String(s) => parse_size(s),
                        _ => None,
                    }
                    .ok_or_else(|| bad("bad speedlimit value"))?;
                    SchedAction::SpeedLimit(bps)
                }
                _ => return Err(bad("action must be pause|resume|speedlimit")),
            };
            Ok(SchedEntry {
                days,
                minute: h * 60 + m,
                action,
            })
        })
        .collect()
}

/// Which state is currently in effect, given `now` as a minute-of-week:
/// for each kind (paused-ness, speedlimit) the most recent occurrence
/// at-or-before `now` within the past week wins; an exact tie in time goes
/// to the later entry in the file. None = no entry of that kind has fired.
/// Pure - `now` is injected, never read from the clock here.
fn effective_state(entries: &[SchedEntry], now: u32) -> (Option<bool>, Option<u64>) {
    let mut paused: Option<(u32, bool)> = None; // (distance back, state)
    let mut limit: Option<(u32, u64)> = None;
    for e in entries {
        for (d, on) in e.days.iter().enumerate() {
            if !on {
                continue;
            }
            let mow = d as u32 * 1440 + e.minute;
            let dist = (now + WEEK_MINUTES - mow) % WEEK_MINUTES;
            match e.action {
                SchedAction::Pause | SchedAction::Resume => {
                    if paused.is_none_or(|(best, _)| dist <= best) {
                        paused = Some((dist, e.action == SchedAction::Pause));
                    }
                }
                SchedAction::SpeedLimit(v) => {
                    if limit.is_none_or(|(best, _)| dist <= best) {
                        limit = Some((dist, v));
                    }
                }
            }
        }
    }
    (paused.map(|(_, p)| p), limit.map(|(_, v)| v))
}

/// Minutes from `now` (a minute-of-week) until the schedule's next
/// Resume entry fires, or `None` when the schedule never resumes.
///
/// The header promises a time only when there is one: a schedule that
/// pauses and never resumes leaves the queue held until someone acts,
/// and inventing "until 08:00" out of the nearest entry of any kind
/// would be a promise the daemon cannot keep. Pure - `now` is injected,
/// exactly like [`effective_state`].
fn next_resume_in(entries: &[SchedEntry], now: u32) -> Option<u32> {
    entries
        .iter()
        .filter(|e| e.action == SchedAction::Resume)
        .flat_map(|e| {
            e.days
                .iter()
                .enumerate()
                .filter(|(_, on)| **on)
                .map(move |(day, _)| {
                    let mow = day as u32 * 1440 + e.minute;
                    match (mow + WEEK_MINUTES - now) % WEEK_MINUTES {
                        // Fires this very minute - which is not a
                        // future time. The next one is a week out.
                        0 => WEEK_MINUTES,
                        forward => forward,
                    }
                })
        })
        .min()
}

fn apply_action(d: &Arc<Daemon>, a: SchedAction) {
    match a {
        SchedAction::Pause | SchedAction::Resume => {
            // A schedule entry is a LATER decision about this hour than
            // any timer armed before it, so it cancels the pending
            // auto-resume exactly as a manual pause or resume does.
            // Without the bump the older sleeper stayed authoritative:
            // "pause for 60 minutes" at 21:30 un-paused the queue at
            // 22:30, inside a 22:00 scheduled off window.
            d.pause_gen.fetch_add(1, Ordering::Relaxed);
            *d.pause_until.lock_ok() = None;
            let pause = a == SchedAction::Pause;
            d.paused.store(pause, Ordering::Relaxed);
            // Claim it, so the header can say who decided and until when
            // instead of showing the same word a deliberate pause gets.
            *d.pause_source.lock_ok() = "schedule";
            if pause {
                d.suspend_active(true); // scheduled pause winds down gracefully
            }
        }
        SchedAction::SpeedLimit(v) => d.set_speed_ceiling_from(v, "schedule"),
    }
}

/// The queue-pause side of an offline transition, as pure state.
///
/// Returns `(paused, paused_by_offline)`.
///
/// Going offline pauses, because the alternative is spending the outage
/// starting jobs that cannot connect: every one of them would fail
/// against articles that were never missing, and the operator would come
/// back to a queue full of red that says nothing about what happened.
///
/// Coming back online unpauses only what THIS mechanism paused. An
/// operator who had already paused by hand, then went offline, then came
/// back online, must still be paused - resuming their download for them
/// is not something going online was asked to do.
fn offline_pause_transition(
    going_offline: bool,
    paused: bool,
    paused_by_offline: bool,
) -> (bool, bool) {
    match going_offline {
        // Claim the pause only if the queue was actually running.
        true => (true, !paused),
        // Release it only if it was ours; either way the claim is spent.
        false => (paused && !paused_by_offline, false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A line is advertised in megaBITS everywhere on earth, so "900M"
    /// in the Line speed box is what a person on a 900 Mbps connection
    /// types - and reading it as 900 MB/s made their line eight times
    /// bigger than it is, which is how a healthy 37 MB/s got scored as
    /// "4% of your line".
    #[test]
    fn bit_units_are_bits_and_byte_units_are_bytes() {
        // 900 Mbps = 112.5 MB/s, however it is spelled.
        for s in [
            "900Mb", "900Mbit", "900Mbits", "900Mbps", "900mbps", "900 Mbps", "900Mb/s",
        ] {
            assert_eq!(parse_size(s), Some(112_500_000), "{s}");
        }
        assert_eq!(parse_size("1Gbps"), Some(125_000_000));
        // Explicit bytes stay bytes...
        assert_eq!(parse_size("900MB"), Some(900_000_000));
        assert_eq!(parse_size("112MB/s"), Some(112_000_000));
        // ...and so does a bare magnitude. 29 call sites read disk and
        // cache sizes through this; they are not secretly about bits.
        assert_eq!(parse_size("900M"), Some(900_000_000));
        assert_eq!(parse_size("1G"), Some(1_000_000_000));
        assert_eq!(parse_size("4096"), Some(4096));
    }

    /// Nothing that parsed before parses differently now. Every suffixed
    /// form was REJECTED by this function, so the change can only turn a
    /// refusal into a number - which is what made it safe to land
    /// against a parser this widely used.
    #[test]
    fn the_old_accepted_forms_are_untouched() {
        assert_eq!(parse_size("0"), Some(0));
        assert_eq!(parse_size("10G"), Some(10_000_000_000));
        assert_eq!(parse_size("4M"), Some(4_000_000));
        assert_eq!(parse_size("  2K  "), Some(2_000));
        assert_eq!(parse_size("who knows"), None);
        assert_eq!(parse_size(""), None);
        assert_eq!(parse_size("-5M"), None);
    }

    /// SAB's `nzo_ids` selector: named ids bypass the start/limit
    /// window entirely (Sonarr reconciles weeks-old downloads by id -
    /// pagination hiding one reads as "deleted" and wedges it).
    #[test]
    fn nzo_ids_select_directly_and_skip_pagination() {
        let p = |kv: &[(&str, &str)]| -> std::collections::HashMap<String, String> {
            kv.iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect()
        };
        // Absent, empty, or all-blank lists mean "no selection".
        assert_eq!(nzo_ids_param(&p(&[])), None);
        assert_eq!(nzo_ids_param(&p(&[("nzo_ids", "")])), None);
        assert_eq!(nzo_ids_param(&p(&[("nzo_ids", " , ,")])), None);
        // A comma list parses with whitespace tolerated.
        let ids = nzo_ids_param(&p(&[(
            "nzo_ids",
            "SABnzbd_nzo_nzbfast1, SABnzbd_nzo_nzbfast7",
        )]))
        .expect("two ids");
        assert!(ids.contains("SABnzbd_nzo_nzbfast1"));
        assert!(ids.contains("SABnzbd_nzo_nzbfast7"));
        assert_eq!(ids.len(), 2);
        // The selection path must not paginate: the same params carry a
        // limit that would hide the row, and the history/queue builders
        // branch on `ids.is_some()` to skip `paginate`. Guard the
        // paginate half here: with limit=1 and start=1 the second slot
        // survives only via the ids branch.
        let slots = vec![json!({"nzo_id": "a"}), json!({"nzo_id": "b"})];
        let paged = paginate(
            slots,
            &p(&[("start", "0"), ("limit", "1"), ("nzo_ids", "b")]),
        );
        assert_eq!(paged.len(), 1, "paginate itself stays id-blind");
    }

    /// SAB accepts priorities as numbers or words; unknown words stay
    /// None so the -100 "not given" sentinel logic is untouched.
    #[test]
    fn priority_tokens_parse_like_sab() {
        use super::sabcompat::parse_priority_token as t;
        assert_eq!(t("2"), Some(2));
        assert_eq!(t("-100"), Some(-100));
        assert_eq!(t("force"), Some(2));
        assert_eq!(t("Force"), Some(2));
        assert_eq!(t("HIGH"), Some(1));
        assert_eq!(t("normal"), Some(0));
        assert_eq!(t("low"), Some(-1));
        assert_eq!(t("paused"), Some(-2));
        assert_eq!(t("urgent"), None);
        assert_eq!(t(""), None);
    }

    /// Going offline pauses; coming back online must unpause ONLY the
    /// pause that going offline created.
    ///
    /// The case that matters is the third: an operator pauses by hand,
    /// then goes offline to free the account, then comes back online.
    /// Resuming their download for them is not what "online" was asked
    /// to do, and it would start a transfer they deliberately stopped -
    /// possibly a metered one.
    #[test]
    fn coming_online_does_not_resume_a_download_the_user_paused() {
        // Running -> offline: offline owns the pause, and gives it back.
        assert_eq!(offline_pause_transition(true, false, false), (true, true));
        assert_eq!(offline_pause_transition(false, true, true), (false, false));

        // Already paused by hand -> offline: the pause is not ours...
        assert_eq!(offline_pause_transition(true, true, false), (true, false));
        // ...so coming back online leaves it exactly as the user set it.
        assert_eq!(offline_pause_transition(false, true, false), (true, false));

        // Online while already running is a no-op on both flags.
        assert_eq!(
            offline_pause_transition(false, false, false),
            (false, false)
        );
    }

    /// The daemon's `fast_par` default and the CLI's (the nzbkit flag
    /// initializer) must be the same value. Today that's by re-export;
    /// if someone splits `FAST_PAR_DEFAULT` back into a local const,
    /// this catches the two drifting apart.
    #[test]
    fn fast_par_default_matches_nzbkit() {
        assert_eq!(FAST_PAR_DEFAULT, nzbkit::par2repair::FAST_PAR_DEFAULT);
    }

    /// A post-script that prints without stopping must cost a bounded
    /// amount of memory. The drain used to `read_to_string` into an
    /// unbounded `String`, so the daemon grew until it died - and it did
    /// so BEFORE the deadline could stop it, because the deadline only
    /// ever checked the process, never the pipe.
    #[cfg(unix)]
    #[test]
    fn a_script_that_never_stops_talking_is_bounded_and_still_killed() {
        let mut cmd = std::process::Command::new("sh");
        cmd.arg("-c")
            .arg("while :; do printf 'noise noise noise\\n' >&2; done");
        let t0 = Instant::now();
        let (status, err) = run_capped(cmd, 1).unwrap();
        assert!(status.is_none(), "the deadline must have killed it");
        assert!(
            t0.elapsed() < std::time::Duration::from_secs(10),
            "returned late"
        );
        assert!(
            err.len() <= SCRIPT_ERR_TAIL + 64,
            "kept {} bytes of stderr; the ring is {SCRIPT_ERR_TAIL}",
            err.len()
        );
        assert!(err.contains("noise"), "the tail is what a log line quotes");
        assert!(err.contains("dropped"), "truncation has to be visible");
    }

    /// The in-flight body budget (28 Jul sweep: 8 workers x 256 MB could
    /// OOM a clamped container): a second concurrent body must WAIT when
    /// the pool is exhausted, the sole active reader must never be
    /// refused (one huge NZB still uploads on a small box), and a
    /// release must wake the waiter.
    #[test]
    fn body_budget_blocks_others_but_never_a_sole_reader() {
        let b = std::sync::Arc::new(BodyBudget::new(10));
        // Sole reader: exceeds the cap outright.
        let mut a = Hold::default();
        b.grow(&mut a, 8);
        b.grow(&mut a, 8);
        assert_eq!(a.bytes, 16, "the sole reader must always be admitted");
        // A second body must wait while the first holds the pool...
        let b2 = b.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        let t = std::thread::spawn(move || {
            let mut h = Hold::default();
            b2.grow(&mut h, 4);
            tx.send(()).unwrap();
            b2.release(h);
        });
        assert!(
            rx.recv_timeout(std::time::Duration::from_millis(200))
                .is_err(),
            "a second reader was admitted past the cap"
        );
        // ...and proceed the moment the first releases.
        b.release(a);
        rx.recv_timeout(std::time::Duration::from_secs(5))
            .expect("the waiter never woke after the release");
        t.join().unwrap();
    }

    /// The deadlock the shape above hides: BOTH readers hold bytes. Each
    /// is part of the total the other is queued behind and neither
    /// releases until its read loop ends, so an unbounded wait parked the
    /// pair forever - and every later body-reading request behind them,
    /// which is all 8 HTTP workers. Reachable unauthenticated (bodies are
    /// buffered before the auth decision) and by accident on a
    /// memory-clamped box with two concurrent uploads.
    #[test]
    fn two_holders_that_exhaust_the_pool_both_finish() {
        let b = std::sync::Arc::new(BodyBudget::new(8));
        let (tx, rx) = std::sync::mpsc::channel();
        // Both must be HOLDING half before either asks for more -
        // otherwise one thread simply runs the whole sequence first and
        // the cycle never forms.
        let gate = std::sync::Arc::new(std::sync::Barrier::new(2));
        let hands: Vec<_> = (0..2)
            .map(|_| {
                let (b, tx, gate) = (b.clone(), tx.clone(), gate.clone());
                std::thread::spawn(move || {
                    let mut h = Hold::default();
                    // Each takes half the pool, then asks for more: the
                    // point at which both are holders and neither can
                    // proceed without the other releasing.
                    b.grow(&mut h, 4);
                    gate.wait();
                    b.grow(&mut h, 4);
                    tx.send(()).unwrap();
                    b.release(h);
                })
            })
            .collect();
        for _ in 0..2 {
            rx.recv_timeout(BODY_BUDGET_WAIT * 3)
                .expect("a body-budget holder never woke: the pool deadlocked");
        }
        for h in hands {
            h.join().unwrap();
        }
    }

    /// The escape hatch that used to be here, run for a while. Codex
    /// found this on the 31 Jul sweep and it was real: the timeout
    /// release was granted to EVERY holder, every round, forever, so a
    /// set of stalled uploads ratcheted the pool upward by one chunk each
    /// per wait instead of being held near the cap. Against the old rule
    /// this reached 117 with a cap of 16 - 7x - inside 600 ms, and in
    /// production it walks at 8 MiB per 5 s back toward the
    /// multi-gigabyte figure the budget exists to prevent, on the
    /// add-only tier `addfile` accepts.
    ///
    /// The bound that has to hold: at most ONE body over the cap, because
    /// only the oldest holder is let past it. Every holder here asks for
    /// far more than its share and none of them ever releases, which is
    /// the slow-loris fleet; `EXTRA` stands in for the per-request `take`
    /// cap that bounds the single over-runner in production.
    #[test]
    fn stalled_holders_cannot_ratchet_the_pool_upward() {
        // Eight, because eight is the HTTP worker count - the fleet size
        // that made the original finding a ~2 GiB one.
        const HOLDERS: u64 = 8;
        const SHARE: u64 = 4;
        const EXTRA: u64 = 16;
        let cap = HOLDERS * SHARE;
        let b = std::sync::Arc::new(BodyBudget::with_wait(
            cap,
            std::time::Duration::from_millis(5),
        ));
        let gate = std::sync::Arc::new(std::sync::Barrier::new(HOLDERS as usize));
        let peak = std::sync::Arc::new(AtomicU64::new(0));
        let hands: Vec<_> = (0..HOLDERS)
            .map(|_| {
                let (b, gate, peak) = (b.clone(), gate.clone(), peak.clone());
                std::thread::spawn(move || {
                    let mut h = Hold::default();
                    b.grow(&mut h, SHARE);
                    // Everyone holds its share before anyone asks for
                    // more, or one thread simply runs the whole sequence
                    // alone as the sole reader.
                    gate.wait();
                    for _ in 0..EXTRA {
                        b.grow(&mut h, 1);
                        peak.fetch_max(b.cur.lock().unwrap().bytes, Ordering::Relaxed);
                    }
                    b.release(h);
                })
            })
            .collect();
        for h in hands {
            h.join().unwrap();
        }
        let peak = peak.load(Ordering::Relaxed);
        assert!(
            peak <= cap + EXTRA,
            "the pool peaked at {peak} against a cap of {cap}: more than one \
             body got past it, so stalled holders are ratcheting it upward"
        );
        assert_eq!(
            b.cur.lock().unwrap().bytes,
            0,
            "every hold must be released"
        );
    }

    /// The shape that leaked a blocking-pool worker per completed job: a
    /// script that backgrounds something and exits happily. The
    /// descendant inherits stdout/stderr, so the pipes stay open long
    /// after the direct child is reaped - and the drain threads used to
    /// be JOINED, which parked the caller for the descendant's lifetime
    /// however short the configured deadline was.
    #[cfg(unix)]
    #[test]
    fn a_backgrounded_descendant_cannot_outlive_the_deadline() {
        let mut cmd = std::process::Command::new("sh");
        cmd.arg("-c").arg("sleep 60 & exit 0");
        let t0 = Instant::now();
        let (status, _) = run_capped(cmd, 5).unwrap();
        let took = t0.elapsed();
        assert!(
            status.is_some_and(|s| s.success()),
            "the script itself exited fine"
        );
        assert!(
            took < std::time::Duration::from_secs(5),
            "waited {took:?} on a descendant holding the pipe"
        );
    }

    /// Two workers registering different first-seen categories used to
    /// race: each took a `cat_list()` snapshot after dropping the
    /// category lock, and the later WRITE could carry the earlier
    /// snapshot - so B's category was written and then overwritten away.
    /// Live memory held both, so it only surfaced after a restart, with
    /// an *arr suddenly failing its category test.
    #[test]
    fn registering_a_category_never_drops_one_already_on_disk() {
        // B landed {tv, movies} while A was still holding {tv, anime}.
        assert_eq!(
            merge_cat_list("tv, movies", "tv, anime"),
            "tv, movies, anime"
        );
        // Idempotent: re-registering something already recorded rewrites
        // the same list.
        assert_eq!(merge_cat_list("tv, movies", "tv, movies"), "tv, movies");
        // First category on a fresh install, and the empty-side cases.
        assert_eq!(merge_cat_list("", "tv"), "tv");
        assert_eq!(merge_cat_list("tv", ""), "tv");
        assert_eq!(merge_cat_list("", ""), "");
        // Whitespace and empty members in a hand-edited file.
        assert_eq!(
            merge_cat_list("tv ,, movies", " anime "),
            "tv, movies, anime"
        );
    }

    /// A scan pass owns a dedicated connection for minutes; the switch
    /// and the wipe button are one click. The pass used to republish
    /// unconditionally when it exited, so switching the indexer OFF
    /// mid-scan got a live shared connection back, and wiping got the
    /// database recreated seconds after the API reported it gone.
    #[cfg(feature = "indexer")]
    #[test]
    fn a_scan_pass_may_only_publish_into_the_index_it_started_in() {
        // The ordinary case: same era, still on.
        assert!(may_publish_index(7, 7, true));
        // Switched off while the pass ran.
        assert!(!may_publish_index(8, 8, false));
        // Wiped while the pass ran - the era moved on, and a wipe that
        // gets its files recreated by an exiting scan was never a wipe.
        assert!(!may_publish_index(9, 8, true));
        // Both, which is what switching off actually looks like (the
        // close bumps the era too).
        assert!(!may_publish_index(9, 8, false));
    }

    /// The ordinary case still has to work: exit status and stderr are
    /// what the caller logs.
    #[cfg(unix)]
    #[test]
    fn a_failing_script_reports_its_status_and_stderr() {
        let mut cmd = std::process::Command::new("sh");
        cmd.arg("-c").arg("echo ignored; echo boom >&2; exit 3");
        let (status, err) = run_capped(cmd, 30).unwrap();
        assert_eq!(status.and_then(|s| s.code()), Some(3));
        assert_eq!(err.trim(), "boom");
    }

    /// An indexer transport error carries the URL it failed on, and that
    /// URL carries the user's API key. It reached a rendered error row on
    /// two surfaces before this scrubber existed.
    #[test]
    fn apikey_never_rides_an_error_string() {
        let msg = "https://idx.example/api?t=search&apikey=SECRET123&q=x: Dns Failed";
        let got = redact_apikey(msg);
        assert!(!got.contains("SECRET123"), "{got}");
        assert_eq!(
            got,
            "https://idx.example/api?t=search&apikey=***&q=x: Dns Failed"
        );
        // Key last in the query, so the value runs to the end of the URL
        // rather than to an '&'.
        let tail = redact_apikey("https://idx/api?t=caps&apikey=abc def");
        assert_eq!(tail, "https://idx/api?t=caps&apikey=*** def");
        // Two of them (a message that quotes the URL twice) and a string
        // with none at all.
        assert_eq!(
            redact_apikey("a apikey=1&b apikey=2&c"),
            "a apikey=***&b apikey=***&c"
        );
        assert_eq!(redact_apikey("plain error"), "plain error");
    }

    /// The GRAB path needs more than [`redact_apikey`]. That scrubber
    /// knows the credential is spelled `apikey=` because WE built the
    /// search URL. An NZB enclosure link comes out of the indexer's own
    /// XML and can spell it anything, so the whole URL past the host goes.
    ///
    /// Regression for a real leak: `fetch_url` names the URL it failed
    /// on, and both `indexer_grab` and the nzblnk ladder put that string
    /// straight into a response the dashboard renders.
    #[test]
    fn a_grab_error_shows_the_host_and_nothing_else() {
        let got = redact_url_creds(
            "http://idx.example/getnzb/abc?r=SECRET123&i=42: 999 bytes is too large for an NZB",
        );
        assert!(!got.contains("SECRET123"), "{got}");
        // The `:` that separated the URL from the sentence goes with the
        // URL - it is attached to it, and telling sentence punctuation
        // apart from URL punctuation is a rabbit hole with a credential
        // at the bottom of it. Dropping is the safe direction, and the
        // message still reads.
        assert_eq!(
            got,
            "http://idx.example/... 999 bytes is too large for an NZB"
        );
        // Userinfo is a credential too.
        assert_eq!(
            redact_url_creds("https://user:pw@idx.example/x?k=1 failed"),
            "https://idx.example/... failed"
        );
        // A bare origin keeps its shape; two URLs in one sentence both go.
        assert_eq!(
            redact_url_creds("https://idx.example refused"),
            "https://idx.example refused"
        );
        assert_eq!(
            redact_url_creds("http://a/x?k=1 then https://b/y?k=2 done"),
            "http://a/... then https://b/... done"
        );
        assert_eq!(redact_url_creds("plain error"), "plain error");
        // https must not be matched as http:// + "s..." when both appear
        // and the https one comes first.
        assert_eq!(
            redact_url_creds("https://b/y?k=2 and http://a/x?k=1"),
            "https://b/... and http://a/..."
        );
    }

    /// §4 C2: the enricher's requests must REUSE a connection.
    ///
    /// `ureq::get(...)` builds a throwaway agent per call, and in ureq
    /// the agent is the connection pool, so every request reconnected
    /// and re-did the TLS handshake. The enricher makes several requests
    /// per title across thousands of titles, so this was a handshake per
    /// lookup for nothing.
    ///
    /// Counting ACCEPTED TCP connections is the direct evidence: three
    /// requests to one host over a keep-alive server must open exactly
    /// one. (Loopback is deliberately not in `is_forbidden_fetch_ip`,
    /// which is what lets the guarded agent be tested at all.)
    #[test]
    fn the_shared_enrich_agent_reuses_one_connection() {
        use std::io::{BufRead, BufReader, Write};
        use std::sync::atomic::{AtomicUsize, Ordering};

        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let accepted = std::sync::Arc::new(AtomicUsize::new(0));
        let acc = accepted.clone();
        let done = std::sync::Arc::new(AtomicUsize::new(0));
        let d2 = done.clone();

        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                acc.fetch_add(1, Ordering::SeqCst);
                let d = d2.clone();
                std::thread::spawn(move || {
                    let peek = stream.try_clone().unwrap();
                    let mut r = BufReader::new(peek);
                    // Serve request after request on this ONE socket for
                    // as long as the client keeps it open.
                    loop {
                        let mut saw_request = false;
                        loop {
                            let mut line = String::new();
                            match r.read_line(&mut line) {
                                Ok(0) => return,
                                Ok(_) => {}
                                Err(_) => return,
                            }
                            if line.starts_with("GET ") {
                                saw_request = true;
                            }
                            if line == "\r\n" || line == "\n" {
                                break;
                            }
                        }
                        if !saw_request {
                            return;
                        }
                        let body = "ok";
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\
                             Connection: keep-alive\r\n\r\n{body}",
                            body.len()
                        );
                        if stream.write_all(resp.as_bytes()).is_err() {
                            return;
                        }
                        let _ = stream.flush();
                        d.fetch_add(1, Ordering::SeqCst);
                    }
                });
            }
        });

        for i in 0..3 {
            // Fetched FRESH each time, exactly as every wall.rs call site
            // does (`shared_enrich_agent().get(...)`). Hoisting it into a
            // local would prove only that ureq pools within one agent -
            // true however this function is written - instead of that the
            // enricher's call sites share one.
            let resp = shared_enrich_agent()
                .get(&format!("http://127.0.0.1:{port}/x{i}"))
                .timeout(std::time::Duration::from_secs(5))
                .call()
                .unwrap_or_else(|e| panic!("request {i} failed: {e}"));
            // The body MUST be drained, or ureq cannot return the
            // connection to the pool and the next request opens a new one.
            let body = resp.into_string().unwrap();
            assert_eq!(body, "ok");
        }

        // Give the last handler a moment to finish writing.
        for _ in 0..50 {
            if done.load(Ordering::SeqCst) >= 3 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
        assert_eq!(
            done.load(Ordering::SeqCst),
            3,
            "server should have served 3 requests"
        );
        assert_eq!(
            accepted.load(Ordering::SeqCst),
            1,
            "three requests opened {} connections - the agent is not pooling",
            accepted.load(Ordering::SeqCst)
        );
    }

    /// A crash between publish_over_previous's two renames used to leave
    /// the superseded download under a pid-suffixed name that nothing in
    /// the tree ever looked at again, with no canonical directory at all:
    /// the job's history record pointed at a missing path, so the user's
    /// previous download had vanished from everywhere the software looks.
    #[test]
    fn an_interrupted_replace_is_put_back_at_startup() {
        let root = std::env::temp_dir().join(format!(
            "nzbfast-replrec-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&root);
        let cat = root.join("tv");
        std::fs::create_dir_all(&cat).unwrap();

        // 1. The crash shape: aside exists, canonical is gone.
        let aside = cat.join(format!("Show.S01E01{REPLACED_SUFFIX}999"));
        std::fs::create_dir_all(&aside).unwrap();
        std::fs::write(aside.join("ep.mkv"), b"the user's episode").unwrap();

        // 2. Both present: ambiguous, must be left strictly alone.
        let keep_canon = cat.join("Other.S01E02");
        let keep_aside = cat.join(format!("Other.S01E02{REPLACED_SUFFIX}999"));
        std::fs::create_dir_all(&keep_canon).unwrap();
        std::fs::create_dir_all(&keep_aside).unwrap();
        std::fs::write(keep_canon.join("new.mkv"), b"new").unwrap();
        std::fs::write(keep_aside.join("old.mkv"), b"old").unwrap();

        // 3. An ordinary directory must not be touched.
        let normal = cat.join("Normal.S01E03");
        std::fs::create_dir_all(&normal).unwrap();

        // 4. Names that merely CONTAIN the suffix are the user's, not
        //    ours: an aside is always <name> + suffix + pid and nothing
        //    else, so a non-numeric tail, an empty tail and an empty stem
        //    are all somebody else's directory. Renaming one to its stem
        //    moves a folder of their media out from under them - and can
        //    collide with a real download of that name.
        let theirs: Vec<PathBuf> = vec![
            cat.join(format!("Movie{REPLACED_SUFFIX}Final")),
            cat.join(format!("Movie{REPLACED_SUFFIX}12ab")),
            cat.join(format!("Movie{REPLACED_SUFFIX}")),
            cat.join(format!("Movie{REPLACED_SUFFIX}999.part2")),
            cat.join(format!("{REPLACED_SUFFIX}999")), // no name in front of it
        ];
        for d in &theirs {
            std::fs::create_dir_all(d).unwrap();
            std::fs::write(d.join("theirs.mkv"), b"theirs").unwrap();
        }

        // 5. A canonical name that itself ends in a suffix-shaped string:
        //    the LAST occurrence is the parking one, so this must be put
        //    back under the whole leading name, not truncated at the
        //    first match.
        let nested = cat.join(format!("Odd{REPLACED_SUFFIX}1a{REPLACED_SUFFIX}777"));
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(nested.join("odd.mkv"), b"odd").unwrap();

        recover_interrupted_publishes(&root);

        let restored = cat.join("Show.S01E01");
        assert!(
            restored.join("ep.mkv").exists(),
            "the only copy must be put back"
        );
        assert!(
            !aside.exists(),
            "the aside name should be gone once restored"
        );
        assert_eq!(
            std::fs::read(restored.join("ep.mkv")).unwrap(),
            b"the user's episode",
            "restored bytes must be the user's, untouched"
        );

        // Nothing deleted in the ambiguous case - guessing wrong there
        // would destroy a directory of somebody's media.
        assert!(keep_canon.join("new.mkv").exists(), "canonical left alone");
        assert!(keep_aside.join("old.mkv").exists(), "spare copy left alone");
        assert!(normal.exists(), "unrelated directories untouched");

        for d in &theirs {
            assert!(
                d.join("theirs.mkv").exists(),
                "{} is not one of our asides and must be left where it is",
                d.display()
            );
        }
        assert!(
            !cat.join("Movie").exists(),
            "a directory that merely contains the suffix was renamed over the user"
        );

        let nested_canon = cat.join(format!("Odd{REPLACED_SUFFIX}1a"));
        assert!(
            nested_canon.join("odd.mkv").exists(),
            "the aside must be split at the LAST suffix, not the first"
        );
        assert!(
            !cat.join("Odd").exists(),
            "split at the first suffix instead of the last"
        );

        let _ = std::fs::remove_dir_all(&root);
    }

    /// The MB in these APIs is 1048576 bytes, not 1000000. MEASURED on
    /// the bench box against both reference clients: an NZB summing to
    /// exactly 104857600 bytes reported as 100 by SABnzbd 5.0.4
    /// (`mode=queue` -> "mb": "100.00") and by NZBGet (`listgroups` ->
    /// FileSizeMB: 100 with FileSizeLo/Hi giving 104857600).
    ///
    /// We divided by 1_000_000, so every size was 4.9% high - Sonarr
    /// multiplies the field back by 1024*1024, which skewed both its
    /// queue sizes and its free-space thresholds.
    #[test]
    fn api_megabytes_are_the_binary_ones_both_clients_use() {
        const PROBE: u64 = 104_857_600; // exactly 100 MiB, the NZB used
        assert_eq!(API_MB_U, 1_048_576);
        assert_eq!(API_MB, 1_048_576.0);
        assert_eq!(PROBE / API_MB_U, 100, "NZBGet reported 100 for these bytes");
        assert_eq!(
            format!("{:.2}", PROBE as f64 / API_MB),
            "100.00",
            "SAB reported \"100.00\" for these bytes"
        );

        // The NZBGet size triple has to agree with itself: Lo/Hi are the
        // exact bytes clients actually key on, and *SizeMB is derived.
        let m = size_fields("File", PROBE);
        let lo = m["FileSizeLo"].as_u64().unwrap();
        let hi = m["FileSizeHi"].as_u64().unwrap();
        assert_eq!(hi * (1 << 32) + lo, PROBE, "Lo/Hi must be the exact bytes");
        assert_eq!(m["FileSizeMB"].as_u64().unwrap(), 100);

        // And the old divisor must not creep back.
        assert_ne!(
            PROBE / 1_000_000,
            PROBE / API_MB_U,
            "104 vs 100 - the whole bug"
        );
    }

    /// Sonarr parses SAB's `timeleft` as a .NET TimeSpan, and the
    /// `hh:mm:ss` form rejects hours above 23 - so an unbounded hours
    /// field did not just misreport one job, it failed the whole
    /// `mode=queue` payload and took every download's tracking with it.
    /// Past a day the value has to carry a days component.
    #[test]
    fn sab_timeleft_never_emits_an_hours_field_dotnet_will_reject() {
        // Under a day: unchanged, bare hours.
        assert_eq!(sab_timeleft(0.0), "0:00:00");
        assert_eq!(sab_timeleft(59.4), "0:00:59");
        assert_eq!(sab_timeleft(3600.0), "1:00:00");
        assert_eq!(sab_timeleft(86_399.0), "23:59:59");

        // The regression: 500 GB on a 40 Mbit line. Was "27:46:12".
        assert_eq!(sab_timeleft(99_972.0), "1:03:46:12");

        // Exactly a day, and a long one.
        assert_eq!(sab_timeleft(86_400.0), "1:00:00:00");
        assert_eq!(sab_timeleft(1_000_000.0), "11:13:46:40");

        // Whatever we emit, the hours field is always parseable.
        for secs in [0.0, 1.0, 86_399.0, 86_400.0, 500_000.0, 9_999_999.0] {
            let out = sab_timeleft(secs);
            let hours: u64 = out.split(':').nth_back(2).unwrap().parse().unwrap();
            assert!(hours <= 23, "{out} has an hours field .NET will reject");
        }

        // Garbage in (a stalled or absurd rate) must not panic or emit
        // something unparseable.
        assert_eq!(sab_timeleft(f64::INFINITY), "0:00:00");
        assert_eq!(sab_timeleft(f64::NAN), "0:00:00");
        assert_eq!(sab_timeleft(-5.0), "0:00:00");
    }
    use serde_json::json;

    /// Every match arm in `apply_setting`, read out of our own source.
    ///
    /// There is no way to reflect over a `match`, and rewriting a hundred
    /// hand-written validators into table rows would be a far bigger risk
    /// than the drift it prevents - so the source IS the reflection. The
    /// arms are string literals at a fixed indent inside one function, so
    /// this is a two-line scan rather than a parser.
    fn apply_setting_arms() -> std::collections::BTreeSet<String> {
        // CR stripped because the splits below are byte-exact. A Windows
        // clone made before `.gitattributes` landed has this source in CRLF
        // (git's own core.autocrlf default), and `"\n}\n"` cannot match
        // "\r\n}\r\n" - so the guard failed with "no recognisable end"
        // rather than reporting drift, which is the one way a guard must
        // never fail. `.gitattributes` pins LF now; this keeps the scan
        // working in a checkout that predates it.
        let src = include_str!("settings.rs").replace('\r', "");
        let body = src
            .split_once("\npub(super) fn apply_setting(")
            .expect("apply_setting moved or was renamed")
            .1
            .split_once("\n}\n")
            .expect("apply_setting has no recognisable end")
            .0;
        body.lines()
            .filter_map(|l| l.strip_prefix("        \""))
            .filter(|l| l.contains("=> {") || l.contains("=> (") || l.contains("=> set_"))
            .flat_map(|l| {
                // One arm can carry several names: `"a" | "b" => {`.
                l.split("=>")
                    .next()
                    .unwrap_or("")
                    .split('|')
                    .map(|n| n.trim().trim_matches('"').to_string())
                    .filter(|n| !n.is_empty() && !n.contains(' '))
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    /// THE guard this whole table exists for.
    ///
    /// Before it, the settings allowlist, the `apply_setting` match and
    /// the `get_config` literal were three hand-maintained lists, and a
    /// setting missing from one of them failed silently - no error, the
    /// setting just did nothing. Now `get_config` and the log rules are
    /// generated from the table, so only this last edge can drift: a new
    /// `apply_setting` arm whose row nobody added (invisible in the UI
    /// and unloggable), or a row whose arm nobody wrote (rejected at the
    /// API with a "this is a bug" message).
    #[test]
    fn apply_arms_match_the_table() {
        let arms = apply_setting_arms();
        // The source scan cannot see cfg attributes, so in slim builds
        // subtract the indexer arms that are compiled out together with
        // their table rows.
        #[cfg(not(feature = "indexer"))]
        let arms: std::collections::BTreeSet<String> = {
            const INDEXER_ARMS: &[&str] = &[
                "index_db",
                "index_gates",
                "index_enabled",
                "spot_enabled",
                "index_interests",
                "index_evict_order",
                "index_evict_kinds",
                "predb_max_rows",
                "predb_seed_days",
            ];
            arms.into_iter()
                .filter(|a| !INDEXER_ARMS.contains(&a.as_str()))
                .collect()
        };
        assert!(
            arms.len() > 60,
            "the source scan found only {} arms - it has stopped matching \
             apply_setting's shape and is no longer guarding anything",
            arms.len()
        );
        let declared: std::collections::BTreeSet<String> = settings()
            .filter(|s| s.write == Write::Setting)
            .map(|s| s.name.to_string())
            .collect();
        let missing_row: Vec<_> = arms.difference(&declared).collect();
        assert!(
            missing_row.is_empty(),
            "apply_setting writes these, but they have no row in the settings \
             table - so get_config never shows them and the config log cannot \
             classify them: {missing_row:?}"
        );
        let missing_arm: Vec<_> = declared.difference(&arms).collect();
        assert!(
            missing_arm.is_empty(),
            "the settings table declares these as writable, but apply_setting \
             has no arm for them - setting one is rejected: {missing_arm:?}"
        );
    }

    /// The watcher deletes the user's .nzb once it has queued it, so
    /// "looks complete" is the check standing between a half-copied file
    /// and a release that is queued in fragments and then unrecoverable.
    /// It must never say yes to a truncated file.
    #[test]
    fn a_truncated_nzb_never_looks_complete() {
        let whole = br#"<?xml version="1.0"?><nzb><file subject="x"></file></nzb>"#;
        assert!(nzb_looks_complete(whole));
        // Trailing whitespace is how most writers finish a file.
        assert!(nzb_looks_complete(b"<nzb></nzb>\n"));
        assert!(nzb_looks_complete(b"<nzb></nzb>\r\n  \t\n"));
        // Every prefix of a real nzb is what a copy in flight looks like,
        // and a half-written one still PARSES - which is the whole reason
        // this function exists rather than trusting the reader.
        for cut in 0..whole.len() {
            assert!(
                !nzb_looks_complete(&whole[..cut]),
                "a {cut}-byte prefix was accepted as a whole nzb"
            );
        }
        assert!(!nzb_looks_complete(b""));
        // The closing tag has to be at the END, not merely present.
        assert!(!nzb_looks_complete(b"<nzb></nzb><file>still writing"));
    }

    /// Sub-second resolution is load-bearing now that a pass can follow
    /// another by 250 ms: at one-second granularity two samples that close
    /// together are identical by construction, so "unchanged since I last
    /// looked" would be true of a copy that is still running.
    #[test]
    fn watch_signature_has_sub_second_resolution() {
        let dir = std::env::temp_dir().join(format!("nzbfast-sig-ms-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("a.nzb");
        std::fs::write(&f, b"<nzb>").unwrap();
        let a = watch_sig(&f).unwrap();
        // A value in seconds would be ~1.7e9; in milliseconds ~1.7e12.
        assert!(a.0 > 1_000_000_000_000, "mtime {} is not milliseconds", a.0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Names are the persisted keys in settings.json. A duplicate row
    /// would make `setting()` resolve to whichever came first, and two
    /// rows exposing the same name would silently drop one value.
    #[test]
    fn setting_names_are_unique() {
        let mut seen = std::collections::BTreeSet::new();
        for s in settings() {
            assert!(seen.insert(s.name), "duplicate settings row: {}", s.name);
        }
    }

    /// Credentials must never reach the log, whatever else changes about
    /// how the table is built.
    #[test]
    fn credentials_are_never_logged() {
        for name in ["apikey", "nzbkey", "omdb_key"] {
            assert_eq!(log_value(name, "hunter2"), "•••");
        }
        assert!(!log_value("notify_targets", r#"[{"kind":"plex","url":"tok"}]"#).contains("tok"));
        assert!(!log_value("feeds", r#"[{"url":"x?apikey=tok"}]"#).contains("tok"));
        assert!(
            !log_value(
                "indexers",
                r#"[{"name":"g","url":"https://x","apikey":"tok"}]"#
            )
            .contains("tok")
        );
        // A name with no row at all is shape-only, not verbatim.
        assert_eq!(
            log_value("brand_new_secret", "hunter2"),
            "(7 chars, not logged)"
        );
    }

    /// The tray cannot link against this binary, so it greps daemon.log
    /// for KEYLESS_MARKER to tell "deliberately refused to start" from
    /// "crashed" - and shows the user completely different advice for
    /// each. If the two copies of the string ever drift, the tray
    /// silently falls back to "stopped unexpectedly, try Restart", which
    /// is the exact wrong answer: restarting fails identically forever.
    /// Keep this in step with crates/nzbtray/src/main.rs.
    #[test]
    fn keyless_marker_matches_the_trays_copy() {
        const TRAY_COPY: &str = "nzbfast cannot start: API key file";
        assert_eq!(
            KEYLESS_MARKER, TRAY_COPY,
            "nzbtray greps for this exact string; update both or the tray \
             shows the wrong advice"
        );
        // And the message a user sees must actually begin with it, or the
        // tray's find() lands mid-sentence and prints a fragment.
        let msg = keyless_help(std::path::Path::new("C:\\x\\apikey"), "is empty");
        assert!(
            msg.starts_with(KEYLESS_MARKER),
            "message must lead with the marker: {msg}"
        );
        // The three remedies are the whole point of the rewrite.
        for needle in [
            "Sonarr",
            "DELETE the file",
            "NZBFAST_OPEN=1",
            "C:\\x\\apikey",
        ] {
            assert!(msg.contains(needle), "missing {needle} from:\n{msg}");
        }
    }

    #[cfg(feature = "indexer")]
    #[test]
    fn live_tip_policy_applies_custom_categories_to_gate_and_ingest() {
        let db = std::env::temp_dir().join(format!(
            "nzbfast-tip-custom-{}-{}.db",
            std::process::id(),
            epoch_secs()
        ));
        let _ = std::fs::remove_file(&db);
        let cats = vec![nzbkit::categories::CustomCategory {
            slug: "formula-1".into(),
            name: "Formula 1".into(),
            pattern: r"^formula\.?1\.".into(),
            not_match: String::new(),
            base: nzbkit::categories::BaseBehavior::Movie,
        }];
        let gates = crate::gates::Gates::from_json(r#"{"kinds":["formula-1"]}"#).unwrap();
        let mut ix = nzbkit::index::Index::open(&db).unwrap();
        install_live_ingest_policy(&mut ix, Some(gates), cats);
        let stem = "Formula1.2026.Round11.Hungary.Qualifying.F1TV.1080p";
        let entry = nzbkit::nntp::OverEntry {
            number: 1,
            subject: format!(r#""{stem}.mkv" yEnc (1/1)"#),
            from: "poster".into(),
            message_id: "<tip-custom@test>".into(),
            bytes: 1024,
            date: 1_700_000_000,
        };
        assert_eq!(
            ix.ingest("alt.binaries.formula1", &[entry], 1_700_000_001)
                .unwrap(),
            1
        );
        let q = nzbkit::index::BrowseQuery {
            kind: Some("formula-1".into()),
            limit: 10,
            ..Default::default()
        };
        let (rows, _) = ix.browse(&q).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].kind, "formula-1");
        drop(ix);
        let _ = std::fs::remove_file(&db);
        let _ = std::fs::remove_file(db.with_extension("db-wal"));
        let _ = std::fs::remove_file(db.with_extension("db-shm"));
    }

    /// Build a Job the way a restart does, so a test does not have to
    /// spell out forty fields.
    /// A LossCauses with nothing known, for messages under test.
    fn no_causes() -> crate::LossCauses<'static> {
        crate::LossCauses {
            missing_430: 0,
            retention_excluded: 0,
            transport_failed: 0,
            transport_sample: None,
            decode_sample: None,
            dead_servers: &[],
            par2_slots: 1,
            stalled: false,
            missing_segments: 0,
            total_segments: 0,
            bytes_arrived: 0,
            backbones: &[],
            post_age_days: 0,
        }
    }

    fn job(v: serde_json::Value) -> Job {
        super::job_from_json(&v).expect("job_from_json")
    }

    /// UX §16: "verified clean" is a claim, and a claim needs a verifier.
    ///
    /// `bad_blocks` used to be a plain `u64` that defaulted to 0, so a
    /// post carrying no PAR2 - and a resume that mapped no block to a
    /// recovery set - arrived at the dashboard indistinguishable from a
    /// download something had checked and found perfect. The health tile
    /// counted them as clean verifications and the timeline drew them as
    /// green ticks. Null is the third answer: nothing verified this.
    #[test]
    fn a_verify_verdict_needs_a_verifier_behind_it() {
        let base = |extra: serde_json::Value| {
            let mut v = json!({
                "nzo_id": "x", "name": "Show.1080p", "nzb_path": "/spool/x.nzb",
                "state": "Completed", "out_dir": "/dl/x",
            });
            for (k, val) in extra.as_object().unwrap() {
                v[k] = val.clone();
            }
            job(v)
        };
        // Nothing recorded at all: not a verdict.
        assert_eq!(base(json!({})).bad_blocks, None);
        // A modern record that verified and found nothing wrong. The
        // block count is what makes the zero mean something.
        let clean = base(json!({"bad_blocks": 0, "verify_blocks": 12_847}));
        assert_eq!(clean.bad_blocks, Some(0));
        assert_eq!(clean.verify_blocks, 12_847);
        // A modern record that verified and found damage.
        assert_eq!(
            base(json!({"bad_blocks": 900, "verify_blocks": 12_847})).bad_blocks,
            Some(900)
        );
        // A record from before the field could be null. A zero with no
        // companion count is unknowable - "verified clean" and "nobody
        // looked" both wrote 0 - and must not be reported as a clean
        // verification. A non-zero count is proof a verifier ran, so it
        // survives as a verdict.
        assert_eq!(base(json!({"bad_blocks": 0})).bad_blocks, None);
        assert_eq!(base(json!({"bad_blocks": 3})).bad_blocks, Some(3));
        // ...and a verifier that ran but mapped nothing checked zero
        // blocks, which is the same non-answer.
        assert_eq!(
            base(json!({"bad_blocks": 0, "verify_blocks": 0})).bad_blocks,
            None
        );
    }

    /// UX §15: the queue percentage's two halves must count ONE thing.
    ///
    /// The pair this replaced divided decoded payload (every slot, PAR2
    /// included) by the NZB's encoded bytes minus recovery volumes, so a
    /// clean download stopped near 97% still claiming a gigabyte "left"
    /// that did not exist, and a damaged one - where the extra recovery
    /// bytes land on the numerator alone - pinned at 100% with articles
    /// still in flight.
    #[test]
    fn fetch_progress_reaches_a_hundred_and_never_passes_it() {
        use std::sync::atomic::Ordering;
        let hub = crate::streamhub::StreamHub::default();
        // No plan published yet: every caller must fall back rather than
        // divide by a plan belonging to nobody.
        assert_eq!(hub.fetch_left(), None);
        hub.fetch_plan.store(1_000, Ordering::Relaxed);
        assert_eq!(hub.fetch_left(), Some((0, 1_000, 1_000)));
        // A resume seeds `done` with what is already in hand, so the bar
        // starts where the bytes are.
        hub.fetch_done.store(600, Ordering::Relaxed);
        assert_eq!(hub.fetch_left(), Some((600, 1_000, 400)));
        // Drained: exactly 100%, exactly nothing left.
        hub.fetch_done.store(1_000, Ordering::Relaxed);
        assert_eq!(hub.fetch_left(), Some((1_000, 1_000, 0)));
        // Two independent atomics, so a reader can land past the plan.
        // Clamped, never an overshoot or an underflowed remainder.
        hub.fetch_done.store(1_200, Ordering::Relaxed);
        assert_eq!(hub.fetch_left(), Some((1_000, 1_000, 0)));
    }

    /// The NZBGet history verdict must separate the failures a user can
    /// actually act on.
    ///
    /// Every failure used to report `FAILURE/PAR` with
    /// `ParStatus: FAILURE` - one bit, so "needs a password", "the disk
    /// filled up" and "the post is missing articles" were
    /// indistinguishable to a client, and all three were blamed on a
    /// repair that in two of the three cases never ran. That sends the
    /// user looking at the release when the problem is on their machine.
    #[test]
    fn nzbget_status_separates_the_failure_kinds() {
        let j = |state: &str, msg: &str| {
            job(json!({
                "nzo_id": "x", "name": "Show.1080p", "nzb_path": "/spool/x.nzb",
                "state": state, "out_dir": "/dl/x", "fail_message": msg,
            }))
        };

        assert_eq!(
            super::nzbget_status(&j("Completed", "")),
            ("SUCCESS/UNPACK", "SUCCESS", "SUCCESS"),
            "the success shape is what the M26 round certified - do not drift it"
        );
        // A password is an unpack verdict with its own NZBGet status, and
        // the par stage succeeded, so blaming par is wrong twice over.
        assert_eq!(
            super::nzbget_status(&j("Failed", "password required to unpack")),
            ("FAILURE/UNPACK", "SUCCESS", "PASSWORD")
        );
        assert_eq!(
            super::nzbget_status(&j("Failed", "write failed: no space left on device")),
            ("FAILURE/UNPACK", "SUCCESS", "SPACE")
        );
        // Windows spells a full disk differently (error 112), and the
        // check that only knew the Unix words reported a tester's
        // disk-full unpack as a generic unpack failure.
        assert_eq!(
            super::nzbget_status(&j(
                "Failed",
                "unpack failed: There is not enough space on the disk. (os error 112)"
            )),
            ("FAILURE/UNPACK", "SUCCESS", "SPACE")
        );
        // The post could not be fetched whole: health, and no par verdict,
        // because par never got to run.
        assert_eq!(
            super::nzbget_status(&j("Failed", "download incomplete: 12 articles missing")),
            ("FAILURE/HEALTH", "NONE", "NONE")
        );
        // The one case that really is a failed repair.
        assert_eq!(
            super::nzbget_status(&j("Failed", "repair could not complete")),
            ("FAILURE/PAR", "FAILURE", "NONE")
        );
    }

    /// NZBGet's priority scale is not ours: theirs runs -100/-50/0/50/100
    /// with 900 for force, ours is SAB's -1/0/1 with 2 for force. Passed
    /// through unmapped, "high" from an *arr landed far above Force.
    #[test]
    fn nzbget_priority_maps_onto_our_scale() {
        assert_eq!(super::nzbget_priority(900), 2, "force");
        assert_eq!(super::nzbget_priority(100), 1, "very high");
        assert_eq!(super::nzbget_priority(50), 1, "high");
        assert_eq!(super::nzbget_priority(0), 0, "normal");
        assert_eq!(super::nzbget_priority(-50), -1, "low");
        assert_eq!(super::nzbget_priority(-100), -1, "very low");
    }

    /// BUG (HIGH): a job caught in post-processing became a permanent
    /// zombie.
    ///
    /// `finalize_completed` corrects the record's out_dir only as its last
    /// statement, so during post-processing - unlock, cleanup, rename, TV
    /// filing, and a NAS move that can run for minutes - the durable
    /// record says "Completed, payload is at X" while the payload is on
    /// its way to Y. A restart there filed the job as a clean success
    /// with a storage path that could be half-copied, or already emptied
    /// by the move, and the *arrs act on that: import the partial file,
    /// or stall with no Failed state to trigger a re-grab.
    ///
    /// Nothing can tell the two apart AFTER the fact, which is why the
    /// intent is written down first. This pins both directions.
    #[test]
    fn only_a_job_caught_mid_finalize_is_reported_failed() {
        let rec = |id: &str, finalizing: bool| {
            json!({
                "nzo_id": id, "name": format!("Show.{id}.1080p"),
                "nzb_path": format!("/spool/{id}.nzb"), "state": "Completed",
                "out_dir": format!("/dl/{id}"), "finalizing": finalizing,
            })
        };
        let (_q, h) = super::restore_records(&[rec("mid", true), rec("done", false)], &[]);

        let mid = h
            .iter()
            .find(|j| j.nzo_id == "mid")
            .expect("interrupted job kept");
        assert_eq!(
            mid.state,
            JobState::Failed,
            "a job caught mid-finalize must not claim success - the *arrs would import \
             a half-moved directory"
        );
        assert!(
            mid.fail_message.contains("/dl/mid"),
            "the message must say where the bytes are, so nothing is lost: {:?}",
            mid.fail_message
        );
        assert!(
            !mid.finalizing,
            "the flag is consumed on restore, not carried forward"
        );

        // The common case is untouched: post-processing finished, only the
        // hooks were lost, so it stays a success.
        let done = h
            .iter()
            .find(|j| j.nzo_id == "done")
            .expect("finished job kept");
        assert_eq!(
            done.state,
            JobState::Completed,
            "a finished job still reports success"
        );
        assert!(done.fail_message.is_empty(), "and carries no failure text");

        // A record written before this field existed must read as "not
        // interrupted" rather than failing every old completed job.
        let legacy = json!({
            "nzo_id": "old", "name": "Old.1080p", "nzb_path": "/spool/old.nzb",
            "state": "Completed", "out_dir": "/dl/old",
        });
        let (_q2, h2) = super::restore_records(&[legacy], &[]);
        assert_eq!(
            h2[0].state,
            JobState::Completed,
            "an upgrade must not mass-fail history that predates the flag"
        );
    }

    /// A job goes Completed (or Failed) the instant its download ends, but
    /// only reaches history when `park` files it - and the whole of
    /// post-processing sits between those two points. Any `save_queue`
    /// during that window persists a TERMINAL record inside the "queue"
    /// array, and restoring it there left it somewhere nothing could reach:
    /// `pick_job` takes only `Queued` jobs, nothing reconciles the arrays,
    /// so it sat in the queue forever - never ran, never appeared in
    /// history, never reported an outcome to the *arrs waiting for one.
    #[test]
    fn a_job_caught_in_post_processing_comes_back_in_history() {
        let rec = |id: &str, state: &str| {
            json!({
                "nzo_id": id, "name": format!("Show.S01E0{}.1080p", id.len()),
                "nzb_path": format!("/spool/{id}.nzb"), "state": state,
                "out_dir": format!("/dl/{id}"),
            })
        };
        // What save_queue writes mid-post-processing, plus the two records
        // that legitimately belong in the queue.
        let queue_arr = vec![
            rec("n1", "Completed"),
            rec("n2", "Failed"),
            // The interrupted transfer: it must STAY queued so the
            // scheduler restarts it and its journal resumes.
            rec("n3", "Downloading"),
            rec("n4", "Queued"),
        ];
        let hist_arr = vec![rec("h1", "Completed")];
        let (q, h) = super::restore_records(&queue_arr, &hist_arr);

        let qids: Vec<&str> = q.iter().map(|j| j.nzo_id.as_str()).collect();
        assert_eq!(
            qids,
            ["n3", "n4"],
            "only records the scheduler can run stay queued"
        );
        // Exactly pick_job's precondition: anything else in this array is
        // unreachable forever.
        assert!(
            q.iter().all(|j| j.state == JobState::Queued),
            "every restored queue record is one pick_job can actually pick"
        );

        let hids: Vec<&str> = h.iter().map(|j| j.nzo_id.as_str()).collect();
        assert_eq!(
            hids,
            ["h1", "n1", "n2"],
            "the interrupted jobs join history after the records already there"
        );
        // The outcome park() would have given them, not a rewrite of it.
        assert_eq!(h[1].state, JobState::Completed);
        assert_eq!(h[2].state, JobState::Failed);
        // ...and no job is in both arrays.
        assert!(q.iter().all(|j| !h.iter().any(|k| k.nzo_id == j.nzo_id)));
    }

    /// `park` retains-then-pushes before its single save, so a well-formed
    /// file never holds one job twice - but a torn or hand-edited one must
    /// not be turned into two history entries by the reconciliation above.
    #[test]
    fn a_record_in_both_arrays_is_restored_once() {
        let rec = |state: &str| {
            json!({"nzo_id": "dup", "name": "X.2024", "nzb_path": "/spool/dup.nzb",
                   "state": state, "out_dir": "/dl/dup"})
        };
        let (q, h) = super::restore_records(&[rec("Completed")], &[rec("Completed")]);
        assert!(q.is_empty());
        assert_eq!(h.len(), 1, "one record, not two");
    }

    /// BUG (MEDIUM, data loss): two Completed records can name ONE
    /// directory, so a delete wiped the live job's files.
    ///
    /// `publish_over_previous` (A6) hands the canonical directory to a
    /// verified re-download but leaves the superseded job's history record
    /// pointing at it too. A delete-with-files on the OLDER record then
    /// `remove_dir_all`'d the NEWER job's payload: the record deleted was
    /// not the data destroyed.
    #[test]
    fn deleting_a_superseded_record_spares_the_newer_jobs_directory() {
        let canon = PathBuf::from("/dl/Movie.2024");
        let rec = |id: &str, state: JobState, dir: &PathBuf, filed: bool| super::DeleteRecord {
            nzo_id: id.to_string(),
            state,
            out_dir: dir.clone(),
            filed,
            locked: false,
        };
        // Both records name the canonical directory; "new" lives there.
        let shared = vec![
            rec("old", JobState::Completed, &canon, false),
            rec("new", JobState::Completed, &canon, false),
        ];

        let plan = super::plan_history_delete(&shared, "old", &[]);
        assert!(plan[0].doomed, "the record still goes");
        assert!(
            !plan[0].may_remove_files,
            "but the files are the newer job's"
        );
        assert!(!plan[1].doomed);

        // The ordinary single-owner delete is untouched.
        let solo = vec![rec(
            "solo",
            JobState::Completed,
            &PathBuf::from("/dl/A"),
            false,
        )];
        let plan = super::plan_history_delete(&solo, "solo", &[]);
        assert!(plan[0].doomed && plan[0].may_remove_files);

        // value=all must still delete. The claimant test runs against the
        // records that SURVIVE, and `all` leaves no history survivors -
        // testing it against the pre-delete list would find every record's
        // directory "claimed" by a doomed sibling and silently stop
        // deleting anything at all.
        let plan = super::plan_history_delete(&shared, "all", &[]);
        assert!(
            plan.iter().all(|p| p.doomed && p.may_remove_files),
            "value=all still removes files"
        );
        // ...but a LIVE queue job in that directory does survive, and wins.
        let plan = super::plan_history_delete(&shared, "all", std::slice::from_ref(&canon));
        assert!(plan.iter().all(|p| p.doomed && !p.may_remove_files));

        // value=failed: the failed record goes, the completed one survives
        // and still claims the directory.
        let mixed = vec![
            rec("f", JobState::Failed, &canon, false),
            rec("c", JobState::Completed, &canon, false),
        ];
        let plan = super::plan_history_delete(&mixed, "failed", &[]);
        assert!(plan[0].doomed && !plan[0].may_remove_files);
        assert!(!plan[1].doomed);

        // A TV-filed record shares its season folder with every sibling by
        // design, and its delete is already narrow (per episode). It must
        // not be disarmed by the claimant test or nothing filed could ever
        // be deleted again.
        let season = PathBuf::from("/dl/Show/Season 03");
        let filed = vec![
            rec("e5", JobState::Completed, &season, true),
            rec("e6", JobState::Completed, &season, true),
        ];
        let plan = super::plan_history_delete(&filed, "e5", &[]);
        assert!(
            plan[0].doomed && plan[0].may_remove_files,
            "the per-episode delete still runs"
        );

        // A comma list still selects exactly what it names.
        let plan = super::plan_history_delete(&mixed, "c,missing", &[]);
        assert!(!plan[0].doomed && plan[1].doomed);
    }

    /// The dashboard's one-click "Clear completed" tidies the list without
    /// throwing away anything the user still has to act on.
    ///
    /// The trap is that "completed" is NOT the same set as the card's
    /// Completed filter chip: a password-locked job downloaded fine, so its
    /// state is Completed and the chip counts it - but its payload is still
    /// packed and that history row carries the only 🔑 to unlock it. A
    /// sweep that took it would silently strand the download.
    #[test]
    fn clear_completed_spares_failures_and_password_locked_records() {
        let rec = |id: &str, state: JobState, locked: bool| super::DeleteRecord {
            nzo_id: id.to_string(),
            state,
            out_dir: PathBuf::from(format!("/dl/{id}")),
            filed: false,
            locked,
        };
        let recs = vec![
            rec("done", JobState::Completed, false),
            rec("failed", JobState::Failed, false),
            rec("locked", JobState::Completed, true),
        ];

        let plan = super::plan_history_delete(&recs, "completed", &[]);
        assert!(
            plan[0].doomed && plan[0].may_remove_files,
            "the finished one goes"
        );
        assert!(
            !plan[1].doomed,
            "a failure stays: it is what retry works from"
        );
        assert!(
            !plan[2].doomed,
            "password-locked stays: only this row can unlock it"
        );

        // The neighbouring selectors keep their own meaning. `failed` is
        // the exact complement of what `completed` takes ONLY for the
        // unlocked records - the locked one is in neither sweep, which is
        // the point: it leaves by an explicit ✕, never by a bulk clear.
        let plan = super::plan_history_delete(&recs, "failed", &[]);
        assert_eq!(
            plan.iter().map(|p| p.doomed).collect::<Vec<_>>(),
            vec![false, true, false]
        );
        let plan = super::plan_history_delete(&recs, "all", &[]);
        assert!(
            plan.iter().all(|p| p.doomed),
            "`all` still means all of them"
        );
        // And an nzo_id that happens to read like a bulk word is still
        // matched by the id arm, not the word arm.
        let plan = super::plan_history_delete(&recs, "locked", &[]);
        assert_eq!(
            plan.iter().map(|p| p.doomed).collect::<Vec<_>>(),
            vec![false, false, true]
        );
    }

    /// The same bug end to end, against real files: delete the superseded
    /// record with del_files=1 and the replacement's payload survives.
    #[test]
    fn a_published_over_directory_is_not_the_old_records_to_delete() {
        let _steady = crate::smart::trash_globals_steady();
        let root = std::env::temp_dir().join(format!("nzbfast-published-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let canon = root.join("Movie.2024");
        std::fs::create_dir_all(&canon).unwrap();
        // The NEW job's verified payload, published over the canonical dir.
        std::fs::write(canon.join("movie.mkv"), b"the good copy").unwrap();

        let rec = |id: &str| super::DeleteRecord {
            nzo_id: id.to_string(),
            state: JobState::Completed,
            out_dir: canon.clone(),
            filed: false,
            locked: false,
        };
        let records = vec![rec("old"), rec("new")];
        let plan = super::plan_history_delete(&records, "old", &[]);
        for (r, p) in records.iter().zip(&plan) {
            if p.doomed && p.may_remove_files {
                super::remove_job_files(
                    &r.out_dir,
                    "Movie.2024",
                    r.filed,
                    &crate::smart::FiledTail::default(),
                );
            }
        }
        assert!(
            canon.join("movie.mkv").exists(),
            "the live job's payload survived"
        );

        // Once the new record is gone too, the directory is deletable.
        let last = vec![rec("new")];
        let plan = super::plan_history_delete(&last, "new", &[]);
        assert!(plan[0].may_remove_files);
        super::remove_job_files(
            &canon,
            "Movie.2024",
            false,
            &crate::smart::FiledTail::default(),
        );
        assert!(!canon.exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// BUG (HIGH, 31 Jul queue soak): the slow-job watchdog's demote flag
    /// landed on a job whose download had already drained (it was waiting
    /// on the previous job's stalled tail), the fetch completed cleanly,
    /// auto-rename moved its directory - and park's demote arm re-queued
    /// the finished job, downloading all 34.5 GB a second time into the
    /// renamed folder. A demotion only counts when its abort actually
    /// failed the download.
    #[test]
    fn a_demote_flag_on_a_completed_job_does_not_requeue_it() {
        // The abort landed: the job failed, the re-queue is the design.
        assert!(demote_requeues(true, false, true));
        // The abort lost the race and the job COMPLETED: history, not queue.
        assert!(!demote_requeues(true, false, false));
        // A deleted job stays deleted, failed or not.
        assert!(!demote_requeues(true, true, true));
        assert!(!demote_requeues(true, true, false));
        // No demotion, no re-queue.
        assert!(!demote_requeues(false, false, true));
    }

    /// BUG (MEDIUM): SAB's DEFAULT_PRIORITY sentinel was stored and sorted
    /// as a literal priority, so a job the user had explicitly marked Low
    /// (-1) ran BEFORE every job the UI labelled Normal (-100).
    #[test]
    fn the_default_priority_sentinel_does_not_outrank_low() {
        let normal = enqueue_priority(SAB_DEFAULT_PRIORITY, false);
        let low = enqueue_priority(-1, false);
        // What every client already calls it...
        assert_eq!(priority_name(SAB_DEFAULT_PRIORITY), "Normal");
        assert_eq!(priority_name(normal), "Normal");
        // ...is now what pick_job orders it as. pick_job's key is
        // (!deferred, priority), so the raw comparison IS the queue order.
        assert!(normal > low, "a Normal job must run before a Low one");
        assert!(
            normal > enqueue_priority(-3, false),
            "and before a held duplicate"
        );
        assert!(enqueue_priority(1, false) > normal);
        assert!(enqueue_priority(2, false) > enqueue_priority(1, false));

        // Everything else is unchanged.
        assert_eq!(enqueue_priority(2, false), 2);
        assert_eq!(enqueue_priority(1, false), 1);
        assert_eq!(enqueue_priority(0, false), 0);
        assert_eq!(enqueue_priority(-1, false), -1);
        // SAB -2 is "add paused", not a priority: the job is Normal and
        // the caller sets `paused` from the request.
        assert_eq!(enqueue_priority(-2, false), 0);
        // A held M14f alternative outranks nothing, whatever was asked for.
        assert_eq!(enqueue_priority(SAB_DEFAULT_PRIORITY, true), -3);
        assert_eq!(enqueue_priority(2, true), -3);
    }

    /// BUG (HIGH): a TV-filed job's out_dir is the SHARED `Show/Season NN`
    /// folder. `retry` used to re-queue it as-is, and because every
    /// delete-with-files guard was re-derived from `state == Completed`,
    /// the re-queue turned "leave the siblings alone" into
    /// `remove_dir_all(SeasonDir)` - the whole season.
    #[test]
    fn retrying_a_filed_job_leaves_the_season_folder_alone() {
        let _steady = crate::smart::trash_globals_steady();
        let root = std::env::temp_dir().join(format!("nzbfast-refile-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let out_root = root.join("downloads");
        let season = out_root.join("tv").join("Some Show").join("Season 02");
        std::fs::create_dir_all(&season).unwrap();
        // This job's episode plus a sibling that must survive.
        std::fs::write(season.join("Some.Show.S02E03.mkv"), b"mine").unwrap();
        std::fs::write(season.join("Some.Show.S02E04.mkv"), b"sibling").unwrap();

        let mut j = job(json!({
            "nzo_id": "SABnzbd_nzo_nzbfast1",
            "name": "Some.Show.S02E03.1080p",
            "nzb_path": "/spool/x.nzb",
            "category": "tv",
            "state": "Completed",
            "out_dir": season.to_string_lossy(),
            "tv_sort": true,
        }));
        // A record written before `filed` existed still answers correctly.
        assert!(
            j.filed,
            "a completed tv_sort job in a Season NN dir is filed"
        );

        // What retry() does to a filed job.
        let (dir, replaces) = refile_out_dir(&out_root, &j.category, &j.name, &|_| DirClaim::Free);
        j.out_dir = dir;
        j.replaces = replaces;
        j.filed = false;
        j.state = JobState::Queued;

        assert_ne!(
            j.out_dir, season,
            "the retry must not download into the season folder"
        );
        assert!(j.out_dir.starts_with(out_root.join("tv")));

        // ...and the delete-with-files that used to take the season now
        // only touches the job's own (empty) directory.
        super::remove_job_files(
            &j.out_dir,
            &j.name,
            j.filed,
            &crate::smart::FiledTail::default(),
        );
        assert!(
            season.join("Some.Show.S02E04.mkv").exists(),
            "sibling episode survived"
        );
        assert!(season.exists(), "the season folder survived");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The other half: a job that IS still filed deletes only its own
    /// episode, and an ordinary (unfiled) job still loses its whole
    /// private directory.
    #[test]
    fn remove_job_files_reads_the_flag_not_the_state() {
        let _steady = crate::smart::trash_globals_steady();
        let root = std::env::temp_dir().join(format!("nzbfast-rmfiles-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let season = root.join("Show").join("Season 01");
        std::fs::create_dir_all(&season).unwrap();
        std::fs::write(season.join("Show.S01E01.mkv"), b"a").unwrap();
        std::fs::write(season.join("Show.S01E02.mkv"), b"b").unwrap();
        super::remove_job_files(
            &season,
            "Show.S01E01.1080p",
            true,
            &crate::smart::FiledTail::default(),
        );
        assert!(season.exists());
        assert!(season.join("Show.S01E02.mkv").exists());

        let private = root.join("Movie.2020");
        std::fs::create_dir_all(&private).unwrap();
        std::fs::write(private.join("movie.mkv"), b"c").unwrap();
        super::remove_job_files(
            &private,
            "Movie.2020",
            false,
            &crate::smart::FiledTail::default(),
        );
        assert!(!private.exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// UX §18 + the filed flag, together: a split payload's SOURCE side
    /// obeys `Job::filed` exactly as its destination does.
    ///
    /// `relocate_completed` moves a TV-filed job OUT of the shared
    /// season folder (its own `same_place` comment says so), so a move
    /// that fails part way records that shared folder as `move_split`.
    /// The history delete now removes both halves - and it reads the
    /// flag for both. Passing `false` for the source instead, on the
    /// reasoning that a split source "is always a job-owned folder",
    /// would hand a whole season of the user's episodes to
    /// `remove_user_dir` on one episode's delete.
    #[test]
    fn a_split_source_that_is_a_season_folder_is_deleted_narrowly() {
        let _steady = crate::smart::trash_globals_steady();
        let root = std::env::temp_dir().join(format!("nzbfast-splitfiled-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        // The SOURCE half of a split move: a shared season folder still
        // holding this episode and two siblings that are nothing to do
        // with the job being deleted.
        let season = root.join("Show").join("Season 01");
        std::fs::create_dir_all(&season).unwrap();
        for ep in ["Show.S01E01.mkv", "Show.S01E02.mkv", "Show.S01E03.mkv"] {
            std::fs::write(season.join(ep), b"x").unwrap();
        }
        super::remove_job_files(
            &season,
            "Show.S01E01.1080p",
            true,
            &crate::smart::FiledTail::default(),
        );
        assert!(
            season.join("Show.S01E02.mkv").exists() && season.join("Show.S01E03.mkv").exists(),
            "deleting one episode took its siblings from the split SOURCE folder"
        );
        assert!(
            season.exists(),
            "the shared season folder itself must survive"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A recoverable delete the Trash refuses must LEAVE the download and
    /// hand the reason back, both arms of it.
    ///
    /// The leaving-it-alone half landed in 70990f19; this pins the half
    /// that makes it visible. `remove_job_files` used to answer a plain
    /// bool, so the refusal reached a `warn!` and stopped there - while
    /// the history or queue row went regardless, taking with it the only
    /// place the user could see that download named. A caller cannot
    /// narrate what it was never told.
    #[test]
    fn a_refused_delete_keeps_the_files_and_says_why() {
        let _serial = crate::smart::one_trash_test_at_a_time();
        let root = std::env::temp_dir().join(format!("nzbfast-refused-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let private = root.join("Movie.2020");
        let season = root.join("Show").join("Season 01");
        std::fs::create_dir_all(&private).unwrap();
        std::fs::create_dir_all(&season).unwrap();
        std::fs::write(private.join("movie.mkv"), b"c").unwrap();
        std::fs::write(season.join("Show - S01E01.mkv"), b"a").unwrap();

        let was = crate::smart::delete_to_trash();
        crate::smart::set_delete_to_trash(true);
        crate::smart::force_trash_unresponsive(true);
        let unfiled = super::remove_job_files(
            &private,
            "Movie.2020",
            false,
            &crate::smart::FiledTail::default(),
        );
        // The filed arm deletes per FILE inside the user's own library,
        // and refuses per file - it must report the same way.
        let filed = super::remove_job_files(
            &season,
            "Show.S01E01.1080p",
            true,
            &crate::smart::FiledTail::default(),
        );
        crate::smart::force_trash_unresponsive(false);
        crate::smart::set_delete_to_trash(was);

        for (out, path, what) in [
            (unfiled, private.join("movie.mkv"), "the private folder"),
            (filed, season.join("Show - S01E01.mkv"), "the filed episode"),
        ] {
            assert!(path.exists(), "{what} must survive a refused delete");
            match out {
                FilesGone::Kept(why) => assert!(
                    !why.is_empty(),
                    "{what}: the refusal has to carry a reason to show"
                ),
                FilesGone::Yes(_) => panic!("{what}: a refused delete reported success"),
            }
        }
        let _ = std::fs::remove_dir_all(&root);
    }

    /// `filed` has to survive a restart: re-deriving it from the current
    /// state is exactly the bug above.
    #[test]
    fn filed_round_trips_through_the_queue_file() {
        let mut j = job(json!({
            "nzo_id": "n1", "name": "Show.S01E01", "nzb_path": "/s/x.nzb",
            "state": "Completed", "out_dir": "/dl/tv/Show/Season 01", "tv_sort": true,
        }));
        assert!(j.filed);
        // Re-queued (a retry that, say, kept the folder) - the flag stays
        // whatever it was set to, and a restart must not "helpfully"
        // recompute it from Queued.
        j.state = JobState::Queued;
        let round = job(super::job_json(&j));
        assert!(round.filed, "filed survives a restart of a re-queued job");
        assert_eq!(round.out_dir, j.out_dir);
    }

    /// BUG (MEDIUM, data loss): the migration for records written before
    /// `filed` existed used to also require `state == "Completed"`. The
    /// pre-upgrade `retry` re-queued a filed job WITHOUT moving it off the
    /// shared season folder and then persisted it, so a legacy record can
    /// perfectly well read `Queued` while `out_dir` is still
    /// `Show/Season NN`. Migrating that as `filed = false` hands the next
    /// delete-with-files a `remove_dir_all` of the whole season - the exact
    /// outcome the flag exists to prevent.
    ///
    /// Deliberately end-to-end: it migrates a real legacy record and then
    /// runs the real delete against a real season folder, rather than just
    /// asserting on the shape predicate.
    #[test]
    fn a_legacy_requeued_record_still_migrates_as_filed() {
        let _steady = crate::smart::trash_globals_steady();
        let root = std::env::temp_dir().join(format!("nzbfast-legacyfiled-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let season = root.join("tv").join("Some Show").join("Season 03");
        std::fs::create_dir_all(&season).unwrap();
        std::fs::write(season.join("Some.Show.S03E01.mkv"), b"mine").unwrap();
        std::fs::write(season.join("Some.Show.S03E02.mkv"), b"sibling").unwrap();

        // Exactly what a pre-`filed` daemon wrote after a retry: no
        // `filed` key at all, and a state of Queued.
        let j = job(json!({
            "nzo_id": "n1",
            "name": "Some.Show.S03E01.1080p",
            "nzb_path": "/spool/x.nzb",
            "category": "tv",
            "state": "Queued",
            "out_dir": season.to_string_lossy(),
            "tv_sort": true,
        }));
        assert!(
            matches!(j.state, JobState::Queued),
            "the legacy record is re-queued, not done"
        );
        assert!(
            j.filed,
            "a legacy tv_sort record in a Season NN dir migrates as filed"
        );

        // And the delete that used to take the season now spares it.
        super::remove_job_files(
            &j.out_dir,
            &j.name,
            j.filed,
            &crate::smart::FiledTail::default(),
        );
        assert!(season.exists(), "the season folder survived");
        assert!(
            season.join("Some.Show.S03E02.mkv").exists(),
            "sibling episode survived"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The naming settings a filed episode was named under, as the tests
    /// below need them: bracketed tokens plus the group, which is the
    /// shape a quality suffix actually takes on disk.
    fn filing_style() -> crate::wall::NameStyle {
        crate::wall::NameStyle {
            resolution: true,
            video_codec: true,
            audio_codec: false,
            source: true,
            group: true,
            year_parens: true,
            quality_brackets: true,
            extra_words: true,
        }
    }

    fn suffix_of(stem: &str) -> String {
        crate::wall::quality_suffix(&crate::wall::parse_release(stem), &filing_style())
    }

    /// BUG (HIGH, data loss): turn auto-rename OFF after episodes have
    /// been filed and the next watchlist upgrade deletes BOTH copies.
    ///
    /// The suffix that keeps a filed delete release-specific used to be
    /// recomputed from the LIVE rename settings at delete time. With
    /// auto-rename off the recompute returns "", and an empty suffix is
    /// not "no suffix on disk" but "the episode base plus any rename tail
    /// at all" - so the delete of the superseded copy swept up the
    /// replacement that had just landed beside it in the same season
    /// folder. The slot still recorded the new release as owned, so
    /// nothing ever re-grabbed it and the user was left with neither.
    ///
    /// The suffix filing used is persisted instead. `legacy` here stands
    /// in for `Daemon::job_suffix` on an install whose auto-rename is now
    /// off: it returns exactly the empty string that did the damage.
    #[test]
    fn turning_auto_rename_off_does_not_delete_the_upgrade_that_replaced_an_episode() {
        let _steady = crate::smart::trash_globals_steady();
        let root = std::env::temp_dir().join(format!("nzbfast-filedsfx-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let season = root.join("tv").join("The Bear").join("Season 03");
        std::fs::create_dir_all(&season).unwrap();

        let old_stem = "The.Bear.S03E05.720p.HDTV-A";
        let new_stem = "The.Bear.S03E05.1080p.WEB.h264-GRP";
        let (old_sfx, new_sfx) = (suffix_of(old_stem), suffix_of(new_stem));
        assert!(
            !old_sfx.is_empty(),
            "auto-rename was on when this was filed"
        );
        assert_ne!(old_sfx, new_sfx, "the upgrade is a different quality");
        let old_file = format!("The Bear - S03E05{old_sfx}.mkv");
        let new_file = format!("The Bear - S03E05{new_sfx}.mkv");
        let sibling = "The Bear - S03E06 [1080p WEB h264]-GRP.mkv";
        for f in [old_file.as_str(), new_file.as_str(), sibling] {
            std::fs::write(season.join(f), b"x").unwrap();
        }

        // The superseded record, as it was filed and then persisted.
        let j = job(json!({
            "nzo_id": "n1",
            "name": old_stem,
            "nzb_path": "/spool/x.nzb",
            "category": "tv",
            "state": "Completed",
            "out_dir": season.to_string_lossy(),
            "tv_sort": true,
            "filed": true,
            "filed_suffix": old_sfx,
        }));

        // The upgrade landed; the watchlist drops what it supersedes -
        // with auto-rename since switched off, so the recompute is "".
        let tail = super::delete_tail(&j, String::new);
        super::remove_job_files(&j.out_dir, &j.name, j.filed, &tail);
        assert!(
            !season.join(&old_file).exists(),
            "the superseded copy is gone"
        );
        assert!(
            season.join(&new_file).exists(),
            "the replacement we just downloaded must survive its own upgrade"
        );
        assert!(
            season.join(sibling).exists(),
            "a sibling episode is never touched"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// An obfuscated post identified by an oracle is FILED under the
    /// oracle's name - "a4f9c2e1" is not a show - so every later
    /// operation on it has to look for the files that were really
    /// written. Keyed on `Job::name`, the delete below finds nothing:
    /// the episode is left in the season folder forever, and the "play"
    /// route cannot find it either.
    #[test]
    fn a_job_filed_under_an_oracles_name_is_deleted_by_that_name() {
        let _steady = crate::smart::trash_globals_steady();
        let root = std::env::temp_dir().join(format!("nzbfast-fbase-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let season = root.join("tv").join("The Bear").join("Season 03");
        std::fs::create_dir_all(&season).unwrap();
        std::fs::write(season.join("The Bear - S03E05 [1080p].mkv"), b"x").unwrap();
        std::fs::write(season.join("The Bear - S03E06 [1080p].mkv"), b"x").unwrap();

        let j = job(json!({
            "nzo_id": "n1",
            // What usenet called it, and what the *arr still matches on.
            "name": "a4f9c2e1b7d048395166cf20",
            "nzb_path": "/spool/x.nzb",
            "category": "tv",
            "state": "Completed",
            "out_dir": season.to_string_lossy(),
            "tv_sort": true,
            "filed": true,
            "filed_suffix": " [1080p]",
            // What it turned out to be, and what filing used.
            "identity_name": "The.Bear.S03E05.1080p.WEB.h264-GRP",
            "identity_src": "srrdb",
            "filed_base": "The.Bear.S03E05.1080p.WEB.h264-GRP",
        }));
        assert_eq!(super::filed_stem(&j), "The.Bear.S03E05.1080p.WEB.h264-GRP");

        let tail = super::delete_tail(&j, String::new);
        super::remove_job_files(&j.out_dir, super::filed_stem(&j), j.filed, &tail);
        assert!(
            !season.join("The Bear - S03E05 [1080p].mkv").exists(),
            "the filed episode was not found by the name it was filed under"
        );
        assert!(
            season.join("The Bear - S03E06 [1080p].mkv").exists(),
            "a sibling episode is never touched"
        );

        // A record with no filed_base - every record written before the
        // identity ladder, and every job whose own name was fine - still
        // answers with its own name.
        let plain = job(json!({
            "nzo_id": "n2",
            "name": "The.Bear.S03E06.1080p.WEB.h264-GRP",
            "nzb_path": "/spool/x.nzb",
            "state": "Completed",
            "out_dir": season.to_string_lossy(),
            "tv_sort": true,
            "filed": true,
        }));
        assert_eq!(
            super::filed_stem(&plain),
            "The.Bear.S03E06.1080p.WEB.h264-GRP"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The other direction: an install that has had auto-rename OFF all
    /// along filed `{base}.{ext}` with no suffix, and its delete must
    /// still work. Its stored suffix is an empty string, and there that
    /// empty string is the truth rather than a wildcard.
    ///
    /// Plus the legacy record that has no stored suffix at all: it falls
    /// back to a recompute, never to a bare "".
    #[test]
    fn an_auto_rename_off_install_still_deletes_the_episode_it_filed() {
        let _steady = crate::smart::trash_globals_steady();
        let root = std::env::temp_dir().join(format!("nzbfast-nosfx-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let season = root.join("tv").join("The Bear").join("Season 03");
        std::fs::create_dir_all(&season).unwrap();
        std::fs::write(season.join("The Bear - S03E05.mkv"), b"x").unwrap();
        std::fs::write(season.join("The Bear - S03E05.en.srt"), b"x").unwrap();
        std::fs::write(season.join("The Bear - S03E06.mkv"), b"x").unwrap();

        let rec = |extra: serde_json::Value| {
            let mut v = json!({
                "nzo_id": "n1",
                "name": "The.Bear.S03E05.720p.HDTV-A",
                "nzb_path": "/spool/x.nzb",
                "category": "tv",
                "state": "Completed",
                "out_dir": season.to_string_lossy(),
                "tv_sort": true,
                "filed": true,
            });
            for (k, val) in extra.as_object().unwrap() {
                v[k] = val.clone();
            }
            job(v)
        };

        // A record written before the suffix was persisted says "I don't
        // know", and the recompute answers for it - not a bare "".
        let legacy = rec(json!({}));
        assert!(
            legacy.filed_suffix.is_none(),
            "a legacy record has no stored suffix"
        );
        assert_eq!(
            super::delete_tail(&legacy, || " [1080p]".to_string()).suffix,
            " [1080p]",
            "a legacy record falls back to the recompute"
        );
        assert_eq!(
            super::delete_tail(&legacy, String::new).title,
            "",
            "and carries no episode title: it was filed before titles existed"
        );

        // The auto-rename-off install: "" is what filing really used.
        let j = rec(json!({"filed_suffix": ""}));
        assert_eq!(j.filed_suffix.as_deref(), Some(""));
        let tail = super::delete_tail(&j, || " [1080p]".to_string());
        assert_eq!(tail.suffix, "", "the stored suffix wins over any recompute");
        super::remove_job_files(&j.out_dir, &j.name, j.filed, &tail);
        assert!(
            !season.join("The Bear - S03E05.mkv").exists(),
            "our episode went"
        );
        assert!(
            !season.join("The Bear - S03E05.en.srt").exists(),
            "and its sidecar"
        );
        assert!(
            season.join("The Bear - S03E06.mkv").exists(),
            "the sibling stayed"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The suffix is history, so it has to survive a restart - including
    /// the empty one, which `unwrap_or_default()` on the way back in
    /// could not tell from "no record at all".
    #[test]
    fn the_filed_suffix_round_trips_through_the_queue_file() {
        let rt = |stored: Option<&str>| {
            let mut j = job(json!({
                "nzo_id": "n1", "name": "Show.S01E01.1080p.WEB-GRP",
                "nzb_path": "/s/x.nzb", "state": "Completed",
                "out_dir": "/dl/tv/Show/Season 01", "tv_sort": true, "filed": true,
            }));
            j.filed_suffix = stored.map(str::to_string);
            job(super::job_json(&j)).filed_suffix
        };
        assert_eq!(
            rt(Some(" [1080p WEB]-GRP")).as_deref(),
            Some(" [1080p WEB]-GRP")
        );
        assert_eq!(
            rt(Some("")).as_deref(),
            Some(""),
            "an empty suffix is a real answer"
        );
        assert_eq!(
            rt(None),
            None,
            "and \"never recorded\" stays distinct from it"
        );
    }

    /// BUG (MEDIUM-HIGH, SSRF): the failure link arrives in a RESPONSE
    /// HEADER from whatever server answered the NZB fetch, and the daemon
    /// then GETs it with an SSRF guard that deliberately permits loopback
    /// and RFC1918 (LAN indexers are the normal case). It may only point
    /// back at the host that supplied it.
    #[test]
    fn a_failure_link_may_only_point_back_at_its_own_indexer() {
        // Same host, different port and path: still the same indexer.
        assert!(failure_link_allowed(
            "http://indexer.example:9118/fail?id=1",
            "indexer.example",
            false
        ));
        assert!(failure_link_allowed(
            "https://Indexer.Example/report",
            "indexer.example",
            false
        ));
        // LAN and loopback indexers keep working.
        assert!(failure_link_allowed(
            "http://127.0.0.1:9117/api?t=failure",
            "127.0.0.1",
            false
        ));
        assert!(failure_link_allowed(
            "http://192.168.1.40:8080/x",
            "192.168.1.40",
            false
        ));
        // Anywhere else is refused - including the classic SSRF targets.
        assert!(!failure_link_allowed(
            "http://127.0.0.1:8989/api/v3/command",
            "indexer.example",
            false
        ));
        assert!(!failure_link_allowed(
            "http://169.254.169.254/latest/meta-data/",
            "indexer.example",
            false
        ));
        assert!(!failure_link_allowed(
            "http://evil.example/x",
            "indexer.example",
            false
        ));
        // Userinfo cannot fake the host, and the LAST '@' wins so a
        // password containing '@' cannot smuggle one in either.
        assert!(!failure_link_allowed(
            "http://indexer.example@127.0.0.1/x",
            "indexer.example",
            false
        ));
        assert!(!failure_link_allowed(
            "http://u:p@a@127.0.0.1/x",
            "indexer.example",
            false
        ));
        // A job with no recorded origin (uploaded NZB, or a record from
        // before the field existed) reports nowhere.
        assert!(!failure_link_allowed(
            "http://indexer.example/fail",
            "",
            false
        ));
        // Non-http schemes and junk are not links at all.
        assert!(!failure_link_allowed(
            "file:///etc/passwd",
            "indexer.example",
            false
        ));
        assert!(!failure_link_allowed("", "", false));
    }

    /// BUG (LOW): host equality alone let an indexer reached over TLS hand
    /// back an http link for the same host. The report GET carries the
    /// user's indexer apikey in its query string, so that is a downgrade
    /// of a relationship they had encrypted, chosen by the far end.
    #[test]
    fn a_failure_link_may_not_downgrade_https_to_http() {
        assert!(!failure_link_allowed(
            "http://indexer.example/fail",
            "indexer.example",
            true
        ));
        assert!(failure_link_allowed(
            "https://indexer.example/fail",
            "indexer.example",
            true
        ));
        // Scheme match is case-insensitive, as schemes are.
        assert!(failure_link_allowed(
            "HTTPS://indexer.example/fail",
            "indexer.example",
            true
        ));
        // Junk with a multi-byte character where the scheme should be:
        // refused, and without panicking on a str slice mid-character.
        assert!(!failure_link_allowed(
            "ht°ps://indexer.example/x",
            "indexer.example",
            true
        ));
        assert!(!failure_link_allowed("é", "indexer.example", true));
        // An http origin is not upgraded-only: it may hand back either.
        assert!(failure_link_allowed(
            "http://indexer.example/fail",
            "indexer.example",
            false
        ));
        assert!(failure_link_allowed(
            "https://indexer.example/fail",
            "indexer.example",
            false
        ));
    }

    /// BUG (MEDIUM): a transient failure is parked with an M32 automatic
    /// retry armed - and was ALSO reported to the indexer as a dead post,
    /// re-grabbed, and used to promote the held M14f duplicate. One
    /// missing-article gap therefore put three grabs of the same title on
    /// the user's block account, and told the indexer a live release was
    /// dead over a gap propagation was expected to fill.
    ///
    /// The retry decision has to be answerable BEFORE the hooks run:
    /// `park` arms `auto_retry_at` after `run_post_job_hooks` has already
    /// spawned, so a guard that reads the field is a race.
    #[test]
    fn a_failure_awaiting_its_automatic_retry_is_not_reported_dead() {
        let base = json!({
            "nzo_id": "SABnzbd_nzo_nzbfast1",
            "name": "Some.Release.1080p",
            "nzb_path": "/spool/x.nzb",
            "out_dir": "/downloads/Some.Release.1080p",
            "state": "Failed",
            "fail_message": "download incomplete: 12 articles missing",
        });
        let cooldown = 900;

        // First failure: eligible for the automatic retry, so nothing is
        // reported and no replacement is grabbed.
        let first = job(base.clone());
        assert_eq!(first.retries, 0);
        assert!(
            auto_retry_eligible(&first, cooldown),
            "a first transient failure retries"
        );
        assert_eq!(
            post_job_plan(&first, "regrab", cooldown),
            Some(false),
            "hooks still run, but the failure is not final yet"
        );

        // The retry ran, failed again: `retry` bumped `retries` and
        // cleared the stamp, so THIS failure is final and must report.
        let mut second = job(base.clone());
        second.retries = 1;
        assert!(
            !auto_retry_eligible(&second, cooldown),
            "only ONE automatic retry"
        );
        assert_eq!(
            post_job_plan(&second, "regrab", cooldown),
            Some(true),
            "the exhausted retry reports and re-grabs"
        );

        // Auto-retry switched off: the very first failure is final.
        assert!(!auto_retry_eligible(&first, 0));
        assert_eq!(post_job_plan(&first, "regrab", 0), Some(true));

        // A local fault is not transient, so it never held the report
        // back - and it is not reported either (fail_kind, tested above).
        let mut local = job(base.clone());
        local.fail_message = "no space left on device".into();
        assert!(!auto_retry_eligible(&local, cooldown));

        // Deleted mid-download: owes nobody anything, retry or not.
        let mut gone = job(base);
        gone.tombstone = true;
        assert!(!auto_retry_eligible(&gone, cooldown));
        assert_eq!(post_job_plan(&gone, "regrab", cooldown), None);
    }

    /// BUG (MEDIUM): the config write logged the raw value with a
    /// three-name deny-list, so every notification token and every feed
    /// url (which carries the indexer apikey) went to stdout - which
    /// logtee mirrors into the dashboard log pane users screenshot into
    /// support threads, and into journald / `docker logs`.
    #[test]
    fn the_config_log_never_prints_a_credential() {
        assert_eq!(log_value("apikey", "s3cr3t"), "•••");
        assert_eq!(log_value("nzbkey", "s3cr3t"), "•••");
        assert_eq!(log_value("omdb_key", "s3cr3t"), "•••");

        // Notify targets: counts and kinds, never a url or a token.
        let targets = r#"[{"kind":"kodi","name":"Living room","url":"http://nas:8080/jsonrpc","token":"user:hunter2"},
                          {"kind":"plex","name":"Plex","url":"http://nas:32400","token":"xxPLEXTOKENxx"},
                          {"kind":"webhook","name":"Discord","url":"https://discord.com/api/webhooks/123/AAAsecretBBB","token":""}]"#;
        let shown = log_value("notify_targets", targets);
        assert_eq!(shown, "3 targets (kodi, plex, webhook)");
        for leak in ["hunter2", "PLEXTOKEN", "AAAsecretBBB", "discord.com", "nas"] {
            assert!(!shown.contains(leak), "{leak} reached the log via {shown}");
        }

        // Feeds: the url essentially always embeds `apikey=`.
        let feeds = r#"[{"url":"https://indexer.example/rss?t=tv&apikey=DEADBEEF","interval_secs":900},
                        {"url":"https://other.example/rss?apikey=CAFE","interval_secs":900}]"#;
        let shown = log_value("feeds", feeds);
        assert_eq!(shown, "2 feeds");
        assert!(!shown.contains("DEADBEEF") && !shown.contains("apikey"));

        // M35 indexer entries: the apikey is its own field.
        let idx = r#"[{"name":"geek","url":"https://api.nzbgeek.info","apikey":"SECRETKEY"}]"#;
        let shown = log_value("indexers", idx);
        assert_eq!(shown, "1 indexers");
        assert!(!shown.contains("SECRETKEY"));

        // Malformed JSON must not fall through to the raw value.
        assert!(!log_value("feeds", "{apikey=DEADBEEF").contains("DEADBEEF"));
        assert!(!log_value("indexers", "{apikey=DEADBEEF").contains("DEADBEEF"));
        assert!(!log_value("notify_targets", "hunter2").contains("hunter2"));

        // Switches, numbers and paths still read verbatim - the line is
        // there to be useful.
        assert_eq!(log_value("connections", "40"), "40");
        assert_eq!(
            log_value("out_dir", "/mnt/media/downloads"),
            "/mnt/media/downloads"
        );
        assert_eq!(log_value("auto_rename", "1"), "1");
        assert_eq!(log_value("failure_link", "regrab"), "regrab");

        // DEFAULT DENY: a setting name this function has never heard of -
        // i.e. the next credential-bearing one someone adds - gets a
        // shape summary, not its value.
        assert_eq!(
            log_value("some_future_token", "supersecret"),
            "(11 chars, not logged)"
        );
        assert_eq!(log_value("some_future_token", ""), "(empty)");
    }

    /// BUG (LOW): the failure-link replacement was enqueued with a
    /// hardcoded priority 0 and password None, and took its category from
    /// the (untrusted) response header. So a Force job's stand-in queued
    /// at Normal, a passworded release's stand-in downloaded in full and
    /// then failed extraction for a password the daemon already had, and
    /// the indexer chose which of the user's destinations it landed in.
    #[test]
    fn a_regrabbed_replacement_keeps_the_password_the_priority_and_our_category() {
        let mut j = job(json!({
            "nzo_id": "SABnzbd_nzo_nzbfast1",
            "name": "Some.Release.1080p",
            "nzb_path": "/spool/x.nzb",
            "category": "movies",
            "out_dir": "/downloads/movies/Some.Release.1080p",
            "state": "Failed",
        }));
        j.priority = 2; // Force
        j.password = Some("hunter2".into());
        assert_eq!(
            replacement_inherits(&j),
            ("movies".to_string(), 2, Some("hunter2".to_string()))
        );

        // A held duplicate's -3 is a "parked" marker, not a speed: never
        // propagate it to a download that is meant to run.
        j.priority = -3;
        assert_eq!(replacement_inherits(&j).1, 0);
        // Low is clamped too: the floor is Normal, so a replacement can
        // never come back parked or deprioritized by accident.
        j.priority = -1;
        assert_eq!(replacement_inherits(&j).1, 0, "clamped at Normal");

        // No password, no category: nothing invented.
        let plain = job(json!({
            "nzo_id": "SABnzbd_nzo_nzbfast2",
            "name": "Other.Release",
            "nzb_path": "/spool/y.nzb",
            "out_dir": "/downloads/Other.Release",
            "state": "Failed",
        }));
        assert_eq!(replacement_inherits(&plain), (String::new(), 0, None));
    }

    /// BUG (MEDIUM): a config save whose value outgrew the 8 KB request
    /// line (a watchlist of ~25 shows) got a correct 414 from the server
    /// and vanished silently in the browser: `api()` called `r.json()`
    /// with no `r.ok` check, the SyntaxError rejected a promise nothing
    /// catches, and the one-click "watch this" then no-opped forever.
    ///
    /// Source-level guard: the embedded dashboard is one file with ~60
    /// call sites, so what matters is that the two fetch helpers funnel
    /// through the checking reader.
    #[test]
    fn the_dashboard_turns_an_http_error_into_a_visible_one() {
        let src = DASHBOARD_HTML;
        assert!(
            src.contains("function httpFail(r){ return {status:false, error:'HTTP '+r.status}; }")
        );
        assert!(src.contains("async function readJson(r){"));
        // Neither helper may parse a response without going through it.
        for helper in [
            "async function api(mode, extra, authKey, post){",
            "async function apiPost(mode, body, authKey){",
        ] {
            let body = &src[src.find(helper).expect("helper present")..];
            let body = &body[..body.find("\n}").expect("helper ends")];
            assert!(
                body.contains("await readJson(r)"),
                "{helper} still parses unchecked"
            );
            assert!(
                !body.contains("await r.json()"),
                "{helper} still parses unchecked"
            );
        }
        // And the JSON-blob settings go up in a POST body, which has no
        // request-line limit to hit in the first place.
        assert!(src.contains("await apiPost('config', {name, value}, auth)"));
    }

    /// Codex sweep 2, 3 Aug MH1: a query string is not a private
    /// channel. It reaches reverse-proxy access logs, the browser's own
    /// network panel and history, and any Referer that follows - so a
    /// setting whose VALUE is a credential must travel in a request
    /// body, whatever its length. `setCfg` sent everything under ~1500
    /// chars as `&value=`, and keys are short, so the one class that
    /// must never be logged was the class that always was.
    ///
    /// Source-level like its neighbour above, and for the same reason:
    /// the property is about which branch a name takes, and the branch
    /// is one line.
    #[test]
    fn a_secret_setting_never_travels_in_the_request_line() {
        let src = DASHBOARD_HTML;
        // The length rule is still there for big JSON blobs, and the
        // secret rule sits beside it as an OR - not an else.
        assert!(
            src.contains("(value.length > 1500 || SECRET_CFG.has(name))"),
            "setCfg no longer forces secrets into the body"
        );
        let set = src
            .split("const SECRET_CFG = new Set(")
            .nth(1)
            .and_then(|s| s.split(");").next())
            .expect("SECRET_CFG present");
        for name in [
            "apikey",
            "nzbkey",
            "omdb_key",
            "notify_targets",
            "arr_instances",
            "indexers",
        ] {
            assert!(set.contains(name), "{name} is not in SECRET_CFG: {set}");
        }
        // notify_test carries a webhook token AND a custom body
        // template. `method:'POST'` does not move query parameters into
        // the body, so it has to be an actual body call.
        assert!(
            src.contains("await apiPost('notify_test', {target: row})"),
            "notify_test still puts the whole target in the request line"
        );
    }

    /// BUG (MEDIUM): `apply_and_save` answers a write it could not persist
    /// with `saved: false` - the value is live, and it reverts at the next
    /// restart - and the dashboard threw that flag away. Every path toasted
    /// a flat "Saved.", and the API-key ones went further: "New API key
    /// created and copied. Paste it into Sonarr, Radarr…" for a key that
    /// dies on the next start. The only warning was the eprintln, which is
    /// stdout on a NAS, i.e. nobody.
    ///
    /// Source-level guard, like the http-error one above: all three paths
    /// that can see the flag must raise the durability bar, and none of
    /// them may refuse the key - the daemon is already on it, so a page
    /// that kept the old one would lock itself out.
    #[test]
    fn the_dashboard_says_when_a_change_is_live_but_not_durable() {
        let src = DASHBOARD_HTML;
        assert!(
            src.contains(r#"<div id="durnotice"></div>"#),
            "no durability bar in the page"
        );
        assert!(src.contains("function durNotice("), "no durability notice");
        assert!(
            src.contains("function durNoticeClear("),
            "the bar can never come down again"
        );

        // Function bodies run to the next top-level declaration: openApiFix
        // is a `busy()` wrapper and has no line that is just "}".
        let body_of = |sig: &str| -> &str {
            let s = &src[src.find(sig).unwrap_or_else(|| panic!("{sig} is gone")) + sig.len()..];
            let end = s
                .find("\nasync function ")
                .unwrap_or(s.len())
                .min(s.find("\nfunction ").unwrap_or(s.len()));
            &s[..end]
        };
        for (name, sig) in [
            ("setCfg", "async function setCfg(name, value){"),
            ("newApiKey", "async function newApiKey(){"),
            ("openApiFix", "async function openApiFix(btn){"),
        ] {
            let body = body_of(sig);
            // Strict ===, so an older daemon that omits the field keeps the
            // old behavior rather than warning on every save.
            assert!(
                body.contains("j.saved === false") || body.contains("j.saved===false"),
                "{name} still ignores saved:false"
            );
            assert!(
                body.contains("durNotice("),
                "{name} warns nobody about a lost write"
            );
        }
        // Both key paths still adopt the new key: the daemon is on it.
        for sig in [
            "async function newApiKey(){",
            "async function openApiFix(btn){",
        ] {
            assert!(
                body_of(sig).contains("localStorage.nzbfastKey = j.apikey")
                    || body_of(sig).contains("localStorage.nzbfastKey=j.apikey"),
                "a saved:false path stopped adopting the key, which locks the page out"
            );
        }
    }

    /// One design system, actually reaching every page. Each surface must
    /// carry the tokens placeholder, and `ui_themed` must leave none of it
    /// behind.
    ///
    /// THE TRAP, hit while writing this: web/ui-tokens.html originally
    /// named the placeholder in its own header comment, so substitution
    /// re-emitted the literal into every served page. A single `.replace`
    /// does not recurse, so nothing broke visibly - it just shipped a
    /// stray marker. Hence the "no marker survives" half.
    #[cfg(feature = "indexer")]
    #[test]
    fn every_served_page_gets_the_shared_design_tokens() {
        const MARK: &str = "__NZBFAST_UI_TOKENS__";
        assert!(
            !UI_TOKENS_HTML.contains(MARK),
            "ui-tokens.html names the placeholder, which re-emits it into every page"
        );
        // The tokens themselves, so a gutted file cannot pass.
        for tok in [
            "--surface:",
            "--surface-2:",
            "data-theme=\"contrast\"",
            "nzbfastTheme",
        ] {
            assert!(UI_TOKENS_HTML.contains(tok), "shared tokens lost {tok}");
        }
        // The wall and the manual were the two pages that did NOT read the
        // user's theme; keep them wired.
        let mut pages: Vec<(&str, &str)> = vec![
            ("dashboard", DASHBOARD_HTML),
            ("wall", WALL_HTML),
            ("manual", MANUAL_HTML),
        ];
        for lang in UI_LOCALES {
            if let Some(m) = manual_i18n(lang) {
                pages.push(("manual-i18n", m));
            }
        }
        for (name, page) in pages {
            assert!(page.contains(MARK), "{name} has no tokens placeholder");
            // No page may keep a private palette that would shadow the
            // shared one.
            assert!(
                !page.contains("--bg:#0a0b10") && !page.contains("--bg:#0f1116"),
                "{name} still carries its own background token"
            );
            assert!(
                !ui_themed(page).contains(MARK),
                "{name} kept a stray placeholder"
            );
        }
    }

    /// BUG (HIGH): a second top-level `function num(v)` - a floor-and-clamp
    /// helper for three server-form boxes - was declared in the same single
    /// `<script>` block as the locale-aware `function num(v, d)` formatter.
    /// Duplicate top-level declarations are legal JS and hoisting makes the
    /// LAST one win, so the 1-arg version became the only `num` on the page
    /// and every size, speed and percentage lost its decimals: a 1727.39 MB
    /// queue item rendered as "1 GB", a 3.4 MB par2 volume as "3 MB", and
    /// the Intl decimal-comma path went dead for comma locales.
    ///
    /// `node --check` cannot catch this (the file is valid JS), so the
    /// guard is a source-level one: no name may be declared twice at the
    /// top level of a served page.
    #[cfg(feature = "indexer")]
    #[test]
    fn no_served_page_declares_the_same_function_twice() {
        for (name, page) in [("dashboard", DASHBOARD_HTML), ("wall", WALL_HTML)] {
            // Column 0 only: that is exactly the top-level scope the whole
            // page shares. Nested declarations are indented and are fine.
            let mut seen: Vec<&str> = Vec::new();
            let mut dupes: Vec<&str> = Vec::new();
            for line in page.lines() {
                let rest = line
                    .strip_prefix("function ")
                    .or_else(|| line.strip_prefix("async function "));
                let Some(rest) = rest else { continue };
                let ident = rest.split(|c: char| !(c.is_alphanumeric() || c == '_' || c == '$'));
                let Some(ident) = ident.into_iter().next().filter(|s| !s.is_empty()) else {
                    continue;
                };
                if seen.contains(&ident) {
                    dupes.push(ident);
                } else {
                    seen.push(ident);
                }
            }
            assert!(
                dupes.is_empty(),
                "{name}: {dupes:?} declared twice at the top level - the later one silently \
                 shadows the earlier for the WHOLE page"
            );
        }

        // And the formatter specifically: it is the one that got shadowed,
        // and it must keep the digit-count argument that ~20 call sites pass.
        assert!(
            DASHBOARD_HTML.contains("function num(v,d){"),
            "the locale-aware number formatter is gone"
        );
        assert!(
            !DASHBOARD_HTML.contains("function num(v){"),
            "a 1-arg num() is back and shadows the formatter"
        );
    }

    #[test]
    fn url_host_parses_the_shapes_that_show_up() {
        assert_eq!(url_host("http://a.example/x"), "a.example");
        assert_eq!(url_host("https://A.Example:443"), "a.example");
        assert_eq!(url_host("http://a.example?q=1"), "a.example");
        assert_eq!(url_host("http://a.example#f"), "a.example");
        assert_eq!(url_host("http://[::1]:8080/x"), "[::1]");
        assert_eq!(url_host("ftp://a.example/x"), "");
        assert_eq!(url_host("/relative"), "");
    }

    /// THE TRAP in masking the notification token: `saveNotify` rebuilds
    /// the whole list from the DOM and the daemon replaces it wholesale,
    /// so masking without merging would make the next Apply write
    /// `token: ""` and destroy every stored credential.
    #[test]
    fn a_blank_token_keeps_the_stored_one() {
        use crate::notify::{Kind, Target};
        let t = |name: &str, kind: Kind, url: &str, token: &str| Target {
            name: name.into(),
            kind,
            url: url.into(),
            token: token.into(),
            body: String::new(),
            enabled: true,
            on_failure: false,
            category: String::new(),
        };
        let old = vec![
            t("Plex", Kind::Plex, "http://nas:32400", "PLEXTOKEN"),
            t("Jelly", Kind::Jellyfin, "http://nas:8096", "JELLYKEY"),
        ];
        // Reordered and edited, both tokens blank as the UI sends them.
        let mut incoming = vec![
            t("Jelly", Kind::Jellyfin, "http://nas:8096", ""),
            // Port corrected: no exact match, but only one Plex named Plex.
            t("Plex", Kind::Plex, "http://nas:32401", ""),
            // Brand new row: nothing to carry forward.
            t("Hook", Kind::Webhook, "https://discord/x", ""),
        ];
        super::merge_notify_tokens(&mut incoming, &old);
        assert_eq!(
            incoming[0].token, "JELLYKEY",
            "reordering must not lose a token"
        );
        assert_eq!(
            incoming[1].token, "PLEXTOKEN",
            "editing the URL must not lose a token"
        );
        assert_eq!(incoming[2].token, "");

        // A token the user actually typed always wins.
        let mut typed = vec![t("Plex", Kind::Plex, "http://nas:32400", "NEW")];
        super::merge_notify_tokens(&mut typed, &old);
        assert_eq!(typed[0].token, "NEW");

        // Ambiguous (two same-kind targets with the same name, URL
        // changed): carry nothing rather than hand over the wrong one.
        let twins = vec![
            t("Plex", Kind::Plex, "http://a:32400", "A"),
            t("Plex", Kind::Plex, "http://b:32400", "B"),
        ];
        let mut moved = vec![t("Plex", Kind::Plex, "http://c:32400", "")];
        super::merge_notify_tokens(&mut moved, &twins);
        assert_eq!(moved[0].token, "");
    }

    /// BUG (LOW, credential leak): the (kind, name) fallback did not check
    /// whether the stored target it landed on was ALREADY claimed by an
    /// exact (kind, url, name) match on a different incoming row. Adding a
    /// second same-kind target that happens to share a name with an
    /// existing one therefore copied the first one's token onto it - a
    /// credential sent to a server that was never meant to have it.
    #[test]
    fn a_token_is_never_carried_onto_a_second_target_of_the_same_name() {
        use crate::notify::{Kind, Target};
        let t = |name: &str, kind: Kind, url: &str, token: &str| Target {
            name: name.into(),
            kind,
            url: url.into(),
            token: token.into(),
            body: String::new(),
            enabled: true,
            on_failure: false,
            category: String::new(),
        };
        // One stored Plex server.
        let old = vec![t("Living Room", Kind::Plex, "http://a:32400", "TOKEN-A")];
        // The user keeps it and adds a SECOND Plex server, reusing the
        // name (a rename they have not got round to, or just a habit).
        let mut incoming = vec![
            t("Living Room", Kind::Plex, "http://a:32400", ""),
            t("Living Room", Kind::Plex, "http://b:32400", ""),
        ];
        super::merge_notify_tokens(&mut incoming, &old);
        assert_eq!(
            incoming[0].token, "TOKEN-A",
            "the target it actually belongs to keeps it"
        );
        assert_eq!(
            incoming[1].token, "",
            "a brand new server must not inherit another's token"
        );

        // Same, with the exact-matching row placed second: the fallback
        // must not depend on the order rows arrive in.
        let mut reordered = vec![
            t("Living Room", Kind::Plex, "http://b:32400", ""),
            t("Living Room", Kind::Plex, "http://a:32400", ""),
        ];
        super::merge_notify_tokens(&mut reordered, &old);
        assert_eq!(
            reordered[0].token, "",
            "a brand new server must not inherit another's token"
        );
        assert_eq!(reordered[1].token, "TOKEN-A");

        // A row whose token the user TYPED still claims its stored twin:
        // that credential is being replaced, not made available to a
        // different server that shares the name.
        let mut typed = vec![
            t("Living Room", Kind::Plex, "http://a:32400", "TYPED"),
            t("Living Room", Kind::Plex, "http://b:32400", ""),
        ];
        super::merge_notify_tokens(&mut typed, &old);
        assert_eq!(typed[0].token, "TYPED");
        assert_eq!(
            typed[1].token, "",
            "the replaced credential is not up for grabs either"
        );

        // The legitimate case must still work: the ONLY row of that
        // (kind, name) had its host corrected, so the token follows it.
        let mut corrected = vec![t("Living Room", Kind::Plex, "http://a:32401", "")];
        super::merge_notify_tokens(&mut corrected, &old);
        assert_eq!(
            corrected[0].token, "TOKEN-A",
            "correcting a port must not drop the token"
        );
    }

    /// The unpack-space forecast has to count the decrypt's temp copy.
    ///
    /// Real case (a tester, 2 Aug): a 13.85 GB RAR5 ENCRYPTED set on a
    /// disk with 15.6 GB free. The volumes fit, so the download ran to
    /// completion and the unpack then died with the disk full. Counting
    /// "volumes + payload" would have told them to free ~12 GB, they
    /// would have freed it, and the finish decrypt - which writes the
    /// plaintext into a temp beside the ciphertext before renaming -
    /// would have failed them a second time.
    #[test]
    fn an_encrypted_set_is_forecast_a_copy_higher_than_a_plain_one() {
        const GB: u64 = 1_000_000_000;
        // Nothing fetched yet: parts + payload.
        assert_eq!(
            unpack_space_needed(10 * GB, 10 * GB, "rar5 store on-disk"),
            20 * GB
        );
        // Same set, encrypted: the decrypt's temp is a third copy.
        assert_eq!(
            unpack_space_needed(10 * GB, 10 * GB, "rar5 store encrypted on-disk"),
            30 * GB
        );
        // The tester's job, fully downloaded (nothing left to fetch):
        // the honest answer is two more copies, not one.
        assert_eq!(
            unpack_space_needed(0, 13_850 * 1_000_000, "rar5 encrypted unlock-at-end"),
            27_700 * 1_000_000
        );
        // A NESTED set materializes one more layer than it looks: the
        // outer volumes stay on disk, level 0's output IS the inner
        // archive, and level 1's is the payload. So a fully-downloaded
        // 20 GB nested set needs the payload AND the intermediate, where
        // this used to promise only the payload - and the job then hit
        // ENOSPC at the second level with the whole download paid for.
        assert_eq!(
            unpack_space_needed(0, 20 * GB, "rar5 store on-disk inner-rar"),
            40 * GB
        );
        assert_eq!(
            unpack_space_needed(0, 20 * GB, "rar5 store on-disk inner-7z"),
            40 * GB
        );
        // Encrypted AND nested pays for both.
        assert_eq!(
            unpack_space_needed(0, 10 * GB, "rar5 encrypted on-disk inner-rar"),
            30 * GB
        );
        // The plain set beside them is untouched: whole tokens only.
        assert_eq!(
            unpack_space_needed(0, 20 * GB, "rar5 store on-disk"),
            20 * GB
        );
        // Which shapes get a forecast at all: the ones that materialize.
        assert!(shape_unpacks_on_disk("rar5 store encrypted on-disk"));
        assert!(shape_unpacks_on_disk("rar5 store encrypted unlock-at-end"));
        assert!(shape_unpacks_on_disk("rar4 mixed-pass"));
        // A clean one-pass set never holds both at once.
        assert!(!shape_unpacks_on_disk("rar5 store one-pass"));
        assert!(!shape_unpacks_on_disk(""));
        // Saturating, not panicking, on absurd sizes.
        assert_eq!(
            unpack_space_needed(u64::MAX, u64::MAX, "encrypted on-disk"),
            u64::MAX
        );
    }

    /// BUG (MEDIUM): deleting an active download aborts the pipeline,
    /// which surfaces as an Err and files the job Failed - so a
    /// cancellation ran the pp-script, sent a "Failed" notification and
    /// reported a healthy post to the indexer as dead.
    #[test]
    fn a_deleted_job_owes_the_outside_world_nothing() {
        assert_eq!(post_job_duties(JobState::Failed, true, "regrab"), None);
        assert_eq!(post_job_duties(JobState::Failed, true, "report"), None);
        // The success race: the fetch returned Ok just before the abort
        // landed. Still deleted, still owes nothing.
        assert_eq!(post_job_duties(JobState::Completed, true, "report"), None);
        // An ordinary failure still reports; an ordinary completion does
        // not, and neither does a failure with the feature off.
        assert_eq!(
            post_job_duties(JobState::Failed, false, "report"),
            Some(true)
        );
        assert_eq!(post_job_duties(JobState::Failed, false, "off"), Some(false));
        assert_eq!(
            post_job_duties(JobState::Completed, false, "regrab"),
            Some(false)
        );
    }

    /// BUG (MEDIUM): a LOCAL fault reported to the indexer as a dead post.
    /// The two policies that read `fail_message` - the auto-retry
    /// cooldown and the dead-post report - now share one classifier.
    #[test]
    fn only_a_dead_post_is_reported_to_the_indexer() {
        // The feature's core cases must still report.
        assert!(
            fail_kind(
                "download incomplete: 3 file(s) with missing segments, 0 decode/write errors"
            )
            .post_unavailable()
        );
        assert!(
            fail_kind("verification failed and PAR2 repair could not complete").post_unavailable()
        );
        assert!(
            fail_kind("pre-flight: articles missing beyond repair (12 segments)")
                .post_unavailable()
        );
        assert!(fail_kind("content no longer retrievable").post_unavailable());

        // Local faults must not - none of these say anything about the post.
        for local in [
            crate::incomplete_reason(0, 7, &no_causes()),
            "No space left on device (os error 28)".to_string(),
            "Permission denied (os error 13)".to_string(),
            "no usable servers".to_string(),
            "password required to unpack".to_string(),
            "an archive in the output directory could not be unpacked".to_string(),
            "the nested-archive pass failed".to_string(),
        ] {
            assert!(
                !fail_kind(&local).post_unavailable(),
                "must not report: {local}"
            );
        }

        // And the auto-retry policy agrees with itself: waiting can fix a
        // missing article or an unfinished repair, but it cannot empty a
        // full disk - retrying that just runs into the same disk again.
        assert!(
            fail_kind(
                "download incomplete: 1 file(s) with missing segments, 0 decode/write errors"
            )
            .transient()
        );
        assert!(fail_kind("verification failed and PAR2 repair could not complete").transient());
        assert!(!fail_kind(&crate::incomplete_reason(0, 7, &no_causes())).transient());
        // Appended cause clauses (retention / dead server) must not shift
        // the classification: still MissingArticles, still transient.
        let hosts = ["news.x.example".to_string()];
        let with_causes = crate::incomplete_reason(
            2,
            0,
            &crate::LossCauses {
                missing_430: 4,
                retention_excluded: 900,
                dead_servers: &hosts,
                ..no_causes()
            },
        );
        assert!(fail_kind(&with_causes).post_unavailable(), "{with_causes}");
        assert!(fail_kind(&with_causes).transient(), "{with_causes}");

        // All-transport losses are the provider's weather, not the
        // post's health: auto-retry yes, indexer dead-post report NO.
        let transport = crate::incomplete_reason(
            3,
            0,
            &crate::LossCauses {
                transport_failed: 12,
                ..no_causes()
            },
        );
        assert!(
            transport.starts_with("download failed on connection errors"),
            "{transport}"
        );
        assert!(!fail_kind(&transport).post_unavailable(), "{transport}");
        assert!(fail_kind(&transport).transient(), "{transport}");

        // A post where every backbone that answered said 430 to every
        // article is DEAD, not damaged. Reported to the indexer like any
        // missing-article failure - but NOT transient: the one automatic
        // retry exists because propagation fills gaps in, and there is no
        // gap here to fill. (Seen in the field, 31 Jul: six minutes and
        // 0 bytes, twice.)
        let gone = crate::incomplete_reason(
            94,
            0,
            &crate::LossCauses {
                missing_430: 12_018,
                missing_segments: 12_018,
                total_segments: 12_018,
                bytes_arrived: 0,
                post_age_days: 21,
                ..no_causes()
            },
        );
        assert!(gone.starts_with("post is gone"), "{gone}");
        assert!(fail_kind(&gone).post_unavailable(), "{gone}");
        assert!(!fail_kind(&gone).transient(), "{gone}");
        // The build tag appends to it like anything else, and an *arr
        // still reads it as health so the grab moves to another release.
        assert!(
            !fail_kind(&crate::with_build(gone.clone())).transient(),
            "{gone}"
        );
        assert_eq!(
            super::nzbget_status(&job(json!({
                "nzo_id": "g", "name": "Show.2160p", "nzb_path": "/spool/g.nzb",
                "state": "Failed", "out_dir": "/dl/g", "fail_message": gone,
            }))),
            ("FAILURE/HEALTH", "NONE", "NONE")
        );
        // And the *arr-facing NZBGet mapping calls it health, so a
        // client moves on rather than blaming repair or the machine.
        assert_eq!(
            super::nzbget_status(&job(json!({
                "nzo_id": "t", "name": "Show.1080p", "nzb_path": "/spool/t.nzb",
                "state": "Failed", "out_dir": "/dl/t", "fail_message": transport,
            }))),
            ("FAILURE/HEALTH", "NONE", "NONE")
        );
        // The version tag a job failure now carries must not disturb any
        // of this - it appends after everything.
        let tagged = crate::with_build(transport);
        assert!(!fail_kind(&tagged).post_unavailable(), "{tagged}");
        assert!(!fail_kind("content no longer retrievable").transient());
        // A takedown verdict is a real dead post, but not worth retrying.
        assert!(!fail_kind("pre-flight: articles missing beyond repair").transient());
    }

    /// The wire tokens the drawer switches on. Pinned because they are an
    /// API: renaming one silently drops a remedy button rather than
    /// breaking a build.
    #[test]
    fn fail_kind_tokens_are_stable() {
        for (msg, want) in [
            (
                "download incomplete: 3 file(s) with missing segments, 0 decode/write errors",
                "missing",
            ),
            (
                "download failed on connection errors: pool stalled",
                "transport",
            ),
            (
                "verification failed and PAR2 repair could not complete",
                "unrepairable",
            ),
            (
                "pre-flight: articles missing beyond repair (12 segments)",
                "preflight",
            ),
            ("content no longer retrievable", "gone"),
            ("No space left on device (os error 28)", "local"),
        ] {
            assert_eq!(fail_kind_token(fail_kind(msg)), want, "{msg}");
        }
    }

    /// The sub-cause inside the message. Each token is keyed on a clause
    /// `incomplete_reason` (or the pool) writes verbatim, so the strings
    /// here are built by the real producers wherever possible.
    #[test]
    fn fail_hint_names_the_sub_cause() {
        let retention = crate::incomplete_reason(
            2,
            0,
            &crate::LossCauses {
                missing_430: 1,
                retention_excluded: 900,
                ..no_causes()
            },
        );
        assert_eq!(fail_hint(&retention), "retention", "{retention}");
        // A post carrying no parity at all: another release is the only
        // answer, even though the KIND is the retryable missing-articles.
        let nopar2 = crate::incomplete_reason(
            1,
            0,
            &crate::LossCauses {
                missing_430: 3,
                par2_slots: 0,
                ..no_causes()
            },
        );
        assert_eq!(fail_hint(&nopar2), "nopar2", "{nopar2}");
        assert_eq!(fail_kind(&nopar2), FailKind::MissingArticles, "{nopar2}");
        // Both forms of the empty pool, including the build tag that gets
        // appended to every job failure.
        for msg in [
            "no usable servers: none are set up yet - add your provider in Server settings",
            "no usable servers: every one you have set up is out of the pool right now - \
             news.x.example (switched off)",
        ] {
            assert_eq!(fail_hint(msg), "servers", "{msg}");
        }
        // A plain failure has no sub-cause and falls back to its kind.
        assert_eq!(fail_hint("Permission denied (os error 13)"), "");
        let plain = crate::incomplete_reason(
            2,
            0,
            &crate::LossCauses {
                missing_430: 4,
                par2_slots: 9,
                ..no_causes()
            },
        );
        assert_eq!(fail_hint(&plain), "", "{plain}");
    }

    /// ONE action per failure, and never the useless one: the audit found
    /// every kind sharing a single Retry, including the two the daemon
    /// itself classifies as unfixable by retrying.
    #[test]
    fn each_failure_gets_the_action_that_can_help() {
        let act = |msg: &str, pw: bool| fail_action(fail_kind(msg), fail_hint(msg), msg, pw);
        // Waiting genuinely helps these two, and only these two.
        assert_eq!(
            act(
                "download incomplete: 1 file(s) with missing segments, 0 decode/write errors",
                false
            ),
            "retry"
        );
        assert_eq!(
            act("download failed on connection errors: pool stalled", false),
            "retry"
        );
        // A dead post, a pre-flight verdict and an unrepairable set are
        // all answered by another release, never by asking again.
        for msg in [
            "content no longer retrievable",
            "pre-flight: articles missing beyond repair (12 segments)",
            "verification failed and PAR2 repair could not complete",
        ] {
            assert_eq!(act(msg, false), "search", "{msg}");
        }
        // Sub-causes outrank the kind.
        let retention = crate::incomplete_reason(
            2,
            0,
            &crate::LossCauses {
                missing_430: 1,
                retention_excluded: 900,
                ..no_causes()
            },
        );
        assert_eq!(act(&retention, false), "retention", "{retention}");
        assert_eq!(
            act("no usable servers: none are set up yet", false),
            "servers"
        );
        // ...and the two that outrank everything. Both are `Local`, and
        // "show the folder" answers neither of them.
        assert_eq!(act("No space left on device (os error 28)", false), "space");
        assert_eq!(act("unpack failed", true), "password");
        // A full disk stays a full disk even for a locked archive: the
        // password prompt is the thing that can actually be completed.
        assert_eq!(
            act("No space left on device (os error 28)", true),
            "password"
        );
        // Everything else local: the folder is where the evidence is.
        assert_eq!(act("Permission denied (os error 13)", false), "path");
    }

    /// Six watch-folder states, four of which are SUCCESSES. The strip
    /// showed one sentence for all six and offered a Delete that destroys
    /// the only copy in exactly the states where it is not safe.
    #[test]
    fn watch_folder_states_are_told_apart() {
        use super::tasks::{watch_fail_ingested, watch_fail_kind, watchfail};
        for (msg, kind, ingested) in [
            (watchfail::TRUNCATED.to_string(), "truncated", false),
            (watchfail::ALREADY_QUEUED.to_string(), "queued", true),
            (watchfail::ALREADY_DONE.to_string(), "done", true),
            (watchfail::UNSAVED.to_string(), "unsaved", true),
            (
                format!("{}: Permission denied (os error 13)", watchfail::KEPT),
                "kept",
                true,
            ),
            (
                "not an NZB: no <nzb> element".to_string(),
                "rejected",
                false,
            ),
        ] {
            assert_eq!(watch_fail_kind(&msg), kind, "{msg}");
            assert_eq!(watch_fail_ingested(kind), ingested, "{msg}");
        }
    }

    #[test]
    fn cat_dest_list_parses_and_round_trips() {
        let list = super::parse_cat_dests(" tv = /NAS/TV, movies=/NAS/Movies ; ; ").unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].0, "tv");
        assert_eq!(list[0].1, std::path::PathBuf::from("/NAS/TV"));
        assert_eq!(
            super::fmt_cat_dests(&list),
            "tv=/NAS/TV, movies=/NAS/Movies"
        );
        // Empty clears; malformed and duplicate entries are rejected.
        assert!(super::parse_cat_dests("").unwrap().is_empty());
        assert!(super::parse_cat_dests("no-equals-here").is_err());
        assert!(super::parse_cat_dests("tv=/a, tv=/b").is_err());
        // Category names get the enqueue-path sanitizing (a traversal
        // token can't map to a folder no job ever used).
        let odd = super::parse_cat_dests("t/v=/NAS/X").unwrap();
        assert_eq!(odd[0].0, nzbkit::disk::sanitize_filename("t/v"));
    }

    /// The two spellings of the failure header in the wild, and the
    /// blank-header case (an indexer that sets it unconditionally).
    #[test]
    fn failure_link_header_aliases() {
        assert_eq!(
            super::pick_failure_link("http://a/fail", ""),
            "http://a/fail"
        );
        assert_eq!(
            super::pick_failure_link("", "http://b/fail"),
            "http://b/fail"
        );
        // Canonical wins when an indexer sends both.
        assert_eq!(
            super::pick_failure_link("http://a/fail", "http://b/fail"),
            "http://a/fail"
        );
        assert_eq!(super::pick_failure_link("", ""), "");
    }

    /// The body decides whether a replacement came back, not the status:
    /// indexers answer 200 with a "nothing found" page all the time, and
    /// queueing that as an NZB would fail a second job for no reason.
    #[test]
    fn only_an_xml_body_counts_as_a_replacement() {
        assert!(super::is_nzb_body(br#"<?xml version="1.0"?><nzb></nzb>"#));
        assert!(!super::is_nzb_body(
            b"<html><body>No results found</body></html>"
        ));
        assert!(!super::is_nzb_body(b""));
        // A bare <nzb> with no declaration is rejected too - same rule
        // FailureLink applies, and being stricter than the thing we are
        // matching would queue junk the reference implementation skips.
        assert!(!super::is_nzb_body(b"<nzb></nzb>"));
    }

    /// A replacement that also fails asks for another. The chain has to
    /// stop on its own, unattended, before it walks an indexer's whole
    /// run of dead posts through someone's block account.
    #[test]
    fn the_regrab_chain_stops_at_the_cap() {
        assert!(super::may_regrab("regrab", 0));
        assert!(super::may_regrab("regrab", super::FAILURE_REGRAB_MAX - 1));
        assert!(!super::may_regrab("regrab", super::FAILURE_REGRAB_MAX));
        assert!(!super::may_regrab("regrab", super::FAILURE_REGRAB_MAX + 9));
        // "report" reaches the indexer but never queues anything, and
        // "off" was already filtered out upstream - neither re-grabs.
        assert!(!super::may_regrab("report", 0));
        assert!(!super::may_regrab("off", 0));
    }

    /// End to end over a real socket: an indexer's X-DNZB headers have to
    /// survive the fetch, or the failure link is never recorded and the
    /// whole feature is silently dead. Loopback is deliberately reachable
    /// through the SSRF guard (see the test below), so this exercises the
    /// real `fetch_url`, agent and all.
    #[test]
    fn fetch_url_keeps_the_indexer_headers() {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/getnzb/abc", listener.local_addr().unwrap());
        let t = std::thread::spawn(move || {
            let (mut sock, _) = listener.accept().unwrap();
            let mut buf = [0u8; 4096];
            let _ = sock.read(&mut buf);
            let body = r#"<?xml version="1.0"?><nzb></nzb>"#;
            let _ = sock.write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\
                     X-DNZB-Failure: http://indexer/fail?id=abc\r\n\
                     X-DNZB-Category: tv\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            );
        });
        let f = super::fetch_url(&url).expect("loopback fetch");
        t.join().unwrap();
        assert_eq!(f.failure_link, "http://indexer/fail?id=abc");
        assert_eq!(f.category, "tv");
        assert!(super::is_nzb_body(&f.bytes));
    }

    /// SSRF guard: cloud-metadata / link-local is refused; loopback, LAN
    /// and CGNAT stay reachable (self-hosted indexers + Tailscale live
    /// there), as do public hosts.
    #[test]
    fn ssrf_guard_blocks_metadata_but_allows_local() {
        use std::net::IpAddr;
        let blocked = [
            "169.254.169.254",        // cloud metadata (link-local)
            "169.254.1.1",            // link-local
            "0.0.0.0",                // unspecified
            "255.255.255.255",        // broadcast
            "fe80::1",                // v6 link-local
            "::ffff:169.254.169.254", // v4-mapped metadata
            "100.100.100.200",        // Alibaba metadata (inside CGNAT)
            "fd00:ec2::254",          // AWS IPv6 IMDS (inside ULA)
        ];
        for s in blocked {
            let ip: IpAddr = s.parse().unwrap();
            assert!(super::is_forbidden_fetch_ip(ip), "should block {s}");
        }
        // Legitimate for a self-hosted downloader - must stay reachable.
        let allowed = [
            "127.0.0.1",    // local indexer on loopback
            "10.0.0.5",     // LAN
            "192.168.1.10", // LAN
            "172.16.9.9",   // LAN
            "100.64.0.1",   // Tailscale CGNAT
            "::1",          // v6 loopback
            "fc00::1",      // v6 ULA (LAN)
            "8.8.8.8",      // public
            "2606:4700:4700::1111",
        ];
        for s in allowed {
            let ip: IpAddr = s.parse().unwrap();
            assert!(!super::is_forbidden_fetch_ip(ip), "should allow {s}");
        }
    }

    // A deterministic ephemeral keypair (fixed seed) drives the crypto-path
    // tests, so they never depend on the production key and there is nothing
    // to regenerate when the embedded key rotates.
    fn test_vector() -> (String, Vec<u8>, String) {
        use ed25519_dalek::{Signer, SigningKey};
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let pub_hex = hex::encode(sk.verifying_key().to_bytes());
        let manifest = br#"{"version":"9.9.9"}"#.to_vec();
        let sig_hex = hex::encode(sk.sign(&manifest).to_bytes());
        (pub_hex, manifest, sig_hex)
    }

    #[test]
    fn manifest_signature_accepts_valid() {
        let (pk, manifest, sig) = test_vector();
        assert!(super::verify_with_key(&pk, &manifest, sig.as_bytes()).is_ok());
    }

    #[test]
    fn manifest_signature_rejects_tampered_body() {
        let (pk, manifest, sig) = test_vector();
        let mut bad = manifest.clone();
        let n = bad.len() - 3;
        bad[n] ^= 0x01;
        assert!(super::verify_with_key(&pk, &bad, sig.as_bytes()).is_err());
    }

    #[test]
    fn manifest_signature_rejects_tampered_sig() {
        let (pk, manifest, mut sig) = test_vector();
        let first = if sig.starts_with('f') { 'e' } else { 'f' };
        sig.replace_range(0..1, &first.to_string());
        assert!(super::verify_with_key(&pk, &manifest, sig.as_bytes()).is_err());
    }

    #[test]
    fn manifest_signature_rejects_wrong_key() {
        // A valid signature under one key must NOT verify under a different
        // key - this is the property that stops a foreign manifest.
        let (_pk, manifest, sig) = test_vector();
        assert!(super::verify_manifest_sig(&manifest, sig.as_bytes()).is_err());
    }

    #[test]
    fn manifest_signature_rejects_malformed_sig() {
        let (pk, manifest, _sig) = test_vector();
        assert!(super::verify_with_key(&pk, &manifest, b"not-hex").is_err());
        assert!(super::verify_with_key(&pk, &manifest, b"abcd").is_err());
        assert!(super::verify_with_key(&pk, &manifest, b"").is_err());
    }

    // ---- anti-rollback ratchet (READ-ONLY phase) ----------------------
    //
    // These pin the properties the LATER enforcing build will rely on. The
    // one thing they must also prove is that this build does not enforce:
    // a regression is recorded and warned about, never refused.

    #[test]
    fn manifest_serial_ratchet_advances_and_never_lowers() {
        use super::SerialStep::*;
        let m = |s: u64| serde_json::json!({ "version": "1.0.0", "serial": s });

        // A fresh install (seen = 0) takes whatever it is first told.
        assert_eq!(super::serial_ratchet(0, &m(100)), Advance(100));
        assert_eq!(super::serial_ratchet(100, &m(140)), Advance(140));

        // THE replay: an old, genuinely-signed manifest served again. The
        // signature is valid - only the serial catches this.
        assert_eq!(
            super::serial_ratchet(140, &m(100)),
            Regressed {
                got: 100,
                seen: 140
            }
        );

        // Re-serving the same manifest is the steady state, not a write.
        assert_eq!(super::serial_ratchet(140, &m(140)), Hold);
    }

    #[test]
    fn manifest_serial_junk_and_absence_hold_the_ratchet() {
        use super::SerialStep::*;
        // Absent: normal during the rollout. Must HOLD, not clear - if it
        // cleared, replaying a pre-serial manifest would disarm the defence.
        assert_eq!(
            super::serial_ratchet(140, &serde_json::json!({ "version": "1.0.0" })),
            Hold
        );
        // Junk must not coerce into a huge serial, which would pin the
        // install above every real release it will ever be offered.
        assert_eq!(
            super::serial_ratchet(140, &serde_json::json!({ "serial": "999999" })),
            Hold
        );
        assert_eq!(
            super::serial_ratchet(140, &serde_json::json!({ "serial": -5 })),
            Hold
        );
        assert_eq!(
            super::serial_ratchet(140, &serde_json::json!({ "serial": 1.5 })),
            Hold
        );
        assert_eq!(
            super::serial_ratchet(140, &serde_json::json!({ "serial": null })),
            Hold
        );
    }

    #[test]
    fn manifest_serial_is_not_enforced_in_this_build() {
        // The read-only guarantee, stated as a test so that flipping to
        // enforcement has to come here and change it deliberately rather
        // than inherit it. `serial_ratchet` reports a regression and that
        // is ALL it can do - there is no variant that refuses, so no
        // caller can act on one by accident.
        use super::SerialStep::*;
        let stale = serde_json::json!({ "version": "99.0.0", "serial": 1 });
        assert_eq!(
            super::serial_ratchet(500, &stale),
            Regressed { got: 1, seen: 500 }
        );
        assert!(
            super::version_newer("99.0.0", env!("CARGO_PKG_VERSION")),
            "the version comparison, which is what actually decides today, is untouched"
        );
    }

    #[test]
    fn embedded_update_key_is_well_formed() {
        // The shipped key must be a valid 32-byte ed25519 public key, or every
        // update check dies at "update key is malformed".
        let raw = hex::decode(super::UPDATE_PUBKEY_HEX).expect("pubkey hex");
        assert_eq!(raw.len(), 32, "UPDATE_PUBKEY_HEX must be 32 bytes");
        let arr: [u8; 32] = raw.try_into().unwrap();
        assert!(ed25519_dalek::VerifyingKey::from_bytes(&arr).is_ok());
    }

    #[test]
    fn parse_sizes() {
        assert_eq!(super::parse_size("500M"), Some(500_000_000));
        assert_eq!(super::parse_size("10G"), Some(10_000_000_000));
        assert_eq!(super::parse_size("1.5T"), Some(1_500_000_000_000));
        assert_eq!(super::parse_size("12345"), Some(12345));
        assert_eq!(super::parse_size("nope"), None);
    }

    // -- M34 index size cap ------------------------------------------------

    /// The order setting is a closed set. Anything else is rejected at
    /// the settings boundary, which is what lets `evict_policy` treat the
    /// stored string as always-valid.
    #[cfg(feature = "indexer")]
    #[test]
    fn evict_order_setting_accepts_exactly_the_five_orders() {
        use nzbkit::index::EvictOrder as O;
        assert!(matches!(
            super::parse_evict_order("ladder"),
            Some(O::Ladder)
        ));
        assert!(matches!(
            super::parse_evict_order("oldest"),
            Some(O::Oldest)
        ));
        assert!(matches!(
            super::parse_evict_order("newest"),
            Some(O::Newest)
        ));
        assert!(matches!(
            super::parse_evict_order("largest"),
            Some(O::Largest)
        ));
        assert!(matches!(
            super::parse_evict_order("smallest"),
            Some(O::Smallest)
        ));
        // Case and whitespace are the user's, not ours.
        assert!(matches!(
            super::parse_evict_order("  LaDdEr "),
            Some(O::Ladder)
        ));
        // Everything else, including the empty string, is refused rather
        // than silently defaulted - a typo must not quietly change which
        // rows get deleted.
        for bad in ["", "random", "ladder,oldest", "biggest", "asc"] {
            assert!(
                super::parse_evict_order(bad).is_none(),
                "{bad:?} must not parse"
            );
        }
        // The advertised list and the parser agree.
        for o in super::EVICT_ORDERS {
            assert!(
                super::parse_evict_order(o).is_some(),
                "{o} advertised but unparseable"
            );
        }
    }

    /// The kinds list is validated for a reason worth spelling out: it is
    /// a RESTRICTION ("evict only these"), so a typo does not evict the
    /// wrong thing - it evicts nothing, and the user is left staring at a
    /// cap that never frees a byte with no error anywhere.
    #[cfg(feature = "indexer")]
    #[test]
    fn evict_kinds_setting_validates_and_normalizes() {
        assert_eq!(super::parse_evict_kinds("").unwrap(), Vec::<String>::new());
        assert_eq!(
            super::parse_evict_kinds("   ").unwrap(),
            Vec::<String>::new()
        );
        assert_eq!(
            super::parse_evict_kinds(" Movie , TV ").unwrap(),
            vec!["movie".to_string(), "tv".to_string()]
        );
        // Duplicates collapse; trailing separators are ignored.
        assert_eq!(
            super::parse_evict_kinds("tv,tv,,other,").unwrap(),
            vec!["tv".to_string(), "other".to_string()]
        );
        let e = super::parse_evict_kinds("movie,film").unwrap_err();
        assert!(e.contains("film"), "the error must name the offender: {e}");
    }

    /// The wizard's answer must not read as an established install: the
    /// setup command runs as its own process, so its answer reaches
    /// settings.json before the daemon has ever started, and the
    /// first-run API key test keys off exactly that file.
    #[test]
    fn a_settings_file_of_wizard_answers_is_still_a_first_run() {
        let dir = std::env::temp_dir().join(format!("nzbfast-setupans-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("settings.json");
        let beyond = |text: &str| {
            std::fs::write(&p, text).unwrap();
            super::settings_beyond_setup_answers(&p)
        };
        assert!(
            !beyond(r#"{"index_interests":"linux,sports"}"#),
            "the wizard answer alone"
        );
        assert!(
            !beyond(r#"{"index_interests":""}"#),
            "answering \"nothing\" is an answer"
        );
        // Anything the daemon itself wrote means it has run.
        assert!(beyond(r#"{"index_interests":"linux","auto_speed":false}"#));
        assert!(beyond(r#"{"apikey":"k"}"#));
        // An empty object carries no wizard answer to explain itself, so
        // the old rule stands: the file exists, the install has run.
        assert!(beyond("{}"));
        // Unreadable or not-an-object: never mint over state we cannot
        // parse.
        assert!(beyond("[1,2,3]"));
        assert!(beyond("this is not json"));
        // A missing file is the caller's case, and answers false here.
        std::fs::remove_file(&p).unwrap();
        assert!(!super::settings_beyond_setup_answers(&p));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rename_punctuation_defaults_preserve_upgrades_only() {
        let dir =
            std::env::temp_dir().join(format!("nzbfast-rename-upgrade-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let config = dir.join("nzbfast.toml");
        let out = dir.join("downloads");
        let settings = dir.join("settings.json");

        assert!(
            !super::legacy_rename_punctuation(&config, &out, &settings),
            "a genuinely fresh install gets the new unpunctuated default"
        );
        std::fs::write(&settings, r#"{"index_interests":"tv"}"#).unwrap();
        assert!(
            !super::legacy_rename_punctuation(&config, &out, &settings),
            "the setup wizard runs before the daemon but is still a fresh install"
        );
        std::fs::write(&settings, "{}").unwrap();
        assert!(
            super::legacy_rename_punctuation(&config, &out, &settings),
            "an established settings file preserves the historical punctuation"
        );

        std::fs::remove_file(&settings).unwrap();
        std::fs::create_dir_all(config.with_file_name(".spool")).unwrap();
        assert!(
            super::legacy_rename_punctuation(&config, &out, &settings),
            "pre-settings installs are also identified by their existing spool"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A scratch data dir + download dir, returned as (dir, config, out).
    /// `new` is the spool beside the config, `old` the one in the download
    /// folder. An empty `new` is created as an empty DIRECTORY (that is the
    /// placeholder case); an empty `old` is not created at all (there is no
    /// leftover to find).
    fn spool_case(name: &str, new: &[&str], old: &[&str]) -> (PathBuf, PathBuf, PathBuf) {
        let dir = std::env::temp_dir().join(format!("nzbfast-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let config = dir.join("config.local.json");
        let out = dir.join("downloads");
        std::fs::create_dir_all(dir.join(".spool")).unwrap();
        for f in new {
            std::fs::write(dir.join(".spool").join(f), f.as_bytes()).unwrap();
        }
        if !old.is_empty() {
            std::fs::create_dir_all(out.join(".spool")).unwrap();
            for f in old {
                std::fs::write(out.join(".spool").join(f), f.as_bytes()).unwrap();
            }
        }
        (dir, config, out)
    }

    /// The report this fixes: Gary's `Downloads\nzbfast\.spool` was still
    /// there on 1.0.10, months after the state moved to the data dir. The
    /// old migration returned the instant the new spool existed and never
    /// looked at what it had left in the download folder.
    ///
    /// The live spool must be untouched (it is the state the daemon runs
    /// on), the download folder must come out clean, and the residue must
    /// still be findable rather than deleted.
    #[test]
    fn a_leftover_download_spool_is_retired_out_of_the_download_folder() {
        let (dir, config, out) = spool_case("retire-leftover", &["queue.json"], &["queue.json"]);
        let spool = super::spool_dir(&config, &out);

        assert_eq!(
            spool,
            dir.join(".spool"),
            "the live spool is the migrated one"
        );
        assert!(!out.join(".spool").exists(), "the download folder is clean");
        assert_eq!(
            std::fs::read_to_string(spool.join("queue.json")).unwrap(),
            "queue.json",
            "the live queue is the one the daemon has been running on"
        );
        assert!(
            spool.join("legacy-spool/queue.json").exists(),
            "the residue is retired, not deleted"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Two leftovers are two installs' residue, so the second gets its own
    /// name instead of merging into a directory that never existed.
    #[test]
    fn a_second_leftover_spool_lands_beside_the_first() {
        let (dir, config, out) = spool_case("retire-twice", &["queue.json"], &["a.nzb"]);
        super::spool_dir(&config, &out);
        std::fs::create_dir_all(out.join(".spool")).unwrap();
        std::fs::write(out.join(".spool/b.nzb"), "b").unwrap();
        let spool = super::spool_dir(&config, &out);

        assert!(spool.join("legacy-spool/a.nzb").exists());
        assert!(spool.join("legacy-spool-1/b.nzb").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An empty spool at the new location is a placeholder, not a completed
    /// migration. Taking it as one would start the daemon on an empty queue
    /// while the real state sat in the download folder - and then save that
    /// empty queue over it.
    #[test]
    fn an_empty_new_spool_does_not_pass_for_a_migration() {
        let (dir, config, out) = spool_case("empty-placeholder", &[], &["queue.json"]);
        let spool = super::spool_dir(&config, &out);

        assert_eq!(
            std::fs::read_to_string(spool.join("queue.json")).unwrap(),
            "queue.json",
            "the real state migrates instead of being shadowed by the placeholder"
        );
        assert!(
            !spool.join("legacy-spool").exists(),
            "a migration is not a retirement"
        );
        assert!(!out.join(".spool").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The ordinary path: nothing in the download folder, nothing to do.
    /// In particular `spool_dir` must not CREATE the spool - the caller
    /// does that, after it has decided which path it is.
    #[test]
    fn a_clean_install_has_nothing_to_migrate_or_retire() {
        let (dir, config, out) = spool_case("no-leftover", &["queue.json"], &[]);
        let spool = super::spool_dir(&config, &out);

        assert_eq!(spool, dir.join(".spool"));
        assert!(!out.join(".spool").exists());
        assert!(!spool.join("legacy-spool").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A watchlist entry protects the index rows the watcher would match.
    /// TV keys carry no year, so they are exact; a film pinned to a year
    /// ALSO protects the year-less form, because a stem with no year in
    /// it parses to `m:<title>` and is the same film.
    #[cfg(feature = "indexer")]
    #[test]
    fn watchlist_entry_yields_the_keys_its_releases_carry() {
        let item = |kind: &str, title: &str, year: Option<u32>| crate::watchlist::WatchItem {
            id: 1,
            kind: kind.into(),
            title: title.into(),
            year,
            seasons: String::new(),
            episodes: String::new(),
            min_quality: String::new(),
            target_quality: "1080p".into(),
            upgrade: true,
            delete_old: false,
            category: String::new(),
            min_age: String::new(),
            max_age: String::new(),
            enabled: true,
        };
        assert_eq!(
            super::watch_item_keys(&item("tv", "The Wire", None)),
            ["t:the wire"]
        );
        assert_eq!(
            super::watch_item_keys(&item("movie", "The Matrix", Some(1999))),
            ["m:the matrix:1999", "m:the matrix"]
        );
        assert_eq!(
            super::watch_item_keys(&item("movie", "Dune", None)),
            ["m:dune"]
        );
        // 24D: a custom entry protects its category's own key space. The
        // bare form is what the episodic and daily shapes key on; the
        // tailed keys one-per-event live in the index, and protected_set
        // resolves those by prefix.
        assert_eq!(
            super::watch_item_keys(&item("formula-1", "Formula1", None)),
            ["c:formula-1:formula1"]
        );
        // Nothing to protect from a blank entry - and crucially, NOT the
        // key "t:" or "m:", which would match every unparsed row.
        assert!(super::watch_item_keys(&item("tv", "   ", None)).is_empty());
    }

    /// The protected set is the whole point of the feature: everything in
    /// it is data the user explicitly asked to keep. All four categories
    /// must survive the assembly, and the assembly must not lose one to
    /// deduplication against another.
    #[cfg(feature = "indexer")]
    #[test]
    fn protected_set_carries_all_four_categories() {
        let p = super::assemble_protected(
            // 1. watchlisted
            vec!["t:the wire".into(), "m:dune".into()],
            // 2 + 3. queued/downloading, and completed history - the
            // daemon's single "owned" key set covers both.
            vec!["t:severance".into(), "m:heat:1995".into()],
            // 4. recently opened (detail sheet)
            vec!["m:arrival:2016".into(), "t:the wire".into()],
            // 4. recently opened (getnzb / queued by id)
            vec![42, 7, 42],
        );
        for want in [
            "t:the wire",     // watchlisted
            "m:dune",         // watchlisted, no year pinned
            "t:severance",    // queued
            "m:heat:1995",    // downloaded
            "m:arrival:2016", // opened
        ] {
            assert!(
                p.title_keys.iter().any(|k| k == want),
                "{want} dropped out of the protected set: {:?}",
                p.title_keys
            );
        }
        // A key in two categories appears once, not twice - the engine
        // binds these as SQL parameters and duplicates are pure waste.
        assert_eq!(
            p.title_keys.iter().filter(|k| *k == "t:the wire").count(),
            1
        );
        assert_eq!(p.title_keys.len(), 5);
        assert_eq!(p.release_ids, vec![7, 42]);
    }

    /// An empty protected set is an empty protected set - it must not
    /// pick up a stray "" key, which would match every unparsed row and
    /// quietly protect the junk the cap exists to shed.
    #[cfg(feature = "indexer")]
    #[test]
    fn protected_set_never_contains_the_empty_key() {
        let p = super::assemble_protected(
            vec![String::new()],
            vec![String::new(), "t:x".into()],
            vec![String::new()],
            vec![-1, 3],
        );
        assert_eq!(p.title_keys, ["t:x"]);
    }

    /// The touch log is the "recently opened" protection. It coalesces
    /// (browsing a card twice is one signal), it expires, and it is
    /// bounded - a scripted crawl of the wall cannot grow the file
    /// without limit or pin the whole database forever.
    #[cfg(feature = "indexer")]
    #[test]
    fn opened_log_coalesces_expires_and_stays_bounded() {
        let mut log = super::OpenedLog::default();
        let t0 = 1_700_000_000i64;
        // First touch is news (persist); the same key a minute later is not.
        assert!(log.touch_title("t:the wire", t0));
        assert!(!log.touch_title("t:the wire", t0 + 60));
        // ...but after the coalesce window it is worth persisting again.
        assert!(log.touch_title("t:the wire", t0 + 2 * super::OPENED_COALESCE_SECS));
        // A blank key is not a signal.
        assert!(!log.touch_title("", t0));
        assert!(log.titles.len() == 1);

        assert!(log.touch_release(5, t0));
        assert!(!log.touch_release(5, t0 + 1));
        // A parse failure gives id -1; that is not a release.
        assert!(!log.touch_release(-1, t0));
        assert_eq!(log.releases.len(), 1);

        // Expiry drops what has aged past the protection window and keeps
        // what has not.
        let window = super::OPENED_PROTECT_DAYS * 86_400;
        log.touch_title("t:old", t0 - window - 1);
        log.expire(t0 + 2 * super::OPENED_COALESCE_SECS, window);
        assert!(!log.titles.contains_key("t:old"));
        assert!(log.titles.contains_key("t:the wire"));

        // Bounded: oldest touches drop first.
        let mut big = super::OpenedLog::default();
        for i in 0..(super::OPENED_MAX_ENTRIES + 50) {
            big.touch_title(&format!("t:{i}"), t0 + i as i64);
        }
        assert_eq!(big.titles.len(), super::OPENED_MAX_ENTRIES);
        assert!(
            !big.titles.contains_key("t:0"),
            "oldest should have been trimmed"
        );
        assert!(
            big.titles
                .contains_key(&format!("t:{}", super::OPENED_MAX_ENTRIES + 49))
        );
    }

    /// A failed index read and an empty index must not look alike to the
    /// wall. The wall latches the first `latest` it receives as its
    /// cursor, so answering a failure with 0 - which is what
    /// `.unwrap_or_default()` did - made the NEXT successful poll report
    /// every non-junk title posted in the last week as an arrival: the
    /// pill claiming 890,000 arrivals, arrived at from the other side.
    #[cfg(feature = "indexer")]
    #[test]
    fn a_failed_tip_read_is_not_a_cursor_of_zero() {
        use nzbkit::index::TipInfo;

        // The index could not be read at all.
        let failed = super::wall_tip_body(None, true);
        assert!(
            failed["latest"].is_null(),
            "a failed read must not answer with a number the wall can latch: {failed}"
        );
        assert_eq!(failed["new"], 0);
        // The browser drops it on exactly this test, so it has to hold.
        assert!(!failed["latest"].is_i64() && !failed["latest"].is_f64());

        // An EMPTY index is a different thing and still reports a real,
        // usable cursor of 0 - the fix must not have made zero unusable.
        let empty = super::wall_tip_body(
            Some(TipInfo {
                latest: 0,
                new_keys: 0,
                keys: Vec::new(),
            }),
            true,
        );
        assert_eq!(
            empty["latest"], 0,
            "an empty index has a genuine zero cursor"
        );

        // And a first poll (`since=-1`) still reports the mark while
        // announcing nothing, which is the case that comment exists for.
        let first = super::wall_tip_body(
            Some(TipInfo {
                latest: 890_000,
                new_keys: 890_000,
                keys: vec!["t:x".into()],
            }),
            false,
        );
        assert_eq!(first["latest"], 890_000);
        assert_eq!(first["new"], 0, "'I just got here' announces nothing");
        assert_eq!(first["keys"].as_array().map(Vec::len), Some(0));
    }

    /// The daemon half above is only half the fix: the poll must actually
    /// refuse to latch a non-number. This greps the shipped wall for that
    /// guard because the HTML is embedded in the binary, so a regression
    /// here ships silently.
    #[cfg(feature = "indexer")]
    #[test]
    fn the_wall_poll_refuses_to_latch_a_failed_tip() {
        let poll = WALL_HTML
            .split("async function tipPoll")
            .nth(1)
            .and_then(|s| s.split("function renderPill").next())
            .expect("wall.html no longer has a tipPoll to guard");
        assert!(
            poll.contains("typeof j.latest!=='number'"),
            "the arrivals poll must drop a tip it cannot read as a number"
        );
        // The guard has to come BEFORE the latch, or it guards nothing.
        let guard = poll.find("typeof j.latest!=='number'").unwrap();
        let latch = poll.find("tipMark=j.latest").expect("the latch moved");
        assert!(guard < latch, "the guard must precede the latch");
    }

    /// `compact_verdict` only answers "is a download running?" once, a
    /// moment before the rewrite starts - and the rewrite then holds the
    /// very gate a starting download waits on. A job arriving one moment
    /// later used to sit in `Downloading` with no progress and nothing
    /// logged for the whole VACUUM: measured on a 175 MB database that is
    /// ~0.5 s, so on the multi-GB indexes this feature exists for it is
    /// minutes. The watcher keeps asking, and can still act on the answer.
    #[cfg(feature = "indexer")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_download_that_starts_mid_vacuum_aborts_it() {
        use std::sync::atomic::{AtomicBool, AtomicUsize};

        // The rewrite is under way and a job turns up.
        let jobs = Arc::new(AtomicUsize::new(0));
        let done = Arc::new(AtomicBool::new(false));
        let aborts = Arc::new(AtomicUsize::new(0));
        let watch = {
            let (j, d, a) = (jobs.clone(), done.clone(), aborts.clone());
            tokio::spawn(super::abort_compact_when_job_starts(j, d, move || {
                a.fetch_add(1, Ordering::Release);
            }))
        };
        // Two poll intervals of quiet: nothing is downloading, so the
        // rewrite must be left alone.
        tokio::time::sleep(std::time::Duration::from_millis(
            super::COMPACT_ABORT_POLL_MS * 2 + 50,
        ))
        .await;
        assert_eq!(
            aborts.load(Ordering::Acquire),
            0,
            "an idle box must not lose its compact"
        );

        jobs.fetch_add(1, Ordering::Release);
        // Bounded, because the failure this guards against is a download
        // that waits forever: without the timeout a watcher that never
        // notices hangs the whole suite instead of naming the bug.
        let saw = tokio::time::timeout(std::time::Duration::from_secs(5), watch)
            .await
            .expect("the watcher never noticed the download - this is the stall itself")
            .unwrap();
        assert!(saw, "a starting download must abort the rewrite");
        assert_eq!(
            aborts.load(Ordering::Acquire),
            1,
            "and abort it exactly once"
        );

        // The other order: the rewrite finished first, so there is no
        // statement left to interrupt. Interrupting is per-CONNECTION, so
        // a late abort would hit whatever the index does next instead.
        let jobs = Arc::new(AtomicUsize::new(0));
        let done = Arc::new(AtomicBool::new(false));
        let aborts = Arc::new(AtomicUsize::new(0));
        let watch = {
            let (j, d, a) = (jobs.clone(), done.clone(), aborts.clone());
            tokio::spawn(super::abort_compact_when_job_starts(j, d, move || {
                a.fetch_add(1, Ordering::Release);
            }))
        };
        done.store(true, Ordering::Release);
        jobs.fetch_add(1, Ordering::Release);
        assert!(!watch.await.unwrap(), "a finished rewrite is not aborted");
        assert_eq!(
            aborts.load(Ordering::Acquire),
            0,
            "and nothing else gets interrupted"
        );
    }

    /// The compaction rule the user chose: never interrupt anything.
    /// VACUUM waits for a moment with no scan pass and no download, and
    /// it also waits for room - it rewrites the whole file beside the
    /// original, and these run on NAS boxes.
    #[cfg(feature = "indexer")]
    #[test]
    fn compaction_defers_while_busy_and_fires_when_idle() {
        use super::CompactVerdict as V;
        let gb: u64 = 1 << 30;
        let plenty = Some(64 * gb);

        // Nothing has asked for it.
        assert_eq!(
            super::compact_verdict(false, false, false, gb, plenty, true),
            V::NotNeeded
        );
        // A scan pass is running - defer.
        assert!(matches!(
            super::compact_verdict(true, true, false, gb, plenty, true),
            V::Busy(_)
        ));
        // A download is in flight - defer. (Checked first: it is the one
        // the user is watching.)
        assert!(matches!(
            super::compact_verdict(true, false, true, gb, plenty, true),
            V::Busy(_)
        ));
        assert!(matches!(
            super::compact_verdict(true, true, true, gb, plenty, true),
            V::Busy(_)
        ));
        // Idle and roomy - go.
        assert_eq!(
            super::compact_verdict(true, false, false, gb, plenty, true),
            V::Go
        );

        // Idle but the volume cannot hold the rebuild: stay deferred
        // rather than fail halfway through rewriting the database.
        match super::compact_verdict(true, false, false, 4 * gb, Some(5 * gb), true) {
            V::NoRoom { need, free } => {
                assert!(need > 8 * gb, "VACUUM needs ~2x the file, got {need}");
                assert_eq!(free, 5 * gb);
            }
            other => panic!("expected NoRoom, got {other:?}"),
        }
        // Unmeasurable volume (an unmounted NAS share) is NOT treated as
        // "plenty of room" - that is how the min-free guard once filled
        // the disk it was protecting.
        assert!(matches!(
            super::compact_verdict(true, false, false, gb, None, true),
            V::NoRoom { .. }
        ));

        // §95: the chunked path needs no scratch space at all - it moves
        // pages down inside the file it already has and truncates. Both
        // of the room checks above must stop applying to it, or the
        // small NAS volumes this matters most on would defer forever
        // (silently and permanently - compact_pending is sticky).
        assert_eq!(
            super::compact_verdict(true, false, false, 4 * gb, Some(5 * gb), false),
            V::Go
        );
        assert_eq!(
            super::compact_verdict(true, false, false, gb, None, false),
            V::Go
        );
        // Busy still outranks it: standing off a download is the rule
        // the whole feature exists to keep.
        assert!(matches!(
            super::compact_verdict(true, false, true, gb, plenty, false),
            V::Busy(_)
        ));
    }

    /// There is no ceiling on the protected set any more - the engine
    /// re-checks every candidate in Rust against the full uncapped set, so
    /// a large set costs scan work and nothing else. What is still bounded
    /// is how many passes an on-demand eviction will make before giving
    /// up, which is the only loop that could otherwise spin.
    #[cfg(feature = "indexer")]
    #[test]
    fn evict_pass_count_is_bounded_and_useful() {
        assert!(
            super::EVICT_MAX_PASSES >= 2,
            "one pass is what undershoot needs a retry for"
        );
        assert!(
            super::EVICT_MAX_PASSES <= 32,
            "a bound this loose is not a bound"
        );
        // The touch log is bounded on both halves so a scripted crawl of
        // the wall cannot grow the protected set without limit.
        assert!(super::OPENED_MAX_ENTRIES > 0);
    }

    /// Two very different reasons a prune stops short, and telling the
    /// user the wrong one sends them hunting for protected releases that
    /// do not exist.
    #[cfg(feature = "indexer")]
    #[test]
    fn shrink_shortfall_distinguishes_protection_from_the_db_floor() {
        let floor = super::shrink_shortfall_reason(0);
        assert!(floor.contains("nothing is protected"), "{floor}");
        let prot = super::shrink_shortfall_reason(12);
        assert!(prot.contains("12 keys"), "{prot}");
        assert!(prot.contains("watchlisted"), "{prot}");
    }

    #[test]
    fn civil_dates() {
        assert_eq!(super::civil_from_days(0), (1970, 1, 1));
        assert_eq!(super::civil_from_days(10957), (2000, 1, 1));
        assert_eq!(super::civil_from_days(20653), (2026, 7, 19));
    }

    #[test]
    fn quota_ledger_persists_and_rolls() {
        let dir = std::env::temp_dir().join(format!("nzbfast-quota-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut led = super::QuotaLedger::open(&dir, 'd');
        led.add(1_000_000);
        led.add(2_000_000);
        // Survives a restart within the same period.
        let mut led2 = super::QuotaLedger::open(&dir, 'd');
        assert_eq!(led2.spent(), 3_000_000);
        // A stale period on disk is discarded on open.
        std::fs::write(dir.join("quota.json"), r#"{"start": 0, "bytes": 999}"#).unwrap();
        let mut led3 = super::QuotaLedger::open(&dir, 'd');
        assert_eq!(led3.spent(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn auto_speed_controller() {
        use super::{AUTO_SPEED_FLOOR, AUTO_SPEED_MAX, AUTO_SPEED_START, auto_speed_step};
        // Quiet network, no ceiling: climbs from the start value.
        let c1 = auto_speed_step(5, 60, 0, 0);
        assert!(c1 > AUTO_SPEED_START, "should climb: {c1}");
        // Congested: multiplicative backoff.
        let c2 = auto_speed_step(200, 60, 10_000_000, 0);
        assert_eq!(c2, 8_000_000);
        // Repeated congestion floors out, never starves.
        let mut cap = 2_000_000;
        for _ in 0..50 {
            cap = auto_speed_step(500, 60, cap, 0);
        }
        assert_eq!(cap, AUTO_SPEED_FLOOR);
        // Probe timeout (delay = MAX) is congestion at its loudest.
        assert!(auto_speed_step(u64::MAX, 60, 10_000_000, 0) < 10_000_000);
        // Ceiling respected on the climb.
        let c3 = auto_speed_step(5, 60, 3_900_000, 4_000_000);
        assert_eq!(c3, 4_000_000);
        // In the dead band (target/2 ..= target): hold.
        assert_eq!(auto_speed_step(45, 60, 5_000_000, 0), 5_000_000);
        // Unlimited climb is bounded by the sanity max.
        let mut cap = AUTO_SPEED_MAX - 1;
        cap = auto_speed_step(0, 60, cap, 0);
        assert_eq!(cap, AUTO_SPEED_MAX);
    }

    #[test]
    fn dupe_keys() {
        assert_eq!(
            super::dupe_key("Show.Name.S01E02.1080p.WEB-DL"),
            Some("show name/s1e2".into())
        );
        assert_eq!(
            super::dupe_key("show name s01e02 720p"),
            Some("show name/s1e2".into())
        );
        // Same episode, different quality → same key.
        assert_eq!(
            super::dupe_key("Show.Name.S01E02.2160p.REMUX"),
            super::dupe_key("Show.Name.S01E02.480p")
        );
        assert_eq!(
            super::dupe_key("Movie.Title.2026.2160p"),
            Some("movie title/2026".into())
        );
        // Daily-date episodes: each date is its own identity (the movie-
        // year arm used to collapse a whole year of a daily show), and
        // dotted vs compact posts of the SAME date share a key.
        assert_eq!(
            super::dupe_key("The.Daily.Show.2026.07.21.Guest.1080p.WEB"),
            Some("the daily show/20260721 guest".into())
        );
        // What that tail is really for: a matchday is not one release.
        // Held on the bare date, the second fixture was admitted paused
        // at priority -3 and only ever promoted if the FIRST failed.
        assert_ne!(
            super::dupe_key("EPL.2026.08.22.Arsenal.vs.Spurs.1080p.WEB.h264-VERUM"),
            super::dupe_key("EPL.2026.08.22.Liverpool.vs.Everton.1080p.WEB.h264-VERUM")
        );
        assert_eq!(
            super::dupe_key("EPL.2026.08.22.Arsenal.vs.Spurs.1080p.WEB.h264-VERUM"),
            Some("epl/20260822 arsenal vs spurs".into())
        );
        // Two encodes of ONE fixture are still one release: resolution,
        // source, codec and group never reach the tail.
        assert_eq!(
            super::dupe_key("EPL.2026.08.22.Arsenal.vs.Spurs.720p.HDTV.x264-OTHER"),
            super::dupe_key("EPL.2026.08.22.Arsenal.vs.Spurs.2160p.WEB.h265-VERUM")
        );
        // Same shape for a fight card and for date-style motorsport,
        // which the year arm's F1 fix could never reach.
        assert_ne!(
            super::dupe_key("UFC.Fight.Night.2026.05.03.Early.Prelims.1080p.WEB-GRP"),
            super::dupe_key("UFC.Fight.Night.2026.05.03.Main.Card.1080p.WEB-GRP")
        );
        assert_ne!(
            super::dupe_key("Formula1.2026.07.19.Hungary.Qualifying.1080p.WEB-DL-MWR"),
            super::dupe_key("Formula1.2026.07.19.Hungary.Race.1080p.WEB-DL-MWR")
        );
        assert_ne!(
            super::dupe_key("The.Daily.Show.2026.07.21.1080p"),
            super::dupe_key("The.Daily.Show.2026.07.28.1080p")
        );
        assert_eq!(
            super::dupe_key("At.Midnight.150615.720p"),
            Some("at midnight/20150615".into())
        );
        assert_eq!(
            super::dupe_key("At.Midnight.20150615.720p"),
            super::dupe_key("At.Midnight.150615.480p")
        );
        // Year in the title, episode marker present → episode wins.
        assert_eq!(
            super::dupe_key("Show.2026.S03E07.WEB"),
            Some("show 2026/s3e7".into())
        );
        // Leading year is a title, trailing year is the marker.
        assert_eq!(
            super::dupe_key("2001.A.Space.Odyssey.1968.1080p"),
            Some("2001 a space odyssey/1968".into())
        );
        // NxNN alternate form ≡ SxxEyy (a 3x07 alt of an owned S03E07
        // used to skip the dupe check entirely and fully download).
        assert_eq!(
            super::dupe_key("Show.Name.3x07.1080p.WEB"),
            super::dupe_key("Show.Name.S03E07.720p.HDTV")
        );
        assert_eq!(
            super::dupe_key("show name 1x02 720p"),
            Some("show name/s1e2".into())
        );
        // "4x4" (single-digit "episode") is a title token, not a marker.
        assert_eq!(
            super::dupe_key("Extreme.4x4.Trucks.2026.1080p"),
            Some("extreme 4x4 trucks/2026".into())
        );
        assert_eq!(super::dupe_key("obfuscated8f3a2bc"), None);
        assert!(super::is_proper("Show.S01E02.PROPER.1080p"));
        assert!(super::is_proper("Movie.2026.REPACK.2160p"));
        assert!(!super::is_proper("The.Real.World.S01E01"));
    }

    /// Event releases put the SEASON in the year slot and their identity
    /// after it. Keyed on title+year alone, every session of every round
    /// of a year collapsed onto one key ("formula1/2026"), so the user's
    /// first F1 grab downloaded and every later one was held as a paused
    /// duplicate at priority -3 - the daily-date bug, one shape over.
    #[test]
    fn event_releases_key_on_what_follows_the_year() {
        let k = |s: &str| super::dupe_key(s).expect(s);
        // The user's two real NZBs: one round, two sessions, and the
        // second in a completely different quality dress. Both keyed to
        // "formula1/2026", so the second arrived paused.
        let show = k(
            "Formula1.2026.Round11.Hungary.Post-Qualifying.Show.F1TV.WEB-DL.1080p.H264.English-MWR",
        );
        let quali = k(
            "Formula1.2026.Round11.Hungary.Qualifying.F1TV.WEB-DL.2160p.HLG.H265.DDP5.1.English-MWR",
        );
        assert_ne!(
            show, quali,
            "the user's two real NZBs must not share a dupe key"
        );
        assert_eq!(
            show,
            "formula1/2026 round11 hungary post qualifying show f1tv"
        );
        assert_eq!(quali, "formula1/2026 round11 hungary qualifying f1tv");
        // Widened: another round in another country, and a third session.
        let belgium = k("Formula1.2026.Round12.Belgium.Race.F1TV.WEB-DL.1080p.H264.English-MWR");
        let race_uhd = k("Formula1.2026.Round11.Hungary.Race.F1TV.WEB-DL.2160p.H265.English-MWR");
        let all = [&show, &quali, &belgium, &race_uhd];
        for (i, a) in all.iter().enumerate() {
            for b in &all[i + 1..] {
                assert_ne!(a, b, "F1 sessions must not share a dupe key");
            }
        }
        // …but the SAME session re-posted in another resolution, codec,
        // source and by another group is still one release. Quality never
        // reaches the tail: the scan stops at the first furniture token.
        assert_eq!(
            race_uhd,
            k("Formula1.2026.Round11.Hungary.Race.F1TV.WEB-DL.1080p.H264.English-MWR")
        );
        assert_eq!(
            race_uhd,
            k("Formula1.2026.Round11.Hungary.Race.F1TV.HDTV.x264.AAC5.1-OTHER")
        );
        // Generalizes past motorsport: rounds, weeks and stages all sit
        // in the same slot, and a bare number is identity, not furniture.
        assert_ne!(
            k("MotoGP.2026.Round05.France.Race.1080p.WEB-DL.H264-GRP"),
            k("MotoGP.2026.Round06.Italy.Race.1080p.WEB-DL.H264-GRP")
        );
        assert_ne!(
            k("NFL.2026.Week.05.Bears.at.Packers.1080p.WEB-DL-GRP"),
            k("NFL.2026.Week.06.Bears.at.Packers.1080p.WEB-DL-GRP")
        );
        assert_ne!(
            k("Cycling.Tour.de.France.2026.Stage.11.1080p.HDTV-GRP"),
            k("Cycling.Tour.de.France.2026.Stage.12.1080p.HDTV-GRP")
        );
        // A group tag is noise even when nothing else separates it from
        // the event name.
        assert_eq!(
            k("Formula1.2026.Round11.Hungary.Race-MWR"),
            k("Formula1.2026.Round11.Hungary.Race-OTHER")
        );
        // Events named by nationality: "Hungarian"/"Belgian" are language
        // tags, so treating a language as a hard stop would have thrown
        // the whole event name away with it and collapsed the season
        // again. A language run is only furniture when it is ALL the tail
        // has (see the dub cases in `ordinary_movies_…`); alongside real
        // identity tokens it is carried.
        assert_eq!(
            k("Formula1.2026.Hungarian.Grand.Prix.Race.1080p.WEB-DL-GRP"),
            "formula1/2026 hungarian grand prix race"
        );
        assert_ne!(
            k("Formula1.2026.Hungarian.Grand.Prix.Race.1080p.WEB-DL-GRP"),
            k("Formula1.2026.Belgian.Grand.Prix.Race.1080p.WEB-DL-GRP")
        );
    }

    /// The other half of the same coin: an ordinary film's year IS its
    /// release date, everything after it is furniture, and the key must
    /// come out byte-identical to what it was before the event fix.
    #[test]
    fn ordinary_movies_keep_their_bare_title_year_key() {
        let k = |s: &str| super::dupe_key(s).expect(s);
        // Two very different encodes of one film - one key.
        assert_eq!(
            k("The.Matrix.1999.1080p.BluRay.x264-GROUP"),
            "the matrix/1999"
        );
        assert_eq!(
            k("The.Matrix.1999.2160p.UHD.BluRay.REMUX.HDR.HEVC.TrueHD.Atmos-FraMeSToR"),
            "the matrix/1999"
        );
        assert_eq!(
            k("The.Matrix.1999.1080p.BluRay.x264-GROUP"),
            k("The.Matrix.1999.2160p.UHD.BluRay.REMUX.HDR.HEVC.TrueHD.Atmos-FraMeSToR")
        );
        // Furniture shapes that must all reduce to nothing: split audio
        // channel tokens, glued channel counts, editions, dubs, friendly
        // renames, and a title that is itself a year.
        for s in [
            "Dune.Part.Two.2024.2160p.WEB-DL.DDP5.1.Atmos.DV.HDR.H.265-FLUX",
            "Dune.Part.Two.2024.1080p.AMZN.WEB-DL.DD.5.1.H.264-NTb",
            "Dune.Part.Two.2024.720p.BluRay.x264.AAC5.1-YTSMX",
            "Dune Part Two (2024) [1080p] [WEBRip] [YTS.MX]",
            "Dune.Part.Two.2024.EXTENDED.1080p.BluRay.x264-GRP",
            "Dune.Part.Two.2024.Directors.Cut.1080p.BluRay.x264-GRP",
            "Dune.Part.Two.2024.German.DL.1080p.BluRay.x264-DEU",
            "Dune.Part.Two.2024.MULTi.TRUEFRENCH.1080p.WEB-GRP",
            "Dune.Part.Two.2024.iNTERNAL.HDR.2160p.WEB.h265-GRP",
        ] {
            assert_eq!(k(s), "dune part two/2024", "{s}");
        }
        // A second year after the marker is furniture, not identity.
        assert_eq!(
            k("Blade.Runner.2049.2017.2160p.WEB-DL"),
            "blade runner/2049"
        );
    }

    /// A double-episode grab is recorded in BOTH episode slots, so an
    /// upgrade of one of them must not delete the download that is still
    /// the only copy of the other - including once the sibling slot has
    /// already been rewritten by the same pass, which is what a scan of
    /// the live slot map misses.
    #[test]
    fn an_upgrade_only_deletes_what_it_fully_replaces() {
        use crate::watchlist as wl;
        let tv = wl::WatchItem {
            id: 7,
            kind: "tv".into(),
            title: "Show Name".into(),
            year: None,
            seasons: String::new(),
            episodes: String::new(),
            min_quality: "any".into(),
            target_quality: "2160p".into(),
            upgrade: true,
            delete_old: true,
            category: String::new(),
            min_age: String::new(),
            max_age: String::new(),
            enabled: true,
        };
        let slot = |stem: &str, nzo: &str| wl::Slot {
            rank: 3,
            stem: stem.into(),
            quality: "720p WEB".into(),
            nzo_id: nzo.into(),
            grabbed_at: 0,
            failed: Vec::new(),
        };
        let double = slot("Show.Name.S01E01E02.720p.WEB.h264-GRP", "nzo-double");
        let single = slot("Show.Name.S01E03.720p.WEB.h264-GRP", "nzo-single");
        let mut state = wl::WatchState::default();
        state.slots.insert("7:s01e01".into(), double.clone());
        state.slots.insert("7:s01e02".into(), double.clone());
        state.slots.insert("7:s01e03".into(), single.clone());
        let p = |s: &str| crate::wall::parse_release(s);

        // Upgrading E02 with a single-episode 1080p leaves E01 with only
        // the double for company - the delete has to wait.
        let e02 = p("Show.Name.S01E02.1080p.WEB.h264-GRP");
        assert!(!super::upgrade_supersedes_all(
            &tv,
            &state,
            &double,
            &e02,
            &[]
        ));
        // ...and still has to wait once E01's own upgrade has rewritten
        // that slot in this very pass. Nothing points at the double any
        // more, but it is still the only copy of E01 until nzo-e01 lands.
        let e01_up = slot("Show.Name.S01E01.1080p.WEB.h264-GRP", "nzo-e01");
        state.slots.insert("7:s01e01".into(), e01_up);
        assert!(!super::upgrade_supersedes_all(
            &tv,
            &state,
            &double,
            &e02,
            &[]
        ));

        // A like-for-like double upgrade reaches both slots, so the
        // superseded copy is deleted as the user asked - leaving it would
        // orphan a full copy on every multi-episode upgrade.
        let both = p("Show.Name.S01E01E02.1080p.WEB.h264-GRP");
        assert!(super::upgrade_supersedes_all(
            &tv,
            &state,
            &double,
            &both,
            &[]
        ));
        // A single-episode grab owns only its own slot.
        let e03 = p("Show.Name.S01E03.1080p.WEB.h264-GRP");
        assert!(super::upgrade_supersedes_all(
            &tv,
            &state,
            &single,
            &e03,
            &[]
        ));
    }

    /// The watch folder's settle gate must fail CLOSED: a signature it
    /// cannot take is not a signature that matches. It also has to
    /// measure what `read` will read, which for a symlinked .nzb is the
    /// target, not the link (whose own size and mtime never move).
    #[test]
    fn watch_signature_follows_links_and_fails_closed() {
        let dir = std::env::temp_dir().join(format!("nzbfast-watchsig-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("post.nzb");
        std::fs::write(&f, b"<nzb></nzb>").unwrap();
        let sig = super::watch_sig(&f).expect("a real file has a signature");
        assert_eq!(sig.1, 11);
        assert_eq!(super::watch_sig(&dir.join("nothing.nzb")), None);
        #[cfg(unix)]
        {
            let link = dir.join("link.nzb");
            std::os::unix::fs::symlink(&f, &link).unwrap();
            assert_eq!(super::watch_sig(&link), Some(sig));
            std::fs::write(&f, b"<nzb>grown</nzb>").unwrap();
            assert_ne!(
                super::watch_sig(&link),
                Some(sig),
                "the target's size counts"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Every platform we ship must actually measure the volume. Windows
    /// had no implementation at all for a while: disk_stat returned None
    /// unconditionally, which silently disabled the min-free guard and
    /// printed "0.00 GB free" on the dashboard.
    #[cfg(any(unix, windows))]
    #[test]
    fn disk_stat_measures_the_volume_holding_a_path() {
        let (free, total) =
            super::disk_stat(&std::env::temp_dir()).expect("the temp dir is on a real filesystem");
        assert!(total > 0, "a mounted volume has a size");
        assert!(free <= total, "free {free} exceeds total {total}");
    }

    /// The min-free guard only acts when free_bytes answers, so a
    /// not-yet-created output directory used to disable it outright: the
    /// job ran and filled the disk the guard was meant to protect. An
    /// unmounted NAS mount point is the same shape.
    #[cfg(any(unix, windows))]
    #[test]
    fn free_bytes_answers_for_a_directory_that_does_not_exist_yet() {
        let base = std::env::temp_dir();
        let here = super::free_bytes(&base).expect("temp dir is on a real filesystem");
        let missing = base.join(format!("nzbfast-absent-{}/deep/deeper", std::process::id()));
        assert!(!missing.exists());
        let got = super::free_bytes(&missing).expect("resolves via the nearest existing ancestor");
        // Same filesystem as the nearest existing ancestor, so the same
        // ballpark - not an exact match, free space moves under us.
        let (lo, hi) = (here.min(got), here.max(got));
        assert!(
            hi - lo < hi / 10,
            "expected the ancestor's filesystem: {here} vs {got}"
        );
    }

    /// The dashboard and the NZBGet-compat status report need (free,
    /// total), and both used bare disk_stat: a completed-downloads dir
    /// that hadn't been created yet (it's made lazily at job completion)
    /// reported "0 MB free on disk", and the *arrs read a full disk.
    #[cfg(any(unix, windows))]
    #[test]
    fn disk_stat_walk_answers_for_a_directory_that_does_not_exist_yet() {
        let base = std::env::temp_dir();
        let missing = base.join(format!(
            "nzbfast-walkabsent-{}/deep/deeper",
            std::process::id()
        ));
        assert!(!missing.exists());
        let (free, total) =
            super::disk_stat_walk(&missing).expect("resolves via the nearest existing ancestor");
        assert!(total > 0, "the ancestor's volume has a size");
        assert!(free <= total);
    }

    /// The key comparison was already constant-time, but a wrong key was
    /// recorded nowhere and slowed nothing down, so an unauthenticated peer
    /// could grind it at full request rate leaving no trace in any log.
    #[test]
    fn repeated_bad_keys_from_one_address_get_refused() {
        let table = super::Mutex::new(std::collections::HashMap::new());
        let note = |ip| super::note_auth_failure_in(&table, ip, "test");
        let attacker = Some(std::net::IpAddr::from([10, 0, 0, 9]));

        for attempt in 1..super::AUTH_FAIL_THRESHOLD {
            assert!(
                !note(attacker),
                "attempt {attempt} should still be allowed through"
            );
        }
        assert!(note(attacker), "the threshold attempt must be refused");
        assert!(note(attacker), "and stay refused");

        // A different address is unaffected - one hostile peer must not lock
        // out the household's *arr apps.
        assert!(!note(Some(std::net::IpAddr::from([10, 0, 0, 10]))));

        // No address at all (a transport that does not report one) is never
        // blocked: accounting fails open, the key check does not.
        assert!(!note(None));
    }

    /// The tracking table must not become the attack: a spray from many
    /// source addresses cannot grow it without bound.
    #[test]
    fn the_auth_failure_table_is_bounded() {
        let table = super::Mutex::new(std::collections::HashMap::new());
        for i in 0..(super::AUTH_FAIL_MAX_TRACKED + 500) {
            let ip = std::net::IpAddr::from(((i as u32) + 0x0100_0000).to_be_bytes());
            super::note_auth_failure_in(&table, Some(ip), "spray");
        }
        assert!(
            table.lock().unwrap().len() <= super::AUTH_FAIL_MAX_TRACKED,
            "the table grew past its ceiling"
        );
    }

    #[cfg(feature = "indexer")]
    #[test]
    fn image_sniff_accepts_real_formats_only() {
        assert!(super::looks_image(&[0xFF, 0xD8, 0xFF, 0xE0, 0x00]));
        assert!(super::looks_image(b"\x89PNG\r\n\x1a\n...."));
        assert!(super::looks_image(b"GIF89a...."));
        assert!(super::looks_image(b"RIFF\x00\x00\x00\x00WEBPVP8 "));
        assert!(!super::looks_image(b"<html><body>404</body></html>"));
        assert!(!super::looks_image(b"RIFF\x00\x00\x00\x00WAVEfmt "));
        assert!(!super::looks_image(b""));
    }

    /// /art/ is unauthenticated, so its name check is the only thing
    /// between a stranger and `art_root.join(...)`. The device names are
    /// the ones that bite: they pass the alphanumeric class, and on
    /// Windows the open resolves to the console and the read never
    /// returns, wedging an HTTP worker for good.
    #[cfg(feature = "indexer")]
    #[test]
    fn art_names_reject_traversal_and_dos_devices() {
        assert!(super::art_name_ok("m_the_matrix_1999.jpg"));
        assert!(super::art_name_ok("t_severance.bd.jpg"));
        assert!(super::art_name_ok("thumb_m_the_matrix_1999.jpg"));
        assert!(!super::art_name_ok(""));
        assert!(!super::art_name_ok("../../etc/passwd"));
        assert!(!super::art_name_ok("a/b.jpg"));
        assert!(!super::art_name_ok("CON"));
        assert!(!super::art_name_ok("con.jpg"));
        assert!(!super::art_name_ok("COM1"));
        assert!(!super::art_name_ok("LPT9.jpg"));
        // The thumb source is joined too, so it gets its own pass.
        assert!(!super::art_name_ok(
            "thumb_CON.jpg".strip_prefix("thumb_").unwrap()
        ));
    }

    /// The pre-auth amplifier. `Content-Type: multipart/form-data;
    /// boundary=` is accepted by tiny_http and makes the delimiter
    /// `--`, so a body of hyphens split once every two bytes - and the
    /// splitter held a fat pointer per segment, turning a 256 MiB body
    /// (which an UNAUTHENTICATED caller gets to send, because the key
    /// may be a form field) into roughly 2 GiB of vector on top of it,
    /// outside the body budget. Both halves are pinned: the boundary is
    /// refused outright, and the parse no longer materializes segments.
    #[test]
    fn an_empty_boundary_parses_nothing() {
        assert!(!super::valid_boundary(""));
        assert!(!super::valid_boundary(&"x".repeat(71)));
        assert!(super::valid_boundary("----nzbfastboundary"));
        let body = b"--".repeat(1 << 20);
        assert!(super::multipart_fields(&body, "").is_empty());
        assert!(super::multipart_file(&body, "").is_none());
    }

    /// One boundary parse for the gateway and both file-part handlers.
    ///
    /// There were three copies and they disagreed after Codex sweep 2's
    /// H1 taught the gateway that a media type's parameter names are
    /// case-insensitive: `Boundary=` then parsed as multipart at the
    /// gateway - fields merged, the key found, auth decided - and as
    /// nothing in `addfile`, so the upload arrived with no file part at
    /// all. The parameter NAME is matched case-insensitively; the VALUE
    /// is a literal delimiter and keeps its case exactly.
    #[test]
    fn one_boundary_parse_serves_the_gateway_and_the_handlers() {
        let b = |c: &str| super::multipart_boundary(c);
        assert_eq!(
            b("multipart/form-data; boundary=AbCd1234"),
            Some("AbCd1234".into())
        );
        // The spellings a standards-compliant client may legally send.
        assert_eq!(
            b("Multipart/Form-Data; Boundary=AbCd1234"),
            Some("AbCd1234".into())
        );
        assert_eq!(
            b("multipart/form-data; BOUNDARY=\"AbCd1234\""),
            Some("AbCd1234".into())
        );
        // The refusals `valid_boundary` exists for, now unforgettable
        // because they live at the single source rather than in each
        // caller.
        assert_eq!(b("multipart/form-data; boundary="), None);
        assert_eq!(b("multipart/form-data"), None);
        assert_eq!(b("application/json"), None);
        assert_eq!(
            b(&format!("multipart/form-data; boundary={}", "x".repeat(71))),
            None
        );
    }

    /// A form with thousands of fields is not a form. The parser's own
    /// working set must be bounded by something other than how many
    /// delimiters the caller sent.
    #[test]
    fn multipart_fields_are_capped() {
        let b = "----nzbfastboundary";
        let mut body = Vec::new();
        for i in 0..1000 {
            body.extend_from_slice(
                format!("--{b}\r\nContent-Disposition: form-data; name=\"f{i}\"\r\n\r\nv\r\n")
                    .as_bytes(),
            );
        }
        body.extend_from_slice(format!("--{b}--\r\n").as_bytes());
        assert_eq!(super::multipart_fields(&body, b).len(), 256);
    }

    /// Codex H8: a part whose "header block" is attacker-sized invalid
    /// UTF-8 must never reach the lossy decode - `from_utf8_lossy`
    /// expands each invalid byte to a 3-byte replacement character, and
    /// this parser runs pre-authentication on a body of up to 256 MiB.
    /// The giant part is skipped; legitimate parts beside it still work.
    #[test]
    fn a_giant_part_header_is_never_decoded() {
        let b = "----nzbfastboundary";
        let mut body = Vec::new();
        // One part: 4 MiB of 0xFF posing as the header, then CRLFCRLF.
        body.extend_from_slice(format!("--{b}\r\n").as_bytes());
        body.extend_from_slice(&vec![0xFFu8; 4 << 20]);
        body.extend_from_slice(b"\r\n\r\nv\r\n");
        // A normal field and a normal file part after it.
        body.extend_from_slice(
            format!("--{b}\r\nContent-Disposition: form-data; name=\"mode\"\r\n\r\naddfile\r\n")
                .as_bytes(),
        );
        body.extend_from_slice(
            format!(
                "--{b}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"e.nzb\"\r\n\r\n<nzb/>\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(format!("--{b}--\r\n").as_bytes());
        assert_eq!(
            super::multipart_fields(&body, b),
            vec![("mode".to_string(), "addfile".to_string())]
        );
        assert_eq!(super::multipart_file(&body, b).unwrap().1, b"<nzb/>");
        // And a header just under the bound still parses - the cap must
        // not eat legitimate long filenames.
        let long_name = "x".repeat(300);
        let mut small = Vec::new();
        small.extend_from_slice(
            format!(
                "--{b}\r\nContent-Disposition: form-data; name=\"n\"; filename=\"{long_name}\"\r\n\r\nd\r\n--{b}--\r\n"
            )
            .as_bytes(),
        );
        assert_eq!(super::multipart_file(&small, b).unwrap().0, long_name);
    }

    #[test]
    fn multipart_parses() {
        let boundary = "----nzbfastboundary";
        let mut body = Vec::new();
        body.extend_from_slice(format!("--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"e.nzb\"\r\nContent-Type: application/x-nzb\r\n\r\n").as_bytes());
        body.extend_from_slice(b"<nzb>hi</nzb>");
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let got = super::multipart_file(&body, boundary).expect("parse");
        assert_eq!(got.0, "e.nzb");
        assert_eq!(got.1, b"<nzb>hi</nzb>");
    }

    /// The SAB-compat field extractor: form fields come out, the file
    /// part stays out (it belongs to multipart_file), and a field-shaped
    /// part carrying megabytes is refused as a parameter.
    #[test]
    fn multipart_fields_parses_and_skips_files() {
        let b = "----nzbfastboundary";
        let mut body = Vec::new();
        for (n, v) in [("mode", "addfile"), ("apikey", "sekrit"), ("cat", "tv")] {
            body.extend_from_slice(
                format!("--{b}\r\nContent-Disposition: form-data; name=\"{n}\"\r\n\r\n{v}\r\n")
                    .as_bytes(),
            );
        }
        body.extend_from_slice(
            format!(
                "--{b}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"e.nzb\"\r\n\r\n<nzb/>\r\n"
            )
            .as_bytes(),
        );
        let huge = "x".repeat(5000);
        body.extend_from_slice(
            format!("--{b}\r\nContent-Disposition: form-data; name=\"blob\"\r\n\r\n{huge}\r\n")
                .as_bytes(),
        );
        body.extend_from_slice(format!("--{b}--\r\n").as_bytes());
        let fields = super::multipart_fields(&body, b);
        assert_eq!(
            fields,
            vec![
                ("mode".to_string(), "addfile".to_string()),
                ("apikey".to_string(), "sekrit".to_string()),
                ("cat".to_string(), "tv".to_string()),
            ]
        );
        // The file part is still the file parser's to find.
        assert_eq!(super::multipart_file(&body, b).unwrap().1, b"<nzb/>");
    }

    use super::{
        SchedAction, effective_state, next_resume_in, parse_days, parse_schedule, parse_size,
    };

    /// Minute-of-week helper for readable test times (Mon=0).
    fn mow(day: u32, h: u32, m: u32) -> u32 {
        day * 1440 + h * 60 + m
    }

    #[test]
    fn sizes_parse() {
        assert_eq!(parse_size("0"), Some(0));
        assert_eq!(parse_size("400000"), Some(400_000));
        assert_eq!(parse_size("500K"), Some(500_000));
        assert_eq!(parse_size("4M"), Some(4_000_000));
        assert_eq!(parse_size("1.5m"), Some(1_500_000));
        assert_eq!(parse_size("2G"), Some(2_000_000_000));
        assert_eq!(parse_size(" 4M "), Some(4_000_000));
        assert_eq!(parse_size("50%"), None);
        assert_eq!(parse_size("-1"), None);
        assert_eq!(parse_size("junk"), None);
    }

    #[test]
    fn days_parse() {
        assert_eq!(parse_days("all"), Some([true; 7]));
        assert_eq!(
            parse_days("mon-fri"),
            Some([true, true, true, true, true, false, false])
        );
        assert_eq!(
            parse_days("sat,sun"),
            Some([false, false, false, false, false, true, true])
        );
        assert_eq!(
            parse_days("Mon,wed-Fri"),
            Some([true, false, true, true, true, false, false])
        );
        // Wrapping range.
        assert_eq!(
            parse_days("sat-mon"),
            Some([true, false, false, false, false, true, true])
        );
        assert_eq!(parse_days("noday"), None);
        assert_eq!(parse_days(""), None);
    }

    #[test]
    fn schedule_parses() {
        let entries = parse_schedule(
            r#"[
              {"days": "mon-fri", "time": "08:00", "action": "speedlimit", "value": "4M"},
              {"days": "mon-fri", "time": "23:30", "action": "speedlimit", "value": 0},
              {"days": "sat,sun", "time": "09:15", "action": "pause"},
              {"days": "all", "time": "17:00", "action": "resume"}
            ]"#,
        )
        .expect("parse");
        assert_eq!(entries.len(), 4);
        assert_eq!(entries[0].action, SchedAction::SpeedLimit(4_000_000));
        assert_eq!(entries[0].minute, 8 * 60);
        assert!(entries[0].days[4] && !entries[0].days[5]);
        assert_eq!(entries[1].action, SchedAction::SpeedLimit(0));
        assert_eq!(entries[2].action, SchedAction::Pause);
        assert_eq!(entries[2].minute, 9 * 60 + 15);
        assert_eq!(entries[3].action, SchedAction::Resume);

        assert!(parse_schedule(r#"{"not": "an array"}"#).is_err());
        assert!(parse_schedule(r#"[{"time": "25:00", "action": "pause"}]"#).is_err());
        assert!(parse_schedule(r#"[{"time": "08:00", "action": "explode"}]"#).is_err());
        assert!(parse_schedule(r#"[{"time": "08:00", "action": "speedlimit"}]"#).is_err());
    }

    #[test]
    fn effective_state_scenarios() {
        let entries = parse_schedule(
            r#"[
              {"days": "mon-fri", "time": "08:00", "action": "speedlimit", "value": "4M"},
              {"days": "mon-fri", "time": "23:00", "action": "speedlimit", "value": 0},
              {"days": "sat", "time": "10:00", "action": "pause"},
              {"days": "sun", "time": "10:00", "action": "resume"}
            ]"#,
        )
        .unwrap();

        // Wed 12:00 - weekday daytime: limited, and Sunday's resume is the
        // most recent pause-kind action.
        assert_eq!(
            effective_state(&entries, mow(2, 12, 0)),
            (Some(false), Some(4_000_000))
        );
        // Wed 23:30 - after the evening lift.
        assert_eq!(
            effective_state(&entries, mow(2, 23, 30)),
            (Some(false), Some(0))
        );
        // Thu 07:59 - still on Wednesday night's state.
        assert_eq!(
            effective_state(&entries, mow(3, 7, 59)),
            (Some(false), Some(0))
        );
        // Exact boundary counts as fired (restart at Thu 08:00 sharp).
        assert_eq!(
            effective_state(&entries, mow(3, 8, 0)),
            (Some(false), Some(4_000_000))
        );
        // Sat 12:00 - weekend pause in effect; Friday night lifted the cap.
        assert_eq!(
            effective_state(&entries, mow(5, 12, 0)),
            (Some(true), Some(0))
        );
        // Sun 09:00 - still paused from Saturday.
        assert_eq!(
            effective_state(&entries, mow(6, 9, 0)),
            (Some(true), Some(0))
        );
        // Sun 11:00 - resumed.
        assert_eq!(
            effective_state(&entries, mow(6, 11, 0)),
            (Some(false), Some(0))
        );
        // Mon 00:00 wrap-around: Sunday's resume is 14h back, Friday's
        // lift is the newest speedlimit.
        assert_eq!(
            effective_state(&entries, mow(0, 0, 0)),
            (Some(false), Some(0))
        );

        // No entries of a kind → None (nothing overridden at startup).
        let only_limit = parse_schedule(
            r#"[{"days": "all", "time": "12:00", "action": "speedlimit", "value": "1M"}]"#,
        )
        .unwrap();
        assert_eq!(
            effective_state(&only_limit, mow(0, 13, 0)),
            (None, Some(1_000_000))
        );
        assert_eq!(effective_state(&[], 0), (None, None));

        // Tie at the same minute: later entry in the file wins.
        let tie = parse_schedule(
            r#"[
              {"days": "mon", "time": "09:00", "action": "pause"},
              {"days": "mon", "time": "09:00", "action": "resume"}
            ]"#,
        )
        .unwrap();
        assert_eq!(effective_state(&tie, mow(0, 9, 0)).0, Some(false));
    }

    /// The "paused - by your schedule until 08:00" clause only gets a
    /// time when the schedule really has one ahead of it.
    #[test]
    fn next_resume_is_the_nearest_one_ahead() {
        let entries = parse_schedule(
            r#"[
              {"days": "mon-fri", "time": "23:00", "action": "pause"},
              {"days": "mon-fri", "time": "08:00", "action": "resume"},
              {"days": "sun", "time": "20:00", "action": "resume"}
            ]"#,
        )
        .unwrap();

        // Mon 23:30, inside the weekday quiet hours: Tuesday 08:00.
        assert_eq!(next_resume_in(&entries, mow(0, 23, 30)), Some(8 * 60 + 30));
        // Fri 23:30 - the weekday resumes are all behind us, so the
        // nearest ahead is Sunday 20:00 (44.5 h), not Monday 08:00.
        assert_eq!(next_resume_in(&entries, mow(4, 23, 30)), Some(44 * 60 + 30));
        // Standing exactly ON a resume minute is not a future time, so
        // the answer is that entry a week out - never "in 0 minutes".
        assert_eq!(next_resume_in(&entries, mow(1, 8, 0)), Some(1440));

        // A schedule that only ever pauses promises nothing.
        let one_way =
            parse_schedule(r#"[{"days": "all", "time": "23:00", "action": "pause"}]"#).unwrap();
        assert_eq!(next_resume_in(&one_way, mow(0, 23, 30)), None);
        assert_eq!(next_resume_in(&[], 0), None);
    }

    #[test]
    fn fires_at_boundaries() {
        let e = parse_schedule(r#"[{"days": "tue", "time": "06:30", "action": "pause"}]"#)
            .unwrap()
            .remove(0);
        assert!(e.fires_at(mow(1, 6, 30)));
        assert!(!e.fires_at(mow(1, 6, 29)));
        assert!(!e.fires_at(mow(1, 6, 31)));
        assert!(!e.fires_at(mow(2, 6, 30)));
    }
}

mod assets;
use assets::*;

/// Discover an article sample spanning a range of ages for the diversity
/// sweep: recent articles (last few thousand) plus progressively older
/// ranges, so retention limits and takedowns actually differentiate the
/// providers. Uses the first reachable server for discovery.
async fn sample_ids_for_diversity(
    servers: &[nzbkit::config::ServerConfig],
    group: &str,
) -> std::result::Result<Vec<String>, String> {
    use nzbkit::nntp::Connection;
    let srv = servers.first().ok_or("no servers configured")?;
    let (mut conn, _) = Connection::connect(srv).await.map_err(|e| e.to_string())?;
    let g = conn.group(group).await.map_err(|e| e.to_string())?;
    let mut ids = Vec::new();
    // Five age bands across the group's article-number range.
    let span = g.high.saturating_sub(g.low).max(1);
    for band in 0..5u64 {
        let center = g.high.saturating_sub(span * band / 5);
        let from = center.saturating_sub(2_000).max(g.low);
        if let Ok(entries) = conn.over(from, center).await {
            // ≥150 KB: the sample doubles as the per-server speed probe's
            // fetch set, and header-only posts would understate it.
            for e in entries
                .into_iter()
                .filter(|e| !e.message_id.is_empty() && e.bytes >= 150_000)
                .take(20)
            {
                ids.push(nzbkit::sysbench::bracket_id(&e.message_id));
            }
        }
    }
    conn.quit().await;
    if ids.is_empty() {
        return Err("no sample articles found".into());
    }
    Ok(ids)
}

#[cfg(test)]
mod spool_naming_tests {
    use super::{api_client, api_origin, origin_of, safe_spool_stem};
    use std::collections::HashMap;

    /// The whole point: a spool file you can match to something you saw.
    #[test]
    fn the_release_name_survives_into_the_filename() {
        assert_eq!(
            safe_spool_stem("Some.Show.S01E02.1080p"),
            "Some.Show.S01E02.1080p"
        );
    }

    /// This string becomes a filename, so it must not be able to escape
    /// the spool directory or hide itself.
    #[test]
    fn a_hostile_name_cannot_escape_the_spool() {
        for bad in ["../../etc/passwd", "..\\..\\windows", "/abs/path", "a/b/c"] {
            let out = safe_spool_stem(bad);
            assert!(!out.contains('/'), "{bad} -> {out}");
            assert!(!out.contains('\\'), "{bad} -> {out}");
            assert!(!out.contains(".."), "{bad} -> {out}");
            assert!(
                !out.starts_with('.'),
                "{bad} -> {out} would be a hidden file"
            );
        }
        // A name of nothing usable still yields a filename.
        assert_eq!(safe_spool_stem("///"), "job");
        assert_eq!(safe_spool_stem(""), "job");
    }

    /// A very long release name plus the job id must not approach a path
    /// limit.
    #[test]
    fn long_names_are_capped() {
        let out = safe_spool_stem(&"A".repeat(500));
        assert!(out.chars().count() <= 60, "{} chars", out.chars().count());
    }

    /// Non-ASCII names are common and must not produce an empty stem.
    #[test]
    fn non_ascii_names_still_produce_something() {
        let out = safe_spool_stem("Кино.2024.Фильм");
        assert!(!out.is_empty());
        assert!(!out.contains('/'));
    }

    #[test]
    fn arr_adds_are_told_apart_from_dashboard_adds() {
        let mut arr = HashMap::new();
        arr.insert("nzbname".to_string(), "Show.S01E01".to_string());
        assert_eq!(origin_of(&arr), "arr");
        assert_eq!(origin_of(&HashMap::new()), "dashboard");
    }

    /// The two Sonarr and Radarr strings are the ones a real Sonarr and
    /// Radarr actually sent during download-client certification,
    /// captured off a live test, not ones we assumed.
    #[test]
    fn real_clients_name_themselves() {
        for (ua, want) in [
            ("Sonarr/4.0.19.2979 (macos 10.0)", "sonarr"),
            ("Radarr/6.3.0.10514 (macos 10.0)", "radarr"),
            ("Lidarr/2.4.3.4248 (ubuntu 22.04)", "lidarr"),
            ("Readarr/0.4.7.2718 (debian 12)", "readarr"),
            ("Prowlarr/1.21.2.4649 (docker)", "prowlarr"),
            ("nzb360/17.4 (Android 14)", "nzb360"),
            ("LunaSea/10.3.0", "lunasea"),
            ("SABnzbd/4.3.2", "sabnzbd"),
            ("NZBGet/21.1", "nzbget"),
            ("curl/8.7.1", "curl"),
        ] {
            assert_eq!(api_client(ua).as_deref(), Some(want), "{ua}");
        }
    }

    /// A browser is not an automation - including our own dashboard,
    /// whose upload posts to the very same addfile endpoint.
    #[test]
    fn browsers_and_silence_fall_back() {
        for ua in [
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) \
             Chrome/126.0.0.0 Safari/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15",
            "",
            "   ",
            "/4.0",
            "Кино/1.0",
        ] {
            assert_eq!(api_client(ua), None, "{ua:?}");
        }
    }

    /// The UA is attacker-controlled and the token is persisted into
    /// queue.json and rendered in the drawer, so nothing that could hurt
    /// either may survive classification.
    #[test]
    fn a_hostile_user_agent_yields_nothing_dangerous() {
        for bad in [
            "../../etc/passwd",
            "..\\..\\windows",
            "<script>alert(1)</script>",
            "a\"; DROP TABLE jobs;--",
            "\u{202e}gnp.exe",
            "Кино.2024.Фильм",
            "\0\0\0",
            "\n\r\tSonarr",
        ] {
            if let Some(tok) = api_client(bad) {
                assert!(
                    tok.chars()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'),
                    "{bad:?} -> {tok}"
                );
                assert!(tok.chars().count() <= 24, "{bad:?} -> {tok}");
            }
        }
        // 500 chars of one token must not persist 500 chars.
        let long = api_client(&format!("{}/1.0", "a".repeat(500))).unwrap();
        assert_eq!(long.chars().count(), 24);
        // Nor may a long name smuggle bytes past the cap by hiding them
        // behind characters the filter drops.
        let mixed = api_client(&"a/b".repeat(200)).unwrap();
        assert_eq!(mixed, "a");
    }

    /// Old records and unidentified callers keep today's behaviour: the
    /// fallback is used verbatim, so nothing needs a queue.json migration.
    #[test]
    fn the_fallback_is_untouched_when_nobody_names_themselves() {
        assert_eq!(
            api_origin("Sonarr/4.0.19.2979 (macos 10.0)", "dashboard"),
            "arr:sonarr"
        );
        assert_eq!(
            api_origin("Mozilla/5.0 (X11; Linux x86_64)", "dashboard"),
            "dashboard"
        );
        assert_eq!(api_origin("", "arr"), "arr");
        assert_eq!(api_origin("nzb360/17.4 (Android 14)", "arr"), "arr:nzb360");
    }
}

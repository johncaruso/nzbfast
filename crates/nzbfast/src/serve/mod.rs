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
mod histstore;
#[cfg(feature = "indexer")]
pub(crate) mod predb_seed;
mod tasks;

mod probeids;

mod mover;
mod postproc;
use postproc::*;

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
    /// §129 2a: PEM certificate chain for opt-in native HTTPS. With
    /// `tls_key` set too, the ONE listener serves https instead of http;
    /// either alone (or neither) keeps plain HTTP, with a startup note
    /// saying which half is missing. Applied at bind time only - change
    /// via settings + restart, like the port.
    pub tls_cert: Option<PathBuf>,
    /// PEM private key matching `tls_cert`.
    pub tls_key: Option<PathBuf>,
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

mod bootstrap;
use bootstrap::*;

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

mod disk;
pub(crate) use disk::*;

mod update;
use update::*;

fn epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

mod groupscan;
use groupscan::*;

mod origin;
use origin::*;

mod maint;
use maint::*;

mod settings;
use settings::*;

mod watchlist;
use watchlist::*;

mod servers;
use servers::*;

mod startup;
use startup::*;

// §125: the throughput graph's learned 100% anchor.
mod linkpeak;

// §129 4b: "Why is this slow?" - live per-job attribution.
mod whyslow;

// §129 3e (§108 decision 4): the chronic slow-storage pause.
mod slowstore;

/// Default for `slow_storage_pause`. ON: decision 4's whole point is
/// that a user whose enclosure is dying should be TOLD, not left
/// watching a sawtooth and blaming their line. The downside of a false
/// positive is bounded by design - the job parks in the queue with its
/// journal intact and comes back on its own the moment three clean write
/// checks land - and the pause has to clear a windowed judge AND a real
/// slow probe before it can fire at all.
pub const SLOW_STORAGE_PAUSE_DEFAULT: bool = true;

pub async fn serve(config: PathBuf, mut opts: ServeOpts) -> Result<()> {
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
    warn_if_config_moved(&minted_key, &opts.out_root);
    // Saved settings may have overridden the CLI budget; republish so the
    // repair paths use the same figure the rest of the daemon does.
    nzbkit::mem::set_process_budget(opts.mem_budget);
    // The listener, the single-instance lock and the Daemon itself
    // (startup.rs). The lock guard rides home in `booted` and must stay
    // alive for the whole run - dropping it frees the lock.
    let booted = boot(&config, &settings_path, opts)?;
    let daemon = booted.daemon.clone();
    let spool = &booted.spool;

    restore_runtime_state(&daemon, &settings_path, spool, &config, &booted.speedlimit)?;

    spawn_core_tasks(
        &daemon,
        &config,
        &settings_path,
        &booted.schedule,
        &booted.feeds,
        #[cfg(feature = "indexer")]
        &booted.index_db,
        booted.mem_budget,
    )?;

    #[cfg(feature = "indexer")]
    let tmdb_key = config_tmdb_key(&config);
    #[cfg(feature = "indexer")]
    tasks::spawn_enrichment_workers(&daemon, &tmdb_key);
    spawn_aux_tasks(&daemon, &config);

    announce_ready(
        &daemon,
        &settings_path,
        &booted.bind,
        booted.port,
        booted.tls_on,
        &minted_key,
        &mut mint_disclosure,
        booted.open,
    );
    #[cfg(feature = "indexer")]
    http::spawn_http_workers(
        booted.server,
        daemon.clone(),
        config.clone(),
        tmdb_key.clone(),
    );
    #[cfg(not(feature = "indexer"))]
    http::spawn_http_workers(booted.server, daemon.clone(), config.clone());

    park_for_embedded_stop().await;
    // Returning drops our Arc<server>; the workers drop theirs within one
    // HTTP_IDLE_TICK (they poll the stop flag between accepts), and the
    // last drop closes the listener so the port is free to rebind.
    Ok(())
}

/// Park until an embedded host asks for an in-process stop. The CLI
/// daemon never does - its stop paths (signals, tray Quit) exit the
/// process - so for it this parks forever, exactly as before.
async fn park_for_embedded_stop() {
    // The armed baseline cannot move while this run is alive: arming
    // happens under the embedded host's engine lock, which a next start
    // can only take after this run's stop() has joined the engine thread.
    let baseline = STOP_BASELINE.load(std::sync::atomic::Ordering::SeqCst);
    loop {
        stop_notify().notified().await;
        if STOP_EPOCH.load(std::sync::atomic::Ordering::SeqCst) > baseline {
            break;
        }
    }
}

/// One tick of the HTTP workers' accept wait. Long enough to cost
/// nothing (8 workers waking twice a second), short enough that an
/// embedded stop releases the listener promptly.
const HTTP_IDLE_TICK: std::time::Duration = std::time::Duration::from_millis(500);

/// Monotonic count of [`request_stop`] calls, compared against the
/// baseline armed by [`arm_embedded_stop`]. A run is stopped once the
/// epoch has moved past its armed baseline. Monotonic on purpose: a
/// previous run's workers keep winding up on the old epoch bump even
/// after the next run re-arms, and a stop issued in the window between
/// start() returning and serve() starting can never be erased (the old
/// reset-at-entry design lost exactly that stop and hung the caller's
/// join forever).
static STOP_EPOCH: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Epoch snapshot taken by [`arm_embedded_stop`] before the engine
/// thread for a run is spawned. The CLI daemon never arms (both stay 0
/// and `request_stop` is never called there).
static STOP_BASELINE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Arm the next embedded run: snapshot the stop epoch so a leftover
/// stop request from a previous run cannot fell this one. Must be
/// called by the embedded host BEFORE spawning the engine thread and
/// under the same lock that serializes start against stop, so every
/// `request_stop` issued after start() returns lands above the
/// baseline.
// dead_code: only the embedded crate root (lib.rs, `ffi` feature) has a
// caller; see request_stop below.
#[allow(dead_code)]
pub fn arm_embedded_stop() {
    STOP_BASELINE.store(
        STOP_EPOCH.load(std::sync::atomic::Ordering::SeqCst),
        std::sync::atomic::Ordering::SeqCst,
    );
}

fn stop_notify() -> &'static tokio::sync::Notify {
    static N: std::sync::OnceLock<tokio::sync::Notify> = std::sync::OnceLock::new();
    N.get_or_init(tokio::sync::Notify::new)
}

/// In-process stop for embedded builds (the iOS staticlib, where exec
/// and process exit are not available): [`serve`] returns instead of
/// parking and the HTTP workers wind up, closing the listener. This is
/// NOT the graceful wind-down the signal path runs - the embedded host
/// stops the tokio runtime after serve() returns, which is what cancels
/// the background tasks. Safe to call before serve() reaches its park
/// loop or more than once per run: the epoch bump is permanent and a
/// Notify permit is held until consumed.
// dead_code: only the embedded crate root (lib.rs, `ffi` feature) has a
// caller; the CLI daemon stops by process exit. The module compiles
// under both roots, so the bin build sees this as dead.
#[allow(dead_code)]
pub fn request_stop() {
    STOP_EPOCH.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    stop_notify().notify_one();
}

mod http;
mod stream;
use stream::*;

mod httputil;
use httputil::*;

mod sabcompat;
use sabcompat::*;

mod script;
use script::*;

mod apiutil;
use apiutil::*;

mod fetch;
pub(crate) use fetch::*;

mod indexers;
pub(crate) use indexers::*;

mod reqbody;
use reqbody::*;

mod fsutil;
use fsutil::*;

mod history;
use history::*;

mod sched;
use sched::*;

mod assets;
use assets::*;

mod webasset;
use webasset::*;

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
#[path = "tests_api.rs"]
mod tests_api;

#[cfg(test)]
#[path = "tests_jobs.rs"]
mod tests_jobs;

#[cfg(test)]
#[path = "tests_grabs.rs"]
mod tests_grabs;

#[cfg(test)]
#[path = "tests_index.rs"]
mod tests_index;

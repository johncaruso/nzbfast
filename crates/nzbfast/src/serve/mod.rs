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
        link_peak: linkpeak::LinkPeak::load(spool.join("linkpeak.json")),
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

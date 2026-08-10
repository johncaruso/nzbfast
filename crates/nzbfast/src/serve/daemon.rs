use super::*;
use tracing::{error, info, warn};

// The index-handle discipline and the M34 size cap - a second `impl Daemon`,
// moved out bodily (TODO 106). A child module, so it keeps the private
// fields and the private reader types in scope.
#[path = "daemon_index.rs"]
mod daemon_index;

/// How many index reads may be in flight at once.
///
/// The point is the gap between this and the HTTP worker count (8): a
/// query surface that has gone slow can occupy at most this many
/// workers, so `/`, `mode=version`, the queue and the *arr endpoints
/// keep answering out of the remainder no matter what the index is
/// doing. WAL readers run concurrently, so these are real parallelism
/// as well as a ceiling - the single shared read connection they
/// replace serialized every query handler behind whichever one was
/// slowest.
#[cfg(feature = "indexer")]
pub(super) const INDEX_READ_CONNS: usize = 4;

/// How long a request may wait for a free read connection before it is
/// told the index is busy.
///
/// A healthy read against this database is sub-millisecond, so this is
/// two orders of magnitude of headroom for an ordinary burst - and a
/// hard promise that a saturated index costs an HTTP worker a tenth of
/// a second rather than however long the slowest query runs.
#[cfg(feature = "indexer")]
pub(super) const INDEX_READ_WAIT: std::time::Duration = std::time::Duration::from_millis(100);

/// The read-only connection pool behind [`Daemon::with_index_read`].
///
/// Deliberately hand-rolled rather than a channel: `drop_index_read`
/// has to invalidate connections that are LENT OUT right now (index_wipe
/// deletes the file under them), which the generation stamp does without
/// waiting for their queries to end.
#[cfg(feature = "indexer")]
#[derive(Default)]
pub struct IndexReadPool {
    inner: Mutex<IndexReadState>,
    /// Signalled every time a connection is handed back.
    handed_back: std::sync::Condvar,
}

#[cfg(feature = "indexer")]
#[derive(Default)]
struct IndexReadState {
    /// Open connections nobody is using.
    idle: Vec<nzbkit::index::Index>,
    /// How many exist at all - idle plus lent out. The ceiling is
    /// [`INDEX_READ_CONNS`].
    live: usize,
    /// Bumped by `drop_index_read`. A connection handed back carrying an
    /// older stamp is closed instead of pooled, so a handle opened
    /// against a since-deleted database can never be served from again.
    generation: u64,
}

/// A borrowed read-only connection, returned to the pool on drop - including
/// on the unwind out of a panicking handler, which is why this is a guard and
/// not a matched pair of calls. A leaked connection would shrink the pool by
/// one permanently, and four panics would close the read path for good.
#[cfg(feature = "indexer")]
pub(super) struct IndexReader<'a> {
    pool: &'a IndexReadPool,
    /// `Some` until dropped.
    conn: Option<nzbkit::index::Index>,
    generation: u64,
}

#[cfg(feature = "indexer")]
impl std::ops::Deref for IndexReader<'_> {
    type Target = nzbkit::index::Index;
    fn deref(&self) -> &Self::Target {
        // Some until Drop runs, and Drop is the only thing that takes it.
        self.conn.as_ref().expect("reader used after drop")
    }
}

#[cfg(feature = "indexer")]
impl Drop for IndexReader<'_> {
    fn drop(&mut self) {
        let Some(conn) = self.conn.take() else { return };
        let mut st = self.pool.inner.lock_ok();
        if self.generation == st.generation {
            st.idle.push(conn);
        } else {
            // Retired mid-query. Closing it here is what keeps `live`
            // honest; the drop happens under the lock, which is a
            // sqlite3_close on an idle connection.
            st.live = st.live.saturating_sub(1);
            drop(conn);
        }
        drop(st);
        self.pool.handed_back.notify_one();
    }
}

/// Every read connection is in use. Not an error in the database sense -
/// nothing failed, the answer just is not available cheaply right now.
#[cfg(feature = "indexer")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct IndexBusy;

/// What [`Daemon::index_read_acquire`] could do for the caller.
#[cfg(feature = "indexer")]
enum Reader<'a> {
    Got(IndexReader<'a>),
    /// Every connection is in use and none came free in time. The caller
    /// must NOT fall back to the read-write handle: parking on that mutex
    /// is the exact failure this path exists to prevent.
    Busy,
    /// No read-only connection could be opened at all (no database file
    /// yet). Startup-shaped, and the caller falls back to `with_index`.
    Unavailable,
}

/// RAII claim on "a connection ladder is running".
///
/// Released on drop, INCLUDING the drop that happens when a ladder
/// future is cancelled by its caller's timeout - which is the case a
/// bare set/clear pair gets wrong, leaving the tuner permanently
/// "busy" after one slow provider.
pub(in crate::serve) struct LadderPermit(std::sync::Arc<Daemon>);

impl LadderPermit {
    /// `None` when another ladder already holds it.
    pub(in crate::serve) fn try_take(d: &std::sync::Arc<Daemon>) -> Option<Self> {
        d.ladder_busy
            .compare_exchange(
                false,
                true,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
            )
            .is_ok()
            .then(|| LadderPermit(d.clone()))
    }
}

impl Drop for LadderPermit {
    fn drop(&mut self) {
        self.0
            .ladder_busy
            .store(false, std::sync::atomic::Ordering::Release);
    }
}

/// A connection ladder in flight, as the dashboard sees it.
#[derive(Clone, serde::Serialize)]
pub struct LadderLive {
    pub host: String,
    /// What the ladder is doing right now, as a TOKEN the UI translates:
    /// climb, recheck, refine, ceiling, runoff, runoff2, done.
    pub phase: String,
    /// Connection count currently being measured.
    pub at: usize,
    /// Every rung settled so far, oldest first.
    pub steps: Vec<nzbkit::sysbench::LadderStep>,
    /// Unix seconds when this run started, so the UI can show elapsed
    /// time without trusting its own clock against the daemon's.
    pub started: u64,
    pub done: bool,
}

/// §129 2b (decision 5): one category's real behavior. Stored in
/// settings.json under `cat_meta` as `{name: {dir, priority, script}}`;
/// every field defaults to "as before".
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub(super) struct CatMeta {
    /// Subfolder of the download root this category lands in (may
    /// nest, "tv/anime"). Empty = a subfolder named after the
    /// category. Absolute destinations stay the mover's job
    /// (`move_completed_cats`).
    #[serde(default)]
    pub dir: String,
    /// Default priority for adds that did not name one (-100). None =
    /// no default. SAB range: -1 low, 0 normal, 1 high, 2 force.
    #[serde(default)]
    pub priority: Option<i32>,
    /// Post-processing script for this category; empty = the global
    /// script setting. A job-level `script=` param still wins.
    #[serde(default)]
    pub script: String,
}

pub struct Daemon {
    /// Streaming handle into the active download (M11).
    pub hub: Arc<crate::StreamHub>,
    /// Paused: no NEW job starts (the active transfer finishes).
    pub paused: std::sync::atomic::AtomicBool,
    /// OFFLINE: touch no provider at all, and hang up everything already
    /// held - the warm pools, the availability oracle's and tip
    /// watcher's sessions, the scan fleet.
    ///
    /// Stronger than pause, and a different question. Pause is about the
    /// QUEUE ("stop starting downloads") and deliberately leaves the
    /// background legs running, because indexing a group is not
    /// downloading. Offline is about the ACCOUNT ("this machine is not
    /// using the provider right now"), which the operator wants when
    /// they are about to use it from a laptop or a seedbox and their
    /// provider only allows one or two addresses at a time. The
    /// idle-release policy answers the same need on a timer; this is the
    /// instant version, for when waiting out a timeout is not what you
    /// want.
    pub offline: std::sync::atomic::AtomicBool,
    /// Whether it was OFFLINE that paused the queue.
    ///
    /// Going offline pauses, so the queue does not spend the outage
    /// starting jobs that cannot connect and burning retries on articles
    /// that were never missing. Coming back online must therefore NOT
    /// unpause a queue the operator had paused themselves, which this
    /// remembers. Set only while holding the transition.
    pub paused_by_offline: std::sync::atomic::AtomicBool,
    pub queue: Mutex<VecDeque<Arc<Mutex<Job>>>>,
    pub history: Mutex<Vec<Arc<Mutex<Job>>>>,
    /// §129 1b: the dashboard's change handles. Bumped at the
    /// persistence seam - `save_queue` for the queue, every history
    /// store write for history - so `mode=dashboard` can answer "nothing
    /// changed" with two atomic loads instead of two payloads. Progress
    /// counters deliberately touch neither: while anything downloads the
    /// queue section is sent regardless (continuous values have no
    /// honest revision).
    pub queue_rev: AtomicU64,
    pub history_rev: AtomicU64,
    /// §129 1b: discrete lifecycle events (job.completed, job.failed...)
    /// with a monotonic `seq`, so clients stop inferring toasts from
    /// snapshot diffs. Ring bounded at `histstore::LIFE_RING`; a client
    /// behind the tail is told to reseed rather than replayed.
    pub life_seq: AtomicU64,
    pub life_events: Mutex<VecDeque<Value>>,
    /// §129 D5: optional retention, BOTH 0 = unlimited (the shipped
    /// default, by ruling). Count keeps the newest N records;
    /// days drops Completed records older than N days.
    pub history_keep_count: AtomicU64,
    pub history_keep_days: AtomicU64,
    /// Serializes "decide where this job goes" against "publish it".
    ///
    /// `choose_out_dir` asks `dir_claim`, which takes and RELEASES the
    /// queue and history locks per probe, and the job only becomes
    /// visible when it is pushed onto the queue much later. Two of the
    /// eight HTTP workers adding names that resolve to one stem both saw
    /// Free, both passed the duplicate check before either was visible,
    /// and both jobs were published with the same `out_dir` - whose
    /// pipelines then overlap by design, so one truncates files the
    /// other is reading. The queue mutex protects the deque, not that
    /// decision. Held across choose + duplicate check + publish; also
    /// taken by the retry and recategorize paths, which pick
    /// directories by the same rule.
    ///
    /// Never taken while holding a queue, history or job lock - it sits
    /// ABOVE all three, and `dir_claim` locks every job in both lists.
    pub add_lock: Mutex<()>,
    /// nzo_ids whose payload is being MOVED on disk right now.
    ///
    /// Recategorizing a finished job runs `move_tree` with no locks
    /// held, deliberately - on a NAS it takes seconds and the queue must
    /// not stall behind it. But the job it snapshotted stays fully live
    /// meanwhile: an auto-retry whose cooldown came due pulled the same
    /// record out of history, reset it to Queued and let the scheduler
    /// start writers at the old path while the move was emptying it, and
    /// a history delete removed the record from under the move entirely.
    /// A job listed here refuses both until the move settles.
    pub moving: Mutex<std::collections::HashSet<String>>,
    /// The mover's work queue: finished jobs whose move to the
    /// completed folder is owed (Job::move_pending). Fed by finalize,
    /// unlock and the boot rescan; drained by per-TARGET sequential
    /// lanes (serve/mover.rs) - same destination stays serial, two
    /// different destinations never queue behind each other.
    pub(super) mover_q: Mutex<VecDeque<Arc<Mutex<Job>>>>,
    /// Wakes the mover when `mover_q` gains work.
    pub(super) mover_wake: tokio::sync::Notify,
    /// The mover's pacing token bucket - ONE for the whole daemon, so
    /// concurrent lanes divide one budget instead of each granting
    /// itself the whole of it. See [`mover::mover_pacer`].
    pub(super) mover_bucket: Mutex<mover::PaceState>,
    /// How file moves share the machine with downloads ("File moves").
    /// "yield" (default): pace the copy to the measured headroom and go
    /// full speed when the queue is idle. "full": never pace. Any
    /// integer: a fixed cap in MB/s. One setting with three modes on
    /// purpose - fast networks want "full", shared links want a number,
    /// everyone else wants downloads to win.
    pub(super) move_pace: Mutex<String>,
    /// Output directories chosen but not yet owned by any job record.
    ///
    /// `dir_claim` answers from the queue and history, so a directory
    /// picked for a payload that is still being MOVED into it belongs to
    /// nobody and reads as Free - and a job added meanwhile is handed
    /// the folder a move is filling. Held only across that gap, and
    /// consulted by `dir_claim` as Active.
    pub reserved: Mutex<std::collections::HashSet<PathBuf>>,
    /// Decoded bytes of the ACTIVE job (shared with the get pipeline).
    pub progress: Arc<AtomicU64>,
    pub active_total: AtomicU64,
    /// The nzo_id whose NETWORK phase owns `progress` / `active_total`
    /// right now, or None between jobs.
    ///
    /// The scheduler deliberately starts job N+1 while job N's tail
    /// (settle, verify, repair, unpack) still runs, and BOTH stay
    /// `Downloading` in the queue for all of it - so "the Downloading
    /// slot" was never a safe way to pair a row with these counters. It
    /// was not one: job N+1 zeroes them at its start, and job N's row,
    /// the hero card and the drawer's per-server baseline all read the
    /// globals unconditionally, so a finishing job's bar fell from ~98%
    /// to 0 and then climbed with a download that was not its own.
    ///
    /// Written with the counters themselves (one lock section, so no
    /// reader can pair this owner with the next job's zeroes) and
    /// cleared at network-drain beside `started_at`, whose lifetime this
    /// exactly shares: "this job's network phase is live".
    pub active_dl: Mutex<Option<String>>,
    pub started_at: Mutex<Option<Instant>>,
    /// When the daemon last stopped downloading - the clock the
    /// idle-release policy runs on. Initialised at boot, so a daemon
    /// that has never run a job counts as idle since it started rather
    /// than as never-idle.
    ///
    /// Distinct from `started_at`, which answers "is a job running right
    /// now". Releasing an account needs the other half of that: how long
    /// it has been since one was.
    pub last_download_end: Mutex<Instant>,
    /// Open transfer-stall episode on the active fetch, if any:
    /// (owning nzo_id, when bytes last moved). Written only by the
    /// watchdog's stall tracker (tasks.rs) - observation, never action -
    /// and read by the queue payload so the active row can say "no data
    /// for Ns" instead of a silently flat chart.
    pub stall_since: Mutex<Option<(String, Instant)>>,
    /// A2 playback contract: memo for the DISK half of per-file playback
    /// readiness, `nzo_id -> (unix secs, media file name and size)`.
    /// Finding a finished job's media file is a bounded directory walk,
    /// and the compact mobile poll asks about a page of history every
    /// few seconds; the answer only changes when someone moves the
    /// files. Entries age out (see `DISK_READINESS_TTL_SECS`).
    pub playback_disk: Mutex<std::collections::HashMap<String, (u64, Option<(String, u64)>)>>,
    pub next_id: AtomicU64,
    /// Download root. Live-swappable (Settings "Download folder"): a change
    /// applies to the NEXT enqueue without a restart. Read via `out_dir()`.
    /// The `spool` below is derived once at startup and stays put, so the
    /// queue journal / usage ledger / art cache never move out from under a
    /// running daemon.
    pub out_root: std::sync::RwLock<PathBuf>,
    /// M33: when set, completed jobs move here after unpack/rename/
    /// filing - e.g. a NAS share - preserving the category subfolder
    /// layout. None = leave downloads under out_root. Live setting
    /// (`move_completed`); for what a failed move leaves behind see
    /// `relocate_completed`.
    pub move_completed: std::sync::RwLock<Option<PathBuf>>,
    /// M33 v2: per-category destination overrides ("tv=/NAS/TV, …").
    /// An override IS that category's root - the category subfolder is
    /// not repeated inside it. Overrides apply even when the global
    /// `move_completed` is unset (only listed categories move then).
    pub move_completed_cats: std::sync::RwLock<Vec<(String, PathBuf)>>,
    pub spool: PathBuf,
    /// The config file this daemon was started with. Held so the rename
    /// pipeline can read a bring-your-own-key value (the TMDB key) at
    /// the moment it needs one: the enrichment worker reads its copy
    /// once at startup, but a user who adds a key later should not have
    /// to restart for the identifier to gain its second source.
    pub cfg_path: PathBuf,
    /// Categories offered to the *arrs via `get_cats` and the NZBGet
    /// `config` category table. Seeded from [`DEFAULT_CATS`], extended by
    /// the `categories` setting, and by every category ever seen on an
    /// add call - see [`Daemon::register_cat`] for why the last of those
    /// is now written through to settings.
    pub cats: Mutex<std::collections::BTreeSet<String>>,
    pub port: u16,
    /// Per-start secret shared with the desktop wrapper through
    /// `runtime.json` - see [`write_runtime_file`]. Never logged, never
    /// sent: it is only ever hashed with a caller-supplied nonce, which is
    /// what lets a wrapper tell this daemon from anything else holding the
    /// port before it hands over the API key.
    pub launcher_token: String,
    /// The launcher owns the port, not the dashboard (see
    /// [`port_locked`]). Set for a container, a compose service and the
    /// Synology package, where the listening port is baked into a
    /// published mapping, a healthcheck or DSM's own Open button, and a
    /// saved override just makes the install unreachable.
    pub port_locked: bool,
    /// §129 2a: the TLS pair THIS run is serving with (None = plain
    /// HTTP). Bind-time state like [`port`](Self::port), not live state:
    /// the settings rows persist a new pair, `pending` surfaces the
    /// difference, and a restart applies it.
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
    pub library_cats: Mutex<Vec<String>>,
    /// nzo_id whose extractor the hub holds (the last real download started).
    pub active_stream: Mutex<Option<String>>,
    /// M12: index database path.
    #[cfg(feature = "indexer")]
    pub index_db: PathBuf,
    /// M12: the shared read-WRITE Index connection (tip watcher, wall
    /// enricher, IMDb refresher, eviction, and every handler that
    /// mutates), opened lazily - None until first use, because the index
    /// is an optional feature and must never block the daemon from
    /// starting. The original single-connection rule ("one connection
    /// avoids cross-connection WAL races") stopped being literal at M28:
    /// each scan task ingests through its own scratch connection and the
    /// busy timeout arbitrates the writers, so cross-connection use
    /// against this WAL database is the daily norm, not a hazard.
    #[cfg(feature = "indexer")]
    pub index: Mutex<Option<nzbkit::index::Index>>,
    /// The read-ONLY siblings for interactive query handlers (wall2,
    /// search, browse, make_nzb, the newznab facade). WAL readers never
    /// wait on the writer, so these endpoints answer during a catch-up
    /// ingest or maintenance pass that holds the connection above for a
    /// minute straight - measured 28 Jul: a wall2 curl queued 62.4s
    /// behind a deepening pass. Opened lazily via `with_index_read`
    /// (only ever AFTER the read-write side has run the migrations), and
    /// retired at every point that drops or republishes the write
    /// connection.
    ///
    /// A POOL, and a bounded wait for it, since 2 Aug. The single shared
    /// read connection this replaces had "all its holds are short
    /// queries" as an unenforced assumption, and on a 32M-release index
    /// it stopped being true: `wall2` spent 85s on a COUNT and
    /// `wall_tip` 76s on a full scan, each holding that one mutex, so
    /// every other query handler queued behind it and parked an HTTP
    /// worker apiece. Eight such waits and the daemon answered nothing
    /// at all - the same silence as 28 Jul, one mutex further along.
    /// See [`INDEX_READ_CONNS`] for why a ceiling matters more than the
    /// concurrency.
    #[cfg(feature = "indexer")]
    pub index_read: IndexReadPool,
    /// When the saturation warning above was last logged (epoch seconds),
    /// so a wedged query surface reports itself once a minute instead of
    /// once per poll.
    #[cfg(feature = "indexer")]
    pub index_read_warned: AtomicU64,
    /// Whether a read-write `Index::open` has succeeded in this process
    /// - i.e. schema creation and migrations have run. Until then
    /// `with_index_read` routes through `with_index`, so a query handler
    /// can never open the read-only connection against a database an
    /// older binary wrote and trip over a missing column.
    #[cfg(feature = "indexer")]
    pub index_migrated: std::sync::atomic::AtomicBool,
    /// Last computed index_stats figures (releases, complete, db_bytes,
    /// live_bytes), served whenever the connection above is busy. The
    /// dashboard's 15s status poll must never park an HTTP worker on
    /// that mutex: a catch-up ingest once held it 62s straight, each
    /// poll parked another of the 4 workers, and one open dashboard
    /// tab wedged the whole API (28 Jul hang).
    #[cfg(feature = "indexer")]
    pub index_stats_cache: Mutex<Option<(u64, u64, u64, u64)>>,
    /// M14g3 auto-speed governor on/off (live-toggleable).
    pub auto_speed: std::sync::atomic::AtomicBool,
    /// STAT-sample every job before downloading it (settings.json
    /// `preflight`). See `ServeOpts::preflight` for why it is off by
    /// default and why it has no dashboard switch.
    pub preflight: std::sync::atomic::AtomicBool,
    /// M7b.1 connection auto-tune on/off (live setting
    /// auto_connections): while the queue is idle, probe each provider's
    /// connection ladder and cap its per-job connections at the knee -
    /// over-asking measured 3-4× slower (connect-flood defense).
    pub auto_connections: std::sync::atomic::AtomicBool,
    /// TODO 112 live connection tuning on/off (live setting
    /// `live_tune`, default OFF until the §129 real-line gate passes;
    /// NZBFAST_LIVE_TUNE=1 is the dev override). With it ON the epoch
    /// controller chooses each server's connection count during
    /// downloads and the stored knee stops capping jobs - measurements
    /// SEED, only typed numbers cap (conn-tuning design, 8 Aug 2026).
    /// Mirrored onto `hub.live_tune` because the pool build in
    /// get/fleet.rs has the hub, not the daemon.
    pub live_tune: std::sync::atomic::AtomicBool,
    /// Hosts currently carrying the decay flag (conn-tuning design §6),
    /// mirrored from conntune.json by the live tuner so the 1 s queue
    /// poll never re-reads the file. Seeded at spawn, updated on every
    /// raise/clear.
    pub shaped_hosts: Mutex<std::collections::HashMap<String, crate::conntune::Shaped>>,
    /// Leave adult titles out of the poster wall and the release list
    /// (settings key `wall_hide_adult`, default ON).
    ///
    /// On by default because the Spotnet source already made that call
    /// for the same reason and the wall should not disagree with it. The
    /// curated views only: every uncurated facade - newznab, the *arrs -
    /// is untouched, because a filter the user set for their own browsing
    /// is not a filter to impose on an automation's search results.
    pub wall_hide_adult: std::sync::atomic::AtomicBool,
    /// Slow-job watchdog on/off (live setting auto_defer): demote a job
    /// that is single-server-bound and slow while other jobs wait.
    pub auto_defer: std::sync::atomic::AtomicBool,
    /// TODO §77 post-health prediction on/off (live setting
    /// `post_health`): STAT a handful of a queued job's articles across
    /// every server and badge the row with the verdict.
    ///
    /// ON by default, unlike `preflight` above, because the two do
    /// different things: `preflight` FAILS a job on its own evidence and
    /// so has to be asked for, while this only ever puts a coloured dot
    /// and a sentence on a queue row. A few dozen STATs per job is the
    /// entire cost.
    pub post_health: std::sync::atomic::AtomicBool,
    /// TODO §77 auto-defer on the health verdict (live setting
    /// `post_health_defer`): a red job sinks below healthier ones of the
    /// same priority in start order.
    ///
    /// OFF by default, and REORDERING ONLY - nothing is removed, paused
    /// or failed. A sample of eight articles is not allowed to decide
    /// that a release is dead (memory `nzbfast-retry-propagation-trap`);
    /// the most it may do is let the queue try the healthy-looking items
    /// first, which costs the red job nothing if the sample was wrong.
    pub post_health_defer: std::sync::atomic::AtomicBool,
    /// Update checker: the manifest of a NEWER version once one is seen
    /// (None = up to date as far as we know), the check on/off toggle,
    /// and the manifest URL (live settings update_checks/update_url).
    /// NOTIFY-ONLY: the daemon never downloads or replaces its own
    /// binary - a newer version just raises the dashboard banner, which
    /// links to the download page.
    pub update_manifest: Mutex<Option<Value>>,
    pub update_checks: std::sync::atomic::AtomicBool,
    /// Highest `serial` ever seen in a signature-verified manifest; 0 =
    /// none seen yet. Persisted (settings `update_serial_seen`) so the
    /// ratchet survives a restart.
    ///
    /// READ-ONLY IN THIS RELEASE, DELIBERATELY. Nothing refuses a manifest
    /// on account of its serial yet - this build only records what it saw
    /// and warns when a serial goes backwards. The enforcing build comes
    /// later, and must not be the first one that clients meet: the stored
    /// value is a one-way local ratchet with no server-side reset, so a
    /// generator that emitted a wrong or absent serial would permanently
    /// wedge the update channel on every install that recorded it, and no
    /// later release could unwedge it. Shipping read-first buys a release
    /// cycle of field evidence that serials really are present and really
    /// are monotonic, before anything depends on that being true.
    pub update_serial_seen: std::sync::atomic::AtomicU64,
    /// Display preference only (not behaviour): show speeds in bits (Mb/s)
    /// instead of bytes (MB/s). Per-daemon so every dashboard client agrees.
    pub unit_bits: std::sync::atomic::AtomicBool,
    pub update_url: Mutex<String>,
    /// §5 i18n: daemon-default UI locale ("" = auto/navigator.language).
    /// Injected into the served dashboard/wall HTML so embedded webviews
    /// (which have no saved browser preference) come up in the right
    /// language. Live setting ui_locale; the API itself stays English.
    pub ui_locale: Mutex<String>,
    /// Auto-deepen (live setting index_deepen): articles of group
    /// HISTORY each scan pass adds below the low-water mark, so the
    /// index grows backward in the background. 0 = off.
    pub index_deepen: AtomicU64,
    /// A8 multi-server indexing (live setting index_coverage, ON by
    /// default): besides the per-group primary, every other eligible
    /// backbone advances its own forward tip so single-backbone posts
    /// and propagation holes still reach the index.
    pub index_coverage: std::sync::atomic::AtomicBool,
    /// A8 targeted gap-fill (live setting index_gapfill): incomplete
    /// releases per scan pass whose posting window is re-OVERed on the
    /// secondary backbones to hunt their missing segments. 0 = off.
    pub index_gapfill: AtomicU64,
    /// Scheduled system benchmark (live setting bench_interval): hours
    /// between automatic sysbench runs, 0 = off. Results (scheduled AND
    /// manual) append to .spool/bench_history.json.
    pub bench_interval: AtomicU64,
    /// Epoch-seconds of the last benchmark run (either kind).
    pub bench_last: AtomicU64,
    /// Idle-server prefetch on/off (live setting auto_prefetch): servers
    /// the active job can't use (their copies 430'd) download the next
    /// queued job in a restricted secondary pipeline instead of idling.
    pub auto_prefetch: std::sync::atomic::AtomicBool,
    /// "Race slow articles" (live setting race_stragglers, ON by
    /// default): the pool may fetch a straggling article from more than
    /// one connection at once - first copy wins, the loser is abandoned
    /// - and replace a session delivering far below its siblings. Costs
    /// a fraction of a percent of extra traffic; measured to halve the
    /// end-of-job tail and to rescue stalled articles in under a second
    /// instead of eight. The pool reads settings.json per job, so a
    /// flip applies from the next download; this atomic backs the
    /// settings API's live read.
    pub race_stragglers: std::sync::atomic::AtomicBool,
    /// "Adaptive connection timeouts" (live setting adaptive_timeouts,
    /// ON by default): replaces the flat 30 s per-response timeout with
    /// a two-phase bound - a pre-first-byte budget trained on each
    /// server's measured response latency (a dead connection is cut in
    /// seconds instead of half a minute) plus a no-progress deadline
    /// once bytes flow, so a slow but alive transfer is never cut.
    /// Fault rigs: 4x on dead-air stalls, stacks on brownout, zero
    /// false kills on a jittery link. Read from settings.json per job
    /// like race_stragglers; this atomic backs the settings API's live
    /// read. NZBFAST_ADAPTIVE_TIMEOUT overrides in either direction.
    pub adaptive_timeouts: std::sync::atomic::AtomicBool,
    /// M29 opt-in routing (`oracle_route`, OFF by default): when on, a
    /// download skips any of your providers whose backbone the
    /// availability ledger is confident is GONE for the release's
    /// (family, age-bucket), saving the doomed round-trips on takedown'd
    /// content. Guarded so it never removes your last usable provider.
    pub oracle_route: std::sync::atomic::AtomicBool,
    /// The running prefetch sidecar, if any.
    pub sidecar: Mutex<Option<Sidecar>>,
    /// nzo_ids whose media chip settled before the identity oracle
    /// answered, so the §76 prober owes them one more on-disk pass
    /// against the canonical name. Pushed by post-processing, drained
    /// by the prober each tick (its final-pass list is task-local, and
    /// a settled job has already left it).
    pub media_rejudge: Mutex<Vec<String>>,
    /// Best sustained download rate seen this session (bytes/sec) - the
    /// reference healthy jobs set for judging slow ones. Fed by the
    /// watchdog's rolling window and by completed-job averages.
    pub best_rate_bps: AtomicU64,
    /// The user/schedule speed cap (0 = unlimited). With the governor on,
    /// this is the CEILING the governed rate moves under; with it off,
    /// it IS the rate.
    pub speed_ceiling: AtomicU64,
    /// M15 budget total, surfaced in the stats host block so the
    /// dashboard can chart RSS as a fraction of its allowance.
    pub mem_budget_total: u64,
    /// M14k RSS feeds - a live setting: the poller re-reads this list
    /// each pass, so dashboard edits apply without a restart.
    pub feeds: Mutex<Vec<crate::rss::FeedConfig>>,
    /// §G: what each feed's last poll did, keyed by feed url. In memory
    /// only - it describes this daemon's run, and a poll interval is
    /// minutes, so a restart refills it almost at once. Pruned by the
    /// poller to the feeds that still exist.
    pub feed_health: Mutex<std::collections::HashMap<String, crate::rss::FeedHealth>>,
    /// §G: the last refusal each news server gave, kept AFTER the pool
    /// it came from is gone. `hub.pool_live` only exists while a job is
    /// running, so the Providers card's refusal detail vanished the
    /// moment the queue drained - which is exactly when someone goes
    /// looking for why nothing downloaded.
    pub last_refusals: Mutex<std::collections::HashMap<String, ServerRefusal>>,
    /// Throughput-attribution events the DAEMON owns - guard pauses,
    /// user pause/resume, cap changes, sidecar starts, indexer yields,
    /// late picks. Same shape and cap as the pool's ring in
    /// `nzbkit::pool::LiveStats`, kept here because `hub.pool_live`
    /// only exists while a job runs and half of what dents throughput
    /// happens outside the pool (the `last_refusals` precedent). The
    /// stats endpoint merges the two rings into one `events` list.
    pub events: Mutex<std::collections::VecDeque<DaemonEvent>>,
    /// M35 third-party Newznab indexers - a live setting, read on every
    /// pull search. Entries carry the user's per-site apikey: masked in
    /// get_config (`has_key`), never logged, never sent to a browser.
    pub indexers: Mutex<Vec<crate::newznab::IndexerConfig>>,
    /// M35 phase 2: may the WATCHLIST spend the user's indexer accounts
    /// looking for wanted items? Read it through
    /// [`Daemon::watchlist_external_on`], never directly: the stored bool
    /// only counts once `watchlist_external_set` says the user answered.
    pub watchlist_external: std::sync::atomic::AtomicBool,
    /// Did the user ever answer that question? The pair is a tri-state:
    /// unset falls back to "on iff at least one indexer is configured",
    /// which is the M35b posture (the local index cannot see obfuscated
    /// posts, so the accounts are the real search surface). An explicit
    /// answer - in EITHER direction - is stored and always wins, so
    /// somebody who turned this off does not get it turned back on by
    /// adding an indexer later.
    pub watchlist_external_set: std::sync::atomic::AtomicBool,
    /// M35 runtime state for the pull-search client: caps cache, daily
    /// hit/grab counters, limit backoffs and the token->result cache
    /// that keeps NZB links (which embed the apikey) server-side.
    pub(super) indexer_rt: Mutex<IndexerRuntime>,
    /// §74: run a watchlist pass the moment a watched release ARRIVES,
    /// rather than waiting up to a minute for the next periodic one.
    /// Default on, and inert without the built-in indexer - the arrivals
    /// it reacts to are the tip watcher's and the pre feed's, so an
    /// install with indexing off never sees one.
    pub watchlist_instant: AtomicBool,
    /// §74: how many instant passes an hour the arrival path may ask
    /// for. 0 = no limit. This bounds PASSES, not grabs: everything a
    /// skipped kick would have found is still grabbed by the periodic
    /// pass a minute later, so the ceiling costs latency on a busy hour
    /// and can never lose a download.
    pub watchlist_instant_max: std::sync::atomic::AtomicU32,
    /// §74: when the instant path last woke the pass, newest last,
    /// trimmed to the last hour - the window `watchlist_instant_max`
    /// applies over.
    #[cfg(feature = "indexer")]
    pub(super) instant_kicks: Mutex<std::collections::VecDeque<i64>>,
    /// §74: arrivals that MATCHED but were not complete yet - release id
    /// → when we first saw it. A post at +6 s is usually still going up,
    /// and the watchlist only ever grabs complete releases, so these are
    /// re-checked on a short cadence instead of being dropped. Missing
    /// articles are never read as final (that is a propagation trap, not
    /// a dead post): an entry simply expires back to the periodic pass.
    #[cfg(feature = "indexer")]
    pub(super) instant_pending: Mutex<std::collections::HashMap<i64, i64>>,
    /// §74: the arrival names that caused the pass now running to be
    /// woken. The pass drains this and stamps any grab it makes of one of
    /// these names as an instant grab - so the record says "this was
    /// grabbed because it arrived", not "a pass happened to run".
    pub(super) instant_hint: Mutex<Vec<String>>,
    /// When `mode=addnzblnk` last ran, newest last, trimmed to the last
    /// [`NZBLNK_WINDOW`].
    ///
    /// This endpoint is the one an OS protocol handler exposes to the
    /// open web: once `nzblnk:` is registered, any page can navigate to
    /// one and, past the browser's own "Open nzbfast?" prompt, reach it.
    /// A link cannot name a location - `h` is a search key, so the
    /// daemon only ever reads its own index or the user's own indexers -
    /// but a page in a loop can still spend two things that are not
    /// free: the unindexed filename scan, and the user's metered
    /// indexer quota. Sliding window, so both are bounded.
    pub(super) nzblnk_recent: Mutex<std::collections::VecDeque<Instant>>,
    /// M23 Smart Folders - a live setting: rules evaluated at enqueue
    /// (first match wins) to pick the category, and remembered per-job
    /// for TV filing at completion.
    pub smart_folders: Mutex<Vec<crate::smart::Rule>>,
    /// Delete a job's .par2 recovery files once it completes and
    /// verifies. Default ON: recovery data is spent the moment the
    /// payload proves intact, and both major clients remove it, so
    /// leaving it reads as a bug ("this NZB is leaving PAR files
    /// behind"). Implemented as an implicit extra entry in the
    /// `cleanup_exts` sweep, so it inherits that sweep's guards.
    pub par_cleanup: AtomicBool,
    /// §129 lane width (settings.json `postproc_jobs`, default 2,
    /// clamp 1..=4). Deliberately not in the settings UI yet - a
    /// setting is three places, and the knob waits for demand.
    pub postproc_jobs: AtomicU64,
    /// §129 3e / §108 decision 4: pause the queue when the output volume
    /// stops keeping up for minutes at a time. The switch, the
    /// thresholds and the live pause all live inside it - see
    /// `serve::slowstore`.
    pub(super) slow_storage: super::slowstore::Governor,
    /// Permissions to put on finished downloads (#20), as a umask: dirs
    /// get `0o777 & !umask`, files `0o666 & !umask`. `u32::MAX` is OFF
    /// and is the default, so an install that says nothing keeps exactly
    /// the modes it has today.
    ///
    /// This exists because ONE umask was covering two trust zones. The
    /// systemd unit sets `UMask=0077` so the spool's API key and provider
    /// credentials are owner-only, which is right - but `--out` lives
    /// inside `ReadWritePaths=/var/lib/nzbfast`, so completed downloads
    /// came out 0700/0600 too and a Sonarr running as any other user
    /// could not read them, nor rename out of the directory. The three
    /// cheap fixes are each wrong in a different direction: relaxing
    /// `UMask` exposes everything the daemon creates at runtime including
    /// a generated API key, moving `--out` relocates downloads for every
    /// existing install on upgrade, and `ExecStartPost=chmod` only ever
    /// reaches the root directory and not the per-job ones made later.
    /// So the output tree gets its modes set explicitly, and the process
    /// umask stays strict.
    ///
    /// Unix only. On Windows it is stored and reported so a config file
    /// survives a round trip through either platform, and does nothing.
    pub out_umask: std::sync::atomic::AtomicU32,
    /// "Fast PAR mode" - route heavy PAR2 repairs through the NTT
    /// syndrome path (research/NTT-STAGE2/3 docs). Live setting,
    /// mirrored into `nzbkit::par2repair::set_fast_par_enabled`; the
    /// `NZBFAST_NTT` environment variable overrides it in both
    /// directions (the bench/test/ops escape hatch), and a verified
    /// divergence trips a process-wide breaker back to the fold path.
    /// Default [`FAST_PAR_DEFAULT`].
    pub fast_par: AtomicBool,
    /// "Unpack with external unrar" - route RAR unpacking through the
    /// unrar subprocess found beside the binary or on PATH, instead of
    /// the native (vendored rars) extractor. Escape hatch for extraction
    /// problems: the native path is faster on every benched shape, so
    /// default off. Obfuscated hash-named sets always take the native
    /// path regardless - the unrar subprocess cannot follow their
    /// naming. Live setting, mirrored into
    /// [`nzbkit::extract::set_prefer_external_unrar`]; the
    /// `NZBFAST_NO_NATIVE_UNRAR` env var forces it on (the pre-setting
    /// escape hatch, kept as an override).
    pub prefer_external_unrar: AtomicBool,
    /// M23 cleanup rules - file extensions deleted from a job's folder
    /// after successful completion. Empty = off.
    pub cleanup_exts: Mutex<Vec<String>>,
    /// SAB/NZBGet-parity passwords file (resolved path; default
    /// `passwords.txt` next to the config): plain text, one candidate
    /// archive password per line, tried in order when a job's volumes
    /// are encrypted and its own password is absent or wrong - both by
    /// the in-stream probe mid-download and by the completion unlock.
    /// Read fresh at every use so hand-edits apply immediately. The
    /// CONTENTS are credentials and never cross get_config or the log;
    /// only the path and a count do.
    pub password_file: Mutex<PathBuf>,
    /// What the dashboard does when an archive turns out passworded:
    /// "now" (prompt the moment the live probe wants one), "done"
    /// (prompt when the job finishes locked - the default), or "never"
    /// (no prompts: the job completes with the archive left packed,
    /// reported through unpack_blocked_by). Consumed client-side except
    /// for the "never" completion shape, which finalize applies.
    pub password_prompt: Mutex<String>,
    /// TODO 101: "off" (the default - volumes are only ever swept AFTER
    /// a successful extraction), "low_disk" (eat them during extraction,
    /// but only on a job whose forecast says it cannot otherwise fit and
    /// whose user consented in the disk-full drawer), or "always" (every
    /// on-disk unpack). Mirrored into [`crate::eatvol`], which is where
    /// the unpack ladder reads it from - several layers below anything
    /// holding a Daemon. An unverified set is never eaten in any mode.
    pub unpack_eat_volumes: Mutex<String>,
    /// TODO 24D user-definable categories - a live setting: match rules
    /// (Smart Folder syntax) that classify releases into user kinds at
    /// scan/finalize time, each with a declared base behavior. Order is
    /// priority. RwLock: read on every scan-pass classify and every
    /// finalize; written only by the settings API.
    pub custom_categories: std::sync::RwLock<Vec<nzbkit::categories::CustomCategory>>,
    /// Set when the category config changed and stored rows need a
    /// re-classification pass; the scan loop consumes it (same pattern
    /// as `scan_deep`).
    pub reclassify_pending: std::sync::atomic::AtomicBool,
    /// Ask the open naming oracles what a finished download actually is
    /// (see `crate::identity`). Default on, and the only outbound
    /// traffic it can produce is at most one srrdb request and at most
    /// one xREL request per completed job, both keyless and both
    /// silent when they fail.
    ///
    /// A switch rather than an assumption: it is the user's line, the
    /// requests name a release they downloaded, and somebody who does
    /// not want their daemon talking to third parties about that is
    /// entitled to say so - which is why it is now an advanced row on
    /// the Auto-rename card rather than an API-only setting. Somebody
    /// who wants to say no has to be able to find the switch.
    pub identity_lookup: std::sync::atomic::AtomicBool,
    /// Auto-rename: on completion, rename the folder + main media file to a
    /// friendly "Title (Year)[ quality]" form (TV keeps Show - S01E02).
    /// Master switch (default on); the five below tune what the quality
    /// suffix carries. Live settings.
    pub auto_rename: std::sync::atomic::AtomicBool,
    pub rename_resolution: std::sync::atomic::AtomicBool,
    pub rename_vcodec: std::sync::atomic::AtomicBool,
    pub rename_acodec: std::sync::atomic::AtomicBool,
    pub rename_source: std::sync::atomic::AtomicBool,
    pub rename_group: std::sync::atomic::AtomicBool,
    /// Wrap the year in parentheses when renaming. Off by default;
    /// "Title (Year)" is what Plex/Jellyfin/Radarr match on, so a
    /// media-server user usually wants it on.
    pub rename_year_parens: std::sync::atomic::AtomicBool,
    /// Wrap the quality facts in square brackets. Off by default.
    pub rename_quality_brackets: std::sync::atomic::AtomicBool,
    /// How many history rows the dashboard shows before the card has to
    /// be expanded. A display preference, but daemon-side like unit_bits
    /// so every browser pointed at this daemon agrees.
    pub history_rows: AtomicU64,
    /// Colour finished names green and failed ones red in History.
    pub history_color_names: std::sync::atomic::AtomicBool,
    /// Live state of a connection ladder while it runs, for the
    /// dashboard to poll. A full run is minutes long now, and the number
    /// it prints is the sharpest single knob in the product - watching
    /// it being derived is how a user comes to trust it, or to spot that
    /// it is measuring a bad evening. `None` between runs.
    ///
    /// SINGLE-WRITER, held by [`LadderPermit`]: do not write this without
    /// holding one. The invariant is structural rather than checked - one
    /// permit means one ladder means one writer - and a generation stamp
    /// here would be a second mechanism asserting what the permit already
    /// guarantees, which is the kind of pair that rots when a third
    /// writer appears and only one of them gets updated.
    pub ladder_live: Mutex<Option<LadderLive>>,
    /// One connection ladder at a time, across BOTH paths.
    ///
    /// Two ladders running at once do not merely race to write a knee -
    /// they invalidate each other's numbers, because each one's sockets
    /// are the other's contention, and a tuner whose whole job is
    /// measuring contention cannot be measuring itself. The existing
    /// post-hoc check ("a manual test landed while this probe ran")
    /// decides who WINS the write; it does not stop either measurement
    /// being wrong. They also both publish `ladder_live`, so the panel
    /// would show one provider's phase against another's rungs.
    pub ladder_busy: std::sync::atomic::AtomicBool,
    /// Set by the dashboard's Cancel to stop a ladder in flight.
    ///
    /// A full run is minutes long and spends real, billed provider
    /// traffic, so "I have changed my mind" has to be answerable. Read
    /// between rungs rather than mid-rung: a rung is 5-10 s, and
    /// abandoning one halfway would leave a half-measured step that is
    /// worse than no step. Cleared when a run starts, so a stale cancel
    /// cannot kill the next one.
    pub ladder_cancel: std::sync::atomic::AtomicBool,
    /// Tint the media chip by video codec, and the archive-shape chip by
    /// what it took to unpack. Two switches rather than one because they
    /// answer different questions - "what is this file" and "what did
    /// getting it cost" - and a user who wants one is not asking for the
    /// other. Both default ON, matching how they shipped; the chips
    /// still spell both facts out in words when the colour is off.
    pub media_chip_color: std::sync::atomic::AtomicBool,
    pub shape_chip_color: std::sync::atomic::AtomicBool,
    /// Keep the words the parser did not recognise ("Round11 Hungary
    /// Race"), so releases differing only in those stay distinct.
    /// On by default: it only ever fires where the renamer would
    /// otherwise refuse to build a name at all.
    pub rename_extra_words: std::sync::atomic::AtomicBool,
    /// Post-download synthesised naming for obfuscated FILMS: when every
    /// other pass has left the feature wearing a hash, read the
    /// container's own facts and ask a film catalogue what it is.
    ///
    /// On by default, which is only defensible because the acceptance
    /// gate renames on certainty rather than on a best guess (see
    /// [`crate::identify`]) - the usual outcome is a note, not a rename.
    /// Visible next to the other rename settings so a user who would
    /// rather nothing reached the network after a download can turn it
    /// off.
    pub rename_identify: std::sync::atomic::AtomicBool,
    /// TODO 78: put the episode's own title in a TV filename
    /// ("Show - S01E02 - Children [1080p].mkv"), from the TVmaze episode
    /// list already cached for the show.
    ///
    /// Default OFF, and the only rename sub-setting that is. Two
    /// reasons: it is the shape Sonarr treats as a chosen token rather
    /// than a default, and turning it on changes the filenames an
    /// existing install already produced - which is exactly what an
    /// *arr's import matcher is looking at. A user who wants it opts in
    /// once and every later download follows.
    pub rename_episode_titles: std::sync::atomic::AtomicBool,
    /// Remove usenet junk (.par2/.nzb/.sfv/.nfo/… + sample clips) from a
    /// finished movie/TV folder (default on).
    pub rename_junk: std::sync::atomic::AtomicBool,
    /// Aggressive: keep ONLY the media file(s), delete everything else
    /// (default off - irreversible).
    pub rename_media_only: std::sync::atomic::AtomicBool,
    /// M12 volume control, live: only index posts newer than this
    /// (seconds; 0 = off). Read by the scan loop each pass.
    pub index_max_age_secs: AtomicU64,
    /// M31a retention, live: when on AND index_max_age_secs > 0, the scan
    /// loop deletes stored rows older than the window (max_age becomes a
    /// true retention window, not just an ingest gate). The stale-partial
    /// reaper runs regardless. Default: on.
    pub index_retention: std::sync::atomic::AtomicBool,
    /// Hold indexing back entirely while a download is running. Header
    /// scanning is not free next to a job: with the default 3 parallel
    /// group scans it takes `min(connections/3, 5)` connections EACH -
    /// 15 of a 20-connection account - and its SQLite writes compete
    /// with the download for CPU and disk on the same box. The daemon
    /// already yields in smaller ways (turbo fan-out off, prunes
    /// deferred, oracle sampler idle); this is the whole-hog version.
    /// On by default: a download is the foreground task, and the index
    /// catches up the moment the queue drains.
    pub(super) index_pause_on_download: std::sync::atomic::AtomicBool,
    /// Manual stop. Clearing the group list was the only way to halt
    /// indexing before, which meant losing the selection to get it back.
    pub(super) index_paused: std::sync::atomic::AtomicBool,
    /// The built-in indexer's master switch, OFF by default.
    ///
    /// Pause is a "not right now"; this is a "not at all". Off means the
    /// feature does not exist for this install: no scanning, no
    /// enrichment, no availability sampling, no newznab facade, no
    /// database - `with_index` refuses to open the file - and the whole
    /// half of the UI it feeds is hidden rather than shown empty.
    ///
    /// Why default off: a header scanner only finds posts that carry a
    /// real filename, and a large share of usenet is deliberately posted
    /// without one (measured in research/index-parity-feasibility-\
    /// 2026-07-28.md: 14.78M scanned rows, 0.21% of them wall-visible).
    /// For anyone whose answer is a commercial indexer - which is most
    /// people - the built-in one is a background cost paid for a page
    /// they never open. Turning it on is one switch away, and the switch
    /// says what it does and does not do.
    ///
    /// EXISTING installs are seeded ON at startup (see `index_enabled`
    /// in `serve()`): an upgrade that silently stopped somebody's
    /// working index would be a data-shaped surprise, not a default.
    pub(super) index_enabled: std::sync::atomic::AtomicBool,
    /// Pre feed over IRC, OFF by default and independently of the
    /// indexer's own switch.
    ///
    /// A scanner can only read what was posted, and a large share of
    /// usenet is posted with the name taken out. The public relay
    /// channels announce `real title + posted filename` together, which
    /// is the one open mechanism that names those posts. It is opt-in
    /// and stays opt-in: it is a persistent connection to a third-party
    /// network that nothing else in this program talks to, and that is a
    /// decision for the user to make rather than a default to discover.
    pub(super) predb_enabled: std::sync::atomic::AtomicBool,
    /// `host` or `host:port` of the IRC network carrying the relay.
    pub(super) predb_server: Mutex<String>,
    /// Comma-separated channel list.
    pub(super) predb_channels: Mutex<String>,
    /// Base nick; a random suffix is appended per connection so two
    /// installs on one network never collide. No account, no NickServ.
    pub(super) predb_nick: Mutex<String>,
    /// Lines heard but not yet written. The relay is chatty in bursts
    /// and the index is shared with the scanner, so lines are batched
    /// rather than each taking the write lock on arrival.
    #[cfg(feature = "indexer")]
    pub(super) predb_pending: Mutex<Vec<nzbkit::predb::PreLine>>,
    /// Last thing the feed did, for the settings card. Plain text, shown
    /// as-is: a feature whose whole job is to talk to somebody else's
    /// server owes the user a legible account of whether it is working.
    pub(super) predb_status: Mutex<String>,
    /// Phase 2 correlation: infer names for obfuscated posts from pre
    /// timing + size. A separate switch from the feed itself, because
    /// hearing lines is harmless and inferring names is a policy.
    pub(super) predb_corr_enabled: std::sync::atomic::AtomicBool,
    /// The auto tier: apply a STRONG, unique, mutually-best correlation
    /// without a human click. Display-name only, revocable, and still
    /// off by default - it is earned per install, not assumed.
    pub(super) predb_corr_auto: std::sync::atomic::AtomicBool,
    /// How many pre rows the feed table may hold. Drives BOTH the prune
    /// and the seed importer's refusal threshold, which is the point of
    /// it being one number: a cap the importer does not know about is a
    /// cap that imports rows the next prune eats.
    pub(super) predb_max_rows: std::sync::atomic::AtomicU64,
    /// Default history window, in days, for a seed import that does not
    /// name one. The design's 180; a bigger window costs the source
    /// more requests, which is why it is a knob and not a guess.
    pub(super) predb_seed_days: std::sync::atomic::AtomicU64,
    /// A seed import is in flight (one at a time, ever).
    #[cfg(feature = "indexer")]
    pub(super) predb_seed_running: std::sync::atomic::AtomicBool,
    /// What the seed importer is doing / last did, for the settings
    /// card. Same contract as `predb_status`.
    #[cfg(feature = "indexer")]
    pub(super) predb_seed_status: Mutex<String>,
    /// Spotnet spot ingestion, OFF by default and independent of
    /// `index_enabled`.
    ///
    /// A separate switch because it is a separate kind of source. The
    /// header indexer reads what usenet happens to say about a posting,
    /// which is nothing at all when the poster obfuscated it. A spot is
    /// somebody publishing a signed record of what they posted, name and
    /// NZB included, so it reaches exactly the releases the scanner
    /// cannot see. Making it a sub-option of the weaker source would
    /// mean running a header scan nobody asked for to get it.
    ///
    /// It shares the database, the pass gate and the pause rules with
    /// indexing (one SQLite file, one writer at a time, and a download
    /// still outranks both) - it just does not need the other switch on.
    pub(super) spot_enabled: std::sync::atomic::AtomicBool,
    /// Spot groups to scan. free.pt is the one live Spotnet group.
    pub(super) spot_groups: Mutex<Vec<String>>,
    /// Articles to walk back on the first pass; later passes resume from
    /// the stored `spots:<group>` high-water mark.
    pub(super) spot_backfill: AtomicU64,
    /// Bumped every time the database underneath the index is
    /// invalidated - switched off, or wiped. A scan pass owns a
    /// DEDICATED `Index::open` connection and republishes a fresh shared
    /// one when it finishes, so without a generation to check against it
    /// reopened (and, after a wipe, RECREATED) the database that had
    /// just been taken away. The switch then read as off while a live
    /// connection sat behind it, and a wipe reported success over files
    /// an exiting scan put back.
    #[cfg(feature = "indexer")]
    pub(super) index_generation: AtomicU64,
    /// Number of foreground jobs whose pipeline has not reached its
    /// terminal park yet. Job N's tail can overlap job N+1's network
    /// phase, so `started_at` cannot represent this lifetime.
    pub(super) index_jobs_active: Arc<AtomicUsize>,
    /// Size cap for the index database in bytes (0 = unlimited, the
    /// default). Live setting, SAB-style sizes accepted on input
    /// ("20G"). Only a cap: nothing is deleted until `index_evict` is
    /// also on - see that field.
    pub index_max_bytes: AtomicU64,
    /// The size cap's master switch, and the ONLY thing that lets the
    /// daemon delete indexed rows on its own. Default OFF, deliberately:
    /// a feature that throws data away does not turn itself on, and a
    /// user who sets a cap out of curiosity must not lose their index to
    /// it. With this off the cap is inert - `index_stats` still reports
    /// how big the database has grown, which is most of the value.
    pub index_evict: std::sync::atomic::AtomicBool,
    /// Which rows the cap sheds first: "ladder" (the engine's blended
    /// junk/age/availability order), "oldest", "newest", "largest",
    /// "smallest". Validated on write, so this always holds one of those.
    pub index_evict_order: Mutex<String>,
    /// Restrict eviction to these release kinds ("movie", "tv",
    /// "software", "other"); empty = every kind is fair game.
    pub index_evict_kinds: Mutex<Vec<String>>,
    /// A prune left free pages behind and the file wants a VACUUM.
    /// Deliberately NOT acted on where it is set: VACUUM exclusive-locks
    /// and rewrites the whole database, so it waits for a genuinely idle
    /// moment (`compact_loop`) rather than stalling a scan pass or a
    /// download. Survives only in memory - a restart is itself an idle
    /// moment and the next prune re-raises it.
    #[cfg(feature = "indexer")]
    pub compact_pending: std::sync::atomic::AtomicBool,
    /// Truth-audit I: what the last AUTOMATIC index trim removed, and
    /// when - (unix seconds, releases removed). The manual button
    /// narrates its own outcome in full; the hourly pass that does the
    /// same work silently was the reason a user could watch their index
    /// shrink with nothing anywhere admitting to it.
    ///
    /// In memory only. It describes this daemon's run: a restart has not
    /// trimmed anything yet, and claiming a trim from a previous process
    /// would be answering a question about now with a fact about then.
    #[cfg(feature = "indexer")]
    pub last_auto_trim: std::sync::Mutex<Option<(i64, u64)>>,
    /// Releases and titles the user has actually looked at: title_key /
    /// release id → unix seconds of the last touch. This is the fourth
    /// protection the size cap honours ("don't evict what I've been
    /// reading"), and it exists because the schema has no wall-render
    /// timestamp to stand in for it - `wall_hidden.at` records when
    /// something was HIDDEN, the opposite signal. Written on the three
    /// deliberate acts: opening a card's detail sheet, pulling an NZB
    /// through /getnzb, and queueing an indexed release.
    /// Persisted to .spool/index-opened.json.
    #[cfg(feature = "indexer")]
    pub index_opened: Mutex<OpenedLog>,
    /// M12 ingest gates, live: (raw JSON text as shown in the UI, parsed
    /// form the scanner uses). Text is empty when gates came from a
    /// --index-gates file (the parsed form still applies).
    #[cfg(feature = "indexer")]
    pub index_gates: Mutex<(String, Option<crate::gates::Gates>)>,
    /// M21: the connection's full line speed in bytes/sec (0 = unset).
    /// SAB remote apps set speed limits as PERCENTAGES - this is what
    /// the percentage is of. Doubles as the tuner's aim point: when the
    /// measured capability of every enabled provider together falls
    /// well short of it, `tune_hint` says so and suggests the lever.
    pub line_speed: AtomicU64,
    /// §125: the learned peak the throughput graph anchors 100% to -
    /// seeded by `line_speed`, overridden by sustained measurement.
    pub link_peak: super::linkpeak::LinkPeak,
    /// §129 4b: the "Why is this slow?" attribution engine - fed by
    /// the same 1 s ticker as `link_peak`, published on the queue poll.
    pub(super) whyslow: super::whyslow::WhySlow,
    /// What the connection tuner wants the user to know: a shortfall
    /// against `line_speed` with the likeliest remedy, or empty when
    /// capability is fine (or unjudgeable - line speed unset, or an
    /// enabled server not yet probed). Read-only in the settings API;
    /// written by the probe loop and manual ladder runs.
    pub tune_hint: Mutex<String>,
    /// CPU% sampling state for stats: (sample time, cpu-secs, last pct).
    pub(super) cpu_sample: Mutex<Option<(Instant, f64, f64)>>,
    /// Rolling (time, decoded-bytes) samples for the live speed readout -
    /// a whole-job average hides stalls (a wedged job kept "reporting"
    /// 400 KB/s); a ~5 s window shows what's happening NOW.
    pub(super) speed_win: Mutex<VecDeque<(Instant, u64)>>,
    /// M18b per-provider data-usage history: "YYYY-MM-DD" → host → bytes,
    /// persisted to .spool/usage.json (metered/block accounts need to see
    /// where the gigabytes went).
    pub(super) usage: Mutex<serde_json::Map<String, Value>>,
    /// Timed pause ("pause for N minutes"): auto-resume deadline. Any
    /// manual pause/resume bumps pause_gen, cancelling the pending timer.
    pub(super) pause_until: Mutex<Option<Instant>>,
    pub(super) pause_gen: AtomicU64,
    // --- M16 settings UI: live-tunable knobs. Each is read at its point
    // of use (per job / per loop tick / per request), so a change from
    // the dashboard takes effect without a restart. Changes are also
    // persisted to settings.json (see save_setting) for the next launch.
    /// Per-server connection cap for the NEXT download.
    pub(super) connections: std::sync::atomic::AtomicUsize,
    /// Pipelining window for the NEXT download.
    pub(super) window: std::sync::atomic::AtomicUsize,
    /// Decoder threads for the NEXT download.
    pub(super) decoders: std::sync::atomic::AtomicUsize,
    /// PAR2 fast verify (CRC32-only in-stream claims) for the NEXT
    /// download; full MD5 stays on settle read-back + disk-fed spans.
    pub(super) fast_verify: std::sync::atomic::AtomicBool,
    /// M32 lean verify: with fast_verify, also skip article CRCs once
    /// PAR2 covers a file (single-CRC32 in-stream; slow-CPU boost).
    pub(super) verify_lean: std::sync::atomic::AtomicBool,
    /// Pause new jobs below this many free bytes (0 = off).
    pub(super) min_free: AtomicU64,
    /// Why the scheduler is starting nothing, for the queue payload:
    /// `("disk", free_gb, floor_gb)` while the min_free guard holds, or
    /// `("quota", spent_gb, cap_gb)` while the period's quota is spent.
    /// `None` when downloads can start. Mirrors the worker's own
    /// guard_reason - without this the dashboard showed "idle" over a
    /// full queue and the only explanation lived in the daemon log.
    pub(super) queue_hold: Mutex<Option<(String, f64, f64)>>,
    /// Who paused the queue, for the header pill: `"user"` (a person at
    /// the dashboard, a remote app, the API) or `"schedule"` (a schedule
    /// entry fired). The offline case is derived from
    /// `paused_by_offline` at render time and needs no slot here.
    ///
    /// Display only - nothing schedules on this. A pause the user never
    /// made read exactly like one they did, so the only way to find out
    /// that a quiet hour had started was to open Settings and work
    /// through the schedule by hand.
    pub(super) pause_source: Mutex<&'static str>,
    /// Who set the speed ceiling now in force: `"user"` (the dashboard
    /// or the config API), `"schedule"`, or `"api"` (a remote app's rate
    /// call). `"auto"` is derived from `auto_speed` at render time.
    /// Display only, same reasoning as `pause_source`.
    pub(super) limit_source: Mutex<&'static str>,
    /// M32: seconds before the one automatic retry of a job that failed
    /// with missing articles (0 = off). Configured in minutes
    /// (auto_retry_mins); NZBFAST_AUTO_RETRY_SECS overrides for tests.
    pub(super) auto_retry_secs: AtomicU64,
    /// Byte budget per quota period (0 = off).
    pub(super) quota: AtomicU64,
    /// b'd' (daily), b'w' (weekly, Monday) or b'm' (monthly).
    pub(super) quota_period: std::sync::atomic::AtomicU8,
    /// §129 2g: a scheduled quota_reset fired; the download runner owns
    /// the ledger and zeroes it on its next pass.
    pub(super) quota_reset: AtomicBool,
    /// §129 2d: what happens to a duplicate add. "pause" (the default,
    /// M14f: held as an ALTERNATIVE that auto-promotes if the original
    /// fails), "discard" (refused outright - the add errors), or "fail"
    /// (filed straight to history as Failed, which is what a *arr wants
    /// so its own failure handling can pick a different release).
    /// Live - read per add. `allow_dupe` (the wall's asked-and-said-yes)
    /// bypasses all three.
    pub(super) dupe_action: Mutex<String>,
    /// §129 2b (decision 5): real per-category behavior, keyed by the
    /// category name. Everything defaults to "as before": empty dir =
    /// the category's own subfolder, priority None = no default,
    /// empty script = the global one. Live - read per add and per
    /// job completion.
    pub(super) cat_meta: Mutex<std::collections::HashMap<String, CatMeta>>,
    /// Watch folder for dropped .nzb files (None = off).
    pub(super) watch_dir: Mutex<Option<PathBuf>>,
    /// Keep the picked-up .nzb in the watch folder instead of moving it
    /// to the Trash (Gary: collectors, and handing the file to someone
    /// for debugging). Off = today's behaviour, where deletion IS the
    /// processed-marker; on, the marker is the persisted seen-set the
    /// watch loop keeps beside the spool (see watch_seen_path), or every
    /// restart would re-download the whole folder. Live - read per
    /// pickup, so it needs no boot-apply beyond the saved-settings replay.
    pub watch_keep_nzb: AtomicBool,
    /// Scan subfolders of the watch folder too, with the first
    /// subfolder's name becoming the job's category (watch/tv/x.nzb
    /// lands in "tv") - the layout Sonarr-era muscle memory expects.
    /// A first-level folder named "rejected" is never scanned: it is
    /// the quarantine below. Live - read per pass.
    pub watch_recursive: AtomicBool,
    /// Move a complete-but-unusable .nzb (parse/enqueue rejection) into
    /// <watch>/rejected/ with a .txt beside it saying why. Off, the
    /// file stays put and only the dashboard strip explains it.
    /// Truncated files are NEVER moved regardless: a stalled copy can
    /// resume, and yanking the destination mid-copy is exactly the
    /// "nzbfast deleted my download" complaint the strip exists to
    /// prevent. Live - read per rejection.
    pub watch_move_rejected: AtomicBool,
    /// Watch-folder files that failed to parse/enqueue, with the
    /// (mtime, len, error, related nzo_id) they failed at. Skipped on
    /// later passes until the file changes - with the watch folder
    /// defaulting to the user's whole Downloads folder, a stray
    /// unparseable .nzb must not be re-read every 5 s forever. Surfaced
    /// in queue_json for the UI.
    ///
    /// The id is the RECORD this file lost to, empty when there isn't
    /// one: "already downloaded" is only actionable if the History entry
    /// standing in the way can be reached, and matching it back up by
    /// name in the page finds the wrong row for a re-post.
    pub(super) watch_failed: Mutex<std::collections::HashMap<PathBuf, (u64, u64, String, String)>>,
    /// Recent watch-folder ingests: (file name, source folder's display
    /// name, unix seconds), newest last, capped small. Surfaced in
    /// queue_json so an open dashboard can toast the pickup the moment
    /// it happens - the consumed file vanishes from the folder (a
    /// browser marks its download "Removed"), and without this the
    /// disappearance had no explanation anywhere a user looks (Gary,
    /// v1.0.14).
    pub(super) watch_picked: Mutex<std::collections::VecDeque<(String, String, i64)>>,
    /// M32: automatic retries that have just RE-QUEUED, as (nzo_id, name,
    /// unix seconds), newest last, capped small. The same ring shape as
    /// `watch_picked` and for the same reason: the moment is invisible
    /// otherwise. A failed row is announced, sits in History for its
    /// cooldown, then silently disappears from History and reappears in
    /// the queue - which reads as the daemon losing the record and
    /// starting an unasked-for download. Surfaced in queue_json; the
    /// dashboard toasts each entry once.
    pub(super) auto_retried: Mutex<std::collections::VecDeque<(String, String, i64)>>,
    /// §96.3: targets the give-up breaker has just stopped chasing:
    /// (the release that failed last, how many distinct releases had
    /// failed, unix seconds), newest last, capped small. Same shape and
    /// purpose as `watch_picked`: the breaker's decision only existed on
    /// a `warn!` line, so a watched show simply stopped arriving with
    /// nothing anywhere to say why.
    pub(super) giveup_tripped: Mutex<std::collections::VecDeque<(String, u64, i64)>>,
    /// Recent watchlist delete_old upgrades that removed the superseded
    /// copy's record: (new release stem, superseded stem, superseded
    /// quality, what became of its files, unix seconds), newest last,
    /// capped small. The fate is `"trash"`, `"gone"` or `"kept"` - three
    /// states, not two, because a Trash that refuses leaves the old copy
    /// on disk and the toast must not announce a delete that did not
    /// happen.
    /// Same contract as `watch_picked` - surfaced in queue_json so an
    /// open dashboard can toast the moment. The upgrade removes a
    /// completed download AND its history row, and until this existed
    /// two log lines were the only narration of a whole release
    /// disappearing.
    pub(super) watch_upgraded:
        Mutex<std::collections::VecDeque<(String, String, String, String, i64)>>,
    /// Deletes whose RECORD went but whose FILES did not: (job name, the
    /// path still on disk, why it was refused, unix seconds), newest
    /// last, capped small. See `Daemon::note_delete_kept`.
    ///
    /// Unlike the rings above this one is not a moment that scrolls past.
    /// The dashboard keeps it on screen until the user dismisses it,
    /// because the path IS the handle: the history row they would have
    /// found the download by is exactly what the delete removed.
    pub(super) delete_kept: Mutex<std::collections::VecDeque<(String, String, String, i64)>>,
    /// Failed API-key attempts per source address: (count, window start).
    ///
    /// The key comparison is constant-time, but nothing recorded a wrong one
    /// and nothing slowed one down - so an unauthenticated peer on the LAN
    /// could grind the key at full request rate, leaving no trace anywhere in
    /// the logs. See `note_auth_failure`.
    pub(super) auth_fails: Mutex<std::collections::HashMap<std::net::IpAddr, (u32, Instant)>>,
    /// M30: viewport-priority enrichment - title keys the wall is
    /// showing unenriched RIGHT NOW. The enricher lanes drain these
    /// ahead of the newest-first backlog, so what's on screen gets its
    /// art first. Bounded FIFO (stale entries evict).
    #[cfg(feature = "indexer")]
    pub(super) enrich_hot: Mutex<std::collections::VecDeque<String>>,
    /// Newsgroup discovery catalogue (mode=groups): the primary server's
    /// LIST ACTIVE + LIST NEWSGROUPS, cached in groups.tsv next to the
    /// index db so a restart doesn't refetch ~100k groups. None until the
    /// cache loads or the first fetch lands.
    #[cfg(feature = "indexer")]
    pub(super) group_catalog: Mutex<Option<Arc<crate::groups::Catalog>>>,
    /// True while a catalogue fetch is in flight (single-flight guard).
    #[cfg(feature = "indexer")]
    pub(super) group_fetching: std::sync::atomic::AtomicBool,
    /// Last catalogue-fetch failure, surfaced in the browser UI.
    #[cfg(feature = "indexer")]
    pub(super) group_fetch_err: Mutex<Option<String>>,
    /// Sampled per-group profiles (size, freshness, rate, content mix)
    /// from an OVER over each group's newest articles. Separate from the
    /// catalogue because it is filled in lazily and incrementally: the
    /// catalogue is one fetch for every group, this is one round trip
    /// PER group, so it is only ever done for groups someone looked at
    /// or that the background pass has reached.
    #[cfg(feature = "indexer")]
    pub(super) group_stats: Mutex<Arc<crate::groupstats::StatsCache>>,
    /// Groups with a sample in flight, so two viewers opening the same
    /// row do not both go to the provider (and so the background pass
    /// never races an on-demand request).
    #[cfg(feature = "indexer")]
    pub(super) group_sampling: Mutex<std::collections::HashSet<String>>,
    /// Opt-in: also fetch newsgroup descriptions from ISC. Off by
    /// default because it is the daemon's only outbound request to a host
    /// that is not the user's news provider.
    pub(super) group_desc_isc: std::sync::atomic::AtomicBool,
    /// Post-processing script (None = off).
    pub(super) script: Mutex<Option<PathBuf>>,
    /// Seconds before a post-processing script is killed. 0 = wait
    /// forever, which is what a multi-hour transcode wants; the default
    /// is generous but finite, because a script that hangs otherwise
    /// holds its blocking thread for the life of the daemon and does so
    /// again for every job that completes after it.
    pub(super) script_timeout: AtomicU64,
    /// Media servers / webhooks told about every finished job. Empty =
    /// off, which is the default. See [`crate::notify`].
    pub(super) notify_targets: Mutex<Vec<crate::notify::Target>>,
    /// §G: how each target's last delivery went, keyed by
    /// [`crate::notify::target_key`]. A failed notification was log-only,
    /// so a webhook with a revoked token stopped working and the only
    /// place that said so was a log line nobody reads. The key embeds the
    /// target url, which is itself a bearer credential for Discord/ntfy:
    /// it is a map key and NOTHING else - never logged, never shipped.
    pub(super) notify_health: Mutex<std::collections::HashMap<String, crate::notify::Outcome>>,
    /// What to do with an indexer's `X-DNZB-Failure` link when a job
    /// fails: "off" (default), "report", or "regrab". See
    /// [`Daemon::report_failure`].
    pub(super) failure_link: Mutex<String>,
    /// Which encode the user would rather have when a title has several.
    /// Biases the order releases are listed in; never hides any of them.
    pub(super) quality_prefs: Mutex<crate::watchlist::QualityPrefs>,
    /// API keys, rotatable live. None = open (no auth).
    pub(super) apikey: Mutex<Option<String>>,
    pub(super) nzbkey: Mutex<Option<String>>,
    /// Per-install secret behind stream_token(). Generated once, persisted
    /// in settings.json - deliberately NOT the apikey, so rotating the key
    /// doesn't orphan every .strm pointer in a Jellyfin/Emby library.
    pub(super) stream_secret: String,
    /// Optional OMDb key (free tier, email-only signup) - richer movie
    /// metadata in the enricher + fix-match search. Live setting.
    pub(super) omdb_key: Mutex<Option<String>>,
    /// Re-verify interval for parked library jobs.
    pub(super) library_recheck_secs: AtomicU64,
    /// Index scanner inputs, read each cycle.
    pub(super) index_groups: Mutex<Vec<String>>,
    /// What the user told the indexer to look for, as interest keys (see
    /// `crate::interests`). Empty means "nothing" and stays that way -
    /// this is the setting that exists so nobody has to accept a default
    /// they did not choose.
    pub(super) index_interests: Mutex<String>,
    /// The interest string whose groups have already been merged into
    /// `index_groups`. Applying is one-shot per change: without this,
    /// every catalogue refresh would re-add a group the user had since
    /// removed by hand, which is the same "we decided for you" behavior
    /// from a different direction.
    pub(super) index_interests_applied: Mutex<String>,
    /// Exact groups appended by interest resolution. A preset group that
    /// was already present is manual and never enters this list, so
    /// unticking the preset cannot delete the user's own subscription.
    pub(super) index_interest_groups: Mutex<Vec<String>>,
    pub(super) index_interval_secs: AtomicU64,
    pub(super) index_backfill: AtomicU64,
    /// mode=index_scan_now: wakes the scan loop out of its interval
    /// sleep; scan_deep carries a one-off backfill-depth override
    /// (0 = none) consumed at the start of the next pass.
    pub(super) scan_now: tokio::sync::Notify,
    #[cfg(feature = "indexer")]
    pub(super) scan_deep: AtomicU64,
    /// Live progress of the in-flight scan pass, for index_stats.
    /// Groups currently scanning (several at once since M28).
    #[cfg(feature = "indexer")]
    pub(super) scan_progress: Mutex<Vec<ScanProgress>>,
    /// M28: concurrent group scans per pass (live setting, clamp 1-8).
    pub(super) index_scan_par: AtomicU64,
    /// True from before the scan loop spawns its group tasks until the
    /// last one joins. `scan_progress` cannot serve this purpose: a task
    /// opens its own Index handle - which takes the database's write
    /// lock for the schema batch - BEFORE it registers itself there, and
    /// the tip watcher writing in that window failed the open outright
    /// with "database is locked".
    pub(super) scan_active: std::sync::atomic::AtomicBool,
    /// Seconds between tip-watcher ticks - the short loop that tracks
    /// only what is NEW at the head of each group, so arrivals reach the
    /// wall in seconds instead of waiting out `index_interval_secs`
    /// (default 900) behind a 200k-article history backfill. Live
    /// setting; 0 turns the watcher off and leaves the full scan pass as
    /// the only path, as it was before.
    pub(super) index_tip_secs: AtomicU64,
    /// Watch-folder poll period. The filesystem watcher is what makes a
    /// drop feel instant; this is the backstop for the cases it cannot
    /// see - notably SMB/NFS mounts, where the kernel gets no events for
    /// a write made on another host.
    pub(super) watch_interval_secs: AtomicU64,
    /// Fired by the filesystem watcher so the loop wakes at once instead
    /// of sitting out the rest of its interval.
    pub(super) watch_scan_now: tokio::sync::Notify,
    /// M29 availability oracle: idle STAT sampling budget in
    /// STATs/hour/server (live setting; 0 disables the sampler).
    pub(super) oracle_sample: AtomicU64,
    /// Time-of-week scheduler entries + their JSON source text (the text
    /// is what get_config echoes back for the UI editor).
    pub(super) schedule: Mutex<Vec<SchedEntry>>,
    pub(super) schedule_text: Mutex<String>,
    /// M23 watchlist - a live setting (key "watchlist"): the watcher
    /// re-reads this each pass, so dashboard edits apply immediately.
    pub watchlist: Mutex<Vec<crate::watchlist::WatchItem>>,
    /// What the watcher has grabbed per item-slot, plus upgrades waiting
    /// to delete their predecessor. Persisted to .spool/watchlist-state.json.
    pub watch_state: Mutex<crate::watchlist::WatchState>,
    /// mode=watchlist_check_now: wakes the watcher out of its sleep.
    pub(super) watch_now: tokio::sync::Notify,
    /// §96.3 give-up breaker: distinct final failures per target
    /// (episode/movie) before the target is given up. 0 = off, the
    /// default - the breaker unmonitors things in the user's *arr, which
    /// is not behaviour to default on.
    pub(super) arr_giveup_threshold: AtomicU64,
    /// The *arr instances the breaker may act on (settings key
    /// `arr_instances`; apikeys redacted from get_config).
    pub(super) arr_instances: Mutex<Vec<super::giveup::ArrInstance>>,
    /// Per-target failure counters, fed by `park` from final failures of
    /// arr- and watchlist-originated jobs. Persisted to
    /// .spool/giveup-state.json. Arc'd so the *arr-calling thread can
    /// release the action latch when the remote work fails.
    pub(super) giveup: Arc<Mutex<super::giveup::GiveupState>>,
    /// Where UI-changed settings persist (next to the server config).
    pub(super) settings_path: PathBuf,
    /// M31b "your wall": cached taste profile (built from completed
    /// history + watchlist). Rebuilt on a ~60 s TTL - a few hundred
    /// history rows is cheap, but the affinity sort hits it per page.
    #[cfg(feature = "indexer")]
    pub(super) taste_cache: Mutex<Option<(std::time::Instant, TasteProfile)>>,
}

/// M31b: the user's demonstrated taste, distilled from their completed
/// downloads and watchlist. Feeds the Affinity ("For you") wall sort and
/// the "Because you watch …" caption. Genre/kind weights are normalized
/// to sum ~1.0; `decade_center` is the weighted-mean release year.
#[cfg(feature = "indexer")]
#[derive(Debug, Clone, Default)]
pub struct TasteProfile {
    /// (genre, normalized weight), strongest first, top ~8.
    pub genres: Vec<(String, f32)>,
    /// (kind "tv"/"movie", normalized weight), strongest first.
    pub kinds: Vec<(String, f32)>,
    /// Weighted-mean release year of the taste set, or None.
    pub decade_center: Option<i32>,
    /// Count of source signals (completed history + watchlist items).
    /// 0 = cold start.
    pub n_signals: u32,
}

/// §G: one news server's last refusal to authenticate, remembered past
/// the pool that saw it.
///
/// [`nzbkit::pool::Refusal`] lives on the live pool, which exists only
/// while a job is running. Copying it here at the point it is observed
/// means the Providers card can still say "this provider rejected your
/// sign-in" once the queue has drained - the state in which a user
/// actually goes looking. Cleared when the same host later connects and
/// moves bytes, so a fixed password stops being reported as broken.
#[derive(Debug, Clone)]
/// One daemon-owned moment for the throughput chart's marker ring -
/// the daemon-side twin of `nzbkit::pool::PoolEvent`, minus the host
/// (these moments belong to the whole daemon, not to one news server).
pub struct DaemonEvent {
    /// Unix milliseconds, same clock as the pool ring and the chart's
    /// throughput samples, so all three lay on top of each other.
    pub at_ms: u64,
    /// `pause` | `resume` | `limit` | `disk` | `quota` | `clear` |
    /// `sidecar` | `indexer` | `late` | `finished` - the dashboard maps
    /// these to severity classes (fault / recovery / phase / user
    /// action), and `finished` is also what closes its "checking
    /// files" phase shading.
    pub kind: &'static str,
    /// A whole sentence for the user, like the pool ring's details.
    pub detail: String,
}

/// Cap for [`Daemon::events`], matching the pool ring's reasoning: a
/// bounded window the UI can always afford to serve.
const DAEMON_EVENT_RING: usize = 256;

#[derive(Debug, Clone)]
pub struct ServerRefusal {
    /// True when retrying cannot help (a bad credential); false when the
    /// account is fine and the server is simply at a connection or IP cap.
    pub permanent: bool,
    /// The server's own status line, verbatim. Not paraphrased on
    /// purpose: "max simultaneous IP addresses reached" tells the user
    /// what to do and our summary of it would not.
    pub line: String,
    /// Unix seconds when it was last seen.
    pub at: i64,
}

/// What the scan loop is doing right now - the shared counter is bumped
/// by index_scan_into as OVER chunks land.
#[cfg(feature = "indexer")]
pub struct ScanProgress {
    pub group: String,
    pub done: Arc<AtomicU64>,
}

// ---------------------------------------------------------------------------
// M34: index size cap + eviction (daemon half)
// ---------------------------------------------------------------------------

/// The eviction orders the `index_evict_order` setting accepts, in the
/// order the UI lists them. Kept as strings here because that is what
/// crosses the settings/API boundary; `parse_evict_order` is the single
/// place that turns one into the engine's enum.
#[cfg(feature = "indexer")]
pub const EVICT_ORDERS: [&str; 5] = ["ladder", "oldest", "newest", "largest", "smallest"];

/// Release kinds the index stores, and so the only values
/// `index_evict_kinds` may name. Anything else is a typo that would
/// silently make the whole restriction match nothing.
#[cfg(feature = "indexer")]
pub const EVICT_KINDS: [&str; 4] = ["movie", "tv", "software", "other"];

/// How long a deliberate touch (detail sheet, /getnzb, queue add) keeps a
/// release safe from the size cap. The user asked for "recently opened"
/// to be protected; a month is long enough that a title you browsed
/// before the weekend is still there on Monday, short enough that a
/// year of idle curiosity does not pin the whole database.
#[cfg(feature = "indexer")]
pub const OPENED_PROTECT_DAYS: i64 = 30;

/// Don't rewrite index-opened.json for a key already touched this
/// recently - browsing a card repeatedly is one signal, not fifty.
#[cfg(feature = "indexer")]
pub(super) const OPENED_COALESCE_SECS: i64 = 3_600;

/// Ceiling on either half of the touch log, so a scripted crawl of the
/// wall cannot grow the file without bound. Oldest touches drop first,
/// which is exactly the order the protection window would have expired
/// them in anyway.
#[cfg(feature = "indexer")]
pub(super) const OPENED_MAX_ENTRIES: usize = 5_000;

/// There is deliberately NO ceiling on the protected set.
///
/// This used to refuse to evict at all past 30_000 protected keys, out of
/// a fear that SQLite's 32_766-variable statement limit would silently
/// truncate the list and delete something the user asked us to keep. That
/// fear was misplaced: `Index::evict_to` binds at most 10_000 protected
/// entries into the candidate query as an OPTIMISATION, and then re-checks
/// every surviving candidate in Rust against the full, uncapped set before
/// deleting it. Overflowing the bind cap costs a little scan work, nothing
/// else, and `evict_protected_set_past_the_bind_limit_still_protects_everything`
/// in index.rs pins that at 30_000 ids plus 30_000 keys.
///
/// So the ceiling only ever produced the worse outcome: a user with a
/// large history got a cap that was never enforced, which is the failure
/// mode the cap exists to prevent. Hand the engine the whole set.
///
/// Bound the pass count instead. The engine's byte estimator is
/// deliberately conservative and can stop a little short of the target
/// (its own doc calls the undershoot self-correcting, on the assumption
/// that the next scan pass finishes the job). A user who pressed a button
/// should not have to wait for a scan pass, so an on-demand eviction
/// re-runs while it is still making progress, up to this many times. Each
/// pass re-seeds its estimate from the measured file, so convergence is
/// fast; the bound is only there so a pathological fixture cannot spin.
#[cfg(feature = "indexer")]
pub(super) const EVICT_MAX_PASSES: usize = 8;

/// Deliberate user attention, remembered. See `Daemon::index_opened`.
#[cfg(feature = "indexer")]
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct OpenedLog {
    /// Wall title_key → unix seconds of the last detail-sheet open.
    #[serde(default)]
    pub titles: std::collections::HashMap<String, i64>,
    /// Index release id → unix seconds of the last /getnzb or queue add.
    #[serde(default)]
    pub releases: std::collections::HashMap<i64, i64>,
}

#[cfg(feature = "indexer")]
impl OpenedLog {
    /// Record a touch. Returns true when the caller should persist -
    /// i.e. this is new information, not the same card opened twice in a
    /// row. Trims to `OPENED_MAX_ENTRIES`, oldest first.
    pub(super) fn touch_title(&mut self, key: &str, now: i64) -> bool {
        if key.is_empty() {
            return false;
        }
        let fresh = self
            .titles
            .get(key)
            .is_some_and(|t| now - *t < OPENED_COALESCE_SECS);
        self.titles.insert(key.to_string(), now);
        Self::trim(&mut self.titles);
        !fresh
    }

    pub(super) fn touch_release(&mut self, id: i64, now: i64) -> bool {
        if id < 0 {
            return false;
        }
        let fresh = self
            .releases
            .get(&id)
            .is_some_and(|t| now - *t < OPENED_COALESCE_SECS);
        self.releases.insert(id, now);
        Self::trim(&mut self.releases);
        !fresh
    }

    pub(super) fn trim<K: Clone + std::hash::Hash + Eq>(m: &mut std::collections::HashMap<K, i64>) {
        if m.len() <= OPENED_MAX_ENTRIES {
            return;
        }
        let mut by_age: Vec<(K, i64)> = m.iter().map(|(k, v)| (k.clone(), *v)).collect();
        by_age.sort_by_key(|(_, t)| *t);
        for (k, _) in by_age.into_iter().take(m.len() - OPENED_MAX_ENTRIES) {
            m.remove(&k);
        }
    }

    /// Drop touches that have aged out of the protection window. Called
    /// before every save so the file self-limits.
    pub(super) fn expire(&mut self, now: i64, window_secs: i64) {
        self.titles.retain(|_, t| now - *t <= window_secs);
        self.releases.retain(|_, t| now - *t <= window_secs);
    }
}

/// The `index_evict_order` string → the engine's enum. `None` for
/// anything else, which `apply_setting` refuses to store in the first
/// place; the fallback at read time is Ladder.
#[cfg(feature = "indexer")]
pub fn parse_evict_order(s: &str) -> Option<nzbkit::index::EvictOrder> {
    use nzbkit::index::EvictOrder as O;
    Some(match s.trim().to_ascii_lowercase().as_str() {
        "ladder" => O::Ladder,
        "oldest" => O::Oldest,
        "newest" => O::Newest,
        "largest" => O::Largest,
        "smallest" => O::Smallest,
        _ => return None,
    })
}

/// The `index_evict_kinds` comma list → validated lowercase kinds.
/// `Err` names the offender: a typo here would restrict eviction to a
/// kind no row carries, and the user would be left staring at a cap that
/// never frees anything.
#[cfg(feature = "indexer")]
pub fn parse_evict_kinds(s: &str) -> std::result::Result<Vec<String>, String> {
    let mut out: Vec<String> = Vec::new();
    for raw in s.split(',') {
        let k = raw.trim().to_ascii_lowercase();
        if k.is_empty() {
            continue;
        }
        if !EVICT_KINDS.contains(&k.as_str()) {
            return Err(format!(
                "unknown kind {k:?} (expected {})",
                EVICT_KINDS.join(", ")
            ));
        }
        if !out.contains(&k) {
            out.push(k);
        }
    }
    Ok(out)
}

// The protected-set trio (assemble_protected / watch_item_keys /
// shrink_shortfall_reason) lives with its callers in daemon_index.rs
// (TODO 106 code motion, size gate); re-exported so every existing
// `super::` and `daemon::` path still resolves here.
#[cfg(feature = "indexer")]
pub use daemon_index::shrink_shortfall_reason;
// The other two have no caller outside daemon_index.rs in a production
// build - only `serve::tests_index` reaches them, through serve's
// `use daemon::*`. Re-exporting them unconditionally is an unused import
// on the non-test build, and this crate builds with `-D warnings`.
#[cfg(all(test, feature = "indexer"))]
pub use daemon_index::{assemble_protected, watch_item_keys};

/// Is this a moment a VACUUM may run in? The engine's `compact()` doc
/// puts the burden on the caller: it exclusive-locks and rewrites the
/// whole file, so anything else touching the database waits it out.
/// Split out from the loop so the "defer while busy, fire when idle"
/// rule is testable on its own.
#[cfg(feature = "indexer")]
#[derive(Debug, PartialEq, Eq)]
pub enum CompactVerdict {
    /// Nothing to do - no prune has asked for it.
    NotNeeded,
    /// A scan pass or a download is in flight; wait.
    Busy(&'static str),
    /// VACUUM wants up to twice the database size in temp space and this
    /// runs on NAS boxes with 8 GB of headroom. Stay deferred rather
    /// than half-rewrite the file onto a full volume.
    NoRoom {
        need: u64,
        free: u64,
    },
    Go,
}

/// What one eviction attempt did. Every variant except `Ran` means
/// nothing was deleted.
#[cfg(feature = "indexer")]
pub enum EvictOutcome {
    /// The engine ran. Carries its report and how many protected keys
    /// stood in the way (0 = the shortfall, if any, is not protection).
    Ran(nzbkit::index::EvictReport, usize),
    /// Not applicable: eviction off, no cap set, or already under it.
    Nothing,
    /// The index could not be opened.
    Unavailable,
}

/// The `wall_tip` response body. `tip: None` means the index read
/// FAILED, and that has to reach the browser as something other than a
/// number.
///
/// The wall latches the first `latest` it is given as its cursor
/// (`if(tipMark<0){tipMark=j.latest}`). Once `since=-1` made 0 a
/// meaningful cursor rather than "uninitialized", a failed read that
/// defaulted to `latest: 0` latched 0 - and the next successful poll
/// then answered "everything posted in the last 7 days arrived just
/// now", which is precisely the pill claiming 890,000 arrivals that the
/// `since=-1` case exists to prevent. A genuinely empty index reports a
/// real 0 and must keep working, so the two cannot share a value:
/// failure is `null`, which the poll's `typeof j.latest!=='number'`
/// guard drops on the floor, leaving the cursor unlatched for the next
/// tick.
/// The job with this id, out of an already-locked list. Takes the
/// iterator rather than the daemon so a caller that is walking the queue
/// for other reasons does not lock it twice.
pub(super) fn find_job<'a>(
    list: impl IntoIterator<Item = &'a Arc<Mutex<Job>>>,
    id: &str,
) -> Option<Arc<Mutex<Job>>> {
    list.into_iter().find(|j| j.lock_ok().nzo_id == id).cloned()
}

#[cfg(feature = "indexer")]
pub(super) fn wall_tip_body(
    tip: Option<nzbkit::index::TipInfo>,
    initialized: bool,
) -> serde_json::Value {
    let Some(tip) = tip else {
        return json!({"latest": serde_json::Value::Null, "new": 0, "keys": []});
    };
    json!({
        "latest": tip.latest,
        "new": if initialized { tip.new_keys } else { 0 },
        "keys": if initialized { tip.keys } else { Vec::new() },
    })
}

/// How often the compact watcher looks for a foreground job. The whole
/// point is that a download does not visibly stall, so this is the worst
/// case the user could see - it wants to be well under the moment it
/// takes them to notice, and it costs one relaxed atomic load per tick.
#[cfg(feature = "indexer")]
pub(super) const COMPACT_ABORT_POLL_MS: u64 = 100;

/// §95: how much of the freelist one `compact_chunk` reclaims, in pages.
///
/// This is the worst case a download can wait for the compactor, so it
/// is the whole quality of the feature: the loop checks for a job
/// between chunks, and a chunk cannot be cut short.
///
/// 2048 pages is 8 MB at the default 4 KB page size. Measured by
/// `nzbkit/tests/compact_abort_latency.rs` on a 1.16 GB index: 66
/// chunks, worst single chunk 169 ms, and across a sweep of arrival
/// offsets the worst a job actually waited was 113 ms - against 4061 ms
/// for the VACUUM path it replaces, which also failed to stop at all
/// for 3 of 9 arrivals. Same order as the COMPACT_ABORT_POLL_MS the old
/// design already accepted, and far below the moment a user notices.
///
/// Chunk cost grows with the FILE, not with this number alone: the same
/// 2048 pages took 67 ms on a 103 MB index and 169 ms on a 1.16 GB one,
/// because the pages being moved are scattered further apart. So this
/// bound is soft at the top end - halve it if a really large index ever
/// makes the wait visible.
///
/// Smaller is not free: each chunk is its own write transaction and
/// truncate. At this size the whole chunked pass costs ~40% more than
/// the single VACUUM did (5991 ms vs 4218 ms on that 1.16 GB index),
/// which is the right trade for idle work that is now both abortable
/// and resumable.
#[cfg(feature = "indexer")]
pub(super) const COMPACT_CHUNK_PAGES: u32 = 2048;

/// The rendezvous between a maintenance statement and the watcher that
/// may need to abort it (Codex sweep 3 Aug M5).
///
/// An interrupt handle is per CONNECTION, not per statement, so handing
/// the watcher a handle taken during an EARLIER `with_index` call was
/// two bugs at once: a job starting before the maintenance closure
/// reacquired the index mutex interrupted whatever unrelated writer
/// held it in the gap (that write rolled back for nothing), and the
/// maintenance then began anyway, with the job now active and the
/// watcher already retired - the multi-minute stall the whole mechanism
/// exists to prevent.
///
/// Both sides go through this one mutex, so exactly one of them wins:
/// either the statement arms first (and the watcher's interrupt lands
/// on it and nothing else), or the watcher stands the statement down
/// first (and it never runs).
#[cfg(feature = "indexer")]
#[derive(Default)]
pub(super) struct MaintenanceArm {
    inner: Mutex<MaintenanceArmState>,
}

#[cfg(feature = "indexer")]
#[derive(Default)]
struct MaintenanceArmState {
    handle: Option<nzbkit::index::InterruptHandle>,
    stood_down: bool,
}

#[cfg(feature = "indexer")]
impl MaintenanceArm {
    /// Called from the blocking task while it HOLDS the index guard,
    /// immediately before the statement. `false` means a job appeared
    /// first and the statement must not run at all.
    pub(super) fn arm(&self, handle: nzbkit::index::InterruptHandle) -> bool {
        let mut st = self.inner.lock_ok();
        if st.stood_down {
            return false;
        }
        st.handle = Some(handle);
        true
    }

    /// Called from the blocking task once the statement has returned,
    /// still holding the guard: a later interrupt must not land on
    /// whatever this connection does next.
    pub(super) fn disarm(&self) {
        self.inner.lock_ok().handle = None;
    }

    /// Called from the watcher when a download starts. Interrupts the
    /// armed statement if there is one, and in every case makes a
    /// not-yet-armed statement stand down.
    pub(super) fn abort(&self) {
        let mut st = self.inner.lock_ok();
        st.stood_down = true;
        if let Some(h) = st.handle.take() {
            h.interrupt();
        }
    }
}

/// Watch for a download starting while a VACUUM is in flight, and abort
/// the rewrite when one does. Returns true if it aborted.
///
/// `compact_verdict` asks whether a download is running BEFORE the
/// rewrite begins, and there is nothing it can do about a job that
/// arrives one moment later - by then the rewrite holds the gate that
/// the download worker blocks on, so the job sits in `Downloading` with
/// no progress and no log line for as long as the rewrite lasts. This is
/// the other half of that check: the same question, asked continuously,
/// with an answer that can still act.
///
/// `abort` is a closure rather than the interrupt handle itself so this
/// can be tested without a database - and so the caller keeps the
/// decision about WHICH connection it is entitled to interrupt.
#[cfg(feature = "indexer")]
pub(super) async fn abort_compact_when_job_starts(
    jobs: Arc<AtomicUsize>,
    done: Arc<AtomicBool>,
    abort: impl Fn(),
) -> bool {
    loop {
        tokio::time::sleep(std::time::Duration::from_millis(COMPACT_ABORT_POLL_MS)).await;
        // Checked first: once the rewrite is over there is no statement
        // to interrupt, and interrupting is per-connection - a late
        // abort would hit whatever the index is doing next.
        if done.load(Ordering::Acquire) {
            return false;
        }
        if jobs.load(Ordering::Acquire) > 0 {
            abort();
            return true;
        }
    }
}

/// `needs_scratch` is the FullRewrite path: only a VACUUM writes a
/// second copy of the database beside the original. §95's chunked path
/// moves pages down inside the file it already has and truncates, so
/// asking a nearly-full volume for twice the file would defer it
/// forever - on exactly the small NAS volumes where reclaiming the space
/// matters most, and where `compact_pending` being sticky means the
/// deferral is silent and permanent.
#[cfg(feature = "indexer")]
pub fn compact_verdict(
    pending: bool,
    scanning: bool,
    downloading: bool,
    db_bytes: u64,
    free: Option<u64>,
    needs_scratch: bool,
) -> CompactVerdict {
    if !pending {
        return CompactVerdict::NotNeeded;
    }
    if downloading {
        return CompactVerdict::Busy("a download is running");
    }
    if scanning {
        return CompactVerdict::Busy("a scan pass is running");
    }
    if !needs_scratch {
        // Chunked: each chunk commits and shortens the file, so the
        // high-water mark is the file itself. Nothing to reserve.
        return CompactVerdict::Go;
    }
    // SQLite writes the rebuilt database beside the original and only
    // then swaps, so peak usage is ~2x. The 64 MB on top covers the
    // journal and keeps a nearly-full volume from being taken to zero.
    let need = db_bytes.saturating_mul(2).saturating_add(64 << 20);
    match free {
        // free_bytes answering None means we could not measure the
        // volume at all. Proceeding blind is how the min-free guard
        // once filled the disk it was protecting; stay deferred.
        None => CompactVerdict::NoRoom { need, free: 0 },
        Some(f) if f < need => CompactVerdict::NoRoom { need, free: f },
        Some(_) => CompactVerdict::Go,
    }
}

impl Daemon {
    /// The passwords-file candidates, read fresh so hand-edits and a
    /// just-imported competitor file apply to the very next unlock.
    pub fn read_unpack_passwords(&self) -> Vec<String> {
        crate::smart::read_password_file(&self.password_file.lock_ok())
    }

    /// Why indexing is standing down, or None if it should run. A reason
    /// rather than a bool so the UI can say WHICH it is - an index that
    /// has quietly stopped growing is otherwise a mystery, and the two
    /// causes need opposite actions from the user.
    ///
    /// The download half counts jobs in flight, NOT `started_at`: job
    /// N's tail overlaps job N+1's network phase, so `started_at` goes
    /// None between queued jobs while the pipeline is still busy.
    #[cfg(feature = "indexer")]
    pub(super) fn indexing_pause_reason(&self) -> Option<&'static str> {
        // Offline outranks everything: it is a promise that this machine
        // is touching no provider, and a scan is provider traffic. The
        // tip watcher already drops and QUITs its held sessions on any
        // reason here, which is most of what going offline has to do.
        if self.offline.load(Ordering::Relaxed) {
            return Some("offline");
        }
        // The master switch outranks pause, and reads differently in the
        // UI: "paused" invites a Resume button, "off" does not - the
        // whole feature is hidden while this one holds.
        if !self.index_enabled.load(Ordering::Relaxed) {
            return Some("off");
        }
        if self.index_paused.load(Ordering::Relaxed) {
            return Some("paused");
        }
        if self.index_pause_on_download.load(Ordering::Relaxed)
            && self.index_jobs_active.load(Ordering::Acquire) > 0
        {
            return Some("downloading");
        }
        // A QUEUED job outranks background scans exactly as a running
        // one does. Measured 2026-08-05: four adds sat 38 s before the
        // runner could pick the first - `index_jobs_active` only rises
        // AFTER pick, so the scanners' whole 100 ms stand-down
        // machinery was blind to work the runner had not reached yet.
        if self.index_pause_on_download.load(Ordering::Relaxed) && self.queue_has_runnable() {
            return Some("downloading");
        }
        None
    }

    /// The same question for the spot leg. Everything after the master
    /// switch is shared with indexing - a paused index means "stop
    /// scanning", and a download outranks every background scan
    /// regardless of which source it feeds - but the switches are
    /// independent, so "off" is asked separately.
    #[cfg(feature = "indexer")]
    pub(super) fn spot_pause_reason(&self) -> Option<&'static str> {
        if self.offline.load(Ordering::Relaxed) {
            return Some("offline");
        }
        if !self.spot_enabled.load(Ordering::Relaxed) {
            return Some("off");
        }
        if self.index_paused.load(Ordering::Relaxed) {
            return Some("paused");
        }
        if self.index_pause_on_download.load(Ordering::Relaxed)
            && self.index_jobs_active.load(Ordering::Acquire) > 0
        {
            return Some("downloading");
        }
        // A QUEUED job outranks background scans exactly as a running
        // one does. Measured 2026-08-05: four adds sat 38 s before the
        // runner could pick the first - `index_jobs_active` only rises
        // AFTER pick, so the scanners' whole 100 ms stand-down
        // machinery was blind to work the runner had not reached yet.
        if self.index_pause_on_download.load(Ordering::Relaxed) && self.queue_has_runnable() {
            return Some("downloading");
        }
        None
    }

    /// True when some queue entry is ready for the runner (Queued and
    /// not paused; deferred counts - the runner picks deferred work
    /// when nothing else is runnable, so it still wants the threads).
    /// Deliberately cheap and approximate: this feeds the scanners'
    /// 100 ms stand-down polls, which need "is a download imminent",
    /// not the runner's full pick logic.
    pub(super) fn queue_has_runnable(&self) -> bool {
        self.queue.lock_ok().iter().any(|j| {
            let g = j.lock_ok();
            g.state == JobState::Queued && !g.paused
        })
    }

    /// Does anything want the index database open? The file backs both
    /// sources, so it is created and held for as long as EITHER switch
    /// is on - and with both off it is never opened, never created on a
    /// fresh install, exactly as when indexing was the only source.
    #[cfg(feature = "indexer")]
    pub(super) fn index_db_wanted(&self) -> bool {
        self.index_enabled.load(Ordering::Relaxed) || self.spot_enabled.load(Ordering::Relaxed)
    }

    /// How many of the user's indexer accounts are configured and on.
    /// The posture question the UI asks in several places: with none of
    /// these there is nothing to search but the local index, and with one
    /// or more the local index is the optional extra.
    pub fn enabled_indexers(&self) -> usize {
        self.indexers.lock_ok().iter().filter(|i| i.enabled).count()
    }

    /// May the watchlist spend the user's indexer accounts? See
    /// `watchlist_external_set` for why this is a tri-state rather than
    /// the plain bool it reads like.
    pub fn watchlist_external_on(&self) -> bool {
        if self.watchlist_external_set.load(Ordering::Relaxed) {
            self.watchlist_external.load(Ordering::Relaxed)
        } else {
            self.enabled_indexers() > 0
        }
    }

    /// §74: the instant watchlist path, compiled from the live watchlist.
    /// `None` when the feature is off or there is nothing enabled to
    /// match - the callers use that to skip installing an arrival watch
    /// at all, so an install without a watchlist pays nothing.
    #[cfg(feature = "indexer")]
    pub(super) fn instant_matcher(&self) -> Option<crate::watchlist::InstantMatcher> {
        if !self.watchlist_instant.load(Ordering::Relaxed) {
            return None;
        }
        let m = crate::watchlist::InstantMatcher::compile(&self.watchlist.lock_ok());
        (!m.is_empty()).then_some(m)
    }

    /// §74: wake the watchlist pass because `names` just arrived, unless
    /// this hour's allowance of instant passes is already spent.
    ///
    /// Returns whether the pass was woken. A refusal is not a lost grab:
    /// the periodic pass runs a minute later over the same index and
    /// applies exactly the same rules, so the ceiling only ever costs the
    /// "instant" part.
    #[cfg(feature = "indexer")]
    pub(super) fn instant_kick(&self, names: &[String], now: i64) -> bool {
        if names.is_empty() {
            return false;
        }
        {
            let mut k = self.instant_kicks.lock_ok();
            if !crate::watchlist::kick_allowed(
                &mut k,
                self.watchlist_instant_max.load(Ordering::Relaxed),
                now,
            ) {
                return false;
            }
        }
        {
            // The pass drains this, so a second arrival landing before it
            // runs joins the same wake-up rather than queueing another.
            let mut hint = self.instant_hint.lock_ok();
            for n in names {
                if !hint.contains(n) {
                    hint.push(n.clone());
                }
            }
            // A watchlist item nobody grabs (below min_quality, say) would
            // otherwise keep re-arriving and grow this without bound.
            const HINT_CAP: usize = 256;
            if hint.len() > HINT_CAP {
                let excess = hint.len() - HINT_CAP;
                hint.drain(..excess);
            }
        }
        self.watch_now.notify_one();
        true
    }

    /// Safe to run heavy index maintenance (prune, reseed, compact) right
    /// now? Two separate questions that one pause predicate cannot answer.
    /// Indexing must be enabled - that is user preference - AND no
    /// download may be in flight, which is a hard constraint REGARDLESS of
    /// the pause preference: with "pause while downloading" switched off,
    /// `indexing_pause_reason()` is None during a job, so gating on it
    /// alone let a prune run straight through somebody's download.
    #[cfg(feature = "indexer")]
    pub(super) fn index_maintenance_ok(&self) -> bool {
        self.indexing_pause_reason().is_none()
            && self.index_jobs_active.load(Ordering::Acquire) == 0
    }

    /// Should the pre feed be connected right now?
    ///
    /// Two switches, both required. Its own, because it is an outbound
    /// connection to a network nothing else here talks to. The indexer's,
    /// because the feed writes into the index database and names indexed
    /// releases - with the indexer off there is nothing for it to name
    /// and nowhere to put what it hears.
    #[cfg(feature = "indexer")]
    pub(super) fn predb_feed_on(&self) -> bool {
        self.predb_enabled.load(Ordering::Relaxed) && self.index_enabled.load(Ordering::Relaxed)
    }

    /// Record what the feed is doing, for the settings card.
    #[cfg(feature = "indexer")]
    pub(super) fn predb_say(&self, what: &str) {
        *self.predb_status.lock_ok() = what.to_string();
    }

    /// Turn the stored settings into a connection description.
    #[cfg(feature = "indexer")]
    pub(super) fn predb_irc_config(&self) -> nzbkit::predb::IrcConfig {
        let raw = self.predb_server.lock_ok().trim().to_string();
        // `host`, `host:port`, `[v6]`, `[v6]:port`. The bracket form has
        // to be split before the last colon is consulted, or every
        // literal IPv6 address reads as a host with a nonsense port.
        let (host, port) = if let Some(rest) = raw.strip_prefix('[') {
            match rest.split_once("]:") {
                Some((h, p)) => (
                    h.to_string(),
                    p.parse().unwrap_or(nzbkit::predb::DEFAULT_PORT),
                ),
                None => (
                    rest.trim_end_matches(']').to_string(),
                    nzbkit::predb::DEFAULT_PORT,
                ),
            }
        } else {
            match raw.rsplit_once(':') {
                Some((h, p)) => match p.parse::<u16>() {
                    Ok(n) => (h.to_string(), n),
                    Err(_) => (raw.clone(), nzbkit::predb::DEFAULT_PORT),
                },
                None => (raw.clone(), nzbkit::predb::DEFAULT_PORT),
            }
        };
        nzbkit::predb::IrcConfig {
            host: if host.is_empty() {
                nzbkit::predb::DEFAULT_HOST.to_string()
            } else {
                host
            },
            port,
            // TLS, and no automatic downgrade. What TLS buys here is not
            // privacy (the channel is public) but ATTRIBUTION: without
            // it, anyone on the path can block 6697, answer on 6667 and
            // inject release names the exact legs go on to match
            // automatically. An operator whose network has no TLS relay
            // opts back in with NZBFAST_PREDB_ALLOW_PLAINTEXT.
            tls: true,
            allow_plaintext: std::env::var_os("NZBFAST_PREDB_ALLOW_PLAINTEXT")
                .is_some_and(|v| v == "1"),
            nick: self.predb_nick.lock_ok().clone(),
            channels: self
                .predb_channels
                .lock_ok()
                .split(',')
                .map(str::trim)
                .filter(|c| !c.is_empty())
                .map(str::to_string)
                .collect(),
        }
    }

    pub(super) fn begin_index_job(self: &Arc<Self>) -> IndexJobGuard {
        let prev = self.index_jobs_active.fetch_add(1, Ordering::AcqRel);
        // Phase marker on the 0 -> 1 edge only (tails overlap the next
        // job, so the counter can sit above 1 for a while), and only
        // when the yield-to-downloads setting actually pauses anything.
        if prev == 0
            && self.index_pause_on_download.load(Ordering::Relaxed)
            && self.index_enabled.load(Ordering::Relaxed)
        {
            self.note_event("indexer", "indexing set aside while downloads run");
        }
        IndexJobGuard(self.index_jobs_active.clone(), Arc::downgrade(self))
    }

    /// Route every manual/scheduled cap change through here so the
    /// governor's ceiling stays in sync.
    pub(super) fn set_speed_ceiling(&self, bps: u64) {
        self.set_speed_ceiling_from(bps, "user");
    }

    /// As [`Self::set_speed_ceiling`], recording WHO chose the number.
    /// A cap a schedule entry applied was presented as the operator's
    /// own setting, so an unexpected 4 MB/s at 08:00 looked like a bug
    /// in the limiter rather than the schedule doing its job.
    pub(super) fn set_speed_ceiling_from(&self, bps: u64, src: &'static str) {
        // Marker on change only: startup re-applies the persisted cap
        // through here, and re-applying the number already in force is
        // not a change anyone made. The auto-speed governor's AIMD
        // steps deliberately bypass this method, so they cannot flood
        // the ring either.
        let old = self.speed_ceiling.swap(bps, Ordering::Relaxed);
        if old != bps {
            let who = match src {
                "schedule" => " by the schedule",
                "api" => " by an API client",
                _ => "",
            };
            let detail = if bps == 0 {
                format!("speed limit removed{who}")
            } else {
                format!("speed limit set to {:.1} MB/s{who}", bps as f64 / 1e6)
            };
            self.note_event("limit", detail);
        }
        *self.limit_source.lock_ok() = src;
        self.hub.rate.set(bps);
    }

    /// Record one daemon-owned moment for the throughput chart's marker
    /// ring, oldest dropped at the cap. Same contract as the pool
    /// ring's `note`: infallible and quiet, because instrumentation
    /// that can fail or block changes the thing it measures.
    pub(super) fn note_event(&self, kind: &'static str, detail: impl Into<String>) {
        let Ok(mut ring) = self.events.lock() else {
            return;
        };
        if ring.len() >= DAEMON_EVENT_RING {
            ring.pop_front();
        }
        ring.push_back(DaemonEvent {
            at_ms: nzbkit::pool::now_ms(),
            kind,
            detail: detail.into(),
        });
    }

    /// Daemon events newest first, for the stats endpoint's merge with
    /// the pool ring.
    pub(super) fn recent_events(&self, limit: usize) -> Vec<DaemonEvent> {
        self.events
            .lock()
            .map(|r| r.iter().rev().take(limit).cloned().collect())
            .unwrap_or_default()
    }

    /// Per-job capability token for /stream URLs (`?t=…`). Media players
    /// can't send API keys, so the authenticated handoffs - /m3u and the
    /// library .strm pointer - embed this instead; it starts THIS job and
    /// nothing else. Derived, not stored: any nzo_id verifies statelessly,
    /// and it stays valid as long as the install (Jellyfin may first play
    /// a .strm months after it was written).
    pub fn stream_token(&self, nzo_id: &str) -> String {
        use sha2::Digest as _;
        let d = sha2::Sha256::digest(format!("{}:{nzo_id}", self.stream_secret).as_bytes());
        format!("{d:x}")[..32].to_string()
    }
}

/// How long the wind-down below is allowed to take before it exits
/// anyway.
///
/// Sized against `docker stop`, which sends SIGTERM and then SIGKILLs 10
/// seconds later. Being killed halfway through the wind-down is the
/// ungraceful exit we are fixing, so the whole sequence has to finish
/// well inside that with room for a loaded host - and every step it
/// waits on is separately bounded (`Connection::quit` at 500 ms, the
/// pool's own EXIT_GRACE at 5 s).
pub(super) const WIND_DOWN_BUDGET: std::time::Duration = std::time::Duration::from_secs(4);

/// How long going offline waits for the wound-down fleet to park before
/// it clears the warm pool regardless.
///
/// Longer than [`WIND_DOWN_BUDGET`] because nothing is about to SIGKILL
/// us: this one is racing the operator's patience, not a container
/// runtime. A graceful pause escalates to a hard abort at ~10 s
/// (`suspend_matching`), and the abort's own QUITs are bounded, so the
/// gauge reaches zero well inside this on any provider that answers at
/// all. It exists for the one that does not.
pub(super) const OFFLINE_PARK_BUDGET: std::time::Duration = std::time::Duration::from_secs(60);

/// Stop cleanly and exit: park the transfer, persist the queue, and
/// hand every open NNTP session back to the provider with a QUIT.
///
/// Shared by `mode=shutdown` and by SIGTERM/SIGINT (issue #13). A
/// container stop has exactly the same work to do as the tray's Quit
/// item, and used to do none of it - nothing was wired to signals, so
/// `docker restart` killed the process outright and left the provider
/// counting ~100 orphaned sessions until its own idle timeout. The
/// restart then asked for a full pool the account could not give it and
/// sat at 0 MB/s.
///
/// Bounded by [`WIND_DOWN_BUDGET`] as a whole: if a step overruns we
/// carry on regardless, because a slow clean exit that gets SIGKILLed is
/// worth no more than the abrupt one.
pub(super) fn wind_down(d: &Arc<Daemon>, rt: &tokio::runtime::Handle, reason: &str) {
    let started = Instant::now();
    info!(target: "shutdown", "{reason} - persisting queue and closing connections");
    // Order matters. Pause first so nothing new is admitted while we are
    // tearing down, THEN wind the transfer down GRACEFULLY.
    //
    // Graceful, not the immediate abort, and the difference is the whole
    // point of this function: the hard abort drops the pool future, and
    // a dropped worker never reaches the `conn.quit()` its exit path is
    // built around. Measured against a mock provider that logs commands
    // - eight busy connections, SIGTERM, eight sockets closed and not one
    // QUIT logged. The graceful path admits no new articles, lets the
    // in-flight window land, and lets each worker say goodbye, which is
    // what actually returns the session slot to the account. It also
    // costs less on resume: what landed is journalled instead of being
    // re-fetched.
    d.paused.store(true, Ordering::Relaxed);
    d.suspend_active(true);
    d.save_queue();
    // Now wait for the sessions themselves to go, because THAT is what
    // the provider is counting - not the job's state.
    //
    // Aborted workers QUIT on their way out, but only at their next
    // response boundary: the abort flag is checked at the top of the
    // worker loop, not inside the read it is parked on. So the job
    // leaves `Downloading` well before the fleet has said goodbye, and
    // waiting on the job (which is what this loop did first) exited
    // after 0.3 s with eight connections still open and not one QUIT
    // sent - measured against a mock provider that logs its commands.
    // The live gauge is the honest signal.
    let connected = || -> usize {
        d.hub
            .pool_live
            .lock_ok()
            .as_ref()
            .map(|l| {
                l.servers
                    .iter()
                    .map(|s| s.connected.load(Ordering::Relaxed))
                    .sum()
            })
            .unwrap_or(0)
    };
    let open_at_signal = connected();
    while started.elapsed() < WIND_DOWN_BUDGET && connected() > 0 {
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    if open_at_signal > 0 {
        let left = connected();
        info!(
            target: "shutdown",
            "{} of {open_at_signal} provider connection(s) closed{}",
            open_at_signal - left,
            if left > 0 {
                format!(" - {left} still busy, dropping them")
            } else {
                String::new()
            }
        );
    }
    // The connections nobody is using are the ones a restart trips over:
    // an idle daemon holds no pool at all, but it does hold parked warm
    // sessions, and those are pure occupancy on the account's cap.
    // `clear()` QUITs each one.
    //
    // `.get()`, NOT `hub.warm()`: the accessor CONSTRUCTS the pool on
    // first call, and construction spawns a keepalive tick, which needs
    // a reactor this thread does not have. On a daemon that had never
    // pooled anything, asking for the pool in order to empty it panicked
    // the wind-down thread - and with SIGTERM's default disposition
    // already replaced, that left a process no `docker stop` could end.
    if let Some(warm) = d.hub.warm.get() {
        let left = WIND_DOWN_BUDGET.saturating_sub(started.elapsed());
        let _ = rt.block_on(async {
            tokio::time::timeout(
                left.max(std::time::Duration::from_millis(200)),
                warm.clear(),
            )
            .await
        });
    }
    info!(
        target: "shutdown",
        "wound down in {:.1}s",
        started.elapsed().as_secs_f64()
    );
    // Flush the log tee's buffer along with stdout before the exit.
    use std::io::Write;
    let _ = std::io::stdout().flush();
}

/// [`wind_down`], then go - and go whatever happens.
///
/// Installing a signal handler replaces SIGTERM's default disposition,
/// so from here on NOTHING else will end this process for us: a panic or
/// a wedge inside the wind-down does not degrade to the old abrupt exit,
/// it degrades to a daemon that ignores `docker stop` entirely and waits
/// out the 10 s until SIGKILL. Both are covered - the wind-down cannot
/// unwind past `catch_unwind`, and the watchdog exits on time even if it
/// blocks forever.
pub(super) fn wind_down_and_exit(d: &Arc<Daemon>, rt: &tokio::runtime::Handle, reason: &str) -> ! {
    {
        let reason = reason.to_string();
        std::thread::spawn(move || {
            std::thread::sleep(WIND_DOWN_BUDGET + std::time::Duration::from_secs(2));
            info!(target: "shutdown", "{reason}: wind-down overran its budget - exiting now");
            std::process::exit(0);
        });
    }
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| wind_down(d, rt, reason)));
    if r.is_err() {
        info!(target: "shutdown", "wind-down failed - exiting anyway");
    }
    std::process::exit(0);
}

/// Wire SIGTERM/SIGINT to [`wind_down_and_exit`].
///
/// Unix only for the terminate signal; Ctrl-C is handled on every
/// platform. A second signal while the first wind-down is still running
/// is ignored on purpose - the budget already bounds it, and re-entering
/// the sequence would abort the QUITs it exists to send.
///
/// The wait runs on a DEDICATED thread with its own single-thread
/// runtime, never as a task on the shared runtime. A spawned signal
/// task is only as responsive as the runtime's free workers, and the
/// index loops park workers in synchronous SQLite work behind one
/// mutex: with every worker blocked that way, a spawned handler is not
/// polled AT ALL - measured on a saturated 4-worker runtime, SIGTERM
/// went unhandled for five minutes, and the live daemon sat ~30 s on
/// SIGTERM mid-deepening (2 Aug, TODO §98.2). On its own thread the
/// same handler answered in under a millisecond under the same
/// saturation. `docker stop` SIGKILLs at 10 s, so those 30 s are the
/// difference between a graceful exit and an abrupt one.
pub(super) fn install_shutdown_signals(daemon: &Arc<Daemon>) {
    let rt = tokio::runtime::Handle::current();
    let d = daemon.clone();
    let spawned = std::thread::Builder::new()
        .name("signal-wait".into())
        .spawn(move || {
            let srt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(r) => r,
                Err(e) => {
                    info!(target: "shutdown", "cannot build the signal runtime ({e}) - stop will be abrupt");
                    return;
                }
            };
            let reason = srt.block_on(wait_for_shutdown_signal());
            // Off this thread too: the wind-down blocks on locks and on
            // `Handle::block_on`, and this thread must stay free to keep
            // ignoring further signals (see above).
            std::thread::spawn(move || wind_down_and_exit(&d, &rt, reason));
            // Park forever rather than return: dropping the runtime
            // would unregister the signal handlers and restore the
            // default disposition, so a second SIGTERM mid-wind-down
            // would kill the process abruptly - the exact exit the
            // wind-down exists to avoid.
            loop {
                std::thread::park();
            }
        })
        .is_ok();
    if !spawned {
        info!(target: "shutdown", "cannot spawn the signal thread - stop will be abrupt");
    }
}

/// Resolve to the name of whichever shutdown signal arrives first.
pub(super) async fn wait_for_shutdown_signal() -> &'static str {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        // A failure to register is not fatal: it costs the graceful exit,
        // not the daemon. Say so rather than dying at startup.
        let mut term = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(e) => {
                info!(target: "shutdown", "cannot listen for SIGTERM ({e}) - stop will be abrupt");
                let _ = tokio::signal::ctrl_c().await;
                return "SIGINT";
            }
        };
        tokio::select! {
            _ = term.recv() => "SIGTERM",
            _ = tokio::signal::ctrl_c() => "SIGINT",
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
        "Ctrl-C"
    }
}

/// Pause now; with `mins > 0` also arm an auto-resume ("pause for N
/// minutes", SAB's set_pause). The timer only fires if no manual
/// pause/resume happened in between (generation check).
pub(super) fn timed_pause(d: &Arc<Daemon>, mins: u64, graceful: bool) {
    let was_paused = d.paused.swap(true, Ordering::Relaxed);
    // Every caller of this is a person or a client acting for one - the
    // scheduler pauses through `apply_action`, which claims the pause
    // for itself.
    *d.pause_source.lock_ok() = "user";
    // M23e: also stop the transfer that's in flight, not just new jobs.
    d.suspend_active(graceful);
    // Marker on the transition only; a re-sent pause of a paused queue
    // is not a new moment.
    if !was_paused {
        d.note_event(
            "pause",
            if mins == 0 {
                "downloads paused".to_string()
            } else {
                format!("downloads paused for {mins} minutes")
            },
        );
    }
    if mins == 0 {
        // Still bump the generation: a plain pause has to cancel any
        // auto-resume a previous timed pause left pending.
        d.pause_gen.fetch_add(1, Ordering::Relaxed);
        *d.pause_until.lock_ok() = None;
    } else {
        arm_pause_timer(d, std::time::Duration::from_secs(mins * 60));
    }
    persist_pause(d);
}

/// Arm the auto-resume timer for a pause that is ALREADY in effect.
///
/// Split out of `timed_pause` so a pause restored at startup can run out
/// the time it has left rather than a fresh full interval, and so it can
/// take a Duration - a pause with 90 seconds to go does not round to a
/// whole number of minutes.
pub(super) fn arm_pause_timer(d: &Arc<Daemon>, dur: std::time::Duration) {
    let my_gen = d.pause_gen.fetch_add(1, Ordering::Relaxed) + 1;
    *d.pause_until.lock_ok() = Some(Instant::now() + dur);
    let d = d.clone();
    std::thread::spawn(move || {
        std::thread::sleep(dur);
        if d.pause_gen.load(Ordering::Relaxed) == my_gen {
            d.paused.store(false, Ordering::Relaxed);
            *d.pause_until.lock_ok() = None;
            persist_pause(&d);
            info!(target: "pause", "timed pause over - resumed");
            d.note_event("resume", "timed pause over - downloads resumed");
        }
    });
}

/// Record the queue's pause state so it survives a restart.
///
/// A pause is a deliberate act - a metered week, a call in progress, a
/// benchmark running - and an update or a crash-restart used to undo it
/// silently, with the queue back at full speed and nothing on screen
/// saying the user's choice had been dropped.
///
/// A timed pause is stored as an ABSOLUTE deadline, not "N minutes left".
/// "Pause for 30 minutes" is a statement about when downloading may start
/// again, so a daemon that is down for an hour must come back running,
/// not sit out another half hour. `restore_pause` handles the deadline
/// that passed while we were gone.
///
/// Called only from the paths that carry the user's intent. Notably NOT
/// from `shutdown`/`restart_daemon`, which pause the queue as part of
/// winding down - persisting that would mean every clean quit came back
/// paused.
pub(super) fn persist_pause(d: &Daemon) {
    let paused = d.paused.load(Ordering::Relaxed);
    let until = d.pause_until.lock_ok().map(|deadline| {
        // Instant is monotonic and process-local, so convert through the
        // time REMAINING to get a wall-clock deadline we can write down.
        unix_now() + deadline.saturating_duration_since(Instant::now()).as_secs() as i64
    });
    // Null removes the key: a running queue leaves nothing behind, so
    // settings.json keeps holding only what the user actually changed.
    save_settings(
        &d.settings_path,
        &[
            ("paused", if paused { json!(true) } else { Value::Null }),
            (
                "pause_until_unix",
                match until.filter(|_| paused) {
                    Some(u) => json!(u),
                    None => Value::Null,
                },
            ),
            // Offline must survive a restart, or a daemon that was
            // deliberately kept off the account would silently reconnect
            // the moment it came back - reoccupying the address slot the
            // operator went offline to free, with nothing on screen
            // saying so.
            (
                "offline",
                match d.offline.load(Ordering::Relaxed) {
                    true => json!(true),
                    false => Value::Null,
                },
            ),
            (
                "paused_by_offline",
                match d.paused_by_offline.load(Ordering::Relaxed) {
                    true => json!(true),
                    false => Value::Null,
                },
            ),
        ],
    );
}

/// Put back the pause the last run was in, at startup.
///
/// Runs BEFORE the scheduler's own startup evaluation, which is allowed
/// to overrule it: a schedule is a standing rule about what should be
/// true at this hour, and it already re-evaluates the whole week on boot
/// for exactly that reason.
pub(super) fn restore_pause(d: &Arc<Daemon>, saved: &serde_json::Map<String, Value>) {
    // Offline first, and independently of the pause below: it is the
    // stronger state and the one with a promise attached (this machine
    // is not on the account). Restored by setting the flags directly
    // rather than through `set_offline`, because the queue pause it
    // would apply is already recorded alongside it - re-deriving it here
    // would forget whether the operator had ALSO paused by hand.
    if saved.get("offline").and_then(Value::as_bool) == Some(true) {
        d.offline.store(true, Ordering::Relaxed);
        d.paused_by_offline.store(
            saved.get("paused_by_offline").and_then(Value::as_bool) == Some(true),
            Ordering::Relaxed,
        );
        info!(target: "offline", "restored: offline, touching no provider");
    }
    if saved.get("paused").and_then(Value::as_bool) != Some(true) {
        return;
    }
    let Some(deadline) = saved.get("pause_until_unix").and_then(Value::as_i64) else {
        d.paused.store(true, Ordering::Relaxed);
        info!(target: "pause", "restored: queue paused");
        return;
    };
    let left = deadline - unix_now();
    if left <= 0 {
        // The auto-resume fell due while the daemon was down. Honour it:
        // start running, and clear the keys so we don't re-read them.
        info!(target: "pause", "timed pause expired while stopped - resumed");
        persist_pause(d);
        return;
    }
    d.paused.store(true, Ordering::Relaxed);
    arm_pause_timer(d, std::time::Duration::from_secs(left as u64));
    info!(target: "pause", "restored: paused, {} min left", (left + 59) / 60);
}

/// M14g3: one 1 Hz auto-speed control step (LEDBAT-flavoured AIMD).
/// `delay_ms` is smoothed RTT minus the base (uncongested) RTT - the
/// queueing delay OUR traffic is inflicting on the household. Above
/// target: multiplicative backoff (yield fast when someone starts a call
/// or a game). Well below target: additive-ish climb to soak spare
/// capacity. Never below the floor (downloads always trickle), never
/// above the user/schedule ceiling.
/// How many failure-link replacements deep an automatic re-grab will go
/// before it stops asking and only reports. An indexer with a run of
/// dead posts for one title would otherwise walk the entire run
/// unattended, which is a lot of someone's block account spent on a
/// title that is evidently not out there.
pub(super) const FAILURE_REGRAB_MAX: u8 = 3;

/// The categories every install offers before anyone configures one.
///
/// These are the *arr family's own out-of-the-box values - Sonarr `tv`,
/// Radarr `movies`, Lidarr `music`, Readarr `books` - so a default
/// install of any of them passes its connection test against a default
/// install of ours. `*` is SABnzbd's "no category" entry and must stay
/// first. Categories cost nothing until a job uses one: the directory is
/// created at download time, not here.
pub(super) const DEFAULT_CATS: &[&str] = &["*", "tv", "movies", "music", "books"];

pub(super) const AUTO_SPEED_TARGET_MS: u64 = 60;
pub(super) const AUTO_SPEED_FLOOR: u64 = 512_000;
pub(super) const AUTO_SPEED_START: u64 = 8_000_000;
pub(super) const AUTO_SPEED_MAX: u64 = 10_000_000_000;

pub(super) fn auto_speed_step(delay_ms: u64, target_ms: u64, cap: u64, ceiling: u64) -> u64 {
    let max = if ceiling == 0 {
        AUTO_SPEED_MAX
    } else {
        ceiling
    };
    let cap = if cap == 0 {
        AUTO_SPEED_START.min(max)
    } else {
        cap
    };
    let new = if delay_ms > target_ms {
        (cap as f64 * 0.8) as u64
    } else if delay_ms < target_ms / 2 {
        (cap as f64 * 1.10) as u64 + 250_000
    } else {
        cap
    };
    new.clamp(AUTO_SPEED_FLOOR.min(max), max)
}

impl Daemon {
    /// Where the newsgroup catalogue cache lives: next to the index db,
    /// same lifecycle (wiping the index leaves it - it's server data,
    /// not scan data).
    #[cfg(feature = "indexer")]
    pub(super) fn groups_cache_path(&self) -> PathBuf {
        self.index_db.with_file_name("groups.tsv")
    }

    /// Sampled per-group profiles, beside the catalogue and with the same
    /// lifecycle.
    #[cfg(feature = "indexer")]
    pub(super) fn groupstats_cache_path(&self) -> PathBuf {
        self.index_db.with_file_name("groupstats.tsv")
    }

    /// M30: dupe keys of everything already in the library or on its
    /// way there - Completed history plus the current queue. The wall
    /// joins browse rows against this to badge "you have this".
    #[cfg(feature = "indexer")]
    pub(super) fn owned_dupe_keys(&self) -> std::collections::HashSet<String> {
        let mut set = std::collections::HashSet::new();
        for j in self.queue.lock_ok().iter() {
            if let Some(k) = j.lock_ok().dupe_key.clone() {
                set.insert(k);
            }
        }
        for j in self.history.lock_ok().iter() {
            let g = j.lock_ok();
            if g.state == JobState::Completed
                && let Some(k) = g.dupe_key.clone()
            {
                set.insert(k);
            }
        }
        set
    }

    /// M31b: the parse-key set of everything the user already has -
    /// completed history plus the live queue. These are `title_key`s (the
    /// wall's grouping key), NOT dupe keys, so the Affinity sort can sink
    /// owned titles with a plain `title_key IN (...)`.
    #[cfg(feature = "indexer")]
    pub(super) fn owned_title_keys(&self) -> std::collections::HashSet<String> {
        let mut set = std::collections::HashSet::new();
        let mut push = |name: &str| {
            let k = crate::wall::parse_release(name).key;
            if !k.is_empty() {
                set.insert(k);
            }
        };
        for j in self.queue.lock_ok().iter() {
            push(&j.lock_ok().name);
        }
        for j in self.history.lock_ok().iter() {
            let g = j.lock_ok();
            if g.state == JobState::Completed {
                push(&g.name);
            }
        }
        set
    }

    /// The categories offered to clients, `*` excluded, as the comma list
    /// the `categories` setting round-trips.
    pub(super) fn cat_list(&self) -> String {
        self.cats
            .lock_ok()
            .iter()
            .filter(|c| *c != "*")
            .cloned()
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// Remember a category, and write it through to settings the first
    /// time it is seen.
    ///
    /// The list used to live only in memory, rebuilt at startup from the
    /// categories still present in `queue.json` - so a category survived
    /// exactly as long as a job carrying it stayed in history, and a
    /// fresh install offered nothing but the built-ins. Sonarr and Radarr
    /// validate their configured category against this list and refuse to
    /// connect when it is absent, so a user whose category was anything
    /// other than a built-in met "Category does not exist" before they
    /// could add the first job that would have registered it.
    pub(super) fn register_cat(&self, cat: &str) {
        if cat.is_empty() || cat == "*" {
            return;
        }
        if !self.cats.lock_ok().insert(cat.to_string()) {
            return;
        }
        // ADDITIVE, because this is a first-seen registration and the
        // list it appends to is not this worker's to replace. The old
        // code took `cat_list()` after dropping the lock and wrote that
        // snapshot whole, so two workers registering different new
        // categories could interleave: B wrote {a,b}, then A overwrote
        // it with {a}. Live memory still held both, so nothing looked
        // wrong until a restart - and then category B was simply gone,
        // and an *arr configured against it failed its category test.
        //
        // Merging inside the settings critical section makes the write
        // order stop mattering: whatever else has landed on disk stays.
        let mine = self.cat_list();
        update_settings(&self.settings_path, |map| {
            let on_disk = map.get("categories").and_then(Value::as_str).unwrap_or("");
            map.insert("categories".into(), json!(merge_cat_list(on_disk, &mine)));
        });
    }

    /// M29: everything a wall verdict needs - the availability-ledger
    /// snapshot plus the user's enabled backbones. None when the ledger
    /// is still empty or no server is enabled (verdicts all null).
    #[cfg(feature = "indexer")]
    pub(super) fn oracle_ctx(
        &self,
        cfg_path: &std::path::Path,
    ) -> Option<(nzbkit::oracle::Snapshot, Vec<String>)> {
        // with_index_read: every caller is an interactive handler (wall2,
        // index_browse, oracle_takedowns) - none may park behind ingest.
        let snap = self.with_index_read(|ix| ix.oracle_snapshot().ok())?;
        if snap.is_empty() {
            return None;
        }
        let mut bbs: Vec<String> = nzbkit::config::Config::load(cfg_path)
            .map(|c| {
                c.servers
                    .iter()
                    .filter(|s| s.enabled)
                    .map(|s| nzbkit::oracle::backbone_of(&s.host))
                    .collect()
            })
            .unwrap_or_default();
        bbs.sort();
        bbs.dedup();
        (!bbs.is_empty()).then_some((snap, bbs))
    }

    /// Enqueue an NZB that arrived over HTTP, keeping what the indexer
    /// said about it in the response headers. `depth` is how many
    /// failure-link replacements deep this one already is: 0 for a
    /// user's own add, +1 for each automatic re-grab.
    pub(super) fn enqueue_fetched(
        &self,
        f: &Fetched,
        name: &str,
        category: &str,
        priority: i32,
        password: Option<&str>,
        depth: u8,
        origin: &str,
        allow_dupe: bool,
    ) -> Result<String> {
        let id = self.enqueue(
            &f.bytes, name, category, priority, password, origin, allow_dupe,
        )?;
        let mut stamped = false;
        if !f.failure_link.is_empty() {
            // Just pushed, so it is at the back; scan anyway rather than
            // assume - enqueue may re-order or park a duplicate.
            let q = self.queue.lock_ok();
            if let Some(job) = q.iter().find(|j| j.lock_ok().nzo_id == id) {
                let mut j = job.lock_ok();
                j.failure_link = f.failure_link.clone();
                j.failure_host = f.host.clone();
                j.failure_https = f.https;
                j.failure_depth = depth;
                stamped = true;
            }
        }
        // enqueue saved the queue BEFORE this stamp existed. Without a
        // second save, a restart in the window loses the link and the
        // depth: the job silently never reports, and a replacement chain
        // restarts its allowance at 0.
        if stamped {
            self.save_queue();
        }
        Ok(id)
    }

    /// Who, if anyone, already owns `p`. The claim rule `choose_out_dir`
    /// runs, shared by the enqueue path and by a retry that has to move a
    /// TV-filed job off the shared season folder.
    ///
    /// Takes no job lock it does not release, and must never be called
    /// while holding one belonging to a job that is still in the queue or
    /// history - it locks every job in both.
    pub(super) fn dir_claim(&self, p: &std::path::Path) -> DirClaim {
        // Reserved but not yet recorded: a recategorize picked this
        // folder and is moving a payload into it. No record names it
        // yet, so the queue/history scan below cannot see it.
        if self.reserved.lock_ok().contains(p) {
            return DirClaim::Active;
        }
        let active = {
            let q = self.queue.lock_ok();
            q.iter().any(|j| j.lock_ok().out_dir == *p)
        } || self.history.lock_ok().iter().any(|j| {
            let g = j.lock_ok();
            g.out_dir == *p && !matches!(g.state, JobState::Completed | JobState::Failed)
        });
        if active {
            return DirClaim::Active;
        }
        let completed = self.history.lock_ok().iter().any(|j| {
            let g = j.lock_ok();
            g.out_dir == *p && g.state == JobState::Completed
        });
        // Only while the files are actually there: a result the user
        // deleted, or that `move_completed` relocated, must release the
        // name, or every re-add of a popular release would climb .2,
        // .3, .4 forever.
        if completed && p.exists() {
            DirClaim::Payload
        } else {
            DirClaim::Free
        }
    }

    /// The canonical (pre-collision) output directory for a name+category.
    pub(super) fn base_out_dir(&self, category: &str, dir_stem: &str) -> PathBuf {
        if category.is_empty() {
            return self.out_dir().join(dir_stem);
        }
        // §129 2b: a category can rename its subfolder (SAB's relative
        // "Folder"). Sanitized per component so "tv/anime" nests and
        // nothing escapes the download root; the default stays the
        // category's own name, exactly as before.
        let sub = self
            .cat_meta
            .lock_ok()
            .get(category)
            .map(|m| m.dir.clone())
            .unwrap_or_default();
        if sub.is_empty() {
            return self.out_dir().join(category).join(dir_stem);
        }
        let mut p = self.out_dir();
        for c in sub
            .split(['/', '\\'])
            .filter(|c| !c.is_empty() && *c != "." && *c != "..")
        {
            p = p.join(nzbkit::disk::sanitize_filename(c));
        }
        p.join(dir_stem)
    }

    /// Where an equivalent release already lives, if anywhere: `("queue" |
    /// "history", that job's name)`. This is the M14f identity check,
    /// lifted out of `enqueue` so the UI can ASK before it adds rather
    /// than only discovering the hold afterwards - a wall Play that
    /// silently became a paused duplicate looked, from the outside, like
    /// a download that simply never started.
    ///
    /// PROPERs are never duplicates, and a stem with no derivable key is
    /// never one either. Same rules the hold itself applies, because it
    /// is the same code.
    pub(crate) fn dupe_collision(&self, stem: &str) -> Option<DupeCollision> {
        if is_proper(stem) {
            return None;
        }
        let k = dupe_key(stem)?;
        let queued = self.queue.lock_ok().iter().find_map(|j| {
            let g = j.lock_ok();
            (g.dupe_key.as_ref() == Some(&k)).then(|| DupeCollision {
                where_: "queue",
                name: g.name.clone(),
                nzo_id: g.nzo_id.clone(),
            })
        });
        if queued.is_some() {
            return queued;
        }
        self.history.lock_ok().iter().find_map(|j| {
            let g = j.lock_ok();
            (g.dupe_key.as_ref() == Some(&k) && g.state == JobState::Completed).then(|| {
                DupeCollision {
                    where_: "history",
                    name: g.name.clone(),
                    nzo_id: g.nzo_id.clone(),
                }
            })
        })
    }

    pub(super) fn enqueue(
        &self,
        nzb_bytes: &[u8],
        name: &str,
        category: &str,
        priority: i32,
        password: Option<&str>,
        origin: &str,
        allow_dupe: bool,
    ) -> Result<String> {
        let n = self.next_id.fetch_add(1, Ordering::Relaxed);
        let nzo_id = format!("SABnzbd_nzo_nzbfast{n}");
        let nzb = nzbkit::nzb::Nzb::parse(nzb_bytes)?;
        let mut stem = name.trim_end_matches(".nzb").to_string();
        // Archive password: an explicit param (SAB API) wins; the
        // `Name{{password}}` convention comes OFF the display name either
        // way (and the output folder - never leak a password into the
        // filesystem); the NZB's own <meta type="password"> is the
        // fallback (the engine would find it again at download time -
        // capturing it here surfaces has_password to the UI).
        let mut password: Option<String> = password.filter(|p| !p.is_empty()).map(str::to_string);
        // All three name conventions - {{pw}}, password=pw, {pw} - are
        // recognized and stripped (crate::smart::name_password).
        if let Some((pw, clean)) = crate::smart::name_password(&stem) {
            password.get_or_insert(pw);
            stem = clean;
        }
        if password.is_none() {
            password = nzb.password().map(str::to_string);
        }
        // Zip-packed post, spotted from the NZB's own file list before a
        // single byte is fetched. We cannot unpack one, so saying it here
        // costs the user a click instead of a download. Name-shaped
        // evidence only - an obfuscated container has no name to read, and
        // guessing from a subject line would cry wolf on ordinary posts.
        let zip_packed = nzb
            .files
            .iter()
            .filter_map(|f| f.filename_hint())
            .any(nzbkit::zip::name_is_zip_shaped);
        if zip_packed {
            info!(
                target: "queue",
                "{nzo_id} looks zip-packed - store and deflate zips unpack \
                 natively, an encrypted one too when the job has a password; an \
                 exotic codec will arrive packed"
            );
        }
        // Named after the release as well as the job id. A folder of
        // SABnzbd_nzo_nzbfast<n>.nzb files could not be matched to
        // anything a user had ever seen; the id stays first so the name
        // is still unique and sortable, and old jobs are unaffected
        // because nzb_path is persisted per job.
        let spool_path = self
            .spool
            .join(format!("{nzo_id}-{}.nzb", safe_spool_stem(&stem)));
        // Atomic: a resume re-parses this file; it must never be torn.
        crate::persist::write_atomic(&spool_path, nzb_bytes)?;
        let total_bytes = nzb.eager_bytes();
        // M23 Smart Folders: the first matching rule can retarget the
        // category (= out_root subfolder) and request TV filing.
        let mut category = category.to_string();
        let mut tv_sort = false;
        let mut smart_rule = String::new();
        if let Some(r) =
            crate::smart::first_match(&self.smart_folders.lock_ok(), &stem, total_bytes)
        {
            if !r.category.is_empty() {
                category = r.category.clone();
            }
            tv_sort = r.tv_sort;
            // Kept on the job: "why is this in Films?" is answerable only
            // by the rule that decided it, and the rule list is editable.
            smart_rule = r.name.clone();
            info!(
                target: "smart",
                "rule {:?} matched {stem:?} → category {:?}{}",
                r.name,
                category,
                if tv_sort { " + TV filing" } else { "" }
            );
        }
        // `category` (the `cat=` request param) and `stem` (from the NZB
        // name / `nzbname`) are untrusted and must never escape out_root:
        // an absolute component replaces the base, and `..` is resolved by
        // the OS at create/remove time - a crafted name plus a delete call
        // could otherwise write to, or recursively delete, an arbitrary
        // directory (bug sweep). Force each to a single contained path
        // component before it ever touches the filesystem.
        if !category.is_empty() {
            category = nzbkit::disk::sanitize_filename(&category);
        }
        // §129 2b: the category's default priority fills an add that
        // did not name one (-100, SAB's "default"). An explicit
        // priority - including -2 add-paused - always wins.
        let mut priority = priority;
        if priority == SAB_DEFAULT_PRIORITY
            && let Some(p) = self
                .cat_meta
                .lock_ok()
                .get(&category)
                .and_then(|m| m.priority)
        {
            priority = p;
        }
        let dir_stem = nzbkit::disk::sanitize_filename(&stem);
        let base_out_dir = self.base_out_dir(&category, &dir_stem);
        // Two DIFFERENT NZBs whose names sanitize to the same stem and carry
        // no dupe_key (no SxxEyy/year marker - e.g. software or music posts)
        // are not caught by the M14f duplicate hold below, so they would
        // share one out_dir. Their pipelines deliberately overlap (A's tail
        // repairs/extracts while B's net leg runs), so B's journal + volume
        // writers truncate the files A is still reading → both corrupt. Give
        // a colliding job its own directory.
        //
        // A COMPLETED job's payload claims its directory too. Treating it as
        // inert meant a re-add reused the folder and the very first decoded
        // span truncated the previous, good result - which was then gone for
        // nothing if the replacement failed on missing articles, a password
        // or ENOSPC. The re-add downloads under its own name and takes over
        // the canonical directory only once it has verified (`replaces`,
        // published by `publish_over_previous`). A FAILED job's leftovers are
        // junk and are still reused in place, so retrying a flaky post does
        // not climb .2, .3, .4.
        // From here to the queue push is one transaction. Choosing a
        // directory and deciding "not a duplicate" are both reads of
        // state this job is about to change, and neither is published
        // until the push, so without the lock two concurrent adds of one
        // release agree on everything and then collide.
        let publish = self.add_lock.lock_ok();
        // dir_claim stats the output volume (`p.exists()`), which can be
        // a network share, and enqueue is reachable from tokio tasks
        // (watchlist watcher, RSS poller) - demote the worker around it.
        let (out_dir, replaces) = crate::persist::blocking_db(|| {
            choose_out_dir(&base_out_dir, &dir_stem, &|p| self.dir_claim(p))
        });
        self.register_cat(&category);
        // M14f duplicate check: same identity already queued, running, or
        // successfully completed → hold this one as an ALTERNATIVE
        // (paused, Duplicate priority). It auto-promotes if the original
        // fails; PROPERs always download.
        //
        // `allow_dupe` is the user having been ASKED and said yes (the
        // wall's confirmation). It suppresses the hold, not the key: the
        // job still carries its identity, so everything downstream that
        // reasons about duplicates keeps working.
        let key = dupe_key(&stem);
        let collision = if allow_dupe {
            None
        } else {
            self.dupe_collision(&stem)
        };
        let duplicate = collision.is_some();
        // §129 2d: what a duplicate add becomes is the user's call now.
        // "pause" is the M14f hold; "discard" refuses the add outright;
        // "fail" files it straight to history as Failed (the *arr
        // contract: a failed grab triggers their own search for a
        // different release, where a silently held one just sits).
        let dupe_action = self.dupe_action.lock_ok().clone();
        if let Some(c) = &collision
            && dupe_action == "discard"
        {
            drop(publish);
            // The spool copy was written above; a refused add must not
            // leave it behind.
            let _ = std::fs::remove_file(&spool_path);
            info!(
                target: "queue",
                "refused {stem:?} - duplicate of {} ({}, {}), and duplicates \
                 are set to be discarded",
                c.name, c.nzo_id, c.where_
            );
            anyhow::bail!(
                "duplicate of {:?} ({}) - discarded; the duplicates setting \
                 decides this",
                c.name,
                c.where_
            );
        }
        // Late-pick groundwork: was the runner free to take this job the
        // moment it lands? Only then does a slow pick mean the runner was
        // starved (the fixed inline-SQLite bug held picks back 38 s)
        // rather than the job simply waiting its turn.
        let runner_idle = self.started_at.lock_ok().is_none()
            && !self.paused.load(std::sync::atomic::Ordering::Relaxed)
            && !self.queue.lock_ok().iter().any(|j| {
                let g = j.lock_ok();
                g.state == JobState::Queued && !g.paused
            });
        let job = Arc::new(Mutex::new(Job {
            origin: origin.to_string(),
            nzo_id: nzo_id.clone(),
            name: stem,
            nzb_sha: nzb_sha(nzb_bytes),
            finalizing: false,
            nzb_path: spool_path,
            category: category.clone(),
            state: JobState::Queued,
            total_bytes,
            out_dir,
            fail_message: String::new(),
            fail_detail: String::new(),
            finished_at: None,
            finished_unix: None,
            // SAB priority -2 means "add paused", -100 means "the default".
            priority: enqueue_priority(priority, duplicate),
            paused: duplicate || priority == -2,
            queued_at: Some(Instant::now()),
            idle_at_add: runner_idle,
            // Stamped by `enqueue_fetched` when the NZB came from a URL
            // and the indexer sent an X-DNZB-Failure header.
            failure_link: String::new(),
            failure_host: String::new(),
            failure_https: false,
            failure_depth: 0,
            identify: String::new(),
            media: None,
            media_rejudge: false,
            retries: 0,
            dupe_key: key,
            library: self.library_cats.lock_ok().contains(&category),
            fetched: false,
            tombstone: false,
            del_on_drop: false,
            suspended: false,
            downloaded_bytes: 0,
            elapsed_secs: 0.0,
            deferred: false,
            defer_reason: String::new(),
            defer_count: 0,
            demote: false,
            bad_blocks: None,
            verify_blocks: 0,
            tv_sort,
            smart_rule,
            filed: false,
            filed_suffix: None,
            filed_title: None,
            filed_base: None,
            password,
            password_required: false,
            eat_volumes_ok: false,
            zip_packed,
            unpack_blocked_by: String::new(),
            move_split: String::new(),
            move_failed: String::new(),
            move_attempts: 0,
            move_pending: false,
            archive_shape: String::new(),
            inner_crc: 0,
            identity_name: String::new(),
            identity_imdb: String::new(),
            identity_src: String::new(),
            auto_retry_at: None,
            auto_retry_why: None,
            pp_params: Vec::new(),
            sab_pp: None,
            script_override: String::new(),
            replaces,
            // §77: filled in by the health prober on its next idle tick.
            // Deliberately not probed inline here - enqueue is called
            // from the HTTP handler, the watch folder and the RSS
            // poller, and none of them may block on a network round trip
            // to every configured server.
            health: None,
            // Counted at completion by the post-processing sweeps.
            cleaned_files: 0,
            cleaned_par2: 0,
            cleaned_trash: false,
        }));
        // §129 2d, dupe_action = "fail": the job never queues - it files
        // straight to history as Failed, through the same seam every
        // history mutation uses (history_upsert beside save_queue), and
        // emits the job.failed lifecycle event a real failure would.
        // Retry from history remains the escape hatch: the spool .nzb
        // is in place and retry asks the duplicates question afresh.
        if let Some(c) = &collision
            && dupe_action == "fail"
        {
            {
                let mut g = job.lock_ok();
                g.state = JobState::Failed;
                g.paused = false;
                g.priority = 0;
                g.fail_message = format!(
                    "duplicate of {:?} ({}) - failed; the duplicates setting decides this",
                    c.name, c.where_
                );
                g.finished_at = Some(Instant::now());
                g.finished_unix = Some(unix_now());
            }
            self.history.lock_ok().push(job.clone());
            drop(publish);
            info!(
                target: "queue",
                "{nzo_id} filed to history as FAILED - duplicate of {} ({}), and \
                 duplicates are set to fail",
                c.name, c.nzo_id
            );
            self.save_queue();
            let _ = self.history_upsert(std::slice::from_ref(&job));
            self.life_emit_parked(&job);
            self.history_enforce_retention();
            return Ok(nzo_id);
        }
        self.queue.lock_ok().push_back(job);
        // Published: the directory and the identity are now visible to
        // every other adder.
        drop(publish);
        if duplicate {
            info!(target: "queue", "added {nzo_id} as ALTERNATIVE (duplicate held)");
        } else {
            info!(target: "queue", "added {nzo_id}");
        }
        self.save_queue();
        Ok(nzo_id)
    }

    /// Truth-audit I: did this job park as a held ALTERNATIVE instead of
    /// joining the queue to run? Read back rather than returned out of
    /// `enqueue`, whose signature sixteen call sites share; the job is in
    /// the queue by the time any caller can ask, and reading it here also
    /// answers correctly for the paths that add through
    /// `enqueue_fetched`.
    ///
    /// Without this the add reply said "Added to the queue" for a job that
    /// is paused at Duplicate priority and will not download until the
    /// original fails - the single most confusing thing the add flow could
    /// say, because the row then sits there doing nothing with no
    /// explanation the user asked for.
    pub(super) fn held_as_duplicate(&self, nzo_id: &str) -> bool {
        self.queue.lock_ok().iter().any(|j| {
            let g = j.lock_ok();
            g.nzo_id == nzo_id && g.paused && g.priority == DUPE_PRIORITY
        })
    }

    /// M18b: bill per-server bytes of a finished download to today's
    /// usage history (UTC days, like the quota) and persist. Best-effort.
    pub(super) fn add_usage(&self, per_server: &[(String, u64)]) {
        let days = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| (d.as_secs() / 86_400) as i64)
            .unwrap_or(0);
        let (y, m, d) = civil_from_days(days);
        let key = format!("{y:04}-{m:02}-{d:02}");
        let mut u = self.usage.lock_ok();
        for bucket in [key.as_str(), "lifetime"] {
            let day = u.entry(bucket.to_string()).or_insert_with(|| json!({}));
            if let Some(map) = day.as_object_mut() {
                for (host, bytes) in per_server {
                    if *bytes == 0 {
                        continue;
                    }
                    let cur = map.get(host).and_then(Value::as_u64).unwrap_or(0);
                    map.insert(host.clone(), json!(cur + bytes));
                }
            }
        }
        // Keep ~60 date buckets ("YYYY-…" sorts before "lifetime", which
        // is never pruned - block accounts span years; "reliability"
        // survives the prune the same way).
        while u.keys().filter(|k| k.starts_with('2')).count() > 60 {
            let oldest = u.keys().find(|k| k.starts_with('2')).cloned();
            if let Some(k) = oldest {
                u.remove(&k);
            }
        }
        self.save_usage(&u);
    }

    pub(super) fn save_usage(&self, u: &serde_json::Map<String, Value>) {
        let path = self.spool.join("usage.json");
        if let Ok(text) = serde_json::to_string_pretty(&Value::Object(u.clone())) {
            let _ = crate::persist::write_atomic(&path, text.as_bytes());
        }
    }

    /// Reliability ledger: accumulate a finished job's per-server article
    /// tries/430s under the never-pruned "reliability" usage bucket -
    /// completion% over lifetime is the keep-subscribing signal.
    pub(super) fn add_reliability(&self, per_server: &[(String, u64, u64)]) {
        if per_server.iter().all(|(_, t, _)| *t == 0) {
            return;
        }
        let mut u = self.usage.lock_ok();
        let rel = u
            .entry("reliability".to_string())
            .or_insert_with(|| json!({}));
        if let Some(map) = rel.as_object_mut() {
            for (host, tried, missing) in per_server {
                if *tried == 0 {
                    continue;
                }
                let (ct, cm) = map
                    .get(host)
                    .map(|v| {
                        let g = |k| v.get(k).and_then(Value::as_u64).unwrap_or(0);
                        (g("tried"), g("missing"))
                    })
                    .unwrap_or((0, 0));
                map.insert(
                    host.clone(),
                    json!({"tried": ct + tried, "missing": cm + missing}),
                );
            }
        }
        self.save_usage(&u);
    }

    /// Lifetime (tried, missing) article counts for `host`, from the
    /// reliability ledger. None until the first finished job recorded any.
    pub(super) fn reliability(&self, host: &str) -> Option<(u64, u64)> {
        let u = self.usage.lock_ok();
        let v = u.get("reliability")?.get(host)?;
        let g = |k| v.get(k).and_then(Value::as_u64).unwrap_or(0);
        let (t, m) = (g("tried"), g("missing"));
        (t > 0).then_some((t, m))
    }

    /// Go offline or come back, and do it NOW rather than on a timer.
    ///
    /// Offline is the instant sibling of the idle-release policy: same
    /// goal (stop occupying the account so the operator can use it from
    /// somewhere else), no waiting. It:
    ///
    /// - pauses the queue, so the outage is not spent starting jobs that
    ///   cannot connect. Without this every job would fail its way
    ///   through the queue against articles that were never missing, and
    ///   the operator would come back to a screen of red that says
    ///   nothing about what happened. The active job winds down through
    ///   the ordinary pause path and parks with its journal intact - a
    ///   one-pass extraction survives, because the journal records where
    ///   each article's bytes physically landed;
    /// - hangs up every parked connection in the warm pool, and shuts
    ///   the pool to new ones until this comes back online - the job
    ///   winding down above parks its fleet as it finishes, so a drain
    ///   on its own is undone seconds later;
    /// - stands the background legs down through
    ///   [`Self::indexing_pause_reason`], which the scan loop, the tip
    ///   watcher and the spot leg all consult, and which makes the tip
    ///   watcher QUIT the sessions it holds.
    ///
    /// Coming back online only unpauses a queue that going offline
    /// paused - see `paused_by_offline`.
    pub fn set_offline(self: &Arc<Self>, want_offline: bool) {
        let was = self.offline.swap(want_offline, Ordering::SeqCst);
        if was == want_offline {
            return;
        }
        let (paused, by_offline) = offline_pause_transition(
            want_offline,
            self.paused.load(Ordering::Relaxed),
            self.paused_by_offline.load(Ordering::Relaxed),
        );
        self.paused.store(paused, Ordering::Relaxed);
        self.paused_by_offline.store(by_offline, Ordering::Relaxed);
        if want_offline {
            *self.pause_until.lock_ok() = None;
        }
        // Bumped either way: an in-flight job has to wind down whether or
        // not this transition was the thing that paused the queue,
        // because staying connected is exactly what offline forbids.
        self.pause_gen.fetch_add(1, Ordering::Relaxed);
        match want_offline {
            true => {
                // The pause flag above is a START-time gate (`pick_job`);
                // nothing samples it inside a running fetch. Without the
                // wind-down below, going offline turned the dot red,
                // answered `{"offline":true}` and printed the line under
                // this comment while the active job's whole fleet stayed
                // connected and transferring - on a big job, hours of
                // exactly the occupancy the operator pressed the control
                // to end. Graceful, like every other pause path: in-flight
                // articles land and journal, so the job re-queues instead
                // of failing and a one-pass extraction survives.
                self.suspend_active(true);
                // The prefetch sidecar is its own hub and its own fleet,
                // so the signal above does not reach it. Sync context
                // here (a blocking API handler thread), so this is the
                // sync poke rather than the async `stop_sidecar`.
                self.poke_sidecar(|_| true);
                self.close_warm_pools();
                // ...and again once the fleet has parked. A graceful
                // wind-down ends with each worker HANDING its connection
                // to the warm pool (`park_or_quit`), so the clear fired
                // above drains a map those sessions have not reached yet
                // and they then sit parked for the whole idle timeout -
                // the occupancy offline exists to end.
                self.clear_warm_pool_once_the_fleet_parks();
                info!(target: "offline", "going offline: queue paused, provider connections closing");
            }
            false => {
                // The load-bearing half of `close_warm_pools`. Offline
                // stops the pool taking connections at all, and only
                // this path reopens it - leave it shut and every later
                // job silently pays the cold start again.
                if let Some(pool) = self.hub.warm.get() {
                    pool.set_accepting(true);
                }
                info!(target: "offline", "back online");
            }
        }
        persist_pause(self);
    }

    /// Hang up every parked connection now, and stop it filling back up.
    ///
    /// Both halves are needed, because the queue pause that goes with
    /// offline is a GRACEFUL wind-down: the workers finish their
    /// in-flight windows and park from the pool's drained exits, which
    /// happens over the following seconds - i.e. after the drain below.
    /// A drain alone would empty the pool and then watch the tail of the
    /// job refill it, up to 64 sessions per server, kept alive by the
    /// keepalive tick while the UI reports offline. So the flag goes
    /// down FIRST, synchronously, and is already down when the spawned
    /// clear lands. (`clear` itself must not latch it: config reloads
    /// call that, and pooling has to survive a saved password.)
    ///
    /// `clear` is async (the goodbyes run concurrently under one bound),
    /// while the callers here are sync API handlers, so this hands it to
    /// the runtime rather than blocking a handler thread on a provider
    /// that may be mute. Nothing waits on the result: the sessions are
    /// already unreachable from the pool the moment `clear` takes its
    /// lock, which is what "offline" actually promises.
    pub(super) fn close_warm_pools(&self) {
        if let Some(pool) = self.hub.warm.get() {
            pool.set_accepting(false);
            let pool = pool.clone();
            tokio::spawn(async move { pool.clear().await });
        }
    }

    /// Hang up again once the wound-down fleet has finished parking.
    ///
    /// The second half of going offline while a job is running. A
    /// graceful wind-down does not close the fleet's sockets: each worker
    /// says goodbye to the queue and then HANDS its live connection to
    /// the warm pool (`park_or_quit`). So the `close_warm_pools()` fired
    /// at the moment of the offline call drains a map those sessions have
    /// not entered yet, and ~one fleet's worth of them park into it a
    /// second later and stay for the whole idle timeout - which is the
    /// occupancy the operator pressed the control to end.
    ///
    /// Waits on the live-connection gauge rather than on the job, for the
    /// reason `wind_down` records: a job leaves `Downloading` well before
    /// its fleet has said goodbye. Bounded, because a provider that never
    /// answers must not leave this polling forever.
    ///
    /// Re-checks `offline` every pass, and that check is load-bearing:
    /// coming back online and starting a job must not meet a clear that
    /// was armed for the previous state and QUITs the new job's freshly
    /// warmed sessions.
    pub(super) fn clear_warm_pool_once_the_fleet_parks(self: &Arc<Self>) {
        let d = self.clone();
        tokio::spawn(async move {
            let connected = || -> usize {
                d.hub
                    .pool_live
                    .lock_ok()
                    .as_ref()
                    .map(|l| {
                        l.servers
                            .iter()
                            .map(|s| s.connected.load(Ordering::Relaxed))
                            .sum()
                    })
                    .unwrap_or(0)
            };
            let deadline = Instant::now() + OFFLINE_PARK_BUDGET;
            loop {
                if !d.offline.load(Ordering::Relaxed) {
                    return;
                }
                if connected() == 0 || Instant::now() >= deadline {
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            if !d.offline.load(Ordering::Relaxed) {
                return;
            }
            // `.get()`, never the constructing accessor - see
            // `close_warm_pools` and the wind-down's note at the same
            // call: asking for the pool in order to empty it CREATES it,
            // and creation spawns a keepalive tick.
            if let Some(pool) = d.hub.warm.get() {
                pool.clear().await;
            }
        });
    }

    /// Push each server's idle-release policy into the warm pool.
    ///
    /// The pool is created lazily by the download path, which has the
    /// hub but not the daemon, so this is called from both: at job start
    /// against the config that job is about to use, and again whenever a
    /// server is saved - an operator turning this on while idle, which
    /// is exactly when they would, must not have to wait for the next
    /// download to see it take effect.
    pub fn push_idle_release_policies(&self, servers: &[nzbkit::config::ServerConfig]) {
        if let Some(pool) = self.hub.warm.get() {
            pool.set_release_policies(servers);
        }
    }

    /// How long since a download last ran, or `None` while one is
    /// running. The clock the background samplers check before deciding
    /// whether to hold a session open across their sleep.
    #[cfg(feature = "indexer")]
    pub fn download_idle_for(&self) -> Option<std::time::Duration> {
        if self.started_at.lock_ok().is_some() {
            return None;
        }
        Some(self.last_download_end.lock_ok().elapsed())
    }

    /// Should a background sampler keep its connection to THIS server
    /// open across ticks, or close it and reconnect on the next one?
    ///
    /// The samplers - the M29 availability oracle and the tip watcher -
    /// each hold one session per server for as long as the indexer is
    /// on, whether or not that server opted into warm pooling. That is a
    /// permanently occupied slot for work that uses the socket for a
    /// fraction of a second per tick, and against a provider limiting
    /// source addresses it is the whole account. Once the daemon has
    /// been download-idle past that server's release timeout they borrow
    /// a slot per tick instead of owning one: the traffic is unchanged,
    /// the occupancy drops to the length of the probe.
    ///
    /// Per server, like everything else here: a strict provider's
    /// timeout must not make the samplers churn reconnects against a lax
    /// one that never had a problem.
    ///
    /// Holding is still right while a download runs, when the account is
    /// in use by this host anyway and the reconnects would be pure cost.
    #[cfg(feature = "indexer")]
    pub fn sampler_may_hold(&self, server: &nzbkit::config::ServerConfig) -> bool {
        let Some(after) = server.idle_release_policy().after else {
            return true;
        };
        self.download_idle_for().is_none_or(|idle| idle < after)
    }

    /// All-core CPU% (0-100) from the process cpu-time delta since the
    /// previous call. One getrusage/task_info per call, no sampling
    /// thread; sub-500 ms re-polls (a second open dashboard, or the
    /// stats poll landing beside the whyslow ticker) reuse the last
    /// reading instead of amplifying noise. Shared sample state - both
    /// consumers reading through here is what keeps them agreeing.
    pub(super) fn cpu_pct(&self) -> f64 {
        let now = Instant::now();
        let cpu = nzbkit::mem::cpu_time_secs().unwrap_or(0.0);
        let ncpu = std::thread::available_parallelism().map_or(1, |n| n.get()) as f64;
        let mut prev = self.cpu_sample.lock_ok();
        match *prev {
            Some((t0, _, last)) if now.duration_since(t0).as_secs_f64() < 0.5 => last,
            Some((t0, c0, _)) => {
                let wall = now.duration_since(t0).as_secs_f64();
                let pct = ((cpu - c0) / wall / ncpu * 100.0).clamp(0.0, 100.0);
                *prev = Some((now, cpu, pct));
                pct
            }
            None => {
                *prev = Some((now, cpu, 0.0));
                0.0
            }
        }
    }

    /// Live download speed (bytes/sec) over a ~5 s rolling window of
    /// decoded-byte samples (also feeds queue_json's kbpersec).
    pub(super) fn current_speed_bps(&self) -> f64 {
        let done = self.progress.load(Ordering::Relaxed);
        let active = self.started_at.lock_ok().is_some();
        let mut win = self.speed_win.lock_ok();
        if !active {
            win.clear();
            return 0.0;
        }
        let now = Instant::now();
        if win.back().is_some_and(|&(_, b)| done < b) {
            win.clear();
        }
        win.push_back((now, done));
        while win
            .front()
            .is_some_and(|&(t, _)| now.duration_since(t).as_secs_f64() > 5.0)
        {
            win.pop_front();
        }
        // Drop the leading no-progress samples: at download start the
        // window otherwise spans the TLS/connect handshakes, and the
        // first shown figures are bytes divided by dead time - a rate
        // that climbs to the truth over five seconds and reads as a slow
        // ramp-up the line never had. Measured from the first byte that
        // moved, the first figure is the real one. Steady state is
        // untouched: consecutive one-second samples always differ while
        // bytes flow.
        while win.len() >= 2 && win[0].1 == win[1].1 {
            win.pop_front();
        }
        match (win.front(), win.back()) {
            (Some(&(t0, b0)), Some(&(t1, b1))) if t1.duration_since(t0).as_secs_f64() > 0.25 => {
                (b1 - b0) as f64 / t1.duration_since(t0).as_secs_f64()
            }
            _ => 0.0,
        }
    }

    /// Lifetime bytes billed to `host` (block-account accounting).
    pub(super) fn usage_lifetime(&self, host: &str) -> u64 {
        self.usage
            .lock_ok()
            .get("lifetime")
            .and_then(|v| v.get(host))
            .and_then(Value::as_u64)
            .unwrap_or(0)
    }

    /// Next runnable job: highest priority first, FIFO within a priority.
    /// Per-job pause always holds a job back; a Force (2) job also runs
    /// while the whole queue is paused.
    pub(super) fn pick_job(&self, queue_paused: bool) -> Option<Arc<Mutex<Job>>> {
        let q = self.queue.lock_ok();
        // TODO §77: does a red pre-flight verdict sink a job? Off by
        // default, and it only ever REORDERS - a sunk job is still in
        // the queue, still startable, and runs the moment nothing
        // healthier is available.
        let health_defer = self.post_health_defer.load(Ordering::Relaxed);
        // Key: (not deferred, priority, not health-sunk) - a
        // watchdog-deferred (slow) job only runs when NO other job is
        // runnable, whatever its priority was. Ties keep queue order
        // (strict > with first-wins).
        let mut best: Option<((bool, i32, bool), Arc<Mutex<Job>>)> = None;
        for j in q.iter() {
            let g = j.lock_ok();
            // A tombstoned job is deleted; nothing may start it again. The
            // delete paths remove it from the queue themselves, so this is
            // the defensive invariant behind them rather than the mechanism -
            // it is what stops a job whose payload and spooled .nzb have
            // already been unlinked from running one more time.
            if g.paused || g.tombstone || g.state != JobState::Queued {
                continue;
            }
            if queue_paused && g.priority < 2 {
                continue;
            }
            // The health sink sits BELOW priority in the key on purpose,
            // where the watchdog's defer sits above it. The watchdog has
            // measured this job going slowly on this line; pre-flight has
            // asked eight articles a question that propagation can
            // answer wrongly, so an advisory guess must never overrule
            // what the user explicitly asked for. Forced jobs (priority
            // 2, which is also what "start this next" sets) are exempt
            // outright.
            let sunk =
                health_defer && g.priority < 2 && g.health.as_ref().is_some_and(|h| h.sinks());
            let key = (!g.deferred, g.priority, !sunk);
            if best.as_ref().is_none_or(|(bk, _)| key > *bk) {
                best = Some((key, j.clone()));
            }
        }
        best.map(|(_, j)| j)
    }

    /// Everything a finished job owes the outside world: the
    /// post-processing script, then the notification targets. One entry
    /// point because a job ends in three different places (runner tail,
    /// idle-server sidecar, library metadata-only pick) and each of them
    /// used to grow its own copy of the script call.
    ///
    /// Order matters: the script may still be moving or renaming files,
    /// and a library scan that runs first indexes the state before it.
    /// Both go on the blocking pool, together, so a slow script delays
    /// the scan rather than the queue.
    /// §129 2b: which script this job runs, if any. Resolution order:
    /// the job's own `script=` param ("None" = explicitly none), the
    /// category's script, the global setting.
    /// §129 2b follow-up: every script this daemon can actually run for
    /// a job - the global setting plus each category's own - keyed by
    /// the BASENAME clients name them by. `mode=get_scripts` serves
    /// these names, and `script=` on an add sends one back, so the two
    /// must resolve through one list or the round trip breaks (it did:
    /// the name came back and was run as a cwd-relative path). First
    /// entry wins a basename tie, global first.
    pub(super) fn known_scripts(&self) -> Vec<(String, PathBuf)> {
        let mut out: Vec<(String, PathBuf)> = Vec::new();
        let mut push = |p: &std::path::Path| {
            if let Some(name) = p.file_name().map(|s| s.to_string_lossy().into_owned())
                && !out.iter().any(|(n, _)| *n == name)
            {
                out.push((name, p.to_path_buf()));
            }
        };
        if let Some(g) = self.script.lock_ok().as_deref() {
            push(g);
        }
        for m in self.cat_meta.lock_ok().values() {
            let s = m.script.trim();
            if !s.is_empty() {
                push(std::path::Path::new(s));
            }
        }
        out
    }

    pub(super) fn resolve_script(&self, job: &Arc<Mutex<Job>>) -> Option<PathBuf> {
        let (over, cat) = {
            let g = job.lock_ok();
            (g.script_override.clone(), g.category.clone())
        };
        if over.eq_ignore_ascii_case("none") {
            return None;
        }
        if !over.is_empty() {
            return Some(PathBuf::from(over));
        }
        let cs = self
            .cat_meta
            .lock_ok()
            .get(&cat)
            .map(|m| m.script.clone())
            .unwrap_or_default();
        if !cs.is_empty() {
            return Some(PathBuf::from(cs));
        }
        self.script.lock_ok().clone()
    }

    /// §129 2b: record the SAB add params the API used to accept and
    /// silently drop (`pp=`, `script=`), and log the compatibility
    /// mapping for the ones one-pass cannot honor literally - never
    /// silently ignore (decision 5).
    ///
    /// `add_only` is true when the request authenticated with the
    /// add-only NZB key rather than the full API key. That credential is
    /// handed to browser push extensions by design, so it must not be
    /// able to choose which program the daemon runs.
    pub(super) fn record_add_params(
        &self,
        nzo_id: &str,
        pp: Option<&str>,
        script: Option<&str>,
        add_only: bool,
    ) {
        let pp = pp
            .and_then(|p| p.trim().parse::<i64>().ok())
            .filter(|p| (0..=3).contains(p));
        let script = script
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            // A bare name is what SAB clients send back from
            // mode=get_scripts, so it must resolve against the same
            // list that answer came from - stored verbatim it became a
            // cwd-relative path that ran nothing. A value with a path
            // separator is an operator-typed location and stays as
            // written; "none" is SAB's own null and suppresses the
            // category/global ladder in resolve_script.
            .and_then(|s| {
                if s.eq_ignore_ascii_case("none") {
                    return Some(s);
                }
                if s.contains('/') || s.contains('\\') {
                    // An operator-typed absolute location, stored as
                    // written - but ONLY for a full-key caller.
                    // `addfile`/`addurl` are on the add-only allowlist,
                    // so without this test the NZB key reached
                    // `Command::new`: `resolve_script` returns
                    // `script_override` verbatim and the job tail
                    // executes it. That is the same escalation
                    // `m_config`'s bootstrap check already refuses ("an
                    // add-only credential escalating to arbitrary
                    // config, and from there to code execution, because
                    // `script` is run on the job tail and `addfile` is
                    // itself add-only") - this was the door left open
                    // beside it. The bare-name form below is safe for
                    // either caller: it resolves against the configured
                    // list and cannot name anything the operator has not
                    // already installed.
                    if add_only {
                        warn!(
                            target: "queue",
                            "{nzo_id}: ignoring script={s:?} - a path may only be \
                             set with the full API key, and this add came in on \
                             the add-only NZB key (name a configured script \
                             instead, or set it on the category)"
                        );
                        return None;
                    }
                    return Some(s);
                }
                match self.known_scripts().into_iter().find(|(n, _)| *n == s) {
                    Some((_, p)) => Some(p.to_string_lossy().into_owned()),
                    None => {
                        warn!(
                            target: "queue",
                            "{nzo_id}: script {s:?} is not configured on this \
                             daemon - the job runs with its category/global \
                             script instead (set the script globally or on \
                             the category to use it)"
                        );
                        None
                    }
                }
            });
        if pp.is_none() && script.is_none() {
            return;
        }
        let Some(job) = self
            .queue
            .lock_ok()
            .iter()
            .find(|j| j.lock_ok().nzo_id == nzo_id)
            .cloned()
        else {
            return;
        };
        {
            let mut g = job.lock_ok();
            if let Some(p) = pp {
                g.sab_pp = Some(p);
                if p <= 1 {
                    info!(
                        target: "queue",
                        "{nzo_id}: pp={p} requested - repair and unpack are integral \
                         to the one-pass download, so the request is recorded and \
                         shown on the job, and the download runs normally"
                    );
                }
            }
            if let Some(s) = script {
                g.script_override = s.clone();
                info!(target: "queue", "{nzo_id}: script={s} for this job");
            }
        }
        self.save_queue();
    }

    /// §129 2e: fire the notification targets routed onto a warning
    /// event ("disk", "quota"). Cheap no-op unless a target actually
    /// asked for the token; the send goes to the blocking pool - the
    /// callers sit in the download runner.
    pub(super) fn notify_event(self: &Arc<Self>, event: &'static str, message: &str) {
        let targets = self.notify_targets.lock_ok().clone();
        if !targets
            .iter()
            .any(|t| t.enabled && t.events.iter().any(|e| e == event))
        {
            return;
        }
        let cx = crate::notify::Ctx::for_event(event, message);
        let d = self.clone();
        tokio::task::spawn_blocking(move || {
            let out = crate::notify::fire(&targets, &cx, unix_now());
            let mut health = d.notify_health.lock_ok();
            for (k, o) in out {
                health.insert(k, o);
            }
        });
    }

    pub(super) fn run_post_job_hooks(self: &Arc<Self>, job: &Arc<Mutex<Job>>) {
        let script = self.resolve_script(job);
        let targets = self.notify_targets.lock_ok().clone();
        let mode = self.failure_link.lock_ok().clone();
        let secs = self.auto_retry_secs.load(Ordering::Relaxed);
        let Some(failing) = post_job_plan(&job.lock_ok(), &mode, secs) else {
            return;
        };
        if script.is_none() && targets.is_empty() && !failing {
            return;
        }
        let d = self.clone();
        let job = job.clone();
        tokio::task::spawn_blocking(move || {
            if let Some(script) = script {
                d.run_script(&script, &job);
            }
            if !targets.is_empty() {
                // §G: keep what each delivery did, so the settings row
                // can say "last send failed: HTTP 401". The map is keyed
                // by kind+url+name and only ever grows to the number of
                // targets the user has configured.
                let out =
                    crate::notify::fire(&targets, &crate::notify::Ctx::from_job(&job), unix_now());
                let mut health = d.notify_health.lock_ok();
                for (k, o) in out {
                    health.insert(k, o);
                }
            }
            // Last: a webhook that reports failures should say so before
            // a replacement for the same title appears in the queue.
            if failing {
                d.report_failure(&job);
            }
        });
    }

    /// Will [`park`](Daemon::park) arm an M32 automatic retry for this
    /// job? See [`auto_retry_eligible`], which both this and the hook
    /// planner share so they cannot drift (they already did once - see
    /// [`fail_kind`]).
    pub(super) fn will_auto_retry(&self, job: &Arc<Mutex<Job>>) -> bool {
        let secs = self.auto_retry_secs.load(Ordering::Relaxed);
        auto_retry_eligible(&job.lock_ok(), secs)
    }

    /// Tell the indexer this download failed, and queue the replacement
    /// it offers - NZBGet's FailureLink, natively.
    ///
    /// An indexer that sends `X-DNZB-Failure` is offering two things at
    /// one URL: a failure report (which is how it learns a post is dead,
    /// and how the next person is spared it) and, in the response body,
    /// another NZB for the same title. `failure_link` chooses how far to
    /// go: "report" sends the report and stops, "regrab" also queues what
    /// comes back. Off by default - it tells a third party what failed
    /// for you, which is a reasonable thing to want and not a reasonable
    /// default.
    ///
    /// A 404, an empty body, or anything that isn't XML means the
    /// indexer has nothing else, which is the ordinary outcome and not an
    /// error. Blocking: call from the blocking pool.
    pub(super) fn report_failure(&self, job: &Arc<Mutex<Job>>) {
        let mode = self.failure_link.lock_ok().clone();
        if mode == "off" {
            return;
        }
        let (link, depth, name, cat, priority, password) = {
            let j = job.lock_ok();
            // A job the user DELETED owes the outside world nothing, and
            // least of all a dead-post report for a post that is not dead.
            if j.state != JobState::Failed || j.tombstone || j.failure_link.is_empty() {
                return;
            }
            // Only a post-unavailability failure is news the indexer can
            // act on. A full disk, a permission error or an unpack that
            // fell over says nothing about the post - reporting it marks
            // a healthy release dead for every other user of that indexer
            // and, under `regrab`, spends bandwidth replacing it.
            if !fail_kind(&j.fail_message).post_unavailable() {
                info!(
                    target: "failurelink",
                    "{}: not reported - {} is a local fault, not a dead post",
                    j.name, j.fail_message
                );
                return;
            }
            if !failure_link_allowed(&j.failure_link, &j.failure_host, j.failure_https) {
                warn!(
                    target: "failurelink",
                    "{}: refusing {} - it does not point back at {} (the indexer that supplied it)",
                    j.name,
                    // The X-DNZB-Failure endpoint is the indexer's own URL and
                    // carries its key - and this line fires exactly on a host
                    // mismatch, which in practice is an indexer serving the
                    // link from a CDN alias with ?apikey= attached. stdout is
                    // not private (logtee mirrors it into mode=log, the
                    // JSON-RPC log methods and `docker logs`), so redact here
                    // like the accept path below already does.
                    redact_url_creds(&j.failure_link),
                    if j.failure_host.is_empty() {
                        "the origin"
                    } else {
                        &j.failure_host
                    }
                );
                return;
            }
            let (cat, priority, password) = replacement_inherits(&j);
            (
                j.failure_link.clone(),
                j.failure_depth,
                j.name.clone(),
                cat,
                priority,
                password,
            )
        };
        let regrab = may_regrab(&mode, depth);
        if mode == "regrab" && !regrab {
            info!(target: "failurelink", "{name}: {depth} replacements already tried - reporting only");
        }
        // In `report` mode the report IS the GET: nothing reads the
        // response, a 404 counts as success, and there is no reason to
        // pull a body down (let alone a large one) only to drop it.
        let fetched = match if regrab {
            fetch_url(&link).map(Some)
        } else {
            ping_url(&link)
        } {
            Ok(f) => f,
            // 404 is the indexer saying "nothing else for that title".
            Err(e) => {
                let s = e.to_string();
                if s.contains("404") {
                    info!(target: "failurelink", "{name}: reported, no other release available");
                } else {
                    // Same reason as the watch leg above: the X-DNZB-Failure
                    // endpoint is the indexer's own URL and carries the key.
                    warn!(target: "failurelink", "{name}: {}", redact_url_creds(&s));
                }
                return;
            }
        };
        let Some(fetched) = fetched else {
            info!(target: "failurelink", "{name}: failure reported to the indexer");
            return;
        };
        if !is_nzb_body(&fetched.bytes) {
            info!(target: "failurelink", "{name}: reported, no other release available");
            return;
        }
        // Our category, always: it selects the output subfolder, the
        // library flag and the move-completed destination, so taking the
        // one out of the (untrusted) response would let the indexer pick
        // which of the user's destinations the payload lands in.
        match self.enqueue_fetched(
            &fetched,
            &format!("{name}.nzb"),
            &cat,
            priority,
            password.as_deref(),
            depth + 1,
            // A failure-link replacement inherits nothing useful from the
            // failed job, but "we picked this for you" is worth saying.
            "failure-link",
            false,
        ) {
            Ok(id) => info!(target: "failurelink", "{name}: queued a replacement ({id})"),
            Err(e) => warn!(target: "failurelink", "{name}: replacement was not usable: {e}"),
        }
    }

    /// M14d: post-processing hook with SABnzbd's contract - the 8
    /// positional args and SAB_* env vars that the existing script
    /// ecosystem (notifiers, sorters, library refreshers) expects.
    pub(super) fn run_script(&self, script: &std::path::Path, job: &Arc<Mutex<Job>>) {
        let (out_dir, name, cat, status, fail_msg, nzo_id, bytes, failure_link) = {
            let j = job.lock_ok();
            (
                j.out_dir.clone(),
                j.name.clone(),
                j.category.clone(),
                // SAB pp-status: 0 = OK, 1 = failed verification.
                if j.state == JobState::Completed {
                    "0"
                } else {
                    "1"
                },
                j.fail_message.clone(),
                j.nzo_id.clone(),
                j.total_bytes,
                j.failure_link.clone(),
            )
        };
        let mut cmd = std::process::Command::new(script);
        cmd.arg(&out_dir) // 1 final dir
            .arg(format!("{name}.nzb")) // 2 original nzb name
            .arg(&name) // 3 clean job name
            .arg("") // 4 indexer report number
            .arg(if cat.is_empty() { "*" } else { &cat }) // 5 category
            .arg("") // 6 group
            .arg(status) // 7 pp status
            // 8 failure URL. We have carried the X-DNZB failure link on
            // the job since the FailureLink work and were passing an
            // empty string here, so a SAB script that does its own dead-
            // post reporting had nothing to report to.
            .arg(&failure_link)
            .env("SAB_COMPLETE_DIR", &out_dir)
            .env("SAB_FINAL_NAME", &name)
            .env("SAB_FILENAME", format!("{name}.nzb"))
            .env("SAB_CAT", if cat.is_empty() { "*" } else { &cat })
            .env("SAB_PP_STATUS", status)
            .env(
                "SAB_STATUS",
                if status == "0" { "Completed" } else { "Failed" },
            )
            .env("SAB_FAIL_MSG", &fail_msg)
            .env("SAB_NZO_ID", &nzo_id)
            .env("SAB_BYTES", bytes.to_string())
            .env("SAB_URL", &failure_link)
            .env("SAB_VERSION", SAB_VERSION);
        let secs = self.script_timeout.load(Ordering::Relaxed);
        match run_capped(cmd, secs) {
            Ok((Some(st), _)) if st.success() => {
                info!(target: "script", "{} ok for {nzo_id}", script.display());
            }
            Ok((Some(st), stderr)) => {
                warn!(
                    target: "script",
                    "{} exited {st} for {nzo_id}: {}",
                    script.display(),
                    stderr.trim()
                );
            }
            // No exit status = we killed it at the deadline.
            Ok((None, _)) => warn!(
                target: "script",
                "{} still running after {secs}s for {nzo_id} - killed. \
                 Raise or clear script_timeout_secs if it needs longer.",
                script.display()
            ),
            Err(e) => warn!(target: "script", "{} failed to launch: {e}", script.display()),
        }
    }

    /// Abort of the prefetch sidecar when a user op removes or pauses the
    /// job it holds (sync handler contexts - the task winds down on its
    /// own; the runner's stop_sidecar await covers pipeline handover).
    ///
    /// Fires inline and then RE-FIRES until the sidecar is actually gone,
    /// for the same reason suspend_matching does: `get_with_progress`
    /// installs the hub's abort and queue-ctl handles asynchronously after
    /// launch, so a single signal that lands in the gap finds both slots
    /// empty and no-ops. `cancelled` is not a safety net there either - the
    /// task reads it once, before the transfer starts, and is then parked
    /// inside the pipeline with nothing left to re-check it.
    ///
    /// That gap was reachable and it lost data-plane work: deleting a job
    /// mid-prefetch removed it from the queue and kept it out of history
    /// (both correct) while the transfer ran to completion, spending
    /// provider quota on a job the user had explicitly deleted and leaving
    /// the finished files in the output directory. Caught by
    /// `jsonrpc_delete_stops_a_prefetching_job`, which failed on
    /// "the delete did not stop the prefetch" roughly 1 run in 40 in
    /// release - the whole reason that assertion exists.
    pub(super) fn poke_sidecar(self: &Arc<Self>, hit: impl Fn(&str) -> bool) {
        // Inline first, so the transfer is already stopping by the time the
        // delete/pause API call returns.
        let Some(id) = self.fire_sidecar_abort(&hit) else {
            return;
        };
        let d = self.clone();
        std::thread::spawn(move || {
            // Bounded like the pause re-fire: 60 s is far longer than the
            // handles take to attach, and the loop exits the moment the
            // sidecar slot is empty or holds a different job.
            for _ in 0..240 {
                std::thread::sleep(std::time::Duration::from_millis(250));
                if d.fire_sidecar_abort(&|s: &str| s == id).is_none() {
                    return;
                }
            }
        });
    }

    /// One abort signal at the current sidecar, if `hit` accepts it.
    /// Returns the nzo_id it fired at, or None when there is nothing to
    /// fire at - which is how the re-fire loop above knows to stop.
    fn fire_sidecar_abort(&self, hit: &impl Fn(&str) -> bool) -> Option<String> {
        let sc = self.sidecar.lock_ok();
        let sc = sc.as_ref().filter(|s| hit(&s.nzo_id))?;
        sc.cancelled.store(true, Ordering::Relaxed);
        if let Some(f) = sc.hub.abort.lock_ok().as_ref() {
            f.store(true, Ordering::Relaxed);
        }
        if let Some(c) = sc.hub.queue_ctl.lock_ok().as_ref() {
            c.abort();
        }
        Some(sc.nzo_id.clone())
    }

    /// Record a delete that removed the RECORD but not the FILES, for the
    /// dashboard's kept-files notice.
    ///
    /// Every delete-with-files path ends here on a [`FilesGone::Kept`],
    /// and the reason is the same one each time: the user asked for
    /// recoverable deletes, no Trash would take the path, and we now
    /// leave the download alone rather than destroying it (70990f19).
    /// That was the right call and it opened this hole - the queue row or
    /// history row goes regardless, so the only handle the user had on a
    /// folder that is still sitting there is the thing the delete removed,
    /// and a `warn!` in a log they will never open is not telling them.
    ///
    /// The path is the replacement handle, which is why it is stored
    /// rather than the id: they cannot open a record that no longer
    /// exists, but they can go and look at the folder.
    pub(super) fn note_delete_kept(&self, name: &str, path: &std::path::Path, why: &str) {
        {
            let mut k = self.delete_kept.lock_ok();
            let path = path.display().to_string();
            // One entry per path. A bulk history sweep over a shared season
            // folder refuses once per record, and a dozen identical rows
            // would bury the one thing the notice has to say.
            if k.iter().any(|(_, p, _, _)| *p == path) {
                return;
            }
            k.push_back((name.to_string(), path, why.to_string(), unix_now()));
            while k.len() > 12 {
                k.pop_front();
            }
        }
        self.save_delete_kept();
    }

    /// Persist the kept-files notices to `.spool/delete-kept.json`.
    ///
    /// This ring is not a moment that scrolls past like the ones beside
    /// it - it is the REPLACEMENT handle on a folder whose history row
    /// was just deleted, and it stays on screen until dismissed. Held
    /// only in memory it did not survive a restart, which includes the
    /// auto-updater's own restart and `restart_daemon` from the settings
    /// UI: the row was already gone, so the user was left with the exact
    /// state the notice exists to prevent - a folder still eating disk,
    /// named by nothing anywhere. The deferred `park()` refusal has no
    /// response to ride back on at all, so for that path this is the
    /// only channel there is.
    pub(super) fn save_delete_kept(&self) {
        let path = self.spool.join("delete-kept.json");
        // The lock is held ACROSS the write, not just around a snapshot.
        // Snapshotting and then writing lets two writers land in the
        // opposite order to the states they carry: a refusal snapshots
        // [X, Y] and is preempted, the user dismisses X and its write of
        // [Y] completes, then the first write lands [X, Y] - and the next
        // restart resurrects the notice the user just cleared, which is
        // the one thing persisting the dismissal exists to prevent.
        // Safe to hold: `write_atomic` takes no other lock of ours, and
        // this mutex is a leaf (never acquired while queue/history are
        // held - both delete arms record after dropping them).
        let kept = self.delete_kept.lock_ok();
        if let Ok(text) = serde_json::to_string_pretty(&*kept) {
            let _ = crate::persist::write_atomic(&path, text.as_bytes());
        }
    }

    /// Park a finished job in history (NZBGet-style: failures are parked,
    /// not lost - mode=retry sends them back through the queue and the
    /// journal resumes from what already landed).
    pub(super) fn park(&self, job: Arc<Mutex<Job>>) {
        let (id, failed, key, demote) = {
            let g = job.lock_ok();
            (
                g.nzo_id.clone(),
                g.state == JobState::Failed,
                g.dupe_key.clone(),
                g.demote,
            )
        };
        // The active-download delete deferred its file removal to here: by
        // now the fetch has drained and no writer can recreate the dir. A
        // tombstoned job is dropped (not filed to history), so its spooled
        // .nzb is dead weight too - remove it (history retry keeps its own).
        {
            let g = job.lock_ok();
            if g.del_on_drop {
                let tail = delete_tail(&g, || self.job_suffix(filed_stem(&g)));
                // The user pressed delete-with-files on a LIVE download
                // and this is where it finally happens, long after the
                // request answered - so a refusal here has no response
                // left to ride back on, and the notice is the only way it
                // reaches them at all.
                if let FilesGone::Kept(why) =
                    remove_job_files(&g.out_dir, filed_stem(&g), g.filed, &tail)
                {
                    self.note_delete_kept(filed_stem(&g), &g.out_dir, &why);
                }
                // The other end of the reservation the delete took when
                // it set this flag: the directory is only safe to hand
                // out once its files are actually gone.
                self.reserved.lock_ok().remove(&g.out_dir);
            }
            if g.tombstone {
                let _ = std::fs::remove_file(&g.nzb_path);
            }
        }
        self.queue.lock_ok().retain(|j| j.lock_ok().nzo_id != id);
        // The job's queue-row activity dies with the row.
        self.hub.activity.lock_ok().remove(&id);
        // §129: so does its recovery-fetch cancel handle. Same key, same
        // place, same reason - the tail is over, and neither map may
        // outgrow the queue.
        self.hub.tail_cancel.lock_ok().remove(&id);
        // Read LIVE, not from the snapshot above: everything between the two
        // is unlocked, and file removal is slow. A queue or JSON-RPC delete
        // landing in that window used to be decided against a stale
        // `tombstone == false`, so the deleted job was requeued (demote arm),
        // filed into history, or had an alternative promoted for a cancel the
        // user had just made. Every terminal branch below re-reads it.
        let tombstone = job.lock_ok().tombstone;
        // Watchdog demotion: back into the queue (deferred, at the end)
        // instead of history - the abort was ours, not a failure. The
        // journal keeps everything already landed, so the eventual rerun
        // fetches only what's still missing.
        // `!tombstone`: a deleted job stays deleted. Both flags together is
        // an ordinary race - the slow-job watchdog demotes at T, the user (or
        // an *arr) deletes at T+ε - and the demote arm used to win, pushing
        // the just-deleted job back onto the queue with its payload removed
        // and its spooled .nzb already unlinked above. It then reappeared in
        // the *arr, ran, and failed.
        // `failed`: the demotion only counts if its abort actually took the
        // download down. The watchdog's abort can lose the race with the
        // finish line - it once fired at a job whose network had already
        // drained (see the runner's stand-down at net-drain) - and a stale
        // flag on a job that went on to COMPLETE must not send it back
        // through the queue: post-processing has renamed its directory by
        // now, so the "rerun" was a full second download of a finished
        // release into the renamed folder (the 31 Jul queue soak).
        if demote_requeues(demote, tombstone, failed) {
            {
                let mut g = job.lock_ok();
                g.state = JobState::Queued;
                g.fail_message.clear();
                // The evidence goes with the verdict it explained - a
                // re-queued job that fails again captures its own.
                g.fail_detail.clear();
                g.finished_at = None;
                g.finished_unix = None;
                g.demote = false;
                g.deferred = true;
                g.defer_count += 1;
            }
            self.queue.lock_ok().push_back(job);
            self.save_queue();
            return;
        }
        if demote {
            // The flag outlived a download that finished anyway (or a
            // tombstone). Scrub it before the record reaches history, or a
            // later retry of this job carries it back here and the arm
            // above requeues that retry's park unconditionally.
            job.lock_ok().demote = false;
        }
        // M32: a FIRST failure with missing articles gets ONE
        // automatic retry after a cooldown - propagation lag is a real
        // cause of missing articles that clears on its own, and the
        // journal makes the rerun fetch only what's still missing. Only
        // transient shapes qualify: password and takedown verdicts don't.
        //
        // The predicate itself is `will_auto_retry`, shared with
        // `run_post_job_hooks` so the report/re-grab side and the
        // duplicate promotion below agree with what actually happens here.
        let armed_auto_retry = self.will_auto_retry(&job);
        if armed_auto_retry {
            let secs = self.auto_retry_secs.load(Ordering::Relaxed);
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            // What we are waiting FOR decides both the delay and what
            // to call it. Propagation filling in missing articles takes
            // real time; a pool that stalled on this machine has nothing
            // to wait for at all, and the old copy told the user to sit
            // out 20 minutes for a propagation that was never the
            // problem.
            let kind = fail_kind(&job.lock_ok().fail_message);
            let (secs, why, token) = match kind {
                FailKind::Transport => (
                    secs.min(SHORT_RETRY_SECS),
                    "connection trouble, not missing articles - retrying shortly",
                    RETRY_WHY_TRANSPORT,
                ),
                _ => (
                    secs,
                    "articles missing - propagation may fill them",
                    RETRY_WHY_PROPAGATION,
                ),
            };
            {
                let mut g = job.lock_ok();
                g.auto_retry_at = Some(now + secs);
                // Beside the stamp, because the delay above was chosen
                // from it: the drawer says "2 minutes, because this was
                // the link and not the post" in the user's own language,
                // which needs the reason as a token and not as this
                // English log line.
                g.auto_retry_why = Some(token.to_string());
            }
            info!(
                target: "retry",
                "{id}: {why}; automatic retry in {} min \
                 (resumes from the journal; only the gaps will be refetched)",
                secs.div_ceil(60)
            );
        }
        // Re-read once more: the demote arm above returns, so this is the
        // first point the history/promotion decisions are actually taken.
        let tombstone = job.lock_ok().tombstone;
        // §96.3: feed the per-target give-up breaker. Here because this
        // is where a failure becomes FINAL - a tombstone owes nobody
        // anything and an armed auto-retry means the story continues.
        if !tombstone {
            self.giveup_note_outcome(&job, armed_auto_retry);
        }
        if !tombstone {
            // C: hand the owed move over only once the record is IN
            // history - the mover looks the job up there, and it runs
            // on its own worker so this park (and the runner tail
            // behind it) never waits on a NAS copy.
            let owes_move = job.lock_ok().move_pending;
            self.history.lock_ok().push(job.clone());
            // §129 1a/1b: the record reaches its own store the moment it
            // reaches history, and the lifecycle event replaces the
            // dashboard's snapshot-diff toast inference. Then retention,
            // which is a no-op unless the optional knobs are set.
            let _ = self.history_upsert(std::slice::from_ref(&job));
            self.life_emit_parked(&job);
            self.history_enforce_retention();
            if owes_move {
                self.mover_enqueue(&job);
            }
        }
        // The original failed → promote its best held ALTERNATIVE (M14f).
        // Not while an automatic retry is armed: the original is coming
        // back through the queue in minutes, and starting the alternative
        // now downloads the same title twice. And not for a tombstone: the
        // "failure" there is the abort the user's own delete fired, so
        // promoting would start downloading the very title they cancelled.
        if failed
            && !tombstone
            && !armed_auto_retry
            && let Some(key) = key
        {
            // BEST, not first. Breaking at the first match promoted
            // whichever alternative happened to be added earliest, so
            // a 720p held before a 2160p won and the 2160p stayed
            // parked for good - the user ended up with the worst copy
            // of the three while two better ones sat in the queue.
            // Rank them the way the watchlist ranks candidates, so
            // "best" means the same thing in both places.
            let q = self.queue.lock_ok();
            let mut best: Option<(u32, usize)> = None;
            for (i, j) in q.iter().enumerate() {
                let g = j.lock_ok();
                if g.priority == -3 && g.dupe_key.as_ref() == Some(&key) && g.paused {
                    let rank = crate::watchlist::quality_rank(&crate::wall::parse_release(&g.name));
                    // Ties keep the earlier-added one, which is the
                    // old behaviour and is as good a tiebreak as any.
                    if best.is_none_or(|(r, _)| rank > r) {
                        best = Some((rank, i));
                    }
                }
            }
            if let Some((rank, i)) = best {
                let mut g = q[i].lock_ok();
                g.paused = false;
                g.priority = 0;
                info!(
                    target: "queue",
                    "{} promoted (best held duplicate of failed {id}, rank {rank})",
                    g.nzo_id
                );
            }
        }
        self.save_queue();
    }

    /// §96.3: one terminal job outcome, seen by the give-up breaker.
    ///
    /// Only the two automated grab loops count - a job the user added by
    /// hand failing says nothing an automation should act on. A
    /// completed download clears its target's counters (the content was
    /// obtainable); a FINAL failure records the release stem, and at the
    /// threshold the target is given up: logged for both paths, and for
    /// an *arr-originated job the configured instances are asked to
    /// unmonitor-then-blocklist (in that order - see the giveup module
    /// note). Caller has already excluded tombstones and holds no locks.
    pub(super) fn giveup_note_outcome(&self, job: &Arc<Mutex<Job>>, armed_auto_retry: bool) {
        let threshold = self.arr_giveup_threshold.load(Ordering::Relaxed);
        if threshold == 0 {
            return;
        }
        let (name, nzo_id, origin, state) = {
            let g = job.lock_ok();
            (g.name.clone(), g.nzo_id.clone(), g.origin.clone(), g.state)
        };
        let from_arr = origin == "arr" || origin.starts_with("arr:");
        if !from_arr && origin != "watchlist" {
            return;
        }
        let p = crate::wall::parse_release(&name);
        let keys = super::giveup::target_keys(&p);
        if keys.is_empty() {
            return;
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        // `token` names the incarnation of each target this decision was
        // made about, snapshotted under the same lock as the latch. The
        // spawned worker below carries it and re-checks it before every
        // destructive *arr call, so a "Try again" pressed while Sonarr
        // is slow cannot be undone by work that was already in flight
        // (Codex sweep 2, 3 Aug M3).
        let (fire, dirty, token) = {
            let mut st = self.giveup.lock_ok();
            match state {
                JobState::Completed => (false, st.record_success(&keys), Vec::new()),
                JobState::Failed if !armed_auto_retry => {
                    let count = st.record_failure(&keys, &name, now);
                    // The latch makes one storm one action (and one log
                    // line); a later success re-arms it.
                    let fire = count >= threshold as usize && st.latch_action(&keys);
                    let token = if fire {
                        st.action_token(&keys)
                    } else {
                        Vec::new()
                    };
                    (fire, true, token)
                }
                _ => return, // not terminal for the breaker's purposes
            }
        };
        if dirty {
            self.save_giveup();
        }
        if !fire {
            return;
        }
        warn!(
            target: "giveup",
            "{name}: {threshold} distinct releases have now failed for this \
             target - giving it up (the watchlist stops pursuing it{})",
            if from_arr { "; asking the *arr to unmonitor it" } else { "" }
        );
        // ...and say it somewhere a user actually looks. An open
        // dashboard toasts this on its next poll and the Watchlist card
        // lists it from `giveup_status` afterwards, so the moment a show
        // stops being chased is visible and reversible.
        {
            let mut ring = self.giveup_tripped.lock_ok();
            ring.push_back((name.clone(), threshold, now));
            while ring.len() > 8 {
                ring.pop_front();
            }
        }
        if !from_arr {
            return;
        }
        let instances: Vec<super::giveup::ArrInstance> = self
            .arr_instances
            .lock_ok()
            .iter()
            .filter(|i| i.enabled)
            .cloned()
            .collect();
        // A plain thread, not the tokio blocking pool: park runs on both
        // async and sync paths, and this fires a handful of times per
        // install lifetime. The latch was taken above; if no instance
        // proves ownership and acts, but at least one attempt FAILED
        // (offline *arr, bad apikey), the latch is released so the next
        // final failure of this target tries again - a logged error is
        // not an unmonitor, and leaving the latch set would suppress the
        // retry forever while the *arr keeps re-grabbing dead releases.
        let giveup = self.giveup.clone();
        let spool = self.spool.clone();
        std::thread::spawn(move || {
            let mut acted = false;
            let mut errored = false;
            let mut stood_down = false;
            // Re-read under the lock every time it is asked, so the
            // answer is about the target as it is NOW, not as it was
            // when the thread started.
            let still_wanted = {
                let giveup = giveup.clone();
                let token = token.clone();
                move || giveup.lock_ok().action_current(&token)
            };
            for inst in &instances {
                if !still_wanted() {
                    stood_down = true;
                    info!(
                        target: "giveup",
                        "{name}: the target was reset while this was in flight - \
                         standing down, nothing was changed in any *arr"
                    );
                    break;
                }
                match super::giveup::arr_give_up(inst, &nzo_id, &name, &still_wanted) {
                    Ok(Some(what)) => {
                        acted = true;
                        info!(target: "giveup", "{name}: {what}");
                    }
                    // The ordinary answer from every instance but the
                    // owner: no history record for our downloadId.
                    Ok(None) => {
                        info!(target: "giveup", "{name}: {}: not the sender, left alone", inst.name)
                    }
                    Err(e) => {
                        errored = true;
                        warn!(target: "giveup", "{name}: {}: {e}", inst.name);
                    }
                }
            }
            // A stand-down is not a failed call: the latch belongs to
            // whatever generation the target is on now, and re-arming
            // it here would undo the reset the user just performed.
            if !acted && errored && !stood_down {
                giveup.lock_ok().clear_action(&token);
                let path = spool.join("giveup-state.json");
                if let Ok(text) = serde_json::to_string_pretty(&*giveup.lock_ok()) {
                    let _ = crate::persist::write_atomic(&path, text.as_bytes());
                }
                info!(
                    target: "giveup",
                    "{name}: no *arr acted and at least one call failed - \
                     will retry at the next final failure"
                );
            }
        });
    }

    /// Persist the give-up counters (small, changes rarely - every
    /// terminal outcome of an automated grab at most).
    pub(super) fn save_giveup(&self) {
        let path = self.spool.join("giveup-state.json");
        if let Ok(text) = serde_json::to_string_pretty(&*self.giveup.lock_ok()) {
            let _ = crate::persist::write_atomic(&path, text.as_bytes());
        }
    }

    /// M23e: pause means PAUSE. Abort the active transfer (Force jobs
    /// are exempt, SAB semantics) after marking it suspended - the tail
    /// handler re-queues it instead of failing it, and the article
    /// journal makes the eventual resume fetch only what's still
    /// missing. Bytes already on disk are never re-downloaded.
    /// Benchmark history: one JSON array in .spool, appended by every
    /// sysbench run (manual or scheduled), capped at 400 entries.
    /// Current download root (live-swappable - see the `out_root` field).
    /// Cloned per call; callers were all one-shot (enqueue, stats), never
    /// hot loops.
    pub fn out_dir(&self) -> PathBuf {
        self.out_root.read_ok().clone()
    }

    /// Current auto-rename name style, read from the live toggles.
    pub(super) fn rename_style(&self) -> crate::wall::NameStyle {
        crate::wall::NameStyle {
            resolution: self.rename_resolution.load(Ordering::Relaxed),
            video_codec: self.rename_vcodec.load(Ordering::Relaxed),
            audio_codec: self.rename_acodec.load(Ordering::Relaxed),
            source: self.rename_source.load(Ordering::Relaxed),
            group: self.rename_group.load(Ordering::Relaxed),
            year_parens: self.rename_year_parens.load(Ordering::Relaxed),
            quality_brackets: self.rename_quality_brackets.load(Ordering::Relaxed),
            extra_words: self.rename_extra_words.load(Ordering::Relaxed),
        }
    }

    /// The quality suffix a job's files WOULD carry if it were filed right
    /// now: the auto-rename toggle gates it, and the tokens come from the
    /// job's own stem under the live NameStyle - exactly as
    /// [`finalize_names`](Daemon::finalize_names) computes it.
    ///
    /// Guesswork, because all three inputs are live settings. A job filed
    /// weeks ago carries [`Job::filed_suffix`] instead, and only a record
    /// written before that field existed falls back to here (see
    /// [`delete_tail`]). If the naming settings changed since filing,
    /// the recomputed suffix no longer matches the file on disk and the
    /// delete becomes a no-op: a leftover, which is the cheap mistake,
    /// rather than a destroyed episode, which is not.
    pub(super) fn job_suffix(&self, name: &str) -> String {
        if !self.auto_rename.load(Ordering::Relaxed) {
            return String::new();
        }
        crate::wall::quality_suffix(&crate::wall::parse_release(name), &self.rename_style())
    }

    /// The episode titles a TV job's rename may use: the show's cached
    /// TVmaze episode list, and NOTHING else.
    ///
    /// CACHE-ONLY, and that is the whole design (TODO 78). The list is
    /// written by the watchlist's 12-hourly calendar refresher, which
    /// runs on a blocking watcher thread where a network call belongs;
    /// this reads the blob it left. A show the cache has never heard of
    /// returns empty and the file gets the name it would have got
    /// anyway - no request, no waiting, and no second rename later,
    /// which is what would actually hurt (a rename that lands after an
    /// *arr imported the file breaks the import).
    ///
    /// v1 is English-only by consequence rather than by choice: TVmaze
    /// publishes original-language titles and that is what the blob
    /// holds. The setting says so.
    pub(super) fn episode_titles(&self, stem: &str) -> crate::smart::EpisodeTitles {
        use crate::smart::EpisodeTitles;
        if !self.rename_episode_titles.load(Ordering::Relaxed) {
            return EpisodeTitles::default();
        }
        let p = crate::wall::parse_release(stem);
        if p.kind != crate::wall::Kind::Tv || p.title.trim().is_empty() {
            return EpisodeTitles::default();
        }
        // Same key the calendar writes: `eplist:<normalised show title>`.
        #[cfg(feature = "indexer")]
        let key = format!("eplist:{}", crate::wall::norm_title(&p.title));
        #[cfg(feature = "indexer")]
        let eps: Vec<crate::wall::EpInfo> = self
            .with_index(|ix| ix.kv_get(&key))
            .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
            .and_then(|v| serde_json::from_value(v["episodes"].clone()).ok())
            .unwrap_or_default();
        // Slim build: no index, so no cached episode list to consult.
        #[cfg(not(feature = "indexer"))]
        let eps: Vec<crate::wall::EpInfo> = Vec::new();
        EpisodeTitles::new(eps.into_iter().map(|e| (e.season, e.episode, e.name)))
    }

    /// Ask what this finished download actually is, and remember what we
    /// learn (the `identity` ladder). Blocking: reads the finished
    /// directory and may make up to two third-party requests.
    ///
    /// Called before the cleanup sweep, because the sweep is what
    /// deletes the `.par2` sidecars this reads. Every rung is optional
    /// and every failure is silence: an offline daemon resolves nothing
    /// and files the job exactly as it would have before.
    pub(super) fn resolve_identity(
        &self,
        out_dir: &std::path::Path,
        posted: &str,
        inner_crc: u32,
    ) -> crate::identity::Identity {
        use nzbkit::release;
        let mut id = crate::identity::Identity::default();
        if !self.identity_lookup.load(Ordering::Relaxed) {
            return id;
        }
        // The local facts first - they cost a directory read and no
        // request, and the fingerprints are needed either way (a job we
        // CAN name is one this table wants to learn from).
        #[cfg(feature = "indexer")]
        let prints = crate::identity::par_fingerprints(out_dir);
        let obfuscated = release::looks_obfuscated(posted);
        let facts = crate::identity::Facts {
            posted: posted.to_string(),
            // Only an unnameable job asks these two: they can improve on
            // nothing else, and `decide_name` would decline them anyway.
            // Reads go on the read-only connection: this runs on a job
            // tail, and parking it behind a long ingest batch would
            // hold the finished job's rename and move behind the
            // scanner.
            #[cfg(feature = "indexer")]
            remembered: obfuscated
                .then(|| self.with_index_read(|ix| ix.par_hash_lookup(&prints).ok().flatten()))
                .flatten(),
            #[cfg(not(feature = "indexer"))]
            remembered: None,
            mkv_title: obfuscated
                .then(|| crate::identity::container_title(out_dir))
                .flatten(),
            // One request per completed job, cached for the process, and
            // impossible at all on a header-encrypted set (no CRC).
            srr: (inner_crc != 0)
                .then(|| crate::srrdb::archive_crc(inner_crc))
                .flatten(),
        };
        if let Some((name, src)) = crate::identity::decide_name(&facts) {
            id.name = name;
            id.src = src;
        }
        // Phase 3: a byte-level answer settles any correlation claim on
        // this release - confirmed names feed the precision meter and
        // arm the exact legs with the proven pairing; contradicted ones
        // are revoked before the wrong name outlives the evidence.
        // mkv-title deliberately does not qualify: it is an unverified
        // claim, and the meter must count only proof.
        #[cfg(feature = "indexer")]
        if matches!(id.src, "srrdb" | "par-hash") {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|t| t.as_secs() as i64)
                .unwrap_or(0);
            let verdict =
                self.with_index_mut(|ix| ix.pre_corr_verdict(posted, &id.name, now).ok().flatten());
            match verdict {
                Some(true) => {
                    info!(target: "predb", "correlation CONFIRMED by {}: {}", id.src, id.name)
                }
                Some(false) => info!(
                    target: "predb",
                    "correlation REJECTED by {} - real name: {}",
                    id.src, id.name
                ),
                None => {}
            }
        }
        id.imdb = facts
            .srr
            .as_ref()
            .map(|h| h.imdb.clone())
            .unwrap_or_default();
        // Whatever we now believe this release is called is what the id
        // hunt and the repost table both key on.
        let best = if id.name.is_empty() { posted } else { &id.name };
        #[cfg(feature = "indexer")]
        let parsed = release::parse_release(best);
        // Our own index may already hold the id, in which case xREL must
        // not be asked - see `xrel_query`.
        #[cfg(feature = "indexer")]
        if id.imdb.is_empty() {
            id.imdb = self
                .with_index_read(|ix| ix.title_get(&parsed.key).ok().flatten())
                .map(|t| t.imdb)
                .unwrap_or_default();
        }
        if let Some(q) = crate::identity::xrel_query(best, &id.imdb) {
            let hits = crate::xrel::search_p2p(&q);
            let found = crate::xrel::imdb_for_release(best, &hits);
            if !found.is_empty() {
                id.imdb = found;
                // Only xREL's own doing when nothing else spoke; a name
                // from srrdb keeps its attribution.
                if id.src.is_empty() {
                    id.src = "xrel";
                }
            }
        }
        // Teach the repost table. Only from a job we can actually name -
        // filing a fingerprint under an obfuscated stem would hand every
        // future repost of these bytes the same non-answer, permanently.
        #[cfg(feature = "indexer")]
        if !prints.is_empty() && !release::looks_obfuscated(best) {
            self.with_index(|ix| {
                ix.par_hash_remember(&prints, best, &parsed.key, unix_now())
                    .ok()
            });
        }
        if !id.is_empty() {
            info!(
                target: "identity",
                "{posted:?} -> {:?} {} (via {})",
                id.name, id.imdb, id.src
            );
        }
        id
    }

    /// Post-unpack naming & cleanup for a completed, unlocked job (blocking
    /// file ops - call from `spawn_blocking`). Removes junk / keeps only
    /// media (movie & TV only), then auto-renames: a movie's folder + main
    /// file, or TV episodes (Season-filed when `tv_sort`, else in place).
    ///
    /// Returns the new out_dir when the folder moved (else None), and the
    /// quality suffix the naming actually used. The suffix is returned
    /// rather than recomputed later because this is the only moment that
    /// knows it: the settings behind it are live, and by the time a delete
    /// needs to match the files on disk they may say something else. The
    /// caller stores it as [`Job::filed_suffix`].
    pub(super) fn finalize_names(
        &self,
        out_dir: &std::path::Path,
        job: &FinalizeJob<'_>,
    ) -> Finalized {
        let (name, cat, tv_sort) = (job.name, job.cat, job.tv_sort);
        let auto_rename = self.auto_rename.load(Ordering::Relaxed);
        let style = self.rename_style();
        // TODO 24D: user categories classify ahead of the built-ins, and
        // the behaviors below are gated on the release's BASE BEHAVIOR,
        // not its kind: built-in Movie/Tv map to themselves, a custom
        // kind to the base its category DECLARED (movie-like / tv-like /
        // none). Explicit, because a kind that is silently neither loses
        // junk-sweep and rename - a coupling that produced bugs twice in
        // the week this was designed.
        let cats = self.custom_categories.read_ok().clone();
        let mut p = nzbkit::categories::classify(name, &cats);
        let base = nzbkit::categories::base_of(&p.kind, &cats);
        use nzbkit::categories::BaseBehavior as Base;
        // Junk / keep-media deletes apply to movie-like & TV-like only -
        // never a software payload, an unclassifiable (obfuscated) set,
        // or a custom category that declared no base (keep-media-only
        // DELETES non-media files, which for a comics or audiobook
        // category is the payload).
        // The counts come back with the record (Finalized::swept): these
        // sweeps delete files out of a finished download, and a count
        // computed and dropped meant the deletes were invisible - the
        // history drawer's cleanup line is built from it.
        let mut swept = 0usize;
        if matches!(base, Base::Movie | Base::Tv) {
            if self.rename_media_only.load(Ordering::Relaxed) {
                swept = crate::smart::keep_media_only(out_dir);
            } else if self.rename_junk.load(Ordering::Relaxed) {
                swept = crate::smart::sweep_junk(out_dir);
            }
        }
        let parent = if cat.is_empty() {
            self.out_dir()
        } else {
            self.out_dir().join(cat)
        };
        // The container outranks the subject line: a "1080p" post over a
        // 720p stream gets the tag its bytes deserve. A measurement only
        // ever REPLACES a differing claim or ADDS an HD one - a name that
        // claimed nothing is not decorated with "480p" noise.
        if auto_rename
            && style.resolution
            && matches!(base, Base::Movie | Base::Tv)
            && let Some(measured) = crate::smart::measured_res(out_dir)
        {
            let claim = p.res.as_deref();
            if claim.is_some_and(|c| c != measured)
                || (claim.is_none() && matches!(measured, "720p" | "1080p" | "2160p"))
            {
                p.res = Some(measured.to_string());
            }
        }
        // A yearless post can still name its film when OUR OWN index
        // already knows the title by exactly one year (the enricher
        // resolved it). Ambiguity declines inside movie_year: a remade
        // title must never guess between its years.
        #[cfg(feature = "indexer")]
        if auto_rename
            && matches!(base, Base::Movie)
            && p.year.is_none()
            && let Some(y) = self.with_index(|ix| {
                ix.movie_year(&nzbkit::release::norm_title(&p.title))
                    .ok()
                    .flatten()
            })
        {
            p.year = Some(y);
        }
        let suffix = if auto_rename {
            crate::wall::quality_suffix(&p, &style)
        } else {
            String::new()
        };
        // One cache read per finished job, and only for a TV stem with
        // the setting on. Gated on auto_rename with the other naming
        // sub-settings: with the master switch off, filing still writes
        // the bare episode base, and decorating THAT would be a rename
        // the user asked not to have.
        let titles = if auto_rename {
            self.episode_titles(name)
        } else {
            crate::smart::EpisodeTitles::default()
        };
        // What filing will actually have written after the base, kept
        // for the delete and play paths. See `smart::FiledTail`.
        let filed_title = crate::smart::filed_title_segment(name, &suffix, &titles);
        let renamed = if tv_sort {
            // Season-filing carries the quality suffix when auto-rename is on.
            crate::smart::tv_organize(&parent, name, out_dir, &suffix, &titles)
        } else if auto_rename {
            match base {
                Base::Tv => {
                    crate::smart::tv_rename(out_dir, name, &suffix, &titles);
                    None
                }
                // Movie-like only - software installers, obfuscated blobs
                // and no-base customs are left as posted (movie_name also
                // guards on year/quality, and still declines event posts
                // whose identity lives after the year - the F1 guard).
                //
                // When it declines, "left as posted" can still mean an
                // obfuscated blob of a filename inside a perfectly good
                // folder, so fall back to naming the video after the
                // release itself. See rename_obfuscated_video.
                Base::Movie => match crate::wall::movie_name(&p, &style) {
                    Some(base) => crate::smart::rename_movie(&parent, out_dir, &base),
                    None => {
                        crate::smart::rename_obfuscated_video(out_dir, name);
                        None
                    }
                },
                // No declared base behaviour: we do not reshape the
                // payload, but an obfuscated video can still take the
                // release name. This is also where a FULLY obfuscated
                // post lands - it parses to no kind at all - so it is
                // the arm synthesised naming actually fires in.
                Base::None => {
                    crate::smart::rename_obfuscated_video(out_dir, name);
                    None
                }
            }
        } else {
            None
        };
        // Last rung, and the only one that asks anything outside this
        // machine: when every pass above has left the feature wearing a
        // hash, the file's own facts may still identify it. Never for
        // TV - see `identify_video` and the module docs.
        //
        // LAST on purpose, and that ordering is the whole relationship
        // with `crate::identity`. Those four oracles read an exact key -
        // an archive CRC, a PAR2 fingerprint, the muxer's own Title -
        // and when one answers, `naming` above is already the canonical
        // release name and the video has been renamed off it. This rung
        // infers from runtime and year, which is the weakest evidence
        // here, so it only ever speaks when they were all silent:
        // `nameless_video` returns None the moment any of them landed a
        // name, and no request goes out.
        let identified = if auto_rename && !tv_sort && !matches!(base, Base::Tv) {
            self.identify_video(out_dir, job)
        } else {
            String::new()
        };
        // C: the move-completed relocation does NOT run here any more.
        // This whole function sits on the finalize tail, and the runner
        // awaits that tail before it may start the next job - so a
        // multi-minute NAS copy used to stall the entire queue. The
        // caller marks the job `move_pending` instead and the mover
        // worker (spawn_mover) runs `relocate_completed` off-path.
        let moved = renamed;
        // #20: the modes go on LAST, once the payload has stopped moving
        // here. The mover applies them again after its relocation, for
        // the same reason and with the destination root.
        let umask = self.out_umask.load(Ordering::Relaxed);
        if umask <= 0o777 {
            let final_dir = moved.as_deref().unwrap_or(out_dir);
            let root = self.out_root.read_ok().clone();
            crate::smart::apply_out_umask(final_dir, Some(&root), umask);
        }
        Finalized {
            moved,
            suffix,
            filed_title,
            identify: identified,
            swept,
        }
    }

    /// The root a completed job in `cat` moves to, and whether it came
    /// from the per-category override (`move_completed_cats`) rather
    /// than the global completed folder. `None` = no destination is
    /// configured for this category, which is the feature being off for
    /// it.
    ///
    /// One lookup, three callers: the finalize gate
    /// ([`Self::move_destination_configured`]), the move itself
    /// ([`Self::relocate_completed`]) and the mover's lane key
    /// ([`mover::lane_key_for`]). They must never disagree - a lane
    /// keyed off a root the move does not use is a lane keyed off the
    /// wrong device.
    pub(super) fn move_dest_root(&self, cat: &str) -> Option<(PathBuf, bool)> {
        // Per-category override wins, and applies even when the global
        // destination is unset.
        let cat_root = self
            .move_completed_cats
            .read()
            .unwrap()
            .iter()
            .find(|(c, _)| *c == cat)
            .map(|(_, p)| p.clone());
        match cat_root {
            Some(p) => Some((p, true)),
            None => self.move_completed.read_ok().clone().map(|p| (p, false)),
        }
    }

    /// Is a move to a completed folder configured for this category?
    /// The gate finalize uses to decide whether a finished job owes the
    /// mover a visit.
    pub(super) fn move_destination_configured(&self, cat: &str) -> bool {
        self.move_dest_root(cat).is_some()
    }

    /// The mover's byte budget right now, in bytes/second. None = no
    /// cap. Read per pacing decision, so a mode change or a download
    /// starting mid-copy takes effect within one chunk.
    ///
    /// `wire_bps` is the caller's live measurement of what downloads
    /// are pulling (the pacer samples the daemon's own progress
    /// counter). Yield mode subtracts it from the line's capacity plus
    /// a 10% margin: on most home setups downloads are receive and the
    /// NAS copy is send, so the wire rarely contends - but CPU, disk
    /// and the NAS itself do, and the download's own measured rate is
    /// the one lever that tracks all of them.
    pub(super) fn mover_budget_bps(&self, wire_bps: u64) -> Option<u64> {
        let mode = self.move_pace.lock_ok().clone();
        match mode.as_str() {
            "full" => None,
            "yield" | "" => {
                // Idle queue: no cap. The threshold is generous so a
                // trickling health probe does not throttle a 10 GbE
                // copy to the floor.
                if wire_bps < 1_000_000 {
                    return None;
                }
                let line = match self.line_speed.load(Ordering::Relaxed) {
                    0 => self.best_rate_bps.load(Ordering::Relaxed),
                    l => l,
                };
                if line == 0 {
                    // Nothing known about the line: fall back to a
                    // fixed modest share rather than guessing zero.
                    return Some(20_000_000);
                }
                Some((line.saturating_sub(wire_bps + line / 10)).max(5_000_000))
            }
            n => n.parse::<u64>().ok().map(|mb| mb.max(1) * 1_000_000),
        }
    }

    /// Hand a finished job to the mover worker. Idempotent enough for
    /// its callers: a job re-enqueued while already queued just gets
    /// processed twice, and the second pass finds `move_pending` false
    /// and does nothing.
    pub(super) fn mover_enqueue(&self, job: &Arc<Mutex<Job>>) {
        self.mover_q.lock_ok().push_back(job.clone());
        self.mover_wake.notify_one();
    }

    /// One mover step: attempt the owed relocation for `job`. Runs on
    /// the blocking pool (bulk I/O). Returns true when the job should
    /// be RE-queued because another actor holds its files right now (a
    /// recategorize mid-flight).
    pub(super) fn mover_process(self: &Arc<Self>, job: &Arc<Mutex<Job>>) -> bool {
        let (id, out_dir, cat) = {
            let g = job.lock_ok();
            if !g.move_pending || g.state != JobState::Completed || g.tombstone {
                // Nothing owed (a delete or a second enqueue got here
                // first). Clear the marker if it survived a tombstone,
                // so a restart does not resurrect the move.
                drop(g);
                job.lock_ok().move_pending = false;
                return false;
            }
            if g.finalizing {
                // An unlock re-run owns the directory; it re-enqueues
                // when it finishes.
                return false;
            }
            (g.nzo_id.clone(), g.out_dir.clone(), g.category.clone())
        };
        // Same fence as recategorize and redrive: deletes and retries
        // stand off while files are in flight.
        if !self.moving.lock_ok().insert(id.clone()) {
            return true; // busy - try again shortly
        }
        struct Fence(Arc<Daemon>, String);
        impl Drop for Fence {
            fn drop(&mut self) {
                self.0.moving.lock_ok().remove(&self.1);
            }
        }
        let _fence = Fence(self.clone(), id);
        // Test-only: a move with visible width, so a test can watch the
        // lanes overlap (and the fleet cap hold) on a machine with one
        // volume, where every real move is an instant rename.
        #[cfg(test)]
        {
            let ms = mover::TEST_MOVE_DELAY_MS.load(Ordering::Relaxed);
            if ms > 0 {
                std::thread::sleep(std::time::Duration::from_millis(ms));
            }
        }
        let (moved, split, failed) = self.relocate_completed(&out_dir, &cat, None);
        let mut j = job.lock_ok();
        j.move_pending = false;
        j.move_failed = failed.unwrap_or_default();
        j.move_split = match &split {
            Some(src) => src.to_string_lossy().to_string(),
            None => String::new(),
        };
        self.settle_move_attempt(&mut j);
        if let Some(dest) = moved {
            j.filed = j.tv_sort && is_season_dir(&dest);
            j.out_dir = dest.clone();
            drop(j);
            // The modes go on after the payload stops moving (#20),
            // rooted at the destination the files now live under.
            let umask = self.out_umask.load(Ordering::Relaxed);
            if umask <= 0o777 {
                let root = self
                    .move_dest_root(&cat)
                    .map(|(r, _)| r)
                    .unwrap_or_else(|| self.out_root.read_ok().clone());
                crate::smart::apply_out_umask(&dest, Some(&root), umask);
            }
        } else {
            drop(j);
        }
        // The record it just rewrote is a HISTORY record (movers run
        // post-park) - its store line has to follow the bytes.
        self.history_upsert_if_present(job);
        self.save_queue();
        false
    }

    /// Post-download synthesised naming (films): if the main video is
    /// STILL nameless after every pass above, read its container facts
    /// and ask a film catalogue what it is.
    ///
    /// Returns the note to record on the job - what the file said about
    /// itself and what the catalogues offered - which is written whether
    /// or not the rename happened. That is the point: the common outcome
    /// is a decline, and a decline that tells the user "108 min, h264,
    /// audio en, and here are the eight films it could be" is worth far
    /// more than a silent one.
    ///
    /// Empty string means the ladder did not run at all (toggle off, or
    /// nothing nameless to rename), which is not worth a note.
    pub(super) fn identify_video(
        &self,
        out_dir: &std::path::Path,
        job: &FinalizeJob<'_>,
    ) -> String {
        if !self.rename_identify.load(Ordering::Relaxed) {
            return String::new();
        }
        // Cheapest question first: is there anything to fix? A payload
        // whose video already carries a human's name is left alone, and
        // costs no disk read and no request.
        let Some(video) = crate::smart::nameless_video(out_dir) else {
            return String::new();
        };
        let Some(facts) = nzbkit::media::probe(&video) else {
            return String::new();
        };
        let tmdb = self.tmdb_key();
        let outcome = crate::identify::identify(&facts, job.post_year, tmdb.as_deref());
        let line = outcome.log_line();
        match outcome.accepted_name() {
            Some(title) => {
                // The gate accepted, so the name has been earned by
                // evidence rather than by grammar - which is why this
                // takes the bare apply path rather than
                // `rename_obfuscated_video`'s release-name one.
                if crate::smart::rename_nameless_video(out_dir, &title) {
                    info!(target: "identify", "{} -> {title}", video.display());
                } else {
                    info!(target: "identify", "{line} (but the rename could not be applied)");
                }
            }
            None => info!(target: "identify", "{}: {line}", video.display()),
        }
        let mut note = line;
        for c in &outcome.shortlist {
            note.push('\n');
            note.push_str(c);
        }
        note
    }

    /// The user's TMDB key, when they configured one. Read per call
    /// rather than cached: it is a config-file value the user may add at
    /// any time, and this is not a hot path (once per obfuscated job).
    pub(super) fn tmdb_key(&self) -> Option<String> {
        nzbkit::config::Config::load(&self.cfg_path)
            .ok()?
            .tmdb_key
            .filter(|k| !k.is_empty())
    }

    /// Why a move destination could not be reached, when the OS error
    /// on its own reads as something it is not.
    ///
    /// `create_dir_all` reports the failure of the deepest component it
    /// could not create. On macOS an absent network volume makes that
    /// component a child of `/Volumes`, which is owned by root - so the
    /// mkdir is refused for want of PERMISSION and the daemon logs
    /// "Permission denied (os error 13)" for a destination whose real
    /// problem is that nothing is mounted there. That message sent one
    /// investigation after a TCC grant that was never involved (8 Aug
    /// 2026); the filesystem could have said so in one line, so now it
    /// does.
    ///
    /// Only speaks when a component ABOVE the job's own folder is
    /// missing. The leaf being absent is the ordinary case - the mover
    /// creates it - and saying so on every failure would be noise.
    pub(super) fn unreachable_dest_hint(dest: &std::path::Path) -> Option<String> {
        // `ancestors` walks leaf-first, so the last one that does not
        // exist is the SHALLOWEST missing component: the thing whose
        // absence explains all the others.
        let mut missing: Option<&std::path::Path> = None;
        for a in dest.ancestors() {
            if a.exists() {
                break;
            }
            missing = Some(a);
        }
        let missing = missing.filter(|m| *m != dest)?;
        // A mount point is a child of the platform's volume root, and
        // that is the mounted-or-not question rather than an ordinary
        // absent folder.
        let at_volume_root = missing.parent().and_then(|p| p.to_str()).is_some_and(|p| {
            matches!(p, "/Volumes" | "/media" | "/mnt") || p.eq_ignore_ascii_case("/net")
        });
        Some(if at_volume_root {
            format!(
                " - {} does not exist, so that volume is probably not mounted \
                 (its parent belongs to root, which is why an absent volume \
                 reports as a permission error)",
                missing.display()
            )
        } else {
            format!(" - {} does not exist", missing.display())
        })
    }

    /// M33: relocate a finished job to the `move_completed` destination
    /// (a NAS share etc.), keeping the category subfolder and whatever
    /// renaming/Season-filing just produced. Returns the job's final
    /// directory when it changed.
    ///
    /// A failed move is not one outcome but two, and they need opposite
    /// answers. `move_tree` stages the cross-device case, so a NAS that
    /// fills or drops leaves the payload whole where it was; but the
    /// same-filesystem merge moves entry by entry, so a failure there can
    /// leave the job split across both directories. We do not guess which
    /// happened - we count the source before and after. Split reports the
    /// destination, because those bytes exist nowhere else and the
    /// alternative is a job record, a dashboard link and a history storage
    /// path all pointing at a directory the files have left.
    ///
    /// Returns (the job's final directory when it changed, the SOURCE
    /// directory that still holds part of the payload, why nothing
    /// moved). The second is `Some` only for the split case - UX §18:
    /// the split was logged and then thrown away, so history painted the
    /// job green and named exactly one of the two folders it was now in.
    /// The third is `Some` only for the nothing-moved failure, and it
    /// exists for the same reason: the error was logged and then thrown
    /// away, so a completed job whose files never left the download
    /// folder looked exactly like one whose files did (7 Aug 2026 -
    /// five of them, for hours). It feeds [`Job::move_failed`], and
    /// with a destination configured this function now never declines
    /// silently: every outcome is a log line, including "already
    /// there".
    pub(super) fn relocate_completed(
        &self,
        out_dir: &std::path::Path,
        cat: &str,
        renamed: Option<PathBuf>,
    ) -> (Option<PathBuf>, Option<PathBuf>, Option<String>) {
        // A per-category override IS that category's root, so the
        // category component is not repeated inside it - which is what
        // `from_cat` is for below.
        let Some((root, from_cat)) = self.move_dest_root(cat) else {
            // The one legitimately silent decline: the feature is off.
            return (renamed, None, None);
        };
        let cur = renamed.clone().unwrap_or_else(|| out_dir.to_path_buf());
        // Mirror the layout under the destination: the path relative to
        // the download root already carries category/Show/Season NN. If
        // the job predates a live out_dir swap, fall back to
        // category + folder name.
        let mut rel = cur
            .strip_prefix(self.out_dir())
            .map(|r| r.to_path_buf())
            .unwrap_or_else(|_| {
                let base = PathBuf::from(cur.file_name().unwrap_or_default());
                if cat.is_empty() {
                    base
                } else {
                    PathBuf::from(cat).join(base)
                }
            });
        if from_cat
            && !cat.is_empty()
            && let Ok(r) = rel.strip_prefix(cat)
        {
            rel = r.to_path_buf();
        }
        let dest = root.join(&rel);
        // Byte equality is not path identity. A destination that ALIASES
        // the job's current folder - a case variant on APFS or NTFS, a
        // symlinked parent, a trailing-dot or "." component - compared
        // unequal here, so move_tree ran with dst == src. Its merge path
        // then walked the directory finding every target "occupied" by
        // the source file itself, and reserve_free_name renamed each real
        // file to "Episode (2).mkv". For a TV-filed job `cur` is the
        // SHARED season folder, so the user's already-filed siblings were
        // mangled too, and every later completion compounded it
        // ("Episode (2) (2).mkv"). Nothing is destroyed, but a whole
        // season loses its filenames and its subtitle stem pairings.
        //
        // canonicalize resolves case, symlinks and oddities; it only
        // works on paths that exist, so fall back to the byte compare
        // when either side does not yet.
        let same_place = dest == cur
            || match (dest.canonicalize(), cur.canonicalize()) {
                (Ok(a), Ok(b)) => a == b,
                _ => false,
            };
        if same_place {
            // Not silent: with a destination configured, "no move
            // happened" and "the move was not owed" have to be
            // distinguishable from the outside. This is the line that
            // was missing while five finished jobs sat in the download
            // folder with nothing anywhere saying why.
            info!(
                target: "move",
                "{} is already inside the completed folder - nothing to move",
                cur.display()
            );
            return (renamed, None, None);
        }
        // One dirent walk of the job's own folder, so a failure can be
        // told apart: nothing moved (the job is still where it was) or
        // some of it did (the job is split, and `cur` is no longer the
        // truth). Counting the DESTINATION instead would not answer it -
        // it merges with what is already there, so a Season folder on a
        // NAS looks non-empty whether our files reached it or not.
        let before = file_count(&cur);
        // Paced: the mover must never slow a live download (mode
        // "yield", the default), and the pacer reads the mode live so
        // a settings change lands within one chunk. The bucket behind
        // it is the daemon's, shared by every lane copying right now.
        let pace = mover::mover_pacer(self);
        match crate::smart::move_tree_paced(&cur, &dest, Some(&pace)) {
            Ok(()) => {
                info!(target: "move", "completed → {}", dest.display());
                (Some(dest), None, None)
            }
            Err(e) => {
                // NOT the flat "leaving files in place" this used to say.
                // The staged cross-device path usually does leave the
                // payload whole, but the same-filesystem merge can stop
                // half way through, and that message sent the user looking
                // in exactly one of the two directories the job was now in.
                // Say which case this was rather than assuming either.
                let moved_some = file_count(&cur) < before;
                // Composed once and carried into BOTH the log line and
                // the job record: the record outlives the ring, and it
                // is the one the dashboard shows.
                let hint = Self::unreachable_dest_hint(&dest).unwrap_or_default();
                error!(
                    target: "move",
                    "{} → {}: {e}{hint}\n\
                     [move] {}",
                    cur.display(),
                    dest.display(),
                    if moved_some {
                        format!(
                            "the payload is now SPLIT - some files moved before this failed. \
                             Check both {} and {} before deleting either.",
                            cur.display(),
                            dest.display()
                        )
                    } else {
                        format!("nothing moved - the download is still at {}", cur.display())
                    }
                );
                // Report where the payload now is. The files that moved
                // exist nowhere else, so keeping the old directory on the
                // job record would send the dashboard, a later delete and
                // the *arr import at a folder they have left.
                // The source travels back beside it so the record can
                // say the payload is in TWO places - the log line above
                // is the only other witness, and it rolls out of the ring.
                if moved_some {
                    (Some(dest), Some(cur), None)
                } else {
                    // Destination + error, composed here because only
                    // this moment has both. It becomes Job::move_failed:
                    // the amber row, the drawer line and the auto-retry
                    // all hang off it.
                    (
                        renamed,
                        None,
                        Some(format!("{}: {e}{hint}", dest.display())),
                    )
                }
            }
        }
    }

    pub(super) fn bench_history_path(&self) -> PathBuf {
        // Working state lives in the fixed spool, not the (now live-swappable)
        // download folder.
        self.spool.join("bench_history.json")
    }

    pub(super) fn bench_history(&self) -> Vec<Value> {
        crate::persist::load_json_with_backup(&self.bench_history_path())
            .and_then(|v| v.as_array().cloned())
            .unwrap_or_default()
    }

    pub(super) fn bench_append(&self, entry: Value) {
        let p = self.bench_history_path();
        let mut list = self.bench_history();
        list.push(entry);
        let n = list.len();
        if n > 400 {
            list.drain(0..n - 400);
        }
        let _ = crate::persist::write_atomic(&p, &serde_json::to_vec(&list).unwrap_or_default());
    }

    /// The queued job with this id, cloned out so the caller works
    /// without holding the queue lock. Locking a Job while holding the
    /// queue is how this tree deadlocks.
    pub(super) fn queue_job(&self, id: &str) -> Option<Arc<Mutex<Job>>> {
        find_job(self.queue.lock_ok().iter(), id)
    }

    /// Same, for history.
    pub(super) fn history_job(&self, id: &str) -> Option<Arc<Mutex<Job>>> {
        find_job(self.history.lock_ok().iter(), id)
    }

    /// Does the job the transfer currently belongs to satisfy `want`?
    ///
    /// The single owner test for every caller that is about to signal
    /// `hub.abort` / `hub.queue_ctl`. Those handles are overwritten per
    /// job and carry no owner tag, so "is this job the live transfer?"
    /// CANNOT be answered from `state == JobState::Downloading`: there is
    /// no Repairing/Extracting state, and job N deliberately stays
    /// Downloading through its whole post-network tail while job N+1 is
    /// already on the wire holding those handles. Steering by state
    /// therefore aimed the abort at the wrong job. `active_stream` is set
    /// to the picked job as the fetch spawns and is the thing the
    /// watchdog already steers by.
    pub(super) fn owns_hub(&self, want: impl Fn(&str) -> bool) -> bool {
        self.active_stream.lock_ok().as_deref().is_some_and(want)
    }

    /// The wire status for a job that has left the network but is still
    /// inside the pipeline - or None if it is not in a post-network tail.
    ///
    /// There is no Verifying/Repairing/Extracting `JobState`: the whole
    /// tail runs inside the same fetch future, so the record says
    /// `Downloading` from the first article to the last extracted byte.
    /// The pipeline does say where it is, though - it advances
    /// `hub.activity` at each section transition, tagged with the owning
    /// nzo_id precisely because job N's tail overlaps job N+1's fetch -
    /// so the phase word is read from there rather than from a second
    /// mechanism that would have to be kept in step with it.
    ///
    /// The words are SABnzbd's own state vocabulary, like `Moving`
    /// beside them in queue_json: Sonarr and Radarr already read all
    /// three as "busy, keep waiting", which is exactly what they mean.
    pub(super) fn tail_phase(&self, nzo_id: &str) -> Option<&'static str> {
        match self.hub.activity.lock_ok().get(nzo_id).copied() {
            Some("verifying") => Some("Verifying"),
            Some("repairing") => Some("Repairing"),
            Some("extracting") => Some("Extracting"),
            _ => None,
        }
    }

    /// Fire the pause signal once. `hard` = the immediate abort (drop
    /// in-flight reads, they re-download on resume); otherwise the graceful
    /// drain (admit no new work, let in-flight finish and journal).
    pub(super) fn fire_pause(&self, hard: bool) {
        if hard {
            if let Some(f) = self.hub.abort.lock_ok().as_ref() {
                f.store(true, Ordering::Relaxed);
            }
            if let Some(c) = self.hub.queue_ctl.lock_ok().as_ref() {
                c.abort();
            }
        } else if let Some(c) = self.hub.queue_ctl.lock_ok().as_ref() {
            c.drain();
        }
    }

    /// Pause the active download. `graceful` winds it down - no new
    /// articles admitted, everything in flight finishes and journals, so a
    /// resume re-fetches only the unstarted queue. `graceful = false` is
    /// the immediate abort (frees the line at once; in-flight re-downloads).
    pub(super) fn suspend_active(self: &Arc<Self>, graceful: bool) {
        self.suspend_matching(graceful, |_| true)
    }

    /// Wind down the running transfer, but only for jobs `want` accepts.
    ///
    /// Pausing ONE job used to set `g.paused` and stop there: the flag
    /// only takes effect when a job next enters the queue, so pausing the
    /// item that was actually downloading left it transferring at full
    /// speed while both API facades answered success and kept reporting
    /// it as Downloading. Only the global pause was wired to the
    /// wind-down machinery. The daemon runs one job at a time, so
    /// scoping that machinery by predicate is all a per-job pause needs.
    pub(super) fn suspend_matching(self: &Arc<Self>, graceful: bool, want: impl Fn(&Job) -> bool) {
        let mut paused: Vec<String> = Vec::new();
        for j in self.queue.lock_ok().iter() {
            let mut g = j.lock_ok();
            if !want(&g) {
                continue;
            }
            // A job in its post-network tail has no transfer left to wind
            // down, and marking it suspended did real damage: it read
            // "Paused" in every client while its repair and unpack
            // carried on, and the tail-completion arm treats
            // `suspended && res.is_err()` as "the user paused this" and
            // puts the job back in the QUEUE - so a pause-all issued
            // during an unpack turned that unpack's failure into a
            // silent re-queue, with no history record and no failure
            // notification. `state == Downloading` cannot tell the two
            // apart on its own; the pipeline's phase word can.
            if g.state == JobState::Downloading
                && g.priority < 2
                && !g.tombstone
                && self.tail_phase(&g.nzo_id).is_none()
            {
                g.suspended = true;
                paused.push(g.nzo_id.clone());
                info!(
                    target: "pause",
                    "{} {} - resumes from the journal",
                    if graceful {
                        "winding down"
                    } else {
                        "suspending"
                    },
                    g.nzo_id
                );
            }
        }
        // The wind-down machinery is global - it signals whichever job
        // owns the hub - so pausing ONE job may only drive it when that
        // job is the owner. `state == Downloading` is not that test (see
        // `owns_hub`): pausing job N during its post-network tail drained
        // job N+1 instead, and N+1's own tail reads N+1's `suspended`
        // (false), so it was never re-queued - it just failed. The
        // re-fire loop below made it worse by firing every 250 ms for up
        // to 60 s and escalating to a hard abort at ~10 s, so a job
        // started after a quick resume could be killed too. Every matched
        // job is still marked suspended above; only the SIGNAL is scoped.
        // The ownership re-check inside the loop is what stops the next
        // owner inheriting this pause.
        //
        // Note `active_stream` is published before the hub handles are
        // installed, so the "signal landed in the gap" race the loop
        // exists for is unaffected: ownership is already true while
        // fire_pause is still a no-op, and the loop keeps retrying.
        let owner_paused =
            |d: &Arc<Self>, ids: &[String]| d.owns_hub(|id| ids.iter().any(|s| s == id));
        if !paused.is_empty() {
            // The pipeline installs its hub abort/queue-ctl handles
            // asynchronously after launch (the same race stop_sidecar
            // re-fires around): a single signal can land in the gap
            // before QueueControl attaches and no-op, leaving the
            // transfer running while the job reads as suspended.
            // Re-fire until the tail handler actually parks it. First
            // shot goes out inline so the transfer is already stopping
            // by the time the pause API call returns.
            if owner_paused(self, &paused) {
                self.fire_pause(!graceful);
            }
            let d = self.clone();
            std::thread::spawn(move || {
                for i in 0..240 {
                    let live = d.queue.lock_ok().iter().any(|j| {
                        let g = j.lock_ok();
                        g.suspended
                            && g.state == JobState::Downloading
                            && !g.tombstone
                            && paused.iter().any(|s| *s == g.nzo_id)
                    });
                    if !live {
                        return;
                    }
                    // Ownership can change under us - job N+1 takes the
                    // hub while N's tail runs - so re-check every pass
                    // rather than inheriting the pause onto whoever is
                    // downloading now.
                    if !d.owns_hub(|id| paused.iter().any(|s| s == id)) {
                        std::thread::sleep(std::time::Duration::from_millis(250));
                        continue;
                    }
                    // A graceful pause lets in-flight articles finish, but
                    // not forever: after ~10 s escalate to a hard abort so
                    // one pathological article can't stall the pause (what
                    // already drained is journaled, so nothing extra is
                    // lost by then aborting the stragglers).
                    d.fire_pause(!graceful || i >= 40);
                    std::thread::sleep(std::time::Duration::from_millis(250));
                }
            });
        }
    }

    /// M32: re-queue any Failed history job whose auto-retry cooldown has
    /// elapsed. Called from the scheduler loop; one lock + linear scan.
    pub(super) fn run_due_auto_retries(self: &Arc<Self>) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let due: Vec<(String, String)> = self
            .history
            .lock_ok()
            .iter()
            .filter_map(|j| {
                let g = j.lock_ok();
                (g.state == JobState::Failed && g.auto_retry_at.is_some_and(|t| t <= now))
                    .then(|| (g.nzo_id.clone(), g.name.clone()))
            })
            .collect();
        for (id, name) in due {
            if self.retry(&id) {
                info!(
                    target: "retry",
                    "{id}: automatic retry (cooldown elapsed - refetching only what's missing)"
                );
                // The row the user was shown as FAILED has just left
                // History and joined the queue. Announce the move: without
                // it the record appears to have been lost and a download
                // nobody asked for appears to have started.
                let mut ring = self.auto_retried.lock_ok();
                ring.push_back((id, name, now as i64));
                while ring.len() > 8 {
                    ring.pop_front();
                }
            }
        }
        // The other half of the cooldown: a COMPLETED job whose move to
        // the completed folder failed retries the MOVE, never the
        // download. Separate arm on purpose - `retry` above would pull
        // the record out of history and re-fetch a payload that is
        // already whole on disk.
        let due_moves: Vec<String> = self
            .history
            .lock_ok()
            .iter()
            .filter_map(|j| {
                let g = j.lock_ok();
                (g.state == JobState::Completed
                    && !g.move_failed.is_empty()
                    && g.auto_retry_at.is_some_and(|t| t <= now))
                .then(|| g.nzo_id.clone())
            })
            .collect();
        for id in due_moves {
            self.redrive_move(&id);
        }
    }

    /// Record what one move attempt did to the job and arm - or refuse
    /// to arm - the next automatic try. Call with the job lock held,
    /// once `move_failed` carries the attempt's outcome.
    ///
    /// The one place the ladder lives. Both movers (the finalize-side
    /// worker and the scheduler's redrive) used to carry their own copy
    /// of "re-arm the flat cooldown", which is how the retry stayed
    /// unbounded in two places at once: nothing counted the attempts,
    /// so nothing could grow the delay or ever stop. An unreachable
    /// destination is not a transient the way a missing article is -
    /// an unmounted destination volume logged 45 identical EACCES
    /// failures over 15 hours on 8 Aug 2026, and the 45th was as
    /// uninformative as the first.
    ///
    /// Giving up is not giving up on the payload: every byte is whole
    /// at `out_dir`, the row stays amber, the drawer still names the
    /// destination and the error, and `Try the move now` restarts the
    /// ladder the moment the user has fixed what was wrong.
    pub(super) fn settle_move_attempt(&self, j: &mut Job) {
        if j.move_failed.is_empty() {
            j.move_attempts = 0;
            // Only ever disarm OUR reason: a stamp left by anything
            // else is not this function's to clear.
            if j.auto_retry_why.as_deref() == Some("move") {
                j.auto_retry_at = None;
                j.auto_retry_why = None;
            }
            return;
        }
        j.move_attempts = j.move_attempts.saturating_add(1);
        let base = self.auto_retry_secs.load(Ordering::Relaxed);
        // Zero is the user turning automatic retries off outright, and
        // it is not a give-up worth logging - they asked for this.
        if base == 0 {
            return;
        }
        if j.move_attempts >= MOVE_RETRY_GIVE_UP {
            // Disarm rather than merely declining to re-arm. The
            // redrive clears the stamp before it tries, so this is
            // usually already None - but the finalize-side mover does
            // not, and a stamp left behind here is the scheduler's cue
            // to run the whole ladder again, which is the unbounded
            // loop this function exists to end.
            j.auto_retry_at = None;
            j.auto_retry_why = None;
            warn!(
                target: "move",
                "{}: giving up on the move after {} failed attempts - {}. \
                 The download is safe at {}; \"Try the move now\" in its \
                 history drawer starts a fresh ladder.",
                j.nzo_id,
                j.move_attempts,
                j.move_failed,
                j.out_dir.display()
            );
            return;
        }
        let secs = move_retry_delay(base, j.move_attempts);
        j.auto_retry_at = Some(unix_now() as u64 + secs);
        j.auto_retry_why = Some("move".to_string());
    }

    /// Re-attempt the move-completed relocation for a parked Completed
    /// job whose first attempt failed (Job::move_failed). Files only -
    /// the download is done and stays done. Returns false when the job
    /// is missing, unfenced state forbids it, or no failure is recorded.
    ///
    /// The observed failure mode this exists for is transient: macOS
    /// denied a network volume to the daemon for a moment and allowed
    /// it minutes later (7 Aug 2026), so "try again on the M32
    /// cooldown" converts hours of silently-stranded payloads into one
    /// delayed move. On another failure the cooldown re-arms - each
    /// attempt is one create_dir plus one copy that stops at the first
    /// error, so a persistently absent NAS costs a probe per cycle, not
    /// a re-download.
    pub(super) fn redrive_move(self: &Arc<Self>, nzo_id: &str) -> bool {
        let Some(job) = self.history_job(nzo_id) else {
            return false;
        };
        // Same fence pair the recategorize path takes, for the same
        // reasons: `moving` keeps deletes/retries off the payload while
        // files are in flight, and `finalizing` means the tail already
        // owns the directory. The fence is dropped by the guard inside
        // the blocking task, so it holds exactly as long as files can
        // be moving; the early-out paths below release it by hand.
        if !self.moving.lock_ok().insert(nzo_id.to_string()) {
            return false;
        }
        struct MoveClaim(Arc<Daemon>, String);
        impl Drop for MoveClaim {
            fn drop(&mut self) {
                self.0.moving.lock_ok().remove(&self.1);
            }
        }
        let claim = MoveClaim(self.clone(), nzo_id.to_string());
        let (out_dir, cat) = {
            let mut g = job.lock_ok();
            if g.state != JobState::Completed || g.finalizing || g.move_failed.is_empty() {
                return false; // claim drops here, releasing the fence
            }
            // Disarm before the attempt so a success does not leave a
            // stale cooldown ticking; a failure re-arms below.
            g.auto_retry_at = None;
            g.auto_retry_why = None;
            (g.out_dir.clone(), g.category.clone())
        };
        let d = self.clone();
        let job2 = job.clone();
        let id2 = nzo_id.to_string();
        // The copy is bulk I/O - blocking pool, with the fence riding
        // along in `claim` so it cannot be released before the move
        // settles.
        tokio::task::spawn_blocking(move || {
            let _claim = claim;
            info!(target: "move", "{id2}: retrying the move to the completed folder");
            let (moved, split, failed) = d.relocate_completed(&out_dir, &cat, None);
            let mut j = job2.lock_ok();
            j.move_failed = failed.unwrap_or_default();
            j.move_split = match &split {
                Some(src) => src.to_string_lossy().to_string(),
                None => String::new(),
            };
            if let Some(dest) = moved {
                j.filed = j.tv_sort && is_season_dir(&dest);
                j.out_dir = dest;
            }
            // Arms the NEXT rung, or stops the ladder. The disarm above
            // ran before the attempt, so this is the only thing that
            // can leave a stamp behind.
            d.settle_move_attempt(&mut j);
            drop(j);
            d.history_upsert_if_present(&job2);
            d.save_queue();
        });
        true
    }

    /// The drawer button's redrive: forget the failed-attempt count
    /// first, then try.
    ///
    /// A user pressing "Try the move now" has almost always just fixed
    /// the thing that was wrong - mounted the volume, granted the
    /// share, freed the disk - so the ladder starts again from its
    /// first rung, and a job the daemon had given up on becomes
    /// automatic again. Without the reset, one manual press on a job at
    /// the give-up count would try exactly once and go quiet forever.
    pub(super) fn retry_move_now(self: &Arc<Self>, nzo_id: &str) -> bool {
        if let Some(job) = self.history_job(nzo_id) {
            job.lock_ok().move_attempts = 0;
        }
        self.redrive_move(nzo_id)
    }

    pub(super) fn retry(&self, nzo_id: &str) -> bool {
        // Same transaction as `enqueue`: this picks an output directory
        // by the same claim rule and republishes the job into the queue,
        // so it must not interleave with an add (or another retry)
        // making the same decision about the same folder.
        let publish = self.add_lock.lock_ok();
        let mut h = self.history.lock_ok();
        // A recategorize is moving this job's payload right now. Taking
        // it out of history and re-queueing it would start writers at
        // the path the move is emptying, and the move would then point
        // the record at the destination while the download continued at
        // the source. The auto-retry timer fires from the scheduler, so
        // this is not a race the user has to lose deliberately.
        //
        // UNDER the history lock, which is the half that makes it work
        // (Codex H7). `history_change_cat` raises its `moving` marker and
        // THEN re-verifies the record is still in history; a check taken
        // outside this lock could pass just before the marker went up
        // while the move still proceeded. Both REST and JSON-RPC history
        // delete already sample it here; retry read it one lock too
        // early, so a recategorize could re-verify the record present,
        // block on `add_lock`, and then move the payload of a job this
        // call had already pulled out of history and re-queued - leaving
        // a full payload at the destination named by no record, while
        // the re-queued job downloaded the release again into the
        // directory the move was emptying.
        if self.moving.lock_ok().contains(nzo_id) {
            info!(target: "retry", "{nzo_id}: refused - its files are being moved right now");
            return false;
        }
        let Some(pos) = h.iter().position(|j| j.lock_ok().nzo_id == nzo_id) else {
            return false;
        };
        // A password unlock is finalizing this record right now - it is
        // extracting/renaming/moving under `out_dir` and will write the
        // committed state back when it settles. Removing and re-queueing
        // the record here would reassign that directory under the
        // running task (Codex sweep 3 Aug H1). Checked under the history
        // lock: set_password raises the flag and then re-verifies the
        // record is still present under this same lock, so whichever
        // committed second sees the other.
        if h[pos].lock_ok().finalizing {
            info!(target: "retry", "{nzo_id}: refused - an unlock is finalizing it right now");
            return false;
        }
        let job = h.remove(pos);
        drop(h);
        // A TV-filed job's out_dir is the SHARED `Show/Season NN` library
        // folder. Re-queueing it as-is would point the whole re-download
        // (journal, volume writers, and every later "delete this job's
        // files") at a directory that belongs to the season, not the job.
        // Give it a fresh private directory instead.
        //
        // So does a job whose old folder someone else has taken since it
        // failed: a Failed record reads as Free, so a re-add of the same
        // name is handed exactly that directory, and re-queueing this one
        // as-is would put two live jobs in it - or, once the re-add has
        // finished, aim this download straight at its verified payload,
        // which is the collision `DirClaim::Payload` exists to prevent.
        // Checked AFTER the history removal above, so an ordinary failed
        // retry still finds its own folder unclaimed and reuses it in
        // place: re-adds must not climb .2/.3/.4.
        let (filed, category, name, cur) = {
            let j = job.lock_ok();
            (
                j.filed,
                j.category.clone(),
                j.name.clone(),
                j.out_dir.clone(),
            )
        };
        // With NO job lock held: dir_claim locks every job in the queue
        // and history.
        let taken = matches!(self.dir_claim(&cur), DirClaim::Active | DirClaim::Payload);
        // A job's out_dir is the absolute path baked in from the
        // download-folder setting IN FORCE WHEN IT WAS ADDED. If that
        // setting has since changed - the user picked a new download folder,
        // or a settings.json was carried between two machines where the old
        // path (a since-unplugged drive, a differently mounted volume) does
        // not even exist - the captured path no longer sits under the
        // current root. Re-running the job as-is would keep writing to, or
        // fail EACCES/ENOENT against, a folder the user has deliberately
        // moved away from (field repro 9 Aug: out_dir was changed to a
        // mounted path, yet retry still targeted the old /Volumes/... one).
        // Re-derive it from the CURRENT root + this job's category, exactly
        // as a fresh add resolves it. A path still under the current root is
        // left untouched, so an ordinary failed retry keeps its own folder,
        // its journal and its progress. (refile_out_dir honours the category
        // as a subfolder; a cat_meta `dir` rename is not re-applied here, the
        // same as the filed/taken paths above - a pre-existing gap, not this
        // fix's concern.)
        let stale = !cur.starts_with(self.out_dir());
        if filed || taken || stale {
            let (dir, replaces) =
                refile_out_dir(&self.out_dir(), &category, &name, &|p| self.dir_claim(p));
            let mut j = job.lock_ok();
            info!(
                target: "retry",
                "{}: {} {} - re-downloading into {} instead",
                j.nzo_id,
                if filed {
                    "was filed into"
                } else if taken {
                    "another job now owns"
                } else {
                    "targeted a download folder that is no longer configured:"
                },
                j.out_dir.display(),
                dir.display()
            );
            j.out_dir = dir;
            j.replaces = replaces;
            j.filed = false;
            // The journal that backed those bytes is in the OLD folder,
            // so nothing is on disk at the new one: this retry really
            // does start from zero, and the queue row must say so rather
            // than inherit a percentage from a directory it has just
            // been moved out of. (An ordinary failed retry keeps its
            // folder, its journal and its figure.)
            j.downloaded_bytes = 0;
            // The two travel together: the job is no longer in the season
            // folder, so the suffix its old files carried there is not an
            // answer about anything this record now owns.
            j.filed_suffix = None;
        }
        {
            let mut j = job.lock_ok();
            j.state = JobState::Queued;
            // A retry is an instruction to RUN the job, so it cannot
            // arrive back in the queue holding a pause `pick_job` will
            // skip it for (Codex sweep 2, 3 Aug M4). The flag reaches
            // here from a pause taken while the job was in its
            // post-network tail, which the tail correctly ignored and
            // then left set; the shared transition now refuses to set
            // it there at all, and this is the belt to that brace - a
            // failed record's pause flag describes nothing either way.
            j.paused = false;
            j.fail_message.clear();
            j.fail_detail.clear();
            j.finished_at = None;
            j.finished_unix = None;
            j.retries += 1;
            // A due-or-pending auto-retry is consumed by ANY retry (manual
            // included) - never leave a stale past-due stamp that would
            // re-trigger endlessly from history.
            j.auto_retry_at = None;
            // Travels with the stamp: a cleared retry has no reason left
            // to explain, and a stale token would caption the NEXT
            // failure's row with the last one's cause.
            j.auto_retry_why = None;
            // TODO §77: the pre-flight verdict is about a moment that has
            // passed. A retry exists BECAUSE the answer may have changed -
            // the automatic one runs on exactly the theory that propagation
            // has filled the gaps since - so the row must not go on showing
            // what the servers said before the last attempt. Cleared rather
            // than aged out: the prober re-samples a job with no verdict on
            // its next idle tick, which is the answer worth having here.
            j.health = None;
        }
        self.queue.lock_ok().push_back(job);
        drop(publish);
        // The record has LEFT history: stop it replaying there. Its new
        // life as a queue record is save_queue's to persist.
        self.history_tombstone(&[nzo_id.to_string()]);
        self.save_queue();
        true
    }

    /// Persist queue + history to `.spool/queue.json` so a daemon restart
    /// doesn't forget the job list. Only the record is at stake: the NZB
    /// itself already lives in the spool, and each out_dir's article
    /// journal makes a resumed download fetch only what's still missing.
    /// Called after every mutation, once the queue/history locks are
    /// released. Best-effort like save_setting: a failed write must never
    /// take down a live daemon.
    ///
    /// Returns whether the record actually landed. Almost every caller is
    /// right to ignore that - the job is live in memory either way. The watch
    /// poller is not: it deletes the user's original .nzb once the job is
    /// accepted, so it needs to know the acceptance survived a restart.
    pub(super) fn save_queue(&self) -> bool {
        // API requests run on a worker pool - serialize the writes so two
        // mutations can't interleave bytes in the file. Take the IO lock
        // BEFORE snapshotting: if the snapshot were built first, a slow
        // encoder (T1) could grab the lock after a later mutation (T2)
        // already wrote its fresher snapshot, then overwrite it with stale
        // state and lose T2's change across restart. Snapshotting under the
        // lock makes the last writer also the one holding the newest state.
        static IO: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _g = IO.lock_ok();
        let jobs: Vec<Value> = self
            .queue
            .lock_ok()
            .iter()
            .map(|j| job_json(&j.lock_ok()))
            .collect();
        // §129 1a: history is NOT here any more. It lives in its own
        // append-only store (`histstore.rs`), written by the sites that
        // actually change it - park, delete, retry, recategorize, the
        // unlock/mover bookkeeping - so an unlimited history stops
        // costing every queue mutation an O(all-time) rewrite.
        let v = json!({
            "next_id": self.next_id.load(Ordering::Relaxed),
            "queue": jobs,
        });
        // The dashboard's change handle, bumped WITH the write: a queue
        // change that should survive restart comes through here, so the
        // revision sees it by construction.
        self.queue_rev.fetch_add(1, Ordering::Relaxed);
        let path = self.spool.join("queue.json");
        match serde_json::to_string_pretty(&v) {
            Ok(text) => match crate::persist::write_atomic(&path, text.as_bytes()) {
                Ok(()) => true,
                Err(e) => {
                    error!(target: "queue", "persist {}: {e}", path.display());
                    false
                }
            },
            Err(e) => {
                error!(target: "queue", "serialize: {e}");
                false
            }
        }
    }

    /// Reload `.spool/queue.json` at startup, re-creating the Job records.
    /// Wall-clock floor (seconds since the Unix epoch) for the RESTORED
    /// id allocator. The snapshot's `next_id` can be stale when the run
    /// that allocated past it could not persist (disk full at enqueue),
    /// and those already-issued ids carry permanent stream tokens - so
    /// a restore must never let allocation fall back behind real time.
    /// Only applied on restore: a fresh daemon with no state keeps its
    /// small ids (and has no earlier run to collide with unless
    /// persistence never worked at all, which startup now warns about).
    fn id_floor() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    /// A job that was Downloading when the daemon stopped comes back
    /// Queued, so the scheduler restarts it and its journal resumes the
    /// transfer.
    pub(super) fn load_queue(&self) {
        // Before anything reads a job's out_dir: put back a download that
        // an interrupted replace left in limbo.
        recover_interrupted_publishes(&self.out_dir());
        let path = self.spool.join("queue.json");
        // A torn/corrupt file falls back to the .bak of the last good
        // parse - never "start empty" and let the next save_queue make
        // the loss permanent.
        // §129 1a: history has its own store now. Replay it FIRST so the
        // legacy-migration merge below can prefer the newer layout when
        // both name an id (a crash between the split's two writes).
        let (stored_hist, wants_compaction) = self.history_replay();
        let (v, mut legacy_hist) = match crate::persist::load_json_with_backup(&path) {
            Some(v) => {
                let legacy = v
                    .get("history")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                (Some(v), legacy)
            }
            None => (None, Vec::new()),
        };
        // Records already living in history.jsonl win over their legacy
        // queue.json copies - the split happened, then something wrote
        // history.jsonl, then the queue.json rewrite was lost.
        legacy_hist.retain(|r| {
            r.get("nzo_id")
                .and_then(Value::as_str)
                .is_none_or(|id| !stored_hist.iter().any(|j| j.nzo_id == id))
        });
        let migrating = !legacy_hist.is_empty();
        let queue_arr = v
            .as_ref()
            .and_then(|v| v.get("queue"))
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let (queued, from_file) = restore_records(&queue_arr, &legacy_hist);
        // `from_file` is the legacy history records plus any terminal
        // records restore_records routed OUT of the queue array
        // (interrupted post-processing). Order for the final Vec, oldest
        // first: legacy array, then the store's records, then the routed
        // ones (they finished last, mid-shutdown). A routed record whose
        // park already reached history.jsonl before the crash keeps the
        // store's copy.
        let legacy_ids: std::collections::HashSet<String> = legacy_hist
            .iter()
            .filter_map(|r| r.get("nzo_id").and_then(Value::as_str))
            .map(str::to_string)
            .collect();
        let (legacy_part, routed): (Vec<Job>, Vec<Job>) = from_file
            .into_iter()
            .partition(|j| legacy_ids.contains(&j.nzo_id));
        let routed: Vec<Job> = routed
            .into_iter()
            .filter(|j| !stored_hist.iter().any(|s| s.nzo_id == j.nzo_id))
            .collect();
        let routed_any = !routed.is_empty();
        let mut history = legacy_part;
        history.extend(stored_hist);
        history.extend(routed);
        let (nq, nh) = (queued.len(), history.len());
        for job in queued {
            self.register_cat(&job.category);
            self.queue.lock_ok().push_back(Arc::new(Mutex::new(job)));
        }
        for job in history {
            self.register_cat(&job.category);
            self.history.lock_ok().push(Arc::new(Mutex::new(job)));
        }
        let v = match v {
            Some(v) => v,
            None => {
                // No queue.json at all, but maybe a history store.
                if wants_compaction {
                    self.history_compact();
                }
                self.history_enforce_retention();
                if nh > 0 {
                    info!(target: "queue", "restored {nh} history jobs");
                }
                return;
            }
        };
        if let Some(n) = v.get("next_id").and_then(Value::as_u64) {
            // Never reuse an id - SABnzbd clients key on nzo_id uniqueness,
            // and stream tokens are H(secret, nzo_id): a reused id would
            // hand a previous job's permanent capability URL to a NEW job.
            // The persisted allocator alone cannot guarantee that (the
            // snapshot write is best-effort and an enqueue whose snapshot
            // failed already returned its id and token), so the wall-clock
            // floor below keeps allocations ahead of any earlier run's
            // even when its snapshots never landed.
            let cur = self.next_id.load(Ordering::Relaxed);
            self.next_id
                .store(n.max(cur).max(Self::id_floor()), Ordering::Relaxed);
        }
        // The one-time split, and the store's own housekeeping. Compact
        // FIRST (it writes every live record, so migrated and routed
        // rows land in history.jsonl), then rewrite queue.json without
        // its history array - in that order, so a crash between the two
        // duplicates records into both files (deduped above on the next
        // boot) rather than losing them from both.
        if migrating || routed_any || wants_compaction {
            self.history_compact();
        }
        if migrating {
            self.save_queue();
            info!(
                target: "queue",
                "history moved out of queue.json into its own store ({} records)",
                nh
            );
        }
        self.history_enforce_retention();
        if nq + nh > 0 {
            info!(target: "queue", "restored {nq} queued + {nh} history jobs");
        }
    }
}

#[cfg(test)]
#[path = "daemon_tests.rs"]
mod daemon_tests;

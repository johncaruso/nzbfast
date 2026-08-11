//! Managed connection pool with pipelining (design: Phase 2b).
//!
//! Design inputs, all paid for empirically:
//! - Pipelining wins +170% on fibre - keep `window` commands in flight.
//! - Providers punish connect bursts → connections spawn with a ramp delay
//!   and are REUSED for the whole run, never churned.
//! - Providers stall reads mid-article under load → per-response timeout;
//!   a stalled/dead connection requeues its in-flight articles and the
//!   worker reconnects with backoff.
//! - Sessions linger server-side after abrupt closes → always QUIT.
//! - Retry taxonomy from the NNTP response codes: transport failures retry (bounded); a 430
//!   "no such article" is authoritative for this server - no retry.

use crate::sync::MutexExt;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tracing::{error, info, warn};

use tokio::sync::{Mutex, mpsc};

use crate::config::ServerConfig;
use crate::nntp::Connection;

/// Reusable article-body buffers. Kills the per-article 800 KB
/// alloc/free churn (mmap + page-zero + TLB shootdowns) on the hot path.
/// Consumers hand buffers back with `give()` once decoded/written.
pub struct BufPool {
    bufs: std::sync::Mutex<Vec<Vec<u8>>>,
    max_held: usize,
}

impl BufPool {
    pub fn new(max_held: usize) -> Arc<BufPool> {
        Arc::new(BufPool {
            bufs: std::sync::Mutex::new(Vec::new()),
            max_held,
        })
    }

    pub fn take(&self) -> Vec<u8> {
        self.bufs
            .lock()
            .unwrap()
            .pop()
            .unwrap_or_else(|| Vec::with_capacity(800 * 1024))
    }

    pub fn give(&self, mut buf: Vec<u8>) {
        buf.clear();
        // Drop a buffer that a single oversized read grew far past the
        // normal article size - clear() keeps capacity, so retaining it
        // would pin that allocation in the pool for the rest of the run.
        // Anything up to 4 MB is a plausible large article; beyond that,
        // let it free and hand back a right-sized buffer next take().
        const KEEP_CAP: usize = 4 * 1024 * 1024;
        if buf.capacity() > KEEP_CAP {
            return;
        }
        let mut bufs = self.bufs.lock_ok();
        if bufs.len() < self.max_held {
            bufs.push(buf);
        }
    }
}

/// Pool-level download speed limiter (M14g): one shared coarse token
/// window charged by every worker of every server after each article body
/// read. 0 = unlimited. Deliberately cheap and coarse (±10% is fine) -
/// one mutex'd (window_start, bytes) pair, workers sleep off any debt
/// asynchronously so runtime threads are never blocked.
pub struct RateLimit {
    bytes_per_sec: AtomicU64,
    /// Virtual clock: the instant the next charged byte is allowed to
    /// land. See [`RateLimit::throttle`].
    next: std::sync::Mutex<Instant>,
    /// Bumped whenever the cap changes, so a worker already sleeping
    /// against the OLD cap stops waiting instead of stranding.
    generation: AtomicU64,
}

impl Default for RateLimit {
    fn default() -> Self {
        RateLimit {
            bytes_per_sec: AtomicU64::new(0),
            next: std::sync::Mutex::new(Instant::now()),
            generation: AtomicU64::new(0),
        }
    }
}

impl RateLimit {
    pub fn new(bytes_per_sec: u64) -> Arc<RateLimit> {
        let rl = RateLimit::default();
        rl.set(bytes_per_sec);
        Arc::new(rl)
    }

    /// Change the cap live. 0 = unlimited.
    ///
    /// A change restarts the virtual clock and bumps the generation:
    /// reservations priced against the old cap are neither re-priced nor
    /// left holding workers, which is what the old 5-second sleep clamp
    /// was reaching for.
    pub fn set(&self, bytes_per_sec: u64) {
        if self.bytes_per_sec.swap(bytes_per_sec, Ordering::Relaxed) == bytes_per_sec {
            return;
        }
        *self.next.lock_ok() = Instant::now();
        self.generation.fetch_add(1, Ordering::Relaxed);
    }

    pub fn get(&self) -> u64 {
        self.bytes_per_sec.load(Ordering::Relaxed)
    }

    /// Charge `n` bytes against the cap and sleep off any debt so the
    /// aggregate rate stays under `bytes_per_sec`. No-op when unlimited.
    ///
    /// A virtual clock, not a byte window: each charge reserves the slice
    /// of wall time its own bytes are worth AT THE CAP IN FORCE WHEN IT
    /// IS CHARGED, and the caller waits out that slice. N workers
    /// therefore queue behind one another and the aggregate rate is the
    /// cap by construction, at any connection count or article size.
    ///
    /// The byte-window version this replaces could not do that. Its sleep
    /// was clamped to 5 s so that a live cap decrease could not strand a
    /// worker against stale debt - but nothing ever forgave that debt,
    /// and its only discharge path (the re-anchor) required the window to
    /// be paid off, which the clamp itself made unreachable. Once the
    /// aggregate settled above the cap it stayed there: every call slept
    /// exactly 5 s forever and the real floor was `connections *
    /// article_size / 5 s` - about 1.28 MB/s at the shipped default of 8
    /// connections, so any cap under ~10 Mbit/s was silently exceeded
    /// with no log line. It also made the --auto-speed governor's whole
    /// back-off range a no-op, since AUTO_SPEED_FLOOR sits inside it.
    /// Forgiving the debt and enforcing the cap are mutually exclusive in
    /// that formulation, which is why the clamp looks reasonable and is
    /// nonetheless wrong; pricing each charge when it is charged removes
    /// the need for either.
    pub async fn throttle(&self, n: u64) {
        let cap = self.bytes_per_sec.load(Ordering::Relaxed);
        if cap == 0 || n == 0 {
            return;
        }
        let generation = self.generation.load(Ordering::Relaxed);
        let deadline = {
            let mut next = self.next.lock_ok();
            let now = Instant::now();
            // `.max(now)` is what stops an idle line banking credit: a
            // clock left behind in the past resumes from now, not from
            // where it stopped.
            let start = (*next).max(now);
            *next = start + Duration::from_secs_f64(n as f64 / cap as f64);
            *next
        };
        // Sliced rather than one long sleep so that a live cap change is
        // noticed within a second even when the reservation is minutes
        // long (a very low cap against a large article).
        loop {
            let now = Instant::now();
            if now >= deadline || self.generation.load(Ordering::Relaxed) != generation {
                return;
            }
            tokio::time::sleep((deadline - now).min(Duration::from_secs(1))).await;
        }
    }
}

/// Live per-server connection target (TODO 112): how many of a server's
/// spawned workers may hold a session RIGHT NOW.
///
/// The fleet is still built at `PoolConfig::connections` - that number
/// is the ceiling, the account fact the user typed - but every worker
/// knows its slot ordinal and parks, holding no connection, while its
/// ordinal sits at or above this target. An outside controller (the
/// live tuner) can therefore move the number in use up and down mid-run
/// without the pool respawning anything: lowering the target drains the
/// highest slots at their next response boundary; raising it wakes
/// them. Nothing here ever writes a settings value - the target is
/// state, not configuration.
///
/// Distinct from the capacity yield (481/502), which is the PROVIDER
/// shrinking the fleet and is one-way for the run: a yielded worker has
/// returned and cannot be woken. This is the controller's dial, and it
/// moves both directions.
#[derive(Debug)]
pub struct ConnTarget {
    tx: tokio::sync::watch::Sender<usize>,
}

impl ConnTarget {
    pub fn new(target: usize) -> Arc<Self> {
        Arc::new(Self {
            tx: tokio::sync::watch::channel(target.max(1)).0,
        })
    }

    pub fn get(&self) -> usize {
        *self.tx.borrow()
    }

    /// Move the live target. Clamped to at least one connection: a
    /// target of 0 would park the whole fleet with the queue still
    /// pending, which is the `connections: 0` hang this file already
    /// refuses at spawn. Slots above the spawned fleet size are simply
    /// not there to wake, so the fleet size is the natural ceiling.
    pub fn set(&self, target: usize) {
        self.tx.send_if_modified(|t| {
            let n = target.max(1);
            if *t == n {
                false
            } else {
                *t = n;
                true
            }
        });
    }

    fn subscribe(&self) -> tokio::sync::watch::Receiver<usize> {
        self.tx.subscribe()
    }
}

/// Park this worker while its slot ordinal is at or above the live
/// target. Returns false if the run ended (or began draining) while
/// parked - the caller must retire, not dial.
///
/// The caller has already returned any connection it held: a parked
/// worker costs the provider nothing.
async fn wait_for_slot(
    target: &ConnTarget,
    slot: u32,
    finished: &mut tokio::sync::watch::Receiver<bool>,
    shared: &Shared,
) -> bool {
    let mut rx = target.subscribe();
    loop {
        if (slot as usize) < *rx.borrow_and_update() {
            return true;
        }
        tokio::select! {
            r = rx.changed() => {
                // Controller gone with the target parked low: admit the
                // slot rather than strand it. The sender lives inside
                // the PoolConfig clones, so in practice this outlives
                // the run.
                if r.is_err() {
                    return true;
                }
            }
            _ = run_over(finished, shared) => return false,
        }
    }
}

#[derive(Clone)]
pub struct PoolConfig {
    pub connections: usize,
    /// Pipelined BODY commands in flight per connection.
    pub window: usize,
    /// Stagger between connection spawns (connect-burst avoidance).
    pub ramp_delay: Duration,
    /// Transport-failure attempts per article before reporting Failed.
    pub article_retries: u8,
    /// Per-response read timeout (stall detection).
    pub read_timeout: Duration,
    /// TODO 96.1, graduated to the "Adaptive connection timeouts"
    /// setting (adaptive_timeouts, ON by default; env
    /// NZBFAST_ADAPTIVE_TIMEOUT overrides in either direction):
    /// replace the flat whole-response `read_timeout` with a two-phase
    /// bound - an adaptive pre-byte budget from the server's TTFB EWMA
    /// (dead connections detected in 2-10 s instead of 30) plus a
    /// progress-rolling stall deadline on the body (a slow-but-alive
    /// transfer is never killed for exceeding a flat cap).
    pub adaptive_timeout: bool,
    /// Backoff after a failed connect, doubled per consecutive failure.
    pub connect_backoff: Duration,
    /// Consecutive connect failures before a worker gives up.
    pub max_connect_attempts: u32,
    /// Paced dials the elected prober rides before declaring a parked
    /// server dead (see [`CAP_PROBE_BOUNCES`], the shipped default).
    /// Configurable for tests only: the ladder is paced off
    /// `connect_backoff`, so a test that shrinks the backoff to keep
    /// the suite quick is left paying 75 REAL connect attempts, and
    /// what one of those costs is the platform's business, not ours -
    /// a refused loopback connect is microseconds on macOS and ~2 s on
    /// Windows, where its SYN is retried. 75 x 2 s outlasted the seal
    /// test's whole budget and read as a pool hang on Windows alone.
    /// Production never notices: at the default 8 s backoff the ladder
    /// is backoff-dominated and a slow refusal is noise.
    pub cap_probe_bounces: u32,
    /// Shared body-buffer pool; None = allocate per article.
    pub buf_pool: Option<Arc<BufPool>>,
    /// Live per-server gauges for dashboards (M14h); None = don't track.
    pub live: Option<Arc<LiveStats>>,
    /// TODO 112: live connection target for THIS server; None = every
    /// spawned worker runs, the old behaviour. See [`ConnTarget`].
    pub live_target: Option<Arc<ConnTarget>>,
    /// Shared pool-level speed limiter; None = unlimited.
    pub rate: Option<Arc<RateLimit>>,
    /// M29 availability oracle: per-article hit/430 outcomes accumulate
    /// here (in memory - the daemon flushes to the ledger per job).
    /// None = don't record.
    pub oracle: Option<Arc<crate::oracle::OracleSink>>,
    /// B3 wire-cap: global in-flight body byte ceiling across the whole
    /// pool (see MemBudget::inflight_cap). Over it, workers stop topping
    /// up their pipeline beyond one request in flight. 0 = uncapped.
    pub inflight_cap: u64,
    /// Connections that outlive this run (see [`crate::warmpool`]).
    /// None = the old behaviour, connect per run and QUIT at the end,
    /// which is still right for a one-shot CLI `get`.
    pub warm: Option<Arc<crate::warmpool::WarmPool>>,
    /// Tail fan-out prototype (off by default, env NZBFAST_TAIL_FANOUT=1):
    /// in the endgame, an IDLE primary connection races a healthy
    /// in-flight article too - same server included - instead of only
    /// the 430-laddering ones. First completion wins, the loser's read
    /// is abandoned, so the waste is bounded to bytes-in-flight at win
    /// time. See `pick_dup` for the exact gates.
    pub tail_fanout: bool,
    /// M7b.2 depth steering (dark, env NZBFAST_STEER_DEPTH=1): a server
    /// whose windowed per-conn rate falls below 1/4 of the best other
    /// live server's tops its pipelines up to depth 1 instead of
    /// `window`, restoring above 1/2 (hysteresis; thresholds env-tunable
    /// while open question 9.3 of the steering design collects measured
    /// values). Full participation at bounded commitment - never a
    /// demotion (§129 3d): the server keeps every connection fetching,
    /// it just stops parking `window` articles behind each slow session.
    /// The clamp gates TOP-UP only; an already-deep pipeline drains
    /// naturally (no shed - that would be a different, gated feature).
    pub steer_depth: bool,
    /// M7b.2 envelope racing (dark, env NZBFAST_RACE_ENVELOPE=1):
    /// per-owner hedge bounds, the idle-picker envelope-race arm, and
    /// the fleet-wide dup-spend hygiene cap; the whole-run 2x
    /// slow-owner rule retires while armed. See `steer::speculative_arm`.
    pub race_envelope: bool,
    /// Steering design §5.7: every byte on this server costs money -
    /// spend none deliberately. Excludes it from all speculative dup
    /// pickers; the endgame verdict ladder and the CRC-steer refetch
    /// stay eligible (last-resort/only-source). Per-server, never
    /// OR-folded; wired from the server's block_account setting.
    pub block_account: bool,
    /// Hedged-request experiment (off by default, env NZBFAST_HEDGE=1):
    /// replace the flat 8 s staleness bound in the dup race with an
    /// adaptive one - 3x the trained dispatch-to-done article-time EWMA,
    /// clamped to [500 ms, 8 s] - so a mid-run straggler is raced after
    /// roughly three article-times instead of a flat 8 s. Hedge issue
    /// rate is capped (see `pick_dup`) so jitter cannot turn into a
    /// duplicate storm.
    pub hedge: bool,
    /// TTFB-suspicion hedge (TODO 115, off by default, env
    /// NZBFAST_TTFB_HEDGE=1): when an adaptive-path read has sat in
    /// PRE-BYTE silence past a suspicion bound (~1 s, or 2x the
    /// server's TTFB EWMA if that is larger), the article is marked
    /// suspect and any topping-up worker dup-races it IMMEDIATELY -
    /// same server included - instead of waiting out the full adaptive
    /// pre-byte budget (floor 2 s) plus a requeue round-trip. First
    /// answer wins, the owner's read is never killed, and every
    /// suspect dup counts against the hedge issue-rate cap so jitter
    /// cannot turn suspicion into a duplicate storm. Only meaningful
    /// with `adaptive_timeout` (the flat read has no pre-byte phase).
    pub ttfb_hedge: bool,
    /// Slow-connection recycle experiment (off by default, env
    /// NZBFAST_RECYCLE_SLOW=1): a connection whose articles keep LOSING
    /// dup races is a degraded TCP session - after
    /// [`RECYCLE_RACE_LOSSES`] consecutive losses it sheds its pipeline
    /// and redials instead of continuing to lose. Racing fixes the
    /// symptom per article; this fixes the cause. Endgame losses never
    /// count: the tail fan-out races every straggler, and losing a
    /// speculative race is not degradation evidence (TODO 111).
    pub recycle_slow: bool,
    /// Slope-recycle experiment (off by default, env
    /// NZBFAST_RECYCLE_SLOPE=1): a session whose own delivery rate sits
    /// below a quarter of its server's per-worker average after 10 s is
    /// a degraded TCP session - redial it proactively, before it loses
    /// races or strands a tail article. The reactive `recycle_slow`
    /// waits for the damage; this watches the slope.
    pub recycle_slope: bool,
    /// Hot-spare experiment (off by default, env NZBFAST_HOT_SPARE=1):
    /// keep ONE authenticated spare connection parked per server during
    /// the run; a worker whose session dies claims it instantly instead
    /// of paying dial + TLS + auth in its critical path, and a filler
    /// task re-dials the spare in the background. The spare is +1 over
    /// the configured budget - a provider at its cap simply refuses it,
    /// which costs nothing.
    pub hot_spare: bool,
    /// Early fan-out experiment (env NZBFAST_TAIL_FANOUT=2, which also
    /// implies `tail_fanout`): arm the endgame dup rules from the
    /// moment the queue runs dry (the pool's tail latch) instead of
    /// waiting for pending <= ENDGAME_MAX. With a big fleet the queue
    /// dries with far more than 64 articles in flight - 48 connections
    /// at window 4 is ~190 - and that whole stretch has idle capacity
    /// the endgame gate refuses to spend. Earlier than queue-dry is
    /// meaningless by construction: no worker is idle before it.
    pub tail_fanout_early: bool,
    /// Flap breaker (ON by default): a server whose ESTABLISHED
    /// sessions keep dying - an external party burning its IP cap, a
    /// provider throttling the account - is clamped to ONE keeper
    /// connection for the rest of the run, as long as another server is
    /// live. The keeper retries (and serves, whenever the provider lets
    /// it in); the rest of the fleet stops churning through
    /// shed-pipeline/redial cycles and its capacity flows to healthy
    /// servers through the shared queue. Without this, a
    /// flapping-but-occasionally-working server never quiets down: the
    /// occasional good session clears the failure counters that retire
    /// a DEAD one.
    pub flap_breaker: bool,
    /// Cap-aware flap keepers (ON by default since the 5 Aug
    /// graduation, env NZBFAST_FLAP_CAP_KEEPERS overrides either way,
    /// TODO 115): when the flap breaker
    /// clamps a server whose accept cap we have OBSERVED (dials bounced
    /// off a capacity refusal while N sessions were established), hold
    /// min(observed cap, configured connections) keepers instead of a
    /// flat one. The eweka IP-cap shape allows two sessions; a single
    /// keeper leaves the second slot - throughput the provider is
    /// willing to give us - on the table (fault matrix 5 Aug: NZBGet
    /// takes it, but with 217 dials of hammering; ours stays in the
    /// tens because keepers redial only when their own session dies and
    /// back off paced on any capacity bounce, never a tight loop).
    /// Never exceeds the per-server connection budget, which is where
    /// account limits (and max_source_ips-derived caps) already landed.
    /// Graduation evidence (standalone chaos flap leg, one box, one
    /// corpus): 43/43 s at 24 dials off, 40/40 s at 36 dials on - a
    /// wall that ties the best competitor while dialling a refusing
    /// provider 6x less than it does.
    pub flap_cap_keepers: bool,
    /// Consumer-triggered CRC retry-elsewhere (TODO 111/114): a body
    /// that fails its own yEnc pcrc32 - or decodes to a different part
    /// than the segment asked for (split-brain; its CRC passes) - is
    /// requeued to a DIFFERENT server exactly once instead of riding
    /// to PAR2 repair. Detection is the decode consumer's EXISTING
    /// pass, reported back through [`QueueControl::note_decoded`]: a
    /// Done outcome defers its `complete_one` and parks its Work in
    /// `Shared::handed` until the verdict, and a bad body is requeued
    /// after claim, the clean refetch re-claiming through the normal
    /// arbitration. (The first cut validation-decoded in the pool -
    /// ~25% CPU at the loopback ceiling; the consumer seam priced at
    /// off-parity CPU, which is why the multi-server pricing gate
    /// could go.) Requires a consumer that actually calls
    /// `note_decoded` for every Done it receives; the download
    /// pipeline's decode consumers do, the other pool users (repair,
    /// nettools, post) leave this off.
    pub crc_steer: bool,
    /// §129 3g: follow every BODY to a provider that has answered a
    /// refusal with no message-id with an alignment fence - a DATE,
    /// pipelined behind it, whose answer cannot be mistaken for a
    /// BODY's ([`Connection::send_fence`]). It is what makes positional
    /// attribution CHECKABLE on a provider that gives us nothing to
    /// check: without it a response dropped upstream is invisible, and
    /// a present article silently collects the refusal meant for the
    /// article behind it.
    ///
    /// On by default, off with `NZBFAST_DESYNC_FENCE=0`. It costs one
    /// six-byte command and one short answer per article, only against
    /// providers that refuse bare, and no round trips - the fence rides
    /// the same pipeline. What it buys is in `provider_demote_rig`:
    /// re-arming the confirming repeat alone still leaked a present
    /// article once in 11 runs at 1-in-7 withheld responses, because
    /// the proof of a desync can arrive AFTER the verdict it should
    /// have stopped. The fence removes the misattribution instead of
    /// undoing it.
    pub desync_fence: bool,
    /// TODO 121.4: the consumer acks every Done id (`note_settled`, or
    /// `note_decoded` under `crc_steer`), so the pool keeps the
    /// article's `done_ok` liveness entry until the body is DECODED
    /// AND WRITTEN, not merely accepted by the outcome channel. That
    /// closes the dead-span verdict's last blind window - a body
    /// sitting in the channel buffer or a decode worker's in-hand
    /// batch under disk backpressure - which could outlast the
    /// grace-plus-votes threshold and let /stream zero-fill bytes it
    /// already had. Same contract as `crc_steer`: only turn this on
    /// for pools whose consumer really acks every Done (the download
    /// pipeline's decode consumers); an ack-less consumer would leak
    /// the set and pin every span "live" forever.
    pub arrival_ack: bool,
}

/// Live per-server gauges, updated by workers with relaxed atomics and
/// readable at any moment (the dashboard's connection-pool view).
pub struct LiveStats {
    pub servers: Vec<ServerLive>,
    /// A capped ring of timestamped pool events, so a throughput dip can
    /// be ATTRIBUTED after the fact instead of guessed at.
    ///
    /// The gauges above are levels: they say what is true now, and a
    /// counter that has been climbing all run cannot tell you that
    /// something happened at 22:59. A dip is an event at a moment, and
    /// until this existed the daemon recorded no moments at all - the
    /// pool counted reconnects into a `PoolStats` field that only the
    /// CLI ever read, and the capacity warning fired `if first`, so the
    /// second and third bounce of a run were silent by construction.
    /// One real dip on a 59 GB job had NOTHING anywhere to explain it.
    ///
    /// Capped and timestamped rather than logged: the log is the wrong
    /// shape (a flapping provider floods it, and nothing aligns it with
    /// the graph), while a bounded ring the UI can overlay on the
    /// throughput trace answers the only question worth asking - what
    /// else was happening at the moment the line fell over.
    pub events: std::sync::Mutex<std::collections::VecDeque<PoolEvent>>,
    /// Run-level racing gauges (M7b.2): dup spend and the hygiene-cap
    /// state, for `report_diagnostics`' consumers and the "Why is this
    /// slow?" panel. See [`steer::RaceLive`].
    pub race: steer::RaceLive,
}

/// One thing that happened to the pool, at a moment.
#[derive(Debug, Clone)]
pub struct PoolEvent {
    /// Unix milliseconds. The dashboard's throughput samples carry their
    /// own wall-clock, so this is what lets the two be laid on top of
    /// each other; a monotonic instant could not cross the API.
    pub at_ms: u64,
    pub host: String,
    /// `reconnect` | `rotate` | `cap` | `blocked` | `retired` |
    /// `missing` | `racing` | `timeout` | `tail` | `drained` - see
    /// [`LiveStats::note`]. The dashboard groups these into severity
    /// classes (fault / tuning / recovery / phase), so a new kind must
    /// be added to its map or it draws in the fallback colour.
    ///
    /// `rotate` vs `reconnect` is the load-bearing split: a session WE
    /// ended on purpose (pre-byte budget, live-target park, promote
    /// shed, slow-session recycle) is the tuner doing its job, and
    /// painting it as a fault taught a flawless 3.3 Gbps run to read
    /// as a failing-connections incident (38 red dots, 7 Aug 2026).
    pub kind: &'static str,
    /// Free text for the user, already specific: the provider's own
    /// refusal line, or the reason a session ended.
    pub detail: String,
}

/// How many events are kept. At the rate a healthy run generates them
/// this is hours; at the rate a sick one does it is the last few
/// minutes, which is exactly the window someone stares at a dip in.
/// Public because a caller that filters by TIME has to ask for the
/// whole ring: `recent_events` takes a COUNT, so any smaller number
/// drops the oldest events in the window before the time filter ever
/// sees them.
pub const EVENT_RING: usize = 256;

/// How long a worker must wait on the write side before it is worth
/// marking. A full channel is the pipeline working as designed - bodies
/// arrive faster than they decode all the time - so the threshold is set
/// where a pause stops being normal and starts being something a person
/// would notice in the graph.
const BLOCKED_NOTE_MS: u64 = 500;

/// Windowed burst notes (missing-article bursts, duplicate racing): at
/// most one marker per server (or per run, for racing) per window,
/// emitted when a window closes with at least the threshold inside it.
/// A marker can land up to one window after the burst began, which is
/// invisible at chart scale - what matters is that a storm of 430s or
/// dups can never flood the ring the way one event per response would,
/// exactly the discipline `BLOCKED_NOTE_MS` set.
const BURST_WINDOW_MS: u64 = 10_000;

/// 430/423 responses from one server inside one window that earn a
/// missing-articles marker. Scattered misses are normal (that is what
/// the retry ladder is for); a burst this size is a take-down or a
/// backfill hole and it bends the graph.
const MISSING_BURST: u64 = 25;

/// Duplicate + hedge dispatches inside one window that mark a racing
/// spike. The tail of every job issues a handful; a sustained spike
/// means the pool is fighting slow articles hard enough to show.
const RACE_BURST: u64 = 12;

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub struct ServerLive {
    pub host: String,
    /// Connection budget: the number of workers the run intends to use
    /// on this server. Atomic because the live tuner (TODO 112) moves
    /// its [`ConnTarget`] mid-run and this gauge must follow; without a
    /// tuner it holds the spawn count for the whole run.
    pub budget: AtomicUsize,
    /// Workers currently holding an open NNTP session.
    pub connected: AtomicUsize,
    /// Raw bytes fetched by this server this run.
    pub bytes: AtomicU64,
    /// Article dispatches sent to this server this run (reliability
    /// denominator - dups and retries each count as a try).
    pub articles_tried: AtomicU64,
    /// 430/423 "no such article" responses from this server this run
    /// (reliability numerator: completion = 1 - missing/tried).
    pub articles_missing: AtomicU64,
    /// §35: the provider's own words when it refused to authenticate,
    /// and whether that refusal is permanent.
    ///
    /// Without this a user with one expired or capped provider pays for
    /// it on every download - the server contributes nothing - and has
    /// nothing anywhere in the UI saying why. The pool already knows;
    /// this carries it out to the dashboard verbatim, because the
    /// provider's own sentence ("max simultaneous IP addresses reached")
    /// tells the user what to do and our paraphrase would not.
    pub refusal: std::sync::Mutex<Option<Refusal>>,
    /// Sessions this server lost and redialled MID-RUN (the first
    /// connect is not one). The pool has always counted these into
    /// `PoolStats::reconnects`, but only the one-shot CLI ever read that
    /// - on the daemon path a worker whose socket died and came back was
    /// invisible, which is the single most likely cause of a dip that
    /// leaves the job itself undamaged.
    pub reconnects: AtomicU64,
    /// Milliseconds this server's workers spent parked because the
    /// fetch→decode channel was FULL - i.e. waiting on everything
    /// downstream (decode, verify, the disk), not on the network.
    ///
    /// This is the half that makes a dip diagnosable rather than merely
    /// visible. Both causes look identical on the throughput graph, and
    /// they have opposite remedies: if the line fell while this was
    /// climbing, the network was fine and the write side could not keep
    /// up (an external enclosure hiccuping, a slow volume); if it fell
    /// while `reconnects` moved instead, it was the provider. Measuring
    /// only one of them would have let every dip be blamed on the one we
    /// happened to instrument.
    pub blocked_ms: AtomicU64,
    /// Unix ms of the last `blocked` event noted for this server, so a
    /// genuinely stalled disk marks the graph once a second instead of
    /// once per article. Without it a bad enough stall would flush the
    /// whole ring with its own events and erase the reconnects sitting
    /// beside them - the instrumentation would destroy the comparison it
    /// exists to make.
    pub last_blocked_note: AtomicU64,
    /// Missing-article burst window: when the current window opened
    /// (unix ms, 0 = not yet opened) and what `articles_missing` read at
    /// that moment. See [`LiveStats::note_missing_burst`].
    pub missing_note_at: AtomicU64,
    pub missing_at_note: AtomicU64,
    /// Unix ms of the last adaptive-timeout marker, same once-a-second
    /// discipline as `last_blocked_note` - a provider gone slow expires
    /// budgets on every worker at once.
    pub last_timeout_note: AtomicU64,
    /// Session-end causes; see [`SessionEnds`]. Same counters the CLI
    /// census prints, kept live for the dashboard.
    pub ends_peer: AtomicU64,
    pub ends_protocol: AtomicU64,
    pub ends_prebyte: AtomicU64,
    pub ends_stall: AtomicU64,
    pub ends_ours: AtomicU64,
    /// M7b.2 PUBLISHED CONTRACT for the live connection tuner (steering
    /// design §4.3; full semantics in the pool `steer` module doc):
    /// windowed delivered rate in B/s as of the last fold (~10 s
    /// half-life, 0 until the first body - read against `srv_rate_at`,
    /// the unix-ms fold stamp), the per-server dispatch-to-done EWMA,
    /// and the `steered` demand bit (true while depth-clamped or
    /// frontier-passed: a rate drop with it set is our own steering,
    /// not a provider knee). Demand-inclusive, fed only from real
    /// delivered bodies - do not rename or filter.
    pub srv_rate: AtomicU64,
    pub srv_rate_at: AtomicU64,
    pub srv_art_ms: AtomicU64,
    pub steered: AtomicBool,
}

/// A server's refusal to authenticate, as shown to the user.
#[derive(Debug, Clone)]
pub struct Refusal {
    /// True when retrying cannot help (bad credential), false when the
    /// server is simply at a connection or IP cap right now.
    pub permanent: bool,
    /// The server's status line, verbatim.
    pub line: String,
}

impl LiveStats {
    pub fn for_servers(servers: &[(ServerConfig, PoolConfig)]) -> Arc<LiveStats> {
        Arc::new(LiveStats {
            servers: servers
                .iter()
                .map(|(s, cfg)| ServerLive {
                    host: s.host.clone(),
                    // With a live target in force the number in use is
                    // the target, not the spawn count - slots above it
                    // park immediately.
                    budget: AtomicUsize::new(
                        cfg.live_target
                            .as_ref()
                            .map_or(cfg.connections, |t| t.get().min(cfg.connections)),
                    ),
                    connected: AtomicUsize::new(0),
                    refusal: std::sync::Mutex::new(None),
                    bytes: AtomicU64::new(0),
                    articles_tried: AtomicU64::new(0),
                    articles_missing: AtomicU64::new(0),
                    reconnects: AtomicU64::new(0),
                    ends_peer: AtomicU64::new(0),
                    ends_protocol: AtomicU64::new(0),
                    ends_prebyte: AtomicU64::new(0),
                    ends_stall: AtomicU64::new(0),
                    ends_ours: AtomicU64::new(0),
                    blocked_ms: AtomicU64::new(0),
                    last_blocked_note: AtomicU64::new(0),
                    missing_note_at: AtomicU64::new(0),
                    missing_at_note: AtomicU64::new(0),
                    last_timeout_note: AtomicU64::new(0),
                    srv_rate: AtomicU64::new(0),
                    srv_rate_at: AtomicU64::new(0),
                    srv_art_ms: AtomicU64::new(0),
                    steered: AtomicBool::new(false),
                })
                .collect(),
            events: std::sync::Mutex::new(std::collections::VecDeque::new()),
            race: Default::default(),
        })
    }

    /// Record one event against a server, oldest dropped at the cap.
    ///
    /// Deliberately infallible and deliberately quiet: instrumentation
    /// that can fail, block, or log is instrumentation that changes the
    /// thing it measures. A poisoned ring is not worth a panic in a
    /// download worker, so it is simply skipped.
    pub fn note(&self, idx: usize, kind: &'static str, detail: impl Into<String>) {
        let Some(host) = self.servers.get(idx).map(|s| s.host.clone()) else {
            return;
        };
        let Ok(mut ring) = self.events.lock() else {
            return;
        };
        if ring.len() >= EVENT_RING {
            ring.pop_front();
        }
        ring.push_back(PoolEvent {
            at_ms: now_ms(),
            host,
            kind,
            detail: detail.into(),
        });
    }

    /// Record an event that belongs to the RUN, not to one server -
    /// phase boundaries (queue dry, drained) and fleet-wide spikes
    /// (duplicate racing). Same ring, empty host; the dashboard shows
    /// these without a server name.
    pub fn note_run(&self, kind: &'static str, detail: impl Into<String>) {
        let Ok(mut ring) = self.events.lock() else {
            return;
        };
        if ring.len() >= EVENT_RING {
            ring.pop_front();
        }
        ring.push_back(PoolEvent {
            at_ms: now_ms(),
            host: String::new(),
            kind,
            detail: detail.into(),
        });
    }

    /// Called on every 430/423 this server answers, AFTER
    /// `articles_missing` was bumped. Emits at most one `missing` marker
    /// per [`BURST_WINDOW_MS`] per server, and only for a window that
    /// held at least [`MISSING_BURST`] misses - scattered misses are the
    /// retry ladder's normal diet and must not mark the graph.
    pub fn note_missing_burst(&self, idx: usize) {
        let Some(s) = self.servers.get(idx) else {
            return;
        };
        let now = now_ms();
        let count = s.articles_missing.load(Ordering::Relaxed);
        let opened = s.missing_note_at.load(Ordering::Relaxed);
        if opened == 0 {
            // First miss of the run opens the first window, no marker.
            if s.missing_note_at
                .compare_exchange(0, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                s.missing_at_note
                    .store(count.saturating_sub(1), Ordering::Relaxed);
            }
            return;
        }
        if now.saturating_sub(opened) < BURST_WINDOW_MS {
            return;
        }
        // Window closed; one racer re-anchors it and judges the burst.
        if s.missing_note_at
            .compare_exchange(opened, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        let since = count.saturating_sub(s.missing_at_note.swap(count, Ordering::Relaxed));
        if since >= MISSING_BURST {
            self.note(
                idx,
                "missing",
                format!(
                    "{since} articles missing from this server in the last \
                     {} seconds",
                    BURST_WINDOW_MS / 1000
                ),
            );
        }
    }

    /// Events newest first, for the API.
    pub fn recent_events(&self, limit: usize) -> Vec<PoolEvent> {
        self.events
            .lock()
            .map(|r| r.iter().rev().take(limit).cloned().collect())
            .unwrap_or_default()
    }
}

/// Decrements the connected gauge when a session ends, however it ends.
struct ConnGauge {
    live: Option<Arc<LiveStats>>,
    idx: usize,
}

impl ConnGauge {
    fn up(live: &Option<Arc<LiveStats>>, idx: usize) -> ConnGauge {
        if let Some(l) = live {
            l.servers[idx].connected.fetch_add(1, Ordering::Relaxed);
        }
        ConnGauge {
            live: live.clone(),
            idx,
        }
    }
}

impl Drop for ConnGauge {
    fn drop(&mut self) {
        if let Some(l) = &self.live {
            l.servers[self.idx]
                .connected
                .fetch_sub(1, Ordering::Relaxed);
        }
    }
}

/// Counts an established session in `Shared::sessions` for exactly as
/// long as the worker holds it, however the session ends. The count
/// exists so a capacity bounce can be priced in sessions actually held
/// (see [`Shared::note_cap_bounce`]) - the dashboard gauge above can't
/// serve that role because `cfg.live` is optional.
struct SessionTally<'a> {
    shared: &'a Shared,
    idx: usize,
}

impl<'a> SessionTally<'a> {
    fn up(shared: &'a Shared, idx: usize) -> Self {
        shared.sessions[idx].fetch_add(1, Ordering::AcqRel);
        SessionTally { shared, idx }
    }
}

impl Drop for SessionTally<'_> {
    fn drop(&mut self) {
        self.shared.sessions[self.idx].fetch_sub(1, Ordering::AcqRel);
    }
}

impl Default for PoolConfig {
    fn default() -> Self {
        PoolConfig {
            connections: 6,
            window: 3,
            ramp_delay: Duration::from_millis(150),
            article_retries: 3,
            read_timeout: Duration::from_secs(30),
            adaptive_timeout: false,
            connect_backoff: Duration::from_secs(2),
            max_connect_attempts: 5,
            cap_probe_bounces: CAP_PROBE_BOUNCES,
            buf_pool: None,
            live: None,
            live_target: None,
            rate: None,
            oracle: None,
            inflight_cap: 0,
            warm: None,
            tail_fanout: false,
            steer_depth: false,
            race_envelope: false,
            block_account: false,
            hedge: false,
            ttfb_hedge: false,
            recycle_slow: false,
            recycle_slope: false,
            hot_spare: false,
            tail_fanout_early: false,
            flap_breaker: true,
            // The env override lives HERE, not only in build_fleet, so
            // every pool - nettools probes, post_cmd, warm-pool rigs -
            // honors NZBFAST_FLAP_CAP_KEEPERS=0 (TODO 121.3; before
            // this, a default-built pool ignored the knob entirely).
            flap_cap_keepers: std::env::var("NZBFAST_FLAP_CAP_KEEPERS")
                .ok()
                .is_none_or(|v| v == "1"),
            crc_steer: false,
            arrival_ack: false,
            // §129 3g. Default ON, with the kill switch HERE rather than
            // only in build_fleet for the same reason `flap_cap_keepers`
            // has it here: every pool must honor it.
            desync_fence: std::env::var("NZBFAST_DESYNC_FENCE")
                .ok()
                .is_none_or(|v| v == "1"),
        }
    }
}

/// One article to fetch, with the routing metadata the pool needs up
/// front. `age_days` drives per-server retention exclusion (M14e):
/// a server with `retention_days: N` never sees requests for articles
/// older than N days.
#[derive(Debug, Clone)]
pub struct ArticleReq {
    pub id: String,
    /// Article age in days (from the NZB `<file date>`); 0 = fresh/unknown.
    pub age_days: u32,
    /// Expected yEnc part number (the NZB `<segment number>`); 0 =
    /// unknown. Only the CRC-retry gate reads it: a body whose decoded
    /// part disagrees with the segment it was requested for is a valid
    /// article for the WRONG id (split-brain server) - its own pcrc32
    /// passes, so identity is the only check that can catch it.
    pub part: u32,
}

impl ArticleReq {
    /// A request with no age information - never retention-excluded.
    pub fn fresh(id: String) -> ArticleReq {
        ArticleReq {
            id,
            age_days: 0,
            part: 0,
        }
    }
}

/// Bitmask of servers whose retention window (`retention_days`, 0 =
/// unlimited) cannot cover an article `age_days` old. Seeded into a Work
/// item's `tried_430` at queue-build time so all downstream routing -
/// fill gates, dup dispatch, terminal-missing accounting - treats
/// "outside retention" exactly like "430'd here".
pub fn retention_mask(retention_days: &[u32], age_days: u32) -> u32 {
    let mut mask = 0u32;
    for (si, &days) in retention_days.iter().enumerate() {
        if days > 0 && age_days > days {
            mask |= server_bit(si);
        }
    }
    mask
}

/// Why the pool declared an article Missing. The distinction is what the
/// failure summary hangs its diagnosis on: `Retention` means WE never
/// asked anyone (a configured `retention_days` ruled every server out),
/// which is a settings problem, not a takedown - folding it into the
/// generic "missing segments" sent users hunting propagation ghosts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MissingCause {
    /// Every server still live was asked and answered 430/423.
    Gone,
    /// The article's age exceeds every configured server's
    /// `retention_days` - no server was ever asked.
    Retention,
}

/// The decode consumer's per-article verdict, reported back through
/// [`QueueControl::note_decoded`] (TODO 114 consumer steer). The
/// consumer reports only what its own decode saw; the expected part
/// number stays in the pool (`Shared::parts`), which does the
/// split-brain identity comparison itself.
#[derive(Debug, Clone, Copy)]
pub enum DecodeReport<'a> {
    /// Decode succeeded; `part` is the body's declared yEnc part
    /// number (None when it declared none).
    Clean { part: Option<u32> },
    /// yEnc decode / pcrc32 failed.
    Bad { why: &'a str },
}

/// What [`QueueControl::note_decoded`] decided about a reported body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeAck {
    /// The consumer owns the outcome exactly as before this seam
    /// existed - process (or account) the body as usual.
    Owned,
    /// The pool took the article back and requeued it to a different
    /// server. Drop the body silently: no write, no counters, no
    /// slot bookkeeping - the refetched copy delivers the outcome.
    Steered,
}

/// Terminal outcome for one article.
#[derive(Debug)]
pub enum FetchOutcome {
    /// Raw dot-stuffed body, ready for `yenc::decode`.
    Done { id: String, raw: Vec<u8> },
    /// No server can produce the article; `cause` says why.
    Missing { id: String, cause: MissingCause },
    /// Transport failures exhausted the retry budget.
    Failed { id: String, error: String },
}

#[derive(Debug, Default)]
pub struct PoolStats {
    pub bytes: u64,
    pub connects: u64,
    pub reconnects: u64,
    /// Did ANY worker ever hold a usable connection to this server (fresh
    /// dial or warm-pool hand-me-down)? False means the server sat out
    /// the entire run - unreachable, or it refused the login - so every
    /// "unanimous 430" verdict was reached without its vote. The failure
    /// summary names such servers; without that, one dead backup silently
    /// turns a single 430 into "missing segments".
    pub ever_connected: bool,
    /// WHY this server's sessions ended, counted where it happens.
    ///
    /// `reconnects` alone says a session died and was redialled; it does
    /// not say who hung up. That gap cost a whole investigation on 6 Aug
    /// 2026: a provider churning 148 sessions in one 190 GB job had six
    /// hypotheses eliminated one at a time (fan-out, hedge, slope
    /// recycle, connection count, provider idle timeout, the pre-byte
    /// budget) purely by exclusion, because "session lost, redialled"
    /// reads identically for a peer FIN, a peer reset, our own read
    /// timeout, our own quit and a protocol desync. See
    /// research/PROVIDER-CHURN-2026-08-06.md.
    pub ends: SessionEnds,
    /// Milliseconds this server's workers spent parked because the
    /// fetch->decode channel was FULL - i.e. waiting on decode, verify
    /// and the disk rather than on the network. The daemon has always
    /// had this (`ServerLive::blocked_ms`); the CLI did not, so a
    /// bench leg could not tell a NETWORK dip from a WRITE-SIDE dip -
    /// which is exactly the question a periodic throughput sawtooth
    /// asks (6 Aug: full rate for 8-9 s, then a drop to 8-21% of peak,
    /// repeating, costing ~12-15% of an 87 GB job).
    pub blocked_ms: u64,
}

/// Per-server tally of how sessions ENDED, by cause.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SessionEnds {
    /// The peer closed or reset the connection, or the socket failed
    /// under us: an I/O-flavoured `NntpError`. THIS is "the provider
    /// hung up on us".
    pub peer: u64,
    /// A well-formed but unusable answer - the response did not parse,
    /// or the echoed message-id did not match what we asked for.
    pub protocol: u64,
    /// Our own pre-first-byte budget expired: the server had not
    /// started answering in time. Distinguished from `stall` because
    /// giving up pre-byte is our budget CHOICE, not evidence the peer
    /// is dead (TODO 121.1).
    pub prebyte: u64,
    /// Our own mid-flow deadline expired: bytes were moving and
    /// stopped. That is a genuine wedge.
    pub stall: u64,
    /// We hung up deliberately - shed for promoted work, over the live
    /// connection target, or a pipeline deeper than a mid-window cap.
    pub ours: u64,
}

/// M11 seek re-prioritization: a live handle to a running fetch's pending
/// queue. The streaming layer promotes the articles under a player's seek
/// point to the queue front; workers pick them up on their next pop.
/// Holds the pool by Weak - the handle can outlive the run harmlessly
/// (promote becomes a no-op once the pool is gone). Anything the caller
/// still needs to read AFTER the run returns has to be latched on the
/// handle itself; see `drained`.
#[derive(Default)]
pub struct QueueControl {
    shared: std::sync::Mutex<Option<std::sync::Weak<Shared>>>,
    /// Latched copy of `Shared::draining`. The pool's last strong `Arc` dies
    /// with the fetch call, so by the time the engine asks whether the run
    /// wound down gracefully the Weak above no longer upgrades - the answer
    /// has to live on the handle the caller still holds.
    drained: AtomicBool,
}

impl QueueControl {
    fn attach(&self, sh: &Arc<Shared>) {
        *self.shared.lock_ok() = Some(Arc::downgrade(sh));
        // A handle reused for a second run starts that run undrained; the
        // latch below describes the pool currently attached, not a past one.
        self.drained.store(false, Ordering::Release);
    }

    /// Move every PENDING article whose message-id is in `ids` to the
    /// front of the queue, in the ORDER GIVEN - the streaming layer passes
    /// the requested byte range's articles seek-point-first, and that is
    /// the order the player will read them in. (Queue relative order is
    /// deliberately NOT preserved: a tail burst leaves file-end articles
    /// ahead of mid-file ones, and a promoted span crossing that boundary
    /// would otherwise download tail-first while the player starves at
    /// the seek point.) Articles already fetched or in flight are
    /// unaffected. Returns how many were moved.
    pub fn promote(&self, ids: &[String]) -> usize {
        self.promote_opts(ids, true)
    }

    /// [`Self::promote`] with the stream-mode side effect explicit.
    /// `engage_stream: false` reorders the queue WITHOUT flipping the
    /// pool into shallow pipelines: the extractor's offset-0 probe wants
    /// its article sooner, but nothing blocks on it, and a scrambled
    /// many-volume set probes once per slot - each 60 s stream-mode
    /// linger would chain into the whole download running shallow.
    pub fn promote_opts(&self, ids: &[String], engage_stream: bool) -> usize {
        let Some(sh) = self
            .shared
            .lock()
            .unwrap()
            .as_ref()
            .and_then(std::sync::Weak::upgrade)
        else {
            return 0;
        };
        // Streaming-layer promotes (and the 7z chase, whose worker
        // blocks on the footer) engage stream mode (shallow pipelines)
        // even when nothing moves.
        if engage_stream {
            sh.note_stream();
        }
        if ids.is_empty() {
            return 0;
        }
        // The queue is a tokio Mutex popped briefly by workers; we're on a
        // plain OS thread (the /stream handler). Bounded try_lock keeps
        // this best-effort - a missed promotion just retries on the next
        // blocked-read window.
        let mut tries = 0;
        let mut q = loop {
            match sh.queue.try_lock() {
                Ok(g) => break g,
                Err(_) if tries < 20 => {
                    tries += 1;
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                Err(_) => return 0,
            }
        };
        if q.is_empty() {
            return 0;
        }
        // Rank = position in the caller's range order (first occurrence
        // wins for duplicate ids).
        let mut rank: HashMap<&str, usize> = HashMap::with_capacity(ids.len());
        for (r, id) in ids.iter().enumerate() {
            rank.entry(id.as_str()).or_insert(r);
        }
        let mut front: Vec<(usize, Work)> = Vec::new();
        let mut rest: VecDeque<Work> = VecDeque::with_capacity(q.len());
        for mut w in q.drain(..) {
            if let Some(&r) = rank.get(w.id.as_str()) {
                w.promoted = true;
                front.push((r, w));
            } else {
                rest.push_back(w);
            }
        }
        let n = front.len();
        front.sort_by_key(|(r, _)| *r);
        q.extend(front.into_iter().map(|(_, w)| w));
        q.append(&mut rest);
        if n > 0 {
            // Count EVERY promoted item still queued (front run + shed
            // re-inserts + prior promotes), record the promote's id set
            // for the shed immunity check, then wake blocked readers so
            // non-promoted in-flight transfers yield the line.
            let total = q.iter().filter(|w| w.promoted).count();
            sh.promoted_pending.store(total, Ordering::Release);
            *sh.promoted_ids.lock_ok() = ids.iter().cloned().collect();
            sh.promote_gen.send_modify(|g| *g += 1);
        }
        n
    }

    /// Responses so far that advanced an article without resolving it
    /// (see [`Shared::deferred`]). A caller's stall watchdog must count
    /// a change here as liveness: a refusal-only run can spend a whole
    /// pass in the `soft_430` confirming repeat, moving neither decoded
    /// bytes nor the outstanding count while working perfectly. `None`
    /// once the run's pool is gone - there is nothing left to stall.
    pub fn deferred(&self) -> Option<u64> {
        // lock_ok, like every other accessor of this mutex: this runs
        // inside the stall watchdog, and a poisoned lock panicking here
        // would silently kill the exact protection it feeds.
        Some(
            self.shared
                .lock_ok()
                .as_ref()
                .and_then(std::sync::Weak::upgrade)?
                .deferred
                .load(Ordering::Relaxed),
        )
    }

    /// M11 stream mode: a live /stream reader touched the hub. Workers
    /// cap their pipelines to `stream_window()` while this stays fresh
    /// (see `Shared::stream_until`), so seek promotions preempt instead
    /// of queueing behind hundreds of MB of pipelined responses. Called
    /// on every reader read - cheap (one mutex + one atomic store).
    pub fn note_stream_active(&self) {
        if let Some(sh) = self
            .shared
            .lock()
            .unwrap()
            .as_ref()
            .and_then(std::sync::Weak::upgrade)
        {
            sh.note_stream();
        }
    }

    /// Can the ATTACHED fetch run still deliver any of `ids` - is one of
    /// them pending in the queue or on the wire right now? `None` means
    /// no pool is attached at all (between runs, or the run drained -
    /// where settle-side repair may still cover the bytes and the caller
    /// must decide how long repair deserves). The /stream reader uses a
    /// `Some(false)` here to conclude a blocked span is terminally
    /// undeliverable, so every unsure path with a live pool - an empty
    /// id list, a queue lock that could not be taken - answers
    /// `Some(true)`, never `Some(false)`.
    ///
    /// Racy by construction and deliberately so: an article can sit
    /// between the queue pop and the in-flight registration for the
    /// length of a `send_body` await, invisible to both checks. Callers
    /// must therefore require consecutive negative verdicts spaced
    /// longer than that window (the stream reader votes 1 s apart)
    /// before acting.
    pub fn any_live(&self, ids: &[String]) -> Option<bool> {
        let sh = self
            .shared
            .lock()
            .unwrap()
            .as_ref()
            .and_then(std::sync::Weak::upgrade)?;
        if ids.is_empty() {
            return Some(true);
        }
        {
            let inf = sh.inflight.lock_ok();
            if ids.iter().any(|id| inf.contains_key(id.as_str())) {
                return Some(true);
            }
        }
        // A body that already ARRIVED and is parked on a full outcome
        // channel is the opposite of dead - it is seconds from being
        // real bytes. Without this, disk backpressure long enough to
        // block the handoff send made a successfully fetched article
        // look terminal and the stream served zeros for bytes it
        // already had.
        {
            let ok = sh.done_ok.lock_ok();
            if ids.iter().any(|id| ok.contains(id.as_str())) {
                return Some(true);
            }
        }
        // A bad-body steer parked in the inbox is a refetch WAITING for
        // a worker's next top-up, not a dead article. That top-up is
        // usually ms away, but with every worker blocked in long
        // pipelined body reads it can be tens of seconds out - long
        // enough for the dead-span verdict to zero-fill the very span
        // the steer is about to rewrite.
        {
            let inbox = sh.steer_inbox.lock_ok();
            if !inbox.is_empty()
                && ids
                    .iter()
                    .any(|id| inbox.iter().any(|w| w.id.as_str() == id.as_str()))
            {
                return Some(true);
            }
        }
        // Same bounded try_lock discipline as `promote`: the caller is a
        // plain OS thread, the queue a tokio Mutex popped by workers.
        let mut tries = 0;
        let q = loop {
            match sh.queue.try_lock() {
                Ok(g) => break g,
                Err(_) if tries < 20 => {
                    tries += 1;
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                Err(_) => return Some(true),
            }
        };
        let set: HashSet<&str> = ids.iter().map(|s| s.as_str()).collect();
        Some(q.iter().any(|w| set.contains(w.id.as_str())))
    }

    /// In-stream PAR2 deferral (issue #14): permanently remove every
    /// PENDING article whose message-id is in `ids` from the queue, and
    /// mark each one terminal WITHOUT emitting a `FetchOutcome` - the
    /// caller owns the accounting for exactly the ids returned. Articles
    /// already in flight (or already resolved) are untouched and resolve
    /// through their normal outcome; a duplicate call for an id already
    /// cancelled is a no-op. Best-effort like `promote`: a missed lock
    /// returns an empty list and the caller may retry.
    pub fn cancel(&self, ids: &HashSet<String>) -> Vec<String> {
        let Some(sh) = self
            .shared
            .lock()
            .unwrap()
            .as_ref()
            .and_then(std::sync::Weak::upgrade)
        else {
            return Vec::new();
        };
        if ids.is_empty() {
            return Vec::new();
        }
        // Same bounded try_lock discipline as `promote`: callers are the
        // decode OS threads, and the queue is a tokio Mutex popped by
        // workers.
        let mut tries = 0;
        let mut q = loop {
            match sh.queue.try_lock() {
                Ok(g) => break g,
                Err(_) if tries < 20 => {
                    tries += 1;
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                Err(_) => return Vec::new(),
            }
        };
        let mut removed: Vec<Work> = Vec::new();
        let mut kept: VecDeque<Work> = VecDeque::with_capacity(q.len());
        for w in q.drain(..) {
            if ids.contains(w.id.as_str()) {
                removed.push(w);
            } else {
                kept.push_back(w);
            }
        }
        *q = kept;
        // A cancelled item may have been seek-promoted; keep the promoted
        // count honest so the shed immunity check stays accurate.
        if removed.iter().any(|w| w.promoted) {
            let total = q.iter().filter(|w| w.promoted).count();
            sh.promoted_pending.store(total, Ordering::Release);
        }
        drop(q);
        // Terminal bookkeeping OUTSIDE the queue lock (claim_done takes
        // the done mutex; complete_one may fire the finished watch when
        // the cancelled articles were the last pending work). The Work
        // items are stashed whole so `requeue` can resurrect them.
        let mut out = Vec::with_capacity(removed.len());
        for w in removed {
            if sh.claim_done(&w.id) {
                sh.complete_one();
                out.push(w.id.clone());
                sh.cancelled.lock_ok().insert(w.id.clone(), w);
            }
        }
        out
    }

    /// Undo a [`cancel`](Self::cancel): put previously-cancelled articles
    /// back into the queue, un-terminal. All-or-nothing per call for the
    /// ids it finds in the stash: on any obstacle (run already finished,
    /// draining, queue lock unobtainable) everything is rolled back and 0
    /// is returned - the caller keeps its deferred accounting. Only ids
    /// a prior `cancel` returned can ever be requeued; unknown ids are
    /// ignored (and do not count toward the return value).
    pub fn requeue(&self, ids: &[String]) -> usize {
        let Some(sh) = self
            .shared
            .lock()
            .unwrap()
            .as_ref()
            .and_then(std::sync::Weak::upgrade)
        else {
            return 0;
        };
        if sh.aborted.load(Ordering::Acquire) || sh.draining.load(Ordering::Acquire) {
            return 0;
        }
        let works: Vec<Work> = {
            let mut stash = sh.cancelled.lock_ok();
            ids.iter().filter_map(|id| stash.remove(id)).collect()
        };
        if works.is_empty() {
            return 0;
        }
        let put_back = |ws: Vec<Work>| {
            let mut stash = sh.cancelled.lock_ok();
            for w in ws {
                stash.insert(w.id.clone(), w);
            }
        };
        // Pending BEFORE the finished check: with the count raised, a
        // concurrent complete_one cannot reach zero and fire finished
        // under us. If finished already fired, the fleet is winding down
        // and nothing would ever fetch these - roll back.
        // A rollback's fetch_sub can be the one that lands pending on
        // zero (a real completion slipped in between our add and sub, and
        // saw an inflated count) - it must then fire `finished` exactly
        // like complete_one, or the fleet waits forever.
        let sub_pending = |n: usize| {
            if sh.pending.fetch_sub(n, Ordering::AcqRel) == n {
                sh.mark_drained();
                let _ = sh.finished.send(true);
            }
        };
        sh.pending.fetch_add(works.len(), Ordering::AcqRel);
        if *sh.finished.borrow() {
            sub_pending(works.len());
            put_back(works);
            return 0;
        }
        {
            let mut done = sh.done.lock_ok();
            for w in &works {
                done.remove(&w.id);
            }
        }
        let mut tries = 0;
        let mut q = loop {
            match sh.queue.try_lock() {
                Ok(g) => break g,
                Err(_) if tries < 20 => {
                    tries += 1;
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                Err(_) => {
                    // Roll back in reverse: re-terminal, drop pending
                    // (firing finished if ours is the zeroing sub),
                    // re-stash.
                    let mut done = sh.done.lock_ok();
                    for w in &works {
                        done.insert(w.id.clone());
                    }
                    drop(done);
                    sub_pending(works.len());
                    put_back(works);
                    return 0;
                }
            }
        };
        let n = works.len();
        q.extend(works);
        n
    }

    /// TODO 114 consumer steer: the decode consumer's per-article
    /// verdict for a `FetchOutcome::Done` body, called once per Done
    /// from the decode OS thread. With `PoolConfig::crc_steer` off (or
    /// no pool attached, or the id unknown) this is a no-op answering
    /// [`DecodeAck::Owned`].
    ///
    /// In steer mode every Done deferred its `complete_one` into
    /// `Shared::handed`; this call settles it. A clean verdict (and a
    /// declared part that matches the requested segment's) finalizes:
    /// the consumer owns the outcome. A bad body - failed pcrc32, or a
    /// valid body for the WRONG article (split-brain; its own CRC
    /// passes, identity is the only tell) - is requeued to a DIFFERENT
    /// server once (requeue-after-claim): the id is un-claimed from
    /// `done` and the stashed Work re-enters the queue with the
    /// deliverer's whole group folded into `tried_fail`, so the
    /// refetch (or a still-racing dup) re-claims through the normal
    /// one-outcome-per-id arbitration. Eligibility is the delivery
    /// rule the shipped gate hardened: `other_can_take` (levels +
    /// aliveness + group + the fill-server 430 pickup gate), checked
    /// AFTER the fold, and one steer per id ever
    /// (`Shared::crc_retried`). Every obstacle - no elsewhere, second
    /// bad copy, aborted/draining/finished run - finalizes as
    /// `Owned`: the consumer processes the body exactly as if this
    /// seam did not exist. The requeue itself goes through
    /// `Shared::steer_inbox`, never the tokio queue lock.
    pub fn note_decoded(&self, id: &str, report: DecodeReport) -> DecodeAck {
        let Some(sh) = self
            .shared
            .lock()
            .unwrap()
            .as_ref()
            .and_then(std::sync::Weak::upgrade)
        else {
            return DecodeAck::Owned;
        };
        let Some(h) = sh.handed.lock_ok().remove(id) else {
            return DecodeAck::Owned;
        };
        // The consumer owns the outcome from here unless a steer
        // completes below; own = the deferred terminal bookkeeping
        // runs now (mirrors the legacy post-send lines).
        let finalize = |sh: &Shared| {
            // Under arrival_ack the consumer's `note_settled` (after
            // decode AND write) owns the done_ok removal: a clean
            // verdict here precedes the disk write, and dropping the
            // liveness entry now would let a slow pwrite outlast the
            // /stream dead-span verdict and zero-fill bytes that are
            // about to land (TODO 121.4's promise, re-opened by the
            // steer seam). Non-ack pools have no later settle call, so
            // they still clear it here.
            if !sh.arrival_ack {
                sh.done_ok.lock_ok().remove(id);
            }
            sh.complete_one();
            DecodeAck::Owned
        };
        let why = match report {
            DecodeReport::Bad { why } => why,
            DecodeReport::Clean { part } => match (sh.parts.get(id), part) {
                (Some(&want), Some(got)) if got != want => {
                    "valid body for the wrong article (part mismatch)"
                }
                _ => return finalize(&sh),
            },
        };
        let dbg = std::env::var_os("NZBFAST_POOL_DEBUG").is_some();
        if sh.aborted.load(Ordering::Acquire)
            || sh.draining.load(Ordering::Acquire)
            || *sh.finished.borrow()
        {
            if dbg {
                eprintln!("[crc-steer] {id}: own (run over/draining)");
            }
            return finalize(&sh);
        }
        let mut w = h.work;
        // Group siblings fold FIRST so other_can_take skips the whole
        // backbone serving the same bad copy - and a fill server's
        // pickup gate (the primary's 430 bit) is enforced inside, so a
        // primary+fill pair never buys a wasted refetch.
        w.tried_fail |= h.group_bits;
        // A dup's bad copy skips the eligibility gate and the once-
        // per-id budget (see the `dup_copy` doc): it requeues even
        // with nowhere better to go, because owning it would write
        // damage a non-dup copy may already have resolved cleanly.
        // Bounded structurally: each server group dup-races an id at
        // most once (`dup_servers`), and the fold above stops the
        // pickers re-racing from this group.
        let charged = !h.dup_copy;
        if charged
            && (!sh.other_can_take(&w, h.server) || !sh.crc_retried.lock_ok().insert(w.id.clone()))
        {
            if dbg {
                eprintln!(
                    "[crc-steer] {id}: own (elsewhere={} already={})",
                    sh.other_can_take(&w, h.server),
                    sh.crc_retried.lock_ok().contains(id)
                );
            }
            return finalize(&sh);
        }
        // NO tokio queue lock here (see the `steer_inbox` field doc):
        // the Work goes into the inbox, which workers drain into the
        // queue under their own `next_work` lock hold. Inbox FIRST,
        // un-claim after: from the moment the id leaves `done` a
        // future claimant is already guaranteed - the drained refetch,
        // or a dup still racing - and `claim_done` arbitrates exactly
        // one, as ever.
        if let Some(l) = &sh.live {
            l.note(
                h.server,
                "crc-retry",
                format!("{id}: {why} - refetching from another server"),
            );
        }
        if dbg {
            eprintln!("[crc-steer] {id}: steered (from server {})", h.server);
        }
        sh.steer_inbox.lock_ok().push(w);
        sh.done.lock_ok().remove(id);
        // The body the consumer holds is dead weight now; the article
        // stays in any_live's sight through the inbox entry pushed
        // above until a worker drains it into the queue.
        sh.done_ok.lock_ok().remove(id);
        DecodeAck::Steered
    }

    /// TODO 121.4: the consumer's "this body is decoded and written"
    /// ack for `arrival_ack` pools. Removes the `done_ok` liveness
    /// entry that has covered the article since its claim - through
    /// the outcome channel's buffer and the consumer's in-hand batch -
    /// so the /stream dead-span verdict can never condemn a span whose
    /// bytes are anywhere in the pipe. A no-op for ids already settled
    /// (steer verdicts, non-ack pools) and after the run ends.
    pub fn note_settled(&self, id: &str) {
        if let Some(sh) = self
            .shared
            .lock()
            .unwrap()
            .as_ref()
            .and_then(std::sync::Weak::upgrade)
        {
            sh.done_ok.lock_ok().remove(id);
        }
    }

    /// Force a pool-state dump (the stall watchdog, on a suspected
    /// deadlock). Same output as NZBFAST_POOL_DEBUG's idle-branch dump,
    /// but on demand - so a hang in the field self-captures the queue /
    /// inflight state that pins the root cause.
    pub fn dump_state(&self) {
        if let Some(sh) = self
            .shared
            .lock()
            .unwrap()
            .as_ref()
            .and_then(std::sync::Weak::upgrade)
        {
            sh.debug_dump_idle();
        }
    }

    /// Hard-stop the run (user cancelled the download). Lock-free by
    /// design: an `aborted` flag every worker loop checks, plus the
    /// finished watch to snap workers out of blocked reads. The old
    /// implementation cleared the queue under a try_lock (starved out
    /// forever on busy pools - 50+ workers contend for that mutex) and
    /// zeroed `pending` (in-flight completions then fetch_sub-wrapped it
    /// to usize::MAX and the pool never returned). The fetch returns
    /// within seconds; the journal keeps what landed.
    pub fn abort(&self) -> bool {
        let Some(sh) = self
            .shared
            .lock()
            .unwrap()
            .as_ref()
            .and_then(std::sync::Weak::upgrade)
        else {
            return false;
        };
        sh.aborted.store(true, Ordering::Release);
        let _ = sh.finished.send(true);
        true
    }

    /// Graceful stop (the friendly Pause): stop admitting new articles but
    /// let everything already in flight finish and journal, then return -
    /// so a resume re-fetches only the unstarted queue, wasting nothing.
    /// Contrast [`abort`](Self::abort), which drops in-flight reads (they
    /// re-download on resume) to free the line immediately.
    pub fn drain(&self) -> bool {
        let Some(sh) = self
            .shared
            .lock()
            .unwrap()
            .as_ref()
            .and_then(std::sync::Weak::upgrade)
        else {
            return false;
        };
        sh.draining.store(true, Ordering::Release);
        // Same state, latched on the handle: the workers read the flag on
        // `Shared`, but `Shared` is gone by the time the engine asks.
        self.drained.store(true, Ordering::Release);
        // Not a hard finish signal: blocked reads must run to completion,
        // so no finished.send here - the read loop drains naturally.
        true
    }

    /// Was a graceful drain requested? The engine checks this AFTER the
    /// network phase returns - to tell a paused wind-down (park + resume)
    /// from a real completion (settle/repair) - and the pool has dropped its
    /// `Shared` by then, so the answer comes from the latch `drain()` left
    /// here. The live-pool read is kept for callers that ask mid-run.
    pub fn is_draining(&self) -> bool {
        self.drained.load(Ordering::Acquire)
            || self
                .shared
                .lock()
                .unwrap()
                .as_ref()
                .and_then(std::sync::Weak::upgrade)
                .is_some_and(|sh| sh.draining.load(Ordering::Acquire))
    }

    /// Network-tail visibility (tail-prefetch experiment): Some(pending
    /// article count) once a primary worker has found the queue dry
    /// with articles still in flight - the pool's own tail latch - and
    /// None before that moment or once the run is gone. `Some(0)` means
    /// the tail completed; a live tail is `Some(n)` with `n > 0`.
    pub fn tail_pending(&self) -> Option<usize> {
        let sh = {
            let g = self.shared.lock_ok();
            g.as_ref()?.upgrade()?
        };
        let latched = sh.tail_started.lock_ok().is_some();
        latched.then(|| sh.pending.load(Ordering::Acquire))
    }
}

/// §129 3g: bare refusals one session remembers having handed out, so a
/// later proof that the session was desynced can void the passes they
/// spent. A desync is proven within a few responses (the first misaligned
/// hit fails its echoed id), so this only ever has to hold the recent
/// tail - and on a wholly-dead post it would otherwise grow to the whole
/// job.
const BARE_LEDGER_MAX: usize = 512;
/// Ceiling on the pool-wide re-arm map ([`Shared::soft_rearm`]).
const SOFT_REARM_MAX: usize = 8192;
/// §129 3g: how many times one article's bare-refusal pass may be given
/// back. This is what makes the re-arm terminate: a server that stalls
/// or desyncs every session would otherwise hand every article its pass
/// back forever and no post would ever resolve as missing (measured -
/// the first cut of this fix hung the 1-in-5 leg outright).
///
/// It has to clear the DEMAND, not merely be finite. Each re-arm
/// answers one desync event that landed on that article, so what an
/// article needs is the number of faulty sessions that touch it - and
/// a cap under that is a false Missing waiting for the right run. A cap
/// of 3 looked fine until it was measured: the sweep's 1-in-7 leg ran
/// articles into it 16 times over three rounds, five of them articles
/// the server HELD, and a contended box turned one of those into
/// exactly the data loss this item is about. Measured demand peaks at
/// 10 at the worst rate the sweep asserts (1-in-5, where one response
/// in five is withheld), so 24 is headroom over the demand rather than
/// a number that sounded safe.
///
/// It costs nothing on a provider that is merely empty: no re-arm can
/// happen without a desync signature, so the ceiling for a
/// healthy-but-absent post is the two dispatches it always was.
const SOFT_REARM_CAP: u8 = 24;

struct Work {
    id: String,
    attempts: u8,
    /// M11: promoted to the queue front by a streaming seek. Shed
    /// pipelines re-insert their abandoned items BEHIND the promoted run,
    /// never ahead of it.
    promoted: bool,
    /// Bitmask of servers that 430'd this article. An article is Missing
    /// only when every configured server has - different backbones have
    /// different retention/takedown profiles, so posts often complete from
    /// the union ("cross-server piecing").
    tried_430: u32,
    /// Bitmask of servers whose transport failed while this article was
    /// the charged one (front of a dead connection). Steering only, not
    /// authoritative: another live eligible server gets first claim on
    /// the retry; with none left the failing server may retry it itself
    /// (still bounded by `attempts`). Without this, a server that
    /// deterministically kills the article's connection can burn the
    /// whole retry budget before a healthy server ever sees the requeue.
    tried_fail: u32,
    /// Tail duplicate: a second dispatch of an article already in flight
    /// on a slower server. First completion wins; a dup's own failures
    /// are silently discarded (the original still owns the outcome).
    dup: bool,
    /// TODO 121.1: attempts of THIS article that expired before a
    /// status byte arrived. Rides the requeue so the next attempt's
    /// pre-byte budget escalates per [`article_prebyte_budget`] -
    /// per-server training alone re-floors between retries.
    prebyte_expiries: u8,
    /// Server groups whose 430/423 arrived WITHOUT an echoed
    /// message-id. Positional attribution can misfile such a miss (a
    /// frontend that dropped the previous pipelined response leaves
    /// the next bare "430 no such article" landing on the wrong front
    /// article), so the first per group is suspect - requeued
    /// uncharged for one confirming retry - and only a repeat from
    /// the same group folds into `tried_430`. §129 3g: the bit is not
    /// permanent. A session that shows it was reading responses off by
    /// one voids the refusals it handed out ([`Shared::void_soft_430`]),
    /// which clears its bits here again.
    soft_430: u32,
    /// §129 3g: this dispatch carried an alignment fence, so its
    /// response is followed by the fence's own and the reader must
    /// consume that too. Set at dispatch from the server's
    /// `bare_refuser` flag, which can arm mid-session - so it is per
    /// ITEM, not per session.
    fenced: bool,
    /// §129 3g: how many times this article's `soft_430` pass has been
    /// GIVEN BACK by [`Shared::void_soft_430`] - capped at
    /// [`SOFT_REARM_CAP`] so a provider that desyncs on every session
    /// cannot keep an article out of a terminal verdict for ever.
    rearms: u8,
    /// This dispatch is a VERDICT PROBE, not payload: the article has
    /// already been refused somewhere and this hop exists only to walk
    /// it toward (or away from) a unanimous Missing. Set per dispatch -
    /// a queued item earns it by carrying `tried_430`/`soft_430` bits,
    /// a ladder fan-out dup is born with it - and read by
    /// [`Pipeline::payload`], because the endgame gates that used to
    /// ask "is this worker idle" only ever meant "is a BODY holding
    /// this socket". A refusal is one small line, so a probe queued
    /// behind other probes costs nothing, and refusing to pipeline
    /// them capped verdict throughput at one article per connection
    /// per round trip - the measured zero-throughput stall before
    /// repair on a damaged post.
    ladder: bool,
}

/// What a worker currently has on the wire, split by kind. The two
/// numbers gate different things: speculation (racing an article
/// someone else may yet deliver) is spent only by a worker with
/// NOTHING outstanding, while a 430-ladder probe only has to keep
/// clear of payload - a body holds the socket for its whole transfer,
/// a refusal for one line.
#[derive(Clone, Copy, Default)]
struct Pipeline {
    /// Everything in flight on this connection.
    used: usize,
    /// Of those, the ones fetching a body we expect to arrive.
    payload: usize,
}

impl Pipeline {
    /// The pipeline a worker's in-flight deque describes.
    fn of(inflight: &VecDeque<Work>) -> Pipeline {
        Pipeline {
            used: inflight.len(),
            payload: inflight.iter().filter(|w| !w.ladder).count(),
        }
    }

    /// Test/callsite shorthand for a worker holding `n` payload bodies.
    #[cfg(test)]
    fn payload(n: usize) -> Pipeline {
        Pipeline {
            used: n,
            payload: n,
        }
    }

    /// Test shorthand for a worker holding `n` ladder probes and
    /// nothing else.
    #[cfg(test)]
    fn probes(n: usize) -> Pipeline {
        Pipeline {
            used: n,
            payload: 0,
        }
    }
}

/// TODO 114 consumer steer: one delivered body awaiting the consumer's
/// decode verdict (see `Shared::handed`). `work` is the rebuilt Work a
/// bad verdict requeues - always `dup: false`, whatever copy won the
/// race - and `server`/`group_bits` identify the deliverer so the
/// steer can exclude its whole backbone.
struct Handed {
    work: Work,
    server: usize,
    group_bits: u32,
    /// The delivered copy was a DUP dispatch that won the claim. A
    /// dup's bad copy never owns damage and never spends the steer
    /// budget (mirror of the pool-side gate's silent dup discard) -
    /// it is requeued unconditionally, because the copy that should
    /// own the outcome may already have lost the claim race inside
    /// the verdict window.
    dup_copy: bool,
}

/// One article currently being fetched by some worker.
struct Inflight {
    server: usize,
    dispatched: Instant,
    dups: u8,
    /// Servers that already 430'd this article - seeded from the Work
    /// item at dispatch, and UPDATED by duplicate dispatches' 430s
    /// (M2c.4): the entry is the authoritative union while the article
    /// is in flight, so the endgame fan-out can reach a unanimous
    /// verdict without waiting for the ladder.
    tried_430: u32,
    /// Servers a duplicate dispatch has already been issued to (mirror
    /// group bits) - the endgame fan-out races each backbone at most
    /// once.
    dup_servers: u32,
    /// Servers whose transport - or, TODO 114, whose delivered BODY -
    /// already failed this article, seeded from the Work item at
    /// dispatch. Dup pickers skip these: racing an article back to a
    /// server that already failed it is wasted work at best, and for
    /// a CRC-steered refetch it is the misfire that loses the race to
    /// the same corrupt copy the steer just rejected (the corrupt dup
    /// claims first and the clean refetch is discarded as the loser).
    tried_fail: u32,
    /// TTFB-suspicion (TODO 115): the owner's read sat in pre-byte
    /// silence past the suspicion bound. `pick_suspect_dup` races
    /// suspect articles immediately - same server included - instead
    /// of waiting out the full adaptive budget.
    suspect: bool,
}

/// State shared by every worker of one fetch run.
///
/// Tail behavior (measured on a high-RTT link): when the queue
/// runs dry but articles are still in flight on servers observed to be
/// much slower, idle workers re-dispatch those articles instead of
/// waiting out the stragglers. `done` arbitrates so exactly one outcome
/// is emitted (and `pending` decremented once) per article.
/// Capacity-episode lifecycle (issue #16), broadcast to parked
/// yielders: Idle = nothing to wait for, Probing = one prober is
/// riding the bounce ladder, Reopened = a session was granted again
/// (parked workers redial), Dead = the prober exhausted its horizon
/// (parked workers exit so the run can reach a truthful terminal).
/// Hard connect outages (wifi drop, VPN reconnect, router reboot)
/// ride the SAME lifecycle via `park_or_probe`: a server that refuses
/// the dial outright is as plausibly transient as one bouncing on a
/// ghost capacity lease.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
enum CapEpisode {
    #[default]
    Idle,
    Probing,
    Reopened,
    Dead,
}

/// One server's authentication standing, shared by all its workers.
struct AuthState {
    /// Set once when the server refuses permanently (bad credentials, a
    /// disabled account). Every worker for this server stops trying:
    /// retrying cannot fix it, and the operator needs to see it, not a
    /// wall of backoff.
    rejected: AtomicBool,
    /// Set when the server refused for CAPACITY reasons. Workers still
    /// retry, but they stand down one at a time rather than all racing
    /// to re-provoke the same cap.
    capacity_capped: AtomicBool,
    /// Workers that have voluntarily given up a slot to a capacity
    /// refusal. This IS the reduced connection count: asking for fewer
    /// sessions is the only response a simultaneous-connection cap
    /// actually accepts.
    yielded: AtomicUsize,
    /// Exactly ONE worker holds the long capacity-probe role (issue
    /// #16). `claim_yield` alone cannot elect a single survivor: early
    /// yielders exit and shrink `alive` while later workers are still
    /// claiming, so several can each read "I am the last" and all ride
    /// the probe ladder at once - harmless when the ladder was five
    /// bounces, a small dial storm now that it is seventy-five.
    cap_prober: AtomicBool,
    /// See [`CapEpisode`]. Yielders park on this instead of dying, so
    /// a cap that clears mid-run gets its fleet back instead of one
    /// prober crawling the rest of the job alone. The u64 is a publish
    /// generation: the watch never returns to Idle, so without it a
    /// LATER episode's parkers would consume the previous episode's
    /// leftover `Reopened` on entry, skip the prober election, and a
    /// permanent outage could never reach `Dead` (each worker bounced
    /// off the stale value forever instead of parking).
    episode: tokio::sync::watch::Sender<(CapEpisode, u64)>,
    /// The server's own words, kept for the log and the dashboard.
    reason: std::sync::Mutex<Option<String>>,
}

impl Default for AuthState {
    fn default() -> Self {
        AuthState {
            rejected: Default::default(),
            capacity_capped: Default::default(),
            yielded: Default::default(),
            cap_prober: Default::default(),
            episode: tokio::sync::watch::channel((CapEpisode::Idle, 0)).0,
            reason: Default::default(),
        }
    }
}

impl AuthState {
    /// Record a refusal. Returns true if this worker is the FIRST to see
    /// it, which is the one that gets to log it.
    fn note(&self, kind: crate::nntp::AuthRefusal, line: &str) -> bool {
        let flag = match kind {
            crate::nntp::AuthRefusal::Permanent => &self.rejected,
            crate::nntp::AuthRefusal::Capacity => &self.capacity_capped,
        };
        let first = !flag.swap(true, Ordering::SeqCst);
        if first {
            *self.reason.lock_ok() = Some(line.to_string());
        }
        first
    }

    /// Try to give up this worker's slot to a capacity refusal. True when
    /// the slot was yielded and the caller must leave the fleet.
    ///
    /// The survivor has to be decided against workers STILL HERE, not
    /// against the configured connection count: a worker can also leave
    /// via the connect ladder or the session bow-out, and neither passes
    /// through this counter. Counting yields against the static config
    /// meant that once anyone had left by another door the target could
    /// never be reached, so every remaining worker yielded and the server
    /// was left with nobody - failing the whole job on exactly the
    /// transient refusal this path exists to survive.
    ///
    /// `alive` counts the calling worker too, and every exit path
    /// decrements it, so a claim is only safe while it leaves someone
    /// behind. fetch_update serialises two simultaneous refusals so they
    /// cannot both conclude they are not the last one out.
    ///
    /// The caller's `alive` decrement lands after this returns (the
    /// worker unwinds to `life.retire()`), so `yielded` holds the claims
    /// that have not shown up in `alive` yet. Counting both makes the
    /// rule conservative: a full fleet stands down to about half rather
    /// than to a single survivor. That is deliberate. Reading `alive`
    /// alone would reduce to exactly one, but leaves a window where two
    /// simultaneous refusals both see two workers left and both go,
    /// which is the zero-worker failure this exists to prevent. Half a
    /// fleet still stops the hammering and still asks the provider for
    /// fewer sessions, which is what a simultaneous-connection cap
    /// actually wants; a stranded server is unrecoverable for the run.
    /// Publish an episode event under a fresh generation, so parkers
    /// can tell it apart from a previous episode's leftover value.
    fn publish_episode(&self, ep: CapEpisode) {
        self.episode.send_modify(|v| *v = (ep, v.1 + 1));
    }

    fn claim_yield(&self, alive: &AtomicUsize) -> bool {
        self.yielded
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |y| {
                (alive.load(Ordering::SeqCst) > y + 1).then_some(y + 1)
            })
            .is_ok()
    }

    fn is_rejected(&self) -> bool {
        self.rejected.load(Ordering::Acquire)
    }

    #[allow(dead_code)] // diagnostic accessor, kept for pool-debug dumps
    fn reason(&self) -> Option<String> {
        self.reason.lock_ok().clone()
    }
}

struct Shared {
    queue: Mutex<VecDeque<Work>>,
    /// Articles not yet terminal (Done/Missing/Failed). Workers may only
    /// exit when this hits zero - a queue that looks empty can still
    /// receive requeues from other workers' in-flight failures/430s.
    pending: AtomicUsize,
    /// Message-ids whose outcome has been emitted.
    done: std::sync::Mutex<HashSet<String>>,
    /// Articles currently in flight, keyed by message-id.
    inflight: std::sync::Mutex<HashMap<String, Inflight>>,
    /// Per-server raw byte counters (also the caller-visible stats).
    bytes: Vec<Arc<AtomicU64>>,
    /// Per-server session-end tally by cause, in [`SessionEnds`] field
    /// order: peer, protocol, prebyte, stall, ours. Counted where the
    /// session actually ends, so a redial that never wins cannot hide
    /// the cause (the same reasoning as `note_flap`).
    ends: Vec<[AtomicU64; 5]>,
    /// Per-server write-side wait (see [`PoolStats::blocked_ms`]). Kept
    /// on Shared as well as LiveStats because the CLI runs without a
    /// live-stats sink and still needs to tell a network dip from a
    /// disk one.
    blocked_ms: Vec<AtomicU64>,
    /// Per-server time-to-status EWMA in ms (adaptive timeout path,
    /// TODO 96.1). 0 = unmeasured, which budgets at the clamp ceiling.
    ttfb_ms: Vec<AtomicU64>,
    /// M29 oracle: article age in days by message-id (only ids with a
    /// known non-zero age; immutable after build). Lets the outcome
    /// recorder bucket a hit/430 without threading age through Work.
    ages: HashMap<String, u32>,
    /// Expected yEnc part number by message-id (only ids that declared
    /// one; immutable after build). Same shape as `ages` for the same
    /// reason: the CRC-retry gate needs it without widening Work.
    parts: HashMap<String, u32>,
    /// Ids the CRC-retry gate has already steered once. Bounds the
    /// experiment to a single cross-server retry per article - the
    /// second bad copy is delivered as-is and PAR2 owns it, exactly as
    /// with the knob off.
    crc_retried: std::sync::Mutex<HashSet<String>>,
    /// §129 3g: bare-refusal passes to RE-ARM, keyed by message-id, the
    /// value being the server-group bits to clear from `Work::soft_430`.
    /// Filled when a session shows it was reading responses off by one -
    /// an id mismatch, a status that cannot answer a BODY, or a read
    /// that stalled with requests outstanding - and drained by the next
    /// bare refusal for that article. Empty on every healthy run, and
    /// the counter beside it keeps the hot path off this lock.
    soft_rearm: std::sync::Mutex<HashMap<String, u32>>,
    soft_rearm_n: AtomicUsize,
    /// TODO 114 consumer steer: Done outcomes handed to the consumer
    /// whose `complete_one` is DEFERRED until the consumer's decode
    /// verdict arrives via [`QueueControl::note_decoded`]. The stashed
    /// Work (plus the deliverer's identity) is what a bad-body verdict
    /// requeues; a clean verdict just finalizes. Keeping these ids in
    /// `pending` is what keeps the fleet alive to serve a steer even
    /// when the damaged body was the last article on the wire. Bounded
    /// by the outcome channel depth plus the consumers' in-hand
    /// batches. Empty unless `PoolConfig::crc_steer` is on.
    handed: std::sync::Mutex<HashMap<String, Handed>>,
    /// TODO 114 consumer steer: requeued-after-claim Work waiting to
    /// re-enter the queue. The verdict thread must NOT take the tokio
    /// queue mutex - it is FIFO-fair and worker-hot, and during a
    /// steer burst a bounded try_lock lost to the worker scans for
    /// long enough to own real damage (measured: up to a third of a
    /// storm's steers at a 200 ms budget). Workers drain this into
    /// the queue at the top of their own `next_work` lock hold. An
    /// item here counts as live in `any_live` (the top-up is usually
    /// ms away, but workers all blocked in long pipelined reads can
    /// hold it back past the dead-span verdict's grace+votes);
    /// `seal_run` drains it so an exhausted fleet still accounts
    /// every steered article.
    steer_inbox: std::sync::Mutex<Vec<Work>>,
    /// Ids whose body ARRIVED and is mid-handoff to the consumer: from
    /// claim to the outcome channel accepting it, the body is out of
    /// `inflight` and out of the queue - invisible to both `any_live`
    /// checks - and a full channel can park that send for many seconds
    /// under disk backpressure (the `blocked_ms` gauge measures exactly
    /// this window). The /stream dead-span verdict must never condemn
    /// such a span (it would serve zeros for bytes that already
    /// arrived), so `any_live` counts these as live. Entries leave
    /// when the body is SETTLED: under `crc_steer` at the consumer's
    /// `note_decoded` verdict, under `arrival_ack` at the consumer's
    /// `note_settled` after decode+write (TODO 121.4 - the channel
    /// buffer and the consumer's in-hand batch were the residual
    /// blind window, and ~6 s of disk backpressure could outlast the
    /// verdict's grace-plus-votes threshold), and otherwise when the
    /// channel accepts the body.
    done_ok: std::sync::Mutex<HashSet<String>>,
    start: Instant,
    /// Monotonic count of DELIBERATE non-terminal progress. The
    /// caller's deadlock watchdog treats a run as wedged when decoded
    /// bytes AND outstanding articles both sit frozen; two kinds of
    /// healthy work move neither: a path that consumes a response and
    /// requeues instead of emitting Hit/Missing/Failed (31 Jul's
    /// dead-post abort, returning through the `soft_430` confirming
    /// repeat), and the outage prober's paced bounce ladder (whose
    /// ~10 min horizon the 180 s watchdog was aborting straight
    /// through). Anything that defers a verdict or paces a recovery
    /// must tick here, and the watchdog counts it as life.
    deferred: AtomicU64,
    /// Diagnostics: dup dispatches issued, and when the queue first ran dry
    /// with work still pending (start of the tail phase).
    dups_issued: AtomicU64,
    tail_started: std::sync::Mutex<Option<Instant>>,
    /// Flips to true the moment every article is terminal. Workers blocked
    /// mid-read on slow connections select on this - without it, a tail
    /// duplicate's win is worthless because the pool still waits for the
    /// slow original to finish streaming (the 15 s zero-throughput tail
    /// observed on Miami).
    finished: tokio::sync::watch::Sender<bool>,
    /// Hard-stop signal (user abort): workers exit at their next loop
    /// check; the finished watch wakes any blocked read. Never zero
    /// `pending` for this - in-flight completions would wrap it.
    aborted: AtomicBool,
    /// Graceful-pause signal: workers stop admitting NEW articles but
    /// finish (and journal) whatever is already in flight, then return.
    /// Unstarted queue items are left for a resume - nothing in flight is
    /// thrown away, unlike `aborted`.
    draining: AtomicBool,
    /// When the last article went terminal (vs when the pool returned).
    drained_at: std::sync::Mutex<Option<Instant>>,
    /// Work items removed by [`QueueControl::cancel`], kept whole (retry
    /// budget, retention seed) so [`QueueControl::requeue`] can resurrect
    /// them exactly as they were - the in-stream PAR2 sniff un-defers a
    /// slot when activation reveals it was set-covered payload after all.
    cancelled: std::sync::Mutex<HashMap<String, Work>>,
    /// Tail duplicates that won their race (emitted the outcome).
    dup_wins: AtomicU64,
    /// The consumer acks decode+write via `note_settled` (see
    /// [`PoolConfig::arrival_ack`]), uniform like `tail_fanout`. Under
    /// it a clean `note_decoded` verdict must NOT drop the `done_ok`
    /// liveness entry - the body is decoded but not yet on disk, and
    /// the write can outlast the dead-span verdict.
    arrival_ack: bool,
    /// Opt-in tail fan-out (see [`PoolConfig::tail_fanout`] and
    /// `pick_dup`): in the endgame, idle primaries race healthy
    /// in-flight articles too. Uniform across servers - the daemon sets
    /// every server's config from one env knob.
    tail_fanout: bool,
    /// Hedge experiment (see [`PoolConfig::hedge`]), uniform like
    /// `tail_fanout`.
    hedge: bool,
    /// TTFB-suspicion hedge (see [`PoolConfig::ttfb_hedge`]), uniform.
    ttfb_hedge: bool,
    /// TTFB-suspicion fast path: true while some in-flight article MAY
    /// be suspect and unraced, so the per-top-up check in `next_work`
    /// costs one atomic load until a suspicion actually fires. Set by
    /// `mark_suspect`, cleared by a `pick_suspect_dup` scan that comes
    /// up empty.
    suspect_pending: AtomicBool,
    /// Early fan-out (see [`PoolConfig::tail_fanout_early`]), uniform.
    tail_fanout_early: bool,
    /// Dispatch-to-done article time EWMA in ms, trained by the 222
    /// Done path only (430s answer with no body and requeues never
    /// completed - both would drag the average away from what a
    /// straggler actually costs). 0 = untrained. Includes time spent
    /// queued behind pipeline-mates, deliberately: that IS the time an
    /// article blocks its slot.
    art_ms: AtomicU64,
    /// Dup dispatches issued on staleness alone (the hedge), for the
    /// issue-rate cap and the diagnostics line.
    hedges_issued: AtomicU64,
    /// The run's shared event ring (every server's `PoolConfig` carries
    /// the same `Arc`). Held here too so moments that belong to the RUN
    /// rather than to one worker - the tail latch, the drain, a racing
    /// spike - can mark the graph from `Shared` methods. None on the
    /// bare CLI paths that build no live view.
    live: Option<Arc<LiveStats>>,
    /// Racing-burst window (see [`Shared::note_race_burst`]): when the
    /// current window opened (unix ms, 0 = none yet) and what
    /// dups+hedges read at that moment.
    race_note_at: AtomicU64,
    races_at_note: AtomicU64,
    /// Unix ms of the last wire-cap marker: the cap check runs on every
    /// pipeline top-up, so an engaged cap on a big fleet would flood the
    /// ring thousands of times over without this gate.
    wire_note_at: AtomicU64,
    /// Hot-spare experiment: one parked, authenticated connection per
    /// server, claimed by any worker whose session dies. Filled by a
    /// per-server background task (spawned lazily by the first worker,
    /// so both the single-runtime and sharded paths get one).
    spares: Vec<std::sync::Mutex<Option<Connection>>>,
    /// One filler per server, whichever worker gets there first.
    spare_filler_started: Vec<AtomicBool>,
    /// Flap breaker: per-server timestamps of established-session
    /// deaths (recorded at the successful REDIAL, which is when the
    /// worker knows the old session both worked and died).
    flap_deaths: Vec<std::sync::Mutex<VecDeque<Instant>>>,
    /// Per server: keeper slots claimed by the workers that keep a
    /// flapping server's light on; everyone else bows out for the run.
    /// The target is 1 (the shipped clamp) unless `flap_cap_keepers`
    /// widens it to the observed accept cap - see
    /// [`Shared::flap_keeper_target`].
    flap_keeper: Vec<AtomicUsize>,
    /// Per server: established sessions held RIGHT NOW by this run's
    /// workers. Sampled at the moment a dial bounces off a capacity
    /// refusal to estimate the provider's accept cap (`flap_cap_seen`).
    sessions: Vec<AtomicUsize>,
    /// Per server: high-water of `sessions` sampled at capacity-refusal
    /// bounces - the largest number of our own sessions the provider
    /// was serving while refusing one more. 0 = never bounced, cap
    /// unknown. Max across bounces, because a bounce can also land
    /// while the server still holds ghosts of sessions it just dropped
    /// (undercounting the true cap); it can never land while it serves
    /// MORE than the cap.
    flap_cap_seen: Vec<AtomicUsize>,
    /// The clamp is narrated once, not once per bowing worker.
    flap_noted: Vec<AtomicBool>,
    /// §129 3g: this server has answered at least one 430/423 with no
    /// message-id on the line, so positional attribution of its
    /// refusals is unverifiable and every later dispatch to it carries
    /// an alignment fence ([`Connection::send_fence`]). Sticky for the
    /// run and per SERVER, not per session: a session's own first bare
    /// refusal is the one that would otherwise be misattributed, so
    /// arming has to outlive the session that learned it.
    bare_refuser: Vec<AtomicBool>,
    /// §129 3g: this server has answered a fence at least once, so its
    /// fences are known to work and a later fence that goes unanswered
    /// is the fault talking, not the provider.
    fence_ok: Vec<AtomicBool>,
    /// §129 3g: fence reads that came to nothing on a server that has
    /// never answered one - the read expired, or (only on a session's
    /// FIRST fenced read, where a fresh socket is aligned by
    /// construction) the fence slot held a BODY-shaped answer, which is
    /// what DATE-silence looks like at pipeline depth above one.
    /// DATE is mandatory in RFC 3977 and the warm pool
    /// already validates parked connections with it, but a provider
    /// that quietly ignores it would otherwise have every session cut
    /// on a fence that was never coming - a broken download in defence
    /// of a fault this provider may not even have. Two of these and
    /// fencing retires for that server, back to the behavior that
    /// shipped before this item.
    fence_dud: Vec<AtomicUsize>,
    /// §129 3g: fencing has retired for this server. Latched and never
    /// cleared, because the alternative - clearing `bare_refuser` - is
    /// undone by the next bare refusal `handle_missing` sees, so
    /// retirement would last exactly one refusal and the live note
    /// would re-emit every cycle. `bare_refuser` must stay armed
    /// regardless: the suspect/soft-430 attribution logic still needs
    /// to know this server's refusals arrive unverifiable.
    fence_off: Vec<AtomicBool>,
    /// M14e tiers: per-server level and live-worker counts. A fill
    /// server's gate only counts LIVE lower-level servers, so a dead
    /// primary (all its workers bowed out) never wedges the queue.
    levels: Vec<u32>,
    alive: Vec<AtomicUsize>,
    /// Per-server: latched true the first time any worker holds a usable
    /// connection (fresh dial or warm-pool). Read into
    /// `PoolStats::ever_connected` when the run returns.
    connected: Vec<AtomicBool>,
    /// §15e per-SERVER auth state, one slot per server index.
    ///
    /// A refusal to authenticate is a property of the server, not of the
    /// worker that happened to discover it, but every worker used to
    /// rediscover it independently: with 8 connections that is 8 workers
    /// x `max_connect_attempts`, each behind its own growing backoff, all
    /// hammering an account that has already said no. For a Giganews
    /// `481 max simultaneous IP addresses reached` that is precisely the
    /// wrong response - the refusal IS about connection count, and behind
    /// a load-balancing multi-WAN router each retry can present a fresh
    /// WAN IP and re-exhaust the very cap it is failing on.
    ///
    /// So the first worker to hear it records it here and the rest read
    /// it instead of re-provoking it.
    auth: Vec<AuthState>,
    /// Live workers across EVERY server (and, on the sharded path, every
    /// shard runtime). `alive` answers "can this server still serve?";
    /// this answers "is anyone at all still able to finish the run?" -
    /// the question the terminal-state invariant turns on. The last
    /// worker out owns [`seal_run`]; see it for why that matters.
    workers_live: AtomicUsize,
    /// M11 stream mode: deadline (ms since `start`, 0 = never engaged)
    /// until which a live /stream reader is considered attached. While
    /// active, workers cap their pipeline to `stream_window()` so a
    /// promoted seek article is never queued behind a deep in-flight
    /// backlog. Refreshed on every reader touch; the linger stops VLC's
    /// per-seek request churn (close + reopen) from flapping the mode.
    stream_until: AtomicU64,
    /// Bumped by every promote() that moves work. Workers blocked mid-read
    /// on a NON-promoted article select on this and abandon the read
    /// (reconnect + uncharged requeue): measured on the real line, a
    /// promoted 32 MB window otherwise lands at the seeking conn's
    /// fair-share (~1/130th of the line) because 100+ busy connections
    /// keep streaming frontier bytes - the whole wave took 4-6 s and a
    /// VLC seek needed several waves. Shedding the fleet on promote
    /// re-dedicates the line to the seek window within ~a reconnect.
    promote_gen: tokio::sync::watch::Sender<u64>,
    /// Approximate count of promoted items still in the pending queue
    /// (set by promote, decremented as workers pop them). Gates the
    /// promote-shed so a stale generation bump can't cause storms.
    promoted_pending: AtomicUsize,
    /// The LAST promote's full id set. The shed immunity check needs it:
    /// an article dispatched BEFORE the promote never carries the
    /// `promoted` flag, yet if its id is in the promoted span, abandoning
    /// it just refetches the same bytes after a reconnect (at play-start
    /// the whole fleet is fetching exactly the head/tail articles the
    /// first promote names - shedding them delayed the volume headers the
    /// extractor needs to classify, live-caught by the ordering e2e).
    promoted_ids: std::sync::Mutex<HashSet<String>>,
    /// Per-server: ms-since-start of the last FRUITLESS full-queue scan
    /// (u64::MAX = never). `next_work`'s scan pops and re-pushes every
    /// item a server can't take - O(queue) under the shared queue lock.
    /// On a mostly-taken-down 12k-segment post (live, 2026-07-20) five
    /// servers that had 430'd everything re-scanned the whole queue every
    /// 25 ms per worker, starving the one server that could still serve:
    /// ~5 MB/s crawling to a flat 0.0 that read as a permanent stall.
    /// A server whose scan just came up empty doesn't rescan within
    /// [`SCAN_RETRY_MS`]; new work only appears via queue mutations, so
    /// the worst case is a one-tick delay picking it up.
    scan_futile: Vec<AtomicU64>,
    /// B3 wire-cap: estimated bytes of BODY responses currently owed to
    /// this pool's pipelines, GLOBAL across servers - the budget-exempt
    /// wire-side memory (pooled ~800 KB bodies + per-conn BufReader).
    /// Charged [`EST_BODY_BYTES`] per dispatched BODY (dups included -
    /// their responses are just as real), released when the item leaves
    /// a worker's pipeline, however it leaves. A fixed estimate keeps
    /// charge/release trivially symmetric; actual sizes only skew the
    /// throttle point, never the balance.
    inflight_body_bytes: AtomicU64,
    /// Per-server windowed throughput signal (M7b.2 steering, see the
    /// `steer` module): a delivered-byte accumulator decayed with a
    /// ~10 s half-life, and the ms-since-start stamp of its last fold
    /// (u64::MAX = never fed - untrained). Fed ONLY beside the
    /// `bytes[]` bump on the 222 body path, so probe or synthetic
    /// traffic can never train it.
    srv_rate_val: Vec<AtomicU64>,
    srv_rate_at: Vec<AtomicU64>,
    /// Per-server dispatch-to-done EWMA in ms, the by-owner twin of
    /// `art_ms` (same fold, same Done-only feeding). 0 = untrained;
    /// the global stays the fleet-wide fallback and clamp source.
    srv_art_ms: Vec<AtomicU64>,
    /// M7b.2 depth steering armed (OR-fold of `PoolConfig::steer_depth`,
    /// like `tail_fanout`).
    steer_depth: bool,
    /// Per-server hysteresis state for the depth clamp (see
    /// `steer_window` in the steer module). Mirrored into
    /// `ServerLive::steered` for the tuner.
    steer_clamped: Vec<AtomicBool>,
    /// M7b.2 envelope racing armed (OR-fold, like `tail_fanout`).
    race_envelope: bool,
    /// §5.7 block-account mask: servers whose bytes are never spent
    /// speculatively, whatever their level.
    block_bits: u32,
    /// Fleet-wide bytes of LOSING dup copies - the hygiene cap's
    /// counter (design 5.2; fleet-wide deliberately, the 3d/3c trap:
    /// per-server counters read zero for cross-server quantities).
    dup_bytes_lost: AtomicU64,
}

/// B3 wire-cap charge per dispatched BODY - the same ~800 KB working
/// estimate the buffer pool and channel depth are sized around.
const EST_BODY_BYTES: u64 = 800 * 1024;

/// How long stream mode outlives the last reader touch. Long enough to
/// span player pauses and per-seek reconnects; short enough that a closed
/// player gives the pool its deep pipelines back.
const STREAM_LINGER: Duration = Duration::from_secs(60);

/// A promote only sheds an in-flight read older than this. Younger reads
/// complete faster than the reconnect would (quit + TLS + BODY ≈ 300 ms)
/// - abandoning them buys nothing and, at play-start, aborts the volume
/// header probes racing the first promote (their displacement behind a
/// 40 MB promoted run stalls extractor classification - caught by the
/// ordering e2e). A read that has already sat this long on a contended
/// line is mid-transfer at ~1/130th fair share, exactly the case where
/// the reconnect wins.
const PROMOTE_SHED_MIN_AGE: Duration = Duration::from_millis(400);

// Timeout/backoff arithmetic lives in `pacing` (split under the size
// gate); the glob keeps every call site and test spelling unchanged.

// TODO 106: one worker's session lifecycle - dial, pipeline, read, and
// every way a session ends - came out whole to pool/session.rs. Imported
// rather than re-exported: these are pool internals, and the glob is what
// keeps `super::handle_body`-style paths working for the test children.
mod session;
use session::*;

mod pacing;
use pacing::*;

// Windowed per-server speed signals for steering and racing (M7b.2) -
// see the module doc. Inherent `impl Shared` methods, so no glob needed;
// pub for `RaceLive`, the run-level racing gauges LiveStats carries.
pub mod steer;

/// Tail fan-out (opt-in, `PoolConfig::tail_fanout`): an idle primary only
/// races a HEALTHY in-flight article once it has been on the wire this
/// long. Same reasoning as `PROMOTE_SHED_MIN_AGE`: a read younger than
/// this finishes faster than the duplicate's dispatch round-trip on any
/// healthy line, so racing it buys nothing and doubles its bytes. A tail
/// article still outstanding past this floor is exactly the straggler
/// the fan-out exists for.
const TAIL_FANOUT_MIN_AGE: Duration = Duration::from_millis(500);

/// Hedge experiment: the flat staleness bound the adaptive one clamps
/// to (and the bound used whenever hedging is off or untrained).
const HEDGE_STALE_MAX: Duration = Duration::from_secs(8);

/// Recycle experiment: consecutive dup-race losses before a connection
/// concludes it is the slow one and redials. One loss can be bad luck
/// (the endgame fan-out races healthy articles on purpose); two in a
/// row with no win between them is a pattern.
const RECYCLE_RACE_LOSSES: u32 = 2;

/// Flap breaker: established-session deaths within [`FLAP_WINDOW`]
/// before a server is clamped to one keeper connection. Six deaths in a
/// minute is a pattern no healthy provider produces; a single bounce or
/// an idle-timeout reap never reaches it.
const FLAP_DEATHS: usize = 6;
const FLAP_WINDOW: Duration = Duration::from_secs(60);

/// Per-connection pipeline depth while stream mode is active. Depth 1
/// means a promoted article waits at most one article's transfer before
/// its BODY goes out - the measured backlog floor behind the M11 seek
/// latency (window 4 × ~120 conns ≈ 360 MB of unpreemptable responses).
/// Line rate ≫ any media bitrate, so the pipelining throughput cost is
/// acceptable for the duration of a stream. `NZBFAST_STREAM_WINDOW`
/// overrides for live A/B tuning.
fn stream_window() -> usize {
    static W: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *W.get_or_init(|| {
        std::env::var("NZBFAST_STREAM_WINDOW")
            .ok()
            .and_then(|v| v.parse().ok())
            .filter(|&w| w >= 1)
            .unwrap_or(1)
    })
}

/// How long a server sits out queue scans after one came up empty.
const SCAN_RETRY_MS: u64 = 100;

/// Consecutive useless sessions - connected, then failed without one
/// well-formed BODY response - before a worker bows out of this server
/// for good. The session-level twin of `max_connect_attempts`.
///
/// The pacing above is otherwise open-ended: a server that connects fine
/// and can never serve a body - a broken or exhausted account - is retried
/// at the 30 s cap forever, one paced retry per article per attempt, and
/// nothing in the loop ever concludes "this server is useless to me". On a
/// large single-server job that stretches the tail (or the whole job) from
/// minutes into hours while making no progress at all.
///
/// Bowing out is the SAME exit connect exhaustion takes - return, drop the
/// worker's `alive` count - so the rest follows from machinery that is
/// already there and already tested: `live_mask` stops counting a server
/// with no workers left, so a multi-server job routes to the healthy
/// backbone, and a single-server job reaches a truthful terminal Failed
/// through `seal_run` instead of stalling silently.
///
/// Sized against the article retry ladder rather than the clock. One
/// article whose response this client can only read as a protocol error
/// (a provider answering a takedown with a non-BODY status, say) burns
/// `article_retries + 1` sessions on its way to terminal - four at the
/// default - and a healthy server must survive a few of those back to
/// back. Twelve leaves room for three such ladders and still bows out
/// after ~4 minutes of default pacing.
const MAX_SESSION_ATTEMPTS: u32 = 12;

/// How many consecutive capacity bounces the LAST prober rides before
/// bowing out (issue #16). Its ladder caps at 2^2 x connect_backoff
/// (~8 s) - a ghost lease can expire at any moment and a 32 s nap
/// past the reopening is wall time a user watches at 0 MB/s - so 75
/// bounces is roughly ten minutes of probing at one paced dial per
/// 8 s, enough for any realistic ghost-session lease and cheap
/// against an account that is genuinely full for good.
const CAP_PROBE_BOUNCES: u32 = 75;

/// M2c.4: at or below this many non-terminal articles the pool is in
/// its ENDGAME - remaining 430-laddering articles are raced across all
/// untried backbones at once instead of hop-by-hop (see `pick_dup`).
/// Small enough that the duplicate traffic is a handful of ~800 KB
/// bodies at worst, large enough to cover realistic damage tails.
const ENDGAME_MAX: usize = 64;

/// One worker's lifetime in the fleet's two head-counts: its server's
/// `alive` (routing) and the run-wide `workers_live` (the terminal-state
/// invariant). Both come down when the worker exits, however it exits -
/// including a panic, where `Drop` runs during the unwind.
///
/// A worker that exits under its own control calls [`retire`](Self::retire)
/// instead, which reports whether it was the LAST one out; only that
/// worker can seal the run, and only it is still holding an outcome
/// sender to seal it with.
struct WorkerLife {
    shared: Arc<Shared>,
    idx: usize,
    retired: bool,
}

impl WorkerLife {
    fn birth(shared: &Arc<Shared>, idx: usize) -> WorkerLife {
        shared.alive[idx].fetch_add(1, Ordering::Relaxed);
        shared.workers_live.fetch_add(1, Ordering::AcqRel);
        WorkerLife {
            shared: shared.clone(),
            idx,
            retired: false,
        }
    }

    /// Leave the fleet deliberately. True when this was the last live
    /// worker of the whole run - exactly one caller ever sees it.
    fn retire(mut self) -> bool {
        self.retired = true;
        let prev = self.shared.alive[self.idx].fetch_sub(1, Ordering::Relaxed);
        note_server_dark(&self.shared, self.idx, prev);
        self.shared.workers_live.fetch_sub(1, Ordering::AcqRel) == 1
    }
}

impl Drop for WorkerLife {
    fn drop(&mut self) {
        if self.retired {
            return; // retire() already did the arithmetic
        }
        let prev = self.shared.alive[self.idx].fetch_sub(1, Ordering::Relaxed);
        note_server_dark(&self.shared, self.idx, prev);
        self.shared.workers_live.fetch_sub(1, Ordering::AcqRel);
    }
}

/// The fleet shrank: `prev == 1` means the departing worker was its
/// server's LAST, so from this moment the server contributes nothing to
/// the run - `live_mask` no longer counts it. That is the single most
/// throughput-denting thing a pool can do quietly, and until this marker
/// existed it WAS quiet: each worker bowed out alone (session or connect
/// exhaustion, an auth yield) and no one said the server itself was gone.
///
/// Natural wind-downs are not bow-outs: with no work pending, or the run
/// aborted or draining, every worker leaves and none of it belongs on
/// the graph. Fires at most once per server per run by construction -
/// `alive` only ever crosses 1 -> 0 once, since workers are never
/// re-spawned after the ramp.
fn note_server_dark(shared: &Shared, idx: usize, prev: usize) {
    if prev != 1
        || shared.pending.load(Ordering::Acquire) == 0
        || shared.aborted.load(Ordering::Acquire)
        || shared.draining.load(Ordering::Acquire)
    {
        return;
    }
    let Some(live) = &shared.live else {
        return;
    };
    let others = shared
        .alive
        .iter()
        .enumerate()
        .filter(|(i, a)| *i != idx && a.load(Ordering::Relaxed) > 0)
        .count();
    let detail = match others {
        0 => "out of the run - its connections kept failing, and no other server is left",
        1 => "out of the run - its connections kept failing; the remaining server carries on",
        _ => "out of the run - its connections kept failing; the other servers carry on",
    };
    live.note(idx, "retired", detail);
}

impl Shared {
    /// Adaptive pre-byte budget for a server (TODO 96.1): 4x its
    /// time-to-status EWMA, clamped to [2 s, 10 s]. Unmeasured servers
    /// budget at the ceiling - generosity until the first sample, never
    /// a guess. With pipelining the status line is often already
    /// buffered (a ~0 ms sample); the floor keeps the budget honest
    /// against that collapse.
    fn ttfb_budget(&self, idx: usize) -> Duration {
        Duration::from_millis(ttfb_budget_ms(self.ttfb_ms[idx].load(Ordering::Relaxed)))
    }

    /// TTFB-suspicion bound for a server (TODO 115): see
    /// [`ttfb_suspect_ms`].
    fn ttfb_suspect_after(&self, idx: usize) -> Duration {
        Duration::from_millis(ttfb_suspect_ms(self.ttfb_ms[idx].load(Ordering::Relaxed)))
    }

    /// Feed one measured time-to-status into the server's EWMA
    /// (alpha 0.2, integer ms, floor 1 so a fast loopback sample can't
    /// re-zero the cell back to "unmeasured"). Plain load/store: a lost
    /// update under a race is one dropped sample, not a wrong number.
    fn note_ttfb(&self, idx: usize, sample: Duration) {
        let ms = (sample.as_millis() as u64).max(1);
        let cell = &self.ttfb_ms[idx];
        let old = cell.load(Ordering::Relaxed);
        let new = if old == 0 { ms } else { (old * 4 + ms) / 5 };
        cell.store(new.max(1), Ordering::Relaxed);
    }

    /// A pre-byte timeout on this server: widen the budget instead of
    /// leaving it where it was.
    ///
    /// Only SUCCESSFUL status reads feed the EWMA, so a budget trained
    /// down to the 2 s floor by pipelined ~0 ms samples had no way back
    /// up if the provider then settled at a stable latency above it:
    /// every read timed out, every timeout produced no sample, and
    /// healthy articles failed forever on a link the flat 30 s path
    /// would have served (Codex sweep 3 Aug M4). A timeout is evidence
    /// too - censored evidence ("at least this long"), so it is folded
    /// in as a doubling rather than a measurement, and the next
    /// successful sample decays it back down through the ordinary EWMA.
    ///
    /// The doubling is applied to the budget that just EXPIRED, not to
    /// the raw EWMA, because the floor routinely hides the EWMA far
    /// below the budget it produced. Doubling the raw value took a
    /// 1 ms EWMA through 2, 4, 8, 16 ms - four charged attempts that
    /// every one of them still spent at the flat 2 s floor, so a
    /// provider that settled at 2.5 s failed every article before the
    /// budget could widen a millisecond (Codex sweep 2, 3 Aug M6).
    /// Escalating from the expired budget makes the next attempt's
    /// budget strictly larger than the one that just failed - 2 s, 4 s,
    /// 8 s, ceiling - so the retry allowance is spent probing upwards
    /// instead of re-testing the same floor four times.
    fn note_ttfb_timeout(&self, idx: usize) {
        let cell = &self.ttfb_ms[idx];
        let old = cell.load(Ordering::Relaxed);
        cell.store(escalated_ttfb_ms(old), Ordering::Relaxed);
    }

    /// Refresh the stream-mode deadline: a reader touched the hub now.
    fn note_stream(&self) {
        let now = self.start.elapsed().as_millis() as u64;
        self.stream_until
            .store(now + STREAM_LINGER.as_millis() as u64, Ordering::Release);
    }

    /// Is a /stream reader considered attached (touched within the linger)?
    fn stream_active(&self) -> bool {
        let until = self.stream_until.load(Ordering::Acquire);
        until != 0 && (self.start.elapsed().as_millis() as u64) < until
    }

    /// Bits of every server that still has at least one worker running.
    /// A server whose workers all bowed out (connect exhaustion) can never
    /// answer for its untried articles - terminal decisions must be made
    /// against this mask, not the full server set.
    fn live_mask(&self) -> u32 {
        let mut m = 0u32;
        for (si, a) in self.alive.iter().enumerate() {
            if a.load(Ordering::Relaxed) > 0 {
                m |= server_bit(si);
            }
        }
        m
    }

    /// Bits a level-L server must see in tried_430 before it may take
    /// queued work: every live server on a lower level.
    fn required_mask(&self, level: u32) -> u32 {
        let mut m = 0u32;
        for (si, &l) in self.levels.iter().enumerate() {
            if l < level && self.alive[si].load(Ordering::Relaxed) > 0 {
                m |= server_bit(si);
            }
        }
        m
    }

    /// Build the queue, seeding each Work's `tried_430` with the servers
    /// whose retention can't cover it. Articles outside EVERY server's
    /// retention never enter the queue (no worker could pop them - they'd
    /// rotate forever); they're returned for an immediate Missing report.
    fn new(
        reqs: Vec<ArticleReq>,
        servers: &[(ServerConfig, PoolConfig)],
    ) -> (Arc<Shared>, Vec<String>) {
        let n_servers = servers.len();
        let retentions: Vec<u32> = servers.iter().map(|(s, _)| s.retention_days).collect();
        let all = servers_mask(n_servers);
        let mut queue: VecDeque<Work> = VecDeque::with_capacity(reqs.len());
        let mut unservable: Vec<String> = Vec::new();
        // A repeated id charges `pending` per occurrence but `claim_done`
        // credits once - the run would never turn terminal and every worker
        // would idle-loop forever. Malformed NZBs do repeat <segment> ids,
        // and this guards every pool entry point regardless of what the
        // caller built: each id is requested exactly once.
        let mut seen: HashSet<String> = HashSet::new();
        let mut dups = 0usize;
        let mut ages: HashMap<String, u32> = HashMap::new();
        let mut parts: HashMap<String, u32> = HashMap::new();
        for r in reqs {
            if !seen.insert(r.id.clone()) {
                dups += 1;
                continue;
            }
            if r.age_days > 0 {
                ages.insert(r.id.clone(), r.age_days);
            }
            if r.part > 0 {
                parts.insert(r.id.clone(), r.part);
            }
            let seed = retention_mask(&retentions, r.age_days);
            if seed & all == all {
                unservable.push(r.id);
            } else {
                queue.push_back(Work {
                    id: r.id,
                    attempts: 0,
                    promoted: false,
                    tried_430: seed,
                    tried_fail: 0,
                    dup: false,
                    prebyte_expiries: 0,
                    soft_430: 0,
                    fenced: false,
                    rearms: 0,
                    ladder: false,
                });
            }
        }
        if dups > 0 {
            info!(
                target: "pool",
                "dropped {dups} duplicate article request(s) - each id is fetched once"
            );
        }
        let pending = AtomicUsize::new(queue.len());
        let shared = Arc::new(Shared {
            queue: Mutex::new(queue),
            pending,
            done: std::sync::Mutex::new(HashSet::new()),
            inflight: std::sync::Mutex::new(HashMap::new()),
            bytes: (0..n_servers)
                .map(|_| Arc::new(AtomicU64::new(0)))
                .collect(),
            ttfb_ms: (0..n_servers).map(|_| AtomicU64::new(0)).collect(),
            ends: (0..n_servers)
                .map(|_| std::array::from_fn(|_| AtomicU64::new(0)))
                .collect(),
            blocked_ms: (0..n_servers).map(|_| AtomicU64::new(0)).collect(),
            ages,
            parts,
            crc_retried: std::sync::Mutex::new(HashSet::new()),
            soft_rearm: std::sync::Mutex::new(HashMap::new()),
            soft_rearm_n: AtomicUsize::new(0),
            handed: std::sync::Mutex::new(HashMap::new()),
            steer_inbox: std::sync::Mutex::new(Vec::new()),
            done_ok: std::sync::Mutex::new(HashSet::new()),
            start: Instant::now(),
            deferred: AtomicU64::new(0),
            dups_issued: AtomicU64::new(0),
            tail_started: std::sync::Mutex::new(None),
            finished: tokio::sync::watch::Sender::new(false),
            aborted: AtomicBool::new(false),
            draining: AtomicBool::new(false),
            drained_at: std::sync::Mutex::new(None),
            cancelled: std::sync::Mutex::new(HashMap::new()),
            dup_wins: AtomicU64::new(0),
            arrival_ack: servers.iter().any(|(_, c)| c.arrival_ack),
            tail_fanout: servers.iter().any(|(_, c)| c.tail_fanout),
            tail_fanout_early: servers.iter().any(|(_, c)| c.tail_fanout_early),
            hedge: servers.iter().any(|(_, c)| c.hedge),
            ttfb_hedge: servers
                .iter()
                .any(|(_, c)| c.ttfb_hedge && c.adaptive_timeout),
            suspect_pending: AtomicBool::new(false),
            art_ms: AtomicU64::new(0),
            hedges_issued: AtomicU64::new(0),
            live: servers.iter().find_map(|(_, c)| c.live.clone()),
            race_note_at: AtomicU64::new(0),
            races_at_note: AtomicU64::new(0),
            wire_note_at: AtomicU64::new(0),
            spares: (0..n_servers)
                .map(|_| std::sync::Mutex::new(None))
                .collect(),
            spare_filler_started: (0..n_servers).map(|_| AtomicBool::new(false)).collect(),
            flap_deaths: (0..n_servers)
                .map(|_| std::sync::Mutex::new(VecDeque::new()))
                .collect(),
            flap_keeper: (0..n_servers).map(|_| AtomicUsize::new(0)).collect(),
            sessions: (0..n_servers).map(|_| AtomicUsize::new(0)).collect(),
            flap_cap_seen: (0..n_servers).map(|_| AtomicUsize::new(0)).collect(),
            flap_noted: (0..n_servers).map(|_| AtomicBool::new(false)).collect(),
            bare_refuser: (0..n_servers).map(|_| AtomicBool::new(false)).collect(),
            fence_ok: (0..n_servers).map(|_| AtomicBool::new(false)).collect(),
            fence_dud: (0..n_servers).map(|_| AtomicUsize::new(0)).collect(),
            fence_off: (0..n_servers).map(|_| AtomicBool::new(false)).collect(),
            levels: servers.iter().map(|(s, _)| s.level).collect(),
            alive: (0..n_servers).map(|_| AtomicUsize::new(0)).collect(),
            connected: (0..n_servers).map(|_| AtomicBool::new(false)).collect(),
            auth: (0..n_servers).map(|_| AuthState::default()).collect(),
            workers_live: AtomicUsize::new(0),
            stream_until: AtomicU64::new(0),
            promote_gen: tokio::sync::watch::Sender::new(0),
            promoted_pending: AtomicUsize::new(0),
            promoted_ids: std::sync::Mutex::new(HashSet::new()),
            scan_futile: (0..n_servers).map(|_| AtomicU64::new(u64::MAX)).collect(),
            inflight_body_bytes: AtomicU64::new(0),
            srv_rate_val: (0..n_servers).map(|_| AtomicU64::new(0)).collect(),
            srv_rate_at: (0..n_servers).map(|_| AtomicU64::new(u64::MAX)).collect(),
            srv_art_ms: (0..n_servers).map(|_| AtomicU64::new(0)).collect(),
            steer_depth: servers.iter().any(|(_, c)| c.steer_depth),
            steer_clamped: (0..n_servers).map(|_| AtomicBool::new(false)).collect(),
            race_envelope: servers.iter().any(|(_, c)| c.race_envelope),
            block_bits: steer::block_bits(servers),
            dup_bytes_lost: AtomicU64::new(0),
        });
        (shared, unservable)
    }

    /// NZBFAST_POOL_DEBUG=1: dump unresolved queue/inflight state from a
    /// worker's idle branch, at most once per 5 s. Diagnostic only.
    fn debug_dump_idle(&self) {
        static LAST: AtomicU64 = AtomicU64::new(0);
        let now = self.start.elapsed().as_secs();
        let last = LAST.load(Ordering::Relaxed);
        if now < last + 5
            || LAST
                .compare_exchange(last, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_err()
        {
            return;
        }
        let alive: Vec<usize> = self
            .alive
            .iter()
            .map(|a| a.load(Ordering::Relaxed))
            .collect();
        info!(
            target: "pool-debug",
            "t={now}s pending={} alive={alive:?}",
            self.pending.load(Ordering::Relaxed)
        );
        if let Ok(q) = self.queue.try_lock() {
            info!(target: "pool-debug", "queue={} item(s)", q.len());
            for w in q.iter().take(30) {
                info!(
                    target: "pool-debug",
                    "  q {} tried_430={:06b} tried_fail={:06b} attempts={} dup={}",
                    w.id, w.tried_430, w.tried_fail, w.attempts, w.dup
                );
            }
        } else {
            info!(target: "pool-debug", "queue lock busy");
        }
        let inf = self.inflight.lock_ok();
        info!(target: "pool-debug", "inflight={} entr(ies)", inf.len());
        for (id, i) in inf.iter().take(30) {
            info!(
                target: "pool-debug",
                "  inflight {} srv={} age={:.1}s dups={} tried_430={:06b}",
                id,
                i.server,
                i.dispatched.elapsed().as_secs_f64(),
                i.dups,
                i.tried_430
            );
        }
    }

    /// Mark one article terminal; wakes every worker when the last lands.
    fn complete_one(&self) {
        if self.pending.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.mark_drained();
            let _ = self.finished.send(true);
        }
    }

    /// The last article just went terminal: latch the moment and mark
    /// the graph. This is the marker that stops the natural end-of-job
    /// throughput fall from reading as a fault - the line drops to zero
    /// here because there is nothing left to fetch, not because
    /// anything broke.
    fn mark_drained(&self) {
        *self.drained_at.lock_ok() = Some(Instant::now());
        if let Some(l) = &self.live {
            l.note_run(
                "drained",
                "all article data is in - nothing left to download",
            );
        }
    }

    /// Called after each duplicate dispatch is issued. Emits at most one
    /// run-level `racing` marker per [`BURST_WINDOW_MS`], and only for a
    /// window holding at least [`RACE_BURST`] dups+hedges - the endgame
    /// of a healthy job issues a handful and must not mark the graph.
    fn note_race_burst(&self) {
        let Some(live) = &self.live else {
            return;
        };
        let total =
            self.dups_issued.load(Ordering::Relaxed) + self.hedges_issued.load(Ordering::Relaxed);
        let now = now_ms();
        let opened = self.race_note_at.load(Ordering::Relaxed);
        if opened == 0 {
            if self
                .race_note_at
                .compare_exchange(0, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                self.races_at_note
                    .store(total.saturating_sub(1), Ordering::Relaxed);
            }
            return;
        }
        if now.saturating_sub(opened) < BURST_WINDOW_MS {
            return;
        }
        if self
            .race_note_at
            .compare_exchange(opened, now, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        let since = total.saturating_sub(self.races_at_note.swap(total, Ordering::Relaxed));
        if since >= RACE_BURST {
            live.note_run(
                "racing",
                format!(
                    "{since} duplicate fetches issued in the last {} seconds - \
                     racing slow articles so the job can finish",
                    BURST_WINDOW_MS / 1000
                ),
            );
        }
    }

    fn report_diagnostics(&self) {
        let dups = self.dups_issued.load(Ordering::Relaxed);
        let wins = self.dup_wins.load(Ordering::Relaxed);
        let hedges = self.hedges_issued.load(Ordering::Relaxed);
        let art = self.art_ms.load(Ordering::Relaxed);
        let spend = self.dup_spend_line();
        let ts = *self.tail_started.lock_ok();
        let da = *self.drained_at.lock_ok();
        let run = self.start.elapsed().as_secs_f64();
        match (ts, da) {
            (Some(t), Some(d)) => info!(
                target: "pool",
                "run {run:.2}s · queue dry at {:.2}s · drained at {:.2}s · {dups} dups ({wins} won) · {hedges} hedges · art {art} ms{spend}",
                (t - self.start).as_secs_f64(),
                (d - self.start).as_secs_f64(),
            ),
            _ => info!(
                target: "pool",
                "run {run:.2}s · no tail · {dups} dups ({wins} won) · {hedges} hedges · art {art} ms{spend}"
            ),
        }
    }

    /// Average delivery rate of a server since the run started, B/s.
    ///
    /// This is a server's SHARE of the job, not its speed: a server given
    /// four times the connections delivers roughly four times the bytes at
    /// identical per-connection speed. Comparisons that mean "is this one
    /// slower" want [`Self::rate_per_worker`].
    fn rate(&self, server: usize) -> f64 {
        let el = self.start.elapsed().as_secs_f64().max(0.5);
        self.bytes[server].load(Ordering::Relaxed) as f64 / el
    }

    /// [`Self::rate`] divided by the server's live workers: what one of
    /// its connections is actually managing, which is the comparable
    /// quantity across servers with different connection counts.
    /// Record WHY a session ended. `slot` indexes [`SessionEnds`] in
    /// field order (0 peer, 1 protocol, 2 prebyte, 3 stall, 4 ours).
    /// Snapshot this server's session-end tally for [`PoolStats`].
    fn session_ends(&self, server: usize) -> SessionEnds {
        let Some(row) = self.ends.get(server) else {
            return SessionEnds::default();
        };
        let g = |i: usize| row[i].load(Ordering::Relaxed);
        SessionEnds {
            peer: g(0),
            protocol: g(1),
            prebyte: g(2),
            stall: g(3),
            ours: g(4),
        }
    }

    /// Count a session end by cause - slots 0 peer, 1 protocol, 2
    /// prebyte, 3 stall, 4 ours - in BOTH the CLI tally (`ends`) and
    /// the dashboard's live per-server counters, from the one call so
    /// the two can never diverge (ends_ours used to be initialized and
    /// never incremented because the live bump was pasted per site).
    fn note_session_end(&self, server: usize, slot: usize) {
        if let Some(row) = self.ends.get(server)
            && let Some(c) = row.get(slot)
        {
            c.fetch_add(1, Ordering::Relaxed);
        }
        if let Some(l) = &self.live
            && let Some(sl) = l.servers.get(server)
        {
            let c = match slot {
                0 => &sl.ends_peer,
                1 => &sl.ends_protocol,
                2 => &sl.ends_prebyte,
                3 => &sl.ends_stall,
                _ => &sl.ends_ours,
            };
            c.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn rate_per_worker(&self, server: usize) -> f64 {
        let alive = self.alive[server].load(Ordering::Relaxed).max(1) as f64;
        self.rate(server) / alive
    }

    /// True when some OTHER live server could take this work item: it
    /// hasn't 430'd it, hasn't transport-failed it, and its fill gate (if
    /// any) is satisfied. Used to steer a transport-failed article's retry
    /// away from the server that just failed it.
    fn other_can_take(&self, w: &Work, me: usize) -> bool {
        for (si, &level) in self.levels.iter().enumerate() {
            if si == me || self.alive[si].load(Ordering::Relaxed) == 0 {
                continue;
            }
            let bit = server_bit(si);
            if w.tried_430 & bit != 0 || w.tried_fail & bit != 0 {
                continue;
            }
            let required = if level > 0 {
                self.required_mask(level)
            } else {
                0
            };
            if w.tried_430 & required == required {
                return true;
            }
        }
        false
    }

    /// M11 stream mode: should this server LEAVE a promoted (seek) item
    /// for a faster one? Seek latency is per-article latency - a slow
    /// backbone's connection sitting on a playhead article costs the
    /// player seconds. Mirror of the tried_fail steering: skip only when
    /// some LIVE, eligible server is measurably faster per worker (>2×),
    /// so promoted work is never stranded - with no clear winner (cold
    /// start, single server) everyone takes it. Judged on the WINDOWED
    /// per-conn rate (steer module) since M7b.2: the whole-run average
    /// answered "was this server slow at some point", and shaping that
    /// starts or lifts mid-run flipped that answer wrongly for the rest
    /// of the run.
    fn faster_can_take(&self, w: &Work, me: usize) -> bool {
        let mine = self.steer_rate_per_worker(me);
        for (si, &level) in self.levels.iter().enumerate() {
            if si == me || self.alive[si].load(Ordering::Relaxed) == 0 {
                continue;
            }
            let bit = server_bit(si);
            if w.tried_430 & bit != 0 || w.tried_fail & bit != 0 {
                continue;
            }
            let required = if level > 0 {
                self.required_mask(level)
            } else {
                0
            };
            if w.tried_430 & required != required {
                continue;
            }
            if self.steer_rate_per_worker(si) > 2.0 * mine {
                return true;
            }
        }
        false
    }

    /// Flap breaker: record an established-session death, trimming the
    /// window in the same visit.
    fn note_flap(&self, idx: usize) {
        let mut d = self.flap_deaths[idx].lock_ok();
        let now = Instant::now();
        d.push_back(now);
        while d
            .front()
            .is_some_and(|t| now.duration_since(*t) > FLAP_WINDOW)
        {
            d.pop_front();
        }
    }

    /// Flap breaker: has this server accumulated [`FLAP_DEATHS`]
    /// established-session deaths inside [`FLAP_WINDOW`]?
    fn is_flapping(&self, idx: usize) -> bool {
        let mut d = self.flap_deaths[idx].lock_ok();
        let now = Instant::now();
        while d
            .front()
            .is_some_and(|t| now.duration_since(*t) > FLAP_WINDOW)
        {
            d.pop_front();
        }
        d.len() >= FLAP_DEATHS
    }

    /// Cap estimation (TODO 115): a dial just bounced off this server's
    /// capacity refusal, so the sessions we hold at this instant are
    /// what the provider is willing to serve concurrently. Keep the
    /// high-water across bounces.
    fn note_cap_bounce(&self, idx: usize) {
        let held = self.sessions[idx].load(Ordering::Acquire);
        self.flap_cap_seen[idx].fetch_max(held, Ordering::AcqRel);
    }

    /// How many keeper connections a flap-clamped server is worth.
    /// The shipped answer is one. With `flap_cap_keepers` on and an
    /// OBSERVED accept cap (a capacity bounce sampled while we held at
    /// least one session), it is the observed cap - never above the
    /// per-server connection budget, which is where the account's own
    /// limits already landed; an unobserved cap stays at one, so a
    /// server that flaps without ever refusing a dial (a throttling
    /// account, a middlebox) keeps the conservative clamp.
    fn flap_keeper_target(&self, idx: usize, cfg: &PoolConfig) -> usize {
        if !cfg.flap_cap_keepers {
            return 1;
        }
        match self.flap_cap_seen[idx].load(Ordering::Acquire) {
            0 => 1,
            cap => cap.min(cfg.connections.max(1)),
        }
    }

    /// Some OTHER server has live workers - the precondition for
    /// clamping this one (a lone server keeps its whole fleet: churn
    /// beats zero throughput when there is no alternative).
    fn other_live(&self, me: usize) -> bool {
        self.alive
            .iter()
            .enumerate()
            .any(|(i, a)| i != me && a.load(Ordering::Relaxed) > 0)
    }

    /// First-emitter check: true exactly once per id.
    fn claim_done(&self, id: &str) -> bool {
        self.done.lock_ok().insert(id.to_string())
    }

    /// §129 3g: a session has just shown it was reading responses off by
    /// one, so every bare refusal in its ledger is positional evidence
    /// collected from a misaligned socket - void the passes those
    /// refusals spent, so the next refusal for those articles is first
    /// evidence again rather than a confirmation.
    ///
    /// `ids` is the window since that session last read an id it could
    /// check, not its whole history: a desync is monotone, so anything
    /// before a checked id came off an aligned socket. Callers decide
    /// what counts as showing it - an id mismatch or an unusable status
    /// is proof, a stall with requests outstanding is the same event
    /// seen from the end of the pipeline.
    ///
    /// The ledger is capped, and so is this map: the cost of a re-arm is
    /// at most one extra dispatch per article, but an unbounded map on a
    /// 50,000-article job is a leak.
    fn void_soft_430(&self, ids: &VecDeque<String>, group_bits: u32) {
        if ids.is_empty() {
            return;
        }
        let mut m = self.soft_rearm.lock_ok();
        for id in ids {
            if m.len() >= SOFT_REARM_MAX && !m.contains_key(id) {
                break;
            }
            *m.entry(id.clone()).or_insert(0) |= group_bits;
        }
        self.soft_rearm_n.store(m.len(), Ordering::Release);
    }

    /// §129 3g: a fence went unanswered. Harmless when this server has
    /// answered one before - that is the withheld-response fault itself,
    /// seen from the end of the pipeline. But a provider that ignores
    /// DATE outright would fail EVERY fence, so if we have never seen
    /// one answered, the second dud retires fencing for this server and
    /// says so once.
    fn note_fence_dud(&self, idx: usize, cfg: &PoolConfig) {
        if self.fence_ok[idx].load(Ordering::Acquire) {
            return;
        }
        if self.fence_dud[idx].fetch_add(1, Ordering::AcqRel) + 1 < 2 {
            return;
        }
        // Latch the retirement, not `bare_refuser`: the suspect logic
        // in `handle_missing` re-arms that on the very next bare 430,
        // so clearing it retires nothing and re-notes forever.
        if !self.fence_off[idx].swap(true, Ordering::AcqRel)
            && let Some(l) = &cfg.live
        {
            l.note(
                idx,
                "fence-off",
                "this provider does not answer DATE, so its responses cannot be checked for alignment - continuing without the check",
            );
        }
    }

    /// §129 3g: the group bits whose bare-refusal pass this article must
    /// get back, consumed on read. Lock-free when nothing is pending,
    /// which is every run that never met a desynced session.
    fn take_soft_rearm(&self, id: &str) -> u32 {
        if self.soft_rearm_n.load(Ordering::Acquire) == 0 {
            return 0;
        }
        let mut m = self.soft_rearm.lock_ok();
        let bits = m.remove(id).unwrap_or(0);
        self.soft_rearm_n.store(m.len(), Ordering::Release);
        bits
    }

    /// TODO 114 consumer steer: park a claimed, about-to-be-delivered
    /// body's Work in `handed` so [`QueueControl::note_decoded`] can
    /// requeue it after claim (see the field doc). Always `dup: false`
    /// - whichever copy won the race, a steer requeues an original;
    /// `dup_copy` remembers which kind won so a dup's bad copy can be
    /// discarded rather than owned.
    fn stash_handed(&self, w: &Work, ctx: ServerCtx) {
        self.handed.lock_ok().insert(
            w.id.clone(),
            Handed {
                work: Work {
                    id: w.id.clone(),
                    attempts: w.attempts,
                    promoted: w.promoted,
                    tried_430: w.tried_430,
                    tried_fail: w.tried_fail,
                    dup: false,
                    prebyte_expiries: w.prebyte_expiries,
                    soft_430: w.soft_430,
                    fenced: false,
                    rearms: w.rearms,
                    ladder: false,
                },
                server: ctx.idx,
                group_bits: ctx.group_bits,
                dup_copy: w.dup,
            },
        );
    }

    /// Post-handoff terminal bookkeeping for a Done delivery. Legacy
    /// (no consumer verdicts): the channel owns the body now, and a
    /// lingering `done_ok` entry would keep ±slack neighbors "live"
    /// forever - clear it and complete. Steer mode: a DELIVERED body
    /// keeps both its `done_ok` and `handed` entries until the
    /// consumer's `note_decoded` verdict; an undelivered one (channel
    /// closed - the consumer is gone) can never be acked, so it
    /// finalizes here.
    fn settle_handoff(&self, steer: bool, ack: bool, delivered: bool, arrived: &str) {
        if steer && delivered {
            return;
        }
        if steer {
            self.handed.lock_ok().remove(arrived);
        }
        // TODO 121.4: an acking consumer owns the done_ok removal
        // (note_settled after decode+write), so the entry keeps the
        // article "live" through the channel buffer and the consumer's
        // in-hand batch - the two windows a handoff-side removal left
        // dark. An undelivered body (channel closed) has no consumer
        // left to ack it and settles here as before.
        if !(ack && delivered) {
            self.done_ok.lock_ok().remove(arrived);
        }
        self.complete_one();
    }

    fn register_inflight(&self, w: &Work, server: usize) {
        if w.dup {
            return; // dups are tracked via the original's entry
        }
        self.inflight.lock_ok().insert(
            w.id.clone(),
            Inflight {
                server,
                dispatched: Instant::now(),
                dups: 0,
                tried_430: w.tried_430,
                dup_servers: 0,
                tried_fail: w.tried_fail,
                suspect: false,
            },
        );
    }

    fn deregister_inflight(&self, w: &Work) {
        if !w.dup {
            self.inflight.lock_ok().remove(&w.id);
        }
    }

    /// Done-path deregistration: also feeds the article-time EWMA the
    /// hedge bound trains on. Failure, requeue and shed paths use plain
    /// [`Self::deregister_inflight`] - a requeue's age is not a
    /// completion time.
    fn deregister_inflight_done(&self, w: &Work) {
        if w.dup {
            return; // dups are tracked via the original's entry
        }
        if let Some(inf) = self.inflight.lock_ok().remove(&w.id) {
            let ms = (inf.dispatched.elapsed().as_millis() as u64).max(1);
            let old = self.art_ms.load(Ordering::Relaxed);
            let new = if old == 0 { ms } else { old - old / 8 + ms / 8 };
            self.art_ms.store(new.max(1), Ordering::Relaxed);
            // M7b.2: the by-owner twin. Charged to the entry's OWNER,
            // not the completing worker - when a dup wins, the elapsed
            // time still describes how long the owner held the article.
            self.note_srv_art(inf.server, ms);
        }
    }

    /// Hedge experiment: the staleness bound for the dup race. 3x the
    /// trained article-time EWMA, clamped between the fan-out age floor
    /// and the old flat 8 s - hedging can only be MORE responsive than
    /// the flat rule, never less, and an untrained EWMA keeps the flat
    /// bound.
    fn hedge_stale_bound(&self) -> Duration {
        if !self.hedge {
            return HEDGE_STALE_MAX;
        }
        match self.art_ms.load(Ordering::Relaxed) {
            0 => HEDGE_STALE_MAX,
            ewma => Duration::from_millis((ewma * 3).clamp(
                TAIL_FANOUT_MIN_AGE.as_millis() as u64,
                HEDGE_STALE_MAX.as_millis() as u64,
            )),
        }
    }

    /// B3 wire-cap: charge one dispatched BODY's estimated bytes.
    fn charge_wire(&self) {
        self.inflight_body_bytes
            .fetch_add(EST_BODY_BYTES, Ordering::AcqRel);
    }

    /// B3 wire-cap: release `n` pipeline items' charges - every exit
    /// from a worker's in-flight deque (outcome, requeue, shed, abort)
    /// releases exactly what dispatch charged.
    ///
    /// Saturating, not wrapping. The charge/release pairing is symmetric
    /// by construction (one charge per item in a worker's deque), but one
    /// asymmetry is enough to wrap this counter to ~u64::MAX, after which
    /// `wire_over_cap` answers true forever and every worker in the pool
    /// is pinned at pipeline depth one for the rest of the run. A
    /// saturating floor degrades into "throttles slightly early" instead.
    fn release_wire(&self, n: usize) {
        let owed = EST_BODY_BYTES.saturating_mul(n as u64);
        let _ = self
            .inflight_body_bytes
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |v| {
                // A worker only ever releases charges it holds, and the
                // global is the sum of all live charges, so this holds for
                // every value we can observe - concurrency included. It
                // fires only when some path has put an UNCHARGED item into
                // a worker's pipeline, which is the whole bug class.
                debug_assert!(
                    v >= owed,
                    "wire-cap over-release: {v} charged, releasing {owed}"
                );
                Some(v.saturating_sub(owed))
            });
    }

    /// B3 wire-cap: true when topping up past the one-in-flight floor
    /// must pause. `cap` 0 = uncapped (default outside budgeted runs).
    fn wire_over_cap(&self, cap: u64) -> bool {
        cap > 0 && self.inflight_body_bytes.load(Ordering::Acquire) >= cap
    }

    /// The wire cap just refused a top-up: mark the graph, at most once
    /// per 30 s for the whole run. The check runs on every pipeline
    /// top-up, and an engaged cap answers true on all of them - the gate
    /// is what keeps a slow-disk run from writing nothing but this.
    fn note_wire_cap(&self) {
        let Some(live) = &self.live else {
            return;
        };
        let now = now_ms();
        let prev = self.wire_note_at.load(Ordering::Relaxed);
        if now.saturating_sub(prev) >= 30_000
            && self
                .wire_note_at
                .compare_exchange(prev, now, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            live.note_run(
                "wire",
                "in-flight data reached its memory ceiling - fetching waits \
                 for decode and the disk to catch up",
            );
        }
    }

    /// Tail duplicate-dispatch: pick an article in flight on another
    /// server that is either much slower than `me` or has been sitting on
    /// this article suspiciously long.
    ///
    /// M2c.4 endgame fan-out: when the job's non-terminal remainder is
    /// small and an in-flight article has already 430'd somewhere, the
    /// rate/staleness conditions no longer apply - every backbone that
    /// hasn't tried it races it at once (each at most once, via
    /// `dup_servers`), so the last few poisoned articles reach their
    /// unanimous-430 Missing verdict in one round-trip instead of
    /// walking the server ladder hop by hop (measured ~7 s of 0.0 MB/s
    /// tail on the damaged leg). `required` keeps fill-server economics:
    /// a level-N server only joins once every live lower level 430'd.
    ///
    /// Opt-in tail fan-out (`PoolConfig::tail_fanout`): in the endgame,
    /// an IDLE primary also races HEALTHY in-flight articles - the last
    /// few articles sitting on whichever connection happened to grab
    /// them, while everyone else has gone idle. Gates: endgame only,
    /// level 0 only (block-account bytes are never spent on speed),
    /// empty pipeline only (a busy worker is not the idle capacity this
    /// spends), article on the wire ≥ [`TAIL_FANOUT_MIN_AGE`], and each
    /// server races an article at most once (`dup_servers`) - which also
    /// spreads idle workers across stragglers instead of piling them
    /// all on one. Unlike the two rules above this one may race an
    /// article on ANOTHER CONNECTION OF ITS OWN SERVER: at the tail the
    /// enemy is usually one degraded TCP session, not a slow provider,
    /// and a fresh session to the same host routinely beats it. The
    /// owner connection can never dup itself - the article rides its
    /// pipeline, so its `window_used` is never 0.
    fn pick_dup(
        &self,
        me: usize,
        my_bit: u32,
        group_bits: u32,
        required: u32,
        pipe: Pipeline,
        level: u32,
    ) -> Option<Work> {
        // Early fan-out experiment: the tail latch flips at the exact
        // moment idle capacity first exists (a primary found the queue
        // dry with work still in flight), which with a big fleet is
        // long before pending reaches ENDGAME_MAX - 48 connections at
        // window 4 dry the queue with ~190 articles still on the wire.
        // The idle-only and once-per-server gates below keep the spend
        // self-limiting at any pending count.
        let endgame = self.pending.load(Ordering::Acquire) <= ENDGAME_MAX
            || (self.tail_fanout_early && self.tail_started.lock_ok().is_some());
        // PER-WORKER, like `faster_can_take` above. `rate()` is a server's
        // whole-run byte total over wall time, so it measures its share of
        // the job, and that share is set mostly by how many connections it
        // was given. Comparing shares made a big server judge a smaller one
        // "half my speed" when every connection was equally fast, so its
        // idle workers duplicated the smaller server's in-flight articles
        // as a matter of course - fetching those bytes twice. Dividing by
        // live workers asks the question the heuristic means to ask: is
        // this article's owner actually slower. WINDOWED since M7b.2
        // (steer module): the whole-run average judged "slow owner" with
        // evidence as stale as the run is long.
        let my_rate = self.steer_rate_per_worker(me);
        // Hedge experiment: adaptive staleness bound, and a cap on how
        // many dups staleness ALONE may issue - one per 20 completions
        // plus a small burst allowance. The rate rule and the endgame
        // are never capped; the cap exists so EWMA jitter on a link
        // with occasional slow articles cannot become a dup storm.
        let stale_bound = self.hedge_stale_bound();
        // M7b.2 hygiene cap (design 5.2): at the cap every SPECULATIVE
        // picker stops arming; ladder dups stay exempt (verdicts, not speed).
        let capped = self.dup_spend_capped();
        let done = self.done.lock_ok();
        let hedges_ok =
            !self.hedge || self.hedges_issued.load(Ordering::Relaxed) < 4 + done.len() as u64 / 20;
        let mut inflight = self.inflight.lock_ok();
        // (id, owner_rate, ladder-progress, stale-only) - endgame prefers
        // the article CLOSEST to its verdict, normal phase the slowest
        // owner; stale-only marks a hedge for the issue-rate cap.
        let mut best: Option<(&String, f64, u32, bool)> = None;
        // Tail fan-out candidates: fewest racers first, then longest on
        // the wire - so the second idle worker picks the second
        // straggler, not the same one.
        let mut fan: Option<(&String, u8, Instant)> = None;
        for (id, inf) in inflight.iter() {
            if inf.tried_430 & my_bit != 0
                || inf.dup_servers & my_bit != 0
                || inf.tried_fail & my_bit != 0
                || done.contains(id)
            {
                continue;
            }
            if endgame && inf.tried_430 != 0 {
                if inf.server == me {
                    continue;
                }
                if pipe.payload > 0 {
                    continue; // ladder probes never ride behind a BODY
                }
                if inf.tried_430 & required != required {
                    continue; // fill gate: lower levels first
                }
                let progress = inf.tried_430.count_ones();
                if best.is_none_or(|(_, _, p, _)| progress > p) {
                    best = Some((id, 0.0, progress, false));
                }
                continue;
            }
            // Tail fan-out (opt-in): endgame, healthy article, idle
            // primary. Same-server racing allowed - see the doc above.
            // An article younger than the age floor falls through to the
            // normal rules instead, so switching this on never REMOVES a
            // dup the rate rule would have issued.
            //
            // Refetch legs are exempt (`tried_fail != 0`): a CRC-steer
            // (or plain failure) requeue is already a recovery fetch on
            // a deliberately chosen server, and the same-server
            // allowance made the recovering twin race ITS OWN steered
            // refetches - on a damage leg that dup-storms up to one
            // lost race per steered article (measured 33-43 dups, 0
            // won, +15-18% raw transfer on the corrupt/splitbrain/
            // corruptstorm matrix legs). Such an article still falls
            // through to the slow-owner/stale rules, which a third
            // server may legitimately win with.
            if self.tail_fanout
                && endgame
                && !capped
                && !self.speculative_blocked(my_bit, level)
                && pipe.used == 0
                && inf.tried_fail == 0
                && inf.dispatched.elapsed() >= TAIL_FANOUT_MIN_AGE
            {
                if fan.is_none_or(|(_, d, t)| (inf.dups, inf.dispatched) < (d, t)) {
                    fan = Some((id, inf.dups, inf.dispatched));
                }
                continue;
            }
            if inf.server == me {
                continue;
            }
            if inf.dups >= 1 {
                continue;
            }
            // Block-account economy: a FILL server never races on speed.
            // It only ever joins the endgame 430-ladder above, which is
            // gated on every live lower level having already missed. Its
            // bytes are paid for per gigabyte, so spending them to
            // re-fetch an article a primary is already delivering is a
            // straight loss - and it became reachable the moment the
            // comparison went per-worker, because a fill server has FEW
            // connections and so looks fast by that measure exactly when
            // it is least worth using. §5.7 widens the gate to any
            // server flagged block_account, whatever its level.
            if self.speculative_blocked(my_bit, level) {
                continue;
            }
            let owner_rate = self.steer_rate_per_worker(inf.server);
            // With race_envelope armed, the whole-run 2x slow-owner rule
            // retires in favor of the envelope race + per-owner hedge
            // bound - see `steer::speculative_arm` for the full gates.
            let arm =
                self.speculative_arm(inf, pipe.used, my_rate, owner_rate, stale_bound, capped);
            if let Some(stale_only) = arm
                && (!stale_only || hedges_ok)
                && best.is_none_or(|(_, r, _, _)| owner_rate < r)
            {
                best = Some((id, owner_rate, 0, stale_only));
            }
        }
        // Ladder probes and slow-owner races keep priority - they carry
        // verdict or recovery value; the fan-out is pure speculation.
        if let Some((_, _, _, true)) = best {
            self.hedges_issued.fetch_add(1, Ordering::Relaxed);
        }
        // A ladder pick is the only one whose bytes buy a VERDICT rather
        // than a copy of a body someone else may still deliver - which is
        // why it alone rides a pipeline that already holds probes, and why
        // the item it hands back is marked as one.
        let is_ladder = matches!(best, Some((_, _, p, false)) if p > 0);
        let rule = match best {
            _ if is_ladder => "ladder",
            Some((_, _, _, true)) => "stale",
            Some(_) if self.race_envelope => "envelope",
            Some(_) => "slow-owner",
            None => "fanout",
        };
        let id = best
            .map(|(id, _, _, _)| id.clone())
            .or_else(|| fan.map(|(id, _, _)| id.clone()))?;
        let inf = inflight.get_mut(&id).unwrap();
        if std::env::var_os("NZBFAST_POOL_DEBUG").is_some() {
            eprintln!(
                "[pick-dup] {id}: rule={rule} me={me} owner={} owner_fail={:#b} age={:?}",
                inf.server,
                inf.tried_fail,
                inf.dispatched.elapsed()
            );
        }
        inf.dups += 1;
        inf.dup_servers |= group_bits;
        self.dups_issued.fetch_add(1, Ordering::Relaxed);
        self.mirror_dup_issued();
        self.note_race_burst();
        Some(Work {
            id,
            attempts: 0,
            promoted: false,
            tried_430: 0,
            tried_fail: 0,
            dup: true,
            prebyte_expiries: 0,
            soft_430: 0,
            fenced: false,
            rearms: 0,
            ladder: is_ladder,
        })
    }

    /// TTFB-suspicion (TODO 115): the owner's read reported pre-byte
    /// silence past the suspicion bound. Flag the article for
    /// [`Self::pick_suspect_dup`]. The entry may already be gone (the
    /// timer races the read's own completion) - that's a no-op.
    fn mark_suspect(&self, id: &str) {
        if let Some(inf) = self.inflight.lock_ok().get_mut(id) {
            inf.suspect = true;
            self.suspect_pending.store(true, Ordering::Release);
            if std::env::var_os("NZBFAST_POOL_DEBUG").is_some() {
                eprintln!("[ttfb-hedge] suspect {id} at {:?}", self.start.elapsed());
            }
        }
    }

    /// TTFB-suspicion dup (TODO 115, gated on [`PoolConfig::ttfb_hedge`]):
    /// race a suspect in-flight article NOW, ahead of queued work,
    /// instead of letting its owner wait out the full adaptive pre-byte
    /// budget and a requeue round-trip. Same machinery as every other
    /// dup - first answer wins, `done` arbitrates, the owner's read is
    /// never killed - and the same economics as the stale rule: primaries
    /// only (fill bytes are never spent on speculation), one dup per
    /// article, each server at most once, and every pick counts against
    /// the hedge issue-rate cap so a jittery link cannot dup-storm.
    /// Unlike the stale rule this MAY race same-server: the owner is a
    /// stalled TCP session, and a sibling session to the same host
    /// routinely answers in one round-trip (the tail fan-out precedent).
    /// And like the tail fan-out, IDLE pickers only (empty pipeline):
    /// a busy worker's dup displaces queued work, which prices real
    /// capacity - measured +6-15% wall on the jitter safety rig when
    /// busy pickers joined, because a dup fetch can eat the same
    /// pre-byte delay that raised the suspicion. Mid-run the pool is
    /// capacity-bound and the hedge cannot win wall time there anyway;
    /// its whole measured payout is at the supply-limited tail, where
    /// idle pickers exist by definition.
    fn pick_suspect_dup(
        &self,
        my_bit: u32,
        group_bits: u32,
        level: u32,
        window_used: usize,
    ) -> Option<Work> {
        if !self.ttfb_hedge
            || self.speculative_blocked(my_bit, level)
            || window_used > 0
            || !self.suspect_pending.load(Ordering::Acquire)
            || self.dup_spend_capped()
        {
            return None;
        }
        let done = self.done.lock_ok();
        if self.hedges_issued.load(Ordering::Relaxed) >= 4 + done.len() as u64 / 20 {
            return None; // capped; the budget path still rescues
        }
        let mut inflight = self.inflight.lock_ok();
        // Oldest suspicion first: it has the least budget left.
        let picked: Option<String> = inflight
            .iter()
            .filter(|(id, inf)| {
                inf.suspect
                    && inf.dups == 0
                    && inf.tried_430 & my_bit == 0
                    && inf.dup_servers & my_bit == 0
                    && inf.tried_fail & my_bit == 0
                    && !done.contains(*id)
            })
            .min_by_key(|(_, inf)| inf.dispatched)
            .map(|(id, _)| id.clone());
        let Some(id) = picked else {
            // Nothing suspect is still unraced - stop paying the scan
            // until a new suspicion fires.
            self.suspect_pending.store(false, Ordering::Release);
            return None;
        };
        let inf = inflight.get_mut(&id).unwrap();
        inf.dups += 1;
        inf.dup_servers |= group_bits;
        self.hedges_issued.fetch_add(1, Ordering::Relaxed);
        self.dups_issued.fetch_add(1, Ordering::Relaxed);
        self.mirror_dup_issued();
        self.note_race_burst();
        if std::env::var_os("NZBFAST_POOL_DEBUG").is_some() {
            eprintln!("[ttfb-hedge] dup-race {id} at {:?}", self.start.elapsed());
        }
        Some(Work {
            id,
            attempts: 0,
            promoted: false,
            tried_430: 0,
            tried_fail: 0,
            dup: true,
            prebyte_expiries: 0,
            soft_430: 0,
            fenced: false,
            rearms: 0,
            ladder: false,
        })
    }
}

/// Fetch every article in `reqs`, streaming outcomes to `out` as they land.
/// Resolves when all work is terminal. Consumers decode/write concurrently -
/// that's the overlap that makes the zero-copy pipeline work.
pub async fn fetch_all(
    server: &ServerConfig,
    cfg: &PoolConfig,
    reqs: Vec<ArticleReq>,
    out: mpsc::Sender<FetchOutcome>,
) -> PoolStats {
    fetch_all_multi(&[(server.clone(), cfg.clone())], reqs, out)
        .await
        .pop()
        .unwrap_or_default()
}

/// Multi-server variant: all servers' workers pull from ONE shared queue, so
/// faster providers naturally take more of the work - this is both the soak
/// mode (aggregate several accounts past any single provider's cap) and the
/// foundation for Phase 3 tiers. Returns per-server stats, same order as
/// `servers`.
///
/// Note: a 430 Missing is currently terminal even in multi-server mode
/// (fine for soak benches on fresh articles); per-server retry of missing
/// articles is Phase 3a's failedServers ledger.
pub async fn fetch_all_multi(
    servers: &[(ServerConfig, PoolConfig)],
    reqs: Vec<ArticleReq>,
    out: mpsc::Sender<FetchOutcome>,
) -> Vec<PoolStats> {
    fetch_all_multi_ctl(servers, reqs, out, None).await
}

/// `fetch_all_multi` with an optional queue-reorder handle (M11 seeks).
pub async fn fetch_all_multi_ctl(
    servers: &[(ServerConfig, PoolConfig)],
    reqs: Vec<ArticleReq>,
    out: mpsc::Sender<FetchOutcome>,
    ctl: Option<&QueueControl>,
) -> Vec<PoolStats> {
    let (shared, unservable) = Shared::new(reqs, servers);
    if let Some(c) = ctl {
        c.attach(&shared);
    }
    // Outside every server's retention: Missing without a single request.
    for id in unservable {
        let _ = out
            .send(FetchOutcome::Missing {
                id,
                cause: MissingCause::Retention,
            })
            .await;
    }

    let mut workers = Vec::new();
    let mut counters = Vec::new();
    // Hold one reference on the run-wide live count for as long as we are
    // still creating workers. Spawned tasks run on other runtime threads
    // immediately, so without this the first worker of a dead server can
    // fail its connect, find itself alone in the count, and seal the run
    // before its siblings have been born.
    shared.workers_live.fetch_add(1, Ordering::AcqRel);
    for (si, (server, cfg)) in servers.iter().enumerate() {
        // A zero here is not a configuration, it is a hang.
        //
        // `connections: 0` spawns no workers at all, so the run returns with
        // every article still non-terminal and no outcome emitted for any of
        // them. `window: 0` is worse: workers start, but the top-up loop can
        // never admit an article, so each one sleeps forever with pending > 0
        // and `finished` never fires - so the join deadline never arms
        // either. Both are reachable straight from the CLI (`get --window 0`)
        // and neither reports anything to the user.
        //
        // Clamped here rather than at each of the several CLI call sites, so
        // the daemon and every other caller of the public pool API get the
        // same floor.
        let cfg = &PoolConfig {
            connections: cfg.connections.max(1),
            window: cfg.window.max(1),
            ..cfg.clone()
        };
        let connects = Arc::new(AtomicU64::new(0));
        let reconnects = Arc::new(AtomicU64::new(0));
        counters.push((
            shared.bytes[si].clone(),
            connects.clone(),
            reconnects.clone(),
        ));
        let ctx = ctx_for(servers, si);
        for i in 0..cfg.connections {
            let server = server.clone();
            let cfg = cfg.clone();
            let shared = shared.clone();
            let out = out.clone();
            let connects = connects.clone();
            let reconnects = reconnects.clone();
            // Counted from spawn (not first connect) so fill-server gates
            // see primaries as live during the ramp.
            let life = WorkerLife::birth(&shared, si);
            let slot = i as u32;
            let ramp = cfg.ramp_delay * slot;
            workers.push(tokio::spawn(async move {
                worker(
                    &server, &cfg, ctx, shared, out, connects, reconnects, life, ramp, slot,
                )
                .await;
            }));
        }
    }
    // The fleet is complete; from here the workers own the live count.
    shared.workers_live.fetch_sub(1, Ordering::AcqRel);
    // `out` moves into join_fleet, which drops it once the run is sealed:
    // the channel must not close until every article has its outcome.
    join_fleet(&shared, out, workers).await;
    shared.report_diagnostics();

    counters
        .into_iter()
        .enumerate()
        .map(|(si, (b, c, r))| PoolStats {
            bytes: b.load(Ordering::Relaxed),
            connects: c.load(Ordering::Relaxed),
            reconnects: r.load(Ordering::Relaxed),
            ever_connected: shared.connected[si].load(Ordering::Relaxed),
            ends: shared.session_ends(si),
            blocked_ms: shared
                .blocked_ms
                .get(si)
                .map_or(0, |c| c.load(Ordering::Relaxed)),
        })
        .collect()
}

/// How long a worker may outlive the run's terminal state before its join
/// is abandoned. Once every article is terminal (or the run is aborted),
/// workers only have goodbyes left - sub-second on a healthy connection.
const EXIT_GRACE: Duration = Duration::from_secs(5);

/// Join every worker, but never let a straggler outlive a finished run.
/// A worker parked on an await with no timeout - a mute peer mid-QUIT, a
/// half-open TCP connection, a TLS handshake that never answers - would
/// otherwise hang the whole fetch AFTER its bytes are complete (seen live
/// on a 190 GB job: one provider ACKed QUIT, sent no goodbye, and the run
/// never returned). Once `finished` fires, stragglers get `EXIT_GRACE`,
/// then are aborted; dropping the task closes its connection, which is
/// exactly what QUIT was for. Runs that never reach terminal state keep
/// the old unbounded join - the deadlock there is someone else's bug.
///
/// This is also where the run's terminal-state postcondition is enforced.
/// A worker seals the run when it is the last to retire, but a worker that
/// PANICKED never retired, and one abandoned at the grace deadline never
/// finished its pipeline - either can drop the live count to zero with no
/// one left holding an outcome sender. `join_fleet` still holds one, so it
/// gets the last word: seal whatever is outstanding, then report if the
/// invariant somehow still does not hold.
///
/// A panicking worker is a bug in this pool, and it used to be invisible:
/// `JoinError` was discarded and its pipeline's articles simply went
/// quiet. It is now logged with its payload and folded into the sealed
/// articles' error text, so it surfaces in the job's own failure record
/// rather than only in a log nobody reads. We do NOT resume the unwind -
/// this runs inside a daemon serving other jobs, and turning one worker's
/// bug into a whole-download abort trades a reported failure for an
/// unreported one.
async fn join_fleet(
    shared: &Arc<Shared>,
    out: mpsc::Sender<FetchOutcome>,
    workers: Vec<tokio::task::JoinHandle<()>>,
) {
    let mut finished = shared.finished.subscribe();
    let deadline = async move {
        let _ = finished.wait_for(|f| *f).await;
        tokio::time::sleep(EXIT_GRACE).await;
    };
    tokio::pin!(deadline);
    let mut expired = false;
    let mut panics = 0usize;
    let mut note_panic = |r: Result<(), tokio::task::JoinError>| {
        if let Err(e) = r
            && e.is_panic()
        {
            panics += 1;
            error!(target: "pool", "worker panicked - its articles are sealed Failed below: {e}");
        }
    };
    for mut w in workers {
        if !expired {
            let joined = tokio::select! {
                r = &mut w => Some(r),
                _ = &mut deadline => {
                    expired = true;
                    warn!(
                        target: "pool",
                        "worker still parked {}s after the run went terminal \
                         (wedged connection?) - abandoning its goodbye",
                        EXIT_GRACE.as_secs()
                    );
                    None
                }
            };
            if let Some(r) = joined {
                note_panic(r);
                continue;
            }
        }
        w.abort();
        // A cancelled task is not a panic - only report real ones.
        note_panic(w.await);
    }
    let reason = if panics > 0 {
        "a pool worker panicked before this article was fetched"
    } else {
        "no connection worker left to fetch this article"
    };
    seal_run(shared, &out, reason).await;
    let left = shared.pending.load(Ordering::Acquire);
    if left > 0
        && shared.workers_live.load(Ordering::Acquire) == 0
        && !shared.aborted.load(Ordering::Acquire)
        && !shared.draining.load(Ordering::Acquire)
    {
        // Neither the queue nor the inflight map named these, so the pool
        // cannot report them itself. Loud, because it means an article
        // went missing from this module's own bookkeeping. Gated on being
        // the run-wide last owner (workers_live == 0, the same condition
        // seal_run uses): on the sharded path an early shard joins its
        // fleet while other shards still legitimately own pending work.
        error!(
            target: "pool",
            "BUG: fleet joined with {left} article(s) non-terminal and unaccounted \
             for - the caller will see slots with no outcome"
        );
    }
}

/// Per-worker identity for cross-server routing.
#[derive(Clone, Copy)]
struct ServerCtx {
    idx: usize,
    bit: u32,
    #[allow(dead_code)] // mask of every server bit; kept beside bit/group_bits
    all: u32,
    /// Bits of this server's whole mirror group (incl. itself): a 430
    /// here is authoritative for all of them (M14e Group).
    group_bits: u32,
    /// Tier (M14e Level): >0 = fill server, gated in next_work.
    level: u32,
}

/// How many servers the routing bitmasks can represent.
///
/// Every routing decision - `tried_430`, retention, live/fail/required/group -
/// is a `u32` keyed by server index, so there is no bit for index 32 and
/// beyond. Enforced at config load (`Config::load`), which is what makes
/// [`server_bit`] total in practice.
pub const MAX_SERVERS: usize = 32;

/// The routing bit for a server index.
///
/// This used to be spelled `1u32 << si.min(31)`, which ALIASED every server
/// from index 31 upward onto bit 31. Server 31 returning 430 therefore set
/// the bit that server 32 reads as "I already tried here", so once servers
/// 0-31 had missed, an article could go terminal Missing without server 32
/// ever being sent a BODY - even when it held the article. A hostile or
/// merely broken provider at index 31 could suppress the last healthy one.
///
/// Returning 0 for an unrepresentable index is defence in depth only: no bit
/// is strictly safer than another server's bit, but the config cap above is
/// what actually keeps this reachable.
#[inline]
fn server_bit(si: usize) -> u32 {
    if si < MAX_SERVERS { 1u32 << si } else { 0 }
}

fn servers_mask(n: usize) -> u32 {
    if n >= MAX_SERVERS {
        u32::MAX
    } else {
        (1u32 << n) - 1
    }
}

fn ctx_for(servers: &[(ServerConfig, PoolConfig)], si: usize) -> ServerCtx {
    let me = &servers[si].0;
    let mut group_bits = server_bit(si);
    if let Some(g) = &me.group {
        for (sj, (s, _)) in servers.iter().enumerate() {
            if s.group.as_deref() == Some(g.as_str()) {
                group_bits |= server_bit(sj);
            }
        }
    }
    ServerCtx {
        idx: si,
        bit: server_bit(si),
        all: servers_mask(servers.len()),
        group_bits,
        level: me.level,
    }
}

/// Next unit of work for this server: queued articles it hasn't 430'd
/// first (rotating skipped items), then - tail phase - a duplicate of an
/// article in flight on a slower/stalled server.
async fn next_work(
    shared: &Shared,
    ctx: ServerCtx,
    out: &mpsc::Sender<FetchOutcome>,
    // Caller's current pipeline, split by kind (M2c.4): in the ENDGAME a
    // 430-laddering article must not ride BEHIND queued payload bodies
    // - head-of-line blocking on the slowest provider's last windows
    // was the measured 4-6 s straggler tail. It may ride behind OTHER
    // PROBES, which is the whole difference: a refusal is one line, so
    // a window of probes answers in one round trip where the old
    // empty-pipeline rule spent one round trip per probe. That cap -
    // one verdict per connection per RTT - is what made a damaged post
    // sit at 0.0 MB/s for ~10 s before repair while every payload byte
    // was already on disk.
    pipe: Pipeline,
) -> Option<Work> {
    // TTFB-suspicion hedge (TODO 115): an idle worker checks for suspect
    // articles first - their owners are sitting in pre-byte silence
    // RIGHT NOW, and the whole point is to answer inside the budget they
    // have left. One atomic load when dark, quiet, or busy.
    if let Some(w) = shared.pick_suspect_dup(ctx.bit, ctx.group_bits, ctx.level, pipe.used) {
        return Some(w);
    }
    let endgame = shared.pending.load(Ordering::Acquire) <= ENDGAME_MAX;
    // Fill-server gate (M14e): a level-N server only takes queued work
    // that every LIVE lower-level server has already 430'd.
    let required = if ctx.level > 0 {
        shared.required_mask(ctx.level)
    } else {
        0
    };
    // Scan throttle: this server's last full scan found nothing takeable
    // and re-shuffled the whole queue for the privilege. Sit out a tick
    // instead of burning the shared queue lock - at scale that burn
    // starves the servers that DO have work (see `scan_futile`).
    let now_ms = shared.start.elapsed().as_millis() as u64;
    let futile_at = shared.scan_futile[ctx.idx].load(Ordering::Relaxed);
    if futile_at != u64::MAX && now_ms.saturating_sub(futile_at) < SCAN_RETRY_MS {
        return shared.pick_dup(ctx.idx, ctx.bit, ctx.group_bits, required, pipe, ctx.level);
    }
    // An article every LIVE server has 430'd is terminal even if servers
    // whose workers bowed out never saw it - a dead server can't answer,
    // and waiting for it deadlocks the whole run (the queue rotates the
    // item forever). Collected under the lock, reported after.
    let live = shared.live_mask();
    let mut unservable: Vec<String> = Vec::new();
    let mut picked: Option<Work> = None;
    // Promoted items this (slow) server steps PAST: they must go back to
    // the queue FRONT in order - a fast server picks from the front, and
    // rotating seek-critical work to the back would strand it.
    let mut left_for_faster: Vec<Work> = Vec::new();
    {
        let mut q = shared.queue.lock().await;
        // TODO 114 consumer steer: adopt any steered requeues parked
        // in the inbox (the verdict thread never takes this lock -
        // see the `steer_inbox` field doc). Promoted articles keep
        // the promoted-front rule the 430 requeue uses.
        {
            let mut inbox = shared.steer_inbox.lock_ok();
            for w in inbox.drain(..) {
                if w.promoted {
                    let at = q.iter().take_while(|x| x.promoted).count().min(q.len());
                    shared.promoted_pending.fetch_add(1, Ordering::AcqRel);
                    q.insert(at, w);
                } else {
                    q.push_back(w);
                }
            }
        }
        for _ in 0..q.len() {
            let Some(mut w) = q.pop_front() else { break };
            if w.tried_430 & live == live {
                unservable.push(w.id);
                continue;
            }
            if w.tried_430 & ctx.bit != 0
                || w.tried_430 & required != required
                || (w.tried_fail & ctx.bit != 0 && shared.other_can_take(&w, ctx.idx))
                || (endgame && pipe.payload > 0 && w.tried_430 != 0)
            {
                q.push_back(w);
            } else if w.promoted
                && w.tried_430 == 0
                && shared.stream_active()
                && shared.faster_can_take(&w, ctx.idx)
            {
                // Untried promoted work waits briefly for a faster server;
                // once ANY backbone has 430'd it, latency beats speed-
                // matching - whoever can serve it, serves it.
                left_for_faster.push(w);
            } else {
                if w.promoted {
                    let _ = shared.promoted_pending.fetch_update(
                        Ordering::AcqRel,
                        Ordering::Acquire,
                        |v| v.checked_sub(1),
                    );
                }
                // Per-dispatch classification (see `Work::ladder`): an
                // article carrying refusal evidence is walking toward a
                // verdict, and this hop is a probe. One that has never
                // been refused is payload, however long it has been
                // queued.
                w.ladder = w.tried_430 != 0 || w.soft_430 != 0;
                picked = Some(w);
                break;
            }
        }
        for w in left_for_faster.into_iter().rev() {
            q.push_front(w);
        }
    }
    if picked.is_none() {
        shared.scan_futile[ctx.idx].store(now_ms, Ordering::Relaxed);
    }
    for id in unservable {
        if shared.claim_done(&id) {
            let _ = out
                .send(FetchOutcome::Missing {
                    id,
                    cause: MissingCause::Gone,
                })
                .await;
            shared.complete_one();
        }
    }
    if picked.is_some() {
        return picked;
    }
    if ctx.level == 0 && shared.pending.load(Ordering::Acquire) > 0 {
        // Only primaries mark the tail - an idle fill server waiting on
        // its gate isn't evidence the queue ran dry.
        let latched_now = {
            let mut ts = shared.tail_started.lock_ok();
            ts.is_none() && {
                *ts = Some(Instant::now());
                true
            }
        };
        // Phase marker, once per run at the latch: from here the line
        // tapers naturally as the last in-flight articles land, and
        // without a marker that taper reads as a fault.
        if latched_now && let Some(l) = &shared.live {
            l.note_run(
                "tail",
                "every article has been handed out - waiting for the last ones in flight",
            );
        }
    }
    shared.pick_dup(ctx.idx, ctx.bit, ctx.group_bits, required, pipe, ctx.level)
}

/// Sharded variant: split all servers' connections across `shards`
/// independent tokio runtimes (each on its own OS threads with its OWN
/// kqueue/epoll I/O driver), all pulling one shared queue. This is the fix
/// for the single-I/O-driver per-process throughput ceiling (measured:
/// 4.1 Gbps per process at 9% CPU). Blocking call - run it via
/// `tokio::task::spawn_blocking` from async contexts.
pub fn fetch_all_sharded(
    servers: Vec<(ServerConfig, PoolConfig)>,
    reqs: Vec<ArticleReq>,
    out: mpsc::Sender<FetchOutcome>,
    shards: usize,
    ctl: Option<&QueueControl>,
) -> Vec<PoolStats> {
    // The same floor fetch_all_multi_ctl applies, for the same reason: a
    // zero here is not a configuration, it is a hang. This path is the
    // daemon's production one, so it needs the clamp at least as much.
    let mut servers = servers;
    for (_, cfg) in servers.iter_mut() {
        cfg.connections = cfg.connections.max(1);
        cfg.window = cfg.window.max(1);
    }
    let (shared, unservable) = Shared::new(reqs, &servers);
    // Same pause/abort/state-dump hookup as fetch_all_multi_ctl: the ctl
    // attaches to Shared, which every shard's workers already poll - so
    // the daemon keeps its whole control surface on the sharded path.
    if let Some(c) = ctl {
        c.attach(&shared);
    }
    // Outside every server's retention: Missing without a single request.
    // (Blocking send is fine - this whole function is documented blocking.)
    for id in unservable {
        let _ = out.blocking_send(FetchOutcome::Missing {
            id,
            cause: MissingCause::Retention,
        });
    }

    let counters: Vec<_> = servers
        .iter()
        .enumerate()
        .map(|(si, _)| {
            (
                shared.bytes[si].clone(),
                Arc::new(AtomicU64::new(0)),
                Arc::new(AtomicU64::new(0)),
            )
        })
        .collect();

    // Deal (server, per-server ramp step) assignments round-robin to shards.
    let n_shards = shards.max(1);
    let mut plans: Vec<Vec<(usize, u32)>> = vec![Vec::new(); n_shards];
    let mut next_shard = 0usize;
    for (si, (_, cfg)) in servers.iter().enumerate() {
        for ci in 0..cfg.connections {
            plans[next_shard % n_shards].push((si, ci as u32));
            next_shard += 1;
        }
    }

    let servers = Arc::new(servers);
    let counters = Arc::new(counters);
    let mut threads = Vec::new();
    // One spawn-gate reference per shard, released by that shard once its
    // own workers exist (see fetch_all_multi_ctl): shards start on their
    // own OS threads, so an early-dying shard must not seal a run whose
    // other shards have not been built yet.
    shared.workers_live.fetch_add(plans.len(), Ordering::AcqRel);
    for plan in plans {
        let servers = servers.clone();
        let counters = counters.clone();
        let shared = shared.clone();
        let out = out.clone();
        threads.push(std::thread::spawn(move || {
            let rt = match tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => {
                    // This shard never created workers, so release the
                    // spawn gate it was charged before the OS thread
                    // started. Panicking here leaked that count and made
                    // every surviving shard believe work could still
                    // finish, suppressing terminal outcomes.
                    warn!(target: "pool", "shard runtime: {e}");
                    shared.workers_live.fetch_sub(1, Ordering::AcqRel);
                    return;
                }
            };
            rt.block_on(async move {
                let mut tasks = Vec::new();
                for (si, ramp_step) in plan {
                    let ctx = ctx_for(&servers, si);
                    let (server, cfg) = servers[si].clone();
                    let (_, connects, reconnects) = counters[si].clone();
                    let shared = shared.clone();
                    let out = out.clone();
                    let life = WorkerLife::birth(&shared, si);
                    // `ramp_step` is the per-server worker ordinal, so it
                    // doubles as the live-target slot.
                    let ramp = cfg.ramp_delay * ramp_step;
                    tasks.push(tokio::spawn(async move {
                        worker(
                            &server, &cfg, ctx, shared, out, connects, reconnects, life, ramp,
                            ramp_step,
                        )
                        .await;
                    }));
                }
                // This shard's workers exist now - hand the live count over
                // to them.
                shared.workers_live.fetch_sub(1, Ordering::AcqRel);
                // Each shard joins its own tasks; `seal_run` is gated on
                // the run-wide live count, so only the shard whose workers
                // are genuinely the last ones out seals anything.
                join_fleet(&shared, out, tasks).await;
            });
        }));
    }
    for t in threads {
        let _ = t.join();
    }
    // If every shard failed before it could enter an async `join_fleet`,
    // there is nobody left to run the async terminal seal. All shard
    // threads are joined here, so the queue and inflight maps are
    // uncontended and can be sealed on this documented blocking path.
    seal_run_blocking(&shared, &out, "all shard runtimes stopped");
    drop(out);
    shared.report_diagnostics();

    counters
        .iter()
        .enumerate()
        .map(|(si, (b, c, r))| PoolStats {
            bytes: b.load(Ordering::Relaxed),
            connects: c.load(Ordering::Relaxed),
            reconnects: r.load(Ordering::Relaxed),
            ever_connected: shared.connected[si].load(Ordering::Relaxed),
            ends: shared.session_ends(si),
            blocked_ms: shared
                .blocked_ms
                .get(si)
                .map_or(0, |c| c.load(Ordering::Relaxed)),
        })
        .collect()
}

fn seal_run_blocking(
    shared: &Arc<Shared>,
    out: &mpsc::Sender<FetchOutcome>,
    reason: &str,
) -> usize {
    if shared.workers_live.load(Ordering::Acquire) > 0
        || shared.pending.load(Ordering::Acquire) == 0
        || shared.aborted.load(Ordering::Acquire)
        || shared.draining.load(Ordering::Acquire)
    {
        return 0;
    }
    let mut orphans: Vec<String> = {
        let mut q = shared
            .queue
            .try_lock()
            .expect("joined shards cannot hold queue");
        q.drain(..).map(|w| w.id).collect()
    };
    orphans.extend(shared.inflight.lock_ok().drain().map(|(id, _)| id));
    orphans.extend(shared.steer_inbox.lock_ok().drain(..).map(|w| w.id));
    let mut sealed = 0;
    for id in orphans {
        if !shared.claim_done(&id) {
            continue;
        }
        let _ = out.blocking_send(FetchOutcome::Failed {
            id,
            error: reason.to_string(),
        });
        shared.complete_one();
        sealed += 1;
    }
    sealed
}

/// Hand a DRAINED connection to the warm pool, or close it when there is
/// no warm pool (one-shot CLI runs). Callers must have an empty in-flight
/// deque: a connection with unread pipelined responses on it is not
/// reusable and must go through `quit()` instead.
async fn park_or_quit(cfg: &PoolConfig, server: &ServerConfig, conn: Connection) {
    match &cfg.warm {
        Some(w) => w.give(server, conn).await,
        None => conn.quit().await,
    }
}

/// One spawned worker: the connect ramp, the session loop, and the run's
/// terminal-state exit protocol. Every worker leaves through here, so the
/// last one out is the one that seals the run (see [`seal_run`]).
#[allow(clippy::too_many_arguments)]
/// Hot-spare filler: keeps ONE authenticated connection parked for its
/// server until the run ends, re-dialling whenever a worker claims it.
/// Ends with the run (`finished`), on user abort, or on graceful drain -
/// `drain()` deliberately sends no `finished`, so the filler must watch
/// the flag itself or a paused job leaves it looping forever with an
/// authenticated provider session (Codex 5 Aug M4). The 500 ms tick
/// below bounds how late it notices. Quits whatever it still holds on
/// every exit path. Connect failures back off 5 s - a provider at its
/// connection cap refuses the spare and that refusal must not become a
/// dial storm against the very cap the workers depend on.
async fn spare_filler(shared: Arc<Shared>, server: ServerConfig, idx: usize) {
    let mut finished = shared.finished.subscribe();
    loop {
        if *finished.borrow()
            || shared.aborted.load(Ordering::Acquire)
            || shared.draining.load(Ordering::Acquire)
        {
            break;
        }
        let empty = shared.spares[idx].lock_ok().is_none();
        if empty {
            match Connection::connect(&server).await {
                Ok((c, _)) => {
                    *shared.spares[idx].lock_ok() = Some(c);
                }
                Err(_) => {
                    tokio::select! {
                        _ = tokio::time::sleep(Duration::from_secs(5)) => {}
                        _ = finished.wait_for(|f| *f) => break,
                    }
                }
            }
        }
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(500)) => {}
            _ = finished.wait_for(|f| *f) => break,
        }
    }
    // Guard dropped before the await - the lock must never be held
    // across a suspension point.
    let leftover = shared.spares[idx].lock_ok().take();
    if let Some(c) = leftover {
        c.quit().await;
    }
}

async fn worker(
    server: &ServerConfig,
    cfg: &PoolConfig,
    ctx: ServerCtx,
    shared: Arc<Shared>,
    out: mpsc::Sender<FetchOutcome>,
    connects: Arc<AtomicU64>,
    reconnects: Arc<AtomicU64>,
    life: WorkerLife,
    ramp: Duration,
    slot: u32,
) {
    // The ramp paces CONNECT bursts, which is what providers punish (a
    // provider given more sockets than it wants is 3-4x SLOWER, see
    // conntune). A worker that reuses a parked connection performs no
    // connect, so pacing it is pure added latency on exactly the path
    // this mechanism exists to speed up.
    //
    // CLAIM one rather than asking whether one exists. A `has()` probe
    // would let every worker in the fleet see the same single parked
    // connection, all conclude they need no ramp, and all dial at once -
    // reintroducing the burst in the one case the pool is nearly empty.
    // `take` is atomic, so exactly as many workers skip the ramp as
    // there are connections to skip it with.
    //
    // The claim must yield to the run finishing, for the same reason the
    // dial in `session_loop` does (§35): `take` validates its candidate
    // with a DATE round-trip bounded by VALIDATE_TIMEOUT, and that bound
    // is 8 s against EXIT_GRACE's 5 s. A worker validating a peer that
    // has gone mute therefore CANNOT return before `join_fleet` gives up
    // on it, so the run pays the whole grace window - the exact tail §35
    // was about, re-entered through the warm path. Losing the candidate
    // on cancellation is already this code's contract: a validation that
    // runs out of time leaves its DATE unanswered on the socket, so the
    // connection is dropped rather than returned or re-parked.
    let mut fin = shared.finished.subscribe();
    // TODO 112: the live-target park comes BEFORE the warm claim - a
    // slot spawned above the target must hold nothing, and a warm
    // connection it claimed would idle out in its hands rather than
    // serve an admitted worker. `admitted: false` means the run ended
    // while parked; fall through so `life.retire()` still seals.
    let admitted = match &cfg.live_target {
        Some(t) => wait_for_slot(t, slot, &mut fin, &shared).await,
        None => true,
    };
    let warm_conn = match &cfg.warm {
        Some(w) if admitted => tokio::select! {
            c = w.take(server) => c,
            // Nothing left to claim it for. Fall through as if the pool
            // were empty rather than returning: `life.retire()` below is
            // what seals the run, and no path may skip it.
            _ = run_over(&mut fin, &shared) => None,
        },
        _ => None,
    };
    // The ramp sleep must yield to abort/finish: at 100 connections ×
    // 150 ms a still-ramping worker would otherwise outlive an aborted
    // run by up to 15 s.
    let ramped = admitted
        && (warm_conn.is_some() || {
            tokio::select! {
                _ = tokio::time::sleep(ramp) => true,
                _ = fin.wait_for(|f| *f) => false,
            }
        });
    if ramped {
        session_loop(
            server,
            cfg,
            ctx,
            shared.clone(),
            out.clone(),
            connects,
            reconnects,
            slot,
            warm_conn,
        )
        .await;
    }
    if life.retire() {
        seal_run(
            &shared,
            &out,
            "no connection worker left to fetch this article",
        )
        .await;
    }
}

/// The read-stall bookkeeping split by WHY the read ended (TODO
/// 121.1/.2). A pre-byte adaptive expiry escalates the charged front
/// article's OWN next-attempt budget (per-server widening alone
/// re-floors between that article's retries) and is NOT a flap death:
/// giving up pre-byte was our budget choice, and a heavy-tailed but
/// healthy provider (cold storage at trained-floor budgets) produces
/// FLAP_DEATHS of them a minute without a session actually dying -
/// clamping it to keepers punished the wrong party. A mid-flow stall
/// on an established session stays a death: bytes were moving and
/// stopped, which is the wedge the flap breaker exists for.
fn note_read_stall(
    shared: &Shared,
    idx: usize,
    session_bytes: u64,
    prebyte_expired: bool,
    front: Option<&mut Work>,
) {
    if prebyte_expired {
        if let Some(w) = front {
            w.prebyte_expiries = w.prebyte_expiries.saturating_add(1);
        }
    } else if session_bytes > 0 {
        // Count it where it happens, not at some later redial this
        // worker may never win (a capped provider bounces most
        // re-entries, which hid the churn entirely).
        shared.note_flap(idx);
    }
}

/// Enforce the pool's terminal-state invariant: every article the caller
/// asked for gets exactly one outcome before the outcome channel closes.
///
/// Nothing else guarantees it. A worker bows out for good after
/// `max_connect_attempts` consecutive connect failures, so if every
/// provider is unreachable at startup - or every worker exhausts its
/// reconnects mid-job - the last one returns with articles still queued,
/// or still owned by the `inflight` map of a worker that died holding
/// them. The fleet joins, the senders drop, and the channel closes having
/// said NOTHING about those ids. The engine does eventually notice the
/// unresolved slots, but by then the pool's diagnostics have lied and
/// repair has run against a network ledger that never recorded the
/// failures it is repairing around.
///
/// So whoever turns the lights out - the last worker to retire, or
/// [`join_fleet`] afterwards for workers that panicked or were abandoned
/// mid-flight - drains everything still non-terminal into one `Failed`
/// per id. `claim_done` keeps that "exactly one" even against a straggler
/// emitting its own outcome concurrently.
///
/// Aborted and draining runs are exempt: both are deliberate early stops
/// whose unfinished work belongs to the caller (a resume re-fetches it),
/// and failing it here would journal a user's pause as a download error.
///
/// Returns the number of articles sealed.
async fn seal_run(shared: &Arc<Shared>, out: &mpsc::Sender<FetchOutcome>, reason: &str) -> usize {
    // Not the last one out: on the sharded path another shard's runtime
    // still has workers that can finish this work.
    if shared.workers_live.load(Ordering::Acquire) > 0
        || shared.pending.load(Ordering::Acquire) == 0
        || shared.aborted.load(Ordering::Acquire)
        || shared.draining.load(Ordering::Acquire)
    {
        return 0;
    }
    // Collected under the locks, emitted after: `out` is bounded, and a
    // send that parks on a slow consumer while the queue is held would
    // stall anything still touching the pool. Queue then inflight is the
    // lock order every other path here uses.
    let mut orphans: Vec<String> = Vec::new();
    {
        let mut q = shared.queue.lock().await;
        orphans.extend(q.drain(..).map(|w| w.id));
        let mut inf = shared.inflight.lock_ok();
        orphans.extend(inf.drain().map(|(id, _)| id));
        orphans.extend(shared.steer_inbox.lock_ok().drain(..).map(|w| w.id));
    }
    let mut sealed = 0usize;
    for id in orphans {
        if !shared.claim_done(&id) {
            continue; // a duplicate dispatch already owns this outcome
        }
        let _ = out
            .send(FetchOutcome::Failed {
                id,
                error: reason.to_string(),
            })
            .await;
        shared.complete_one();
        sealed += 1;
    }
    if sealed > 0 {
        error!(
            target: "pool",
            "fleet exhausted with {sealed} article(s) unresolved - reported \
             Failed ({reason}) so the run's terminal ledger is truthful"
        );
    }
    sealed
}

/// M11 stream-mode shed: requeue a deliberately abandoned pipeline.
/// Nothing failed, so nothing is charged an attempt. Items are inserted
/// directly BEHIND the promoted run at the queue front, preserving their
/// relative order: ahead of the promoted run they would re-create the
/// very backlog the shed exists to clear; at the queue back, the head-of-
/// file bytes a sequential player needs next would land after gigabytes
/// of tail. Tail duplicates are dropped (the original owns the outcome).
async fn shed_pipeline(shared: &Shared, inflight: &mut VecDeque<Work>) {
    // B3 wire-cap: the whole pipeline leaves flight in one go.
    shared.release_wire(inflight.len());
    let mut q = shared.queue.lock().await;
    let mut at = q.iter().take_while(|w| w.promoted).count();
    while let Some(w) = inflight.pop_front() {
        if w.dup {
            continue;
        }
        shared.deregister_inflight(&w);
        if shared.done.lock_ok().contains(&w.id) {
            continue; // a dup already emitted this article's outcome
        }
        if w.promoted {
            shared.promoted_pending.fetch_add(1, Ordering::AcqRel);
        }
        let idx = at.min(q.len());
        q.insert(idx, w);
        at += 1;
    }
}

/// On connection death: the front in-flight article (the one that actually
/// errored) is charged an attempt; the rest were casualties of the same
/// connection and requeue free. Articles over budget report Failed. Tail
/// duplicates are dropped silently - the original dispatch owns the
/// outcome (and if the dup had already won, `done` protects the original).
/// Resolves once this worker is no longer needed: every article terminal
/// (`finished`), or a graceful drain under way.
///
/// Used to race blocking work that has no business outliving the run.
/// `drain()` deliberately does not send `finished`, so draining has to be
/// polled rather than awaited - same 250 ms slice as [`backoff_or_finish`],
/// which is the resolution a human notices and far below any dial timeout.
async fn run_over(finished: &mut tokio::sync::watch::Receiver<bool>, shared: &Shared) {
    loop {
        if shared.draining.load(Ordering::Acquire) {
            return;
        }
        tokio::select! {
            _ = finished.wait_for(|f| *f) => return,
            _ = tokio::time::sleep(Duration::from_millis(250)) => {}
        }
    }
}

/// Wait out a connect backoff, but give up the moment the RUN is done.
///
/// Returns false if the work finished while we slept, meaning this worker
/// should retire rather than reconnect.
///
/// A bare sleep here held whole jobs open. Measured on the bench farm with
/// one dead server in a six-server config: a job whose bytes had all
/// arrived by 0.79 s did not RETURN until 3.17 s, so about 75% of it was
/// spent after the last byte with nothing outstanding but a server that
/// was never going to answer. Per-job cost of one dead provider was 4.1 s
/// against 2.0 s without it - a dead server doubled every download.
async fn backoff_or_finish(
    backoff: Duration,
    finished: &mut tokio::sync::watch::Receiver<bool>,
    shared: &Shared,
) -> bool {
    if *finished.borrow() || shared.draining.load(Ordering::Acquire) {
        return false;
    }
    // Race the wait against a DRAIN as well as a finish. `drain()`
    // deliberately does not send `finished`, and nothing on the connect
    // side checks `draining`, so a worker on an unreachable server slept
    // out its whole ladder before retiring: with the defaults that is
    // 2+4+8+16 s of backoff plus four dial timeouts, and the user's
    // pause - which completes only when the fetch returns - visibly hung
    // for the best part of a minute. The session-backoff path already
    // slices for exactly this reason; the connect path never did.
    let deadline = tokio::time::Instant::now() + backoff;
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            return true;
        }
        let step = left.min(Duration::from_millis(250));
        tokio::select! {
            _ = tokio::time::sleep(step) => {}
            _ = async { let _ = finished.wait_for(|f| *f).await; } => return false,
        }
        if shared.draining.load(Ordering::Acquire) {
            return false;
        }
    }
}

/// `charge_front`: whether the front-of-pipeline casualty pays for the
/// death (attempts bump + this server's `tried_fail` bit). Pass true
/// when the front article is implicated - its own read stalled past
/// budget, or the session never did any useful work (the RST-after-AUTH
/// livelock the charge exists to break). Pass false for a clean
/// connection death AFTER at least one completed body: that is the flap
/// shape, the next-queued article is innocent, and branding it walked a
/// whole twin-only backlog into the queue - the flapping server then
/// sat idle for the entire drain of a bandwidth-saturated sibling
/// (measured 7.5 s of wasted capacity per 300 MB on the chaos flap
/// leg) because every queued article carried its bit and
/// `other_can_take` barred a retake. A session with a completed body
/// is progress by definition, so the uncharged requeue cannot livelock:
/// the moment such an article is the FIRST casualty of a zero-work
/// session, that session charges it.
async fn requeue_or_fail(
    shared: &Shared,
    out: &mpsc::Sender<FetchOutcome>,
    cfg: &PoolConfig,
    ctx: ServerCtx,
    inflight: &mut VecDeque<Work>,
    error: &str,
    charge_front: bool,
) {
    // Failed outcomes are emitted AFTER the queue lock drops: `out` is a
    // bounded channel, and a send that parks on a slow consumer while the
    // queue is locked would stall every worker that needs the queue.
    let mut failed: Vec<String> = Vec::new();
    // B3 wire-cap: the dead connection's whole pipeline leaves flight.
    shared.release_wire(inflight.len());
    {
        let mut q = shared.queue.lock().await;
        let mut first = true;
        while let Some(mut w) = inflight.pop_front() {
            let charged = first && charge_front;
            first = false;
            if w.dup {
                continue;
            }
            shared.deregister_inflight(&w);
            if shared.done.lock_ok().contains(&w.id) {
                continue; // a dup already emitted this article's outcome
            }
            if charged {
                w.attempts += 1;
                w.tried_fail |= ctx.bit;
                if w.attempts > cfg.article_retries {
                    if shared.claim_done(&w.id) {
                        failed.push(w.id);
                    }
                    continue;
                }
            }
            q.push_front(w);
        }
    }
    for id in failed {
        let _ = out
            .send(FetchOutcome::Failed {
                id,
                error: error.to_string(),
            })
            .await;
        shared.complete_one();
    }
}

#[cfg(test)]
mod inline_tests;

#[cfg(test)]
mod event_ring_tests;

#[cfg(test)]
mod ratelimit_tests;

#[cfg(test)]
mod unit_tests;

#[cfg(test)]
mod rig_tests;

#[cfg(test)]
mod fault_rigs;

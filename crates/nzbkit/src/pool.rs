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

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

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
        let mut bufs = self.bufs.lock().unwrap();
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
    window: std::sync::Mutex<(Instant, u64)>,
}

impl Default for RateLimit {
    fn default() -> Self {
        RateLimit {
            bytes_per_sec: AtomicU64::new(0),
            window: std::sync::Mutex::new((Instant::now(), 0)),
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
    pub fn set(&self, bytes_per_sec: u64) {
        self.bytes_per_sec.store(bytes_per_sec, Ordering::Relaxed);
    }

    pub fn get(&self) -> u64 {
        self.bytes_per_sec.load(Ordering::Relaxed)
    }

    /// Charge `n` bytes against the cap and sleep off any debt so the
    /// aggregate rate stays under `bytes_per_sec`. No-op when unlimited.
    pub async fn throttle(&self, n: u64) {
        let cap = self.bytes_per_sec.load(Ordering::Relaxed);
        if cap == 0 || n == 0 {
            return;
        }
        let sleep = {
            let mut w = self.window.lock().unwrap();
            let now = Instant::now();
            let elapsed = now.duration_since(w.0).as_secs_f64();
            // Re-anchor once the window is old and paid off: keeps the
            // arithmetic bounded without banking idle-time credit.
            if elapsed >= 1.0 && (w.1 as f64) <= cap as f64 * elapsed {
                *w = (now, 0);
            }
            w.1 += n;
            let elapsed = now.duration_since(w.0).as_secs_f64();
            let owed = w.1 as f64 / cap as f64;
            // Clamp so a live cap DECREASE never strands a worker in a
            // multi-second sleep computed against stale window debt.
            (owed > elapsed).then(|| Duration::from_secs_f64((owed - elapsed).min(5.0)))
        };
        if let Some(d) = sleep {
            tokio::time::sleep(d).await;
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
    /// Backoff after a failed connect, doubled per consecutive failure.
    pub connect_backoff: Duration,
    /// Consecutive connect failures before a worker gives up.
    pub max_connect_attempts: u32,
    /// Shared body-buffer pool; None = allocate per article.
    pub buf_pool: Option<Arc<BufPool>>,
    /// Live per-server gauges for dashboards (M14h); None = don't track.
    pub live: Option<Arc<LiveStats>>,
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
}

/// Live per-server gauges, updated by workers with relaxed atomics and
/// readable at any moment (the dashboard's connection-pool view).
pub struct LiveStats {
    pub servers: Vec<ServerLive>,
}

pub struct ServerLive {
    pub host: String,
    /// Connection budget (workers spawned).
    pub budget: usize,
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
                    budget: cfg.connections,
                    connected: AtomicUsize::new(0),
                    refusal: std::sync::Mutex::new(None),
                    bytes: AtomicU64::new(0),
                    articles_tried: AtomicU64::new(0),
                    articles_missing: AtomicU64::new(0),
                })
                .collect(),
        })
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
        ConnGauge { live: live.clone(), idx }
    }
}

impl Drop for ConnGauge {
    fn drop(&mut self) {
        if let Some(l) = &self.live {
            l.servers[self.idx].connected.fetch_sub(1, Ordering::Relaxed);
        }
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
            connect_backoff: Duration::from_secs(2),
            max_connect_attempts: 5,
            buf_pool: None,
            live: None,
            rate: None,
            oracle: None,
            inflight_cap: 0,
            warm: None,
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
}

impl ArticleReq {
    /// A request with no age information - never retention-excluded.
    pub fn fresh(id: String) -> ArticleReq {
        ArticleReq { id, age_days: 0 }
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

/// Terminal outcome for one article.
#[derive(Debug)]
pub enum FetchOutcome {
    /// Raw dot-stuffed body, ready for `yenc::decode`.
    Done { id: String, raw: Vec<u8> },
    /// Server says the article doesn't exist (430/423).
    Missing { id: String },
    /// Transport failures exhausted the retry budget.
    Failed { id: String, error: String },
}

#[derive(Debug, Default)]
pub struct PoolStats {
    pub bytes: u64,
    pub connects: u64,
    pub reconnects: u64,
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
        *self.shared.lock().unwrap() = Some(Arc::downgrade(sh));
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
        let Some(sh) = self.shared.lock().unwrap().as_ref().and_then(std::sync::Weak::upgrade)
        else {
            return 0;
        };
        // A promote only ever comes from the streaming layer - engage
        // stream mode (shallow pipelines) even when nothing moves.
        sh.note_stream();
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
            *sh.promoted_ids.lock().unwrap() = ids.iter().cloned().collect();
            sh.promote_gen.send_modify(|g| *g += 1);
        }
        n
    }

    /// M11 stream mode: a live /stream reader touched the hub. Workers
    /// cap their pipelines to `stream_window()` while this stays fresh
    /// (see `Shared::stream_until`), so seek promotions preempt instead
    /// of queueing behind hundreds of MB of pipelined responses. Called
    /// on every reader read - cheap (one mutex + one atomic store).
    pub fn note_stream_active(&self) {
        if let Some(sh) = self.shared.lock().unwrap().as_ref().and_then(std::sync::Weak::upgrade)
        {
            sh.note_stream();
        }
    }

    /// Force a pool-state dump (the stall watchdog, on a suspected
    /// deadlock). Same output as NZBFAST_POOL_DEBUG's idle-branch dump,
    /// but on demand - so a hang in the field self-captures the queue /
    /// inflight state that pins the root cause.
    pub fn dump_state(&self) {
        if let Some(sh) = self.shared.lock().unwrap().as_ref().and_then(std::sync::Weak::upgrade)
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
        let Some(sh) = self.shared.lock().unwrap().as_ref().and_then(std::sync::Weak::upgrade)
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
        let Some(sh) = self.shared.lock().unwrap().as_ref().and_then(std::sync::Weak::upgrade)
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
}

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
}

/// State shared by every worker of one fetch run.
///
/// Tail behavior (measured on a high-RTT link): when the queue
/// runs dry but articles are still in flight on servers observed to be
/// much slower, idle workers re-dispatch those articles instead of
/// waiting out the stragglers. `done` arbitrates so exactly one outcome
/// is emitted (and `pending` decremented once) per article.
/// One server's authentication standing, shared by all its workers.
#[derive(Default)]
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
    /// The server's own words, kept for the log and the dashboard.
    reason: std::sync::Mutex<Option<String>>,
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
            *self.reason.lock().unwrap() = Some(line.to_string());
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

    fn reason(&self) -> Option<String> {
        self.reason.lock().unwrap().clone()
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
    /// M29 oracle: article age in days by message-id (only ids with a
    /// known non-zero age; immutable after build). Lets the outcome
    /// recorder bucket a hit/430 without threading age through Work.
    ages: HashMap<String, u32>,
    start: Instant,
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
    /// Tail duplicates that won their race (emitted the outcome).
    dup_wins: AtomicU64,
    /// M14e tiers: per-server level and live-worker counts. A fill
    /// server's gate only counts LIVE lower-level servers, so a dead
    /// primary (all its workers bowed out) never wedges the queue.
    levels: Vec<u32>,
    alive: Vec<AtomicUsize>,
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

/// Ceiling on the session-level backoff (see [`session_backoff_delay`]).
/// Long enough that a permanently broken account costs a provider a
/// couple of connects a minute per worker; short enough that a provider
/// coming back from a maintenance window is picked up again promptly.
const SESSION_BACKOFF_MAX: Duration = Duration::from_secs(30);

/// Pacing for a session that CONNECTED but then failed without doing any
/// useful work - a provider that accepts TCP+TLS+AUTHINFO and then
/// answers every BODY with `502 byte limit exceeded` / `400 idle timeout`,
/// or RSTs after the first command.
///
/// The connect-failure backoff above never covers that shape: the connect
/// succeeds every time, so `connect_failures` stays 0 and the failure
/// paths reconnect instantly. One worker then runs connect → AUTH → BODY →
/// error → reconnect several times a second, and a 50-connection pool
/// aims that at one account until the whole queue burns through its
/// retries. On a 250k-segment single-server job that is on the order of a
/// million connect+AUTH attempts at full rate - the traffic shape
/// providers ban accounts for.
///
/// The counter this feeds is reset by a session that did USEFUL WORK
/// (any well-formed BODY response), not merely by one that connected: a
/// connection that has been serving for hours and hits one transient
/// error is back at step one, while a session that can only ever fail
/// keeps climbing. Backing off is per-worker sleep, so a bad server's
/// workers pace themselves without holding anything the rest of the pool
/// needs - queued work was already released by `requeue_or_fail`.
fn session_backoff_delay(cfg: &PoolConfig, failures: u32) -> Duration {
    let step = failures.clamp(1, 16) - 1;
    // A zero/absurd configured base would defeat the whole point.
    let base = cfg.connect_backoff.max(Duration::from_millis(50));
    base.saturating_mul(1u32 << step).min(SESSION_BACKOFF_MAX)
}

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
        WorkerLife { shared: shared.clone(), idx, retired: false }
    }

    /// Leave the fleet deliberately. True when this was the last live
    /// worker of the whole run - exactly one caller ever sees it.
    fn retire(mut self) -> bool {
        self.retired = true;
        self.shared.alive[self.idx].fetch_sub(1, Ordering::Relaxed);
        self.shared.workers_live.fetch_sub(1, Ordering::AcqRel) == 1
    }
}

impl Drop for WorkerLife {
    fn drop(&mut self) {
        if self.retired {
            return; // retire() already did the arithmetic
        }
        self.shared.alive[self.idx].fetch_sub(1, Ordering::Relaxed);
        self.shared.workers_live.fetch_sub(1, Ordering::AcqRel);
    }
}

impl Shared {
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
    fn new(reqs: Vec<ArticleReq>, servers: &[(ServerConfig, PoolConfig)]) -> (Arc<Shared>, Vec<String>) {
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
        for r in reqs {
            if !seen.insert(r.id.clone()) {
                dups += 1;
                continue;
            }
            if r.age_days > 0 {
                ages.insert(r.id.clone(), r.age_days);
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
                });
            }
        }
        if dups > 0 {
            eprintln!("[pool] dropped {dups} duplicate article request(s) - each id is fetched once");
        }
        let pending = AtomicUsize::new(queue.len());
        let shared = Arc::new(Shared {
            queue: Mutex::new(queue),
            pending,
            done: std::sync::Mutex::new(HashSet::new()),
            inflight: std::sync::Mutex::new(HashMap::new()),
            bytes: (0..n_servers).map(|_| Arc::new(AtomicU64::new(0))).collect(),
            ages,
            start: Instant::now(),
            dups_issued: AtomicU64::new(0),
            tail_started: std::sync::Mutex::new(None),
            finished: tokio::sync::watch::Sender::new(false),
            aborted: AtomicBool::new(false),
            draining: AtomicBool::new(false),
            drained_at: std::sync::Mutex::new(None),
            dup_wins: AtomicU64::new(0),
            levels: servers.iter().map(|(s, _)| s.level).collect(),
            alive: (0..n_servers).map(|_| AtomicUsize::new(0)).collect(),
            auth: (0..n_servers).map(|_| AuthState::default()).collect(),
            workers_live: AtomicUsize::new(0),
            stream_until: AtomicU64::new(0),
            promote_gen: tokio::sync::watch::Sender::new(0),
            promoted_pending: AtomicUsize::new(0),
            promoted_ids: std::sync::Mutex::new(HashSet::new()),
            scan_futile: (0..n_servers).map(|_| AtomicU64::new(u64::MAX)).collect(),
            inflight_body_bytes: AtomicU64::new(0),
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
        let alive: Vec<usize> = self.alive.iter().map(|a| a.load(Ordering::Relaxed)).collect();
        eprintln!(
            "[pool-debug] t={now}s pending={} alive={alive:?}",
            self.pending.load(Ordering::Relaxed)
        );
        if let Ok(q) = self.queue.try_lock() {
            eprintln!("[pool-debug] queue={} item(s)", q.len());
            for w in q.iter().take(30) {
                eprintln!(
                    "[pool-debug]   q {} tried_430={:06b} tried_fail={:06b} attempts={} dup={}",
                    w.id, w.tried_430, w.tried_fail, w.attempts, w.dup
                );
            }
        } else {
            eprintln!("[pool-debug] queue lock busy");
        }
        let inf = self.inflight.lock().unwrap();
        eprintln!("[pool-debug] inflight={} entr(ies)", inf.len());
        for (id, i) in inf.iter().take(30) {
            eprintln!(
                "[pool-debug]   inflight {} srv={} age={:.1}s dups={} tried_430={:06b}",
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
            *self.drained_at.lock().unwrap() = Some(Instant::now());
            let _ = self.finished.send(true);
        }
    }

    fn report_diagnostics(&self) {
        let dups = self.dups_issued.load(Ordering::Relaxed);
        let wins = self.dup_wins.load(Ordering::Relaxed);
        let ts = *self.tail_started.lock().unwrap();
        let da = *self.drained_at.lock().unwrap();
        let run = self.start.elapsed().as_secs_f64();
        match (ts, da) {
            (Some(t), Some(d)) => eprintln!(
                "[pool] run {run:.2}s · queue dry at {:.2}s · drained at {:.2}s · {dups} dups ({wins} won)",
                (t - self.start).as_secs_f64(),
                (d - self.start).as_secs_f64(),
            ),
            _ => eprintln!("[pool] run {run:.2}s · no tail · {dups} dups ({wins} won)"),
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
            let required = if level > 0 { self.required_mask(level) } else { 0 };
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
    /// start, single server) everyone takes it.
    fn faster_can_take(&self, w: &Work, me: usize) -> bool {
        let mine = self.rate_per_worker(me);
        for (si, &level) in self.levels.iter().enumerate() {
            if si == me || self.alive[si].load(Ordering::Relaxed) == 0 {
                continue;
            }
            let bit = server_bit(si);
            if w.tried_430 & bit != 0 || w.tried_fail & bit != 0 {
                continue;
            }
            let required = if level > 0 { self.required_mask(level) } else { 0 };
            if w.tried_430 & required != required {
                continue;
            }
            if self.rate_per_worker(si) > 2.0 * mine {
                return true;
            }
        }
        false
    }

    /// First-emitter check: true exactly once per id.
    fn claim_done(&self, id: &str) -> bool {
        self.done.lock().unwrap().insert(id.to_string())
    }

    fn register_inflight(&self, w: &Work, server: usize) {
        if w.dup {
            return; // dups are tracked via the original's entry
        }
        self.inflight.lock().unwrap().insert(
            w.id.clone(),
            Inflight {
                server,
                dispatched: Instant::now(),
                dups: 0,
                tried_430: w.tried_430,
                dup_servers: 0,
            },
        );
    }

    fn deregister_inflight(&self, w: &Work) {
        if !w.dup {
            self.inflight.lock().unwrap().remove(&w.id);
        }
    }

    /// B3 wire-cap: charge one dispatched BODY's estimated bytes.
    fn charge_wire(&self) {
        self.inflight_body_bytes.fetch_add(EST_BODY_BYTES, Ordering::AcqRel);
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
        let _ = self.inflight_body_bytes.fetch_update(
            Ordering::AcqRel,
            Ordering::Acquire,
            |v| {
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
            },
        );
    }

    /// B3 wire-cap: true when topping up past the one-in-flight floor
    /// must pause. `cap` 0 = uncapped (default outside budgeted runs).
    fn wire_over_cap(&self, cap: u64) -> bool {
        cap > 0 && self.inflight_body_bytes.load(Ordering::Acquire) >= cap
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
    fn pick_dup(
        &self,
        me: usize,
        my_bit: u32,
        group_bits: u32,
        required: u32,
        window_used: usize,
        level: u32,
    ) -> Option<Work> {
        let endgame = self.pending.load(Ordering::Acquire) as usize <= ENDGAME_MAX;
        // PER-WORKER, like `faster_can_take` above. `rate()` is a server's
        // whole-run byte total over wall time, so it measures its share of
        // the job, and that share is set mostly by how many connections it
        // was given. Comparing shares made a big server judge a smaller one
        // "half my speed" when every connection was equally fast, so its
        // idle workers duplicated the smaller server's in-flight articles
        // as a matter of course - fetching those bytes twice. Dividing by
        // live workers asks the question the heuristic means to ask: is
        // this article's owner actually slower.
        let my_rate = self.rate_per_worker(me);
        let done = self.done.lock().unwrap();
        let mut inflight = self.inflight.lock().unwrap();
        // (id, owner_rate, ladder-progress) - endgame prefers the article
        // CLOSEST to its verdict, normal phase the slowest owner.
        let mut best: Option<(&String, f64, u32)> = None;
        for (id, inf) in inflight.iter() {
            if inf.server == me
                || inf.tried_430 & my_bit != 0
                || inf.dup_servers & my_bit != 0
                || done.contains(id)
            {
                continue;
            }
            if endgame && inf.tried_430 != 0 {
                if window_used > 0 {
                    continue; // ladder probes ride EMPTY pipelines only
                }
                if inf.tried_430 & required != required {
                    continue; // fill gate: lower levels first
                }
                let progress = inf.tried_430.count_ones();
                if best.is_none_or(|(_, _, p)| progress > p) {
                    best = Some((id, 0.0, progress));
                }
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
            // it is least worth using.
            if level > 0 {
                continue;
            }
            let owner_rate = self.rate_per_worker(inf.server);
            let stale = inf.dispatched.elapsed() > Duration::from_secs(8);
            if my_rate > 2.0 * owner_rate || stale {
                // Prefer the slowest owner.
                if best.is_none_or(|(_, r, _)| owner_rate < r) {
                    best = Some((id, owner_rate, 0));
                }
            }
        }
        let id = best.map(|(id, _, _)| id.clone())?;
        let inf = inflight.get_mut(&id).unwrap();
        inf.dups += 1;
        inf.dup_servers |= group_bits;
        self.dups_issued.fetch_add(1, Ordering::Relaxed);
        Some(Work {
            id,
            attempts: 0,
            promoted: false,
            tried_430: 0,
            tried_fail: 0,
            dup: true,
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
        let _ = out.send(FetchOutcome::Missing { id }).await;
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
        counters.push((shared.bytes[si].clone(), connects.clone(), reconnects.clone()));
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
            let ramp = cfg.ramp_delay * i as u32;
            workers.push(tokio::spawn(async move {
                worker(&server, &cfg, ctx, shared, out, connects, reconnects, life, ramp).await;
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
        .map(|(b, c, r)| PoolStats {
            bytes: b.load(Ordering::Relaxed),
            connects: c.load(Ordering::Relaxed),
            reconnects: r.load(Ordering::Relaxed),
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
            eprintln!("[pool] worker panicked - its articles are sealed Failed below: {e}");
        }
    };
    for mut w in workers {
        if !expired {
            let joined = tokio::select! {
                r = &mut w => Some(r),
                _ = &mut deadline => {
                    expired = true;
                    eprintln!(
                        "[pool] worker still parked {}s after the run went terminal \
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
    if left > 0 && !shared.aborted.load(Ordering::Acquire) && !shared.draining.load(Ordering::Acquire)
    {
        // Neither the queue nor the inflight map named these, so the pool
        // cannot report them itself. Loud, because it means an article
        // went missing from this module's own bookkeeping.
        eprintln!(
            "[pool] BUG: fleet joined with {left} article(s) non-terminal and unaccounted \
             for - the caller will see slots with no outcome"
        );
    }
}

/// Per-worker identity for cross-server routing.
#[derive(Clone, Copy)]
struct ServerCtx {
    idx: usize,
    bit: u32,
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
    if n >= MAX_SERVERS { u32::MAX } else { (1u32 << n) - 1 }
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
    // Caller's current pipeline depth (M2c.4): in the ENDGAME a
    // 430-laddering article must not ride BEHIND queued payload bodies
    // - head-of-line blocking on the slowest provider's last windows
    // was the measured 4-6 s straggler tail. Idle workers (depth 0)
    // answer a ladder probe in one RTT.
    window_used: usize,
) -> Option<Work> {
    let endgame = shared.pending.load(Ordering::Acquire) as usize <= ENDGAME_MAX;
    // Fill-server gate (M14e): a level-N server only takes queued work
    // that every LIVE lower-level server has already 430'd.
    let required = if ctx.level > 0 { shared.required_mask(ctx.level) } else { 0 };
    // Scan throttle: this server's last full scan found nothing takeable
    // and re-shuffled the whole queue for the privilege. Sit out a tick
    // instead of burning the shared queue lock - at scale that burn
    // starves the servers that DO have work (see `scan_futile`).
    let now_ms = shared.start.elapsed().as_millis() as u64;
    let futile_at = shared.scan_futile[ctx.idx].load(Ordering::Relaxed);
    if futile_at != u64::MAX && now_ms.saturating_sub(futile_at) < SCAN_RETRY_MS {
        return shared.pick_dup(ctx.idx, ctx.bit, ctx.group_bits, required, window_used, ctx.level);
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
        for _ in 0..q.len() {
            let Some(w) = q.pop_front() else { break };
            if w.tried_430 & live == live {
                unservable.push(w.id);
                continue;
            }
            if w.tried_430 & ctx.bit != 0
                || w.tried_430 & required != required
                || (w.tried_fail & ctx.bit != 0 && shared.other_can_take(&w, ctx.idx))
                || (endgame && window_used > 0 && w.tried_430 != 0)
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
                    let _ = shared
                        .promoted_pending
                        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |v| v.checked_sub(1));
                }
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
            let _ = out.send(FetchOutcome::Missing { id }).await;
            shared.complete_one();
        }
    }
    if picked.is_some() {
        return picked;
    }
    if ctx.level == 0 && shared.pending.load(Ordering::Acquire) > 0 {
        // Only primaries mark the tail - an idle fill server waiting on
        // its gate isn't evidence the queue ran dry.
        shared
            .tail_started
            .lock()
            .unwrap()
            .get_or_insert_with(Instant::now);
    }
    shared.pick_dup(ctx.idx, ctx.bit, ctx.group_bits, required, window_used, ctx.level)
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
        let _ = out.blocking_send(FetchOutcome::Missing { id });
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
                    eprintln!("[pool] shard runtime: {e}");
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
                    let ramp = cfg.ramp_delay * ramp_step;
                    tasks.push(tokio::spawn(async move {
                        worker(&server, &cfg, ctx, shared, out, connects, reconnects, life, ramp)
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
        .map(|(b, c, r)| PoolStats {
            bytes: b.load(Ordering::Relaxed),
            connects: c.load(Ordering::Relaxed),
            reconnects: r.load(Ordering::Relaxed),
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
        let mut q = shared.queue.try_lock().expect("joined shards cannot hold queue");
        q.drain(..).map(|w| w.id).collect()
    };
    orphans.extend(shared.inflight.lock().unwrap().drain().map(|(id, _)| id));
    let mut sealed = 0;
    for id in orphans {
        if !shared.claim_done(&id) {
            continue;
        }
        let _ = out.blocking_send(FetchOutcome::Failed { id, error: reason.to_string() });
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
    let warm_conn = match &cfg.warm {
        Some(w) => tokio::select! {
            c = w.take(server) => c,
            // Nothing left to claim it for. Fall through as if the pool
            // were empty rather than returning: `life.retire()` below is
            // what seals the run, and no path may skip it.
            _ = run_over(&mut fin, &shared) => None,
        },
        None => None,
    };
    // The ramp sleep must yield to abort/finish: at 100 connections ×
    // 150 ms a still-ramping worker would otherwise outlive an aborted
    // run by up to 15 s.
    let ramped = warm_conn.is_some() || {
        tokio::select! {
            _ = tokio::time::sleep(ramp) => true,
            _ = fin.wait_for(|f| *f) => false,
        }
    };
    if ramped {
        session_loop(
            server,
            cfg,
            ctx,
            shared.clone(),
            out.clone(),
            connects,
            reconnects,
            warm_conn,
        )
        .await;
    }
    if life.retire() {
        seal_run(&shared, &out, "no connection worker left to fetch this article").await;
    }
}

#[allow(clippy::too_many_arguments)]
async fn session_loop(
    server: &ServerConfig,
    cfg: &PoolConfig,
    ctx: ServerCtx,
    shared: Arc<Shared>,
    out: mpsc::Sender<FetchOutcome>,
    connects: Arc<AtomicU64>,
    reconnects: Arc<AtomicU64>,
    // A parked connection already claimed (and validated) by `worker`
    // before the ramp; used for the first session instead of dialling.
    mut preclaimed: Option<Connection>,
) {
    let mut connect_failures: u32 = 0;
    // Consecutive sessions that connected and then died without doing any
    // useful work, and the delay they have armed for the next connect.
    let mut session_failures: u32 = 0;
    let mut pending_backoff: Option<Duration> = None;
    let mut ever_connected = false;
    let mut finished = shared.finished.subscribe();
    let mut promote_gen = shared.promote_gen.subscribe();

    'session: loop {
        // A session that can only ever fail bows out for good, exactly as
        // connect exhaustion does below (see `MAX_SESSION_ATTEMPTS`) -
        // this worker's `alive` count comes down with it, so a
        // multi-server job steers to the healthy backbone and a
        // single-server one seals a truthful Failed. Checked before the
        // backoff: a worker that is leaving anyway must not sit out a 30 s
        // sleep on the way out. Only the fast-failure paths touch the
        // counter, and any well-formed BODY response clears it, so a
        // connection that has been serving is never walked toward this by
        // a rough patch.
        if session_failures >= MAX_SESSION_ATTEMPTS {
            return;
        }
        // Session-level pacing (see `session_backoff_delay`). Armed only
        // by the fast failure paths - protocol error, failed send, failed
        // flush - which otherwise reconnect with zero delay. Deliberate
        // reconnects (pipeline shed, promote shed) never arm it, and the
        // read-stall path is already paced by `read_timeout`. The session
        // guard has been dropped by the `continue` that got us here, so a
        // worker sleeping this off is not counted as connected.
        // Abort sets `finished`, so that arm covers it; a graceful pause
        // does not, hence the short slices - a drain must not wait out a
        // 30 s backoff before this worker retires.
        if let Some(d) = pending_backoff.take() {
            // Deadline on the runtime's clock, not `std`'s: the slices
            // below are `tokio::time::sleep`, and mixing the two makes
            // this a busy-wait under a test clock (the sleeps return, the
            // deadline never moves). Identical in production, where the
            // two clocks are the same clock.
            let until = tokio::time::Instant::now() + d;
            loop {
                let left = until.saturating_duration_since(tokio::time::Instant::now());
                if left.is_zero() || shared.draining.load(Ordering::Acquire) {
                    break;
                }
                tokio::select! {
                    _ = tokio::time::sleep(left.min(Duration::from_millis(250))) => {}
                    // The run finished (or was aborted) while this worker
                    // was sitting out.
                    _ = finished.wait_for(|f| *f) => return,
                }
            }
        }
        if shared.pending.load(Ordering::Acquire) == 0 {
            // A worker that claimed a parked connection before the ramp and
            // then found the queue already empty is holding a DRAINED,
            // freshly validated session - `take` sent its DATE and read the
            // answer, and nothing has been written since. Dropping it here
            // closed it, so the pool SHRANK every time a fleet outran its
            // work: measured over six back-to-back jobs, three parked
            // connections eroded to two and the fourth job dialled again
            // despite a hit on every claim. That is the warm pool paying to
            // destroy exactly what it exists to keep, and it bites hardest
            // under load, which is when a fleet is most likely to have one
            // worker finish everything before its siblings start.
            if let Some(c) = preclaimed.take() {
                park_or_quit(cfg, server, c).await;
            }
            return; // every article is terminal
        }
        if shared.aborted.load(Ordering::Acquire) {
            // Aborts close, per the module rule every other abort exit
            // follows - the user is done with this server, not pausing.
            if let Some(c) = preclaimed.take() {
                c.quit().await;
            }
            return; // user abort
        }

        // A parked connection first. `take` has already validated it with
        // a DATE round-trip, so it is interchangeable with a fresh
        // connect here and none of the error handling below has to know
        // the difference. Worth roughly five round-trips, a TLS
        // handshake, and - the part that actually dominates on a short
        // job - a TCP congestion window that is already open.
        let warm = match preclaimed.take() {
            Some(c) => Some(c),
            None => match &cfg.warm {
                // Raced for the same reason as the dial below: the
                // claim's DATE validation is bounded at 8 s against
                // EXIT_GRACE's 5 s, so a mute peer here holds the whole
                // run open exactly as an unanswered SYN used to (§35).
                Some(w) => tokio::select! {
                    c = w.take(server) => c,
                    _ = run_over(&mut finished, &shared) => return,
                },
                None => None,
            },
        };
        let mut conn = match warm {
            Some(c) => {
                connect_failures = 0;
                ever_connected = true;
                c
            }
            None => {
                // Settled already: this server has told us the account is
                // no good. Workers that reach here later must not re-ask -
                // that is the storm this exists to stop, and it is also
                // how a wrong password used to cost every worker its full
                // backoff ladder before anyone bowed out.
                if shared.auth[ctx.idx].is_rejected() {
                    return;
                }
                if let Some(w) = &cfg.warm {
                    w.miss();
                }
                // §35: the dial is the one blocking call in this loop that
                // never watched the run. The session backoff above selects
                // on `finished`, `backoff_or_finish` slices its sleep - but
                // `connect` ran to its own CONNECT_TIMEOUT (20 s) whatever
                // had happened to the job meanwhile, so a worker inside a
                // dial when the last article went terminal kept the WHOLE
                // run alive until `join_fleet` gave up on it after
                // EXIT_GRACE.
                //
                // That cost a flat 5.0 s and it needed no dead server: 40
                // of 40 farm runs paid it, the healthy six-server config
                // included, because a provider bouncing a redundant
                // connection off its simultaneous-IP cap (`502 max number
                // of simultaneous IP addresses reached`) leaves a worker
                // redialling exactly like an unreachable one. A 0.35 GB
                // job whose bytes were all in at 0.65 s returned at 5.65 s.
                // Racing the dial: same job, same box, 0.74 s.
                let dialed = tokio::select! {
                    r = Connection::connect(server) => r,
                    _ = run_over(&mut finished, &shared) => return,
                };
                match dialed {
            Ok((c, _)) => {
                connects.fetch_add(1, Ordering::Relaxed);
                if ever_connected {
                    reconnects.fetch_add(1, Ordering::Relaxed);
                }
                ever_connected = true;
                connect_failures = 0;
                c
            }
            // §15e: an AUTHINFO refusal is the server's answer to this
            // ACCOUNT, so it is settled once for every worker rather than
            // rediscovered by each of them. The two kinds want opposite
            // responses, and conflating them is what made a Giganews cap
            // so expensive.
            Err(crate::nntp::NntpError::AuthFailed { kind, line }) => {
                let first = shared.auth[ctx.idx].note(kind, &line);
                // Out to the dashboard, so the user is told which server
                // stopped pulling its weight and in whose words.
                if let Some(live) = &cfg.live
                    && let Some(sl) = live.servers.get(ctx.idx)
                {
                    *sl.refusal.lock().unwrap() = Some(Refusal {
                        permanent: kind == crate::nntp::AuthRefusal::Permanent,
                        line: line.clone(),
                    });
                }
                match kind {
                    crate::nntp::AuthRefusal::Permanent => {
                        // Retrying cannot fix a credential. Say it once,
                        // per SERVER, and take every worker off it.
                        if first {
                            eprintln!(
                                "[pool] {}: authentication rejected, not retrying: {line}",
                                server.host
                            );
                        }
                        return;
                    }
                    crate::nntp::AuthRefusal::Capacity => {
                        // The account is fine; the server will not give us
                        // ANOTHER session. Retrying at the same connection
                        // count re-provokes exactly the limit being hit, so
                        // this worker permanently yields its slot and the
                        // survivors carry the job at a count the provider
                        // will actually accept.
                        if first {
                            eprintln!(
                                "[pool] {}: at its connection/IP cap, reducing connections: {line}",
                                server.host
                            );
                        }
                        // Keep at least one worker trying, or a cap that
                        // clears later would leave the server unused for
                        // the rest of the run.
                        if shared.auth[ctx.idx].claim_yield(&shared.alive[ctx.idx]) {
                            return;
                        }
                        connect_failures += 1;
                        if connect_failures >= cfg.max_connect_attempts {
                            return;
                        }
                        if !backoff_or_finish(
                            cfg.connect_backoff * 2u32.pow(connect_failures.min(5) - 1),
                            &mut finished,
                            &shared,
                        )
                        .await
                        {
                            return;
                        }
                        continue 'session;
                    }
                }
            }
            Err(e) => {
                connect_failures += 1;
                // Say WHY, once per worker per run. This was a bare
                // `Err(_)` and the silence was expensive: a server that
                // cannot authenticate, cannot resolve, or is refusing
                // the TLS handshake looks EXACTLY like a server whose
                // articles are all missing - every article ends up
                // Failed/Missing with no hint which of the two it was.
                // First failure only, so a flapping provider cannot
                // flood the log, and the message names the fix.
                if connect_failures == 1 {
                    eprintln!("[pool] {}: connect failed: {e}", server.host);
                }
                if connect_failures >= cfg.max_connect_attempts {
                    // This worker bows out; remaining work is served by the
                    // others (or reported Failed when the queue drains at
                    // exhausted attempts elsewhere).
                    return;
                }
                let backoff = cfg.connect_backoff * 2u32.pow(connect_failures.min(5) - 1);
                if !backoff_or_finish(backoff, &mut finished, &shared).await {
                    return;
                }
                continue 'session;
            }
                }
            }
        };

        // Dashboard gauge: this worker holds a session until the next
        // 'session iteration or return drops the guard.
        let _gauge = ConnGauge::up(&cfg.live, ctx.idx);

        // In-flight commands, oldest first (responses arrive in order).
        let mut inflight: VecDeque<Work> = VecDeque::with_capacity(cfg.window);

        loop {
            if shared.aborted.load(Ordering::Acquire) {
                shared.release_wire(inflight.len());
                conn.quit().await;
                return; // user abort
            }
            // M11 stream mode: while a player is attached, run shallow
            // pipelines so a promoted seek article's BODY goes out within
            // ~one article of the promote, not after the whole window.
            let win = if shared.stream_active() {
                stream_window().min(cfg.window)
            } else {
                cfg.window
            };
            // A pipeline deeper than the live cap (stream mode engaged
            // mid-window) is abandoned outright: the sent BODYs can't be
            // unsent, but dropping the connection stops their responses
            // from serializing ahead of promoted work on this socket.
            // In-flight items requeue uncharged; the reconnect is cheap
            // next to the multi-second drain it replaces. Workers hit
            // this at their next response boundary, so the reconnects
            // stagger naturally. (Not during drain: a graceful pause
            // must complete - and journal - what's already in flight.)
            if inflight.len() > win && !shared.draining.load(Ordering::Acquire) {
                shed_pipeline(&shared, &mut inflight).await;
                conn.quit().await;
                continue 'session;
            }
            // Top up the window - unless draining, when we admit nothing
            // new and just let the in-flight requests below complete.
            while inflight.len() < win {
                if shared.draining.load(Ordering::Acquire) {
                    break;
                }
                // B3 wire-cap: over the global in-flight byte budget,
                // stop topping up - but never below ONE request in
                // flight, so every connection stays busy and the pool
                // can't deadlock (the response drain below is what
                // releases charges and reopens the cap).
                if !inflight.is_empty() && shared.wire_over_cap(cfg.inflight_cap) {
                    break;
                }
                let Some(w) = next_work(&shared, ctx, &out, inflight.len()).await else {
                    break;
                };
                // B3 wire-cap: charge at dispatch, BEFORE the send can
                // fail. Every release is a `release_wire(inflight.len())`
                // over a worker's deque, so the only workable invariant is
                // "one charge per item in that deque" - and the failed-send
                // path below deliberately puts `w` into it. Charging after
                // the send left that one item uncharged while
                // requeue_or_fail released for it anyway: one flaky send
                // wrapped the global counter and collapsed every worker in
                // the pool to pipeline depth one.
                shared.charge_wire();
                if conn.send_body(&w.id).await.is_err() {
                    // Charge the failed article by making it the front-of-inflight
                    // casualty so requeue_or_fail bumps attempts/tried_fail and
                    // fails it past article_retries. Without this the item requeues
                    // UNCHARGED (it was popped, never registered in inflight), and a
                    // server that RSTs right after AUTH loops connect+AUTH forever on
                    // a single-server job - pending never reaches 0. dup items are
                    // still dropped by requeue_or_fail.
                    inflight.push_front(w);
                    requeue_or_fail(&shared, &out, cfg, ctx, &mut inflight, "send failed").await;
                    session_failures += 1;
                    pending_backoff = Some(session_backoff_delay(cfg, session_failures));
                    continue 'session;
                }
                if let Some(l) = &cfg.live {
                    l.servers[ctx.idx].articles_tried.fetch_add(1, Ordering::Relaxed);
                }
                shared.register_inflight(&w, ctx.idx);
                inflight.push_back(w);
            }
            if inflight.is_empty() {
                // THE reuse point. `inflight.is_empty()` is the whole
                // safety argument: no BODY is outstanding, so there are
                // no unread responses queued on this socket and the next
                // job can pick it up mid-conversation. Every other exit
                // from this loop abandons in-flight responses and closes.
                if shared.pending.load(Ordering::Acquire) == 0 {
                    park_or_quit(cfg, server, conn).await;
                    return; // truly drained
                }
                if shared.draining.load(Ordering::Acquire) {
                    park_or_quit(cfg, server, conn).await;
                    return; // graceful pause: in-flight done, queue left for resume
                }
                // Idle but articles are still in flight elsewhere and may
                // requeue (or become dup candidates) - re-check shortly.
                if std::env::var_os("NZBFAST_POOL_DEBUG").is_some() {
                    shared.debug_dump_idle();
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
                continue;
            }
            if conn.flush().await.is_err() {
                requeue_or_fail(&shared, &out, cfg, ctx, &mut inflight, "flush failed").await;
                session_failures += 1;
                pending_backoff = Some(session_backoff_delay(cfg, session_failures));
                continue 'session;
            }

            let mut buf = match &cfg.buf_pool {
                Some(p) => p.take(),
                None => Vec::with_capacity(800 * 1024),
            };
            // A worker mid-read must notice global completion: once a tail
            // duplicate wins somewhere, waiting out a slow original here
            // would stall the whole pool's return. It must also notice a
            // PROMOTE while its in-flight article is non-promoted work: a
            // streaming seek needs the whole line NOW, and 100+ conns
            // placidly finishing frontier articles hold the promoted wave
            // to one conn's fair share (measured 4-6 s per 32 MB window).
            // Abandoning the read (reconnect, uncharged requeue) frees
            // this conn for promoted work within ~a TLS handshake.
            let mut shed_for_promote = false;
            let read = {
                let read_fut = tokio::time::timeout(cfg.read_timeout, conn.read_body_into(&mut buf));
                tokio::pin!(read_fut);
                loop {
                    tokio::select! {
                        r = &mut read_fut => break Some(r),
                        _ = async {
                            let _ = finished.wait_for(|f| *f).await;
                        } => break None,
                        _ = promote_gen.changed() => {
                            // Immune if ANY in-flight article is promoted
                            // work - by flag (popped after the promote) OR
                            // by id (dispatched before the promote but
                            // inside its span; shedding those would just
                            // refetch the same bytes after a reconnect).
                            let fetching_promoted = inflight.iter().any(|w| w.promoted) || {
                                let ids = shared.promoted_ids.lock().unwrap();
                                inflight.iter().any(|w| ids.contains(&w.id))
                            };
                            // And only abandon a read that has already
                            // proven slower than a reconnect (see
                            // PROMOTE_SHED_MIN_AGE).
                            let old_enough = inflight.front().is_none_or(|w| {
                                shared
                                    .inflight
                                    .lock()
                                    .unwrap()
                                    .get(&w.id)
                                    .is_none_or(|inf| inf.dispatched.elapsed() >= PROMOTE_SHED_MIN_AGE)
                            });
                            if shared.stream_active()
                                && shared.promoted_pending.load(Ordering::Acquire) > 0
                                && !fetching_promoted
                                && old_enough
                            {
                                shed_for_promote = true;
                                break None;
                            }
                            // Already fetching promoted work (or no
                            // promoted work left): keep reading.
                        }
                    }
                }
            };
            let Some(read) = read else {
                if let Some(p) = &cfg.buf_pool {
                    p.give(buf);
                }
                if shed_for_promote {
                    shed_pipeline(&shared, &mut inflight).await;
                    conn.quit().await; // internally bounded
                    continue 'session;
                }
                shared.release_wire(inflight.len());
                conn.quit().await; // internally bounded
                return;
            };
            // Useful work: a well-formed BODY response (222, or an
            // authoritative 430/423 - both mean the session is healthy and
            // talking NNTP). THIS is what clears the session backoff, not
            // the connect: a connection that has served for hours and then
            // hits one transient error must not be paced as if it were a
            // broken account, and a session that can only ever fail must
            // not clear its counter just by connecting again.
            if matches!(&read, Ok(Ok(_))) {
                session_failures = 0;
            }
            match read {
                Ok(Ok(true)) => {
                    let w = inflight.pop_front().expect("response without command");
                    shared.release_wire(1);
                    shared.bytes[ctx.idx].fetch_add(buf.len() as u64, Ordering::Relaxed);
                    if let Some(l) = &cfg.live {
                        l.servers[ctx.idx].bytes.fetch_add(buf.len() as u64, Ordering::Relaxed);
                    }
                    // Speed limiter: charge the body and sleep off any debt
                    // BEFORE processing continues (async - the runtime
                    // thread stays free for other workers' I/O).
                    if let Some(rate) = &cfg.rate {
                        rate.throttle(buf.len() as u64).await;
                    }
                    // M29 oracle: a served body is a labeled "this
                    // backbone HAS articles of this age" sample - charged
                    // per 222 regardless of who owns the outcome (dups
                    // included; the response is real evidence either way).
                    if let Some(o) = &cfg.oracle {
                        o.hit(ctx.idx, shared.ages.get(&w.id).copied().unwrap_or(0));
                    }
                    shared.deregister_inflight(&w);
                    if shared.claim_done(&w.id) {
                        if w.dup {
                            shared.dup_wins.fetch_add(1, Ordering::Relaxed);
                        }
                        let _ = out.send(FetchOutcome::Done { id: w.id, raw: buf }).await;
                        shared.complete_one();
                    } else if let Some(p) = &cfg.buf_pool {
                        // A duplicate dispatch beat us to it.
                        p.give(buf);
                    }
                }
                Ok(Ok(false)) => {
                    let mut w = inflight.pop_front().expect("response without command");
                    shared.release_wire(1);
                    if let Some(p) = &cfg.buf_pool {
                        p.give(buf);
                    }
                    // Reliability: this server said "no such article" -
                    // charged even for dups (the response is authoritative
                    // for this server regardless of who owns the outcome).
                    if let Some(l) = &cfg.live {
                        l.servers[ctx.idx].articles_missing.fetch_add(1, Ordering::Relaxed);
                    }
                    // M29 oracle: the mirror of the hit above - one miss
                    // per actual 430/423 wire response. Derived Missing
                    // verdicts (retention seeding, unanimity) are NOT
                    // recorded; only real answers train the ledger.
                    if let Some(o) = &cfg.oracle {
                        o.miss(ctx.idx, shared.ages.get(&w.id).copied().unwrap_or(0));
                    }
                    if w.dup {
                        // M2c.4: a duplicate's 430 is real evidence, not a
                        // discard - merge it into the article's
                        // authoritative mask (the inflight entry while the
                        // original is out reading, the queued copy if it
                        // already requeued) and declare Missing the moment
                        // the union goes unanimous, instead of waiting for
                        // the original to walk the rest of the ladder.
                        let live = shared.live_mask();
                        let mut unanimous = false;
                        {
                            let mut m = shared.inflight.lock().unwrap();
                            if let Some(inf) = m.get_mut(&w.id) {
                                inf.tried_430 |= ctx.group_bits;
                                unanimous = inf.tried_430 & live == live;
                            }
                        }
                        if !unanimous {
                            // Tail queues are tiny (endgame ≤64) - a linear
                            // stamp is cheap, and a miss (article mid-hand-
                            // off) only costs one redundant attempt.
                            let mut q = shared.queue.lock().await;
                            if let Some(qi) = q.iter_mut().find(|x| x.id == w.id) {
                                qi.tried_430 |= ctx.group_bits;
                                unanimous = qi.tried_430 & live == live;
                            }
                        }
                        if unanimous && shared.claim_done(&w.id) {
                            let _ = out.send(FetchOutcome::Missing { id: w.id }).await;
                            shared.complete_one();
                        }
                        continue;
                    }
                    // Fold in any 430s duplicate dispatches accumulated on
                    // the inflight entry while this original was reading.
                    if let Some(inf) = shared.inflight.lock().unwrap().remove(&w.id) {
                        w.tried_430 |= inf.tried_430;
                    }
                    // 430 is authoritative for this server AND its mirror
                    // group; route to untried LIVE servers before declaring
                    // the article missing (dead servers can never answer -
                    // counting them here deadlocked the run pre-fix).
                    w.tried_430 |= ctx.group_bits;
                    let live = shared.live_mask();
                    if w.tried_430 & live == live {
                        if shared.claim_done(&w.id) {
                            let _ = out.send(FetchOutcome::Missing { id: w.id }).await;
                            shared.complete_one();
                        }
                    } else if w.promoted {
                        // A promoted (playhead) article 430'd here must
                        // retry on another backbone NOW - at the queue
                        // back it sits behind gigabytes while the player
                        // starves (live wedge: DMCA-holed head articles
                        // cycling 430 → back → re-promote → 430).
                        let mut q = shared.queue.lock().await;
                        let at = q.iter().take_while(|x| x.promoted).count().min(q.len());
                        shared.promoted_pending.fetch_add(1, Ordering::AcqRel);
                        q.insert(at, w);
                    } else {
                        shared.queue.lock().await.push_back(w);
                    }
                }
                Ok(Err(e)) => {
                    if let Some(p) = &cfg.buf_pool {
                        p.give(buf);
                    }
                    conn.quit().await;
                    requeue_or_fail(&shared, &out, cfg, ctx, &mut inflight, &e.to_string()).await;
                    session_failures += 1;
                    pending_backoff = Some(session_backoff_delay(cfg, session_failures));
                    continue 'session;
                }
                Err(_) => {
                    // Stalled mid-response; connection state unusable.
                    if let Some(p) = &cfg.buf_pool {
                        p.give(buf);
                    }
                    requeue_or_fail(&shared, &out, cfg, ctx, &mut inflight, "read stall").await;
                    continue 'session;
                }
            }
        }
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
        let mut inf = shared.inflight.lock().unwrap();
        orphans.extend(inf.drain().map(|(id, _)| id));
    }
    let mut sealed = 0usize;
    for id in orphans {
        if !shared.claim_done(&id) {
            continue; // a duplicate dispatch already owns this outcome
        }
        let _ = out
            .send(FetchOutcome::Failed { id, error: reason.to_string() })
            .await;
        shared.complete_one();
        sealed += 1;
    }
    if sealed > 0 {
        eprintln!(
            "[pool] fleet exhausted with {sealed} article(s) unresolved - reported \
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
        if shared.done.lock().unwrap().contains(&w.id) {
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

async fn requeue_or_fail(
    shared: &Shared,
    out: &mpsc::Sender<FetchOutcome>,
    cfg: &PoolConfig,
    ctx: ServerCtx,
    inflight: &mut VecDeque<Work>,
    error: &str,
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
            let charged = first;
            first = false;
            if w.dup {
                continue;
            }
            shared.deregister_inflight(&w);
            if shared.done.lock().unwrap().contains(&w.id) {
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
mod tests {
    use super::*;

    #[test]
    fn retention_mask_excludes_only_outdated_servers() {
        // Servers: [unlimited, 10-day, 100-day, unlimited].
        let r = [0u32, 10, 100, 0];
        assert_eq!(retention_mask(&r, 0), 0, "fresh article: no exclusions");
        assert_eq!(retention_mask(&r, 10), 0, "age == retention still served");
        assert_eq!(retention_mask(&r, 11), 0b0010, "past 10-day server only");
        assert_eq!(retention_mask(&r, 100), 0b0010);
        assert_eq!(retention_mask(&r, 101), 0b0110, "past both limited servers");
        assert_eq!(
            retention_mask(&r, u32::MAX),
            0b0110,
            "unlimited never excluded"
        );
        assert_eq!(retention_mask(&[], 500), 0, "no servers, no bits");
    }

    #[test]
    fn seed_masks_and_unservable_split() {
        let reqs = vec![
            ArticleReq::fresh("<fresh@x>".into()),
            ArticleReq {
                id: "<old@x>".into(),
                age_days: 30,
            },
            ArticleReq {
                id: "<ancient@x>".into(),
                age_days: 400,
            },
        ];
        // Both servers limited: 10-day and 90-day.
        let srv = |retention_days: u32| {
            (
                ServerConfig {
                    host: "x".into(),
                    port: 119,
                    tls: false,
                    username: None,
                    password: None,
                    connections: 1,
                    rcvbuf: None,
                    level: 0,
                    group: None,
                    retention_days,
                    block_bytes: None,
                    bind_ip: None,
                    socks5: None,
                    enabled: true,
                    warm_pool: false,
                },
                PoolConfig::default(),
            )
        };
        let (shared, unservable) = Shared::new(reqs, &[srv(10), srv(90)]);
        // The 400-day article is outside every retention → never queued.
        assert_eq!(unservable, vec!["<ancient@x>".to_string()]);
        assert_eq!(shared.pending.load(Ordering::Relaxed), 2);
        let q = shared.queue.try_lock().unwrap();
        assert_eq!(q.len(), 2);
        assert_eq!(q[0].id, "<fresh@x>");
        assert_eq!(q[0].tried_430, 0);
        assert_eq!(q[1].id, "<old@x>");
        assert_eq!(
            q[1].tried_430, 0b01,
            "30-day article pre-excluded from the 10-day server"
        );
    }

    #[test]
    fn shared_new_dedupes_repeated_ids() {
        // A malformed NZB can list the same <segment> id twice. Charging
        // `pending` per occurrence but crediting per id (claim_done) left
        // the run non-terminal forever. Repeats are dropped at build time,
        // servable and unservable alike.
        let reqs = vec![
            ArticleReq::fresh("<a@x>".into()),
            ArticleReq::fresh("<b@x>".into()),
            ArticleReq::fresh("<a@x>".into()), // servable repeat
            ArticleReq {
                id: "<ancient@x>".into(),
                age_days: 400,
            },
            ArticleReq {
                id: "<ancient@x>".into(),
                age_days: 400,
            }, // unservable repeat - must not report Missing twice
        ];
        let srv = (
            ServerConfig {
                host: "x".into(),
                port: 119,
                tls: false,
                username: None,
                password: None,
                connections: 1,
                rcvbuf: None,
                level: 0,
                group: None,
                retention_days: 10,
                block_bytes: None,
                bind_ip: None,
                socks5: None,
                enabled: true,
                warm_pool: false,
            },
            PoolConfig::default(),
        );
        let (shared, unservable) = Shared::new(reqs, &[srv]);
        assert_eq!(unservable, vec!["<ancient@x>".to_string()]);
        assert_eq!(shared.pending.load(Ordering::Relaxed), 2);
        let q = shared.queue.try_lock().unwrap();
        assert_eq!(q.len(), 2);
        assert_eq!(q[0].id, "<a@x>");
        assert_eq!(q[1].id, "<b@x>");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn duplicate_ids_reach_terminal_with_one_outcome_per_id() {
        // Regression (TODO §7): duplicate ids in reqs wedged
        // fetch_all_multi forever - pending charged twice, credited once.
        // With dedupe the run must RETURN, with exactly one Done per
        // unique id.
        let mut articles = std::collections::HashMap::new();
        let data: Vec<u8> = (0..50_000u32).map(|i| i as u8).collect();
        let segs = crate::mock::make_file_articles("d.bin", &data, 10_000, "dup", &mut articles);
        let srv = crate::mock::MockServer::start(articles, crate::mock::Chaos::default()).await;

        let mut reqs: Vec<ArticleReq> = segs
            .iter()
            .map(|(id, _, _)| ArticleReq::fresh(format!("<{id}>")))
            .collect();
        let n_unique = reqs.len();
        reqs.push(ArticleReq::fresh(format!("<{}>", segs[0].0)));
        reqs.push(ArticleReq::fresh(format!("<{}>", segs[0].0)));
        reqs.push(ArticleReq::fresh(format!("<{}>", segs[segs.len() - 1].0)));

        let cfg = PoolConfig {
            connections: 2,
            ramp_delay: Duration::from_millis(0),
            ..PoolConfig::default()
        };
        let servers = vec![(srv.server_config(), cfg)];
        let (tx, mut rx) = mpsc::channel(16);
        let fetch = tokio::spawn(async move { fetch_all_multi(&servers, reqs, tx).await });
        // Drain in a task so a regression fails LOUD at the timeout below
        // instead of wedging the test on a channel that never closes.
        let collect = tokio::spawn(async move {
            let mut done: Vec<String> = Vec::new();
            while let Some(o) = rx.recv().await {
                match o {
                    FetchOutcome::Done { id, .. } => done.push(id),
                    other => panic!("unexpected outcome: {other:?}"),
                }
            }
            done
        });
        tokio::time::timeout(Duration::from_secs(30), fetch)
            .await
            .expect("fetch_all_multi hung on duplicate ids")
            .unwrap();
        let done = collect.await.unwrap();
        assert_eq!(done.len(), n_unique, "one outcome per unique id");
        let uniq: HashSet<&str> = done.iter().map(String::as_str).collect();
        assert_eq!(uniq.len(), n_unique, "no id reported twice");
    }

    /// A server whose scan found nothing takeable must NOT rescan (and
    /// re-rotate) the whole queue on its next call - on a 12k-segment
    /// post that only one provider still carried (live, 2026-07-20), the
    /// other five servers' every-25ms full-queue scans starved the
    /// serving one to a flat 0.0 MB/s. The throttle trades ≤100 ms of
    /// pickup latency for that lock storm.
    #[tokio::test(flavor = "multi_thread")]
    async fn futile_scan_throttles_before_retrying() {
        let mk = |host: &str| {
            (
                ServerConfig {
                    host: host.into(),
                    port: 119,
                    tls: false,
                    username: None,
                    password: None,
                    connections: 1,
                    level: 0,
                    group: None,
                    retention_days: 0,
                    rcvbuf: None,
                    block_bytes: None,
                    bind_ip: None,
                    socks5: None,
                    enabled: true,
                    warm_pool: false,
                },
                PoolConfig::default(),
            )
        };
        let servers = vec![mk("a"), mk("b")];
        let reqs: Vec<ArticleReq> =
            (0..50).map(|i| ArticleReq::fresh(format!("<t{i}>"))).collect();
        let (shared, _) = Shared::new(reqs, &servers);
        // Both servers "live" so nothing is judged unservable.
        let _a = WorkerLife::birth(&shared, 0);
        let _b = WorkerLife::birth(&shared, 1);
        // Server 0 has 430'd the entire queue.
        for w in shared.queue.lock().await.iter_mut() {
            w.tried_430 |= 0b01;
        }
        let ctx = ServerCtx { idx: 0, bit: 0b01, all: 0b11, group_bits: 0b01, level: 0 };
        let (tx, _rx) = mpsc::channel(64);

        assert!(next_work(&shared, ctx, &tx, 0).await.is_none());
        assert_ne!(shared.scan_futile[0].load(Ordering::Relaxed), u64::MAX);

        // Fresh takeable work appears; within the throttle window the
        // server still sits out (documented ≤SCAN_RETRY_MS latency)…
        shared.queue.lock().await.push_front(Work {
            id: "<fresh>".into(),
            attempts: 0,
            promoted: false,
            tried_430: 0,
            tried_fail: 0,
            dup: false,
        });
        assert!(next_work(&shared, ctx, &tx, 0).await.is_none(), "throttled");
        assert_eq!(shared.queue.lock().await.len(), 51, "queue untouched");

        // …and picks it up once the window passes.
        tokio::time::sleep(Duration::from_millis(SCAN_RETRY_MS + 30)).await;
        let w = next_work(&shared, ctx, &tx, 0).await.expect("work after window");
        assert_eq!(w.id, "<fresh>");
    }

    /// M2c.4 endgame fan-out: with few articles left, a 430-laddering
    /// in-flight article is raced by every untried backbone at once -
    /// no rate/staleness preconditions - while the fill gate, the
    /// once-per-backbone rule, and the normal-phase conditions all hold.
    #[tokio::test]
    async fn endgame_fans_out_dup_races_for_laddering_articles() {
        let mk = |host: &str| {
            (
                ServerConfig {
                    host: host.into(),
                    port: 119,
                    tls: false,
                    username: None,
                    password: None,
                    connections: 1,
                    level: 0,
                    group: None,
                    retention_days: 0,
                    rcvbuf: None,
                    block_bytes: None,
                    bind_ip: None,
                    socks5: None,
                    enabled: true,
                    warm_pool: false,
                },
                PoolConfig::default(),
            )
        };
        let servers = vec![mk("a"), mk("b"), mk("c")];
        // 3 pending ≤ ENDGAME_MAX → endgame rules apply.
        let reqs: Vec<ArticleReq> =
            (0..3).map(|i| ArticleReq::fresh(format!("<e{i}>"))).collect();
        let (shared, _) = Shared::new(reqs, &servers);
        // In flight on server 0, already 430'd by server 1's backbone.
        let lad = Work {
            id: "<e0>".into(),
            attempts: 0,
            promoted: false,
            tried_430: 0b010,
            tried_fail: 0,
            dup: false,
        };
        shared.register_inflight(&lad, 0);

        // Fill gate first: a server whose required lower levels haven't
        // all 430'd yet must NOT join the race.
        assert!(shared.pick_dup(2, 0b100, 0b100, 0b011, 0, 1).is_none(), "fill-gated");
        // Endgame grant: no rate/staleness precondition needed.
        assert!(
            shared.pick_dup(2, 0b100, 0b100, 0, 3, 1).is_none(),
            "busy pipeline never carries a ladder probe"
        );
        let d = shared.pick_dup(2, 0b100, 0b100, 0, 0, 1).expect("endgame dup race");
        assert_eq!(d.id, "<e0>");
        assert!(d.dup);
        // Each backbone races at most once.
        assert!(shared.pick_dup(2, 0b100, 0b100, 0, 0, 1).is_none(), "already racing");
        // A backbone that 430'd it never re-tries.
        assert!(shared.pick_dup(1, 0b010, 0b010, 0, 0, 1).is_none(), "430'd backbone");

        // Normal phase (pending > ENDGAME_MAX): same shape gets NO dup -
        // owner isn't slow (all rates 0) and isn't stale yet.
        let reqs: Vec<ArticleReq> = (0..(ENDGAME_MAX + 10))
            .map(|i| ArticleReq::fresh(format!("<n{i}>")))
            .collect();
        let (big, _) = Shared::new(reqs, &servers);
        let lad2 = Work {
            id: "<n0>".into(),
            attempts: 0,
            promoted: false,
            tried_430: 0b010,
            tried_fail: 0,
            dup: false,
        };
        big.register_inflight(&lad2, 0);
        assert!(big.pick_dup(2, 0b100, 0b100, 0, 0, 0).is_none(), "normal phase unchanged");
    }

    /// §35: a bigger server must not duplicate a smaller one's work just
    /// for being bigger.
    ///
    /// `rate()` is bytes-over-wall-time, so it tracks a server's SHARE of
    /// the job, and that share is set mostly by how many connections it
    /// was given. Judged on shares, a server with 4x the connections reads
    /// as "4x faster" even when every individual connection is identical,
    /// and its idle workers then duplicated the smaller server's in-flight
    /// articles as routine - the same bytes fetched twice. The question
    /// the heuristic means to ask is whether the OWNER is slow, which is a
    /// per-connection quantity.
    #[tokio::test]
    async fn a_server_with_more_connections_is_not_mistaken_for_a_faster_one() {
        let mk = |host: &str| {
            (
                ServerConfig {
                    host: host.into(),
                    port: 119,
                    tls: false,
                    username: None,
                    password: None,
                    connections: 1,
                    level: 0,
                    group: None,
                    retention_days: 0,
                    rcvbuf: None,
                    block_bytes: None,
                    bind_ip: None,
                    socks5: None,
                    enabled: true,
                    warm_pool: false,
                },
                PoolConfig::default(),
            )
        };
        let servers = vec![mk("big"), mk("small")];
        // Well past ENDGAME_MAX so the endgame's unconditional fan-out
        // does not apply and only the rate rule is under test.
        let reqs: Vec<ArticleReq> = (0..(ENDGAME_MAX + 10))
            .map(|i| ArticleReq::fresh(format!("<r{i}>")))
            .collect();
        let (shared, _) = Shared::new(reqs, &servers);

        // Identical per-connection speed; server 0 simply has 4x the
        // workers, so it has moved 4x the bytes.
        shared.alive[0].store(8, Ordering::Relaxed);
        shared.alive[1].store(2, Ordering::Relaxed);
        shared.bytes[0].store(400_000_000, Ordering::Relaxed);
        shared.bytes[1].store(100_000_000, Ordering::Relaxed);

        let w = Work {
            id: "<r0>".into(),
            attempts: 0,
            promoted: false,
            tried_430: 0,
            tried_fail: 0,
            dup: false,
        };
        shared.register_inflight(&w, 1); // owned by the SMALL server

        assert!(
            shared.pick_dup(0, 0b01, 0b01, 0, 0, 0).is_none(),
            "the big server duplicated an equally fast connection's article"
        );

        // And the rule still fires when the owner really is slower per
        // connection: same worker counts, a quarter of the bytes.
        shared.bytes[1].store(25_000_000, Ordering::Relaxed);
        let d = shared
            .pick_dup(0, 0b01, 0b01, 0, 0, 0)
            .expect("a genuinely slow owner should still be raced");
        assert_eq!(d.id, "<r0>");
        assert!(d.dup);
    }

    /// A FILL server must never race on speed, only on the endgame
    /// 430-ladder (which is gated on every live lower level having
    /// missed). Its bytes are billed per gigabyte, so re-fetching an
    /// article a primary is already delivering is a straight loss.
    ///
    /// This became reachable the moment the dup comparison went
    /// per-worker: a fill server is given FEW connections, so by that
    /// measure it looks fast exactly when it is least worth spending.
    #[tokio::test]
    async fn a_fill_server_never_duplicates_primary_work_on_speed() {
        let mk = |host: &str, level: u32| {
            (
                ServerConfig {
                    host: host.into(),
                    port: 119,
                    tls: false,
                    username: None,
                    password: None,
                    connections: 1,
                    level,
                    group: None,
                    retention_days: 0,
                    rcvbuf: None,
                    block_bytes: None,
                    bind_ip: None,
                    socks5: None,
                    enabled: true,
                    warm_pool: false,
                },
                PoolConfig::default(),
            )
        };
        let servers = vec![mk("primary", 0), mk("block", 1)];
        let reqs: Vec<ArticleReq> = (0..(ENDGAME_MAX + 10))
            .map(|i| ArticleReq::fresh(format!("<f{i}>")))
            .collect();
        let (shared, _) = Shared::new(reqs, &servers);

        // The block server has one fast connection; the primary has many
        // slower ones. Per worker the block server wins by miles.
        shared.alive[0].store(50, Ordering::Relaxed);
        shared.alive[1].store(1, Ordering::Relaxed);
        shared.bytes[0].store(50_000_000, Ordering::Relaxed);
        shared.bytes[1].store(50_000_000, Ordering::Relaxed);

        let w = Work {
            id: "<f0>".into(),
            attempts: 0,
            promoted: false,
            tried_430: 0,
            tried_fail: 0,
            dup: false,
        };
        shared.register_inflight(&w, 0); // owned by the PRIMARY

        assert!(
            shared.pick_dup(1, 0b10, 0b10, 0, 0, 1).is_none(),
            "a block server spent paid bytes racing an article already arriving"
        );
        // The primary, in its place, would take it.
        assert!(
            shared.pick_dup(1, 0b10, 0b10, 0, 0, 0).is_some(),
            "the rate rule itself should still fire for a level-0 server"
        );
    }

    #[tokio::test]
    async fn queue_control_promotes_to_front_preserving_order() {
        // M11: promoted ids move to the front in their original relative
        // order; everything else keeps its order behind them.
        let servers: Vec<(ServerConfig, PoolConfig)> = vec![(
            ServerConfig {
                host: "s".into(),
                port: 119,
                tls: false,
                username: None,
                password: None,
                connections: 1,
                level: 0,
                group: None,
                retention_days: 0,
                rcvbuf: None,
                block_bytes: None,
                bind_ip: None,
                socks5: None,
                enabled: true,
                warm_pool: false,
            },
            PoolConfig::default(),
        )];
        let reqs: Vec<ArticleReq> =
            (0..10).map(|i| ArticleReq::fresh(format!("<a{i}>"))).collect();
        let (shared, unservable) = Shared::new(reqs, &servers);
        assert!(unservable.is_empty());
        let ctl = QueueControl::default();
        ctl.attach(&shared);
        // The caller's order (seek-point-first) is the front order - NOT
        // the queue's relative order.
        let ids: Vec<String> = ["<a7>", "<a3>", "<a9>"].iter().map(|s| s.to_string()).collect();
        assert_eq!(ctl.promote(&ids), 3);
        let q = shared.queue.lock().await;
        let order: Vec<&str> = q.iter().map(|w| w.id.as_str()).collect();
        assert_eq!(
            order,
            ["<a7>", "<a3>", "<a9>", "<a0>", "<a1>", "<a2>", "<a4>", "<a5>", "<a6>", "<a8>"]
        );
        drop(q);
        // Unknown ids are a no-op; a dead pool (Weak gone) is a no-op.
        assert_eq!(ctl.promote(&["<zz>".to_string()]), 0);
        drop(shared);
        assert_eq!(ctl.promote(&ids), 0);
    }

    fn one_server() -> Vec<(ServerConfig, PoolConfig)> {
        vec![(
            ServerConfig {
                host: "s".into(),
                port: 119,
                tls: false,
                username: None,
                password: None,
                connections: 1,
                level: 0,
                group: None,
                retention_days: 0,
                rcvbuf: None,
                block_bytes: None,
                bind_ip: None,
                socks5: None,
                enabled: true,
                warm_pool: false,
            },
            PoolConfig::default(),
        )]
    }

    #[test]
    fn wire_cap_accounting_charges_and_releases_symmetrically() {
        // B3: the cap gate reads the running estimate; every charge must
        // be matched by exactly one release, whichever exit path takes it.
        let (shared, _) = Shared::new(vec![ArticleReq::fresh("<w@x>".into())], &one_server());
        assert_eq!(shared.inflight_body_bytes.load(Ordering::Acquire), 0);
        assert!(!shared.wire_over_cap(EST_BODY_BYTES), "empty pool is under any cap");

        shared.charge_wire();
        assert_eq!(shared.inflight_body_bytes.load(Ordering::Acquire), EST_BODY_BYTES);
        assert!(shared.wire_over_cap(EST_BODY_BYTES), "at the cap counts as over");
        assert!(!shared.wire_over_cap(0), "cap 0 = uncapped, never throttles");
        assert!(!shared.wire_over_cap(2 * EST_BODY_BYTES));

        // A batch release (shed / dead connection) drops the whole
        // pipeline's charge in one call.
        shared.charge_wire();
        shared.charge_wire();
        shared.release_wire(2);
        assert_eq!(shared.inflight_body_bytes.load(Ordering::Acquire), EST_BODY_BYTES);
        shared.release_wire(1);
        assert_eq!(shared.inflight_body_bytes.load(Ordering::Acquire), 0);
        assert!(!shared.wire_over_cap(EST_BODY_BYTES));

        // A zero-count release (empty pipeline on abort) is a no-op.
        shared.release_wire(0);
        assert_eq!(shared.inflight_body_bytes.load(Ordering::Acquire), 0);
    }

    #[tokio::test]
    async fn a_dead_pipeline_releases_exactly_what_dispatch_charged() {
        // Carried regression: the worker used to charge the wire only
        // AFTER send_body succeeded, while the failed-send path pushes
        // that same article into the deque requeue_or_fail bulk-releases.
        // One flaky send therefore released a charge nobody took; the
        // counter wrapped to ~u64::MAX, wire_over_cap answered true for
        // the rest of the run, and every worker in the pool collapsed to
        // pipeline depth one. Model the worker's dispatch sequence.
        let servers = one_server();
        let (shared, _) = Shared::new(
            vec![ArticleReq::fresh("<f0@x>".into()), ArticleReq::fresh("<f1@x>".into())],
            &servers,
        );
        let ctx = ctx_for(&servers, 0);
        let cfg = PoolConfig::default();
        let (tx, _rx) = mpsc::channel(8);
        // Without a live worker the queue scan declares everything
        // unanimously-430 Missing before we get to dispatch it.
        let _life = WorkerLife::birth(&shared, 0);

        let mut inflight: VecDeque<Work> = VecDeque::new();
        // One article dispatched normally...
        let w0 = next_work(&shared, ctx, &tx, 0).await.expect("queued work");
        shared.charge_wire();
        shared.register_inflight(&w0, 0);
        inflight.push_back(w0);
        // ...and the next one's send fails, so it joins the same deque as
        // the front-of-pipeline casualty.
        let w1 = next_work(&shared, ctx, &tx, 1).await.expect("queued work");
        shared.charge_wire();
        inflight.push_front(w1);
        assert_eq!(
            shared.inflight_body_bytes.load(Ordering::Acquire),
            2 * EST_BODY_BYTES,
            "every item in a worker's pipeline carries exactly one charge"
        );

        requeue_or_fail(&shared, &tx, &cfg, ctx, &mut inflight, "send failed").await;
        assert_eq!(
            shared.inflight_body_bytes.load(Ordering::Acquire),
            0,
            "the dead pipeline must release exactly its own charges"
        );
        assert!(!shared.wire_over_cap(EST_BODY_BYTES), "counter wrapped past zero");
    }

    #[tokio::test]
    async fn stream_mode_engages_on_promote_and_reader_touch() {
        // M11 stream mode: any reader touch (note_stream_active) or any
        // promote - even one that moves nothing - flips the pool into
        // shallow-pipeline mode; a fresh pool starts with it off.
        let reqs: Vec<ArticleReq> =
            (0..4).map(|i| ArticleReq::fresh(format!("<a{i}>"))).collect();
        let (shared, _) = Shared::new(reqs, &one_server());
        let ctl = QueueControl::default();
        ctl.attach(&shared);
        assert!(!shared.stream_active(), "stream mode must start disengaged");
        ctl.note_stream_active();
        assert!(shared.stream_active(), "reader touch engages stream mode");

        let (shared2, _) = Shared::new(
            (0..4).map(|i| ArticleReq::fresh(format!("<b{i}>"))).collect(),
            &one_server(),
        );
        let ctl2 = QueueControl::default();
        ctl2.attach(&shared2);
        assert_eq!(ctl2.promote(&["<zz>".to_string()]), 0);
        assert!(
            shared2.stream_active(),
            "a promote engages stream mode even when nothing moves"
        );
    }

    #[tokio::test]
    async fn promoted_work_routes_to_the_faster_server() {
        // M11 stream mode: a slow server steps PAST promoted items a >2×
        // faster live server can take - leaving them at the queue front -
        // but still takes non-promoted work, and takes promoted work
        // itself when no faster server exists (never stranded).
        let mk = |host: &str| {
            (
                ServerConfig {
                    host: host.into(),
                    port: 119,
                    tls: false,
                    username: None,
                    password: None,
                    connections: 1,
                    level: 0,
                    group: None,
                    retention_days: 0,
                    rcvbuf: None,
                    block_bytes: None,
                    bind_ip: None,
                    socks5: None,
                    enabled: true,
                    warm_pool: false,
                },
                PoolConfig::default(),
            )
        };
        let servers = vec![mk("slow"), mk("fast")];
        let reqs: Vec<ArticleReq> =
            (0..4).map(|i| ArticleReq::fresh(format!("<a{i}>"))).collect();
        let (shared, _) = Shared::new(reqs, &servers);
        let _a = WorkerLife::birth(&shared, 0);
        let _b = WorkerLife::birth(&shared, 1);
        let ctl = QueueControl::default();
        ctl.attach(&shared);
        // Server 1 measured 10× faster than server 0.
        shared.bytes[0].store(1_000_000, Ordering::Relaxed);
        shared.bytes[1].store(10_000_000, Ordering::Relaxed);
        // Promote a1 and a2; stream mode engages via the promote.
        let ids: Vec<String> = ["<a1>", "<a2>"].iter().map(|s| s.to_string()).collect();
        assert_eq!(ctl.promote(&ids), 2);

        let slow = ServerCtx { idx: 0, bit: 0b01, all: 0b11, group_bits: 0b01, level: 0 };
        let fast = ServerCtx { idx: 1, bit: 0b10, all: 0b11, group_bits: 0b10, level: 0 };
        let (tx, _rx) = mpsc::channel(16);

        // The slow server skips a1/a2 and takes the first non-promoted
        // item; the promoted run stays at the queue front.
        let w = next_work(&shared, slow, &tx, 0).await.expect("slow gets non-promoted work");
        assert_eq!(w.id, "<a0>");
        assert_eq!(
            shared.queue.lock().await.front().map(|w| w.id.clone()),
            Some("<a1>".into()),
            "promoted run must stay at the front for the fast server"
        );
        // The fast server takes the promoted item.
        let w = next_work(&shared, fast, &tx, 0).await.expect("fast gets promoted work");
        assert_eq!(w.id, "<a1>");
        assert!(w.promoted);
        // A promoted item some backbone already 430'd bypasses the
        // speed-matching: latency beats routing once it's on a recovery
        // path (the live wedge: fast servers cycling 430 → requeue while
        // slow ones politely skipped).
        shared.queue.lock().await.front_mut().unwrap().tried_430 = 0b10;
        let w = next_work(&shared, slow, &tx, 0).await.expect("slow takes the 430-recovery item");
        assert_eq!(w.id, "<a2>");
        assert!(w.promoted);

        // Kill the fast server; the slow one must take promoted work
        // rather than strand it.
        let reqs2: Vec<ArticleReq> = vec![ArticleReq::fresh("<b0>".into())];
        let (shared2, _) = Shared::new(reqs2, &servers);
        let _c = WorkerLife::birth(&shared2, 0);
        let ctl2 = QueueControl::default();
        ctl2.attach(&shared2);
        shared2.bytes[0].store(1_000_000, Ordering::Relaxed);
        shared2.bytes[1].store(10_000_000, Ordering::Relaxed);
        assert_eq!(ctl2.promote(&["<b0>".to_string()]), 1);
        let w = next_work(&shared2, slow, &tx, 0).await.expect("slow takes it when alone");
        assert_eq!(w.id, "<b0>");
    }

    #[tokio::test]
    async fn shed_pipeline_requeues_behind_promoted_run_uncharged() {
        // M11 shed: a worker abandoning its pre-stream pipeline puts the
        // in-flight items back BEHIND the promoted run, in order, without
        // charging attempts; tail dups are dropped, not requeued.
        let reqs: Vec<ArticleReq> =
            (0..10).map(|i| ArticleReq::fresh(format!("<a{i}>"))).collect();
        let (shared, _) = Shared::new(reqs, &one_server());
        let ctl = QueueControl::default();
        ctl.attach(&shared);

        // Simulate a window-3 pipeline: a0..a2 popped and dispatched.
        // Dispatch charges the wire cap, so the fixture must too - every
        // item in a worker's pipeline carries exactly one charge.
        let mut inflight: VecDeque<Work> = VecDeque::new();
        {
            let mut q = shared.queue.lock().await;
            for _ in 0..3 {
                let w = q.pop_front().unwrap();
                shared.charge_wire();
                shared.register_inflight(&w, 0);
                inflight.push_back(w);
            }
        }
        // A tail dup rides the same pipeline (charged too - its response
        // is just as real).
        shared.charge_wire();
        inflight.push_back(Work {
            id: "<a5>".into(),
            attempts: 0,
            promoted: false,
            tried_430: 0,
            tried_fail: 0,
            dup: true,
        });
        // A seek promotes a7 and a3 to the front (in that range order).
        let ids: Vec<String> = ["<a7>", "<a3>"].iter().map(|s| s.to_string()).collect();
        assert_eq!(ctl.promote(&ids), 2);

        shed_pipeline(&shared, &mut inflight).await;
        assert!(inflight.is_empty());
        let q = shared.queue.lock().await;
        let order: Vec<&str> = q.iter().map(|w| w.id.as_str()).collect();
        assert_eq!(
            order,
            ["<a7>", "<a3>", "<a0>", "<a1>", "<a2>", "<a4>", "<a5>", "<a6>", "<a8>", "<a9>"],
            "shed items must slot in behind the promoted run, in order"
        );
        assert!(
            q.iter().all(|w| w.attempts == 0),
            "an abandoned pipeline is not a failure - no attempts charged"
        );
        assert_eq!(
            q.iter().filter(|w| w.dup).count(),
            0,
            "the tail dup must be dropped, not requeued"
        );
        drop(q);
        assert!(
            shared.inflight.lock().unwrap().is_empty(),
            "shed items must be deregistered from inflight"
        );
        assert_eq!(
            shared.inflight_body_bytes.load(Ordering::Acquire),
            0,
            "the shed pipeline must release every charge it held, dup included"
        );
    }

    #[tokio::test]
    async fn drain_signals_graceful_and_leaves_the_queue_intact() {
        // The friendly Pause plumbing: drain() flips is_draining (which the
        // worker top-up loop checks to stop admitting new articles) WITHOUT
        // touching the queue - so everything unstarted is still there for a
        // resume. Contrast abort(), which is the hard stop.
        let servers: Vec<(ServerConfig, PoolConfig)> = vec![(
            ServerConfig {
                host: "s".into(),
                port: 119,
                tls: false,
                username: None,
                password: None,
                connections: 1,
                level: 0,
                group: None,
                retention_days: 0,
                rcvbuf: None,
                block_bytes: None,
                bind_ip: None,
                socks5: None,
                enabled: true,
                warm_pool: false,
            },
            PoolConfig::default(),
        )];
        let reqs: Vec<ArticleReq> =
            (0..8).map(|i| ArticleReq::fresh(format!("<a{i}>"))).collect();
        let (shared, _) = Shared::new(reqs, &servers);
        let ctl = QueueControl::default();
        ctl.attach(&shared);

        assert!(!ctl.is_draining());
        assert!(ctl.drain(), "drain should reach the live pool");
        assert!(ctl.is_draining(), "is_draining must reflect a requested drain");
        // The queue is untouched - unstarted work is preserved for resume.
        assert_eq!(shared.queue.lock().await.len(), 8);

        // The ordering that matters in production: the engine only asks
        // AFTER the fetch call returned, which is where the pool's last
        // strong Arc dies. The answer must survive that.
        drop(shared);
        assert!(
            ctl.is_draining(),
            "a drain requested on a live pool must still read as draining once the pool is gone"
        );

        // A dead pool (Weak gone) is a no-op, never a panic - and it must
        // not latch a drain that never reached a run.
        let dead = QueueControl::default();
        assert!(!dead.drain());
        assert!(!dead.is_draining());
    }

    #[tokio::test]
    async fn rate_limit_paces_charges() {
        // 1 MB charged in 100 KB chunks at 10 MB/s ≈ 100 ms. Generous
        // bounds only - CI machines wobble.
        let rl = RateLimit::new(10_000_000);
        let t0 = Instant::now();
        for _ in 0..10 {
            rl.throttle(100_000).await;
        }
        let el = t0.elapsed();
        assert!(el >= Duration::from_millis(60), "too fast: {el:?}");
        assert!(el <= Duration::from_secs(2), "too slow: {el:?}");
    }

    #[tokio::test]
    async fn rate_limit_zero_is_unlimited() {
        let rl = RateLimit::new(0);
        let t0 = Instant::now();
        for _ in 0..100 {
            rl.throttle(10_000_000).await;
        }
        assert!(t0.elapsed() < Duration::from_millis(100));
        // And a live set() takes effect.
        rl.set(1_000_000);
        assert_eq!(rl.get(), 1_000_000);
        let t0 = Instant::now();
        rl.throttle(300_000).await; // fresh window: ~300 ms owed
        assert!(t0.elapsed() >= Duration::from_millis(100));
    }

    /// Drain a finished run's outcome channel into id → outcome-count.
    /// `try_recv` on purpose: anything still missing here was NOT emitted
    /// before the pool returned, which is exactly the contract under test.
    fn tally(rx: &mut mpsc::Receiver<FetchOutcome>) -> HashMap<String, usize> {
        let mut seen: HashMap<String, usize> = HashMap::new();
        while let Ok(o) = rx.try_recv() {
            let id = match o {
                FetchOutcome::Done { id, .. }
                | FetchOutcome::Missing { id }
                | FetchOutcome::Failed { id, .. } => id,
            };
            *seen.entry(id).or_default() += 1;
        }
        seen
    }

    fn assert_exactly_one_outcome_each(ids: &[String], seen: &HashMap<String, usize>) {
        for id in ids {
            assert_eq!(
                seen.get(id).copied().unwrap_or(0),
                1,
                "{id} must have exactly one terminal outcome, got {:?}",
                seen.get(id)
            );
        }
        assert_eq!(seen.len(), ids.len(), "unexpected extra outcomes: {seen:?}");
    }

    /// A15 regression: a server that never accepts a connection.
    ///
    /// Every worker burns `max_connect_attempts` and bows out. Before the
    /// seal, the last one out simply returned - `join_fleet` had no
    /// postcondition, the senders dropped, and the channel closed without
    /// a single word about any of the requested articles. Downstream that
    /// reads as "the network said nothing", so repair ran against a
    /// ledger that never recorded the failures.
    #[tokio::test]
    async fn dead_server_seals_every_article_before_returning() {
        // Bind then drop: a port with nothing listening, so connect()
        // fails immediately rather than hanging on a firewalled SYN.
        let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        let mut server = one_server()[0].0.clone();
        server.host = "127.0.0.1".into();
        server.port = port;
        let cfg = PoolConfig {
            connections: 3,
            ramp_delay: Duration::ZERO,
            connect_backoff: Duration::from_millis(1),
            max_connect_attempts: 2,
            ..Default::default()
        };
        let ids: Vec<String> = (0..5).map(|i| format!("<seal{i}@x>")).collect();
        let reqs: Vec<ArticleReq> = ids.iter().cloned().map(ArticleReq::fresh).collect();
        let (tx, mut rx) = mpsc::channel(64);
        tokio::time::timeout(
            Duration::from_secs(20),
            fetch_all_multi(&[(server, cfg)], reqs, tx),
        )
        .await
        .expect("run hung with no reachable server");

        let seen = tally(&mut rx);
        assert_exactly_one_outcome_each(&ids, &seen);
    }

    /// §15e: a rejected credential is settled ONCE for the server, not
    /// rediscovered by every worker.
    ///
    /// Each worker used to burn its own `max_connect_attempts` behind its
    /// own growing backoff, so the account that had already said no got
    /// asked `connections x max_connect_attempts` times - here 8 x 5 = 40.
    /// Nothing about that can succeed, and on a provider that refuses for
    /// CAPACITY reasons (same 481) the retries re-provoke the very limit
    /// being hit.
    #[tokio::test]
    async fn a_rejected_credential_is_asked_once_per_server_not_once_per_worker() {
        use crate::mock::{Chaos, MockServer};
        let srv = MockServer::start(
            std::collections::HashMap::new(),
            Chaos { auth_rejected: true, ..Default::default() },
        )
        .await;
        let mut server = srv.server_config();
        server.username = Some("u".into());
        server.password = Some("p".into());
        const CONNS: usize = 8;
        let cfg = PoolConfig {
            connections: CONNS,
            ramp_delay: Duration::ZERO,
            connect_backoff: Duration::from_millis(1),
            max_connect_attempts: 5,
            ..Default::default()
        };
        let ids: Vec<String> = (0..4).map(|i| format!("<perm{i}@x>")).collect();
        let reqs: Vec<ArticleReq> = ids.iter().cloned().map(ArticleReq::fresh).collect();
        let (tx, mut rx) = mpsc::channel(64);
        tokio::time::timeout(
            Duration::from_secs(20),
            fetch_all_multi(&[(server, cfg)], reqs, tx),
        )
        .await
        .expect("run hung on a permanently rejected server");

        // The terminal-state contract still holds.
        let seen = tally(&mut rx);
        assert_exactly_one_outcome_each(&ids, &seen);

        // Workers start concurrently, so up to `CONNS` can be in the air
        // before the first refusal is recorded - but not a single retry
        // beyond that.
        let accepted = srv.accepted.load(Ordering::Relaxed);
        assert!(
            accepted <= CONNS as u64,
            "a rejected credential was re-asked: {accepted} connections for {CONNS} workers"
        );
    }

    /// §15e: a CAPACITY refusal is answered by asking for fewer
    /// connections, which is the only thing a simultaneous-connection or
    /// simultaneous-IP cap actually accepts.
    ///
    /// Giganews answers `481 max simultaneous IP addresses reached` for a
    /// perfectly good account at its cap - the same code as a wrong
    /// password, so only the text tells them apart. Retrying all workers
    /// at the same count re-provokes it, and behind a multi-WAN router
    /// each retry can present a fresh IP and re-exhaust the cap itself.
    /// Workers yield their slots instead, leaving one still trying so a
    /// cap that clears later does not strand the server for the run.
    #[tokio::test]
    async fn a_capacity_refusal_yields_connections_instead_of_hammering() {
        use crate::mock::{Chaos, MockServer};
        let srv = MockServer::start(
            std::collections::HashMap::new(),
            Chaos {
                auth_rejected: true,
                auth_refusal_text: Some(
                    "481 max simultaneous IP addresses reached".into(),
                ),
                ..Default::default()
            },
        )
        .await;
        let mut server = srv.server_config();
        server.username = Some("u".into());
        server.password = Some("p".into());
        const CONNS: usize = 8;
        const ATTEMPTS: u32 = 5;
        let cfg = PoolConfig {
            connections: CONNS,
            ramp_delay: Duration::ZERO,
            connect_backoff: Duration::from_millis(1),
            max_connect_attempts: ATTEMPTS,
            ..Default::default()
        };
        let ids: Vec<String> = (0..4).map(|i| format!("<cap{i}@x>")).collect();
        let reqs: Vec<ArticleReq> = ids.iter().cloned().map(ArticleReq::fresh).collect();
        let (tx, mut rx) = mpsc::channel(64);
        tokio::time::timeout(
            Duration::from_secs(20),
            fetch_all_multi(&[(server, cfg)], reqs, tx),
        )
        .await
        .expect("run hung on a server at its connection cap");

        let seen = tally(&mut rx);
        assert_exactly_one_outcome_each(&ids, &seen);

        // Each worker gets one look, then yields; the last one standing
        // spends the retry budget alone. The old behaviour was every
        // worker spending it: CONNS * ATTEMPTS = 40.
        let accepted = srv.accepted.load(Ordering::Relaxed);
        assert!(
            accepted < (CONNS as u64 * ATTEMPTS as u64),
            "capacity refusal still hammered the cap: {accepted} connections"
        );
        assert!(
            accepted >= CONNS as u64,
            "workers should each get one look before yielding, got {accepted}"
        );
    }

    /// §34: a dead server must not hold the run open after the work is
    /// done. Measured on the bench farm, one dead provider in a
    /// six-server config DOUBLED per-job time (4.1 s vs 2.0 s): the bytes
    /// were all in at 0.79 s and the run did not return until 3.17 s,
    /// with nothing outstanding but a server that would never answer.
    /// Its workers were asleep in a connect backoff that could not see
    /// the run finish.
    ///
    /// Here the live server can serve everything immediately while the
    /// dead one's backoff is far longer than the work, so if the backoff
    /// is not raced against the finish signal the run cannot come back
    /// inside the timeout.
    #[tokio::test]
    async fn a_dead_server_does_not_hold_the_run_open_after_the_work_is_done() {
        use crate::mock::{Chaos, MockServer};
        let mut arts = std::collections::HashMap::new();
        let data: Vec<u8> = (0..20_000u32).map(|i| i as u8).collect();
        let segs = crate::mock::make_file_articles("t.bin", &data, 5_000, "tail", &mut arts);
        let ids: Vec<String> = segs.iter().map(|(id, _, _)| format!("<{id}>")).collect();
        let live = MockServer::start(arts, Chaos::default()).await;

        // Dead: TCP connects, AUTHINFO never succeeds.
        let dead = MockServer::start(
            std::collections::HashMap::new(),
            Chaos {
                auth_rejected: true,
                auth_refusal_text: Some("481 max simultaneous IP addresses reached".into()),
                ..Default::default()
            },
        )
        .await;
        let mut dead_cfg = dead.server_config();
        dead_cfg.username = Some("u".into());
        dead_cfg.password = Some("p".into());

        // A backoff far longer than the work: 30 s of sleeping against a
        // job that finishes in milliseconds.
        let slow = PoolConfig {
            connections: 2,
            ramp_delay: Duration::ZERO,
            connect_backoff: Duration::from_secs(30),
            max_connect_attempts: 5,
            ..Default::default()
        };
        let fast = PoolConfig { connections: 2, ramp_delay: Duration::ZERO, ..Default::default() };

        let reqs: Vec<ArticleReq> = ids.iter().cloned().map(ArticleReq::fresh).collect();
        let (tx, mut rx) = mpsc::channel(64);
        let t0 = Instant::now();
        tokio::time::timeout(
            Duration::from_secs(20),
            fetch_all_multi(&[(live.server_config(), fast), (dead_cfg, slow)], reqs, tx),
        )
        .await
        .expect("a dead server's backoff held the run open past the work");
        let elapsed = t0.elapsed();

        let seen = tally(&mut rx);
        assert_exactly_one_outcome_each(&ids, &seen);
        // The work itself is milliseconds. Without the finish-aware
        // backoff this same test takes ~5 s, so the threshold has to
        // discriminate rather than merely bound: generous for a loaded
        // CI box, nowhere near a single 30 s backoff leg.
        assert!(
            elapsed < Duration::from_secs(2),
            "run took {elapsed:?} for work that was done immediately"
        );
    }

    /// The classification is the whole feature, and it keys off free-form
    /// provider text, so it is pinned directly. Anything not recognisably
    /// about capacity must read as Permanent: retrying a bad credential
    /// forever is the worse of the two failures.
    #[test]
    fn auth_refusals_are_classified_by_what_the_provider_actually_says() {
        use crate::nntp::{AuthRefusal, classify_auth_refusal};
        for line in [
            "481 max simultaneous IP addresses reached",
            "502 Too many connections",
            "481 Connection limit reached",
            "482 too many sessions for this user",
            "400 no more connections available",
        ] {
            assert_eq!(
                classify_auth_refusal(line),
                AuthRefusal::Capacity,
                "should be a capacity refusal: {line}"
            );
        }
        for line in [
            "481 authentication failed",
            "481 Authentication rejected",
            "502 Permission denied",
            "481 account suspended",
            "",
        ] {
            assert_eq!(
                classify_auth_refusal(line),
                AuthRefusal::Permanent,
                "should be permanent: {line}"
            );
        }
    }

    /// Regression for the capacity-yield survivor rule.
    ///
    /// `35c7ca9` decided the survivor by counting yields up to
    /// `cfg.connections`. Workers also leave through the connect ladder
    /// and the session bow-out, and neither increments that counter, so
    /// once anyone had left by another door the target was unreachable
    /// and EVERY remaining worker yielded - leaving the server with
    /// nobody, on precisely the transient refusal the arm exists to ride
    /// out. A single-server job then sealed the rest of its articles
    /// Failed seconds before the cap cleared.
    ///
    /// The rule under test: a worker may only yield while it leaves
    /// someone behind, however the others left.
    #[test]
    fn a_capacity_yield_always_leaves_one_worker_behind() {
        let auth = AuthState::default();

        // Eight configured, but six already retired on the connect ladder
        // during a blip - none of them through `yielded`.
        let alive = AtomicUsize::new(2);

        // Worker 7 takes the refusal: one other is still up, so it goes.
        assert!(auth.claim_yield(&alive), "a worker with company should yield");
        alive.fetch_sub(1, Ordering::SeqCst); // WorkerLife::drop

        // Worker 8 is now the last one on this server. Under the old
        // `yielded < cfg.connections` rule it saw 2 < 8 and left too.
        assert!(
            !auth.claim_yield(&alive),
            "the last worker must not yield: that strands the server for the run"
        );
        assert_eq!(alive.load(Ordering::SeqCst), 1, "someone must still be trying");

        // And it keeps refusing to leave however often the cap is hit.
        for _ in 0..5 {
            assert!(!auth.claim_yield(&alive), "still the last one out");
        }
    }

    /// The same rule with nobody having left early: the fleet stands
    /// down, but never past the last worker however long the cap lasts.
    ///
    /// The count it settles on is deliberately conservative (about half,
    /// not one) because `yielded` also counts claims whose `alive`
    /// decrement has not landed yet - see `claim_yield`. What must hold
    /// for every fleet size is: fewer workers than we started with, and
    /// never zero.
    #[test]
    fn a_yielding_fleet_shrinks_but_never_empties() {
        for start in [1usize, 2, 4, 8, 30] {
            let auth = AuthState::default();
            let alive = AtomicUsize::new(start);
            for _ in 0..100 {
                if auth.claim_yield(&alive) {
                    alive.fetch_sub(1, Ordering::SeqCst);
                }
            }
            let left = alive.load(Ordering::SeqCst);
            assert!(left >= 1, "fleet of {start} was stranded with no workers");
            assert!(
                left <= start,
                "fleet of {start} somehow grew to {left}"
            );
            if start > 1 {
                assert!(
                    left < start,
                    "fleet of {start} never stood down at all, so the cap is still being hammered"
                );
            }
        }
    }

    /// A15 regression, the other half: the TCP connect always succeeds,
    /// so this is not a connect-refused fast path - the session is simply
    /// never usable. Same contract: one outcome per requested id, all of
    /// them emitted before the fetch returns.
    #[tokio::test]
    async fn server_that_never_authenticates_seals_every_article() {
        use crate::mock::{Chaos, MockServer};
        let srv = MockServer::start(
            std::collections::HashMap::new(),
            Chaos { auth_rejected: true, ..Default::default() },
        )
        .await;
        let mut server = srv.server_config();
        server.username = Some("u".into());
        server.password = Some("p".into());
        let cfg = PoolConfig {
            connections: 2,
            ramp_delay: Duration::ZERO,
            connect_backoff: Duration::from_millis(1),
            max_connect_attempts: 2,
            ..Default::default()
        };
        let ids: Vec<String> = (0..4).map(|i| format!("<auth{i}@x>")).collect();
        let reqs: Vec<ArticleReq> = ids.iter().cloned().map(ArticleReq::fresh).collect();
        let (tx, mut rx) = mpsc::channel(64);
        tokio::time::timeout(
            Duration::from_secs(20),
            fetch_all_multi(&[(server, cfg)], reqs, tx),
        )
        .await
        .expect("run hung on a server that never authenticates");

        let seen = tally(&mut rx);
        assert_exactly_one_outcome_each(&ids, &seen);
        for id in &ids {
            assert!(seen.contains_key(id));
        }
    }

    /// A dead server must not poison a healthy one: the seal only fires
    /// when the LAST worker of the whole run leaves, so articles the live
    /// backbone can still serve are served, not failed out from under it.
    #[tokio::test]
    async fn one_dead_server_does_not_seal_work_the_live_one_can_still_do() {
        use crate::mock::{Chaos, MockServer, make_file_articles};
        let mut articles = std::collections::HashMap::new();
        let payload: Vec<u8> = (0..40_000u32).map(|i| (i * 3) as u8).collect();
        make_file_articles("h.bin", &payload, 8_000, "sl", &mut articles);
        let n = articles.len();
        let healthy = MockServer::start(articles.clone(), Chaos::default()).await;

        let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        let mut dead = one_server()[0].0.clone();
        dead.host = "127.0.0.1".into();
        dead.port = port;

        let live_cfg = PoolConfig {
            connections: 2,
            ramp_delay: Duration::ZERO,
            ..Default::default()
        };
        // Bows out fast, long before the healthy server finishes.
        let dead_cfg = PoolConfig {
            connections: 2,
            ramp_delay: Duration::ZERO,
            connect_backoff: Duration::from_millis(1),
            max_connect_attempts: 1,
            ..Default::default()
        };
        let ids: Vec<String> = articles.keys().cloned().collect();
        let reqs: Vec<ArticleReq> = ids.iter().cloned().map(ArticleReq::fresh).collect();
        let (tx, mut rx) = mpsc::channel(256);
        tokio::time::timeout(
            Duration::from_secs(30),
            fetch_all_multi(
                &[(healthy.server_config(), live_cfg), (dead, dead_cfg)],
                reqs,
                tx,
            ),
        )
        .await
        .expect("run hung with one dead server");

        let mut done = 0;
        let mut seen: HashMap<String, usize> = HashMap::new();
        while let Ok(o) = rx.try_recv() {
            let id = match o {
                FetchOutcome::Done { id, .. } => {
                    done += 1;
                    id
                }
                FetchOutcome::Missing { id } | FetchOutcome::Failed { id, .. } => id,
            };
            *seen.entry(id).or_default() += 1;
        }
        assert_eq!(done, n, "the live server had to deliver every article");
        assert_exactly_one_outcome_each(&ids, &seen);
    }

    #[tokio::test]
    async fn mute_quit_server_cannot_hang_a_finished_run() {
        // Regression (the 190 GB exit-path hang): a provider that swallows
        // QUIT - TCP up, no goodbye - parked the worker's unbounded goodbye
        // read forever, and the fleet join with it, AFTER every byte was on
        // disk. quit() is now hard-bounded, so the run must return alone.
        use crate::mock::{Chaos, MockServer, make_file_articles};
        let mut articles = std::collections::HashMap::new();
        let payload: Vec<u8> = (0..40_000u32).map(|i| i as u8).collect();
        make_file_articles("f.bin", &payload, 8_000, "mq", &mut articles);
        let n = articles.len();
        let srv = MockServer::start(
            articles.clone(),
            Chaos { mute_quit: true, ..Default::default() },
        )
        .await;
        let cfg = PoolConfig {
            connections: 3,
            ramp_delay: Duration::ZERO,
            ..Default::default()
        };
        let reqs: Vec<ArticleReq> =
            articles.keys().map(|id| ArticleReq::fresh(id.clone())).collect();
        let (tx, mut rx) = mpsc::channel(64);
        let t0 = Instant::now();
        tokio::time::timeout(
            Duration::from_secs(20),
            fetch_all_multi(&[(srv.server_config(), cfg)], reqs, tx),
        )
        .await
        .expect("run hung on a mute-QUIT server");
        // Well under EXIT_GRACE: the bounded quit alone frees the join.
        assert!(t0.elapsed() < Duration::from_secs(4), "took {:?}", t0.elapsed());
        let mut done = 0;
        while let Ok(o) = rx.try_recv() {
            if matches!(o, FetchOutcome::Done { .. }) {
                done += 1;
            }
        }
        assert_eq!(done, n);
    }

    #[tokio::test]
    async fn mute_greeting_straggler_does_not_hold_a_finished_run() {
        // §35: a server that accepts and never greets parks its worker
        // inside the dial. This used to cost the run a full EXIT_GRACE -
        // join_fleet's backstop was the ONLY thing that ended it, because
        // the dial itself never watched the run. Measured on the farm at
        // 5.0 s added to a 1.1 s job, on every job, for as long as the
        // unreachable entry stayed in the config. The dial now races the
        // finish, so the straggler leaves with everyone else and the
        // grace window is never entered.
        use crate::mock::{Chaos, MockServer, make_file_articles};
        let mut articles = std::collections::HashMap::new();
        let payload: Vec<u8> = (0..40_000u32).map(|i| (i * 7) as u8).collect();
        make_file_articles("g.bin", &payload, 8_000, "mg", &mut articles);
        let n = articles.len();
        let healthy = MockServer::start(articles.clone(), Chaos::default()).await;
        let mute = MockServer::start(
            std::collections::HashMap::new(),
            Chaos { mute_greeting: true, ..Default::default() },
        )
        .await;
        let fast = PoolConfig {
            connections: 2,
            ramp_delay: Duration::ZERO,
            ..Default::default()
        };
        let one = PoolConfig {
            connections: 1,
            ramp_delay: Duration::ZERO,
            ..Default::default()
        };
        let reqs: Vec<ArticleReq> =
            articles.keys().map(|id| ArticleReq::fresh(id.clone())).collect();
        let (tx, mut rx) = mpsc::channel(64);
        let t0 = Instant::now();
        tokio::time::timeout(
            Duration::from_secs(30),
            fetch_all_multi(
                &[(healthy.server_config(), fast), (mute.server_config(), one)],
                reqs,
                tx,
            ),
        )
        .await
        .expect("run hung on a never-greeting server");
        let el = t0.elapsed();
        // Comfortably inside the grace window, not at the end of it: the
        // straggler is released by the finish, not abandoned by the join.
        assert!(
            el < EXIT_GRACE,
            "run waited out the dial of a server nobody needed: {el:?}"
        );
        let mut done = 0;
        while let Ok(o) = rx.try_recv() {
            if matches!(o, FetchOutcome::Done { .. }) {
                done += 1;
            }
        }
        assert_eq!(done, n);
    }

    /// §35, reached through the WARM path instead of the dial.
    ///
    /// Claiming a parked connection validates it with a DATE round-trip
    /// bounded by `warmpool::VALIDATE_TIMEOUT` - 8 s, against EXIT_GRACE's
    /// 5 s. A worker validating a peer that has gone mute therefore could
    /// not return before `join_fleet` gave up on it, so the run paid the
    /// whole grace window exactly as an unanswered SYN used to make it.
    /// Latent while the warm pool ships off by default, which is the
    /// reason to pin it now: TODO 36 turns it on per server.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_mute_parked_connection_does_not_hold_a_finished_run() {
        use crate::mock::{Chaos, MockServer, make_file_articles};
        // Greets, then never another word, every socket held open with no
        // RST or FIN - the shape a CGNAT idle eviction leaves behind, and
        // the one DATE validation exists to catch. Blocking std sockets on
        // their own thread so the peer keeps working regardless of what
        // the async runtime is doing.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            use std::io::Write as _;
            let mut held = Vec::new();
            while let Ok((mut s, _)) = listener.accept() {
                let _ = s.write_all(b"200 mock ready\r\n");
                let _ = s.flush();
                held.push(s);
            }
        });
        let mute = ServerConfig {
            host: addr.ip().to_string(),
            port: addr.port(),
            tls: false,
            username: None,
            password: None,
            connections: 1,
            rcvbuf: None,
            level: 0,
            group: None,
            retention_days: 0,
            block_bytes: None,
            bind_ip: None,
            socks5: None,
            enabled: true,
            warm_pool: false,
        };

        let mut articles = std::collections::HashMap::new();
        let payload: Vec<u8> = (0..40_000u32).map(|i| (i * 3) as u8).collect();
        make_file_articles("w.bin", &payload, 8_000, "wp", &mut articles);
        let n = articles.len();
        let healthy = MockServer::start(articles.clone(), Chaos::default()).await;

        // Park a live connection to the mute peer, exactly as the previous
        // job in a queue would have left one.
        let warm = crate::warmpool::WarmPool::new(crate::warmpool::DEFAULT_MAX_IDLE, 4);
        let (c, _) = Connection::connect(&mute).await.expect("greeting");
        warm.give(&mute, c).await;
        assert_eq!(warm.idle_count().await, 1, "the claim must have something to claim");

        let fast = PoolConfig {
            connections: 2,
            ramp_delay: Duration::ZERO,
            ..Default::default()
        };
        let warmed = PoolConfig {
            connections: 1,
            ramp_delay: Duration::ZERO,
            warm: Some(warm.clone()),
            ..Default::default()
        };
        let reqs: Vec<ArticleReq> =
            articles.keys().map(|id| ArticleReq::fresh(id.clone())).collect();
        let (tx, mut rx) = mpsc::channel(64);
        let t0 = Instant::now();
        tokio::time::timeout(
            Duration::from_secs(30),
            fetch_all_multi(&[(healthy.server_config(), fast), (mute, warmed)], reqs, tx),
        )
        .await
        .expect("run hung claiming a parked connection from a mute peer");
        let el = t0.elapsed();
        assert!(
            el < EXIT_GRACE,
            "run waited out the validation of a connection nobody needed: {el:?}"
        );
        let mut done = 0;
        while let Ok(o) = rx.try_recv() {
            if matches!(o, FetchOutcome::Done { .. }) {
                done += 1;
            }
        }
        assert_eq!(done, n, "the healthy server still had to deliver every article");
    }

    #[test]
    fn session_backoff_grows_then_caps() {
        let cfg = PoolConfig {
            connect_backoff: Duration::from_millis(100),
            ..Default::default()
        };
        assert_eq!(session_backoff_delay(&cfg, 1), Duration::from_millis(100));
        assert_eq!(session_backoff_delay(&cfg, 2), Duration::from_millis(200));
        assert_eq!(session_backoff_delay(&cfg, 4), Duration::from_millis(800));
        assert_eq!(session_backoff_delay(&cfg, 9), Duration::from_millis(25_600));
        assert_eq!(session_backoff_delay(&cfg, 10), SESSION_BACKOFF_MAX);
        // No overflow, no runaway, however deep the failure count goes.
        assert_eq!(session_backoff_delay(&cfg, u32::MAX), SESSION_BACKOFF_MAX);
        // A configured base of ~0 must not defeat the pacing.
        let zero = PoolConfig {
            connect_backoff: Duration::ZERO,
            ..Default::default()
        };
        assert!(session_backoff_delay(&zero, 1) >= Duration::from_millis(50));
    }

    /// Regression: a broken account must not be reconnect-stormed.
    ///
    /// The shape is a provider that accepts TCP and AUTHINFO every time
    /// and then answers every BODY with a non-BODY status. Before the
    /// session backoff, the `Ok(Err(_))` path did `requeue_or_fail` and
    /// `continue 'session` with ZERO delay, and `connect_failures` was
    /// reset by the successful connect, so the connect backoff never
    /// applied: connect → AUTH → BODY → error → reconnect, several times
    /// a second per worker, for as long as the queue had retries left.
    /// On a big single-server job that is ~a million connect+AUTH
    /// attempts at full rate - what providers ban accounts for.
    ///
    /// So this asserts on the RATE, not on eventual give-up: how many
    /// connections the server accepted inside a fixed window.
    #[tokio::test]
    async fn broken_session_server_is_paced_not_stormed() {
        use crate::mock::{Chaos, MockServer, make_file_articles};
        let mut articles = HashMap::new();
        let payload: Vec<u8> = (0..200_000u32).map(|i| (i * 5) as u8).collect();
        make_file_articles("storm.bin", &payload, 4_000, "st", &mut articles);
        let srv = MockServer::start(
            articles.clone(),
            Chaos { body_error: Some(u64::MAX), ..Default::default() },
        )
        .await;
        const WORKERS: usize = 4;
        let cfg = PoolConfig {
            connections: WORKERS,
            window: 1,
            ramp_delay: Duration::ZERO,
            connect_backoff: Duration::from_millis(100),
            // Deep enough that the queue cannot drain inside the window -
            // the test must measure the storm, not the bow-out.
            article_retries: 200,
            ..Default::default()
        };
        let reqs: Vec<ArticleReq> =
            articles.keys().map(|id| ArticleReq::fresh(id.clone())).collect();
        let (tx, _rx) = mpsc::channel(1024);
        let window = Duration::from_secs(1);
        let t0 = Instant::now();
        // Cancel at the window: the run is deliberately unfinishable.
        let _ = tokio::time::timeout(
            window,
            fetch_all_multi(&[(srv.server_config(), cfg)], reqs, tx),
        )
        .await;
        let accepted = srv.accepted.load(Ordering::Relaxed);
        assert!(
            accepted >= WORKERS as u64,
            "every worker should have tried at least once, got {accepted}"
        );
        // Paced: 100/200/400/800 ms per worker is at most 4 connects each
        // inside a 1 s window. The generous ceiling still sits two orders
        // of magnitude below the unpaced loop (thousands over loopback).
        assert!(
            accepted <= 10 * WORKERS as u64,
            "connect storm: {accepted} connections in {:?}",
            t0.elapsed()
        );
    }

    /// One worker pacing itself must not pace the pool: the backoff is a
    /// per-worker sleep taken with nothing held (the queue was released by
    /// `requeue_or_fail` first), so a healthy backbone keeps running at
    /// full speed alongside a broken one.
    #[tokio::test]
    async fn a_backing_off_server_does_not_slow_the_healthy_one() {
        use crate::mock::{Chaos, MockServer, make_file_articles};
        let mut articles = HashMap::new();
        let payload: Vec<u8> = (0..80_000u32).map(|i| (i * 11) as u8).collect();
        make_file_articles("mix.bin", &payload, 8_000, "mx", &mut articles);
        let n = articles.len();
        let healthy = MockServer::start(articles.clone(), Chaos::default()).await;
        let broken = MockServer::start(
            articles.clone(),
            Chaos { body_error: Some(u64::MAX), ..Default::default() },
        )
        .await;
        let mk = |conns| PoolConfig {
            connections: conns,
            ramp_delay: Duration::ZERO,
            connect_backoff: Duration::from_millis(100),
            article_retries: 10,
            ..Default::default()
        };
        let reqs: Vec<ArticleReq> =
            articles.keys().map(|id| ArticleReq::fresh(id.clone())).collect();
        let (tx, mut rx) = mpsc::channel(256);
        tokio::time::timeout(
            Duration::from_secs(30),
            fetch_all_multi(
                &[
                    (healthy.server_config(), mk(2)),
                    (broken.server_config(), mk(2)),
                ],
                reqs,
                tx,
            ),
        )
        .await
        .expect("run hung with one session-broken server");
        let mut done = 0;
        while let Ok(o) = rx.try_recv() {
            if matches!(o, FetchOutcome::Done { .. }) {
                done += 1;
            }
        }
        assert_eq!(done, n, "the healthy server had to deliver every article");
    }

    /// An account that starts working again must be picked straight back
    /// up: the backoff counter is cleared by a session that did useful
    /// work, so no long delay stays armed behind a recovery.
    #[tokio::test]
    async fn session_backoff_clears_once_the_server_works_again() {
        use crate::mock::{Chaos, MockServer, make_file_articles};
        let mut articles = HashMap::new();
        let payload: Vec<u8> = (0..80_000u32).map(|i| (i * 13) as u8).collect();
        make_file_articles("rec.bin", &payload, 8_000, "rc", &mut articles);
        let n = articles.len();
        // The first three BODYs fail; after that the server is healthy.
        let srv = MockServer::start(
            articles.clone(),
            Chaos { body_error: Some(3), ..Default::default() },
        )
        .await;
        let cfg = PoolConfig {
            connections: 1,
            window: 1,
            ramp_delay: Duration::ZERO,
            connect_backoff: Duration::from_millis(100),
            article_retries: 10,
            ..Default::default()
        };
        let reqs: Vec<ArticleReq> =
            articles.keys().map(|id| ArticleReq::fresh(id.clone())).collect();
        let (tx, mut rx) = mpsc::channel(256);
        let t0 = Instant::now();
        tokio::time::timeout(
            Duration::from_secs(30),
            fetch_all_multi(&[(srv.server_config(), cfg)], reqs, tx),
        )
        .await
        .expect("run hung on a server that recovered");
        let el = t0.elapsed();
        let mut done = 0;
        while let Ok(o) = rx.try_recv() {
            if matches!(o, FetchOutcome::Done { .. }) {
                done += 1;
            }
        }
        assert_eq!(done, n, "every article must land once the server recovers");
        // 100 + 200 + 400 ms of pacing, and nothing left armed after the
        // first good body - not the 800 ms+ steps a counter that kept
        // climbing would have charged the rest of the run.
        assert!(el < Duration::from_secs(3), "recovery was delayed: {el:?}");
    }

    /// Step a paused clock in 1 ms slices for as long as the returned
    /// guard lives.
    ///
    /// A paused clock auto-advances to the NEAREST armed deadline whenever
    /// the runtime idles - including while it is idling on real socket
    /// I/O. With only the pool's own timers armed, that nearest deadline
    /// can be a connect or read timeout the loopback exchange was about to
    /// satisfy, and the test measures spurious timeouts instead of the
    /// behaviour under test (measured: one connection accepted, zero
    /// BODYs, every worker gone on connect exhaustion). A metronome caps
    /// each jump at a millisecond, so every I/O wait is re-polled ~1 ms of
    /// virtual time at a time while the long backoffs still cost nothing.
    struct Metronome(tokio::task::JoinHandle<()>);

    impl Metronome {
        fn start() -> Metronome {
            Metronome(tokio::spawn(async {
                loop {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
            }))
        }
    }

    impl Drop for Metronome {
        fn drop(&mut self) {
            self.0.abort();
        }
    }

    /// Regression: the session pacing had no give-up ceiling.
    ///
    /// A server that accepts every connection and answers every BODY with
    /// a non-BODY status - a broken or exhausted account - was retried at
    /// the 30 s cap for as long as the queue had retries left, and the
    /// queue's retries are per article: on a large single-server job that
    /// is hours of paced reconnects that can never produce a byte. The
    /// worker now bows out at `MAX_SESSION_ATTEMPTS` the way a
    /// connect-exhausted one does, and the run seals a truthful Failed.
    ///
    /// Paused clock, so this asserts on the CEILING and not on how fast
    /// the box is: the whole ladder of backoffs is spent in virtual time,
    /// and the run must be over inside the bound the ceiling implies.
    /// `article_retries` is absurd on purpose - the run has to end because
    /// the workers bowed out, not because the articles ran out of tries.
    #[tokio::test(start_paused = true)]
    async fn a_server_that_never_serves_a_body_bows_out_within_the_ceiling() {
        let _tick = Metronome::start();
        use crate::mock::{Chaos, MockServer, make_file_articles};
        let mut articles = HashMap::new();
        let payload: Vec<u8> = (0..60_000u32).map(|i| (i * 17) as u8).collect();
        make_file_articles("ceil.bin", &payload, 6_000, "cl", &mut articles);
        let srv = MockServer::start(
            articles.clone(),
            Chaos { body_error: Some(u64::MAX), ..Default::default() },
        )
        .await;
        const WORKERS: usize = 3;
        let cfg = PoolConfig {
            connections: WORKERS,
            window: 1,
            ramp_delay: Duration::ZERO,
            // Production pacing, not a test-shrunk one: the ceiling has to
            // hold at the 30 s cap, which is where the hours came from.
            connect_backoff: Duration::from_secs(2),
            article_retries: 250,
            ..Default::default()
        };
        let ids: Vec<String> = articles.keys().cloned().collect();
        let reqs: Vec<ArticleReq> = ids.iter().cloned().map(ArticleReq::fresh).collect();
        let (tx, mut rx) = mpsc::channel(256);
        // The ceiling's own arithmetic: the sleeps armed by failures
        // 1..MAX (2, 4, 8, 16 s, then the 30 s cap), after which the last
        // useless session returns without sleeping again. Plus the fleet's
        // exit grace and a little slack for the sessions themselves.
        let ladder: Duration = (1..MAX_SESSION_ATTEMPTS)
            .map(|f| session_backoff_delay(&cfg, f))
            .sum();
        let bound = ladder + EXIT_GRACE + Duration::from_secs(30);
        let t0 = tokio::time::Instant::now();
        tokio::time::timeout(
            bound,
            fetch_all_multi(&[(srv.server_config(), cfg)], reqs, tx),
        )
        .await
        .unwrap_or_else(|_| {
            panic!("no give-up ceiling: still retrying a never-serving server after {bound:?}")
        });
        let el = t0.elapsed();
        assert!(el <= bound, "over the ceiling's bound: {el:?} > {bound:?}");
        // Terminal for every article - the seal, not a silent stall.
        let seen = tally(&mut rx);
        assert_exactly_one_outcome_each(&ids, &seen);
        // And the ceiling is per worker: each one gets at most
        // MAX_SESSION_ATTEMPTS sessions out of this server, ever.
        let accepted = srv.accepted.load(Ordering::Relaxed);
        assert!(
            accepted <= WORKERS as u64 * MAX_SESSION_ATTEMPTS as u64,
            "{accepted} connections for {WORKERS} workers is past the ceiling"
        );
        // The failures under test have to be SESSION failures: every
        // worker must have got a session and asked it for a body. Without
        // this the test passes on a run that never got past connect (which
        // is exactly how it fails on a paused clock with no metronome).
        let bodies = srv.body_log.lock().unwrap().len();
        assert!(
            accepted >= WORKERS as u64 && bodies >= WORKERS,
            "not the shape under test: {accepted} sessions, {bodies} BODYs"
        );
    }

    /// The other side of that ceiling: it must not fire on a server that
    /// comes back. This one fails one BODY short of `MAX_SESSION_ATTEMPTS`
    /// and then serves normally - the counter is cleared by the first
    /// well-formed response, so the job completes instead of bowing out.
    #[tokio::test(start_paused = true)]
    async fn a_server_recovering_just_under_the_ceiling_still_completes() {
        let _tick = Metronome::start();
        use crate::mock::{Chaos, MockServer, make_file_articles};
        let mut articles = HashMap::new();
        let payload: Vec<u8> = (0..60_000u32).map(|i| (i * 19) as u8).collect();
        make_file_articles("near.bin", &payload, 6_000, "nr", &mut articles);
        let n = articles.len();
        let srv = MockServer::start(
            articles.clone(),
            Chaos {
                body_error: Some(MAX_SESSION_ATTEMPTS as u64 - 1),
                ..Default::default()
            },
        )
        .await;
        // One connection, one BODY in flight: every failure is exactly one
        // session failure, so the counter reaches MAX - 1 and stops there.
        let cfg = PoolConfig {
            connections: 1,
            window: 1,
            ramp_delay: Duration::ZERO,
            connect_backoff: Duration::from_secs(2),
            // The retry ladder must not be what ends this run either: the
            // first article eats every one of those failed sessions.
            article_retries: 250,
            ..Default::default()
        };
        let ids: Vec<String> = articles.keys().cloned().collect();
        let reqs: Vec<ArticleReq> = ids.iter().cloned().map(ArticleReq::fresh).collect();
        let (tx, mut rx) = mpsc::channel(256);
        tokio::time::timeout(
            Duration::from_secs(600),
            fetch_all_multi(&[(srv.server_config(), cfg)], reqs, tx),
        )
        .await
        .expect("a recovering server must not be given up on");
        let mut done = 0;
        while let Ok(o) = rx.try_recv() {
            if matches!(o, FetchOutcome::Done { .. }) {
                done += 1;
            }
        }
        assert_eq!(
            done, n,
            "every article must land: the server recovered before the ceiling"
        );
    }
}

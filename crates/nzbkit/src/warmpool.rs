//! Connections that outlive a job.
//!
//! Every job used to build a fresh fleet and QUIT every socket at the end,
//! so each job paid, per connection: a TCP handshake, a TLS handshake, two
//! sequential AUTHINFO round-trips, and then the first BODY - about five
//! round-trips, ~400 ms on a transatlantic path. On top of that came the
//! spawn ramp (150 ms x connection index, so the 30th connection started
//! 4.35 s late) and, worst of all, TCP slow start on every flow.
//!
//! Slow start is the expensive one and the reason this is not just a
//! latency micro-optimisation. A fresh flow begins at an initial window of
//! ~10 packets and needs several RTTs to climb to the path's rate; a
//! connection that has already been carrying data is sitting in congestion
//! avoidance with a grown window and resumes at full speed instantly. For
//! a 300 MB episode - a few seconds of transfer - the ramp WAS most of the
//! download.
//!
//! Design notes:
//!
//! - **Only fully-drained connections are parked.** A connection is
//!   reusable exactly when it has no unread pipelined responses on the
//!   socket. The pool parks from its two drained exits and nowhere else;
//!   every other exit (abort, pipeline shed, promote shed, protocol error,
//!   read stall) deliberately abandons in-flight responses and MUST close.
//!
//! - **Validated on the way out, not on the way in.** `take` sends a DATE
//!   and requires the response before handing the connection over, so a
//!   caller can treat a checkout exactly like a fresh connect and every
//!   existing error path keeps its meaning. That costs one round-trip
//!   instead of five, and - the point - it keeps the congestion window.
//!   A provider that reaped the socket, an idle-timeout, a NAT eviction
//!   and a redeploy all surface here as "cache miss, connect fresh".
//!
//! - **Idle connections are given back.** A parked connection holds a slot
//!   against the account's connection limit, which the user's other
//!   clients also draw on, so they are evicted after `max_idle`. The
//!   keepalive tick doubles as the reaper.
//!
//! - **An idle POOL is released, not just an idle connection.** `max_idle`
//!   ages out each session from its own park time; the release policy
//!   below acts on the pool as a whole once no job has touched it for a
//!   while, and trims every server down to a floor. The distinction
//!   matters to a provider that caps CONCURRENT DISTINCT SOURCE IPS per
//!   account rather than connections - see
//!   [`WarmPool::set_release_policies`].

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

use crate::config::ServerConfig;
use crate::nntp::Connection;

/// How often the keepalive tick runs. Providers commonly drop an idle
/// NNTP session somewhere between two and ten minutes, and RFC 3977 lets
/// a server close whenever it likes, so this stays well inside the
/// shortest timeout we have seen.
const KEEPALIVE_EVERY: Duration = Duration::from_secs(60);

/// A parked connection older than this is closed rather than kept alive:
/// it is occupying one of the account's connection slots that the user's
/// other clients (and their *arr stack) also draw on.
///
/// This is the ABSOLUTE ceiling on how long any session is held, and the
/// idle-release policy below only ever shortens it. Nothing the operator
/// can configure makes the pool hold a connection for longer than this,
/// so no setting here can create an indefinite hold.
pub const DEFAULT_MAX_IDLE: Duration = Duration::from_secs(600);

/// Release the pool down to its floor after this long with no job
/// touching it.
///
/// Chosen against the re-warm cost, which is what the pool exists to
/// avoid: a cold fleet costs 4.5-14.3x on job start, so a timeout of
/// tens of seconds would spend that repeatedly and defeat the feature,
/// while jobs arriving minutes apart are already a cold start from the
/// user's point of view. Five minutes covers the case the pool actually
/// pays for - a queue of NZBs draining back to back, an *arr grabbing a
/// season - and gives the account back on any longer gap.
pub const DEFAULT_IDLE_RELEASE: Duration = Duration::from_secs(300);

/// The same timeout when the operator has configured a provider known to
/// cap concurrent distinct SOURCE IPS - see
/// [`crate::config::caps_source_ips`]. Shorter because the cost of
/// holding is qualitatively different there: it is not a slice of a
/// generous connection allowance, it is one of two or three IP slots for
/// the whole account, so the user's other machines are locked out
/// entirely rather than merely slowed.
pub const CAPPED_IDLE_RELEASE: Duration = Duration::from_secs(120);

/// Most connections the daemon parks per server.
///
/// Deliberately generous rather than tied to the configured
/// `connections`: the fleet that parks them was already sized by the
/// account limit so it cannot overshoot, while a cap read from a config
/// that has since SHRUNK would evict live connections mid-run.
///
/// Public because it is also the ceiling on a meaningful idle-release
/// FLOOR - keeping more than the pool will ever park is the same as
/// keeping everything, and a setting that silently means nothing is
/// worse than one that is clamped.
pub const MAX_PER_SERVER: usize = 64;

/// Bound on the DATE that validates a parked connection, instead of the
/// protocol-wide 60 s command timeout it used to inherit.
///
/// A parked flow is precisely what a NAT/CGNAT idle eviction or a
/// firewall restart black-holes without an RST or a FIN: the write still
/// succeeds locally and the answer never comes. At the command timeout
/// that cost a full minute per corpse, serially, in both the checkout and
/// the keepalive - a pool of 64 could stall a checkout for an hour while
/// the tick, due again every minute, never caught up with itself.
///
/// Nothing is lost by giving up early here: the fallback is a fresh
/// connect, which is what a dead session needs anyway. But it must stay
/// well clear of a merely slow provider, which is why this is seconds and
/// not the 40-160 ms a warm validate actually measures.
const VALIDATE_TIMEOUT: Duration = Duration::from_secs(8);

struct Parked {
    conn: Connection,
    /// Invalidation generation at park time. A keepalive or checkout that
    /// crosses `clear`/`retain_servers` may finish its DATE afterwards, but
    /// must not resurrect or return the superseded session.
    generation: u64,
    /// When this connection last completed a command successfully - the
    /// park itself counts, since the pool only parks drained sessions.
    fresh_at: Instant,
    /// When it entered the cache, for `max_idle` eviction.
    parked_at: Instant,
}

/// Close a whole set of parked sessions at once.
///
/// A fleet-wide goodbye is the same shape as the keepalive's fleet-wide
/// ping, and needs the same treatment for the same reason. `quit` is
/// bounded at 500 ms, so a black-holed path costs that per session and
/// SERIALLY it multiplies: measured 8.0 s for 16 sessions on a mute peer,
/// linear in the count. Production parks 64 PER SERVER, so one server
/// costs 32 s and a six-server config over three minutes - more than
/// three times the interval `tick` is due again in, so the reaper could
/// never catch up with itself, which is the exact stall the batched ping
/// exists to stop. `retain_servers` is worse: the daemon awaits it on the
/// way into EVERY job, so a credential change could stall the next
/// download's first byte by half a minute.
///
/// Concurrently the whole batch costs one bound. Nothing here is ordered
/// and nothing reads a result - these sessions are already out of the map
/// and their only remaining job is to say goodbye.
async fn quit_all(parked: Vec<Parked>) {
    let mut set = tokio::task::JoinSet::new();
    for p in parked {
        set.spawn(async move { p.conn.quit().await });
    }
    while set.join_next().await.is_some() {}
}

#[derive(Default)]
pub struct WarmStats {
    pub hits: AtomicU64,
    pub misses: AtomicU64,
    pub parked: AtomicU64,
    pub evicted: AtomicU64,
    pub reaped: AtomicU64,
    /// Closed by the idle-release policy, as opposed to aged out one by
    /// one by `max_idle` (`evicted`). Separated because they answer
    /// different questions: `evicted` says sessions are outliving their
    /// usefulness, `released` says the account was handed back.
    pub released: AtomicU64,
}

pub struct WarmPool {
    idle: Mutex<HashMap<String, Vec<Parked>>>,
    generation: AtomicU64,
    max_idle: Duration,
    /// Most connections parked per server. Never exceeds the account's
    /// own limit, because the fleet that parks them was already sized by
    /// it, but capped explicitly so a config that shrinks `connections`
    /// cannot leave a bigger old fleet parked.
    per_server: usize,
    /// Per-server idle-release policy, keyed exactly as `idle` is.
    ///
    /// Keyed rather than global because a server is an ACCOUNT: each
    /// provider counts its own limit against its own account, and two
    /// servers share nothing. A single policy would either shorten a lax
    /// provider's timeout for no benefit or leave a strict one's lockout
    /// in place.
    ///
    /// Empty until the daemon installs one, so a pool built by a caller
    /// that knows nothing about the setting (the CLI, a test) releases
    /// nothing and behaves exactly as it did before.
    ///
    /// A std mutex, not the async one guarding `idle`: this is only ever
    /// swapped wholesale or cloned, never held across an await, and it
    /// has to be settable from the sync config paths (a server saved
    /// from the dashboard runs on a blocking handler thread). Making it
    /// async would have forced those to spawn a task just to store two
    /// numbers.
    release: std::sync::Mutex<HashMap<String, crate::config::ReleasePolicy>>,
    /// Last time a job touched the pool, in either direction. A checkout
    /// and a park are both "a job is using this account", and idleness
    /// has to mean neither has happened - measuring only checkouts would
    /// call a pool idle in the middle of the job that just filled it.
    ///
    /// A std mutex on an `Instant`: never held across an await, and the
    /// tick reads it before taking the map lock.
    last_activity: std::sync::Mutex<Instant>,
    pub stats: WarmStats,
}

/// Identity of a reusable session. Credentials are part of it: a
/// connection authenticated as the old user must never be handed out
/// after the config changes. Hashed rather than stored so the password
/// never sits in a map key that might reach a log or a debug dump.
fn key(s: &ServerConfig) -> String {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    s.username.hash(&mut h);
    s.password.hash(&mut h);
    s.socks5.hash(&mut h);
    s.bind_ip.hash(&mut h);
    format!("{}:{}:{}:{:016x}", s.host, s.port, s.tls, h.finish())
}

impl WarmPool {
    /// Build a pool and spawn its keepalive/reaper tick. Hold the `Arc`
    /// for as long as connections should stay warm - the tick stops when
    /// the last strong reference goes.
    pub fn new(max_idle: Duration, per_server: usize) -> Arc<WarmPool> {
        let pool = Arc::new(WarmPool {
            idle: Mutex::new(HashMap::new()),
            generation: AtomicU64::new(0),
            max_idle,
            per_server,
            release: std::sync::Mutex::new(HashMap::new()),
            last_activity: std::sync::Mutex::new(Instant::now()),
            stats: WarmStats::default(),
        });
        let weak = Arc::downgrade(&pool);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(KEEPALIVE_EVERY).await;
                let Some(p) = weak.upgrade() else { return };
                p.tick().await;
            }
        });
        pool
    }

    /// Install each server's idle-release policy, replacing whatever was
    /// installed before.
    ///
    /// `policy.after` is how long the pool must go untouched before it
    /// trims that server; `None` disables releasing for it, which is the
    /// right answer for a NAS or seedbox that is the account's only
    /// consumer - there is nobody to hand the slots back TO, and holding
    /// them costs that install nothing.
    ///
    /// `policy.keep` is the floor the trim releases DOWN TO, not to
    /// zero, so a job arriving after the timeout still starts on a warm
    /// session while the rest of that server's slots are free.
    ///
    /// One caveat decides that floor, and it is the whole reason this
    /// exists: a provider that caps concurrent distinct SOURCE IPS
    /// (UsenetExpress at 2, Giganews and Newshosting at 1) counts the
    /// HOST, not the socket. Against those, keeping one connection
    /// occupies exactly as much of the cap as keeping sixty, so a floor
    /// of 1 frees nothing at all and the floor must be 0. A floor above
    /// zero is only meaningful where the limit being shared is a
    /// connection COUNT.
    ///
    /// Note the interaction with `max_idle`, which still applies to
    /// whatever survives: the floor is kept for the rest of that
    /// session's `max_idle`, not forever. So this can only ever shorten
    /// how long the account is occupied - there is no setting here that
    /// makes the pool hold a connection indefinitely.
    ///
    /// A server absent from `servers` keeps no policy and is never
    /// released by this path. That is deliberate rather than an
    /// oversight: a server the config no longer lists is
    /// `retain_servers`' business, which closes it outright instead of
    /// trimming it to a floor.
    pub fn set_release_policies(&self, servers: &[ServerConfig]) {
        let next: HashMap<String, crate::config::ReleasePolicy> =
            servers.iter().map(|s| (key(s), s.idle_release_policy())).collect();
        *self.release.lock().unwrap() = next;
    }

    /// One server's installed policy, for the dashboard and for tests.
    pub fn release_policy(&self, server: &ServerConfig) -> Option<crate::config::ReleasePolicy> {
        self.release.lock().unwrap().get(&key(server)).copied()
    }

    fn touch(&self) {
        *self.last_activity.lock().unwrap() = Instant::now();
    }

    /// A live, validated session for `server`, or None to connect fresh.
    ///
    /// The DATE round-trip is the contract: callers get a connection that
    /// has just answered a command, so a checkout is interchangeable with
    /// a connect and no existing error path has to learn about staleness.
    pub async fn take(&self, server: &ServerConfig) -> Option<Connection> {
        // Before the early `?` returns: a checkout that MISSES is still a
        // job reaching for this account, and the release policy must not
        // treat a pool that is being hammered with misses as idle.
        self.touch();
        let k = key(server);
        loop {
            let mut candidate = {
                let mut idle = self.idle.lock().await;
                let v = idle.get_mut(&k)?;
                // Newest first: the most recently parked connection has
                // the warmest congestion window and the longest time left
                // before any provider idle timeout.
                v.pop()?
            };
            // A candidate that runs out of VALIDATE_TIMEOUT is abandoned
            // with its DATE unanswered on the socket, so it can only be
            // dropped here - never returned, never put back in the map.
            match tokio::time::timeout(VALIDATE_TIMEOUT, candidate.conn.date()).await {
                Ok(Ok(_)) if candidate.generation == self.generation.load(Ordering::Acquire) => {
                    self.stats.hits.fetch_add(1, Ordering::Relaxed);
                    return Some(candidate.conn);
                }
                Err(_) => {
                    // A TIMEOUT is different in kind from a refusal, and
                    // the difference is what bounds this loop. An answer -
                    // even an error - costs a round-trip; silence costs
                    // the whole deadline, and silence is a property of the
                    // PATH, so the rest of this server's parked set is
                    // behind the same black hole. Trying them one by one
                    // would multiply the deadline by `per_server`, which
                    // production builds as 64: eight seconds becomes eight
                    // minutes, and the caller is waiting on a fresh
                    // connect it could have made immediately.
                    //
                    // So the first timeout condemns the whole entry. The
                    // cost of being wrong is a few warm sessions dropped
                    // on a genuine provider stall; the cost of being right
                    // and not acting is the stall this constant exists to
                    // stop.
                    let dead = {
                        let mut idle = self.idle.lock().await;
                        idle.remove(&k).unwrap_or_default()
                    };
                    self.stats.reaped.fetch_add(dead.len() as u64 + 1, Ordering::Relaxed);
                    return None;
                }
                _ => {
                    // Answered, but not usably: a reaped socket, or a
                    // session the config change superseded. That cost one
                    // round-trip, so try the next one - a provider that
                    // reaped one probably reaped several.
                    self.stats.reaped.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }

    /// Park a connection that has NO unread responses on its socket.
    /// Anything else must be closed instead - see the module docs.
    pub async fn give(&self, server: &ServerConfig, conn: Connection) {
        self.touch();
        if self.per_server == 0 {
            conn.quit().await;
            return;
        }
        let k = key(server);
        let mut idle = self.idle.lock().await;
        let v = idle.entry(k).or_default();
        if v.len() >= self.per_server {
            drop(idle);
            self.stats.evicted.fetch_add(1, Ordering::Relaxed);
            conn.quit().await;
            return;
        }
        let now = Instant::now();
        let generation = self.generation.load(Ordering::Acquire);
        v.push(Parked { conn, generation, fresh_at: now, parked_at: now });
        self.stats.parked.fetch_add(1, Ordering::Relaxed);
    }

    /// Count a checkout that had to connect instead.
    pub fn miss(&self) {
        self.stats.misses.fetch_add(1, Ordering::Relaxed);
    }

    /// Close everything. Call on a config change: a parked connection
    /// authenticated with superseded credentials, or bound to a since
    /// removed source address, must not survive it.
    pub async fn clear(&self) {
        let drained: Vec<Parked> = {
            let mut idle = self.idle.lock().await;
            self.generation.fetch_add(1, Ordering::AcqRel);
            idle.drain().flat_map(|(_, v)| v).collect()
        };
        quit_all(drained).await;
    }

    /// Keep only sessions whose complete server identity still exists in
    /// the freshly loaded config. The daemon reloads config per job; without
    /// this reconciliation, old-password/bind/proxy sessions occupied the
    /// provider's connection cap for up to ten minutes even though their map
    /// key correctly prevented reuse.
    pub async fn retain_servers(&self, servers: &[ServerConfig]) {
        let keep: std::collections::HashSet<String> = servers.iter().map(key).collect();
        let drained: Vec<Parked> = {
            let mut idle = self.idle.lock().await;
            // Also invalidates DATE calls currently outside the map. It is
            // safe to drop a valid ping crossing a job boundary; it is not
            // safe to let a removed identity reappear after this returns.
            let generation = self.generation.fetch_add(1, Ordering::AcqRel) + 1;
            let stale: Vec<String> =
                idle.keys().filter(|k| !keep.contains(*k)).cloned().collect();
            let drained = stale
                .into_iter()
                .filter_map(|k| idle.remove(&k))
                .flatten()
                .collect();
            // Retained sessions crossed the same invalidation boundary while
            // protected by the map lock, so advance their ticket. A checkout
            // or keepalive already outside the map keeps the old generation
            // and is deliberately reaped instead of racing the config reload.
            for parked in idle.values_mut().flatten() {
                parked.generation = generation;
            }
            drained
        };
        quit_all(drained).await;
    }

    /// Number of parked connections, for the dashboard.
    pub async fn idle_count(&self) -> usize {
        self.idle.lock().await.values().map(|v| v.len()).sum()
    }

    /// How long since a job last used the pool.
    pub fn idle_for(&self) -> Duration {
        self.last_activity.lock().unwrap().elapsed()
    }

    /// Trim each server down to ITS OWN floor once the pool has gone
    /// untouched for that server's release timeout, handing those
    /// connection slots (and, for an address-capped provider, the
    /// account itself) back to the operator's other machines.
    ///
    /// Per server throughout: a server is an account, and one provider's
    /// limit says nothing about another's. A mixed config - a flatrate
    /// primary that does not care, plus a block account at a provider
    /// allowing two addresses - correctly releases the second on its own
    /// short timeout while the first keeps its fleet warm.
    ///
    /// Runs BEFORE the keepalive pings in `tick`, so a session about to
    /// be released does not first spend a round-trip being kept alive.
    ///
    /// Granularity is one keepalive interval, since this is the tick's
    /// passenger: a 300 s timeout releases somewhere in 300-360 s. That
    /// is well inside the tolerance of a setting whose whole purpose is
    /// "a few minutes", and it costs no second timer.
    async fn release_if_idle(&self) {
        let idle_for = self.idle_for();
        let policies = self.release.lock().unwrap().clone();
        if policies.is_empty() {
            return;
        }
        let surplus: Vec<Parked> = {
            let mut idle = self.idle.lock().await;
            let mut out = Vec::new();
            for (k, v) in idle.iter_mut() {
                // No policy for this key = not a server the daemon last
                // installed one for; leave it to `retain_servers`.
                let Some(p) = policies.get(k) else { continue };
                let Some(after) = p.after else { continue };
                if idle_for < after {
                    continue;
                }
                let keep = p.keep;
                if v.len() > keep {
                    // Oldest first. `take` pops from the END, so the tail
                    // holds the most recently parked - the warmest
                    // congestion window and the longest left before the
                    // provider's own idle timeout. Releasing from the
                    // front keeps the best of what the floor allows.
                    out.extend(v.drain(..v.len() - keep));
                }
            }
            // A server trimmed to nothing leaves an empty Vec that `take`
            // would treat as a hit-then-miss; drop the entry outright.
            idle.retain(|_, v| !v.is_empty());
            out
        };
        if surplus.is_empty() {
            return;
        }
        self.stats.released.fetch_add(surplus.len() as u64, Ordering::Relaxed);
        // Concurrently, for the reason in `quit_all`: a released fleet is
        // the same shape as a cleared one, and serially a black-holed set
        // of 64 would outlast the interval this tick is due again in.
        quit_all(surplus).await;
    }

    /// Keepalive + reap. Releases an idle pool down to its floor, evicts
    /// anything past `max_idle`, then pings whatever has gone quiet for a
    /// keepalive interval and drops what does not answer, so `take`
    /// almost always finds a live session.
    async fn tick(&self) {
        self.release_if_idle().await;
        let now = Instant::now();
        // Take the connections that need work OUT of the map, so the lock
        // is never held across a network round-trip - a slow provider
        // would otherwise stall every worker trying to check one out.
        let mut expired: Vec<Parked> = Vec::new();
        let mut to_ping: Vec<(String, Parked)> = Vec::new();
        {
            let mut idle = self.idle.lock().await;
            for (k, v) in idle.iter_mut() {
                let mut keep = Vec::with_capacity(v.len());
                for p in v.drain(..) {
                    if now.duration_since(p.parked_at) >= self.max_idle {
                        expired.push(p);
                    } else if now.duration_since(p.fresh_at) >= KEEPALIVE_EVERY {
                        to_ping.push((k.clone(), p));
                    } else {
                        keep.push(p);
                    }
                }
                *v = keep;
            }
        }
        self.stats.evicted.fetch_add(expired.len() as u64, Ordering::Relaxed);
        quit_all(expired).await;
        // Ping the whole batch at once. One black-holed flow costs a
        // VALIDATE_TIMEOUT, and serially a pool of 64 of them would take
        // far longer to reap than the KEEPALIVE_EVERY interval this tick
        // is due again in - so the reaper could never catch up while
        // `take` went on handing out sessions already known to be dead.
        let mut pings = tokio::task::JoinSet::new();
        for (k, p) in to_ping {
            pings.spawn(async move {
                let mut p = p;
                let alive = matches!(
                    tokio::time::timeout(VALIDATE_TIMEOUT, p.conn.date()).await,
                    Ok(Ok(_))
                );
                (k, p, alive)
            });
        }
        while let Some(joined) = pings.join_next().await {
            match joined {
                Ok((k, mut p, true))
                    if p.generation == self.generation.load(Ordering::Acquire) =>
                {
                    p.fresh_at = Instant::now();
                    let mut idle = self.idle.lock().await;
                    let v = idle.entry(k).or_default();
                    if v.len() < self.per_server {
                        v.push(p);
                    } else {
                        drop(idle);
                        self.stats.evicted.fetch_add(1, Ordering::Relaxed);
                        p.conn.quit().await;
                    }
                }
                _ => {
                    self.stats.reaped.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mock::{Chaos, MockServer};

    async fn server() -> MockServer {
        MockServer::start(Default::default(), Chaos::default()).await
    }

    /// Points at a bare loopback listener, for the tests that need a peer
    /// they can kill, hold mute or answer on cue - none of which a
    /// MockServer will do.
    fn bare_config(addr: std::net::SocketAddr) -> ServerConfig {
        ServerConfig {
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
            idle_release_secs: None,
            idle_keep: None,
            max_source_ips: None,
        }
    }

    /// `bare_config` with an explicit idle-release policy, since the
    /// policy now travels ON the server rather than on the pool.
    fn policy_config(
        addr: std::net::SocketAddr,
        secs: Option<u64>,
        keep: u32,
    ) -> ServerConfig {
        ServerConfig {
            idle_release_secs: Some(secs.unwrap_or(0)),
            idle_keep: Some(keep),
            ..bare_config(addr)
        }
    }

    /// A provider that greets and then never says another word, holding
    /// every socket open: the shape a NAT/CGNAT idle eviction or a
    /// firewall restart leaves behind, where the flow is black-holed with
    /// no RST or FIN, our write still succeeds locally and the answer
    /// never comes. Blocking std sockets on their own thread, so the fake
    /// peer keeps working under a paused test clock.
    fn mute_provider() -> std::net::SocketAddr {
        use std::io::Write as _;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut held = Vec::new();
            while let Ok((mut s, _)) = listener.accept() {
                let _ = s.write_all(b"200 mock ready\r\n");
                let _ = s.flush();
                held.push(s); // open forever, mute forever
            }
        });
        addr
    }

    /// A provider that answers normally AND counts how many sockets are
    /// still open against it.
    ///
    /// The whole point of the release tests. The pool's own bookkeeping
    /// saying a connection is gone proves nothing to a provider counting
    /// slots against the account - and nothing to the user's laptop
    /// being turned away - unless the socket is actually closed. A
    /// `idle_count == 0` that left five ESTABLISHED sessions on the wire
    /// is precisely the bug being tested for, and only an observer at
    /// the other end can see the difference.
    fn counting_provider() -> (std::net::SocketAddr, Arc<std::sync::atomic::AtomicUsize>) {
        use std::io::{BufRead, BufReader, Write as _};
        use std::sync::atomic::AtomicUsize;

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().unwrap();
        let live = Arc::new(AtomicUsize::new(0));
        let counter = live.clone();
        std::thread::spawn(move || {
            while let Ok((mut s, _)) = listener.accept() {
                let live = counter.clone();
                live.fetch_add(1, Ordering::SeqCst);
                // A thread per session, blocking std sockets: the peer
                // has to keep answering while the test drives the pool,
                // and has to notice a close the moment it happens.
                std::thread::spawn(move || {
                    let _ = s.write_all(b"200 mock ready\r\n");
                    let _ = s.flush();
                    let mut reader = BufReader::new(s.try_clone().expect("dup"));
                    let mut line = String::new();
                    loop {
                        line.clear();
                        match reader.read_line(&mut line) {
                            Ok(0) | Err(_) => break, // FIN or RST: gone
                            Ok(_) => {}
                        }
                        let quit = line.to_ascii_uppercase().starts_with("QUIT");
                        let reply: &[u8] =
                            if quit { b"205 bye\r\n" } else { b"111 20260731000000\r\n" };
                        if s.write_all(reply).is_err() {
                            break;
                        }
                        let _ = s.flush();
                        if quit {
                            break;
                        }
                    }
                    live.fetch_sub(1, Ordering::SeqCst);
                });
            }
        });
        (addr, live)
    }

    /// Wait (briefly, on the real clock) for the peer's open-session
    /// count to reach `want`, and report what it actually got to. The
    /// close is observed on another thread, so polling for it is the
    /// difference between testing the behaviour and racing it.
    async fn live_settles(live: &std::sync::atomic::AtomicUsize, want: usize) -> usize {
        for _ in 0..200 {
            let n = live.load(Ordering::SeqCst);
            if n == want {
                return n;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        live.load(Ordering::SeqCst)
    }

    /// Age the pool's activity clock by hand. It is a real monotonic
    /// `Instant`, which no test clock moves, so this is the only way to
    /// reach a multi-minute timeout without waiting out minutes.
    fn go_idle_for(pool: &WarmPool, d: Duration) {
        let mut t = pool.last_activity.lock().unwrap();
        *t = t.checked_sub(d).expect("monotonic clock older than the rewind");
    }

    /// The headline: an idle pool must hand the SOCKETS back, not merely
    /// forget about them.
    ///
    /// This is the cost the warm pool never priced. Providers that cap
    /// concurrent distinct source IPs per account - UsenetExpress at 2,
    /// Giganews and Newshosting at 1 - count an idle daemon's IP as an
    /// occupied slot for as long as the socket exists, so a home box
    /// doing nothing at all locks the user's laptop, seedbox or bench
    /// machine out of their own account. Internal state is not what the
    /// provider counts, so it is not what this asserts.
    #[tokio::test(flavor = "multi_thread")]
    async fn an_idle_pool_closes_its_sockets_not_just_its_bookkeeping() {
        const N: usize = 5;
        let (addr, live) = counting_provider();
        let sc = policy_config(addr, Some(300), 0);
        let pool = WarmPool::new(DEFAULT_MAX_IDLE, 8);
        pool.set_release_policies(std::slice::from_ref(&sc));

        for _ in 0..N {
            let (conn, _) = Connection::connect(&sc).await.unwrap();
            pool.give(&sc, conn).await;
        }
        assert_eq!(live_settles(&live, N).await, N, "the provider sees {N} sessions");

        // A pool that was in use a moment ago is not idle, and releasing
        // it would spend the 4.5-14.3x cold-start cost this module
        // exists to avoid.
        pool.tick().await;
        assert_eq!(pool.idle_count().await, N, "a pool still in use must be left alone");
        assert_eq!(live.load(Ordering::SeqCst), N);

        go_idle_for(&pool, Duration::from_secs(301));
        pool.tick().await;

        assert_eq!(pool.idle_count().await, 0);
        assert_eq!(pool.stats.released.load(Ordering::Relaxed), N as u64);
        assert_eq!(
            live_settles(&live, 0).await,
            0,
            "the pool dropped {N} sessions from its map but left them ESTABLISHED \
             on the wire: the account is still locked to this host's IP, which is \
             the entire problem the idle release exists to solve"
        );
    }

    /// Releasing DOWN TO a floor rather than to zero: the next job still
    /// starts on a warm session per server while the rest of the fleet's
    /// slots go back to the account.
    ///
    /// The survivor must be the most recently parked one - the warmest
    /// congestion window, and the longest left before the provider's own
    /// idle timeout - for the same reason `take` pops from the end.
    ///
    /// Worth stating plainly: a floor above zero is only meaningful
    /// against a CONNECTION cap. A provider capping source IPs counts
    /// this host once whether it holds one session or sixty, which is
    /// why the derived default for those is a floor of zero.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_release_floor_keeps_the_warmest_and_frees_the_rest() {
        let (addr, live) = counting_provider();
        let sc = policy_config(addr, Some(120), 1);
        let pool = WarmPool::new(DEFAULT_MAX_IDLE, 8);
        pool.set_release_policies(std::slice::from_ref(&sc));

        for _ in 0..4 {
            let (conn, _) = Connection::connect(&sc).await.unwrap();
            pool.give(&sc, conn).await;
        }
        let newest = {
            let idle = pool.idle.lock().await;
            idle.values().flatten().map(|p| p.parked_at).max().expect("four parked")
        };

        go_idle_for(&pool, Duration::from_secs(121));
        pool.tick().await;

        assert_eq!(pool.idle_count().await, 1, "released down to the floor, not to zero");
        assert_eq!(pool.stats.released.load(Ordering::Relaxed), 3);
        assert_eq!(
            live_settles(&live, 1).await,
            1,
            "three of the four sockets must actually be closed"
        );
        {
            let idle = pool.idle.lock().await;
            let kept = idle.values().flatten().map(|p| p.parked_at).next().expect("one left");
            assert_eq!(
                kept, newest,
                "the floor kept the OLDEST session: it has the least of the warm \
                 congestion window the pool exists to preserve and the least time \
                 left before the provider reaps it anyway"
            );
        }
        // And it is a session, not a placeholder: a floor that cannot be
        // checked out has kept nothing.
        let mut got = pool.take(&sc).await.expect("the kept session");
        got.date().await.expect("a kept session still speaks NNTP");
    }

    /// The mixed config, and the reason the policy is per SERVER: a
    /// flatrate primary that does not care about idle connections,
    /// alongside a block account at a provider allowing two addresses.
    ///
    /// A server is an ACCOUNT. Each provider counts its own limit
    /// against its own account and the two share nothing, so one
    /// process-wide policy is wrong in both directions - it would either
    /// drag the primary down to the strict account's short timeout and
    /// zero floor, throwing away warm connections on a link that never
    /// had a problem, or leave the strict account's lockout in place.
    ///
    /// Two separate peers, so the socket counts are independent and the
    /// assertion is about real connections rather than bookkeeping.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_strict_server_releases_while_a_lax_one_keeps_its_fleet() {
        let (lax_addr, lax_live) = counting_provider();
        let (strict_addr, strict_live) = counting_provider();
        // The lax one is not due to release for an hour; the strict one
        // is due after two minutes and keeps nothing.
        let lax = policy_config(lax_addr, Some(3600), 4);
        let strict = policy_config(strict_addr, Some(120), 0);

        let pool = WarmPool::new(DEFAULT_MAX_IDLE, 8);
        pool.set_release_policies(&[lax.clone(), strict.clone()]);
        for sc in [&lax, &strict] {
            for _ in 0..3 {
                let (conn, _) = Connection::connect(sc).await.unwrap();
                pool.give(sc, conn).await;
            }
        }
        assert_eq!(live_settles(&lax_live, 3).await, 3);
        assert_eq!(live_settles(&strict_live, 3).await, 3);

        // Idle past the strict server's timeout, nowhere near the lax
        // one's.
        go_idle_for(&pool, Duration::from_secs(300));
        pool.tick().await;

        assert_eq!(
            live_settles(&strict_live, 0).await,
            0,
            "the address-capped account must be handed back on its own timeout"
        );
        assert_eq!(
            lax_live.load(Ordering::SeqCst),
            3,
            "the other provider shares nothing with it and must keep its warm \
             fleet: letting the strictest server in the config decide for all of \
             them spends the cold-start cost on links that never had the problem"
        );
        assert_eq!(pool.idle_count().await, 3);
        assert_eq!(pool.stats.released.load(Ordering::Relaxed), 3);
    }

    /// The off switch. A NAS or seedbox that is the account's only
    /// consumer has nobody to hand the slots back to, so releasing them
    /// is pure cost - it buys a cold start for nothing.
    #[tokio::test(flavor = "multi_thread")]
    async fn releasing_can_be_turned_off_entirely() {
        let (addr, live) = counting_provider();
        let sc = policy_config(addr, None, 0);
        let pool = WarmPool::new(DEFAULT_MAX_IDLE, 8);
        pool.set_release_policies(std::slice::from_ref(&sc));
        assert_eq!(pool.release_policy(&sc).expect("installed").after, None);

        for _ in 0..3 {
            let (conn, _) = Connection::connect(&sc).await.unwrap();
            pool.give(&sc, conn).await;
        }
        // Far past any timeout a policy could have set, but still inside
        // `max_idle`, which is a separate mechanism and still applies.
        go_idle_for(&pool, Duration::from_secs(3600));
        pool.tick().await;

        assert_eq!(pool.idle_count().await, 3, "nothing may be released with the policy off");
        assert_eq!(pool.stats.released.load(Ordering::Relaxed), 0);
        assert_eq!(live.load(Ordering::SeqCst), 3);
    }

    /// `max_idle` remains the ceiling on ANY held session, whatever the
    /// release policy says. It is what makes the floor safe: "keep one
    /// per server" keeps it for the rest of that session's `max_idle`,
    /// not forever, so no setting reachable here can produce the
    /// indefinite hold the whole change is meant to remove.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_floor_does_not_outlive_max_idle() {
        let (addr, live) = counting_provider();
        let sc = policy_config(addr, Some(120), 2);
        let pool = WarmPool::new(Duration::from_secs(600), 8);
        pool.set_release_policies(std::slice::from_ref(&sc));

        for _ in 0..3 {
            let (conn, _) = Connection::connect(&sc).await.unwrap();
            pool.give(&sc, conn).await;
        }
        // Age the sessions themselves past max_idle, as an hour of
        // sitting there would.
        {
            let mut idle = pool.idle.lock().await;
            for p in idle.values_mut().flatten() {
                p.parked_at = p
                    .parked_at
                    .checked_sub(Duration::from_secs(601))
                    .expect("monotonic clock older than max_idle");
            }
        }
        go_idle_for(&pool, Duration::from_secs(121));
        pool.tick().await;

        assert_eq!(
            pool.idle_count().await,
            0,
            "a floor of 2 must not exempt those two from max_idle - that would \
             turn a bounded 10-minute hold into a permanent one, which is worse \
             than the behaviour this change replaces"
        );
        assert_eq!(live_settles(&live, 0).await, 0);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn take_on_empty_is_a_miss() {
        let srv = server().await;
        let pool = WarmPool::new(DEFAULT_MAX_IDLE, 4);
        assert!(pool.take(&srv.server_config()).await.is_none());

    }

    #[tokio::test(flavor = "multi_thread")]
    async fn parked_connection_comes_back_alive() {
        let srv = server().await;
        let sc = srv.server_config();
        let pool = WarmPool::new(DEFAULT_MAX_IDLE, 4);

        let (conn, _) = Connection::connect(&sc).await.unwrap();
        pool.give(&sc, conn).await;
        assert_eq!(pool.idle_count().await, 1);


        let mut got = pool.take(&sc).await.expect("a parked connection");
        // Usable for real work, not merely non-null: this is the whole
        // contract the pool's worker relies on.
        got.date().await.expect("checked-out connection still speaks NNTP");
        assert_eq!(pool.stats.hits.load(Ordering::Relaxed), 1);
        assert_eq!(pool.idle_count().await, 0);
    }

    /// The provider reaped the socket while it was parked. `take` must
    /// report a miss, not hand out a corpse - otherwise the first BODY of
    /// the next job fails and an article burns a retry it never needed.
    /// This is the case the DATE validation exists for, and it is the
    /// normal end state of any connection left idle long enough.
    ///
    /// Driven by a bare listener rather than MockServer: MockServer's
    /// `Drop` aborts only its accept loop, so an already-established
    /// connection would survive and the test would prove nothing.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_dead_parked_connection_is_reaped_not_served() {
        use tokio::io::AsyncWriteExt;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (closed_tx, closed_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            s.write_all(b"200 mock ready\r\n").await.unwrap();
            s.flush().await.unwrap();
            s.shutdown().await.ok();
            drop(s);
            let _ = closed_tx.send(());
        });

        let sc = bare_config(addr);
        let pool = WarmPool::new(DEFAULT_MAX_IDLE, 4);
        let (conn, _) = Connection::connect(&sc).await.unwrap();
        pool.give(&sc, conn).await;
        closed_rx.await.unwrap(); // the peer is definitively gone

        assert!(pool.take(&sc).await.is_none(), "must not serve a dead session");
        assert_eq!(pool.stats.reaped.load(Ordering::Relaxed), 1);
        assert_eq!(pool.stats.hits.load(Ordering::Relaxed), 0);
    }

    /// The nastier version of the same end state: the peer is gone but
    /// nothing told us, so the socket still accepts writes and the answer
    /// simply never arrives. A user starting a job over a path whose flows
    /// have been black-holed must not sit and wait for the whole parked
    /// fleet to time out one at a time before the first article moves.
    ///
    /// Paused clock: the validation parks on IO, so tokio auto-advances
    /// straight to whatever deadline bounds it and the test spends no real
    /// time waiting. `waited` is therefore a measurement of the deadline
    /// itself, which is the thing under test.
    #[tokio::test]
    async fn a_black_holed_parked_connection_does_not_stall_a_checkout() {
        let sc = bare_config(mute_provider());
        let pool = WarmPool::new(DEFAULT_MAX_IDLE, 4);
        let (conn, _) = Connection::connect(&sc).await.unwrap();
        pool.give(&sc, conn).await;

        // Only now: the connect above needs the real clock to complete.
        tokio::time::pause();
        let t0 = tokio::time::Instant::now();
        let got = pool.take(&sc).await;
        let waited = t0.elapsed();

        assert!(got.is_none(), "must not serve a black-holed session");
        assert_eq!(pool.stats.reaped.load(Ordering::Relaxed), 1);
        assert_eq!(pool.idle_count().await, 0, "and must not park it again");
        assert!(
            waited < Duration::from_secs(30),
            "a checkout against a black-holed peer waited {waited:?}: warm-pool \
             validation needs its own short deadline, not the 60 s bound every \
             other command inherits"
        );
    }

    /// A deadline PER CANDIDATE is not a bound: silence is a property of
    /// the path, so when one parked session has been black-holed the rest
    /// of that server's set is behind the same hole, and trying them one
    /// by one multiplies the deadline by `per_server` - which production
    /// builds as 64. Eight seconds becomes eight minutes, while the
    /// caller waits for a fresh connect it could have made at once.
    ///
    /// So the whole entry is condemned on the FIRST timeout. This is the
    /// half a single-connection test cannot see.
    /// Paused clock, same as its sibling above: the validation parks on
    /// IO, so tokio auto-advances to whatever deadline bounds it and
    /// `waited` measures the deadline rather than real time.
    #[tokio::test]
    async fn one_black_holed_session_condemns_the_rest_of_that_server() {
        let sc = bare_config(mute_provider());
        let pool = WarmPool::new(DEFAULT_MAX_IDLE, 8);
        for _ in 0..6 {
            let (conn, _) = Connection::connect(&sc).await.unwrap();
            pool.give(&sc, conn).await;
        }
        assert_eq!(pool.idle_count().await, 6);

        tokio::time::pause();
        let t0 = tokio::time::Instant::now();
        let got = pool.take(&sc).await;
        let waited = t0.elapsed();

        assert!(got.is_none(), "must not serve a black-holed session");
        assert!(
            waited < VALIDATE_TIMEOUT * 2,
            "six black-holed sessions cost {waited:?}: the checkout paid the \
             deadline once per candidate instead of condemning the set, which \
             is the stall the deadline was added to stop"
        );
        assert_eq!(
            pool.idle_count().await,
            0,
            "and the rest of the set must be gone, not left for the next checkout"
        );
        assert_eq!(pool.stats.reaped.load(Ordering::Relaxed), 6);
    }

    /// The other direction, and the reason the deadline is seconds rather
    /// than the 40-160 ms a warm validate measures: a provider that is
    /// merely slow is still alive, and reaping it would throw away the
    /// congestion window this whole module exists to keep. Real clock -
    /// the peer's delay has to be real to prove anything.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_slow_but_live_provider_is_not_reaped() {
        use std::io::{Read as _, Write as _};
        /// Far beyond a healthy validate, far inside the deadline.
        const SLOW: Duration = Duration::from_millis(1500);

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            let (mut s, _) = listener.accept().expect("accept");
            s.write_all(b"200 mock ready\r\n").expect("greeting");
            s.flush().expect("flush");
            let mut buf = [0u8; 64];
            let mut first = true;
            while matches!(s.read(&mut buf), Ok(n) if n > 0) {
                if first {
                    std::thread::sleep(SLOW);
                    first = false;
                }
                if s.write_all(b"111 20260727000000\r\n").is_err() {
                    break;
                }
                let _ = s.flush();
            }
        });

        let sc = bare_config(addr);
        let pool = WarmPool::new(DEFAULT_MAX_IDLE, 4);
        let (conn, _) = Connection::connect(&sc).await.unwrap();
        pool.give(&sc, conn).await;

        let mut got = pool.take(&sc).await.expect("a slow provider is not a dead one");
        got.date().await.expect("checked-out connection still speaks NNTP");
        assert_eq!(pool.stats.hits.load(Ordering::Relaxed), 1);
        assert_eq!(pool.stats.reaped.load(Ordering::Relaxed), 0);
    }

    /// The keepalive doubles as the reaper, and a fleet of black-holed
    /// flows is exactly when that matters: production parks up to 64 per
    /// server. Validated one at a time against the 60 s command bound, a
    /// pass took longer than the interval it is due again in, so the
    /// reaper could never catch up while `take` went on handing out the
    /// same corpses.
    ///
    /// Paused clock again, so the pings' deadlines pass in virtual time and
    /// the test costs no real time. What is bounded is the whole pass: it
    /// must cost about ONE validation deadline for the batch, not one per
    /// connection.
    #[tokio::test]
    async fn the_keepalive_reaps_a_black_holed_fleet_inside_its_own_interval() {
        let sc = bare_config(mute_provider());
        let pool = WarmPool::new(DEFAULT_MAX_IDLE, 4);
        for _ in 0..4 {
            let (conn, _) = Connection::connect(&sc).await.unwrap();
            pool.give(&sc, conn).await;
        }
        assert_eq!(pool.idle_count().await, 4);
        // Age the batch into the keepalive's sights by hand: the pool
        // timestamps with a real monotonic clock, which no test clock moves.
        {
            let mut idle = pool.idle.lock().await;
            for p in idle.values_mut().flatten() {
                p.fresh_at = p
                    .fresh_at
                    .checked_sub(KEEPALIVE_EVERY + Duration::from_secs(1))
                    .expect("monotonic clock older than one keepalive interval");
            }
        }

        tokio::time::pause();
        let t0 = tokio::time::Instant::now();
        pool.tick().await;
        let took = t0.elapsed();

        assert_eq!(pool.stats.reaped.load(Ordering::Relaxed), 4, "all four are dead");
        assert_eq!(pool.idle_count().await, 0, "nothing dead may stay parked");
        assert!(
            took < VALIDATE_TIMEOUT * 2,
            "one keepalive pass over 4 black-holed sessions took {took:?}: it \
             must bound its pings and run them together, or a pool of 64 can \
             never be reaped inside the {KEEPALIVE_EVERY:?} the tick is due \
             again in"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn per_server_cap_evicts_the_surplus() {
        let srv = server().await;
        let sc = srv.server_config();
        let pool = WarmPool::new(DEFAULT_MAX_IDLE, 2);
        for _ in 0..4 {
            let (conn, _) = Connection::connect(&sc).await.unwrap();
            pool.give(&sc, conn).await;
        }
        assert_eq!(pool.idle_count().await, 2, "capped at per_server");
        assert_eq!(pool.stats.evicted.load(Ordering::Relaxed), 2);
    }

    /// Credentials are part of the identity. A session authenticated as
    /// the OLD user must never be handed out after the config changes,
    /// which would silently keep downloading on a replaced account.
    #[tokio::test(flavor = "multi_thread")]
    async fn changed_credentials_do_not_match_a_parked_session() {
        let srv = server().await;
        let sc = srv.server_config();
        let pool = WarmPool::new(DEFAULT_MAX_IDLE, 4);
        let (conn, _) = Connection::connect(&sc).await.unwrap();
        pool.give(&sc, conn).await;

        let mut other = sc.clone();
        other.username = Some("someone-else".into());
        assert!(pool.take(&other).await.is_none(), "different account, different pool");
        // The original entry is untouched.
        assert!(pool.take(&sc).await.is_some());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn config_reconciliation_reaps_removed_sessions_but_keeps_valid_ones() {
        let srv = server().await;
        let sc = srv.server_config();
        let pool = WarmPool::new(DEFAULT_MAX_IDLE, 4);
        for _ in 0..2 {
            let (conn, _) = Connection::connect(&sc).await.unwrap();
            pool.give(&sc, conn).await;
        }

        pool.retain_servers(std::slice::from_ref(&sc)).await;
        assert!(
            pool.take(&sc).await.is_some(),
            "a still-configured session survives reconciliation"
        );

        pool.retain_servers(&[]).await;
        assert_eq!(pool.idle_count().await, 0);
        assert!(
            pool.take(&sc).await.is_none(),
            "a removed server cannot leave an idle session behind"
        );
    }

    /// The invalidation gap `clear` alone cannot close: a checkout takes
    /// its candidate OUT of the map before validating it, so for the
    /// length of one DATE round-trip that session exists nowhere `clear`
    /// can reach it. Without the generation fence the DATE simply
    /// succeeds and the checkout hands back a session that the config
    /// change was supposed to have destroyed - authenticated as the old
    /// user, or bound to a source address that is gone.
    ///
    /// Deterministic, not timed: the fake provider tells us when the DATE
    /// has arrived and does not answer until we say so, so the
    /// invalidation is guaranteed to land inside the window.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_checkout_crossing_an_invalidation_is_not_handed_back() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (asked_tx, asked_rx) = tokio::sync::oneshot::channel();
        let (answer_tx, answer_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            s.write_all(b"200 mock ready\r\n").await.unwrap();
            // Wait for the validation command itself, so "the checkout is
            // mid-flight" is an observed fact rather than a sleep.
            let mut seen = Vec::new();
            let mut buf = [0u8; 64];
            while !seen.windows(4).any(|w| w == b"DATE") {
                match s.read(&mut buf).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => seen.extend_from_slice(&buf[..n]),
                }
            }
            let _ = asked_tx.send(());
            let _ = answer_rx.await;
            // A perfectly healthy answer. The session is not dead; it is
            // superseded, which is the whole point.
            let _ = s.write_all(b"111 20260727000000\r\n").await;
            let _ = s.flush().await;
            // Hold the socket open until the test drops us.
            std::future::pending::<()>().await;
        });

        let sc = bare_config(addr);
        let pool = WarmPool::new(DEFAULT_MAX_IDLE, 4);
        let (conn, _) = Connection::connect(&sc).await.unwrap();
        pool.give(&sc, conn).await;

        let checkout = {
            let pool = pool.clone();
            let sc = sc.clone();
            tokio::spawn(async move { pool.take(&sc).await })
        };
        asked_rx.await.expect("the checkout must reach its DATE");
        // The config changed while that DATE was in flight.
        pool.clear().await;
        answer_tx.send(()).unwrap();

        assert!(
            checkout.await.unwrap().is_none(),
            "a session invalidated mid-checkout must not be served, however \
             well it answered"
        );
        assert_eq!(pool.stats.hits.load(Ordering::Relaxed), 0);
    }

    /// End to end, and the reason the whole module exists: run two jobs
    /// back to back through the real pool with a shared WarmPool, and the
    /// SECOND job must open no new TCP connections at all.
    ///
    /// Asserted on the mock's `accepted` counter rather than on timing,
    /// because the win this buys - five saved round-trips, a skipped TLS
    /// handshake and an already-open congestion window - is invisible over
    /// loopback where the RTT is ~0. Connection count is the thing that
    /// actually changed; the latency follows from it on a real path.
    ///
    /// The second job is sized to what the first job actually PARKED,
    /// which is not the same as its `connections` budget. A worker whose
    /// siblings have already emptied the queue returns at the `pending ==
    /// 0` guard without ever dialling, so a job opens only as many
    /// connections as its work needed - and under load a starved fleet
    /// degenerates to one busy worker, so a three-connection job routinely
    /// parks one. Letting the second job out-demand the parked set does
    /// not test the pool: the surplus workers find it empty and correctly
    /// dial, which is a cache miss behaving exactly as designed. Reading
    /// `idle_count` as the second job's budget makes the premise a
    /// measured fact instead of a timing accident. (This is why the test
    /// was load-flaky on Windows: the `> 0` check it used to make passed
    /// on a pool of one while three workers went looking.)
    #[tokio::test(flavor = "multi_thread")]
    async fn a_second_job_opens_no_new_connections() {
        use crate::pool::{ArticleReq, FetchOutcome, PoolConfig, fetch_all_multi};

        let mut articles = std::collections::HashMap::new();
        let data: Vec<u8> = (0..40_000u32).map(|i| i as u8).collect();
        let segs = crate::mock::make_file_articles("w.bin", &data, 8_000, "warm", &mut articles);
        let srv = MockServer::start(articles, Chaos::default()).await;
        let pool = WarmPool::new(DEFAULT_MAX_IDLE, 8);

        let run = |pool: Arc<WarmPool>, connections: usize| {
            let sc = srv.server_config();
            let reqs: Vec<ArticleReq> = segs
                .iter()
                .map(|(id, _, _)| ArticleReq::fresh(format!("<{id}>")))
                .collect();
            let n = reqs.len();
            async move {
                let cfg = PoolConfig {
                    connections,
                    ramp_delay: Duration::from_millis(0),
                    warm: Some(pool),
                    ..PoolConfig::default()
                };
                let servers = vec![(sc, cfg)];
                let (tx, mut rx) = tokio::sync::mpsc::channel(64);
                let fetch =
                    tokio::spawn(async move { fetch_all_multi(&servers, reqs, tx).await });
                let mut done = 0usize;
                while let Some(o) = rx.recv().await {
                    if matches!(o, FetchOutcome::Done { .. }) {
                        done += 1;
                    }
                }
                fetch.await.unwrap();
                assert_eq!(done, n, "every article fetched");
            }
        };

        run(pool.clone(), 3).await;
        let after_first = srv.accepted.load(Ordering::Relaxed);
        let misses_after_first = pool.stats.misses.load(Ordering::Relaxed);
        assert!(after_first > 0, "the first job must actually connect");
        let parked = pool.idle_count().await;
        assert!(parked > 0, "the first job must park its connections");

        run(pool.clone(), parked).await;
        assert_eq!(
            srv.accepted.load(Ordering::Relaxed),
            after_first,
            "the second job must reuse parked connections, not dial again"
        );
        // The same statement in the pool's own words, and the one that
        // names the mechanism when it breaks: a worker records a miss on
        // exactly the path that goes on to dial.
        assert_eq!(
            pool.stats.misses.load(Ordering::Relaxed),
            misses_after_first,
            "the second job must not record a single cache miss"
        );
        assert!(pool.stats.hits.load(Ordering::Relaxed) > 0);
    }

    /// A worker claims a parked connection BEFORE the ramp - deliberately,
    /// so a reuse pays no ramp latency - and only then discovers whether
    /// there is any work left for it. When there is not, the session it is
    /// holding is drained and freshly validated, and it must go back in the
    /// pool: dropping it made the pool shrink every time a fleet outran its
    /// work, which is precisely what a loaded machine does to it. Six
    /// back-to-back jobs eroded three parked connections to two, and the
    /// fourth job dialled again with a hit on every single claim.
    ///
    /// Driven by a job with NOTHING to fetch, which is the same state a
    /// straggler wakes into and needs no timing to arrange: every worker
    /// claims, finds `pending == 0`, and retires.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_worker_that_finds_no_work_returns_its_claim_to_the_pool() {
        use crate::pool::{ArticleReq, PoolConfig, fetch_all_multi};

        let srv = server().await;
        let sc = srv.server_config();
        let pool = WarmPool::new(DEFAULT_MAX_IDLE, 8);
        for _ in 0..3 {
            let (conn, _) = Connection::connect(&sc).await.unwrap();
            pool.give(&sc, conn).await;
        }
        let dialed = srv.accepted.load(Ordering::Relaxed);

        let cfg = PoolConfig {
            connections: 3,
            ramp_delay: Duration::from_millis(0),
            warm: Some(pool.clone()),
            ..PoolConfig::default()
        };
        let servers = vec![(sc.clone(), cfg)];
        let (tx, mut rx) = tokio::sync::mpsc::channel(64);
        let fetch = tokio::spawn(async move {
            fetch_all_multi(&servers, Vec::<ArticleReq>::new(), tx).await
        });
        while rx.recv().await.is_some() {}
        fetch.await.unwrap();

        assert_eq!(
            pool.idle_count().await,
            3,
            "a claim the run had no work for must be parked again, not closed - \
             the warm pool exists to keep these sessions, not to spend them"
        );
        assert_eq!(
            srv.accepted.load(Ordering::Relaxed),
            dialed,
            "and nothing may have been dialled to replace them"
        );
        // Still usable, not merely counted: a re-parked claim has to be a
        // live session or the next job's checkout reaps it right back out.
        let mut got = pool.take(&sc).await.expect("a re-parked claim");
        got.date().await.expect("re-parked connection still speaks NNTP");
    }

    /// The goodbye half of the same argument the batched ping makes above.
    /// `quit` is bounded at 500 ms, so a set of black-holed sessions closed
    /// one at a time costs that PER SESSION: measured 8.0 s for 16, linear.
    /// Production parks 64 per server, so one server was 32 s and a
    /// six-server config over three minutes - and `retain_servers`, which
    /// runs this same drain, is awaited on the way into EVERY daemon job,
    /// so a credential change stalled the next download's first byte.
    ///
    /// Real clock, and a mute peer so every goodbye costs the full bound:
    /// what is under test is that the batch costs ONE of them, not N.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_fleet_of_goodbyes_costs_one_bound_not_one_each() {
        const N: usize = 12;
        let sc = bare_config(mute_provider());
        let pool = WarmPool::new(DEFAULT_MAX_IDLE, 64);
        for _ in 0..N {
            let (conn, _) = Connection::connect(&sc).await.unwrap();
            pool.give(&sc, conn).await;
        }
        assert_eq!(pool.idle_count().await, N);

        let t0 = std::time::Instant::now();
        pool.clear().await;
        let took = t0.elapsed();

        assert_eq!(pool.idle_count().await, 0, "clear must close everything");
        // One 500 ms bound plus slack, against N x 500 ms = 6 s serially.
        assert!(
            took < Duration::from_millis(2500),
            "closing {N} black-holed sessions took {took:?}: the goodbyes must \
             run together, or a 64-per-server pool spends half a minute per \
             server saying them - on the path a config reload blocks"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn clear_closes_everything() {
        let srv = server().await;
        let sc = srv.server_config();
        let pool = WarmPool::new(DEFAULT_MAX_IDLE, 4);
        for _ in 0..3 {
            let (conn, _) = Connection::connect(&sc).await.unwrap();
            pool.give(&sc, conn).await;
        }
        pool.clear().await;
        assert_eq!(pool.idle_count().await, 0);
        assert!(pool.take(&sc).await.is_none());
    }
}

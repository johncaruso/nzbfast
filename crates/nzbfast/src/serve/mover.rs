//! §129 parallelism census, the mover half: per-TARGET mover lanes.
//!
//! The destination mover used to be ONE sequential worker across jobs -
//! right for one destination (two multi-GB copies to the same NAS or
//! disk fight each other, and `move_tree`'s staging-name scheme must
//! never arbitrate two live moves into one Season folder), wrong across
//! destinations: a move to a slow NAS held up a move to a fast local
//! disk that shares nothing with it. The target IS the wall, so the
//! serialization is now per target: one lane per destination DEVICE,
//! spawned on demand, each lane a sequential worker with exactly the
//! old semantics (blocking-pool `mover_process`, busy verdicts paused
//! and re-queued). Two different devices never queue behind each other;
//! the same device stays serial and FIFO.
//!
//! Three things carry the correctness:
//!
//! - the lane key is the destination root's DEVICE, not its path (see
//!   [`lane_key`]) - which is what keeps nested roots, a category
//!   override under its own global root, and every job that could land
//!   in one Season folder on ONE lane;
//! - [`MOVER_MAX_CONCURRENT`] bounds the whole fleet, because every
//!   move reads the same download volume however many destinations
//!   there are;
//! - the pacer's token bucket is one shared instance ([`mover_pacer`]),
//!   so N concurrent copies divide one budget instead of each granting
//!   itself the full one.

use super::*;
use std::collections::HashMap;
use tracing::debug;

/// How many moves may be in flight at once across ALL lanes.
///
/// Lanes exist so two destinations stop queueing behind each other, not
/// so a machine can run ten bulk copies at once: every move READS the
/// same download volume, and each one holds a blocking-pool thread for
/// as long as the copy takes. Three is plenty of lane freedom for the
/// shapes that motivated this (a NAS copy, a local copy, a straggler)
/// and keeps the source disk and the pool civil.
///
/// Deliberately a constant rather than a setting: a setting is three
/// places and a question nobody outside this file can answer better
/// than the file can.
const MOVER_MAX_CONCURRENT: usize = 3;

/// Test-only: how long a move pretends to take, inside the `moving`
/// fence, so a test can watch lanes overlap without a second physical
/// volume. Read by `Daemon::mover_process`.
#[cfg(test)]
pub(super) static TEST_MOVE_DELAY_MS: AtomicU64 = AtomicU64::new(0);

/// The device behind `root`, as a lane key. `None` when it cannot be
/// resolved at all, which the caller turns into the shared lane.
#[cfg(unix)]
fn device_key(root: &Path) -> Option<String> {
    use std::os::unix::fs::MetadataExt;
    // The destination root itself often does not exist yet - the first
    // move to a new completed folder creates it - so walk up to the
    // deepest ancestor that does. That is the volume the root will be
    // created on, which is the device the copy will actually hit.
    for cur in root.ancestors() {
        if let Ok(md) = std::fs::metadata(cur) {
            return Some(format!("dev:{}", md.dev()));
        }
    }
    None
}

/// The device behind `root`, as a lane key. `None` when it cannot be
/// resolved at all, which the caller turns into the shared lane.
#[cfg(windows)]
fn device_key(root: &Path) -> Option<String> {
    // The volume a path lives on IS its prefix here: a drive letter
    // (`C:\`) or a UNC server+share (`\\nas\media`). Case is not
    // significant on Windows, so key on the lowercased form or the same
    // share reached two ways would get two lanes.
    match root.components().next() {
        Some(std::path::Component::Prefix(p)) => Some(format!(
            "vol:{}",
            p.as_os_str().to_string_lossy().to_lowercase()
        )),
        _ => None,
    }
}

/// The lane a destination root belongs to: its DEVICE, never its path
/// string.
///
/// The device is what concurrent moves actually contend for, and it is
/// also what makes nested roots safe for free: a global root
/// `/nas/done` and a category root `/nas/done/tv` are one volume, so
/// they share one lane and stay serial. A path key would have split
/// them and pointed two bulk copies at one NAS. The same follows for
/// `move_tree`'s staging scheme - jobs that can meet in one Season
/// folder share a destination subtree, hence a device, hence a lane.
///
/// Anything unresolvable returns the shared lane (the empty key):
/// falling back to serial is always correct, a wrong split is not.
pub(super) fn lane_key(root: &Path) -> String {
    device_key(root).unwrap_or_default()
}

/// The lane for a job in `cat`: the device of the destination root
/// `relocate_completed` will pick for it.
///
/// A job with no destination configured never reaches the mover
/// (`move_destination_configured` gates `move_pending`); if one ever
/// does, it takes the shared lane.
pub(super) fn lane_key_for(d: &Daemon, cat: &str) -> String {
    match d.move_dest_root(cat) {
        Some((root, _)) => lane_key(&root),
        None => String::new(),
    }
}

/// The live lanes, keyed by device, and the one permit pool they all
/// draw from.
pub(super) struct Lanes {
    map: HashMap<String, tokio::sync::mpsc::UnboundedSender<Arc<Mutex<Job>>>>,
    permits: Arc<tokio::sync::Semaphore>,
}

impl Lanes {
    pub(super) fn new() -> Self {
        Self {
            map: HashMap::new(),
            permits: Arc::new(tokio::sync::Semaphore::new(MOVER_MAX_CONCURRENT)),
        }
    }

    /// Hand `job` to `key`'s lane, starting that lane on first use.
    ///
    /// A lane lives for the daemon's life once started. The population
    /// is bounded by the number of destination DEVICES - a handful -
    /// and a lane that never dies cannot race an enqueue: there is no
    /// window in which the map holds a worker that has already decided
    /// to stop.
    pub(super) fn dispatch(&mut self, d: &Arc<Daemon>, key: String, job: Arc<Mutex<Job>>) {
        let permits = self.permits.clone();
        let daemon = d.clone();
        let lane = key.clone();
        let tx = self
            .map
            .entry(key)
            .or_insert_with(|| spawn_lane(&daemon, lane, permits));
        // The receiver outlives every sender by construction, so this
        // cannot fail; if it somehow did, the job goes back on the
        // dispatcher's queue rather than vanishing.
        if let Err(e) = tx.send(job) {
            d.mover_q.lock_ok().push_back(e.0);
        }
    }

    /// How many lanes are running - the shape this whole change is
    /// about, and the only way a test can see it without two volumes.
    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.map.len()
    }
}

/// One device's lane: a sequential worker over that destination only,
/// with exactly the pre-lane semantics - the copy on the blocking pool,
/// a busy verdict paused and sent to the back of the queue.
fn spawn_lane(
    d: &Arc<Daemon>,
    key: String,
    permits: Arc<tokio::sync::Semaphore>,
) -> tokio::sync::mpsc::UnboundedSender<Arc<Mutex<Job>>> {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Arc<Mutex<Job>>>();
    let d = d.clone();
    let back = tx.clone();
    debug!(target: "move", "mover lane {} started", if key.is_empty() { "shared" } else { &key });
    tokio::spawn(async move {
        while let Some(job) = rx.recv().await {
            // The cap is global, not per lane: the lanes are separate
            // destinations but one SOURCE volume and one blocking pool.
            let permit = permits.clone().acquire_owned().await;
            let d2 = d.clone();
            let j2 = job.clone();
            let requeue = tokio::task::spawn_blocking(move || d2.mover_process(&j2))
                .await
                .unwrap_or(false);
            drop(permit);
            if requeue {
                // Another actor holds this job's files (a recategorize
                // mid-flight). Pause, then the BACK of this lane's own
                // queue: a job that cannot move must not hold up the
                // ones behind it, and must not spin either.
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                if let Err(e) = back.send(job) {
                    d.mover_q.lock_ok().push_back(e.0);
                }
            }
        }
    });
    tx
}

/// C: the mover dispatcher - drains `Daemon::mover_q` into per-device
/// lanes. The queue this frees is the DOWNLOAD queue - the finalize
/// tail used to run the move inline, and the runner awaited that tail
/// before starting the next job.
pub(super) fn spawn_mover(daemon: &Arc<Daemon>) {
    let d = daemon.clone();
    tokio::spawn(async move {
        let mut lanes = Lanes::new();
        loop {
            let job = d.mover_q.lock_ok().pop_front();
            match job {
                Some(job) => {
                    let cat = job.lock_ok().category.clone();
                    // One config read and one stat walk per job, here on
                    // the dispatcher rather than in the lane: the key
                    // has to be decided before the job is handed over.
                    let key = lane_key_for(&d, &cat);
                    lanes.dispatch(&d, key, job);
                }
                None => d.mover_wake.notified().await,
            }
        }
    });
}

/// The mover's token bucket. ONE per daemon (`Daemon::mover_bucket`),
/// drawn from by every lane.
///
/// This state used to be built per CALL, inside `mover_pacer`. With
/// lanes that would be a bug with a number attached: N concurrent moves
/// would each grant themselves the FULL yield-mode budget, breaking the
/// "never slow a live download" promise by exactly the number of lanes
/// running. One bucket for the fleet is the whole design - splitting
/// the budget per lane would just re-introduce the same arithmetic in a
/// harder-to-see place.
pub(super) struct PaceState {
    window: Instant,
    sent: u64,
    sample_at: Instant,
    sample_bytes: u64,
    wire_bps: u64,
}

impl Default for PaceState {
    fn default() -> Self {
        Self {
            window: Instant::now(),
            sent: 0,
            sample_at: Instant::now(),
            sample_bytes: 0,
            wire_bps: 0,
        }
    }
}

/// A pacing callback for `move_tree_paced`: a token bucket fed by
/// [`Daemon::mover_budget_bps`], with its own live sample of what
/// downloads are currently pulling. Called once per copied chunk with
/// the chunk's size; sleeps just enough to hold the budget.
///
/// The state is the daemon's, not the closure's, so every concurrent
/// move draws from the one bucket - the budget belongs to the mover,
/// not to each copy.
pub(super) fn mover_pacer(d: &Daemon) -> impl Fn(u64) + Send + Sync + '_ {
    move |bytes: u64| {
        let now = Instant::now();
        let nap = {
            let mut g = d.mover_bucket.lock_ok();
            // Refresh the download-rate sample every ~500 ms from the
            // daemon's own progress counter.
            let since = now.duration_since(g.sample_at).as_secs_f64();
            if since >= 0.5 {
                let prog = d.progress.load(Ordering::Relaxed);
                if g.sample_bytes > 0 && prog >= g.sample_bytes {
                    g.wire_bps = ((prog - g.sample_bytes) as f64 / since) as u64;
                }
                g.sample_bytes = prog;
                g.sample_at = now;
            }
            let Some(bps) = d.mover_budget_bps(g.wire_bps) else {
                // Uncapped: keep the window fresh so a cap arriving
                // mid-copy does not instantly charge for the burst.
                g.window = now;
                g.sent = 0;
                return;
            };
            g.sent += bytes;
            let elapsed = now.duration_since(g.window).as_secs_f64();
            let over = g.sent as f64 - bps as f64 * elapsed;
            let nap = (over > 0.0)
                .then(|| std::time::Duration::from_secs_f64((over / bps as f64).min(0.5)));
            if elapsed > 2.0 {
                // Roll the window from the moment this caller resumes,
                // so the debt it is about to pay is not charged twice.
                g.window = now + nap.unwrap_or_default();
                g.sent = 0;
            }
            nap
        };
        // Slept OUTSIDE the lock on purpose: several lanes can be in
        // here at once, and holding it across the sleep would turn one
        // shared budget into a convoy - each copy queueing for its turn
        // to wait.
        if let Some(nap) = nap {
            std::thread::sleep(nap);
        }
    }
}

#[cfg(test)]
mod lane_tests;

//! M7b.1 - per-provider connection auto-tuning state.
//!
//! Measured 21 Jul 2026 (BENCHMARKS/PLAN §M7b): asking a provider for
//! more sockets than it wants to grant is 3-4× SLOWER than asking for
//! the knee (connect-flood defense) - connection count is the sharpest
//! single knob in the product, and it punishes the intuitive "more is
//! faster" direction. The daemon probes each provider's ladder while
//! idle (serve.rs) and stores the knee here; every job build then caps
//! each server's connections at min(configured, knee).
//!
//! State lives in `conntune.json` NEXT TO the config file (like
//! settings.json), so plain CLI `nzbfast get` runs benefit from the
//! daemon's probes too. The stored knee is the RAW recommendation; the
//! configured per-server `connections` (the account limit) stays the
//! hard cap at application time - a knee above it is surfaced as a
//! suggestion, never applied silently.

use crate::MutexExt;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Re-probe a provider after this long (knees move with provider policy).
pub const STALE_SECS: u64 = 7 * 86_400;

/// Re-probe a SUSPECT knee after this long instead - soon enough to
/// confirm or clear it within a day, far enough that the second sample
/// sees a different hour (a one-time provider or link issue at probe
/// time shouldn't survive corroboration).
pub const SUSPECT_STALE_SECS: u64 = 6 * 3600;

/// Stamped on every entry this build writes.
///
/// v0 = written before the `suspect` guard existed, so a low knee in a
/// v0 entry has never been corroborated by anything - it is one 5 s
/// ladder's opinion, which is exactly the sample that capped James at 6
/// of 18 and held him there. Guards that only run at RECORD time cannot
/// help an install whose bad knee is already on disk: nothing re-reads
/// it until the 7-day stale clock expires. The version lets
/// [`reopen_low_knees`] tell "measured under the old rules" from
/// "measured and corroborated under the new ones" exactly once.
pub const SCHEMA: u32 = 1;

/// The slowest ladder peak worth believing, in Gbps.
///
/// A ladder every rung of which moved essentially nothing did not
/// measure a knee - it measured a provider that would not serve bodies.
/// `discover_ids` only needs GROUP/OVER, so an account that answers
/// those and then 430s or 502s every BODY, or a link that drops in the
/// seconds after discovery, produces a full set of 0.00 Gbps rungs.
///
/// Recorded, that reads as a knee of 2: the selection is "smallest rung
/// within 90% of the peak", and with a peak of 0.0 the test `gbps >=
/// peak * 0.9` is `0.0 >= 0.0`, which the FIRST rung passes. Worse, the
/// cause is usually structural rather than transient, so the re-probe
/// reproduces it exactly and CORROBORATES it - `suspect` clears and
/// every job on that provider is capped at 2 connections for good.
/// Corroboration defends against a one-time bad sample; it cannot
/// defend against a deterministic one. So: no throughput, no knee.
pub const MIN_LADDER_GBPS: f64 = 0.01;

/// Fraction of the ladder's peak a rung must reach to be worth
/// recommending.
///
/// This was 0.9, on the reasoning that 6% more speed is not worth twice
/// the sockets. That is a sane trade for a machine and the wrong trade
/// for this product: losing a benchmark by 5% is losing it, and the
/// sockets cost the user nothing they can feel. A tester measured 32,
/// 36 and 40 connections at 4m52s, 4m37s and 4m37s on the same file and
/// was auto-tuned to 32 - a real 5% given away by design (4 Aug).
///
/// Not tighter than the measurement, though. 0.98 was tried and is
/// false precision: in the replication harness a provider whose line
/// caps at 4 MB/s reads 0.032 at 4 sockets and 0.033 at 8 - the same
/// speed twice, 3% apart because that is what repeated samples of a
/// network path do - and a 2% bar duly "found" a knee at 8. Tightening
/// past the noise floor does not buy accuracy, it buys tie-breaking by
/// luck, and it does it in the direction of always recommending more
/// sockets than the line can use.
///
/// 5% is the width this can actually defend, and it is only worth
/// having because `conn_ladder` runs a run-off first, re-measuring every
/// rung near the top at double the window - so a 5% gap that survives is
/// far more likely to be real. The 5% a tester lost was not lost here
/// anyway: it was lost by the CLIMB stopping early, which is fixed at
/// its own threshold rather than by pretending to a precision the
/// samples do not have.
pub const LADDER_BAR: f64 = 0.95;

/// How far under the peak a rung has to fall to count as CONTRADICTING
/// the rungs around it.
///
/// Deliberately its own number rather than [`LADDER_BAR`], which it used
/// to share. Those two constants answer different questions - "is this
/// rung fast enough to recommend" and "is this curve physically
/// possible" - and tying them meant tightening the selection quietly
/// disarmed the noise detector: at a 5% bar the field curve
/// (16c 30, 24c 25, 28c 20, 32c 32 MB/s) stopped registering as jagged
/// at all, because 16c no longer cleared the bar, so nothing "crossed it
/// twice". The ladder that started this work would have been read as
/// clean, re-measured never, and recorded as trusted.
///
/// 10% is a shape test, and shapes are not close calls: a rung sitting a
/// tenth below two rungs that bracket it is not a throughput curve.
pub const JAGGED_BAR: f64 = 0.90;

/// The knee a ladder measured.
pub struct Knee {
    /// The count to recommend, clamped to the sockets the provider
    /// actually granted at that rung.
    pub connections: usize,
    /// The rung the knee was read off, BEFORE the granted clamp. Once
    /// clamped the recommendation may match no rung at all, and the UI
    /// still has to know which row to mark.
    pub asked: usize,
    /// The fastest rung - the other half of the comparison the whole
    /// verdict rests on.
    pub peak_at: usize,
    /// Ladder peak (Gbps).
    pub gbps: f64,
    /// The rate curve crossed the bar more than once: a rung BETWEEN
    /// the cheapest one clearing it and the peak read below it. Real
    /// throughput curves do not do that, so this ladder is noise.
    pub jagged: bool,
    /// Rungs to re-measure to settle a jagged ladder (empty otherwise).
    /// See [`merge_samples`].
    pub contested: Vec<usize>,
}

/// Fold a second sample of some rungs back into a ladder.
///
/// The BETTER of the two readings wins, which is not the cowardly
/// choice it looks like. Every mechanism that makes a rung mis-measure
/// on this path pushes the rate DOWN: competing traffic, packet loss, a
/// provider throttling a burst, an article supply that drained before
/// the window closed. Nothing makes a socket count read faster than it
/// can actually go - the one upward artifact, provider-side caching, is
/// already excluded by giving every step distinct articles. So of two
/// disagreeing samples of the same rung, the higher is the one less
/// interfered with, and averaging them just splits the difference with
/// a known-bad measurement.
///
/// It also stops the confirmation pass being theatre. A rung that read
/// 20 against a bar of 28 cannot be rehabilitated by averaging even if
/// it re-reads at a full 31 - the mean is 25.5, still under the bar -
/// so every jagged ladder would stay jagged no matter what the second
/// sample said, and the probes would be spent to change nothing.
///
/// The asymmetry this would otherwise create is handled by which rungs
/// get re-measured, not by the estimator: the peak is in the contested
/// set precisely because the climb's flat re-check already gave it a
/// best-of-two, so every rung in the comparison ends up sampled the
/// same way.
///
/// Bytes SUM: both transfers really happened and the usage ledger is
/// owed all of them. `granted` takes the larger; `saturated` comes from
/// whichever sample won, since it describes that measurement.
pub fn merge_samples(
    steps: &[nzbkit::sysbench::LadderStep],
    extra: &[nzbkit::sysbench::LadderStep],
) -> Vec<nzbkit::sysbench::LadderStep> {
    steps
        .iter()
        .map(|s| {
            let Some(e) = extra.iter().find(|e| e.connections == s.connections) else {
                return s.clone();
            };
            // A non-finite sample carries no information; keep the one
            // that does rather than letting it win a comparison it
            // cannot lose.
            let win_e = e.gbps.is_finite() && (!s.gbps.is_finite() || e.gbps > s.gbps);
            let better = if win_e { e } else { s };
            nzbkit::sysbench::LadderStep {
                connections: s.connections,
                granted: s.granted.max(e.granted),
                gbps: better.gbps,
                bytes: s.bytes.saturating_add(e.bytes),
                saturated: better.saturated,
            }
        })
        .collect()
}

/// Read a ladder's knee.
///
/// `None` when the ladder moved essentially nothing (see
/// [`MIN_LADDER_GBPS`]) - the caller must record NOTHING in that case,
/// leaving the provider untuned rather than capped.
///
/// The finiteness filter is not decoration: a NaN peak fails every `>=`
/// it is given, so a plain comparison would fall through and the rung
/// scan below would then match nothing (or, written the other way
/// round, match rung one) - the same wrong answer this guard exists to
/// stop. An infinite rate is nonsense from a timer that read zero, and
/// belongs on the same side of the door. Non-finite rungs are dropped
/// rather than allowed to set the peak: `total_cmp` sorts NaN ABOVE
/// every real rate, so one garbage sample picked as the peak would
/// throw away a ladder whose other rungs measured fine. Drop them all
/// and an all-NaN ladder still leaves nothing to pick from, which is
/// the `None` this guard wanted.
///
/// Given a peak worth believing, two rules pick the rung:
///
/// 1. The knee is the CHEAPEST rung reaching [`LADDER_BAR`] of the peak.
///    Half the sockets for 94% of the rate is a good trade.
/// 2. But it has to hold that rate all the way UP to the peak rung.
///    Scanning from the bottom and taking the first rung over the bar
///    picks, on a jittery link, a low rung that got one lucky sample -
///    and ignores the refinement probes that already measured the rungs
///    above it BELOW the bar. A measured ladder on a domestic line -
///    16c→30, 24c→25, 28c→20, 32c→32 MB/s - answered 16, while the
///    bisection had just priced 24 and 28 under the bar. Walking DOWN
///    from the peak costs nothing extra and cannot cross a dip.
///
/// Then the pick is clamped to the sockets the provider actually
/// GRANTED at that rung. Asking for more than a provider grants
/// measured 3-4× slower (connect-flood defense), so answering "32" when
/// the account ceiling is 21 would point the user the wrong way down
/// the sharpest knob in the product.
pub fn knee_of(steps: &[nzbkit::sysbench::LadderStep]) -> Option<Knee> {
    let mut v: Vec<&nzbkit::sysbench::LadderStep> =
        steps.iter().filter(|s| s.gbps.is_finite()).collect();
    v.sort_by_key(|s| s.connections);
    let peak_at = (0..v.len()).max_by(|&a, &b| v[a].gbps.total_cmp(&v[b].gbps))?;
    let peak = v[peak_at].gbps;
    if peak < MIN_LADDER_GBPS {
        return None;
    }
    let bar = peak * LADDER_BAR;
    // Walk down from the peak while the rate holds: the lowest rung of
    // that unbroken run is the cheapest one that is genuinely as fast.
    let mut i = peak_at;
    while i > 0 && v[i - 1].gbps >= bar {
        i -= 1;
    }
    // Where a bottom-up scan WOULD have stopped. Lower than where we
    // landed means the curve dipped back under the bar in between.
    // The shape test runs on its OWN bar (see JAGGED_BAR): a curve that
    // dips a tenth below its neighbours is impossible whatever tolerance
    // the recommendation happens to use.
    let jbar = peak * JAGGED_BAR;
    let first_over = v.iter().position(|s| s.gbps >= jbar).unwrap_or(i);
    let jagged = (first_over..=peak_at).any(|k| v[k].gbps < jbar);
    let pick = v[i];
    // `granted + 2 < asked` is the same "the provider is refusing
    // sockets" test the climb and the dashboard's ceiling note use - a
    // socket or two short of the ask is ordinary timing, not a ceiling.
    let connections = if pick.granted > 0 && pick.granted + 2 < pick.connections {
        pick.granted
    } else {
        pick.connections
    };
    Some(Knee {
        connections,
        asked: pick.connections,
        peak_at: v[peak_at].connections,
        gbps: peak,
        jagged,
        contested: if jagged {
            // The rungs whose readings are what make this curve
            // impossible: everything under the bar between the cheap
            // rung that cleared it and the peak, plus the peak itself.
            //
            // The peak is in the list because it SETS the bar, and it
            // is the one rung the climb already sampled twice, keeping
            // the better of the two (the flat re-check) - so it sits
            // high by construction while every other rung is a single
            // sample. Re-measuring it is what makes the comparison
            // fair.
            v[first_over..=peak_at]
                .iter()
                .filter(|s| s.gbps < jbar || s.connections == v[peak_at].connections)
                .map(|s| s.connections)
                .collect()
        } else {
            Vec::new()
        },
    })
}

/// Whether auto connection tuning is enabled in the dashboard settings
/// (settings.json next to the config; absent key = the default, ON).
/// The toggle gates APPLICATION as well as probing: switching it off
/// must lift a stored knee from the very next job, not keep capping
/// with stale state the user has disowned.
///
/// Through the same backup-aware loader every other settings read uses
/// (Codex sweep 2, 3 Aug ML3). A bare `read` + parse treats a torn or
/// half-written settings.json as "no setting", which for this key means
/// the default - ON. The daemon meanwhile loads the .bak and correctly
/// knows the user turned it OFF, so the two authorities disagreed and
/// every new job re-applied stored knees the user had disowned. One
/// loader, one answer.
pub fn enabled(config: &Path) -> bool {
    crate::persist::load_json_with_backup(&config.with_file_name("settings.json"))
        .and_then(|v| v.get("auto_connections").and_then(|v| v.as_bool()))
        .unwrap_or(true)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tuned {
    /// Recommended connection count (smallest reaching ≥90% of the
    /// ladder's peak rate).
    pub connections: usize,
    /// Most sockets the provider actually granted during the probe.
    pub granted: usize,
    /// The rung the knee was read off, BEFORE the granted clamp - the
    /// persisted twin of [`Knee::asked`].
    ///
    /// Stored because `connections` alone cannot be read back: it is
    /// already clamped to the sockets the provider granted at that rung,
    /// so `asked` is the other half of "32 asked, 21 granted" and the
    /// only thing that makes an account-tier ceiling visible after the
    /// fact. It also keeps the line-speed tip honest: comparing granted
    /// against the CONFIGURED count claimed "granted only 16 of the 20
    /// connections asked for" on a ladder that stopped at the knee and
    /// never requested 20 - a statement about the user's account built
    /// from a number nothing ever asked for, made exactly when they are
    /// short of their line speed and looking for a reason to pay for a
    /// higher tier. 0 on an entry written before this field existed,
    /// which reads as "unknown" and says nothing rather than guessing.
    #[serde(default)]
    pub asked: usize,
    /// Peak rate observed on the ladder (Gbps).
    pub gbps: f64,
    /// Unix time of the probe.
    pub checked: u64,
    /// "auto" (idle probe) or "manual" (dashboard ladder run).
    #[serde(default)]
    pub source: String,
    /// The knee would cut the configured connection count substantially
    /// and no earlier probe agrees yet - a single 5 s-per-rung ladder on
    /// a jittery link can fake a knee far below the true one (James: 6
    /// of 18). A suspect knee is NOT applied to jobs and is re-probed on
    /// the short clock; a second probe landing in the same place clears
    /// the flag (and, hours apart, samples a different time of day).
    #[serde(default)]
    pub suspect: bool,
    /// The ceiling in force when this knee was measured: the smaller of
    /// the global connections setting and the server's own configured
    /// count. Stored because the ceiling is an INPUT to the ladder (it
    /// sets how far the rungs climb), so raising it invalidates the
    /// measurement - see [`reopen_low_knees`]. 0 on a v0 entry.
    #[serde(default)]
    pub limit: usize,
    /// Schema version of this entry; see [`SCHEMA`].
    #[serde(default)]
    pub v: u32,
    /// The last measurement that was NOT trusted enough to apply, kept
    /// so the next probe has something to agree with.
    ///
    /// Without it a suspect result had only two possible fates, and both
    /// were wrong: replace the applied knee (which un-applies a working
    /// cap - see [`record`]) or be discarded (in which case a knee that
    /// really HAS moved can never be corroborated, because every future
    /// probe is compared against the stale applied value it disagrees
    /// with). Holding the observation separately lets the cap stay up
    /// while the candidate waits for a second opinion.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending: Option<usize>,
}

/// The connection ceiling a job would actually hand this server: the
/// global setting and the server's own configured count are both caps,
/// and the tuner has to reason about the smaller one. Judging a knee
/// against the server's number alone called 6 "suspiciously low" on an
/// install whose global setting was 6 - it was simply the ceiling.
/// Connections a job will really open on one server.
///
/// `base` is what the user's own settings allow (the global count capped
/// by this server's own, and by any sidecar borrowing). The knee may
/// only ever lower that, never raise it.
///
/// A PINNED server takes `base` untouched. That is the whole point of
/// the pin and it is checked first, so no future ordering question can
/// put a measurement in front of an instruction: the tuner is a guess
/// about the link, the pin is a statement from the person watching it,
/// and the person wins.
///
/// A SUSPECT knee is not applied either - it is a low reading still
/// waiting for a second probe to agree with it.
pub fn applied_connections(base: usize, pinned: bool, tuned: Option<&Tuned>) -> usize {
    if pinned {
        return base;
    }
    match tuned {
        Some(t) if t.connections > 0 && !t.suspect => base.min(t.connections),
        _ => base,
    }
}

pub fn effective_limit(global: usize, server_connections: u32) -> usize {
    global.max(1).min((server_connections.max(1)) as usize)
}

/// TODO 112: the live epoch controller's master gate. Dark until the
/// three loopback rigs (nzbkit tests/live_tune.rs) have earned it a
/// default. Independent of `auto_connections` on purpose: that toggle
/// governs the OFFLINE prober; the per-server escape from live tuning
/// is `pin_connections`, exactly as it is for applied knees.
pub fn live_tune_on() -> bool {
    std::env::var("NZBFAST_LIVE_TUNE").is_ok_and(|v| v == "1")
}

/// Whether a freshly measured knee should be withheld from jobs until a
/// second probe agrees with it.
///
/// ONE rule for both paths. It used to live only in the auto probe,
/// while the dashboard's Test button - the one a user actually presses,
/// and the only one that runs while the link is busy with whatever else
/// they are doing - wrote its result as trusted and capped their jobs
/// from the next download. That is backwards: a hand-triggered run is
/// the LESS controlled measurement of the two, because the auto probe at
/// least waits for an idle queue and an idle scan first.
///
/// "The user saw every rung, so it is their call" was the old
/// justification, and it does not survive contact with the screenshots:
/// what a user sees is a verdict sentence and an Apply button, not a
/// judgement about whether 6 of 50 is metrologically sound.
///
/// `prior` is the knee already on file for this host, if any.
pub fn is_suspect(best: usize, ceiling: usize, jagged: bool, prior: Option<&Tuned>) -> bool {
    // A knee that would cut the allowance to less than half, or a ladder
    // whose rungs contradict each other, is unproven until a second
    // probe lands in the same place - hours apart, so it samples a
    // different time of day.
    let unproven = jagged || best.saturating_mul(2) <= ceiling;
    // Through `corroborates`, which knows to compare against a PARKED
    // reading when there is one - inlining the comparison here would
    // quietly re-introduce the frozen-cap bug it exists to avoid.
    unproven && !corroborates(prior, best)
}

pub fn path_for(config: &Path) -> PathBuf {
    config.with_file_name("conntune.json")
}

pub fn load(config: &Path) -> HashMap<String, Tuned> {
    std::fs::read(path_for(config))
        .ok()
        .and_then(|b| serde_json::from_slice::<HashMap<String, Tuned>>(&b).ok())
        .unwrap_or_default()
}

/// Serializes every read-modify-write of conntune.json. The daemon's
/// probe loop, a manual ladder run and a settings edit all live in THIS
/// process: without the lock, two concurrent writers each load the old
/// map and the second write drops the first host's update - and both
/// used the same `.conntune.<pid>.tmp` path, tearing the file. The lock
/// removes the lost update; write_atomic (process-wide temp counter)
/// removes the torn write.
static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn save(config: &Path, map: &HashMap<String, Tuned>) {
    if let Ok(bytes) = serde_json::to_vec_pretty(map) {
        let _ = crate::persist::write_atomic(&path_for(config), &bytes);
    }
}

/// Merge one host's probe result in and persist.
/// Does a fresh reading agree with the one already on file?
///
/// Against `pending` when there is one. That is the whole point of
/// parking it: the applied value is precisely the number the pending
/// reading disagreed with, so corroborating against it could only ever
/// fail, and a knee that has genuinely moved would be re-measured and
/// re-rejected forever.
pub fn corroborates(prev: Option<&Tuned>, best: usize) -> bool {
    prev.is_some_and(|p| {
        let a = p.pending.unwrap_or(p.connections).max(1) as f64;
        let b = best.max(1) as f64;
        (a - b).abs() <= a.max(b) * 0.25
    })
}

pub fn record(config: &Path, host: &str, t: Tuned) {
    let _g = LOCK.lock_ok();
    let mut map = load(config);
    let t = reconcile(map.get(host), t);
    map.insert(host.to_string(), t);
    save(config, &map);
}

/// What actually gets stored, given what was already there.
///
/// A SUSPECT measurement must never replace an APPLIED one. Jobs skip
/// suspect entries entirely, so overwriting a corroborated `{8, applied}`
/// with an unproven `{21, suspect}` does not merely change the cap - it
/// removes it, and the provider runs at the full configured count in the
/// over-asking direction the whole feature exists to prevent. That is a
/// worse state than either number, it lasts until two more probes agree,
/// and the UI meanwhile says "nothing has been applied" while something
/// has just been un-applied.
///
/// So the old entry keeps applying and the new reading is parked in
/// `pending`, where the next probe can corroborate it. Two probes still
/// move a knee that has genuinely changed; one noisy evening moves
/// nothing.
///
/// A trusted measurement replaces outright and clears `pending` - it has
/// already been corroborated, and there is nothing left to wait for.
fn reconcile(prev: Option<&Tuned>, new: Tuned) -> Tuned {
    match prev {
        Some(p) if new.suspect && !p.suspect && p.connections > 0 => Tuned {
            // The applied half stays exactly as it was...
            connections: p.connections,
            suspect: false,
            granted: p.granted,
            asked: p.asked,
            limit: p.limit,
            // ...and the new observation is what the clock now runs for.
            pending: Some(new.connections),
            gbps: new.gbps,
            checked: new.checked,
            source: new.source,
            v: SCHEMA,
        },
        _ => new,
    }
}

/// Put low knees back up for corroboration, and report which hosts moved.
///
/// A stored knee is a measurement taken under a ceiling - the ladder
/// only climbs as far as the configured count allows - so when the user
/// raises that ceiling the old measurement no longer answers the
/// question they are now asking. Until now nothing re-read the file on
/// that event, and the field report is unambiguous: James set 22, then
/// 24, restarted the app, tried a fresh NZB, and every job still ran at
/// the stored knee of 6 with the dashboard showing a flat `6/6`. The
/// number he typed had no effect and no way to have one.
///
/// So: for each host the user has configured, if the ceiling is now
/// higher than the one the knee was measured under AND the knee is less
/// than half of it, mark the entry `suspect` (jobs stop applying it, so
/// the user's number takes effect from the very next download) and zero
/// `checked` (the idle prober re-measures at its next opportunity, and
/// the corroboration rule decides). A knee that was right comes back
/// within one probe; a knee that was one bad 5 s sample does not.
///
/// v0 entries carry `limit: 0`, so this also sweeps the pre-guard files
/// already sitting on testers' disks the first time a new build runs -
/// which is the only thing that unsticks an install like James's.
/// Every entry seen is stamped to the current [`SCHEMA`], so the sweep
/// is once per entry, not once per call.
pub fn reopen_low_knees(
    config: &Path,
    limit_for: impl Fn(&str) -> Option<usize>,
) -> Vec<(String, usize, usize)> {
    let _g = LOCK.lock_ok();
    let mut map = load(config);
    let mut moved = Vec::new();
    let mut dirty = false;
    for (host, t) in map.iter_mut() {
        let Some(limit) = limit_for(host) else {
            continue; // not a server this install has configured
        };
        if limit > t.limit && t.connections * 2 <= limit && !t.suspect {
            t.suspect = true;
            t.checked = 0;
            moved.push((host.clone(), t.connections, limit));
            dirty = true;
        }
        // Record the ceiling this entry has now been judged against,
        // so the same raise never reopens it twice.
        if t.limit != limit || t.v != SCHEMA {
            t.limit = limit;
            t.v = SCHEMA;
            dirty = true;
        }
    }
    if dirty {
        save(config, &map);
    }
    moved
}

/// [`reopen_low_knees`] for a whole install: reads the server list off
/// disk and judges every stored knee against that server's effective
/// ceiling. Logs what it reopened, because a connection count silently
/// changing under the user is precisely the thing that took a support
/// round-trip to explain last time.
pub fn reopen_for_install(config: &Path, global: usize) {
    let Ok(cfg) = nzbkit::config::Config::load(config) else {
        return;
    };
    let limits: HashMap<&str, usize> = cfg
        .servers
        .iter()
        .map(|s| (s.host.as_str(), effective_limit(global, s.connections)))
        .collect();
    for (host, knee, limit) in reopen_low_knees(config, |h| limits.get(h).copied()) {
        println!(
            "[tune] {host}: your connection setting is now {limit}, well above the \
             measured {knee} - jobs will use {limit} while that measurement is \
             re-taken"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(n: usize, suspect: bool) -> Tuned {
        Tuned {
            connections: n,
            granted: n,
            asked: n,
            gbps: 1.0,
            checked: 100,
            source: "auto".into(),
            suspect,
            pending: None,
            limit: 24,
            v: SCHEMA,
        }
    }

    /// M6: a parked reading is an OUTSTANDING QUESTION, and the TTL
    /// picker has to see it. `reconcile` deliberately leaves `suspect`
    /// false on these - the old knee stays in force - so a picker that
    /// only reads `suspect` puts the second opinion on the seven-day
    /// clock and the parked candidate is never resolved.
    #[test]
    fn a_parked_candidate_is_an_open_question() {
        let applied = entry(8, false);
        let held = reconcile(Some(&applied), entry(21, true));
        assert!(!held.suspect, "the cap must stay applied");
        assert_eq!(held.pending, Some(21));
        // What the TTL picker in tasks.rs asks. Both halves matter: this
        // entry is NOT suspect, so `pending` is the only thing that can
        // put it back on the short clock.
        let short = held.suspect || held.pending.is_some();
        assert!(short, "a parked candidate must re-probe on the SHORT clock");
        // …and a settled entry stays on the long one.
        let settled = reconcile(Some(&applied), entry(9, false));
        assert!(
            !(settled.suspect || settled.pending.is_some()),
            "a corroborated knee must not re-probe every six hours"
        );
    }

    /// The regression the jagged term introduced: an unproven reading
    /// must not be able to REMOVE a cap that is currently working.
    ///
    /// Jobs skip suspect entries, so overwriting an applied {8} with a
    /// suspect {21} does not change the cap - it deletes it, and the
    /// provider runs at the full configured count in the over-asking
    /// direction the feature exists to prevent.
    #[test]
    fn a_suspect_reading_never_unapplies_a_working_cap() {
        let applied = entry(8, false);
        let mut noisy = entry(21, true);
        noisy.checked = 999;
        let out = reconcile(Some(&applied), noisy);
        assert_eq!(out.connections, 8, "the working cap must survive");
        assert!(!out.suspect, "and must still be applied");
        assert_eq!(
            out.pending,
            Some(21),
            "the new reading waits for a second opinion"
        );
        assert_eq!(
            out.checked, 999,
            "on the short clock, so it is re-probed soon"
        );
    }

    /// …but a knee that really has moved still gets there, in two
    /// probes. The second reading is compared against the PARKED one,
    /// not against the applied value it disagreed with - otherwise
    /// corroboration could only ever fail and the cap would be frozen
    /// forever.
    #[test]
    fn a_parked_reading_can_still_win_on_the_next_probe() {
        let mut held = entry(8, false);
        held.pending = Some(21);
        assert!(
            corroborates(Some(&held), 21),
            "a repeat of the parked reading agrees"
        );
        assert!(corroborates(Some(&held), 19), "and so does one within 25%");
        assert!(
            !corroborates(Some(&held), 8),
            "the applied value is not the yardstick now"
        );
        // Corroborated, so the caller records it trusted - which replaces
        // outright and clears the parking space.
        let out = reconcile(Some(&held), entry(21, false));
        assert_eq!(out.connections, 21);
        assert!(!out.suspect);
        assert_eq!(out.pending, None, "nothing left to wait for");
    }

    /// With nothing applied yet there is nothing to protect, and a
    /// suspect reading is stored as-is so it can be corroborated.
    #[test]
    fn a_suspect_reading_stands_when_no_cap_is_in_force() {
        let out = reconcile(None, entry(6, true));
        assert_eq!(out.connections, 6);
        assert!(out.suspect);
        // Replacing one suspect entry with another is fine too: neither
        // is applied, so nothing is lost.
        let out = reconcile(Some(&entry(6, true)), entry(9, true));
        assert_eq!(out.connections, 9);
    }

    fn knee(n: usize, suspect: bool) -> Tuned {
        Tuned {
            connections: n,
            granted: n,
            asked: n,
            gbps: 1.0,
            checked: 0,
            source: "auto".into(),
            suspect,
            limit: 50,
            v: SCHEMA,
            pending: None,
        }
    }

    /// The escape hatch, and the only reason it exists: a knee the user
    /// has measured to be wrong must not be able to touch them.
    #[test]
    fn a_pinned_server_ignores_the_knee() {
        let low = knee(6, false);
        assert_eq!(
            applied_connections(40, false, Some(&low)),
            6,
            "unpinned: capped"
        );
        assert_eq!(
            applied_connections(40, true, Some(&low)),
            40,
            "pinned: the user wins"
        );
    }

    /// Pinning is not a licence to exceed the account: it makes the
    /// user's OWN number authoritative, and that number is already the
    /// global setting capped by this server's limit.
    #[test]
    fn a_pin_does_not_raise_the_ceiling() {
        assert_eq!(applied_connections(8, true, Some(&knee(30, false))), 8);
        assert_eq!(applied_connections(8, true, None), 8);
    }

    /// Unpinned behaviour is untouched, including the suspect rule.
    #[test]
    fn an_unpinned_server_still_obeys_a_trusted_knee_only() {
        assert_eq!(
            applied_connections(40, false, Some(&knee(6, true))),
            40,
            "suspect: not applied"
        );
        assert_eq!(
            applied_connections(40, false, Some(&knee(0, false))),
            40,
            "no knee recorded"
        );
        assert_eq!(applied_connections(40, false, None), 40);
    }

    fn step(connections: usize, gbps: f64) -> nzbkit::sysbench::LadderStep {
        nzbkit::sysbench::LadderStep {
            connections,
            granted: connections,
            gbps,
            bytes: 0,
            saturated: false,
        }
    }

    /// A ladder that moved nothing is NOT a knee of 2.
    ///
    /// `gbps >= peak * 0.9` with a peak of 0.0 is `0.0 >= 0.0`, which the
    /// first rung passes - so an all-zero ladder used to record a knee of
    /// 2 and cap every job on that provider. The auto path called that
    /// `suspect` and waited for a second probe, but the cause (an account
    /// that answers GROUP/OVER and then serves no bodies) is structural,
    /// so the re-probe reproduced it exactly and CORROBORATED it. The
    /// manual path wrote `suspect: false` and applied it immediately.
    #[test]
    fn a_ladder_that_moved_nothing_yields_no_knee() {
        let dead = [step(2, 0.0), step(4, 0.0), step(8, 0.0)];
        assert!(
            knee_of(&dead).is_none(),
            "an all-zero ladder is not a knee of 2"
        );

        // A trickle is the same story: still far below anything a real
        // provider serves, and it would pick rung one just as readily.
        let trickle = [step(2, 0.0001), step(4, 0.0002)];
        assert!(knee_of(&trickle).is_none());

        // An empty ladder has no peak at all.
        assert!(knee_of(&[]).is_none());

        // NaN must not sail through the comparison into rung one.
        assert!(knee_of(&[step(2, f64::NAN), step(4, f64::NAN)]).is_none());
    }

    /// One unusable rung must not throw away the rungs that measured
    /// fine: `total_cmp` ranks NaN above every real rate, so a NaN
    /// allowed to set the peak would discard the whole ladder.
    #[test]
    fn a_single_nan_rung_does_not_discard_the_ladder() {
        let steps = [step(2, 1.0), step(4, 2.0), step(8, 4.0), step(16, f64::NAN)];
        let k = knee_of(&steps).expect("a NaN rung sank a usable ladder");
        assert_eq!(k.connections, 8);
        assert_eq!(k.peak_at, 8);
    }

    /// The real behaviour is untouched: smallest rung within 90% of the
    /// peak, which is the point of the ladder.
    #[test]
    fn a_real_ladder_still_finds_its_knee() {
        let steps = [step(2, 1.0), step(4, 2.0), step(8, 4.0), step(16, 4.1)];
        let k = knee_of(&steps).expect("a real ladder has a knee");
        assert_eq!(k.connections, 8);
        assert_eq!(k.gbps, 4.1);
        assert!(!k.jagged);

        // A flat-from-the-start ladder genuinely knees at its first rung,
        // and that must still be reported - the guard is about zero
        // throughput, not about low connection counts.
        let flat = [step(2, 3.0), step(4, 3.05), step(8, 3.1)];
        let k = knee_of(&flat).expect("a flat ladder still knees at rung one");
        assert_eq!(k.connections, 2);
        assert_eq!(k.gbps, 3.1);
    }

    /// MB/s as the dashboard shows it → a ladder step with its own
    /// granted count.
    fn rung(connections: usize, granted: usize, mbps: f64) -> nzbkit::sysbench::LadderStep {
        nzbkit::sysbench::LadderStep {
            connections,
            granted,
            gbps: mbps * 8.0 / 1000.0,
            bytes: 0,
            saturated: false,
        }
    }

    /// The ladder that started this: 16c read 30 MB/s, then
    /// 24c and 28c read 25 and 20, then 32c - on only 21 granted sockets
    /// - read 32. The bottom-up scan answered 16: it took the first rung
    /// over the bar and never looked at the two refinement probes that
    /// had just priced the rungs above it UNDER the bar.
    #[test]
    fn the_knee_is_not_read_across_a_dip() {
        let steps = [
            rung(2, 2, 7.0),
            rung(4, 4, 13.0),
            rung(8, 8, 19.0),
            rung(16, 16, 30.0),
            rung(24, 24, 25.0),
            rung(28, 28, 20.0),
            rung(32, 21, 32.0),
        ];
        let k = knee_of(&steps).expect("a ladder this fast has a knee");
        // 30 clears 0.9×32=28.8, but 24c and 28c sit under it - the knee
        // cannot reach down past that dip to claim them.
        assert_eq!(k.asked, 32, "the knee was read across a dip");
        // …and that rung only ever ran on 21 sockets, so 21 is the
        // number. Asking for 32 is the 3-4×-slower direction.
        assert_eq!(k.connections, 21, "the knee was not clamped to granted");
        assert!(k.jagged, "a curve crossing the bar twice is jagged");
    }

    /// The cheap-rung trade still has to work: on a clean curve the knee
    /// is the LOWEST rung within 10% of the peak, not the peak itself.
    #[test]
    fn a_clean_curve_still_knees_at_the_cheapest_fast_rung() {
        let steps = [
            rung(2, 2, 7.0),
            rung(4, 4, 13.0),
            rung(8, 8, 19.0),
            rung(16, 16, 30.0),
            rung(32, 32, 31.0),
        ];
        let k = knee_of(&steps).expect("a clean ladder has a knee");
        assert_eq!(k.connections, 16);
        assert_eq!(k.peak_at, 32);
        assert!(!k.jagged, "a monotonic curve must not read as jagged");
    }

    /// The contested list is exactly the rungs whose readings make the
    /// curve impossible - the sub-bar dip, plus the peak that sets the
    /// bar and is the one rung the climb already sampled twice keeping
    /// the better. Re-measuring the pick and the peak alone would not
    /// settle anything: what makes this curve jagged is 24c and 28c.
    #[test]
    fn a_jagged_ladder_nominates_the_rungs_that_disagree() {
        let steps = [
            rung(2, 2, 7.0),
            rung(8, 8, 19.0),
            rung(16, 16, 30.0),
            rung(24, 24, 25.0),
            rung(28, 28, 20.0),
            rung(32, 21, 32.0),
        ];
        let k = knee_of(&steps).expect("a ladder this fast has a knee");
        assert_eq!(k.contested, vec![24, 28, 32]);

        // A clean ladder pays nothing: nothing to re-measure.
        let clean = [rung(2, 2, 7.0), rung(8, 8, 19.0), rung(16, 16, 30.0)];
        assert!(knee_of(&clean).expect("clean ladder").contested.is_empty());
    }

    /// A second sample of the dip settles it. Re-measured free of
    /// whatever was interfering, 24c and 28c clear the bar, the curve
    /// stops contradicting itself, and the cheap rung is honestly the
    /// knee - the answer the single jittery sample only guessed at.
    #[test]
    fn a_settled_dip_hands_back_the_cheap_rung() {
        let steps = [
            rung(2, 2, 7.0),
            rung(8, 8, 19.0),
            rung(16, 16, 30.0),
            rung(24, 24, 25.0),
            rung(28, 28, 20.0),
            rung(32, 21, 32.0),
        ];
        // The dip was noise: it re-reads in line with its neighbours.
        let extra = [rung(24, 24, 31.0), rung(28, 28, 31.0), rung(32, 21, 31.0)];
        let merged = merge_samples(&steps, &extra);
        let k = knee_of(&merged).expect("a merged ladder still has a knee");
        assert!(
            !k.jagged,
            "the dip was re-measured away but still reads jagged"
        );
        // 24, not the 16 this expected while the bar was 10%. Settled,
        // the curve reads 16c 30, 24c 31, 28c 31, 32c 32 MB/s - and 16c
        // is 6% off the best, which is precisely the gap the tightened
        // bar exists to stop giving away. The cheap rung wins when it is
        // genuinely as fast; this one is not.
        assert_eq!(
            k.connections, 24,
            "a settled curve must yield the cheapest FAST rung"
        );
    }

    /// A dip that reproduces is real, and the knee stays on the safe
    /// side of it rather than reaching down past a rate the line
    /// genuinely does not hold.
    #[test]
    fn a_dip_that_reproduces_keeps_the_conservative_knee() {
        let steps = [
            rung(2, 2, 7.0),
            rung(8, 8, 19.0),
            rung(16, 16, 30.0),
            rung(24, 24, 25.0),
            rung(28, 28, 20.0),
            rung(32, 21, 32.0),
        ];
        let extra = [rung(24, 24, 24.0), rung(28, 28, 21.0), rung(32, 21, 32.0)];
        let merged = merge_samples(&steps, &extra);
        let k = knee_of(&merged).expect("a merged ladder still has a knee");
        assert!(k.jagged, "a reproducing dip is still a dip");
        assert_eq!(k.connections, 21);
    }

    /// Bytes from BOTH samples are owed to the usage ledger, and the
    /// rate is the less-interfered-with of the two.
    #[test]
    fn merging_takes_the_better_rate_and_sums_the_bytes() {
        let mut a = rung(16, 16, 30.0);
        a.bytes = 1_000;
        let mut b = rung(16, 14, 20.0);
        b.bytes = 700;
        let m = merge_samples(&[a], &[b]);
        assert_eq!(m[0].bytes, 1_700, "the ledger is owed both transfers");
        assert_eq!(m[0].granted, 16);
        assert!(
            (m[0].gbps - 30.0 * 8.0 / 1000.0).abs() < 1e-9,
            "rate is the better sample"
        );

        // A NaN re-read must not win a comparison it cannot lose.
        let m = merge_samples(&[rung(16, 16, 30.0)], &[rung(16, 16, f64::NAN)]);
        assert!((m[0].gbps - 30.0 * 8.0 / 1000.0).abs() < 1e-9);

        // A rung with no second sample is passed through untouched.
        let solo = merge_samples(&[rung(8, 8, 19.0)], &[rung(16, 16, 30.0)]);
        assert_eq!(solo.len(), 1);
        assert_eq!(solo[0].connections, 8);
        assert!((solo[0].gbps - 19.0 * 8.0 / 1000.0).abs() < 1e-9);
    }

    /// Sockets a provider refuses by ones and twos are ordinary timing,
    /// not an account ceiling - don't ratchet the knee down for them.
    #[test]
    fn a_socket_short_of_the_ask_is_not_a_ceiling() {
        let steps = [rung(2, 2, 7.0), rung(8, 8, 19.0), rung(16, 15, 30.0)];
        let k = knee_of(&steps).expect("a real ladder has a knee");
        assert_eq!(k.connections, 16);
    }

    #[test]
    fn record_and_load_round_trip() {
        let dir = std::env::temp_dir().join(format!("nzbfast-conntune-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = dir.join("config.local.json");
        assert!(load(&cfg).is_empty());
        record(
            &cfg,
            "news.example.com",
            Tuned {
                connections: 12,
                granted: 12,
                asked: 12,
                gbps: 4.9,
                checked: 1,
                source: "auto".into(),
                suspect: false,
                limit: 20,
                v: SCHEMA,
                pending: None,
            },
        );
        record(
            &cfg,
            "fill.example.com",
            Tuned {
                connections: 4,
                granted: 4,
                asked: 4,
                gbps: 0.8,
                checked: 2,
                source: "manual".into(),
                suspect: true,
                limit: 8,
                v: SCHEMA,
                pending: None,
            },
        );
        let m = load(&cfg);
        assert_eq!(m.len(), 2);
        assert_eq!(m["news.example.com"].connections, 12);
        assert!(!m["news.example.com"].suspect);
        assert_eq!(m["fill.example.com"].source, "manual");
        assert!(m["fill.example.com"].suspect);
        // No settings.json in the dir: the toggle defaults ON.
        assert!(enabled(&cfg));
        std::fs::write(
            cfg.with_file_name("settings.json"),
            br#"{"auto_connections":false}"#,
        )
        .unwrap();
        assert!(!enabled(&cfg));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The v1.0.14 field case, end to end on the file.
    ///
    /// A pre-guard entry (v0, no `suspect`, no `limit`) holding a knee
    /// of 6 must stop capping the moment the install's ceiling is read
    /// as 24, and must be queued for a re-probe rather than deleted -
    /// if 6 really is this provider's knee, one probe puts it back.
    #[test]
    fn a_raised_ceiling_reopens_a_low_pre_guard_knee() {
        let dir = std::env::temp_dir().join(format!("nzbfast-reopen-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = dir.join("config.local.json");
        // Exactly the shape v1.0.14 wrote: no `suspect`, no `limit`, no `v`.
        std::fs::write(
            path_for(&cfg),
            br#"{"news.newsdemon.com":{"connections":6,"granted":6,"gbps":0.24,
                 "checked":1754000000,"source":"auto"}}"#,
        )
        .unwrap();
        let before = load(&cfg);
        assert!(!before["news.newsdemon.com"].suspect, "v0 entry applies");
        assert_eq!(before["news.newsdemon.com"].v, 0);

        let moved = reopen_low_knees(&cfg, |_| Some(24));
        assert_eq!(moved, vec![("news.newsdemon.com".into(), 6, 24)]);
        let after = load(&cfg);
        let t = &after["news.newsdemon.com"];
        assert!(t.suspect, "a reopened knee must stop capping jobs");
        assert_eq!(t.checked, 0, "and must be eligible for an immediate probe");
        assert_eq!(t.limit, 24, "judged against the ceiling now in force");
        assert_eq!(t.v, SCHEMA);
        // The knee itself survives, so the re-probe has something to
        // corroborate against - deleting it would throw that away.
        assert_eq!(t.connections, 6);

        // Idempotent: the same ceiling must not reopen it a second time
        // (a settings save, or every daemon restart, would otherwise
        // re-arm a knee the probe loop had just cleared).
        assert!(reopen_low_knees(&cfg, |_| Some(24)).is_empty());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Knees the user's ceiling has NOT outgrown are left alone: a knee
    /// at or near the ceiling is the tuner agreeing with the user, and a
    /// host that isn't a configured server is none of this code's
    /// business.
    #[test]
    fn reopen_leaves_settled_knees_alone() {
        let dir = std::env::temp_dir().join(format!("nzbfast-reopen2-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = dir.join("config.local.json");
        let mk = |c: usize, limit: usize| Tuned {
            connections: c,
            granted: c,
            asked: c,
            gbps: 1.0,
            checked: 9,
            source: "auto".into(),
            suspect: false,
            limit,
            v: SCHEMA,
            pending: None,
        };
        record(&cfg, "near.example.com", mk(20, 24)); // 20 of 24: agrees
        record(&cfg, "low.example.com", mk(6, 24)); // already judged at 24
        record(&cfg, "gone.example.com", mk(2, 24)); // no longer configured
        let moved = reopen_low_knees(&cfg, |h| (h != "gone.example.com").then_some(24));
        assert!(moved.is_empty(), "nothing should have moved: {moved:?}");
        let m = load(&cfg);
        assert!(m.values().all(|t| !t.suspect));
        assert_eq!(m["gone.example.com"].checked, 9);

        // But raise the ceiling past the one they were judged at and the
        // low knee - and only the low knee - reopens: 20 of 26 is still
        // the tuner agreeing with the user, 6 of 26 is not.
        let moved = reopen_low_knees(&cfg, |h| (h != "gone.example.com").then_some(26));
        assert_eq!(moved, vec![("low.example.com".into(), 6, 26)]);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

//! TODO 112: the live connection tuner - tracking the knee in realtime.
//!
//! The offline ladder (`sysbench::conn_ladder`) measures a knee at setup
//! time; facts change (provider load, time of day, an external party on
//! the account). This module is the slow, epoch-based controller that
//! tracks it DURING real downloads: hold the fleet for an epoch, measure
//! delivered bytes, perturb by ONE connection, keep what measured
//! better. The offline knee stays the prior; the account's configured
//! `connections` is the hard ceiling and is never written by anything
//! here - the target is state, not a setting.
//!
//! Everything the offline tuner's hardening taught is baked into the
//! shape (see the conn-tuner saga: JAGGED_BAR, the test that asserted
//! the noise, CLIMB_GAIN):
//!
//! - Provider throughput swings 2-3x minute to minute, so single
//!   readings decide nothing: a probe is PAIRED A/B epochs, repeated,
//!   and judged on the median - a slow drift hits both sides of a pair
//!   where it cannot masquerade as a verdict.
//! - Asymmetric bars, both defensible against the noise floor rather
//!   than precise-looking: an up-move must EARN its socket
//!   ([`UP_GAIN`]); a down-move needs the smaller fleet to have cost
//!   nearly nothing ([`DOWN_KEEP`]).
//! - A contaminated epoch (queue ran dry, rate limiter engaged, flap
//!   clamp, capacity refusal) does not bend a verdict - it ABORTS the
//!   whole cycle. A contaminated measurement is not a slightly-wrong
//!   measurement.
//! - Never probe upward unless the last full epoch was clean: an idle
//!   queue or an engaged limiter makes "more sockets" unmeasurable, and
//!   a capacity refusal makes it hostile.
//!
//! Decisions are a pure function of the observations fed in - no I/O,
//! no clocks - so every rule here is pinned by a unit test that cannot
//! be anything else (the wave-6 lesson: the pure test was right because
//! it could not assert the noise). The wall-clock rigs in
//! `tests/live_tune.rs` only ask whether the whole thing hangs together
//! against a real pool and a mock provider.

/// Minimum relative gain a +1 connection must show (median over pairs)
/// to be kept. 4% sits above the paired-epoch noise floor the rigs can
/// defend while keeping a one-socket step detectable up to ~25
/// connections; past that a single socket's honest contribution is
/// inside the noise and the controller is DESIGNED to stop, leaving the
/// prior/ceiling in charge.
pub const UP_GAIN: f64 = 1.04;

/// A -1 connection is kept while the smaller fleet still delivers at
/// least this fraction of the larger one's rate: below the knee one
/// socket is worth ~1/M of the rate, so a genuine knee-or-below fleet
/// fails this immediately and the down-walk stops.
pub const DOWN_KEEP: f64 = 0.985;

/// Fast path for gross mistuning: if the FIRST up pair alone gains this
/// much, keep it without waiting for the remaining pairs. A fleet far
/// below the knee gains ~1/M per socket (25% at 4), which no honest
/// noise band needs three pairs to see; near the knee this never fires
/// and the full-median path decides. A noise spike that sneaks one
/// up-move through is walked back by the next down cycle - the
/// asymmetry is safe because down cycles never use the fast path.
pub const EARLY_UP_GAIN: f64 = 1.15;

/// A/B pairs per probe cycle (median-of-3, the offline run-off's
/// best-of-three carried over).
pub const PAIRS: u32 = 3;

/// One measured epoch: everything the controller is allowed to know
/// about it. The caller owns HOW these are measured (which gauges,
/// which clock); the controller only ever sees this.
#[derive(Debug, Clone, Copy)]
pub struct EpochObs {
    /// Delivered bytes / elapsed for THIS server over the epoch.
    pub rate_bps: f64,
    /// The queue had work the whole epoch - a dry or near-dry queue
    /// measures the queue, not the line.
    pub busy: bool,
    /// The global rate limiter was engaged (or the aggregate sat at its
    /// cap): the line is not the binding constraint, so socket-count
    /// verdicts are meaningless.
    pub rate_limited: bool,
    /// This server is flap-clamped or saw a capacity refusal this
    /// epoch: the provider is already saying "fewer".
    pub capacity_pressure: bool,
    /// The fleet actually reached the target it was asked to run
    /// (connected >= desired for the measuring stretch). An epoch that
    /// never reached its fleet measures the ramp, not the rung.
    pub fleet_met: bool,
}

impl EpochObs {
    fn clean(&self) -> bool {
        self.busy && !self.rate_limited && !self.capacity_pressure && self.fleet_met
    }
}

/// Which side of the current target a cycle is probing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Dir {
    Up,
    Down,
}

impl Dir {
    fn flip(self) -> Dir {
        match self {
            Dir::Up => Dir::Down,
            Dir::Down => Dir::Up,
        }
    }
}

#[derive(Debug)]
enum Phase {
    /// Sit at the kept target for `left` clean epochs before probing
    /// again - the heavy hysteresis. `next` is the direction the next
    /// cycle will try.
    Hold { left: u32, next: Dir },
    /// Mid-cycle: epochs alternate base target and base +/- 1, one pair
    /// at a time, base first (`on_probe` flips every epoch).
    Probe {
        dir: Dir,
        on_probe: bool,
        base: Vec<f64>,
        probe: Vec<f64>,
    },
}

/// Per-server live tuner. Feed it one [`EpochObs`] per epoch; read
/// [`ServerTuner::desired`] afterwards and run the fleet there for the
/// next epoch.
#[derive(Debug)]
pub struct ServerTuner {
    /// The KEPT connection count - what the controller currently
    /// believes the knee to be.
    target: usize,
    /// Hard ceiling: the account's configured `connections` (or the
    /// spawned fleet size, whichever is smaller). Never exceeded, never
    /// written here.
    ceiling: usize,
    /// Clean epochs a fresh verdict must wait out between cycles.
    hold_epochs: u32,
    phase: Phase,
}

impl ServerTuner {
    /// `prior` is the starting belief (the offline knee when one is
    /// trusted, else the configured count); `ceiling` the account fact.
    pub fn new(prior: usize, ceiling: usize, hold_epochs: u32) -> Self {
        let ceiling = ceiling.max(1);
        ServerTuner {
            target: prior.clamp(1, ceiling),
            ceiling,
            hold_epochs,
            // Down first: freeing sockets the line does not need is the
            // cheap direction, and a too-high prior is the harmful one
            // (over-asking is what providers punish).
            phase: Phase::Hold {
                left: hold_epochs,
                next: Dir::Down,
            },
        }
    }

    /// The connection count the fleet should run at for the NEXT epoch.
    /// During a probe cycle this alternates between the base target and
    /// the perturbed rung; between cycles it is the kept target.
    pub fn desired(&self) -> usize {
        match &self.phase {
            Phase::Hold { .. } => self.target,
            Phase::Probe { dir, on_probe, .. } => {
                if *on_probe {
                    match dir {
                        Dir::Up => (self.target + 1).min(self.ceiling),
                        Dir::Down => self.target.saturating_sub(1).max(1),
                    }
                } else {
                    self.target
                }
            }
        }
    }

    /// The kept target (what the controller believes, ignoring any
    /// in-flight perturbation).
    pub fn target(&self) -> usize {
        self.target
    }

    pub fn ceiling(&self) -> usize {
        self.ceiling
    }

    /// Feed the epoch that just finished, measured at the count
    /// [`ServerTuner::desired`] answered when it started.
    pub fn on_epoch(&mut self, obs: EpochObs) {
        // Capacity pressure is more than contamination: the provider
        // has vetoed the CURRENT size, so probing up is off the table
        // for a while and the belief itself steps down. This is the
        // live analogue of the 481/502 capacity yield, expressed as a
        // kept verdict instead of a one-way worker exit.
        if obs.capacity_pressure {
            self.target = self.target.saturating_sub(1).max(1);
            self.phase = Phase::Hold {
                left: self.hold_epochs.max(1) * 2,
                next: Dir::Down,
            };
            return;
        }
        if !obs.clean() {
            // A contaminated epoch aborts the cycle outright - and a
            // Hold does not tick down, so probing never starts on the
            // heels of dirt (the "never probe upward when the queue is
            // near empty / limiter engaged" rule falls out of this).
            if let Phase::Probe { .. } = self.phase {
                self.phase = Phase::Hold {
                    left: self.hold_epochs,
                    next: Dir::Down,
                };
            }
            return;
        }
        match &mut self.phase {
            Phase::Hold { left, next } => {
                if *left > 0 {
                    *left -= 1;
                    return;
                }
                let dir = *next;
                // A rung with no room in the probed direction flips.
                let dir = match dir {
                    Dir::Up if self.target >= self.ceiling => Dir::Down,
                    Dir::Down if self.target <= 1 => Dir::Up,
                    d => d,
                };
                if self.target >= self.ceiling && self.target <= 1 {
                    // ceiling 1: nothing to tune.
                    return;
                }
                self.phase = Phase::Probe {
                    dir,
                    on_probe: true, // this epoch ran at base; next runs the probe rung
                    base: vec![obs.rate_bps],
                    probe: Vec::new(),
                };
            }
            Phase::Probe {
                dir,
                on_probe,
                base,
                probe,
            } => {
                if *on_probe {
                    probe.push(obs.rate_bps);
                } else {
                    base.push(obs.rate_bps);
                }
                let dir = *dir;
                // Early keep for gross under-tuning: the first complete
                // pair alone may be unambiguous.
                let early = dir == Dir::Up
                    && base.len() == 1
                    && probe.len() == 1
                    && probe[0] >= base[0] * EARLY_UP_GAIN;
                let full = base.len() >= PAIRS as usize && probe.len() >= PAIRS as usize;
                if !(early || full) {
                    *on_probe = !*on_probe;
                    return;
                }
                let gain = median(probe) / median(base).max(1.0);
                let (kept, next) = match dir {
                    Dir::Up if gain >= UP_GAIN => (Some(self.target + 1), Dir::Up),
                    Dir::Down if gain >= DOWN_KEEP => {
                        (Some(self.target.saturating_sub(1).max(1)), Dir::Down)
                    }
                    d => (None, d.flip()),
                };
                if let Some(t) = kept {
                    self.target = t.clamp(1, self.ceiling);
                    // Momentum: a kept move re-probes the same
                    // direction immediately - a grossly mistuned fleet
                    // walks to the knee in consecutive cycles instead
                    // of one step per hold window.
                    self.phase = Phase::Hold { left: 0, next };
                } else {
                    self.phase = Phase::Hold {
                        left: self.hold_epochs,
                        next,
                    };
                }
            }
        }
    }
}

fn median(xs: &[f64]) -> f64 {
    let mut v: Vec<f64> = xs.to_vec();
    v.sort_by(|a, b| a.total_cmp(b));
    if v.is_empty() {
        return 0.0;
    }
    let mid = v.len() / 2;
    if v.len() % 2 == 1 {
        v[mid]
    } else {
        (v[mid - 1] + v[mid]) / 2.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A provider model in one closure: rate for a fleet of `m` on a
    /// line whose knee is `knee`, with a deterministic "noise" wobble
    /// per epoch so no verdict can lean on exact equality. The wobble
    /// (+/-2%) is BELOW both bars on purpose - these tests pin the
    /// decision rules, the rigs pin behaviour under real jitter.
    fn drive(t: &mut ServerTuner, knee: usize, epochs: usize, seed: &mut u32) {
        for _ in 0..epochs {
            let m = t.desired();
            let r = (m.min(knee)) as f64 * 1_000_000.0;
            // xorshift, deterministic: +/-2%.
            *seed ^= *seed << 13;
            *seed ^= *seed >> 17;
            *seed ^= *seed << 5;
            let wobble = 1.0 + ((*seed % 400) as f64 - 200.0) / 10_000.0;
            t.on_epoch(EpochObs {
                rate_bps: r * wobble,
                busy: true,
                rate_limited: false,
                capacity_pressure: false,
                fleet_met: true,
            });
        }
    }

    #[test]
    fn converges_up_from_a_low_prior() {
        let mut t = ServerTuner::new(4, 30, 2);
        let mut seed = 0x1234_5678;
        drive(&mut t, 12, 400, &mut seed);
        assert!(
            (11..=13).contains(&t.target()),
            "stopped at {} against a knee of 12",
            t.target()
        );
    }

    #[test]
    fn converges_down_from_a_high_prior() {
        let mut t = ServerTuner::new(24, 30, 2);
        let mut seed = 0x0dd_ba11;
        drive(&mut t, 12, 400, &mut seed);
        assert!(
            (11..=13).contains(&t.target()),
            "stopped at {} against a knee of 12",
            t.target()
        );
    }

    /// The no-oscillation gate in pure form: a fleet already at the
    /// knee on a flat healthy line must not walk anywhere, however long
    /// it runs - the noise-chasing failure the offline tuner's history
    /// warns about.
    #[test]
    fn a_flat_line_at_the_knee_holds_steady() {
        let mut t = ServerTuner::new(12, 30, 2);
        let mut seed = 0xbeef_cafe;
        for _ in 0..10 {
            drive(&mut t, 12, 100, &mut seed);
            assert!(
                (11..=13).contains(&t.target()),
                "walked to {} on a flat line",
                t.target()
            );
        }
    }

    /// The ceiling is the account fact: however hungry the line, the
    /// controller never asks past it - and a prior above it is clamped
    /// on construction.
    #[test]
    fn the_ceiling_is_absolute() {
        let mut t = ServerTuner::new(50, 8, 2);
        assert_eq!(t.target(), 8);
        let mut seed = 0x5eed;
        drive(&mut t, 100, 300, &mut seed); // knee far above the ceiling
        assert_eq!(t.target(), 8);
        assert!(t.desired() <= 8);
    }

    /// Dirty epochs decide nothing and abort in-flight cycles: feed a
    /// mistuned fleet nothing but starved epochs and it must not move.
    #[test]
    fn starved_or_limited_epochs_never_move_the_target() {
        for (busy, limited) in [(false, false), (true, true)] {
            let mut t = ServerTuner::new(4, 30, 2);
            for _ in 0..100 {
                let m = t.desired();
                t.on_epoch(EpochObs {
                    rate_bps: m as f64 * 1_000_000.0,
                    busy,
                    rate_limited: limited,
                    capacity_pressure: false,
                    fleet_met: true,
                });
            }
            assert_eq!(t.target(), 4, "moved on dirty epochs (busy={busy})");
        }
    }

    /// Capacity pressure steps the belief DOWN and parks the tuner -
    /// the provider said "fewer", which outranks any measurement.
    #[test]
    fn capacity_pressure_steps_down_and_holds() {
        let mut t = ServerTuner::new(12, 30, 2);
        t.on_epoch(EpochObs {
            rate_bps: 0.0,
            busy: true,
            rate_limited: false,
            capacity_pressure: true,
            fleet_met: false,
        });
        assert_eq!(t.target(), 11);
        assert_eq!(t.desired(), 11);
    }

    /// Rig 2 in pure form: the line's capacity changes mid-run and the
    /// controller re-converges - the facts-on-the-ground-changed case.
    #[test]
    fn reconverges_when_the_knee_moves() {
        let mut t = ServerTuner::new(6, 30, 2);
        let mut seed = 0x00c0_ffee;
        drive(&mut t, 6, 300, &mut seed);
        assert!((5..=7).contains(&t.target()), "phase 1: {}", t.target());
        // The provider frees capacity: the knee doubles.
        drive(&mut t, 14, 500, &mut seed);
        assert!(
            (13..=15).contains(&t.target()),
            "did not follow the knee up: {}",
            t.target()
        );
        // And tightens again.
        drive(&mut t, 8, 500, &mut seed);
        assert!(
            (7..=9).contains(&t.target()),
            "did not follow the knee down: {}",
            t.target()
        );
    }

    /// A ceiling of one is not tunable and must simply sit still.
    #[test]
    fn a_single_connection_account_is_left_alone() {
        let mut t = ServerTuner::new(1, 1, 2);
        let mut seed = 3;
        drive(&mut t, 10, 100, &mut seed);
        assert_eq!(t.target(), 1);
        assert_eq!(t.desired(), 1);
    }
}

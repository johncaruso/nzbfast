//! §125: the throughput graph's 100% line - learn the link's real peak.
//!
//! The graph used to scale to whatever the visible window happened to
//! contain, so "how are we doing" had no fixed answer: a line hugging
//! the top might be a saturated 10 Gbit link or a bad hour on a 1 Gbit
//! one. The anchor this module learns gives the chart a stable
//! definition of 100%: the best rate this link has actually sustained.
//! Working well then LOOKS like working well - a band riding the top -
//! and a shortfall is legible as the gap it is.
//!
//! Three sources, in order of authority:
//!
//! 1. MEASURED: the best 30 s sustained rate ever observed, persisted
//!    to .spool/linkpeak.json (the same measure-then-remember shape as
//!    the connection knee in conntune.json). Observation is the truth.
//! 2. LINE: the Settings line speed. It seeds the anchor so the graph
//!    is honest from the first download - but it is a PRIOR, and it
//!    only rules while no measurement has either beaten it or gathered
//!    enough evidence against it (see `invalidated_line_bps`).
//! 3. Nothing: anchor unknown, the dashboard keeps its old
//!    scale-to-window behaviour.
//!
//! Learning is deliberately asymmetric. Raising is instant: a sustained
//! window above the anchor is proof the link can do it (a VU meter
//! never clips the incoming spike). Lowering needs HOURS of evidence:
//! being below peak while downloading is normal - small-job tails,
//! provider ceilings, a slow remote - so only a long stretch of
//! full-effort, unthrottled downloading that never comes near the
//! anchor is allowed to pull it down. Semi-permanent, in other words:
//! the anchor moves only when future measurements invalidate it.
//!
//! What never counts as evidence: seconds with a user speed limit in
//! force below the anchor (a throttled line cannot demonstrate
//! anything), and seconds with no bytes moving (a stalled provider is
//! a provider problem, not a link measurement).

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Instant;

use crate::MutexExt;

/// A "sustained" rate is the average over this many consecutive
/// countable seconds. Long enough to flatten the write-side sawtooth
/// and per-article jitter, short enough that a real peak inside an
/// ordinary download registers.
const SUSTAIN_SECS: usize = 30;

/// A sustained window at or above this fraction of the anchor counts as
/// the link confirming it, and resets the down-learn clock. 90%, not
/// 100%: riding within a TLS-overhead of the peak is the peak.
const CONFIRM_BAR: f64 = 0.9;

/// Full-effort active seconds below the confirm bar before the anchor
/// lowers to the best rate that stretch actually reached. Three hours
/// of unthrottled downloading that never came within 10% of the anchor
/// is evidence about the LINK, not about one job.
const DOWNLEARN_SECS: u64 = 3 * 3600;

/// Raise only past this margin, so jitter exactly at the peak does not
/// churn the stored value (and its persist) every window.
const RAISE_MARGIN: f64 = 1.01;

/// Persist a raise at most this often; the final value always lands on
/// the next quiet tick. Lowerings persist immediately - they carry three
/// hours of evidence and happen once.
const SAVE_MIN_SECS: u64 = 30;

/// What linkpeak.json holds.
#[derive(Serialize, Deserialize, Default, Clone, Debug)]
pub struct Stored {
    /// Best sustained rate measured on this link, bytes/sec. 0 = no
    /// measurement yet.
    #[serde(default)]
    pub measured_bps: u64,
    /// Unix time of the last change, for the curious reading the file.
    #[serde(default)]
    pub checked: u64,
    /// The Settings line speed this learner gathered DOWNLEARN_SECS of
    /// evidence against. While the setting still holds this exact
    /// value, the (lower) measurement rules the anchor; the moment the
    /// user types a DIFFERENT line speed, that new declaration becomes
    /// a live prior again and gets its own chance. Retyping after an
    /// ISP upgrade therefore reseeds the graph instantly instead of
    /// arguing with stale evidence about the old plan.
    #[serde(default)]
    pub invalidated_line_bps: u64,
}

/// The learner, pure of IO so tests can drive it a simulated second at
/// a time.
#[derive(Default)]
pub(super) struct Core {
    pub(super) stored: Stored,
    /// The last up-to-SUSTAIN_SECS countable samples, bytes/sec.
    /// Cleared by any non-countable second, so a full window really is
    /// consecutive.
    win: VecDeque<f64>,
    /// Best sustained rate since the anchor was last confirmed/changed.
    best_since_confirm: f64,
    /// Countable full-window seconds since then - the down-learn clock.
    active_secs: u64,
}

impl Core {
    /// The anchor the dashboard should treat as 100%, and where it came
    /// from: ("measured" | "line"), or (0, "") when nothing is known.
    pub(super) fn effective(&self, line_bps: u64) -> (u64, &'static str) {
        let m = self.stored.measured_bps;
        if m > 0 && (line_bps == 0 || m >= line_bps || self.stored.invalidated_line_bps == line_bps)
        {
            (m, "measured")
        } else if line_bps > 0 {
            (line_bps, "line")
        } else {
            (0, "")
        }
    }

    /// Feed one second of observation. Returns true when `stored`
    /// changed and should (eventually) be persisted.
    pub(super) fn step(&mut self, bps: f64, throttle_bps: u64, line_bps: u64) -> bool {
        let (anchor, _) = self.effective(line_bps);
        // A user speed limit below (or near) the anchor makes every
        // sample a measurement of the limiter. Near, not just below:
        // a cap AT the anchor still clips the peaks that would confirm
        // it, so give it 5% of air before trusting the samples again.
        if throttle_bps > 0 && (throttle_bps as f64) < anchor as f64 * 1.05 {
            self.win.clear();
            return false;
        }
        if bps <= 0.0 {
            self.win.clear();
            return false;
        }
        self.win.push_back(bps);
        if self.win.len() > SUSTAIN_SECS {
            self.win.pop_front();
        }
        if self.win.len() < SUSTAIN_SECS {
            return false;
        }
        let sustained = self.win.iter().sum::<f64>() / self.win.len() as f64;
        self.active_secs += 1;
        self.best_since_confirm = self.best_since_confirm.max(sustained);
        if anchor == 0 || sustained > anchor as f64 * RAISE_MARGIN {
            // Demonstrated. Raise instantly (or record the very first
            // measurement); the graph rescales and stays there.
            self.stored.measured_bps = sustained as u64;
            self.reset_clock();
            true
        } else if sustained >= anchor as f64 * CONFIRM_BAR {
            // The link just showed it can still do (about) the anchor.
            self.reset_clock();
            false
        } else if self.active_secs >= DOWNLEARN_SECS && self.best_since_confirm > 0.0 {
            // Hours of full-effort downloading never came near the
            // anchor: the real peak is what that stretch actually
            // reached. If a typed line speed was ruling, it is the
            // thing being disowned - remember which value, so only THAT
            // declaration stays overridden.
            if line_bps > 0 && (self.best_since_confirm as u64) < line_bps {
                self.stored.invalidated_line_bps = line_bps;
            }
            self.stored.measured_bps = self.best_since_confirm as u64;
            self.reset_clock();
            true
        } else {
            false
        }
    }

    fn reset_clock(&mut self) {
        self.best_since_confirm = 0.0;
        self.active_secs = 0;
    }
}

/// The daemon-facing wrapper: Core behind a lock, plus load/persist.
pub struct LinkPeak {
    core: Mutex<Core>,
    path: PathBuf,
    /// (last persist instant, dirty) - raises are throttled to
    /// SAVE_MIN_SECS, and `dirty` makes sure the settled value lands on
    /// a later tick instead of staying memory-only.
    save: Mutex<(Option<Instant>, bool)>,
}

impl LinkPeak {
    pub fn load(path: PathBuf) -> Self {
        let stored = crate::persist::load_json_with_backup(&path)
            .and_then(|v| serde_json::from_value::<Stored>(v).ok())
            .unwrap_or_default();
        LinkPeak {
            core: Mutex::new(Core {
                stored,
                ..Core::default()
            }),
            path,
            save: Mutex::new((None, false)),
        }
    }

    /// The dashboard's 100% anchor - see [`Core::effective`].
    pub fn effective(&self, line_bps: u64) -> (u64, &'static str) {
        self.core.lock_ok().effective(line_bps)
    }

    /// One second of observation from the ticker.
    pub fn tick(&self, bps: f64, throttle_bps: u64, line_bps: u64) {
        let (changed, lowered, snapshot) = {
            let mut c = self.core.lock_ok();
            let before = c.stored.measured_bps;
            let changed = c.step(bps, throttle_bps, line_bps);
            if changed {
                c.stored.checked = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
            }
            (
                changed,
                changed && c.stored.measured_bps < before,
                c.stored.clone(),
            )
        };
        let mut save = self.save.lock_ok();
        let due = changed
            && (lowered
                || save
                    .0
                    .is_none_or(|t| t.elapsed().as_secs() >= SAVE_MIN_SECS));
        // A raise inside the throttle window only marks dirty; the next
        // tick past the window writes the settled value.
        if changed && !due {
            save.1 = true;
        }
        let flush_dirty = save.1
            && save
                .0
                .is_none_or(|t| t.elapsed().as_secs() >= SAVE_MIN_SECS);
        if due || flush_dirty {
            *save = (Some(Instant::now()), false);
            drop(save);
            if let Ok(bytes) = serde_json::to_vec_pretty(&snapshot) {
                let _ = crate::persist::write_atomic(&self.path, &bytes);
            }
        }
    }
}

/// The 1 s ticker. Reads the same rolling speed window the queue API
/// serves, so the learner and the readout can never disagree about what
/// the link was doing.
pub(super) fn spawn(daemon: &std::sync::Arc<super::daemon::Daemon>) {
    use std::sync::atomic::Ordering;
    let d = daemon.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            let bps = d.current_speed_bps();
            let throttle = d.hub.rate.get();
            let line = d.line_speed.load(Ordering::Relaxed);
            d.link_peak.tick(bps, throttle, line);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(c: &mut Core, secs: usize, bps: f64, throttle: u64, line: u64) {
        for _ in 0..secs {
            c.step(bps, throttle, line);
        }
    }

    #[test]
    fn first_sustained_window_becomes_the_measurement() {
        let mut c = Core::default();
        run(&mut c, SUSTAIN_SECS - 1, 100e6, 0, 0);
        assert_eq!(c.effective(0), (0, ""), "no anchor before a full window");
        c.step(100e6, 0, 0);
        assert_eq!(c.effective(0), (100_000_000, "measured"));
    }

    #[test]
    fn line_speed_seeds_until_measurement_beats_it() {
        let mut c = Core::default();
        let line = 1_000_000_000;
        run(&mut c, SUSTAIN_SECS + 10, 500e6, 0, line);
        // Below the seed: the typed number still rules the anchor, and
        // nothing is stored yet - a rate under the prior is not a
        // measurement of the link until the down-learn evidence says so.
        assert_eq!(c.effective(line), (line, "line"));
        assert_eq!(c.stored.measured_bps, 0);
        // Above the seed: observation takes over instantly.
        run(&mut c, SUSTAIN_SECS, 1.2e9, 0, line);
        assert_eq!(c.effective(line), (1_200_000_000, "measured"));
    }

    #[test]
    fn hours_below_the_seed_disown_it() {
        let mut c = Core::default();
        let line = 1_000_000_000;
        run(
            &mut c,
            SUSTAIN_SECS + DOWNLEARN_SECS as usize,
            500e6,
            0,
            line,
        );
        assert_eq!(
            c.effective(line),
            (500_000_000, "measured"),
            "three active hours of evidence lower the anchor"
        );
        assert_eq!(c.stored.invalidated_line_bps, line);
        // A DIFFERENT typed value is a fresh declaration and seeds again.
        assert_eq!(c.effective(2_000_000_000), (2_000_000_000, "line"));
    }

    #[test]
    fn confirming_windows_reset_the_downlearn_clock() {
        let mut c = Core::default();
        run(&mut c, SUSTAIN_SECS, 1e9, 0, 0);
        assert_eq!(c.stored.measured_bps, 1_000_000_000);
        // Alternate long slow stretches with an occasional confirming
        // window; the clock never accumulates DOWNLEARN_SECS.
        for _ in 0..5 {
            run(&mut c, (DOWNLEARN_SECS / 2) as usize, 500e6, 0, 0);
            run(&mut c, SUSTAIN_SECS, 950e6, 0, 0);
        }
        assert_eq!(
            c.effective(0),
            (1_000_000_000, "measured"),
            "an anchor the link keeps confirming does not decay"
        );
    }

    #[test]
    fn throttled_and_idle_seconds_are_not_evidence() {
        let mut c = Core::default();
        run(&mut c, SUSTAIN_SECS, 1e9, 0, 0);
        // A 100 MB/s user cap: three "hours" at the cap teach nothing.
        run(&mut c, DOWNLEARN_SECS as usize + 100, 100e6, 100_000_000, 0);
        assert_eq!(c.effective(0), (1_000_000_000, "measured"));
        // Idle seconds break the window: 29 fast samples, a stall, 29
        // more - never a sustained window, never a raise.
        let mut c2 = Core::default();
        run(&mut c2, SUSTAIN_SECS - 1, 2e9, 0, 0);
        c2.step(0.0, 0, 0);
        run(&mut c2, SUSTAIN_SECS - 1, 2e9, 0, 0);
        assert_eq!(c2.effective(0), (0, ""));
    }

    #[test]
    fn jitter_at_the_peak_does_not_churn_the_store() {
        let mut c = Core::default();
        run(&mut c, SUSTAIN_SECS, 1e9, 0, 0);
        let anchored = c.stored.measured_bps;
        // Riding within the raise margin: confirmed, not rewritten.
        let mut changes = 0;
        for _ in 0..100 {
            if c.step(1.005e9, 0, 0) {
                changes += 1;
            }
        }
        assert_eq!(changes, 0);
        assert_eq!(c.stored.measured_bps, anchored);
    }
}

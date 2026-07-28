//! Does parking connections actually help THIS link? (§36)
//!
//! The warm pool is off by default and settled per server, because the
//! answer is a property of the link and we cannot know a user's link. This
//! measures it on their own machine and returns a verdict they can act on.
//!
//! **What is measured, and why not whole downloads.** Benchmarking whole
//! jobs is what we tried first: on a real Starlink link, 60 paired
//! repetitions over about two hours still could not separate the arms
//! (-0.1%, CI -6.2% to +5.9%), because the link's own jitter is far larger
//! than the 1-2 s the pool saves. No user will wait two hours per server,
//! and at any bearable repetition count that approach reports noise as a
//! verdict.
//!
//! So this measures only what the pool actually changes: **the time to a
//! usable connection**, fresh versus claimed. That isolates the TCP
//! handshake, the TLS handshake, two sequential AUTHINFO round-trips and
//! the slow-start ramp, with far less variance than a download, so it
//! needs few samples and finishes in seconds.
//!
//! **Statistics, each rule learned from getting it wrong.**
//!
//! - Samples are PAIRED and ALTERNATED. An unpaired comparison on a
//!   variable link is worthless - we measured a 2.5x spread on identical
//!   bytes - and a fixed arm order lets drift masquerade as a result.
//! - The verdict rests on a CONFIDENCE INTERVAL, never a point estimate.
//!   A point estimate from few samples is exactly how an interim read
//!   showed -5.9% and then reversed.
//! - Inconclusive resolves to OFF. An interval spanning zero means "no
//!   measurable benefit here", which is a recommendation to leave it off,
//!   not an invitation to round in favour.
//!
//! **What this deliberately does NOT measure: whether pooling is SAFE on
//! this link.** It times connections; it cannot see a provider's
//! simultaneous-IP cap. On a multi-WAN host - the Antigua box runs three
//! Starlink WANs - outbound connections can leave from different source
//! addresses, and a provider that caps simultaneous IPs (Giganews) then
//! refuses. Parked connections make that WORSE, because they hold their
//! slots between jobs instead of releasing them.
//!
//! So a "worthwhile" verdict for such a provider on such a host is a
//! measurement of latency that is true and a recommendation that is
//! wrong. Pin the provider's egress to one WAN (`bind_ip`) before
//! trusting this for it, or leave that server's pool off regardless of
//! what the numbers say. The verdict is advice about speed, never a
//! clearance to hold connections open.

use std::time::{Duration, Instant};

use crate::config::ServerConfig;
use crate::nntp::Connection;

/// What the measurement concluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Claiming a parked connection is faster by a margin the samples
    /// actually support.
    Worthwhile,
    /// The interval spans zero: no measurable benefit on this link.
    /// Resolves to OFF - this is the honest answer, not a failure.
    NoMeasurableBenefit,
    /// The link could not be measured at all (every connect failed).
    Failed,
}

/// One server's result, in the terms the UI reports.
#[derive(Debug, Clone)]
pub struct BenchResult {
    pub verdict: Verdict,
    /// Paired samples that produced a usable delta.
    pub samples: usize,
    /// Median milliseconds to a usable connection, fresh.
    pub fresh_ms: f64,
    /// Median milliseconds to a usable connection, claimed from the pool.
    pub warm_ms: f64,
    /// Mean paired saving in ms (positive = warm is faster), with the
    /// 95% interval that decided the verdict.
    pub saved_ms: f64,
    pub ci_low_ms: f64,
    pub ci_high_ms: f64,
    /// Why, in one line, for the UI to show verbatim.
    pub detail: String,
}

impl BenchResult {
    /// The recommendation, as the setting value the user would store.
    pub fn recommends_on(&self) -> bool {
        self.verdict == Verdict::Worthwhile
    }
}

/// Paired samples to take. Enough for the interval to mean something on a
/// steady link, few enough that the whole run is seconds: each pair costs
/// roughly two connects.
pub const PAIRS: usize = 12;

/// A pair is discarded if either arm takes longer than this - a stall is
/// not a measurement, and letting one land would swamp the mean.
const ARM_TIMEOUT: Duration = Duration::from_secs(20);

/// Student's t for 95% two-sided, by degrees of freedom (n-1), clamped at
/// the tail to the normal approximation. Small-sample intervals must not
/// use 1.96 - with n=12 that understates the interval by ~12%, which is
/// exactly the direction that would turn noise into a recommendation.
fn t_95(df: usize) -> f64 {
    const T: [f64; 30] = [
        12.706, 4.303, 3.182, 2.776, 2.571, 2.447, 2.365, 2.306, 2.262, 2.228, 2.201, 2.179,
        2.160, 2.145, 2.131, 2.120, 2.110, 2.101, 2.093, 2.086, 2.080, 2.074, 2.069, 2.064,
        2.060, 2.056, 2.052, 2.048, 2.045, 2.042,
    ];
    match df {
        0 => f64::INFINITY,
        d if d <= 30 => T[d - 1],
        _ => 1.96,
    }
}

fn median(xs: &mut [f64]) -> f64 {
    if xs.is_empty() {
        return 0.0;
    }
    xs.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let n = xs.len();
    match n % 2 {
        1 => xs[n / 2],
        _ => (xs[n / 2 - 1] + xs[n / 2]) / 2.0,
    }
}

/// Decide from paired deltas (ms, positive = warm faster).
///
/// Split out from the I/O so the statistics are testable without a
/// server: this is the part that must not be got wrong.
pub fn verdict_from_deltas(deltas: &[f64]) -> (Verdict, f64, f64, f64) {
    let n = deltas.len();
    if n < 3 {
        return (Verdict::Failed, 0.0, 0.0, 0.0);
    }
    let mean = deltas.iter().sum::<f64>() / n as f64;
    let var = deltas.iter().map(|d| (d - mean).powi(2)).sum::<f64>() / (n as f64 - 1.0);
    let se = (var / n as f64).sqrt();
    let half = t_95(n - 1) * se;
    let (lo, hi) = (mean - half, mean + half);
    // Worthwhile only when the whole interval is on the faster side. An
    // interval touching zero is "no measurable benefit", which is OFF.
    let verdict = match lo > 0.0 {
        true => Verdict::Worthwhile,
        false => Verdict::NoMeasurableBenefit,
    };
    (verdict, mean, lo, hi)
}

/// Time a fresh connect to the point the connection is USABLE: greeting
/// read and AUTHINFO complete, which is what a caller waits for.
async fn time_fresh(server: &ServerConfig) -> Option<(Duration, Connection)> {
    let t0 = Instant::now();
    let conn = tokio::time::timeout(ARM_TIMEOUT, Connection::connect(server))
        .await
        .ok()?
        .ok()?
        .0;
    Some((t0.elapsed(), conn))
}

/// Time claiming an already-open connection: the DATE validation the warm
/// pool does on checkout, which is the whole cost of a hit.
async fn time_claim(conn: &mut Connection) -> Option<Duration> {
    let t0 = Instant::now();
    tokio::time::timeout(ARM_TIMEOUT, conn.exec("DATE")).await.ok()?.ok()?;
    Some(t0.elapsed())
}

/// Measure one server. Alternates which arm goes first on every pair so
/// drift cannot accumulate into one of them.
pub async fn measure(server: &ServerConfig, pairs: usize) -> BenchResult {
    let mut deltas = Vec::with_capacity(pairs);
    let mut fresh_all = Vec::with_capacity(pairs);
    let mut warm_all = Vec::with_capacity(pairs);

    // Give up early on a server that is not answering, rather than
    // spending `pairs` x ARM_TIMEOUT on it. Without this a black-holed
    // host burns four minutes and then reports "timed out", which reads
    // as our failure rather than as its own - and a caller's ceiling
    // would cut it off before the verdict was ever formed.
    let mut consecutive_failures = 0usize;
    const GIVE_UP_AFTER: usize = 3;

    for i in 0..pairs {
        if consecutive_failures >= GIVE_UP_AFTER && deltas.is_empty() {
            break;
        }
        // A held-open connection stands in for a parked one: claiming it
        // costs exactly what a pool hit costs (one DATE round-trip).
        let Some((fresh_a, mut held)) = time_fresh(server).await else {
            consecutive_failures += 1;
            continue;
        };
        let warm = match i % 2 {
            // Alternate: on odd pairs the claim is timed BEFORE the
            // second fresh connect, on even pairs after.
            0 => time_claim(&mut held).await,
            _ => {
                let w = time_claim(&mut held).await;
                let _ = time_fresh(server).await;
                w
            }
        };
        let Some(warm) = warm else {
            held.quit().await;
            consecutive_failures += 1;
            continue;
        };
        held.quit().await;
        consecutive_failures = 0;

        let f = fresh_a.as_secs_f64() * 1000.0;
        let w = warm.as_secs_f64() * 1000.0;
        fresh_all.push(f);
        warm_all.push(w);
        deltas.push(f - w);
    }

    let (verdict, mean, lo, hi) = verdict_from_deltas(&deltas);
    let fresh_ms = median(&mut fresh_all.clone());
    let warm_ms = median(&mut warm_all.clone());
    let detail = match verdict {
        Verdict::Failed => {
            "could not measure this server - no connection completed".to_string()
        }
        Verdict::NoMeasurableBenefit => format!(
            "no measurable benefit on this link: {mean:.0} ms saved per connection, \
             but the range ({lo:.0} to {hi:.0} ms) includes zero, so leave it off"
        ),
        Verdict::Worthwhile => format!(
            "saves about {mean:.0} ms per connection (range {lo:.0} to {hi:.0} ms), \
             on top of keeping the connection's built-up speed"
        ),
    };
    BenchResult {
        verdict,
        samples: deltas.len(),
        fresh_ms,
        warm_ms,
        saved_ms: mean,
        ci_low_ms: lo,
        ci_high_ms: hi,
        detail,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The rule that matters: an interval touching zero is OFF. This is
    /// the guard against the interim read that showed -5.9% and reversed.
    #[test]
    fn an_interval_spanning_zero_is_never_a_recommendation() {
        // Big mean, but wildly variable - exactly the Starlink shape.
        let noisy = vec![120.0, -80.0, 200.0, -150.0, 90.0, -60.0, 30.0, -40.0];
        let (v, _, lo, hi) = verdict_from_deltas(&noisy);
        assert_eq!(v, Verdict::NoMeasurableBenefit);
        assert!(lo < 0.0 && hi > 0.0, "interval should span zero: {lo}..{hi}");
    }

    /// A steady, real saving is recognised.
    #[test]
    fn a_consistent_saving_is_recommended() {
        let steady: Vec<f64> = vec![210.0, 195.0, 205.0, 220.0, 198.0, 207.0, 212.0, 201.0];
        let (v, mean, lo, _) = verdict_from_deltas(&steady);
        assert_eq!(v, Verdict::Worthwhile);
        assert!(mean > 190.0 && lo > 0.0);
    }

    /// A consistent LOSS must never read as a benefit.
    #[test]
    fn a_consistent_loss_is_not_a_benefit() {
        let worse: Vec<f64> = vec![-30.0, -28.0, -35.0, -31.0, -29.0, -33.0];
        let (v, mean, _, hi) = verdict_from_deltas(&worse);
        assert_eq!(v, Verdict::NoMeasurableBenefit);
        assert!(mean < 0.0 && hi < 0.0, "a clear loss: {mean} ({hi})");
    }

    /// Too few samples cannot produce a verdict at all.
    #[test]
    fn too_few_samples_is_failed_not_a_guess() {
        assert_eq!(verdict_from_deltas(&[]).0, Verdict::Failed);
        assert_eq!(verdict_from_deltas(&[500.0]).0, Verdict::Failed);
        assert_eq!(verdict_from_deltas(&[500.0, 480.0]).0, Verdict::Failed);
    }

    /// Small samples must use Student's t, not 1.96. With n=12 the normal
    /// approximation understates the interval by ~12%, and that error runs
    /// in the direction that turns noise into a recommendation.
    #[test]
    fn small_samples_use_the_t_distribution() {
        assert!(t_95(11) > 2.1, "t for n=12 should be ~2.20, got {}", t_95(11));
        assert!(t_95(1) > 12.0, "t for n=2 is very wide");
        assert_eq!(t_95(100), 1.96, "large samples converge on the normal");

        // A borderline set that t calls inconclusive and 1.96 would not.
        let d: Vec<f64> = vec![
            40.0, -5.0, 60.0, 10.0, 55.0, -10.0, 45.0, 5.0, 50.0, 0.0, 35.0, 15.0,
        ];
        let (v, mean, lo, _) = verdict_from_deltas(&d);
        assert!(mean > 0.0, "the point estimate favours warm: {mean}");
        let n = d.len() as f64;
        let var = d.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (n - 1.0);
        let se = (var / n).sqrt();
        assert!(
            mean - 1.96 * se > lo,
            "the normal interval must be narrower than the t interval"
        );
        let _ = v;
    }
}

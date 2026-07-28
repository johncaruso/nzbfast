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
//!   Alternated means the order INSIDE the pair changes: half the pairs
//!   time fresh and then warm, half time warm and then fresh, so a link
//!   that is steadily slowing cannot charge the whole of that trend to
//!   one arm.
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
/// steady link, few enough that the whole run is seconds: a pair costs one
/// connect, or two on the pairs that time the claim first.
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

/// Measure one server. Alternates which arm of the pair is timed FIRST,
/// so drift cannot accumulate into one of them. Odd pairs pay for that
/// with an extra connect: something has to be open before it can be
/// claimed, and on those pairs that opening connect's timing is thrown
/// away in favour of a fresh connect taken after the claim.
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
        // costs exactly what a pool hit costs (one DATE round-trip). The
        // connect that opens it is only the pair's fresh arm when the
        // fresh arm is the one going first.
        let Some((fresh_a, mut held)) = time_fresh(server).await else {
            consecutive_failures += 1;
            continue;
        };
        // Alternate which arm of the PAIR is timed first, so monotonic
        // drift lands on fresh on half the pairs and on warm on the other
        // half instead of biasing every delta the same way.
        let timed = match i % 2 {
            // Even: fresh went first, and it is the connect above. The
            // claim on the connection it opened follows it.
            0 => {
                let w = time_claim(&mut held).await;
                held.quit().await;
                w.map(|w| (fresh_a, w))
            }
            // Odd: warm goes first. The connect above only exists to have
            // something to claim, so its timing is DISCARDED; the fresh
            // arm is a second connect taken after the claim. The held
            // connection is closed before it, so both arms are measured
            // with the same number of our own sessions open.
            _ => {
                let w = time_claim(&mut held).await;
                held.quit().await;
                match w {
                    // A failed claim leaves nothing to pair a fresh arm
                    // with, so do not pay for the second connect at all.
                    None => None,
                    Some(w) => match time_fresh(server).await {
                        Some((fresh_b, second)) => {
                            // QUIT it rather than dropping it: an
                            // abandoned socket holds a provider slot
                            // until it times out, and the next pair may
                            // need that slot.
                            second.quit().await;
                            Some((fresh_b, w))
                        }
                        None => None,
                    },
                }
            }
        };
        let Some((fresh, warm)) = timed else {
            consecutive_failures += 1;
            continue;
        };
        consecutive_failures = 0;

        let f = fresh.as_secs_f64() * 1000.0;
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
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    /// The smallest server [`measure`] can be run against: greeting,
    /// DATE, QUIT, nothing else. Connections numbered `slow_from` and
    /// later (1-based, in accept order) sit on `delay` before sending
    /// their greeting.
    ///
    /// That delay is what makes the arm ORDER observable from outside:
    /// the pair's fresh arm is either the connect that opened the
    /// connection to claim, or a later one taken after the claim, and
    /// only the second of those lands on a slowed connection.
    struct GreetingRig {
        cfg: ServerConfig,
        accepted: Arc<AtomicUsize>,
        _task: tokio::task::JoinHandle<()>,
    }

    async fn greeting_rig(slow_from: usize, delay: Duration) -> GreetingRig {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        let seen = accepted.clone();
        let task = tokio::spawn(async move {
            while let Ok((sock, _)) = listener.accept().await {
                let n = seen.fetch_add(1, Ordering::SeqCst) + 1;
                tokio::spawn(async move {
                    if n >= slow_from {
                        tokio::time::sleep(delay).await;
                    }
                    let (r, mut w) = sock.into_split();
                    if w.write_all(b"200 rig ready\r\n").await.is_err() {
                        return;
                    }
                    let mut lines = BufReader::new(r).lines();
                    while let Ok(Some(line)) = lines.next_line().await {
                        let up = line.trim().to_ascii_uppercase();
                        let quit = up.starts_with("QUIT");
                        let reply: &[u8] = match () {
                            _ if quit => b"205 bye\r\n",
                            _ if up.starts_with("DATE") => b"111 20260727120000\r\n",
                            _ => b"500 unknown\r\n",
                        };
                        if w.write_all(reply).await.is_err() || quit {
                            return;
                        }
                    }
                });
            }
        });
        // Built through serde so the rig keeps compiling when a field is
        // added to ServerConfig: everything but the host has a default.
        let cfg: ServerConfig = serde_json::from_str(&format!(
            r#"{{"host":"{}","port":{},"tls":false}}"#,
            addr.ip(),
            addr.port()
        ))
        .unwrap();
        GreetingRig { cfg, accepted, _task: task }
    }

    /// The alternation the module doc promises has to be REAL: on the
    /// pairs that time the claim first, the fresh arm must be the connect
    /// taken AFTER it, not the one that opened the claimed connection.
    /// Regression: those pairs used to make the second connect, throw its
    /// timing away and record the first one, so fresh was measured first
    /// on every single pair and steady drift biased every delta the same
    /// way.
    ///
    /// Two pairs, and only the third connection is slowed. Pair 0 times
    /// fresh first (connection 1, fast). Pair 1 times the claim first
    /// (on connection 2, fast) and its fresh arm is connection 3, the
    /// slow one - so the recorded fresh median must carry that delay.
    #[tokio::test(flavor = "multi_thread")]
    async fn the_fresh_arm_of_a_warm_first_pair_is_the_later_connect() {
        let rig = greeting_rig(3, Duration::from_millis(1500)).await;
        let r = measure(&rig.cfg, 2).await;

        assert_eq!(r.samples, 2, "both pairs should have produced a delta");
        assert_eq!(
            rig.accepted.load(Ordering::SeqCst),
            3,
            "one connect for the fresh-first pair, two for the warm-first pair"
        );
        // Median of two samples is their mean: one near-zero connect and
        // one 1500 ms connect. Recording the discarded arm instead would
        // leave this in the single-digit milliseconds. The margins are wide
        // (600 out of a 750 floor, 400 for a couple of round-trips) so a
        // few hundred ms of scheduler stall under a parallel build cannot
        // flake the test, while the regression it pins still misses by 100x.
        assert!(
            r.fresh_ms > 600.0,
            "the slowed connect must be the recorded fresh arm, got {:.1} ms",
            r.fresh_ms
        );
        // The claim never touches the slowed connection.
        assert!(r.warm_ms < 400.0, "claims are one round-trip, got {:.1} ms", r.warm_ms);
    }

    /// Against a server that answers everything, no pair is lost - the
    /// restructured loop must not drop a pair on the branch that makes
    /// the second connect.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_healthy_server_yields_every_pair() {
        let rig = greeting_rig(usize::MAX, Duration::ZERO).await;
        let r = measure(&rig.cfg, 4).await;
        assert_eq!(r.samples, 4);
        assert_eq!(
            rig.accepted.load(Ordering::SeqCst),
            6,
            "two fresh-first pairs at one connect, two warm-first pairs at two"
        );
        assert_ne!(r.verdict, Verdict::Failed);
    }

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

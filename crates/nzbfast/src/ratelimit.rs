//! Per-provider token buckets for the wall enricher (plan §4 C3).
//!
//! The enricher's original pacing was "sleep N ms after each title",
//! which is not a rate limiter. Its real cost per title is
//! `max(delay, latency)`, so a slow provider silently spends its own
//! allowance twice: once waiting for the response, once sleeping the
//! full window afterwards. It also cannot express "this provider allows
//! one request per second" when a single title makes three requests -
//! the burst goes out back to back and only the gap between TITLES is
//! controlled.
//!
//! MusicBrainz is the provider that forced the issue. It enforces
//! roughly 1 request/second and blocks clients that ignore it, so the
//! music lane needs a limit on REQUESTS, not on titles.
//!
//! Scope, stated honestly: this module is used by the music and book
//! providers only. The movie and TV lanes still pace by sleeping between
//! titles. Moving them across is the rest of C3 and is deliberately not
//! bundled here - it means deleting their per-title sleep at the same
//! time, and that pacing was measured and shipped days ago (research
//! §7.2). Adding a bucket underneath it without removing it would just
//! make the movie lane slower.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// A rate-limited upstream. One bucket each, because the limits are
/// per-service: the Cover Art Archive is fronted by the Internet
/// Archive, not by MusicBrainz, and spending one's budget on the other
/// is exactly the mistake §4 C3 describes ("lanes should be per
/// provider, not per kind").
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Provider {
    /// Hard ~1 req/s, enforced, and they block abusers. Not a courtesy.
    MusicBrainz,
    /// Cover Art Archive (redirects to archive.org). No published limit;
    /// paced anyway because we are an unattended background crawler.
    CoverArt,
    /// OpenLibrary. No published limit for search.json; same reasoning.
    OpenLibrary,
}

impl Provider {
    /// (requests per second, burst). The burst is what lets one title's
    /// two-or-three calls go out without waiting; the rate is what holds
    /// the long-run average where the provider asked for it.
    fn limit(self) -> (f64, f64) {
        match self {
            // No burst at all. MusicBrainz measures the gap between
            // consecutive requests, so letting even two through
            // back-to-back is the thing that gets a client blocked.
            Provider::MusicBrainz => (1.0, 1.0),
            Provider::CoverArt => (2.0, 2.0),
            Provider::OpenLibrary => (2.0, 2.0),
        }
    }
}

/// One provider's limiter state, as a GCRA "theoretical arrival time".
///
/// `tat` is the instant the NEXT request would be perfectly on-rate.
/// Each caller pushes it forward by one interval and sleeps until its
/// own turn comes round, so N threads arriving together queue at
/// 1/rate apart instead of all sleeping the same interval and then
/// firing simultaneously - which is the failure a plain
/// "refill, and if short, sleep the deficit" bucket has, because a
/// waiting caller computes its sleep from `now` and never accounts for
/// the callers already reserved ahead of it.
struct Bucket {
    tat: Instant,
}

fn buckets() -> &'static Mutex<HashMap<Provider, Bucket>> {
    static B: OnceLock<Mutex<HashMap<Provider, Bucket>>> = OnceLock::new();
    B.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Interval between requests, and how far ahead of the perfect rate a
/// burst may run.
fn timings(p: Provider) -> (Duration, Duration) {
    let (rate, burst) = p.limit();
    let interval = Duration::from_secs_f64(1.0 / rate);
    // A burst of 1 means no tolerance at all: strictly one interval
    // between consecutive requests.
    (interval, interval.mul_f64(burst - 1.0))
}

/// Block until this provider may be called again, then claim the slot.
///
/// The slot is claimed under the lock and slept for outside it, so
/// concurrent callers form a queue rather than a thundering herd.
pub fn acquire(p: Provider) {
    let (interval, tolerance) = timings(p);
    let wait = {
        let now = Instant::now();
        let mut map = buckets().lock().unwrap_or_else(|e| e.into_inner());
        let b = map.entry(p).or_insert(Bucket { tat: now });
        // How long until this request would be conforming. Computed as
        // `tat - (now + tolerance)` rather than `(tat - tolerance) - now`
        // so no Instant is ever moved backwards past its origin.
        let wait = b.tat.saturating_duration_since(now + tolerance);
        // Claim: the next caller queues one whole interval behind us.
        b.tat = b.tat.max(now) + interval;
        wait
    };
    if !wait.is_zero() {
        std::thread::sleep(wait);
    }
}

/// Push this provider's next slot out by `secs`, on top of whatever is
/// already queued. For an explicit "you are going too fast" from
/// upstream (HTTP 429/503 + Retry-After), where carrying on at the
/// nominal rate is what gets a client banned.
pub fn penalise(p: Provider, secs: u64) {
    let secs = secs.clamp(1, 60);
    let now = Instant::now();
    let mut map = buckets().lock().unwrap_or_else(|e| e.into_inner());
    let b = map.entry(p).or_insert(Bucket { tat: now });
    b.tat = b.tat.max(now) + Duration::from_secs(secs);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A bucket with no burst must space consecutive calls by its whole
    /// interval - the property MusicBrainz actually enforces. Uses the
    /// real MusicBrainz bucket, so a future edit that quietly gives it a
    /// burst fails here.
    #[test]
    fn musicbrainz_spaces_consecutive_calls_by_a_second() {
        let t0 = Instant::now();
        // First call drains the single token, the next two must wait.
        for _ in 0..3 {
            acquire(Provider::MusicBrainz);
        }
        let spent = t0.elapsed();
        assert!(
            spent >= Duration::from_millis(1900),
            "three calls at 1 req/s took only {spent:?} - the limit is not being applied"
        );
    }

    /// Two threads must QUEUE, not both sleep the same interval and then
    /// fire together. This is the bug the reserve-under-lock design
    /// exists to prevent, and a naive "sleep then take" implementation
    /// passes the serial test above while failing this one.
    #[test]
    fn concurrent_callers_queue_instead_of_colliding() {
        // Fresh provider state is process-global, so measure the DELTA
        // across the four calls rather than assuming an empty bucket.
        acquire(Provider::OpenLibrary);
        let t0 = Instant::now();
        std::thread::scope(|s| {
            for _ in 0..4 {
                s.spawn(|| acquire(Provider::OpenLibrary));
            }
        });
        // 2 req/s: four queued calls cannot clear in under ~1.5 s.
        let spent = t0.elapsed();
        assert!(
            spent >= Duration::from_millis(1400),
            "four concurrent calls at 2 req/s cleared in {spent:?} - they collided"
        );
    }

    #[test]
    fn a_penalty_pushes_the_next_slot_out() {
        acquire(Provider::CoverArt);
        penalise(Provider::CoverArt, 2);
        let t0 = Instant::now();
        acquire(Provider::CoverArt);
        assert!(t0.elapsed() >= Duration::from_millis(1900));
    }
}

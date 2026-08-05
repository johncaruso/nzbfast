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
//! Every lane is on a bucket now. The movie and TV lanes came across on
//! 27 Jul and their per-title sleeps were deleted in the same change -
//! a bucket UNDER a sleep is just a slower sleep. What that move
//! measured is the reason the numbers below are what they are, and it
//! is worth reading before adjusting any of them:
//!
//! The Wikidata action API does not enforce a rate. It enforces a
//! QUOTA: ten requests, then HTTP 429 with a `Retry-After` that counts
//! down to a ~60 s window reset. Probed 27 Jul at 400 ms and at 1000 ms
//! spacing - both got exactly ten through and were then refused for the
//! rest of the run, which is what tells you it is a count and not a
//! rate. The old sleep-between-titles pacing could not see this: a movie
//! title makes two or three Wikidata calls back to back, so the burst
//! inside ONE title spent a quarter of a window, and 3-4 titles in every
//! 10 stalled ~55 s on a 429. Measured cost of that: 18.6-23.6 s/title
//! across three runs. The quota, not the sleep, was setting the pace.
//!
//! Two consequences worth keeping in mind before tuning anything here:
//!
//! - **The keyless movie lane is at its provider's ceiling.** Ten
//!   requests a minute over two or three per title is 3-4 titles a
//!   minute, and that is the whole budget. No pacing scheme beats it;
//!   only asking Wikidata FEWER times per title would.
//! - **Do not merge buckets by operator.** `Wikipedia` looks like it
//!   belongs with `Wikidata` and does not - see its doc comment.

use crate::MutexExt;
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// A rate-limited upstream. One bucket each, because the limits are
/// per-service: the Cover Art Archive is fronted by the Internet
/// Archive, not by MusicBrainz, and spending one's budget on the other
/// is exactly the mistake §4 C3 describes ("lanes should be per
/// provider, not per kind").
// Slim builds only exercise the Srrdb/Xrel/Qlever lanes; gating variants would
// cascade through every match below, so the unused ones are allowed instead.
#[cfg_attr(not(feature = "indexer"), allow(dead_code))]
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Provider {
    /// Hard ~1 req/s, enforced, and they block abusers. Not a courtesy.
    MusicBrainz,
    /// Cover Art Archive (redirects to archive.org). No published limit;
    /// paced anyway because we are an unattended background crawler.
    CoverArt,
    /// OpenLibrary. No published limit for search.json; same reasoning.
    OpenLibrary,
    /// The Wikidata action API (www.wikidata.org/w/api.php). The tightest
    /// limit any lane here faces, and the one that sets the keyless movie
    /// lane's ceiling.
    Wikidata,
    /// Wikipedia's REST summary endpoint (en.wikipedia.org/api/rest_v1).
    ///
    /// A SEPARATE bucket from Wikidata, and that is a measured fact, not
    /// a guess: probed 27 Jul, 24 consecutive calls at 2.5 req/s with no
    /// refusal, while wikidata.org was simultaneously refusing anything
    /// past ten a minute. Putting both on one bucket was tried first and
    /// cost the movie lane 41% - the Wikipedia half of every title sat
    /// waiting on an allowance it does not actually spend.
    Wikipedia,
    /// The Wikidata SPARQL endpoint (query.wikidata.org), which is a
    /// third service again. Only the person-page filmography uses it,
    /// one query at a time, on a click - so this rate is a courtesy
    /// default rather than a probed figure, and it is deliberately NOT
    /// the Wikidata bucket: a person page must not queue behind the
    /// enricher's crawl.
    WikidataSparql,
    /// The QLever Wikidata mirror at qlever.cs.uni-freiburg.de, which
    /// serves the same graph as WikidataSparql from an entirely
    /// different operator - a university research group, not the
    /// Wikimedia Foundation. Post-download identification queries it
    /// because WDQS has been answering 502 for this class of query.
    ///
    /// Its own bucket for the reason the Wikipedia doc comment gives:
    /// separate operator, separate allowance. Rate is courtesy, not a
    /// probed figure. It is deliberately slow because nothing waits on
    /// it - a completed job's rename is not a click - and because a
    /// free academic endpoint answering a query that scans every film
    /// in Wikidata deserves a wide berth.
    WikidataQlever,
    /// TVmaze. Publishes 20 requests / 10 seconds and means it; probed
    /// 27 Jul at 2 req/s for 24 consecutive calls with no refusal.
    Tvmaze,
    /// OMDb, on the user's own free key. The free tier is capped per DAY
    /// (1,000 calls), not per second, so this bucket is courtesy only -
    /// going slower here does not buy a single extra lookup.
    Omdb,
    /// TMDB, bring-your-own-key only (they decline applications for NZB
    /// tooling). Their documented ceiling is ~50 req/s, far above
    /// anything a background enricher does.
    Tmdb,
    /// AniList, the last-chance fallback for video. 90 requests/minute
    /// published, and unlike the others here that figure is NOT probed -
    /// it is a rare fallback, so a live calibration run would have spent
    /// more of their capacity than the enricher does.
    AniList,
    /// srrdb's keyless search API. They publish no rate, and their terms
    /// ask callers to use it rather than scrape it - so this is a
    /// courtesy figure and the CALL SITE is where the politeness really
    /// lives: at most one lookup per finished download, cached, and
    /// silent on any error.
    Srrdb,
    /// xREL's v2 API. Two published limits, and the tighter one governs:
    /// 900 calls/hour overall, but SEARCH methods are capped at 2 calls
    /// per 5 seconds. See the quota test - one call per 5 s is what fits
    /// inside that window with a burst of 1, and 720/hour is comfortably
    /// under the hourly ceiling as well.
    Xrel,
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
            // Sized to fit inside a fixed window of 10 requests / 60 s,
            // which is the shape probing found. 7.5 s apart is 8 per
            // minute in the steady state, and 9 in the first minute
            // after an idle bucket (t=0 plus eight more) - one request
            // of headroom under the quota.
            //
            // NO BURST, and that is the second thing this was measured
            // into rather than reasoned into. A burst of 2 is tempting:
            // a movie title's first two Wikidata calls (search, then
            // claims) are what produce the card, so letting them go back
            // to back is what a title the user is LOOKING AT wants. But
            // it puts 10 in that first window - exactly the quota - and
            // live runs drew a 429 anyway in 2 of 3 attempts, because
            // anything else on this IP shares the allowance. The 45 s
            // stall a 429 costs is far worse than the 7.5 s the burst
            // saved. Verified at this spacing: 24 consecutive calls,
            // three minutes, zero 429s.
            Provider::Wikidata => (8.0 / 60.0, 1.0),
            Provider::Wikipedia => (2.0, 2.0),
            Provider::WikidataSparql => (1.0, 2.0),
            // One query every 4 seconds, no burst. A single completed
            // job makes exactly one of these, so this only ever paces a
            // queue draining several obfuscated jobs in a row - which is
            // precisely when a courtesy limit matters.
            Provider::WikidataQlever => (0.25, 1.0),
            // 20 requests / 10 s published. A leaky bucket emits
            // `burst + rate*T` in a window of length T, so 2 req/s with
            // a burst of 2 is 22 in their window - over the line every
            // time the enricher runs flat out. 1.8 lands on exactly 20.
            Provider::Tvmaze => (1.8, 2.0),
            Provider::Omdb => (3.0, 2.0),
            Provider::Tmdb => (5.0, 5.0),
            // 90/minute published; 1.5 with a burst of 2 is 92. Same
            // arithmetic as TVmaze above, and see the quota test.
            Provider::AniList => (1.4, 2.0),
            Provider::Srrdb => (1.0, 1.0),
            // 2 calls / 5 s on search methods. Same leaky-bucket
            // arithmetic as TVmaze: with the minimum burst of 1, the
            // rate has to be 0.2 to keep `burst + 5*rate` at 2.
            Provider::Xrel => (0.2, 1.0),
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
        let mut map = buckets().lock_ok();
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

/// Claim a slot only if the wait is short, and REFUSE rather than queue
/// when it is not. Returns whether the caller may make the request.
///
/// `acquire` is right for the background enricher, which has nothing
/// better to do than wait its turn. It is wrong on an interactive path:
/// the dashboard's search runs on one of a few blocking API workers, in
/// front of the HTTP timeout, so a queued claim (or a 60 s `penalise`
/// from a 429 the enricher drew) parks a worker for as long as the
/// bucket says - and enough clicks park every worker, which stalls
/// dashboard polling too. A click that cannot be served fast should
/// degrade to whatever the handler already knows locally.
///
/// A refusal must cost the caller nothing and the LANE nothing: `tat` is
/// left exactly as it was, so a refused click does not slow the
/// enricher down or push the next caller further out.
#[cfg(feature = "indexer")]
pub fn try_acquire(p: Provider, max_wait: Duration) -> bool {
    let (interval, tolerance) = timings(p);
    let wait = {
        let now = Instant::now();
        let mut map = buckets().lock_ok();
        let b = map.entry(p).or_insert(Bucket { tat: now });
        let wait = b.tat.saturating_duration_since(now + tolerance);
        if wait > max_wait {
            return false;
        }
        b.tat = b.tat.max(now) + interval;
        wait
    };
    if !wait.is_zero() {
        std::thread::sleep(wait);
    }
    true
}

/// Push this provider's next slot out by `secs`, on top of whatever is
/// already queued. For an explicit "you are going too fast" from
/// upstream (HTTP 429/503 + Retry-After), where carrying on at the
/// nominal rate is what gets a client banned.
pub fn penalise(p: Provider, secs: u64) {
    let secs = secs.clamp(1, 60);
    let now = Instant::now();
    let mut map = buckets().lock_ok();
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

    /// Every provider whose limit is a fixed-window QUOTA rather than a
    /// rate. A leaky bucket can emit `burst + rate*T` in a window of
    /// length T, so a config is only safe while
    /// `burst + window*rate <= quota` - and that is not obvious from
    /// either number alone: raising the rate to use "the last of the
    /// budget", or handing a provider a burst so a hot card appears
    /// sooner, is exactly the tempting edit that puts the movie lane
    /// back to stalling ~45 s on a 429. Both were tried live on Wikidata
    /// before this test existed.
    ///
    /// Pure arithmetic on purpose: a real one would have to spend a
    /// minute of each provider's allowance to say the same thing.
    #[test]
    fn quota_providers_stay_inside_their_windows() {
        // (provider, window seconds, requests allowed in that window).
        // Wikidata's is measured (see the module header); TVmaze's and
        // AniList's are the figures they publish.
        const QUOTAS: [(Provider, f64, f64); 5] = [
            (Provider::Wikidata, 60.0, 10.0),
            (Provider::Tvmaze, 10.0, 20.0),
            (Provider::AniList, 60.0, 90.0),
            // xREL publishes two, and BOTH have to hold: the search
            // window is the binding one, the hourly ceiling is the one a
            // future rate rise would breach first.
            (Provider::Xrel, 5.0, 2.0),
            (Provider::Xrel, 3600.0, 900.0),
        ];
        for (p, window, quota) in QUOTAS {
            let (rate, burst) = p.limit();
            let worst = burst + window * rate;
            assert!(
                worst <= quota,
                "{p:?} could emit {worst} in a {window} s window; the quota is {quota}"
            );
        }
    }

    /// `try_acquire` refuses without reserving. Both halves matter: a
    /// refusal that still pushed `tat` would let a burst of refused
    /// clicks starve the enricher of the very allowance they never used.
    #[cfg(feature = "indexer")]
    #[test]
    fn try_acquire_refuses_without_consuming() {
        // TVmaze's bucket belongs to this test alone. Drain its burst
        // first: while a bucket is still inside its tolerance every
        // caller is conforming and there is nothing to refuse.
        let (interval, _) = timings(Provider::Tvmaze);
        acquire(Provider::Tvmaze);
        acquire(Provider::Tvmaze);
        let t0 = Instant::now();
        for _ in 0..5 {
            assert!(
                !try_acquire(Provider::Tvmaze, Duration::from_millis(50)),
                "a slot ~{interval:?} out was granted against a 50 ms budget"
            );
        }
        // Five refusals must leave the queue exactly where it was: the
        // next slot is one interval out, not six.
        assert!(
            try_acquire(Provider::Tvmaze, interval * 2),
            "the refusals consumed the slots they declined"
        );
        assert!(
            t0.elapsed() < interval * 2,
            "waited {:?} for a slot {interval:?} out - the refusals pushed it back",
            t0.elapsed()
        );
    }

    /// An idle bucket grants immediately, and the grant IS a claim.
    #[cfg(feature = "indexer")]
    #[test]
    fn try_acquire_grants_and_claims() {
        // Wikidata: no burst, 7.5 s apart, and no other test here spends
        // from it - so both halves are unambiguous and neither sleeps.
        let t0 = Instant::now();
        assert!(try_acquire(Provider::Wikidata, Duration::from_millis(200)));
        assert!(
            t0.elapsed() < Duration::from_millis(100),
            "an idle bucket made us wait"
        );
        assert!(
            !try_acquire(Provider::Wikidata, Duration::from_millis(200)),
            "the grant above did not claim the slot"
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

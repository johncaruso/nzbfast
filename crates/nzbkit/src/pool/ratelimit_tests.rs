//! Rate-limit and connection-target unit tests, moved out of pool.rs's
//! inline `tests` mod to keep the file inside its size-gate baseline.
//! Self-contained: none of these touch the inline mod's own helpers.

use super::*;

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

/// The shipped-default bug: with the old byte-window the per-call
/// sleep was clamped to 5 s and the debt was never forgiven, so the
/// aggregate could not be held below `connections * article / 5 s` -
/// ~1.28 MB/s at 8 connections, i.e. every cap under ~10 Mbit/s was
/// silently exceeded.
///
/// Necessarily slower than a unit test wants: the clamp is 5 s of
/// WALL time, so nothing under that can observe it. 8 workers x
/// 150 KB at 150 KB/s owes 8 s; the old code answered in ~5.
#[tokio::test]
async fn rate_limit_holds_a_cap_below_the_old_clamp_floor() {
    const CAP: u64 = 150_000;
    const WORKERS: u64 = 8;
    let rl = RateLimit::new(CAP);
    let t0 = Instant::now();
    let mut set = tokio::task::JoinSet::new();
    for _ in 0..WORKERS {
        let rl = rl.clone();
        set.spawn(async move { rl.throttle(CAP).await });
    }
    while set.join_next().await.is_some() {}
    let el = t0.elapsed();
    // Owed is WORKERS seconds (each charges exactly one second's
    // worth). Generous lower bound: anything near 5 s is the clamp.
    assert!(
        el >= Duration::from_secs_f64(WORKERS as f64 * 0.8),
        "the cap was exceeded - {el:?} for {WORKERS}s of charged bytes"
    );
    assert!(
        el <= Duration::from_secs(WORKERS * 3),
        "far too slow: {el:?}"
    );
}

/// A live cap change must not leave a worker asleep against the old
/// one. The virtual clock prices each charge when it is charged, so a
/// decrease never re-prices old bytes; the generation bump is what
/// releases anyone already waiting.
#[tokio::test]
async fn a_live_cap_change_releases_a_sleeping_worker() {
    let rl = RateLimit::new(1_000); // 1 KB/s: 100 KB owes 100 s
    let t0 = Instant::now();
    let waiter = {
        let rl = rl.clone();
        tokio::spawn(async move { rl.throttle(100_000).await })
    };
    tokio::time::sleep(Duration::from_millis(200)).await;
    rl.set(0); // the user removed the limit
    waiter.await.unwrap();
    assert!(
        t0.elapsed() < Duration::from_secs(5),
        "stranded against the old cap"
    );
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

#[test]
fn conn_target_clamps_to_one() {
    // 0 would park the whole fleet with work pending - the
    // `connections: 0` hang, reached through the side door.
    let t = ConnTarget::new(0);
    assert_eq!(t.get(), 1);
    t.set(0);
    assert_eq!(t.get(), 1);
    t.set(5);
    assert_eq!(t.get(), 5);
}

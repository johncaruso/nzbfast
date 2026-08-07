//! The tail-optimization campaign's payout/safety rigs (TODO 113).
//!
//! Moved verbatim out of pool.rs's inline `tests` mod: these are the
//! chaos-rig legs (payout_*, safety_*, flap/gauntlet/fight, CRC-retry
//! storms, TTFB hedge) that grew the file past its size-gate entry
//! during the 5 Aug fault campaign. A child module of `pool` (same
//! pattern as unit_tests.rs) so private internals stay reachable via
//! `super::*`; sibling `#[cfg(test)]` mods cannot share helpers, so the
//! rig helpers (payout_leg and friends) live here with every test that
//! uses them.

use super::*;

/// Payout rig: run one full fetch against mock servers and return
/// (elapsed, done-count, reconnect-note ring). Every leg must
/// complete every article - a payout that loses data is a loss.
async fn payout_leg(
    servers: Vec<(ServerConfig, PoolConfig)>,
    ids: Vec<ArticleReq>,
) -> (Duration, usize, Vec<String>) {
    let live = LiveStats::for_servers(&servers);
    let servers: Vec<(ServerConfig, PoolConfig)> = servers
        .into_iter()
        .map(|(s, mut c)| {
            c.live = Some(live.clone());
            (s, c)
        })
        .collect();
    let (tx, mut rx) = mpsc::channel(64);
    let t0 = Instant::now();
    let fetch = tokio::spawn(async move { fetch_all_multi(&servers, ids, tx).await });
    let collect = tokio::spawn(async move {
        let mut done = 0usize;
        while let Some(o) = rx.recv().await {
            if matches!(o, FetchOutcome::Done { .. }) {
                done += 1;
            }
        }
        done
    });
    tokio::time::timeout(Duration::from_secs(120), fetch)
        .await
        .expect("payout leg hung")
        .unwrap();
    let elapsed = t0.elapsed();
    let done = collect.await.unwrap();
    let notes: Vec<String> = live
        .events
        .lock()
        .unwrap()
        .iter()
        .map(|e| format!("{} {}", e.host, e.detail))
        .collect();
    (elapsed, done, notes)
}

fn payout_server(
    srv: &crate::mock::MockServer,
    conns: usize,
    cfg: PoolConfig,
) -> (ServerConfig, PoolConfig) {
    let mut sc = srv.server_config();
    sc.connections = conns as u32;
    (
        sc,
        PoolConfig {
            connections: conns,
            ramp_delay: Duration::from_millis(0),
            ..cfg
        },
    )
}

/// PAYOUT: hedged requests, in the one shape the OLD rules cannot
/// see. A single article stalls on a server whose other connection
/// stays healthy - so the owner never reads as slow (the 2x rate
/// rule stays dark) and the only rescues are the flat 8 s stale
/// rule (off) versus the hedge's adaptive bound (on). Both servers
/// are throttled to EQUAL per-connection rates for the same reason.
/// The first version of this rig stalled ids early on an unthrottled
/// server and proved something else entirely: the rate rule rescued
/// everything in 500 ms because a hung loopback server's per-worker
/// rate collapses instantly. That is worth knowing - the existing
/// rules already cover the whole-server-degraded shape - but the
/// hedge exists for the single-straggler-on-a-healthy-server shape,
/// which is what this rig now builds.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "wall-clock payout measurement - flaky under suite load, run with --ignored"]
async fn payout_hedge_rescues_stalls_in_under_a_second_not_eight() {
    let data: Vec<u8> = (0..640_000u32).map(|i| i as u8).collect();
    let mk_maps = || {
        let mut articles = std::collections::HashMap::new();
        let segs = crate::mock::make_file_articles("h.bin", &data, 8_000, "hp", &mut articles);
        (articles, segs)
    };
    let (arts_a, segs) = mk_maps();
    let (arts_b, _) = mk_maps();
    // Stragglers late in the queue, so the owner has a healthy rate
    // history when they hit. Several of them, and A gets 3 of the 4
    // connections below, because the mock's stall triggers on the
    // FIRST request for an id wherever it lands: a single stalled id
    // first-requested by healthy B proves nothing, and which server
    // wins that race is a coin flip. Six ids against a 3:1 fleet
    // makes "no stall ever bit A" a (1/4)^6 event.
    let stall: std::collections::HashSet<String> = [55, 59, 63, 67, 71, 75]
        .into_iter()
        .map(|i| format!("<{}>", segs[i].0))
        .collect();
    let leg = |hedge: bool| {
        let arts_a = arts_a.clone();
        let arts_b = arts_b.clone();
        let stall = stall.clone();
        let ids: Vec<ArticleReq> = segs
            .iter()
            .map(|(id, _, _)| ArticleReq::fresh(format!("<{id}>")))
            .collect();
        async move {
            // 40 KB/s per connection stretches the run to ~4 s of
            // pre-stall history. That matters: the old rate rule
            // rescues once the hung server's RUN-AVERAGE decays
            // past 2x, and that crossing lands at roughly four
            // times the stall's onset - a fast rig compresses it
            // right onto the hedge's own timescale and the two
            // become indistinguishable (measured: 2.2 s vs 1.9 s
            // at 200 KB/s). At 40 KB/s the old rules answer at
            // ~11 s (flat-8s stale wins the crossing race), the
            // hedge at ~5 s, and the gap is the payout.
            let equal_rate = crate::mock::Throttle {
                per_conn_bps: 40_000,
                ..Default::default()
            };
            let a = crate::mock::MockServer::start(
                arts_a,
                crate::mock::Chaos {
                    stall,
                    throttle: equal_rate.clone(),
                    ..Default::default()
                },
            )
            .await;
            let b = crate::mock::MockServer::start(
                arts_b,
                crate::mock::Chaos {
                    throttle: equal_rate,
                    ..Default::default()
                },
            )
            .await;
            let cfg = PoolConfig {
                hedge,
                window: 2,
                read_timeout: Duration::from_secs(12),
                ..Default::default()
            };
            let servers = vec![payout_server(&a, 3, cfg.clone()), payout_server(&b, 1, cfg)];
            let r = payout_leg(servers, ids).await;
            println!(
                "  leg: A served {} accepted {} · B served {} accepted {}",
                a.served.load(Ordering::Relaxed),
                a.accepted.load(Ordering::Relaxed),
                b.served.load(Ordering::Relaxed),
                b.accepted.load(Ordering::Relaxed),
            );
            r
        }
    };
    let (off, done_off, _) = leg(false).await;
    let (on, done_on, _) = leg(true).await;
    println!("hedge payout: off {off:?} on {on:?}");
    assert_eq!(done_off, segs.len());
    assert_eq!(done_on, segs.len());
    // Off: the stragglers wait for whichever old rule answers first
    // (flat-8s stale, or the run-average crossing).
    assert!(
        off > Duration::from_secs(9),
        "off leg finished too fast for the stalls to have bitten \
         ({off:?}) - rig broken"
    );
    // On: the hedge rescues at the adaptive bound. Measured over
    // repeated runs: off 11.9-13.0 s, on 6.2-7.9 s - a ratio bound
    // absorbs the serialization variance through B's single idle
    // connection where an absolute one flaked.
    assert!(
        on.as_secs_f64() < off.as_secs_f64() * 0.75,
        "hedge paid out nothing ({on:?} vs {off:?})"
    );
}

/// PAYOUT: slope recycle. One degraded session (8 KB/s against
/// healthy 100 KB/s siblings) on a single server. Reactive rules
/// cannot dup same-server outside the tail; the slope recycle
/// redials the degraded session as soon as it proves itself slow,
/// and the replacement is healthy. Slow by construction (~1 min for
/// both legs) - run explicitly.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "payout measurement (~1 min) - run with --ignored"]
async fn payout_slope_recycle_frees_a_degraded_session() {
    let data: Vec<u8> = (0..6_000_000u32).map(|i| i as u8).collect();
    let mut articles = std::collections::HashMap::new();
    let segs = crate::mock::make_file_articles("s.bin", &data, 50_000, "sp", &mut articles);
    let leg = |slope: bool| {
        let articles = articles.clone();
        let ids: Vec<ArticleReq> = segs
            .iter()
            .map(|(id, _, _)| ArticleReq::fresh(format!("<{id}>")))
            .collect();
        async move {
            let srv = crate::mock::MockServer::start(
                articles,
                crate::mock::Chaos {
                    slow_conn: Some((1, 8_000)),
                    throttle: crate::mock::Throttle {
                        per_conn_bps: 100_000,
                        ..Default::default()
                    },
                    ..Default::default()
                },
            )
            .await;
            let cfg = PoolConfig {
                recycle_slope: slope,
                ..Default::default()
            };
            payout_leg(vec![payout_server(&srv, 3, cfg)], ids).await
        }
    };
    let (off, done_off, notes_off) = leg(false).await;
    let (on, done_on, notes_on) = leg(true).await;
    println!("slope payout: off {off:?} on {on:?} (notes on: {notes_on:?})");
    assert_eq!(done_off, segs.len());
    assert_eq!(done_on, segs.len());
    assert!(
        notes_on.iter().any(|n| n.contains("degraded session")),
        "slope recycle never fired on the degraded-session rig"
    );
    assert!(
        !notes_off.iter().any(|n| n.contains("degraded session")),
        "off leg recycled - knob leak"
    );
    assert!(
        on < off,
        "recycling the degraded session did not pay ({on:?} vs {off:?})"
    );
}

/// PAYOUT: hot spare. Connections die every 5 bodies and a dial
/// costs 250 ms (the mock's greeting delay standing in for
/// TCP+TLS+AUTH). The spare pays that cost in the background; the
/// workers' critical path skips it.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "wall-clock payout measurement - flaky under suite load, run with --ignored"]
async fn payout_hot_spare_hides_reconnect_latency() {
    let data: Vec<u8> = (0..1_800_000u32).map(|i| i as u8).collect();
    let mut articles = std::collections::HashMap::new();
    let segs = crate::mock::make_file_articles("k.bin", &data, 20_000, "ks", &mut articles);
    let leg = |spare: bool| {
        let articles = articles.clone();
        let ids: Vec<ArticleReq> = segs
            .iter()
            .map(|(id, _, _)| ArticleReq::fresh(format!("<{id}>")))
            .collect();
        async move {
            let srv = crate::mock::MockServer::start(
                articles,
                crate::mock::Chaos {
                    drop_after: 8,
                    greet_delay_ms: 250,
                    // Throttled so deaths arrive slower than the
                    // spare's refill cycle (poll + greet ~750 ms) -
                    // the realistic shape; unthrottled loopback
                    // kills sessions every few ms and no filler
                    // could keep up (nor would it need to: that
                    // shape is a dead server, not a flapping one).
                    throttle: crate::mock::Throttle {
                        per_conn_bps: 200_000,
                        ..Default::default()
                    },
                    ..Default::default()
                },
            )
            .await;
            let cfg = PoolConfig {
                hot_spare: spare,
                connect_backoff: Duration::from_millis(50),
                ..Default::default()
            };
            payout_leg(vec![payout_server(&srv, 3, cfg)], ids).await
        }
    };
    let (off, done_off, _) = leg(false).await;
    let (on, done_on, _) = leg(true).await;
    println!("spare payout: off {off:?} on {on:?}");
    assert_eq!(done_off, segs.len());
    assert_eq!(done_on, segs.len());
    // The saving is bounded by the filler's 500 ms refill cycle
    // against this rig's ~300 ms death spacing (~2-3 of 11 deaths
    // covered, ~200 ms measured). Real sessions die minutes apart,
    // where every death is covered; the refill cadence is the
    // tuning lever if this graduates.
    assert!(
        on + Duration::from_millis(100) < off,
        "the spare hid no reconnect latency ({on:?} vs {off:?})"
    );
}

/// Flap breaker: six established-session deaths inside the window
/// flip a server to flapping (a trickle outside it never does); the
/// clamp needs another live server; the keeper slot is claimed
/// exactly once.
#[tokio::test]
async fn flap_breaker_clamps_a_flapping_server_to_one_keeper() {
    let mk = |host: &str| {
        (
            ServerConfig {
                host: host.into(),
                port: 119,
                tls: false,
                username: None,
                password: None,
                connections: 1,
                pin_connections: false,
                level: 0,
                group: None,
                retention_days: 0,
                rcvbuf: None,
                block_bytes: None,
                bind_ip: None,
                socks5: None,
                enabled: true,
                warm_pool: false,
                idle_release_secs: None,
                idle_keep: None,
                max_source_ips: None,
            },
            PoolConfig::default(),
        )
    };
    let servers = vec![mk("flappy"), mk("steady")];
    let reqs: Vec<ArticleReq> = (0..4)
        .map(|i| ArticleReq::fresh(format!("<f{i}>")))
        .collect();
    let (shared, _) = Shared::new(reqs, &servers);
    shared.alive[1].store(1, Ordering::Relaxed);

    for _ in 0..(FLAP_DEATHS - 1) {
        shared.note_flap(0);
    }
    assert!(!shared.is_flapping(0), "one short of the threshold");
    shared.note_flap(0);
    assert!(shared.is_flapping(0));
    assert!(shared.other_live(0), "steady is live");

    // Keeper slot: exactly one claimant wins (the default target is
    // one, however many capacity bounces were sampled).
    let claim = |target: usize| {
        shared.flap_keeper[0]
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |k| {
                (k < target).then_some(k + 1)
            })
            .is_ok()
    };
    let target = shared.flap_keeper_target(0, &servers[0].1);
    assert_eq!(target, 1, "shipped default: one keeper");
    assert!(claim(target), "first claim takes the keeper slot");
    assert!(!claim(target), "second claim must lose");

    // A lone server is never clamped - churn beats zero throughput.
    shared.alive[1].store(0, Ordering::Relaxed);
    assert!(!shared.other_live(0), "no other live server");
}

/// Cap-aware keepers (TODO 115): with `flap_cap_keepers` on, the
/// keeper target follows the OBSERVED accept cap - sessions held at
/// the moment a dial bounced off a capacity refusal - never above
/// the connection budget, and stays at the conservative one when no
/// bounce was ever sampled or the knob is off.
#[tokio::test]
async fn flap_keeper_target_follows_observed_cap() {
    let mk = |host: &str, cap_aware: bool| {
        (
            ServerConfig {
                host: host.into(),
                port: 119,
                tls: false,
                username: None,
                password: None,
                connections: 8,
                pin_connections: false,
                level: 0,
                group: None,
                retention_days: 0,
                rcvbuf: None,
                block_bytes: None,
                bind_ip: None,
                socks5: None,
                enabled: true,
                warm_pool: false,
                idle_release_secs: None,
                idle_keep: None,
                max_source_ips: None,
            },
            PoolConfig {
                connections: 8,
                flap_cap_keepers: cap_aware,
                ..PoolConfig::default()
            },
        )
    };
    let servers = vec![mk("burned", true), mk("steady", true)];
    let reqs: Vec<ArticleReq> = (0..4)
        .map(|i| ArticleReq::fresh(format!("<f{i}>")))
        .collect();
    let (shared, _) = Shared::new(reqs, &servers);

    // No bounce ever sampled: the clamp stays at one.
    assert_eq!(shared.flap_keeper_target(0, &servers[0].1), 1);

    // Two sessions held when the dial bounced: target 2.
    shared.sessions[0].store(2, Ordering::Release);
    shared.note_cap_bounce(0);
    assert_eq!(shared.flap_keeper_target(0, &servers[0].1), 2);

    // A later bounce against ghost-held slots (fewer of OUR
    // sessions live) must not shrink the estimate.
    shared.sessions[0].store(0, Ordering::Release);
    shared.note_cap_bounce(0);
    assert_eq!(shared.flap_keeper_target(0, &servers[0].1), 2);

    // The connection budget is a hard ceiling - the account's own
    // limits (and max_source_ips-derived caps) already landed there.
    shared.sessions[0].store(30, Ordering::Release);
    shared.note_cap_bounce(0);
    assert_eq!(shared.flap_keeper_target(0, &servers[0].1), 8);

    // Knob off: shipped behavior, one keeper, whatever was seen.
    let off = mk("burned", false);
    assert_eq!(shared.flap_keeper_target(0, &off.1), 1);
}

/// PAYOUT (fault campaign, TODO 111): the IP-cap flap - the
/// production eweka shape. Server "burned" allows 2 concurrent
/// sessions (the rest bounce off a 502 cap refusal), and the two
/// winners die every 2 bodies at a crawl; "steady" is healthy. The
/// flap breaker should collapse burned's churn to one keeper and
/// leave the wall no worse.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "wall-clock payout measurement - run with --ignored"]
async fn payout_flap_breaker_collapses_ip_cap_churn() {
    let data: Vec<u8> = (0..8_000_000u32).map(|i| i as u8).collect();
    let mut articles = std::collections::HashMap::new();
    let segs = crate::mock::make_file_articles("c.bin", &data, 50_000, "fc", &mut articles);
    let leg = |breaker: bool| {
        let arts_a = articles.clone();
        let arts_b = articles.clone();
        let ids: Vec<ArticleReq> = segs
            .iter()
            .map(|(id, _, _)| ArticleReq::fresh(format!("<{id}>")))
            .collect();
        async move {
            let burned = crate::mock::MockServer::start(
                arts_a,
                crate::mock::Chaos {
                    accept_cap: Some(2),
                    drop_after: 1,
                    throttle: crate::mock::Throttle {
                        per_conn_bps: 60_000,
                        ..Default::default()
                    },
                    ..Default::default()
                },
            )
            .await;
            let steady = crate::mock::MockServer::start(
                arts_b,
                crate::mock::Chaos {
                    throttle: crate::mock::Throttle {
                        per_conn_bps: 150_000,
                        ..Default::default()
                    },
                    ..Default::default()
                },
            )
            .await;
            let cfg = PoolConfig {
                flap_breaker: breaker,
                connect_backoff: Duration::from_millis(100),
                ..Default::default()
            };
            // Staggered dials for the capped server (the TODO 111
            // probes hit this): eight simultaneous dials race the
            // mock's live count past the cap before any accept task
            // checks it, so ALL of them can bounce and the
            // capacity-yield ladder sometimes bows the whole fleet
            // out before a session ever establishes - a served-0,
            // clampless leg. 50 ms apart, the first two win their
            // slots; the rest bounce off a genuinely full cap.
            let bcfg = PoolConfig {
                connections: 8,
                ramp_delay: Duration::from_millis(50),
                ..cfg.clone()
            };
            let mut bsc = burned.server_config();
            bsc.connections = 8;
            let servers = vec![(bsc, bcfg), payout_server(&steady, 4, cfg)];
            payout_leg(servers, ids).await
        }
    };
    let (off, done_off, notes_off) = leg(false).await;
    let (on, done_on, notes_on) = leg(true).await;
    let churn = |notes: &[String]| {
        notes
            .iter()
            .filter(|n| n.starts_with("127.0.0.1") && n.contains("session lost"))
            .count()
    };
    // The two mocks share a host string, so count per-leg totals -
    // steady never drops sessions, so every "session lost" is
    // burned's.
    println!(
        "flap payout: off {off:?} ({} drops) on {on:?} ({} drops) clamp_noted={}",
        churn(&notes_off),
        churn(&notes_on),
        notes_on.iter().any(|n| n.contains("sessions flapping")),
    );
    assert_eq!(done_off, segs.len());
    assert_eq!(done_on, segs.len());
    // The clamp NOTE is no longer asserted (6 Aug): with the
    // immediate-first-retry ladder default-on, the two cap-slot
    // winners redial with zero delay after each one-body death and
    // reclaim their own slots before any bounced worker's paced retry
    // can win one - so no worker ever LOSES the keeper claim, which
    // is the only event that printed "sessions flapping" here. The
    // clamp mechanism itself is pinned by the fast
    // flap_breaker_clamps_a_flapping_server_to_one_keeper test; what
    // this rig now pins is the OUTCOME the note used to stand in
    // for: the churn stays collapsed (a couple of dozen paced
    // redials, not NZBGet's 217-dial hammering on this same shape)
    // and the politeness costs no wall time.
    assert!(
        churn(&notes_on) < 60,
        "flap churn is no longer collapsed ({} drops)",
        churn(&notes_on)
    );
    assert!(
        on.as_secs_f64() < off.as_secs_f64() * 1.15,
        "the clamp cost wall time ({on:?} vs {off:?})"
    );
}

/// PAYOUT (TODO 115): cap-aware keepers on the same IP-cap flap.
/// The provider accepts TWO sessions; the shipped breaker keeps
/// one, leaving the second slot's throughput on the table (NZBGet
/// takes it - and pays 217 dials of hammering for it, fault matrix
/// 5 Aug). With NZBFAST_FLAP_CAP_KEEPERS the clamp holds
/// min(observed cap, budget) = 2 keepers: wall at-or-below the
/// single-keeper clamp, dials in the same order (each keeper
/// redials on its own session's death, paced on any bounce).
#[tokio::test(flavor = "multi_thread")]
#[ignore = "wall-clock payout measurement - run with --ignored"]
async fn payout_flap_cap_keepers_hold_the_caps_worth() {
    let data: Vec<u8> = (0..8_000_000u32).map(|i| i as u8).collect();
    let mut articles = std::collections::HashMap::new();
    let segs = crate::mock::make_file_articles("c.bin", &data, 50_000, "fk", &mut articles);
    let leg = |cap_keepers: bool| {
        let arts_a = articles.clone();
        let arts_b = articles.clone();
        let ids: Vec<ArticleReq> = segs
            .iter()
            .map(|(id, _, _)| ArticleReq::fresh(format!("<{id}>")))
            .collect();
        async move {
            let burned = crate::mock::MockServer::start(
                arts_a,
                crate::mock::Chaos {
                    accept_cap: Some(2),
                    drop_after: 1,
                    throttle: crate::mock::Throttle {
                        per_conn_bps: 60_000,
                        ..Default::default()
                    },
                    ..Default::default()
                },
            )
            .await;
            let steady = crate::mock::MockServer::start(
                arts_b,
                crate::mock::Chaos {
                    throttle: crate::mock::Throttle {
                        per_conn_bps: 150_000,
                        ..Default::default()
                    },
                    ..Default::default()
                },
            )
            .await;
            let cfg = PoolConfig {
                flap_cap_keepers: cap_keepers,
                connect_backoff: Duration::from_millis(100),
                ..Default::default()
            };
            // Staggered dials, same reason as the flap payout above:
            // simultaneous dials can all bounce off a genuinely full
            // cap and bow the whole fleet out before a session
            // establishes.
            let bcfg = PoolConfig {
                connections: 8,
                ramp_delay: Duration::from_millis(50),
                ..cfg.clone()
            };
            let mut bsc = burned.server_config();
            bsc.connections = 8;
            let servers = vec![(bsc, bcfg), payout_server(&steady, 4, cfg)];
            let dials = burned.accepted.clone();
            let (wall, done, notes) = payout_leg(servers, ids).await;
            (wall, done, notes, dials.load(Ordering::Relaxed))
        }
    };
    let (off, done_off, _notes_off, dials_off) = leg(false).await;
    let (on, done_on, _notes_on, dials_on) = leg(true).await;
    println!(
        "cap-keeper payout: off {off:?} ({dials_off} dials) \
         on {on:?} ({dials_on} dials)"
    );
    assert_eq!(done_off, segs.len());
    assert_eq!(done_on, segs.len());
    // The clamp/widen NOTES are no longer asserted (6 Aug): with the
    // immediate-first-retry ladder default-on, the two cap-slot
    // winners reclaim their own slots with zero delay after each
    // one-body death, so the keeper claim race - and both narration
    // lines this rig used to key on - never happens on this shape;
    // the fleet arrives at the two-keeper outcome directly. The
    // mechanism tests (flap_breaker_clamps_a_flapping_server_to_one_
    // keeper and payout_flap_cap_keepers... in the fast suite) still
    // pin the notes where they can occur. What this rig pins is the
    // OUTCOME: the cap's worth of throughput at wall parity, dials
    // in the single-keeper's order - not NZBGet's 217-dial hammering
    // on this same shape.
    assert!(
        on.as_secs_f64() <= off.as_secs_f64() * 1.10,
        "cap-aware keepers cost wall time ({on:?} vs {off:?})"
    );
    assert!(
        dials_on <= dials_off * 3,
        "cap-aware keepers multiplied dials ({dials_on} vs {dials_off})"
    );
    assert!(
        dials_on < 100,
        "dials left the polite order on the cap flap ({dials_on})"
    );
}

/// SAFETY (fault campaign, TODO 111): jitter must kill nothing.
/// Every 5th body arrives 1.8 s late on an otherwise healthy
/// single server - the satellite shape. The adaptive timeout's
/// graduation gate: it must complete with no more session churn
/// and no more wall time than the flat path. (Its TTFB floor is
/// 2 s and its stall bound rolls with progress, so 1.8 s spikes
/// sit inside both by design - this pins that design.)
#[tokio::test(flavor = "multi_thread")]
#[ignore = "wall-clock safety measurement - run with --ignored"]
async fn safety_adaptive_timeout_kills_nothing_on_a_jittery_link() {
    let data: Vec<u8> = (0..1_600_000u32).map(|i| i as u8).collect();
    let mut articles = std::collections::HashMap::new();
    let segs = crate::mock::make_file_articles("j.bin", &data, 20_000, "jt", &mut articles);
    let leg = |adaptive: bool| {
        let articles = articles.clone();
        let ids: Vec<ArticleReq> = segs
            .iter()
            .map(|(id, _, _)| ArticleReq::fresh(format!("<{id}>")))
            .collect();
        async move {
            let srv = crate::mock::MockServer::start(
                articles,
                crate::mock::Chaos {
                    jitter: Some((5, 1_800)),
                    throttle: crate::mock::Throttle {
                        per_conn_bps: 100_000,
                        ..Default::default()
                    },
                    ..Default::default()
                },
            )
            .await;
            let cfg = PoolConfig {
                adaptive_timeout: adaptive,
                read_timeout: Duration::from_secs(12),
                ..Default::default()
            };
            payout_leg(vec![payout_server(&srv, 3, cfg)], ids).await
        }
    };
    let (flat, done_flat, notes_flat) = leg(false).await;
    let (adap, done_adap, notes_adap) = leg(true).await;
    let churn = |notes: &[String]| notes.iter().filter(|n| n.contains("session lost")).count();
    println!(
        "jitter safety: flat {flat:?} ({} drops) adaptive {adap:?} ({} drops)",
        churn(&notes_flat),
        churn(&notes_adap)
    );
    assert_eq!(done_flat, segs.len());
    assert_eq!(done_adap, segs.len());
    assert!(
        churn(&notes_adap) <= churn(&notes_flat),
        "adaptive killed sessions jitter should not kill ({} vs {})",
        churn(&notes_adap),
        churn(&notes_flat)
    );
    assert!(
        adap.as_secs_f64() < flat.as_secs_f64() * 1.15,
        "adaptive cost wall time on a healthy jittery link ({adap:?} vs {flat:?})"
    );
}

/// PAYOUT (fault campaign, TODO 111): whole-server brownout - a
/// provider's frontend goes mute mid-run and never recovers, while
/// a healthy twin carries the group. Three legs: pre-1.0.16
/// behaviour (everything off), the shipped defaults (fan-out early
/// + hedge + slope recycle + flap breaker), and shipped + adaptive
/// timeout.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "wall-clock payout measurement - run with --ignored"]
async fn payout_brownout_recovery_across_config_tiers() {
    let data: Vec<u8> = (0..2_400_000u32).map(|i| i as u8).collect();
    let mut articles = std::collections::HashMap::new();
    let segs = crate::mock::make_file_articles("b.bin", &data, 20_000, "bo", &mut articles);
    let leg = |shipped: bool, adaptive: bool| {
        let arts_a = articles.clone();
        let arts_b = articles.clone();
        let ids: Vec<ArticleReq> = segs
            .iter()
            .map(|(id, _, _)| ArticleReq::fresh(format!("<{id}>")))
            .collect();
        async move {
            let throttle = crate::mock::Throttle {
                per_conn_bps: 100_000,
                ..Default::default()
            };
            let mute = crate::mock::MockServer::start(
                arts_a,
                crate::mock::Chaos {
                    brownout_after: 40,
                    throttle: throttle.clone(),
                    ..Default::default()
                },
            )
            .await;
            let steady = crate::mock::MockServer::start(
                arts_b,
                crate::mock::Chaos {
                    throttle,
                    ..Default::default()
                },
            )
            .await;
            let cfg = PoolConfig {
                tail_fanout: shipped,
                tail_fanout_early: shipped,
                hedge: shipped,
                recycle_slope: shipped,
                flap_breaker: shipped,
                adaptive_timeout: adaptive,
                read_timeout: Duration::from_secs(12),
                ..Default::default()
            };
            let servers = vec![
                payout_server(&mute, 3, cfg.clone()),
                payout_server(&steady, 3, cfg),
            ];
            payout_leg(servers, ids).await
        }
    };
    let (old, done_old, _) = leg(false, false).await;
    let (ship, done_ship, _) = leg(true, false).await;
    let (adap, done_adap, _) = leg(true, true).await;
    println!("brownout payout: old {old:?} shipped {ship:?} shipped+adaptive {adap:?}");
    assert_eq!(done_old, segs.len());
    assert_eq!(done_ship, segs.len());
    assert_eq!(done_adap, segs.len());
    assert!(
        old > Duration::from_secs(10),
        "old leg finished too fast for the brownout to have bitten ({old:?})"
    );
    assert!(
        ship.as_secs_f64() < old.as_secs_f64() * 0.7,
        "the shipped defaults paid out nothing on a brownout ({ship:?} vs {old:?})"
    );
    assert!(
        adap.as_secs_f64() < ship.as_secs_f64() * 1.15,
        "adaptive regressed the shipped config ({adap:?} vs {ship:?})"
    );
}

/// NEVER-REGRESS (fault matrix, TODO 115): the brownout wedge.
/// In the 5 Aug fault matrix one client NEVER finished this shape
/// (a server going mute mid-run with a same-priority healthy twin
/// present) - it sat on the mute server forever and reported
/// nothing. This fixture pins that nzbfast can never score the
/// shape that way: with the shipped tier of defenses the job must
/// COMPLETE, fast. Not ignored - a wedge here must scream in CI,
/// not print a slow number. Margins are structural: the pass path
/// is a few seconds, the wedge is forever (payout_leg's 120 s
/// completion bound fires first), so suite load cannot flake it.
#[tokio::test(flavor = "multi_thread")]
async fn safety_brownout_wedge_never_regresses() {
    let data: Vec<u8> = (0..1_200_000u32).map(|i| i as u8).collect();
    let mut articles = std::collections::HashMap::new();
    let segs = crate::mock::make_file_articles("nw.bin", &data, 20_000, "nw", &mut articles);
    let throttle = crate::mock::Throttle {
        per_conn_bps: 400_000,
        ..Default::default()
    };
    let mute = crate::mock::MockServer::start(
        articles.clone(),
        crate::mock::Chaos {
            brownout_after: 20,
            throttle: throttle.clone(),
            ..Default::default()
        },
    )
    .await;
    let steady = crate::mock::MockServer::start(
        articles,
        crate::mock::Chaos {
            throttle,
            ..Default::default()
        },
    )
    .await;
    // The shipped tier (what the daemon runs by default), pinned
    // explicitly like the payout rigs above.
    let cfg = PoolConfig {
        tail_fanout: true,
        tail_fanout_early: true,
        hedge: true,
        recycle_slope: true,
        flap_breaker: true,
        adaptive_timeout: true,
        read_timeout: Duration::from_secs(12),
        ..Default::default()
    };
    let ids: Vec<ArticleReq> = segs
        .iter()
        .map(|(id, _, _)| ArticleReq::fresh(format!("<{id}>")))
        .collect();
    let servers = vec![
        payout_server(&mute, 3, cfg.clone()),
        payout_server(&steady, 3, cfg),
    ];
    let (wall, done, _) = payout_leg(servers, ids).await;
    assert_eq!(
        done,
        segs.len(),
        "brownout wedge regression: {done}/{} articles after {wall:?}",
        segs.len()
    );
    assert!(
        wall < Duration::from_secs(60),
        "brownout took {wall:?} - the mute server is being waited on, \
         not abandoned; this is the wedge shape, fix it"
    );
}

/// NEVER-REGRESS (fault matrix, TODO 115): the slowconn
/// ride-along. In the 5 Aug fault matrix one client rode a single
/// degraded session (50 KB/s against a healthy server) all the way
/// to the end - 6x the field's wall - because nothing it shipped
/// could see a slow-but-alive connection. This fixture pins that
/// nzbfast always frees itself: one crawling session (1 KB/s
/// against 400 KB/s siblings, so each article it holds costs 20 s)
/// must not set the wall. Ride-along blows past 120 s (payout_leg
/// screams); the pass path is seconds.
#[tokio::test(flavor = "multi_thread")]
async fn safety_slowconn_ride_along_never_regresses() {
    let data: Vec<u8> = (0..1_200_000u32).map(|i| i as u8).collect();
    let mut articles = std::collections::HashMap::new();
    let segs = crate::mock::make_file_articles("nr.bin", &data, 20_000, "nr", &mut articles);
    let srv = crate::mock::MockServer::start(
        articles,
        crate::mock::Chaos {
            slow_conn: Some((1, 1_000)),
            throttle: crate::mock::Throttle {
                per_conn_bps: 400_000,
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .await;
    let cfg = PoolConfig {
        tail_fanout: true,
        tail_fanout_early: true,
        hedge: true,
        recycle_slope: true,
        flap_breaker: true,
        adaptive_timeout: true,
        read_timeout: Duration::from_secs(12),
        ..Default::default()
    };
    let ids: Vec<ArticleReq> = segs
        .iter()
        .map(|(id, _, _)| ArticleReq::fresh(format!("<{id}>")))
        .collect();
    let (wall, done, _) = payout_leg(vec![payout_server(&srv, 3, cfg)], ids).await;
    assert_eq!(
        done,
        segs.len(),
        "slowconn regression: {done}/{} articles after {wall:?}",
        segs.len()
    );
    assert!(
        wall < Duration::from_secs(45),
        "slowconn took {wall:?} - the degraded session is setting \
         the wall; this is the ride-along shape, fix it"
    );
}

/// PAYOUT (fault campaign, TODO 111): dead-air stalls price the
/// adaptive timeout, dark since 96.1. Six ids hang BEFORE the
/// status line; the flat path waits the whole read_timeout per hit,
/// the adaptive TTFB budget gives up at its 2 s floor.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "wall-clock payout measurement - run with --ignored"]
async fn payout_adaptive_timeout_cuts_dead_air_stalls() {
    let data: Vec<u8> = (0..640_000u32).map(|i| i as u8).collect();
    let mut articles = std::collections::HashMap::new();
    let segs = crate::mock::make_file_articles("d.bin", &data, 8_000, "at", &mut articles);
    let stall_pre: std::collections::HashSet<String> = [30, 38, 46, 54, 62, 70]
        .into_iter()
        .map(|i| format!("<{}>", segs[i].0))
        .collect();
    let leg = |adaptive: bool| {
        let articles = articles.clone();
        let stall_pre = stall_pre.clone();
        let ids: Vec<ArticleReq> = segs
            .iter()
            .map(|(id, _, _)| ArticleReq::fresh(format!("<{id}>")))
            .collect();
        async move {
            let srv = crate::mock::MockServer::start(
                articles,
                crate::mock::Chaos {
                    stall_pre,
                    throttle: crate::mock::Throttle {
                        per_conn_bps: 100_000,
                        ..Default::default()
                    },
                    ..Default::default()
                },
            )
            .await;
            let cfg = PoolConfig {
                adaptive_timeout: adaptive,
                read_timeout: Duration::from_secs(12),
                ..Default::default()
            };
            payout_leg(vec![payout_server(&srv, 3, cfg)], ids).await
        }
    };
    let (off, done_off, _) = leg(false).await;
    let (on, done_on, _) = leg(true).await;
    println!("adaptive payout: off {off:?} on {on:?}");
    assert_eq!(done_off, segs.len());
    assert_eq!(done_on, segs.len());
    assert!(
        off > Duration::from_secs(12),
        "off leg finished too fast for the dead air to have bitten ({off:?})"
    );
    assert!(
        on.as_secs_f64() < off.as_secs_f64() * 0.6,
        "the adaptive budget paid out nothing ({on:?} vs {off:?})"
    );
}

/// PAYOUT (TODO 115): the TTFB-suspicion hedge prices what the
/// adaptive budget leaves on the table, in the shape where dead air
/// actually costs WALL time: stalls near the queue's end, where the
/// stalled article itself gates completion. BOTH legs run the
/// adaptive budget - the A/B is suspicion. Off, a tail stall costs
/// the full 2 s pre-byte floor plus a requeue round-trip before the
/// run can end; on, a sibling connection dup-races it after ~1 s of
/// silence and the answer lands with a second of budget still on
/// the clock. `greet` prices the same shape with a per-connection
/// dial cost, so the hedge proves it still pays when reconnects
/// cost real round trips.
///
/// Mid-queue stalls are deliberately NOT the rig: there the run is
/// capacity-bound and the budget seconds a stalled connection sits
/// out are lost either way ("kill nothing" means the owner waits
/// regardless) - measured 6.5 s vs 6.5 s with the dups firing on
/// cue. The hedge buys article LATENCY, and latency is wall time
/// only when supply is short. Tail fan-out is left off so the legs
/// price suspicion itself, not the shipped endgame racer it
/// partially overlaps (fan-out needs an IDLE picker and 500 ms on
/// the wire; suspicion races from any topping-up worker at ~1 s,
/// pre-endgame included, and is the only rule that races a
/// same-server stall outside the endgame).
async fn ttfb_hedge_deadair_legs(greet_delay_ms: u64) -> (Duration, Duration, usize) {
    let data: Vec<u8> = (0..640_000u32).map(|i| i as u8).collect();
    let mut articles = std::collections::HashMap::new();
    let segs = crate::mock::make_file_articles("t.bin", &data, 8_000, "th", &mut articles);
    // ONE stall, on the very last article: the shape is then
    // deterministic - the stalled read starts once its healthy
    // pipeline-mates are done, nothing traps behind it, and both
    // sibling connections are idle pickers when suspicion fires.
    // Several spread stalls measured bimodal (4-9 s per leg): with
    // window 4 a second stall lands as a trapped MATE of the first
    // stalled connection as often as not, and whether the serial
    // 2 s chains stack on one conn is a per-run coin flip.
    let stall_pre: std::collections::HashSet<String> =
        std::iter::once(format!("<{}>", segs[segs.len() - 1].0)).collect();
    let leg = |ttfb_hedge: bool| {
        let articles = articles.clone();
        let stall_pre = stall_pre.clone();
        let ids: Vec<ArticleReq> = segs
            .iter()
            .map(|(id, _, _)| ArticleReq::fresh(format!("<{id}>")))
            .collect();
        async move {
            let srv = crate::mock::MockServer::start(
                articles,
                crate::mock::Chaos {
                    stall_pre,
                    greet_delay_ms,
                    throttle: crate::mock::Throttle {
                        per_conn_bps: 100_000,
                        ..Default::default()
                    },
                    ..Default::default()
                },
            )
            .await;
            let cfg = PoolConfig {
                adaptive_timeout: true,
                ttfb_hedge,
                read_timeout: Duration::from_secs(12),
                ..Default::default()
            };
            payout_leg(vec![payout_server(&srv, 3, cfg)], ids).await
        }
    };
    let (off, done_off, _) = leg(false).await;
    let (on, done_on, _) = leg(true).await;
    assert_eq!(done_off, segs.len());
    assert_eq!(done_on, segs.len());
    (off, on, segs.len())
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "wall-clock payout measurement - flaky under suite load, run with --ignored"]
async fn payout_ttfb_hedge_beats_the_budget_on_dead_air() {
    let (off, on, _) = ttfb_hedge_deadair_legs(0).await;
    println!("ttfb-hedge payout: off {off:?} on {on:?}");
    // Off: tail stalls sit out the 2 s budget floor before the run
    // can end (healthy transfer alone is ~2.1 s).
    assert!(
        off > Duration::from_secs(3),
        "off leg finished too fast for the dead air to have bitten ({off:?}) - rig broken"
    );
    // On: suspicion at ~1 s, the dup answers inside the budget. The
    // payout is per-stall seconds (budget floor minus suspicion
    // bound, ~1 s), so the bound is absolute, not a ratio.
    assert!(
        on.as_secs_f64() + 0.6 < off.as_secs_f64(),
        "the ttfb hedge paid out nothing ({on:?} vs {off:?})"
    );
}

/// PAYOUT (TODO 115): the greet-delay gate. Dials cost 250 ms on
/// this rig, so the off leg's timeout-and-requeue path pays real
/// reconnect round trips - the hedge must still win, not merely tie
/// a strategy whose redials happened to be free on loopback.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "wall-clock payout measurement - flaky under suite load, run with --ignored"]
async fn payout_ttfb_hedge_still_pays_when_dials_cost() {
    let (off, on, _) = ttfb_hedge_deadair_legs(250).await;
    println!("ttfb-hedge dial-cost payout: off {off:?} on {on:?}");
    assert!(
        off > Duration::from_secs(3),
        "off leg finished too fast for the dead air to have bitten ({off:?}) - rig broken"
    );
    assert!(
        on.as_secs_f64() + 0.6 < off.as_secs_f64(),
        "the ttfb hedge stopped paying once dials cost real time ({on:?} vs {off:?})"
    );
}

/// SAFETY (TODO 115): the jitter gate, same shape as
/// [`safety_adaptive_timeout_kills_nothing_on_a_jittery_link`].
/// Every 5th body arrives 1.8 s late PRE-BYTE on a healthy single
/// server, which is exactly what suspicion smells - so this is the
/// hedge's worst case: it may spend bounded dup fetches, but it
/// must add ZERO reconnects (the owner is never killed) and no
/// wall time.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "wall-clock safety measurement - run with --ignored"]
async fn safety_ttfb_hedge_kills_nothing_on_a_jittery_link() {
    let data: Vec<u8> = (0..1_600_000u32).map(|i| i as u8).collect();
    let mut articles = std::collections::HashMap::new();
    let segs = crate::mock::make_file_articles("j.bin", &data, 20_000, "js", &mut articles);
    let leg = |ttfb_hedge: bool| {
        let articles = articles.clone();
        let ids: Vec<ArticleReq> = segs
            .iter()
            .map(|(id, _, _)| ArticleReq::fresh(format!("<{id}>")))
            .collect();
        async move {
            let srv = crate::mock::MockServer::start(
                articles,
                crate::mock::Chaos {
                    jitter: Some((5, 1_800)),
                    throttle: crate::mock::Throttle {
                        per_conn_bps: 100_000,
                        ..Default::default()
                    },
                    ..Default::default()
                },
            )
            .await;
            let cfg = PoolConfig {
                adaptive_timeout: true,
                ttfb_hedge,
                read_timeout: Duration::from_secs(12),
                ..Default::default()
            };
            let r = payout_leg(vec![payout_server(&srv, 3, cfg)], ids).await;
            (r, srv.accepted.load(Ordering::Relaxed))
        }
    };
    let ((off, done_off, notes_off), accepted_off) = leg(false).await;
    let ((on, done_on, notes_on), accepted_on) = leg(true).await;
    let churn = |notes: &[String]| notes.iter().filter(|n| n.contains("session lost")).count();
    println!(
        "ttfb-hedge jitter safety: off {off:?} ({} drops, {accepted_off} accepts) \
         on {on:?} ({} drops, {accepted_on} accepts)",
        churn(&notes_off),
        churn(&notes_on),
    );
    assert_eq!(done_off, segs.len());
    assert_eq!(done_on, segs.len());
    // THE gate: suspicion may dup, it must never dial. Every accept
    // beyond the off leg's would be a reconnect the hedge caused.
    assert!(
        accepted_on <= accepted_off,
        "the ttfb hedge added reconnects on a jittery link ({accepted_on} vs {accepted_off})"
    );
    assert!(
        churn(&notes_on) <= churn(&notes_off),
        "the ttfb hedge killed sessions jitter should not kill ({} vs {})",
        churn(&notes_on),
        churn(&notes_off)
    );
    assert!(
        on.as_secs_f64() < off.as_secs_f64() * 1.15,
        "the ttfb hedge cost wall time on a healthy jittery link ({on:?} vs {off:?})"
    );
}

/// [`payout_leg`] with a PAUSING consumer: reads outcomes for 1 s,
/// then stops reading for 2 s, forever - the external-enclosure
/// write-side stall (a disk that periodically parks/flushes while
/// the network is healthy). Channel depth is the caller's, because
/// that IS the experiment: how much outcome buffer it takes to
/// smooth a periodic write stall (TODO 108 evidence).
async fn payout_leg_pausing(
    servers: Vec<(ServerConfig, PoolConfig)>,
    ids: Vec<ArticleReq>,
    depth: usize,
) -> (Duration, usize) {
    let (tx, mut rx) = mpsc::channel(depth);
    let t0 = Instant::now();
    let fetch = tokio::spawn(async move { fetch_all_multi(&servers, ids, tx).await });
    let collect = tokio::spawn(async move {
        let mut done = 0usize;
        loop {
            let awake = Instant::now();
            while awake.elapsed() < Duration::from_secs(1) {
                match tokio::time::timeout(Duration::from_millis(50), rx.recv()).await {
                    Ok(Some(o)) => {
                        if matches!(o, FetchOutcome::Done { .. }) {
                            done += 1;
                        }
                    }
                    Ok(None) => return done,
                    Err(_) => {}
                }
            }
            // The stall: 2 s in every 3 during which NOTHING is
            // read - workers park on `out.send` once the channel
            // and the kernel's socket buffers are full.
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    });
    tokio::time::timeout(Duration::from_secs(120), fetch)
        .await
        .expect("payout leg hung")
        .unwrap();
    let elapsed = t0.elapsed();
    (elapsed, collect.await.unwrap())
}

/// TODO 111 experiment 2, write-side stall: the consumer pauses
/// reading the outcome channel 2 s in every 3 (the external-
/// enclosure shape behind TODO 108) while the line itself is
/// healthy. Legs differ ONLY in outcome-channel depth - the
/// candidate smoothing knob (MemBudget::channel_depth clamps at 8
/// on small boxes, 256 on big ones; 512 models "spend more"). The
/// walls are the evidence curve for the slow-disk breaker design:
/// how much of the stall a deeper budget actually hides, and where
/// it stops paying.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "wall-clock payout measurement - flaky under suite load, run with --ignored"]
async fn payout_channel_depth_smooths_a_stalling_write_side() {
    let data: Vec<u8> = (0..7_680_000u32).map(|i| (i >> 4) as u8).collect();
    let mut articles = std::collections::HashMap::new();
    let segs = crate::mock::make_file_articles("s.bin", &data, 64_000, "ws", &mut articles);
    let leg = |depth: usize| {
        let articles = articles.clone();
        let ids: Vec<ArticleReq> = segs
            .iter()
            .map(|(id, _, _)| ArticleReq::fresh(format!("<{id}>")))
            .collect();
        async move {
            let srv = crate::mock::MockServer::start(
                articles,
                crate::mock::Chaos {
                    throttle: crate::mock::Throttle {
                        per_conn_bps: 400_000,
                        ..Default::default()
                    },
                    ..Default::default()
                },
            )
            .await;
            let cfg = PoolConfig {
                window: 2,
                ..Default::default()
            };
            payout_leg_pausing(vec![payout_server(&srv, 3, cfg)], ids, depth).await
        }
    };
    let mut walls = Vec::new();
    for depth in [8usize, 64, 256, 512] {
        let (wall, done) = leg(depth).await;
        assert_eq!(done, segs.len(), "depth {depth} lost outcomes");
        println!("write-stall: depth {depth:>3} → wall {wall:.2?}");
        walls.push((depth, wall));
    }
    // The shallow (small-box) budget must pay measurably more wall
    // than the deep one on the same stall pattern - that gap is
    // the smoothing a deeper budget buys. Generous ratio: kernel
    // socket buffers absorb a real share of the stall on loopback
    // and that share is itself a finding, not noise to assert away.
    let shallow = walls[0].1.as_secs_f64();
    let deep = walls[3].1.as_secs_f64();
    assert!(
        shallow > deep * 1.1,
        "channel depth bought nothing: shallow {shallow:.2}s vs deep {deep:.2}s"
    );
}

/// TODO 111 round 7 (Starlink), SAFETY: single-dish satellite
/// handovers - the whole fleet freezes in dead air for 1.2 s every
/// 4 s, then fully recovers (the route switch). The shipped
/// defaults (fan-out early + hedge + slope recycle + flap breaker)
/// and the adaptive-timeout candidate must treat this as weather,
/// not damage: no recycle storm, no session churn, wall within the
/// freeze tax both ways. The freeze sits under the adaptive
/// pre-byte floor (2 s) and the slope window (10 s, and everyone
/// freezes TOGETHER so no session ever reads slow against the
/// fleet) - this rig pins that reasoning against the code.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "wall-clock payout measurement - flaky under suite load, run with --ignored"]
async fn safety_shipped_defaults_survive_starlink_handovers() {
    let data: Vec<u8> = (0..3_840_000u32).map(|i| (i >> 6) as u8).collect();
    let mut articles = std::collections::HashMap::new();
    let segs = crate::mock::make_file_articles("h.bin", &data, 8_000, "ho", &mut articles);
    let leg = |shipped: bool, adaptive: bool| {
        let articles = articles.clone();
        let ids: Vec<ArticleReq> = segs
            .iter()
            .map(|(id, _, _)| ArticleReq::fresh(format!("<{id}>")))
            .collect();
        async move {
            let srv = crate::mock::MockServer::start(
                articles,
                crate::mock::Chaos {
                    handover: Some((4_000, 1_200, 1)),
                    throttle: crate::mock::Throttle {
                        per_conn_bps: 100_000,
                        ..Default::default()
                    },
                    ..Default::default()
                },
            )
            .await;
            let cfg = PoolConfig {
                tail_fanout: shipped,
                tail_fanout_early: shipped,
                hedge: shipped,
                recycle_slope: shipped,
                flap_breaker: shipped,
                adaptive_timeout: adaptive,
                read_timeout: Duration::from_secs(12),
                window: 2,
                ..Default::default()
            };
            let r = payout_leg(vec![payout_server(&srv, 3, cfg)], ids).await;
            (r, srv.accepted.load(Ordering::Relaxed))
        }
    };
    let ((old, done_old, _), acc_old) = leg(false, false).await;
    let ((ship, done_ship, _), acc_ship) = leg(true, false).await;
    let ((adap, done_adap, _), acc_adap) = leg(true, true).await;
    println!(
        "handover safety: old {old:.2?} ({acc_old} conns) · shipped {ship:.2?} \
         ({acc_ship}) · +adaptive {adap:.2?} ({acc_adap})"
    );
    assert_eq!(done_old, segs.len());
    assert_eq!(done_ship, segs.len());
    assert_eq!(done_adap, segs.len());
    // Weather, not damage: no leg may pay a churn tax over the
    // freeze-schedule floor the off leg establishes.
    assert!(
        ship.as_secs_f64() < old.as_secs_f64() * 1.15,
        "shipped defaults paid a churn tax on handovers ({ship:?} vs {old:?})"
    );
    assert!(
        adap.as_secs_f64() < old.as_secs_f64() * 1.15,
        "adaptive paid a churn tax on handovers ({adap:?} vs {old:?})"
    );
    // And no reconnect storm: the fleet is 3 connections; a recycle
    // or timeout loop would show up as accepts.
    assert!(
        acc_ship <= 5 && acc_adap <= 5,
        "handover freezes caused session churn (accepts: shipped {acc_ship}, \
         adaptive {acc_adap})"
    );
}

/// TODO 111 round 7 (Starlink x multi-WAN): one dish is always
/// mid-obstruction - two WANs whose 4 s freeze windows tile the
/// whole 8 s period, so at every moment exactly half the fleet is
/// in dead air, but NEVER the same half for long. Multi-WAN flips
/// the handover question from safety to PAYOUT: with one WAN a
/// freeze self-heals before any rule can react, but with two the
/// healthy half is an escape path, and the fan-out + hedge dup
/// machinery is the only thing that can take it mid-tail - the
/// frozen WAN's in-flight articles are otherwise hostages until
/// the window ends.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "wall-clock payout measurement - flaky under suite load, run with --ignored"]
async fn payout_multiwan_fanout_rescues_the_frozen_wan() {
    let data: Vec<u8> = (0..1_280_000u32).map(|i| (i >> 7) as u8).collect();
    let mut articles = std::collections::HashMap::new();
    let segs = crate::mock::make_file_articles("m.bin", &data, 8_000, "mw", &mut articles);
    let leg = |race: bool| {
        let articles = articles.clone();
        let ids: Vec<ArticleReq> = segs
            .iter()
            .map(|(id, _, _)| ArticleReq::fresh(format!("<{id}>")))
            .collect();
        async move {
            let srv = crate::mock::MockServer::start(
                articles,
                crate::mock::Chaos {
                    // Complementary windows: WAN 0 frozen [0,4),
                    // WAN 1 frozen [4,8) of every 8 s.
                    handover: Some((8_000, 4_000, 2)),
                    throttle: crate::mock::Throttle {
                        per_conn_bps: 40_000,
                        ..Default::default()
                    },
                    ..Default::default()
                },
            )
            .await;
            let cfg = PoolConfig {
                tail_fanout: race,
                tail_fanout_early: race,
                hedge: race,
                read_timeout: Duration::from_secs(12),
                window: 2,
                ..Default::default()
            };
            payout_leg(vec![payout_server(&srv, 4, cfg)], ids).await
        }
    };
    let (off, done_off, _) = leg(false).await;
    let (on, done_on, _) = leg(true).await;
    println!("multi-WAN handover: off {off:.2?} on {on:.2?}");
    assert_eq!(done_off, segs.len());
    assert_eq!(done_on, segs.len());
    // Both legs pay the halved capacity; the payout is the tail,
    // where off waits out the frozen WAN's window (up to 4 s) and
    // on dups the hostages onto the healthy WAN within ~1 s.
    // Measured 20.45 s vs 17.56 s (the ~3 s is exactly one freeze
    // window) - the ratio bound leaves room for scheduler noise
    // around a payout that is structurally one window wide.
    assert!(
        on.as_secs_f64() < off.as_secs_f64() * 0.92,
        "the dup machinery rescued nothing across WANs ({on:?} vs {off:?})"
    );
}

/// TODO 111 round 7 (multi-WAN): asymmetric WANs - three
/// connections ride the fast dish (100 KB/s) and every fourth
/// lands on the slow fallback line (12 KB/s), round-robin, the
/// load-balancer shape. The open question this rig answers: does
/// the shipped slope recycle treat the slow-but-HEALTHY path as a
/// degraded session (its rate really is under 25% of the fleet
/// per-worker average) - and if it fires, is that churn or an
/// escape? With round-robin rebalancing a redial usually lands on
/// the fast WAN, so firing is probe-and-abandon of the slow path;
/// the rig prices exactly that.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "wall-clock payout measurement - flaky under suite load, run with --ignored"]
async fn payout_recycle_slope_probes_an_asymmetric_multiwan() {
    let data: Vec<u8> = (0..3_840_000u32).map(|i| (i >> 8) as u8).collect();
    let mut articles = std::collections::HashMap::new();
    let segs = crate::mock::make_file_articles("a.bin", &data, 8_000, "aw", &mut articles);
    let leg = |slope: bool| {
        let articles = articles.clone();
        let ids: Vec<ArticleReq> = segs
            .iter()
            .map(|(id, _, _)| ArticleReq::fresh(format!("<{id}>")))
            .collect();
        async move {
            let srv = crate::mock::MockServer::start(
                articles,
                crate::mock::Chaos {
                    wan_conn_bps: vec![100_000, 100_000, 100_000, 12_000],
                    ..Default::default()
                },
            )
            .await;
            let cfg = PoolConfig {
                recycle_slope: slope,
                read_timeout: Duration::from_secs(12),
                window: 2,
                ..Default::default()
            };
            payout_leg(vec![payout_server(&srv, 4, cfg)], ids).await
        }
    };
    let (off, done_off, notes_off) = leg(false).await;
    let (on, done_on, notes_on) = leg(true).await;
    let fired = |notes: &[String]| {
        notes
            .iter()
            .filter(|n| n.contains("recycled a degraded session"))
            .count()
    };
    println!(
        "asymmetric multi-WAN: off {off:.2?} ({} recycles) on {on:.2?} ({} recycles)",
        fired(&notes_off),
        fired(&notes_on),
    );
    assert_eq!(done_off, segs.len());
    assert_eq!(done_on, segs.len());
    assert_eq!(fired(&notes_off), 0, "slope off must not recycle");
    // The slow-but-healthy WAN really does read as degraded - the
    // recycle fires. The assert pins the OUTCOME being an escape,
    // not a churn loop: bounded firings and no wall regression.
    assert!(
        fired(&notes_on) >= 1,
        "the slow WAN never read as degraded - rig broken: {notes_on:?}"
    );
    assert!(
        fired(&notes_on) <= 6,
        "slope recycle churned on the asymmetric fleet ({} firings)",
        fired(&notes_on)
    );
    assert!(
        on.as_secs_f64() < off.as_secs_f64() * 1.05,
        "the escape regressed the wall ({on:?} vs {off:?})"
    );
}

/// TODO 111 round 7 (Starlink x multi-WAN): rain fade on ONE of
/// two paths. Two server entries (in production: the same provider
/// twice, each bound to a WAN via `bind_ip` - the one multi-WAN
/// shape nzbfast can actually see, since a load balancer under a
/// single entry is invisible to per-server stats). Three seconds
/// in, path A's line collapses to 20 KB/s and stays there - rain
/// on one dish. The queue self-balances by pull, so the healthy
/// path naturally takes more; the priced question is the shipped
/// rules' behaviour on the faded-but-alive path: the slope recycle
/// reads A's sessions as degraded but a redial lands on the SAME
/// faded path (nothing within A to escape to), and the endgame dup
/// rules are what actually rescue A's hostage articles via B.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "wall-clock payout measurement - flaky under suite load, run with --ignored"]
async fn payout_rain_fade_drains_to_the_healthy_wan() {
    let data: Vec<u8> = (0..2_880_000u32).map(|i| (i >> 3) as u8).collect();
    let mk_maps = || {
        let mut articles = std::collections::HashMap::new();
        let segs = crate::mock::make_file_articles("r.bin", &data, 8_000, "rf", &mut articles);
        (articles, segs)
    };
    let (arts_a, segs) = mk_maps();
    let (arts_b, _) = mk_maps();
    let leg = |shipped: bool| {
        let arts_a = arts_a.clone();
        let arts_b = arts_b.clone();
        let ids: Vec<ArticleReq> = segs
            .iter()
            .map(|(id, _, _)| ArticleReq::fresh(format!("<{id}>")))
            .collect();
        async move {
            let per_conn = crate::mock::Throttle {
                per_conn_bps: 60_000,
                ..Default::default()
            };
            let a = crate::mock::MockServer::start(
                arts_a,
                crate::mock::Chaos {
                    throttle: per_conn.clone(),
                    ..Default::default()
                },
            )
            .await;
            let b = crate::mock::MockServer::start(
                arts_b,
                crate::mock::Chaos {
                    throttle: per_conn,
                    ..Default::default()
                },
            )
            .await;
            // Rain sets in on path A three seconds into the run
            // and does not lift.
            let fade = a.line_control();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(3)).await;
                fade.set_line_bps(20_000);
            });
            let cfg = PoolConfig {
                tail_fanout: shipped,
                tail_fanout_early: shipped,
                hedge: shipped,
                recycle_slope: shipped,
                flap_breaker: shipped,
                read_timeout: Duration::from_secs(12),
                window: 2,
                ..Default::default()
            };
            let servers = vec![payout_server(&a, 3, cfg.clone()), payout_server(&b, 3, cfg)];
            payout_leg(servers, ids).await
        }
    };
    let (off, done_off, _) = leg(false).await;
    let (on, done_on, notes_on) = leg(true).await;
    let recycles = notes_on
        .iter()
        .filter(|n| n.contains("recycled a degraded session"))
        .count();
    println!("rain fade: off {off:.2?} on {on:.2?} ({recycles} recycles on the faded path)");
    assert_eq!(done_off, segs.len());
    assert_eq!(done_on, segs.len());
    // The shipped rules must at minimum not make rain WORSE - the
    // slope recycle's redials land back on the faded path, so any
    // win has to come from the dup machinery outweighing that
    // churn. The measured split is the finding either way.
    assert!(
        on.as_secs_f64() < off.as_secs_f64() * 1.10,
        "shipped rules regressed a one-path rain fade ({on:?} vs {off:?}, \
         {recycles} recycles)"
    );
}

/// TODO 111 round 7 (Starlink/CGNAT): mid-transfer silent eviction
/// - after 20 bodies a connection's NAT entry ages out and it goes
/// permanently mute, no close, no RST. The flat read timeout pays
/// its full 12 s per eviction; the adaptive TTFB budget gives up
/// at its 2 s floor and redials (a fresh accept = a fresh NAT
/// entry). This is the recoverable half of the keepalive story -
/// the idle-parked-connection half stays unpriceable on loopback.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "wall-clock payout measurement - flaky under suite load, run with --ignored"]
async fn payout_adaptive_timeout_survives_cgnat_evictions() {
    let data: Vec<u8> = (0..960_000u32).map(|i| (i >> 9) as u8).collect();
    let mut articles = std::collections::HashMap::new();
    let segs = crate::mock::make_file_articles("n.bin", &data, 8_000, "ce", &mut articles);
    let leg = |adaptive: bool| {
        let articles = articles.clone();
        let ids: Vec<ArticleReq> = segs
            .iter()
            .map(|(id, _, _)| ArticleReq::fresh(format!("<{id}>")))
            .collect();
        async move {
            let srv = crate::mock::MockServer::start(
                articles,
                crate::mock::Chaos {
                    mute_after_bodies: 20,
                    throttle: crate::mock::Throttle {
                        per_conn_bps: 100_000,
                        ..Default::default()
                    },
                    ..Default::default()
                },
            )
            .await;
            let cfg = PoolConfig {
                adaptive_timeout: adaptive,
                read_timeout: Duration::from_secs(12),
                window: 2,
                ..Default::default()
            };
            payout_leg(vec![payout_server(&srv, 3, cfg)], ids).await
        }
    };
    let (off, done_off, _) = leg(false).await;
    let (on, done_on, _) = leg(true).await;
    println!("cgnat eviction: off {off:.2?} on {on:.2?}");
    assert_eq!(done_off, segs.len());
    assert_eq!(done_on, segs.len());
    assert!(
        off > Duration::from_secs(14),
        "off leg finished too fast for the evictions to have bitten ({off:?})"
    );
    assert!(
        on.as_secs_f64() < off.as_secs_f64() * 0.5,
        "the adaptive budget paid out nothing on evictions ({on:?} vs {off:?})"
    );
}

/// TODO 111 experiment 3, slow-start trickle: every FRESH
/// connection crawls for its first 1.2 s (congestion-window /
/// middlebox warm-up) and sessions keep dying (drop every 20
/// bodies), so a reconnect-heavy run pays the crawl over and over.
/// The hot spare is the priced candidate: a parked spare rides its
/// crawl window out while idle, so the worker that claims it after
/// a death starts at full speed instead of at the trickle. (The
/// warm pool shares this shape across RUNS; the spare is the
/// in-run version this rig can price.)
#[tokio::test(flavor = "multi_thread")]
#[ignore = "wall-clock payout measurement - flaky under suite load, run with --ignored"]
async fn payout_hot_spare_skips_the_slow_start_trickle() {
    let data: Vec<u8> = (0..1_920_000u32).map(|i| (i >> 5) as u8).collect();
    let mut articles = std::collections::HashMap::new();
    let segs = crate::mock::make_file_articles("t.bin", &data, 8_000, "ss", &mut articles);
    let leg = |spare: bool| {
        let articles = articles.clone();
        let ids: Vec<ArticleReq> = segs
            .iter()
            .map(|(id, _, _)| ArticleReq::fresh(format!("<{id}>")))
            .collect();
        async move {
            let srv = crate::mock::MockServer::start(
                articles,
                crate::mock::Chaos {
                    drop_after: 20,
                    slow_start: Some((1200, 10_000)),
                    // A real dial costs round trips; without this a
                    // loopback reconnect is free and the spare has
                    // nothing to hide.
                    greet_delay_ms: 250,
                    throttle: crate::mock::Throttle {
                        per_conn_bps: 100_000,
                        ..Default::default()
                    },
                    ..Default::default()
                },
            )
            .await;
            let cfg = PoolConfig {
                hot_spare: spare,
                window: 2,
                ..Default::default()
            };
            let mut sv = payout_server(&srv, 3, cfg);
            // Stagger the fleet's dials so deaths desynchronize
            // (real sessions never die in lockstep) - otherwise
            // three simultaneous deaths fight over the one spare.
            sv.1.ramp_delay = Duration::from_millis(400);
            payout_leg(vec![sv], ids).await
        }
    };
    let (off, done_off, _) = leg(false).await;
    let (on, done_on, _) = leg(true).await;
    println!("slow-start trickle: off {off:.2?} on {on:.2?}");
    assert_eq!(done_off, segs.len());
    assert_eq!(done_on, segs.len());
    // MEASURED VERDICT (5 Aug, the finding this rig exists for):
    // the payout is real but SMALL - 19.2 s vs 20.7 s, ~7% - and
    // structurally bounded, not noise. One spare refilled every
    // 500 ms against fleet-wide deaths every ~1 s covers about a
    // third of the reconnects, and a spare claimed young is still
    // inside its own crawl window. Meanwhile the 2 s session
    // backoff every organic death (connect_backoff x 2^0) already
    // hides most of a 1.2 s crawl behind a sleep both legs pay.
    // Slow-start trickle wants FEWER RECONNECTS (keepalive) or a
    // spare per dying worker, not one faster spare - the assert
    // pins "never worse, some payout", which is all this shape
    // supports.
    assert!(
        on.as_secs_f64() < off.as_secs_f64() * 0.97,
        "the hot spare paid out nothing against slow-start ({on:?} vs {off:?})"
    );
}

/// [`payout_leg_verified`] with an ACKING consumer (TODO 114): the
/// collector plays the decode consumer's part of the steer seam,
/// reporting every Done body through `note_decoded` exactly like
/// `decode_consumer_loop` does - a Steered ack drops the body and
/// counts nothing (the refetched copy owns the outcome). Same
/// tallies as the verified leg: (wall, done, bad_crc, wrong_part,
/// notes).
async fn payout_leg_steered(
    servers: Vec<(ServerConfig, PoolConfig)>,
    ids: Vec<ArticleReq>,
) -> (Duration, usize, usize, usize, Vec<String>) {
    let parts: std::collections::HashMap<String, u32> = ids
        .iter()
        .filter(|r| r.part > 0)
        .map(|r| (r.id.clone(), r.part))
        .collect();
    let live = LiveStats::for_servers(&servers);
    let servers: Vec<(ServerConfig, PoolConfig)> = servers
        .into_iter()
        .map(|(s, mut c)| {
            c.live = Some(live.clone());
            (s, c)
        })
        .collect();
    let ctl = Arc::new(QueueControl::default());
    let (tx, mut rx) = mpsc::channel(64);
    let t0 = Instant::now();
    let ctl_fetch = ctl.clone();
    let fetch =
        tokio::spawn(async move { fetch_all_multi_ctl(&servers, ids, tx, Some(&ctl_fetch)).await });
    let collect = tokio::spawn(async move {
        let (mut done, mut bad_crc, mut wrong_part) = (0usize, 0usize, 0usize);
        let mut scratch = Vec::new();
        while let Some(o) = rx.recv().await {
            if let FetchOutcome::Done { id, raw } = o {
                match crate::yenc_simd::decode_into_integrity(&raw, &mut scratch, true) {
                    Err(_) => {
                        if ctl.note_decoded(
                            &id,
                            DecodeReport::Bad {
                                why: "yEnc decode/CRC failed",
                            },
                        ) == DecodeAck::Steered
                        {
                            continue;
                        }
                        done += 1;
                        bad_crc += 1;
                    }
                    Ok((meta, _)) => {
                        if ctl.note_decoded(&id, DecodeReport::Clean { part: meta.part })
                            == DecodeAck::Steered
                        {
                            continue;
                        }
                        done += 1;
                        if let (Some(&want), Some(got)) = (parts.get(&id), meta.part)
                            && got != want
                        {
                            wrong_part += 1;
                        }
                    }
                }
            }
        }
        (done, bad_crc, wrong_part)
    });
    tokio::time::timeout(Duration::from_secs(120), fetch)
        .await
        .expect("steered payout leg hung")
        .unwrap();
    let elapsed = t0.elapsed();
    let (done, bad_crc, wrong_part) = collect.await.unwrap();
    let notes: Vec<String> = live
        .events
        .lock()
        .unwrap()
        .iter()
        .map(|e| format!("{} {}", e.host, e.detail))
        .collect();
    (elapsed, done, bad_crc, wrong_part, notes)
}

/// TODO 114, corrupt storm through the consumer seam (`crc_steer`):
/// the acking collector (playing the decode consumer) reports each
/// body's verdict through `note_decoded`, and a bad body is
/// requeued AFTER claim/delivery. Server A corrupts EVERYTHING it
/// serves (not every 3rd) with 3 of the 4 connections, so steers
/// keep firing all the way through the tail - the shape only the
/// deferred `complete_one` can serve: with completion charged at
/// delivery, the run would already be over when the last verdicts
/// arrived.
#[tokio::test(flavor = "multi_thread")]
async fn crc_steer_storm_steers_damage_from_the_consumer_seam() {
    let data: Vec<u8> = (0..480_000u32).map(|i| (i >> 3) as u8).collect();
    let mk_maps = || {
        let mut articles = std::collections::HashMap::new();
        let segs = crate::mock::make_file_articles("s.bin", &data, 8_000, "st", &mut articles);
        (articles, segs)
    };
    let (arts_a, segs) = mk_maps();
    let (arts_b, _) = mk_maps();
    let ids: Vec<ArticleReq> = segs
        .iter()
        .map(|(id, _, part)| ArticleReq {
            id: format!("<{id}>"),
            age_days: 0,
            part: *part,
        })
        .collect();
    let a = crate::mock::MockServer::start(
        arts_a,
        crate::mock::Chaos {
            corrupt_every: 1,
            ..Default::default()
        },
    )
    .await;
    let b = crate::mock::MockServer::start(arts_b, Default::default()).await;
    let cfg = PoolConfig {
        crc_steer: true,
        window: 2,
        ..Default::default()
    };
    let servers = vec![payout_server(&a, 3, cfg.clone()), payout_server(&b, 1, cfg)];
    let (_, done, bad, wrong, notes) = payout_leg_steered(servers, ids).await;
    println!("consumer-steer storm: {bad} damaged of {done} owned");
    assert_eq!(done, segs.len());
    assert_eq!(wrong, 0, "no split-brain in this rig");
    // Every body A serves is corrupt and B holds a clean copy of
    // every id - so not one corrupt body may be OWNED by the
    // consumer, however late in the run it was delivered.
    assert_eq!(bad, 0, "consumer steer accepted corrupt bodies: {notes:?}");
    assert!(
        notes
            .iter()
            .any(|n| n.contains("refetching from another server")),
        "no consumer steer was ever noted: {notes:?}"
    );
}

/// TODO 114, split-brain through the consumer seam (`crc_steer`).
/// The consumer reports the DECODED
/// part number; the expected-part comparison (the load-bearing
/// identity check - these bodies PASS their own pcrc32) happens in
/// the pool, which owns `Shared::parts`.
#[tokio::test(flavor = "multi_thread")]
async fn crc_steer_covers_split_brain_from_the_consumer_seam() {
    let data: Vec<u8> = (0..320_000u32).map(|i| (i >> 2) as u8).collect();
    let mk_maps = || {
        let mut articles = std::collections::HashMap::new();
        let segs = crate::mock::make_file_articles("v.bin", &data, 8_000, "vb", &mut articles);
        (articles, segs)
    };
    let (arts_a, segs) = mk_maps();
    let (arts_b, _) = mk_maps();
    let swap: std::collections::HashMap<String, String> = [5, 11, 17, 23, 29, 35]
        .into_iter()
        .map(|i| (format!("<{}>", segs[i].0), format!("<{}>", segs[i + 1].0)))
        .collect();
    let ids: Vec<ArticleReq> = segs
        .iter()
        .map(|(id, _, part)| ArticleReq {
            id: format!("<{id}>"),
            age_days: 0,
            part: *part,
        })
        .collect();
    let a = crate::mock::MockServer::start(
        arts_a,
        crate::mock::Chaos {
            swap,
            ..Default::default()
        },
    )
    .await;
    let b = crate::mock::MockServer::start(arts_b, Default::default()).await;
    let cfg = PoolConfig {
        crc_steer: true,
        window: 2,
        ..Default::default()
    };
    let servers = vec![payout_server(&a, 3, cfg.clone()), payout_server(&b, 1, cfg)];
    let (_, done, bad, wrong, notes) = payout_leg_steered(servers, ids).await;
    println!("consumer-steer split-brain: {wrong} wrong of {done} owned");
    assert_eq!(done, segs.len());
    assert_eq!(bad, 0, "split-brain bodies must PASS pcrc32");
    assert_eq!(wrong, 0, "consumer steer accepted wrong bodies: {notes:?}");
    assert!(
        notes.iter().any(|n| n.contains("wrong article")),
        "no part-mismatch steer was ever noted: {notes:?}"
    );
}

/// TODO 114 anti-wedge: `crc_steer` on a SINGLE-server config (no
/// elsewhere - `other_can_take` can never say yes). Every corrupt
/// body must be delivered as-is and the run must terminate: the
/// deferred `complete_one` settles at the consumer's verdict, so a
/// finalize that never fired would hang the fetch with pending > 0
/// forever. This is the exact shape the graduated default must be
/// free on.
#[tokio::test(flavor = "multi_thread")]
async fn crc_steer_single_server_delivers_as_is_and_terminates() {
    let data: Vec<u8> = (0..160_000u32).map(|i| (i >> 2) as u8).collect();
    let mut articles = std::collections::HashMap::new();
    let segs = crate::mock::make_file_articles("l.bin", &data, 8_000, "ls", &mut articles);
    let ids: Vec<ArticleReq> = segs
        .iter()
        .map(|(id, _, part)| ArticleReq {
            id: format!("<{id}>"),
            age_days: 0,
            part: *part,
        })
        .collect();
    let a = crate::mock::MockServer::start(
        articles,
        crate::mock::Chaos {
            corrupt_every: 3,
            ..Default::default()
        },
    )
    .await;
    let cfg = PoolConfig {
        crc_steer: true,
        window: 2,
        ..Default::default()
    };
    let servers = vec![payout_server(&a, 2, cfg)];
    let (_, done, bad, wrong, notes) = payout_leg_steered(servers, ids).await;
    println!("consumer-steer single-server: {bad} damaged of {done} owned");
    assert_eq!(done, segs.len(), "run must terminate with every id owned");
    assert_eq!(wrong, 0);
    assert!(bad >= 3, "the storm never bit ({bad} corrupt) - rig broken");
    assert!(
        !notes.iter().any(|n| n.contains("refetching")),
        "steered with nowhere to go: {notes:?}"
    );
}

/// TODO 114 second-bad-copy bound: BOTH servers corrupt everything
/// they serve, `crc_steer` on. Each id steers exactly once
/// (`Shared::crc_retried`), the refetched copy is also bad, and
/// the consumer owns it - damage delivered, run terminates, no
/// steer loop. Mirrors "exactly like the knob being off" from the
/// shipped gate's contract.
#[tokio::test(flavor = "multi_thread")]
async fn crc_steer_second_bad_copy_is_owned_not_looped() {
    let data: Vec<u8> = (0..160_000u32).map(|i| (i >> 2) as u8).collect();
    let mk_maps = || {
        let mut articles = std::collections::HashMap::new();
        let segs = crate::mock::make_file_articles("m.bin", &data, 8_000, "mb", &mut articles);
        (articles, segs)
    };
    let (arts_a, segs) = mk_maps();
    let (arts_b, _) = mk_maps();
    let ids: Vec<ArticleReq> = segs
        .iter()
        .map(|(id, _, part)| ArticleReq {
            id: format!("<{id}>"),
            age_days: 0,
            part: *part,
        })
        .collect();
    let chaos = crate::mock::Chaos {
        corrupt_every: 1,
        ..Default::default()
    };
    let a = crate::mock::MockServer::start(arts_a, chaos.clone()).await;
    let b = crate::mock::MockServer::start(arts_b, chaos).await;
    let cfg = PoolConfig {
        crc_steer: true,
        window: 2,
        ..Default::default()
    };
    let servers = vec![payout_server(&a, 2, cfg.clone()), payout_server(&b, 2, cfg)];
    let (_, done, bad, _, _) = payout_leg_steered(servers, ids).await;
    println!("consumer-steer both-bad: {bad} damaged of {done} owned");
    assert_eq!(done, segs.len(), "run must terminate with every id owned");
    assert_eq!(
        bad,
        segs.len(),
        "every id's second copy is also corrupt and must be owned as-is"
    );
}

/// Gauntlet leg: like `payout_leg` but returns the outcome tallies
/// AND the LiveStats. The mocks all answer to the host string
/// "127.0.0.1", so per-server claims (which server got clamped, who
/// suffered session churn) must come from the per-INDEX gauges, not
/// the event ring's host field.
async fn gauntlet_leg(
    servers: Vec<(ServerConfig, PoolConfig)>,
    ids: Vec<ArticleReq>,
) -> (Duration, usize, usize, Arc<LiveStats>) {
    let live = LiveStats::for_servers(&servers);
    let servers: Vec<(ServerConfig, PoolConfig)> = servers
        .into_iter()
        .map(|(s, mut c)| {
            c.live = Some(live.clone());
            (s, c)
        })
        .collect();
    let (tx, mut rx) = mpsc::channel(64);
    let t0 = Instant::now();
    let fetch = tokio::spawn(async move { fetch_all_multi(&servers, ids, tx).await });
    let collect = tokio::spawn(async move {
        let (mut done, mut missing) = (0usize, 0usize);
        while let Some(o) = rx.recv().await {
            match o {
                FetchOutcome::Done { .. } => done += 1,
                FetchOutcome::Missing { .. } => missing += 1,
                FetchOutcome::Failed { .. } => {}
            }
        }
        (done, missing)
    });
    tokio::time::timeout(Duration::from_secs(120), fetch)
        .await
        .expect("gauntlet leg hung")
        .unwrap();
    let elapsed = t0.elapsed();
    let (done, missing) = collect.await.unwrap();
    (elapsed, done, missing, live)
}

/// Count of flap-clamp announcements in a leg's event ring. At most
/// one per server per run by construction (`flap_noted`), so this is
/// also "how many servers were clamped".
fn clamp_count(live: &LiveStats) -> usize {
    live.events
        .lock()
        .unwrap()
        .iter()
        .filter(|e| e.detail.contains("sessions flapping"))
        .count()
}

/// THE GAUNTLET (TODO 111 interaction stage): four servers, four
/// SIMULTANEOUS distinct faults in one run - an IP-cap flapper
/// (accept_cap + die-every-body), a mid-run brownout, a jittery but
/// healthy link, and a clean server - across three config tiers:
/// everything off, the shipped defaults, and everything on (shipped
/// + adaptive timeout + the dark knobs hot_spare and recycle_slow).
/// The prior rounds priced each mitigation ALONE; this run pins the
/// safety gates in combination:
///   - every article completes on every tier;
///   - everything-on is never worse than shipped by more than 10%;
///   - the flap clamp fires exactly once, and only the flapper can
///     have earned it: FLAP_DEATHS is 6, the brownout's mute
///     frontend kills at most its 3 initial established sessions
///     (post-brownout sessions never serve a byte, so their deaths
///     do not count), and the jitter/clean servers drop nothing;
///   - the jittery server suffers ZERO session kills on every tier
///     (its reconnects gauge stays 0): the flat timeout, the
///     adaptive budget, the slope recycle and the race-loss recycle
///     all sit above 1.5 s spikes alone, and must stay there when
///     armed together.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "wall-clock payout measurement - run with --ignored"]
async fn gauntlet_four_faults_three_config_tiers() {
    // Sized so the mitigated legs still run ~8 s: the flap clamp
    // needs FLAP_DEATHS established-session deaths to accumulate
    // BEFORE the queue drains, and a 4 s leg raced it (measured:
    // the shipped tier finished clampless at 2.4 MB).
    let data: Vec<u8> = (0..4_800_000u32).map(|i| i as u8).collect();
    let mut articles = std::collections::HashMap::new();
    let segs = crate::mock::make_file_articles("g.bin", &data, 20_000, "gl", &mut articles);
    // tier 0 = everything off, 1 = shipped defaults, 2 = everything on
    let leg = |tier: u8| {
        let articles = articles.clone();
        let ids: Vec<ArticleReq> = segs
            .iter()
            .map(|(id, _, _)| ArticleReq::fresh(format!("<{id}>")))
            .collect();
        async move {
            let flapper = crate::mock::MockServer::start(
                articles.clone(),
                crate::mock::Chaos {
                    accept_cap: Some(2),
                    drop_after: 1,
                    // Fast enough that the two cap winners cycle
                    // (serve one body, die) quickly - the clamp
                    // needs their deaths on the board early.
                    throttle: crate::mock::Throttle {
                        per_conn_bps: 100_000,
                        ..Default::default()
                    },
                    ..Default::default()
                },
            )
            .await;
            let brownout = crate::mock::MockServer::start(
                articles.clone(),
                crate::mock::Chaos {
                    brownout_after: 30,
                    throttle: crate::mock::Throttle {
                        per_conn_bps: 100_000,
                        ..Default::default()
                    },
                    ..Default::default()
                },
            )
            .await;
            let jittery = crate::mock::MockServer::start(
                articles.clone(),
                crate::mock::Chaos {
                    jitter: Some((5, 1_500)),
                    throttle: crate::mock::Throttle {
                        per_conn_bps: 100_000,
                        ..Default::default()
                    },
                    ..Default::default()
                },
            )
            .await;
            let clean = crate::mock::MockServer::start(
                articles,
                crate::mock::Chaos {
                    throttle: crate::mock::Throttle {
                        per_conn_bps: 150_000,
                        ..Default::default()
                    },
                    ..Default::default()
                },
            )
            .await;
            let cfg = PoolConfig {
                flap_breaker: tier >= 1,
                tail_fanout: tier >= 1,
                tail_fanout_early: tier >= 1,
                hedge: tier >= 1,
                recycle_slope: tier >= 1,
                adaptive_timeout: tier >= 2,
                hot_spare: tier >= 2,
                recycle_slow: tier >= 2,
                read_timeout: Duration::from_secs(12),
                connect_backoff: Duration::from_millis(100),
                ..Default::default()
            };
            // Staggered flapper dials (the other servers keep ramp 0):
            // six simultaneous dials race the mock's live count to 6
            // before any accept task checks the cap, so every one of
            // them can bounce and the capacity-yield ladder may bow
            // the whole fleet out before a single session
            // establishes. 50 ms apart, the first two win their
            // slots and the rest bounce off a genuinely full cap -
            // the shape the clamp exists for.
            let fcfg = PoolConfig {
                connections: 6,
                ramp_delay: Duration::from_millis(50),
                ..cfg.clone()
            };
            let mut fsc = flapper.server_config();
            fsc.connections = 6;
            let servers = vec![
                (fsc, fcfg),
                payout_server(&brownout, 3, cfg.clone()),
                payout_server(&jittery, 3, cfg.clone()),
                payout_server(&clean, 3, cfg),
            ];
            gauntlet_leg(servers, ids).await
        }
    };
    let (t_off, done_off, miss_off, live_off) = leg(0).await;
    let (t_ship, done_ship, miss_ship, live_ship) = leg(1).await;
    let (t_on, done_on, miss_on, live_on) = leg(2).await;
    let jitter_kills = |l: &LiveStats| l.servers[2].reconnects.load(Ordering::Relaxed);
    let clean_kills = |l: &LiveStats| l.servers[3].reconnects.load(Ordering::Relaxed);
    // Mechanism counters, for attributing any unexpected churn: the
    // ring's host field cannot tell the mocks apart, but the detail
    // text names the knob that acted.
    let recycles = |l: &LiveStats, what: &str| {
        l.events
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.detail.contains(what))
            .count()
    };
    println!(
        "gauntlet notes on-tier: slow-recycles {} slope-recycles {}",
        recycles(&live_on, "recycled a slow session"),
        recycles(&live_on, "recycled a degraded session"),
    );
    println!(
        "gauntlet: off {t_off:?} shipped {t_ship:?} on {t_on:?} · clamps \
         off/ship/on {}/{}/{} · jitter kills {}/{}/{} · clean kills {}/{}/{}",
        clamp_count(&live_off),
        clamp_count(&live_ship),
        clamp_count(&live_on),
        jitter_kills(&live_off),
        jitter_kills(&live_ship),
        jitter_kills(&live_on),
        clean_kills(&live_off),
        clean_kills(&live_ship),
        clean_kills(&live_on),
    );
    for (name, done, miss) in [
        ("off", done_off, miss_off),
        ("shipped", done_ship, miss_ship),
        ("on", done_on, miss_on),
    ] {
        assert_eq!(done, segs.len(), "{name} tier lost articles");
        assert_eq!(miss, 0, "{name} tier declared healthy articles Missing");
    }
    // Rig sanity is ENGAGEMENT, not a wall ordering: on loopback the
    // flapper's cap churn is free (instant redials), so the clamp
    // can trade a little wall time for the churn it removes and the
    // off tier is NOT reliably the slowest. What must be true is
    // that the faults actually bit - the unmitigated flapper churned
    // hard enough that a clamp had something to engage on.
    assert!(
        live_off.servers[0].reconnects.load(Ordering::Relaxed) >= FLAP_DEATHS as u64,
        "rig broken - the flapper never churned on the off tier"
    );
    assert!(
        t_on.as_secs_f64() < t_ship.as_secs_f64() * 1.10,
        "everything-on regressed the shipped defaults ({t_on:?} vs {t_ship:?})"
    );
    assert_eq!(
        clamp_count(&live_off),
        0,
        "the clamp fired with the breaker off - knob leak"
    );
    assert_eq!(
        clamp_count(&live_ship),
        1,
        "expected exactly the flapper clamped on the shipped tier"
    );
    assert_eq!(
        clamp_count(&live_on),
        1,
        "expected exactly the flapper clamped on the everything-on tier"
    );
    for (name, l) in [
        ("off", &live_off),
        ("shipped", &live_ship),
        ("on", &live_on),
    ] {
        assert_eq!(
            jitter_kills(l),
            0,
            "{name} tier killed sessions on the jittery-but-healthy server"
        );
        assert_eq!(
            clean_kills(l),
            0,
            "{name} tier killed sessions on the clean server"
        );
    }
}

/// FIGHT PROBE (TODO 111): dup racing + recycle_slow versus the flap
/// keeper. After the clamp, the keeper is the flapping server's only
/// session and it crawls, so the healthy server's idle workers dup
/// its articles via the rate rule and usually win. With recycle_slow
/// ON, two consecutive race losses shed the keeper's pipeline and
/// redial it - churn the clamp exists to stop, potentially
/// reintroduced by another knob. Measured claim: switching
/// recycle_slow on must not inflate the flapping server's accepted
/// sessions past 2x its knob-off churn, and must not cost wall time.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "wall-clock payout measurement - run with --ignored"]
async fn fight_recycle_slow_must_not_churn_the_flap_keeper() {
    let data: Vec<u8> = (0..6_000_000u32).map(|i| i as u8).collect();
    let mut articles = std::collections::HashMap::new();
    let segs = crate::mock::make_file_articles("f.bin", &data, 30_000, "fk", &mut articles);
    let leg = |recycle: bool| {
        let arts_a = articles.clone();
        let arts_b = articles.clone();
        let ids: Vec<ArticleReq> = segs
            .iter()
            .map(|(id, _, _)| ArticleReq::fresh(format!("<{id}>")))
            .collect();
        async move {
            let flapper = crate::mock::MockServer::start(
                arts_a,
                crate::mock::Chaos {
                    accept_cap: Some(2),
                    drop_after: 2,
                    throttle: crate::mock::Throttle {
                        per_conn_bps: 100_000,
                        ..Default::default()
                    },
                    ..Default::default()
                },
            )
            .await;
            let steady = crate::mock::MockServer::start(
                arts_b,
                crate::mock::Chaos {
                    throttle: crate::mock::Throttle {
                        per_conn_bps: 150_000,
                        ..Default::default()
                    },
                    ..Default::default()
                },
            )
            .await;
            let cfg = PoolConfig {
                flap_breaker: true,
                tail_fanout: true,
                tail_fanout_early: true,
                hedge: true,
                recycle_slow: recycle,
                read_timeout: Duration::from_secs(12),
                connect_backoff: Duration::from_millis(100),
                ..Default::default()
            };
            // The flapper's dials are STAGGERED (unlike payout_server's
            // ramp 0): six simultaneous dials race the mock's live
            // count to 6 before any task checks the cap, every one of
            // them bounces, and the capacity-yield ladder can bow the
            // whole fleet out before a single session establishes -
            // measured as a served-0, clampless flapper. Real dials
            // are never perfectly simultaneous; 50 ms apart, the
            // first two win their slots and the rest bounce off a
            // genuinely full cap, which is the shape the clamp is for.
            let fcfg = PoolConfig {
                connections: 6,
                ramp_delay: Duration::from_millis(50),
                ..cfg.clone()
            };
            let mut fsc = flapper.server_config();
            fsc.connections = 6;
            let servers = vec![(fsc, fcfg), payout_server(&steady, 3, cfg)];
            let r = gauntlet_leg(servers, ids).await;
            (
                r,
                flapper.accepted.load(Ordering::Relaxed),
                flapper.served.load(Ordering::Relaxed),
            )
        }
    };
    let ((t_off, done_off, _, live_off), acc_off, served_off) = leg(false).await;
    let ((t_on, done_on, _, live_on), acc_on, served_on) = leg(true).await;
    let recycles = |l: &LiveStats| {
        l.events
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.detail.contains("recycled a slow session"))
            .count()
    };
    println!(
        "keeper churn: off {t_off:?} accepted {acc_off} served {served_off} · \
         on {t_on:?} accepted {acc_on} served {served_on} (recycles {})",
        recycles(&live_on)
    );
    assert_eq!(done_off, segs.len());
    assert_eq!(done_on, segs.len());
    assert_eq!(
        clamp_count(&live_off),
        1,
        "rig broken - the clamp never engaged"
    );
    assert_eq!(
        clamp_count(&live_on),
        1,
        "rig broken - the clamp never engaged"
    );
    assert_eq!(
        recycles(&live_off),
        0,
        "recycle fired with the knob off - knob leak"
    );
    assert!(
        acc_on <= acc_off * 2,
        "recycle_slow redial-stormed the clamped server \
         ({acc_on} accepted sessions vs {acc_off} with the knob off)"
    );
    assert!(
        t_on.as_secs_f64() < t_off.as_secs_f64() * 1.15,
        "recycle_slow cost wall time on the clamped rig ({t_on:?} vs {t_off:?})"
    );
}

/// FIGHT PROBE (TODO 111): slope recycle + adaptive timeout on the
/// same degraded session must not double-punish. The slope rule
/// redials a session delivering under a quarter of its siblings'
/// rate; the adaptive budget's stall deadline rolls with progress,
/// so a slow-but-alive transfer must NOT also be killed as stalled
/// (a kill strikes the session and requeues its pipeline - paying
/// twice for one diagnosis). Claim: adding adaptive to slope changes
/// neither completion nor churn beyond the slope's own deliberate
/// redial, and costs no wall time.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "wall-clock payout measurement (~1 min) - run with --ignored"]
async fn fight_slope_plus_adaptive_must_not_double_punish() {
    // 120 articles, like payout_slope: the slope rule only runs while
    // pending > ENDGAME_MAX (64), so a smaller queue leaves the
    // normal phase before the 10 s proof window opens and the knob
    // structurally cannot fire (measured: 72 articles, zero slope
    // recycles in either leg).
    let data: Vec<u8> = (0..6_000_000u32).map(|i| i as u8).collect();
    let mut articles = std::collections::HashMap::new();
    let segs = crate::mock::make_file_articles("s2.bin", &data, 50_000, "sa", &mut articles);
    let leg = |adaptive: bool| {
        let articles = articles.clone();
        let ids: Vec<ArticleReq> = segs
            .iter()
            .map(|(id, _, _)| ArticleReq::fresh(format!("<{id}>")))
            .collect();
        async move {
            let srv = crate::mock::MockServer::start(
                articles,
                crate::mock::Chaos {
                    slow_conn: Some((1, 8_000)),
                    throttle: crate::mock::Throttle {
                        per_conn_bps: 100_000,
                        ..Default::default()
                    },
                    ..Default::default()
                },
            )
            .await;
            let cfg = PoolConfig {
                recycle_slope: true,
                adaptive_timeout: adaptive,
                read_timeout: Duration::from_secs(12),
                ..Default::default()
            };
            gauntlet_leg(vec![payout_server(&srv, 3, cfg)], ids).await
        }
    };
    let (t_off, done_off, _, live_off) = leg(false).await;
    let (t_on, done_on, _, live_on) = leg(true).await;
    let churn = |l: &LiveStats| l.servers[0].reconnects.load(Ordering::Relaxed);
    let slopes = |l: &LiveStats| {
        l.events
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.detail.contains("recycled a degraded session"))
            .count()
    };
    println!(
        "slope+adaptive: slope-only {t_off:?} ({} reconnects, {} slope) · \
         both {t_on:?} ({} reconnects, {} slope)",
        churn(&live_off),
        slopes(&live_off),
        churn(&live_on),
        slopes(&live_on),
    );
    assert_eq!(done_off, segs.len());
    assert_eq!(done_on, segs.len());
    assert!(
        slopes(&live_on) >= 1,
        "rig broken - the slope recycle never fired with adaptive on"
    );
    // The slope's own deliberate redial is the only churn either leg
    // should show; adaptive piling kills on top would read as extra
    // reconnects here.
    assert!(
        churn(&live_on) <= churn(&live_off) + 1,
        "adaptive added session kills on top of the slope recycle \
         ({} vs {})",
        churn(&live_on),
        churn(&live_off)
    );
    assert!(
        t_on.as_secs_f64() < t_off.as_secs_f64() * 1.25,
        "adaptive cost wall time on the degraded-session rig ({t_on:?} vs {t_off:?})"
    );
}

/// FIGHT PROBE (TODO 111): tail fan-out must not eat the hot spare.
/// Racers are never fresh dials - `pick_dup` hands dup work to a
/// connection that already exists (idle primaries), and the spare is
/// only claimable at session START after a death (`session_loop`
/// takes `spares[idx]` before dialling). So on a healthy run with
/// both knobs on, the accepted-session count must be exactly the
/// workers plus the one parked spare - a fan-out that dialled extra
/// sessions, or ate and re-filled the spare, would show up right
/// here. Count-based, so it runs in the normal suite.
#[tokio::test(flavor = "multi_thread")]
async fn fanout_does_not_eat_the_hot_spare() {
    let data: Vec<u8> = (0..1_200_000u32).map(|i| i as u8).collect();
    let mut articles = std::collections::HashMap::new();
    let segs = crate::mock::make_file_articles("h2.bin", &data, 20_000, "hs", &mut articles);
    let ids: Vec<ArticleReq> = segs
        .iter()
        .map(|(id, _, _)| ArticleReq::fresh(format!("<{id}>")))
        .collect();
    let srv = crate::mock::MockServer::start(
        articles,
        crate::mock::Chaos {
            throttle: crate::mock::Throttle {
                per_conn_bps: 400_000,
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .await;
    let cfg = PoolConfig {
        tail_fanout: true,
        tail_fanout_early: true,
        hot_spare: true,
        ..Default::default()
    };
    let (_, done, missing, _) = gauntlet_leg(vec![payout_server(&srv, 3, cfg)], ids).await;
    assert_eq!(done, segs.len());
    assert_eq!(missing, 0);
    let accepted = srv.accepted.load(Ordering::Relaxed);
    assert!(
        accepted <= 4,
        "expected 3 workers + 1 parked spare, got {accepted} accepted \
         sessions - something dialled beyond the budget"
    );
}

/// FIGHT PROBE (TODO 111): the flap clamp must not break 430
/// unanimity. A clamped server still counts in `live_mask` while its
/// keeper lives, so a Missing verdict needs the keeper's own 430
/// vote (or the server's full death). Six ids exist on NO server;
/// the flapping server clamps early in the run; every one of the six
/// must still reach its Missing verdict and the job must terminate -
/// a clamp that muted the keeper's vote would hang these forever.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "wall-clock payout measurement - run with --ignored"]
async fn fight_flap_clamp_still_reaches_missing_verdicts() {
    let data: Vec<u8> = (0..3_000_000u32).map(|i| i as u8).collect();
    let mut articles = std::collections::HashMap::new();
    let segs = crate::mock::make_file_articles("m2.bin", &data, 30_000, "mv", &mut articles);
    let ghosts: Vec<String> = (0..6).map(|i| format!("<ghost-{i}@mv>")).collect();
    let ids: Vec<ArticleReq> = segs
        .iter()
        .map(|(id, _, _)| format!("<{id}>"))
        .chain(ghosts.iter().cloned())
        .map(ArticleReq::fresh)
        .collect();
    let flapper = crate::mock::MockServer::start(
        articles.clone(),
        crate::mock::Chaos {
            accept_cap: Some(2),
            drop_after: 1,
            throttle: crate::mock::Throttle {
                per_conn_bps: 60_000,
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .await;
    let steady = crate::mock::MockServer::start(
        articles,
        crate::mock::Chaos {
            throttle: crate::mock::Throttle {
                per_conn_bps: 150_000,
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .await;
    let cfg = PoolConfig {
        flap_breaker: true,
        tail_fanout: true,
        tail_fanout_early: true,
        hedge: true,
        recycle_slope: true,
        read_timeout: Duration::from_secs(12),
        connect_backoff: Duration::from_millis(100),
        ..Default::default()
    };
    // Staggered flapper dials, same reason as the keeper-churn probe:
    // six simultaneous dials all bounce off the mock's racing live
    // count and the capacity-yield ladder can kill the server before
    // it ever flaps.
    let fcfg = PoolConfig {
        connections: 6,
        ramp_delay: Duration::from_millis(50),
        ..cfg.clone()
    };
    let mut fsc = flapper.server_config();
    fsc.connections = 6;
    let servers = vec![(fsc, fcfg), payout_server(&steady, 3, cfg)];
    let (t, done, missing, live) = gauntlet_leg(servers, ids).await;
    println!(
        "clamp+unanimity: {t:?}, {done} done, {missing} missing, clamps {}",
        clamp_count(&live)
    );
    assert_eq!(done, segs.len(), "lost real articles");
    assert_eq!(
        missing,
        ghosts.len(),
        "the poisoned articles never reached their Missing verdicts under the clamp"
    );
    assert_eq!(
        clamp_count(&live),
        1,
        "rig broken - the clamp never engaged"
    );
}

/// Early fan-out (NZBFAST_TAIL_FANOUT=2): the tail latch arms the
/// endgame dup rules at queue-dry, well above ENDGAME_MAX pending;
/// plain fan-out (=1) still waits for the pending threshold.
#[tokio::test]
async fn early_fanout_arms_at_the_tail_latch_not_the_pending_floor() {
    let mk = |host: &str, early: bool| {
        (
            ServerConfig {
                host: host.into(),
                port: 119,
                tls: false,
                username: None,
                password: None,
                connections: 1,
                pin_connections: false,
                level: 0,
                group: None,
                retention_days: 0,
                rcvbuf: None,
                block_bytes: None,
                bind_ip: None,
                socks5: None,
                enabled: true,
                warm_pool: false,
                idle_release_secs: None,
                idle_keep: None,
                max_source_ips: None,
            },
            PoolConfig {
                tail_fanout: true,
                tail_fanout_early: early,
                ..Default::default()
            },
        )
    };
    let mk_reqs = || -> Vec<ArticleReq> {
        (0..(ENDGAME_MAX + 40))
            .map(|i| ArticleReq::fresh(format!("<q{i}>")))
            .collect()
    };
    let w = Work {
        id: "<q0>".into(),
        attempts: 0,
        promoted: false,
        tried_430: 0,
        tried_fail: 0,
        dup: false,
        prebyte_expiries: 0,
        soft_430: 0,
    };

    // Plain fan-out, tail latched, pending far above the floor: the
    // endgame rules stay dark.
    let servers = vec![mk("a", false), mk("b", false)];
    let (plain, _) = Shared::new(mk_reqs(), &servers);
    plain
        .tail_started
        .lock_ok()
        .get_or_insert_with(Instant::now);
    plain.register_inflight(&w, 0);
    plain.inflight.lock_ok().get_mut("<q0>").unwrap().dispatched =
        Instant::now() - Duration::from_secs(1);
    assert!(
        plain.pick_dup(1, 0b10, 0b10, 0, 0, 0).is_none(),
        "plain fan-out fired above ENDGAME_MAX"
    );

    // Early fan-out: same shape, latch armed -> healthy race fires.
    let servers = vec![mk("a", true), mk("b", true)];
    let (early, _) = Shared::new(mk_reqs(), &servers);
    early.register_inflight(&w, 0);
    early.inflight.lock_ok().get_mut("<q0>").unwrap().dispatched =
        Instant::now() - Duration::from_secs(1);
    // ...but not before the latch: no tail, no early rules.
    assert!(
        early.pick_dup(1, 0b10, 0b10, 0, 0, 0).is_none(),
        "early fan-out fired before the queue ever ran dry"
    );
    early
        .tail_started
        .lock_ok()
        .get_or_insert_with(Instant::now);
    let d = early
        .pick_dup(1, 0b10, 0b10, 0, 0, 0)
        .expect("early fan-out races at the tail latch");
    assert_eq!(d.id, "<q0>");
    assert!(d.dup);

    // Refetch exemption: an article on its recovery leg (tried_fail
    // set by a CRC-steer or failure requeue) is never fan-out raced -
    // not even by its own server, whose same-server allowance was the
    // dup-storm path on the damage matrix legs (one lost race per
    // steered article). It still falls through to the rate rules,
    // where the same-server and my-bit gates already refuse it.
    let servers = vec![mk("a", true), mk("b", true)];
    let (steered, _) = Shared::new(mk_reqs(), &servers);
    steered
        .tail_started
        .lock_ok()
        .get_or_insert_with(Instant::now);
    let refetch = Work {
        id: "<q0>".into(),
        attempts: 0,
        promoted: false,
        tried_430: 0,
        tried_fail: 0b01, // steered off server a
        dup: false,
        prebyte_expiries: 0,
        soft_430: 0,
    };
    steered.register_inflight(&refetch, 1); // recovery leg on server b
    steered
        .inflight
        .lock_ok()
        .get_mut("<q0>")
        .unwrap()
        .dispatched = Instant::now() - Duration::from_secs(1);
    assert!(
        steered.pick_dup(1, 0b10, 0b10, 0, 0, 0).is_none(),
        "fan-out raced a steer refetch on its own server"
    );
    assert!(
        steered.pick_dup(0, 0b01, 0b01, 0, 0, 0).is_none(),
        "the server whose copy was bad re-raced the refetch"
    );
}

/// Tail-prefetch experiment: `QueueControl::tail_pending` answers
/// None before the pool's tail latch, Some(pending) after, and None
/// again once the run's Shared is gone.
#[tokio::test]
async fn queue_control_exports_the_tail_latch() {
    let mk = |host: &str| {
        (
            ServerConfig {
                host: host.into(),
                port: 119,
                tls: false,
                username: None,
                password: None,
                connections: 1,
                pin_connections: false,
                level: 0,
                group: None,
                retention_days: 0,
                rcvbuf: None,
                block_bytes: None,
                bind_ip: None,
                socks5: None,
                enabled: true,
                warm_pool: false,
                idle_release_secs: None,
                idle_keep: None,
                max_source_ips: None,
            },
            PoolConfig::default(),
        )
    };
    let servers = vec![mk("a")];
    let reqs: Vec<ArticleReq> = (0..3)
        .map(|i| ArticleReq::fresh(format!("<t{i}>")))
        .collect();
    let (shared, _) = Shared::new(reqs, &servers);
    let ctl = QueueControl::default();
    ctl.attach(&shared);
    assert_eq!(ctl.tail_pending(), None, "no tail latched yet");
    shared
        .tail_started
        .lock_ok()
        .get_or_insert_with(Instant::now);
    assert_eq!(ctl.tail_pending(), Some(3), "latched tail reports pending");
    drop(shared);
    assert_eq!(ctl.tail_pending(), None, "gone run answers None");
}

/// Hedge experiment (opt-in `PoolConfig::hedge`): the dup race's
/// staleness bound adapts to the trained article-time EWMA (3x,
/// clamped [500 ms, 8 s]) instead of a flat 8 s, the Done path
/// trains the EWMA, and stale-only dups respect the issue-rate cap.
/// Off keeps the flat bound.
#[tokio::test]
async fn hedge_races_a_straggler_at_the_adaptive_bound() {
    let mk = |host: &str, hedge: bool| {
        (
            ServerConfig {
                host: host.into(),
                port: 119,
                tls: false,
                username: None,
                password: None,
                connections: 1,
                pin_connections: false,
                level: 0,
                group: None,
                retention_days: 0,
                rcvbuf: None,
                block_bytes: None,
                bind_ip: None,
                socks5: None,
                enabled: true,
                warm_pool: false,
                idle_release_secs: None,
                idle_keep: None,
                max_source_ips: None,
            },
            PoolConfig {
                hedge,
                ..Default::default()
            },
        )
    };
    let servers = vec![mk("a", true), mk("b", true)];
    // Normal phase: the endgame's own rules must stay out of the way.
    let reqs: Vec<ArticleReq> = (0..(ENDGAME_MAX + 10))
        .map(|i| ArticleReq::fresh(format!("<s{i}>")))
        .collect();
    let (shared, _) = Shared::new(reqs, &servers);

    // Bound math: untrained keeps the flat 8 s; trained is 3x the
    // EWMA clamped to [500 ms, 8 s].
    assert_eq!(shared.hedge_stale_bound(), Duration::from_secs(8));
    shared.art_ms.store(100, Ordering::Relaxed);
    assert_eq!(shared.hedge_stale_bound(), Duration::from_millis(500));
    shared.art_ms.store(400, Ordering::Relaxed);
    assert_eq!(shared.hedge_stale_bound(), Duration::from_millis(1200));
    shared.art_ms.store(10_000, Ordering::Relaxed);
    assert_eq!(shared.hedge_stale_bound(), Duration::from_secs(8));

    // The Done path trains the EWMA (first sample is taken whole).
    shared.art_ms.store(0, Ordering::Relaxed);
    let w0 = Work {
        id: "<s0>".into(),
        attempts: 0,
        promoted: false,
        tried_430: 0,
        tried_fail: 0,
        dup: false,
        prebyte_expiries: 0,
        soft_430: 0,
    };
    shared.register_inflight(&w0, 0);
    shared
        .inflight
        .lock_ok()
        .get_mut("<s0>")
        .unwrap()
        .dispatched = Instant::now() - Duration::from_secs(1);
    shared.deregister_inflight_done(&w0);
    let trained = shared.art_ms.load(Ordering::Relaxed);
    assert!(
        (900..=1200).contains(&trained),
        "one 1 s completion should train the EWMA to ~1000 ms, got {trained}"
    );

    // A healthy article 2 s in flight, equal rates: the flat rule
    // keeps waiting, the trained bound (400 ms EWMA -> 1.2 s) races
    // it and counts a hedge.
    shared.art_ms.store(400, Ordering::Relaxed);
    let w1 = Work {
        id: "<s1>".into(),
        attempts: 0,
        promoted: false,
        tried_430: 0,
        tried_fail: 0,
        dup: false,
        prebyte_expiries: 0,
        soft_430: 0,
    };
    shared.register_inflight(&w1, 0);
    shared
        .inflight
        .lock_ok()
        .get_mut("<s1>")
        .unwrap()
        .dispatched = Instant::now() - Duration::from_secs(2);
    let d = shared
        .pick_dup(1, 0b10, 0b10, 0, 0, 0)
        .expect("straggler past the adaptive bound should be hedged");
    assert_eq!(d.id, "<s1>");
    assert!(d.dup);
    assert_eq!(shared.hedges_issued.load(Ordering::Relaxed), 1);

    // The issue-rate cap gates stale-only dups.
    shared.hedges_issued.store(1000, Ordering::Relaxed);
    let w2 = Work {
        id: "<s2>".into(),
        attempts: 0,
        promoted: false,
        tried_430: 0,
        tried_fail: 0,
        dup: false,
        prebyte_expiries: 0,
        soft_430: 0,
    };
    shared.register_inflight(&w2, 0);
    shared
        .inflight
        .lock_ok()
        .get_mut("<s2>")
        .unwrap()
        .dispatched = Instant::now() - Duration::from_secs(2);
    assert!(
        shared.pick_dup(1, 0b10, 0b10, 0, 0, 0).is_none(),
        "a capped hedge still issued"
    );

    // OFF (the default): 2 s is not stale against the flat 8 s.
    let servers_off = vec![mk("a", false), mk("b", false)];
    let reqs: Vec<ArticleReq> = (0..(ENDGAME_MAX + 10))
        .map(|i| ArticleReq::fresh(format!("<s{i}>")))
        .collect();
    let (off, _) = Shared::new(reqs, &servers_off);
    off.art_ms.store(400, Ordering::Relaxed);
    off.register_inflight(&w1, 0);
    off.inflight.lock_ok().get_mut("<s1>").unwrap().dispatched =
        Instant::now() - Duration::from_secs(2);
    assert!(
        off.pick_dup(1, 0b10, 0b10, 0, 0, 0).is_none(),
        "hedge fired while switched off"
    );
}

/// TTFB-suspicion hedge (TODO 115, opt-in `PoolConfig::ttfb_hedge`):
/// the suspicion bound's math, and every gate on the suspect dup -
/// off by default, suspect flag required, one dup per article,
/// same-server allowed, each server at most once, fill servers
/// never, the hedge issue-rate cap honoured, and the fast-path flag
/// cleared once nothing suspect is left unraced.
#[tokio::test]
async fn suspect_dup_races_a_pre_byte_stall_at_once() {
    // Bound math: floor 1 s, 2x the EWMA past 500 ms.
    assert_eq!(ttfb_suspect_ms(0), 1000);
    assert_eq!(ttfb_suspect_ms(80), 1000);
    assert_eq!(ttfb_suspect_ms(500), 1000);
    assert_eq!(ttfb_suspect_ms(800), 1600);

    let mk = |host: &str, on: bool| {
        (
            ServerConfig {
                host: host.into(),
                port: 119,
                tls: false,
                username: None,
                password: None,
                connections: 1,
                pin_connections: false,
                level: 0,
                group: None,
                retention_days: 0,
                rcvbuf: None,
                block_bytes: None,
                bind_ip: None,
                socks5: None,
                enabled: true,
                warm_pool: false,
                idle_release_secs: None,
                idle_keep: None,
                max_source_ips: None,
            },
            PoolConfig {
                ttfb_hedge: on,
                adaptive_timeout: on,
                ..Default::default()
            },
        )
    };
    let mk_work = |id: &str| Work {
        id: id.into(),
        attempts: 0,
        promoted: false,
        tried_430: 0,
        tried_fail: 0,
        dup: false,
        prebyte_expiries: 0,
        soft_430: 0,
    };
    let servers = vec![mk("a", true), mk("b", true)];
    let reqs: Vec<ArticleReq> = (0..(ENDGAME_MAX + 10))
        .map(|i| ArticleReq::fresh(format!("<s{i}>")))
        .collect();
    let (shared, _) = Shared::new(reqs, &servers);

    // In flight on server 0, healthy: nobody races it.
    shared.register_inflight(&mk_work("<s0>"), 0);
    assert!(shared.pick_suspect_dup(0b10, 0b10, 0, 0).is_none());

    // Suspicion fires: a SAME-SERVER sibling may race it, the pick
    // counts as a hedge, and the second pick finds nothing (one dup
    // per article) and clears the fast-path flag.
    shared.mark_suspect("<s0>");
    assert!(shared.suspect_pending.load(Ordering::Acquire));
    assert!(
        shared.pick_suspect_dup(0b1, 0b1, 1, 0).is_none(),
        "fill server spent block bytes on a suspicion"
    );
    assert!(
        shared.pick_suspect_dup(0b1, 0b1, 0, 2).is_none(),
        "busy picker displaced queued work with a suspicion dup"
    );
    let d = shared
        .pick_suspect_dup(0b1, 0b1, 0, 0)
        .expect("suspect article should be raced immediately");
    assert_eq!(d.id, "<s0>");
    assert!(d.dup);
    assert_eq!(shared.hedges_issued.load(Ordering::Relaxed), 1);
    assert!(shared.pick_suspect_dup(0b10, 0b10, 0, 0).is_none());
    assert!(
        !shared.suspect_pending.load(Ordering::Acquire),
        "an empty scan should clear the fast-path flag"
    );

    // A server the article already dupped to never re-races it, and
    // the issue-rate cap gates fresh suspicions.
    shared.mark_suspect("<s0>");
    assert!(shared.pick_suspect_dup(0b1, 0b1, 0, 0).is_none());
    shared.register_inflight(&mk_work("<s1>"), 0);
    shared.mark_suspect("<s1>");
    shared.hedges_issued.store(1000, Ordering::Relaxed);
    assert!(
        shared.pick_suspect_dup(0b10, 0b10, 0, 0).is_none(),
        "a capped suspect dup still issued"
    );

    // OFF (the default): a suspect mark goes nowhere.
    let servers_off = vec![mk("a", false), mk("b", false)];
    let reqs: Vec<ArticleReq> = (0..4)
        .map(|i| ArticleReq::fresh(format!("<s{i}>")))
        .collect();
    let (off, _) = Shared::new(reqs, &servers_off);
    assert!(!off.ttfb_hedge, "dark flag leaked into Shared");
    off.register_inflight(&mk_work("<s0>"), 0);
    off.mark_suspect("<s0>");
    assert!(
        off.pick_suspect_dup(0b10, 0b10, 0, 0).is_none(),
        "suspect dup fired while switched off"
    );
}
/// TODO 112: the live connection target moves BOTH directions
/// mid-run. Lowering it must drain the highest slots to their next
/// response boundary and park them (connected falls to the target,
/// no worker retires); raising it must wake them (connected climbs
/// again); and every article still gets its outcome. Assertions are
/// on the `connected` gauge, never on rates - socket counts are
/// deterministic on loopback, throughput is not.
#[tokio::test(flavor = "multi_thread")]
async fn a_live_target_change_parks_and_wakes_workers() {
    let data: Vec<u8> = (0..3_000_000u32).map(|i| i as u8).collect();
    let mut articles = std::collections::HashMap::new();
    let segs = crate::mock::make_file_articles("t.bin", &data, 20_000, "lt", &mut articles);
    let ids: Vec<ArticleReq> = segs
        .iter()
        .map(|(id, _, _)| ArticleReq::fresh(format!("<{id}>")))
        .collect();
    let srv = crate::mock::MockServer::start(
        articles,
        crate::mock::Chaos {
            // Slow enough that the run comfortably outlives three
            // target moves, fast enough to finish inside CI bounds.
            throttle: crate::mock::Throttle {
                per_conn_bps: 150_000,
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .await;
    let target = ConnTarget::new(4);
    let (sc, mut cfg) = payout_server(&srv, 4, PoolConfig::default());
    cfg.live_target = Some(target.clone());
    let servers = vec![(sc, cfg)];
    let live = LiveStats::for_servers(&servers);
    let servers: Vec<(ServerConfig, PoolConfig)> = servers
        .into_iter()
        .map(|(s, mut c)| {
            c.live = Some(live.clone());
            (s, c)
        })
        .collect();
    let (tx, mut rx) = mpsc::channel(64);
    let fetch = tokio::spawn(async move { fetch_all_multi(&servers, ids, tx).await });
    let collect = tokio::spawn(async move {
        let mut done = 0usize;
        while let Some(o) = rx.recv().await {
            if matches!(o, FetchOutcome::Done { .. }) {
                done += 1;
            }
        }
        done
    });
    let connected = |live: &LiveStats| live.servers[0].connected.load(Ordering::Relaxed);
    let wait_conns = |want: usize| {
        let live = live.clone();
        async move {
            let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
            loop {
                let got = live.servers[0].connected.load(Ordering::Relaxed);
                if got == want {
                    return;
                }
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "connected stuck at {got}, wanted {want}"
                );
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    };
    // Phase 1: the full fleet authenticates.
    wait_conns(4).await;
    // Phase 2: lower the target - the three highest slots drain
    // (window 3 x 20 KB at 150 KB/s is sub-second) and park.
    target.set(1);
    wait_conns(1).await;
    // Hold a beat: a parked slot must STAY parked, not flap back.
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_eq!(connected(&live), 1, "a parked slot redialled unasked");
    // Phase 3: raise it again - parked is not retired.
    target.set(3);
    wait_conns(3).await;
    tokio::time::timeout(Duration::from_secs(60), fetch)
        .await
        .expect("run hung across live target changes")
        .unwrap();
    assert_eq!(collect.await.unwrap(), segs.len());
}

/// PAYOUT (TODO 121.1): a cold-storage article - dead air before the
/// status line on EVERY attempt, then a normal answer - survives with
/// no knobs. The per-server widening alone cannot save it: its ladder
/// caps at the 10 s adaptive ceiling and fast pipelined samples
/// re-floor the EWMA between the slow article's retries, so all four
/// attempts ran under 12 s and the article failed on a healthy
/// provider. The article's own expiry count now escalates its next
/// attempt 10 s -> 20 s -> 30 s, so attempt three answers. Runtime is
/// real waiting (~25 s): the budgets under test are consts.
#[tokio::test(flavor = "multi_thread")]
async fn payout_prebyte_escalation_saves_cold_storage_articles() {
    let data: Vec<u8> = (0..320_000u32).map(|i| i as u8).collect();
    let mut articles = std::collections::HashMap::new();
    let segs = crate::mock::make_file_articles("c.bin", &data, 8_000, "cold", &mut articles);
    // The LAST article is the cold one, so the fast bulk has trained
    // the EWMA to the floor by the time it dispatches.
    let cold_id = format!("<{}>", segs.last().unwrap().0);
    let slow_ttfb: std::collections::HashMap<String, u64> =
        [(cold_id.clone(), 12_000u64)].into_iter().collect();
    let srv = crate::mock::MockServer::start(
        articles,
        crate::mock::Chaos {
            slow_ttfb,
            ..Default::default()
        },
    )
    .await;
    let ids: Vec<ArticleReq> = segs
        .iter()
        .map(|(id, _, _)| ArticleReq::fresh(format!("<{id}>")))
        .collect();
    let n = ids.len();
    let cfg = PoolConfig {
        adaptive_timeout: true,
        ..Default::default()
    };
    let (elapsed, done, _) = payout_leg(vec![payout_server(&srv, 3, cfg)], ids).await;
    println!("cold-storage payout: {elapsed:?} for {done}/{n}");
    assert_eq!(
        done, n,
        "the cold-storage article must complete without NZBFAST_READ_TIMEOUT_SECS"
    );
}

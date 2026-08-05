//! TODO 112: the live connection tuner, measured end to end.
//!
//! The pure decision rules are pinned in `livetune`'s unit tests; these
//! rigs ask the only question those cannot - does the whole loop hang
//! together against a REAL pool and a mock provider with a real
//! bandwidth shape (knee = line_bps / per_conn_bps)? Three rigs, per
//! the spec:
//!
//! 1. convergence - start mistuned in both directions; the controller
//!    must approach the knee, and the under-tuned leg must beat its
//!    mistuned wall.
//! 2. re-convergence - the line's capacity changes mid-run
//!    (`MockServer::set_line_bps`), the facts-changed case.
//! 3. no-oscillation - a flat healthy line at the knee; the fleet must
//!    hold steady. The noise-chasing gate: the offline tuner's history
//!    says this is where controllers fail.
//!
//! Wall-clock measurements, so all three are #[ignore]d - run with
//! `cargo test -p nzbkit --test live_tune -- --ignored`. Assertions are
//! deliberately wide: rung counts near the knee are a coin toss inside
//! the noise (the wave-6 lesson), so the rigs assert BANDS and wall
//! ratios, never exact rungs.

use nzbkit::config::ServerConfig;
use nzbkit::livetune::{EpochObs, ServerTuner};
use nzbkit::mock::{Chaos, MockServer, Throttle, make_file_articles};
use nzbkit::pool::{ArticleReq, ConnTarget, FetchOutcome, LiveStats, PoolConfig, fetch_all_multi};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const SEG: usize = 20_000;

fn corpus(total_bytes: usize) -> (HashMap<String, Vec<u8>>, Vec<ArticleReq>) {
    let data: Vec<u8> = (0..total_bytes as u32)
        .map(|i| (i * 17 % 253) as u8)
        .collect();
    let mut articles = HashMap::new();
    let segs = make_file_articles("live.bin", &data, SEG, "lt", &mut articles);
    let ids = segs
        .iter()
        .map(|(id, _, _)| ArticleReq::fresh(format!("<{id}>")))
        .collect();
    (articles, ids)
}

struct Leg {
    wall: Duration,
    /// The tuner's kept target when the run ended (== the fixed fleet
    /// size for untuned legs).
    final_target: usize,
    /// Every kept target sampled at epoch boundaries, for band checks.
    targets_seen: Vec<usize>,
}

/// Run one download leg. `spawn` workers are built; without a tuner the
/// fleet just runs at `start`, with one the controller moves the live
/// target from `start` as it decides. `mid_run` fires once, roughly
/// `at_frac` of the way through the corpus (rig 2's re-provisioning).
async fn leg(
    srv: &MockServer,
    ids: Vec<ArticleReq>,
    spawn: usize,
    start: usize,
    tuned: bool,
    epoch: Duration,
    mid_run: Option<(f64, Box<dyn Fn() + Send>)>,
) -> Leg {
    let mut sc: ServerConfig = srv.server_config();
    sc.connections = spawn as u32;
    let target = ConnTarget::new(start);
    let cfg = PoolConfig {
        connections: spawn,
        ramp_delay: Duration::ZERO,
        live_target: Some(target.clone()),
        ..Default::default()
    };
    let servers = vec![(sc, cfg)];
    let live = LiveStats::for_servers(&servers);
    let servers: Vec<(ServerConfig, PoolConfig)> = servers
        .into_iter()
        .map(|(s, mut c)| {
            c.live = Some(live.clone());
            (s, c)
        })
        .collect();
    let total = ids.len();
    let done = Arc::new(AtomicUsize::new(0));
    let (tx, mut rx) = tokio::sync::mpsc::channel(64);
    let t0 = Instant::now();
    let fetch = tokio::spawn(async move { fetch_all_multi(&servers, ids, tx).await });
    let done2 = done.clone();
    let collect = tokio::spawn(async move {
        let mut n = 0usize;
        while let Some(o) = rx.recv().await {
            if matches!(o, FetchOutcome::Done { .. }) {
                n += 1;
                done2.store(n, Ordering::Relaxed);
            }
        }
        n
    });

    // The controller loop: one EpochObs per epoch off the live gauges,
    // exactly what the daemon's driver will do. The tuner stops being
    // fed once the queue is near its tail - a drying queue measures the
    // queue (the "never probe when the queue is near empty" rule; here
    // the whole epoch is discarded via busy=false).
    let mut tuner = ServerTuner::new(start, spawn, 1);
    let mut targets_seen = vec![tuner.target()];
    let mut fired = false;
    let mut last_bytes = 0u64;
    loop {
        target.set(if tuned { tuner.desired() } else { start });
        live.servers[0]
            .budget
            .store(target.get(), Ordering::Relaxed);
        tokio::time::sleep(epoch).await;
        if fetch.is_finished() {
            break;
        }
        let n = done.load(Ordering::Relaxed);
        if let Some((frac, f)) = &mid_run
            && !fired
            && (n as f64) >= total as f64 * frac
        {
            f();
            fired = true;
        }
        let bytes = live.servers[0].bytes.load(Ordering::Relaxed);
        let rate = (bytes - last_bytes) as f64 / epoch.as_secs_f64();
        last_bytes = bytes;
        let connected = live.servers[0].connected.load(Ordering::Relaxed);
        // Near-tail epochs are dirty by construction: not enough queue
        // left to keep the fleet busy for a whole epoch.
        let busy = total - n > target.get() * 8;
        let obs = EpochObs {
            rate_bps: rate,
            busy,
            rate_limited: false,
            capacity_pressure: false,
            fleet_met: connected >= target.get().min(tuner.desired()),
        };
        if tuned {
            tuner.on_epoch(obs);
            targets_seen.push(tuner.target());
        }
    }
    tokio::time::timeout(Duration::from_secs(60), fetch)
        .await
        .expect("leg hung")
        .unwrap();
    let wall = t0.elapsed();
    let done = collect.await.unwrap();
    assert_eq!(done, total, "articles lost during live tuning");
    Leg {
        wall,
        final_target: tuner.target(),
        targets_seen,
    }
}

fn throttled(per_conn: u64, line: u64) -> Chaos {
    Chaos {
        throttle: Throttle {
            per_conn_bps: per_conn,
            line_bps: line,
            ..Default::default()
        },
        ..Default::default()
    }
}

/// Rig 1a: under-tuned start. Knee 12 (line 1.8 MB/s / 150 KB/s), fleet
/// starts at 4. The controller must walk up toward the knee and the
/// wall must beat the mistuned baseline - the James shape (a fleet
/// pinned far below the line for no physical reason).
#[tokio::test(flavor = "multi_thread")]
#[ignore = "wall-clock live-tuner rig (~2 min) - run with --ignored"]
async fn rig1_convergence_from_under_tuned_beats_the_mistuned_wall() {
    let (articles, ids) = corpus(60_000_000);
    let srv = MockServer::start(articles, throttled(150_000, 1_800_000)).await;
    let epoch = Duration::from_millis(1500);
    let base = leg(&srv, ids.clone(), 4, 4, false, epoch, None).await;
    let tuned = leg(&srv, ids, 20, 4, true, epoch, None).await;
    eprintln!(
        "RIG1a base {:?} tuned {:?} final target {} path {:?}",
        base.wall, tuned.wall, tuned.final_target, tuned.targets_seen
    );
    assert!(
        tuned.final_target >= 9,
        "never approached the knee of 12: stopped at {} (path {:?})",
        tuned.final_target,
        tuned.targets_seen
    );
    assert!(
        tuned.final_target <= 15,
        "overshot the knee of 12: {} (path {:?})",
        tuned.final_target,
        tuned.targets_seen
    );
    assert!(
        tuned.wall.as_secs_f64() < base.wall.as_secs_f64() * 0.75,
        "no payout over the mistuned wall: tuned {:?} vs base {:?}",
        tuned.wall,
        base.wall
    );
}

/// Rig 1b: over-tuned start. Knee 10 (600 KB/s / 60 KB/s), fleet starts
/// at 16. The mock's line shares fairly, so over-asking costs wall
/// nothing HERE (the field penalty is a provider behaviour the model
/// deliberately does not invent) - the claim is convergence: the
/// controller must shed the sockets the line cannot use, one per cycle
/// (down-moves have no early-keep path on purpose), and must not be
/// slower than the baseline by more than the probing overhead. The
/// slow line is what buys the walk enough epochs to finish.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "wall-clock live-tuner rig (~3 min) - run with --ignored"]
async fn rig1_convergence_from_over_tuned_sheds_useless_sockets() {
    let (articles, ids) = corpus(60_000_000);
    let srv = MockServer::start(articles, throttled(60_000, 600_000)).await;
    let epoch = Duration::from_millis(1500);
    let base = leg(&srv, ids.clone(), 16, 16, false, epoch, None).await;
    let tuned = leg(&srv, ids, 16, 16, true, epoch, None).await;
    eprintln!(
        "RIG1b base {:?} tuned {:?} final target {} path {:?}",
        base.wall, tuned.wall, tuned.final_target, tuned.targets_seen
    );
    assert!(
        tuned.final_target <= 12,
        "kept sockets the line cannot use: {} (path {:?})",
        tuned.final_target,
        tuned.targets_seen
    );
    assert!(
        tuned.final_target >= 8,
        "shed past the knee of 10: {} (path {:?})",
        tuned.final_target,
        tuned.targets_seen
    );
    assert!(
        tuned.wall.as_secs_f64() < base.wall.as_secs_f64() * 1.2,
        "probing overhead ate the run: tuned {:?} vs base {:?}",
        tuned.wall,
        base.wall
    );
}

/// Rig 2: the facts change mid-run. Knee starts at 6 (360 KB/s line),
/// the provider re-provisions to 1.08 MB/s (knee 18, above the spawned
/// ceiling of 14) once a third of the corpus is down. The controller
/// must notice and climb - the whole reason a live tuner exists over
/// the offline snapshot.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "wall-clock live-tuner rig (~2 min) - run with --ignored"]
async fn rig2_reconverges_after_a_mid_run_capacity_change() {
    let (articles, ids) = corpus(50_000_000);
    let srv = MockServer::start(articles, throttled(60_000, 360_000)).await;
    let epoch = Duration::from_millis(1500);
    let line = srv.line_control();
    let tuned = leg(
        &srv,
        ids,
        14,
        6,
        true,
        epoch,
        Some((
            0.33,
            Box::new(move || line.set_line_bps(1_080_000)) as Box<dyn Fn() + Send>,
        )),
    )
    .await;
    eprintln!(
        "RIG2 wall {:?} final target {} path {:?}",
        tuned.wall, tuned.final_target, tuned.targets_seen
    );
    assert!(
        tuned.final_target >= 10,
        "did not follow the line up after the re-provision: {} (path {:?})",
        tuned.final_target,
        tuned.targets_seen
    );
}

/// Rig 3, the SAFETY gate: a flat healthy line with the fleet already
/// at the knee. The controller may probe (that is its job) but the KEPT
/// target must hold - every sampled target stays inside one connection
/// of the knee for the whole run. This is the gate the offline tuner's
/// history says noise-chasers fail; it cleared the adaptive timeout's
/// jitter gate in the same spirit.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "wall-clock live-tuner rig (~2 min) - run with --ignored"]
async fn rig3_a_flat_healthy_line_holds_steady() {
    let (articles, ids) = corpus(45_000_000);
    let srv = MockServer::start(articles, throttled(60_000, 600_000)).await;
    let epoch = Duration::from_millis(1500);
    let tuned = leg(&srv, ids, 20, 10, true, epoch, None).await;
    eprintln!(
        "RIG3 wall {:?} final target {} path {:?}",
        tuned.wall, tuned.final_target, tuned.targets_seen
    );
    for (i, t) in tuned.targets_seen.iter().enumerate() {
        assert!(
            (9..=11).contains(t),
            "epoch {i}: the kept target walked to {t} on a flat line (path {:?})",
            tuned.targets_seen
        );
    }
}

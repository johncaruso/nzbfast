//! Lib-level unit tests for pool internals (coverage ratchet, 5 Aug).
//!
//! The tail-optimization campaign landed pool code that the daemon and
//! chaos integration suites exercise heavily - but `cargo llvm-cov -p
//! nzbkit --lib` cannot see integration coverage, so the nightly floor
//! read the campaign as a regression. These tests pin the pure helpers,
//! state machines and control-surface paths directly. A child module of
//! `pool` (not an entry in the inline `tests` mod) so pool.rs itself
//! stays inside its size-gate entry while the private internals remain
//! reachable through `super::*`.

use super::*;
use crate::config::ServerConfig;
use crate::mock::{Chaos, MockServer, make_file_articles};

fn server(host: &str) -> ServerConfig {
    ServerConfig {
        host: host.into(),
        port: 119,
        tls: false,
        username: None,
        password: None,
        connections: 1,
        pin_connections: false,
        rcvbuf: None,
        level: 0,
        group: None,
        retention_days: 0,
        block_bytes: None,
        bind_ip: None,
        socks5: None,
        enabled: true,
        warm_pool: false,
        idle_release_secs: None,
        idle_keep: None,
        max_source_ips: None,
    }
}

fn fresh(ids: &[&str]) -> Vec<ArticleReq> {
    ids.iter()
        .map(|id| ArticleReq::fresh((*id).into()))
        .collect()
}

fn work(id: &str) -> Work {
    Work {
        id: id.into(),
        attempts: 0,
        promoted: false,
        tried_430: 0,
        tried_fail: 0,
        dup: false,
    }
}

#[test]
fn flap_window_trims_old_deaths_before_judging() {
    let (sh, _) = Shared::new(fresh(&["<a@x>"]), &[(server("s"), PoolConfig::default())]);
    for _ in 0..FLAP_DEATHS - 1 {
        sh.note_flap(0);
    }
    assert!(
        !sh.is_flapping(0),
        "one under the threshold is a rough patch, not a flap"
    );
    sh.note_flap(0);
    assert!(sh.is_flapping(0));
    // A lone server is never clamped: churn beats zero throughput when
    // there is no alternative.
    assert!(!sh.other_live(0));
    sh.note_cap_bounce(0);
    assert_eq!(
        sh.flap_keeper_target(0, &PoolConfig::default()),
        1,
        "no session was held at bounce time, so no cap was observed"
    );
    sh.sessions[0].store(2, Ordering::Release);
    sh.note_cap_bounce(0);
    let cfg = PoolConfig {
        connections: 8,
        ..Default::default()
    };
    assert_eq!(
        sh.flap_keeper_target(0, &cfg),
        2,
        "an observed accept cap widens the clamp past one keeper"
    );
    assert_eq!(
        sh.flap_keeper_target(
            0,
            &PoolConfig {
                connections: 1,
                ..Default::default()
            }
        ),
        1,
        "never above the per-server budget, where account limits already landed"
    );
    let off = PoolConfig {
        flap_cap_keepers: false,
        connections: 8,
        ..Default::default()
    };
    assert_eq!(
        sh.flap_keeper_target(0, &off),
        1,
        "knob off keeps the shipped answer"
    );
}

#[test]
fn auth_state_keeps_the_servers_own_words_for_the_first_refusal_only() {
    let (sh, _) = Shared::new(fresh(&["<a@x>"]), &[(server("s"), PoolConfig::default())]);
    let auth = &sh.auth[0];
    assert_eq!(auth.reason(), None);
    assert!(auth.note(crate::nntp::AuthRefusal::Permanent, "502 no thanks"));
    assert!(!auth.note(crate::nntp::AuthRefusal::Permanent, "502 said twice"));
    assert!(auth.is_rejected());
    assert_eq!(
        auth.reason().as_deref(),
        Some("502 no thanks"),
        "the dashboard shows what the provider actually said, once"
    );
}

#[test]
fn ctx_for_unions_mirror_group_bits() {
    let mut a = server("a");
    a.group = Some("eu".into());
    let mut b = server("b");
    b.group = Some("eu".into());
    let c = server("c");
    let servers = vec![
        (a, PoolConfig::default()),
        (b, PoolConfig::default()),
        (c, PoolConfig::default()),
    ];
    let ctx = ctx_for(&servers, 0);
    assert_eq!(ctx.idx, 0);
    assert_eq!(ctx.bit, 0b001);
    assert_eq!(
        ctx.group_bits, 0b011,
        "a 430 is authoritative for the whole mirror group"
    );
    assert_eq!(ctx.level, 0);
    let lone = ctx_for(&servers, 2);
    assert_eq!(
        lone.group_bits, 0b100,
        "no group means the server answers for itself"
    );
}

#[test]
fn shared_new_seeds_age_and_part_maps_for_the_pool_paths_that_read_them() {
    let reqs = vec![
        ArticleReq {
            id: "<aged@x>".into(),
            age_days: 30,
            part: 2,
        },
        ArticleReq::fresh("<plain@x>".into()),
    ];
    let (sh, unservable) = Shared::new(reqs, &[(server("s"), PoolConfig::default())]);
    assert!(unservable.is_empty(), "an unlimited server serves any age");
    assert_eq!(
        sh.parts.get("<aged@x>").copied(),
        Some(2),
        "the CRC gate needs the requested part to catch split-brain swaps"
    );
    assert_eq!(
        sh.parts.get("<plain@x>"),
        None,
        "part 0 means no declared part"
    );
    assert_eq!(sh.ages.get("<aged@x>").copied(), Some(30));
}

#[test]
fn transport_failure_steering_asks_who_else_could_take_the_work() {
    let servers = vec![
        (server("p"), PoolConfig::default()),
        (server("q"), PoolConfig::default()),
    ];
    let (sh, _) = Shared::new(fresh(&["<a@x>"]), &servers);
    let mut w = work("<a@x>");
    assert!(
        !sh.other_can_take(&w, 0),
        "a server with no live workers can never take the retry"
    );
    sh.alive[1].store(1, Ordering::Relaxed);
    assert!(sh.other_can_take(&w, 0));
    w.tried_fail = 0b10;
    assert!(
        !sh.other_can_take(&w, 0),
        "a server that already transport-failed this article is not an elsewhere"
    );
    // Cold start: no rate difference is measurable, so promoted work is
    // never stranded waiting for a faster server.
    let w2 = work("<a@x>");
    assert!(!sh.faster_can_take(&w2, 0));
}

#[test]
fn buf_pool_reuses_small_buffers_and_frees_oversized_ones() {
    let pool = BufPool::new(1);
    let mut a = pool.take();
    assert!(a.is_empty(), "a fresh take is an empty buffer");
    a.extend_from_slice(b"body bytes");
    pool.give(a);
    let b = pool.take();
    assert!(b.is_empty(), "give() clears before parking");
    // At max_held 1, a second parked buffer is dropped, not stored.
    pool.give(Vec::with_capacity(1024));
    pool.give(Vec::with_capacity(2048));
    let _ = pool.take();
    let refilled = pool.take();
    assert_eq!(
        refilled.capacity(),
        800 * 1024,
        "the surplus give was dropped, so this take allocated fresh"
    );
    // A buffer grown past the 4 MB keep-cap must not pin its allocation
    // in the pool for the rest of the run.
    pool.give(Vec::with_capacity(5 * 1024 * 1024));
    assert!(
        pool.take().capacity() < 5 * 1024 * 1024,
        "an oversized buffer is freed, not parked"
    );
}

#[test]
fn stream_window_defaults_to_one() {
    // The env knob is unset in the test environment, so the OnceLock
    // resolves the shipped default.
    assert_eq!(stream_window(), 1);
}

#[test]
fn ttfb_suspicion_bound_floors_at_one_second_then_tracks_the_ewma() {
    let floor = TTFB_SUSPECT_MIN.as_millis() as u64;
    assert_eq!(
        ttfb_suspect_ms(0),
        floor,
        "unmeasured suspects at the floor"
    );
    assert_eq!(ttfb_suspect_ms(400), floor, "2x a fast EWMA stays floored");
    assert_eq!(
        ttfb_suspect_ms(600),
        1200,
        "a slow honest server pushes the bound out instead of hedging everything"
    );
}

#[test]
fn ttfb_suspect_after_reads_the_servers_own_ewma() {
    let (sh, _) = Shared::new(fresh(&["<a@x>"]), &[(server("s"), PoolConfig::default())]);
    assert_eq!(
        sh.ttfb_suspect_after(0),
        TTFB_SUSPECT_MIN,
        "no history means no reason to wait"
    );
    sh.note_ttfb(0, Duration::from_secs(2));
    assert_eq!(
        sh.ttfb_suspect_after(0),
        Duration::from_millis(4000),
        "first sample seeds the EWMA whole, and the bound is 2x it"
    );
}

#[test]
fn mark_suspect_flags_a_live_entry_and_ignores_a_finished_one() {
    let cfg = PoolConfig {
        ttfb_hedge: true,
        adaptive_timeout: true,
        ..Default::default()
    };
    let (sh, _) = Shared::new(fresh(&["<a@x>"]), &[(server("s"), cfg)]);
    // The timer races the read's own completion: the entry may already
    // be gone, and that must be a no-op, not a panic or a stuck flag.
    sh.mark_suspect("<gone@x>");
    assert!(!sh.suspect_pending.load(Ordering::Acquire));
    sh.register_inflight(&work("<a@x>"), 0);
    sh.mark_suspect("<a@x>");
    assert!(sh.suspect_pending.load(Ordering::Acquire));
    assert!(sh.inflight.lock_ok().get("<a@x>").unwrap().suspect);
}

/// The suspect-dup gate ladder, in the order the code checks it: dark
/// flag, fill level, busy picker, no pending suspicion, issue-rate cap,
/// per-server once, and the empty-scan fast-path flag clear.
#[test]
fn pick_suspect_dup_walks_its_gate_ladder() {
    let hedge_cfg = PoolConfig {
        ttfb_hedge: true,
        adaptive_timeout: true,
        ..Default::default()
    };
    // Dark flag: a pool built without the knob never races, suspicion
    // or not.
    let (dark, _) = Shared::new(fresh(&["<a@x>"]), &[(server("s"), PoolConfig::default())]);
    dark.register_inflight(&work("<a@x>"), 0);
    dark.mark_suspect("<a@x>");
    assert!(dark.pick_suspect_dup(0b01, 0b01, 0, 0).is_none());

    let (sh, _) = Shared::new(
        fresh(&["<a@x>", "<b@x>"]),
        &[(server("p"), hedge_cfg.clone()), (server("q"), hedge_cfg)],
    );
    sh.register_inflight(&work("<a@x>"), 0);
    // No suspicion yet: the fast-path flag keeps the scan free.
    assert!(sh.pick_suspect_dup(0b10, 0b10, 0, 0).is_none());
    sh.mark_suspect("<a@x>");
    // Fill servers never spend block bytes on speculation, and a busy
    // picker's dup would displace queued work.
    assert!(sh.pick_suspect_dup(0b10, 0b10, 1, 0).is_none());
    assert!(sh.pick_suspect_dup(0b10, 0b10, 0, 3).is_none());
    // The hedge issue-rate cap prices jitter: over it, the budget path
    // still rescues, but no new dup is issued.
    sh.hedges_issued.store(1_000, Ordering::Relaxed);
    assert!(sh.pick_suspect_dup(0b10, 0b10, 0, 0).is_none());
    sh.hedges_issued.store(0, Ordering::Relaxed);

    let dup = sh
        .pick_suspect_dup(0b10, 0b10, 0, 0)
        .expect("an idle primary races the suspect");
    assert_eq!(dup.id, "<a@x>");
    assert!(dup.dup, "raced copy is a duplicate, never an owner");
    assert_eq!(sh.hedges_issued.load(Ordering::Relaxed), 1);
    {
        let inf = sh.inflight.lock_ok();
        let e = inf.get("<a@x>").unwrap();
        assert_eq!(e.dups, 1);
        assert_eq!(
            e.dup_servers & 0b10,
            0b10,
            "this server is spent for this article"
        );
    }
    // dups >= 1 filters the entry for every later picker, so the scan
    // comes up empty and clears the fast-path flag until a NEW
    // suspicion fires.
    assert!(sh.pick_suspect_dup(0b01, 0b01, 0, 0).is_none());
    assert!(
        !sh.suspect_pending.load(Ordering::Acquire),
        "an empty scan stops paying for itself"
    );
}

#[test]
fn required_mask_counts_only_live_lower_levels() {
    let mut fill = server("f");
    fill.level = 1;
    let servers = vec![
        (server("p0"), PoolConfig::default()),
        (server("p1"), PoolConfig::default()),
        (fill, PoolConfig::default()),
    ];
    let (sh, _) = Shared::new(fresh(&["<a@x>"]), &servers);
    sh.alive[0].store(1, Ordering::Relaxed);
    sh.alive[2].store(1, Ordering::Relaxed);
    assert_eq!(
        sh.live_mask(),
        0b101,
        "only servers with running workers count"
    );
    assert_eq!(
        sh.required_mask(1),
        0b001,
        "a fill server waits on live primaries only - a dead one can never 430"
    );
    assert_eq!(sh.required_mask(0), 0, "level 0 answers to nobody");
}

#[test]
fn wire_cap_note_marks_the_graph_once_per_window() {
    let servers = vec![(server("s"), PoolConfig::default())];
    let live = LiveStats::for_servers(&servers);
    let cfg = PoolConfig {
        live: Some(live.clone()),
        ..Default::default()
    };
    let (sh, _) = Shared::new(fresh(&["<a@x>"]), &[(server("s"), cfg)]);
    assert!(!sh.wire_over_cap(0), "cap 0 is uncapped");
    sh.charge_wire();
    assert!(sh.wire_over_cap(1), "one charge trips a 1-byte cap");
    sh.note_wire_cap();
    sh.note_wire_cap();
    let wires = live
        .events
        .lock()
        .unwrap()
        .iter()
        .filter(|e| e.kind == "wire")
        .count();
    assert_eq!(
        wires, 1,
        "an engaged cap answers every top-up; the ring must not"
    );
    sh.release_wire(1);
    assert!(
        !sh.wire_over_cap(1),
        "release undoes exactly what dispatch charged"
    );
    // Without live stats the note is a no-op, not a panic - CLI runs
    // have no ring.
    let (bare, _) = Shared::new(fresh(&["<b@x>"]), &[(server("s"), PoolConfig::default())]);
    bare.note_wire_cap();
}

#[test]
fn race_burst_note_opens_its_window_before_ever_marking() {
    let servers = vec![(server("s"), PoolConfig::default())];
    let live = LiveStats::for_servers(&servers);
    let cfg = PoolConfig {
        live: Some(live.clone()),
        ..Default::default()
    };
    let (sh, _) = Shared::new(fresh(&["<a@x>"]), &[(server("s"), cfg)]);
    sh.note_race_burst();
    sh.note_race_burst();
    let racing = live
        .events
        .lock()
        .unwrap()
        .iter()
        .filter(|e| e.kind == "racing")
        .count();
    assert_eq!(
        racing, 0,
        "the endgame of a healthy job issues a handful of dups and must not mark the graph"
    );
    // No ring, no work - the early return, not a panic.
    let (bare, _) = Shared::new(fresh(&["<b@x>"]), &[(server("s"), PoolConfig::default())]);
    bare.note_race_burst();
}

#[test]
fn any_live_answers_from_inflight_then_queue_then_absence() {
    let ctl = QueueControl::default();
    assert_eq!(
        ctl.any_live(&["<a@x>".to_string()]),
        None,
        "before attach there is no pool to ask"
    );
    let (sh, _) = Shared::new(
        fresh(&["<q1@x>", "<q2@x>"]),
        &[(server("s"), PoolConfig::default())],
    );
    ctl.attach(&sh);
    assert_eq!(ctl.any_live(&[]), Some(true), "no ids is vacuously live");
    assert_eq!(
        ctl.any_live(&["<q1@x>".to_string()]),
        Some(true),
        "still queued means still live"
    );
    assert_eq!(
        ctl.any_live(&["<nope@x>".to_string()]),
        Some(false),
        "unknown everywhere is the negative verdict"
    );
    sh.register_inflight(&work("<w@x>"), 0);
    assert_eq!(
        ctl.any_live(&["<w@x>".to_string()]),
        Some(true),
        "in flight answers without touching the queue lock"
    );
}

#[test]
fn requeue_rolls_back_when_the_run_is_over_or_aborted() {
    assert_eq!(
        QueueControl::default().requeue(&["<a@x>".to_string()]),
        0,
        "no pool attached, nothing to resurrect"
    );
    // Finished-run rollback: cancel the last pending article, complete
    // the other, then try to resurrect - the fleet is winding down and
    // nothing would ever fetch it, so the stash keeps it and the caller
    // keeps its accounting.
    let ctl = QueueControl::default();
    let (sh, _) = Shared::new(
        fresh(&["<a@x>", "<b@x>"]),
        &[(server("s"), PoolConfig::default())],
    );
    ctl.attach(&sh);
    // The finished watch only latches with a subscriber alive - workers
    // hold one in production, so the test must too.
    let finished = sh.finished.subscribe();
    let mut cancel_ids = HashSet::new();
    cancel_ids.insert("<a@x>".to_string());
    assert_eq!(ctl.cancel(&cancel_ids), vec!["<a@x>".to_string()]);
    assert!(sh.claim_done("<b@x>"));
    sh.complete_one();
    assert!(
        *finished.borrow(),
        "the cancelled+completed pair drained the run"
    );
    assert_eq!(ctl.requeue(&["<a@x>".to_string()]), 0);
    assert!(
        sh.cancelled.lock_ok().contains_key("<a@x>"),
        "rollback re-stashes, so a later retry is still possible"
    );
    assert_eq!(
        sh.pending.load(Ordering::Acquire),
        0,
        "the probe count was undone"
    );
    // Unknown ids never count toward the return value.
    assert_eq!(ctl.requeue(&["<never@x>".to_string()]), 0);
    // Aborted-run refusal, before any stash lookup.
    let ctl2 = QueueControl::default();
    let (sh2, _) = Shared::new(
        fresh(&["<c@x>", "<d@x>"]),
        &[(server("s"), PoolConfig::default())],
    );
    ctl2.attach(&sh2);
    let mut ids2 = HashSet::new();
    ids2.insert("<c@x>".to_string());
    assert_eq!(ctl2.cancel(&ids2), vec!["<c@x>".to_string()]);
    assert!(ctl2.abort());
    assert_eq!(ctl2.requeue(&["<c@x>".to_string()]), 0);
}

/// The on-demand pool-state dump (stall watchdog, NZBFAST_POOL_DEBUG's
/// idle branch). The throttle static admits one dump per 5 s of a
/// pool's lifetime and the clock is the pool's own age, so this test
/// pays real seconds - that is the price of covering a diagnostic whose
/// whole job is to fire from a hung run in the field.
#[test]
fn dump_state_survives_a_held_queue_and_then_prints_it() {
    let ctl = QueueControl::default();
    let (sh, _) = Shared::new(
        fresh(&["<a@x>", "<b@x>"]),
        &[(server("s"), PoolConfig::default())],
    );
    ctl.attach(&sh);
    sh.register_inflight(&work("<w@x>"), 0);
    // Detached ctl: a dump on a dead pool is a no-op.
    QueueControl::default().dump_state();
    std::thread::sleep(Duration::from_millis(5_100));
    {
        // A busy queue must degrade to "lock busy", never block the
        // watchdog that is trying to diagnose a hang.
        let _held = sh.queue.try_lock().expect("test owns the queue");
        ctl.dump_state();
    }
    std::thread::sleep(Duration::from_millis(5_100));
    ctl.dump_state(); // queue free: the full queue + inflight listing
    ctl.dump_state(); // and the once-per-5s throttle swallows this one
}

#[test]
fn seal_run_blocking_fails_orphans_exactly_once() {
    let (sh, _) = Shared::new(
        fresh(&["<a@x>", "<b@x>"]),
        &[(server("s"), PoolConfig::default())],
    );
    let (tx, mut rx) = mpsc::channel(8);
    // Live workers: not this path's job - the async seal owns it.
    sh.workers_live.store(1, Ordering::Release);
    assert_eq!(seal_run_blocking(&sh, &tx, "shards stopped"), 0);
    sh.workers_live.store(0, Ordering::Release);
    // A draining run keeps its queue intact for the resume.
    sh.draining.store(true, Ordering::Release);
    assert_eq!(seal_run_blocking(&sh, &tx, "shards stopped"), 0);
    sh.draining.store(false, Ordering::Release);
    // One orphan still queued, one stranded in flight: both must reach
    // a terminal Failed, and the pending count must reach zero.
    {
        let mut q = sh.queue.try_lock().unwrap();
        let w = q.pop_front().unwrap();
        drop(q);
        sh.register_inflight(&w, 0);
    }
    assert_eq!(seal_run_blocking(&sh, &tx, "all shard runtimes stopped"), 2);
    let mut failed = Vec::new();
    while let Ok(o) = rx.try_recv() {
        match o {
            FetchOutcome::Failed { id, error } => {
                assert_eq!(error, "all shard runtimes stopped");
                failed.push(id);
            }
            other => panic!("unexpected outcome: {other:?}"),
        }
    }
    failed.sort();
    assert_eq!(failed, vec!["<a@x>".to_string(), "<b@x>".to_string()]);
    assert_eq!(sh.pending.load(Ordering::Acquire), 0);
    // Nothing left: the pending==0 early return, and no double report.
    assert_eq!(seal_run_blocking(&sh, &tx, "again"), 0);
}

#[tokio::test]
async fn fetch_all_serves_one_server_end_to_end() {
    let mut articles = std::collections::HashMap::new();
    let payload: Vec<u8> = (0..20_000u32).map(|i| (i * 3) as u8).collect();
    let segs = make_file_articles("w.bin", &payload, 8_000, "one", &mut articles);
    let srv = MockServer::start(articles, Chaos::default()).await;
    let reqs: Vec<ArticleReq> = segs
        .iter()
        .map(|(id, _, _)| ArticleReq::fresh(format!("<{id}>")))
        .collect();
    let n = reqs.len();
    let cfg = PoolConfig {
        connections: 1,
        ramp_delay: Duration::ZERO,
        ..Default::default()
    };
    let (tx, mut rx) = mpsc::channel(64);
    let stats = tokio::time::timeout(
        Duration::from_secs(20),
        fetch_all(&srv.server_config(), &cfg, reqs, tx),
    )
    .await
    .expect("run hung");
    let mut done = 0;
    while let Ok(o) = rx.try_recv() {
        match o {
            FetchOutcome::Done { .. } => done += 1,
            other => panic!("unexpected outcome: {other:?}"),
        }
    }
    assert_eq!(done, n);
    assert!(stats.ever_connected);
    assert!(
        stats.bytes > 0,
        "the single-server wrapper reports its own stats"
    );
}

/// The daemon's production entry point: shard threads with their own
/// runtimes, one shared queue, the blocking seal after the join. Runs
/// on a plain test thread exactly like the daemon calls it.
#[test]
fn sharded_fetch_serves_everything_across_shards() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let mut articles = std::collections::HashMap::new();
    let payload: Vec<u8> = (0..60_000u32).map(|i| (i * 7) as u8).collect();
    let segs = make_file_articles("s.bin", &payload, 8_000, "shard", &mut articles);
    // The mock's accept loop lives on this runtime; it must stay alive
    // for the whole blocking fetch below.
    let srv = rt.block_on(MockServer::start(articles, Chaos::default()));
    let mut server = srv.server_config();
    server.retention_days = 10;
    server.connections = 3;
    let mut reqs: Vec<ArticleReq> = segs
        .iter()
        .map(|(id, _, _)| ArticleReq::fresh(format!("<{id}>")))
        .collect();
    let n_fresh = reqs.len();
    // Outside the only server's retention: Missing without a request,
    // reported on the sharded path's own blocking send.
    reqs.push(ArticleReq {
        id: "<ancient@x>".into(),
        age_days: 400,
        part: 0,
    });
    let cfg = PoolConfig {
        connections: 3,
        ramp_delay: Duration::ZERO,
        ..Default::default()
    };
    let ctl = QueueControl::default();
    let (tx, mut rx) = mpsc::channel(1024);
    let stats = fetch_all_sharded(vec![(server, cfg)], reqs, tx, 2, Some(&ctl));
    let mut done = 0;
    let mut retention = 0;
    while let Ok(o) = rx.try_recv() {
        match o {
            FetchOutcome::Done { .. } => done += 1,
            FetchOutcome::Missing {
                cause: MissingCause::Retention,
                ..
            } => retention += 1,
            other => panic!("unexpected outcome: {other:?}"),
        }
    }
    assert_eq!(
        done, n_fresh,
        "every servable article lands across both shards"
    );
    assert_eq!(retention, 1);
    assert_eq!(stats.len(), 1);
    assert!(stats[0].ever_connected);
    assert!(stats[0].bytes > 0);
    assert!(stats[0].connects >= 1, "the shard plans actually dialled");
    assert_eq!(
        ctl.any_live(&[]),
        None,
        "the ctl holds a Weak - a finished run detaches it, it never leaks the pool"
    );
}

/// Shards degraded to zero built runtimes still owe every article a
/// terminal outcome - the blocking seal is the only seller left.
#[test]
fn sharded_fetch_with_zero_shard_clamp_still_reports() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    let mut articles = std::collections::HashMap::new();
    let payload: Vec<u8> = (0..8_000u32).map(|i| i as u8).collect();
    let segs = make_file_articles("z.bin", &payload, 8_000, "zero", &mut articles);
    let srv = rt.block_on(MockServer::start(articles, Chaos::default()));
    let reqs: Vec<ArticleReq> = segs
        .iter()
        .map(|(id, _, _)| ArticleReq::fresh(format!("<{id}>")))
        .collect();
    let n = reqs.len();
    // connections 0 and window 0 are configuration nonsense the daemon
    // can hand us mid-edit; the sharded clamp must turn both into 1.
    let cfg = PoolConfig {
        connections: 0,
        window: 0,
        ramp_delay: Duration::ZERO,
        ..Default::default()
    };
    let (tx, mut rx) = mpsc::channel(64);
    let stats = fetch_all_sharded(vec![(srv.server_config(), cfg)], reqs, tx, 0, None);
    let mut done = 0;
    while let Ok(o) = rx.try_recv() {
        if matches!(o, FetchOutcome::Done { .. }) {
            done += 1;
        }
    }
    assert_eq!(
        done, n,
        "shards.max(1) and connections.max(1) kept the run alive"
    );
    assert!(stats[0].bytes > 0);
}

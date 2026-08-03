//! Connection-tuner replication suite: conn_ladder against a mock
//! provider with a REAL bandwidth shape - a per-socket cap (why more
//! connections help) and a line cap (why they stop helping) - plus the
//! one-time transient dip that produced the field failure (a Mac tuned
//! to 6 connections of a configured 18, downloading at a third of the
//! link for a week).
//!
//! These run real 2-3 s ladder rungs over localhost, so the suite costs
//! ~1 min of wall clock. That is the point: the tuner's failure was a
//! MEASUREMENT failure, and only a measured replication protects it.

use nzbkit::mock::{Chaos, MockServer, OverRow, Throttle};
use std::collections::HashMap;

const MB: u64 = 1_000_000;

/// A group of ~600 KB articles (the size sysbench's supply model
/// assumes) with overview rows, so discover_ids finds them.
fn bench_group(n: usize) -> (HashMap<String, Vec<u8>>, Vec<OverRow>) {
    let mut articles = HashMap::new();
    let mut rows = Vec::new();
    // One shared payload: the ladder measures transfer, not content.
    let data: Vec<u8> = (0..600_000u32).map(|i| (i * 31 % 251) as u8).collect();
    for i in 0..n {
        let art = nzbkit::yenc::encode("t.bin", data.len() as u64, None, 1, &data);
        let id = format!("<tune-{i}@mock>");
        rows.push(OverRow {
            number: i as u64 + 1,
            subject: format!("tune article {i}"),
            from: "bench@mock".into(),
            message_id: id.clone(),
            bytes: art.len() as u64,
        });
        articles.insert(id, art);
    }
    (articles, rows)
}

async fn ladder_against(
    throttle: Throttle,
    max_conns: usize,
    secs_per_step: u64,
) -> Vec<nzbkit::sysbench::LadderStep> {
    let (articles, rows) = bench_group(220);
    let srv = MockServer::start_full(
        articles,
        HashMap::new(),
        rows,
        Chaos {
            throttle,
            ..Chaos::default()
        },
    )
    .await;
    let cfg = srv.server_config();
    nzbkit::sysbench::conn_ladder(&cfg, "alt.binaries.bench", max_conns, secs_per_step)
        .await
        .expect("ladder ran")
}

/// The knee-pick the daemon and the dashboard both apply to a ladder:
/// smallest rung reaching 90% of the peak.
fn recommended(steps: &[nzbkit::sysbench::LadderStep]) -> usize {
    let peak = steps.iter().map(|s| s.gbps).fold(0.0, f64::max);
    steps
        .iter()
        .find(|s| s.gbps >= peak * 0.9)
        .map(|s| s.connections)
        .unwrap_or(8)
}

/// A provider shaped 1 MB/s per socket under an 8 MB/s line has its
/// knee at 8: the ladder must find it (not stop short of it, not
/// recommend far past it) and the knee rung must SOAK the line - the
/// whole point of tuning is that the recommended count saturates what
/// the path can give.
#[tokio::test(flavor = "multi_thread")]
async fn ladder_finds_the_knee_and_soaks_the_line() {
    let steps = ladder_against(
        Throttle {
            per_conn_bps: MB,
            line_bps: 8 * MB,
            ..Throttle::default()
        },
        20,
        3,
    )
    .await;
    let rungs: Vec<String> = steps
        .iter()
        .map(|s| format!("{}c {:.3}", s.connections, s.gbps))
        .collect();
    let best = recommended(&steps);
    assert!(
        (7..=12).contains(&best),
        "knee should land at ~8 (1 MB/s per conn, 8 MB/s line), got {best}: {rungs:?}"
    );
    // The ladder must have tested PAST the knee to know it is one.
    assert!(
        steps.iter().any(|s| s.connections > 10),
        "never probed past the knee: {rungs:?}"
    );
    // And the knee rung soaks the line: >= ~80% of 8 MB/s (0.064 Gbps),
    // slack for pacing granularity and the connect ramp.
    let peak = steps.iter().map(|s| s.gbps).fold(0.0, f64::max);
    assert!(
        peak >= 0.051,
        "peak {peak:.3} Gbps does not soak the 0.064 Gbps line: {rungs:?}"
    );
}

/// The field failure, replayed end to end: a healthy 1 MB/s-per-socket
/// provider with a line far above the tested rungs, EXCEPT the first
/// sample at 8 connections hits a transient (line dips to 3 MB/s for
/// exactly that rung). The old ladder believed the one bad sample:
/// 8 read below 4, the climb stopped, and the 4..8 bisect recommended
/// ~6 - James's number. The re-race must see through it and keep
/// climbing to the top of the ladder.
#[tokio::test(flavor = "multi_thread")]
async fn transient_dip_does_not_fake_a_knee() {
    let steps = ladder_against(
        Throttle {
            per_conn_bps: MB,
            line_bps: 32 * MB,
            // Fires when the 8-conn rung comes up and dies with those
            // sockets - swallowing that one sample, wherever the rung's
            // boundaries land in real time.
            dip_at_conns: 8,
            dip_to_bps: 3 * MB,
        },
        16,
        3,
    )
    .await;
    let rungs: Vec<String> = steps
        .iter()
        .map(|s| format!("{}c {:.3}", s.connections, s.gbps))
        .collect();
    let best = recommended(&steps);
    assert!(
        best >= 12,
        "the transient dip faked a knee at {best} (the field bug recommended 6): {rungs:?}"
    );
    assert!(
        steps.iter().any(|s| s.connections >= 16),
        "the climb stopped at the dip instead of re-racing through it: {rungs:?}"
    );
}

/// Control for the dip test: the SAME shape with a genuine knee (line
/// capped at 4 MB/s, so 4 sockets saturate it). The re-race must NOT
/// turn a real knee into an endless climb - a genuine flat reproduces
/// and the ladder stops, recommending near 4.
#[tokio::test(flavor = "multi_thread")]
async fn a_genuine_knee_still_stops_the_climb() {
    let steps = ladder_against(
        Throttle {
            per_conn_bps: MB,
            line_bps: 4 * MB,
            ..Throttle::default()
        },
        20,
        3,
    )
    .await;
    let rungs: Vec<String> = steps
        .iter()
        .map(|s| format!("{}c {:.3}", s.connections, s.gbps))
        .collect();
    let best = recommended(&steps);
    assert!(
        (3..=6).contains(&best),
        "knee should land at ~4 (4 MB/s line), got {best}: {rungs:?}"
    );
    // A real knee must not send the ladder to the ceiling.
    let max_tested = steps.iter().map(|s| s.connections).max().unwrap_or(0);
    assert!(
        max_tested < 20,
        "a genuine flat should stop the climb well before max: {rungs:?}"
    );
}

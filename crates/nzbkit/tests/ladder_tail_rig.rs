//! The 430-ladder tail: how long a damaged post sits at zero
//! throughput AFTER its last payload byte is on disk.
//!
//! Measured on a 20-core ARM desktop over a 10 Gbps line (11 Aug 2026),
//! five real backbones, against a 6.6 GB REMUX with poisoned segments:
//! repair itself cost 0.69 s at damage 5 and 2.22 s at damage 60, but
//! the job's wall was 19 s and 31 s. The difference
//! is entirely a stall in front of repair - every payload byte
//! written, the wire idle, and articles reaching terminal Missing at
//! about six per second while the recovery volumes sat prefetched and
//! ready. Nothing was waiting on data; it was waiting on VERDICTS.
//!
//! A poisoned article is refused by every provider, and a terminal
//! Missing needs unanimity, so each one has to be asked of every
//! backbone. The cost was never the asking - it was that the pool
//! would only ask ONE question per connection at a time: in the
//! endgame a 430-laddering article was refused a place in a pipeline
//! that already held anything at all, so N articles across G backbones
//! cost N*G round trips divided by the connection count, and each
//! article's own G hops ran strictly one after another.
//!
//! This rig rebuilds that shape on loopback with mock providers whose
//! refusals carry a realistic delay, and reports the number that
//! matters: the gap between the last delivered body and the last
//! verdict. That gap IS the stall the progress line renders as
//! "0.0 MB/s, written 6.42 GB, (42 missing)".
//!
//! Both provider families are here on purpose. A non-echoing provider
//! (one whose "430 no such article" does not repeat the id back) is
//! asked twice for every article it does not have, because a bare
//! refusal is positional evidence only - see `Work::soft_430`. Three
//! of the five mocks echo and two do not, which is roughly what a real
//! five-provider fleet looks like.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

use nzbkit::config::ServerConfig;
use nzbkit::mock::{Chaos, MockServer, make_file_articles};
use nzbkit::pool::{ArticleReq, FetchOutcome, LiveStats, PoolConfig, fetch_all_multi};
use tokio::sync::mpsc;

/// Payload bytes per healthy article.
const ART: usize = 8_000;
/// Backbones in the fleet, and connections on each - the shape of
/// the fleet the stall was measured on (5 providers, 20 connections).
const SERVERS: usize = 5;
const CONNS: usize = 4;
/// Healthy articles. Enough that the run has a real download phase to
/// finish before the ladder tail starts.
const N_GOOD: usize = 240;
/// A refusal's round trip. A real 430 is not free - the provider has
/// to fail to find the article - and this is the number that decides
/// how long a dead queue takes to drive to terminal. 40 ms is the
/// friendly end of what the real-provider legs saw.
const MISS_MS: u64 = 40;

/// What one leg cost.
struct Leg {
    label: String,
    wall: Duration,
    /// The stall: last delivered body to last terminal verdict. This is
    /// the quantity the fix is about.
    tail: Duration,
    done: usize,
    missing: usize,
    /// BODY commands the mocks logged, fleet-wide. The ladder's traffic
    /// bill - it may go UP when the tail gets shorter (asking three
    /// backbones at once costs the same questions, just not in series),
    /// but it must not explode.
    dispatched: u64,
}

impl Leg {
    fn line(&self) -> String {
        format!(
            "{:<28} wall {:>6.2}s   ladder tail {:>6.2}s   {} done, {} missing, \
             {} dispatches",
            self.label,
            self.wall.as_secs_f64(),
            self.tail.as_secs_f64(),
            self.done,
            self.missing,
            self.dispatched,
        )
    }
}

/// One leg: `n_dead` poisoned ids that every backbone refuses, mixed
/// into `N_GOOD` healthy ones.
async fn ladder_leg(label: &str, n_dead: usize) -> Leg {
    let data: Vec<u8> = (0..(ART * N_GOOD) as u32).map(|i| i as u8).collect();
    let mut articles: HashMap<String, Vec<u8>> = HashMap::new();
    let segs = make_file_articles("payload.bin", &data, ART, "good", &mut articles);
    let dead: Vec<String> = (0..n_dead).map(|i| format!("<dead{i}@mock>")).collect();

    // Every backbone refuses every poisoned id. Three echo the id on
    // the refusal line, two answer bare - the split that decides
    // whether an article is asked once or twice per backbone.
    let mut mocks = Vec::new();
    for si in 0..SERVERS {
        let chaos = Chaos {
            missing: dead.iter().cloned().collect::<HashSet<String>>(),
            missing_delay_ms: MISS_MS,
            echo_missing_id: si % 2 == 0,
            ..Default::default()
        };
        mocks.push(MockServer::start(articles.clone(), chaos).await);
    }

    let servers: Vec<(ServerConfig, PoolConfig)> = mocks
        .iter()
        .map(|m| {
            let mut sc = m.server_config();
            sc.connections = CONNS as u32;
            (
                sc,
                PoolConfig {
                    connections: CONNS,
                    ramp_delay: Duration::from_millis(0),
                    ..Default::default()
                },
            )
        })
        .collect();
    let live = LiveStats::for_servers(&servers);
    let servers: Vec<(ServerConfig, PoolConfig)> = servers
        .into_iter()
        .map(|(s, mut c)| {
            c.live = Some(live.clone());
            (s, c)
        })
        .collect();

    let mut reqs: Vec<ArticleReq> = segs
        .iter()
        .map(|(id, _, _)| ArticleReq::fresh(format!("<{id}>")))
        .collect();
    for id in &dead {
        reqs.push(ArticleReq::fresh(id.clone()));
    }

    let (tx, mut rx) = mpsc::channel(64);
    let t0 = Instant::now();
    let fetch = tokio::spawn(async move { fetch_all_multi(&servers, reqs, tx).await });
    let collect = tokio::spawn(async move {
        let (mut done, mut missing) = (0usize, 0usize);
        // The two ends of the stall: when the payload stopped arriving,
        // and when the last verdict finally landed.
        let (mut last_done, mut last_missing) = (t0, t0);
        while let Some(o) = rx.recv().await {
            match o {
                FetchOutcome::Done { .. } => {
                    done += 1;
                    last_done = Instant::now();
                }
                FetchOutcome::Missing { .. } => {
                    missing += 1;
                    last_missing = Instant::now();
                }
                FetchOutcome::Failed { .. } => {}
            }
        }
        (done, missing, last_done, last_missing)
    });
    tokio::time::timeout(Duration::from_secs(180), fetch)
        .await
        .expect("ladder leg hung")
        .unwrap();
    let wall = t0.elapsed();
    let (done, missing, last_done, last_missing) = collect.await.unwrap();
    let dispatched: u64 = mocks
        .iter()
        .map(|m| m.body_log.lock().unwrap().len() as u64)
        .sum();
    Leg {
        label: label.to_string(),
        wall,
        tail: last_missing.saturating_duration_since(last_done),
        done,
        missing,
        dispatched,
    }
}

/// THE CONTRACT, in two clauses that do not depend on how fast the box
/// is.
///
/// **More damage must never be FASTER.** The endgame begins when the
/// job's remainder drops to `ENDGAME_MAX` (64) articles, so damage 60
/// runs inside it and damage 120 starts outside. Above that count the
/// endgame rules are dark and laddering articles pipeline
/// freely; at or below it they were refused a place in any pipeline
/// that held anything at all, so the fleet could carry only one
/// outstanding verdict per connection. Damage 60 sat inside that
/// penalty box and damage 120 did not, and the rig measured exactly
/// that inversion: 6.28 s of tail against 4.69 s for twice the work.
/// A monotonic ladder is the signature of the box being gone, and it
/// says nothing about clock speed.
///
/// **And the tail must stay near what the refusals themselves cost.**
/// Every question this fleet asks is one mock refusal, and the mocks
/// answer serially per connection, so the whole tail can never beat
/// `questions / connections * MISS_MS`. Landing within a small
/// multiple of that floor means the wall belongs to the provider and
/// not to the pool's own scheduling. The fixed shape measures ~1.1x;
/// the old one measured ~6.7x, because each article's five hops ran
/// strictly in series and each hop cost a whole queue rotation.
#[tokio::test(flavor = "multi_thread")]
async fn a_poisoned_tail_reaches_its_verdicts_in_round_trips_not_rotations() {
    let mid = ladder_leg("damage 60", 60).await;
    let big = ladder_leg("damage 120", 120).await;
    println!("\n430-ladder tail:\n  {}\n  {}", mid.line(), big.line());
    for (leg, dead) in [(&mid, 60), (&big, 120)] {
        assert_eq!(leg.done, N_GOOD, "{} lost healthy articles", leg.label);
        assert_eq!(
            leg.missing, dead,
            "{} left poisoned articles without a verdict",
            leg.label
        );
    }
    assert!(
        mid.tail < big.tail,
        "damage 60 is in a penalty box damage 120 escapes: {:?} of tail \
         against {:?} for twice the damage - the endgame is refusing to \
         pipeline verdicts again",
        mid.tail,
        big.tail,
    );
    // Refusals the fleet had to buy, and the wall they cannot beat.
    let questions = mid.dispatched.saturating_sub(N_GOOD as u64);
    let floor = Duration::from_millis(questions * MISS_MS / (SERVERS * CONNS) as u64);
    assert!(
        mid.tail < floor * 4,
        "the ladder tail is back: {:?} against a {:?} refusal floor for \
         {questions} questions",
        mid.tail,
        floor,
    );
    // The fan-out asks the same questions in parallel rather than more
    // of them: at most one per backbone per article, plus the single
    // confirming repeat each non-echoing provider still owes on the
    // refusal that arms its fence.
    let ceiling = 60 * 7;
    assert!(
        questions < ceiling,
        "ladder dispatches ran away: {questions} against a {ceiling} ceiling",
    );
}

/// The same shape across the damage ladder, printed rather than
/// asserted - the A/B table for a benchmark round. Run with
/// `--ignored --nocapture`.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "wall-clock A/B table - run with --ignored"]
async fn ladder_tail_across_the_damage_ladder() {
    let mut table = Vec::new();
    for n in [5usize, 20, 60, 120] {
        table.push(ladder_leg(&format!("damage {n}"), n).await);
    }
    println!(
        "\n430-ladder tail, {SERVERS} backbones x {CONNS} connections, {MISS_MS} ms refusals:"
    );
    for leg in &table {
        println!("  {}", leg.line());
    }
    for leg in &table {
        assert_eq!(leg.done, N_GOOD, "{} lost healthy articles", leg.label);
    }
}

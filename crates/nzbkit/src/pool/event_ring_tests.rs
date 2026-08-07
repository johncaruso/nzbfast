//! Event-ring unit tests, moved out of pool.rs's inline `tests` mod so
//! the file stays inside its size-gate baseline (the gate's own rule:
//! test code moves to a child module, production overgrowth moves to a
//! helper, baselines are never raised). A child module of `pool`, same
//! shape as unit_tests.rs and rig_tests.rs, so `super::*` still reaches
//! the private internals these exercise.

use super::*;

/// Built directly rather than through `for_servers`: these tests are
/// about the ring, and threading a full ServerConfig literal through
/// them would make them fail whenever an unrelated field is added.
fn live(hosts: &[&str]) -> Arc<LiveStats> {
    Arc::new(LiveStats {
        servers: hosts
            .iter()
            .map(|h| ServerLive {
                host: (*h).to_string(),
                budget: AtomicUsize::new(1),
                connected: AtomicUsize::new(0),
                refusal: std::sync::Mutex::new(None),
                bytes: AtomicU64::new(0),
                articles_tried: AtomicU64::new(0),
                articles_missing: AtomicU64::new(0),
                reconnects: AtomicU64::new(0),
                ends_peer: AtomicU64::new(0),
                ends_protocol: AtomicU64::new(0),
                ends_prebyte: AtomicU64::new(0),
                ends_stall: AtomicU64::new(0),
                ends_ours: AtomicU64::new(0),
                blocked_ms: AtomicU64::new(0),
                last_blocked_note: AtomicU64::new(0),
                missing_note_at: AtomicU64::new(0),
                missing_at_note: AtomicU64::new(0),
                last_timeout_note: AtomicU64::new(0),
            })
            .collect(),
        events: std::sync::Mutex::new(std::collections::VecDeque::new()),
    })
}

/// The ring is bounded, and it drops the OLDEST.
///
/// A daemon runs for weeks. An unbounded event list would be a slow
/// leak in the one place nobody looks, and dropping the newest would
/// make it useless precisely when it is busy - which is when a dip
/// happens.
#[test]
fn the_ring_is_capped_and_keeps_the_newest() {
    let l = live(&["a.example"]);
    for i in 0..(EVENT_RING + 50) {
        l.note(0, "reconnect", format!("#{i}"));
    }
    assert_eq!(l.events.lock().unwrap().len(), EVENT_RING);
    let newest = l.recent_events(1);
    assert_eq!(newest[0].detail, format!("#{}", EVENT_RING + 49));
}

/// Newest first, because that is the order the question is asked in:
/// "what just happened", never "what happened first".
#[test]
fn recent_events_are_newest_first() {
    let l = live(&["a.example"]);
    l.note(0, "cap", "one");
    l.note(0, "cap", "two");
    l.note(0, "cap", "three");
    let got: Vec<String> = l.recent_events(2).into_iter().map(|e| e.detail).collect();
    assert_eq!(got, vec!["three".to_string(), "two".to_string()]);
}

/// Events carry the host, so a dip on a six-provider run can be put
/// down to ONE of them. A count with no host would say a reconnect
/// happened and leave the user to guess where.
#[test]
fn an_event_names_the_server_it_happened_to() {
    let l = live(&["a.example", "b.example"]);
    l.note(1, "reconnect", "session lost, redialled");
    let e = l.recent_events(1);
    assert_eq!(e[0].host, "b.example");
    assert_eq!(e[0].kind, "reconnect");
}

/// An out-of-range index is a no-op, not a panic. This is called from
/// download workers; instrumentation must never be the thing that
/// takes a run down.
#[test]
fn a_bad_index_is_ignored_rather_than_fatal() {
    let l = live(&["a.example"]);
    l.note(9, "reconnect", "nowhere");
    assert!(l.recent_events(10).is_empty());
}

/// Timestamped in wall clock, which is what lets the UI lay an event
/// against a throughput sample. A monotonic instant could not cross
/// the API, and an index into the ring would not survive the cap.
#[test]
fn events_carry_a_wall_clock_moment() {
    let before = now_ms();
    let l = live(&["a.example"]);
    l.note(0, "blocked", "waited 800 ms for the write side");
    let e = l.recent_events(1);
    assert!(e[0].at_ms >= before, "{} < {before}", e[0].at_ms);
    assert!(e[0].at_ms <= now_ms());
}

/// Phase boundaries and fleet-wide spikes belong to the RUN, not to
/// a server - they ride the same ring with an empty host, which is
/// how the dashboard knows not to print one.
#[test]
fn run_events_ride_the_ring_without_a_host() {
    let l = live(&["a.example"]);
    l.note_run("tail", "every article has been handed out");
    let e = l.recent_events(1);
    assert_eq!(e[0].kind, "tail");
    assert_eq!(e[0].host, "");
}

/// The missing-article marker is windowed: the first 430 opens a
/// window silently, a window that closes with a burst inside it
/// yields exactly one marker, and a window that closes quiet yields
/// none. Without the threshold every retry ladder would mark the
/// graph; without the window a take-down's hundreds of 430s would
/// flush the ring - the same discipline as the blocked note.
#[test]
fn missing_bursts_mark_once_per_window_and_only_over_threshold() {
    let l = live(&["a.example"]);
    let s = &l.servers[0];
    s.articles_missing.fetch_add(1, Ordering::Relaxed);
    l.note_missing_burst(0);
    assert!(
        l.recent_events(10).is_empty(),
        "opening the window is silent"
    );
    // A burst lands inside the window, and the window closes.
    s.articles_missing
        .fetch_add(MISSING_BURST, Ordering::Relaxed);
    s.missing_note_at
        .store(now_ms() - BURST_WINDOW_MS - 1, Ordering::Relaxed);
    l.note_missing_burst(0);
    let e = l.recent_events(10);
    assert_eq!(e.len(), 1, "one marker per closed window");
    assert_eq!(e[0].kind, "missing");
    // The next window closes with only a scatter inside: no marker.
    s.articles_missing.fetch_add(3, Ordering::Relaxed);
    s.missing_note_at
        .store(now_ms() - BURST_WINDOW_MS - 1, Ordering::Relaxed);
    l.note_missing_burst(0);
    assert_eq!(l.recent_events(10).len(), 1, "a quiet window adds nothing");
}

fn shared_with_live(hosts: &[&str]) -> (Arc<Shared>, Arc<LiveStats>) {
    let servers: Vec<(ServerConfig, PoolConfig)> = hosts
        .iter()
        .map(|h| {
            let sc: ServerConfig = serde_json::from_value(serde_json::json!({"host": h})).unwrap();
            (sc, PoolConfig::default())
        })
        .collect();
    let l = LiveStats::for_servers(&servers);
    let servers: Vec<(ServerConfig, PoolConfig)> = servers
        .into_iter()
        .map(|(sc, mut cfg)| {
            cfg.live = Some(l.clone());
            (sc, cfg)
        })
        .collect();
    let (shared, _) = Shared::new(vec![ArticleReq::fresh("<a@x>".into())], &servers);
    (shared, l)
}

/// The racing marker is the run-level twin of the missing one: the
/// dups+hedges counters close a window, a spike inside it earns one
/// marker, and a second look inside the same window adds nothing.
#[test]
fn racing_bursts_mark_once_per_window() {
    let (shared, l) = shared_with_live(&["a.example"]);
    shared.dups_issued.store(RACE_BURST + 2, Ordering::Relaxed);
    shared
        .race_note_at
        .store(now_ms() - BURST_WINDOW_MS - 1, Ordering::Relaxed);
    shared.note_race_burst();
    let e = l.recent_events(10);
    assert_eq!(e.len(), 1);
    assert_eq!(e[0].kind, "racing");
    assert_eq!(e[0].host, "");
    // Same window, more calls: silent.
    shared.note_race_burst();
    assert_eq!(l.recent_events(10).len(), 1);
}

/// A server whose LAST worker leaves mid-run (pending work, no abort,
/// no drain) marks the graph once; the same departure during a
/// natural wind-down - nothing pending - marks nothing, because every
/// worker leaves at the end of every job and none of that is a fault.
#[test]
fn a_server_going_dark_mid_run_marks_the_graph_once() {
    let (shared, l) = shared_with_live(&["a.example", "b.example"]);
    assert!(shared.pending.load(Ordering::Acquire) > 0);
    note_server_dark(&shared, 0, 2);
    assert!(l.recent_events(10).is_empty(), "not the last worker");
    note_server_dark(&shared, 0, 1);
    let e = l.recent_events(10);
    assert_eq!(e.len(), 1);
    assert_eq!(e[0].kind, "retired");
    assert_eq!(e[0].host, "a.example");
    // Natural wind-down: queue empty, everyone leaves, no marker.
    let (shared2, l2) = shared_with_live(&["a.example"]);
    shared2.pending.store(0, Ordering::Release);
    note_server_dark(&shared2, 0, 1);
    assert!(l2.recent_events(10).is_empty());
}

/// The drain latch is also the phase marker that stops the natural
/// end-of-job throughput fall from reading as a fault.
#[test]
fn draining_the_last_article_marks_the_phase() {
    let (shared, l) = shared_with_live(&["a.example"]);
    shared.mark_drained();
    let e = l.recent_events(10);
    assert_eq!(e.len(), 1);
    assert_eq!(e[0].kind, "drained");
    assert!(shared.drained_at.lock_ok().is_some());
}

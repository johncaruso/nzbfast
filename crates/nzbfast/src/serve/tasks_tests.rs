//! §106 phase 3: unit tests for the pure helpers and small
//! Daemon-backed functions in serve/tasks.rs. StallTracker basics live
//! in `stall_tests`; only the edges it misses are covered here.

use super::*;
use serde_json::json;
use std::time::{Duration, Instant};

fn tdir(name: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("nzbfast-tsk-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn mkjob(name: &str, identity: &str) -> Job {
    let mut j = super::super::job_from_json(&json!({
        "nzo_id": "tsk1",
        "name": name,
        "nzb_path": "/spool/tsk1.nzb",
        "out_dir": "/dl/tsk1",
        "state": "Queued",
    }))
    .expect("job_from_json");
    j.identity_name = identity.to_string();
    j
}

fn facts(res: Option<&str>, complete: bool) -> nzbkit::mediaprobe::MediaFacts {
    nzbkit::mediaprobe::MediaFacts {
        res: res.map(|s| s.to_string()),
        complete,
        ..Default::default()
    }
}

// ---------------------------------------------------------------------
// 1. lane_kind
// ---------------------------------------------------------------------

#[cfg(feature = "indexer")]
#[test]
fn lane_kind_maps_the_four_lanes_and_nothing_else() {
    use crate::wall::Kind;
    assert_eq!(super::lane_kind("tv"), Kind::Tv);
    assert_eq!(super::lane_kind("movie"), Kind::Movie);
    assert_eq!(super::lane_kind("music"), Kind::Music);
    assert_eq!(super::lane_kind("book"), Kind::Book);
    // Anything else - empty, wrong case, unknown - is Other, which the
    // enricher stamps without a provider call.
    assert_eq!(super::lane_kind(""), Kind::Other);
    assert_eq!(super::lane_kind("TV"), Kind::Other);
    assert_eq!(super::lane_kind("other"), Kind::Other);
}

// ---------------------------------------------------------------------
// 2. watch_fail_id
// ---------------------------------------------------------------------

#[test]
fn watch_fail_id_is_an_opaque_16_hex_handle_of_the_full_path() {
    let a = super::watch_fail_id(std::path::Path::new("/a/same.nzb"));
    assert_eq!(a.len(), 16);
    assert!(
        a.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    );
    // Deterministic.
    assert_eq!(a, super::watch_fail_id(std::path::Path::new("/a/same.nzb")));
    // The FULL path is the identity: same basename, different dir.
    let b = super::watch_fail_id(std::path::Path::new("/b/same.nzb"));
    assert_ne!(a, b);
    // A digest, never the path itself.
    assert!(!a.contains("same") && !a.contains("nzb"));
    assert!(!b.contains("same") && !b.contains("nzb"));
}

// ---------------------------------------------------------------------
// 3. watch_fail_kind edges
// ---------------------------------------------------------------------

#[test]
fn watch_fail_kind_matches_exactly_except_the_kept_prefix() {
    use super::watchfail;
    // Only KEPT is starts_with; the others are exact equality, so a
    // message merely CONTAINING one stays "rejected".
    let wrapped = format!("note: {} (seen twice)", watchfail::TRUNCATED);
    assert_eq!(super::watch_fail_kind(&wrapped), "rejected");
    assert_eq!(super::watch_fail_kind(""), "rejected");
    let kept = format!("{}: Permission denied (os error 13)", watchfail::KEPT);
    assert_eq!(super::watch_fail_kind(&kept), "kept");
}

// ---------------------------------------------------------------------
// 4. media_claim_name
// ---------------------------------------------------------------------

#[test]
fn media_claim_name_prefers_a_non_empty_identity() {
    let j = mkjob("posted.name", "");
    assert_eq!(super::media_claim_name(&j), "posted.name");
    let j = mkjob("posted.name", "Canonical.Name-GRP");
    assert_eq!(super::media_claim_name(&j), "Canonical.Name-GRP");
    // Whitespace is non-empty: no trimming happens here.
    let j = mkjob("posted.name", "   ");
    assert_eq!(super::media_claim_name(&j), "   ");
}

// ---------------------------------------------------------------------
// 5. media_settled
// ---------------------------------------------------------------------

#[test]
fn media_settled_four_way_truth_table() {
    // No media at all.
    let j = mkjob("x", "");
    assert!(!super::media_settled(&j));
    // Complete but nothing to show (any() false).
    let mut j = mkjob("x", "");
    j.media = Some(facts(None, true));
    assert!(!super::media_settled(&j));
    // Complete and showing, but owed a re-judge.
    let mut j = mkjob("x", "");
    j.media = Some(facts(Some("1080p"), true));
    j.media_rejudge = true;
    assert!(!super::media_settled(&j));
    // Complete, showing, no re-judge owed: settled.
    let mut j = mkjob("x", "");
    j.media = Some(facts(Some("1080p"), true));
    assert!(super::media_settled(&j));
}

// ---------------------------------------------------------------------
// 6. latch_media
// ---------------------------------------------------------------------

#[test]
fn latch_media_never_downgrades_and_reports_real_changes() {
    use std::sync::{Arc, Mutex};
    // Empty facts over an existing answer: refused, answer untouched.
    let job = Arc::new(Mutex::new(mkjob("x", "")));
    job.lock_ok().media = Some(facts(Some("2160p"), true));
    assert!(!super::latch_media(&job, facts(None, false)));
    assert_eq!(
        job.lock_ok().media.as_ref().unwrap().res.as_deref(),
        Some("2160p")
    );
    // Identical facts: no change to report.
    assert!(!super::latch_media(&job, facts(Some("2160p"), true)));
    // Empty facts over None DO latch (the "probe ran, saw nothing yet"
    // record is itself information).
    let job = Arc::new(Mutex::new(mkjob("x", "")));
    assert!(super::latch_media(&job, facts(None, false)));
    assert!(job.lock_ok().media.is_some());
    // A mismatch list writes and returns true.
    let mut f = facts(Some("1080p"), true);
    f.mismatch.push(nzbkit::mediaprobe::facts::Mismatch {
        field: nzbkit::mediaprobe::facts::Field::Resolution,
        claimed: "2160p".to_string(),
        actual: "1080p".to_string(),
    });
    assert!(super::latch_media(&job, f.clone()));
    assert_eq!(job.lock_ok().media.as_ref(), Some(&f));
}

// ---------------------------------------------------------------------
// 7. StallTracker edges
// ---------------------------------------------------------------------

#[test]
fn stall_opens_exactly_at_the_threshold_and_reports_since() {
    let t0 = Instant::now();
    let mut s = StallTracker::new(Duration::from_secs(10));
    assert!(s.observe(t0, Some(("a", "job-a")), 100).is_none());
    // >= semantics: exactly T after the baseline opens the episode.
    match s.observe(t0 + Duration::from_secs(10), Some(("a", "job-a")), 100) {
        Some(StallEvent::Opened { idle_secs, since }) => {
            assert_eq!(idle_secs, 10);
            assert_eq!(since, t0);
        }
        _ => panic!("expected Opened exactly at the threshold"),
    }
}

#[test]
fn stall_bytes_going_backwards_count_as_progress() {
    let t0 = Instant::now();
    let tick = |secs: u64| t0 + Duration::from_secs(secs);
    let mut s = StallTracker::new(Duration::from_secs(10));
    assert!(s.observe(t0, Some(("a", "job-a")), 500).is_none());
    // A LOWER total is still "total != last": the clock resets.
    assert!(s.observe(tick(5), Some(("a", "job-a")), 400).is_none());
    // 10s from t0 but only 5s from the backwards move: still quiet.
    assert!(s.observe(tick(10), Some(("a", "job-a")), 400).is_none());
    assert!(matches!(
        s.observe(tick(15), Some(("a", "job-a")), 400),
        Some(StallEvent::Opened { idle_secs: 10, .. })
    ));
    // And an open episode is CLEARED by a backwards move too.
    assert!(matches!(
        s.observe(tick(20), Some(("a", "job-a")), 300),
        Some(StallEvent::Cleared { .. })
    ));
}

#[test]
fn stall_no_open_episode_means_silence_on_job_end() {
    let t0 = Instant::now();
    let tick = |secs: u64| t0 + Duration::from_secs(secs);
    let mut s = StallTracker::new(Duration::from_secs(10));
    // Never any job: nothing to say.
    assert!(s.observe(t0, None, 0).is_none());
    // A job that leaves BEFORE its episode opens ends silently.
    assert!(s.observe(tick(1), Some(("a", "job-a")), 100).is_none());
    assert!(s.observe(tick(5), None, 0).is_none());
    assert!(s.observe(tick(6), None, 0).is_none());
}

// ---------------------------------------------------------------------
// 8. prune_person_art
// ---------------------------------------------------------------------

#[cfg(feature = "indexer")]
fn art_file(dir: &std::path::Path, name: &str, len: usize, age_secs: u64) {
    let p = dir.join(name);
    std::fs::write(&p, vec![0u8; len]).unwrap();
    let t = std::time::SystemTime::now() - Duration::from_secs(age_secs);
    let f = std::fs::OpenOptions::new().write(true).open(&p).unwrap();
    f.set_times(std::fs::FileTimes::new().set_accessed(t).set_modified(t))
        .unwrap();
}

#[cfg(feature = "indexer")]
#[test]
fn prune_person_art_spares_posters_and_leaves_an_under_cap_dir_alone() {
    let dir = tdir("prune-spare");
    // Posters and backdrops are never candidates, however old or large.
    art_file(&dir, "m_the_matrix_1999.jpg", 5000, 9000);
    art_file(&dir, "t_severance.bd.jpg", 5000, 9000);
    art_file(&dir, "p1.jpg", 100, 300);
    super::prune_person_art(&dir, 200);
    assert!(dir.join("m_the_matrix_1999.jpg").exists());
    assert!(dir.join("t_severance.bd.jpg").exists());
    assert!(dir.join("p1.jpg").exists());
    // Under the cap: a no-op even for headshots.
    art_file(&dir, "p2.jpg", 50, 100);
    super::prune_person_art(&dir, 10_000);
    assert!(dir.join("p1.jpg").exists());
    assert!(dir.join("p2.jpg").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(feature = "indexer")]
#[test]
fn prune_person_art_evicts_oldest_first_and_stops_at_the_cap() {
    let dir = tdir("prune-evict");
    art_file(&dir, "p1.jpg", 100, 3000); // oldest
    art_file(&dir, "p2.jpg", 100, 2000);
    art_file(&dir, "p3.jpg", 100, 1000); // newest
    art_file(&dir, "m_poster.jpg", 1000, 9000); // never counted
    // 300 headshot bytes over a 250 cap: evicting p1 alone reaches 200.
    super::prune_person_art(&dir, 250);
    assert!(!dir.join("p1.jpg").exists());
    assert!(dir.join("p2.jpg").exists());
    assert!(dir.join("p3.jpg").exists());
    assert!(dir.join("m_poster.jpg").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------
// 9. sample_ids
// ---------------------------------------------------------------------

fn epoch_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

#[test]
fn sample_ids_excludes_recovery_volumes_and_wraps_ids() {
    let dir = tdir("sample-ids");
    let now = epoch_now();
    let xml = format!(
        r#"<?xml version="1.0"?>
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
 <file subject="data.bin yEnc (1/2)" date="{}">
  <groups><group>alt.binaries.test</group></groups>
  <segments>
   <segment bytes="1000" number="1">seg1@test</segment>
   <segment bytes="1000" number="2">seg2@test</segment>
  </segments>
 </file>
 <file subject="set.par2 yEnc (1/1)" date="{}">
  <groups><group>alt.binaries.test</group></groups>
  <segments><segment bytes="500" number="1">par2main@test</segment></segments>
 </file>
 <file subject="set.vol000+01.par2 yEnc (1/1)" date="{}">
  <groups><group>alt.binaries.test</group></groups>
  <segments><segment bytes="500" number="1">vol@test</segment></segments>
 </file>
</nzb>"#,
        now - 5 * 86_400 - 10,
        now - 2 * 86_400 - 10,
        now // if the volume leaked into the age, it would read 0
    );
    let path = dir.join("post.nzb");
    std::fs::write(&path, xml).unwrap();
    let (ids, age) = super::sample_ids(&path, 64).expect("sampled");
    assert!(ids.contains(&"<seg1@test>".to_string()));
    assert!(ids.contains(&"<seg2@test>".to_string()));
    // The base .par2 index IS sampled; recovery volumes are not.
    assert!(ids.contains(&"<par2main@test>".to_string()));
    assert!(!ids.iter().any(|i| i.contains("vol@test")));
    // Age is the minimum over the sampled files: 2 days, not 5, not 0.
    assert_eq!(age, 2);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn sample_ids_answers_none_for_volume_only_or_unreadable_posts() {
    let dir = tdir("sample-none");
    let xml = format!(
        r#"<?xml version="1.0"?>
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
 <file subject="set.vol000+01.par2 yEnc (1/1)" date="{}">
  <groups><group>alt.binaries.test</group></groups>
  <segments><segment bytes="500" number="1">vol@test</segment></segments>
 </file>
</nzb>"#,
        epoch_now() - 86_400
    );
    let path = dir.join("vols.nzb");
    std::fs::write(&path, xml).unwrap();
    assert!(super::sample_ids(&path, 8).is_none());
    assert!(super::sample_ids(&dir.join("missing.nzb"), 8).is_none());
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------
// 10. update_tune_hint
// ---------------------------------------------------------------------

fn srv(host: &str, block: Option<u64>) -> nzbkit::config::ServerConfig {
    nzbkit::config::ServerConfig {
        host: host.into(),
        port: 563,
        tls: true,
        username: None,
        password: None,
        connections: 20,
        pin_connections: false,
        rcvbuf: None,
        level: 0,
        group: None,
        retention_days: 0,
        block_bytes: block,
        bind_ip: None,
        socks5: None,
        enabled: true,
        warm_pool: false,
        idle_release_secs: None,
        idle_keep: None,
        max_source_ips: None,
    }
}

fn tuned(gbps: f64, asked: usize, connections: usize) -> crate::conntune::Tuned {
    crate::conntune::Tuned {
        connections,
        granted: connections,
        asked,
        gbps,
        checked: 0,
        source: String::new(),
        suspect: false,
        limit: 0,
        v: 0,
        pending: None,
    }
}

#[test]
fn tune_hint_bands_stale_setting_well_short_and_clear() {
    let dir = tdir("tune-bands");
    let d = super::super::testutil::test_daemon(&dir);
    // Line speed is stored in bytes/s: 1 Gbps.
    d.line_speed.store(125_000_000, Ordering::Relaxed);
    let servers = vec![srv("news.a.example", None)];
    let map = |g: f64| {
        let mut m = std::collections::HashMap::new();
        m.insert("news.a.example".to_string(), tuned(g, 20, 20));
        m
    };
    // >110% of the line: the SETTING is called stale.
    super::update_tune_hint(&d, &servers, &map(1.2));
    assert!(d.tune_hint.lock_ok().contains("the setting looks low"));
    // <80%: well short, providers are the lever.
    super::update_tune_hint(&d, &servers, &map(0.5));
    assert!(d.tune_hint.lock_ok().contains("well short"));
    // In between: the hint clears.
    super::update_tune_hint(&d, &servers, &map(1.0));
    assert!(d.tune_hint.lock_ok().is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn tune_hint_block_accounts_never_gate_the_verdict() {
    let dir = tdir("tune-block");
    let d = super::super::testutil::test_daemon(&dir);
    d.line_speed.store(125_000_000, Ordering::Relaxed);
    // Only a block account: nothing is ever measured, so no verdict -
    // even with a tuned entry sitting there saying "well short".
    let block_only = vec![srv("block.example", Some(500 << 30))];
    let mut m = std::collections::HashMap::new();
    m.insert("block.example".to_string(), tuned(0.2, 20, 20));
    *d.tune_hint.lock_ok() = "stale words".to_string();
    super::update_tune_hint(&d, &block_only, &m);
    assert!(d.tune_hint.lock_ok().is_empty());
    // A block account BESIDE a measured server must not suppress the
    // verdict, even though the prober never gave it a tuned entry.
    let mixed = vec![
        srv("block.example", Some(500 << 30)),
        srv("news.a.example", None),
    ];
    let mut m = std::collections::HashMap::new();
    m.insert("news.a.example".to_string(), tuned(0.5, 20, 20));
    super::update_tune_hint(&d, &mixed, &m);
    assert!(d.tune_hint.lock_ok().contains("well short"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn tune_hint_tips_tier_cap_unknown_asked_and_single_provider() {
    let dir = tdir("tune-tips");
    let d = super::super::testutil::test_daemon(&dir);
    d.line_speed.store(125_000_000, Ordering::Relaxed);
    // asked > connections: the account-tier tip names the exact pair.
    let two = vec![srv("news.a.example", None), srv("news.b.example", None)];
    let mut m = std::collections::HashMap::new();
    m.insert("news.a.example".to_string(), tuned(0.3, 32, 21));
    m.insert("news.b.example".to_string(), tuned(0.2, 8, 8));
    super::update_tune_hint(&d, &two, &m);
    {
        let h = d.tune_hint.lock_ok();
        assert!(h.contains("granted only 21 of the 32"));
        assert!(h.contains("news.a.example"));
    }
    // asked == 0 is a pre-field entry: unknown, so no tier claim - the
    // generic "faster provider" tip stands in.
    let mut m = std::collections::HashMap::new();
    m.insert("news.a.example".to_string(), tuned(0.3, 0, 6));
    m.insert("news.b.example".to_string(), tuned(0.2, 0, 6));
    super::update_tune_hint(&d, &two, &m);
    {
        let h = d.tune_hint.lock_ok();
        assert!(!h.contains("granted only"));
        assert!(h.contains("a faster provider"));
    }
    // A single measured provider gets the parallel-headroom tip.
    let one = vec![srv("news.a.example", None)];
    let mut m = std::collections::HashMap::new();
    m.insert("news.a.example".to_string(), tuned(0.5, 20, 20));
    super::update_tune_hint(&d, &one, &m);
    assert!(
        d.tune_hint
            .lock_ok()
            .contains("a second provider adds parallel headroom")
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------
// 11. download_idle
// ---------------------------------------------------------------------

#[test]
fn download_idle_requires_both_pipelines_quiet() {
    let dir = tdir("dl-idle");
    let d = super::super::testutil::test_daemon(&dir);
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let mk_sidecar = || Sidecar {
        nzo_id: "s1".to_string(),
        hub: Arc::new(crate::StreamHub::default()),
        progress: Arc::new(AtomicU64::new(0)),
        cancelled: Arc::new(AtomicBool::new(false)),
        task: rt.spawn(async {}),
        borrowed: false,
    };
    // Neither running: idle.
    assert!(super::download_idle(&d));
    // Primary runner only.
    *d.started_at.lock_ok() = Some(Instant::now());
    assert!(!super::download_idle(&d));
    // Both.
    *d.sidecar.lock_ok() = Some(mk_sidecar());
    assert!(!super::download_idle(&d));
    // Sidecar only (the runner-tail window §77 stands down for).
    *d.started_at.lock_ok() = None;
    assert!(!super::download_idle(&d));
    *d.sidecar.lock_ok() = None;
    assert!(super::download_idle(&d));
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------
// 12. instant_arrivals
// ---------------------------------------------------------------------

#[cfg(feature = "indexer")]
#[test]
fn instant_arrivals_kicks_complete_hits_and_first_sighting_wins() {
    use nzbkit::index::WatchHit;
    let dir = tdir("instant");
    let d = super::super::testutil::test_daemon(&dir);
    d.instant_pending.lock_ok().insert(7, 111);
    // A complete hit leaves pending and kicks the watchlist pass.
    super::instant_arrivals(
        &d,
        vec![WatchHit {
            id: 7,
            name: "Show.S01E01.1080p-GRP".to_string(),
            complete: true,
        }],
        0,
        1000,
    );
    assert!(!d.instant_pending.lock_ok().contains_key(&7));
    assert!(
        d.instant_hint
            .lock_ok()
            .contains(&"Show.S01E01.1080p-GRP".to_string())
    );
    // An incomplete hit is stamped once; a later batch must NOT
    // re-stamp it (the first clock is what expires it).
    let hit = |now| {
        super::instant_arrivals(
            &d,
            vec![WatchHit {
                id: 9,
                name: "Still.Uploading".to_string(),
                complete: false,
            }],
            0,
            now,
        )
    };
    hit(100);
    assert_eq!(d.instant_pending.lock_ok().get(&9), Some(&100));
    hit(200);
    assert_eq!(d.instant_pending.lock_ok().get(&9), Some(&100));
    // Empty hits early-return even when drops were reported.
    let hints_before = d.instant_hint.lock_ok().len();
    super::instant_arrivals(&d, Vec::new(), 3, 300);
    assert_eq!(d.instant_pending.lock_ok().get(&9), Some(&100));
    assert_eq!(d.instant_hint.lock_ok().len(), hints_before);
    let _ = std::fs::remove_dir_all(&dir);
}

#![cfg(feature = "indexer")]
//! TODO §74 end to end: a watched show is grabbed SECONDS after it is
//! posted, not at the next periodic watchlist pass.
//!
//! Everything here runs against a real daemon and a real (mock) news
//! server, because the claim is about the seam between three moving
//! parts: the tip watcher noticing a new article, the arrival watch
//! inside the index reporting it, and the ordinary watchlist pass being
//! woken by that report. A seeded database cannot test any of it - the
//! post has to ARRIVE.
//!
//! What each case pins:
//!
//! - `an_arriving_release_is_grabbed_without_waiting_for_the_pass`: the
//!   headline. The daemon's periodic pass is 60 s away; the job is in the
//!   queue long before that, and the watchlist's own record says it was
//!   grabbed because it arrived.
//! - `a_post_still_going_up_is_not_grabbed_until_it_is_complete`: the
//!   completeness gate. A release seen at +6 s is usually half-posted, and
//!   half a post is not a download. It is grabbed once the rest lands -
//!   once, not once per batch.
//! - `the_quality_ladder_still_applies_on_the_instant_path`: the whole
//!   design constraint. The instant path grabs through the SAME pass, so
//!   a worse encode arriving later cannot preempt the better one already
//!   in hand.
//!
//! The harness is the shape tests/watchlist_packs.rs uses - copied, not
//! shared, because nzbfast is a binary-only crate and integration tests
//! cannot import from each other.

mod scratch;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};

use nzbkit::mock::{Chaos, MockServer, OverRow};

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// (status, body) of a GET; connection refusals retried, answers never.
fn http_get(port: u16, req: &str) -> (u16, String) {
    let msg = format!("GET {req} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n");
    let mut last = String::new();
    for attempt in 0..5u32 {
        match http_once(port, &msg) {
            Ok(out) => return out,
            Err(e) => {
                last = e.to_string();
                std::thread::sleep(std::time::Duration::from_millis(
                    100 * u64::from(attempt) + 50,
                ));
            }
        }
    }
    panic!("daemon on :{port} never served {req}: {last}");
}

fn http_once(port: u16, msg: &str) -> std::io::Result<(u16, String)> {
    let mut s = TcpStream::connect(("127.0.0.1", port))?;
    s.write_all(msg.as_bytes())?;
    let mut out = String::new();
    let read = s.read_to_string(&mut out);
    if out.is_empty() {
        return Err(read.err().unwrap_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "closed without answering",
            )
        }));
    }
    let status: u16 = out
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    Ok((
        status,
        out.split("\r\n\r\n").nth(1).unwrap_or("").to_string(),
    ))
}

fn pct(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

struct KillOnDrop(Child);
impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct Daemon {
    _child: KillOnDrop,
    port: u16,
}

async fn serve(dir: &Path, build: impl Fn(u16) -> Command) -> Daemon {
    for attempt in 0..3 {
        let port = free_port();
        let logfile = dir.join(format!("daemon-{port}.log"));
        let out = std::fs::File::create(&logfile).unwrap();
        let err = out.try_clone().unwrap();
        let mut cmd = build(port);
        cmd.stdout(Stdio::from(out)).stderr(Stdio::from(err));
        let child = KillOnDrop(cmd.spawn().unwrap());
        let log = logfile.clone();
        let (child, ready) = tokio::task::spawn_blocking(move || {
            let mut child = child;
            let ready = wait_ready(&mut child, port, &log);
            (child, ready)
        })
        .await
        .unwrap();
        if ready {
            return Daemon {
                _child: child,
                port,
            };
        }
        let tail = std::fs::read_to_string(&logfile).unwrap_or_default();
        assert!(
            attempt < 2,
            "daemon exited without binding :{port}\n--- log ---\n{tail}"
        );
    }
    unreachable!()
}

/// Wait for OUR daemon's own banner (a bare connect cannot tell a
/// port-race stranger apart from our child).
fn wait_ready(child: &mut KillOnDrop, port: u16, logfile: &Path) -> bool {
    let banner = format!("open the dashboard at  http://localhost:{port}/");
    for _ in 0..600 {
        if std::fs::read_to_string(logfile)
            .unwrap_or_default()
            .contains(&banner)
            && TcpStream::connect(("127.0.0.1", port)).is_ok()
        {
            return true;
        }
        if child.0.try_wait().ok().flatten().is_some() {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let tail = std::fs::read_to_string(logfile).unwrap_or_default();
    panic!("daemon never came up on :{port}\n--- log ---\n{tail}");
}

const GROUP: &str = "alt.binaries.teevee";

/// The article numbers these tests post at. The index is seeded with a
/// high-water mark of [`SEEDED_MARK`], so everything at or above
/// `SEEDED_MARK + 1` is, to the tip watcher, a post that has just
/// arrived.
const SEEDED_MARK: u64 = 100;

fn row(number: u64, subject: &str, msgid: &str, bytes: u64) -> OverRow {
    OverRow {
        number,
        subject: subject.into(),
        from: "poster@x".into(),
        message_id: format!("<{msgid}>"),
        bytes,
    }
}

/// One complete release as it appears on the wire: the payload and its
/// par2 sidecar. A release is complete when every file it has shown has
/// all its parts, which is what the watchlist requires before grabbing.
fn release(n: u64, stem: &str) -> Vec<OverRow> {
    vec![
        row(
            n,
            &format!("\"{stem}.rar\" yEnc (1/1)"),
            &format!("p{n}@x"),
            40_000,
        ),
        row(
            n + 1,
            &format!("\"{stem}.par2\" yEnc (1/1)"),
            &format!("q{n}@x"),
            400,
        ),
    ]
}

/// The first half of a two-part file: seen, matched, but NOT complete.
fn half_release(n: u64, stem: &str) -> Vec<OverRow> {
    vec![row(
        n,
        &format!("\"{stem}.rar\" yEnc (1/2)"),
        &format!("p{n}@x"),
        40_000,
    )]
}

fn other_half(n: u64, stem: &str) -> Vec<OverRow> {
    vec![row(
        n,
        &format!("\"{stem}.rar\" yEnc (2/2)"),
        &format!("p{n}b@x"),
        40_000,
    )]
}

fn daemon_cmd(dir: &Path, cfg: &Path, db: &Path, port: u16) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
    c.env("NZBFAST_OPEN", "1")
        .env("NZBFAST_NO_ENRICH", "1")
        .arg("--config")
        .arg(cfg)
        .arg("serve")
        // Loopback only - see tests/newznab.rs on the macOS firewall.
        .arg("--bind")
        .arg("127.0.0.1")
        .arg("--port")
        .arg(port.to_string())
        .arg("--out")
        .arg(dir.join("complete"))
        .arg("--index-db")
        .arg(db);
    c
}

/// A daemon watching a live group on `mock`, with `items` as the
/// watchlist and an index that already knows the group (so the tip
/// watcher, which never seeds a group itself, will follow it).
async fn watching(dir: &Path, mock: &MockServer, items: &str) -> Daemon {
    let _ = std::fs::remove_dir_all(dir);
    std::fs::create_dir_all(dir).unwrap();
    let db = dir.join("index.db");
    let host = mock.addr.ip().to_string();
    {
        // The tip watcher follows each group's chosen PRIMARY and only
        // groups a full pass has already scanned: it reads the primary
        // out of kv and refuses a group whose high-water mark is 0
        // (seeding needs a backfill the tip leg does not do). Both are
        // written here so the watcher starts from a group that looks
        // scanned, with everything above the mark still to come.
        let ix = nzbkit::index::Index::open(&db).unwrap();
        let key = nzbkit::index::Index::server_key(&host);
        ix.kv_set(&format!("scan_primary:{GROUP}"), &key).unwrap();
        ix.set_high_water(GROUP, &key, SEEDED_MARK).unwrap();
    }
    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        format!(
            "{{\"servers\":[{{\"host\":\"{host}\",\"port\":{},\"tls\":false,\"connections\":4}}]}}",
            mock.addr.port()
        ),
    )
    .unwrap();
    // index_enabled: the local leg needs the database open at all.
    // index_tip_secs at its 5 s floor so a tick is a test's worth of
    // waiting rather than the 20 s default. The periodic watchlist pass
    // is 60 s and is NOT configurable - which is exactly what makes
    // these assertions about the instant path and not about it.
    std::fs::write(
        cfg.with_file_name("settings.json"),
        format!(
            "{{\"index_enabled\": true, \"index_tip_secs\": 5, \
              \"index_groups\": [\"{GROUP}\"], \"watchlist_instant\": true}}"
        ),
    )
    .unwrap();
    let d = serve(dir, |port| daemon_cmd(dir, &cfg, &db, port)).await;
    let port = d.port;
    let items = items.to_string();
    tokio::task::spawn_blocking(move || {
        // Pause the queue BEFORE anything can be grabbed. These mocks
        // serve overview rows but no article bodies, so an unpaused job
        // starts, finds nothing, and fails into history within a second -
        // and a FAILED watchlist grab correctly frees its slot for
        // another release, which would quietly undo the very state these
        // tests are about. Paused, a grab stays a grab.
        http_get(port, "/api?mode=pause&output=json");
        let (_, r) = http_get(
            port,
            &format!(
                "/api?mode=config&name=watchlist&value={}&output=json",
                pct(&items)
            ),
        );
        assert!(r.contains("true"), "watchlist not accepted: {r}");
    })
    .await
    .unwrap();
    d
}

/// Everything the daemon has been asked to download: the queue AND the
/// history. It has to be both - these mocks serve no bodies for the
/// synthesized NZB, so a grab can fail out of the queue and into history
/// before the next poll.
fn grabbed(port: u16) -> String {
    let (_, q) = http_get(port, "/api?mode=queue&output=json");
    let (_, h) = http_get(port, "/api?mode=history&output=json");
    format!("{q}\n{h}")
}

/// Poll until `needle` has been grabbed, or give up after `secs`.
fn wait_grabbed(port: u16, needle: &str, secs: u64) -> Option<String> {
    for _ in 0..(secs * 4) {
        let seen = grabbed(port);
        if seen.contains(needle) {
            return Some(seen);
        }
        std::thread::sleep(std::time::Duration::from_millis(250));
    }
    None
}

/// How many JOBS carry this name, across queue and history. Counted on
/// the name FIELD rather than by substring: a failure detail quotes the
/// release name a dozen times over. Two field names, because the SAB
/// queue calls it `filename` and the history calls it `name` - counting
/// only one of them reads a real job as none at all.
fn jobs_named(blob: &str, stem: &str) -> usize {
    blob.matches(&format!("\"filename\":\"{stem}\"")).count()
        + blob.matches(&format!("\"name\":\"{stem}\"")).count()
}

fn status(port: u16) -> String {
    http_get(port, "/api?mode=watchlist_status&output=json").1
}

/// The headline: a watched release is posted while the daemon is
/// running, and it is grabbed within a tip tick - long before the 60 s
/// periodic pass would have looked. The watchlist's own `instant` record
/// is what proves WHICH path grabbed it: only an arrival sets it.
#[tokio::test(flavor = "multi_thread")]
async fn an_arriving_release_is_grabbed_without_waiting_for_the_pass() {
    let dir = std::env::temp_dir().join(format!("nzbfast-wlinst-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let mock = MockServer::start_full(
        Default::default(),
        Default::default(),
        Vec::new(),
        Chaos::default(),
    )
    .await;
    let d = watching(
        &dir,
        &mock,
        r#"[{"id":1,"kind":"tv","title":"Wanted Show","seasons":"","episodes":"",
             "min_quality":"any","target_quality":"1080p","enabled":true}]"#,
    )
    .await;
    let port = d.port;
    // Nothing is posted yet, so nothing can be grabbed. THEN it arrives.
    mock.post_overview(release(
        SEEDED_MARK + 1,
        "Wanted.Show.S01E01.1080p.WEB.h264-GRP",
    ));
    let started = std::time::Instant::now();
    tokio::task::spawn_blocking(move || {
        let seen = wait_grabbed(port, "Wanted.Show.S01E01", 45).unwrap_or_else(|| {
            panic!("the arriving release was never grabbed:\n{}", grabbed(port))
        });
        assert!(
            seen.contains("Wanted.Show.S01E01.1080p.WEB.h264-GRP"),
            "grabbed under the wrong name: {seen}"
        );
        // The record the instant path writes, and the periodic one never
        // does. Polled: the pass publishes its state at the END, so the
        // job is visible in the queue before the record is.
        let mut st = String::new();
        for _ in 0..40 {
            st = status(port);
            if st.contains("\"instant\"") && st.contains("Wanted.Show.S01E01") {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
        assert!(
            st.contains("Wanted.Show.S01E01"),
            "the grab was not recorded as an arrival - it came from the \
             periodic pass, not the instant path: {st}"
        );
        assert!(
            st.contains("\"instant_on\":true"),
            "the instant path reports itself off: {st}"
        );
    })
    .await
    .unwrap();
    // A guard on the claim itself rather than on the machinery: the
    // periodic pass is 60 s, so anything at or past that proves nothing
    // even if every assertion above passed.
    assert!(
        started.elapsed() < std::time::Duration::from_secs(55),
        "grabbed only after the periodic pass would have run ({:?}) - \
         this test can no longer tell the two paths apart",
        started.elapsed()
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The completeness gate. A post seen seconds after it starts going up is
/// usually half there, and half a post is not a download - the watchlist
/// waits. When the rest lands it is grabbed, once.
#[tokio::test(flavor = "multi_thread")]
async fn a_post_still_going_up_is_not_grabbed_until_it_is_complete() {
    let dir = std::env::temp_dir().join(format!("nzbfast-wlinst-part-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let mock = MockServer::start_full(
        Default::default(),
        Default::default(),
        Vec::new(),
        Chaos::default(),
    )
    .await;
    let d = watching(
        &dir,
        &mock,
        r#"[{"id":1,"kind":"tv","title":"Wanted Show","seasons":"","episodes":"",
             "min_quality":"any","target_quality":"1080p","enabled":true}]"#,
    )
    .await;
    let port = d.port;
    let stem = "Wanted.Show.S01E02.1080p.WEB.h264-GRP";
    // Part one of two: the uploader is still going.
    mock.post_overview(half_release(SEEDED_MARK + 1, stem));
    let mock = std::sync::Arc::new(mock);
    let m2 = mock.clone();
    tokio::task::spawn_blocking(move || {
        // Two tip ticks' worth of silence. The release is in the index
        // and matches the item; grabbing it now would download half a
        // file and call it an episode.
        std::thread::sleep(std::time::Duration::from_secs(13));
        let seen = grabbed(port);
        assert!(
            !seen.contains("Wanted.Show.S01E02"),
            "a post that is still going up was grabbed:\n{seen}"
        );
        // The rest of it lands.
        m2.post_overview(other_half(SEEDED_MARK + 3, stem));
        wait_grabbed(port, "Wanted.Show.S01E02", 45)
            .unwrap_or_else(|| panic!("the completed post was never grabbed:\n{}", grabbed(port)));
        // Once. Two arrivals of the same release (the half, then the
        // rest) must not become two jobs - the slot the pass fills is
        // what stops it, the same as any other grab. Counted on the job
        // NAME field: the blob also carries the stem in paths and log
        // lines, so a naive substring count says eleven.
        std::thread::sleep(std::time::Duration::from_secs(2));
        let seen = grabbed(port);
        assert_eq!(
            jobs_named(&seen, stem),
            1,
            "the release was grabbed more than once:\n{seen}"
        );
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// The design constraint: the instant path does not grab anything - it
/// wakes the ordinary pass, which applies the whole ladder. So a worse
/// encode arriving after a better one is skipped exactly as it would be
/// on the periodic path.
#[tokio::test(flavor = "multi_thread")]
async fn the_quality_ladder_still_applies_on_the_instant_path() {
    let dir = std::env::temp_dir().join(format!("nzbfast-wlinst-q-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let mock = MockServer::start_full(
        Default::default(),
        Default::default(),
        Vec::new(),
        Chaos::default(),
    )
    .await;
    let d = watching(
        &dir,
        &mock,
        r#"[{"id":1,"kind":"tv","title":"Wanted Show","seasons":"","episodes":"",
             "min_quality":"any","target_quality":"1080p","enabled":true,"upgrade":true}]"#,
    )
    .await;
    let port = d.port;
    mock.post_overview(release(
        SEEDED_MARK + 1,
        "Wanted.Show.S01E03.1080p.WEB.h264-GRP",
    ));
    let mock = std::sync::Arc::new(mock);
    let m2 = mock.clone();
    tokio::task::spawn_blocking(move || {
        wait_grabbed(port, "Wanted.Show.S01E03.1080p", 45)
            .unwrap_or_else(|| panic!("the 1080p arrival was never grabbed:\n{}", grabbed(port)));
        // A worse encode of the same episode arrives next.
        m2.post_overview(release(
            SEEDED_MARK + 10,
            "Wanted.Show.S01E03.720p.HDTV.x264-GRP",
        ));
        std::thread::sleep(std::time::Duration::from_secs(13));
        let seen = grabbed(port);
        assert!(
            !seen.contains("720p.HDTV"),
            "an arriving WORSE encode preempted the one already in hand - \
             the instant path is not going through the quality ladder:\n{seen}"
        );
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

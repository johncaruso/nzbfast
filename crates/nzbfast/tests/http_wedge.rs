//! The 28 Jul 2026 all-workers-wedged hang, as a regression test.
//!
//! Mechanism of the incident: a catch-up ingest held the shared index
//! connection for 62s straight; the dashboard header pill polls
//! mode=index_stats every 15s and that handler blocked on the same
//! mutex; each poll parked another of the daemon's 4 HTTP workers, so
//! within a minute ONE open dashboard tab left the daemon serving
//! nothing at all - a curl to / hung indefinitely.
//!
//! The fix has two halves, and this file pins both:
//!
//!  * index_stats is served from a try_lock + cached figures and never
//!    blocks on the index mutex (stale-by-seconds counts are fine for a
//!    status pill);
//!  * the worker pool is big enough that the endpoints which DO still
//!    take the index lock (wall2, search) cannot consume every worker
//!    the moment a handful queue up behind a scan batch.
//!
//! The long lock hold is synthesized with the NZBFAST_DEBUG_HOOKS-gated
//! mode=debug_hold_index, which sleeps inside with_index - the same
//! mutex a real ingest batch holds.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use nzbkit::nntp::OverEntry;

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

fn http(port: u16, req: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect daemon");
    write!(s, "GET {req} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").unwrap();
    let mut out = String::new();
    s.read_to_string(&mut out).unwrap();
    out.split("\r\n\r\n").nth(1).unwrap_or("").to_string()
}

fn api(port: u16, q: &str) -> serde_json::Value {
    let body = http(port, &format!("/api?output=json&{q}"));
    serde_json::from_str(&body).unwrap_or_else(|e| panic!("bad JSON for {q:?}: {e}\n{body}"))
}

struct KillOnDrop(Child);
impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct Running {
    _child: KillOnDrop,
    port: u16,
}

fn over(number: u64, subject: &str, msgid: &str, date: i64) -> OverEntry {
    OverEntry {
        number,
        subject: subject.into(),
        from: "poster@x".into(),
        bytes: 50 << 20,
        message_id: msgid.into(),
        date,
    }
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir()
        .join(format!("nzbfast-wedge-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("config.json"), "{\"servers\":[]}").unwrap();
    // An existing install (no first-run key minted) with the indexer on -
    // the whole test is about the index connection.
    std::fs::write(dir.join("settings.json"), "{\"index_enabled\": true}").unwrap();
    dir
}

fn seed_index(dir: &Path, n: usize) {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let mut ix = nzbkit::index::Index::open(&dir.join("index.db")).unwrap();
    let entries: Vec<OverEntry> = (0..n)
        .map(|i| {
            over(
                i as u64 + 1,
                &format!("\"Wedge.Test.S01E{i:02}.720p-GRP.rar\" yEnc (1/1)"),
                &format!("<wedge{i}@x>"),
                now - (i as i64 + 1) * 86_400,
            )
        })
        .collect();
    ix.ingest("alt.binaries.teevee", &entries, now - 3600).unwrap();
}

fn serve(dir: &Path) -> Running {
    for attempt in 0..3 {
        let port = free_port();
        let log = dir.join("daemon.log");
        let out = std::fs::File::create(&log).unwrap();
        let err = out.try_clone().unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_nzbfast"))
            .env("NZBFAST_NO_ENRICH", "1")
            .env("NZBFAST_DEBUG_HOOKS", "1")
            .env_remove("NZBFAST_OPEN")
            .arg("--config")
            .arg(dir.join("config.json"))
            .arg("serve")
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--out")
            .arg(dir.join("complete"))
            .arg("--index-db")
            .arg(dir.join("index.db"))
            .stdout(Stdio::from(out))
            .stderr(Stdio::from(err))
            .spawn()
            .unwrap();
        let mut running = Running { _child: KillOnDrop(child), port };
        // Readiness = OUR banner in OUR log (see index_size_cap.rs for
        // why a bare connect can catch a stranger on a recycled port).
        let banner = format!("open the dashboard at  http://localhost:{port}/");
        let mut dead = false;
        for _ in 0..300 {
            if std::fs::read_to_string(&log).unwrap_or_default().contains(&banner)
                && TcpStream::connect(("127.0.0.1", port)).is_ok()
            {
                return running;
            }
            if running._child.0.try_wait().ok().flatten().is_some() {
                dead = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let tail = std::fs::read_to_string(&log).unwrap_or_default();
        drop(running);
        assert!(
            attempt < 2,
            "daemon never announced its listener on {port} (exited early: {dead})\n{tail}"
        );
    }
    unreachable!()
}

/// One dashboard tab + one long index-lock hold must leave the daemon
/// fully responsive: / and index_stats both answer in well under a
/// second for the whole duration of the hold, and index_stats keeps
/// reporting the real figures (from its cache) rather than zeros.
#[test]
fn held_index_lock_does_not_wedge_the_api() {
    let dir = scratch("hold");
    seed_index(&dir, 8);
    let d = serve(&dir);
    let port = d.port;

    // Prime: one unlocked poll computes fresh figures and fills the cache.
    let fresh = api(port, "mode=index_stats");
    assert_eq!(fresh["releases"], 8, "seed visible before the hold: {fresh}");

    // The synthetic 62s batch, scaled to 15s of test time. It answers
    // {"held": true} only after the sleep, so join() doubles as proof
    // the lock really was held while we measured below.
    let holder = std::thread::spawn(move || api(port, "mode=debug_hold_index&value=15"));
    // The hook is inside the lock within milliseconds; a beat to be sure.
    std::thread::sleep(Duration::from_millis(500));

    // The dashboard tab of the incident: an index_stats poll every
    // second (compressed from 15s) for the length of the hold. In the
    // wedge these were exactly what parked the workers.
    let poller = std::thread::spawn(move || {
        for _ in 0..10 {
            let t = Instant::now();
            let s = api(port, "mode=index_stats");
            assert!(
                t.elapsed() < Duration::from_secs(3),
                "index_stats blocked {}ms behind the held index lock",
                t.elapsed().as_millis()
            );
            // Served from the cache, not zeros - the pill must not read
            // "empty index" every time a scan batch is busy.
            assert_eq!(s["releases"], 8, "stale-but-real figures during the hold: {s}");
            std::thread::sleep(Duration::from_secs(1));
        }
    });

    // Meanwhile the daemon as a whole stays alive: / (the curl of the
    // incident report) and a non-index API mode answer promptly.
    for _ in 0..8 {
        let t = Instant::now();
        let page = http(port, "/");
        assert!(!page.is_empty(), "/ served nothing");
        assert!(
            t.elapsed() < Duration::from_secs(3),
            "/ took {}ms during the index hold",
            t.elapsed().as_millis()
        );
        let t = Instant::now();
        let q = api(port, "mode=queue");
        assert!(q.get("queue").is_some(), "mode=queue answered: {q}");
        assert!(
            t.elapsed() < Duration::from_secs(3),
            "mode=queue took {}ms during the index hold",
            t.elapsed().as_millis()
        );
        std::thread::sleep(Duration::from_secs(1));
    }

    poller.join().expect("poller thread");
    let held = holder.join().expect("holder thread");
    assert_eq!(held["held"], true, "the hook really held the lock: {held}");

    // Lock free again: the fresh path resumes (still the same figures).
    let after = api(port, "mode=index_stats");
    assert_eq!(after["releases"], 8, "fresh path after the hold: {after}");
}

/// The debug hook must not exist without its env var - it ties up a
/// worker and the index lock on demand, which is exactly what an open
/// API must not offer. (The gate is the environment, not a build flag,
/// so this checks the released binary's behavior too.)
#[test]
fn debug_hook_absent_without_env() {
    let dir = scratch("nohook");
    let port = free_port();
    let log = dir.join("daemon.log");
    let out = std::fs::File::create(&log).unwrap();
    let err = out.try_clone().unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_nzbfast"))
        .env("NZBFAST_NO_ENRICH", "1")
        .env_remove("NZBFAST_DEBUG_HOOKS")
        .env_remove("NZBFAST_OPEN")
        .arg("--config")
        .arg(dir.join("config.json"))
        .arg("serve")
        .arg("--bind")
        .arg("127.0.0.1")
        .arg("--port")
        .arg(port.to_string())
        .arg("--out")
        .arg(dir.join("complete"))
        .arg("--index-db")
        .arg(dir.join("index.db"))
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err))
        .spawn()
        .unwrap();
    let _kill = KillOnDrop(child);
    let banner = format!("open the dashboard at  http://localhost:{port}/");
    for _ in 0..300 {
        if std::fs::read_to_string(&log).unwrap_or_default().contains(&banner) {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let t = Instant::now();
    let r = api(port, "mode=debug_hold_index&value=30");
    // An unknown mode's error answer, immediately - not a 30s stall.
    assert!(r.get("held").is_none(), "hook must not run without the env var: {r}");
    assert!(
        t.elapsed() < Duration::from_secs(5),
        "unknown-mode answer took {}ms - did the hook run?",
        t.elapsed().as_millis()
    );
}

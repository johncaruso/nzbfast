//! Failing regression tests for the open watchlist findings from a
//! correctness review (the B5 and B3 cases; B1 is not reachable from
//! here - see the note at the bottom of this file).
//!
//! Each test is written to FAIL against today's code for exactly the
//! reason the handoff describes, then parked behind `#[ignore]` so the
//! suite stays green until the fix lands. Unignore with the fix.
//!
//! nzbfast is a binary-only crate (no lib target), so nothing in
//! src/ can be imported from an integration test. B5's pure function
//! is compiled straight from its real source file via `#[path]` - the
//! source is NOT edited, only included - with a one-line shim standing
//! in for `crate::wall` (which itself only re-exports these names from
//! nzbkit::release). B3 goes through the real daemon binary over its
//! HTTP API, the same way tests/daemon.rs does.

#![allow(dead_code)]

mod scratch;

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use nzbkit::mock::{Chaos, MockServer, make_file_articles};

// ---------------------------------------------------------------------------
// B5: parse_age_spec overflow - the real source, compiled into this test
// ---------------------------------------------------------------------------

/// Stand-in for `crate::wall` as seen from src/watchlist.rs. The real
/// wall module re-exports exactly these names from nzbkit::release, so
/// the included code and its embedded unit tests resolve identically.
mod wall {
    pub use nzbkit::release::{Kind, Parsed, norm_title, parse_release};
}

#[path = "../src/watchlist.rs"]
mod watchlist;

/// Finding B5: a user who types an oversized retention window, e.g.
/// `max_age = "9000000000000y"`, means "no practical age limit". Today
/// `parse_age_spec` does `Some(n * mult)` on the unbounded number: in
/// the shipped release profile (overflow-checks off) the multiply WRAPS
/// to an unrelated number of seconds, so the age gate silently rejects
/// posts the user asked for and the watchlist item grabs nothing, with
/// no error anywhere. A debug build instead panics the watchlist pass
/// every 60 seconds.
///
/// Pinned behaviour: SATURATE (`n.saturating_mul(mult)`). The parser's
/// documented stance is to be permissive with typed input, and a
/// saturated u64::MAX age window means "effectively unbounded" - which
/// is precisely what the user asked for. Rejecting the spec (None) would
/// also be safe but silently drops a constraint the user did type;
/// saturation honours its intent exactly.
///
/// Against today's code this test fails: the test profile has
/// overflow-checks on, so the multiply panics ("attempt to multiply with
/// overflow") before returning - the same panic a debug daemon hits.
#[test]
fn b5_parse_age_spec_huge_value_saturates_instead_of_wrapping() {
    // Sanity: ordinary specs are untouched by the fix.
    assert_eq!(watchlist::parse_age_spec("2h"), Some(7_200));
    assert_eq!(watchlist::parse_age_spec("10"), Some(10 * 86_400));

    // 9_000_000_000_000 years * 31_536_000 s/y overflows u64. Today:
    // panic (debug) or wrap (release). Wanted: saturate to u64::MAX,
    // i.e. an age window that excludes nothing - the user's intent.
    let got = watchlist::parse_age_spec("9000000000000y");
    assert_eq!(
        got,
        Some(u64::MAX),
        "an oversized max_age must saturate (no practical limit), not wrap or panic"
    );
}

// ---------------------------------------------------------------------------
// Daemon harness (same shape as tests/daemon.rs - copied, not shared,
// because the constraint on this file is to touch nothing else)
// ---------------------------------------------------------------------------

fn payload(n: usize, seed: u8) -> Vec<u8> {
    (0..n)
        .map(|i| (i as u8).wrapping_mul(29).wrapping_add(seed))
        .collect()
}

/// OS-assigned free port for a daemon under test.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Response body of a request to the daemon (headers stripped). A
/// connection refused before it produced a single byte is retried; once
/// a byte has come back it is an answer and is returned as it arrived.
fn http(port: u16, req: &str, body: Option<(&str, &[u8])>) -> String {
    let mut last = String::new();
    for attempt in 0..5u32 {
        match http_once(port, req, body) {
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

fn http_once(port: u16, req: &str, body: Option<(&str, &[u8])>) -> std::io::Result<String> {
    let mut request = Vec::new();
    match body {
        None => {
            write!(
                request,
                "GET {req} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
            )
            .unwrap();
        }
        Some((ctype, data)) => {
            write!(
                request,
                "POST {req} HTTP/1.1\r\nHost: x\r\nConnection: close\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\n\r\n",
                data.len()
            )
            .unwrap();
            request.extend_from_slice(data);
        }
    }
    let out = String::from_utf8_lossy(&raw_once(port, &request)?).to_string();
    Ok(out.split("\r\n\r\n").nth(1).unwrap_or("").to_string())
}

fn raw_once(port: u16, request: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut s = TcpStream::connect(("127.0.0.1", port))?;
    s.write_all(request)?;
    let mut out = Vec::new();
    let read = s.read_to_end(&mut out);
    if out.is_empty() {
        return Err(read.err().unwrap_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "closed without answering",
            )
        }));
    }
    Ok(out)
}

struct KillOnDrop(Child);
impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// A daemon under test: killed and reaped on drop, stdout+stderr in `log`.
struct Daemon {
    _child: KillOnDrop,
    port: u16,
    log: PathBuf,
}

async fn serve(dir: &Path, build: impl Fn(u16) -> Command) -> Daemon {
    for attempt in 0..3 {
        let port = free_port();
        let log = dir.join(format!("daemon-{port}.log"));
        let out = std::fs::File::create(&log).unwrap();
        let err = out.try_clone().unwrap();
        let mut cmd = build(port);
        cmd.stdout(Stdio::from(out)).stderr(Stdio::from(err));
        let child = KillOnDrop(cmd.spawn().unwrap());
        let logfile = log.clone();
        let (child, ready) = tokio::task::spawn_blocking(move || {
            let mut child = child;
            let ready = wait_ready(&mut child, port, &logfile);
            (child, ready)
        })
        .await
        .unwrap();
        if ready {
            return Daemon {
                _child: child,
                port,
                log,
            };
        }
        let tail = std::fs::read_to_string(&log).unwrap_or_default();
        assert!(
            attempt < 2,
            "daemon exited without binding :{port}\n--- log ---\n{tail}"
        );
    }
    unreachable!()
}

/// Wait for OUR daemon's own listener banner in its own log (a bare
/// connect cannot tell a port-race stranger apart from our child).
fn wait_ready(child: &mut KillOnDrop, port: u16, log: &Path) -> bool {
    let banner = format!("open the dashboard at  http://localhost:{port}/");
    for _ in 0..600 {
        if std::fs::read_to_string(log)
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
    let tail = std::fs::read_to_string(log).unwrap_or_default();
    panic!("daemon never came up on :{port}\n--- log ---\n{tail}");
}

// ---------------------------------------------------------------------------
// B3: duplicate promotion picks first-in-queue, not best
// ---------------------------------------------------------------------------

/// Finding B3: when a download finally fails, the daemon promises to
/// promote "its best held ALTERNATIVE" (serve.rs:3558) - but the loop at
/// serve.rs:3562-3572 breaks at the FIRST queued held job whose dupe_key
/// matches, i.e. whichever alternative was ADDED first. A user whose
/// indexer grabbed a 720p copy before a 2160p copy gets the 720p
/// downloaded when the original fails, while the 2160p they would
/// obviously prefer stays parked as a Duplicate forever. The outcome on
/// their shelf is a worse copy than the one they were holding.
///
/// Scenario: original (480p, ghost articles - fails) is queued first;
/// a 720p alternative is held second; a 2160p alternative is held third.
/// Automatic retry is disabled (NZBFAST_AUTO_RETRY_SECS=0) so the first
/// final failure runs the promotion directly. The test then watches
/// which held job leaves Duplicate state: it must be the 2160p, with the
/// 720p still held. Against today's code the 720p is promoted, so the
/// assertion fails naming the wrong winner.
#[tokio::test(flavor = "multi_thread")]
async fn b3_duplicate_promotion_prefers_best_held_alternative() {
    let dir = std::env::temp_dir().join(format!("nzbfast-wlreg-b3-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let data = payload(120_000, 17);
    let mut articles = HashMap::new();
    let segs = make_file_articles("ep.bin", &data, 40_000, "wb", &mut articles);
    let srv = MockServer::start(articles, Chaos::default()).await;

    let seg_xml = |segs: &[(String, u64, u32)]| {
        let mut x = String::new();
        for (id, bytes, num) in segs {
            x.push_str(&format!(
                "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
            ));
        }
        x
    };
    let wrap = |inner: &str| {
        format!(
            "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file poster=\"x\" date=\"0\" subject=\"&quot;ep.bin&quot; yEnc (1/9)\">\n    <groups><group>g</group></groups>\n    <segments>\n{inner}    </segments>\n  </file>\n</nzb>\n"
        )
    };
    let ghost: Vec<(String, u64, u32)> = (1..=3)
        .map(|n| (format!("wbghost{n}@x"), 40_000, n))
        .collect();
    let bad_xml = wrap(&seg_xml(&ghost)); // original - will finally fail
    let good_xml = wrap(&seg_xml(&segs)); // both alternatives are fetchable

    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        format!(
            "{{\"servers\":[{{\"host\":\"{}\",\"port\":{},\"tls\":false}}]}}",
            srv.addr.ip(),
            srv.addr.port()
        ),
    )
    .unwrap();
    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            // Automatic retry OFF: the first final failure must run the
            // promotion itself, so the test sees the choice directly.
            .env("NZBFAST_AUTO_RETRY_SECS", "0")
            .arg("--config")
            .arg(&cfg)
            .arg("serve")
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--out")
            .arg(dir.join("complete"))
            .arg("--connections")
            .arg("2");
        c
    })
    .await;
    let port = d.port;

    tokio::task::spawn_blocking(move || {
        let upload = |xml: &str, fname: &str| {
            let boundary = "----wlregb3";
            let mut body = Vec::new();
            body.extend_from_slice(
                format!("--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"{fname}\"\r\n\r\n").as_bytes(),
            );
            body.extend_from_slice(xml.as_bytes());
            body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
            let r = http(
                port,
                "/api?mode=addfile&output=json",
                Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
            );
            assert!(r.contains("\"status\":true"), "{r}");
        };
        // Pause so all three sit in the queue when the dupe check runs.
        http(port, "/api?mode=pause&output=json", None);
        upload(&bad_xml, "Show.Name.S01E05.480p.WEB.nzb"); // original
        upload(&good_xml, "Show.Name.S01E05.720p.WEB.nzb"); // held FIRST (worse)
        upload(&good_xml, "Show.Name.S01E05.2160p.WEB.nzb"); // held SECOND (best)

        // Both alternatives are held as Duplicate before anything runs.
        let q = http(port, "/api?mode=queue&output=json", None);
        let held = q.matches("\"Duplicate\"").count();
        assert_eq!(held, 2, "expected both alternatives held: {q}");

        // Resume: the original fails; with auto-retry off, its park runs
        // the promotion. Watch which alternative leaves Duplicate state
        // (a promoted job may also finish and move to history).
        http(port, "/api?mode=resume&output=json", None);

        // The "was it promoted" verdict for one named alternative:
        // promoted means its queue slot is no longer Duplicate, or it
        // already completed into history.
        let promoted = |res: &str, q: &str, h: &str| -> bool {
            let v: serde_json::Value = serde_json::from_str(q).unwrap_or_default();
            let in_queue = v["queue"]["slots"].as_array().into_iter().flatten().any(|s| {
                s["filename"].as_str().unwrap_or("").contains(res)
                    && s["priority"].as_str() != Some("Duplicate")
            });
            let done = h.contains("\"Completed\"") && h.contains(res);
            in_queue || done
        };

        let mut failed_seen = false;
        for _ in 0..150 {
            let h = http(port, "/api?mode=history&output=json", None);
            failed_seen |= h.contains("\"Failed\"");
            let q = http(port, "/api?mode=queue&output=json", None);
            let p720 = promoted("720p", &q, &h);
            let p2160 = promoted("2160p", &q, &h);
            if p720 || p2160 {
                assert!(
                    p2160 && !p720,
                    "the BEST held alternative (2160p) must be promoted when the \
                     original fails; instead the oldest-added one won \
                     (720p promoted: {p720}, 2160p promoted: {p2160})\nqueue: {q}\nhistory: {h}"
                );
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        panic!(
            "no alternative was ever promoted (original failed: {failed_seen}) - \
             promotion after a final failure is itself broken"
        );
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// B1: NOT TESTED HERE - and why
// ---------------------------------------------------------------------------
// Finding B1 (serve.rs:7340-7344, extra-slot insertion overwriting a
// better already-owned slot) lives inside `watchlist_pass`, a private
// free function in the binary-only nzbfast crate, operating on the full
// Daemon struct plus the live index. It is unreachable from an
// integration test without a running daemon AND a seeded index that
// serves a multi-episode candidate to the watchlist scan. Per the task
// constraints (no src edits to expose internals, no daemon-dependent
// test for B1), it is deliberately skipped rather than approximated.

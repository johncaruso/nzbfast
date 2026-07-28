//! M14g gate: pool-level speed limiter - a capped download takes the wall
//! clock it must, the cap is visible in mode=queue, and mode=config lifts
//! it live without a restart.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Instant;

use nzbkit::mock::{Chaos, MockServer, make_file_articles};

fn payload(n: usize, seed: u8) -> Vec<u8> {
    (0..n).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed)).collect()
}

/// OS-assigned free port for a daemon under test. The old pid-derived
/// scheme (`BASE + pid % M`, mixed moduli) collided for whole pid windows
/// - e.g. pid ∈ [80000,81000) gave two tests the same port, killing
/// whichever daemon bound second - and could also land on the ephemeral
/// range the suites' own client sockets draw from.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

/// Response body of a request to the daemon (headers stripped).
///
/// A connection REFUSED before it produced a single byte is retried. That
/// is not the same as tolerating a bad answer: tiny_http's honest reply
/// when it cannot start a thread for a new connection is to drop the
/// socket unread, and with our request still in its receive buffer the
/// kernel turns that into an RST - which arrives here as ECONNRESET. A
/// full `cargo test` runs these suites in parallel, each test with a whole
/// daemon behind it, so `thread::Builder::spawn` really does hit EAGAIN,
/// and a test then failed on a refusal to serve rather than on anything it
/// asserts. Once a byte has come back it is an answer, and it is returned
/// (or fails) exactly as it arrived - a truncated response must never be
/// retried away.
fn http(port: u16, req: &str, body: Option<(&str, &[u8])>) -> String {
    let mut last = String::new();
    for attempt in 0..5u32 {
        match http_once(port, req, body) {
            Ok(out) => return out,
            Err(e) => {
                last = e.to_string();
                std::thread::sleep(std::time::Duration::from_millis(100 * u64::from(attempt) + 50));
            }
        }
    }
    panic!("daemon on :{port} never served {req}: {last}");
}

/// One attempt. Returns Err ONLY when the daemon produced nothing at all;
/// a partial or malformed response is data, and is handed back for the
/// caller's assertions to judge.
fn http_once(port: u16, req: &str, body: Option<(&str, &[u8])>) -> std::io::Result<String> {
    let mut request = Vec::new();
    match body {
        None => {
            write!(request, "GET {req} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n").unwrap();
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
    let mut s = TcpStream::connect(("127.0.0.1", port))?;
    s.write_all(&request)?;
    let mut out = String::new();
    // Zero bytes back is a refusal to serve, however the peer
    // phrased it: an RST (Err) when our request was never read off
    // the receive buffer, a plain FIN (Ok) when it was read and then
    // dropped unanswered. Neither carries anything to judge, so both
    // are retried. The moment ANY byte arrives it is an answer and is
    // returned exactly as it came - errors included - because a
    // truncated body must never be retried away.
    let read = s.read_to_string(&mut out);
    if out.is_empty() {
        return Err(read.err().unwrap_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "closed without answering",
            )
        }));
    }
    Ok(out.split("\r\n\r\n").nth(1).unwrap_or("").to_string())
}

fn nzb_xml(name: &str, segs: &[(String, u64, u32)]) -> String {
    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
    );
    xml.push_str(&format!(
        "  <file poster=\"x\" date=\"0\" subject=\"&quot;{name}&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
        segs.len()
    ));
    for (id, bytes, num) in segs {
        xml.push_str(&format!(
            "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
        ));
    }
    xml.push_str("    </segments>\n  </file>\n</nzb>\n");
    xml
}

fn addfile(port: u16, fname: &str, xml: &str) -> String {
    let boundary = "----throttleb";
    let mut body = Vec::new();
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"{fname}\"\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(xml.as_bytes());
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    http(
        port,
        "/api?mode=addfile&output=json",
        Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
    )
}

/// Poll history until it holds `n` Completed entries; returns the elapsed
/// time since call start, or panics after the budget. (Counting, not name
/// matching - every nzo_id contains the substring "fast".)
fn wait_n_completed(port: u16, n: usize, budget_ms: u64) -> std::time::Duration {
    let t0 = Instant::now();
    while t0.elapsed().as_millis() < budget_ms as u128 {
        let h = http(port, "/api?mode=history&output=json", None);
        if h.matches("\"Completed\"").count() >= n {
            return t0.elapsed();
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    panic!("history never reached {n} Completed within {budget_ms} ms");
}

struct KillOnDrop(Child);
impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        // ...and reap it. kill() alone leaves a zombie holding its pid for
        // the rest of the binary's run.
        let _ = self.0.wait();
    }
}

/// A daemon under test: killed and reaped on drop.
struct Daemon {
    _child: KillOnDrop,
    port: u16,
}

/// Launch a daemon under `dir` and return once OUR daemon is serving.
///
/// `build` is handed the port to serve on and returns the fully
/// configured command; it may be called again on a fresh port, so it must
/// not consume anything.
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
        // The readiness wait blocks; keep it off the runtime's workers,
        // where this test's own mock server is running.
        let (child, ready) = tokio::task::spawn_blocking(move || {
            let mut child = child;
            let ready = wait_ready(&mut child, port, &log);
            (child, ready)
        })
        .await
        .unwrap();
        if ready {
            return Daemon { _child: child, port };
        }
        // The daemon exited instead of binding: `free_port()` handed :port
        // to a parallel test between our bind(:0) and the daemon's bind,
        // and that test's daemon won it. Try a fresh port.
        let tail = std::fs::read_to_string(&logfile).unwrap_or_default();
        assert!(attempt < 2, "daemon exited without binding :{port}\n--- log ---\n{tail}");
    }
    unreachable!()
}

/// Wait for OUR daemon's own listener banner, not for "something answers
/// on :port". A bare connect cannot tell the two apart, and under a full
/// parallel run they diverge: `free_port()` can hand :port to a second
/// test between our bind(:0) and our daemon's bind, that test's daemon
/// wins the port, ours exits, and a plain connect then succeeds against
/// the OTHER daemon. The test would run against a stranger and, when that
/// stranger's owner finished and killed it, fail mid-request with
/// ConnectionReset. The banner is read from this daemon's own log, so it
/// can only be ours, and it is printed immediately after the bind returns.
///
/// False means the child exited first (the port race above); a genuine
/// hang panics with the log.
fn wait_ready(child: &mut KillOnDrop, port: u16, logfile: &Path) -> bool {
    let banner = format!("open the dashboard at  http://localhost:{port}/");
    for _ in 0..600 {
        if std::fs::read_to_string(logfile).unwrap_or_default().contains(&banner)
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

#[tokio::test(flavor = "multi_thread")]
async fn speedlimit_paces_and_lifts_live() {
    let dir = std::env::temp_dir().join(format!("nzbfast-throttle-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    // Two ~2 MB posts on one mock server.
    let slow_data = payload(2_000_000, 5);
    let fast_data = payload(2_000_000, 9);
    let mut articles = HashMap::new();
    let slow_segs = make_file_articles("slow.bin", &slow_data, 100_000, "sl", &mut articles);
    let fast_segs = make_file_articles("fast.bin", &fast_data, 100_000, "fa", &mut articles);
    let srv = MockServer::start(articles, Chaos::default()).await;

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
        // The daemon mints an API key on a genuinely first run (see
        // serve::first_run_apikey). These suites drive it keyless on purpose,
        // so they take the same deliberate opt-out an operator would.
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            .arg("--config")
            .arg(&cfg)
            .arg("serve")
            // Loopback only. These suites never need LAN reach, and binding
            // 0.0.0.0 makes the macOS firewall raise a prompt for every freshly
            // built test binary, which is a new path on every run.
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--out")
            .arg(dir.join("complete"))
            .arg("--connections")
            .arg("2")
            .arg("--speedlimit")
            .arg("500K");
        c
    })
    .await;
    let port = d.port;

    let slow_xml = nzb_xml("slow.bin", &slow_segs);
    let fast_xml = nzb_xml("fast.bin", &fast_segs);
    let dir2 = dir.clone();
    tokio::task::spawn_blocking(move || {
        // The CLI-set cap is visible before anything downloads.
        let q = http(port, "/api?mode=queue&output=json", None);
        assert!(q.contains("\"speedlimit_abs\":500000"), "{q}");

        // ~2 MB (≈2.05 MB raw yEnc actually charged) at 500 KB/s must take
        // ≥ 4 s of reading - assert a generous ≥ 3 s lower bound only.
        let r = addfile(port, "slow.nzb", &slow_xml);
        assert!(r.contains("\"status\":true"), "{r}");
        let took = wait_n_completed(port, 1, 60_000);
        assert!(
            took >= std::time::Duration::from_secs(3),
            "throttled download finished suspiciously fast: {took:?}"
        );
        assert_eq!(
            std::fs::read(dir2.join("complete/slow/slow.bin")).unwrap(),
            payload(2_000_000, 5),
            "throttled payload corrupt"
        );

        // Lift the cap live via the SAB-shaped config endpoint.
        let r = http(
            port,
            "/api?mode=config&name=speedlimit&value=0&output=json",
            None,
        );
        assert!(r.contains("\"status\":true"), "{r}");
        let q = http(port, "/api?mode=queue&output=json", None);
        assert!(q.contains("\"speedlimit_abs\":0"), "{q}");

        // Bad values are rejected without touching the cap.
        let r = http(
            port,
            "/api?mode=config&name=speedlimit&value=junk&output=json",
            None,
        );
        assert!(r.contains("\"status\":false"), "{r}");
        let q = http(port, "/api?mode=queue&output=json", None);
        assert!(q.contains("\"speedlimit_abs\":0"), "{q}");

        // Uncapped, the same-sized post completes fast (loose bound - this
        // took ≥ 4 s while capped).
        let r = addfile(port, "fast.nzb", &fast_xml);
        assert!(r.contains("\"status\":true"), "{r}");
        let took = wait_n_completed(port, 2, 30_000);
        assert!(
            took < std::time::Duration::from_secs(3),
            "uncapped download still slow: {took:?}"
        );
        assert_eq!(
            std::fs::read(dir2.join("complete/fast/fast.bin")).unwrap(),
            payload(2_000_000, 9),
            "uncapped payload corrupt"
        );
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// M14g3 smoke: with the governor on (localhost RTT ≈ base, so it only
/// ever climbs), downloads complete untouched, the toggle round-trips
/// via the API, and turning it off restores the ceiling.
#[tokio::test(flavor = "multi_thread")]
async fn auto_speed_governor_smoke() {
    let dir = std::env::temp_dir().join(format!("nzbfast-autospeed-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let data = payload(1_000_000, 17);
    let mut articles = HashMap::new();
    let segs = make_file_articles("as.bin", &data, 100_000, "as", &mut articles);
    let srv = MockServer::start(articles, Chaos::default()).await;
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
            .arg("--config")
            .arg(&cfg)
            .arg("serve")
            // Loopback only. These suites never need LAN reach, and binding
            // 0.0.0.0 makes the macOS firewall raise a prompt for every freshly
            // built test binary, which is a new path on every run.
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--out")
            .arg(dir.join("complete"))
            .arg("--connections")
            .arg("2")
            .arg("--auto-speed");
        c
    })
    .await;
    let port = d.port;

    let dir2 = dir.clone();
    tokio::task::spawn_blocking(move || {
        let q = http(port, "/api?mode=queue&output=json", None);
        assert!(q.contains("\"auto_speed\":true"), "{q}");

        addfile(port, "as.nzb", &nzb_xml("as.bin", &segs));
        wait_n_completed(port, 1, 30_000);
        assert_eq!(
            std::fs::read(dir2.join("complete/as/as.bin")).unwrap(),
            data
        );

        // Toggle off: rate returns to the (unlimited) ceiling.
        let r = http(port, "/api?mode=config&name=auto_speed&value=0&output=json", None);
        assert!(r.contains("\"status\":true"), "{r}");
        let q = http(port, "/api?mode=queue&output=json", None);
        assert!(q.contains("\"auto_speed\":false"), "{q}");
        assert!(q.contains("\"speedlimit_abs\":0"), "{q}");
        // And back on.
        let r = http(port, "/api?mode=config&name=auto_speed&value=1&output=json", None);
        assert!(r.contains("\"status\":true"), "{r}");
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

//! Daemon API test (M5 gate): a Sonarr-style cycle - version probe,
//! addfile upload, queue polling, history with final storage path - all
//! against the real binary + mock NNTP servers.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use nzbkit::mock::{Chaos, MockServer, make_file_articles};

fn payload(n: usize, seed: u8) -> Vec<u8> {
    (0..n).map(|i| (i as u8).wrapping_mul(29).wrapping_add(seed)).collect()
}

/// OS-assigned free port for a daemon under test. The old pid-derived
/// scheme (`BASE + pid % M`, mixed moduli) collided for whole pid windows
/// - e.g. pid ∈ [80000,81000) gave two tests the same port, killing
/// whichever daemon bound second - and could also land on the ephemeral
/// range the suites' own client sockets draw from.
fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Response body of a request to the daemon (headers stripped).
///
/// A connection REFUSED before it produced a single byte is retried. That
/// is not the same as tolerating a bad answer: tiny_http's honest reply
/// when it cannot start a thread for a new connection is to drop the
/// socket unread, and with our request still in its receive buffer the
/// kernel turns that into an RST - which arrives here as ECONNRESET. This
/// suite runs 24 tests in parallel, each with a full daemon behind it, so
/// `thread::Builder::spawn` really does hit EAGAIN, and a test then failed
/// on a refusal to serve rather than on anything it asserts. Once a byte
/// has come back it is an answer, and it is returned (or fails) exactly as
/// it arrived - a truncated response must never be retried away.
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
    let out = String::from_utf8_lossy(&raw_once(port, &request)?).to_string();
    Ok(out.split("\r\n\r\n").nth(1).unwrap_or("").to_string())
}

/// A hand-written request whose response headers are KEPT - /stream,
/// /m3u, /watch and JSON-RPC, where the test reads the status line or a
/// binary body itself. Refusals are retried on the same terms as `http`.
fn raw(port: u16, request: &[u8]) -> Vec<u8> {
    let mut last = String::new();
    for attempt in 0..5u32 {
        match raw_once(port, request) {
            Ok(out) => return out,
            Err(e) => {
                last = e.to_string();
                std::thread::sleep(std::time::Duration::from_millis(100 * u64::from(attempt) + 50));
            }
        }
    }
    let line = String::from_utf8_lossy(request).lines().next().unwrap_or("").to_string();
    panic!("daemon on :{port} never answered {line:?}: {last}");
}

fn raw_once(port: u16, request: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut s = TcpStream::connect(("127.0.0.1", port))?;
    s.write_all(request)?;
    let mut out = Vec::new();
    // Zero bytes back is a refusal to serve, however the peer
    // phrased it: an RST (Err) when our request was never read off
    // the receive buffer, a plain FIN (Ok) when it was read and then
    // dropped unanswered. Neither carries anything to judge, so both
    // are retried. The moment ANY byte arrives it is an answer and is
    // returned exactly as it came - errors included - because a
    // truncated body must never be retried away.
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
        // ...and reap it. kill() alone leaves a zombie holding its pid
        // for the rest of the binary's run, and this suite starts two
        // dozen daemons.
        let _ = self.0.wait();
    }
}

/// A daemon under test: killed and reaped on drop, with its stdout and
/// stderr captured to `log` so the test can read what it printed.
struct Daemon {
    _child: KillOnDrop,
    port: u16,
    log: PathBuf,
}

/// Launch a daemon under `dir` and return once OUR daemon is serving.
///
/// `build` is handed the port to serve on and returns the fully
/// configured command; it may be called again on a fresh port, so it must
/// not consume anything.
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
        // The readiness wait blocks; keep it off the runtime's workers,
        // where this test's own mock server is running.
        let (child, ready) = tokio::task::spawn_blocking(move || {
            let mut child = child;
            let ready = wait_ready(&mut child, port, &logfile);
            (child, ready)
        })
        .await
        .unwrap();
        if ready {
            return Daemon { _child: child, port, log };
        }
        // The daemon exited instead of binding: `free_port()` handed
        // :port to a parallel test between our bind(:0) and the daemon's
        // bind, and that test's daemon won it. Try a fresh port.
        let tail = std::fs::read_to_string(&log).unwrap_or_default();
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
fn wait_ready(child: &mut KillOnDrop, port: u16, log: &Path) -> bool {
    let banner = format!("open the dashboard at  http://localhost:{port}/");
    for _ in 0..600 {
        if std::fs::read_to_string(log).unwrap_or_default().contains(&banner)
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

/// Seed the settings.json beside `cfg` so the daemon this test spawns
/// deletes permanently instead of moving to the Trash.
///
/// `smart::TRASH` defaults ON everywhere except a `cfg(test)` build, and
/// these suites drive the REAL binary: the child is a normal build, so the
/// default it picks up is the user-facing one. Every fixture its cleanup
/// sweeps or its watch poller delete therefore landed in the DEVELOPER's
/// own ~/.Trash, once per `cargo test` run, with nothing to tell them
/// apart from files they deleted themselves.
///
/// settings.json is the only lever that reaches the child - there is no
/// flag for this - and the daemon applies the key on startup (see serve's
/// `delete_to_trash` arm). Call it after writing the config and before
/// `serve`, for any daemon that will delete a fixture. Merges rather than
/// overwrites, so a test that seeds settings of its own keeps them.
///
/// The file existing at all is itself a signal the daemon reads: a
/// settings.json carrying anything but the wizard's own answers means
/// "existing install" (serve::settings_beyond_setup_answers), which flips
/// the two rename-punctuation defaults to the pre-upgrade shape. So on a
/// first run - no spool beside the config yet - the fresh-install values
/// are pinned back explicitly, and this helper changes exactly the one
/// behaviour it is for. A second launch against the same directory has a
/// spool, so the daemon reaches the same verdict with or without us.
fn delete_without_the_trash(cfg: &Path) {
    let path = cfg.with_file_name("settings.json");
    let mut saved = std::fs::read(&path)
        .ok()
        .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
        .and_then(|v| match v {
            serde_json::Value::Object(m) => Some(m),
            _ => None,
        })
        .unwrap_or_default();
    saved.insert("delete_to_trash".to_string(), serde_json::Value::Bool(false));
    if !cfg.with_file_name(".spool").exists() {
        for key in ["rename_year_parens", "rename_quality_brackets"] {
            saved.entry(key).or_insert(serde_json::Value::Bool(false));
        }
    }
    std::fs::write(&path, serde_json::Value::Object(saved).to_string()).unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn sonarr_style_cycle() {
    let dir = std::env::temp_dir().join(format!("nzbfast-daemon-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    // Content on the mock server.
    let data = payload(400_000, 3);
    let mut articles = HashMap::new();
    let segs = make_file_articles("episode.bin", &data, 40_000, "ep", &mut articles);
    let srv = MockServer::start(articles, Chaos::default()).await;

    // NZB to upload.
    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file poster=\"x\" date=\"0\" subject=\"&quot;episode.bin&quot; yEnc (1/11)\">\n    <groups><group>g</group></groups>\n    <segments>\n",
    );
    for (id, bytes, num) in &segs {
        xml.push_str(&format!(
            "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
        ));
    }
    xml.push_str("    </segments>\n  </file>\n</nzb>\n");

    // Daemon config + launch.
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
    // Post-proc hook (M14d): records SAB-contract args + env for assert.
    //
    // Written in the host's own script language, because `run_script` spawns
    // the file directly and a `#!/bin/sh` shebang means nothing on Windows -
    // there is no /bin/sh to honour it, so the hook simply never ran and this
    // suite reported "hook never ran" the first time it was run there. Rust
    // CAN spawn a .cmd (std applies cmd.exe's own argument escaping to
    // .bat/.cmd since the BatBadBut fix), so the Windows leg exercises the
    // real post-processing contract rather than skipping it.
    #[cfg(unix)]
    let hook = {
        let hook = dir.join("hook.sh");
        std::fs::write(
            &hook,
            "#!/bin/sh\nprintf 'args:%s|%s|%s|%s\\nenv:%s|%s|%s\\n' \"$1\" \"$3\" \"$5\" \"$7\" \"$SAB_PP_STATUS\" \"$SAB_FINAL_NAME\" \"$SAB_CAT\" > \"$(dirname \"$0\")/hook.out\"\n",
        )
        .unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();
        hook
    };
    #[cfg(windows)]
    let hook = {
        let hook = dir.join("hook.cmd");
        // `%~dp0` carries its own trailing separator. `|` is a pipe to cmd
        // even inside a parenthesised block, hence `^|`, and `%~1` strips the
        // quotes Windows leaves around a path argument containing spaces.
        std::fs::write(
            &hook,
            "@echo off\r\n> \"%~dp0hook.out\" (\r\n\
             echo args:%~1^|%~3^|%~5^|%~7\r\n\
             echo env:%SAB_PP_STATUS%^|%SAB_FINAL_NAME%^|%SAB_CAT%\r\n\
             )\r\n",
        )
        .unwrap();
        hook
    };
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
            .arg("--apikey")
            .arg("sekrit")
            .arg("--out")
            .arg(dir.join("complete"))
            .arg("--script")
            .arg(&hook)
            .arg("--connections")
            .arg("3");
        c
    })
    .await;
    let port = d.port;

    let dir2 = dir.clone();
    tokio::task::spawn_blocking(move || {
        // Bad API key rejected.
        let r = http(port, "/api?mode=version&apikey=wrong&output=json", None);
        assert!(r.contains("API Key Incorrect"), "{r}");
        // Version probe (Sonarr's connection test).
        let r = http(port, "/api?mode=version&apikey=sekrit&output=json", None);
        assert!(r.contains("version"), "{r}");
        // SAB-compat: browser addons (NZBDonkey, NZB Unity) send mode and
        // apikey as POST form fields with an EMPTY query string. Both form
        // encodings must authenticate - these used to log "[auth] rejected
        // key for api" because only the query string was parsed.
        let r = http(
            port,
            "/api",
            Some((
                "application/x-www-form-urlencoded",
                b"mode=version&apikey=sekrit&output=json".as_slice(),
            )),
        );
        assert!(r.contains("version"), "urlencoded form auth failed: {r}");
        let fb = "----fieldsboundary";
        let mut fbody = Vec::new();
        for (n, v) in [("mode", "queue"), ("apikey", "sekrit"), ("output", "json")] {
            fbody.extend_from_slice(
                format!(
                    "--{fb}\r\nContent-Disposition: form-data; name=\"{n}\"\r\n\r\n{v}\r\n"
                )
                .as_bytes(),
            );
        }
        fbody.extend_from_slice(format!("--{fb}--\r\n").as_bytes());
        let fctype = format!("multipart/form-data; boundary={fb}");
        let r = http(port, "/api", Some((&fctype, &fbody)));
        assert!(!r.contains("API Key"), "multipart form auth failed: {r}");
        assert!(r.contains("queue"), "multipart form mode ignored: {r}");
        // The query still wins on conflict: a wrong key in the body must
        // not override a valid one in the query.
        let r = http(
            port,
            "/api?mode=version&apikey=sekrit&output=json",
            Some((
                "application/x-www-form-urlencoded",
                b"apikey=wrong".as_slice(),
            )),
        );
        assert!(r.contains("version"), "query key must win: {r}");
        let r = http(port, "/api?mode=get_config&apikey=sekrit&output=json", None);
        assert!(r.contains("complete_dir"), "{r}");

        // addfile (multipart, category tv).
        let boundary = "----nzbfastboundary";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"episode.nzb\"\r\nContent-Type: application/x-nzb\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(xml.as_bytes());
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let ctype = format!("multipart/form-data; boundary={boundary}");
        let r = http(
            port,
            "/api?mode=addfile&apikey=sekrit&cat=tv&output=json",
            Some((&ctype, &body)),
        );
        assert!(r.contains("nzo_ids"), "{r}");
        assert!(r.contains("\"status\":true"), "{r}");

        // Poll until it lands in history as Completed.
        let mut done = false;
        for _ in 0..100 {
            let h = http(port, "/api?mode=history&apikey=sekrit&output=json", None);
            if h.contains("\"Completed\"") {
                assert!(h.contains("episode"), "{h}");
                done = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        assert!(done, "download never completed");

        // Payload extracted to the category dir, byte-identical.
        let out = dir2.join("complete/tv/episode/episode.bin");
        assert!(out.exists(), "output missing at {}", out.display());

        // Post-proc hook ran with the SAB contract (async - poll briefly).
        //
        // Poll for the CONTENT, not for the file. The hook redirects with
        // `> hook.out`, and the shell creates/truncates that file before
        // printf writes a byte into it - so `exists()` goes true while the
        // file is still empty. On a loaded machine (every test binary in
        // parallel) the scheduler fits the whole poll into that window and
        // the read returns "", which is the §16i flake: it failed on the
        // first assert with an empty record, never on "hook never ran".
        // `env:` is the second of the two printf lines, so seeing it means
        // the write finished.
        let hook_out = dir2.join("hook.out");
        let mut rec = String::new();
        for _ in 0..50 {
            rec = std::fs::read_to_string(&hook_out).unwrap_or_default();
            if rec.contains("env:") {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        assert!(!rec.is_empty(), "hook never ran");
        assert!(rec.contains("|episode|tv|0"), "{rec}"); // clean name, cat, pp=OK
        assert!(rec.contains("env:0|episode|tv"), "{rec}");
        // $1 final dir, separator-normalised: the daemon hands the script a
        // NATIVE path, so this is "complete\\tv\\episode" on Windows.
        assert!(rec.replace('\\', "/").contains("complete/tv/episode"), "{rec}");
    })
    .await
    .unwrap();
    assert_eq!(
        std::fs::read(dir.join("complete/tv/episode/episode.bin")).unwrap(),
        data
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Live repro 2026-07-20 (Seinfeld S08E05, 12,109 segments): a plain
/// single-file NZB with SYNTHESIZED segment numbering - the NZB's
/// "segment 1" is not the yEnc offset-0 article; the real offset-0 sits
/// arbitrarily deep in the queue (here: dead last). Pre-fix, every
/// decoded span piled into unclassified-slot holds for the whole run:
/// no data file on disk, stats files[] empty, nothing journaled. The
/// per-slot spill must flip the slot Plain mid-download, so the file
/// appears on disk long before the last article, and the job completes
/// byte-identical.
#[tokio::test(flavor = "multi_thread")]
async fn scrambled_segment_numbering_single_file() {
    let dir = std::env::temp_dir().join(format!("nzbfast-scramble-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    // 12 MB plain file; --mem-limit 64M puts the per-slot spill budget at
    // ~7.2 MB (holds_cap 28.8 MB / 4), so the scramble trips it mid-run.
    let data = payload(12_000_000, 6);
    let mut articles = HashMap::new();
    let segs = make_file_articles("video.bin", &data, 40_000, "sc", &mut articles);
    let total_arts = segs.len();
    // Slow the mock slightly so the download is long enough to observe.
    let srv = MockServer::start(
        articles,
        Chaos {
            delay_ms: 5,
            ..Chaos::default()
        },
    )
    .await;

    // Synthesized numbering: NZB order is scrambled, part 1 (the yEnc
    // offset-0 article) goes LAST, and the <segment number=> attributes
    // are renumbered 1..N in the new order - numbering and subject lie,
    // exactly like the live post (obfuscated subject: no filename hint).
    let mut order: Vec<usize> = (1..total_arts).collect();
    let mut state = 0x5eed_u64;
    for i in (1..order.len()).rev() {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        order.swap(i, (state >> 33) as usize % (i + 1));
    }
    order.push(0); // offset-0 article dead last
    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file poster=\"x\" date=\"0\" subject=\"29a1f0b3c4d5e6f7 [1/1] yEnc\">\n    <groups><group>g</group></groups>\n    <segments>\n",
    );
    for (pos, &si) in order.iter().enumerate() {
        let (id, bytes, _) = &segs[si];
        xml.push_str(&format!(
            "      <segment bytes=\"{bytes}\" number=\"{}\">{id}</segment>\n",
            pos + 1
        ));
    }
    xml.push_str("    </segments>\n  </file>\n</nzb>\n");

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
            .arg("--mem-limit")
            .arg("64M")
            .arg("serve")
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--apikey")
            .arg("sekrit")
            .arg("--out")
            .arg(dir.join("complete"))
            .arg("--connections")
            .arg("3");
        c
    })
    .await;
    let port = d.port;

    let served = srv.served.clone();
    let body_log = srv.body_log.clone();
    let out_root = dir.join("complete");
    let find_video = move |root: &std::path::Path| -> Option<std::path::PathBuf> {
        fn walk(d: &std::path::Path, out: &mut Option<std::path::PathBuf>) {
            let Ok(rd) = std::fs::read_dir(d) else { return };
            for e in rd.flatten() {
                let p = e.path();
                if p.is_dir() {
                    walk(&p, out);
                } else if p.file_name().is_some_and(|n| n == "video.bin") {
                    *out = Some(p);
                }
            }
        }
        let mut found = None;
        walk(root, &mut found);
        found
    };

    tokio::task::spawn_blocking(move || {
        let boundary = "----nzbfastboundary";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"scrambled.nzb\"\r\nContent-Type: application/x-nzb\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(xml.as_bytes());
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let ctype = format!("multipart/form-data; boundary={boundary}");
        let r = http(
            port,
            "/api?mode=addfile&apikey=sekrit&output=json",
            Some((&ctype, &body)),
        );
        assert!(r.contains("\"status\":true"), "{r}");

        // THE regression assertion: the data file must hit the disk while
        // the download is still fetching (spill fired), not only at the
        // end-of-run settle. Record how many articles the mock had served
        // when the file first appeared.
        let mut served_at_file: Option<u64> = None;
        let mut done = false;
        for _ in 0..1200 {
            if served_at_file.is_none() && find_video(&out_root).is_some() {
                served_at_file = Some(served.load(std::sync::atomic::Ordering::Relaxed));
            }
            let h = http(port, "/api?mode=history&apikey=sekrit&output=json", None);
            if h.contains("\"Completed\"") {
                done = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        assert!(done, "download never completed");
        let at = served_at_file.expect("video.bin never appeared on disk");
        assert!(
            at + 10 < total_arts as u64,
            "file only appeared at settle ({at}/{total_arts} articles served) - \
             the unclassified slot never spilled"
        );

        // Scramble sanity: the offset-0 article really was fetched late -
        // otherwise this test isn't reproducing synthesized numbering.
        let log = body_log.lock().unwrap();
        let pos = log
            .iter()
            .position(|id| id == "<sc-1@mock>")
            .expect("offset-0 article never fetched");
        assert!(
            pos > log.len() / 2,
            "offset-0 article fetched at {pos}/{} - scramble ineffective",
            log.len()
        );

        let out = find_video(&out_root).expect("output file vanished after completion");
        out
    })
    .await
    .map(|out| assert_eq!(std::fs::read(&out).unwrap(), data, "output not byte-identical"))
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// M14a/b: the extended SABnzbd facade - two-tier keys, priorities
/// (incl. Force-runs-while-paused and add-paused), park-to-history,
/// retry, failed_only, pagination, del_files.
#[tokio::test(flavor = "multi_thread")]
async fn sab_facade_priorities_and_retry() {
    let dir = std::env::temp_dir().join(format!("nzbfast-facade-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let data = payload(200_000, 5);
    let mut articles = HashMap::new();
    let segs = make_file_articles("good.bin", &data, 40_000, "gd", &mut articles);
    let srv = MockServer::start(articles, Chaos::default()).await;

    let nzb_for = |name: &str, segs: &[(String, u64, u32)]| {
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
    };
    let good_xml = nzb_for("good.bin", &segs);
    // Articles that don't exist on the server → the job must fail and park.
    let ghost_segs: Vec<(String, u64, u32)> =
        (1..=3).map(|n| (format!("ghost{n}@x"), 40_000, n)).collect();
    let bad_xml = nzb_for("bad.bin", &ghost_segs);

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
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--apikey")
            .arg("sekrit")
            .arg("--nzbkey")
            .arg("addonly")
            .arg("--out")
            .arg(dir.join("complete"))
            .arg("--connections")
            .arg("2");
        c
    })
    .await;
    let port = d.port;

    let dir2 = dir.clone();
    tokio::task::spawn_blocking(move || {
        let upload = |xml: &str, extra: &str| -> String {
            let boundary = "----facadeb";
            let mut body = Vec::new();
            body.extend_from_slice(
                format!("--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"j.nzb\"\r\n\r\n").as_bytes(),
            );
            body.extend_from_slice(xml.as_bytes());
            body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
            let r = http(
                port,
                &format!("/api?mode=addfile&output=json{extra}"),
                Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
            );
            assert!(r.contains("\"status\":true"), "{r}");
            r.split("SABnzbd_nzo_").nth(1).unwrap().split('"').next()
                .map(|s| format!("SABnzbd_nzo_{s}")).unwrap()
        };
        let poll_history = |pred: &dyn Fn(&str) -> bool, what: &str| {
            for _ in 0..150 {
                let h = http(port, "/api?mode=history&apikey=sekrit&output=json", None);
                if pred(&h) {
                    return h;
                }
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
            panic!("timed out waiting for {what}");
        };

        // Two-tier keys: the NZB key may add but not read.
        let r = http(port, "/api?mode=queue&apikey=addonly&output=json", None);
        assert!(r.contains("API Key Incorrect"), "{r}");
        let r = http(port, "/api?mode=get_cats&apikey=sekrit&output=json", None);
        assert!(r.contains("\"tv\""), "{r}");

        // Pause the whole queue, then add: bad (normal prio, via NZB key),
        // good (Force via priority change) - Force must run while paused.
        http(port, "/api?mode=pause&apikey=sekrit&output=json", None);
        let bad_id = upload(&bad_xml, "&apikey=addonly");
        let good_id = upload(&good_xml, "&apikey=sekrit&cat=tv");
        let r = http(
            port,
            &format!("/api?mode=queue&name=priority&value={good_id}&value2=2&apikey=sekrit&output=json"),
            None,
        );
        assert!(r.contains("\"status\":true"), "{r}");
        let h = poll_history(&|h: &str| h.contains("Completed"), "force job while paused");
        assert!(h.contains(&good_id), "{h}");
        // The bad job must still be queued: the queue is paused.
        let q = http(port, "/api?mode=queue&apikey=sekrit&output=json", None);
        assert!(q.contains(&bad_id), "{q}");
        assert!(q.contains("\"priority\":\"Normal\""), "{q}");

        // Resume: the bad job runs, fails, parks in history.
        http(port, "/api?mode=resume&apikey=sekrit&output=json", None);
        let h = poll_history(&|h: &str| h.contains("Failed"), "bad job to fail");
        assert!(h.contains(&bad_id), "{h}");

        // failed_only filters the completed one out.
        let h = http(port, "/api?mode=history&failed_only=1&apikey=sekrit&output=json", None);
        assert!(h.contains(&bad_id) && !h.contains(&good_id), "{h}");
        // Pagination: limit=1 returns one slot but reports both.
        let h = http(port, "/api?mode=history&start=0&limit=1&apikey=sekrit&output=json", None);
        assert!(h.contains("\"noofslots\":2"), "{h}");
        assert_eq!(h.matches("nzo_id").count(), 1, "{h}");

        // Retry sends it back through the queue; it fails again and the
        // history entry now records the attempt.
        let r = http(
            port,
            &format!("/api?mode=retry&value={bad_id}&apikey=sekrit&output=json"),
            None,
        );
        assert!(r.contains("\"status\":true"), "{r}");
        let h = poll_history(
            &|h: &str| h.contains("\"retry\":1") && h.contains("Failed"),
            "retried job to fail again",
        );
        assert!(h.contains(&bad_id), "{h}");

        // add-paused (priority -2) holds the job until per-job resume.
        let paused_id = upload(&good_xml, "&apikey=sekrit&priority=-2");
        std::thread::sleep(std::time::Duration::from_millis(600));
        let q = http(port, "/api?mode=queue&apikey=sekrit&output=json", None);
        assert!(q.contains("\"Paused\""), "{q}");
        http(
            port,
            &format!("/api?mode=queue&name=resume&value={paused_id}&apikey=sekrit&output=json"),
            None,
        );
        poll_history(&|h: &str| h.matches("Completed").count() >= 2, "paused job after resume");

        // History delete with del_files removes the storage dir.
        let out_dir = dir2.join("complete/tv/j");
        assert!(out_dir.exists(), "expected {}", out_dir.display());
        http(
            port,
            &format!("/api?mode=history&name=delete&value={good_id}&del_files=1&apikey=sekrit&output=json"),
            None,
        );
        assert!(!out_dir.exists(), "del_files should remove {}", out_dir.display());
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// M14f: a queued duplicate is held as ALTERNATIVE and auto-promoted
/// when the original fails.
///
/// "Fails" means FINALLY fails. A first missing-article failure is parked
/// with an M32 automatic retry armed, and promoting the alternative there
/// would download the same title twice in parallel - the retry is about
/// to fetch the very gaps that failed. So this runs with a 5 s cooldown
/// and checks both halves: held while the retry is pending, promoted once
/// it has been spent.
#[tokio::test(flavor = "multi_thread")]
async fn duplicate_held_then_promoted() {
    let dir = std::env::temp_dir().join(format!("nzbfast-dupe-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let data = payload(120_000, 11);
    let mut articles = HashMap::new();
    let segs = make_file_articles("ep.bin", &data, 40_000, "dp", &mut articles);
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
    let ghost: Vec<(String, u64, u32)> =
        (1..=3).map(|n| (format!("dghost{n}@x"), 40_000, n)).collect();
    let bad_xml = wrap(&seg_xml(&ghost)); // 720p "original" - will fail
    let good_xml = wrap(&seg_xml(&segs)); // 1080p duplicate - must take over

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
            // Short M32 cooldown instead of the 20 min default: the promotion
            // waits for the automatic retry to be spent, and the test needs to
            // see both sides of that within its own lifetime.
            .env("NZBFAST_AUTO_RETRY_SECS", "5")
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
            let boundary = "----dupeb";
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
        // Pause so both jobs sit in the queue when the dupe check runs.
        http(port, "/api?mode=pause&output=json", None);
        upload(&bad_xml, "Show.Name.S01E02.720p.WEB.nzb");
        upload(&good_xml, "Show.Name.S01E02.1080p.WEB.nzb");
        let q = http(port, "/api?mode=queue&output=json", None);
        assert!(q.contains("\"Duplicate\""), "{q}");
        assert!(q.contains("show name/s1e2"), "{q}");

        // Resume: 720p fails → 1080p ALTERNATIVE must promote and finish.
        http(port, "/api?mode=resume&output=json", None);

        // FIRST failure: an automatic retry is armed, so the alternative
        // is still held. park decides this synchronously with the history
        // push, so the queue may be read as soon as Failed appears.
        let mut held = false;
        for _ in 0..150 {
            let h = http(port, "/api?mode=history&output=json", None);
            if h.contains("\"Failed\"") {
                let q = http(port, "/api?mode=queue&output=json", None);
                assert!(
                    q.contains("\"Duplicate\""),
                    "promoted while an automatic retry was pending: {q}"
                );
                held = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        assert!(held, "the original never failed");

        // The retry runs, fails again (retries == 1, no longer eligible),
        // and THAT failure promotes the alternative.
        let mut ok = false;
        for _ in 0..150 {
            let h = http(port, "/api?mode=history&output=json", None);
            if h.contains("\"Completed\"") && h.contains("\"Failed\"") {
                assert!(h.contains("1080p"), "{h}");
                ok = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        assert!(ok, "alternative was never promoted/completed");
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// M14k: RSS automation - the daemon polls a feed, filters with rules,
/// fetches the accepted item's NZB over HTTP, downloads it, and never
/// re-grabs a seen guid.
#[tokio::test(flavor = "multi_thread")]
async fn rss_feed_auto_grabs() {
    let dir = std::env::temp_dir().join(format!("nzbfast-rss-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let data = payload(150_000, 13);
    let mut articles = HashMap::new();
    let segs = make_file_articles("r.bin", &data, 40_000, "rs", &mut articles);
    let srv = MockServer::start(articles, Chaos::default()).await;
    let mut nzb_xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file poster=\"x\" date=\"0\" subject=\"&quot;r.bin&quot; yEnc (1/9)\">\n    <groups><group>g</group></groups>\n    <segments>\n",
    );
    for (id, bytes, num) in &segs {
        nzb_xml.push_str(&format!(
            "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
        ));
    }
    nzb_xml.push_str("    </segments>\n  </file>\n</nzb>\n");

    // Indexer stand-in: /rss (feed with one 1080p item + one 480p item)
    // and /grab (the NZB). Counts grabs to prove seen-dedupe.
    let web = tiny_http::Server::http("127.0.0.1:0").unwrap();
    let web_port = web.server_addr().to_ip().unwrap().port();
    let grabs = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
    let grabs2 = grabs.clone();
    let nzb_body = nzb_xml.clone();
    std::thread::spawn(move || {
        for req in web.incoming_requests() {
            let url = req.url().to_string();
            let body = if url.starts_with("/rss") {
                format!(
                    r#"<?xml version="1.0"?><rss><channel>
<item><title>Grab.Me.S01E01.1080p.WEB</title><guid>want-1</guid>
<enclosure url="http://127.0.0.1:{web_port}/grab" length="150000"/></item>
<item><title>Skip.Me.S01E01.480p.WEB</title><guid>skip-1</guid>
<enclosure url="http://127.0.0.1:{web_port}/grab-bad" length="150000"/></item>
</channel></rss>"#
                )
            } else if url.starts_with("/grab-bad") {
                panic!("rejected item was fetched");
            } else {
                grabs2.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                nzb_body.clone()
            };
            let _ = req.respond(tiny_http::Response::from_string(body));
        }
    });

    let feeds = dir.join("feeds.json");
    std::fs::write(
        &feeds,
        format!(
            r#"[{{"url":"http://127.0.0.1:{web_port}/rss","interval_secs":1,"category":"tv","rules":["Reject: *480p*","Accept: *1080p*"]}}]"#
        ),
    )
    .unwrap();

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
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--out")
            .arg(dir.join("complete"))
            .arg("--feeds")
            .arg(&feeds)
            .arg("--connections")
            .arg("2");
        c
    })
    .await;
    let port = d.port;

    tokio::task::spawn_blocking(move || {
        // The 1080p item must be auto-grabbed and complete.
        let mut done = false;
        for _ in 0..150 {
            let h = http(port, "/api?mode=history&output=json", None);
            if h.contains("\"Completed\"") {
                assert!(h.contains("Grab.Me.S01E01.1080p.WEB"), "{h}");
                done = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        assert!(done, "rss item never downloaded");
        // Give the poller 2 more cycles: seen-guid dedupe must hold the
        // grab count at 1 (the /grab-bad panic guards the reject rule).
        std::thread::sleep(std::time::Duration::from_millis(2500));
        assert_eq!(grabs.load(std::sync::atomic::Ordering::Relaxed), 1);
        let q = http(port, "/api?mode=queue&output=json", None);
        assert!(!q.contains("Grab.Me"), "re-queued a seen item: {q}");
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// M14g: an absurd --min-free threshold must hold every job in the queue.
#[tokio::test(flavor = "multi_thread")]
async fn disk_guard_holds_queue() {
    let dir = std::env::temp_dir().join(format!("nzbfast-guard-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let data = payload(100_000, 9);
    let mut articles = HashMap::new();
    let segs = make_file_articles("g.bin", &data, 40_000, "gg", &mut articles);
    let srv = MockServer::start(articles, Chaos::default()).await;
    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file poster=\"x\" date=\"0\" subject=\"&quot;g.bin&quot; yEnc (1/3)\">\n    <groups><group>g</group></groups>\n    <segments>\n",
    );
    for (id, bytes, num) in &segs {
        xml.push_str(&format!(
            "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
        ));
    }
    xml.push_str("    </segments>\n  </file>\n</nzb>\n");

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
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--out")
            .arg(dir.join("complete"))
            .arg("--min-free")
            .arg("1000T")
            .arg("--connections")
            .arg("2");
        c
    })
    .await;
    let port = d.port;

    tokio::task::spawn_blocking(move || {
        let boundary = "----guardb";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!("--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"g.nzb\"\r\n\r\n").as_bytes(),
        );
        body.extend_from_slice(xml.as_bytes());
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        http(
            port,
            "/api?mode=addfile&output=json",
            Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
        );
        // No disk headroom → the job must still be Queued (not started,
        // not failed) after plenty of scheduler wakeups.
        std::thread::sleep(std::time::Duration::from_millis(1500));
        let q = http(port, "/api?mode=queue&output=json", None);
        assert!(q.contains("\"Queued\""), "{q}");
        let h = http(port, "/api?mode=history&output=json", None);
        assert!(h.contains("\"noofslots\":0"), "{h}");
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread")]
async fn stream_while_downloading() {
    // M11: a store-mode rar'd mkv streams over /stream with correct bytes
    // WHILE the download is still running (write stage throttled to keep
    // the window open; the reader must block on not-yet-landed spans).
    use nzbkit::rar::fixtures;
    let dir = std::env::temp_dir().join(format!("nzbfast-stream-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let inner = payload(24_000_000, 7); // 24 MB "movie"
    let vols = [
        fixtures::rar5_volume_n(&[("movie.mkv", 24_000_000, &inner[..8_000_000], false, true)], 0),
        fixtures::rar5_volume_n(
            &[("movie.mkv", 24_000_000, &inner[8_000_000..16_000_000], true, true)],
            1,
        ),
        fixtures::rar5_volume_n(&[("movie.mkv", 24_000_000, &inner[16_000_000..], true, false)], 2),
    ];
    let mut articles = HashMap::new();
    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
    );
    for (i, vol) in vols.iter().enumerate() {
        let name = format!("m.part{}.rar", i + 1);
        let segs = make_file_articles(&name, vol, 300_000, &format!("mv{i}"), &mut articles);
        xml.push_str(&format!(
            "  <file poster=\"x\" date=\"0\" subject=\"&quot;{name}&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
            segs.len()
        ));
        for (id, bytes, num) in &segs {
            xml.push_str(&format!(
                "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
            ));
        }
        xml.push_str("    </segments>\n  </file>\n");
    }
    xml.push_str("</nzb>\n");
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
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--out")
            .arg(dir.join("complete"))
            .arg("--connections")
            .arg("2")
            .env("NZBFAST_THROTTLE_WRITE_MBPS", "3"); // ~8 s download window
        c
    })
    .await;
    let port = d.port;

    let inner2 = inner.clone();
    tokio::task::spawn_blocking(move || {
        // Upload the NZB.
        let boundary = "----streamb";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!("--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"movie.nzb\"\r\n\r\n").as_bytes(),
        );
        body.extend_from_slice(xml.as_bytes());
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        http(
            port,
            "/api?mode=addfile&output=json",
            Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
        );

        // Wait for the stream to exist (download started + mkv writer up).
        let mut got: Vec<u8> = Vec::new();
        for _ in 0..200 {
            let raw = raw(
                port,
                b"GET /stream HTTP/1.1\r\nHost: x\r\nRange: bytes=0-99999\r\nConnection: close\r\n\r\n",
            );
            let text_end = raw.windows(4).position(|w| w == b"\r\n\r\n");
            if let Some(p) = text_end {
                let head = String::from_utf8_lossy(&raw[..p]).to_string();
                if head.contains("206") {
                    got = raw[p + 4..].to_vec();
                    break;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        if got.len() != 100_000 {
            panic!(
                "range length {} head_bytes={:?} tail={:?}",
                got.len(),
                &got[..24.min(got.len())],
                &got[got.len().saturating_sub(16)..]
            );
        }
        assert_eq!(&got[..], &inner2[..100_000], "streamed head bytes differ");

        // M14h: live stats while the download runs - pool gauges up,
        // download lane moving, extract writers visible.
        let s = http(port, "/api?mode=stats&output=json", None);
        assert!(s.contains("\"active\":true"), "{s}");
        assert!(s.contains("\"budget\":2"), "{s}");
        assert!(s.contains("\"connected\":"), "{s}");
        assert!(s.contains("movie.mkv"), "{s}");

        // Mid-file range while the tail is still downloading - reader must
        // block until covered, then return exact bytes.
        let raw = raw(
            port,
            b"GET /stream HTTP/1.1\r\nHost: x\r\nRange: bytes=20000000-20050000\r\nConnection: close\r\n\r\n",
        );
        let p = raw.windows(4).position(|w| w == b"\r\n\r\n").expect("hdrs");
        assert!(String::from_utf8_lossy(&raw[..p]).contains("206"), "{}", String::from_utf8_lossy(&raw[..p]));
        assert_eq!(&raw[p + 4..], &inner2[20_000_000..20_050_001], "mid-range bytes differ");
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread")]
async fn stream_encrypted_while_downloading() {
    // An ENCRYPTED store rar streams over /stream mid-download: the file
    // on disk is AES-256-CBC ciphertext (the finish decrypt hasn't run),
    // so the served bytes prove the on-the-fly CBC decryption path.
    use nzbkit::rar::fixtures;
    let dir = std::env::temp_dir().join(format!("nzbfast-encstream-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let inner = payload(24_000_003, 8); // odd length → end-padding truncate
    let f = fixtures::encrypt_file("s3cret", &inner, 5);
    let n = f.cipher.len();
    let (a, b) = (8_000_016, 16_000_000); // 16-aligned mid splits
    let vols = [
        fixtures::rar5_volume_enc(&[("movie.mkv", &f, 0..a, false, true)], Some(0)),
        fixtures::rar5_volume_enc(&[("movie.mkv", &f, a..b, true, true)], Some(1)),
        fixtures::rar5_volume_enc(&[("movie.mkv", &f, b..n, true, false)], Some(2)),
    ];
    let mut articles = HashMap::new();
    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
    );
    for (i, vol) in vols.iter().enumerate() {
        let name = format!("m.part{}.rar", i + 1);
        let segs = make_file_articles(&name, vol, 300_000, &format!("ev{i}"), &mut articles);
        xml.push_str(&format!(
            "  <file poster=\"x\" date=\"0\" subject=\"&quot;{name}&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
            segs.len()
        ));
        for (id, bytes, num) in &segs {
            xml.push_str(&format!(
                "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
            ));
        }
        xml.push_str("    </segments>\n  </file>\n");
    }
    xml.push_str("</nzb>\n");
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
            // The finish decrypt must NOT be able to reach for unrar; native
            // decryption + on-the-fly streaming is the whole point.
            .env("NZBFAST_TEST_FORBID_UNRAR", "1")
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
            .arg("2")
            .env("NZBFAST_THROTTLE_WRITE_MBPS", "3"); // ~8 s download window
        c
    })
    .await;
    let port = d.port;

    let inner2 = inner.clone();
    let dir2 = dir.clone();
    tokio::task::spawn_blocking(move || {
        // Upload with the {{password}} filename convention.
        let boundary = "----encstreamb";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!("--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"movie{{{{s3cret}}}}.nzb\"\r\n\r\n").as_bytes(),
        );
        body.extend_from_slice(xml.as_bytes());
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        http(
            port,
            "/api?mode=addfile&output=json",
            Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
        );

        // Head range while still downloading (and still ciphertext).
        let mut got: Vec<u8> = Vec::new();
        for _ in 0..200 {
            let raw = raw(
                port,
                b"GET /stream HTTP/1.1\r\nHost: x\r\nRange: bytes=0-99999\r\nConnection: close\r\n\r\n",
            );
            if let Some(p) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                if String::from_utf8_lossy(&raw[..p]).contains("206") {
                    got = raw[p + 4..].to_vec();
                    break;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        assert_eq!(got.len(), 100_000, "head range length");
        assert_eq!(&got[..], &inner2[..100_000], "decrypted head bytes differ");

        // Mid-file range spanning a volume boundary, decrypted on the fly
        // (block-unaligned start exercises the IV-block read).
        let raw = raw(
            port,
            b"GET /stream HTTP/1.1\r\nHost: x\r\nRange: bytes=15999990-16050000\r\nConnection: close\r\n\r\n",
        );
        let p = raw.windows(4).position(|w| w == b"\r\n\r\n").expect("hdrs");
        assert!(String::from_utf8_lossy(&raw[..p]).contains("206"));
        assert_eq!(&raw[p + 4..], &inner2[15_999_990..16_050_001], "mid-range decrypt differs");

        // Wait for the JOB to complete - not just for the file to reach a
        // length. The inner file is preallocated to the unpacked size and
        // holds ciphertext until the finish decrypt, so length alone is
        // not a done signal (reading it mid-download yields ciphertext).
        // Poll history for Completed, then the file is plaintext.
        let mut completed = false;
        for _ in 0..600 {
            let h = http(port, "/api?mode=history&output=json", None);
            if h.replace(' ', "").contains("\"status\":\"Completed\"") {
                completed = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        assert!(completed, "job never reached Completed");
        let mkv = dir2.join("complete/movie/movie.mkv");
        let got =
            std::fs::read(&mkv).unwrap_or_else(|e| panic!("reading {}: {e}", mkv.display()));
        assert_eq!(got.len(), inner2.len(), "final file length");
        let first_diff = got.iter().zip(&inner2).position(|(a, b)| a != b);
        assert!(first_diff.is_none(), "final file differs at byte {first_diff:?}");
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// M11 ordering e2e: the mock server records BODY request order, so this
/// proves the two queue-shaping behaviors end to end (not just byte
/// correctness, which `stream_while_downloading` covers):
///  1. tail burst - the LAST volume's articles fetch right after the
///     first volume, before ANY middle-volume article (MKV Cues / MP4
///     moov live at file end; players read them before starting play);
///  2. seek re-prioritization - a Range request far past the write
///     frontier promotes the articles under it, so the middle volume is
///     entered at the seek point, not at its first article.
/// One connection, window 1, and a fixed per-article server delay make
/// the BODY log a faithful picture of the pending-queue order.
#[tokio::test(flavor = "multi_thread")]
async fn stream_seek_promotes_and_tail_bursts() {
    use nzbkit::rar::fixtures;
    let dir = std::env::temp_dir().join(format!("nzbfast-seekord-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    // 48 MB movie in 3 store-mode rar5 volumes of 16 MB payload each:
    // volA = inner[0..16M], volB = [16..32M], volC = [32..48M]. Volumes
    // are sized well above the promote window's 4 MB PRE_ROLL so a
    // mid-volume seek still provably enters the volume mid-way.
    let inner = payload(48_000_000, 11);
    let vols = [
        fixtures::rar5_volume_n(&[("movie.mkv", 48_000_000, &inner[..16_000_000], false, true)], 0),
        fixtures::rar5_volume_n(
            &[("movie.mkv", 48_000_000, &inner[16_000_000..32_000_000], true, true)],
            1,
        ),
        fixtures::rar5_volume_n(&[("movie.mkv", 48_000_000, &inner[32_000_000..], true, false)], 2),
    ];
    let mut articles = HashMap::new();
    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
    );
    for (i, vol) in vols.iter().enumerate() {
        let name = format!("m.part{}.rar", i + 1);
        let tag = ["volA", "volB", "volC"][i];
        let segs = make_file_articles(&name, vol, 300_000, tag, &mut articles);
        xml.push_str(&format!(
            "  <file poster=\"x\" date=\"0\" subject=\"&quot;{name}&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
            segs.len()
        ));
        for (id, bytes, num) in &segs {
            xml.push_str(&format!(
                "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
            ));
        }
        xml.push_str("    </segments>\n  </file>\n");
    }
    xml.push_str("</nzb>\n");
    // 80 ms per article paces the ~162-article download to ~13 s - wide
    // timing margins so the seek reliably lands before the middle volume
    // starts naturally, even under full-suite parallelism.
    let srv = MockServer::start(
        articles,
        Chaos {
            delay_ms: 80,
            ..Chaos::default()
        },
    )
    .await;
    let body_log = srv.body_log.clone();

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
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--out")
            .arg(dir.join("complete"))
            .arg("--connections")
            .arg("1")
            .arg("--window")
            .arg("1");
        c
    })
    .await;
    let port = d.port;

    // "<volB-13@mock>" → Some(13) for tag "volB".
    fn part_of(id: &str, tag: &str) -> Option<u32> {
        id.strip_prefix('<')?
            .strip_prefix(tag)?
            .strip_prefix('-')?
            .split('@')
            .next()?
            .parse()
            .ok()
    }

    let inner2 = inner.clone();
    tokio::task::spawn_blocking(move || {
        let boundary = "----seekord";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!("--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"movie.nzb\"\r\n\r\n").as_bytes(),
        );
        body.extend_from_slice(xml.as_bytes());
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        http(
            port,
            "/api?mode=addfile&output=json",
            Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
        );

        // Wait for the stream to come up (tail bytes landed, writer
        // live). Probe the file TAIL, not byte 0: a probe's reader
        // promotes a SEEK_READAHEAD (32 MB) playhead window, and from
        // position 0 that window spans volA and ALL of volB - displacing
        // the volC tail burst behind it and racing volB into the store
        // before the gate below trips. A tail probe's window is pure
        // volC, so volB provably stays untouched until the seek.
        let mut up = false;
        for _ in 0..600 {
            let raw = raw(
                port,
                b"GET /stream HTTP/1.1\r\nHost: x\r\nRange: bytes=47900000-47999999\r\nConnection: close\r\n\r\n",
            );
            if String::from_utf8_lossy(&raw).starts_with("HTTP/1.1 206") {
                up = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        assert!(up, "/stream never became ready");

        // 1. Tail burst: wait until a few tail-volume (volC) articles have
        // been requested and assert the middle volume (volB) hasn't been
        // touched - volC jumped the queue at build. (Queue order makes
        // this deterministic: all bursted volC precede any volB. Part 1 of
        // every volume is exempt - each volume's first article goes out
        // early so the extractor can parse rar headers and map volumes.)
        let pre_len = loop {
            let log = body_log.lock().unwrap();
            if log.iter().filter(|id| id.starts_with("<volC-")).count() >= 3 {
                assert!(
                    !log.iter().any(|id| part_of(id, "volB").is_some_and(|n| n >= 2)),
                    "middle volume fetched before the tail burst: {log:?}"
                );
                break log.len();
            }
            drop(log);
            std::thread::sleep(std::time::Duration::from_millis(25));
        };

        // 2. Seek: inner byte 24 MB is the middle of volB - far past the
        // write frontier, so the range start must promote the articles
        // under it. The read blocks until they land, then returns exact
        // bytes.
        let raw = raw(
            port,
            b"GET /stream HTTP/1.1\r\nHost: x\r\nRange: bytes=24000000-24049999\r\nConnection: close\r\n\r\n",
        );
        let p = raw.windows(4).position(|w| w == b"\r\n\r\n").expect("hdrs");
        assert!(
            String::from_utf8_lossy(&raw[..p]).contains("206"),
            "{}",
            String::from_utf8_lossy(&raw[..p])
        );
        assert_eq!(&raw[p + 4..], &inner2[24_000_000..24_050_000], "seek bytes differ");

        // The seek entered volB mid-volume: every volB article requested
        // so far sits at/after the promoted window (24 MB seek − 4 MB
        // pre-roll → volB offset ~4 MB → part ~14 of 54, minus the
        // ladder's ±2 slack) - linear order would have started at part 1.
        let log = body_log.lock().unwrap();
        let volb: Vec<u32> =
            log[pre_len..].iter().filter_map(|id| part_of(id, "volB")).collect();
        assert!(!volb.is_empty(), "no volB articles fetched for the seek");
        assert!(
            volb.iter().all(|&n| n >= 8),
            "volB entered at part {volb:?} - promotion should start it mid-volume"
        );
        assert!(
            volb.iter().any(|&n| (10..=20).contains(&n)),
            "no volB article near the 12 MB seek point: {volb:?}"
        );
        assert!(
            !log[..pre_len].iter().any(|id| part_of(id, "volB").is_some_and(|n| n >= 2)),
            "volB data fetched before the seek"
        );
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// M11 deep-window preemption e2e: same 3-volume fixture as
/// `stream_seek_promotes_and_tail_bursts`, but with 4 connections × window
/// 4 - the real-world shape where a promote used to queue behind ~16
/// already-pipelined BODYs and a seek took tens of seconds at scale. The
/// live /stream reader engages the pool's stream mode (shallow pipelines +
/// shed of deep ones), so a promoted article must be REQUESTED within K
/// BODYs of the promote, not after every connection drains its window.
/// The final byte-identical completion check proves the shed/requeue path
/// loses nothing.
#[tokio::test(flavor = "multi_thread")]
async fn stream_promote_preempts_deep_windows() {
    use nzbkit::rar::fixtures;
    let dir = std::env::temp_dir().join(format!("nzbfast-seekpre-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let inner = payload(48_000_000, 13);
    let vols = [
        fixtures::rar5_volume_n(&[("movie.mkv", 48_000_000, &inner[..16_000_000], false, true)], 0),
        fixtures::rar5_volume_n(
            &[("movie.mkv", 48_000_000, &inner[16_000_000..32_000_000], true, true)],
            1,
        ),
        fixtures::rar5_volume_n(&[("movie.mkv", 48_000_000, &inner[32_000_000..], true, false)], 2),
    ];
    let mut articles = HashMap::new();
    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
    );
    for (i, vol) in vols.iter().enumerate() {
        let name = format!("m.part{}.rar", i + 1);
        let tag = ["volA", "volB", "volC"][i];
        let segs = make_file_articles(&name, vol, 300_000, tag, &mut articles);
        xml.push_str(&format!(
            "  <file poster=\"x\" date=\"0\" subject=\"&quot;{name}&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
            segs.len()
        ));
        for (id, bytes, num) in &segs {
            xml.push_str(&format!(
                "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
            ));
        }
        xml.push_str("    </segments>\n  </file>\n");
    }
    xml.push_str("</nzb>\n");
    // 80 ms per article: 4 connections serve ~50 articles/s, so the
    // ~162-article download runs ~3 s - slow enough that the 24 MB seek
    // lands while the middle volume is still pending, fast enough for
    // the suite. (16 MB volumes: sized well above the promote window's
    // 4 MB PRE_ROLL so mid-volume entry stays provable.)
    let srv = MockServer::start(
        articles,
        Chaos {
            delay_ms: 80,
            ..Chaos::default()
        },
    )
    .await;
    let body_log = srv.body_log.clone();
    let pause = srv.pause.clone();

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
    // `serve` captures the daemon's stdout, which this test needs: it
    // uses the "[stream] seek@… promoted" print as the exact promote
    // marker while the mock is frozen.
    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
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
            .arg("4")
            .arg("--window")
            .arg("4");
        c
    })
    .await;
    let port = d.port;
    let daemon_log = d.log.clone();

    // "<volB-13@mock>" → Some(13) for tag "volB".
    fn part_of(id: &str, tag: &str) -> Option<u32> {
        id.strip_prefix('<')?
            .strip_prefix(tag)?
            .strip_prefix('-')?
            .split('@')
            .next()?
            .parse()
            .ok()
    }

    let inner2 = inner.clone();
    let dir2 = dir.clone();
    tokio::task::spawn_blocking(move || {
        // Liveness deadlines in this test are sized for a fully loaded
        // machine (`cargo test --workspace --release` runs many test
        // binaries in parallel and stretches the nominal ~5 s run to
        // 25 s+). The preemption assertions themselves are anchored to
        // the daemon's promote marker while the mock is frozen, so
        // generous deadlines cost nothing in correctness - they only
        // delay reporting on a genuinely hung run.
        let boundary = "----seekpre";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!("--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"movie.nzb\"\r\n\r\n").as_bytes(),
        );
        body.extend_from_slice(xml.as_bytes());
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        http(
            port,
            "/api?mode=addfile&output=json",
            Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
        );

        // Wait for the stream to come up. The successful request also
        // engages the pool's stream mode - from here on, pipelines are
        // shallow and any deep pre-stream window gets shed.
        //
        // Probe the file TAIL, not byte 0: a probe's reader promotes a
        // SEEK_READAHEAD (32 MB) playhead window, and from position 0
        // that window spans volA AND ALL OF volB - displacing the volC
        // tail burst behind it and racing volB into the store before the
        // freeze below can land (the flake this test used to have under
        // suite load: the seek point was already covered, so the seek
        // promote - and its log marker - never fired). A tail probe's
        // window is pure volC, leaving volB pending until the real seek
        // no matter how slowly this thread gets scheduled.
        let mut up = false;
        for _ in 0..900 {
            let raw = raw(
                port,
                b"GET /stream HTTP/1.1\r\nHost: x\r\nRange: bytes=47900000-47999999\r\nConnection: close\r\n\r\n",
            );
            if String::from_utf8_lossy(&raw).starts_with("HTTP/1.1 206") {
                up = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        assert!(up, "/stream never became ready");

        // Let the run get going (tail burst served) but seek while the
        // middle volume is still pending: 3 volC articles ≈ 58 served of
        // the ~81 (volA+volC tail) that precede any volB data in queue
        // order.
        loop {
            let log = body_log.lock().unwrap();
            if log.iter().filter(|id| id.starts_with("<volC-")).count() >= 3 {
                break;
            }
            drop(log);
            std::thread::sleep(std::time::Duration::from_millis(25));
        }

        // Freeze the mock (connections stop reading commands), land the
        // seek's promote at a KNOWN point in the body log, then release.
        // Without the freeze, scheduler jitter between capturing the log
        // length and the daemon executing the promote lets an unbounded
        // number of legitimately-ordered requests slip in between.
        pause.store(true, std::sync::atomic::Ordering::Release);
        std::thread::sleep(std::time::Duration::from_millis(300));

        // Seek to inner byte 24 MB (middle of volB), far past the write
        // frontier. The promote must preempt: with stream mode active no
        // connection holds more than one in-flight BODY, so the promoted
        // articles go out within ~one BODY per connection - not after
        // 4-deep windows drain.
        //
        // Hand-rolled rather than `raw()`: this request is deliberately
        // left in flight, unread, while the assertions below run against
        // the frozen mock.
        let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
        write!(s, "GET /stream HTTP/1.1\r\nHost: x\r\nRange: bytes=24000000-24049999\r\nConnection: close\r\n\r\n").unwrap();
        // Wait for the daemon's own promote print - the exact marker that
        // the queue reorder has happened - while the log is frozen, then
        // snapshot the promote point and release the world. (The world
        // is frozen, so waiting longer is free - the deadline only has
        // to beat scheduler starvation on a loaded machine.)
        let mut promoted = false;
        for _ in 0..1200 {
            let l = std::fs::read_to_string(&daemon_log).unwrap_or_default();
            if l.contains("seek@24000000 → promoted") {
                promoted = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(25));
        }
        assert!(promoted, "the seek's promote never fired while frozen");
        let pre_len = body_log.lock().unwrap().len();
        pause.store(false, std::sync::atomic::Ordering::Release);
        let mut raw = Vec::new();
        s.read_to_end(&mut raw).unwrap();
        let p = raw.windows(4).position(|w| w == b"\r\n\r\n").expect("hdrs");
        assert!(
            String::from_utf8_lossy(&raw[..p]).contains("206"),
            "{}",
            String::from_utf8_lossy(&raw[..p])
        );
        assert_eq!(&raw[p + 4..], &inner2[24_000_000..24_050_000], "seek bytes differ");

        {
            let log = body_log.lock().unwrap();
            let post = &log[pre_len..];
            // The promoted window (24 MB − 4 MB pre-roll → volB from
            // ~part 12 of 54, ±2 ladder slack) must
            // be REQUESTED within K articles of the promote: 4 in-flight
            // singles + a few requests racing the promote itself. A
            // regression to backlog-drain pickup lands at ~13+ (4 conns ×
            // 3 remaining window slots ahead of it).
            const K: usize = 8;
            let first_promoted = post
                .iter()
                .position(|id| part_of(id, "volB").is_some_and(|n| n >= 8))
                .expect("no promoted volB article requested after the seek");
            assert!(
                first_promoted < K,
                "promoted article only requested after {first_promoted} others (window backlog not preempted): {post:?}"
            );
            // And the promotion entered volB mid-volume, at the seek point.
            let volb: Vec<u32> = post.iter().filter_map(|id| part_of(id, "volB")).collect();
            assert!(
                volb.iter().all(|&n| n >= 8),
                "volB entered at part {volb:?} - promotion should start it mid-volume"
            );
            assert!(
                volb.iter().any(|&n| (20..=34).contains(&n)),
                "no volB article near the 24 MB seek point: {volb:?}"
            );
        }

        // The shed/requeue path must lose nothing: the download completes
        // and the extracted movie is byte-identical. ~162 articles at
        // 80 ms across 4 connections is ~4 s nominal, but extraction +
        // suite load can multiply that several-fold.
        let mut done = false;
        for _ in 0..750 {
            let h = http(port, "/api?mode=history&output=json", None);
            if h.contains("\"Completed\"") {
                done = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        assert!(done, "download never completed after the seek");
        fn find_file(dir: &std::path::Path, name: &str) -> Option<std::path::PathBuf> {
            for e in std::fs::read_dir(dir).ok()? {
                let p = e.ok()?.path();
                if p.is_dir() {
                    if let Some(f) = find_file(&p, name) {
                        return Some(f);
                    }
                } else if p.file_name().is_some_and(|f| f == name) {
                    return Some(p);
                }
            }
            None
        }
        let out = find_file(&dir2.join("complete"), "movie.mkv").expect("movie.mkv missing");
        assert_eq!(std::fs::read(&out).unwrap(), inner2, "extracted bytes differ");
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// "Stream an NZB" front door: `addfile&stream=1` enqueues at Force
/// priority and answers with the player-handoff links (m3u + tokenized
/// /stream/<id>); the /m3u link serves a playlist pointing at the
/// stream. The same links come from GET /watch?url= (303 → the m3u).
#[tokio::test(flavor = "multi_thread")]
async fn stream_add_returns_player_links() {
    let dir = std::env::temp_dir().join(format!("nzbfast-streamadd-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let data = payload(600_000, 3);
    let mut articles = HashMap::new();
    let segs = make_file_articles("show.mkv", &data, 300_000, "sa", &mut articles);
    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file poster=\"x\" date=\"0\" subject=\"&quot;show.mkv&quot; yEnc (1/2)\">\n    <groups><group>g</group></groups>\n    <segments>\n",
    );
    for (id, bytes, num) in &segs {
        xml.push_str(&format!(
            "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
        ));
    }
    xml.push_str("    </segments>\n  </file>\n</nzb>\n");
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
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--out")
            .arg(dir.join("complete"));
        c
    })
    .await;
    let port = d.port;

    tokio::task::spawn_blocking(move || {
        let boundary = "----streamadd";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!("--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"show.nzb\"\r\n\r\n").as_bytes(),
        );
        body.extend_from_slice(xml.as_bytes());
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let r = http(
            port,
            "/api?mode=addfile&output=json&stream=1",
            Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
        );
        assert!(r.contains("\"status\":true"), "{r}");
        assert!(r.contains("\"m3u\":") && r.contains("/m3u/"), "no m3u link: {r}");
        assert!(r.contains("\"stream\":") && r.contains("/stream/"), "no stream link: {r}");

        // Force priority: the queue/history slot reports it (job may
        // complete instantly - 600 KB, no delay - so check both).
        let mut forced = false;
        for _ in 0..100 {
            let q = http(port, "/api?mode=queue&output=json", None);
            let h = http(port, "/api?mode=history&output=json", None);
            if q.contains("\"priority\":\"Force\"") || q.contains("\"Force\"") {
                forced = true;
                break;
            }
            if h.contains("\"Completed\"") {
                forced = true; // ran to completion straight away - it led the queue
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        assert!(forced, "stream add neither Force-queued nor completed");

        // The m3u link answers with a playlist pointing at the stream.
        let m3u = String::from_utf8_lossy(&raw(
            port,
            b"GET /m3u/SABnzbd_nzo_nzbfast1 HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
        ))
        .to_string();
        assert!(m3u.contains("#EXTM3U") && m3u.contains("/stream/SABnzbd_nzo_nzbfast1?t="), "{m3u}");

        // /watch with a bad URL fails loudly (502), not silently.
        let bad = String::from_utf8_lossy(&raw(
            port,
            b"GET /watch?url=http://127.0.0.1:9/none.nzb HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
        ))
        .to_string();
        assert!(bad.starts_with("HTTP/1.1 502"), "{bad}");
        // /watch without url= is a 400.
        let nourl = String::from_utf8_lossy(&raw(
            port,
            b"GET /watch HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
        ))
        .to_string();
        assert!(nourl.starts_with("HTTP/1.1 400"), "{nourl}");
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// Queue/history persistence: job records survive a daemon kill -9.
/// A completed job must come back in history, a paused queued job must
/// come back queued (still paused), and resuming it after the restart
/// must download the payload byte-identically.
#[tokio::test(flavor = "multi_thread")]
async fn queue_survives_restart() {
    let dir = std::env::temp_dir().join(format!("nzbfast-persist-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let keeper_data = payload(200_000, 7);
    let later_data = payload(160_000, 11);
    let mut articles = HashMap::new();
    let keeper_segs = make_file_articles("keeper.bin", &keeper_data, 40_000, "kp", &mut articles);
    let later_segs = make_file_articles("later.bin", &later_data, 40_000, "lt", &mut articles);
    let srv = MockServer::start(articles, Chaos::default()).await;

    let nzb_for = |name: &str, segs: &[(String, u64, u32)]| {
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
    };
    let keeper_xml = nzb_for("keeper.bin", &keeper_segs);
    let later_xml = nzb_for("later.bin", &later_segs);

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
    let build = |port: u16| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
            .arg("--config")
            .arg(&cfg)
            .arg("serve")
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--apikey")
            .arg("sekrit")
            .arg("--out")
            .arg(dir.join("complete"))
            .arg("--connections")
            .arg("2");
        c
    };
    let upload = |port: u16, xml: &str, extra: &str| -> String {
        let boundary = "----persistb";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!("--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"j.nzb\"\r\n\r\n").as_bytes(),
        );
        body.extend_from_slice(xml.as_bytes());
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let r = http(
            port,
            &format!("/api?mode=addfile&apikey=sekrit&output=json{extra}"),
            Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
        );
        assert!(r.contains("\"status\":true"), "{r}");
        r.split("SABnzbd_nzo_").nth(1).unwrap().split('"').next()
            .map(|s| format!("SABnzbd_nzo_{s}")).unwrap()
    };
    let poll_history = |port: u16, pred: &dyn Fn(&str) -> bool, what: &str| {
        for _ in 0..150 {
            let h = http(port, "/api?mode=history&apikey=sekrit&output=json", None);
            if pred(&h) {
                return h;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        panic!("timed out waiting for {what}");
    };

    // Daemon A: complete one job, add a second paused, then kill -9.
    let a = serve(&dir, &build).await;
    let port_a = a.port;
    let (keeper_id, later_id) = tokio::task::spawn_blocking(move || {
        let keeper_id = upload(port_a, &keeper_xml, "&cat=tv");
        poll_history(port_a, &|h: &str| h.contains("Completed"), "keeper job");
        // priority -2 = add paused: stays Queued so it's still in the
        // queue when the daemon dies.
        let later_id = upload(port_a, &later_xml, "&priority=-2");
        let q = http(port_a, "/api?mode=queue&apikey=sekrit&output=json", None);
        assert!(q.contains(&later_id) && q.contains("\"Paused\""), "{q}");
        (keeper_id, later_id)
    })
    .await
    .unwrap();
    // kill -9 (KillOnDrop kills and reaps): persistence must not depend
    // on a graceful shutdown.
    drop(a);

    // Daemon B on a fresh port, same spool: both records must be back.
    let b = serve(&dir, &build).await;
    let port_b = b.port;
    let dir2 = dir.clone();
    tokio::task::spawn_blocking(move || {
        let q = http(port_b, "/api?mode=queue&apikey=sekrit&output=json", None);
        assert!(q.contains(&later_id), "queued job lost across restart: {q}");
        assert!(q.contains("\"Paused\""), "per-job pause lost across restart: {q}");
        let h = http(port_b, "/api?mode=history&apikey=sekrit&output=json", None);
        assert!(h.contains(&keeper_id), "history lost across restart: {h}");
        assert!(h.contains("\"Completed\""), "{h}");
        // The restored category survives too (out_dir under complete/tv).
        // Compared with the separator normalised: the daemon reports NATIVE
        // paths, so on Windows this reads "complete\\tv\\j" (JSON-escaped)
        // and a literal "complete/tv/j" could never match.
        assert!(h.replace("\\\\", "/").contains("complete/tv/j"), "{h}");

        // Resume the restored job - it must actually download.
        http(
            port_b,
            &format!("/api?mode=queue&name=resume&value={later_id}&apikey=sekrit&output=json"),
            None,
        );
        poll_history(
            port_b,
            &|h: &str| h.contains(&later_id) && h.matches("Completed").count() >= 2,
            "restored job after resume",
        );
        assert_eq!(
            std::fs::read(dir2.join("complete/j/later.bin")).unwrap(),
            later_data,
            "restored job payload differs"
        );
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// M21: the NZBGet JSON-RPC facade - a remote-control app's whole
/// session: version, append (base64 NZB), listgroups, pause/resume via
/// status, editqueue GroupDelete, rate.
#[tokio::test(flavor = "multi_thread")]
async fn nzbget_jsonrpc_facade_cycle() {
    let dir = std::env::temp_dir().join(format!("nzbfast-jsonrpc-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let data = payload(200_000, 5);
    let mut articles = HashMap::new();
    let segs = make_file_articles("show.bin", &data, 40_000, "jr", &mut articles);
    let srv = MockServer::start(articles, Chaos::default()).await;
    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file poster=\"x\" date=\"0\" subject=\"&quot;show.bin&quot; yEnc (1/6)\">\n    <groups><group>g</group></groups>\n    <segments>\n",
    );
    for (id, bytes, num) in &segs {
        xml.push_str(&format!(
            "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
        ));
    }
    xml.push_str("    </segments>\n  </file>\n</nzb>\n");

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
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--out")
            .arg(dir.join("complete"));
        c
    })
    .await;
    let port = d.port;

    // Simple std base64 encoder for the append payload.
    fn b64(data: &[u8]) -> String {
        const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for c in data.chunks(3) {
            let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
            let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
            out.push(A[(n >> 18) as usize & 63] as char);
            out.push(A[(n >> 12) as usize & 63] as char);
            out.push(if c.len() > 1 { A[(n >> 6) as usize & 63] as char } else { '=' });
            out.push(if c.len() > 2 { A[n as usize & 63] as char } else { '=' });
        }
        out
    }

    let dir2 = dir.clone();
    tokio::task::spawn_blocking(move || {
        let rpc = |method: &str, params: String| -> String {
            let body = format!("{{\"method\":\"{method}\",\"params\":{params},\"id\":7}}");
            http(port, "/jsonrpc", Some(("application/json", body.as_bytes())))
        };
        // version
        let v = rpc("version", "[]".into());
        assert!(v.contains("21.0"), "{v}");
        // append (v13 param order), paused via priority 0 - it will start
        // downloading from the mock; that's fine.
        let ap = rpc(
            "append",
            format!("[\"show.nzb\",\"{}\",\"tv\",0,false,false,\"\",0,\"SCORE\"]", b64(xml.as_bytes())),
        );
        let nzbid: i64 = serde_json::from_str::<serde_json::Value>(&ap)
            .ok()
            .and_then(|v| v.get("result").and_then(|r| r.as_i64()))
            .unwrap_or(0);
        assert!(nzbid > 0, "append failed: {ap}");
        // listgroups sees it (or it may already be in history if tiny+fast;
        // poll both).
        let mut seen = false;
        for _ in 0..50 {
            let lg = rpc("listgroups", "[]".into());
            let hi = rpc("history", "[]".into());
            if lg.contains("show.nzb") || lg.contains("\"NZBID\"") && lg.contains(&nzbid.to_string())
                || hi.contains(&format!("\"NZBID\":{nzbid}"))
            {
                seen = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        assert!(seen, "job never visible via listgroups/history");
        // pause / status / resume
        rpc("pausedownload", "[]".into());
        let st = rpc("status", "[]".into());
        assert!(st.contains("\"DownloadPaused\":true"), "{st}");
        rpc("resumedownload", "[]".into());
        let st = rpc("status", "[]".into());
        assert!(st.contains("\"DownloadPaused\":false"), "{st}");
        // rate limit round-trip
        rpc("rate", "[2500]".into());
        let st = rpc("status", "[]".into());
        assert!(st.contains(&format!("\"DownloadLimit\":{}", 2500 * 1024)), "{st}");
        rpc("rate", "[0]".into());
        // history cleanup op is exercised by HistoryDelete once done.
        for _ in 0..100 {
            let hi = rpc("history", "[]".into());
            if hi.contains(&format!("\"NZBID\":{nzbid}")) {
                let del = rpc("editqueue", format!("[\"HistoryDelete\",\"\",[{nzbid}]]"));
                assert!(del.contains("true"), "{del}");
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        panic!("download never completed into history");
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir2);
}

/// Revealing and rotating the API key are full-`apikey` operations. The
/// add-only `nzbkey` exists so a script can submit NZBs WITHOUT gaining
/// control; handing it the API key would promote it to exactly that in
/// one request, so these two modes must never join the add_only
/// allowlist. Also pins that a rotated key actually persists - it lives
/// in settings.json, written by the caller of apply_setting, and a miss
/// there would hand the user a key that stops working at the next
/// restart after they had already pasted it into Sonarr.
#[tokio::test(flavor = "multi_thread")]
async fn apikey_reveal_and_rotate_need_the_api_key() {
    let dir = std::env::temp_dir().join(format!("nzbfast-keyui-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        format!("{{\"servers\":[{{\"host\":\"127.0.0.1\",\"port\":{},\"tls\":false}}]}}", free_port()),
    )
    .unwrap();
    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_NO_ENRICH", "1")
            .arg("--config")
            .arg(&cfg)
            .arg("serve")
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--apikey")
            .arg("fullkey")
            .arg("--nzbkey")
            .arg("addkey")
            .arg("--out")
            .arg(dir.join("complete"));
        c
    })
    .await;
    let port = d.port;

    let dir2 = dir.clone();
    tokio::task::spawn_blocking(move || {
        // The add-only key gets nothing from either mode.
        for mode in ["apikey_show", "apikey_new"] {
            let r = http(port, &format!("/api?mode={mode}&apikey=addkey&output=json"), None);
            assert!(r.contains("\"status\":false"), "{mode} answered the add-only key: {r}");
            assert!(!r.contains("fullkey"), "{mode} LEAKED the api key to the add-only key: {r}");
            // And no key at all is refused too.
            let r = http(port, &format!("/api?mode={mode}&output=json"), None);
            assert!(r.contains("\"status\":false"), "{mode} answered an unauthenticated caller: {r}");
            assert!(!r.contains("fullkey"), "{mode} LEAKED the api key unauthenticated: {r}");
        }

        // The real key can read it.
        let r = http(port, "/api?mode=apikey_show&apikey=fullkey&output=json", None);
        assert!(r.contains("\"apikey\":\"fullkey\""), "reveal did not return the key: {r}");

        // Rotate, then prove the OLD key is dead, the NEW one works, and
        // the new one reached settings.json rather than only memory.
        let r = http(port, "/api?mode=apikey_new&apikey=fullkey&output=json", None);
        let new = r
            .split("\"apikey\":\"")
            .nth(1)
            .and_then(|s| s.split('"').next())
            .expect("no key in rotate response")
            .to_string();
        assert_ne!(new, "fullkey", "rotate returned the same key: {r}");

        let r = http(port, "/api?mode=version&apikey=fullkey&output=json", None);
        assert!(r.contains("\"status\":false"), "the old key still works after a rotate: {r}");
        let r = http(port, &format!("/api?mode=version&apikey={new}&output=json"), None);
        assert!(r.contains("\"nzbfast\""), "the new key does not work: {r}");

        let saved = std::fs::read_to_string(dir2.join("settings.json")).unwrap_or_default();
        assert!(
            saved.contains(&new),
            "rotated key never reached settings.json, so it dies on restart: {saved}"
        );
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// The other half of a rotation: the write that FAILS. On a full disk or a
/// read-only settings folder the daemon is already on the new key (nothing
/// can put the old one back) but settings.json still holds the old one, so
/// the key dies at the next restart. The answer is `status: true` with the
/// key AND `saved: false` - the dashboard needs the key to keep talking to
/// this daemon, and the durability flag to say so on screen rather than in
/// a stdout line nobody reads on a NAS.
///
/// Pins the producer side of the contract the dashboard now consumes. Root
/// ignores the permission bits, so it can only run unprivileged.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn a_rotation_that_cannot_be_persisted_says_so() {
    use std::os::unix::fs::PermissionsExt;
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("skipped: root writes into a read-only directory anyway");
        return;
    }
    let dir = std::env::temp_dir().join(format!("nzbfast-keyro-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        format!("{{\"servers\":[{{\"host\":\"127.0.0.1\",\"port\":{},\"tls\":false}}]}}", free_port()),
    )
    .unwrap();
    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_NO_ENRICH", "1")
            .arg("--config")
            .arg(&cfg)
            .arg("serve")
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--apikey")
            .arg("fullkey")
            .arg("--out")
            .arg(dir.join("complete"));
        c
    })
    .await;
    let port = d.port;

    let dir2 = dir.clone();
    let (rot, ver, before, after) = tokio::task::spawn_blocking(move || {
        // Everything the daemon still needs lives in .spool, whose own bits
        // are untouched; only NEW files beside the config become impossible,
        // which is exactly settings.json's atomic temp file.
        let before = std::fs::read_to_string(dir2.join("settings.json")).unwrap_or_default();
        std::fs::set_permissions(&dir2, std::fs::Permissions::from_mode(0o555)).unwrap();
        let rot = http(port, "/api?mode=apikey_new&apikey=fullkey&output=json", None);
        let new = rot
            .split("\"apikey\":\"")
            .nth(1)
            .and_then(|s| s.split('"').next())
            .unwrap_or_default()
            .to_string();
        let ver = http(port, &format!("/api?mode=version&apikey={new}&output=json"), None);
        let after = std::fs::read_to_string(dir2.join("settings.json")).unwrap_or_default();
        // Restore before asserting, or the dir cannot be cleaned up.
        let _ = std::fs::set_permissions(&dir2, std::fs::Permissions::from_mode(0o755));
        (rot, ver, before, after)
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);

    assert!(rot.contains("\"status\":true"), "a live rotation reported failure: {rot}");
    assert!(
        rot.contains("\"saved\":false"),
        "the un-persisted rotation claimed to be durable: {rot}"
    );
    assert!(ver.contains("\"nzbfast\""), "the daemon is not on the key it handed out: {ver}");
    assert_eq!(before, after, "settings.json changed under a read-only directory");
}

/// Security regression: the add-only `nzbkey` must not gain full control
/// through the NZBGet `/jsonrpc` facade. `append`/`version`/`status` are
/// allowed for it; queue/rate/config mutation (editqueue GroupFinalDelete,
/// rate, pausedownload) is full-`apikey` only. Before the fix, /jsonrpc
/// accepted either key with no tier check and the add-only key could wipe
/// the queue.
#[tokio::test(flavor = "multi_thread")]
async fn jsonrpc_add_only_key_cannot_control_queue() {
    let dir = std::env::temp_dir().join(format!("nzbfast-jrpc-tier-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        format!("{{\"servers\":[{{\"host\":\"127.0.0.1\",\"port\":{},\"tls\":false}}]}}", free_port()),
    )
    .unwrap();
    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            .arg("--config")
            .arg(&cfg)
            .arg("serve")
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--apikey")
            .arg("fullkey")
            .arg("--nzbkey")
            .arg("addkey")
            .arg("--out")
            .arg(dir.join("complete"));
        c
    })
    .await;
    let port = d.port;

    let dir2 = dir.clone();
    tokio::task::spawn_blocking(move || {
        fn b64(data: &[u8]) -> String {
            const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            let mut out = String::new();
            for c in data.chunks(3) {
                let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
                let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
                out.push(A[(n >> 18) as usize & 63] as char);
                out.push(A[(n >> 12) as usize & 63] as char);
                out.push(if c.len() > 1 { A[(n >> 6) as usize & 63] as char } else { '=' });
                out.push(if c.len() > 2 { A[n as usize & 63] as char } else { '=' });
            }
            out
        }
        // POST /jsonrpc with HTTP Basic `x:<pw>`; return the HTTP status code.
        let rpc = |pw: &str, method: &str, params: &str| -> u16 {
            let cred = b64(format!("x:{pw}").as_bytes());
            let body = format!("{{\"method\":\"{method}\",\"params\":{params},\"id\":1}}");
            let mut request = Vec::new();
            write!(
                request,
                "POST /jsonrpc HTTP/1.1\r\nHost: x\r\nConnection: close\r\nAuthorization: Basic {cred}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                body.len()
            )
            .unwrap();
            request.extend_from_slice(body.as_bytes());
            let out = String::from_utf8_lossy(&raw(port, &request)).to_string();
            out.split_whitespace().nth(1).and_then(|c| c.parse().ok()).unwrap_or(0)
        };

        // Add-only key: the permitted methods work...
        assert_eq!(rpc("addkey", "version", "[]"), 200, "add-only version allowed");
        // ...but every control method is refused with 403.
        assert_eq!(
            rpc("addkey", "editqueue", "[\"GroupFinalDelete\",[1]]"),
            403,
            "add-only key must NOT delete the queue via /jsonrpc"
        );
        assert_eq!(rpc("addkey", "rate", "[100]"), 403, "add-only rate must be forbidden");
        assert_eq!(rpc("addkey", "pausedownload", "[]"), 403, "add-only pause must be forbidden");
        assert_eq!(rpc("addkey", "config", "[]"), 403, "add-only config must be forbidden");

        // Full key: control methods are NOT blocked (not 401/403).
        assert_ne!(rpc("fullkey", "editqueue", "[\"GroupFinalDelete\",[1]]"), 403);
        assert_ne!(rpc("fullkey", "editqueue", "[\"GroupFinalDelete\",[1]]"), 401);

        // Wrong password: rejected outright.
        assert_eq!(rpc("bogus", "version", "[]"), 401, "wrong key rejected");
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir2);
}

/// M23 Smart Folders + cleanup rules, end to end: rules set live via the
/// config API route an UNcategorized upload to its category, junk files
/// are deleted after completion, and the finished job is filed as
/// [Show]/Season NN/ with the video renamed "Show - S01E02.ext".
#[tokio::test(flavor = "multi_thread")]
async fn smart_folders_and_cleanup() {
    let dir = std::env::temp_dir().join(format!("nzbfast-smart-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    // Two files on the mock server: the episode video + an .sfv the
    // cleanup rule should delete.
    let stem = "My.Show.S01E02.1080p.WEB.x264-TEST";
    let video = payload(300_000, 7);
    let junk = payload(20_000, 9);
    let mut articles = HashMap::new();
    let vsegs =
        make_file_articles(&format!("{stem}.mkv"), &video, 40_000, "vid", &mut articles);
    let jsegs =
        make_file_articles(&format!("{stem}.sfv"), &junk, 40_000, "junk", &mut articles);
    let srv = MockServer::start(articles, Chaos::default()).await;

    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
    );
    for (name, segs) in [(format!("{stem}.mkv"), &vsegs), (format!("{stem}.sfv"), &jsegs)] {
        xml.push_str(&format!(
            "  <file poster=\"x\" date=\"0\" subject=\"&quot;{name}&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
            segs.len()
        ));
        for (id, bytes, num) in segs.iter() {
            xml.push_str(&format!(
                "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
            ));
        }
        xml.push_str("    </segments>\n  </file>\n");
    }
    xml.push_str("</nzb>\n");

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
    // The .sfv below is a real delete by the real binary: keep it out of
    // the developer's Trash.
    delete_without_the_trash(&cfg);
    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            .arg("--config")
            .arg(&cfg)
            .arg("serve")
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--apikey")
            .arg("sekrit")
            .arg("--out")
            .arg(dir.join("complete"));
        c
    })
    .await;
    let port = d.port;

    let dir2 = dir.clone();
    tokio::task::spawn_blocking(move || {
        // %-encode a config value for the query string.
        let pct = |s: &str| -> String {
            s.bytes()
                .map(|b| {
                    if b.is_ascii_alphanumeric() {
                        (b as char).to_string()
                    } else {
                        format!("%{b:02X}")
                    }
                })
                .collect()
        };
        // Live settings via the config API: a rule (regex + size floor,
        // first-match-wins is unit-tested) and the cleanup list.
        let rule = r#"[{"name":"myshow","match":"^My\\.Show\\.","not_match":"720p","min_size":"100K","category":"tv","tv_sort":true}]"#;
        let r = http(
            port,
            &format!("/api?mode=config&name=smart_folders&value={}&apikey=sekrit&output=json", pct(rule)),
            None,
        );
        assert!(r.contains("\"status\":true"), "{r}");
        let r = http(
            port,
            &format!("/api?mode=config&name=cleanup_exts&value={}&apikey=sekrit&output=json", pct("par2, sfv")),
            None,
        );
        assert!(r.contains("\"status\":true"), "{r}");

        // Upload WITHOUT a category - the smart rule must pick "tv".
        let boundary = "----nzbfastboundary";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"{stem}.nzb\"\r\nContent-Type: application/x-nzb\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(xml.as_bytes());
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let ctype = format!("multipart/form-data; boundary={boundary}");
        let r = http(port, "/api?mode=addfile&apikey=sekrit&output=json", Some((&ctype, &body)));
        assert!(r.contains("nzo_ids"), "{r}");

        let mut hist = String::new();
        for _ in 0..150 {
            hist = http(port, "/api?mode=history&apikey=sekrit&output=json", None);
            if hist.contains("\"Completed\"") || hist.contains("\"Failed\"") {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        assert!(hist.contains("\"Completed\""), "never completed: {hist}");

        // Filed as [Show]/Season NN/ under the rule's category, with the
        // video renamed and the .sfv cleaned up; the original job dir is
        // gone and history reports the final storage path. Auto-rename is
        // on by default and adds the " 1080p" quality tag to the episode -
        // unbracketed, since rename_quality_brackets defaults off.
        let dest = dir2.join("complete/tv/My Show/Season 01");
        assert_eq!(
            std::fs::read(dest.join("My Show - S01E02 1080p.mkv")).expect("renamed video"),
            payload(300_000, 7)
        );
        let left: Vec<_> = std::fs::read_dir(&dest)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.ends_with(".sfv"))
            .collect();
        assert!(left.is_empty(), "sfv survived cleanup: {left:?}");
        assert!(
            !dir2.join(format!("complete/tv/{stem}")).exists(),
            "original job dir should be gone"
        );
        assert!(hist.contains("Season 01"), "history path not updated: {hist}");

        // N7: Play on this finished row must serve THIS episode. A filed
        // job's out_dir is the SHARED season folder, and the completed
        // branch used to serve "the biggest media file in out_dir" - so a
        // larger sibling sitting beside it (the user's own E03 here) was
        // what came back when you pressed play on E02.
        let sibling = dest.join("My Show - S01E03 1080p.mkv");
        std::fs::write(&sibling, payload(900_000, 13)).unwrap();
        let id = hist
            .split("\"nzo_id\":\"")
            .nth(1)
            .and_then(|s| s.split('"').next())
            .unwrap_or_else(|| panic!("no nzo_id in history: {hist}"))
            .to_string();
        let resp = raw(
            port,
            format!("GET /stream/{id}?apikey=sekrit HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        );
        let cut = resp.windows(4).position(|w| w == b"\r\n\r\n").expect("no headers") + 4;
        let (head, served) = resp.split_at(cut);
        let head = String::from_utf8_lossy(head).to_string();
        assert!(head.contains("200 OK"), "{head}");
        assert_eq!(
            served.len(),
            300_000,
            "served the wrong file - {} bytes is the sibling episode",
            served.len()
        );
        assert_eq!(served, &payload(300_000, 7)[..], "served bytes are not this episode's");
        assert!(sibling.exists(), "playing must not disturb the sibling");
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// Reported against 1.0.9: an F1 round finished as
/// "1fRbH6e0eX8v5hv7fSyXgBb.mkv" with every rename option ticked. The
/// smart renamer declines event posts on purpose (every round would
/// reduce to "Formula1 (2026)" and collide), but the decline must not
/// leave an obfuscated stem sitting inside a perfectly named folder.
#[tokio::test(flavor = "multi_thread")]
async fn obfuscated_event_release_still_gets_named() {
    let dir = std::env::temp_dir().join(format!("nzbfast-obf-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    // The job carries the real release name; the article inside does not.
    let rel = "Formula1.2026.Round11.Hungary.Race.F1TV.WEB-DL.2160p.HLG.H265.DDP5.1.English-MWR";
    let inner = "1fRbH6e0eX8v5hv7fSyXgBb";
    let video = payload(200_000, 21);
    let mut articles = HashMap::new();
    let vsegs =
        make_file_articles(&format!("{inner}.mkv"), &video, 40_000, "obf", &mut articles);
    let srv = MockServer::start(articles, Chaos::default()).await;

    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
    );
    xml.push_str(&format!(
        "  <file poster=\"x\" date=\"0\" subject=\"&quot;{inner}.mkv&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
        vsegs.len()
    ));
    for (id, bytes, num) in vsegs.iter() {
        xml.push_str(&format!(
            "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
        ));
    }
    xml.push_str("    </segments>\n  </file>\n</nzb>\n");

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
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--apikey")
            .arg("sekrit")
            .arg("--out")
            .arg(dir.join("complete"));
        c
    })
    .await;
    let port = d.port;

    let dir2 = dir.clone();
    tokio::task::spawn_blocking(move || {
        // Pin the de-obfuscation fallback specifically: with extra words
        // ON (the default) this release is named from its own event
        // words instead, which obfuscated_event_release_keeps_its_words
        // covers.
        let r = http(
            port,
            "/api?mode=config&name=rename_extra_words&value=0&apikey=sekrit&output=json",
            None,
        );
        assert!(r.contains("\"status\":true"), "{r}");

        let boundary = "----nzbfastboundary";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"{rel}.nzb\"\r\nContent-Type: application/x-nzb\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(xml.as_bytes());
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let ctype = format!("multipart/form-data; boundary={boundary}");
        let r = http(port, "/api?mode=addfile&apikey=sekrit&output=json", Some((&ctype, &body)));
        assert!(r.contains("nzo_ids"), "{r}");

        let mut hist = String::new();
        for _ in 0..150 {
            hist = http(port, "/api?mode=history&apikey=sekrit&output=json", None);
            if hist.contains("\"Completed\"") || hist.contains("\"Failed\"") {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        assert!(hist.contains("\"Completed\""), "never completed: {hist}");

        // The folder keeps the release name (it always did); the point of
        // the fix is that the VIDEO now does too, instead of staying
        // "1fRbH6e0eX8v5hv7fSyXgBb.mkv".
        let job = dir2.join("complete").join(rel);
        assert_eq!(
            std::fs::read(job.join(format!("{rel}.mkv"))).expect("video renamed to the release"),
            payload(200_000, 21)
        );
        assert!(
            !job.join(format!("{inner}.mkv")).exists(),
            "obfuscated stem survived"
        );
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// The other half of the F1 report: with rename_extra_words on (the
/// default) the event is named from the words that distinguish it, so a
/// whole season does not collapse onto one folder.
#[tokio::test(flavor = "multi_thread")]
async fn obfuscated_event_release_keeps_its_words() {
    let dir = std::env::temp_dir().join(format!("nzbfast-evw-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let rel = "Formula1.2026.Round11.Hungary.Race.F1TV.WEB-DL.2160p.HLG.H265.DDP5.1.English-MWR";
    let inner = "1fRbH6e0eX8v5hv7fSyXgBb";
    let video = payload(200_000, 21);
    let mut articles = HashMap::new();
    let vsegs =
        make_file_articles(&format!("{inner}.mkv"), &video, 40_000, "evw", &mut articles);
    let srv = MockServer::start(articles, Chaos::default()).await;

    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
    );
    xml.push_str(&format!(
        "  <file poster=\"x\" date=\"0\" subject=\"&quot;{inner}.mkv&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
        vsegs.len()
    ));
    for (id, bytes, num) in vsegs.iter() {
        xml.push_str(&format!(
            "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
        ));
    }
    xml.push_str("    </segments>\n  </file>\n</nzb>\n");

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
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--apikey")
            .arg("sekrit")
            .arg("--out")
            .arg(dir.join("complete"));
        c
    })
    .await;
    let port = d.port;

    let dir2 = dir.clone();
    tokio::task::spawn_blocking(move || {
        let cfg = http(port, "/api?mode=get_config&apikey=sekrit&output=json", None);
        assert!(cfg.contains("\"rename_extra_words\":true"), "should default on: {cfg}");

        let boundary = "----nzbfastboundary";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"{rel}.nzb\"\r\nContent-Type: application/x-nzb\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(xml.as_bytes());
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let ctype = format!("multipart/form-data; boundary={boundary}");
        let r = http(port, "/api?mode=addfile&apikey=sekrit&output=json", Some((&ctype, &body)));
        assert!(r.contains("nzo_ids"), "{r}");

        let mut hist = String::new();
        for _ in 0..150 {
            hist = http(port, "/api?mode=history&apikey=sekrit&output=json", None);
            if hist.contains("\"Completed\"") || hist.contains("\"Failed\"") {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        assert!(hist.contains("\"Completed\""), "never completed: {hist}");

        let tidy = "Formula1 2026 Round11 Hungary Race F1TV 2160p";
        let job = dir2.join("complete").join(tidy);
        assert!(
            job.is_dir(),
            "expected the event named from its own words; complete/ holds {:?}",
            std::fs::read_dir(dir2.join("complete"))
                .unwrap()
                .flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            std::fs::read(job.join(format!("{tidy}.mkv"))).expect("video matches the folder"),
            payload(200_000, 21)
        );
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// M24 passworded archives, end to end: an encrypted-header RAR
/// completes with password_required flagged in history; set_password
/// attempts an unlock (and reports a wrong password); NZB-meta and
/// "Name{{pw}}" passwords are captured at enqueue.
#[tokio::test(flavor = "multi_thread")]
async fn passworded_archive_flow() {
    let dir = std::env::temp_dir().join(format!("nzbfast-pw-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    // Three posts: an encrypted-header rar, and two plain bins for the
    // password-source paths (NZB meta / name convention).
    let locked = nzbkit::rar::fixtures::rar4_encrypted_headers(4096);
    let plain = payload(60_000, 11);
    let mut articles = HashMap::new();
    let lsegs = make_file_articles(
        "Locked.Release.2026.rar",
        &locked,
        40_000,
        "lk",
        &mut articles,
    );
    let msegs = make_file_articles("meta.bin", &plain, 40_000, "mt", &mut articles);
    let nsegs = make_file_articles("named.bin", &plain, 40_000, "nm", &mut articles);
    let srv = MockServer::start(articles, Chaos::default()).await;

    let nzb_for = |fname: &str, segs: &[(String, u64, u32)], head: &str| {
        let mut xml = format!(
            "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n{head}  <file poster=\"x\" date=\"0\" subject=\"&quot;{fname}&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
            segs.len()
        );
        for (id, bytes, num) in segs {
            xml.push_str(&format!(
                "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
            ));
        }
        xml.push_str("    </segments>\n  </file>\n</nzb>\n");
        xml
    };
    let locked_xml = nzb_for("Locked.Release.2026.rar", &lsegs, "");
    let meta_xml = nzb_for(
        "meta.bin",
        &msegs,
        "  <head><meta type=\"password\">metapw</meta></head>\n",
    );
    let named_xml = nzb_for("named.bin", &nsegs, "");

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
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--apikey")
            .arg("sekrit")
            .arg("--out")
            .arg(dir.join("complete"));
        c
    })
    .await;
    let port = d.port;

    let dir2 = dir.clone();
    tokio::task::spawn_blocking(move || {
        let addfile = |nzb_name: &str, xml: &str| {
            let boundary = "----nzbfastboundary";
            let mut body = Vec::new();
            body.extend_from_slice(
                format!(
                    "--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"{nzb_name}\"\r\nContent-Type: application/x-nzb\r\n\r\n"
                )
                .as_bytes(),
            );
            body.extend_from_slice(xml.as_bytes());
            body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
            let ctype = format!("multipart/form-data; boundary={boundary}");
            let r = http(port, "/api?mode=addfile&apikey=sekrit&output=json", Some((&ctype, &body)));
            assert!(r.contains("nzo_ids"), "{r}");
        };
        addfile("Locked.Release.2026.nzb", &locked_xml);
        addfile("Meta.Release.nzb", &meta_xml);
        addfile("Named.Release{{n4me pw}}.nzb", &named_xml);

        // All three land in history.
        let slots = |h: &str| -> Vec<serde_json::Value> {
            serde_json::from_str::<serde_json::Value>(h)
                .ok()
                .and_then(|v| v["history"]["slots"].as_array().cloned())
                .unwrap_or_default()
        };
        let mut done = Vec::new();
        for _ in 0..150 {
            let h = http(port, "/api?mode=history&apikey=sekrit&output=json", None);
            done = slots(&h);
            if done.len() == 3 && done.iter().all(|s| s["status"] == "Completed") {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        assert_eq!(done.len(), 3, "not all jobs completed: {done:?}");
        let by_name = |name: &str| -> serde_json::Value {
            done.iter().find(|s| s["name"] == name).cloned().unwrap_or_else(|| {
                panic!("no history slot named {name}: {done:?}")
            })
        };

        // Encrypted set: flagged, volumes intact on disk.
        let locked_slot = by_name("Locked.Release.2026");
        assert_eq!(locked_slot["password_required"], true, "{locked_slot}");
        assert!(
            dir2.join("complete/Locked.Release.2026/Locked.Release.2026.rar").exists(),
            "verified volume must stay on disk"
        );
        // NZB meta password captured; nothing to unlock on a plain bin.
        let meta_slot = by_name("Meta.Release");
        assert_eq!(meta_slot["has_password"], true, "{meta_slot}");
        assert_eq!(meta_slot["password_required"], false, "{meta_slot}");
        // "Name{{pw}}": password split out, clean job name.
        let named_slot = by_name("Named.Release");
        assert_eq!(named_slot["has_password"], true, "{named_slot}");

        // set_password on the locked job: accepted, background unlock
        // runs, and (our fixture being undecryptable) reports the
        // password didn't work while keeping the flag.
        let id = locked_slot["nzo_id"].as_str().unwrap();
        let r = http(
            port,
            &format!("/api?mode=set_password&value={id}&password=wrongpw&apikey=sekrit&output=json"),
            None,
        );
        assert!(r.contains("\"status\":true"), "{r}");
        let mut reported = false;
        for _ in 0..50 {
            let h = http(port, "/api?mode=history&apikey=sekrit&output=json", None);
            let s = slots(&h);
            if let Some(l) = s.iter().find(|s| s["name"] == "Locked.Release.2026") {
                if l["fail_message"].as_str().unwrap_or("").contains("did not unlock") {
                    assert_eq!(l["password_required"], true, "{l}");
                    reported = true;
                    break;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        assert!(reported, "wrong password never reported");
        // Unknown id rejected.
        let r = http(
            port,
            "/api?mode=set_password&value=nope&password=x&apikey=sekrit&output=json",
            None,
        );
        assert!(r.contains("unknown nzo_id"), "{r}");
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// Drag-to-reorder: `mode=queue&name=switch&value=<nzo_id>&value2=<pos>`
/// moves a queued job to that index (SAB parity for the dashboard's drag
/// handles). Out-of-range positions clamp; unknown ids are refused.
#[tokio::test(flavor = "multi_thread")]
async fn queue_switch_reorders() {
    let dir = std::env::temp_dir().join(format!("nzbfast-switch-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    // No articles needed - the queue stays paused, nothing downloads.
    let srv = MockServer::start(HashMap::new(), Chaos::default()).await;
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
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--apikey")
            .arg("sekrit")
            .arg("--out")
            .arg(dir.join("complete"));
        c
    })
    .await;
    let port = d.port;

    tokio::task::spawn_blocking(move || {
        http(port, "/api?mode=pause&apikey=sekrit&output=json", None);

        let upload = |name: &str| -> String {
            let xml = format!(
                "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file poster=\"x\" date=\"0\" subject=\"&quot;{name}&quot; yEnc (1/1)\">\n    <groups><group>g</group></groups>\n    <segments>\n      <segment bytes=\"1000\" number=\"1\">{name}@x</segment>\n    </segments>\n  </file>\n</nzb>\n"
            );
            let boundary = "----switchb";
            let mut body = Vec::new();
            body.extend_from_slice(
                format!("--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"{name}.nzb\"\r\n\r\n").as_bytes(),
            );
            body.extend_from_slice(xml.as_bytes());
            body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
            let r = http(
                port,
                "/api?mode=addfile&apikey=sekrit&output=json",
                Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
            );
            assert!(r.contains("\"status\":true"), "{r}");
            r.split("SABnzbd_nzo_").nth(1).unwrap().split('"').next()
                .map(|s| format!("SABnzbd_nzo_{s}")).unwrap()
        };
        let a = upload("sw-a.bin");
        let b = upload("sw-b.bin");
        let c = upload("sw-c.bin");

        let order = |q: &str| {
            let mut ids: Vec<(usize, &str)> = [&a, &b, &c]
                .iter()
                // Quote-anchored: nzo ids are sequential, so a bare find
                // of ...nzbfast1 would also match inside ...nzbfast10.
                .map(|id| (q.find(&format!("{id}\"")).expect("id in queue"), id.as_str()))
                .collect();
            ids.sort();
            ids.into_iter().map(|(_, id)| id.to_string()).collect::<Vec<_>>()
        };

        let q = http(port, "/api?mode=queue&apikey=sekrit&output=json", None);
        assert_eq!(order(&q), vec![a.clone(), b.clone(), c.clone()], "{q}");

        // Move c to the front.
        let r = http(
            port,
            &format!("/api?mode=queue&name=switch&value={c}&value2=0&apikey=sekrit&output=json"),
            None,
        );
        assert!(r.contains("\"status\":true") && r.contains("\"position\":0"), "{r}");
        let q = http(port, "/api?mode=queue&apikey=sekrit&output=json", None);
        assert_eq!(order(&q), vec![c.clone(), a.clone(), b.clone()], "{q}");

        // Out-of-range position clamps to the end.
        let r = http(
            port,
            &format!("/api?mode=queue&name=switch&value={c}&value2=99&apikey=sekrit&output=json"),
            None,
        );
        assert!(r.contains("\"status\":true") && r.contains("\"position\":2"), "{r}");
        let q = http(port, "/api?mode=queue&apikey=sekrit&output=json", None);
        assert_eq!(order(&q), vec![a.clone(), b.clone(), c.clone()], "{q}");

        // Unknown id is refused.
        let r = http(
            port,
            "/api?mode=queue&name=switch&value=SABnzbd_nzo_nope&value2=0&apikey=sekrit&output=json",
            None,
        );
        assert!(r.contains("\"status\":false"), "{r}");
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// Slow-job watchdog: a job whose articles live only on one SLOW server
/// (the other server 430s everything) is auto-deferred to the back of
/// the queue while a fast job waits - the fast job completes first, and
/// the deferred one then resumes from its journal and finishes too.
#[tokio::test(flavor = "multi_thread")]
async fn slow_single_server_job_deferred() {
    let dir = std::env::temp_dir().join(format!("nzbfast-defer-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    // Fast server: warmup + fast job articles, tiny per-article delay so
    // completed-job averages are measured over a real span. Slow server:
    // ONLY the slow job's articles, 250 ms per article (~160 KB/s at 2
    // connections vs multi-MB/s fast → far under the 40% threshold).
    let mut fast_articles = HashMap::new();
    // Big enough that its network phase lasts ≥0.5 s (the guard for
    // recording a completed-job average into the session-best rate).
    let warm_segs =
        make_file_articles("warm.bin", &payload(8_000_000, 7), 40_000, "wm", &mut fast_articles);
    let fastj_segs =
        make_file_articles("fastjob.bin", &payload(1_600_000, 9), 40_000, "fj", &mut fast_articles);
    let mut slow_articles = HashMap::new();
    let slow_segs = make_file_articles(
        "slowjob.bin",
        &payload(3_000_000, 11),
        20_000,
        "sj",
        &mut slow_articles,
    );
    let fast_srv = MockServer::start(
        fast_articles,
        Chaos { delay_ms: 10, ..Chaos::default() },
    )
    .await;
    let slow_srv = MockServer::start(
        slow_articles,
        Chaos { delay_ms: 250, ..Chaos::default() },
    )
    .await;

    let nzb_for = |name: &str, segs: &[(String, u64, u32)]| {
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
    };

    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        format!(
            "{{\"servers\":[{{\"host\":\"{}\",\"port\":{},\"tls\":false}},{{\"host\":\"{}\",\"port\":{},\"tls\":false}}]}}",
            fast_srv.addr.ip(),
            fast_srv.addr.port(),
            slow_srv.addr.ip(),
            slow_srv.addr.port()
        ),
    )
    .unwrap();
    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            .env("NZBFAST_DEFER_WARMUP_SECS", "2")
            .env("NZBFAST_DEFER_WINDOW_SECS", "3")
            .arg("--config")
            .arg(&cfg)
            .arg("serve")
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--apikey")
            .arg("sekrit")
            .arg("--out")
            .arg(dir.join("complete"))
            .arg("--connections")
            .arg("2");
        c
    })
    .await;
    let port = d.port;

    let (warm_xml, fast_xml, slow_xml) = (
        nzb_for("warm.bin", &warm_segs),
        nzb_for("fastjob.bin", &fastj_segs),
        nzb_for("slowjob.bin", &slow_segs),
    );
    tokio::task::spawn_blocking(move || {
        let upload = |xml: &str, fname: &str| -> String {
            let boundary = "----deferb";
            let mut body = Vec::new();
            body.extend_from_slice(
                format!("--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"{fname}\"\r\n\r\n").as_bytes(),
            );
            body.extend_from_slice(xml.as_bytes());
            body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
            let r = http(
                port,
                "/api?mode=addfile&apikey=sekrit&output=json",
                Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
            );
            assert!(r.contains("\"status\":true"), "{r}");
            r.split("SABnzbd_nzo_").nth(1).unwrap().split('"').next()
                .map(|s| format!("SABnzbd_nzo_{s}")).unwrap()
        };
        let poll = |pred: &dyn Fn(&str, &str) -> bool, what: &str| -> (String, String) {
            for _ in 0..300 {
                let q = http(port, "/api?mode=queue&apikey=sekrit&output=json", None);
                let h = http(port, "/api?mode=history&apikey=sekrit&output=json", None);
                if pred(&q, &h) {
                    return (q, h);
                }
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
            panic!("timed out waiting for {what}");
        };

        // Warmup on the fast server establishes the session-best rate.
        let warm_id = upload(&warm_xml, "warm.nzb");
        poll(&|_q, h| h.contains(&warm_id) && h.contains("Completed"), "warmup completion");

        // Slow job starts (only candidate); fast job queues behind it.
        let slow_id = upload(&slow_xml, "slowjob.nzb");
        poll(&|q, _h| q.contains(&slow_id) && q.contains("Downloading"), "slow job start");
        let fast_id = upload(&fast_xml, "fastjob.nzb");

        // The watchdog defers the slow job (warmup 2 s + window 3 s).
        let (q, _) = poll(
            &|q, _h| q.contains("\"deferred\":true"),
            "watchdog deferral of the slow job",
        );
        assert!(q.contains(&slow_id), "{q}");
        assert!(q.contains("defer_reason"), "{q}");

        // The fast job overtakes and completes while the slow one is
        // still pending.
        let (_, h) = poll(
            &|_q, h| h.contains(&fast_id) && h.contains("Completed"),
            "fast job completion",
        );
        assert!(
            !h.contains(&slow_id),
            "slow job should still be queued when the fast one lands: {h}"
        );

        // The deferred job then runs (only candidate left), resumes from
        // its journal, and completes.
        poll(
            &|_q, h| h.contains(&slow_id) && h.matches("Completed").count() >= 3,
            "deferred job eventual completion",
        );
    })
    .await
    .unwrap();
    assert_eq!(
        std::fs::read(dir.join("complete/slowjob/slowjob.bin")).unwrap(),
        payload(3_000_000, 11),
        "deferred job payload differs after journal resume"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Idle-server prefetch: while job A grinds on the slow server (the fast
/// server 430s all its articles), the idle fast server starts queued job
/// B in a sidecar pipeline - B completes while A is still downloading,
/// and A still finishes normally afterwards.
#[tokio::test(flavor = "multi_thread")]
async fn idle_servers_prefetch_next_job() {
    let dir = std::env::temp_dir().join(format!("nzbfast-prefetch-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    // Slow server: ONLY job A's articles, 250 ms each (~160 KB/s at 2
    // conns → A runs ~19 s). Fast server: ONLY job B's articles.
    let mut slow_articles = HashMap::new();
    let a_segs = make_file_articles(
        "slowa.bin",
        &payload(3_000_000, 21),
        20_000,
        "sa",
        &mut slow_articles,
    );
    let mut fast_articles = HashMap::new();
    let b_segs = make_file_articles(
        "fastb.bin",
        &payload(2_000_000, 23),
        40_000,
        "fb",
        &mut fast_articles,
    );
    let slow_srv = MockServer::start(
        slow_articles,
        Chaos { delay_ms: 250, ..Chaos::default() },
    )
    .await;
    // Mildly delayed so the sidecar run spans a few poll ticks - the test
    // wants to OBSERVE the transient "prefetching" flag, and an instant
    // localhost transfer finishes between two 200 ms polls.
    let fast_srv = MockServer::start(
        fast_articles,
        Chaos { delay_ms: 100, ..Chaos::default() },
    )
    .await;

    let nzb_for = |name: &str, segs: &[(String, u64, u32)]| {
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
    };

    let cfg = dir.join("config.json");
    // Distinct HOST STRINGS for the two loopback mocks ("localhost"
    // resolves to 127.0.0.1, and the connector prefers IPv4): host is
    // server identity throughout (exclusions, usage, stats), and the
    // sidecar's busy-host exclusion must not catch the idle server.
    std::fs::write(
        &cfg,
        format!(
            "{{\"servers\":[{{\"host\":\"127.0.0.1\",\"port\":{},\"tls\":false}},{{\"host\":\"localhost\",\"port\":{},\"tls\":false}}]}}",
            slow_srv.addr.port(),
            fast_srv.addr.port()
        ),
    )
    .unwrap();
    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            .env("NZBFAST_DEFER_WARMUP_SECS", "2")
            .env("NZBFAST_DEFER_WINDOW_SECS", "3")
            .arg("--config")
            .arg(&cfg)
            .arg("serve")
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--apikey")
            .arg("sekrit")
            .arg("--out")
            .arg(dir.join("complete"))
            .arg("--connections")
            .arg("2");
        c
    })
    .await;
    let port = d.port;

    let (a_xml, b_xml) = (nzb_for("slowa.bin", &a_segs), nzb_for("fastb.bin", &b_segs));
    tokio::task::spawn_blocking(move || {
        let upload = |xml: &str, fname: &str| -> String {
            let boundary = "----prefb";
            let mut body = Vec::new();
            body.extend_from_slice(
                format!("--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"{fname}\"\r\n\r\n").as_bytes(),
            );
            body.extend_from_slice(xml.as_bytes());
            body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
            let r = http(
                port,
                "/api?mode=addfile&apikey=sekrit&output=json",
                Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
            );
            assert!(r.contains("\"status\":true"), "{r}");
            r.split("SABnzbd_nzo_").nth(1).unwrap().split('"').next()
                .map(|s| format!("SABnzbd_nzo_{s}")).unwrap()
        };
        let poll = |pred: &dyn Fn(&str, &str) -> bool, what: &str| -> (String, String) {
            for _ in 0..300 {
                let q = http(port, "/api?mode=queue&apikey=sekrit&output=json", None);
                let h = http(port, "/api?mode=history&apikey=sekrit&output=json", None);
                if pred(&q, &h) {
                    return (q, h);
                }
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
            panic!("timed out waiting for {what}");
        };

        // A starts (only job); B queues behind it.
        let a_id = upload(&a_xml, "slowa.nzb");
        poll(&|q, _| q.contains(&a_id) && q.contains("Downloading"), "job A start");
        let b_id = upload(&b_xml, "fastb.nzb");

        // The fast server is idle for A → sidecar starts B; the queue
        // reports it as prefetching.
        let (q, _) = poll(&|q, _| q.contains("\"prefetching\":true"), "sidecar start");
        assert!(q.contains(&b_id), "{q}");

        // B completes entirely on the idle server WHILE A still runs.
        let (q, h) = poll(
            &|_, h| h.contains(&b_id) && h.contains("Completed"),
            "B completion via sidecar",
        );
        assert!(
            q.contains(&a_id) && q.contains("Downloading"),
            "A should still be downloading when B lands: {q}"
        );
        assert!(!h.contains(&a_id), "{h}");

        // A still finishes normally on its slow server.
        poll(
            &|_, h| h.contains(&a_id) && h.matches("Completed").count() >= 2,
            "A eventual completion",
        );
    })
    .await
    .unwrap();
    assert_eq!(
        std::fs::read(dir.join("complete/fastb/fastb.bin")).unwrap(),
        payload(2_000_000, 23),
        "sidecar-completed payload differs"
    );
    assert_eq!(
        std::fs::read(dir.join("complete/slowa/slowa.bin")).unwrap(),
        payload(3_000_000, 21),
        "slow job payload differs"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Connection borrowing when the ONLY idle server is dead: one healthy
/// server carries job A while the second rejects authentication. The
/// dead server moves no bytes, so by the byte test it looks idle - but a
/// sidecar built on it alone prefetches nothing (seen live in a
/// queue soak, 31 Jul, where this cost 34% line-idle), and simply
/// skipping the spawn loses the tail-overlap entirely (49 s line-idle of
/// a 144 s queue in that state). The monitor must instead borrow a
/// BOUNDED slice of the healthy busy server - here 2 of the account's
/// 8-connection headroom next to the active job's 4 - never the dead
/// one, and B completes on that slice while A still downloads at its
/// own full fleet.
#[tokio::test(flavor = "multi_thread")]
async fn prefetch_borrows_from_the_busy_server_when_no_healthy_idle() {
    let dir = std::env::temp_dir().join(format!("nzbfast-prefdead-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    // Healthy server: A's AND B's articles, 250 ms each so A's run is
    // wide enough for the monitor's warmup+window to elapse. Dead
    // server: no articles, rejects every AUTHINFO.
    let mut articles = HashMap::new();
    let a_segs =
        make_file_articles("slowa.bin", &payload(4_000_000, 71), 20_000, "da", &mut articles);
    let b_segs =
        make_file_articles("afterb.bin", &payload(400_000, 73), 40_000, "db", &mut articles);
    let good_srv =
        MockServer::start(articles, Chaos { delay_ms: 250, ..Chaos::default() }).await;
    let dead_srv =
        MockServer::start(HashMap::new(), Chaos { auth_rejected: true, ..Chaos::default() })
            .await;

    let nzb_for = |name: &str, segs: &[(String, u64, u32)]| {
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
    };

    let cfg = dir.join("config.json");
    // Credentials on the dead server so the client actually sends the
    // AUTHINFO the mock refuses; distinct host strings as elsewhere.
    std::fs::write(
        &cfg,
        format!(
            "{{\"servers\":[{{\"host\":\"127.0.0.1\",\"port\":{},\"tls\":false}},{{\"host\":\"localhost\",\"port\":{},\"tls\":false,\"username\":\"u\",\"password\":\"wrong\"}}]}}",
            good_srv.addr.port(),
            dead_srv.addr.port()
        ),
    )
    .unwrap();
    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            .env("NZBFAST_DEFER_WARMUP_SECS", "2")
            .env("NZBFAST_DEFER_WINDOW_SECS", "3")
            .arg("--config")
            .arg(&cfg)
            .arg("serve")
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--apikey")
            .arg("sekrit")
            .arg("--out")
            .arg(dir.join("complete"))
            .arg("--connections")
            .arg("4");
        c
    })
    .await;
    let port = d.port;
    let log_path = d.log.clone();

    let (a_xml, b_xml) = (nzb_for("slowa.bin", &a_segs), nzb_for("afterb.bin", &b_segs));
    let b_id = tokio::task::spawn_blocking(move || {
        let upload = |xml: &str, fname: &str| -> String {
            let boundary = "----prefd";
            let mut body = Vec::new();
            body.extend_from_slice(
                format!("--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"{fname}\"\r\n\r\n").as_bytes(),
            );
            body.extend_from_slice(xml.as_bytes());
            body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
            let r = http(
                port,
                "/api?mode=addfile&apikey=sekrit&output=json",
                Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
            );
            assert!(r.contains("\"status\":true"), "{r}");
            r.split("SABnzbd_nzo_").nth(1).unwrap().split('"').next()
                .map(|s| format!("SABnzbd_nzo_{s}")).unwrap()
        };
        let poll = |pred: &dyn Fn(&str, &str) -> bool, what: &str| -> (String, String) {
            for _ in 0..300 {
                let q = http(port, "/api?mode=queue&apikey=sekrit&output=json", None);
                let h = http(port, "/api?mode=history&apikey=sekrit&output=json", None);
                if pred(&q, &h) {
                    return (q, h);
                }
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
            panic!("timed out waiting for {what}");
        };

        // A starts (only job); B queues behind it.
        let a_id = upload(&a_xml, "slowa.nzb");
        poll(&|q, _| q.contains(&a_id) && q.contains("Downloading"), "job A start");
        let b_id = upload(&b_xml, "afterb.nzb");

        // The monitor notes the dead idle server and borrows from the
        // busy one instead - the log carries both decisions.
        for i in 0..300 {
            let log = std::fs::read_to_string(&log_path).unwrap_or_default();
            if log.contains("borrowing from the busy server(s) instead") {
                break;
            }
            assert!(i < 299, "the monitor never noted the refused idle server:\n{log}");
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        let log = std::fs::read_to_string(&log_path).unwrap_or_default();
        let borrow_line = log
            .lines()
            .find(|l| l.contains("borrowing connection(s) from busy server(s)"))
            .unwrap_or_else(|| panic!("no borrow spawn in the log:\n{log}"))
            .to_string();
        // The slice is bounded (2 = headroom cap, not the fleet's 4) and
        // built ONLY on the healthy busy host - never the refused one.
        assert!(borrow_line.contains("127.0.0.1 x2"), "wrong borrow slice: {borrow_line}");
        assert!(!borrow_line.contains("localhost"), "borrowed the dead server: {borrow_line}");

        // B completes on the borrowed slice WHILE A still downloads.
        let (q, _) = poll(
            &|_, h| h.contains(&b_id) && h.contains("Completed"),
            "B completion via borrowed sidecar",
        );
        assert!(
            q.contains(&a_id) && q.contains("Downloading"),
            "A should still be downloading when B lands: {q}"
        );

        // A still completes normally at its own pace: the borrow must
        // not have cost A its fleet. 200 articles at 250 ms over 4
        // connections is ~12.5 s connection-bound; a sidecar that stole
        // half the fleet would push A toward 25 s. Generous margin for
        // connect overhead and a loaded CI box, but well under starved.
        let (_, h) = poll(
            &|_, h| h.contains(&a_id) && h.matches("Completed").count() >= 2,
            "A completion",
        );
        // Keys serialize alphabetically, so a slot's elapsed_secs sits
        // BEFORE its nzo_id: the last one preceding A's id is A's.
        let a_elapsed: f64 = h
            .split(&a_id)
            .next()
            .and_then(|s| s.rsplit("\"elapsed_secs\":").next())
            .and_then(|s| s.trim().split(',').next())
            .and_then(|s| s.trim().parse().ok())
            .unwrap_or_else(|| panic!("no elapsed_secs for A in history: {h}"));
        assert!(
            a_elapsed < 19.0,
            "active job slowed to {a_elapsed:.1}s (ideal ~12.5s) - the borrow starved it"
        );
        b_id
    })
    .await
    .unwrap();

    let log = std::fs::read_to_string(&d.log).unwrap_or_default();
    assert!(
        log.contains(&format!("[prefetch] {b_id} completed entirely on borrowed connections")),
        "B was not finished by the borrowed sidecar:\n{log}"
    );
    // The budget never double-counted: the healthy server saw the active
    // job's 4 connections plus at most the 2 borrowed ones - a sidecar
    // that built a FULL second fleet (or a primary re-run of B) would
    // push this to 8+.
    let conns = good_srv.accepted.load(std::sync::atomic::Ordering::Relaxed);
    assert!(
        (4..=7).contains(&conns),
        "healthy server saw {conns} connections, want the 4-conn fleet + ≤2 borrowed + slack"
    );
    assert_eq!(
        std::fs::read(dir.join("complete/afterb/afterb.bin")).unwrap(),
        payload(400_000, 73),
        "B payload differs"
    );
    assert_eq!(
        std::fs::read(dir.join("complete/slowa/slowa.bin")).unwrap(),
        payload(4_000_000, 71),
        "A payload differs"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// M23e: pause stops the ACTIVE transfer, not just new jobs. The
/// in-flight job aborts and suspends back to Queued (never into history
/// as Failed), and resume finishes it from the article journal -
/// byte-identical output.
#[tokio::test(flavor = "multi_thread")]
async fn pause_suspends_active_download() {
    let dir = std::env::temp_dir().join(format!("nzbfast-pause-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    // 2 MB at a 250 KB/s cap ≈ 8 s of transfer - a wide pause window.
    let data = payload(2_000_000, 9);
    let mut articles = HashMap::new();
    let segs = make_file_articles("suspend.bin", &data, 40_000, "pz", &mut articles);
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
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--out")
            .arg(dir.join("complete"))
            .arg("--speedlimit")
            .arg("250K")
            .arg("--connections")
            .arg("2");
        c
    })
    .await;
    let port = d.port;

    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file poster=\"x\" date=\"0\" subject=\"&quot;suspend.bin&quot; yEnc (1/50)\">\n    <groups><group>g</group></groups>\n    <segments>\n",
    );
    for (id, bytes, num) in &segs {
        xml.push_str(&format!(
            "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
        ));
    }
    xml.push_str("    </segments>\n  </file>\n</nzb>\n");

    tokio::task::spawn_blocking(move || {
        let boundary = "----nzbfastboundary";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"suspend.nzb\"\r\nContent-Type: application/x-nzb\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(xml.as_bytes());
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let ctype = format!("multipart/form-data; boundary={boundary}");
        let r = http(port, "/api?mode=addfile&output=json", Some((&ctype, &body)));
        assert!(r.contains("\"status\":true"), "{r}");

        // Wait for the transfer to actually start.
        // Slot-level status only: the queue-level "status" reads
        // "Downloading" whenever ANY slot exists. A slot object renders
        // "status":"...","timeleft":... (alphabetical keys), so anchor
        // on that pair.
        let slot_downloading = |q: &str| q.contains("\"status\":\"Downloading\",\"timeleft\"");
        let mut started = false;
        for _ in 0..50 {
            let q = http(port, "/api?mode=queue&output=json", None);
            if slot_downloading(&q) {
                started = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        assert!(started, "download never started");

        // PAUSE: the active job must leave Downloading and go back to
        // Queued - and must NOT appear in history as Failed.
        let r = http(port, "/api?mode=pause&output=json", None);
        assert!(r.contains("\"status\":true"), "{r}");
        // IMMEDIATE feedback: the suspended slot reads Paused within a
        // second of the pause ack (not Downloading until the pipeline
        // finishes unwinding).
        let mut fast = false;
        for _ in 0..5 {
            let q = http(port, "/api?mode=queue&output=json", None);
            if q.contains("\"status\":\"Paused\",\"timeleft\"") {
                fast = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        assert!(fast, "pause not reflected as Paused within 1 s");
        let mut suspended = false;
        for _ in 0..50 {
            let q = http(port, "/api?mode=queue&output=json", None);
            if q.contains("\"paused\":true") && !slot_downloading(&q) && q.contains("suspend") {
                suspended = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        assert!(suspended, "pause did not suspend the active download");
        let h = http(port, "/api?mode=history&output=json", None);
        assert!(
            !h.contains("Failed") && !h.contains("Completed"),
            "suspended job leaked into history: {h}"
        );
        // Still suspended a moment later (nothing restarted it).
        std::thread::sleep(std::time::Duration::from_millis(1200));
        let q = http(port, "/api?mode=queue&output=json", None);
        assert!(!slot_downloading(&q), "job restarted while paused: {q}");

        // RESUME: finishes from the journal.
        let r = http(port, "/api?mode=resume&output=json", None);
        assert!(r.contains("\"status\":true"), "{r}");
        let mut done = false;
        for _ in 0..300 {
            let h = http(port, "/api?mode=history&output=json", None);
            assert!(!h.contains("\"Failed\""), "resume failed: {h}");
            if h.contains("\"Completed\"") {
                done = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        assert!(done, "resumed download never completed");
    })
    .await
    .unwrap();

    assert_eq!(
        std::fs::read(dir.join("complete/suspend/suspend.bin")).unwrap(),
        data,
        "resumed output not byte-identical"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Live settings changed via mode=config must survive a daemon restart:
/// each set persists to settings.json immediately, and startup restores
/// it. (The auto_* bools plus update_checks/update_url/index_deepen/
/// bench_interval used to be set-but-never-restored - a restart silently
/// reverted them to defaults while settings.json still showed the
/// user's choice.)
#[tokio::test(flavor = "multi_thread")]
async fn live_settings_survive_restart() {
    let dir = std::env::temp_dir().join(format!("nzbfast-liveset-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    // A server entry is required by config load; nothing connects to it
    // in this test (no jobs are queued), so a dead port is fine.
    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        format!("{{\"servers\":[{{\"host\":\"127.0.0.1\",\"port\":{},\"tls\":false}}]}}", free_port()),
    )
    .unwrap();
    let build = |port: u16| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
            .arg("--config")
            .arg(&cfg)
            .arg("serve")
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--apikey")
            .arg("sekrit")
            .arg("--out")
            .arg(dir.join("complete"));
        c
    };

    // Every value differs from its startup default. update_url set to
    // empty exercises the meaningful-empty case (= checks disabled).
    let sets: &[(&str, &str)] = &[
        ("auto_speed", "0"),
        ("auto_defer", "0"),
        ("auto_prefetch", "0"),
        ("auto_connections", "0"),
        ("update_checks", "0"),
        ("update_url", ""),
        ("index_deepen", "123456"),
        ("bench_interval", "6"),
        // 24D user categories: URL-encoded
        // [{"slug":"formula-1","name":"Formula 1","match":"formula1","base":"movie"}]
        (
            "custom_categories",
            "%5B%7B%22slug%22%3A%22formula-1%22%2C%22name%22%3A%22Formula%201%22%2C%22match%22%3A%22formula1%22%2C%22base%22%3A%22movie%22%7D%5D",
        ),
        // Opt-in indexing: the interest keys the user chose. Unknown
        // keys are dropped, so what comes back is exactly the offered
        // set they asked for and nothing else.
        ("index_interests", "linux%2Csports%2Cnot-a-thing"),
        // 24D: a watchlist entry targeting that category - kind is the
        // slug, and a year pin is legal on it (an event post's year is
        // its season).
        (
            "watchlist",
            "%5B%7B%22id%22%3A1%2C%22kind%22%3A%22formula-1%22%2C%22title%22%3A%22Formula1%22%2C%22year%22%3A2026%2C%22seasons%22%3A%22%22%2C%22episodes%22%3A%22%22%2C%22min_quality%22%3A%22any%22%2C%22target_quality%22%3A%221080p%22%2C%22upgrade%22%3Atrue%2C%22delete_old%22%3Afalse%2C%22category%22%3A%22sport%22%2C%22enabled%22%3Atrue%7D%5D",
        ),
    ];
    let expect: &[&str] = &[
        "\"auto_speed\":false",
        "\"auto_defer\":false",
        "\"auto_prefetch\":false",
        "\"auto_connections\":false",
        "\"update_checks\":false",
        "\"update_url\":\"\"",
        "\"index_deepen\":123456",
        "\"bench_interval\":6",
        "\"slug\":\"formula-1\"",
        "\"base\":\"movie\"",
        "\"kind\":\"formula-1\"",
        "\"title\":\"Formula1\"",
        "\"index_interests\":\"linux,sports\"",
    ];

    let a = serve(&dir, &build).await;
    let port_a = a.port;
    tokio::task::spawn_blocking(move || {
        for (name, value) in sets {
            let r = http(
                port_a,
                &format!("/api?mode=config&name={name}&value={value}&apikey=sekrit&output=json"),
                None,
            );
            assert!(r.contains("\"status\":true"), "set {name}: {r}");
        }
        // Applied live before any restart.
        let c = http(port_a, "/api?mode=get_config&apikey=sekrit&output=json", None);
        for e in expect {
            assert!(c.contains(e), "live after set, missing {e}: {c}");
        }
        // 24D: a category slug shadowing a built-in kind is refused, and
        // the refusal must not clobber the saved list.
        let r = http(
            port_a,
            "/api?mode=config&name=custom_categories&value=%5B%7B%22slug%22%3A%22movie%22%2C%22match%22%3A%22x%22%7D%5D&apikey=sekrit&output=json",
            None,
        );
        assert!(r.contains("built-in"), "reserved slug accepted: {r}");
        let c = http(port_a, "/api?mode=get_config&apikey=sekrit&output=json", None);
        assert!(c.contains("\"slug\":\"formula-1\""), "saved list clobbered: {c}");
    })
    .await
    .unwrap();
    // kill -9 (KillOnDrop kills and reaps): persistence must not depend
    // on a graceful shutdown.
    drop(a);

    let b = serve(&dir, &build).await;
    let port_b = b.port;
    tokio::task::spawn_blocking(move || {
        let c = http(port_b, "/api?mode=get_config&apikey=sekrit&output=json", None);
        for e in expect {
            assert!(c.contains(e), "lost across restart, missing {e}: {c}");
        }
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// A pause is a deliberate act, and a restart used to undo it silently:
/// the queue came back at full speed with nothing on screen saying the
/// user's choice had been dropped. An update, a crash or a reboot all hit
/// this, and a metered connection pays for it.
///
/// Four cases, because the naive fix breaks two of them:
///  - a plain pause survives a kill -9 (persistence cannot depend on a
///    graceful shutdown - a crash is exactly when it matters);
///  - a resume is not "no news", it clears the pause for good;
///  - a timed pause whose deadline passed while the daemon was down comes
///    back RUNNING - "pause for 30 minutes" is a statement about when
///    downloading may start again, not a fresh 30 minutes on every boot;
///  - `mode=shutdown` pauses the queue as part of winding down, and that
///    internal pause must NOT be recorded, or every clean quit would come
///    back paused.
#[tokio::test(flavor = "multi_thread")]
async fn pause_survives_restart() {
    let dir = std::env::temp_dir().join(format!("nzbfast-pausep-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    // Nothing connects to it (no jobs are queued), so a dead port is fine.
    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        format!("{{\"servers\":[{{\"host\":\"127.0.0.1\",\"port\":{},\"tls\":false}}]}}", free_port()),
    )
    .unwrap();
    let build = |port: u16| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
            .arg("--config")
            .arg(&cfg)
            .arg("serve")
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--out")
            .arg(dir.join("complete"));
        c
    };
    let settings = dir.join("settings.json");
    let paused_now = |port: u16| {
        let q = http(port, "/api?mode=queue&output=json", None);
        assert!(q.contains("\"paused\":"), "no queue paused flag: {q}");
        q.contains("\"paused\":true")
    };

    // 1. PAUSE, then kill -9.
    let a = serve(&dir, &build).await;
    let port_a = a.port;
    tokio::task::spawn_blocking(move || {
        let r = http(port_a, "/api?mode=pause&output=json", None);
        assert!(r.contains("\"status\":true"), "{r}");
        assert!(paused_now(port_a), "pause did not take effect");
    })
    .await
    .unwrap();
    drop(a);

    // Still paused on the next boot - the whole point.
    let b = serve(&dir, &build).await;
    let port_b = b.port;
    tokio::task::spawn_blocking(move || {
        assert!(paused_now(port_b), "pause was lost across a restart");
        // 2. RESUME, so the next boot must come back running.
        let r = http(port_b, "/api?mode=resume&output=json", None);
        assert!(r.contains("\"status\":true"), "{r}");
        assert!(!paused_now(port_b), "resume did not take effect");
    })
    .await
    .unwrap();
    drop(b);
    let s = std::fs::read_to_string(&settings).unwrap_or_default();
    assert!(!s.contains("\"paused\""), "resume left a pause behind: {s}");

    let c = serve(&dir, &build).await;
    let port_c = c.port;
    tokio::task::spawn_blocking(move || {
        assert!(!paused_now(port_c), "came back paused after a resume");
        // 3. A timed pause, forced to look like one that fell due while
        // the daemon was down. Set it live so the deadline is written by
        // the daemon, then wind the deadline back on disk.
        let r = http(port_c, "/api?mode=pause&value=30&output=json", None);
        assert!(r.contains("\"status\":true"), "{r}");
        assert!(paused_now(port_c), "timed pause did not take effect");
    })
    .await
    .unwrap();
    drop(c);
    let s = std::fs::read_to_string(&settings).unwrap();
    let mut v: serde_json::Value = serde_json::from_str(&s).unwrap();
    let deadline = v["pause_until_unix"].as_i64().expect("timed pause wrote no deadline");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    assert!(
        deadline > now + 25 * 60 && deadline <= now + 30 * 60,
        "deadline is not ~30 min out ({deadline} vs now {now}) - stored as an interval?"
    );
    v["pause_until_unix"] = serde_json::json!(now - 5);
    std::fs::write(&settings, serde_json::to_string_pretty(&v).unwrap()).unwrap();

    let d = serve(&dir, &build).await;
    let port_d = d.port;
    tokio::task::spawn_blocking(move || {
        assert!(!paused_now(port_d), "an expired timed pause came back paused");
        // 4. A clean shutdown pauses internally; that must not be saved.
        let r = http(port_d, "/api?mode=shutdown&output=json", Some(("text/plain", b"")));
        assert!(r.contains("\"status\":true"), "{r}");
    })
    .await
    .unwrap();
    // Let the daemon finish exiting before reading what it left on disk.
    std::thread::sleep(std::time::Duration::from_millis(1500));
    drop(d);
    let s = std::fs::read_to_string(&settings).unwrap_or_default();
    assert!(
        !s.contains("\"paused\""),
        "a clean shutdown recorded its own internal pause: {s}"
    );

    let e = serve(&dir, &build).await;
    let port_e = e.port;
    tokio::task::spawn_blocking(move || {
        assert!(!paused_now(port_e), "came back paused after a clean shutdown");
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// The two rename-punctuation toggles replaced behaviour that used to be
/// hard-coded ON. Fresh installs get the new default, but an install that
/// already has state has to keep the old shape: history cleanup recomputes
/// a filed episode's name from these settings, so flipping them under an
/// existing library orphans every file already named the old way.
///
/// The predicate is unit-tested; what is pinned here is that the daemon
/// actually starts its two flags from it. Both halves are asserted,
/// because a default that is unconditionally ON passes the upgrade case
/// on its own.
#[tokio::test(flavor = "multi_thread")]
async fn rename_punctuation_defaults_split_fresh_installs_from_upgrades() {
    let root = std::env::temp_dir().join(format!("nzbfast-renamedef-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);

    // Only a wizard answer on disk: still a fresh install.
    // Anything else: an install that has already been used.
    for (name, settings, want) in [
        ("fresh", r#"{"index_interests":"linux"}"#, false),
        ("upgrade", r#"{"index_deepen":123456}"#, true),
    ] {
        let dir = root.join(name);
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = dir.join("config.json");
        std::fs::write(
            &cfg,
            format!(
                "{{\"servers\":[{{\"host\":\"127.0.0.1\",\"port\":{},\"tls\":false}}]}}",
                free_port()
            ),
        )
        .unwrap();
        std::fs::write(dir.join("settings.json"), settings).unwrap();
        let out = dir.join("complete");
        let d = serve(&dir, |port| {
            let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
            c.env("NZBFAST_OPEN", "1")
                .env("NZBFAST_NO_ENRICH", "1")
                .arg("--config")
                .arg(&cfg)
                .arg("serve")
                .arg("--bind")
                .arg("127.0.0.1")
                .arg("--port")
                .arg(port.to_string())
                .arg("--apikey")
                .arg("sekrit")
                .arg("--out")
                .arg(&out);
            c
        })
        .await;
        let port = d.port;
        tokio::task::spawn_blocking(move || {
            let body = http(port, "/api?mode=get_config&apikey=sekrit&output=json", None);
            let v: serde_json::Value = serde_json::from_str(&body).unwrap();
            let cfg = &v["config"]["nzbfast"];
            for key in ["rename_year_parens", "rename_quality_brackets"] {
                assert_eq!(
                    cfg[key], want,
                    "{name} install: {key} must start {want} - an upgrade keeps the \
                     naming its library already uses, a fresh install gets the new \
                     default: {cfg}"
                );
            }
        })
        .await
        .unwrap();
    }
    let _ = std::fs::remove_dir_all(&root);
}

/// M32: a FIRST failure with missing articles gets
/// exactly ONE automatic retry after the cooldown. The retried run fails
/// again (articles still ghosts) and must NOT reschedule - the retry
/// counter stays at 1 and the job stays Failed.
#[tokio::test(flavor = "multi_thread")]
async fn auto_retry_fires_once_after_cooldown() {
    let dir = std::env::temp_dir().join(format!("nzbfast-autoretry-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    // No articles on the server at all → every segment is a ghost and the
    // job fails with "download incomplete" (the transient shape).
    let srv = MockServer::start(HashMap::new(), Chaos::default()).await;
    let ghost_segs: Vec<(String, u64, u32)> =
        (1..=3).map(|n| (format!("aghost{n}@x"), 40_000, n)).collect();
    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
    );
    xml.push_str(
        "  <file poster=\"x\" date=\"0\" subject=\"&quot;ar.bin&quot; yEnc (1/3)\">\n    <groups><group>g</group></groups>\n    <segments>\n",
    );
    for (id, bytes, num) in &ghost_segs {
        xml.push_str(&format!(
            "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
        ));
    }
    xml.push_str("    </segments>\n  </file>\n</nzb>\n");

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
            .env("NZBFAST_AUTO_RETRY_SECS", "2")
            .arg("--config")
            .arg(&cfg)
            .arg("serve")
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--apikey")
            .arg("sekrit")
            .arg("--out")
            .arg(dir.join("complete"))
            .arg("--connections")
            .arg("2");
        c
    })
    .await;
    let port = d.port;

    tokio::task::spawn_blocking(move || {
        let boundary = "----autoretryb";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!("--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"ar.nzb\"\r\n\r\n").as_bytes(),
        );
        body.extend_from_slice(xml.as_bytes());
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let r = http(
            port,
            "/api?mode=addfile&output=json&apikey=sekrit",
            Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
        );
        assert!(r.contains("\"status\":true"), "{r}");

        let poll = |pred: &dyn Fn(&str) -> bool, what: &str| {
            for _ in 0..150 {
                let h = http(port, "/api?mode=history&apikey=sekrit&output=json", None);
                if pred(&h) {
                    return h;
                }
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
            panic!("timed out waiting for {what}");
        };

        // First failure parks with retry count 0…
        poll(&|h: &str| h.contains("Failed"), "first failure");
        // …then the auto retry fires after ~2 s, runs, and fails again.
        let h = poll(
            &|h: &str| h.contains("\"retry\":1") && h.contains("Failed"),
            "the automatic retry to run and fail",
        );
        assert!(h.contains("Failed"), "{h}");

        // One shot only: well past another cooldown, no third attempt.
        std::thread::sleep(std::time::Duration::from_secs(5));
        let h = http(port, "/api?mode=history&apikey=sekrit&output=json", None);
        assert!(
            h.contains("\"retry\":1") && !h.contains("\"retry\":2"),
            "auto-retry must fire exactly once: {h}"
        );
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// A zip post whose container cannot be READ (here: zip magic over
/// bytes that are not an archive) - the shape a user reported as "it
/// downloaded and there was nothing there". Store/deflate zips now
/// unpack natively (see `zip_payload_post_unpacks_natively` below); this
/// pins what happens when one still cannot be produced.
///
/// Three things have to hold at once, and each of them was broken:
/// the queue warns BEFORE the download (the NZB's file list is enough
/// to know), the job FAILS with a reason naming the archive rather than
/// reporting a green "Completed" an *arr would act on by giving up, and
/// the archive is still on disk afterwards - the keep-media-only
/// tidy-up used to delete the one file we had just told the user to
/// unpack by hand.
#[tokio::test(flavor = "multi_thread")]
async fn zip_payload_post_fails_with_a_reason() {
    let dir = std::env::temp_dir().join(format!("nzbfast-zip-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    // A movie-shaped release whose payload is one zip. Real local file
    // header magic so the on-disk detectors see a container, not just a
    // suggestive name.
    let stem = "Some.Movie.2019.1080p.BluRay.x264-TEST";
    let mut zip = b"PK\x03\x04".to_vec();
    zip.extend_from_slice(&payload(200_000, 11));
    let mut articles = HashMap::new();
    let segs = make_file_articles(&format!("{stem}.zip"), &zip, 40_000, "zip", &mut articles);
    let srv = MockServer::start(articles, Chaos::default()).await;

    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
    );
    xml.push_str(&format!(
        "  <file poster=\"x\" date=\"0\" subject=\"&quot;{stem}.zip&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
        segs.len()
    ));
    for (id, bytes, num) in segs.iter() {
        xml.push_str(&format!(
            "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
        ));
    }
    xml.push_str("    </segments>\n  </file>\n</nzb>\n");

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
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--apikey")
            .arg("sekrit")
            .arg("--out")
            .arg(dir.join("complete"));
        c
    })
    .await;
    let port = d.port;

    let dir2 = dir.clone();
    tokio::task::spawn_blocking(move || {
        // Keep-media-only ON: the setting that used to delete the zip.
        let r = http(
            port,
            "/api?mode=config&name=rename_media_only&value=1&apikey=sekrit&output=json",
            None,
        );
        assert!(r.contains("\"status\":true"), "{r}");

        let boundary = "----nzbfastboundary";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"{stem}.nzb\"\r\nContent-Type: application/x-nzb\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(xml.as_bytes());
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let ctype = format!("multipart/form-data; boundary={boundary}");
        let r = http(port, "/api?mode=addfile&apikey=sekrit&output=json", Some((&ctype, &body)));
        assert!(r.contains("nzo_ids"), "{r}");

        // The warning is available from the queue, before a byte lands.
        // (A fast mock can finish first, so accept the history side too.)
        let mut warned = false;
        for _ in 0..150 {
            let q = http(port, "/api?mode=queue&apikey=sekrit&output=json", None);
            if q.contains("\"zip_packed\":true") {
                warned = true;
                break;
            }
            let h = http(port, "/api?mode=history&apikey=sekrit&output=json", None);
            if h.contains("\"Completed\"") || h.contains("\"Failed\"") {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }

        let mut hist = String::new();
        for _ in 0..150 {
            hist = http(port, "/api?mode=history&apikey=sekrit&output=json", None);
            if hist.contains("\"Completed\"") || hist.contains("\"Failed\"") {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        // Failed, not Completed. Every byte arrived, but the payload is
        // still packed, so the release delivered nothing importable -
        // and Completed is a verdict an *arr acts on by never looking
        // again. Failed is what makes it blocklist and grab a usable
        // release instead.
        assert!(hist.contains("\"Failed\""), "a zip payload must fail the job: {hist}");
        assert!(
            hist.contains("could not be unpacked"),
            "history must say why, not just that it failed: {hist}"
        );
        assert!(warned || hist.contains("\"zip_packed\":true"), "no zip warning anywhere: {hist}");

        // The whole point: the archive is still there. Auto-rename gives
        // the folder its tidy name, so find it rather than assume it.
        let out = std::fs::read_dir(dir2.join("complete"))
            .expect("complete dir")
            .flatten()
            .map(|e| e.path())
            .find(|p| p.is_dir())
            .expect("job output dir");
        let left: Vec<String> = std::fs::read_dir(&out)
            .expect("output dir")
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            left.iter().any(|n| n.ends_with(".zip")),
            "keep-media-only deleted the only copy of the payload: {left:?}"
        );
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// The other half, and the behaviour change: a REAL store+deflate zip
/// payload now unpacks natively, so the job COMPLETES with the payload
/// on disk instead of failing with the archive left for the user.
///
/// Keep-media-only is on, as in the failing twin - the sweep must keep
/// the extracted media and must not trip over the container it replaced.
#[tokio::test(flavor = "multi_thread")]
async fn zip_payload_post_unpacks_natively() {
    let dir = std::env::temp_dir().join(format!("nzbfast-zipok-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let stem = "Some.Movie.2021.1080p.BluRay.x264-TEST";
    let movie: Vec<u8> = (0..300_000u32).map(|i| (i as u8).wrapping_mul(37)).collect();
    let zip = nzbkit::zip::fixtures::zip_of(&[
        nzbkit::zip::fixtures::Spec::deflated("Some.Movie.2021.mkv", &movie),
        nzbkit::zip::fixtures::Spec::stored("readme.nfo", b"scene info"),
    ]);
    let mut articles = HashMap::new();
    let segs = make_file_articles(&format!("{stem}.zip"), &zip, 40_000, "zipok", &mut articles);
    let srv = MockServer::start(articles, Chaos::default()).await;

    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
    );
    xml.push_str(&format!(
        "  <file poster=\"x\" date=\"0\" subject=\"&quot;{stem}.zip&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
        segs.len()
    ));
    for (id, bytes, num) in segs.iter() {
        xml.push_str(&format!(
            "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
        ));
    }
    xml.push_str("    </segments>\n  </file>\n</nzb>\n");

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
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--apikey")
            .arg("sekrit")
            .arg("--out")
            .arg(dir.join("complete"));
        c
    })
    .await;
    let port = d.port;

    let dir2 = dir.clone();
    tokio::task::spawn_blocking(move || {
        let r = http(
            port,
            "/api?mode=config&name=rename_media_only&value=1&apikey=sekrit&output=json",
            None,
        );
        assert!(r.contains("\"status\":true"), "{r}");

        let boundary = "----nzbfastboundary";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"{stem}.nzb\"\r\nContent-Type: application/x-nzb\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(xml.as_bytes());
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let ctype = format!("multipart/form-data; boundary={boundary}");
        let r = http(port, "/api?mode=addfile&apikey=sekrit&output=json", Some((&ctype, &body)));
        assert!(r.contains("nzo_ids"), "{r}");

        let mut hist = String::new();
        for _ in 0..200 {
            hist = http(port, "/api?mode=history&apikey=sekrit&output=json", None);
            if hist.contains("\"Completed\"") || hist.contains("\"Failed\"") {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        assert!(hist.contains("\"Completed\""), "a store/deflate zip must complete: {hist}");

        let out = std::fs::read_dir(dir2.join("complete"))
            .expect("complete dir")
            .flatten()
            .map(|e| e.path())
            .find(|p| p.is_dir())
            .expect("job output dir");
        // The payload landed, byte-exact, and the container it came from
        // is gone (its bytes are the payload now). The auto-renamer gives
        // the media file the release name, so match on the extension.
        let mkv = walk_find_ext(&out, "mkv").unwrap_or_else(|| {
            panic!("no extracted payload under {}", out.display())
        });
        assert_eq!(std::fs::read(&mkv).unwrap(), movie, "extracted bytes differ");
        let left: Vec<String> = std::fs::read_dir(&out)
            .expect("output dir")
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            !left.iter().any(|n| n.ends_with(".zip")),
            "the container should be gone once its payload landed: {left:?}"
        );
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// Find a file by EXTENSION anywhere under `root`. The auto-renamer both
/// renames the payload to the release name and may tidy it into a
/// subfolder, so neither the name nor the depth is fixed.
fn walk_find_ext(root: &std::path::Path, ext: &str) -> Option<std::path::PathBuf> {
    let mut dirs = vec![root.to_path_buf()];
    while let Some(d) = dirs.pop() {
        for e in std::fs::read_dir(&d).ok()?.flatten() {
            let p = e.path();
            if p.is_dir() {
                dirs.push(p);
            } else if p.extension().is_some_and(|x| x == ext) {
                return Some(p);
            }
        }
    }
    None
}

/// The other half of the zip story: a zip that is NOT the payload.
///
/// A `Subs/subs.zip`-style sidecar beside a feature that landed fine
/// must not fail anything - the user got what they came for. But it is
/// the case where the cleanup actually runs, and keep-media-only used to
/// delete every non-video file, destroying the one archive we had just
/// told the user to unpack by hand. So: Completed, the archive still on
/// disk, and the job carrying a note that names it.
#[tokio::test(flavor = "multi_thread")]
async fn zip_sidecar_is_noted_and_survives_cleanup() {
    let dir = std::env::temp_dir().join(format!("nzbfast-zipside-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let stem = "Other.Movie.2021.1080p.BluRay.x264-TEST";
    let video = payload(300_000, 13);
    let mut extras = b"PK\x03\x04".to_vec();
    extras.extend_from_slice(&payload(50_000, 17));
    let mut articles = HashMap::new();
    let vsegs =
        make_file_articles(&format!("{stem}.mkv"), &video, 40_000, "vid2", &mut articles);
    let zsegs =
        make_file_articles(&format!("{stem}.zip"), &extras, 40_000, "zip2", &mut articles);
    let srv = MockServer::start(articles, Chaos::default()).await;

    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
    );
    for (name, segs) in [(format!("{stem}.mkv"), &vsegs), (format!("{stem}.zip"), &zsegs)] {
        xml.push_str(&format!(
            "  <file poster=\"x\" date=\"0\" subject=\"&quot;{name}&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
            segs.len()
        ));
        for (id, bytes, num) in segs.iter() {
            xml.push_str(&format!(
                "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
            ));
        }
        xml.push_str("    </segments>\n  </file>\n");
    }
    xml.push_str("</nzb>\n");

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
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--apikey")
            .arg("sekrit")
            .arg("--out")
            .arg(dir.join("complete"));
        c
    })
    .await;
    let port = d.port;

    let dir2 = dir.clone();
    tokio::task::spawn_blocking(move || {
        // Keep-media-only ON: the setting that used to eat the archive.
        let r = http(
            port,
            "/api?mode=config&name=rename_media_only&value=1&apikey=sekrit&output=json",
            None,
        );
        assert!(r.contains("\"status\":true"), "{r}");

        let boundary = "----nzbfastboundary";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"{stem}.nzb\"\r\nContent-Type: application/x-nzb\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(xml.as_bytes());
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let ctype = format!("multipart/form-data; boundary={boundary}");
        let r = http(port, "/api?mode=addfile&apikey=sekrit&output=json", Some((&ctype, &body)));
        assert!(r.contains("nzo_ids"), "{r}");

        let mut hist = String::new();
        for _ in 0..150 {
            hist = http(port, "/api?mode=history&apikey=sekrit&output=json", None);
            if hist.contains("\"Completed\"") || hist.contains("\"Failed\"") {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        assert!(
            hist.contains("\"Completed\""),
            "a sidecar zip must not fail a job whose payload landed: {hist}"
        );
        assert!(
            hist.contains(&format!("\"unpack_blocked_by\":\"{stem}.zip\"")),
            "history must name the sidecar it left packed: {hist}"
        );

        // The feature was renamed and kept, and the archive survived the
        // non-media sweep that runs only on a successful job.
        let out = std::fs::read_dir(dir2.join("complete"))
            .expect("complete dir")
            .flatten()
            .map(|e| e.path())
            .find(|p| p.is_dir())
            .expect("job output dir");
        let left: Vec<String> = std::fs::read_dir(&out)
            .expect("output dir")
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            left.iter().any(|n| n.ends_with(".zip")),
            "keep-media-only deleted the archive again: {left:?}"
        );
        assert!(left.iter().any(|n| n.ends_with(".mkv")), "feature missing: {left:?}");
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread")]
async fn archive_shape_is_live_in_the_queue_and_kept_in_history() {
    // TODO §25: the extractor works out what a set is the moment the
    // first volume's headers parse. The queue payload must carry that
    // WHILE the job downloads (the dashboard badge), and the same tag
    // must survive onto the history entry once it finishes.
    use nzbkit::rar::fixtures;
    let dir = std::env::temp_dir().join(format!("nzbfast-shape-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let inner = payload(12_000_000, 11);
    let vols = [
        fixtures::rar5_volume_n(&[("movie.mkv", 12_000_000, &inner[..6_000_000], false, true)], 0),
        fixtures::rar5_volume_n(&[("movie.mkv", 12_000_000, &inner[6_000_000..], true, false)], 1),
    ];
    let mut articles = HashMap::new();
    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
    );
    for (i, vol) in vols.iter().enumerate() {
        let name = format!("s.part{}.rar", i + 1);
        let segs = make_file_articles(&name, vol, 300_000, &format!("sh{i}"), &mut articles);
        xml.push_str(&format!(
            "  <file poster=\"x\" date=\"0\" subject=\"&quot;{name}&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
            segs.len()
        ));
        for (id, bytes, num) in &segs {
            xml.push_str(&format!(
                "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
            ));
        }
        xml.push_str("    </segments>\n  </file>\n");
    }
    xml.push_str("</nzb>\n");
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
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--out")
            .arg(dir.join("complete"))
            .arg("--connections")
            .arg("2")
            // Keep the download window open long enough to observe the
            // queue mid-flight.
            .env("NZBFAST_THROTTLE_WRITE_MBPS", "3");
        c
    })
    .await;
    let port = d.port;

    tokio::task::spawn_blocking(move || {
        let boundary = "----shapeb";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!("--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"movie.nzb\"\r\n\r\n").as_bytes(),
        );
        body.extend_from_slice(xml.as_bytes());
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        http(
            port,
            "/api?mode=addfile&output=json",
            Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
        );

        // Live: the badge appears while the job is still Downloading.
        let mut live = String::new();
        for _ in 0..200 {
            let q = http(port, "/api?mode=queue&output=json", None);
            if q.contains("\"archive_shape\":\"rar5 store one-pass\"") {
                live = q;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        assert!(
            live.contains("\"status\":\"Downloading\""),
            "shape must show up while the job is still running: {live}"
        );

        // Latched: the finished entry keeps it for the history view.
        let mut hist = String::new();
        for _ in 0..400 {
            let h = http(port, "/api?mode=history&output=json", None);
            if h.contains("\"status\":\"Completed\"") {
                hist = h;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        assert!(
            hist.contains("\"archive_shape\":\"rar5 store one-pass\""),
            "history entry lost the shape: {hist}"
        );
    })
    .await
    .unwrap();
    // The same fact reaches the log (and so `nzbfast get`'s console),
    // folded into the volume line rather than printed on its own.
    let log = std::fs::read_to_string(&d.log).unwrap_or_default();
    assert!(
        log.contains("extracting in-stream [RAR5 · stored · one-pass]"),
        "shape missing from the volume line:\n{log}"
    );
    // Folded into ONE volume line however many volumes land (the other
    // occurrence is the end-of-job summary, which is meant to carry it).
    assert_eq!(
        log.matches("extracting in-stream [").count(),
        1,
        "the shape must not repeat on every volume line:\n{log}"
    );
    assert!(
        log.contains("volumes never touched disk [RAR5 · stored · one-pass]:"),
        "shape missing from the final summary:\n{log}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A retry must never be aimed at a directory another job has taken.
///
/// A Failed history record does not claim its output folder, so a re-add
/// of the same name is handed exactly that folder. Retrying the original
/// then put two live jobs in one directory - and once the re-add had
/// COMPLETED, the retry downloaded straight over its verified payload,
/// which is the collision a completed job's claim exists to prevent.
///
/// Both halves are pinned: an ordinary failed retry still reuses its own
/// folder in place (retrying a flaky post must not climb .2/.3/.4), and a
/// retry whose folder now holds someone else's finished download re-homes
/// beside it.
#[tokio::test(flavor = "multi_thread")]
async fn retry_re_homes_off_a_completed_re_adds_folder() {
    let dir = std::env::temp_dir().join(format!("nzbfast-retryhome-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let data = payload(200_000, 31);
    let mut articles = HashMap::new();
    let segs = make_file_articles("keeper.bin", &data, 40_000, "rh", &mut articles);
    let srv = MockServer::start(articles, Chaos::default()).await;

    let nzb_for = |file: &str, segs: &[(String, u64, u32)]| {
        let mut xml = format!(
            "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file poster=\"x\" date=\"0\" subject=\"&quot;{file}&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
            segs.len()
        );
        for (id, bytes, num) in segs {
            xml.push_str(&format!(
                "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
            ));
        }
        xml.push_str("    </segments>\n  </file>\n</nzb>\n");
        xml
    };
    let ghost: Vec<(String, u64, u32)> =
        (1..=3).map(|n| (format!("rhghost{n}@x"), 40_000, n)).collect();
    let ghost_xml = nzb_for("gone.bin", &ghost);
    let good_xml = nzb_for("keeper.bin", &segs);

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
            // No M32 automatic retry: this test drives the retries itself.
            .env("NZBFAST_AUTO_RETRY_SECS", "0")
            .arg("--config")
            .arg(&cfg)
            .arg("serve")
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--out")
            .arg(dir.join("complete"));
        c
    })
    .await;
    let port = d.port;

    let dir2 = dir.clone();
    tokio::task::spawn_blocking(move || {
        let upload = |xml: &str, fname: &str| -> String {
            let boundary = "----rhb";
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
            r.split("SABnzbd_nzo_").nth(1).unwrap().split('"').next()
                .map(|s| format!("SABnzbd_nzo_{s}")).unwrap()
        };
        // The history slot for one job, once `pred` holds for it.
        let slot = |id: &str, pred: &dyn Fn(&serde_json::Value) -> bool, what: &str| -> serde_json::Value {
            for _ in 0..200 {
                let raw = http(port, "/api?mode=history&output=json", None);
                let v: serde_json::Value = serde_json::from_str(&raw)
                    .unwrap_or_else(|e| panic!("bad history JSON: {e}\n{raw}"));
                let hit = v["history"]["slots"]
                    .as_array()
                    .and_then(|a| a.iter().find(|s| s["nzo_id"] == id).cloned());
                match hit {
                    Some(s) if pred(&s) => return s,
                    _ => std::thread::sleep(std::time::Duration::from_millis(200)),
                }
            }
            panic!("timed out waiting for {what}");
        };
        // The storage path's last component - the whole question here is
        // whether it is the shared "alpha" or a private "alpha.2", and
        // comparing whole paths would only compare temp-dir symlinks.
        let folder = |s: &serde_json::Value| {
            Path::new(s["storage"].as_str().unwrap_or_default())
                .file_name()
                .map(|f| f.to_string_lossy().to_string())
                .unwrap_or_default()
        };
        let failed = |s: &serde_json::Value| s["status"] == "Failed";

        // The original fails: nobody else is in its folder.
        let a_id = upload(&ghost_xml, "alpha.nzb");
        let s = slot(&a_id, &failed, "the first failure");
        assert_eq!(folder(&s), "alpha", "{s}");

        // Retried with the folder still its own: it must be reused in
        // place, or every retry of a flaky post would climb .2, .3, .4.
        let r = http(port, &format!("/api?mode=retry&value={a_id}&output=json"), None);
        assert!(r.contains("\"status\":true"), "{r}");
        let s = slot(&a_id, &|s| failed(s) && s["retry"] == 1, "the retried failure");
        assert_eq!(folder(&s), "alpha", "an ordinary failed retry must reuse its own folder: {s}");
        assert!(
            !dir2.join("complete/alpha.2").exists(),
            "a plain retry climbed to alpha.2"
        );

        // Same name added again. The failed record does not hold the
        // folder, so this one takes it - and finishes there.
        let b_id = upload(&good_xml, "alpha.nzb");
        let s = slot(&b_id, &|s| s["status"] == "Completed", "the re-add to complete");
        assert_eq!(folder(&s), "alpha", "{s}");
        assert_eq!(
            std::fs::read(dir2.join("complete/alpha/keeper.bin")).unwrap(),
            payload(200_000, 31),
            "the re-add did not land its payload"
        );

        // NOW retry the original. Its old folder is another job's verified
        // payload, so this download must go somewhere else.
        let r = http(port, &format!("/api?mode=retry&value={a_id}&output=json"), None);
        assert!(r.contains("\"status\":true"), "{r}");
        let s = slot(&a_id, &|s| failed(s) && s["retry"] == 2, "the second retried failure");
        assert_eq!(
            folder(&s),
            "alpha.2",
            "the retry was aimed at the completed job's folder: {s}"
        );
        assert_eq!(
            std::fs::read(dir2.join("complete/alpha/keeper.bin")).unwrap(),
            payload(200_000, 31),
            "the retry wrote over the completed payload"
        );
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// Cancelling a download must not start the copy of it that was being
/// held back.
///
/// M14f parks a second grab of the same episode as an ALTERNATIVE and
/// promotes it when the original FAILS. A user delete aborts the transfer,
/// which arrives at the same place as a failure - so cancelling a download
/// unpaused its held duplicate and immediately started downloading the
/// very title the user had just cancelled. Genuine failures must still
/// promote, so both outcomes are driven here through one daemon.
#[tokio::test(flavor = "multi_thread")]
async fn cancelling_a_download_leaves_its_duplicate_held() {
    let dir = std::env::temp_dir().join(format!("nzbfast-canceldupe-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let mut articles = HashMap::new();
    // The cancelled original is deliberately long (250 ms an article, 2
    // connections → ~6 s) so the delete lands mid-transfer.
    let orig = make_file_articles("orig.bin", &payload(2_000_000, 51), 40_000, "cd", &mut articles);
    let held = make_file_articles("held.bin", &payload(400_000, 53), 40_000, "cd", &mut articles);
    let alt = make_file_articles("alt.bin", &payload(400_000, 55), 40_000, "cd", &mut articles);
    let srv = MockServer::start(articles, Chaos { delay_ms: 250, ..Chaos::default() }).await;

    let nzb_for = |file: &str, segs: &[(String, u64, u32)]| {
        let mut xml = format!(
            "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file poster=\"x\" date=\"0\" subject=\"&quot;{file}&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
            segs.len()
        );
        for (id, bytes, num) in segs {
            xml.push_str(&format!(
                "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
            ));
        }
        xml.push_str("    </segments>\n  </file>\n</nzb>\n");
        xml
    };
    let ghost: Vec<(String, u64, u32)> =
        (1..=3).map(|n| (format!("cdghost{n}@x"), 40_000, n)).collect();
    let (orig_xml, held_xml) = (nzb_for("orig.bin", &orig), nzb_for("held.bin", &held));
    let (dead_xml, alt_xml) = (nzb_for("dead.bin", &ghost), nzb_for("alt.bin", &alt));

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
            // No M32 automatic retry: it holds the alternative back on a
            // first failure, and this test is about the promotion itself.
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
        let upload = |xml: &str, fname: &str| -> String {
            let boundary = "----cdb";
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
            r.split("SABnzbd_nzo_").nth(1).unwrap().split('"').next()
                .map(|s| format!("SABnzbd_nzo_{s}")).unwrap()
        };
        let poll = |pred: &dyn Fn(&str, &str) -> bool, what: &str| -> (String, String) {
            for _ in 0..300 {
                let q = http(port, "/api?mode=queue&output=json", None);
                let h = http(port, "/api?mode=history&output=json", None);
                if pred(&q, &h) {
                    return (q, h);
                }
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
            panic!("timed out waiting for {what}");
        };
        // ONE queue slot. The payload carries a queue-wide "status" of its
        // own, so a substring search for "Downloading" says nothing about
        // the job being asked about.
        let qslot = |q: &str, id: &str| -> serde_json::Value {
            let v: serde_json::Value = serde_json::from_str(q)
                .unwrap_or_else(|e| panic!("bad queue JSON: {e}\n{q}"));
            v["queue"]["slots"]
                .as_array()
                .and_then(|a| a.iter().find(|s| s["nzo_id"] == id).cloned())
                .unwrap_or(serde_json::Value::Null)
        };

        // Paused so both land in the queue before the duplicate check runs.
        http(port, "/api?mode=pause&output=json", None);
        let orig_id = upload(&orig_xml, "Show.Name.S01E02.720p.WEB.nzb");
        let held_id = upload(&held_xml, "Show.Name.S01E02.1080p.WEB.nzb");
        let q = http(port, "/api?mode=queue&output=json", None);
        assert_eq!(qslot(&q, &held_id)["priority"], "Duplicate", "not held: {q}");
        http(port, "/api?mode=resume&output=json", None);

        // Cancel the original while it is actually transferring.
        poll(
            &|q, _| qslot(q, &orig_id)["status"] == "Downloading",
            "the original to start",
        );
        let r = http(
            port,
            &format!("/api?mode=queue&name=delete&value={orig_id}&output=json"),
            None,
        );
        assert!(r.contains("\"status\":true"), "{r}");

        // A GENUINE failure of an unrelated title, used both as the other
        // half of the guard and as the marker that the cancelled job's
        // tail has long since run.
        let dead_id = upload(&dead_xml, "Other.Show.S05E01.720p.WEB.nzb");
        let alt_id = upload(&alt_xml, "Other.Show.S05E01.1080p.WEB.nzb");
        let (q, h) = poll(
            &|_, h| h.contains(&dead_id) && h.contains(&alt_id),
            "the failed original and its promoted alternative",
        );
        assert!(h.contains("\"Failed\"") && h.contains("\"Completed\""), "{h}");

        // The cancelled title's alternative is still held, and nothing
        // about the cancelled job reached history.
        assert_eq!(
            qslot(&q, &held_id)["priority"],
            "Duplicate",
            "the cancelled download promoted its held duplicate: {q}"
        );
        assert!(!h.contains(&held_id), "the held duplicate downloaded anyway: {h}");
        assert!(!h.contains(&orig_id), "a cancelled job must not reach history: {h}");
    })
    .await
    .unwrap();
    // Rig check: the delete really did land on a live transfer (the whole
    // point - a job cancelled before it started never reaches park()).
    let log = std::fs::read_to_string(&d.log).unwrap_or_default();
    assert!(
        log.contains("[queue] active download stopped by user"),
        "the delete did not hit a running download:\n{log}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Deleting a job that is being prefetched must stop it, whichever API
/// the delete came in on.
///
/// The idle-server prefetch runs a QUEUED job in a sidecar pipeline, so
/// "not the active download" is not the same as "not running". The
/// NZBGet-facing delete never told the sidecar anything, so the job the
/// user (or Sonarr) removed kept downloading, ran the whole completion
/// tail - unlock, rename, TV filing, the move to the destination folder,
/// the pp-script - and parked itself into history as Completed. The next
/// queued job must still be prefetched normally afterwards.
#[tokio::test(flavor = "multi_thread")]
async fn jsonrpc_delete_stops_a_prefetching_job() {
    let dir = std::env::temp_dir().join(format!("nzbfast-rpcdel-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    // Slow server: only job A's articles (250 ms each → A runs ~19 s).
    // Fast server: B's and C's, delayed too so the sidecar run is wide
    // enough to delete into.
    let mut slow_articles = HashMap::new();
    let a_segs = make_file_articles(
        "grinder.bin",
        &payload(3_000_000, 61),
        20_000,
        "sd",
        &mut slow_articles,
    );
    let mut fast_articles = HashMap::new();
    let b_segs =
        make_file_articles("doomed.bin", &payload(2_000_000, 63), 40_000, "fd", &mut fast_articles);
    let c_segs =
        make_file_articles("keeps.bin", &payload(600_000, 65), 40_000, "fk", &mut fast_articles);
    let slow_srv =
        MockServer::start(slow_articles, Chaos { delay_ms: 250, ..Chaos::default() }).await;
    let fast_srv =
        MockServer::start(fast_articles, Chaos { delay_ms: 250, ..Chaos::default() }).await;

    let nzb_for = |file: &str, segs: &[(String, u64, u32)]| {
        let mut xml = format!(
            "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file poster=\"x\" date=\"0\" subject=\"&quot;{file}&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
            segs.len()
        );
        for (id, bytes, num) in segs {
            xml.push_str(&format!(
                "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
            ));
        }
        xml.push_str("    </segments>\n  </file>\n</nzb>\n");
        xml
    };
    let a_xml = nzb_for("grinder.bin", &a_segs);
    let b_xml = nzb_for("doomed.bin", &b_segs);
    let c_xml = nzb_for("keeps.bin", &c_segs);

    let cfg = dir.join("config.json");
    // Distinct host STRINGS for the two loopback mocks: host is server
    // identity throughout, and the sidecar's busy-host exclusion must not
    // catch the idle one.
    std::fs::write(
        &cfg,
        format!(
            "{{\"servers\":[{{\"host\":\"127.0.0.1\",\"port\":{},\"tls\":false}},{{\"host\":\"localhost\",\"port\":{},\"tls\":false}}]}}",
            slow_srv.addr.port(),
            fast_srv.addr.port()
        ),
    )
    .unwrap();
    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            .env("NZBFAST_DEFER_WARMUP_SECS", "2")
            .env("NZBFAST_DEFER_WINDOW_SECS", "3")
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

    let deleted = tokio::task::spawn_blocking(move || {
        let upload = |xml: &str, fname: &str| -> String {
            let boundary = "----rpcdb";
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
            r.split("SABnzbd_nzo_").nth(1).unwrap().split('"').next()
                .map(|s| format!("SABnzbd_nzo_{s}")).unwrap()
        };
        let qslot = |q: &str, id: &str| -> serde_json::Value {
            let v: serde_json::Value = serde_json::from_str(q)
                .unwrap_or_else(|e| panic!("bad queue JSON: {e}\n{q}"));
            v["queue"]["slots"]
                .as_array()
                .and_then(|a| a.iter().find(|s| s["nzo_id"] == id).cloned())
                .unwrap_or(serde_json::Value::Null)
        };
        let poll = |pred: &dyn Fn(&str, &str) -> bool, what: &str| -> (String, String) {
            for _ in 0..300 {
                let q = http(port, "/api?mode=queue&output=json", None);
                let h = http(port, "/api?mode=history&output=json", None);
                if pred(&q, &h) {
                    return (q, h);
                }
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
            panic!("timed out waiting for {what}");
        };

        // A grinds on the slow server; B and C queue behind it.
        let a_id = upload(&a_xml, "grinder.nzb");
        poll(&|q, _| qslot(q, &a_id)["status"] == "Downloading", "job A to start");
        let b_id = upload(&b_xml, "doomed.nzb");
        let c_id = upload(&c_xml, "keeps.nzb");

        // The idle fast server picks B up.
        poll(&|q, _| qslot(q, &b_id)["prefetching"] == true, "B's prefetch to start");

        // Sonarr's delete: NZBGet editqueue, addressing the numeric id.
        let nzbid: i64 = b_id
            .chars()
            .rev()
            .take_while(|c| c.is_ascii_digit())
            .collect::<String>()
            .chars()
            .rev()
            .collect::<String>()
            .parse()
            .unwrap();
        let body = format!(
            "{{\"method\":\"editqueue\",\"params\":[\"GroupDelete\",\"\",[{nzbid}]],\"id\":7}}"
        );
        let r = http(port, "/jsonrpc", Some(("application/json", body.as_bytes())));
        assert!(r.contains("true"), "GroupDelete refused: {r}");

        // C is prefetched and completes: the delete stops one job, not
        // the feature.
        let (q, h) = poll(&|_, h| h.contains(&c_id), "C to complete on the idle server");
        assert!(h.contains("\"Completed\""), "{h}");
        assert!(
            qslot(&q, &a_id)["status"] == "Downloading",
            "A should still be running - the rig proves nothing otherwise: {q}"
        );

        // The deleted job is gone from both views, and it never published.
        assert!(qslot(&q, &b_id).is_null(), "the deleted job is still queued: {q}");
        assert!(
            !h.contains(&b_id),
            "a job deleted mid-prefetch came back as a finished download: {h}"
        );
        b_id
    })
    .await
    .unwrap();
    let log = std::fs::read_to_string(&d.log).unwrap_or_default();
    assert!(
        log.contains(&format!("[prefetch] {deleted} starting")),
        "rig: the deleted job was never the prefetched one:\n{log}"
    );
    assert!(
        !log.contains(&format!("[prefetch] {deleted} completed")),
        "the delete did not stop the prefetch:\n{log}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// §44: an API-added job records WHICH client sent it, not just that
/// some automation did. The Sonarr string here is one a real Sonarr
/// sent during download-client certification, captured off a live
/// test rather than assumed.
///
/// The browser leg matters as much as the Sonarr one: our own dashboard
/// uploads to this very endpoint, so a UA that names no automation must
/// leave the old parameter heuristic untouched.
#[tokio::test(flavor = "multi_thread")]
async fn the_client_that_added_a_job_is_named() {
    let dir = std::env::temp_dir().join(format!("nzbfast-origin-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    // Nothing is ever fetched - the daemon is paused throughout - so an
    // empty server is enough to satisfy startup.
    let srv = MockServer::start(HashMap::new(), Chaos::default()).await;
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
        let xml = "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  \
             <file poster=\"x\" date=\"0\" subject=\"&quot;o.rar&quot; yEnc (1/1)\">\n    \
             <groups><group>g</group></groups>\n    <segments>\n      \
             <segment bytes=\"100\" number=\"1\">nosuchseg</segment>\n    \
             </segments>\n  </file>\n</nzb>\n";
        // `http` cannot set a User-Agent, and the header IS the evidence
        // under test, so the request is written out by hand.
        let add = |ua: &str, fname: &str| -> String {
            let boundary = "----originb";
            let mut body = Vec::new();
            body.extend_from_slice(
                format!("--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"{fname}\"\r\n\r\n").as_bytes(),
            );
            body.extend_from_slice(xml.as_bytes());
            body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
            let mut request = Vec::new();
            write!(
                request,
                "POST /api?mode=addfile&output=json HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\
                 User-Agent: {ua}\r\nContent-Type: multipart/form-data; boundary={boundary}\r\n\
                 Content-Length: {}\r\n\r\n",
                body.len()
            )
            .unwrap();
            request.extend_from_slice(&body);
            String::from_utf8_lossy(&raw(port, &request)).to_string()
        };

        // Paused, so both jobs are still in the queue to be read back.
        http(port, "/api?mode=pause&output=json", None);
        let r = add("Sonarr/4.0.19.2979 (macos 10.0)", "Named.Client.S01E01.nzb");
        assert!(r.contains("\"status\":true"), "{r}");
        let r = add(
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 \
             (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
            "Browser.Upload.S01E02.nzb",
        );
        assert!(r.contains("\"status\":true"), "{r}");

        let q = http(port, "/api?mode=queue&output=json", None);
        assert!(q.contains("\"origin\":\"arr:sonarr\""), "the client was not named: {q}");
        assert!(
            q.contains("\"origin\":\"dashboard\""),
            "a browser upload was misread as an automation: {q}"
        );
        // The bare `arr` bucket is what this replaces for a named client.
        assert!(!q.contains("\"origin\":\"arr\""), "{q}");
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// Categories are configuration, not a side effect of what has been
/// downloaded.
///
/// They used to live only in memory as "the built-ins plus whatever an
/// add call happened to carry", rebuilt at startup from the categories
/// still present in queue.json. Two consequences, both of which meet a
/// user before they can download anything: a fresh install offered only
/// `tv` and `movies`, and Sonarr/Radarr REFUSE to connect when their
/// configured category is missing from the list ("Category does not
/// exist"), so the category could never be registered by the add that
/// would have registered it. And a category did not outlive the last job
/// carrying it - clear history, lose the category.
#[tokio::test(flavor = "multi_thread")]
async fn categories_are_configurable_and_survive_a_restart() {
    let dir = std::env::temp_dir().join(format!("nzbfast-cats-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        format!("{{\"servers\":[{{\"host\":\"127.0.0.1\",\"port\":{},\"tls\":false}}]}}", free_port()),
    )
    .unwrap();
    let launch = {
        let cfg = cfg.clone();
        let dir = dir.clone();
        move |port: u16| {
            let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
            c.env("NZBFAST_NO_ENRICH", "1")
                .arg("--config")
                .arg(&cfg)
                .arg("serve")
                .arg("--bind")
                .arg("127.0.0.1")
                .arg("--port")
                .arg(port.to_string())
                .arg("--apikey")
                .arg("sekrit")
                .arg("--out")
                .arg(dir.join("complete"));
            c
        }
    };
    let d = serve(&dir, &launch).await;
    let port = d.port;

    tokio::task::spawn_blocking(move || {
        // Out of the box we answer for the *arr family's OWN defaults -
        // Sonarr tv, Radarr movies, Lidarr music, Readarr books - so a
        // default install of any of them passes its connection test
        // against a default install of ours.
        let r = http(port, "/api?mode=get_cats&apikey=sekrit&output=json", None);
        for c in ["tv", "movies", "music", "books"] {
            assert!(r.contains(&format!("\"{c}\"")), "default category {c} missing: {r}");
        }

        // A user whose Sonarr is set to a category of its own can add it,
        // with no job needed to teach us the name.
        let r = http(
            port,
            "/api?mode=config&name=categories&value=sonarr,%20radarr&apikey=sekrit&output=json",
            None,
        );
        assert!(r.contains("\"status\":true"), "{r}");
        let r = http(port, "/api?mode=get_cats&apikey=sekrit&output=json", None);
        assert!(r.contains("\"sonarr\""), "{r}");
        assert!(r.contains("\"radarr\""), "{r}");
        // The built-ins are a floor: editing the list cannot strand a
        // client that was already configured against one of them.
        assert!(r.contains("\"tv\""), "editing the list dropped a built-in: {r}");

        // The NZBGet facade's category table is what Sonarr's nzbget-mode
        // Test validates against, so it must agree with get_cats.
        let body = br#"{"method":"config","params":[],"id":1}"#;
        let mut request = Vec::new();
        write!(
            request,
            "POST /jsonrpc HTTP/1.1\r\nHost: x\r\nConnection: close\r\nAuthorization: Basic eDpzZWtyaXQ=\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .unwrap();
        request.extend_from_slice(body);
        let r = String::from_utf8_lossy(&raw(port, &request)).to_string();
        assert!(r.contains("sonarr"), "nzbget config table has no sonarr category: {r}");
    })
    .await
    .unwrap();

    // Restart: the category must still be there. Nothing was ever
    // downloaded, so the old queue-derived list would have lost it.
    drop(d);
    let d = serve(&dir, &launch).await;
    let port = d.port;
    tokio::task::spawn_blocking(move || {
        let r = http(port, "/api?mode=get_cats&apikey=sekrit&output=json", None);
        assert!(r.contains("\"sonarr\""), "category did not survive the restart: {r}");
        assert!(r.contains("\"radarr\""), "{r}");
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// The NZBGet facade answers with NZBGet's own vocabulary.
///
/// Two gaps this pins. Every failure used to report `FAILURE/PAR` with
/// `ParStatus: FAILURE` - one bit, so "needs a password", "the disk
/// filled up" and "the post is missing articles" were indistinguishable
/// to a client, and all three were blamed on a repair that in two of the
/// three cases never ran. And an unimplemented method returned a null
/// RESULT, which on the wire is what "succeeded, nothing to report"
/// looks like, so a client could not tell the two apart.
#[tokio::test(flavor = "multi_thread")]
async fn nzbget_facade_reports_real_statuses_and_real_errors() {
    let dir = std::env::temp_dir().join(format!("nzbfast-nzbgstat-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        format!("{{\"servers\":[{{\"host\":\"127.0.0.1\",\"port\":{},\"tls\":false}}]}}", free_port()),
    )
    .unwrap();
    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_NO_ENRICH", "1")
            .arg("--config")
            .arg(&cfg)
            .arg("serve")
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--apikey")
            .arg("sekrit")
            .arg("--out")
            .arg(dir.join("complete"));
        c
    })
    .await;
    let port = d.port;

    tokio::task::spawn_blocking(move || {
        let rpc = |method: &str, params: &str| -> String {
            let body = format!("{{\"method\":\"{method}\",\"params\":{params},\"id\":1}}");
            let mut request = Vec::new();
            write!(
                request,
                "POST /jsonrpc HTTP/1.1\r\nHost: x\r\nConnection: close\r\nAuthorization: Basic eDpzZWtyaXQ=\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                body.len()
            )
            .unwrap();
            request.extend_from_slice(body.as_bytes());
            String::from_utf8_lossy(&raw(port, &request)).to_string()
        };

        // A method we do not implement is an ERROR, not an empty success.
        let r = rpc("makecoffee", "[]");
        assert!(r.contains("\"error\""), "{r}");
        assert!(r.contains("no such method"), "{r}");
        assert!(!r.contains("\"error\":null"), "unknown method answered as success: {r}");

        // Same for an editqueue command we do not implement - `false`
        // was also the answer for "that job does not exist".
        let r = rpc("editqueue", "[\"GroupSetDupeKey\",\"x\",[1]]");
        assert!(r.contains("unsupported editqueue command"), "{r}");

        // Implemented ones still answer as results, error null.
        let r = rpc("version", "[]");
        assert!(r.contains("\"error\":null"), "{r}");
        let r = rpc("status", "[]");
        assert!(r.contains("\"error\":null"), "{r}");
        // Including the ones that are honest no-ops for us: we have one
        // pause covering the whole pipeline, not a separate post queue.
        let r = rpc("pausepost", "[]");
        assert!(r.contains("\"error\":null"), "{r}");

        // Sonarr rejects a client reporting KeepHistory 0, so the config
        // dump must keep carrying a non-zero one.
        let r = rpc("config", "[]");
        assert!(r.contains("KeepHistory"), "{r}");
        assert!(!r.contains("\"Value\":\"0\""), "KeepHistory went to 0, which Sonarr refuses: {r}");
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// The SAB surface a remote app and an *arr actually poll.
///
/// Four gaps, each one a thing a client asks for and used to be told
/// nothing about: `mode=warnings` was a permanent empty list, so "no
/// server configured" was invisible in every app that has a warnings
/// pane; there was no `mode=status` or `mode=get_scripts` at all, which
/// is what the mobile remotes poll rather than `fullstatus`; and
/// `change_cat` existed only on the NZBGet side, so which client type
/// the user picked decided whether recategorizing a queued job worked.
#[tokio::test(flavor = "multi_thread")]
async fn sab_facade_status_warnings_and_change_cat() {
    let dir = std::env::temp_dir().join(format!("nzbfast-sabstat-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // A config with NO servers: the first-run state, and the one a user
    // wiring up Sonarr is most likely to be sitting in.
    let cfg = dir.join("config.json");
    std::fs::write(&cfg, "{\"servers\":[]}").unwrap();
    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_NO_ENRICH", "1")
            .arg("--config")
            .arg(&cfg)
            .arg("serve")
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--apikey")
            .arg("sekrit")
            .arg("--out")
            .arg(dir.join("complete"));
        c
    })
    .await;
    let port = d.port;

    tokio::task::spawn_blocking(move || {
        // The condition is real and currently stopping all work, so it
        // must reach a client that shows warnings.
        let r = http(port, "/api?mode=warnings&apikey=sekrit&output=json", None);
        assert!(r.contains("No Usenet server"), "warnings stayed empty: {r}");

        // mode=status carries the same warning, plus what a remote app
        // badges: the count, the pause state, free space.
        let r = http(port, "/api?mode=status&apikey=sekrit&output=json", None);
        assert!(r.contains("\"have_warnings\":\"1\""), "{r}");
        assert!(r.contains("No Usenet server"), "{r}");
        assert!(r.contains("\"paused\""), "{r}");
        assert!(r.contains("\"diskspace1\""), "{r}");
        assert!(r.contains("\"completedir\""), "{r}");

        // An empty script list makes a client show no dropdown at all,
        // so "None" is the honest floor.
        let r = http(port, "/api?mode=get_scripts&apikey=sekrit&output=json", None);
        assert!(r.contains("\"None\""), "{r}");

        // Pause before queueing, and it has to be before: "no server, so
        // it never starts" is not true. With an empty server list the job
        // IS picked up, fails "config has no servers" inside half a
        // second, and parks to history. In isolation the three round
        // trips below beat that; under the full suite's load they did not,
        // and the queue read found an empty slot list perhaps one run in
        // six. A paused queue is never picked from, so the job stays
        // Queued for as long as this test needs it.
        let r = http(port, "/api?mode=pause&apikey=sekrit&output=json", None);
        assert!(r.contains("\"status\":true"), "pause refused: {r}");

        // Queue a job and move it to another category. Nothing has been
        // written, so this re-derives the output directory rather than
        // moving files.
        let nzb = "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file poster=\"x\" date=\"0\" subject=\"&quot;chg.bin&quot; yEnc (1/1)\">\n    <groups><group>g</group></groups>\n    <segments><segment bytes=\"100\" number=\"1\">&lt;a@x&gt;</segment></segments>\n  </file>\n</nzb>\n";
        let body = format!(
            "--BB\r\nContent-Disposition: form-data; name=\"nzbfile\"; filename=\"Chg.Show.S01E01.1080p.nzb\"\r\nContent-Type: application/xml\r\n\r\n{nzb}\r\n--BB--\r\n"
        );
        let r = http(
            port,
            "/api?mode=addfile&apikey=sekrit&cat=tv&output=json",
            Some(("multipart/form-data; boundary=BB", body.as_bytes())),
        );
        let id = r
            .split("\"nzo_ids\":[\"")
            .nth(1)
            .and_then(|s| s.split('"').next())
            .expect("no nzo_id in addfile response")
            .to_string();

        let r = http(
            port,
            &format!("/api?mode=change_cat&value={id}&value2=movies&apikey=sekrit&output=json"),
            None,
        );
        assert!(r.contains("\"status\":true"), "change_cat refused: {r}");
        let q = http(port, "/api?mode=queue&apikey=sekrit&output=json", None);
        assert!(q.contains("\"cat\":\"movies\""), "category did not change: {q}");

        // An unknown id is an error, not a silent success.
        let r = http(
            port,
            "/api?mode=change_cat&value=nope&value2=tv&apikey=sekrit&output=json",
            None,
        );
        assert!(r.contains("\"status\":false"), "{r}");
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// Post-download synthesised naming is ON out of the box, is visible in
/// the config the dashboard reads, and survives a restart once turned
/// off.
///
/// Default-on is only defensible because the ladder's acceptance gate
/// renames on certainty rather than on a best guess. A user who would
/// rather nothing at all reached the network after a download must be
/// able to turn it off and have that stick - a toggle that silently came
/// back on at the next restart would be worse than no toggle.
#[tokio::test(flavor = "multi_thread")]
async fn synthesised_naming_defaults_on_and_its_off_switch_persists() {
    let dir = std::env::temp_dir().join(format!("nzbfast-identify-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        format!("{{\"servers\":[{{\"host\":\"127.0.0.1\",\"port\":{},\"tls\":false}}]}}", free_port()),
    )
    .unwrap();
    let launch = {
        let cfg = cfg.clone();
        let dir = dir.clone();
        move |port: u16| {
            let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
            c.env("NZBFAST_NO_ENRICH", "1")
                .arg("--config")
                .arg(&cfg)
                .arg("serve")
                .arg("--bind")
                .arg("127.0.0.1")
                .arg("--port")
                .arg(port.to_string())
                .arg("--apikey")
                .arg("sekrit")
                .arg("--out")
                .arg(dir.join("complete"));
            c
        }
    };
    let d = serve(&dir, &launch).await;
    let port = d.port;
    tokio::task::spawn_blocking(move || {
        let cfg = http(port, "/api?mode=get_config&apikey=sekrit&output=json", None);
        assert!(cfg.contains("\"rename_identify\":true"), "should default on: {cfg}");
        let r = http(
            port,
            "/api?mode=config&name=rename_identify&value=0&apikey=sekrit&output=json",
            None,
        );
        assert!(r.contains("\"status\":true"), "{r}");
        let cfg = http(port, "/api?mode=get_config&apikey=sekrit&output=json", None);
        assert!(cfg.contains("\"rename_identify\":false"), "{cfg}");
    })
    .await
    .unwrap();

    drop(d);
    let d = serve(&dir, &launch).await;
    let port = d.port;
    tokio::task::spawn_blocking(move || {
        let cfg = http(port, "/api?mode=get_config&apikey=sekrit&output=json", None);
        assert!(
            cfg.contains("\"rename_identify\":false"),
            "the off switch did not survive the restart: {cfg}"
        );
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// The container Title rung of the identity ladder, end to end and
/// entirely offline: a post whose subject line says nothing carries the
/// real release name inside the Matroska header, and the finished job
/// is both LABELLED with it and RENAMED off it.
///
/// The interesting half is that the posted name stays on the record.
/// History reports `name` exactly as submitted - every SAB client and
/// every *arr matches on it - with the discovered name in its own field
/// beside it.
#[tokio::test(flavor = "multi_thread")]
async fn an_obfuscated_post_is_named_by_its_own_container() {
    let dir = std::env::temp_dir().join(format!("nzbfast-ident-e2e-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    // What the poster called it: nothing at all.
    let stem = "a4f9c2e1b7d048395166cf20";
    // What the muxer called it, repacker credit and all.
    const REAL: &str = "Example.Movie.2019.1080p.BluRay.x264-GRP";
    let mut video = nzbkit::mkv::test_mux_titled(
        Some(5400.0),
        Some((1920, 1080)),
        Some(&format!("{REAL}, RMZ.cr")),
    );
    // Void padding, the way a real mux carries it, to a plausible size.
    while video.len() < 200_000 {
        video.extend(nzbkit::mkv::el(&[0xEC], &vec![0u8; 8000]));
    }

    let mut articles = HashMap::new();
    let vsegs = make_file_articles(&format!("{stem}.mkv"), &video, 40_000, "vid", &mut articles);
    let srv = MockServer::start(articles, Chaos::default()).await;

    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
    );
    xml.push_str(&format!(
        "  <file poster=\"x\" date=\"0\" subject=\"&quot;{stem}.mkv&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
        vsegs.len()
    ));
    for (id, bytes, num) in vsegs.iter() {
        xml.push_str(&format!("      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"));
    }
    xml.push_str("    </segments>\n  </file>\n</nzb>\n");

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
        // NO_ENRICH keeps the two networked rungs (srrdb, xREL) off the
        // wire; the container rung is local and runs regardless, which
        // is the whole point of gating them separately.
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            .arg("--config")
            .arg(&cfg)
            .arg("serve")
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--apikey")
            .arg("sekrit")
            .arg("--out")
            .arg(dir.join("complete"));
        c
    })
    .await;
    let port = d.port;

    let dir2 = dir.clone();
    tokio::task::spawn_blocking(move || {
        let boundary = "----nzbfastboundary";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"{stem}.nzb\"\r\nContent-Type: application/x-nzb\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(xml.as_bytes());
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let ctype = format!("multipart/form-data; boundary={boundary}");
        let r = http(port, "/api?mode=addfile&apikey=sekrit&cat=movies&output=json", Some((&ctype, &body)));
        assert!(r.contains("nzo_ids"), "{r}");

        let mut hist = String::new();
        for _ in 0..150 {
            hist = http(port, "/api?mode=history&apikey=sekrit&output=json", None);
            if hist.contains("\"Completed\"") || hist.contains("\"Failed\"") {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        assert!(hist.contains("\"Completed\""), "never completed: {hist}");

        // The discovered name is recorded, attributed, and beside - not
        // instead of - the name the job was submitted under.
        assert!(
            hist.contains(&format!("\"identity_name\":\"{REAL}\"")),
            "container name not recorded: {hist}"
        );
        assert!(hist.contains("\"identity_src\":\"mkv-title\""), "{hist}");
        assert!(hist.contains(&format!("\"name\":\"{stem}\"")), "posted name was overwritten: {hist}");

        // …and the payload on disk is filed under it, which is what the
        // user actually sees. Auto-rename is on by default, so the movie
        // folder and its video both take the discovered title.
        let root = dir2.join("complete/movies");
        let found: Vec<String> = std::fs::read_dir(&root)
            .expect("category dir")
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        assert!(
            found.iter().any(|f| f.starts_with("Example Movie")),
            "payload was not filed under the discovered name: {found:?}"
        );
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// Security regression: the add-only `nzbkey` must not reach arbitrary
/// config through the first-key bootstrap hatch.
///
/// The hatch exists so an admin who set the NZB key first is not locked
/// out of ever setting a full API key. It authorises `mode=config` for the
/// add-only key when it sees `name=apikey` - but it read that name from the
/// QUERY string while the handler prefers the POST BODY, so
/// `?name=apikey` + `{"name":"script"}` authorised one setting and wrote a
/// different one. `script` is executed on the job tail and `addfile` is
/// itself add-only, so that was an add-only credential escalating to code
/// execution. Reproduced against the published 1.0.10 image before the fix.
#[tokio::test(flavor = "multi_thread")]
async fn bootstrap_hatch_cannot_write_a_setting_other_than_the_apikey() {
    let dir = std::env::temp_dir().join(format!("nzbfast-bootstrap-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        format!("{{\"servers\":[{{\"host\":\"127.0.0.1\",\"port\":{},\"tls\":false}}]}}", free_port()),
    )
    .unwrap();
    // NZBFAST_OPEN keeps first_run_apikey from minting one, which is what
    // puts the daemon in the exact state the hatch serves: an add-only key
    // set, no full apikey yet.
    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            .arg("--config")
            .arg(&cfg)
            .arg("serve")
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--nzbkey")
            .arg("addkey")
            .arg("--out")
            .arg(dir.join("complete"));
        c
    })
    .await;
    let port = d.port;

    let cfg2 = cfg.clone();
    tokio::task::spawn_blocking(move || {
        // POST /api?<query> with a JSON body; return the response body.
        let post = |query: &str, body: &str| -> String {
            let mut request = Vec::new();
            write!(
                request,
                "POST /api?{query} HTTP/1.1\r\nHost: x\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                body.len()
            )
            .unwrap();
            request.extend_from_slice(body.as_bytes());
            String::from_utf8_lossy(&raw(port, &request)).to_string()
        };

        // The escalation: the query names the one authorised setting, the
        // body names a different one.
        let out = post(
            "mode=config&name=apikey&apikey=addkey",
            "{\"name\":\"script\",\"value\":\"/tmp/pwn.sh\"}",
        );
        assert!(
            !out.contains("\"status\":true"),
            "add-only key wrote a non-apikey setting through the bootstrap hatch: {out}"
        );

        // ...and it really did not land.
        let settings = cfg2.with_file_name("settings.json");
        let saved = std::fs::read_to_string(&settings).unwrap_or_default();
        assert!(
            !saved.contains("pwn.sh"),
            "the escalated setting was persisted anyway: {saved}"
        );

        // The hatch itself must still work, or an admin who set the NZB key
        // first is locked out of ever setting a full key.
        let ok = post(
            "mode=config&name=apikey&apikey=addkey",
            "{\"name\":\"apikey\",\"value\":\"thefullkey123\"}",
        );
        assert!(ok.contains("\"status\":true"), "the legitimate bootstrap broke: {ok}");
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// C1 (one-pass encrypted plan, 2026-07-31): a password attached via
/// mode=set_password WHILE the job is still downloading reaches the live
/// run through the hub's late-password cell and unlocks the set in that
/// same run - Completed, unlocked, no password_required parking, no
/// manual retry. Since the probe-window extension (C2 step 1) the unlock
/// normally happens IN-STREAM while the set is still parked; this test
/// pins only the run-level contract, whichever route wins - the one-pass
/// route itself is pinned by set_password_mid_download_goes_one_pass
/// below. Before C1 the download task's start-time copy of j.password
/// was stale forever, so the very password the user had already typed
/// sat unread until the job failed.
#[tokio::test(flavor = "multi_thread")]
async fn set_password_mid_download_unlocks_in_same_run() {
    use nzbkit::rar::fixtures;
    let dir = std::env::temp_dir().join(format!("nzbfast-latepw-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    // Encrypted RAR5 STORE set, no password known at enqueue: every slot's
    // mapper blocks (encrypted entry, no password) and the volumes demote
    // to disk - the exact shape the redditor hit.
    let inner = payload(24_000_003, 8);
    let f = fixtures::encrypt_file("l4tepw", &inner, 5);
    let n = f.cipher.len();
    let (a, b) = (8_000_016, 16_000_000); // 16-aligned mid splits
    let vols = [
        fixtures::rar5_volume_enc(&[("movie.mkv", &f, 0..a, false, true)], Some(0)),
        fixtures::rar5_volume_enc(&[("movie.mkv", &f, a..b, true, true)], Some(1)),
        fixtures::rar5_volume_enc(&[("movie.mkv", &f, b..n, true, false)], Some(2)),
    ];
    let mut articles = HashMap::new();
    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
    );
    for (i, vol) in vols.iter().enumerate() {
        let name = format!("lp.part{}.rar", i + 1);
        let segs = make_file_articles(&name, vol, 300_000, &format!("lp{i}"), &mut articles);
        xml.push_str(&format!(
            "  <file poster=\"x\" date=\"0\" subject=\"&quot;{name}&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
            segs.len()
        ));
        for (id, bytes, num) in &segs {
            xml.push_str(&format!(
                "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
            ));
        }
        xml.push_str("    </segments>\n  </file>\n");
    }
    xml.push_str("</nzb>\n");
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
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--apikey")
            .arg("sekrit")
            .arg("--out")
            .arg(dir.join("complete"))
            .arg("--connections")
            .arg("2")
            // ~8 s download window so set_password lands mid-download.
            .env("NZBFAST_THROTTLE_WRITE_MBPS", "3");
        c
    })
    .await;
    let port = d.port;

    let inner2 = inner.clone();
    let dir2 = dir.clone();
    tokio::task::spawn_blocking(move || {
        // Plain filename: NO {{password}} convention, no NZB meta.
        let boundary = "----latepwb";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!("--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"movie.nzb\"\r\n\r\n").as_bytes(),
        );
        body.extend_from_slice(xml.as_bytes());
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let r = http(
            port,
            "/api?mode=addfile&apikey=sekrit&output=json",
            Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
        );
        assert!(r.contains("\"status\":true"), "{r}");
        let id = r
            .split("SABnzbd_nzo_")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .map(|s| format!("SABnzbd_nzo_{s}"))
            .unwrap();

        // Wait for the download to actually start...
        let mut started = false;
        for _ in 0..150 {
            let q = http(port, "/api?mode=queue&apikey=sekrit&output=json", None);
            if q.contains(&id) && q.contains("Downloading") {
                started = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        assert!(started, "job never reached Downloading");
        // ...then attach the password mid-flight.
        let r = http(
            port,
            &format!("/api?mode=set_password&value={id}&password=l4tepw&apikey=sekrit&output=json"),
            None,
        );
        assert!(r.contains("\"status\":true"), "{r}");

        // The job must complete UNLOCKED in this same run.
        let mut slot = serde_json::Value::Null;
        for _ in 0..300 {
            let h = http(port, "/api?mode=history&apikey=sekrit&output=json", None);
            if let Some(s) = serde_json::from_str::<serde_json::Value>(&h)
                .ok()
                .and_then(|v| v["history"]["slots"].as_array().cloned())
                .and_then(|slots| slots.iter().find(|s| s["nzo_id"] == id.as_str()).cloned())
            {
                if s["status"] == "Completed" || s["status"] == "Failed" {
                    slot = s;
                    break;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        assert_eq!(slot["status"], "Completed", "{slot}");
        assert_eq!(
            slot["password_required"], false,
            "late password must unlock in the same run: {slot}"
        );

        // Plaintext on disk, byte-exact; spent volumes swept.
        let out = dir2.join("complete/movie");
        let mkv = std::fs::read(out.join("movie.mkv")).expect("movie.mkv missing");
        assert_eq!(mkv.len(), inner2.len());
        assert!(mkv == inner2, "decrypted payload differs");
        assert!(
            !out.join("lp.part1.rar").exists(),
            "spent volumes must be swept after the unlock"
        );
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// Any `lp.part*.rar` anywhere under `root` - a demoted volume
/// materializing on disk. The one-pass tests below poll this the whole
/// run: for their shape a sighting at ANY moment means the set demoted
/// (a demoted volume stays on disk until the finish sweep, so a 200ms
/// poll cannot miss it).
fn find_lp_volume(root: &std::path::Path) -> Option<std::path::PathBuf> {
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).into_iter().flatten().flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
            } else if p
                .file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with("lp.part"))
            {
                return Some(p);
            }
        }
    }
    None
}

/// C2 step 1 (probe-window extension): a password typed mid-download
/// reaches the slots PARKED by try_pw_await while their bytes are still
/// in RAM - the in-stream probe hook now collects the hub's late-password
/// cell as a structured candidate - so the job goes ONE-PASS. Volumes
/// never materialize on disk (no demote, no C1 unlock-from-disk at
/// finish), and the daemon log carries the in-stream probe's unlock line
/// naming set_password as the source.
#[tokio::test(flavor = "multi_thread")]
async fn set_password_mid_download_goes_one_pass() {
    use nzbkit::rar::fixtures;
    let dir = std::env::temp_dir().join(format!("nzbfast-latepw1p-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    // Same shape as set_password_mid_download_unlocks_in_same_run:
    // encrypted RAR5 STORE set, no password known at enqueue.
    let inner = payload(24_000_003, 8);
    let f = fixtures::encrypt_file("l4tepw", &inner, 5);
    let n = f.cipher.len();
    let (a, b) = (8_000_016, 16_000_000); // 16-aligned mid splits
    let vols = [
        fixtures::rar5_volume_enc(&[("movie.mkv", &f, 0..a, false, true)], Some(0)),
        fixtures::rar5_volume_enc(&[("movie.mkv", &f, a..b, true, true)], Some(1)),
        fixtures::rar5_volume_enc(&[("movie.mkv", &f, b..n, true, false)], Some(2)),
    ];
    let mut articles = HashMap::new();
    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
    );
    for (i, vol) in vols.iter().enumerate() {
        let name = format!("lp.part{}.rar", i + 1);
        let segs = make_file_articles(&name, vol, 300_000, &format!("lp{i}"), &mut articles);
        xml.push_str(&format!(
            "  <file poster=\"x\" date=\"0\" subject=\"&quot;{name}&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
            segs.len()
        ));
        for (id, bytes, num) in &segs {
            xml.push_str(&format!(
                "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
            ));
        }
        xml.push_str("    </segments>\n  </file>\n");
    }
    xml.push_str("</nzb>\n");
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
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--apikey")
            .arg("sekrit")
            .arg("--out")
            .arg(dir.join("complete"))
            .arg("--connections")
            .arg("2")
            // ~8 s download window so set_password lands mid-download
            // with most of the set still undownloaded.
            .env("NZBFAST_THROTTLE_WRITE_MBPS", "3");
        c
    })
    .await;
    let port = d.port;
    let daemon_log = d.log.clone();

    let inner2 = inner.clone();
    let dir2 = dir.clone();
    tokio::task::spawn_blocking(move || {
        // Plain filename: NO {{password}} convention, no NZB meta.
        let boundary = "----latepw1pb";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!("--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"movie.nzb\"\r\n\r\n").as_bytes(),
        );
        body.extend_from_slice(xml.as_bytes());
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let r = http(
            port,
            "/api?mode=addfile&apikey=sekrit&output=json",
            Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
        );
        assert!(r.contains("\"status\":true"), "{r}");
        let id = r
            .split("SABnzbd_nzo_")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .map(|s| format!("SABnzbd_nzo_{s}"))
            .unwrap();

        // Wait for actual BYTE progress, not just the Downloading status:
        // the status publishes before the download task captures
        // j.password, and a password landing in that gap is a start-time
        // password (no park, no probe) - exactly what this test must NOT
        // exercise. Bytes on the wire prove the capture already happened.
        let mut started = false;
        for _ in 0..300 {
            let q = http(port, "/api?mode=queue&apikey=sekrit&output=json", None);
            if let Some(s) = serde_json::from_str::<serde_json::Value>(&q)
                .ok()
                .and_then(|v| v["queue"]["slots"].as_array().cloned())
                .and_then(|slots| slots.iter().find(|s| s["nzo_id"] == id.as_str()).cloned())
            {
                let mb: f64 = s["mb"].as_str().unwrap_or("0").parse().unwrap_or(0.0);
                let mbleft: f64 = s["mbleft"].as_str().unwrap_or("0").parse().unwrap_or(0.0);
                if mb > 0.0 && mbleft < mb - 0.5 {
                    started = true;
                    break;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        assert!(started, "job never showed download progress");
        let r = http(
            port,
            &format!("/api?mode=set_password&value={id}&password=l4tepw&apikey=sekrit&output=json"),
            None,
        );
        assert!(r.contains("\"status\":true"), "{r}");

        // Wait for completion, checking the WHOLE way that no volume
        // ever materializes - the set must stay parked in RAM until the
        // probe re-keys it, then stream one-pass. A volume file at any
        // point means the set demoted and took C1's disk route instead.
        let mut slot = serde_json::Value::Null;
        for _ in 0..300 {
            if let Some(v) = find_lp_volume(&dir2.join("complete")) {
                panic!("set demoted: volume materialized at {}", v.display());
            }
            let h = http(port, "/api?mode=history&apikey=sekrit&output=json", None);
            if let Some(s) = serde_json::from_str::<serde_json::Value>(&h)
                .ok()
                .and_then(|v| v["history"]["slots"].as_array().cloned())
                .and_then(|slots| slots.iter().find(|s| s["nzo_id"] == id.as_str()).cloned())
            {
                if s["status"] == "Completed" || s["status"] == "Failed" {
                    slot = s;
                    break;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        assert_eq!(slot["status"], "Completed", "{slot}");
        assert_eq!(
            slot["password_required"], false,
            "late password must unlock in the same run: {slot}"
        );

        // Plaintext on disk, byte-exact; still no volumes anywhere.
        let out = dir2.join("complete/movie");
        let mkv = std::fs::read(out.join("movie.mkv")).expect("movie.mkv missing");
        assert_eq!(mkv.len(), inner2.len());
        assert!(mkv == inner2, "decrypted payload differs");
        assert!(
            find_lp_volume(&dir2.join("complete")).is_none(),
            "one-pass run must never leave volume files"
        );

        // And the unlock route is the in-stream probe fed by the typed
        // password - not a sidecar harvest, not the finish ladder.
        let log = std::fs::read_to_string(&daemon_log).unwrap_or_default();
        assert!(
            log.contains("set_password (typed mid-download)"),
            "expected the in-stream probe to credit set_password:\n{log}"
        );
        assert!(log.contains("(in-stream probe)"), "{log}");
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// Wrong-then-right: a wrong password typed mid-download must not burn
/// the corrected one. The probe hook's tried-set is keyed by
/// (salt, value), so the wrong value is remembered per-archive but the
/// correction is a NEW value and gets tested - the set still unlocks
/// in-stream and goes one-pass. (Keying the tried-set by salt alone
/// would skip the correction, demote the set, and fail this test with
/// volumes on disk.)
#[tokio::test(flavor = "multi_thread")]
async fn set_password_wrong_then_right_mid_download_one_pass() {
    use nzbkit::rar::fixtures;
    let dir = std::env::temp_dir().join(format!("nzbfast-latepwwr-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let inner = payload(24_000_003, 8);
    let f = fixtures::encrypt_file("l4tepw", &inner, 5);
    let n = f.cipher.len();
    let (a, b) = (8_000_016, 16_000_000); // 16-aligned mid splits
    let vols = [
        fixtures::rar5_volume_enc(&[("movie.mkv", &f, 0..a, false, true)], Some(0)),
        fixtures::rar5_volume_enc(&[("movie.mkv", &f, a..b, true, true)], Some(1)),
        fixtures::rar5_volume_enc(&[("movie.mkv", &f, b..n, true, false)], Some(2)),
    ];
    let mut articles = HashMap::new();
    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
    );
    for (i, vol) in vols.iter().enumerate() {
        let name = format!("lp.part{}.rar", i + 1);
        let segs = make_file_articles(&name, vol, 300_000, &format!("lp{i}"), &mut articles);
        xml.push_str(&format!(
            "  <file poster=\"x\" date=\"0\" subject=\"&quot;{name}&quot; yEnc (1/{})\">\n    <groups><group>g</group></groups>\n    <segments>\n",
            segs.len()
        ));
        for (id, bytes, num) in &segs {
            xml.push_str(&format!(
                "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
            ));
        }
        xml.push_str("    </segments>\n  </file>\n");
    }
    xml.push_str("</nzb>\n");
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
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--apikey")
            .arg("sekrit")
            .arg("--out")
            .arg(dir.join("complete"))
            .arg("--connections")
            .arg("2")
            .env("NZBFAST_THROTTLE_WRITE_MBPS", "3");
        c
    })
    .await;
    let port = d.port;
    let daemon_log = d.log.clone();

    let inner2 = inner.clone();
    let dir2 = dir.clone();
    tokio::task::spawn_blocking(move || {
        let boundary = "----latepwwrb";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!("--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"movie.nzb\"\r\n\r\n").as_bytes(),
        );
        body.extend_from_slice(xml.as_bytes());
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let r = http(
            port,
            "/api?mode=addfile&apikey=sekrit&output=json",
            Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
        );
        assert!(r.contains("\"status\":true"), "{r}");
        let id = r
            .split("SABnzbd_nzo_")
            .nth(1)
            .unwrap()
            .split('"')
            .next()
            .map(|s| format!("SABnzbd_nzo_{s}"))
            .unwrap();

        // Same progress-wait as the one-pass variant: bytes must be
        // flowing before the first password lands, so BOTH passwords go
        // through the probe rather than the start-time capture.
        let mut started = false;
        for _ in 0..300 {
            let q = http(port, "/api?mode=queue&apikey=sekrit&output=json", None);
            if let Some(s) = serde_json::from_str::<serde_json::Value>(&q)
                .ok()
                .and_then(|v| v["queue"]["slots"].as_array().cloned())
                .and_then(|slots| slots.iter().find(|s| s["nzo_id"] == id.as_str()).cloned())
            {
                let mb: f64 = s["mb"].as_str().unwrap_or("0").parse().unwrap_or(0.0);
                let mbleft: f64 = s["mbleft"].as_str().unwrap_or("0").parse().unwrap_or(0.0);
                if mb > 0.0 && mbleft < mb - 0.5 {
                    started = true;
                    break;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        assert!(started, "job never showed download progress");

        // The typo first. Two seconds is >2 probe cycles (750ms cadence,
        // spans arriving continuously under the throttle), so the wrong
        // value is genuinely tried and rejected - entering the tried-set
        // under this archive's salt - before the correction lands.
        let r = http(
            port,
            &format!("/api?mode=set_password&value={id}&password=wr0ngpw&apikey=sekrit&output=json"),
            None,
        );
        assert!(r.contains("\"status\":true"), "{r}");
        std::thread::sleep(std::time::Duration::from_secs(2));
        let r = http(
            port,
            &format!("/api?mode=set_password&value={id}&password=l4tepw&apikey=sekrit&output=json"),
            None,
        );
        assert!(r.contains("\"status\":true"), "{r}");

        let mut slot = serde_json::Value::Null;
        for _ in 0..300 {
            if let Some(v) = find_lp_volume(&dir2.join("complete")) {
                panic!(
                    "corrected password was skipped and the set demoted: \
                     volume materialized at {}",
                    v.display()
                );
            }
            let h = http(port, "/api?mode=history&apikey=sekrit&output=json", None);
            if let Some(s) = serde_json::from_str::<serde_json::Value>(&h)
                .ok()
                .and_then(|v| v["history"]["slots"].as_array().cloned())
                .and_then(|slots| slots.iter().find(|s| s["nzo_id"] == id.as_str()).cloned())
            {
                if s["status"] == "Completed" || s["status"] == "Failed" {
                    slot = s;
                    break;
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        assert_eq!(slot["status"], "Completed", "{slot}");
        assert_eq!(slot["password_required"], false, "{slot}");

        let out = dir2.join("complete/movie");
        let mkv = std::fs::read(out.join("movie.mkv")).expect("movie.mkv missing");
        assert_eq!(mkv.len(), inner2.len());
        assert!(mkv == inner2, "decrypted payload differs");
        assert!(
            find_lp_volume(&dir2.join("complete")).is_none(),
            "one-pass run must never leave volume files"
        );
        let log = std::fs::read_to_string(&daemon_log).unwrap_or_default();
        assert!(
            log.contains("set_password (typed mid-download)"),
            "expected the in-stream probe to credit set_password:\n{log}"
        );
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// The `prefer_external_unrar` setting, applied live over the API (no
/// restart), must hand a NAMED compressed set to the unrar subprocess:
/// the top-level chase latches off (so the set materializes instead of
/// streaming through the native decoder) and the disk unpack skips the
/// native engine. Opt-in like the compressed e2e: needs a working
/// `unrar` on PATH, which CI does not install.
#[tokio::test(flavor = "multi_thread")]
async fn prefer_external_unrar_setting_routes_unpack_to_subprocess() {
    let have = |c: &str| {
        std::env::var_os("PATH").is_some_and(|p| {
            std::env::split_paths(&p)
                .any(|d| d.join(c).is_file() || d.join(format!("{c}.exe")).is_file())
        })
    };
    if !have("unrar") {
        eprintln!("skipping: unrar not installed");
        return;
    }
    let dir = std::env::temp_dir().join(format!("nzbfast-extunrar-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    // Real WinRAR m3 fixture: compressed, so it can never one-pass as a
    // store set - with the chase latched off it must reach the disk path.
    let arch = std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../vendor/rars/tests/fixtures/rar50/m3_default.rar"),
    )
    .unwrap();
    let mut articles = HashMap::new();
    let segs = make_file_articles("c.rar", &arch, 4000, "xu", &mut articles);
    let srv = MockServer::start(articles, Chaos::default()).await;

    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file poster=\"x\" date=\"0\" subject=\"&quot;c.rar&quot; yEnc (1/3)\">\n    <groups><group>g</group></groups>\n    <segments>\n",
    );
    for (id, bytes, num) in &segs {
        xml.push_str(&format!(
            "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
        ));
    }
    xml.push_str("    </segments>\n  </file>\n</nzb>\n");

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
    delete_without_the_trash(&cfg);
    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            .arg("--config")
            .arg(&cfg)
            .arg("serve")
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--apikey")
            .arg("sekrit")
            .arg("--out")
            .arg(dir.join("complete"));
        c
    })
    .await;
    let port = d.port;
    let daemon_log = d.log.clone();

    let dir2 = dir.clone();
    tokio::task::spawn_blocking(move || {
        // Flip the setting over the API - the whole point is that it
        // applies to the job added next, with no daemon restart.
        let r = http(
            port,
            "/api?mode=config&name=prefer_external_unrar&value=1&apikey=sekrit&output=json",
            None,
        );
        assert!(!r.contains("error"), "setting rejected: {r}");
        let r = http(port, "/api?mode=get_config&apikey=sekrit&output=json", None);
        assert!(
            r.contains("\"prefer_external_unrar\":true"),
            "get_config does not echo the setting: {r}"
        );

        let boundary = "----nzbfastboundary";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"compressed.nzb\"\r\nContent-Type: application/x-nzb\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(xml.as_bytes());
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let ctype = format!("multipart/form-data; boundary={boundary}");
        let r = http(port, "/api?mode=addfile&apikey=sekrit&output=json", Some((&ctype, &body)));
        assert!(r.contains("\"status\":true"), "{r}");

        let mut done = false;
        for _ in 0..300 {
            let h = http(port, "/api?mode=history&apikey=sekrit&output=json", None);
            if h.contains("\"Completed\"") {
                done = true;
                break;
            }
            assert!(!h.contains("\"Failed\""), "job failed:\n{h}");
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        let log = std::fs::read_to_string(&daemon_log).unwrap_or_default();
        assert!(done, "download never completed\n--- daemon log ---\n{log}");

        // The routing proof: the subprocess ran, the native engine did not.
        assert!(
            log.contains("unpacking archive with unrar"),
            "unrar subprocess never chosen:\n{log}"
        );
        assert!(log.contains("unrar complete"), "unrar did not finish:\n{log}");
        assert!(
            !log.contains("unpacking archive natively"),
            "native engine ran despite prefer_external_unrar:\n{log}"
        );

        // And the payload it published is really there.
        fn find(dir: &Path, name: &str) -> bool {
            std::fs::read_dir(dir).into_iter().flatten().flatten().any(|e| {
                let p = e.path();
                if p.is_dir() {
                    find(&p, name)
                } else {
                    p.file_name().is_some_and(|n| n == name)
                }
            })
        }
        assert!(
            find(&dir2.join("complete"), "bigtext_64k.bin"),
            "unpacked payload missing:\n{log}"
        );
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// The counterpart guarantee: an OBFUSCATED hash-named set ignores
/// `prefer_external_unrar` and unpacks natively - the unrar subprocess
/// derives volume names from the first volume's, which for a hash name
/// names nothing on disk, so the native header-order path is the only
/// one that can unpack this shape. Needs no external tools at all, so
/// it runs everywhere including CI.
#[tokio::test(flavor = "multi_thread")]
async fn prefer_external_unrar_setting_ignored_for_obfuscated_sets() {
    let dir = std::env::temp_dir().join(format!("nzbfast-extunrar-obf-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    // The same compressed fixture under a hash name: compressed so the
    // store path demotes it to disk, extensionless so only the
    // obfuscated sniff can claim it there.
    let arch = std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../vendor/rars/tests/fixtures/rar50/m3_default.rar"),
    )
    .unwrap();
    let mut articles = HashMap::new();
    let segs = make_file_articles("a91f3c0d77b2e4", &arch, 4000, "xo", &mut articles);
    let srv = MockServer::start(articles, Chaos::default()).await;

    let mut xml = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file poster=\"x\" date=\"0\" subject=\"kDjq0 [1/1]\">\n    <groups><group>g</group></groups>\n    <segments>\n",
    );
    for (id, bytes, num) in &segs {
        xml.push_str(&format!(
            "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
        ));
    }
    xml.push_str("    </segments>\n  </file>\n</nzb>\n");

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
    delete_without_the_trash(&cfg);
    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            .arg("--config")
            .arg(&cfg)
            .arg("serve")
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--apikey")
            .arg("sekrit")
            .arg("--out")
            .arg(dir.join("complete"));
        c
    })
    .await;
    let port = d.port;
    let daemon_log = d.log.clone();

    let dir2 = dir.clone();
    tokio::task::spawn_blocking(move || {
        let r = http(
            port,
            "/api?mode=config&name=prefer_external_unrar&value=1&apikey=sekrit&output=json",
            None,
        );
        assert!(!r.contains("error"), "setting rejected: {r}");

        let boundary = "----nzbfastboundary";
        let mut body = Vec::new();
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"obf.nzb\"\r\nContent-Type: application/x-nzb\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(xml.as_bytes());
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let ctype = format!("multipart/form-data; boundary={boundary}");
        let r = http(port, "/api?mode=addfile&apikey=sekrit&output=json", Some((&ctype, &body)));
        assert!(r.contains("\"status\":true"), "{r}");

        let mut done = false;
        for _ in 0..300 {
            let h = http(port, "/api?mode=history&apikey=sekrit&output=json", None);
            if h.contains("\"Completed\"") {
                done = true;
                break;
            }
            assert!(!h.contains("\"Failed\""), "job failed:\n{h}");
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        let log = std::fs::read_to_string(&daemon_log).unwrap_or_default();
        assert!(done, "download never completed\n--- daemon log ---\n{log}");

        // The hash-named set took the native obfuscated path, and the
        // setting never routed it at the subprocess.
        assert!(
            log.contains("obfuscated RAR set"),
            "obfuscated handoff never engaged:\n{log}"
        );
        assert!(
            log.contains("native unpack complete"),
            "native obfuscated unpack did not finish:\n{log}"
        );
        assert!(
            !log.contains("unpacking archive with unrar"),
            "obfuscated set was handed to the unrar subprocess:\n{log}"
        );

        fn find(dir: &Path, name: &str) -> bool {
            std::fs::read_dir(dir).into_iter().flatten().flatten().any(|e| {
                let p = e.path();
                if p.is_dir() {
                    find(&p, name)
                } else {
                    p.file_name().is_some_and(|n| n == name)
                }
            })
        }
        assert!(
            find(&dir2.join("complete"), "bigtext_64k.bin"),
            "unpacked payload missing:\n{log}"
        );
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

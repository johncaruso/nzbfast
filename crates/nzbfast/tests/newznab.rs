//! M12 gate: the newznab facade - Sonarr/Radarr can use nzbfast as an
//! INDEXER (caps/search/tvsearch → items → /getnzb), and the continuous
//! scan loop populates the index from a live (mock) news server.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};

use nzbkit::mock::{Chaos, MockServer, OverRow};
use nzbkit::nntp::OverEntry;

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// (status, body) of a GET against the daemon.
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
fn http_get(port: u16, req: &str) -> (u16, String) {
    let mut last = String::new();
    for attempt in 0..5u32 {
        match http_get_once(port, req) {
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
fn http_get_once(port: u16, req: &str) -> std::io::Result<(u16, String)> {
    let mut s = TcpStream::connect(("127.0.0.1", port))?;
    write!(s, "GET {req} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n\r\n")?;
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
    let status: u16 = out
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    Ok((status, out.split("\r\n\r\n").nth(1).unwrap_or("").to_string()))
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

fn over(number: u64, subject: &str, msgid: &str, bytes: u64) -> OverEntry {
    OverEntry {
        number,
        subject: subject.into(),
        from: "poster@x".into(),
        message_id: msgid.into(),
        bytes,
        date: 0,
    }
}

/// Same, but carrying the article's own Date - which is what makes the
/// release's upload time differ from the time we indexed it.
fn over_dated(number: u64, subject: &str, msgid: &str, bytes: u64, date: i64) -> OverEntry {
    OverEntry { date, ..over(number, subject, msgid, bytes) }
}

#[tokio::test(flavor = "multi_thread")]
async fn newznab_caps_search_and_getnzb() {
    let dir = std::env::temp_dir().join(format!("nzbfast-nn-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    // Seed a complete 2-file release + an incomplete one directly.
    let db = dir.join("index.db");
    {
        let mut ix = nzbkit::index::Index::open(&db).unwrap();
        ix.ingest(
            "alt.binaries.teevee",
            &[
                over(1, "\"Show.Name.S01E02.1080p.rar\" yEnc (1/1)", "<a1@x>", 1000),
                over(2, "\"Show.Name.S01E02.1080p.par2\" yEnc (1/1)", "<a2@x>", 200),
                over(3, "\"Partial.Movie.2026.rar\" yEnc (1/2)", "<b1@x>", 1000),
            ],
            1_700_000_000,
        )
        .unwrap();
    }

    let cfg = dir.join("config.json");
    std::fs::write(&cfg, "{\"servers\":[{\"host\":\"127.0.0.1\",\"port\":1,\"tls\":false}]}")
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
            .arg("--apikey")
            .arg("sekrit")
            .arg("--out")
            .arg(dir.join("complete"))
            .arg("--index-db")
            .arg(&db);
        c
    })
    .await;
    let port = d.port;

    tokio::task::spawn_blocking(move || {
        // Auth required.
        let (code, _) = http_get(port, "/api?t=caps");
        assert_eq!(code, 401);
        // Caps.
        let (code, body) = http_get(port, "/api?t=caps&apikey=sekrit");
        assert_eq!(code, 200);
        assert!(body.contains("<caps>") && body.contains("tv-search"), "{body}");
        // Search: only the COMPLETE release is offered, categorized TV.
        let (_, body) = http_get(port, "/newznab/api?t=search&q=show&apikey=sekrit");
        assert!(body.contains("Show.Name.S01E02.1080p"), "{body}");
        assert!(body.contains("value=\"5000\""), "{body}");
        assert!(!body.contains("Partial.Movie"), "{body}");
        // tvsearch with season/ep params finds it too.
        let (_, body) = http_get(
            port,
            "/api?t=tvsearch&q=show+name&season=1&ep=2&apikey=sekrit",
        );
        assert!(body.contains("Show.Name.S01E02"), "{body}");
        // Follow the enclosure link → NZB with the seeded segment ids.
        let link = body
            .split("<link>")
            .nth(1)
            .and_then(|r| r.split("</link>").next())
            .expect("item link")
            .replace("&amp;", "&");
        let path = link.split(&format!(":{port}")).nth(1).expect("relative path");
        let (code, nzb) = http_get(port, path);
        assert_eq!(code, 200, "{nzb}");
        assert!(nzb.contains("<nzb"), "{nzb}");
        assert!(nzb.contains("a1@x") && nzb.contains("a2@x"), "{nzb}");
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test(flavor = "multi_thread")]
async fn scan_loop_populates_index_live() {
    let dir = std::env::temp_dir().join(format!("nzbfast-nnscan-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    // Mock server with a header plane: two-file complete release.
    let rows = vec![
        OverRow {
            number: 10,
            subject: "\"Live.Show.S03E07.720p.rar\" yEnc (1/1)".into(),
            from: "poster@x".into(),
            message_id: "<lv1@x>".into(),
            bytes: 5000,
        },
        OverRow {
            number: 11,
            subject: "\"Live.Show.S03E07.720p.par2\" yEnc (1/1)".into(),
            from: "poster@x".into(),
            message_id: "<lv2@x>".into(),
            bytes: 500,
        },
    ];
    let srv =
        MockServer::start_full(Default::default(), Default::default(), rows, Chaos::default())
            .await;

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
    let db = dir.join("index.db");
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
            .arg("--index-db")
            .arg(&db)
            .arg("--index-groups")
            .arg("mock.group")
            .arg("--index-interval")
            .arg("30");
        c
    })
    .await;
    let port = d.port;

    tokio::task::spawn_blocking(move || {
        // The first scan pass should land the release within seconds.
        for i in 0..100 {
            let (_, body) = http_get(port, "/api?t=search&q=live+show");
            if body.contains("Live.Show.S03E07.720p") {
                assert!(body.contains("value=\"5000\""), "{body}");
                return;
            }
            if i == 99 {
                panic!("scan loop never indexed the release:\n{body}");
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// Number of `<item>` elements in a feed.
fn items(body: &str) -> usize {
    body.matches("<item>").count()
}

/// The numeric categories are the standard newznab tree in BOTH
/// directions: `cat=` selects the kind it names, and the id reported back
/// is the one that kind would have been asked for. Software (PC, 4000)
/// was the regression - it filtered and reported as Other, so a client
/// asking for cat=4000 saw no software at all, and software that did come
/// back was labelled 2000/8000.
#[tokio::test(flavor = "multi_thread")]
async fn newznab_categories_follow_the_standard_tree() {
    let dir = std::env::temp_dir().join(format!("nzbfast-nncat-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    // One complete release per kind we carry an id for.
    let db = dir.join("index.db");
    {
        let mut ix = nzbkit::index::Index::open(&db).unwrap();
        ix.ingest(
            "alt.binaries.misc",
            &[
                over(1, "\"CCleaner.Pro.Plus.v6.36.x64.Setup.rar\" yEnc (1/1)", "<s1@x>", 1000),
                over(2, "\"CCleaner.Pro.Plus.v6.36.x64.Setup.par2\" yEnc (1/1)", "<s2@x>", 200),
                over(3, "\"Cat.Show.S04E01.1080p.rar\" yEnc (1/1)", "<t1@x>", 1000),
                over(4, "\"Cat.Show.S04E01.1080p.par2\" yEnc (1/1)", "<t2@x>", 200),
                over(5, "\"Cat.Movie.2019.1080p.BluRay.rar\" yEnc (1/1)", "<m1@x>", 1000),
                over(6, "\"Cat.Movie.2019.1080p.BluRay.par2\" yEnc (1/1)", "<m2@x>", 200),
            ],
            1_700_000_000,
        )
        .unwrap();
    }

    let cfg = dir.join("config.json");
    std::fs::write(&cfg, "{\"servers\":[{\"host\":\"127.0.0.1\",\"port\":1,\"tls\":false}]}")
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
            .arg("--index-db")
            .arg(&db);
        c
    })
    .await;
    let port = d.port;

    tokio::task::spawn_blocking(move || {
        // cat=4000 selects software, and software reports 4000 back.
        let (_, body) = http_get(port, "/api?t=search&cat=4000");
        assert_eq!(items(&body), 1, "{body}");
        assert!(body.contains("CCleaner.Pro.Plus"), "{body}");
        assert!(body.contains("value=\"4000\""), "{body}");

        // A PC SUBcategory (4050 = PC/Games) rides its parent's thousand.
        let (_, body) = http_get(port, "/api?t=search&cat=4050");
        assert!(body.contains("CCleaner.Pro.Plus"), "{body}");

        // The other two kinds keep their own ids, and no longer swallow
        // software the way the old `_ => other` arm did.
        let (_, body) = http_get(port, "/api?t=search&cat=5000,5040");
        assert_eq!(items(&body), 1, "{body}");
        assert!(body.contains("Cat.Show.S04E01") && body.contains("value=\"5000\""), "{body}");
        let (_, body) = http_get(port, "/api?t=search&cat=2000");
        assert_eq!(items(&body), 1, "{body}");
        assert!(body.contains("Cat.Movie.2019") && body.contains("value=\"2000\""), "{body}");

        // Categories we carry nothing for (3000 Audio, 7000 Books) are an
        // empty feed - never a silently unfiltered one.
        for cat in ["3000", "7000", "6000", "1000"] {
            let (code, body) = http_get(port, &format!("/api?t=search&cat={cat}"));
            assert_eq!(code, 200, "{body}");
            assert_eq!(items(&body), 0, "cat={cat} answered with items:\n{body}");
        }

        // No cat at all still means no filter: all three come back.
        let (_, body) = http_get(port, "/api?t=search");
        assert_eq!(items(&body), 3, "{body}");

        // Caps advertise PC alongside the rest, so a client knows to ask.
        let (_, caps) = http_get(port, "/api?t=caps");
        assert!(caps.contains(r#"<category id="4000" name="PC"/>"#), "{caps}");
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

/// The pubDate of the feed item whose title contains `needle`.
fn pubdate_of(body: &str, needle: &str) -> String {
    for item in body.split("<item>").skip(1) {
        let item = item.split("</item>").next().unwrap_or("");
        if item.contains(needle) {
            return item
                .split("<pubDate>")
                .nth(1)
                .and_then(|r| r.split("</pubDate>").next())
                .unwrap_or_default()
                .to_string();
        }
    }
    panic!("no item for {needle} in feed:\n{body}");
}

/// A feed item is dated when it was UPLOADED, not when we indexed it.
///
/// Sonarr and Radarr take a release's age straight from pubDate and
/// reject on it twice: against the provider's retention, and against the
/// minimum-age hold that gives a bad post time to be replaced before they
/// grab it. Dating everything "now" makes a five-year-old backfilled
/// release look minutes old, so the minimum-age hold never fires and
/// retention never trims.
///
/// The other side of it: `first_posted` 0 is a live sentinel for a
/// release whose OVER Date did not parse, and dating THOSE 1970 reads as
/// infinitely old and gets them rejected wholesale. They fall back to
/// when we saw them.
#[tokio::test(flavor = "multi_thread")]
async fn feed_items_are_dated_by_upload_not_by_index_time() {
    let dir = std::env::temp_dir().join(format!("nzbfast-nndate-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    // 14 Jul 2017, the upload date carried by the articles.
    const UPLOADED: i64 = 1_500_000_000;
    // 2 Feb 2026, when this install indexed them.
    const INDEXED: i64 = 1_770_000_000;

    let db = dir.join("index.db");
    {
        let mut ix = nzbkit::index::Index::open(&db).unwrap();
        // A backfilled release: posted years ago, indexed today.
        ix.ingest(
            "alt.binaries.teevee",
            &[
                over_dated(1, "\"Old.Show.S01E01.1080p.rar\" yEnc (1/1)", "<o1@x>", 1000, UPLOADED),
                over_dated(2, "\"Old.Show.S01E01.1080p.par2\" yEnc (1/1)", "<o2@x>", 200, UPLOADED),
            ],
            INDEXED,
        )
        .unwrap();
        // A release whose Date never parsed: first_seen is real, but
        // first_posted walks down to the 0 sentinel. (The MIN on conflict
        // is what a backfill leg does; first_seen is not rewritten.)
        let undated = [
            over(3, "\"Nodate.Show.S02E02.1080p.rar\" yEnc (1/1)", "<n1@x>", 1000),
            over(4, "\"Nodate.Show.S02E02.1080p.par2\" yEnc (1/1)", "<n2@x>", 200),
        ];
        ix.ingest("alt.binaries.teevee", &undated, INDEXED).unwrap();
        ix.ingest("alt.binaries.teevee", &undated, 0).unwrap();
    }

    let cfg = dir.join("config.json");
    std::fs::write(&cfg, "{\"servers\":[{\"host\":\"127.0.0.1\",\"port\":1,\"tls\":false}]}")
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
            .arg("--index-db")
            .arg(&db);
        c
    })
    .await;
    let port = d.port;

    tokio::task::spawn_blocking(move || {
        let (code, body) = http_get(port, "/api?t=search");
        assert_eq!(code, 200, "{body}");
        assert_eq!(items(&body), 2, "{body}");

        // The backfilled one advertises 2017, the year it was posted -
        // not 2026, the year we happened to scan the group.
        let old = pubdate_of(&body, "Old.Show.S01E01");
        assert!(
            old.contains(" 2017 "),
            "backfilled release is dated by index time, not upload time: {old}\n{body}"
        );

        // The unknown-date one keeps its first_seen and is NOT dated 1970.
        let nodate = pubdate_of(&body, "Nodate.Show.S02E02");
        assert!(
            nodate.contains(" 2026 "),
            "unknown-date release should fall back to when we saw it: {nodate}\n{body}"
        );
        assert!(!nodate.contains("1970"), "unknown-date release dated at the epoch: {nodate}");
    })
    .await
    .unwrap();
    let _ = std::fs::remove_dir_all(&dir);
}

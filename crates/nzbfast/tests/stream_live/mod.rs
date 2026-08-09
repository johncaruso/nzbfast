//! M11 playback: the five rigs that drive /stream against a job that
//! is still downloading - plain and encrypted store-mode rars, the
//! seek that promotes a deep window, the deep-window preempt, and the
//! `addfile&stream=1` front door with its player-handoff links.
//!
//! A sibling-dir child of daemon.rs (the daemon_chip6 / stream_chaos
//! pattern) so the parent stays inside its size-gate baseline; harness
//! via `super::*`.

use super::*;

#[tokio::test(flavor = "multi_thread")]
async fn stream_while_downloading() {
    // M11: a store-mode rar'd mkv streams over /stream with correct bytes
    // WHILE the download is still running (write stage throttled to keep
    // the window open; the reader must block on not-yet-landed spans).
    use nzbkit::rar::fixtures;
    let dir = std::env::temp_dir().join(format!("nzbfast-stream-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    let inner = payload(24_000_000, 7); // 24 MB "movie"
    let vols = [
        fixtures::rar5_volume_n(
            &[("movie.mkv", 24_000_000, &inner[..8_000_000], false, true)],
            0,
        ),
        fixtures::rar5_volume_n(
            &[(
                "movie.mkv",
                24_000_000,
                &inner[8_000_000..16_000_000],
                true,
                true,
            )],
            1,
        ),
        fixtures::rar5_volume_n(
            &[("movie.mkv", 24_000_000, &inner[16_000_000..], true, false)],
            2,
        ),
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
    let _scratch = scratch::ScratchDir::attach(&dir);

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
            if let Some(p) = raw.windows(4).position(|w| w == b"\r\n\r\n")
                && String::from_utf8_lossy(&raw[..p]).contains("206") {
                    got = raw[p + 4..].to_vec();
                    break;
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
    let _scratch = scratch::ScratchDir::attach(&dir);

    // 48 MB movie in 3 store-mode rar5 volumes of 16 MB payload each:
    // volA = inner[0..16M], volB = [16..32M], volC = [32..48M]. Volumes
    // are sized well above the promote window's 4 MB PRE_ROLL so a
    // mid-volume seek still provably enters the volume mid-way.
    let inner = payload(48_000_000, 11);
    let vols = [
        fixtures::rar5_volume_n(
            &[("movie.mkv", 48_000_000, &inner[..16_000_000], false, true)],
            0,
        ),
        fixtures::rar5_volume_n(
            &[(
                "movie.mkv",
                48_000_000,
                &inner[16_000_000..32_000_000],
                true,
                true,
            )],
            1,
        ),
        fixtures::rar5_volume_n(
            &[("movie.mkv", 48_000_000, &inner[32_000_000..], true, false)],
            2,
        ),
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
    let _scratch = scratch::ScratchDir::attach(&dir);

    let inner = payload(48_000_000, 13);
    let vols = [
        fixtures::rar5_volume_n(
            &[("movie.mkv", 48_000_000, &inner[..16_000_000], false, true)],
            0,
        ),
        fixtures::rar5_volume_n(
            &[(
                "movie.mkv",
                48_000_000,
                &inner[16_000_000..32_000_000],
                true,
                true,
            )],
            1,
        ),
        fixtures::rar5_volume_n(
            &[("movie.mkv", 48_000_000, &inner[32_000_000..], true, false)],
            2,
        ),
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
    let _scratch = scratch::ScratchDir::attach(&dir);

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

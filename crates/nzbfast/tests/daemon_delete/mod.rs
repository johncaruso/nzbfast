//! The NZBGet delete verbs, end to end: what each of the four does to
//! the queue, to history and to the files, and what deleting a job the
//! prefetch sidecar is still running has to wait for.
//!
//! A submodule of the daemon target rather than its own `tests/*.rs`,
//! for the reason every sibling here is one: a top-level file would
//! become a separate target and fall out of the standard daemon gate.
//! It also keeps daemon.rs under the size gate (TODO 106) - these two
//! legs arrived with the delete verbs in 65c3498c and pushed it over.

use super::*;

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
    let _scratch = scratch::ScratchDir::attach(&dir);

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
    let b_segs = make_file_articles(
        "doomed.bin",
        &payload(2_000_000, 63),
        40_000,
        "fd",
        &mut fast_articles,
    );
    let c_segs = make_file_articles(
        "keeps.bin",
        &payload(600_000, 65),
        40_000,
        "fk",
        &mut fast_articles,
    );
    let slow_srv = MockServer::start(
        slow_articles,
        Chaos {
            delay_ms: 250,
            ..Chaos::default()
        },
    )
    .await;
    let fast_srv = MockServer::start(
        fast_articles,
        Chaos {
            delay_ms: 250,
            ..Chaos::default()
        },
    )
    .await;

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

    let out_root = dir.join("complete");
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

        // M5: GroupDelete is delete-and-file, not delete-and-forget. The
        // job leaves the queue, never publishes as a finished download,
        // and history gets a row that says the user removed it.
        assert!(qslot(&q, &b_id).is_null(), "the deleted job is still queued: {q}");
        let hslot = |h: &str, id: &str| -> serde_json::Value {
            let v: serde_json::Value = serde_json::from_str(h)
                .unwrap_or_else(|e| panic!("bad history JSON: {e}\n{h}"));
            v["history"]["slots"]
                .as_array()
                .and_then(|a| a.iter().find(|s| s["nzo_id"] == id).cloned())
                .unwrap_or(serde_json::Value::Null)
        };
        let b_row = hslot(&h, &b_id);
        assert!(
            !b_row.is_null(),
            "GroupDelete must file a history row for the job it removed: {h}"
        );
        assert_eq!(
            b_row["status"], "Failed",
            "a deleted row must not read as a finished download: {b_row}"
        );
        assert_eq!(b_row["fail_message"], "deleted from the queue", "{b_row}");
        // The NZBGet view spells the same row in NZBGet's own vocabulary.
        let jr = http(
            port,
            "/jsonrpc",
            Some((
                "application/json",
                br#"{"method":"history","id":9}"#.as_slice(),
            )),
        );
        assert!(
            jr.contains("\"DELETED/MANUAL\""),
            "the JSON-RPC history must mark the deleted row DELETED/MANUAL: {jr}"
        );

        // M5's active leg: GroupDelete on the DOWNLOADING job. The
        // pipeline aborts, park() finishes the cleanup - removes the
        // files GroupDelete asked for - and files the history row.
        let a_nzbid: i64 = a_id
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
            "{{\"method\":\"editqueue\",\"params\":[\"GroupDelete\",\"\",[{a_nzbid}]],\"id\":8}}"
        );
        let r = http(port, "/jsonrpc", Some(("application/json", body.as_bytes())));
        assert!(r.contains("true"), "GroupDelete of the active job refused: {r}");
        let (_, h) = poll(
            &|_, h| {
                let v: serde_json::Value = match serde_json::from_str(h) {
                    Ok(v) => v,
                    Err(_) => return false,
                };
                v["history"]["slots"]
                    .as_array()
                    .is_some_and(|a| a.iter().any(|s| s["nzo_id"] == a_id.as_str()))
            },
            "the active delete to park into history",
        );
        let a_row = hslot(&h, &a_id);
        assert_eq!(a_row["fail_message"], "deleted from the queue", "{a_row}");
        // The files half is deferred to park, so it is allowed to lag
        // the history row by the drain - poll rather than assert.
        let a_out = out_root.join("grinder");
        for _ in 0..300 {
            if !a_out.exists() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        assert!(
            !a_out.exists(),
            "an active GroupDelete must remove the payload once the fetch drains: {}",
            a_out.display()
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

/// M5 (14 Aug sweep): the four NZBGet delete verbs carry four distinct
/// contracts, and one collapsed arm served them all - no file removal,
/// no history row, every variant identical. Per NZBGet's editqueue
/// documentation and the nzbgetcom ChangeLog:
///
///   GroupDelete      files deleted, history row DELETED/MANUAL
///   GroupDupeDelete  files deleted, history row DELETED/DUPE
///   GroupFinalDelete files deleted, NO history row (what Sonarr and
///                    Radarr send to cancel - the orphaned-payload bug)
///   GroupParkDelete  files RETAINED, history row DELETED/MANUAL
///
/// Queued fixtures against a dead server, paused, so every job sits
/// still while its verb lands. The retry at the end proves the filed
/// rows are live records (spooled NZB kept, tombstone scrubbed), not
/// just rendered corpses.
#[tokio::test(flavor = "multi_thread")]
async fn nzbget_delete_variants_keep_their_own_contracts() {
    let dir = std::env::temp_dir().join(format!("nzbfast-rpcvariants-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let dead_port = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    let cfg = dir.join("config.json");
    std::fs::write(
        &cfg,
        format!("{{\"servers\":[{{\"host\":\"127.0.0.1\",\"port\":{dead_port},\"tls\":false}}]}}"),
    )
    .unwrap();
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
            .arg("--out")
            .arg(dir.join("complete"));
        c
    })
    .await;
    let port = d.port;

    tokio::task::spawn_blocking(move || {
        let upload = |stem: &str| -> String {
            let xml = format!(
                "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  <file poster=\"x\" date=\"0\" subject=\"{stem}.bin (1/1)\">\n    <groups><group>g</group></groups>\n    <segments>\n      <segment bytes=\"10000\" number=\"1\">{stem}seg1@test</segment>\n    </segments>\n  </file>\n</nzb>\n"
            );
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
            let r = http(port, "/api?mode=addfile&output=json", Some((&ctype, &body)));
            assert!(r.contains("\"status\":true"), "{r}");
            r.split("SABnzbd_nzo_").nth(1).unwrap().split('"').next()
                .map(|s| format!("SABnzbd_nzo_{s}")).unwrap()
        };
        let nzbid = |nzo: &str| -> i64 {
            nzo.chars()
                .rev()
                .take_while(|c| c.is_ascii_digit())
                .collect::<String>()
                .chars()
                .rev()
                .collect::<String>()
                .parse()
                .unwrap()
        };
        let editqueue = |cmd: &str, id: i64| -> String {
            let body = format!(
                "{{\"method\":\"editqueue\",\"params\":[\"{cmd}\",\"\",[{id}]],\"id\":3}}"
            );
            http(port, "/jsonrpc", Some(("application/json", body.as_bytes())))
        };
        let hslot = |h: &str, id: &str| -> serde_json::Value {
            let v: serde_json::Value = serde_json::from_str(h)
                .unwrap_or_else(|e| panic!("bad history JSON: {e}\n{h}"));
            v["history"]["slots"]
                .as_array()
                .and_then(|a| a.iter().find(|s| s["nzo_id"] == id).cloned())
                .unwrap_or(serde_json::Value::Null)
        };

        let r = http(port, "/api?mode=pause&output=json", None);
        assert!(r.contains("\"status\":true"), "{r}");
        let ids: Vec<String> = ["alpha", "bravo", "charlie", "delta"]
            .iter()
            .map(|s| upload(s))
            .collect();
        // Every job gets a payload directory the verb must judge: three
        // verbs delete it, one retains it.
        for stem in ["alpha", "bravo", "charlie", "delta"] {
            let p = out.join(stem);
            std::fs::create_dir_all(&p).unwrap();
            std::fs::write(p.join("part.bin"), b"partial payload").unwrap();
        }

        for (cmd, nzo) in [
            ("GroupDelete", &ids[0]),
            ("GroupDupeDelete", &ids[1]),
            ("GroupFinalDelete", &ids[2]),
            ("GroupParkDelete", &ids[3]),
        ] {
            let r = editqueue(cmd, nzbid(nzo));
            assert!(r.contains("true"), "{cmd} refused: {r}");
        }

        let q = http(port, "/api?mode=queue&output=json", None);
        let v: serde_json::Value = serde_json::from_str(&q).unwrap();
        assert_eq!(v["queue"]["slots"].as_array().map(Vec::len), Some(0), "{q}");

        // File retention per verb.
        assert!(!out.join("alpha").exists(), "GroupDelete must remove the files");
        assert!(!out.join("bravo").exists(), "GroupDupeDelete must remove the files");
        assert!(!out.join("charlie").exists(), "GroupFinalDelete must remove the files");
        assert!(
            out.join("delta").join("part.bin").exists(),
            "GroupParkDelete must retain the downloaded files"
        );

        // History per verb, SAB view: three rows filed, FinalDelete none.
        let h = http(port, "/api?mode=history&output=json", None);
        assert_eq!(hslot(&h, &ids[0])["fail_message"], "deleted from the queue", "{h}");
        assert_eq!(
            hslot(&h, &ids[1])["fail_message"],
            "deleted from the queue as a duplicate",
            "{h}"
        );
        assert!(
            hslot(&h, &ids[2]).is_null(),
            "GroupFinalDelete must not file a history row: {h}"
        );
        assert_eq!(hslot(&h, &ids[3])["fail_message"], "deleted from the queue", "{h}");

        // The same rows in NZBGet's own vocabulary.
        let jr = http(
            port,
            "/jsonrpc",
            Some(("application/json", br#"{"method":"history","id":4}"#.as_slice())),
        );
        let v: serde_json::Value = serde_json::from_str(&jr).unwrap();
        let jr_status = |id: i64| -> String {
            v["result"]
                .as_array()
                .and_then(|a| a.iter().find(|e| e["NZBID"] == id))
                .map(|e| {
                    format!(
                        "{} {}",
                        e["Status"].as_str().unwrap_or(""),
                        e["DeleteStatus"].as_str().unwrap_or("")
                    )
                })
                .unwrap_or_default()
        };
        assert_eq!(jr_status(nzbid(&ids[0])), "DELETED/MANUAL MANUAL", "{jr}");
        assert_eq!(jr_status(nzbid(&ids[1])), "DELETED/DUPE DUPE", "{jr}");
        assert_eq!(jr_status(nzbid(&ids[2])), "", "{jr}");
        assert_eq!(jr_status(nzbid(&ids[3])), "DELETED/MANUAL MANUAL", "{jr}");

        // A filed row is a record, not a corpse: retry re-queues it from
        // the spooled NZB, and the re-queued job is one pick_job will
        // actually run (delete_status and tombstone both scrubbed).
        let r = http(
            port,
            &format!("/api?mode=retry&value={}&output=json", ids[0]),
            None,
        );
        assert!(r.contains("\"status\":true"), "retrying a deleted row: {r}");
        let q = http(port, "/api?mode=queue&output=json", None);
        assert!(q.contains(&ids[0]), "the retried row must be back in the queue: {q}");
        let h = http(port, "/api?mode=history&output=json", None);
        assert!(
            hslot(&h, &ids[0]).is_null(),
            "the retried row must have left history: {h}"
        );
    })
    .await
    .unwrap();

    drop(d);
    let _ = std::fs::remove_dir_all(&dir);
}

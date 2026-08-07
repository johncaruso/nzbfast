//! §123 chip-6 fault x lifecycle cross product: the daemon's pause and
//! kill-9 controls exercised WHILE a server fault is live, which no
//! prior rig did (faults and lifecycle were always tested apart). A
//! sibling-dir child of daemon.rs (the stream_chaos pattern) so the
//! parent stays inside its size-gate baseline; harness via `super::*`.

use super::*;
use nzbkit::mock::Throttle;

fn nzb_for(name: &str, segs: &[(String, u64, u32)]) -> String {
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

fn upload(port: u16, xml: &str) -> String {
    let boundary = "----chip6b";
    let mut body = Vec::new();
    body.extend_from_slice(
        format!("--{boundary}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"j.nzb\"\r\n\r\n").as_bytes(),
    );
    body.extend_from_slice(xml.as_bytes());
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    let r = http(
        port,
        "/api?mode=addfile&apikey=sekrit&output=json",
        Some((&format!("multipart/form-data; boundary={boundary}"), &body)),
    );
    assert!(r.contains("\"status\":true"), "{r}");
    r.split("SABnzbd_nzo_")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .map(|s| format!("SABnzbd_nzo_{s}"))
        .unwrap()
}

fn poll_until(port: u16, pred: &dyn Fn(&str) -> bool, what: &str, tries: usize) -> String {
    for _ in 0..tries {
        let h = http(port, "/api?mode=history&apikey=sekrit&output=json", None);
        if pred(&h) {
            return h;
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    panic!("timed out waiting for {what}");
}

fn build_cmd(cfg: std::path::PathBuf, dir: std::path::PathBuf) -> impl Fn(u16) -> Command {
    move |port: u16| {
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
    }
}

/// Pause and resume INSIDE a hard-outage window: the fleet is parked
/// behind the elected prober (the issue #16 machinery) when the pause
/// lands, which is exactly the seam §123's stand-down note flagged
/// ("if a wedge ever shows up around a prober parking, that is the
/// seam to check"). The pause must take hold against a fully parked
/// fleet, and the resume - issued after the outage clears - must
/// re-dial and finish byte-perfect.
#[tokio::test(flavor = "multi_thread")]
async fn pause_inside_an_outage_window_then_resume_completes() {
    let dir = std::env::temp_dir().join(format!("nzbfast-chip6-po-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let data = payload(240_000, 23);
    let mut articles = HashMap::new();
    let segs = make_file_articles("po.bin", &data, 40_000, "po", &mut articles);
    // 2.5 s of hard connect refusals from mock start: the daemon's
    // fleet exhausts its ladder and parks well inside it.
    let srv = MockServer::start(
        articles,
        Chaos {
            refuse_connect_ms: 2_500,
            ..Default::default()
        },
    )
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
    let d = serve(&dir, build_cmd(cfg.clone(), dir.clone())).await;
    let port = d.port;
    let dir2 = dir.clone();
    tokio::task::spawn_blocking(move || {
        let xml = nzb_for("po.bin", &segs);
        let id = upload(port, &xml);
        // Let the fleet hit the outage and park, then pause the job
        // while everything is parked.
        std::thread::sleep(std::time::Duration::from_millis(800));
        let r = http(
            port,
            &format!("/api?mode=queue&name=pause&value={id}&apikey=sekrit&output=json"),
            None,
        );
        assert!(r.contains("\"status\":true"), "pause refused: {r}");
        // Outage clears at 2.5 s; resume after it.
        std::thread::sleep(std::time::Duration::from_millis(2_200));
        let r = http(
            port,
            &format!("/api?mode=queue&name=resume&value={id}&apikey=sekrit&output=json"),
            None,
        );
        assert!(r.contains("\"status\":true"), "resume refused: {r}");
        poll_until(
            port,
            &|h: &str| h.contains("\"Completed\""),
            "paused-through-outage job",
            150,
        );
        assert_eq!(
            std::fs::read(dir2.join("complete/j/po.bin")).unwrap(),
            data,
            "payload differs after pause-through-outage"
        );
    })
    .await
    .unwrap();
}

/// kill -9 MID-DOWNLOAD against a flapping server, then restart on the
/// same spool: crash-resume has only ever been tested with the job at
/// rest (queue_survives_restart pauses first). Here the daemon dies
/// with bytes in flight and volumes half-written, and the restarted
/// daemon must pick the job up on its own and finish byte-perfect -
/// against a server that keeps dropping every 6th body the whole time.
#[tokio::test(flavor = "multi_thread")]
async fn kill9_mid_download_resumes_against_a_flapping_server() {
    let dir = std::env::temp_dir().join(format!("nzbfast-chip6-k9-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let data = payload(600_000, 31);
    let mut articles = HashMap::new();
    let segs = make_file_articles("k9.bin", &data, 30_000, "k9", &mut articles);
    // Flap + slow: drop the connection every 6 bodies, and pace bodies
    // so the job is reliably mid-flight when the SIGKILL lands.
    let srv = MockServer::start(
        articles,
        Chaos {
            drop_after: 6,
            throttle: Throttle {
                per_conn_bps: 60_000,
                ..Default::default()
            },
            ..Default::default()
        },
    )
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
    let a = serve(&dir, build_cmd(cfg.clone(), dir.clone())).await;
    let port_a = a.port;
    let segs2 = segs.clone();
    tokio::task::spawn_blocking(move || {
        let xml = nzb_for("k9.bin", &segs2);
        let _ = upload(port_a, &xml);
        // Wait until bytes are genuinely in flight (queue shows the
        // job downloading with some of it gone), then die.
        for _ in 0..100 {
            let q = http(port_a, "/api?mode=queue&apikey=sekrit&output=json", None);
            if q.contains("Downloading") {
                std::thread::sleep(std::time::Duration::from_millis(700));
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        panic!("job never started downloading");
    })
    .await
    .unwrap();
    drop(a); // kill -9, mid-flight
    let b = serve(&dir, build_cmd(cfg, dir.clone())).await;
    let port_b = b.port;
    let dir2 = dir.clone();
    tokio::task::spawn_blocking(move || {
        poll_until(
            port_b,
            &|h: &str| h.contains("\"Completed\""),
            "crash-resumed job against the flap",
            300,
        );
        assert_eq!(
            std::fs::read(dir2.join("complete/j/k9.bin")).unwrap(),
            data,
            "payload differs after kill-9 crash-resume"
        );
    })
    .await
    .unwrap();
}

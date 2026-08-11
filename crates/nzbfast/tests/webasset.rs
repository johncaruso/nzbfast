//! TODO §129 phase 0c: the embedded pages (dashboard, wall, manual,
//! i18n catalogues) are served gzip-compressed with an ETag over the
//! final substituted bytes, and revalidate as a 304 instead of
//! re-crossing the wire in full (~760 KB per dashboard load before).
//! This file pins the contract:
//!
//!  * Accept-Encoding: gzip -> Content-Encoding: gzip, and the body
//!    actually inflates back to the page;
//!  * no Accept-Encoding -> identity body, same ETag (the validator
//!    hashes content, not encoding);
//!  * If-None-Match with the current tag -> 304 with no body;
//!  * Cache-Control stays no-cache, so a daemon upgrade still reaches
//!    the UI at the next load (as a fresh 200, because the bytes - and
//!    therefore the tag - changed).

mod scratch;

use std::io::{Read, Write};
use std::net::TcpStream;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct KillOnDrop(Child);
impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Raw request with caller-chosen extra headers; returns (head, body)
/// with the body de-chunked. Bytes, not String - a gzip body is binary.
fn http_raw(port: u16, path: &str, extra: &str) -> (String, Vec<u8>) {
    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect daemon");
    write!(
        s,
        "GET {path} HTTP/1.1\r\nHost: x\r\n{extra}Connection: close\r\n\r\n"
    )
    .unwrap();
    let mut raw = Vec::new();
    let _ = s.read_to_end(&mut raw);
    let at = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("headers");
    let (head, body) = raw.split_at(at + 4);
    let head = String::from_utf8_lossy(head).to_string();
    let body = if head
        .to_ascii_lowercase()
        .contains("transfer-encoding: chunked")
    {
        dechunk(body)
    } else {
        body.to_vec()
    };
    (head, body)
}

/// Minimal chunked decoder, same shape as http_wedge.rs's (tiny_http
/// chunks any response at or over 32 KB, which the dashboard always is).
fn dechunk(mut b: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    while let Some(nl) = b.windows(2).position(|w| w == b"\r\n") {
        let line = String::from_utf8_lossy(&b[..nl]);
        let n = usize::from_str_radix(line.split(';').next().unwrap_or("").trim(), 16).unwrap_or(0);
        if n == 0 {
            break;
        }
        let (start, end) = (nl + 2, nl + 2 + n);
        if end > b.len() {
            out.extend_from_slice(&b[start.min(b.len())..]);
            break;
        }
        out.extend_from_slice(&b[start..end]);
        b = &b[(end + 2).min(b.len())..];
    }
    out
}

fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        k.eq_ignore_ascii_case(name).then(|| v.trim())
    })
}

fn gunzip(b: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    flate2::read::GzDecoder::new(b)
        .read_to_end(&mut out)
        .unwrap();
    out
}

fn serve(dir: &std::path::Path) -> (KillOnDrop, u16) {
    for attempt in 0..3 {
        let port = free_port();
        let log = dir.join("daemon.log");
        let out = std::fs::File::create(&log).unwrap();
        let err = out.try_clone().unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_nzbfast"))
            .env("NZBFAST_NO_ENRICH", "1")
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
            .stdout(Stdio::from(out))
            .stderr(Stdio::from(err))
            .spawn()
            .unwrap();
        let mut child = KillOnDrop(child);
        // Readiness = OUR banner in OUR log (a bare connect can catch a
        // stranger on a recycled port - see index_size_cap.rs).
        let banner = format!("open the dashboard at  http://localhost:{port}/");
        for _ in 0..300 {
            if std::fs::read_to_string(&log)
                .unwrap_or_default()
                .contains(&banner)
                && TcpStream::connect(("127.0.0.1", port)).is_ok()
            {
                return (child, port);
            }
            if child.0.try_wait().ok().flatten().is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        drop(child);
        assert!(attempt < 2, "daemon never announced its listener");
    }
    unreachable!()
}

#[test]
fn pages_gzip_etag_and_304() {
    let dir = std::env::temp_dir().join(format!("nzbfast-webasset-{}", std::process::id()));
    let dir = scratch::ScratchDir::attach(&dir);
    std::fs::write(dir.join("config.json"), "{\"servers\":[]}").unwrap();
    let (_daemon, port) = serve(&dir);

    // 1. Compressed dashboard: encoded, tagged, and it inflates back.
    let (head, body) = http_raw(port, "/", "Accept-Encoding: gzip\r\n");
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(header(&head, "Content-Encoding"), Some("gzip"), "{head}");
    assert_eq!(header(&head, "Cache-Control"), Some("no-cache"), "{head}");
    assert_eq!(header(&head, "Vary"), Some("Accept-Encoding"), "{head}");
    let etag = header(&head, "ETag")
        .expect("dashboard carries an ETag")
        .to_string();
    let plain = gunzip(&body);
    assert!(
        String::from_utf8_lossy(&plain).contains("nzbfast"),
        "inflated dashboard is the dashboard"
    );
    assert!(
        body.len() * 3 < plain.len(),
        "gzip earned its keep: {} compressed vs {} plain",
        body.len(),
        plain.len()
    );

    // 2. No Accept-Encoding: identity body, same validator.
    let (head2, body2) = http_raw(port, "/", "");
    assert!(head2.starts_with("HTTP/1.1 200"), "{head2}");
    assert_eq!(header(&head2, "Content-Encoding"), None, "{head2}");
    assert_eq!(header(&head2, "ETag"), Some(etag.as_str()), "{head2}");
    assert_eq!(body2, plain, "identity body matches the inflated one");

    // 3. Revalidation: the tag comes back as a bodyless 304.
    let (head3, body3) = http_raw(
        port,
        "/",
        &format!("Accept-Encoding: gzip\r\nIf-None-Match: {etag}\r\n"),
    );
    assert!(head3.starts_with("HTTP/1.1 304"), "{head3}");
    assert!(body3.is_empty(), "304 carries no body");

    // 4. A locale catalogue rides the same path.
    let (head4, body4) = http_raw(port, "/i18n/fr.json", "Accept-Encoding: gzip\r\n");
    assert!(head4.starts_with("HTTP/1.1 200"), "{head4}");
    assert_eq!(header(&head4, "Content-Encoding"), Some("gzip"), "{head4}");
    assert!(header(&head4, "ETag").is_some(), "{head4}");
    let cat = gunzip(&body4);
    assert!(
        serde_json::from_slice::<serde_json::Value>(&cat).is_ok(),
        "catalogue inflates to valid JSON"
    );
}

/// TODO §140 / issue #31: the user's own stylesheet comes from the config
/// folder, not the binary. The point of the feature is editing it without
/// a rebuild, so what this pins is that a RUNNING daemon serves the new
/// bytes after the file changes on disk - and that having no file at all
/// is quiet rather than a 404 in everyone's console.
#[test]
fn the_user_stylesheet_is_live_from_the_config_folder() {
    let dir = std::env::temp_dir().join(format!("nzbfast-usercss-{}", std::process::id()));
    let dir = scratch::ScratchDir::attach(&dir);
    std::fs::write(dir.join("config.json"), "{\"servers\":[]}").unwrap();
    let (_daemon, port) = serve(&dir);

    // No file: an empty stylesheet, not an error. Both pages link it, so
    // a 404 here would be a red console line on every install.
    let (head, body) = http_raw(port, "/custom.css", "");
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert!(
        header(&head, "Content-Type").is_some_and(|c| c.starts_with("text/css")),
        "{head}"
    );
    assert!(body.is_empty(), "no file means no rules");

    // Written while the daemon runs: served on the next request, with no
    // restart. This is the assertion that would fail the moment anyone
    // "optimised" the file into an include_str! or a boot-time cache.
    std::fs::write(dir.join("custom.css"), "body{--acc:#ff00aa}\n").unwrap();
    let (head2, body2) = http_raw(port, "/custom.css", "");
    assert!(head2.starts_with("HTTP/1.1 200"), "{head2}");
    assert_eq!(String::from_utf8_lossy(&body2), "body{--acc:#ff00aa}\n");
    let etag = header(&head2, "ETag").expect("stylesheet carries an ETag");

    // Edited again: new bytes, and a validator that moved with them, so a
    // browser holding the old copy cannot 304 its way past the change.
    std::fs::write(dir.join("custom.css"), "body{--acc:#00ccff}\n").unwrap();
    let (head3, body3) = http_raw(port, "/custom.css", &format!("If-None-Match: {etag}\r\n"));
    assert!(head3.starts_with("HTTP/1.1 200"), "{head3}");
    assert_eq!(String::from_utf8_lossy(&body3), "body{--acc:#00ccff}\n");
    assert_ne!(
        header(&head3, "ETag"),
        Some(etag),
        "the tag tracks the file"
    );

    // And the page asks for it after its own styles, so an equally
    // specific user rule wins without !important.
    let (_, page) = http_raw(port, "/", "");
    let page = String::from_utf8_lossy(&page);
    let link = page
        .find(r#"<link rel="stylesheet" href="/custom.css">"#)
        .expect("dashboard links the user stylesheet");
    assert!(link > page.rfind("</style>").expect("no style block"));
}

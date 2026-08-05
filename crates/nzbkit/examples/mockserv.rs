//! Standalone mock NNTP server for installer acceptance runs on boxes
//! with no Usenet account: serves a
//! deterministic file over plain TCP on a fixed local port and writes
//! the matching .nzb next to itself, so an *installed* nzbfast (server
//! host 127.0.0.1, the printed port, TLS off) can run a real download
//! through the full stack - pool, decode, verify, assemble.
//!
//!   cargo run -p nzbkit --example mockserv -- [outdir] [port] [mb]
//!
//! `mb` sizes the payload (default 4 - the installer-acceptance
//! shape); the netem rounds serve hundreds of MB so a lossy-link leg
//! runs long enough to measure. Runs until killed.

use std::collections::HashMap;

use nzbkit::mock::{Chaos, MockServer, make_file_articles};

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    let mut args = std::env::args().skip(1);
    let outdir = std::path::PathBuf::from(args.next().unwrap_or_else(|| ".".into()));
    let port: u16 = args.next().and_then(|p| p.parse().ok()).unwrap_or(1190);
    let mb: u64 = args.next().and_then(|p| p.parse().ok()).unwrap_or(4);

    // Deterministic, incompressible-ish payload in ~500 KB articles.
    let data: Vec<u8> = (0..mb * 1_000_000)
        .map(|i| (i.wrapping_mul(2654435761) >> 16) as u8)
        .collect();
    let mut articles = HashMap::new();
    let segs = make_file_articles("mock-4mb.bin", &data, 500_000, "mocktest", &mut articles);

    let mut nzb = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n\
         <file poster=\"mock@example.com\" date=\"0\" subject=\"mock-4mb.bin (1/1)\">\n\
         <groups><group>alt.binaries.test</group></groups>\n<segments>\n",
    );
    for (id, bytes, number) in &segs {
        nzb.push_str(&format!(
            "<segment bytes=\"{bytes}\" number=\"{number}\">{id}</segment>\n"
        ));
    }
    nzb.push_str("</segments>\n</file>\n</nzb>\n");
    let nzb_path = outdir.join("mock-test.nzb");
    std::fs::write(&nzb_path, nzb).expect("write nzb");

    let srv = MockServer::start_bound(
        &format!("127.0.0.1:{port}"),
        articles,
        HashMap::new(),
        Vec::new(),
        Chaos::default(),
    )
    .await;
    println!("mock NNTP on {} - nzb at {}", srv.addr, nzb_path.display());
    println!(
        "point nzbfast at host 127.0.0.1, port {}, TLS off, no auth",
        srv.addr.port()
    );
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(3600)).await;
    }
}

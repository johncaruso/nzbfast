//! What TLS is my provider actually giving me?
//!
//!   cargo run --release --example tlsprobe -- news.example.com:563 …
//!
//! Under TLS 1.3 the SERVER picks from our offer, so the suite we prefer
//! and the suite we get are different questions. AES-256-GCM runs ~15-18%
//! slower than AES-128-GCM per byte, and TLS covers every downloaded
//! byte, so on a weak CPU this is a throughput question, not a cosmetic
//! one. Sends no credentials and no NNTP commands - handshake only.

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.is_empty() {
        eprintln!("usage: tlsprobe <host[:port]> [host[:port] …]   (default port 563)");
        std::process::exit(2);
    }
    for a in args {
        let (host, port) = match a.rsplit_once(':') {
            Some((h, p)) if p.parse::<u16>().is_ok() => (h.to_string(), p.parse().unwrap()),
            _ => (a.clone(), 563u16),
        };
        match nzbkit::nntp::probe_tls(&host, port).await {
            Ok((proto, suite)) => println!("{host}:{port}  {proto}  {suite}"),
            Err(e) => println!("{host}:{port}  FAILED: {e}"),
        }
    }
}

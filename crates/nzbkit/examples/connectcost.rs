//! What does opening a connection actually cost, against a real provider?
//!
//!   cargo run --release --example connectcost -- [config.json] [samples]
//!
//! Times the two things the warm pool trades between: a cold
//! `Connection::connect` (TCP handshake + TLS handshake + AUTHINFO USER +
//! AUTHINFO PASS, about five round-trips) against the single round-trip
//! `DATE` that validates a parked connection instead.
//!
//! The ratio between them is the per-connection saving at job start, and
//! it is invisible on loopback - which is exactly why this talks to the
//! real thing. It still understates the win, because it cannot show the
//! other half: a reused connection is already in congestion avoidance
//! with an open window, while a fresh one restarts at slow start.
//!
//! Handshakes and DATE only. No articles, no measurable bandwidth.

use std::time::Instant;

#[tokio::main(flavor = "multi_thread")]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let path = args
        .first()
        .cloned()
        .unwrap_or_else(|| "config.local.json".into());
    let samples: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(5);

    let cfg = match nzbkit::config::Config::load(std::path::Path::new(&path)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{path}: {e}");
            std::process::exit(2);
        }
    };

    println!(
        "{:<28} {:>12} {:>12} {:>9}",
        "server", "cold connect", "warm DATE", "saved"
    );
    for s in cfg.servers.iter().filter(|s| s.enabled) {
        let mut cold = Vec::new();
        let mut warm = Vec::new();
        let mut held = None;
        for _ in 0..samples {
            let t0 = Instant::now();
            let Ok((mut c, _)) = nzbkit::nntp::Connection::connect(s).await else {
                continue;
            };
            cold.push(t0.elapsed().as_secs_f64() * 1e3);
            let t1 = Instant::now();
            if c.date().await.is_ok() {
                warm.push(t1.elapsed().as_secs_f64() * 1e3);
            }
            // Keep one alive to the end so the provider sees a normal
            // session rather than a connect storm of instant QUITs.
            match held {
                None => held = Some(c),
                Some(_) => c.quit().await,
            }
        }
        if let Some(c) = held {
            c.quit().await;
        }
        let med = |v: &mut Vec<f64>| -> f64 {
            if v.is_empty() {
                return f64::NAN;
            }
            v.sort_by(|a, b| a.partial_cmp(b).unwrap());
            v[v.len() / 2]
        };
        let (c, w) = (med(&mut cold), med(&mut warm));
        println!("{:<28} {:>9.1} ms {:>9.1} ms {:>8.1}x", s.host, c, w, c / w);
    }
}

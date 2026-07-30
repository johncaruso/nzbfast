//! Ad-hoc RING-path extraction benchmark (not shipped). Forces the
//! streaming-ring pipeline by zeroing the buffered/flat limit, so the
//! solid-chain and big-member ring paths can be timed in isolation from the
//! flat-apply fast path (which otherwise wins the mode selection).
//!
//!   cargo run -q --release --features parallel --example bench_ring_chain \
//!       -- <dir> [iters]

use std::io::{sink, Write};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let dir = std::path::PathBuf::from(args.get(1).expect("usage: bench_ring_chain <dir> [iters]"));
    let iters: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(1);
    let mut vols: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().map(|e| e == "rar").unwrap_or(false))
        .collect();
    vols.sort();
    let archives: Vec<_> = vols
        .iter()
        .map(|p| rars::ArchiveReader::read_path(p).unwrap())
        .collect();
    let options = rars::ArchiveReadOptions::new().with_rar50_buffered_decode_limit(0);
    for _ in 0..iters {
        let t = std::time::Instant::now();
        rars::extract_volumes_to_with_options(&archives, options.clone(), |_meta| {
            Ok(Box::new(sink()) as Box<dyn Write>)
        })
        .unwrap();
        eprintln!("ring {:>8.3}s", t.elapsed().as_secs_f64());
    }
}

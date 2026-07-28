//! Ad-hoc extraction benchmark (not shipped). Decodes a multivolume set to a
//! sink N times to isolate decode CPU from disk and give profilers a window.
//!
//!   cargo run -q --release --example bench_extract -- <dir> [iters]

use std::io::{sink, Write};
use std::path::PathBuf;
use std::time::Instant;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let dir = PathBuf::from(args.get(1).expect("usage: bench_extract <dir> [iters]"));
    let iters: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(1);

    let mut vols: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().map(|e| e == "rar").unwrap_or(false))
        .collect();
    vols.sort();
    let archives: Vec<_> = vols
        .iter()
        .map(|p| rars::ArchiveReader::read_path(p).unwrap())
        .collect();

    for _ in 0..iters {
        let t = Instant::now();
        rars::extract_volumes_to(&archives, None, |_meta| {
            Ok(Box::new(sink()) as Box<dyn Write>)
        })
        .unwrap();
        eprintln!("extract_volumes_to {:>8.3}s", t.elapsed().as_secs_f64());
    }
}

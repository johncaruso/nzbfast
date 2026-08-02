//! The recovery-record repair the DAEMON actually runs: parse the archive,
//! then `repair_recovery_to_path`, which scans only the recovery service's
//! own bytes instead of hunting `{RB}` markers across the whole volume,
//! and clones rather than copies the volume where the filesystem can.
//!
//! `bench_rr_stream` times the raw fallback (headers unparseable), which is
//! not the path a payload-damaged volume takes.
//!
//!   cargo run -q --release -p rars --example bench_rr_product -- <damaged.rar> <out.rar>

use std::path::Path;
use std::time::Instant;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let damaged = args.get(1).expect("usage: bench_rr_product <damaged.rar> <out.rar>");
    let out_path = args.get(2).expect("need an output path");
    let budget: u64 = 64 << 20;

    let t = Instant::now();
    let options = rars::ArchiveReadOptions::with_optional_password(None);
    let archive = rars::ArchiveReader::read_path_with_options(Path::new(damaged), options)
        .expect("parse archive");
    let parse_ms = t.elapsed().as_secs_f64() * 1000.0;

    std::fs::remove_file(out_path).ok();

    let t2 = Instant::now();
    let rebuilt = archive
        .repair_recovery_to_path(Path::new(out_path), None, budget)
        .expect("repair");
    let repair_ms = t2.elapsed().as_secs_f64() * 1000.0;
    let total_ms = t.elapsed().as_secs_f64() * 1000.0;
    println!(
        "product: parse {parse_ms:.1} ms + repair {repair_ms:.1} ms = {total_ms:.1} ms, {} shard(s)",
        rebuilt.len()
    );
}

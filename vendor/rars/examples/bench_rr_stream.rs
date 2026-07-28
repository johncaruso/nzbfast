//! Times the STREAMING recovery-record repair added by 2857ac2, against the
//! same archive bench_rr_buffered runs. New tree only - the v1.0.7 tree has
//! no recovery/stream.rs at all, so the baseline for this leg IS the
//! buffered path.
//!
//!   cargo run -q --release -p rars --example bench_rr_stream -- <damaged.rar> <out.rar> [pristine.rar]

use std::fs::File;
use std::path::Path;
use std::time::Instant;

use rars::recovery::stream::{
    repair_prefix_streaming, scan_inline_recovery_chunks, FileSource,
};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let damaged = args.get(1).expect("usage: bench_rr_stream <damaged.rar> <out.rar> [pristine]");
    let out_path = args.get(2).expect("need an output path");
    // The daemon's own default order of magnitude, not the whole machine:
    // the whole point of the change is that this bounds the run.
    let budget: u64 = 64 << 20;

    let source = FileSource::open(Path::new(damaged)).expect("open damaged archive");
    println!("stream: input {} MiB, budget {} MiB", source_len(&source) >> 20, budget >> 20);

    let t = Instant::now();
    let scan = scan_inline_recovery_chunks(&source, budget).expect("scan recovery chunks");
    let scan_ms = t.elapsed().as_secs_f64() * 1000.0;

    std::fs::remove_file(out_path).ok();
    let mut dest = File::options()
        .read(true)
        .write(true)
        .create_new(true)
        .open(out_path)
        .expect("create output");

    let t2 = Instant::now();
    let rebuilt = repair_prefix_streaming(&source, 0, &scan, &source, &mut dest, budget);
    let repair_ms = t2.elapsed().as_secs_f64() * 1000.0;
    let total_ms = t.elapsed().as_secs_f64() * 1000.0;

    match &rebuilt {
        Ok(shards) => println!(
            "stream: scan {scan_ms:.1} ms + repair {repair_ms:.1} ms = {total_ms:.1} ms, {} shard(s) rebuilt",
            shards.len()
        ),
        Err(e) => println!("stream: FAILED after {total_ms:.1} ms: {e:?}"),
    }
    drop(dest);

    if let (Some(pristine), Ok(_)) = (args.get(3), &rebuilt) {
        let want = std::fs::read(pristine).expect("read pristine");
        let got = std::fs::read(out_path).expect("read repaired");
        println!("stream: byte-exact vs pristine: {}", got == want);
    }
}

fn source_len(s: &FileSource) -> u64 {
    use rars::recovery::stream::RangeSource;
    s.len()
}

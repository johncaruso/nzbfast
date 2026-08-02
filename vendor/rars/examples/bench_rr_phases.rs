//! Phase breakdown of the streaming recovery-record repair.
//!
//! The published 512 MB loss against `rar r` is a whole-pipeline number and
//! says nothing about WHERE it goes. This times each pass separately:
//! marker scan, whole-file copy, per-group damage detection, and the solve.
//!
//!   cargo run -q --release -p rars --example bench_rr_phases -- <damaged.rar> <out.rar>

use std::fs::File;
use std::path::Path;
use std::time::Instant;

use rars::recovery::rar5;
use rars::recovery::stream::{
    damaged_shards, repair_prefix_streaming, scan_inline_recovery_chunks,
    scan_inline_recovery_chunks_in, FileSource, RangeSource,
};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let damaged = args.get(1).expect("usage: bench_rr_phases <damaged.rar> <out.rar>");
    let out_path = args.get(2).expect("need an output path");
    let budget: u64 = 64 << 20;

    let source = FileSource::open(Path::new(damaged)).expect("open damaged archive");
    let len = source.len();
    println!("input {} MiB", len >> 20);

    // Whole-file scan (what bench_rr_stream does).
    let t = Instant::now();
    let scan = scan_inline_recovery_chunks(&source, budget).expect("scan");
    let scan_whole = t.elapsed().as_secs_f64() * 1000.0;

    let protected = scan.protected_size().unwrap();
    let plan = scan.plan().unwrap();
    let groups = rar5::recovery_groups(plan).unwrap();
    println!(
        "protected {protected} bytes, {} records, {} groups, group_count {}",
        scan.chunks.len(),
        groups.len(),
        plan.group_count
    );

    // Range-limited scan (what repair_recovery_to_file does): only the
    // recovery service's own bytes.
    let area_start = scan
        .chunks
        .iter()
        .map(|c| c.parity.start - plan.header_size)
        .min()
        .unwrap();
    let t = Instant::now();
    let scan2 = scan_inline_recovery_chunks_in(&source, area_start..len, budget).expect("scan_in");
    let scan_range = t.elapsed().as_secs_f64() * 1000.0;
    assert_eq!(scan2.chunks.len(), scan.chunks.len());

    // Damage detection, per group, over the whole protected prefix.
    let t = Instant::now();
    let mut damaged_total = 0usize;
    for (group, states) in groups.iter().zip(&scan.group_states) {
        if states.is_empty() {
            continue;
        }
        damaged_total += damaged_shards(&source, 0, protected, plan, *group, states)
            .unwrap()
            .len();
    }
    let detect = t.elapsed().as_secs_f64() * 1000.0;

    // Raw copy of the whole file, the first thing the repair does.
    std::fs::remove_file(out_path).ok();
    let t = Instant::now();
    {
        let mut src = File::open(damaged).unwrap();
        let mut dst = File::create(out_path).unwrap();
        std::io::copy(&mut src, &mut dst).unwrap();
        dst.sync_data().ok();
    }
    let copy = t.elapsed().as_secs_f64() * 1000.0;

    // Whole repair, for reference.
    std::fs::remove_file(out_path).ok();
    let mut dest = File::options()
        .read(true)
        .write(true)
        .create_new(true)
        .open(out_path)
        .unwrap();
    let t = Instant::now();
    let rebuilt = repair_prefix_streaming(&source, 0, &scan, &source, &mut dest, budget).unwrap();
    let repair = t.elapsed().as_secs_f64() * 1000.0;

    println!("scan whole-file : {scan_whole:8.1} ms");
    println!("scan rr-range   : {scan_range:8.1} ms");
    println!("detect damage   : {detect:8.1} ms  ({damaged_total} shard(s) over all groups)");
    println!("plain file copy : {copy:8.1} ms");
    println!("repair (all)    : {repair:8.1} ms  ({} shard(s) rebuilt)", rebuilt.len());
    println!(
        "-> solve+write residue = repair - copy - detect = {:8.1} ms",
        repair - copy - detect
    );
}

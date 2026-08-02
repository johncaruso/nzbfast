//! Damage detection: the current strided walk vs a sequential one.
//!
//! `damaged_shards` is called once per GROUP and walks all 200 data shards
//! inside it, so the read pattern is 64 KiB out of every `group_count` bytes,
//! repeated once per group. The union of those slices is the protected
//! prefix in file order - shard-major, group-minor - so the same CRC64s can
//! come off ONE sequential pass, which also splits cleanly across cores.
//!
//!   cargo run -q --release -p rars --example bench_rr_detect -- <archive.rar>
//!   cargo run -q --release -p rars --features parallel --example bench_rr_detect -- <archive.rar>

use std::path::Path;
use std::time::Instant;

use rars::recovery::rar5::{self, crc64_update};
use rars::recovery::stream::{damaged_shards, scan_inline_recovery_chunks, FileSource, RangeSource};

const IO_BUF: usize = 256 * 1024;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let path = args.get(1).expect("usage: bench_rr_detect <archive.rar>");
    let source = FileSource::open(Path::new(path)).expect("open archive");
    let scan = scan_inline_recovery_chunks(&source, 64 << 20).expect("scan");
    let plan = scan.plan().unwrap();
    let protected = scan.protected_size().unwrap();
    let groups = rar5::recovery_groups(plan).unwrap();
    let shards = plan.data_shards as usize;
    println!(
        "{} MiB protected, {} shards x {} groups = {} slices",
        protected >> 20,
        shards,
        groups.len(),
        shards * groups.len()
    );

    // (a) what the repair does today: per group, per shard, strided.
    let t = Instant::now();
    let mut current: Vec<Vec<usize>> = Vec::new();
    for (group, states) in groups.iter().zip(&scan.group_states) {
        current.push(damaged_shards(&source, 0, protected, plan, *group, states).unwrap());
    }
    let strided = t.elapsed().as_secs_f64() * 1000.0;

    // (b) one sequential pass, shard-major: exactly file order.
    let t = Instant::now();
    let sequential_crcs = sequential(&source, protected, plan.group_count, &groups, shards);
    let sequential_ms = t.elapsed().as_secs_f64() * 1000.0;

    // (c) the same pass split across cores, one shard per task.
    let t = Instant::now();
    let parallel_crcs = parallel(&source, protected, plan.group_count, &groups, shards);
    let parallel_ms = t.elapsed().as_secs_f64() * 1000.0;

    // Agreement: rebuild the same damaged lists from the sequential CRCs.
    let rebuilt = to_damaged(&sequential_crcs, &scan.group_states, groups.len(), shards);
    assert_eq!(rebuilt, current, "sequential pass disagrees with the strided one");
    assert_eq!(sequential_crcs, parallel_crcs, "parallel pass disagrees");
    let found: usize = current.iter().map(|g| g.len()).sum();

    println!("strided (today) : {strided:8.1} ms");
    println!("sequential      : {sequential_ms:8.1} ms  ({:.2}x)", strided / sequential_ms);
    println!("parallel        : {parallel_ms:8.1} ms  ({:.2}x)", strided / parallel_ms);
    println!("{found} damaged shard(s), all three agree");
}

/// CRC64 of every (shard, group) slice, indexed `[shard][group]`.
fn sequential<S: RangeSource>(
    src: &S,
    protected: u64,
    group_count: u64,
    groups: &[rar5::RecoveryGroup],
    shards: usize,
) -> Vec<Vec<u64>> {
    let mut buf = vec![0u8; IO_BUF];
    (0..shards)
        .map(|shard| one_shard(src, protected, group_count, groups, shard, &mut buf))
        .collect()
}

#[cfg(feature = "parallel")]
fn parallel<S: RangeSource + Sync>(
    src: &S,
    protected: u64,
    group_count: u64,
    groups: &[rar5::RecoveryGroup],
    shards: usize,
) -> Vec<Vec<u64>> {
    use rayon::prelude::*;
    (0..shards)
        .into_par_iter()
        .map(|shard| {
            let mut buf = vec![0u8; IO_BUF];
            one_shard(src, protected, group_count, groups, shard, &mut buf)
        })
        .collect()
}

#[cfg(not(feature = "parallel"))]
fn parallel<S: RangeSource + Sync>(
    src: &S,
    protected: u64,
    group_count: u64,
    groups: &[rar5::RecoveryGroup],
    shards: usize,
) -> Vec<Vec<u64>> {
    sequential(src, protected, group_count, groups, shards)
}

/// Every group's CRC64 for one shard, read as one contiguous run.
fn one_shard<S: RangeSource>(
    src: &S,
    protected: u64,
    group_count: u64,
    groups: &[rar5::RecoveryGroup],
    shard: usize,
    buf: &mut [u8],
) -> Vec<u64> {
    groups
        .iter()
        .map(|group| {
            let start = (shard as u64 * group_count + group.offset).min(protected);
            let end = (start + group.len).min(protected);
            let mut state = 0u64;
            let mut at = start;
            while at < end {
                let take = buf.len().min((end - at) as usize);
                src.read_at(at, &mut buf[..take]).unwrap();
                state = crc64_update(&buf[..take], state);
                at += take as u64;
            }
            state
        })
        .collect()
}

fn to_damaged(
    crcs: &[Vec<u64>],
    states: &[Vec<u64>],
    groups: usize,
    shards: usize,
) -> Vec<Vec<usize>> {
    (0..groups)
        .map(|group| {
            (0..shards)
                .filter(|&shard| crcs[shard][group] != states[group][shard])
                .collect()
        })
        .collect()
}

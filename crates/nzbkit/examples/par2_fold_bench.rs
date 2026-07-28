//! Repair-math microbenchmark: the GF(2^16) multi-accumulate alone.
//!
//! Times `dsts[j] ^= Σ_i coeff(j,i)·srcs[i]` directly, with every buffer
//! allocated and filled up front, so nothing but the fold is inside the
//! timer. An earlier version drove the full `Reconstructor` and was
//! swamped by allocator cost on Windows (the alloc/fill/free floor
//! exceeded the whole measured run), which is worth remembering before
//! trusting any repair number that includes buffer churn.
//!
//! The sweep over MISSING is the point: work is split by row, and rows
//! ARE the missing-block count, so light damage - the common field case
//! - is where a parallelism ceiling shows up.
//!
//! cargo run --release -p nzbkit --example par2_fold_bench

use std::time::Instant;

use nzbkit::par2repair::bench_fold;

/// 640 KiB: a usenet-typical PAR2 block size.
const BLOCK: usize = 640 << 10;
const WORDS: usize = BLOCK / 2;
/// One 32 MiB fold batch's worth of present slices (BATCH_BYTES).
const INPUTS: usize = (32 << 20) / BLOCK;
const REPEATS: usize = 9;

fn xorshift(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

fn main() {
    let cores = std::thread::available_parallelism().map_or(0, |n| n.get());
    println!(
        "block {} KiB · {INPUTS} sources/batch · {cores} cores · fold only",
        BLOCK >> 10
    );

    // Sources: built once, reused by every configuration.
    let mut state = 0x243F6A88_85A308D3u64;
    let srcs_owned: Vec<Vec<u8>> = (0..INPUTS)
        .map(|_| {
            let mut v = vec![0u8; BLOCK];
            for c in v.chunks_mut(8) {
                let r = xorshift(&mut state).to_le_bytes();
                c.copy_from_slice(&r[..c.len()]);
            }
            v
        })
        .collect();
    let srcs: Vec<&[u8]> = srcs_owned.iter().map(|v| v.as_slice()).collect();

    println!(
        "{:>8}  {:>10}  {:>12}  {:>10}",
        "missing", "best (ms)", "fold GB/s", "vs 1-miss"
    );
    let mut baseline_rate = 0.0f64;
    for &m in &[1usize, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024] {
        // Destinations allocated once, outside the timer, and reused:
        // the fold is an XOR accumulate, so repeating it changes the
        // contents but not the work done.
        let mut dsts: Vec<Vec<u16>> = (0..m).map(|_| vec![0u16; WORDS]).collect();
        let exps: Vec<u32> = (0..m as u32).collect();

        let mut best = f64::MAX;
        for _ in 0..REPEATS {
            let t0 = Instant::now();
            bench_fold(&mut dsts, &srcs, &|j, i| {
                nzbkit::gf16::pow2(i as u64 * exps[j] as u64)
            });
            best = best.min(t0.elapsed().as_secs_f64());
            std::hint::black_box(&dsts);
        }
        let work = INPUTS as f64 * BLOCK as f64 * m as f64;
        let rate = work / best / 1e9;
        if m == 1 {
            baseline_rate = rate;
        }
        println!(
            "{m:>8}  {:>10.2}  {:>12.1}  {:>9.2}x",
            best * 1e3,
            rate,
            rate / baseline_rate
        );
    }
}

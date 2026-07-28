//! yEnc decode throughput: rapidyenc SIMD path vs the scalar oracle.
//!
//! Builds ~200 MB of encoded articles in memory (typical Usenet article
//! payloads, ~700 KB each), then decodes the whole set in a loop with each
//! decoder and reports MB/s over the *encoded* (wire) bytes processed.
//!
//! Run with: cargo run -p nzbkit --release --example yenc_bench

use std::time::Instant;

const TARGET_ENCODED: usize = 200 * 1024 * 1024;
const PART_SIZE: usize = 700_000;
const PASSES: usize = 3;

fn main() {
    // Deterministic pseudo-random payload (splitmix64) - worst-ish case for
    // yEnc: ~1/256 escapes, exercises every byte value.
    let mut seed = 0x00C0FFEE_5EED_1234u64;
    let mut next = move || {
        seed = seed.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = seed;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    };

    let mut payload = vec![0u8; PART_SIZE];
    let mut articles: Vec<Vec<u8>> = Vec::new();
    let mut encoded_total = 0usize;
    let mut part_no = 1u32;
    while encoded_total < TARGET_ENCODED {
        for chunk in payload.chunks_mut(8) {
            let v = next().to_le_bytes();
            chunk.copy_from_slice(&v[..chunk.len()]);
        }
        let begin = 1 + (part_no as u64 - 1) * PART_SIZE as u64;
        let art = nzbkit::yenc::encode(
            "bench.bin",
            300 * PART_SIZE as u64,
            Some((part_no, 300)),
            begin,
            &payload,
        );
        encoded_total += art.len();
        articles.push(art);
        part_no += 1;
    }
    println!(
        "corpus: {} articles, {:.1} MB encoded ({} KB payload each)",
        articles.len(),
        encoded_total as f64 / 1e6,
        PART_SIZE / 1000
    );
    let (dk, ck) = nzbkit::yenc_simd::kernels();
    println!("rapidyenc kernels: decode=0x{dk:x} crc=0x{ck:x} (NEON=0x1000, ARMCRC=0x8, PMULL=0x48)");

    // Warm-up + verify both paths agree before timing.
    let a = nzbkit::yenc::decode(&articles[0]).unwrap();
    let b = nzbkit::yenc_simd::decode(&articles[0]).unwrap();
    assert_eq!(a, b);

    for (label, dec) in [
        (
            "rapidyenc SIMD",
            nzbkit::yenc_simd::decode as fn(&[u8]) -> Result<_, _>,
        ),
        ("scalar oracle ", nzbkit::yenc::decode),
    ] {
        let mut best = f64::MAX;
        for _ in 0..PASSES {
            let start = Instant::now();
            let mut out_bytes = 0usize;
            for art in &articles {
                let d = dec(art).unwrap();
                out_bytes += d.data.len();
            }
            let secs = start.elapsed().as_secs_f64();
            assert!(out_bytes > 0);
            best = best.min(secs);
        }
        println!(
            "{label}: {:7.1} MB/s encoded-in  ({:.1} MB/s decoded-out), best of {PASSES}",
            encoded_total as f64 / 1e6 / best,
            (articles.len() * PART_SIZE) as f64 / 1e6 / best,
        );
    }
}

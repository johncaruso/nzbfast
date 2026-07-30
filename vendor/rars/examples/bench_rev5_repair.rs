//! Ad-hoc RAR5 shard reconstruction benchmark (not shipped). Builds a
//! synthetic shard grid with real GF(2^16) parity via the crate's own
//! encoder, drops `missing` data shards, and times the rebuild -- the kernel
//! behind both `.rev5` repair and inline recovery records.
//!
//!   cargo run -q --release --features parallel --example bench_rev5_repair \
//!       -- <data_shards> <recovery_count> <missing> <shard_bytes>

fn lcg(state: &mut u64) -> u8 {
    *state = state
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    (*state >> 33) as u8
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let n_data: usize = args[1].parse().unwrap();
    let n_rec: usize = args[2].parse().unwrap();
    let n_missing: usize = args[3].parse().unwrap();
    let shard: usize = args[4].parse().unwrap();
    assert!(shard.is_multiple_of(2), "shard length must be even");

    let mut state = 0x2545F4914F6CDD1Du64;
    let data: Vec<Vec<u8>> = (0..n_data)
        .map(|_| (0..shard).map(|_| lcg(&mut state)).collect())
        .collect();
    let refs: Vec<&[u8]> = data.iter().map(Vec::as_slice).collect();

    let t = std::time::Instant::now();
    let parity = rars::recovery::rar5::encode_parity_shards(&refs, n_rec).unwrap();
    let encode_elapsed = t.elapsed();

    let mut present: Vec<Option<&[u8]>> = data.iter().map(|v| Some(v.as_slice())).collect();
    for slot in present.iter_mut().take(n_missing) {
        *slot = None;
    }
    let recovery: Vec<(usize, &[u8])> =
        (0..n_missing).map(|i| (i, parity[i].as_slice())).collect();

    let t = std::time::Instant::now();
    let out = rars::recovery::rar5::reconstruct_data_shards(&present, &recovery).unwrap();
    let elapsed = t.elapsed();

    let mut ok = true;
    for i in 0..n_missing {
        if out[i] != data[i] {
            ok = false;
        }
    }
    let repaired_mib = (n_missing * shard) as f64 / (1024.0 * 1024.0);
    let encoded_mib = (n_rec * shard) as f64 / (1024.0 * 1024.0);
    println!(
        "{n_data} data + {n_rec} rec, {n_missing} missing, {shard} B shard: \
         encode {encode_elapsed:?} ({:.1} MiB/s parity), repair {elapsed:?} \
         ({:.1} MiB/s rebuilt)  correct={ok}",
        encoded_mib / encode_elapsed.as_secs_f64(),
        repaired_mib / elapsed.as_secs_f64()
    );
}

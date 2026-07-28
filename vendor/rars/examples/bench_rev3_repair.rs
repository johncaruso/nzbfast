//! Ad-hoc RAR3 `.rev` reconstruction benchmark (not shipped). Builds a
//! synthetic volume set with real RS(255) parity, drops `missing` data
//! volumes, and times the rebuild -- the shape a `.rev` repair hits when PAR2
//! is absent or insufficient.
//!
//!   cargo run -q --release --features parallel --example bench_rev3_repair \
//!       -- <data_volumes> <recovery_count> <missing> <shard_bytes>

fn lcg(state: &mut u64) -> u8 {
    *state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
    (*state >> 33) as u8
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let n_data: usize = args[1].parse().unwrap();
    let n_rec: usize = args[2].parse().unwrap();
    let n_missing: usize = args[3].parse().unwrap();
    let shard: usize = args[4].parse().unwrap();

    // Random data volumes, then real parity via the crate's own encoder shape.
    let mut state = 0x2545F4914F6CDD1Du64;
    let data: Vec<Vec<u8>> = (0..n_data)
        .map(|_| (0..shard).map(|_| lcg(&mut state)).collect())
        .collect();

    // Build parity with the same generator the decoder assumes, column-wise.
    // (Reuses the public reconstruct path's field by round-tripping through a
    // known-good encode: we encode each column with a local RS8 encoder.)
    let parity = encode_parity(&data, n_rec, shard);

    let mut present: Vec<Option<&[u8]>> = data.iter().map(|v| Some(v.as_slice())).collect();
    for slot in present.iter_mut().take(n_missing) {
        *slot = None;
    }
    let recovery: Vec<(usize, &[u8])> = (0..n_missing).map(|i| (i, parity[i].as_slice())).collect();

    let t = std::time::Instant::now();
    let out = rars::recovery::rar3::reconstruct_data_volumes(&present, n_rec, &recovery).unwrap();
    let elapsed = t.elapsed();

    let mut ok = true;
    for i in 0..n_missing {
        if out[i] != data[i] {
            ok = false;
        }
    }
    let mib = shard as f64 / (1024.0 * 1024.0);
    println!(
        "{n_data} data + {n_rec} rec, {n_missing} missing, {shard} B shard: {elapsed:?}  \
         ({:.3} MiB/s)  correct={ok}",
        mib / elapsed.as_secs_f64()
    );
}

// Minimal RS(255) GF(256) encoder matching RSCoder8's generator convention.
fn encode_parity(data: &[Vec<u8>], n_rec: usize, shard: usize) -> Vec<Vec<u8>> {
    let mut exp = [0u8; 512];
    let mut log = [0u16; 256];
    let mut v = 1u16;
    for i in 0..255 {
        log[v as usize] = i as u16;
        exp[i] = v as u8;
        v <<= 1;
        if v > 0xff {
            v ^= 0x11d;
        }
    }
    for i in 255..512 {
        exp[i] = exp[i - 255];
    }
    let mul = |a: u8, b: u8| -> u8 {
        if a == 0 || b == 0 {
            0
        } else {
            exp[(log[a as usize] + log[b as usize]) as usize]
        }
    };
    let mulpoly = |left: &[u8], right: &[u8]| -> Vec<u8> {
        let mut out = vec![0u8; n_rec];
        for li in 0..n_rec {
            if left.get(li).copied().unwrap_or(0) == 0 {
                continue;
            }
            for ri in 0..(n_rec - li) {
                out[li + ri] ^= mul(left[li], right.get(ri).copied().unwrap_or(0));
            }
        }
        out
    };
    let mut generator = vec![0u8; n_rec];
    let mut current = vec![0u8; n_rec];
    current[0] = 1;
    for i in 1..=n_rec {
        let mut factor = vec![0u8; n_rec];
        factor[0] = exp[i];
        if n_rec > 1 {
            factor[1] = 1;
        }
        generator = mulpoly(&factor, &current);
        current.clone_from(&generator);
    }

    let mut parity = vec![vec![0u8; shard]; n_rec];
    let mut shift = vec![0u8; n_rec + 1];
    for offset in 0..shard {
        shift.iter_mut().for_each(|s| *s = 0);
        for column in data.iter() {
            let feedback = column[offset] ^ shift[n_rec - 1];
            for index in (1..n_rec).rev() {
                shift[index] = shift[index - 1] ^ mul(generator[index], feedback);
            }
            shift[0] = mul(generator[0], feedback);
        }
        for index in 0..n_rec {
            parity[index][offset] = shift[n_rec - index - 1];
        }
    }
    parity
}

//! Component benchmark for the mapped PAR2 reader: reconstruct a large
//! store-mode RAR volume once, then read its complete volume view in PAR2
//! block-sized calls. Setup and fixture construction are outside the clock.

use nzbkit::extract::Extractor;
use nzbkit::rar::fixtures;
use std::time::Instant;

fn envn(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn main() {
    let payload_len = envn("NZBFAST_MAPPED_BYTES", 256 << 20);
    let block = envn("NZBFAST_MAPPED_BLOCK", 64 << 10);
    let rounds = envn("NZBFAST_MAPPED_ROUNDS", 7);
    assert!(block > 0);

    let mut payload = vec![0u8; payload_len];
    let mut state = 0x243F_6A88_85A3_08D3u64;
    for chunk in payload.chunks_mut(8) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        chunk.copy_from_slice(&state.to_le_bytes()[..chunk.len()]);
    }
    let volume = fixtures::rar5_volume(&[(
        "payload.bin",
        payload_len as u64,
        payload.as_slice(),
        false,
        false,
    )]);

    let dir = std::env::temp_dir().join(format!("nzbfast-par2-mapped-read-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let extractor = Extractor::new(&dir, 1, true);
    for (i, chunk) in volume.chunks(1 << 20).enumerate() {
        extractor
            .write(0, "bench.rar", volume.len() as u64, (i << 20) as u64, chunk)
            .unwrap();
    }
    assert!(
        extractor.is_mapped(0),
        "fixture must stay on the mapped path"
    );

    println!(
        "mapped volume {:.2} MiB, block {} KiB, {rounds} rounds",
        volume.len() as f64 / (1 << 20) as f64,
        block >> 10
    );
    let mut buf = vec![0u8; block];
    let mut guard = 0u64;
    for round in 0..rounds {
        let started = Instant::now();
        let mut off = 0usize;
        while off < volume.len() {
            let take = block.min(volume.len() - off);
            extractor.read_at(0, off as u64, &mut buf[..take]).unwrap();
            guard = guard.wrapping_add(buf[0] as u64);
            guard = guard.wrapping_add(buf[take - 1] as u64);
            off += take;
        }
        println!(
            "round {round}: {:.3}s ({:.2} GiB/s)",
            started.elapsed().as_secs_f64(),
            volume.len() as f64 / started.elapsed().as_secs_f64() / (1u64 << 30) as f64
        );
    }
    println!("guard {guard}");
    std::fs::remove_dir_all(&dir).unwrap();
}

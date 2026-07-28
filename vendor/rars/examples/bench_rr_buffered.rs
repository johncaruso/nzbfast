//! Times the BUFFERED recovery-record repair: the whole-archive path that
//! both the v1.0.7 tree and the current one still expose.
//!
//! Compiles against both trees, so it is the like-for-like leg. Peak RSS is
//! the point as much as wall time - this path holds the archive, a repaired
//! copy, and the padded shards at once.
//!
//!   cargo run -q --release -p rars --example bench_rr_buffered -- <damaged.rar> [pristine.rar]

use std::time::Instant;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let damaged = args.get(1).expect("usage: bench_rr_buffered <damaged.rar> [pristine.rar]");
    let input = std::fs::read(damaged).expect("read damaged archive");
    println!("buffered: input {} MiB", input.len() >> 20);

    let t = Instant::now();
    let out = rars::recovery::rar5::repair_inline_recovery_archive(&input);
    let ms = t.elapsed().as_secs_f64() * 1000.0;

    match &out {
        Ok(repaired) => println!("buffered: repaired {} MiB in {ms:.1} ms", repaired.len() >> 20),
        Err(e) => println!("buffered: FAILED after {ms:.1} ms: {e:?}"),
    }

    // Correctness gate: a fast wrong answer is not a result.
    if let (Some(pristine), Ok(repaired)) = (args.get(2), &out) {
        let want = std::fs::read(pristine).expect("read pristine archive");
        // The repair rebuilds the protected prefix; compare that span.
        let n = repaired.len().min(want.len());
        let exact = repaired[..n] == want[..n] && repaired.len() == want.len();
        println!("buffered: byte-exact vs pristine: {exact}");
    }
}

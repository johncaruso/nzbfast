//! One-off validation harness: run the §87 par2-sidecar fold to
//! completion against a COPY of an index DB and report what it did.
//! Never point this at the live index - the walk writes.
//!
//!   cargo run --release -p nzbkit --example sidecar_fold_walk -- <copy.db>

use std::path::Path;

fn main() {
    let path = std::env::args()
        .nth(1)
        .expect("usage: sidecar_fold_walk <index.db copy>");
    let mut ix = nzbkit::index::Index::open(Path::new(&path)).expect("open");
    let t0 = std::time::Instant::now();
    let (mut pairs, mut moved, mut strides) = (0usize, 0usize, 0u64);
    loop {
        // A generous budget: this harness wants throughput, not the
        // daemon's ~1 s mutex-hold bound.
        let (p, f, done) = ix
            .par2_sidecar_fold(std::time::Duration::from_secs(30))
            .expect("fold stride");
        pairs += p;
        moved += f;
        strides += 1;
        if strides % 20 == 0 || done {
            println!(
                "{:>6} strides  {:>6} pairs folded  {:>7} par2 files moved  {:.1?}",
                strides,
                pairs,
                moved,
                t0.elapsed()
            );
        }
        if done {
            break;
        }
    }
    println!(
        "DONE: {pairs} sidecar rows folded, {moved} par2 files, {strides} strides, {:.1?}",
        t0.elapsed()
    );
}

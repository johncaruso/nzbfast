//! Drive `par2repair::repair_dir` on a directory, for profiling the
//! offline/CLI disk-repair path against a real corpus.
//!
//! cargo run --release -p nzbkit --example par2_repair_dir -- <dir>
//!
//! Set NZBFAST_REPAIR_TIMING=1 for the per-phase breakdown.

use std::time::Instant;

fn main() {
    let dir = std::env::args().nth(1).expect("usage: par2_repair_dir <dir>");
    let t0 = Instant::now();
    let status = nzbkit::par2repair::repair_dir(std::path::Path::new(&dir));
    println!("total {:.3?}  status: {:?}", t0.elapsed(), status.map(|s| match s {
        nzbkit::par2repair::RepairStatus::NoDamage => "NoDamage".to_string(),
        nzbkit::par2repair::RepairStatus::Repaired(r) => {
            format!("Repaired rebuilt={} adopted={}", r.blocks_rebuilt, r.blocks_adopted)
        }
        nzbkit::par2repair::RepairStatus::Unrepairable { needed, have } => {
            format!("Unrepairable needed={needed} have={have}")
        }
    }));
}

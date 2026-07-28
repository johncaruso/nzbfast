//! Times the RAR1.3 decode path on a fuzz slow unit, in RELEASE.
//!
//! Replicates crates/nzbkit/fuzz/fuzz_targets/rar_extract.rs exactly -
//! same window/decode caps, same 64 MiB output cap that terminates the
//! bomb - so the number is comparable to the fuzz round that flagged it,
//! without the instrumentation the fuzz build carries (the 22.6 s figure
//! in the original report was an instrumented measurement).
//!
//!   cargo run -q --release -p rars --example bench_rar13 -- <unit> [iters]

use std::io::Write;
use std::time::Instant;

use rars::{ArchiveReadOptions, ArchiveReader};

struct CapSink(usize);
impl Write for CapSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0 = self.0.saturating_add(buf.len());
        if self.0 > 64 * 1024 * 1024 {
            return Err(std::io::Error::new(std::io::ErrorKind::Other, "output cap"));
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let path = args.get(1).expect("usage: bench_rar13 <slow-unit> [iters]");
    let iters: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(5);
    let data = std::fs::read(path).expect("read slow unit");

    let opts = || {
        ArchiveReadOptions::new()
            .with_rar50_max_window(1 << 20)
            .with_rar50_buffered_decode_limit(1 << 20)
    };

    let mut best = f64::MAX;
    for _ in 0..iters {
        let t = Instant::now();
        if let Ok(archive) = ArchiveReader::read_with_options(&data, opts()) {
            let _ = archive.extract_to_with_options(opts(), |_meta| {
                Ok(Box::new(CapSink(0)) as Box<dyn Write>)
            });
        }
        let ms = t.elapsed().as_secs_f64() * 1000.0;
        println!("  iter {ms:.1} ms");
        best = best.min(ms);
    }
    println!("rar13 slow unit ({} bytes): BEST {best:.1} ms", data.len());
}

//! Component benchmark for overlapping RAR29 match copies.
//!
//! Archive construction and parsing happen outside the extraction clock.

use rars::rar15_40::{
    write_rar29_compressed_archive_with_filter_policy, FileEntry, FilterPolicy, WriterOptions,
};
use rars::{ArchiveReader, ArchiveVersion, FeatureSet};
use std::io::{Result as IoResult, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

struct CountingSink(Arc<AtomicU64>);

impl Write for CountingSink {
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        self.0.fetch_add(buf.len() as u64, Ordering::Relaxed);
        Ok(buf.len())
    }

    fn flush(&mut self) -> IoResult<()> {
        Ok(())
    }
}

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

fn main() {
    let bytes = env_usize("RARS_RAR4_BYTES", 128 << 20);
    let period = env_usize("RARS_RAR4_PERIOD", 1).max(1);
    let iters = env_usize("RARS_RAR4_ITERS", 9);
    let seed: Vec<u8> = (0..period)
        .map(|index| ((index * 37 + 11) % 251) as u8)
        .collect();
    let payload: Vec<u8> = seed.iter().copied().cycle().take(bytes).collect();
    let archive_bytes = write_rar29_compressed_archive_with_filter_policy(
        &[FileEntry {
            name: b"periodic.bin",
            data: &payload,
            file_time: 0,
            file_attr: 0x20,
            host_os: 3,
            password: None,
            file_comment: None,
        }],
        WriterOptions::new(ArchiveVersion::Rar29, FeatureSet::default()),
        FilterPolicy::Lz,
    )
    .expect("build RAR29 archive");
    let packed_len = archive_bytes.len();
    let archive = ArchiveReader::read_owned(archive_bytes).expect("parse generated archive");
    eprintln!(
        "shape bytes={bytes} period={period} packed_bytes={packed_len} ratio={:.5}",
        packed_len as f64 / bytes as f64
    );

    for round in 0..iters {
        let accepted = Arc::new(AtomicU64::new(0));
        let start = Instant::now();
        archive
            .extract_to(None, {
                let accepted = Arc::clone(&accepted);
                move |_| Ok(Box::new(CountingSink(Arc::clone(&accepted))) as Box<dyn Write>)
            })
            .expect("extract generated archive");
        let elapsed = start.elapsed().as_secs_f64();
        assert_eq!(accepted.load(Ordering::Relaxed), bytes as u64);
        eprintln!(
            "round={round} seconds={elapsed:.6} mib_s={:.1}",
            bytes as f64 / (1024.0 * 1024.0) / elapsed
        );
    }
}

//! Component benchmark for pooled, non-solid RAR5 compressed members.
//!
//! Archive construction and parsing are outside the timed extraction.

use rars::rar50::{CompressedEntry, Rar50Writer, WriterOptions};
use rars::{ArchiveReadOptions, ArchiveReader, ArchiveVersion, FeatureSet};
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
    let members = env_usize("RARS_COMP_MEMBERS", 64);
    let bytes = env_usize("RARS_COMP_BYTES", 1 << 20);
    let iters = env_usize("RARS_COMP_ITERS", 7);
    let payload: Vec<u8> = (0..bytes)
        .scan(0x9e37_79b9u32, |state, index| {
            *state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            Some(if (index / 4096).is_multiple_of(2) {
                b"RAR5-reader-benchmark-periodic-data"[index % 35]
            } else {
                (*state >> 24) as u8
            })
        })
        .collect();
    let names: Vec<Vec<u8>> = (0..members)
        .map(|index| format!("member-{index:04}.bin").into_bytes())
        .collect();
    let entries: Vec<_> = names
        .iter()
        .map(|name| CompressedEntry {
            name,
            data: &payload,
            mtime: None,
            attributes: 0x20,
            host_os: 3,
        })
        .collect();
    let options = WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::default())
        .with_compression_level(3)
        .with_dictionary_size(1 << 20);
    let archive_bytes = Rar50Writer::new(options)
        .compressed_entries(&entries)
        .finish()
        .expect("build compressed RAR5 archive");
    let packed_len = archive_bytes.len();
    let archive = ArchiveReader::read_owned(archive_bytes).expect("parse generated archive");
    assert!(archive.members().all(|member| !member.meta.is_stored));
    let expected = members as u64 * bytes as u64;
    eprintln!(
        "shape members={members} member_bytes={bytes} total_mib={:.1} archive_mib={:.1}",
        expected as f64 / (1024.0 * 1024.0),
        packed_len as f64 / (1024.0 * 1024.0)
    );

    for round in 0..iters {
        let accepted = Arc::new(AtomicU64::new(0));
        let start = Instant::now();
        archive
            .extract_to_with_options(ArchiveReadOptions::default(), {
                let accepted = Arc::clone(&accepted);
                move |_| Ok(Box::new(CountingSink(Arc::clone(&accepted))) as Box<dyn Write>)
            })
            .expect("extract generated archive");
        let elapsed = start.elapsed().as_secs_f64();
        assert_eq!(accepted.load(Ordering::Relaxed), expected);
        eprintln!(
            "round={round} seconds={elapsed:.6} mib_s={:.1}",
            expected as f64 / (1024.0 * 1024.0) / elapsed
        );
    }
}

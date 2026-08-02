//! Component benchmark for the RAR5 STORE extractor.
//!
//! Archive construction and parsing happen outside the clock. The extraction
//! target only counts accepted bytes, so the result isolates the read,
//! integrity, pipeline, and per-member scheduling costs.
//!
//! Environment:
//!   RARS_STORE_MEMBERS (default 10000)
//!   RARS_STORE_BYTES   (default 4096)
//!   RARS_STORE_ITERS   (default 7)

use rars::rar50::{EncryptedStoredEntry, Rar50Writer, StoredEntry, WriterOptions};
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
    let members = env_usize("RARS_STORE_MEMBERS", 10_000);
    let bytes = env_usize("RARS_STORE_BYTES", 4 * 1024);
    let iters = env_usize("RARS_STORE_ITERS", 7);
    let encrypted = std::env::var_os("RARS_STORE_ENCRYPTED").is_some();
    let payload: Vec<u8> = (0..bytes)
        .map(|index| ((index * 131 + 17) % 251) as u8)
        .collect();
    let names: Vec<Vec<u8>> = (0..members)
        .map(|index| format!("member-{index:06}.bin").into_bytes())
        .collect();
    let entries: Vec<_> = names
        .iter()
        .map(|name| StoredEntry {
            name,
            data: &payload,
            mtime: None,
            attributes: 0x20,
            host_os: 3,
        })
        .collect();

    let encrypted_entries: Vec<_> = names
        .iter()
        .map(|name| EncryptedStoredEntry {
            name,
            data: &payload,
            mtime: None,
            attributes: 0x20,
            host_os: 3,
            password: b"benchmark-password",
        })
        .collect();
    let mut encrypted_features = FeatureSet::default();
    encrypted_features.file_encryption = true;
    let archive_bytes = if encrypted {
        Rar50Writer::new(WriterOptions::new(
            ArchiveVersion::Rar50,
            encrypted_features,
        ))
        .encrypted_stored_entries(&encrypted_entries)
        .finish()
    } else {
        Rar50Writer::new(WriterOptions::default())
            .stored_entries(&entries)
            .finish()
    }
    .expect("build RAR5 STORE archive");
    let archive = ArchiveReader::read_owned(archive_bytes).expect("parse generated archive");
    let expected = members as u64 * bytes as u64;
    eprintln!(
        "shape members={members} member_bytes={bytes} encrypted={encrypted} total_mib={:.1}",
        expected as f64 / (1024.0 * 1024.0)
    );

    for round in 0..iters {
        let accepted = Arc::new(AtomicU64::new(0));
        let start = Instant::now();
        let options = if encrypted {
            ArchiveReadOptions::with_password(b"benchmark-password")
        } else {
            ArchiveReadOptions::default()
        };
        archive
            .extract_to_with_options(options, {
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

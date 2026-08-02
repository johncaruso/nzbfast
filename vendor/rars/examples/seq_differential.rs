//! Three-way differential for the volume-SEQUENCE driver (not shipped).
//!
//! Extracts one multivolume set twice - through `extract_volumes_to` (the
//! whole-set walk, which decodes a split member at its Finish fragment)
//! and through `extract_volume_sequence_to` (the chase's driver, which
//! decodes it incrementally as the volumes arrive) - and prints a sha256
//! per member for each. The caller diffs those against `unrar x`.
//!
//! The sequence side reads every volume through a `GrowableBuffer` fed by
//! a trickle thread, so the header parse AND every payload read block at
//! an arrival frontier, exactly as a chase does.
//!
//!   cargo run -q --release --features parallel --example seq_differential \
//!       -- <dir> [password]

use rars::{ArchiveReadOptions, BlockingRangeSource, GrowableBuffer};
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

type Digests = Arc<Mutex<Vec<(String, String, u64)>>>;

fn sink(out: &Digests, name: &[u8]) -> Box<dyn Write> {
    struct Sink {
        out: Digests,
        name: String,
        hasher: Sha256,
        bytes: u64,
    }
    impl Write for Sink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.hasher.update(buf);
            self.bytes += buf.len() as u64;
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl Drop for Sink {
        fn drop(&mut self) {
            let digest = std::mem::take(&mut self.hasher).finalize();
            self.out.lock().unwrap().push((
                self.name.clone(),
                digest.iter().map(|b| format!("{b:02x}")).collect(),
                self.bytes,
            ));
        }
    }
    Box::new(Sink {
        out: Arc::clone(out),
        name: String::from_utf8_lossy(name).into_owned(),
        hasher: Sha256::new(),
        bytes: 0,
    })
}

fn report(label: &str, digests: &Digests) {
    let mut rows = digests.lock().unwrap().clone();
    rows.sort();
    for (name, digest, bytes) in rows {
        println!("{label}\t{name}\t{bytes}\t{digest}");
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let dir = PathBuf::from(args.get(1).expect("usage: seq_differential <dir> [password]"));
    let password = args.get(2).map(|s| s.as_bytes().to_vec());
    let options = || ArchiveReadOptions::with_optional_password(password.as_deref());

    let mut paths: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.ends_with(".rar") || n.contains(".r0") || n.contains(".r1"))
        })
        .collect();
    // Volume order, not lexical order: old-style RAR4 naming runs
    // `.rar` then `.r00`, `.r01`, ..., which sorts backwards.
    paths.sort_by_key(|p| {
        let name = p.file_name().unwrap().to_string_lossy().to_lowercase();
        let old_style = name.ends_with(".rar") && !name.contains(".part");
        (!old_style as u8, name)
    });
    let parts: Vec<Vec<u8>> = paths.iter().map(|p| std::fs::read(p).unwrap()).collect();
    let is_rar5 = parts[0].starts_with(b"Rar!\x1a\x07\x01\x00");

    // 1. The whole-set walk.
    let walk: Digests = Arc::new(Mutex::new(Vec::new()));
    let started = std::time::Instant::now();
    if is_rar5 {
        let archives: Vec<_> = paths
            .iter()
            .map(|p| rars::rar50::Archive::parse_path_with_options(p, options()).unwrap())
            .collect();
        rars::rar50::extract_volumes_to(&archives, options(), |meta| Ok(sink(&walk, &meta.name)))
            .unwrap();
    } else {
        let archives: Vec<_> = paths
            .iter()
            .map(|p| rars::rar15_40::Archive::parse_path_with_options(p, options()).unwrap())
            .collect();
        rars::rar15_40::extract_volumes_to(&archives, options(), |meta| {
            Ok(sink(&walk, &meta.name))
        })
        .unwrap();
    }
    let walk_secs = started.elapsed().as_secs_f64();

    // 2. The sequence driver, over trickling blocking sources.
    let seq: Digests = Arc::new(Mutex::new(Vec::new()));
    let mut feeders = Vec::new();
    let parts_ref = &parts;
    let started = std::time::Instant::now();
    let next_v5 = |index: usize| -> rars::Result<Option<rars::rar50::Archive>> {
        if index >= parts_ref.len() {
            return Ok(None);
        }
        let part = parts_ref[index].clone();
        let buffer = Arc::new(GrowableBuffer::with_total_len(part.len() as u64));
        let feed = Arc::clone(&buffer);
        feeders.push(std::thread::spawn(move || {
            for chunk in part.chunks(1 << 20) {
                feed.append(chunk);
                std::thread::yield_now();
            }
        }));
        rars::rar50::Archive::parse_stream(
            buffer as Arc<dyn BlockingRangeSource>,
            parts_ref[index].len() as u64,
            ArchiveReadOptions::with_optional_password(password.as_deref()),
        )
        .map(Some)
    };
    if is_rar5 {
        rars::rar50::extract_volume_sequence_to(next_v5, options(), |meta| {
            Ok(sink(&seq, &meta.name))
        })
        .unwrap();
    } else {
        let mut feeders4 = Vec::new();
        rars::rar15_40::extract_volume_sequence_to(
            |index: usize| -> rars::Result<Option<rars::rar15_40::Archive>> {
                if index >= parts_ref.len() {
                    return Ok(None);
                }
                let part = parts_ref[index].clone();
                let buffer = Arc::new(GrowableBuffer::with_total_len(part.len() as u64));
                let feed = Arc::clone(&buffer);
                feeders4.push(std::thread::spawn(move || {
                    for chunk in part.chunks(1 << 20) {
                        feed.append(chunk);
                        std::thread::yield_now();
                    }
                }));
                rars::rar15_40::Archive::parse_stream(
                    buffer as Arc<dyn BlockingRangeSource>,
                    parts_ref[index].len() as u64,
                    ArchiveReadOptions::with_optional_password(password.as_deref()),
                )
                .map(Some)
            },
            options(),
            |meta| Ok(sink(&seq, &meta.name)),
        )
        .unwrap();
        for f in feeders4 {
            f.join().unwrap();
        }
    }
    let seq_secs = started.elapsed().as_secs_f64();
    for f in feeders {
        f.join().unwrap();
    }

    report("walk", &walk);
    report("seq", &seq);
    eprintln!("walk {walk_secs:.3}s  seq {seq_secs:.3}s");
}

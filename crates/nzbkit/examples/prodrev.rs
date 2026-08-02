//! `.rev` recovery-volume restoration, on the product's own code path.
//!
//! `vendor/rars/examples/bench_rev5_repair` times the GF kernel against a
//! synthetic shard grid: no files, no CRC matching, no streaming. That is the
//! right tool for kernel work and the wrong one for a competitive leg, where
//! the other side (`rarpar rar restore-volumes`, `rar rc`) is handed a
//! directory and has to do the whole job.
//!
//! This driver does the whole job through the same rars entry points
//! `crates/nzbfast/src/main.rs` uses, with the same repair budget the daemon
//! resolves: read every `.rev` header, CRC-verify its payload by streaming,
//! match the surviving `.rar` volumes to slots by size and CRC32, then
//! `repair_rev5_volumes_streaming` into temps that are renamed into place.
//!
//!   prodrev <dir>

use rars::recovery::stream::{FileSource, RangeSource};
use std::io::{Seek, Write};
use std::path::PathBuf;

fn main() {
    let dir = PathBuf::from(std::env::args().nth(1).expect("usage: prodrev <dir>"));
    nzbkit::mem::set_process_budget(nzbkit::mem::MemBudget::auto());
    let budget = nzbkit::mem::process_budget().repair_cap();

    // Every .rev in the directory, header-parsed and payload-verified.
    let mut rev_paths: Vec<PathBuf> = std::fs::read_dir(&dir)
        .expect("read dir")
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x.eq_ignore_ascii_case("rev")))
        .collect();
    rev_paths.sort();
    let mut rev_sources = Vec::new();
    let mut rev_meta = Vec::new();
    for path in &rev_paths {
        let source = FileSource::open(path).expect("open .rev");
        let meta = rars::rar50::read_rev5_meta(&source).expect("parse .rev");
        assert!(
            rars::rar50::verify_rev5_payload(&source, &meta).expect("read .rev payload"),
            "{} fails its own checksum",
            path.display()
        );
        rev_sources.push(source);
        rev_meta.push(meta);
    }
    assert!(!rev_meta.is_empty(), "no .rev files in {}", dir.display());

    let first = &rev_meta[0];
    let slots = first.meta.data_volumes.clone();

    // Slots carry no filenames, so surviving volumes are matched by size+CRC32
    // exactly as the daemon matches them; a damaged volume simply fails to
    // match and its slot gets rebuilt.
    let mut volumes: Vec<PathBuf> = std::fs::read_dir(&dir)
        .expect("read dir")
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x.eq_ignore_ascii_case("rar")))
        .collect();
    volumes.sort();
    let mut slot_path: Vec<Option<PathBuf>> = vec![None; slots.len()];
    let mut slot_name: Vec<Option<String>> = vec![None; slots.len()];
    for path in &volumes {
        let Ok((crc, len)) = rars::recovery::stream::crc32_of(path) else {
            continue;
        };
        for (i, meta) in slots.iter().enumerate() {
            if slot_path[i].is_none() && meta.file_size == len && meta.crc32 == crc {
                slot_name[i] = path.file_name().map(|n| n.to_string_lossy().into_owned());
                slot_path[i] = Some(path.clone());
                break;
            }
        }
    }
    let missing: Vec<usize> = (0..slots.len())
        .filter(|&i| slot_path[i].is_none())
        .collect();
    if missing.is_empty() {
        eprintln!("all data volumes verify; .rev not needed");
        return;
    }
    assert!(
        missing.len() <= rev_meta.len(),
        "{} volumes missing, only {} .rev files",
        missing.len(),
        rev_meta.len()
    );

    let mut intact_sources: Vec<Option<FileSource>> = Vec::with_capacity(slots.len());
    for path in &slot_path {
        intact_sources.push(
            path.as_ref()
                .map(|p| FileSource::open(p).expect("open volume")),
        );
    }
    let intact: Vec<Option<&dyn RangeSource>> = intact_sources
        .iter()
        .map(|s| s.as_ref().map(|s| s as &dyn RangeSource))
        .collect();
    let recovery: Vec<rars::rar50::Rev5RecoverySource<'_>> = (0..rev_meta.len())
        .filter_map(|i| {
            Some(rars::rar50::Rev5RecoverySource {
                row: rev_meta[i].row().ok()?,
                source: &rev_sources[i],
                payload: rev_meta[i].payload.clone(),
            })
        })
        .collect();

    let mut temps: Vec<(PathBuf, std::fs::File)> = Vec::new();
    for (slot, _) in missing.iter().enumerate() {
        let p = dir.join(format!("revtmp{}-{slot}", std::process::id()));
        let f = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&p)
            .expect("stage rebuild");
        temps.push((p, f));
    }

    rars::rar50::repair_rev5_volumes_streaming(
        &slots,
        &intact,
        &recovery,
        first.meta.recovery_count as usize,
        budget,
        &mut |slot, offset, bytes| {
            let file = &mut temps[slot].1;
            file.seek(std::io::SeekFrom::Start(offset))
                .and_then(|_| file.write_all(bytes))
                .map_err(|e| rars::Error::from(std::io::Error::other(e.to_string())))
        },
    )
    .expect("rebuild");

    // Name each rebuilt slot from a surviving neighbour's partNN pattern.
    let known = slot_name
        .iter()
        .enumerate()
        .find_map(|(i, n)| n.as_ref().map(|n| (i, n.clone())))
        .expect("at least one surviving volume");
    // Close every staged file before any rename: the set is only ever renamed
    // into place once all of them are written, which is the daemon's rule too.
    let temp_paths: Vec<PathBuf> = temps.iter().map(|(p, _)| p.clone()).collect();
    drop(temps);
    for (t, &slot) in missing.iter().enumerate() {
        let name = derive_part_name(&known.1, known.0, slot)
            .unwrap_or_else(|| format!("rebuilt-{slot}.rar"));
        std::fs::rename(&temp_paths[t], dir.join(&name)).expect("rename rebuilt volume");
    }
    eprintln!("rebuilt {} volume(s)", missing.len());
}

fn rfind_ascii_ci(hay: &str, needle: &str) -> Option<usize> {
    let (h, n) = (hay.as_bytes(), needle.as_bytes());
    if n.is_empty() || h.len() < n.len() {
        return None;
    }
    (0..=h.len() - n.len())
        .rev()
        .find(|&i| h[i..i + n.len()].eq_ignore_ascii_case(n))
}

fn derive_part_name(known: &str, known_slot: usize, slot: usize) -> Option<String> {
    let p = rfind_ascii_ci(known, ".part")?;
    let tail = &known[p + 5..];
    let digits: String = tail.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() || digits.parse::<usize>().ok()? != known_slot + 1 {
        return None;
    }
    Some(format!(
        "{}{}{:0width$}{}",
        &known[..p],
        &known[p..p + 5],
        slot + 1,
        &tail[digits.len()..],
        width = digits.len()
    ))
}

//! Ad-hoc extraction correctness check (not shipped). Extracts a multivolume
//! set to real files under <outdir>, so the caller can sha256 them against the
//! source. Companion to bench_extract.
//!
//!   cargo run -q --release --features parallel --example verify_extract -- <dir> <outdir> [password]

use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

/// Entry name -> output path, mirroring the archive's layout the way unrar
/// does. Traversal-safe: absolute prefixes and `..`/`.` components are
/// dropped, so every entry lands under `outdir`.
fn entry_path(outdir: &std::path::Path, name: &[u8]) -> PathBuf {
    let name = String::from_utf8_lossy(name);
    let mut path = outdir.to_path_buf();
    path.extend(
        name.split(['/', '\\'])
            .filter(|part| !part.is_empty() && *part != "." && *part != ".."),
    );
    path
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let dir = PathBuf::from(args.get(1).expect("usage: verify_extract <dir> <outdir>"));
    let outdir = PathBuf::from(args.get(2).expect("usage: verify_extract <dir> <outdir>"));
    let password = args.get(3).map(|s| s.as_bytes().to_vec());
    std::fs::create_dir_all(&outdir).unwrap();

    let mut vols: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().map(|e| e == "rar").unwrap_or(false))
        .collect();
    vols.sort();
    // Parse with the password (one ReadSession) so header-encrypted sets
    // work too.
    let options = password
        .as_deref()
        .map(rars::ArchiveReadOptions::with_password)
        .unwrap_or_default();
    let mut session = rars::ReadSession::new(options);
    let archives: Vec<_> = vols
        .iter()
        .map(|p| session.read_path(p).unwrap())
        .collect();

    rars::extract_volumes_to(&archives, password.as_deref(), |meta| {
        let path = entry_path(&outdir, &meta.name);
        if meta.is_directory {
            std::fs::create_dir_all(&path).unwrap();
            return Ok(Box::new(std::io::sink()) as Box<dyn Write>);
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        Ok(Box::new(File::create(path).unwrap()) as Box<dyn Write>)
    })
    .unwrap();
    eprintln!("extracted to {}", outdir.display());
}

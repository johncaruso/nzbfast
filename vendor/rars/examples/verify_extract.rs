//! Ad-hoc extraction correctness check (not shipped). Extracts a multivolume
//! set to real files under <outdir>, so the caller can sha256 them against the
//! source. Companion to bench_extract.
//!
//!   cargo run -q --release --features parallel --example verify_extract -- <dir> <outdir>

use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let dir = PathBuf::from(args.get(1).expect("usage: verify_extract <dir> <outdir>"));
    let outdir = PathBuf::from(args.get(2).expect("usage: verify_extract <dir> <outdir>"));
    std::fs::create_dir_all(&outdir).unwrap();

    let mut vols: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().map(|e| e == "rar").unwrap_or(false))
        .collect();
    vols.sort();
    let archives: Vec<_> = vols
        .iter()
        .map(|p| rars::ArchiveReader::read_path(p).unwrap())
        .collect();

    rars::extract_volumes_to(&archives, None, |meta| {
        let name = String::from_utf8_lossy(&meta.name);
        let base = name.rsplit(['/', '\\']).next().unwrap_or("out");
        let path = outdir.join(base);
        Ok(Box::new(File::create(path).unwrap()) as Box<dyn Write>)
    })
    .unwrap();
    eprintln!("extracted to {}", outdir.display());
}

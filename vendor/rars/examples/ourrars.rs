//! Shootout contestant: extract a multivolume set to real files.
//!
//!   ourrars <voldir> <outdir> [password]
//!
//! Same interface and same code path as the Windows rig's ourrars.exe, so the
//! two legs of the shootout drive our extractor identically: read every *.rar
//! in the directory in sorted order, then `extract_volumes_to` exactly as the
//! daemon does.

use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let dir = PathBuf::from(args.get(1).expect("usage: ourrars <dir> <outdir> [password]"));
    let outdir = PathBuf::from(args.get(2).expect("usage: ourrars <dir> <outdir> [password]"));
    let password: Option<Vec<u8>> = args.get(3).map(|s| s.as_bytes().to_vec());
    std::fs::create_dir_all(&outdir).unwrap();

    let mut vols: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().map(|e| e == "rar").unwrap_or(false))
        .collect();
    vols.sort();

    let options = rars::ArchiveReadOptions::with_optional_password(password.as_deref());
    let archives: Vec<_> = vols
        .iter()
        .map(|p| rars::ArchiveReader::read_path_with_options(p, options).unwrap())
        .collect();

    rars::extract_volumes_to(&archives, password.as_deref(), |meta| {
        let name = String::from_utf8_lossy(&meta.name);
        let base = name.rsplit(['/', '\\']).next().unwrap_or("out");
        let path = outdir.join(base);
        Ok(Box::new(File::create(path).unwrap()) as Box<dyn Write>)
    })
    .unwrap();
}

//! Ad-hoc RAR29 multivolume generator (not shipped): rar 7.x cannot
//! create RAR4, so a split-member RAR4 differential corpus comes from our
//! own encoder. It runs at roughly 66 KB/s, so keep the input small.
//!
//!   cargo run -q --release --example gen_rar4_volumes -- <input> <outdir> <per-vol>
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let src = std::fs::read(&args[1]).unwrap();
    let outdir = std::path::PathBuf::from(&args[2]);
    let per_vol: usize = args[3].parse().unwrap();
    std::fs::create_dir_all(&outdir).unwrap();
    let parts = rars::rar15_40::write_compressed_volumes(
        rars::rar15_40::FileEntry {
            name: b"big.dat",
            data: &src,
            file_time: 0,
            file_attr: 0x20,
            host_os: 3,
            password: None,
            file_comment: None,
        },
        rars::rar15_40::WriterOptions::new(
            rars::ArchiveVersion::Rar29,
            rars::FeatureSet::default(),
        ),
        per_vol,
    )
    .unwrap();
    // unrar continues a `volN.rar` set as OLD naming (.r00, .r01, ...).
    for (index, part) in parts.iter().enumerate() {
        let name = if index == 0 {
            "vol.rar".to_string()
        } else {
            format!("vol.r{:02}", index - 1)
        };
        std::fs::write(outdir.join(&name), part).unwrap();
        println!("{name} {} bytes", part.len());
    }
}

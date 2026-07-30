//! Ad-hoc RAR29 (RAR4) archive generator (not shipped): rar 7.x can no
//! longer create RAR4, so bench corpora for the legacy decoder come from
//! our own encoder (unrar-validated). LZ-only: the PPMd policy makes
//! archives that decode 40x slower in every tool, which benchmarks PPMd,
//! not the LZ path.
//!
//!   cargo run -q --release --example gen_rar4 -- <input-file> <out.rar> [ppmd]
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let src = std::fs::read(&args[1]).unwrap();
    let out = &args[2];
    let options = rars::rar15_40::WriterOptions::new(
        rars::ArchiveVersion::Rar29,
        rars::FeatureSet::default(),
    );
    let bytes = rars::rar15_40::write_rar29_compressed_archive_with_filter_policy(
        &[rars::rar15_40::FileEntry {
            name: b"big.dat",
            data: &src,
            file_time: 0,
            file_attr: 0x20,
            host_os: 3,
            password: None,
            file_comment: None,
        }],
        options,
        if args.get(3).map(String::as_str) == Some("ppmd") {
            rars::rar15_40::FilterPolicy::Ppmd
        } else {
            rars::rar15_40::FilterPolicy::Lz
        },
    )
    .unwrap();
    std::fs::write(out, bytes).unwrap();
}

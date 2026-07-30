//! Ad-hoc: parse a volume directory per-call vs through one ReadSession
//! (the cross-volume KDF cache) with a password.
//!
//!   bench_parse_session <dir> <password> [session|percall]
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let dir = std::path::PathBuf::from(&args[1]);
    let password = args[2].as_bytes().to_vec();
    let mode = args.get(3).map(String::as_str).unwrap_or("session");
    let mut vols: Vec<_> = std::fs::read_dir(&dir).unwrap().map(|e| e.unwrap().path())
        .filter(|p| p.extension().map(|e| e == "rar").unwrap_or(false)).collect();
    vols.sort();
    let options = rars::ArchiveReadOptions::with_password(&password);
    let t = std::time::Instant::now();
    let count = if mode == "session" {
        let mut session = rars::ReadSession::new(options);
        vols.iter().map(|p| session.read_path(p).unwrap()).count()
    } else {
        vols.iter().map(|p| rars::ArchiveReader::read_path_with_options(p, options).unwrap()).count()
    };
    println!("{mode}: {count} volumes parsed in {:?}", t.elapsed());
}

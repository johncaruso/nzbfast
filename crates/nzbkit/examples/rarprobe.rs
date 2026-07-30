//! Diagnostic: map RAR volume headers from on-disk files and print what
//! the arithmetic gate would see. Usage: rarprobe <files...>

use nzbkit::rar::{feed_headers_incrementally_pub, ArchiveMap, ArithGate, VolumeMapper};

fn main() {
    // --head N: feed only the first N bytes (a partially-downloaded
    // volume is sparse - the incremental feeder would walk into holes
    // and report artifact blockers).
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let mut head: Option<usize> = None;
    if args.first().map(|a| a == "--head").unwrap_or(false) {
        args.remove(0);
        head = Some(args.remove(0).parse().unwrap());
    }
    let mut mappers: Vec<VolumeMapper> = Vec::new();
    for p in &args {
        let Ok(mut f) = std::fs::File::open(p) else {
            eprintln!("{p}: open failed");
            continue;
        };
        let size = f.metadata().map(|m| m.len()).unwrap_or(0);
        let mut m = VolumeMapper::new(size);
        if let Some(n) = head {
            use std::io::Read;
            let mut buf = vec![0u8; n];
            let got = f.read(&mut buf).unwrap_or(0);
            m.feed(0, &buf[..got]);
        } else {
            feed_headers_incrementally_pub(&mut f, size, &mut m);
        }
        let name = std::path::Path::new(p)
            .file_name()
            .unwrap()
            .to_string_lossy()
            .into_owned();
        println!(
            "== {} size={} ver={:?} volnum={:?} complete={} blocker={:?} entries={}",
            &name[..name.len().min(24)],
            size,
            m.version,
            m.volume_number,
            m.complete,
            m.blocker,
            m.entries.len()
        );
        for e in &m.entries {
            println!(
                "   entry name={:?} unp={} dl={} off={} method={:?} enc={} dir={} szunk={} sb={} sa={} crc={:?} hash={}",
                &e.name[..e.name.len().min(40)],
                e.unpacked_size,
                e.data_len,
                e.data_off,
                e.method,
                e.encrypted,
                e.is_dir,
                e.size_unknown,
                e.split_before,
                e.split_after,
                e.file_crc,
                e.hash.is_some()
            );
        }
        mappers.push(m);
    }
    let refs: Vec<&VolumeMapper> = mappers.iter().collect();
    match ArchiveMap::resolve_arithmetic(&refs) {
        ArithGate::Place { bases, closed } => println!("GATE: Place closed={closed} bases={bases:?}"),
        ArithGate::Shape => println!("GATE: Shape"),
        ArithGate::Numbers => println!("GATE: Numbers"),
    }
}

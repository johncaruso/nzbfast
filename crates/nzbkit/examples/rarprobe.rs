//! Diagnostic: map RAR volume headers from on-disk files and print what
//! the arithmetic gate would see.
//! Usage: rarprobe [--head N] [--password PW] <files...>

use nzbkit::rar::{
    ArchiveMap, ArithGate, EntryCrypt, VolumeMapper, feed_headers_incrementally_pub,
};

fn main() {
    // --head N: feed only the first N bytes (a partially-downloaded
    // volume is sparse - the incremental feeder would walk into holes
    // and report artifact blockers).
    // --password PW: what the extractor would see WITH a key. Without it
    // an encrypted set reports only its blocker, and a header-encrypted
    // one reports nothing at all - which is the whole question when a
    // locked set is the thing being debugged.
    let mut args: Vec<String> = std::env::args().skip(1).collect();
    let mut head: Option<usize> = None;
    let mut password: Option<String> = None;
    while let Some(flag) = args.first().cloned() {
        match flag.as_str() {
            "--head" => {
                args.remove(0);
                head = Some(args.remove(0).parse().unwrap());
            }
            "--password" => {
                args.remove(0);
                password = Some(args.remove(0));
            }
            _ => break,
        }
    }
    let mut mappers: Vec<VolumeMapper> = Vec::new();
    for p in &args {
        let Ok(mut f) = std::fs::File::open(p) else {
            eprintln!("{p}: open failed");
            continue;
        };
        let size = f.metadata().map(|m| m.len()).unwrap_or(0);
        let mut m =
            VolumeMapper::with_password(size, password.as_deref().map(std::sync::Arc::from));
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
            // Which key schedule the entry needs, and whether anything
            // could vouch for the password before decrypting: RAR4 never
            // can, so those sets always assemble ciphertext and take the
            // verdict from the CRC at finish.
            match &e.crypt {
                Some(EntryCrypt::Rar5(c)) => println!(
                    "     crypt=rar5 aes256 lg2={} check={} tweaked={}",
                    c.lg2_count,
                    c.check.is_some(),
                    c.tweaked_checksum
                ),
                Some(EntryCrypt::Rar4(c)) => println!(
                    "     crypt=rar4 aes128 salt={} check=none (verdict at finish)",
                    c.salt.is_some()
                ),
                None if e.encrypted => {
                    println!("     crypt=UNSUPPORTED (pre-3.0 cipher) - unrar fallback")
                }
                None => {}
            }
        }
        mappers.push(m);
    }
    let refs: Vec<&VolumeMapper> = mappers.iter().collect();
    match ArchiveMap::resolve_arithmetic(&refs) {
        ArithGate::Place { bases, closed } => {
            println!("GATE: Place closed={closed} bases={bases:?}")
        }
        ArithGate::Shape => println!("GATE: Shape"),
        ArithGate::Numbers => println!("GATE: Numbers"),
    }
}

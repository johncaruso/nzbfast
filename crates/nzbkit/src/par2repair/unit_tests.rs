//! Lib-level unit tests for the DIRECTORY repair path (coverage §122.5).
//!
//! A child module of `par2repair` (the pool/unit_tests.rs pattern) so
//! par2repair.rs itself stays inside its size-gate entry while the
//! private internals remain reachable through `super::*`. The inline
//! `mod tests` exercises the math and the mapped driver; everything
//! here goes through the on-disk entry points - `repair_dir`,
//! `repair_present_sets`, `covered_names`, `sniffed_packet_files` -
//! with real serialized packet files, because those paths were only
//! ever reached from the nzbfast binaries and a --lib measurement
//! cannot see that.

use super::*;

/// Wrap a body in a valid packet (magic, length, body MD5) - the same
/// shape par2.rs's own tests build. Header is 64 bytes per spec.
fn pkt(set_id: [u8; 16], ptype: &[u8; 16], body: &[u8]) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(par2::MAGIC);
    p.extend_from_slice(&(64 + body.len() as u64).to_le_bytes());
    p.extend_from_slice(&[0u8; 16]); // md5 patched below
    p.extend_from_slice(&set_id);
    p.extend_from_slice(ptype);
    p.extend_from_slice(body);
    let md5: [u8; 16] = Md5::digest(&p[32..]).into();
    p[16..32].copy_from_slice(&md5);
    p
}

fn fid(i: usize) -> [u8; 16] {
    let mut f = [0u8; 16];
    f[0] = i as u8 + 1;
    f
}

/// Serialized index file: Main + per-file FileDesc + IFSC packets.
fn par2_index(set_id: [u8; 16], bs: usize, files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut main = Vec::new();
    main.extend_from_slice(&(bs as u64).to_le_bytes());
    main.extend_from_slice(&(files.len() as u32).to_le_bytes());
    for i in 0..files.len() {
        main.extend_from_slice(&fid(i));
    }
    let mut out = pkt(set_id, par2::TYPE_MAIN, &main);
    for (i, (name, data)) in files.iter().enumerate() {
        let mut desc = Vec::new();
        desc.extend_from_slice(&fid(i));
        desc.extend_from_slice(&<[u8; 16]>::from(Md5::digest(data)));
        // Short files: md5_16k IS the whole-file MD5, not zero-padded.
        let head = &data[..data.len().min(16384)];
        desc.extend_from_slice(&<[u8; 16]>::from(Md5::digest(head)));
        desc.extend_from_slice(&(data.len() as u64).to_le_bytes());
        let mut nb = name.as_bytes().to_vec();
        while nb.len() % 4 != 0 {
            nb.push(0);
        }
        desc.extend_from_slice(&nb);
        out.extend(pkt(set_id, par2::TYPE_FILEDESC, &desc));
        let mut body = fid(i).to_vec();
        for chunk in data.chunks(bs) {
            let mut padded = chunk.to_vec();
            padded.resize(bs, 0);
            body.extend_from_slice(&<[u8; 16]>::from(Md5::digest(&padded)));
            body.extend_from_slice(&crc32fast::hash(&padded).to_le_bytes());
        }
        out.extend(pkt(set_id, par2::TYPE_IFSC, &body));
    }
    out
}

/// The set's global input slices: files in Main order, zero-padded.
fn global_slices(files: &[(&str, &[u8])], bs: usize) -> Vec<Vec<u8>> {
    let mut slices = Vec::new();
    for (_, data) in files {
        for c in data.chunks(bs) {
            let mut v = c.to_vec();
            v.resize(bs, 0);
            slices.push(v);
        }
    }
    slices
}

/// One recovery slice's data for exponent `e` - the same generator the
/// inline math tests validate against the Reconstructor.
fn generate_recovery(slices: &[Vec<u8>], bs: usize, e: u32) -> Vec<u8> {
    let logs = input_base_logs(slices.len()).unwrap();
    let mut acc = vec![0u16; bs / 2];
    for (d, &k) in slices.iter().zip(&logs) {
        MulTable::new(gf16::pow2(k as u64 * e as u64)).xor_mul_into(&mut acc, d);
    }
    acc.iter().flat_map(|w| w.to_le_bytes()).collect()
}

/// Serialized recovery volume holding one RecvSlic packet per exponent.
fn par2_volume(set_id: [u8; 16], bs: usize, files: &[(&str, &[u8])], exps: &[u32]) -> Vec<u8> {
    let slices = global_slices(files, bs);
    let mut out = Vec::new();
    for &e in exps {
        let mut body = e.to_le_bytes().to_vec();
        body.extend_from_slice(&generate_recovery(&slices, bs, e));
        out.extend(pkt(set_id, par2::TYPE_RECVSLIC, &body));
    }
    out
}

fn payload(len: usize, seed: u64) -> Vec<u8> {
    let mut s = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..len)
        .map(|_| {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            (s >> 24) as u8
        })
        .collect()
}

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "nzbfast-par2dir-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

const BS: usize = 64;
const SET: [u8; 16] = [9u8; 16];

#[test]
fn clean_set_reads_no_damage_and_names_its_files() {
    let dir = tmpdir("clean");
    let a = payload(200, 1); // 4 slices, 8-byte tail
    let b = payload(97, 2); // 2 slices, 33-byte tail
    let files: &[(&str, &[u8])] = &[("a.bin", &a), ("b.bin", &b)];
    std::fs::write(dir.join("a.bin"), &a).unwrap();
    std::fs::write(dir.join("b.bin"), &b).unwrap();
    std::fs::write(dir.join("set.par2"), par2_index(SET, BS, files)).unwrap();
    std::fs::write(
        dir.join("set.vol0+2.par2"),
        par2_volume(SET, BS, files, &[0, 1]),
    )
    .unwrap();
    match repair_dir(&dir).expect("clean set verifies") {
        RepairStatus::NoDamage => {}
        other => panic!("expected NoDamage, got {other:?}"),
    }
    let mut names = covered_names(&dir).expect("names parse");
    names.sort();
    assert_eq!(names, ["a.bin", "b.bin"]);
    assert!(
        sniffed_packet_files(&dir).expect("sniff walks").is_empty(),
        "every packet file here is named *.par2"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn damage_and_a_missing_file_rebuild_from_recovery_slices() {
    let dir = tmpdir("rebuild");
    let a = payload(200, 3);
    let b = payload(97, 4);
    let files: &[(&str, &[u8])] = &[("a.bin", &a), ("b.bin", &b)];
    // a.bin: slice 1 corrupted in place. b.bin: gone entirely.
    let mut a_damaged = a.clone();
    for x in &mut a_damaged[64..128] {
        *x ^= 0x5a;
    }
    std::fs::write(dir.join("a.bin"), &a_damaged).unwrap();
    std::fs::write(dir.join("set.par2"), par2_index(SET, BS, files)).unwrap();
    // Four recovery slices for three missing blocks - and the volume is a
    // SECOND packet file, so the critical-complete break routes its scan
    // through the background thread overlapped with target verify.
    std::fs::write(
        dir.join("set.vol0+4.par2"),
        par2_volume(SET, BS, files, &[0, 1, 2, 3]),
    )
    .unwrap();
    let report = match repair_dir(&dir).expect("repairable set repairs") {
        RepairStatus::Repaired(r) => r,
        other => panic!("expected Repaired, got {other:?}"),
    };
    assert_eq!(
        report.blocks_rebuilt, 3,
        "one a.bin slice + two b.bin slices"
    );
    assert_eq!(report.blocks_adopted, 0);
    assert_eq!(report.files_created, ["b.bin"], "absent file recreated");
    let mut patched = report.files_patched.clone();
    patched.sort();
    assert_eq!(patched, ["a.bin", "b.bin"]);
    assert!(report.consumed_sources.is_empty());
    assert_eq!(std::fs::read(dir.join("a.bin")).unwrap(), a);
    assert_eq!(std::fs::read(dir.join("b.bin")).unwrap(), b);
    // A second pass over the repaired dir is the NoDamage path.
    match repair_dir(&dir).expect("repaired set re-verifies") {
        RepairStatus::NoDamage => {}
        other => panic!("expected NoDamage after repair, got {other:?}"),
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn too_little_recovery_reports_the_shortfall() {
    let dir = tmpdir("short");
    let c = payload(200, 5);
    let files: &[(&str, &[u8])] = &[("c.bin", &c)];
    let mut damaged = c.clone();
    for x in &mut damaged[0..128] {
        *x ^= 0x77; // slices 0 and 1 both bad
    }
    std::fs::write(dir.join("c.bin"), &damaged).unwrap();
    std::fs::write(dir.join("set.par2"), par2_index(SET, BS, files)).unwrap();
    std::fs::write(
        dir.join("set.vol0+1.par2"),
        par2_volume(SET, BS, files, &[0]),
    )
    .unwrap();
    // Two missing, one slice on disk. The last-resort escalation slides
    // over the identified-but-damaged target itself, finds nothing (the
    // corrupt bytes are gone), and the verdict states the arithmetic.
    match repair_dir(&dir).expect("shortfall is a verdict, not an error") {
        RepairStatus::Unrepairable { needed, have } => {
            assert_eq!((needed, have), (2, 1));
        }
        other => panic!("expected Unrepairable, got {other:?}"),
    }
    assert_eq!(
        std::fs::read(dir.join("c.bin")).unwrap(),
        damaged,
        "an unrepairable set must not touch the file"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn sliding_scan_adopts_shifted_block_content_from_a_fragment() {
    let dir = tmpdir("slide");
    let c = payload(200, 6);
    let files: &[(&str, &[u8])] = &[("c.bin", &c)];
    let mut damaged = c.clone();
    for x in &mut damaged[64..128] {
        *x ^= 0x33; // slice 1 bad
    }
    std::fs::write(dir.join("c.bin"), &damaged).unwrap();
    // No recovery slices at all - but a junk-named fragment carries the
    // lost block's bytes at an UNALIGNED offset only the rolling-CRC
    // window can find.
    let mut frag = vec![0xEEu8; 10];
    frag.extend_from_slice(&c[64..128]);
    std::fs::write(dir.join("frag"), &frag).unwrap();
    std::fs::write(dir.join("set.par2"), par2_index(SET, BS, files)).unwrap();
    let report = match repair_dir(&dir).expect("adoption repairs without recovery") {
        RepairStatus::Repaired(r) => r,
        other => panic!("expected Repaired, got {other:?}"),
    };
    assert_eq!(report.blocks_rebuilt, 0);
    assert_eq!(report.blocks_adopted, 1);
    assert_eq!(report.adopted_from, ["frag"]);
    assert!(
        report.consumed_sources.is_empty(),
        "a fragment is not a byte-for-byte copy of any target - never swept"
    );
    assert_eq!(std::fs::read(dir.join("c.bin")).unwrap(), c);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_wholly_renamed_copy_is_adopted_and_reported_consumed() {
    let dir = tmpdir("adopt");
    let a = payload(200, 7);
    let files: &[(&str, &[u8])] = &[("a.bin", &a)];
    // The obfuscated-post shape: the payload exists only under a hash
    // name, the FileDesc name is absent, no recovery slices anywhere.
    std::fs::write(dir.join("0f9a7c"), &a).unwrap();
    std::fs::write(dir.join("set.par2"), par2_index(SET, BS, files)).unwrap();
    // The name gate skips the set (no FileDesc name on disk)...
    assert!(
        repair_present_sets(&dir)
            .expect("present-set walk")
            .is_empty(),
        "no declared name on disk means the plain entry point skips"
    );
    // ...and the renamed fallback attempts it anyway and succeeds.
    let outcomes = repair_present_or_renamed_sets(&dir).expect("fallback runs");
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].names, ["a.bin"]);
    let report = match outcomes[0].status.as_ref().expect("set repairs") {
        RepairStatus::Repaired(r) => r,
        other => panic!("expected Repaired, got {other:?}"),
    };
    assert_eq!(report.blocks_adopted, 4, "every slice found in the copy");
    assert_eq!(report.files_created, ["a.bin"]);
    assert_eq!(
        report.consumed_sources,
        [dir.join("0f9a7c")],
        "the donor is a proven byte-for-byte copy, so the caller may sweep it"
    );
    assert_eq!(std::fs::read(dir.join("a.bin")).unwrap(), a);
    // With the payload landed, the plain entry point now sees the set
    // and reports it clean.
    let again = repair_present_sets(&dir).expect("present-set walk");
    assert_eq!(again.len(), 1);
    assert!(
        matches!(again[0].status, Ok(RepairStatus::NoDamage)),
        "{:?}",
        again[0].status
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_sniffed_extensionless_volume_serves_its_slices() {
    let dir = tmpdir("sniff");
    let d = payload(200, 8);
    let files: &[(&str, &[u8])] = &[("d.bin", &d)];
    let mut damaged = d.clone();
    for x in &mut damaged[128..192] {
        *x ^= 0x0f; // slice 2 bad
    }
    std::fs::write(dir.join("d.bin"), &damaged).unwrap();
    std::fs::write(dir.join("set.par2"), par2_index(SET, BS, files)).unwrap();
    // The recovery volume ships under a junk name with no extension -
    // only the packet-magic sniff can find it.
    std::fs::write(dir.join("qq"), par2_volume(SET, BS, files, &[0])).unwrap();
    assert_eq!(
        sniffed_packet_files(&dir).expect("sniff walks"),
        [dir.join("qq")],
        "the extensionless volume is the one sniff-only packet file"
    );
    match repair_dir(&dir).expect("sniffed slices repair") {
        RepairStatus::Repaired(r) => assert_eq!(r.blocks_rebuilt, 1),
        other => panic!("expected Repaired, got {other:?}"),
    }
    assert_eq!(std::fs::read(dir.join("d.bin")).unwrap(), d);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn recovery_slice_locators_report_only_the_wanted_set() {
    let files_data = payload(200, 9);
    let files: &[(&str, &[u8])] = &[("e.bin", &files_data)];
    let vol = par2_volume(SET, BS, files, &[0, 5]);
    let locs = recovery_slice_locators(&vol, &SET);
    assert_eq!(locs.len(), 2);
    assert_eq!(locs[0].0, 0);
    assert_eq!(locs[1].0, 5);
    for &(_, off, len) in &locs {
        assert_eq!(len, BS, "slice data length is the block size");
        assert!(off + len <= vol.len());
    }
    // A foreign set id sees nothing.
    assert!(recovery_slice_locators(&vol, &[1u8; 16]).is_empty());
    // Slice data at the reported offset is the slice the generator made.
    let slices = global_slices(files, BS);
    let want = generate_recovery(&slices, BS, 0);
    assert_eq!(&vol[locs[0].1..locs[0].1 + locs[0].2], &want[..]);
}

//! End-to-end differential test of the native repair driver against
//! par2cmdline: create a real PAR2 set with the reference tool, damage
//! the files, repair natively, and require byte-identical restoration -
//! then apply the SAME damage to a second copy, let par2cmdline repair
//! it, and require our outputs to match its outputs file-for-file.
//!
//! Skips (like the nzbfast e2e suite) when no `par2` is on PATH.

use nzbkit::par2repair::{repair_dir, RepairStatus};
use std::path::{Path, PathBuf};
use std::process::Command;

fn have_par2() -> bool {
    let ok = Command::new("par2")
        .arg("-V")
        .output()
        .is_ok_and(|o| o.status.success());
    // CI installs par2 on purpose (see pr-check.yml, both legs), so there a
    // missing one is a broken job, not a reason to quietly cover less. Every
    // caller of this SKIPS when it is false, which is exactly the shape that
    // reads as a green run with silently reduced coverage - the failure mode
    // this whole Windows pass kept turning up.
    assert!(
        ok || std::env::var_os("NZBFAST_REQUIRE_PAR2").is_none(),
        "NZBFAST_REQUIRE_PAR2 is set but `par2 -V` does not run - the PAR2 tests \
         would have skipped and the run would have looked green"
    );
    ok
}

struct TempDir(PathBuf);
impl TempDir {
    fn new(tag: &str) -> TempDir {
        let p = std::env::temp_dir().join(format!(
            "nzbkit-par2repair-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Deterministic, NON-periodic file contents (xorshift64). A repeating
/// pattern lets par2cmdline's sliding-window scan "find" a damaged
/// block's content intact elsewhere in the file, sidestepping RS repair
/// and breaking the differential comparison.
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

/// par2-create over `files` in `dir` with block size 4096.
fn par2_create(dir: &Path, files: &[&str], extra: &[&str]) {
    let st = Command::new("par2")
        .arg("create")
        .arg("-s4096")
        .args(extra)
        .arg("-q")
        .arg("testset")
        .args(files)
        .current_dir(dir)
        .status()
        .expect("run par2 create");
    assert!(st.success(), "par2 create failed");
}

fn read(dir: &Path, name: &str) -> Vec<u8> {
    std::fs::read(dir.join(name)).unwrap_or_else(|e| panic!("read {name}: {e}"))
}

/// The damage pattern both dirs receive: two corrupt blocks in a.bin,
/// b.bin truncated mid-block, c.bin deleted outright.
fn inflict_damage(dir: &Path) {
    let a = dir.join("a.bin");
    let mut bytes = std::fs::read(&a).unwrap();
    bytes[100..300].fill(0xEE); // block 0
    bytes[9000..9100].fill(0x11); // block 2
    std::fs::write(&a, bytes).unwrap();
    let b = std::fs::OpenOptions::new()
        .write(true)
        .open(dir.join("b.bin"))
        .unwrap();
    b.set_len(5000).unwrap(); // loses blocks 1 and 2 (tail)
    drop(b);
    std::fs::remove_file(dir.join("c.bin")).unwrap();
}

#[test]
fn native_repair_matches_par2cmdline_byte_for_byte() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    // a.bin spans 9 blocks with a tail; b.bin 3 blocks with a tail;
    // c.bin is smaller than one block.
    let names = ["a.bin", "b.bin", "c.bin"];
    let pristine = [payload(33_000, 1), payload(10_000, 2), payload(700, 3)];

    let ours = TempDir::new("native");
    let theirs = TempDir::new("reference");
    for dir in [&ours.0, &theirs.0] {
        for (n, d) in names.iter().zip(&pristine) {
            std::fs::write(dir.join(n), d).unwrap();
        }
    }
    // One set, copied verbatim to the reference dir so both repair the
    // exact same recovery data.
    par2_create(&ours.0, &names, &["-r40"]);
    for e in std::fs::read_dir(&ours.0).unwrap() {
        let p = e.unwrap().path();
        if p.extension().is_some_and(|x| x == "par2") {
            std::fs::copy(&p, theirs.0.join(p.file_name().unwrap())).unwrap();
        }
    }
    inflict_damage(&ours.0);
    inflict_damage(&theirs.0);

    // Native repair restores the pristine bytes…
    match repair_dir(&ours.0).expect("native repair runs") {
        RepairStatus::Repaired(r) => {
            // 2 corrupt in a.bin + 2 lost in b.bin + 1 whole-file c.bin.
            assert_eq!(r.blocks_rebuilt, 5, "5 blocks needed rebuilding");
            assert_eq!(r.files_created, vec!["c.bin"]);
            let mut patched = r.files_patched.clone();
            patched.sort();
            assert_eq!(patched, vec!["a.bin", "b.bin", "c.bin"]);
        }
        other => panic!("expected Repaired, got {other:?}"),
    }
    for (n, d) in names.iter().zip(&pristine) {
        assert_eq!(&read(&ours.0, n), d, "{n} restored to pristine bytes");
    }

    // …and par2cmdline, given identical damage, produces identical files.
    let st = Command::new("par2")
        .arg("repair")
        .arg("-q")
        .arg("testset.par2")
        .current_dir(&theirs.0)
        .status()
        .expect("run par2 repair");
    assert!(st.success(), "reference repair failed");
    for n in &names {
        assert_eq!(
            read(&ours.0, n),
            read(&theirs.0, n),
            "{n}: native output differs from par2cmdline output"
        );
    }
}

#[test]
fn clean_set_reports_no_damage_and_writes_nothing() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let t = TempDir::new("clean");
    let data = payload(20_000, 4);
    std::fs::write(t.0.join("only.bin"), &data).unwrap();
    par2_create(&t.0, &["only.bin"], &["-r10"]);
    let before = std::fs::metadata(t.0.join("only.bin")).unwrap().modified().unwrap();
    match repair_dir(&t.0).expect("repair runs") {
        RepairStatus::NoDamage => {}
        other => panic!("expected NoDamage, got {other:?}"),
    }
    let after = std::fs::metadata(t.0.join("only.bin")).unwrap().modified().unwrap();
    assert_eq!(before, after, "clean file untouched");
}

#[test]
fn damage_beyond_recovery_reports_unrepairable_counts() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let t = TempDir::new("unrep");
    let data = payload(33_000, 5);
    std::fs::write(t.0.join("big.bin"), &data).unwrap();
    par2_create(&t.0, &["big.bin"], &["-c1"]); // one recovery block only
    let mut bytes = std::fs::read(t.0.join("big.bin")).unwrap();
    bytes[100] ^= 0xFF; // block 0
    bytes[5000] ^= 0xFF; // block 1
    std::fs::write(t.0.join("big.bin"), bytes).unwrap();
    match repair_dir(&t.0).expect("repair runs") {
        RepairStatus::Unrepairable { needed, have } => {
            assert_eq!((needed, have), (2, 1));
        }
        other => panic!("expected Unrepairable, got {other:?}"),
    }
    // par2cmdline agrees this set is unrepairable.
    let st = Command::new("par2")
        .arg("repair")
        .arg("-q")
        .arg("testset.par2")
        .current_dir(&t.0)
        .status()
        .expect("run par2 repair");
    assert!(!st.success(), "reference tool must also fail");
}

/// Not part of the suite - perf sanity vs par2cmdline on a ~200 MB set:
/// `cargo test -p nzbkit --release --test par2repair_dir -- --ignored perf`
#[test]
#[ignore]
fn perf_smoke_200mb_vs_par2cmdline() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let names = ["big.bin"];
    let data = payload(200 << 20, 42);
    let bs = 768_000usize;
    let ours = TempDir::new("perf-native");
    let theirs = TempDir::new("perf-reference");
    for dir in [&ours.0, &theirs.0] {
        std::fs::write(dir.join("big.bin"), &data).unwrap();
    }
    let st = Command::new("par2")
        .args(["create", &format!("-s{bs}"), "-r5", "-q", "testset", "big.bin"])
        .current_dir(&ours.0)
        .status()
        .unwrap();
    assert!(st.success());
    for e in std::fs::read_dir(&ours.0).unwrap() {
        let p = e.unwrap().path();
        if p.extension().is_some_and(|x| x == "par2") {
            std::fs::copy(&p, theirs.0.join(p.file_name().unwrap())).unwrap();
        }
    }
    // 12 damaged blocks scattered through the file.
    for dir in [&ours.0, &theirs.0] {
        let f = std::fs::OpenOptions::new()
            .write(true)
            .open(dir.join("big.bin"))
            .unwrap();
        for i in 0..12u64 {
            let off = i * 17 * bs as u64 + 100;
            use std::io::{Seek, SeekFrom, Write};
            let mut f2 = &f;
            f2.seek(SeekFrom::Start(off)).unwrap();
            f2.write_all(&[0xEE; 256]).unwrap();
        }
    }
    let t0 = std::time::Instant::now();
    match repair_dir(&ours.0).unwrap() {
        RepairStatus::Repaired(r) => assert_eq!(r.blocks_rebuilt, 12),
        other => panic!("expected Repaired, got {other:?}"),
    }
    let native = t0.elapsed();
    let t0 = std::time::Instant::now();
    let st = Command::new("par2")
        .args(["repair", "-q", "testset.par2"])
        .current_dir(&theirs.0)
        .status()
        .unwrap();
    assert!(st.success());
    let reference = t0.elapsed();
    assert_eq!(read(&ours.0, "big.bin"), data, "native restored pristine");
    assert_eq!(read(&ours.0, "big.bin"), read(&theirs.0, "big.bin"));
    println!("perf 200MB/12 blocks: native {native:.2?} vs par2cmdline {reference:.2?}");
}

#[test]
fn overlong_file_is_truncated_back_to_spec() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let t = TempDir::new("overlong");
    let data = payload(9_000, 6);
    std::fs::write(t.0.join("f.bin"), &data).unwrap();
    par2_create(&t.0, &["f.bin"], &["-r10"]);
    let mut longer = data.clone();
    longer.extend_from_slice(&[0xAB; 4096]);
    std::fs::write(t.0.join("f.bin"), &longer).unwrap();
    match repair_dir(&t.0).expect("repair runs") {
        RepairStatus::Repaired(r) => {
            assert_eq!(r.blocks_rebuilt, 0, "no RS work - pure truncation");
            assert_eq!(r.files_patched, vec!["f.bin"]);
        }
        other => panic!("expected Repaired, got {other:?}"),
    }
    assert_eq!(read(&t.0, "f.bin"), data);
}

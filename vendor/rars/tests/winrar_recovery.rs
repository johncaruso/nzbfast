//! Multi-group RAR5 recovery against REAL WinRAR output.
//!
//! Every other recovery test in this crate round-trips our OWN encoder, so a
//! shared misunderstanding of the format would pass all of them - which is
//! exactly how the pre-13 MB ceiling survived. This one builds archives with
//! RARLab's `rar`, repairs them with our code, and requires the result to be
//! byte-identical to the pristine file AND to what `rar r` produces from the
//! same damage.
//!
//! `#[ignore]` by default for two reasons: it needs the proprietary `rar`
//! binary, which is not in CI, and the archives it builds are far past the
//! 1 MB the tree keeps as fixtures (a single group is 200 x 64 KiB, so
//! anything under ~13 MB cannot exercise the multi-group path at all).
//!
//!   cargo test -p rars --features parallel --test winrar_recovery \
//!       -- --ignored --nocapture

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use rars::recovery::rar5;
use rars::recovery::stream::{
    repair_prefix_streaming, scan_inline_recovery_chunks, FileSource,
};

fn have_rar() -> bool {
    Command::new("rar")
        .arg("-iver")
        .output()
        .map(|o| o.status.success() || !o.stdout.is_empty())
        .unwrap_or(false)
}

fn workdir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("rars-winrar-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create work dir");
    dir
}

/// A payload `rar -m0` will store verbatim, so the protected region is the
/// size we asked for rather than whatever compression happened to give.
fn write_payload(path: &Path, bytes: usize) {
    let mut state = 0x2545_F491_4F6C_DD1Du64;
    let mut buf = Vec::with_capacity(bytes);
    while buf.len() < bytes {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        buf.extend_from_slice(&state.to_le_bytes());
    }
    buf.truncate(bytes);
    fs::write(path, &buf).expect("write payload");
}

fn damage(path: &Path, spots: &[f64], len: usize) {
    use std::io::{Seek, SeekFrom, Write};
    let size = fs::metadata(path).expect("stat").len();
    let mut f = fs::OpenOptions::new().write(true).open(path).expect("open");
    for (i, frac) in spots.iter().enumerate() {
        let at = (size as f64 * frac) as u64;
        if at + len as u64 >= size {
            continue;
        }
        f.seek(SeekFrom::Start(at)).expect("seek");
        f.write_all(&vec![0xA5u8.wrapping_add(i as u8); len])
            .expect("write");
    }
}

/// Repairs `damaged` into `out` through the STREAMING path, which is the one
/// the daemon uses (`repair_recovery_to_file` / `repair_inline_recovery_path`).
fn repair_streaming(damaged: &Path, out: &Path) -> Vec<usize> {
    let source = FileSource::open(damaged).expect("open damaged");
    let scan = scan_inline_recovery_chunks(&source, 64 << 20).expect("scan recovery records");

    let plan = scan.plan().expect("a plan");
    let groups = rars::recovery::rar5::recovery_groups(plan).expect("groups");
    assert!(
        groups.len() > 1,
        "this fixture must span more than one group or it proves nothing \
         (group_count {}, groups {})",
        plan.group_count,
        groups.len()
    );

    let _ = fs::remove_file(out);
    let mut dest = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(out)
        .expect("create output");
    repair_prefix_streaming(&source, 0, &scan, &source, &mut dest, 64 << 20)
        .expect("streaming repair")
}

#[test]
#[ignore = "needs the proprietary `rar` binary and builds >13 MB archives"]
fn multi_group_recovery_matches_winrar_byte_for_byte() {
    if !have_rar() {
        eprintln!("SKIP: `rar` not on PATH - this test needs RARLab's binary");
        return;
    }

    // 16 MB is the smallest size that spans two groups (200 shards x 64 KiB
    // = 13.1 MB is exactly one); 128 MB gives eleven, including a short tail.
    for mb in [16usize, 128] {
        let dir = workdir(&format!("{mb}mb"));
        let payload = dir.join("payload.bin");
        write_payload(&payload, mb * 1024 * 1024);

        let status = Command::new("rar")
            .args(["a", "-ma5", "-m0", "-rr5p", "-idq", "-ep"])
            .arg(dir.join("a.rar"))
            .arg(&payload)
            .status()
            .expect("run rar a");
        assert!(status.success(), "rar a failed for {mb} MB");
        fs::remove_file(&payload).ok();

        let pristine = dir.join("a.rar");
        let damaged = dir.join("dmg.rar");
        fs::copy(&pristine, &damaged).expect("copy");
        damage(&damaged, &[0.2, 0.5, 0.8], 3000);

        // Ours, through the daemon's streaming path.
        let ours = dir.join("ours.rar");
        let rebuilt = repair_streaming(&damaged, &ours);
        assert!(!rebuilt.is_empty(), "{mb} MB: nothing was rebuilt");
        assert_eq!(
            fs::read(&ours).expect("read ours"),
            fs::read(&pristine).expect("read pristine"),
            "{mb} MB: our repair is not byte-identical to the pristine archive"
        );

        // RARLab's own repair of the SAME damaged file, as an independent
        // oracle: agreeing with the original could still hide a shared
        // misreading of which bytes the record protects.
        let status = Command::new("rar")
            .args(["r", "-y", "-idq"])
            .arg(&damaged)
            .current_dir(&dir)
            .status()
            .expect("run rar r");
        assert!(status.success(), "rar r failed for {mb} MB");
        let theirs = dir.join("fixed.dmg.rar");
        assert!(theirs.exists(), "{mb} MB: rar r produced no output");
        assert_eq!(
            fs::read(&ours).expect("read ours"),
            fs::read(&theirs).expect("read theirs"),
            "{mb} MB: our repair differs from `rar r`'s"
        );

        eprintln!("{mb} MB: byte-identical to pristine AND to `rar r`");
        fs::remove_dir_all(&dir).ok();
    }
}

//! Issue #40 pins for the RAR/7z families: a file that arrives
//! NAMED `.cbr`/`.cb7` is the payload, never packaging. Split out
//! of `unpack.rs` to keep it under its size-gate ceiling; it is
//! the same module, only its text moved.
use super::*;

fn dir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("nzbfast-payload-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn write_with_head(dir: &std::path::Path, name: &str, head: &[u8]) -> PathBuf {
    let mut data = head.to_vec();
    data.resize(4096, 0u8);
    let p = dir.join(name);
    std::fs::write(&p, &data).unwrap();
    p
}

const RAR5: &[u8] = b"Rar!\x1a\x07\x01\x00";
const SEVENZ: &[u8] = &[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];

#[test]
fn a_named_cbr_is_never_an_obfuscated_volume() {
    let d = dir("obf");
    write_with_head(&d, "Event Leviathan 01.cbr", RAR5);
    // An obfuscated volume beside it must still be collected: the
    // guard keys on the named extension, never on content.
    let obf = write_with_head(&d, "a1b2c3d4e5f6", RAR5);
    assert_eq!(collect_obfuscated_rar_volumes(&d).unwrap(), vec![obf]);
    std::fs::remove_dir_all(&d).unwrap();
}

#[test]
fn payload_files_are_not_extractable_archives() {
    let d = dir("extractable");
    let cbr = write_with_head(&d, "comic.cbr", RAR5);
    let cb7 = write_with_head(&d, "comic.cb7", SEVENZ);
    assert!(!is_extractable_archive(&cbr));
    assert!(!is_extractable_archive(&cb7));
    // Obfuscated names keep the sniff.
    let bin = write_with_head(&d, "payload.bin", RAR5);
    assert!(is_extractable_archive(&bin));
    std::fs::remove_dir_all(&d).unwrap();
}

#[test]
fn a_named_cb7_is_never_collected_as_sevenz() {
    let d = dir("cb7");
    write_with_head(&d, "comic.cb7", SEVENZ);
    assert!(collect_sevenz_archives(&d).unwrap().is_empty());
    // A named .7z and an obfuscated 7z both still collect.
    write_with_head(&d, "release.7z", SEVENZ);
    write_with_head(&d, "deadbeef.bin", SEVENZ);
    assert_eq!(collect_sevenz_archives(&d).unwrap().len(), 2);
    std::fs::remove_dir_all(&d).unwrap();
}

/// The whole-ladder pin: a directory whose only archive-headed file
/// is a `.cbr` has NOTHING to unpack - `Ok(None)`, not the stray
/// "looks like an archive but no extractor claimed it" failure, and
/// the comic survives byte-identical.
#[test]
fn a_cbr_only_dir_has_nothing_to_unpack_and_keeps_the_comic() {
    let d = dir("ladder");
    let p = write_with_head(&d, "Event Leviathan 01 (2019).cbr", RAR5);
    let before = std::fs::read(&p).unwrap();
    assert_eq!(extract_one_level(&d, None, 0).unwrap(), None);
    assert_eq!(std::fs::read(&p).unwrap(), before);
    std::fs::remove_dir_all(&d).unwrap();
}

//! `unpack`'s passwords-file case: the operator's own list reaching the
//! ON-DISK extraction ladder (the advP/advQ root cause, 12 Aug).
//!
//! A child module file rather than an inline `mod tests`: unpack.rs is
//! over its size-gate ceiling (TODO 106) and the numbers only go down.
//! Same pattern as smart/tests.rs.

use super::*;

/// The operator's passwords file must reach the ON-DISK extraction
/// ladder, not just the in-stream RAR probe.
///
/// This is the advP/advQ root cause (the four-way correctness round,
/// 12 Aug): the file was readable only from the RAR check-value probe
/// and the post-completion unlock, so the two shapes that arrive here
/// with no check to probe - a header-encrypted 7z, an encrypted zip -
/// were left packed with the right password already in hand.
#[test]
fn the_operator_passwords_file_reaches_the_disk_ladder() {
    use nzbkit::zip::fixtures::{Encrypt, Spec, zip_of};
    let dir = std::env::temp_dir().join(format!("nzbfast-pwfile-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let payload: Vec<u8> = (0..30_000u32).map(|i| (i * 5 + 1) as u8).collect();
    std::fs::write(
        dir.join("locked.zip"),
        zip_of(&[Spec {
            encrypt: Some(Encrypt::Ae {
                password: "fromthefile",
                strength: 3,
                vendor_version: 2,
            }),
            ..Spec::deflated("movie.mkv", &payload)
        }]),
    )
    .unwrap();

    // With no file configured there is no candidate, so the level
    // resolves nothing and the job would arrive packed - today's
    // behaviour for every zip whose password we were never told.
    crate::smart::set_operator_password_file(None);
    assert_eq!(resolve_level_password(&dir, None), None);

    // Configured, the winning line is found - a wrong line first, so
    // the sweep (not a lucky single entry) is what is under test.
    let list = dir.join("pw.txt");
    std::fs::write(&list, "wrong-one\nfromthefile\n").unwrap();
    crate::smart::set_operator_password_file(Some(list));
    assert_eq!(
        resolve_level_password(&dir, None).as_deref(),
        Some("fromthefile")
    );
    // And the level actually unpacks with it.
    assert!(extract_one_level(&dir, None, 0).unwrap().is_some());
    assert_eq!(std::fs::read(dir.join("movie.mkv")).unwrap(), payload);

    crate::smart::set_operator_password_file(None);
    let _ = std::fs::remove_dir_all(&dir);
}

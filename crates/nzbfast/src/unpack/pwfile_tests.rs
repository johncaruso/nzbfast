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

/// Codex sweep G, 13 Aug 2026: two encrypted containers in one post
/// need not share a password. The resolver ran once for the LEVEL and
/// handed its answer to every job, so the second archive stayed packed
/// while the pass reported success - and the top-level command exited
/// 0 because the first archive's output looked like the payload.
#[test]
fn each_encrypted_container_resolves_its_own_password() {
    use nzbkit::zip::fixtures::{Encrypt, Spec, zip_of};
    let dir = std::env::temp_dir().join(format!("nzbfast-pwjobs-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let a: Vec<u8> = (0..20_000u32).map(|i| (i * 7 + 3) as u8).collect();
    let b: Vec<u8> = (0..24_000u32).map(|i| (i * 11 + 5) as u8).collect();
    for (name, member, pw, data) in [
        ("a.zip", "sample.mkv", "alpha", &a),
        ("b.zip", "movie.mkv", "beta", &b),
    ] {
        std::fs::write(
            dir.join(name),
            zip_of(&[Spec {
                encrypt: Some(Encrypt::Ae {
                    password: pw,
                    strength: 3,
                    vendor_version: 2,
                }),
                ..Spec::deflated(member, data)
            }]),
        )
        .unwrap();
    }
    let list = dir.join("pw.txt");
    std::fs::write(&list, "alpha\nbeta\n").unwrap();
    crate::smart::set_operator_password_file(Some(list));

    assert!(extract_one_level(&dir, None, 0).unwrap().is_some());
    assert_eq!(std::fs::read(dir.join("sample.mkv")).unwrap(), a);
    assert_eq!(
        std::fs::read(dir.join("movie.mkv")).unwrap(),
        b,
        "the second container must resolve its OWN password"
    );

    crate::smart::set_operator_password_file(None);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Codex sweep F, 13 Aug 2026: a ZipCrypto check byte is ONE byte, so
/// it admits a wrong password once in 256 tries - which the docs said
/// all along, while the caller stopped at the first value the check
/// liked and never tried another. The checked-in `zipcrypto.zip` is
/// admitted by `wrong-93` as well as by its real value `SECRET`, so
/// ordering the accident first left the archive packed. The extraction
/// is the authority; the check is only a shortlist.
#[test]
fn a_false_positive_header_check_does_not_end_the_candidate_sweep() {
    let root =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../nzbkit/tests/fixtures/zip");
    let dir = std::env::temp_dir().join(format!("nzbfast-pwfalse-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::copy(root.join("zipcrypto.zip"), dir.join("locked.zip")).unwrap();
    let parts = vec![dir.join("locked.zip")];
    // The premise: BOTH values pass the one-byte check.
    assert!(nzbkit::zip::password_opens(&parts, Some("wrong-93")));
    assert!(nzbkit::zip::password_opens(&parts, Some("SECRET")));

    let list = dir.join("pw.txt");
    std::fs::write(&list, "wrong-93\nSECRET\n").unwrap();
    crate::smart::set_operator_password_file(Some(list));
    let cands = zip_password_candidates(&dir, &parts, None);
    let vals: Vec<Option<&str>> = cands.iter().map(|(v, _)| v.as_deref()).collect();
    assert!(
        vals.contains(&Some("wrong-93")) && vals.contains(&Some("SECRET")),
        "the shortlist keeps going past the first hit: {vals:?}"
    );

    assert!(extract_one_level(&dir, None, 0).unwrap().is_some());
    let want: Vec<u8> = (0..20000u32).map(|i| ((i * 37 + 11) % 256) as u8).collect();
    assert_eq!(std::fs::read(dir.join("movie.bin")).unwrap(), want);

    crate::smart::set_operator_password_file(None);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The password probe decodes a content block to judge a key, so it
/// holds the same content-aware declared-size gate as extraction
/// (bug-sweep H1+H2, 14 Aug 2026): a content dictionary bomb and the
/// zeroed-start recovery shape both answer Fails at the gate, before
/// ArchiveReader allocates anything.
#[test]
fn bomb_declaring_containers_fail_the_key_check_at_the_gate() {
    let fixtures = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../nzbkit/tests/fixtures/sevenz"
    );
    for name in ["bomb-content-dict.7z", "recovered-zero-start.bin"] {
        let p = std::path::Path::new(fixtures).join(name);
        assert_eq!(
            sevenz_password_check_capped(&p, Some("any"), 1 << 20),
            SevenzKey::Fails,
            "{name} must fail at the gate"
        );
    }
}

/// Codex sweep M, 13 Aug 2026: what rejects a wrong key on a
/// data-encrypted 7z entry is the entry's CHECKSUM, at its END. The key
/// check reads at most 64 MB, so a first member bigger than that never
/// reached the checksum and the capped read came back "opens" for ANY
/// value - the first candidate tried won and the archive stayed packed.
/// Reaching the cap is now indeterminate, not a pass.
#[test]
fn a_capped_7z_key_check_is_indeterminate_not_a_pass() {
    use sevenz_rust2::{ArchiveEntry, ArchiveWriter, Password, encoder_options::AesEncoderOptions};
    let dir = std::env::temp_dir().join(format!("nzbfast-7zcap-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // Copy coding plus AES: a wrong key yields garbage bytes and no
    // error at all until the checksum - exactly the shape the cap hides.
    let payload: Vec<u8> = (0..64_000u32).map(|i| (i * 31 + 7) as u8).collect();
    let bytes = {
        let mut w = ArchiveWriter::new(std::io::Cursor::new(Vec::new())).unwrap();
        w.set_encrypt_header(false); // plaintext headers: it OPENS unkeyed
        w.set_content_methods(vec![AesEncoderOptions::new(Password::from("right")).into()]);
        w.push_archive_entry(ArchiveEntry::new_file("payload.bin"), Some(&payload[..]))
            .unwrap();
        w.finish().unwrap().into_inner()
    };
    let z = dir.join("locked.7z");
    std::fs::write(&z, &bytes).unwrap();

    // Unbounded enough to reach the checksum: the answers are settled.
    assert_eq!(
        sevenz_password_check_capped(&z, Some("right"), 1 << 20),
        SevenzKey::Opens
    );
    assert_eq!(
        sevenz_password_check_capped(&z, Some("wrong"), 1 << 20),
        SevenzKey::Fails
    );
    // Cut short of it, neither value can be judged - and the wrong one
    // must NOT come back as a pass.
    assert_eq!(
        sevenz_password_check_capped(&z, Some("wrong"), 1_024),
        SevenzKey::Unknown,
        "a read that stopped before the checksum settles nothing"
    );
    assert_eq!(
        sevenz_password_check_capped(&z, Some("right"), 1_024),
        SevenzKey::Unknown
    );

    // And the shortlist puts what IS settled first, so the extraction
    // spends itself on the proven value before any indeterminate one.
    let list = dir.join("pw.txt");
    std::fs::write(&list, "wrong\nright\n").unwrap();
    crate::smart::set_operator_password_file(Some(list));
    let cands = sevenz_password_candidates(&z, &dir, None);
    assert_eq!(
        cands.first().and_then(|(v, _)| v.clone()).as_deref(),
        Some("right")
    );

    crate::smart::set_operator_password_file(None);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Codex sweep 13 Aug U1+U2: two encrypted NAMED RAR groups need not
/// share a password, and a harvested value must never shadow the one
/// the caller supplied.
///
/// The level resolver probed only the FIRST encrypted RAR (a.rar), and
/// its harvested answer replaced the job password for the whole level -
/// so b.rar, a RAR4 set whose check-less header can only be opened by
/// the password the user actually gave, was tried with a.rar's value,
/// failed as "wrong password", and stayed packed while the run
/// reported success. Per-group resolution keeps the caller's password
/// leading each group's candidate order.
#[test]
fn each_encrypted_rar_group_resolves_its_own_password() {
    let fixtures = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../vendor/rars/tests/fixtures");
    let dir = std::env::temp_dir().join(format!("nzbfast-pwrar-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // a.rar: RAR5, password "testpass", carries a check value so the
    // harvest can prove its candidate. b.rar: RAR4, password "junrar",
    // check-less - ONLY the caller's password can open it.
    std::fs::copy(
        fixtures.join("rar50/encrypted_solid.rar"),
        dir.join("a.rar"),
    )
    .unwrap();
    std::fs::copy(
        fixtures.join("rar15_40/encrypted/rar4_junrar_password.rar"),
        dir.join("b.rar"),
    )
    .unwrap();
    let list = dir.join("pw.txt");
    std::fs::write(&list, "testpass\n").unwrap();
    crate::smart::set_operator_password_file(Some(list));

    let out = extract_one_level(&dir, Some("junrar"), 0).unwrap();
    assert_eq!(out, Some(NestOutcome::Produced), "both groups must unpack");
    assert_eq!(
        std::fs::read(dir.join("file1.txt")).unwrap(),
        b"file1\n",
        "the RAR4 group must be opened with the CALLER's password, \
         not the harvested one"
    );

    crate::smart::set_operator_password_file(None);
    let _ = std::fs::remove_dir_all(&dir);
}

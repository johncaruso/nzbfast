//! Tests for the encrypted-stream extraction path, moved out of crypto.rs
//! bodily (TODO 106).
//!
//! Attached with `#[path]` from crypto.rs so `super::*` still names the
//! crypto module's private internals - the same shape serve/ uses for its
//! `*_tests.rs` siblings.

use super::*;
use crate::rar::fixtures;

use crate::extract::testutil::*;

#[test]
fn encrypted_single_volume_decrypts_in_stream() {
    let dir = tmpdir("enc-single");
    // Non-16-aligned length exercises the end-padding truncate.
    let plain = payload(200_003, 41);
    let f = fixtures::encrypt_file("hunter2", &plain, 5);
    let vol =
        fixtures::rar5_volume_enc(&[("movie.mkv", &f, 0..f.cipher.len(), false, false)], None);
    let ex = Extractor::new(&dir, 1, true);
    ex.set_password("hunter2");
    feed(&ex, 0, "v.rar", &vol, 7000, 3);
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(rep.decrypted, vec!["movie.mkv".to_string()]);
    assert_eq!(rep.extracted, vec![("movie.mkv".to_string(), 200_003)]);
    let out = std::fs::read(dir.join("movie.mkv")).unwrap();
    assert_eq!(out.len(), plain.len(), "padding must be truncated");
    assert_eq!(out, plain);
    assert!(!dir.join("v.rar").exists(), "one-pass: no volume on disk");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Finding 8: an encrypted RAR5 STORE entry with a plain (non-tweaked)
/// stored CRC must have its DECRYPTED plaintext verified. The password
/// check proves the key, not that every ciphertext block survived the
/// wire, so damaged ciphertext (the outer PAR2 vouches for the archive
/// as-posted) would otherwise decrypt to corrupt plaintext and report
/// success. With the CRC present, pristine ciphertext succeeds and a
/// single flipped ciphertext byte fails the extraction loudly.
#[test]
fn encrypted_store_verifies_plaintext_crc() {
    let plain = payload(200_003, 47);
    // Pristine: with_crc set, tweaked clear -> plaintext CRC is checked
    // and matches, so extraction succeeds.
    let mut f = fixtures::encrypt_file("hunter2", &plain, 6);
    f.with_crc = true;
    f.tweaked = false;
    let dir = tmpdir("enc-crc-ok");
    let vol =
        fixtures::rar5_volume_enc(&[("movie.mkv", &f, 0..f.cipher.len(), false, false)], None);
    let ex = Extractor::new(&dir, 1, true);
    ex.set_password("hunter2");
    feed(&ex, 0, "v.rar", &vol, 7000, 7);
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(std::fs::read(dir.join("movie.mkv")).unwrap(), plain);
    std::fs::remove_dir_all(&dir).unwrap();

    // Damaged ciphertext, correct password: decryption yields corrupt
    // plaintext whose CRC no longer matches -> hard failure, no clean
    // output. (Before finding 8's fix this returned Ok with corrupt
    // movie.mkv.)
    let mut fbad = fixtures::encrypt_file("hunter2", &plain, 6);
    fbad.with_crc = true;
    fbad.tweaked = false;
    fbad.cipher[80_000] ^= 0x5A;
    let dir = tmpdir("enc-crc-bad");
    let vol = fixtures::rar5_volume_enc(
        &[("movie.mkv", &fbad, 0..fbad.cipher.len(), false, false)],
        None,
    );
    let ex = Extractor::new(&dir, 1, true);
    ex.set_password("hunter2");
    feed(&ex, 0, "v.rar", &vol, 7000, 8);
    let res = ex.finish();
    assert!(res.is_err(), "damaged encrypted plaintext must not succeed");
    let out = dir.join("movie.mkv");
    assert!(
        !out.exists() || std::fs::read(&out).unwrap() != plain,
        "corrupt plaintext must not masquerade as the clean file"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Increment B: a TWEAKED-checksum entry stores the keyed fold of the
/// plaintext CRC32, which used to make it un-verifiable - `expect_crc`
/// was filtered to None and the decrypted output shipped with no
/// integrity check at all. The gate now folds the computed CRC the
/// same way before comparing, so a tweaked entry gets exactly the
/// protection an untweaked one has: clean bytes verify, damaged
/// ciphertext fails hard instead of masquerading as output.
#[test]
fn tweaked_checksum_entry_is_verified_through_the_keyed_fold() {
    let plain = payload(140_003, 44);

    // Clean, tweaked: must extract byte-exact.
    let mut f = fixtures::encrypt_file("hunter2", &plain, 21);
    f.with_crc = true;
    f.tweaked = true;
    let dir = tmpdir("enc-tweaked-ok");
    let vol =
        fixtures::rar5_volume_enc(&[("movie.mkv", &f, 0..f.cipher.len(), false, false)], None);
    let ex = Extractor::new(&dir, 1, true);
    ex.set_password("hunter2");
    feed(&ex, 0, "v.rar", &vol, 7000, 21);
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(std::fs::read(dir.join("movie.mkv")).unwrap(), plain);
    std::fs::remove_dir_all(&dir).unwrap();

    // Damaged ciphertext under the same tweaked entry: the folded
    // comparison must catch it. Before this gate the mismatch was
    // invisible and the corrupt file shipped as success.
    let mut fbad = fixtures::encrypt_file("hunter2", &plain, 22);
    fbad.with_crc = true;
    fbad.tweaked = true;
    fbad.cipher[70_000] ^= 0x5A;
    let dir = tmpdir("enc-tweaked-bad");
    let vol = fixtures::rar5_volume_enc(
        &[("movie.mkv", &fbad, 0..fbad.cipher.len(), false, false)],
        None,
    );
    let ex = Extractor::new(&dir, 1, true);
    ex.set_password("hunter2");
    feed(&ex, 0, "v.rar", &vol, 7000, 22);
    let res = ex.finish();
    assert!(res.is_err(), "damaged tweaked plaintext must not succeed");
    let out = dir.join("movie.mkv");
    assert!(
        !out.exists() || std::fs::read(&out).unwrap() != plain,
        "corrupt plaintext must not masquerade as the clean file"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Increment B2: a CHECK-LESS encrypted RAR5 store set - the crypt
/// record carries no password check, so nothing can verify the
/// password before data is decrypted - used to demote to disk on
/// sight. It now maps one-pass and is adjudicated at finish against
/// the whole-file checksum, which lives on the set's LAST piece (the
/// head's value describes only its own volume). Split across three
/// volumes so the tail lookup is what makes it work.
#[test]
fn checkless_encrypted_store_set_maps_and_verifies_at_finish() {
    let plain = payload(300_007, 51);
    let mut f = fixtures::encrypt_file("n0check", &plain, 31);
    f.with_crc = true;
    f.no_check = true;
    let n = f.cipher.len();
    let (a, b) = (100_016, 200_016);
    let vols = [
        fixtures::rar5_volume_enc(&[("movie.mkv", &f, 0..a, false, true)], Some(0)),
        fixtures::rar5_volume_enc(&[("movie.mkv", &f, a..b, true, true)], Some(1)),
        fixtures::rar5_volume_enc(&[("movie.mkv", &f, b..n, true, false)], Some(2)),
    ];
    let dir = tmpdir("enc-checkless-ok");
    let ex = Extractor::new(&dir, 3, true);
    ex.set_password("n0check");
    for (i, v) in vols.iter().enumerate() {
        feed(&ex, i, &format!("v{i}.rar"), v, 7000, 31 + i as u64);
    }
    let rep = ex.finish().unwrap();
    assert!(
        rep.fallbacks.is_empty(),
        "must not demote: {:?}",
        rep.fallbacks
    );
    assert_eq!(std::fs::read(dir.join("movie.mkv")).unwrap(), plain);
    for i in 0..vols.len() {
        assert!(
            !dir.join(format!("v{i}.rar")).exists(),
            "volume {i} must not touch disk (one-pass)"
        );
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The other half of B2's contract: the SAME check-less set with the
/// WRONG password must not publish garbage. Nothing could veto the
/// password up front, so the whole-file checksum is the verdict - it
/// misses, and the group demotes (volumes materialize byte-exact for
/// the disk path, which validates the password itself) instead of
/// either shipping noise or failing the whole download.
#[test]
fn checkless_encrypted_store_set_wrong_password_demotes_not_publishes() {
    let plain = payload(300_007, 52);
    let mut f = fixtures::encrypt_file("rightpw", &plain, 33);
    f.with_crc = true;
    f.no_check = true;
    let n = f.cipher.len();
    let vols = [
        fixtures::rar5_volume_enc(&[("movie.mkv", &f, 0..n / 2, false, true)], Some(0)),
        fixtures::rar5_volume_enc(&[("movie.mkv", &f, n / 2..n, true, false)], Some(1)),
    ];
    let dir = tmpdir("enc-checkless-wrongpw");
    let ex = Extractor::new(&dir, 2, true);
    ex.set_password("wrongpw");
    for (i, v) in vols.iter().enumerate() {
        feed(&ex, i, &format!("v{i}.rar"), v, 7000, 41 + i as u64);
    }
    let rep = ex.finish().expect("a wrong password must not fail the job");
    assert!(!rep.fallbacks.is_empty(), "the group must demote");
    let out = dir.join("movie.mkv");
    assert!(
        !out.exists() || std::fs::read(&out).unwrap() != plain,
        "wrong-password output must never masquerade as the payload"
    );
    // The volumes are the deliverable now, and must be byte-exact -
    // this is the property that assembling CIPHERTEXT (rather than
    // decrypting in place) buys.
    for (i, v) in vols.iter().enumerate() {
        let got = std::fs::read(dir.join(format!("v{i}.rar")))
            .unwrap_or_else(|e| panic!("volume {i} must materialize: {e}"));
        assert!(got == *v, "volume {i} must materialize byte-exact");
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

/// `rar a -htb` writes a BLAKE2sp digest INSTEAD of a CRC32, and nzbkit
/// has no BLAKE2sp of its own - so nothing in the one-pass path can
/// adjudicate such an output. `instream_decrypt_allowed` diverts the
/// shape away from write-time decryption explicitly so the disk path
/// (where rars checks the keyed digest) takes it, but nothing demoted
/// it: the finish pass built a job with `expect_crc = None`, the RAR5
/// password check set `verified = true`, and the demotion filter let it
/// through. Result: plaintext published with no integrity verdict at
/// all, on an archive whose ciphertext may have been damaged before the
/// yEnc/PAR2 pass ever saw it (Codex sweep 12 Aug F2).
///
/// A CORRECT password, deliberately: the point is that a verified key is
/// not a verified payload.
///
/// Both split shapes, and in both feed orders. The SPLIT case is the one
/// that mattered most and the one the report missed: only the tail
/// fragment carries the whole-file checks, so the write-time veto reads
/// `hash: None, file_crc: None` off the head, answers "allowed", and
/// latches the plaintext-once route for the whole file - which made
/// whether anything was checked depend on which volume arrived first.
#[test]
fn a_hash_only_encrypted_set_demotes_rather_than_publishing_unchecked() {
    let plain = payload(300_007, 53);
    let mut f = fixtures::encrypt_file("hunter2", &plain, 37);
    // The shape: a digest, and NO CRC32.
    f.with_hash = true;
    f.with_crc = false;
    let n = f.cipher.len();
    let unsplit = vec![fixtures::rar5_volume_enc(
        &[("movie.mkv", &f, 0..n, false, false)],
        None,
    )];
    let split = vec![
        fixtures::rar5_volume_enc(&[("movie.mkv", &f, 0..150_016, false, true)], Some(0)),
        fixtures::rar5_volume_enc(&[("movie.mkv", &f, 150_016..n, true, false)], Some(1)),
    ];
    for (label, vols, tail_first) in [
        ("unsplit", unsplit, false),
        ("split-head-first", split.clone(), false),
        ("split-tail-first", split, true),
    ] {
        let dir = tmpdir(&format!("enc-hash-only-{label}"));
        let ex = Extractor::new(&dir, vols.len(), true);
        ex.set_password("hunter2");
        let order: Vec<usize> = if tail_first {
            (0..vols.len()).rev().collect()
        } else {
            (0..vols.len()).collect()
        };
        for i in order {
            feed(&ex, i, &format!("v{i}.rar"), &vols[i], 7000, 51 + i as u64);
        }
        let rep = ex.finish().unwrap();
        assert!(
            !rep.fallbacks.is_empty(),
            "{label}: a set nothing here can check must demote to the verifying disk path"
        );
        assert!(
            rep.decrypted.is_empty(),
            "{label}: nothing may be reported as decrypted: {:?}",
            rep.decrypted
        );
        assert!(
            !dir.join("movie.mkv").exists(),
            "{label}: no unverified plaintext may be published"
        );
        // And the volumes are byte-exact, so the disk path gets the
        // posted bytes to verify the digest against.
        for (i, v) in vols.iter().enumerate() {
            let got = std::fs::read(dir.join(format!("v{i}.rar")))
                .unwrap_or_else(|e| panic!("{label}: volume {i} must materialize: {e}"));
            assert!(got == *v, "{label}: volume {i} must materialize byte-exact");
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

/// The twin: a digest AND a CRC32 is fully adjudicable here, so it must
/// still take the one-pass route. Without this the fix above would be
/// indistinguishable from "demote anything with a hash record".
#[test]
fn a_hash_plus_crc_encrypted_set_still_maps_one_pass() {
    let plain = payload(300_007, 54);
    let mut f = fixtures::encrypt_file("hunter2", &plain, 39);
    f.with_hash = true;
    f.with_crc = true;
    let vol =
        fixtures::rar5_volume_enc(&[("movie.mkv", &f, 0..f.cipher.len(), false, false)], None);
    let dir = tmpdir("enc-hash-and-crc");
    let ex = Extractor::new(&dir, 1, true);
    ex.set_password("hunter2");
    feed(&ex, 0, "v.rar", &vol, 7000, 61);
    let rep = ex.finish().unwrap();
    assert!(
        rep.fallbacks.is_empty(),
        "must not demote: {:?}",
        rep.fallbacks
    );
    assert_eq!(std::fs::read(dir.join("movie.mkv")).unwrap(), plain);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The decrypt pass shards a file across threads, seeding each shard's
/// CBC chain from the ciphertext block before it and folding the shard
/// CRCs back with `crc32_combine`. Every shard count must therefore
/// produce byte-identical plaintext and an identical CRC to the serial
/// pass - including when `unp` is not 16-aligned, so the tail shard
/// carries padding that must stay out of the CRC.
#[test]
fn decrypt_shards_match_the_serial_pass() {
    // Over DECRYPT_PARALLEL_MIN so the sharded path actually engages,
    // and deliberately not a multiple of 16 or of the shard size.
    let plain = payload((36 << 20) + 7, 91);
    let key = rarcrypt::AesKey::Aes256([0x3Cu8; 32]);
    let iv = [0x5Au8; 16];
    let mut cipher = plain.clone();
    cipher.resize(rarcrypt::align16(plain.len() as u64) as usize, 0);
    rarcrypt::CbcEncStream::new(&key, &iv).encrypt(&mut cipher);

    let dir = tmpdir("decrypt-shards");
    let src = dir.join("cipher.bin");
    std::fs::write(&src, &cipher).unwrap();
    let expect_crc = crc32fast::hash(&plain);

    for threads in [1usize, 2, 3, 5, 8, 64] {
        let out = dir.join(format!("plain-{threads}.bin"));
        let wf = File::options()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(&out)
            .unwrap();
        decrypt_pass(
            &src,
            &wf,
            &key,
            &iv,
            plain.len() as u64,
            Some(CrcGate {
                stored: expect_crc,
                hash_key: None,
            }),
            threads,
        )
        .unwrap_or_else(|e| panic!("{threads} shards: {e}"));
        drop(wf);
        assert_eq!(
            std::fs::read(&out).unwrap(),
            plain,
            "{threads} shards produced different plaintext"
        );
    }

    // A wrong stored CRC must still be caught on the sharded path: the
    // combine has to reproduce the real whole-file CRC, not just agree
    // with itself.
    let out = dir.join("bad.bin");
    let wf = File::options()
        .create(true)
        .truncate(true)
        .read(true)
        .write(true)
        .open(&out)
        .unwrap();
    let err = decrypt_pass(
        &src,
        &wf,
        &key,
        &iv,
        plain.len() as u64,
        Some(CrcGate {
            stored: expect_crc ^ 1,
            hash_key: None,
        }),
        8,
    );
    assert!(err.is_err(), "sharded pass must still enforce the CRC");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Shard scaling of the finish decrypt, for the low-end story. Run it
/// with `--ignored --nocapture`, and with `--cfg aes_force_soft` to see
/// the no-AES-hardware case (some budget ARM NAS SoCs omit the crypto
/// extensions, and the RAR format leaves no cipher to fall back to).
#[test]
#[ignore = "timing bench, not a correctness gate"]
fn decrypt_shard_scaling_bench() {
    let plain = payload(256 << 20, 13);
    let key = rarcrypt::AesKey::Aes256([0x11u8; 32]);
    let iv = [0x22u8; 16];
    let mut cipher = plain.clone();
    rarcrypt::CbcEncStream::new(&key, &iv).encrypt(&mut cipher);
    let dir = tmpdir("decrypt-bench");
    let src = dir.join("cipher.bin");
    std::fs::write(&src, &cipher).unwrap();
    let crc = crc32fast::hash(&plain);
    println!("256 MiB encrypted store file");
    for threads in [1usize, 2, 4, 8] {
        let out = dir.join("plain.bin");
        let wf = File::options()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(&out)
            .unwrap();
        let t = std::time::Instant::now();
        decrypt_pass(
            &src,
            &wf,
            &key,
            &iv,
            plain.len() as u64,
            Some(CrcGate {
                stored: crc,
                hash_key: None,
            }),
            threads,
        )
        .unwrap();
        let el = t.elapsed().as_secs_f64();
        println!(
            "  {threads} shard(s): {el:6.3}s  {:7.1} MB/s",
            (plain.len() as f64 / 1e6) / el
        );
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Finding A8. The finish decrypt replaces an encrypted store output
/// with its plaintext, and that output is exactly what the
/// crash-resume journal's placement records point into. Rewriting it
/// IN PLACE meant a kill mid-pass left the file half plaintext and
/// half ciphertext while the journal still vouched for it - the resume
/// run then copied those poisoned bytes into the volume files and
/// marked the message ids restored, so they were skipped instead of
/// refetched and, without PAR2, the retry could never converge.
///
/// The guarantee is about ORDERING, so that is what is asserted here:
/// the publish barrier fires once per output, and at that moment the
/// output on disk is still byte-exact ciphertext. Every earlier
/// instant therefore looks identical to a killed process, and the
/// publish itself is a rename - so no kill can ever observe a mix.
#[test]
fn decrypt_publishes_only_after_the_journal_barrier_clears() {
    let dir = tmpdir("enc-barrier");
    let plain = payload(200_003, 51);
    let f = fixtures::encrypt_file("hunter2", &plain, 5);
    let cipher = f.cipher.clone();
    let vol =
        fixtures::rar5_volume_enc(&[("movie.mkv", &f, 0..f.cipher.len(), false, false)], None);
    let ex = Extractor::new(&dir, 1, true);
    ex.set_password("hunter2");
    // This test guards the LEGACY ciphertext+finish-decrypt path
    // (still shipped behind NZBFAST_NO_INSTREAM_DECRYPT).
    ex.set_instream_decrypt(false);
    // The name the old code derived deterministically for its temp. An
    // archive is free to ship a member called this (finding A13), so
    // the pass must not go anywhere near it.
    let decoy = dir.join("movie.mkv.nzbdec.tmp");
    std::fs::write(&decoy, b"a legitimate archive member").unwrap();

    let calls: Arc<Mutex<Vec<Vec<String>>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_at_barrier: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
    {
        let (calls, seen, out) = (
            calls.clone(),
            seen_at_barrier.clone(),
            dir.join("movie.mkv"),
        );
        ex.set_decrypt_barrier(Arc::new(move |names: &[String]| {
            calls.lock().unwrap().push(names.to_vec());
            *seen.lock().unwrap() = std::fs::read(&out).unwrap();
            Ok(())
        }));
    }
    feed(&ex, 0, "v.rar", &vol, 7000, 3);
    let rep = ex.finish().unwrap();

    assert_eq!(rep.decrypted, vec!["movie.mkv".to_string()]);
    assert_eq!(
        *calls.lock().unwrap(),
        vec![vec!["movie.mkv".to_string()]],
        "the journal's claim must be retired for exactly the published output"
    );
    let at_barrier = seen_at_barrier.lock().unwrap().clone();
    assert_eq!(
        &at_barrier[..cipher.len()],
        &cipher[..],
        "the output was mutated before the journal stopped vouching for it"
    );
    assert_eq!(std::fs::read(dir.join("movie.mkv")).unwrap(), plain);
    assert_eq!(
        std::fs::read(&decoy).unwrap(),
        b"a legitimate archive member",
        "an archive member must never be mistaken for decrypt scratch"
    );
    assert!(
        leftover_scratch(&dir).is_empty(),
        "decrypt scratch left behind: {:?}",
        leftover_scratch(&dir)
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Finding A8, the other half: when the journal's claim CANNOT be
/// retired, nothing may be published. The job fails, and the output is
/// left byte-exact ciphertext - which is what makes a crash here
/// recoverable, because the journal is still telling the truth and the
/// resume run rebuilds the volumes from local bytes with no refetch.
#[test]
fn decrypt_publishes_nothing_when_the_barrier_refuses() {
    let dir = tmpdir("enc-barrier-fail");
    let plain = payload(200_003, 52);
    let f = fixtures::encrypt_file("hunter2", &plain, 5);
    let cipher = f.cipher.clone();
    let vol =
        fixtures::rar5_volume_enc(&[("movie.mkv", &f, 0..f.cipher.len(), false, false)], None);
    let ex = Extractor::new(&dir, 1, true);
    ex.set_password("hunter2");
    // This test guards the LEGACY ciphertext+finish-decrypt path
    // (still shipped behind NZBFAST_NO_INSTREAM_DECRYPT).
    ex.set_instream_decrypt(false);
    ex.set_decrypt_barrier(Arc::new(|_: &[String]| {
        Err(io::Error::other("journal is not writable"))
    }));
    feed(&ex, 0, "v.rar", &vol, 7000, 3);

    let err = match ex.finish() {
        Err(e) => e,
        Ok(_) => panic!("publish went ahead without the journal's permission"),
    };
    assert!(err.to_string().contains("journal is not writable"), "{err}");
    let on_disk = std::fs::read(dir.join("movie.mkv")).unwrap();
    assert_eq!(
        &on_disk[..cipher.len()],
        &cipher[..],
        "ciphertext must survive byte-exact so the journal stays true"
    );
    assert!(
        !on_disk.starts_with(&plain[..1024]),
        "plaintext was published without permission"
    );
    assert!(
        leftover_scratch(&dir).is_empty(),
        "decrypt scratch left behind: {:?}",
        leftover_scratch(&dir)
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Decrypt scratch from a killed run is swept, and a failed pass
/// leaves none of its own - a stale temp must never reach the user's
/// output directory or the keep-media-only sweep.
#[test]
fn stale_decrypt_scratch_is_swept() {
    let dir = tmpdir("enc-scratch");
    let stale = dir.join(format!("{DEC_TMP_PREFIX}999999.7.tmp"));
    std::fs::write(&stale, b"corpse of a killed run").unwrap();
    let plain = payload(70_001, 53);
    let f = fixtures::encrypt_file("pw", &plain, 9);
    let vol = fixtures::rar5_volume_enc(&[("a.bin", &f, 0..f.cipher.len(), false, false)], None);
    let ex = Extractor::new(&dir, 1, true);
    ex.set_password("pw");
    feed(&ex, 0, "v.rar", &vol, 7000, 4);
    ex.finish().unwrap();
    assert!(!stale.exists(), "stale decrypt scratch survived the pass");
    assert!(leftover_scratch(&dir).is_empty());
    assert_eq!(std::fs::read(dir.join("a.bin")).unwrap(), plain);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The aliasing hazard with the decoy arriving the way it actually
/// does in the wild: as a genuine member of the same download,
/// written by this very extraction rather than planted beforehand.
/// The old deterministic `<output>.nzbdec.tmp` name truncated it and
/// then renamed it away, so a real file silently became the decrypt
/// scratch. Ported from the parallel isolated-staging fix, whose
/// scratch-subdirectory approach this file solves with `create_new`.
#[test]
fn decrypt_temp_cannot_alias_an_extracted_member() {
    let dir = tmpdir("enc-temp-alias");
    let plain = payload(180_000, 73);
    let f = fixtures::encrypt_file("pw", &plain, 3);
    let enc =
        fixtures::rar5_volume_enc(&[("movie.mkv", &f, 0..f.cipher.len(), false, false)], None);
    // A second, ordinary volume whose member is named exactly like the
    // temp the old code would have derived for movie.mkv.
    let decoy = payload(9_000, 74);
    let bait = fixtures::rar5_volume(&[(
        "movie.mkv.nzbdec.tmp",
        decoy.len() as u64,
        &decoy,
        false,
        false,
    )]);
    let ex = Extractor::new(&dir, 2, true);
    ex.set_password("pw");
    feed(&ex, 0, "a.rar", &enc, 7000, 4);
    feed(&ex, 1, "b.rar", &bait, 3000, 5);
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(rep.decrypted, vec!["movie.mkv".to_string()]);
    assert_eq!(std::fs::read(dir.join("movie.mkv")).unwrap(), plain);
    assert_eq!(
        std::fs::read(dir.join("movie.mkv.nzbdec.tmp")).unwrap(),
        decoy,
        "the decrypt temp overwrote a legitimate member of the same name"
    );
    assert!(leftover_scratch(&dir).is_empty());
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The real multi-volume shape: ONE CBC stream carved at arbitrary
/// (non-16-aligned) offsets, same crypt record in every volume, fed
/// interleaved and out of order.
#[test]
fn encrypted_split_volumes_decrypt() {
    let dir = tmpdir("enc-split");
    let plain = payload(500_007, 42);
    let f = fixtures::encrypt_file("s3cret", &plain, 11);
    let n = f.cipher.len();
    let (a, b) = (170_003, 340_006); // deliberately odd split points
    let vols = [
        fixtures::rar5_volume_enc(&[("film.mkv", &f, 0..a, false, true)], Some(0)),
        fixtures::rar5_volume_enc(&[("film.mkv", &f, a..b, true, true)], Some(1)),
        fixtures::rar5_volume_enc(&[("film.mkv", &f, b..n, true, false)], Some(2)),
    ];
    let ex = Extractor::new(&dir, 3, true);
    ex.set_password("s3cret");
    feed(&ex, 2, "x.part3.rar", &vols[2], 9000, 11);
    feed(&ex, 0, "x.part1.rar", &vols[0], 9000, 12);
    feed(&ex, 1, "x.part2.rar", &vols[1], 9000, 13);
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(rep.decrypted, vec!["film.mkv".to_string()]);
    assert_eq!(std::fs::read(dir.join("film.mkv")).unwrap(), plain);
    assert!(!dir.join("x.part1.rar").exists());
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Plaintext-once equivalence: the in-stream decrypt path and the
/// legacy ciphertext+finish-decrypt path must produce byte-identical
/// output for every arrival order and article size - including
/// pathological articles smaller than two cipher blocks, where every
/// span is nothing BUT seams.
#[test]
fn instream_decrypt_matches_legacy_across_orders_and_sizes() {
    let plain = payload(120_003, 77);
    let mut f = fixtures::encrypt_file("hunter2", &plain, 21);
    f.with_crc = true; // engage the composed-CRC verify too
    f.tweaked = false;
    let vol =
        fixtures::rar5_volume_enc(&[("movie.mkv", &f, 0..f.cipher.len(), false, false)], None);
    for art in [17usize, 33, 4096, 7000] {
        for seed in [1u64, 2, 3] {
            let mut outs: Vec<Vec<u8>> = Vec::new();
            for instream in [true, false] {
                let dir = tmpdir(&format!("eqv-{art}-{seed}-{instream}"));
                let ex = Extractor::new(&dir, 1, true);
                ex.set_password("hunter2");
                ex.set_instream_decrypt(instream);
                feed(&ex, 0, "v.rar", &vol, art, seed);
                let rep = ex.finish().unwrap();
                assert!(
                    rep.fallbacks.is_empty(),
                    "art={art} seed={seed}: {:?}",
                    rep.fallbacks
                );
                assert_eq!(rep.decrypted, vec!["movie.mkv".to_string()]);
                outs.push(std::fs::read(dir.join("movie.mkv")).unwrap());
                assert!(!dir.join("v.rar").exists(), "no volume on disk either way");
                std::fs::remove_dir_all(&dir).unwrap();
            }
            assert_eq!(
                outs[0], plain,
                "in-stream output wrong at art={art} seed={seed}"
            );
            assert_eq!(outs[0], outs[1], "paths diverge at art={art} seed={seed}");
        }
    }
}

/// Split encrypted file, in-stream: one CBC stream across three
/// volumes, volumes fed out of order, seams crossing volume
/// boundaries.
#[test]
fn instream_split_volumes_decrypt() {
    let dir = tmpdir("instream-split");
    let plain = payload(500_007, 42);
    let f = fixtures::encrypt_file("s3cret", &plain, 11);
    let n = f.cipher.len();
    let (a, b) = (170_003, 340_006);
    let vols = [
        fixtures::rar5_volume_enc(&[("film.mkv", &f, 0..a, false, true)], Some(0)),
        fixtures::rar5_volume_enc(&[("film.mkv", &f, a..b, true, true)], Some(1)),
        fixtures::rar5_volume_enc(&[("film.mkv", &f, b..n, true, false)], Some(2)),
    ];
    let ex = Extractor::new(&dir, 3, true);
    ex.set_password("s3cret");
    ex.set_instream_decrypt(true);
    feed(&ex, 2, "x.part3.rar", &vols[2], 4099, 31);
    feed(&ex, 0, "x.part1.rar", &vols[0], 4099, 32);
    feed(&ex, 1, "x.part2.rar", &vols[1], 4099, 33);
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(rep.decrypted, vec!["film.mkv".to_string()]);
    assert_eq!(std::fs::read(dir.join("film.mkv")).unwrap(), plain);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The posted-bytes shim: after an in-stream decrypt, read_at over
/// the whole volume view must reproduce the POSTED volume
/// byte-exactly - headers from the stash, data areas re-encrypted
/// from the plaintext on disk, seam/tail slivers from retained
/// cipher. This is what PAR2 settle read-back, mapped repair and
/// fallback all consume.
#[test]
fn instream_read_at_reproduces_posted_volume_bytes() {
    let dir = tmpdir("instream-shim");
    // Big enough to cross a checkpoint stride with the small chunk.
    let plain = payload(300_005, 55);
    let f = fixtures::encrypt_file("pw", &plain, 9);
    let vol =
        fixtures::rar5_volume_enc(&[("movie.mkv", &f, 0..f.cipher.len(), false, false)], None);
    let ex = Extractor::new(&dir, 1, true);
    ex.set_password("pw");
    ex.set_instream_decrypt(true);
    feed(&ex, 0, "v.rar", &vol, 7001, 5);
    // Whole-volume round trip.
    let mut got = vec![0u8; vol.len()];
    ex.read_at(0, 0, &mut got).unwrap();
    assert_eq!(got, vol, "shim must reproduce the posted volume");
    // Unaligned interior windows, crossing data-area edges.
    for (off, len) in [(1u64, 31usize), (999, 4097), (150_001, 50_003)] {
        let mut w = vec![0u8; len];
        ex.read_at(0, off, &mut w).unwrap();
        assert_eq!(
            w,
            vol[off as usize..off as usize + len],
            "window {off}+{len}"
        );
    }
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(std::fs::read(dir.join("movie.mkv")).unwrap(), plain);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A file spanning several checkpoint strides: the shim must chain
/// from the nearest checkpoint (not the file head), deep windows
/// must reproduce posted bytes, and a repair landing past the first
/// stride must refresh the checkpoints it crosses.
#[test]
fn instream_checkpoints_serve_deep_windows_and_repairs() {
    let dir = tmpdir("instream-ckpt");
    let plain = payload(3_500_003, 91);
    let mut f = fixtures::encrypt_file("hunter2", &plain, 66);
    f.with_crc = true;
    f.tweaked = false;
    let vol =
        fixtures::rar5_volume_enc(&[("movie.mkv", &f, 0..f.cipher.len(), false, false)], None);
    let mut damaged = vol.clone();
    for i in 2_500_000..2_500_048 {
        damaged[i] ^= 0xA7;
    }
    let ex = Extractor::new(&dir, 1, true);
    ex.set_password("hunter2");
    ex.set_instream_decrypt(true);
    feed(&ex, 0, "v.rar", &damaged, 65_536, 14);
    // Deep windows chain from checkpoints, not a multi-MB walk.
    for (off, len) in [(3_200_001u64, 8_192usize), (1_048_570, 64), (2_097_140, 40)] {
        let mut w = vec![0u8; len];
        ex.read_at(0, off, &mut w).unwrap();
        assert_eq!(w, damaged[off as usize..off as usize + len], "window {off}");
    }
    // Repair the damage (crosses nothing aligned on purpose).
    ex.patch_volume_span(0, 2_499_997, &vol[2_499_997..2_500_051])
        .unwrap();
    let mut got = vec![0u8; vol.len()];
    ex.read_at(0, 0, &mut got).unwrap();
    assert_eq!(got, vol, "healed volume view across strides");
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(std::fs::read(dir.join("movie.mkv")).unwrap(), plain);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Mapped repair on a plaintext-once file: damaged cipher decrypts
/// to garbage plaintext locally, the patch rewrites the repaired
/// blocks AND the CBC-adjacent following block, and the stored-CRC
/// gate passes on the healed plaintext.
#[test]
fn instream_patch_heals_damaged_cipher_and_adjacency() {
    let dir = tmpdir("instream-patch");
    let plain = payload(200_003, 61);
    let mut f = fixtures::encrypt_file("hunter2", &plain, 33);
    f.with_crc = true;
    f.tweaked = false;
    let vol =
        fixtures::rar5_volume_enc(&[("movie.mkv", &f, 0..f.cipher.len(), false, false)], None);
    // Damage a mid-data range of the POSTED bytes before feeding -
    // the wire delivered corrupt cipher, exactly what PAR2 repairs.
    let mut damaged = vol.clone();
    for i in 45_000..45_040 {
        damaged[i] ^= 0x5A;
    }
    let ex = Extractor::new(&dir, 1, true);
    ex.set_password("hunter2");
    ex.set_instream_decrypt(true);
    feed(&ex, 0, "v.rar", &damaged, 7000, 8);
    // Repair the damaged span with the true posted bytes (unaligned
    // edges on purpose - the patch window logic must round out).
    ex.patch_volume_span(0, 44_997, &vol[44_997..45_043])
        .unwrap();
    // The healed volume view must be the pristine posted bytes...
    let mut got = vec![0u8; vol.len()];
    ex.read_at(0, 0, &mut got).unwrap();
    assert_eq!(got, vol, "healed volume view");
    // ...and the plaintext (incl. the adjacency block) must verify.
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(std::fs::read(dir.join("movie.mkv")).unwrap(), plain);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// An incomplete in-stream set falls back to materialized volumes,
/// and every byte the fallback writes must be the POSTED byte (the
/// shim rebuilding cipher from plaintext), never plaintext leaking
/// into a volume file.
#[test]
fn instream_incomplete_set_materializes_posted_bytes() {
    let dir = tmpdir("instream-fallback");
    let plain = payload(200_003, 71);
    let f = fixtures::encrypt_file("hunter2", &plain, 44);
    let vol =
        fixtures::rar5_volume_enc(&[("movie.mkv", &f, 0..f.cipher.len(), false, false)], None);
    let ex = Extractor::new(&dir, 1, true);
    ex.set_password("hunter2");
    ex.set_instream_decrypt(true);
    // Feed everything except one mid-file article.
    let art = 7000usize;
    let skip = 91_000usize;
    let mut i = 0;
    while i < vol.len() {
        let e = (i + art).min(vol.len());
        if i != skip {
            ex.write(0, "v.rar", vol.len() as u64, i as u64, &vol[i..e])
                .unwrap();
        }
        i = e;
    }
    let rep = ex.finish().unwrap();
    assert!(!rep.fallbacks.is_empty(), "incomplete set must fall back");
    let disk = std::fs::read(dir.join("v.rar")).unwrap();
    // Every fed byte materialized must equal the posted byte.
    let mut i = 0;
    while i < vol.len().min(disk.len()) {
        let e = (i + art).min(vol.len()).min(disk.len());
        if i != skip {
            assert_eq!(
                &disk[i..e],
                &vol[i..e],
                "materialized volume must hold posted bytes at {i}"
            );
        }
        i = e;
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Plaintext-once bookkeeping: spans that fed an in-stream-decrypted
/// file are never journaled (a resume must refetch them - the disk
/// holds plaintext, not the posted bytes a restore would copy into
/// volume files), and /stream serves the output as a plain file.
#[test]
fn instream_spans_never_journal_and_stream_is_plain() {
    let dir = tmpdir("instream-journal");
    let plain = payload(150_001, 81);
    let f = fixtures::encrypt_file("hunter2", &plain, 55);
    let vol =
        fixtures::rar5_volume_enc(&[("movie.mkv", &f, 0..f.cipher.len(), false, false)], None);
    let ex = Extractor::new(&dir, 1, true);
    ex.set_password("hunter2");
    ex.set_instream_decrypt(true);
    let mut any_placed = false;
    let art = 7000usize;
    let mut i = 0;
    while i < vol.len() {
        let e = (i + art).min(vol.len());
        let p = ex
            .write(0, "v.rar", vol.len() as u64, i as u64, &vol[i..e])
            .unwrap();
        if let Persist::Placed(_) = p {
            any_placed = true;
        }
        i = e;
    }
    assert!(
        !any_placed,
        "no article of an in-stream-decrypted file may be journaled"
    );
    assert!(
        matches!(ex.open_stream("movie.mkv"), StreamOpen::Plain),
        "plaintext-once output streams as a plain file"
    );
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(std::fs::read(dir.join("movie.mkv")).unwrap(), plain);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Phase 2 of plaintext-once: a journaled run's D/E/K/T records let a
/// resume RE-ENCRYPT the on-disk plaintext back into posted volume
/// bytes. Simulates a kill (drop without finish), then restores and
/// compares every restored span byte-for-byte against the posted
/// volume - including the final article, whose last block needs the
/// journaled tail padding.
#[test]
fn instream_journal_restores_posted_bytes_for_resume() {
    let dir = tmpdir("instream-resume");
    let plain = payload(2_300_005, 87); // > 2 checkpoint strides
    let f = fixtures::encrypt_file("hunter2", &plain, 77);
    let vol =
        fixtures::rar5_volume_enc(&[("movie.mkv", &f, 0..f.cipher.len(), false, false)], None);
    let art = 50_000usize;
    let n_arts = vol.len().div_ceil(art);

    // Run 1: journal exactly like main.rs does, "crash" before the
    // last two articles and before finish.
    let (journal, _) = crate::journal::Journal::open(&dir, b"nzb-x").unwrap();
    let mut d_ids: Vec<String> = Vec::new();
    {
        let ex = Extractor::new(&dir, 1, true);
        ex.set_password("hunter2");
        ex.set_instream_decrypt(true);
        // Mirror main.rs: D records park until their span's seam
        // bytes are physically on disk (usually one article later).
        let mut pending: Vec<(String, Vec<Frag>)> = Vec::new();
        for i in 0..n_arts - 2 {
            let s = i * art;
            let e = (s + art).min(vol.len());
            let id = format!("<a{i}@t>");
            let p = ex
                .write(0, "v.rar", vol.len() as u64, s as u64, &vol[s..e])
                .unwrap();
            match p {
                Persist::PlacedCrypto(frags) => pending.push((id, frags)),
                Persist::Placed(_) => panic!("crypto span must journal as D, not R"),
                Persist::No | Persist::Held(_) => {}
            }
            pending.retain(|(id, frags)| {
                if ex.crypto_span_on_disk(frags) {
                    let ev = ex.drain_crypto_events();
                    journal.record_crypto_events(&ev);
                    journal.record_placed_crypto(
                        0,
                        id,
                        ex.slot_file_info(0),
                        "v.rar",
                        vol.len() as u64,
                        frags,
                        &ex.crypto_frag_mask(frags),
                    );
                    d_ids.push(id.clone());
                    false
                } else {
                    true
                }
            });
        }
        // Killed: dropped without finish. The frontier article's
        // seam never settled, so it must still be parked.
        assert!(!pending.is_empty(), "the frontier span must be unjournaled");
    }
    drop(journal);
    // The plaintext output must exist from run 1.
    assert!(dir.join("movie.mkv").exists());
    assert!(!d_ids.is_empty(), "run 1 recorded D articles");

    // Resume: parse + restore with the password.
    let (_j2, resume) = crate::journal::Journal::open(&dir, b"nzb-x").unwrap();
    assert!(
        resume.crypto_files.contains_key("movie.mkv"),
        "E record parsed"
    );
    let restored = crate::journal::restore(&dir, &resume, Some("hunter2"));
    // Every D article restores (its plaintext fully on disk - the
    // skipped articles' seams only affect themselves).
    for id in &d_ids {
        assert!(restored.ids.contains(id), "{id} must restore");
    }
    // And the rebuilt volume bytes are the POSTED bytes.
    let rebuilt = std::fs::read(dir.join("v.rar")).unwrap();
    for seed in &restored.seeds {
        for &(off, len) in &seed.spans {
            assert_eq!(
                &rebuilt[off as usize..(off + len) as usize],
                &vol[off as usize..(off + len) as usize],
                "restored span {off}+{len} must be posted bytes"
            );
        }
    }
    // No password: nothing restores, articles refetch.
    let none = crate::journal::restore(&dir, &resume, None);
    assert!(none.ids.is_empty(), "no password must mean no restores");
    // Wrong password: KDF succeeds but produces the wrong keystream;
    // the checkpoint cross-verify rejects the walk, so nothing is
    // restored (rather than poisoned volumes).
    let wrong = crate::journal::restore(&dir, &resume, Some("wrong"));
    assert!(
        wrong.ids.is_empty(),
        "wrong password must not restore: {:?}",
        wrong.ids.len()
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A D record without its E facts (torn journal tail, or a file
/// whose params line was lost) must refetch, never guess.
#[test]
fn journal_d_without_e_refetches() {
    let dir = tmpdir("d-without-e");
    std::fs::write(dir.join("movie.mkv"), payload(64_000, 3)).unwrap();
    let text = "nzbfast-journal v1 d41d8cd98f00b204e9800998ecf8427e\n\
                S 0 100000 v.rar\n\
                F 0 movie.mkv\n\
                D 0 0:0:5000:32768 <a1@t>\n";
    std::fs::write(dir.join(".nzbfast.journal"), text).unwrap();
    // Reparse through the real reader (fingerprint of b"" matches).
    let (_j, resume) = crate::journal::Journal::open(&dir, b"").unwrap();
    let restored = crate::journal::restore(&dir, &resume, Some("pw"));
    assert!(restored.ids.is_empty(), "D without E must refetch");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// `-hp` shape: encrypted headers AND encrypted data.
#[test]
fn encrypted_headers_volume_decrypts() {
    let dir = tmpdir("enc-hdrs");
    let plain = payload(150_001, 43);
    let f = fixtures::encrypt_file("pw", &plain, 21);
    let vol = fixtures::rar5_volume_enc_headers(
        &[("obf.bin", &f, 0..f.cipher.len(), false, false)],
        None,
        "pw",
        22,
    );
    let ex = Extractor::new(&dir, 1, true);
    ex.set_password("pw");
    feed(&ex, 0, "0abc123.rar", &vol, 6000, 9);
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(rep.decrypted, vec!["obf.bin".to_string()]);
    assert_eq!(std::fs::read(dir.join("obf.bin")).unwrap(), plain);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Wrong password: the check value rejects it BEFORE any garbage is
/// written; the volume materializes byte-identical (unrar / retry
/// with the right password still possible).
#[test]
fn encrypted_wrong_password_materializes_volume() {
    let dir = tmpdir("enc-wrongpw");
    let plain = payload(90_000, 44);
    let f = fixtures::encrypt_file("right", &plain, 31);
    let vol = fixtures::rar5_volume_enc(&[("a.bin", &f, 0..f.cipher.len(), false, false)], None);
    let ex = Extractor::new(&dir, 1, true);
    ex.set_password("wrong");
    feed(&ex, 0, "v.rar", &vol, 7000, 5);
    let rep = ex.finish().unwrap();
    assert!(
        rep.fallbacks.iter().any(|(_, w)| w.contains("password")),
        "{:?}",
        rep.fallbacks
    );
    assert!(rep.decrypted.is_empty());
    assert_eq!(
        std::fs::read(dir.join("v.rar")).unwrap(),
        vol,
        "byte-exact volume"
    );
    assert!(!dir.join("a.bin").exists(), "no half-written decoy output");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// No password at all: today's behavior - volumes on disk, reason
/// names encryption.
#[test]
fn encrypted_without_password_materializes_volume() {
    let dir = tmpdir("enc-nopw");
    let plain = payload(60_000, 45);
    let f = fixtures::encrypt_file("x", &plain, 33);
    let vol = fixtures::rar5_volume_enc(&[("a.bin", &f, 0..f.cipher.len(), false, false)], None);
    let ex = Extractor::new(&dir, 1, true);
    feed(&ex, 0, "v.rar", &vol, 7000, 6);
    let rep = ex.finish().unwrap();
    assert!(
        rep.fallbacks.iter().any(|(_, w)| w.contains("encrypted")),
        "{:?}",
        rep.fallbacks
    );
    assert_eq!(std::fs::read(dir.join("v.rar")).unwrap(), vol);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The committed REAL `rar 7.23` fixtures, driven through the full
/// extractor: single encrypted volume, encrypted headers, and the
/// 3-volume split - each must produce the exact payload with no
/// volume files left behind.
#[test]
fn real_rar_fixtures_extract_and_decrypt() {
    let secret = include_bytes!("../../testdata/rar5/secret.bin").to_vec();
    let cases: Vec<(&str, Vec<(&str, &[u8])>)> = vec![
        (
            "store",
            vec![(
                "enc-store.rar",
                include_bytes!("../../testdata/rar5/enc-store.rar"),
            )],
        ),
        (
            "hdrs",
            vec![(
                "enc-hdrs.rar",
                include_bytes!("../../testdata/rar5/enc-hdrs.rar"),
            )],
        ),
        (
            "vols",
            vec![
                (
                    "enc-vols.part1.rar",
                    include_bytes!("../../testdata/rar5/enc-vols.part1.rar"),
                ),
                (
                    "enc-vols.part2.rar",
                    include_bytes!("../../testdata/rar5/enc-vols.part2.rar"),
                ),
                (
                    "enc-vols.part3.rar",
                    include_bytes!("../../testdata/rar5/enc-vols.part3.rar"),
                ),
            ],
        ),
    ];
    for (tag, vols) in cases {
        let dir = tmpdir(&format!("enc-real-{tag}"));
        let ex = Extractor::new(&dir, vols.len(), true);
        ex.set_password("testpw123");
        for (si, (name, bytes)) in vols.iter().enumerate() {
            feed(&ex, si, name, bytes, 1400, 60 + si as u64);
        }
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{tag}: {:?}", rep.fallbacks);
        assert_eq!(rep.decrypted, vec!["secret.bin".to_string()], "{tag}");
        assert_eq!(
            std::fs::read(dir.join("secret.bin")).unwrap(),
            secret,
            "{tag}"
        );
        for (name, _) in &vols {
            assert!(
                !dir.join(name).exists(),
                "{tag}: volume {name} materialized"
            );
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

/// The committed REAL RAR4 fixtures (`unrar t`-validated; see
/// testdata/rar4/README.md), driven through the full extractor.
/// RAR4 has no password check, so every one of these takes the
/// UNVERIFIED route - ciphertext assembled at store offsets, decrypted
/// at finish, and published only once the header's plaintext CRC32
/// accepts it - yet the outcome must be the same one-pass extraction
/// RAR5 gets: exact payload, no volume left on disk.
#[test]
fn real_rar4_fixtures_extract_and_decrypt() {
    let secret = include_bytes!("../../testdata/rar4/secret.bin").to_vec();
    let cases: Vec<(&str, Vec<(&str, &[u8])>)> = vec![
        (
            "store",
            vec![(
                "enc-store.rar",
                include_bytes!("../../testdata/rar4/enc-store.rar"),
            )],
        ),
        (
            "hdrs",
            vec![(
                "enc-hdrs.rar",
                include_bytes!("../../testdata/rar4/enc-hdrs.rar"),
            )],
        ),
        (
            "vols",
            vec![
                (
                    "enc-vols.part1.rar",
                    include_bytes!("../../testdata/rar4/enc-vols.part1.rar"),
                ),
                (
                    "enc-vols.part2.rar",
                    include_bytes!("../../testdata/rar4/enc-vols.part2.rar"),
                ),
                (
                    "enc-vols.part3.rar",
                    include_bytes!("../../testdata/rar4/enc-vols.part3.rar"),
                ),
            ],
        ),
        (
            "hdrvols",
            vec![
                (
                    "enc-hdr-vols.part1.rar",
                    include_bytes!("../../testdata/rar4/enc-hdr-vols.part1.rar"),
                ),
                (
                    "enc-hdr-vols.part2.rar",
                    include_bytes!("../../testdata/rar4/enc-hdr-vols.part2.rar"),
                ),
                (
                    "enc-hdr-vols.part3.rar",
                    include_bytes!("../../testdata/rar4/enc-hdr-vols.part3.rar"),
                ),
            ],
        ),
    ];
    for (tag, vols) in cases {
        let dir = tmpdir(&format!("enc-real4-{tag}"));
        let ex = Extractor::new(&dir, vols.len(), true);
        ex.set_password("testpw123");
        for (si, (name, bytes)) in vols.iter().enumerate() {
            feed(&ex, si, name, bytes, 137, 60 + si as u64);
        }
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{tag}: {:?}", rep.fallbacks);
        assert_eq!(rep.decrypted, vec!["inner.bin".to_string()], "{tag}");
        assert_eq!(
            std::fs::read(dir.join("inner.bin")).unwrap(),
            secret,
            "{tag}"
        );
        for (name, _) in &vols {
            assert!(
                !dir.join(name).exists(),
                "{tag}: volume {name} materialized"
            );
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

/// A RAR4 volume holding TWO inner files. RAR4 salts each file
/// separately (the writer draws a fresh one per entry), so each needs
/// its OWN derived key and its own IV - a single archive-wide key,
/// which is what a RAR5-shaped assumption would give, decrypts the
/// second file to noise. Both must come out, and the finish pass must
/// pair each output with the right head entry.
#[test]
fn rar4_multi_file_volume_derives_a_key_per_inner_file() {
    let dir = tmpdir("enc4-multi");
    let a_plain = payload(40_000, 51);
    let b_plain = payload(25_003, 52); // odd: exercises the tail pad too
    let fa = fixtures::encrypt_file_v4("pw", &a_plain, 41);
    let fb = fixtures::encrypt_file_v4("pw", &b_plain, 42);
    assert_ne!(
        fa.salt, fb.salt,
        "the fixture must give each file its own salt"
    );
    let vol = fixtures::rar4_volume_enc(&[
        ("a.bin", &fa, 0..fa.cipher.len(), false, false),
        ("b.bin", &fb, 0..fb.cipher.len(), false, false),
    ]);
    let ex = Extractor::new(&dir, 1, true);
    ex.set_password("pw");
    feed(&ex, 0, "v.rar", &vol, 4096, 8);
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(
        rep.decrypted,
        vec!["a.bin".to_string(), "b.bin".to_string()]
    );
    assert_eq!(std::fs::read(dir.join("a.bin")).unwrap(), a_plain);
    assert_eq!(std::fs::read(dir.join("b.bin")).unwrap(), b_plain);
    assert!(!dir.join("v.rar").exists(), "volume must not materialize");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The wrong password on a RAR4 `-p` set. Nothing can catch it before
/// the decrypt pass, so this is the case the unverified route exists
/// for: the CRC gate must reject, the group must DEMOTE rather than
/// fail the job, and the assembled bytes must come back out as the
/// byte-exact posted volume for unrar or a corrected retry.
#[test]
fn rar4_wrong_password_demotes_to_a_byte_exact_volume() {
    let dir = tmpdir("enc4-wrongpw");
    let plain = payload(60_000, 46);
    let f = fixtures::encrypt_file_v4("rightpw", &plain, 31);
    let vol = fixtures::rar4_volume_enc(&[("a.bin", &f, 0..f.cipher.len(), false, false)]);
    let ex = Extractor::new(&dir, 1, true);
    ex.set_password("wrongpw");
    feed(&ex, 0, "v.rar", &vol, 7000, 6);
    let rep = ex.finish().unwrap();
    assert!(
        rep.decrypted.is_empty(),
        "nothing may publish: {:?}",
        rep.decrypted
    );
    assert!(
        rep.fallbacks
            .iter()
            .any(|(_, w)| w.contains("wrong password")),
        "the demote must name the real cause: {:?}",
        rep.fallbacks
    );
    assert_eq!(
        std::fs::read(dir.join("v.rar")).unwrap(),
        vol,
        "the demoted volume must be byte-exact for a retry"
    );
    assert!(
        !dir.join("a.bin").exists(),
        "no wrong-key garbage published"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A RAR4 encrypted entry whose header carries no CRC (a zero field,
/// which the parser reads as "not computed") has NOTHING to adjudicate
/// an unverifiable password against, so it must demote before
/// decrypting rather than publish bytes no one vouched for.
#[test]
fn rar4_encrypted_without_a_checksum_demotes() {
    let dir = tmpdir("enc4-nocrc");
    let plain = payload(50_000, 47);
    let f = fixtures::encrypt_file_v4("pw", &plain, 32);
    let mut vol = fixtures::rar4_volume_enc(&[("a.bin", &f, 0..f.cipher.len(), false, false)]);
    // Blank the file header's CRC field (file header at 20, CRC at +16)
    // and repair the header CRC16 so the block still parses.
    let hdr = 20usize;
    let hsize = u16::from_le_bytes(vol[hdr + 5..hdr + 7].try_into().unwrap()) as usize;
    vol[hdr + 16..hdr + 20].fill(0);
    let hc = (crc32fast::hash(&vol[hdr + 2..hdr + hsize]) & 0xffff) as u16;
    vol[hdr..hdr + 2].copy_from_slice(&hc.to_le_bytes());
    let ex = Extractor::new(&dir, 1, true);
    ex.set_password("pw"); // the RIGHT password, but unverifiable
    feed(&ex, 0, "v.rar", &vol, 7000, 5);
    let rep = ex.finish().unwrap();
    assert!(rep.decrypted.is_empty());
    assert!(
        rep.fallbacks.iter().any(|(_, w)| w.contains("encrypted")),
        "{:?}",
        rep.fallbacks
    );
    assert_eq!(std::fs::read(dir.join("v.rar")).unwrap(), vol);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A check-less encrypted archive can't have its password verified
/// natively (the stored CRC is keyed), so it must fall back to unrar
/// rather than risk a silent wrong-password decrypt.
#[test]
fn encrypted_without_check_falls_back() {
    let dir = tmpdir("enc-nocheck");
    let plain = payload(80_000, 61);
    let mut f = fixtures::encrypt_file("pw", &plain, 7);
    f.no_check = true;
    let vol = fixtures::rar5_volume_enc(&[("a.bin", &f, 0..f.cipher.len(), false, false)], None);
    let ex = Extractor::new(&dir, 1, true);
    ex.set_password("pw"); // correct password, but unverifiable
    feed(&ex, 0, "v.rar", &vol, 7000, 5);
    let rep = ex.finish().unwrap();
    assert!(rep.decrypted.is_empty());
    assert!(
        rep.fallbacks.iter().any(|(_, w)| w.contains("encrypted")),
        "{:?}",
        rep.fallbacks
    );
    // Byte-exact volume kept for unrar / a corrected retry.
    assert_eq!(std::fs::read(dir.join("v.rar")).unwrap(), vol);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// On-the-fly stream decryption: while an encrypted file is still
/// ciphertext on disk (mid-download), `open_stream` hands back a
/// `StreamCrypt` whose `decrypt_range` yields the exact plaintext for
/// arbitrary offsets - the basis of streaming encrypted releases
/// before the finish decrypt runs.
#[test]
fn stream_crypt_decrypts_arbitrary_ranges_before_finish() {
    let dir = tmpdir("enc-stream");
    let plain = payload(300_003, 71);
    let f = fixtures::encrypt_file("pw", &plain, 9);
    let vol =
        fixtures::rar5_volume_enc(&[("movie.mkv", &f, 0..f.cipher.len(), false, false)], None);
    let ex = Extractor::new(&dir, 1, true);
    ex.set_password("pw");
    // This test guards the LEGACY ciphertext+finish-decrypt path
    // (still shipped behind NZBFAST_NO_INSTREAM_DECRYPT).
    ex.set_instream_decrypt(false);
    // Feed everything but DON'T finish() - the file is ciphertext.
    feed(&ex, 0, "v.rar", &vol, 7000, 4);
    let StreamOpen::Encrypted(file, crypt) = ex.open_stream("movie.mkv") else {
        panic!("expected an encrypted stream handle");
    };
    assert_eq!(crypt.plain_len, plain.len() as u64);
    // Random-ish ranges, including offset 0, a mid-block start, and
    // the final partial block.
    for &(pos, len) in &[
        (0u64, 100u64),
        (16, 4096),
        (12345, 50000),
        (plain.len() as u64 - 7, 7),
        (100_000, 200_003),
    ] {
        let (lo, clen) = crypt.covered_bounds(pos, len);
        assert!(lo + clen <= crypt.cipher_len);
        let mut out = vec![0u8; len as usize];
        crypt.decrypt_range(&file, pos, &mut out).unwrap();
        assert_eq!(
            out,
            &plain[pos as usize..(pos + len) as usize],
            "range {pos}+{len}"
        );
    }
    // Dropping the handle releases the reader lease; finish then
    // decrypts in place (no live reader) to the same plaintext.
    drop(crypt);
    drop(file);
    let rep = ex.finish().unwrap();
    assert_eq!(rep.decrypted, vec!["movie.mkv".to_string()]);
    assert_eq!(std::fs::read(dir.join("movie.mkv")).unwrap(), plain);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// With a live stream reader attached, finish() must NOT mutate the
/// file in place: it decrypts to a temp file and renames, so the
/// reader's captured fd keeps decrypting the intact ciphertext inode
/// even after the on-disk file becomes plaintext.
#[test]
fn finish_temp_renames_while_a_reader_streams() {
    let dir = tmpdir("enc-stream-finish");
    let plain = payload(260_000, 72);
    let f = fixtures::encrypt_file("pw", &plain, 3);
    let vol =
        fixtures::rar5_volume_enc(&[("movie.mkv", &f, 0..f.cipher.len(), false, false)], None);
    let ex = Extractor::new(&dir, 1, true);
    ex.set_password("pw");
    // This test guards the LEGACY ciphertext+finish-decrypt path
    // (still shipped behind NZBFAST_NO_INSTREAM_DECRYPT).
    ex.set_instream_decrypt(false);
    feed(&ex, 0, "v.rar", &vol, 7000, 4);
    let StreamOpen::Encrypted(file, crypt) = ex.open_stream("movie.mkv") else {
        panic!("expected an encrypted stream handle");
    };
    // finish() runs WHILE the reader holds its handle → temp+rename.
    let rep = ex.finish().unwrap();
    assert_eq!(rep.decrypted, vec!["movie.mkv".to_string()]);
    // On-disk file is now plaintext…
    assert_eq!(std::fs::read(dir.join("movie.mkv")).unwrap(), plain);
    // …yet the live reader's fd still reads the ciphertext inode and
    // decrypts correctly (rename kept it alive).
    let mut out = vec![0u8; 40_000];
    crypt.decrypt_range(&file, 90_000, &mut out).unwrap();
    assert_eq!(out, &plain[90_000..130_000]);
    // A NEW open now sees plaintext → raw reads (Plain).
    assert!(matches!(ex.open_stream("movie.mkv"), StreamOpen::Plain));
    drop(crypt);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A header-encrypted set whose password never turns up (the bench
/// release1 shape) must NOT park its payload in RAM up to the holds
/// cap: parked spans page to scratch beyond the pw-await window, so
/// peak held bytes stay at the window while the finish demote still
/// materializes byte-exact volumes with the password reason. Before
/// the pager, a 1.6 GB set sat fully resident on a big-RAM box - the
/// highest peak RSS of all five clients in the 2026-08-10 re-cut.
#[test]
fn pw_await_parked_spans_page_to_scratch() {
    let dir = tmpdir("pw-await-page");
    let plain = payload(24_000_000, 51);
    let f = fixtures::encrypt_file("no-candidate-knows-this", &plain, 9);
    let vol = fixtures::rar5_volume_enc_headers(
        &[("obf.bin", &f, 0..f.cipher.len(), false, false)],
        None,
        "no-candidate-knows-this",
        13,
    );
    let ex = Extractor::new(&dir, 1, true);
    // Window = (cap/4).clamp(4 MB, 64 MB) = 8 MB; the 24 MB payload
    // must overflow it to scratch, staying far under the 32 MB cap so
    // nothing demotes on "held-bytes cap".
    ex.set_holds_cap(32 << 20);
    ex.set_password_probe(std::sync::Arc::new(|_probe| None));
    // Offset 0 first so the slot classifies Rar (and parks on the
    // password blocker) before the data piles - a shuffle that lands
    // it late would route the early spans through the unclassified
    // path instead, which is not this test's subject.
    ex.write(0, "v.rar", vol.len() as u64, 0, &vol[..7000])
        .unwrap();
    feed(&ex, 0, "v.rar", &vol, 7000, 11);
    assert!(
        ex.holds_peak() < 12 << 20,
        "parked spans stayed resident: peak {} for a {} B payload",
        ex.holds_peak(),
        vol.len()
    );
    assert!(
        ex.holds_paged_total() > 10 << 20,
        "paging never engaged: {}",
        ex.holds_paged_total()
    );
    let rep = ex.finish().unwrap();
    assert!(
        rep.fallbacks
            .iter()
            .any(|(_, w)| w.contains("password") && !w.contains("held-bytes cap")),
        "{:?}",
        rep.fallbacks
    );
    assert_eq!(
        std::fs::read(dir.join("v.rar")).unwrap(),
        vol,
        "materialized volume must be byte-exact"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The rescue survives paging: a probe that produces the password only
/// at the finish force-probe must still re-key and extract one-pass,
/// re-feeding the parked spans from scratch (`reclaim_span` preads).
#[test]
fn pw_await_probe_hit_refeeds_paged_spans() {
    let dir = tmpdir("pw-await-page-hit");
    let plain = payload(24_000_000, 52);
    let f = fixtures::encrypt_file("late-sidecar-pw", &plain, 10);
    let vol = fixtures::rar5_volume_enc_headers(
        &[("obf.bin", &f, 0..f.cipher.len(), false, false)],
        None,
        "late-sidecar-pw",
        14,
    );
    let ex = Extractor::new(&dir, 1, true);
    ex.set_holds_cap(32 << 20);
    let landed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let l = landed.clone();
    ex.set_password_probe(std::sync::Arc::new(move |probe| {
        // Every mid-feed probe misses (the sidecar has not "landed"
        // yet); the finish force-probe hits, when the parked spans are
        // on scratch.
        if !l.load(std::sync::atomic::Ordering::SeqCst) {
            return None;
        }
        (probe.verify("late-sidecar-pw") == crate::rar::PwVerdict::Verified)
            .then(|| "late-sidecar-pw".to_string())
    }));
    // Offset 0 first for the same deterministic classification as the
    // paging test above.
    ex.write(0, "v.rar", vol.len() as u64, 0, &vol[..7000])
        .unwrap();
    feed(&ex, 0, "v.rar", &vol, 7000, 12);
    landed.store(true, std::sync::atomic::Ordering::SeqCst);
    assert!(
        ex.holds_paged_total() > 10 << 20,
        "paging never engaged: {}",
        ex.holds_paged_total()
    );
    let rep = ex.finish().unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(rep.decrypted, vec!["obf.bin".to_string()]);
    assert_eq!(std::fs::read(dir.join("obf.bin")).unwrap(), plain);
    assert!(!dir.join("v.rar").exists(), "one-pass: no volume on disk");
    std::fs::remove_dir_all(&dir).unwrap();
}

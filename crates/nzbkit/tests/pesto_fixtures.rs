//! The pesto tiny-PAR2 rung against the census's committed evidence
//! (research/fixtures/pesto-par2-2026-08-10/): ten real sidecar bodies
//! fetched from public Usenet, including the collision pair that makes
//! the 16k-MD5 hash gate non-negotiable.
//!
//! The load-bearing test is the last one: in the census, payload
//! rel_id 3526876 was claimed by FOUR sets on counter+length (True
//! Detective S04E06 true; two Oz episodes and Sopranos S03E12 false),
//! and only the FileDesc first-16-KiB MD5 separated them. This file
//! re-proves from committed bytes that a candidate which passes the
//! counter-containment and length-ratio pre-filters still writes NO
//! name until the payload's own bytes match a FileDesc hash.

use std::path::{Path, PathBuf};

use nzbkit::par2::{self, Par2Set};
use nzbkit::pesto;

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../research/fixtures/pesto-par2-2026-08-10")
}

fn manifest() -> serde_json::Value {
    let raw = std::fs::read(fixture_dir().join("manifest.json")).expect("fixture manifest");
    serde_json::from_str(std::str::from_utf8(&raw).unwrap()).unwrap()
}

/// Every committed sidecar parses through the production parser, keeps
/// its recovery-set id, and self-names exactly as the manifest recorded
/// at census time - the 99.5%-parse / 100%-self-name proof, replayable.
#[test]
fn all_fixture_sidecars_parse_and_self_name() {
    let m = manifest();
    let fixtures = m["fixtures"].as_array().expect("fixtures list");
    assert_eq!(fixtures.len(), 10, "the census committed ten bodies");
    for f in fixtures {
        let name = f["fixture_file"].as_str().unwrap();
        let bytes = std::fs::read(fixture_dir().join(name)).expect(name);
        assert_eq!(&bytes[..8], par2::MAGIC, "{name}: magic");
        let set = Par2Set::parse(&[&bytes]).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(
            par2::hex16(&set.recovery_set_id),
            f["recovery_set_id"].as_str().unwrap(),
            "{name}: set id"
        );
        assert_eq!(set.block_size, f["block_size"].as_u64().unwrap(), "{name}");
        let want = f["filedescs"].as_array().unwrap();
        assert_eq!(set.files.len(), want.len(), "{name}: FileDesc count");
        for (got, want) in set.files.iter().zip(want) {
            assert_eq!(got.name, want["name"].as_str().unwrap(), "{name}");
            assert_eq!(got.length, want["length"].as_u64().unwrap(), "{name}");
            assert_eq!(
                par2::hex16(&got.md5_16k),
                want["md5_16k"].as_str().unwrap(),
                "{name}"
            );
            assert_eq!(
                par2::hex16(&got.md5),
                want["md5"].as_str().unwrap(),
                "{name}"
            );
        }
        // Self-naming: a real, readable release name came out.
        assert!(
            !nzbkit::release::looks_obfuscated(set.files[0].name.trim_end_matches(".mkv")),
            "{name}: FileDesc must carry a real name"
        );
        // And the object's own message-id obeys the pesto grammar.
        let mid = f["source_msgid"].as_str().unwrap();
        assert!(
            pesto::parse_msgid(mid).is_some(),
            "{mid}: census message-ids must parse"
        );
    }
}

/// The collision pair carries DIFFERENT first-16k hashes, so at most
/// one of the competing sets can ever be confirmed against one payload
/// - the property the whole gate rests on.
#[test]
fn the_collision_pair_is_separable_by_hash_alone() {
    let dir = fixture_dir();
    let read = |prefix: &str| -> Par2Set {
        let name = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .find(|n| n.starts_with(prefix))
            .expect("collision fixture present");
        Par2Set::parse(&[&std::fs::read(dir.join(name)).unwrap()]).unwrap()
    };
    let truth = read("6b6c393a411f"); // True Detective S04E06 - confirmed true
    let false_claim = read("6031993e38dc"); // Sopranos S03E12 - hash-rejected
    assert!(truth.files[0].name.starts_with("True.Detective.S04E06"));
    assert!(false_claim.files[0].name.starts_with("The.Sopranos.S03E12"));
    assert_ne!(
        truth.files[0].md5_16k, false_claim.files[0].md5_16k,
        "the gate can always pick at most one claimant"
    );
}

/// End to end from committed bytes: the false claimant PASSES the
/// counter-containment and length-ratio pre-filters against a payload
/// (exactly how the census's counter+length pass mislinked it), and the
/// hash gate still refuses to write a name because the payload's bytes
/// match no FileDesc. Skipping the gate here is what would ship >=2.4%
/// wrong names - this test is the guard on the whole lane.
#[test]
fn the_hash_gate_rejects_the_false_claimant() {
    let dir = fixture_dir();
    let bytes = {
        let name = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .find(|n| n.starts_with("6031993e38dc"))
            .expect("Sopranos S03E12 fixture present");
        std::fs::read(dir.join(name)).unwrap()
    };
    let set = Par2Set::parse(&[&bytes]).unwrap();
    let descs = pesto::PestoDesc::from_set(&set);
    let sum_len: u64 = descs.iter().map(|d| d.length).sum();
    assert_eq!(sum_len, 4_760_509_218, "Sopranos S03E12 declared length");

    // A scratch index holding an obfuscated payload the pre-filters
    // WILL link to this set: its counter range contains C-1 and its
    // on-wire size sits mid-band (ratio ~1.025).
    let tmp = std::env::temp_dir().join(format!("nzbfast-pesto-fix-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).unwrap();
    let mut ix = nzbkit::index::Index::open(&tmp.join("index.db")).unwrap();
    // C from the fixture's own message-id counter (0x1837).
    let base_ctr = pesto::parse_msgid("<18ca03189058f500.1837.8159eff123016a78@bdzqkgolovkpdk.com>")
        .unwrap()
        .counter as i64;
    let entries: Vec<nzbkit::nntp::OverEntry> = (0..7u32)
        .map(|i| nzbkit::nntp::OverEntry {
            number: 0,
            subject: format!(r#""9f8e7d6c5b4a392817.rar" yEnc ({}/7)"#, i + 1),
            from: "p@x".into(),
            message_id: format!(
                "<18ca03189058f4aa.{:04x}.aaaabbbbccccdddd@example.org>",
                base_ctr as u32 - 7 + i
            ),
            bytes: 697_000_000,
            date: 0,
        })
        .collect();
    ix.ingest("alt.binaries.moovee", &entries, 1000).unwrap();
    let rid = ix.release_ids_by_stem("9f8e7d6c5b4a392817.rar").unwrap()[0];

    let row = nzbkit::index::PestoSetRow {
        set_id: par2::hex16(&set.recovery_set_id),
        grp: "alt.binaries.moovee".into(),
        base_ctr,
        sum_len: sum_len as i64,
        files: descs,
        tries: 0,
    };
    // The pre-filters link it - this is the census's mislink, replayed.
    let cands = ix.pesto_candidates(&row).unwrap();
    assert_eq!(
        cands.iter().map(|c| c.id).collect::<Vec<_>>(),
        vec![rid],
        "counter+length alone WOULD have claimed this payload"
    );
    // ...and the hash gate is what stops it: the payload's actual head
    // bytes (any bytes that are not the Sopranos encode - here another
    // committed body) match no FileDesc, so no name may be written.
    let head = {
        let name = std::fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .find(|n| n.starts_with("6b6c393a411f"))
            .unwrap();
        std::fs::read(dir.join(name)).unwrap()
    };
    assert!(
        head.len() >= 16384,
        "stand-in head must cover the hash span"
    );
    assert_eq!(
        ix.pesto_confirm(&row, rid, &head, 2000).unwrap(),
        None,
        "the gate must refuse a hash mismatch"
    );
    assert!(
        ix.name_claims(rid).unwrap().is_empty(),
        "not even a recorded claim without the hash"
    );
    assert_eq!(
        ix.stem_by_id(rid).unwrap().as_deref(),
        Some("9f8e7d6c5b4a392817"),
        "the release keeps its stem - no name shipped"
    );
    drop(ix);
    let _ = std::fs::remove_dir_all(&tmp);
}

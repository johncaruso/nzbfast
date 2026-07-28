//! Regression tests pinning three confirmed index defects found by a
//! correctness review of the index (the C3, D3 and D2 cases).
//! Each test is written to FAIL against the defective code and pass
//! once the finding is fixed; they ship `#[ignore]`d so the suite stays
//! green while the findings are open.

use nzbkit::index::{BrowseQuery, BrowseSort, Credit, Index};
use nzbkit::nntp::OverEntry;
use std::path::PathBuf;

/// Fresh on-disk index in a per-test temp directory (same idiom as the
/// in-crate index tests - no tempdir dev-dependency in this crate).
fn temp_index(tag: &str) -> (Index, PathBuf) {
    let dir = std::env::temp_dir().join(format!(
        "nzbfast-index-regr-{tag}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let ix = Index::open(&dir.join("index.db")).unwrap();
    (ix, dir)
}

fn entry(subject: &str, from: &str, id: &str, bytes: u64) -> OverEntry {
    OverEntry {
        number: 0,
        subject: subject.into(),
        from: from.into(),
        message_id: format!("<{id}>"),
        bytes,
        date: 0,
    }
}

/// Finding C3: the browse view's Category sort orders the `res` TEXT
/// column lexicographically, so a user sorting by Category (descending,
/// the default direction) sees 720p releases ranked ABOVE 2160p and
/// 1080p - the exact opposite of the "lead with the best encode" the
/// sort promises. A user picking the top row of a category gets a
/// worse encode than the index actually holds.
#[test]
fn category_sort_ranks_resolution_by_quality_not_lexicographically() {
    let (mut ix, _dir) = temp_index("c3");
    let mk = |f: &str, from: &str, id: &str| {
        entry(&format!("\"{f}\" yEnc (1/1)"), from, id, 4 << 30)
    };
    ix.ingest(
        "alt.binaries.test",
        &[
            mk("Alpha.Film.2020.480p.WEB.x264-GRP.mkv", "a@a", "r1"),
            mk("Bravo.Film.2021.2160p.BluRay.x265-GRP.mkv", "b@b", "r2"),
            mk("Charlie.Film.2022.720p.WEB.x264-GRP.mkv", "c@c", "r3"),
            mk("Delta.Film.2023.1080p.BluRay.x264-GRP.mkv", "d@d", "r4"),
        ],
        1_000,
    )
    .unwrap();
    let (rows, total) = ix
        .browse(&BrowseQuery {
            sort: BrowseSort::Kind,
            desc: true,
            ..Default::default()
        })
        .unwrap();
    assert_eq!(total, 4);
    // All four are the same kind ("movie"), so within the category the
    // descending sort must lead with the best encode.
    let res: Vec<&str> = rows.iter().map(|r| r.res.as_str()).collect();
    assert_eq!(
        res,
        ["2160p", "1080p", "720p", "480p"],
        "Category sort (desc) must rank resolution by quality; \
         lexicographic TEXT ordering puts 720p above 2160p"
    );
}

/// Finding D3: `total_parts` is last-write-wins on re-ingest and part
/// numbers are unioned across batches. When a poster re-rars a release
/// reusing the same volume filenames, segments from BOTH generations
/// merge into one file row and the union satisfies the smaller total,
/// so the release is marked complete and its NZB mixes message-ids
/// from two incompatible rar sets. The user downloads a "complete"
/// release that extracts corrupt.
#[test]
fn rerar_with_reused_filenames_must_not_mark_a_mixed_generation_complete() {
    let (mut ix, _dir) = temp_index("d3");
    let fname = "Echo.Film.2024.1080p.BluRay.x264-GRP.part1.rar";
    let poster = "poster@example.com";
    // Generation 1: a 5-part posting of which only parts 3..5 were seen
    // (parts 1 and 2 expired or were taken down). Incomplete, correctly.
    ix.ingest(
        "alt.binaries.test",
        &[
            entry(&format!("\"{fname}\" yEnc (3/5)"), poster, "gen1-p3", 750_000),
            entry(&format!("\"{fname}\" yEnc (4/5)"), poster, "gen1-p4", 750_000),
            entry(&format!("\"{fname}\" yEnc (5/5)"), poster, "gen1-p5", 750_000),
        ],
        1_000,
    )
    .unwrap();
    let rows = ix.search("", 10).unwrap();
    assert_eq!(rows.len(), 1);
    assert!(!rows[0].complete, "3 of 5 parts is incomplete");

    // Generation 2: the poster re-rars with different settings (now only
    // 3 parts) and reposts under the SAME filenames; parts 1 and 2 of
    // the new set arrive in a later scan batch.
    ix.ingest(
        "alt.binaries.test",
        &[
            entry(&format!("\"{fname}\" yEnc (1/3)"), poster, "gen2-p1", 750_000),
            entry(&format!("\"{fname}\" yEnc (2/3)"), poster, "gen2-p2", 750_000),
        ],
        2_000,
    )
    .unwrap();

    let rows = ix.search("", 10).unwrap();
    assert_eq!(rows.len(), 1);
    let rel = &rows[0];
    // Sanity: the defect's mechanism really is present - the emitted NZB
    // mixes message-ids from both generations of the archive.
    let nzb = ix.make_nzb(rel.id).unwrap();
    let mixed = nzb.contains("gen1-p4") && nzb.contains("gen2-p1");
    // No coherent single-generation part set exists (gen2 is missing its
    // part 3; gen1 is missing parts 1 and 2), so the release must not be
    // reported complete. Today `total_parts` takes the last batch's 3,
    // the unioned 5 part numbers satisfy nsegs >= total_parts, and the
    // release flips to complete with a corrupt mixed-generation NZB.
    assert!(
        !rel.complete,
        "release marked complete from two incompatible rar generations \
         (mixed-generation NZB: {mixed})"
    );
}

/// Finding D2: `person_upsert`'s name fallback only refuses rows whose
/// SAME handle type differs, so a person already pinned by one handle
/// type (a Wikidata Q-id) absorbs a same-named different person arriving
/// with the other handle type (a TVmaze id). The blank-fill UPDATE then
/// stamps the TVmaze id onto the wrong person, and every future credit
/// for that TVmaze id lands on the merged row: the person page shows one
/// human wearing two people's filmographies, and nothing in the UI can
/// split them apart again.
#[test]
#[ignore = "finding D2 is a DESIGN LIMIT, not a bug - see person_upsert's doc \
comment. Merging across different handle types is required for one person seen \
by two providers (people_identity_credits_and_the_search_leg pins it), and the \
same rule necessarily merges two different same-named people. Fixing needs a \
disambiguator, not a tighter query. Kept as the spec for that future work."]
fn person_upsert_keeps_two_people_apart_once_each_has_a_different_handle_type() {
    let (ix, _dir) = temp_index("d2");
    // "Chris Evans" the actor, identified by Wikidata.
    let actor = ix
        .person_upsert(&Credit {
            name: "Chris Evans".into(),
            role: "actor".into(),
            wikidata_qid: "Q3564164".into(),
            ..Default::default()
        })
        .unwrap();
    // "Chris Evans" the TV presenter, identified by TVmaze - a different
    // human, carrying a handle the actor's row does not have.
    let presenter = ix
        .person_upsert(&Credit {
            name: "Chris Evans".into(),
            role: "presenter".into(),
            tvmaze_id: 42,
            ..Default::default()
        })
        .unwrap();
    assert_ne!(
        actor, presenter,
        "a credit identified by TVmaze must not merge into a row already \
         identified by Wikidata just because the names match"
    );
    // The actor's row must not have been stamped with the presenter's id.
    let row = ix.person_get(actor).unwrap().unwrap();
    assert_eq!(
        row.tvmaze_id, 0,
        "the Wikidata-identified actor absorbed the presenter's TVmaze id"
    );
}

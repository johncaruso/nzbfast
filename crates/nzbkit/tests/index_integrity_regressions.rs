//! Regression tests pinning three confirmed index defects found by a
//! correctness review of the index (the C3, D3 and D2 cases).
//! Each test is written to FAIL against the defective code and pass
//! once the finding is fixed; an open finding ships `#[ignore]`d so the
//! suite stays green while it is open, and the `#[ignore]` comes off
//! when it is fixed. All three are fixed and running.

mod scratch;

use nzbkit::index::{BrowseQuery, BrowseSort, Credit, Index};
use nzbkit::nntp::OverEntry;

/// Fresh on-disk index in a per-test temp directory (same idiom as the
/// in-crate index tests - no tempdir dev-dependency in this crate).
fn temp_index(tag: &str) -> (Index, scratch::ScratchDir) {
    let dir = std::env::temp_dir().join(format!("nzbfast-index-regr-{tag}-{}", std::process::id()));
    let dir = scratch::ScratchDir::attach(&dir);
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
    let mk =
        |f: &str, from: &str, id: &str| entry(&format!("\"{f}\" yEnc (1/1)"), from, id, 4 << 30);
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
            entry(
                &format!("\"{fname}\" yEnc (3/5)"),
                poster,
                "gen1-p3",
                750_000,
            ),
            entry(
                &format!("\"{fname}\" yEnc (4/5)"),
                poster,
                "gen1-p4",
                750_000,
            ),
            entry(
                &format!("\"{fname}\" yEnc (5/5)"),
                poster,
                "gen1-p5",
                750_000,
            ),
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
            entry(
                &format!("\"{fname}\" yEnc (1/3)"),
                poster,
                "gen2-p1",
                750_000,
            ),
            entry(
                &format!("\"{fname}\" yEnc (2/3)"),
                poster,
                "gen2-p2",
                750_000,
            ),
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

/// Finding D2: `person_upsert`'s name fallback only refused rows whose
/// SAME handle type differed, so a person already pinned by one handle
/// type (a Wikidata Q-id) absorbed a same-named different person arriving
/// with the other handle type (a TVmaze id). The blank-fill UPDATE then
/// stamped the TVmaze id onto the wrong person, and every future credit
/// for that TVmaze id landed on the merged row: the person page showed
/// one human wearing two people's filmographies, and nothing in the UI
/// could split them apart again.
///
/// Fixed by giving the two id spaces something in common to disagree
/// about rather than by tightening the query - which could only have
/// forked the one person the merge exists for. `born` is that fact: it is
/// what BOTH cast providers publish (TVmaze in the cast payload,
/// Wikidata as P569), so it is the one that fires on this exact shape.
///
/// The IMDb id is matched too and is the stronger claim where it exists,
/// but only Wikidata can supply one for a person - measured 27 Jul 2026,
/// TVmaze exposes no person-level IMDb id by any route. See
/// `person_upsert`'s doc comment.
#[test]
fn person_upsert_keeps_two_people_apart_once_each_has_a_different_handle_type() {
    let (ix, _dir) = temp_index("d2");
    // "Chris Evans" the actor, from a film's cast: a Wikidata Q-id, and
    // the IMDb id and birthday that ride along with it.
    let actor = ix
        .person_upsert(&Credit {
            name: "Chris Evans".into(),
            role: "actor".into(),
            wikidata_qid: "Q170572".into(),
            imdb: "nm0262635".into(),
            born: "1981-06-13".into(),
            ..Default::default()
        })
        .unwrap();
    // "Chris Evans" the TV presenter, from a show's cast: a different
    // human, carrying a handle the actor's row does not have and no IMDb
    // id at all, because TVmaze has none to give.
    let presenter = ix
        .person_upsert(&Credit {
            name: "Chris Evans".into(),
            role: "presenter".into(),
            tvmaze_id: 42,
            born: "1966-04-01".into(),
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
    assert_eq!(row.born, "1981-06-13", "the birth date was not stored");

    // The other half of the same rule: a credit that contradicts nothing
    // still merges. This is the shape the fix must not break - one human
    // whose TV credit and film credit share only a name and a birthday.
    let (ix, _dir) = temp_index("d2-merge");
    let film = ix
        .person_upsert(&Credit {
            name: "Tom Cruise".into(),
            role: "actor".into(),
            wikidata_qid: "Q37079".into(),
            imdb: "nm0000129".into(),
            born: "1962-07-03".into(),
            ..Default::default()
        })
        .unwrap();
    let tv = ix
        .person_upsert(&Credit {
            name: "Tom Cruise".into(),
            role: "actor".into(),
            tvmaze_id: 555,
            born: "1962-07-03".into(),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(
        film, tv,
        "one human seen by two providers forked into two rows"
    );
    let row = ix.person_get(film).unwrap().unwrap();
    assert_eq!(
        (row.tvmaze_id, row.wikidata_qid.as_str(), row.imdb.as_str()),
        (555, "Q37079", "nm0000129"),
        "the merged row did not collect both handles"
    );
}

/// The IMDb id is an identity claim in its own right, in both
/// directions: two people who differ on one are different people even
/// when everything else about the credit matches, and one person is
/// found by it even when the providers agree on nothing else.
///
/// This is the join the `people.imdb` column was always shaped for. It
/// only fires between providers that both publish an `nm…` id, which
/// today means Wikidata and anything added later - see `person_upsert`
/// for why TVmaze is not one of them, and why `born` carries the
/// cross-provider case instead.
#[test]
fn person_upsert_separates_two_people_who_differ_on_the_imdb_id() {
    let (ix, _dir) = temp_index("d2-imdb");
    let a = ix
        .person_upsert(&Credit {
            name: "Michael Jordan".into(),
            role: "actor".into(),
            imdb: "nm0001392".into(),
            ..Default::default()
        })
        .unwrap();
    let b = ix
        .person_upsert(&Credit {
            name: "Michael Jordan".into(),
            role: "actor".into(),
            imdb: "nm2027656".into(),
            ..Default::default()
        })
        .unwrap();
    assert_ne!(a, b, "two different IMDb ids are two different people");
    // …and the same id is the same person, arriving with a handle the
    // first credit never had.
    let again = ix
        .person_upsert(&Credit {
            name: "Michael Jordan".into(),
            role: "actor".into(),
            imdb: "nm0001392".into(),
            tvmaze_id: 77,
            ..Default::default()
        })
        .unwrap();
    assert_eq!(again, a, "the IMDb id did not identify the person it names");
    let row = ix.person_get(a).unwrap().unwrap();
    assert_eq!(
        row.tvmaze_id, 77,
        "the second provider's handle was not filled in"
    );
    // A credit that knows only the name still lands on one of them
    // rather than forking a third row: a blank never contradicts.
    let bare = ix
        .person_upsert(&Credit {
            name: "Michael Jordan".into(),
            role: "actor".into(),
            ..Default::default()
        })
        .unwrap();
    assert!(
        bare == a || bare == b,
        "a handle-less credit forked a new row"
    );
}

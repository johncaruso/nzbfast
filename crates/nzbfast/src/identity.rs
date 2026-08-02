//! What a finished download actually IS, when the name it was posted
//! under does not say.
//!
//! Four independent enrichers, each one operating only on facts already
//! in hand at the moment a job completes. None of them fetches an
//! article; none of them runs a background sweep; every one of them
//! degrades to silence offline.
//!
//! - **srrdb archive-CRC** (`crate::srrdb`): the RAR headers we already
//!   read state an inner file's CRC32, which is an exact key to a
//!   canonical scene name and an IMDb id.
//! - **PAR2 hash16k repost table** (`Index::par_hash_lookup`): the
//!   sidecar fingerprints the OUTER volumes, so it identifies a repost
//!   of something we named before even when the archive headers are
//!   encrypted. The one path here that survives `-hp`.
//! - **Matroska Title** (`nzbkit::mkv`): the muxer's own name for the
//!   file, which a reposter who scrambled the subject line usually
//!   never reached inside the container to clear.
//! - **xREL P2P** (`crate::xrel`): not a name at all - an IMDb id for
//!   the true-P2P groups whose releases the scene predbs never carry.
//!
//! The result is a SECOND opinion recorded beside the posted name, never
//! a replacement for it: `Job::name` is what the user and the *arrs
//! match on. Renaming reads the second opinion; the API reports both.
//!
//! The decision logic is pure and lives here; the fetching is in the two
//! client modules. That split is what lets the ladder be tested without
//! a network, and it is also what keeps the rate-limited calls
//! conditional - `xrel_query` decides whether a request is worth making
//! before one is made.

use nzbkit::release;

/// May the identity oracles put a request on the wire at all?
///
/// `NZBFAST_NO_ENRICH=1` is the test suite's "do not touch the real
/// internet" switch, and this ladder is metadata enrichment by another
/// name - without the guard, every end-to-end daemon test whose fixture
/// name carries a group tag would put a live xREL search on the wire.
///
/// Checked at the network boundary inside each client rather than at
/// the call sites, so a new call site cannot forget it. The LOCAL rungs
/// (the repost table, the container Title) are unaffected and stay
/// testable end to end.
pub fn may_call_out() -> bool {
    std::env::var_os("NZBFAST_NO_ENRICH").is_none()
}

/// The second opinion, when there is one.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Identity {
    /// A canonical release name to prefer when renaming. Empty when no
    /// oracle offered one, or when the posted name was already good.
    pub name: String,
    /// IMDb id in `tt` form, empty when nothing knew one.
    pub imdb: String,
    /// Which oracle answered - see the module note on why the user gets
    /// told this rather than just the name.
    pub src: &'static str,
}

impl Identity {
    pub fn is_empty(&self) -> bool {
        self.name.is_empty() && self.imdb.is_empty()
    }
}

/// Everything the naming decision reads. Assembled by the caller so the
/// decision itself touches no disk and no network.
#[derive(Debug, Default)]
pub struct Facts {
    /// The name the job was submitted under.
    pub posted: String,
    /// srrdb's answer for this set's inner-file CRC32.
    pub srr: Option<crate::srrdb::SrrHit>,
    /// `(name, title_key)` from the PAR2 repost table.
    pub remembered: Option<(String, String)>,
    /// Segment>Info>Title of the payload's main video, credit already
    /// stripped.
    pub mkv_title: Option<String>,
}

/// Pick the best name available, and say where it came from.
///
/// Ordered by how much the answer is worth trusting, not by how much it
/// costs:
///
/// 1. **srrdb**, always when it answered. A CRC32 hit is the same bytes,
///    and what it returns is the release's canonical spelling - which
///    beats the posted name even when the posted name is perfectly
///    readable, because that is what a media server matches on.
/// 2. **The repost table**, when the posted name says nothing. An exact
///    fingerprint match against a release WE named, so it is as certain
///    as srrdb about identity and less certain only about spelling.
/// 3. **The container's Title**, when the posted name says nothing and
///    the Title reads as a release name. The weakest of the three: it is
///    an unverified claim by whoever muxed the file.
///
/// 2 and 3 are gated on the posted name being obfuscated because that is
/// the only case where they can improve on it. A readable posted name is
/// the submitter's own words, and replacing those on a container's say-so
/// would break the one thing the user is sure of.
pub fn decide_name(f: &Facts) -> Option<(String, &'static str)> {
    let posted = f.posted.trim();
    let take = |cand: &str, src: &'static str| -> Option<(String, &'static str)> {
        let cand = cand.trim();
        // A path is not a release name from ANY source. Refused whole
        // rather than sanitised: mapping the separators leaves a name
        // like ".. etc Film" - not an escape, but a hidden dotfile made
        // out of a string that was never a name in the first place.
        if cand.contains('/') || cand.contains('\\') || cand.starts_with('.') {
            return None;
        }
        let cand = release::sanitize_name(cand);
        // Nothing to say if it agrees with the name we already have, and
        // nothing usable if sanitising emptied it.
        (!cand.is_empty() && !cand.eq_ignore_ascii_case(posted)).then_some((cand, src))
    };
    if let Some(hit) = &f.srr
        && let Some(got) = take(&hit.release, "srrdb")
    {
        return Some(got);
    }
    if !release::looks_obfuscated(posted) {
        return None;
    }
    if let Some((name, _)) = &f.remembered
        && let Some(got) = take(name, "par-hash")
    {
        return Some(got);
    }
    let title = f.mkv_title.as_deref()?;
    // The one candidate nobody vouched for, so it has to pass the
    // release-name bar on its own before it may rename anything.
    release::looks_like_release_name(title)
        .then(|| take(title, "mkv-title"))
        .flatten()
}

/// The query to ask xREL, or `None` for "do not spend a request".
///
/// Three gates, all of them about not making a pointless call on a
/// service with a 2-per-5-seconds search budget:
///
/// - an id we already hold answers the question, so nothing to ask;
/// - a name with no group tag is not a release xREL indexes;
/// - a name that reads as obfuscated has nothing to search WITH.
///
/// The query is the title and year rather than the whole release name:
/// xREL's search is a text search over its own catalogue, and handing it
/// "…2160p.WEB.H265-POKE" narrows to the tokens rather than the film.
pub fn xrel_query(name: &str, known_imdb: &str) -> Option<String> {
    if !known_imdb.trim().is_empty() {
        return None;
    }
    let name = name.trim();
    if release::looks_obfuscated(name) || release::group_of(name).is_none() {
        return None;
    }
    let p = release::parse_release(name);
    let title = p.title.trim();
    if title.is_empty() {
        return None;
    }
    Some(match p.year {
        Some(y) => format!("{title} {y}"),
        None => title.to_string(),
    })
}

/// Read the PAR2 sidecars sitting beside a finished download and return
/// their member fingerprints.
///
/// Sidecars only, and only the top level: `.par2` files are what the
/// post shipped, and the recovery volumes repeat the same critical
/// packets, so the index alone answers. Called BEFORE the cleanup sweep,
/// which is what deletes them.
pub fn par_fingerprints(dir: &std::path::Path) -> Vec<(String, String)> {
    // A main index is small (tens of KB); a `.vol000+50.par2` is not,
    // and reading a 700 MB recovery volume to learn what its first
    // packet already said would stall the tail. Read the smallest few
    // candidates and stop as soon as one set parses.
    const MAX_READ: u64 = 8 << 20;
    let Ok(rd) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut cands: Vec<(u64, std::path::PathBuf)> = rd
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("par2"))
                && p.is_file()
        })
        .filter_map(|p| Some((p.metadata().ok()?.len(), p)))
        .filter(|(len, _)| *len <= MAX_READ)
        .collect();
    cands.sort();
    for (_, path) in cands.iter().take(4) {
        let Ok(bytes) = std::fs::read(path) else {
            continue;
        };
        if let Ok(set) = nzbkit::par2::Par2Set::parse(&[&bytes]) {
            let pairs = set.member_hash16k();
            if !pairs.is_empty() {
                return pairs;
            }
        }
    }
    Vec::new()
}

/// The Matroska Title of a finished download's main video, with the
/// repacker credit stripped. `None` when there is no Matroska main
/// video, or it carries no Title.
pub fn container_title(dir: &std::path::Path) -> Option<String> {
    let video = crate::smart::main_video(dir)?;
    if !matches!(
        video
            .extension()
            .map(|e| e.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default()
            .as_str(),
        "mkv" | "webm"
    ) {
        return None;
    }
    nzbkit::mkv::probe(&video)?.title
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::srrdb::SrrHit;

    fn srr(release: &str) -> Option<SrrHit> {
        Some(SrrHit {
            release: release.into(),
            imdb: "tt1".into(),
        })
    }

    const OBF: &str = "a4f9c2e1b7d0483951";
    const GOOD: &str = "Example.Movie.2019.1080p.BluRay.x264-GRP";
    const CANON: &str = "Example.Movie.2019.1080p.BluRay.x264-CANON";

    /// An exact CRC hit outranks everything, INCLUDING a readable posted
    /// name: it is the release's canonical spelling and that is what a
    /// media server matches on.
    #[test]
    fn an_exact_crc_hit_wins_even_over_a_readable_name() {
        let f = Facts {
            posted: GOOD.into(),
            srr: srr(CANON),
            ..Default::default()
        };
        assert_eq!(decide_name(&f), Some((CANON.to_string(), "srrdb")));
    }

    /// The weaker two only speak when the posted name says nothing. A
    /// readable name is the submitter's own words and a container's
    /// claim does not get to overrule them.
    #[test]
    fn the_weaker_oracles_stay_quiet_over_a_readable_name() {
        let f = Facts {
            posted: GOOD.into(),
            remembered: Some((CANON.into(), "m:x".into())),
            mkv_title: Some(CANON.into()),
            ..Default::default()
        };
        assert_eq!(decide_name(&f), None);
    }

    #[test]
    fn an_obfuscated_name_takes_the_repost_table_then_the_container() {
        let remembered = Facts {
            posted: OBF.into(),
            remembered: Some((GOOD.into(), "m:example movie:2019".into())),
            mkv_title: Some(CANON.into()),
            ..Default::default()
        };
        // The fingerprint is exact; the container's claim is not.
        assert_eq!(
            decide_name(&remembered),
            Some((GOOD.to_string(), "par-hash"))
        );

        let container = Facts {
            posted: OBF.into(),
            mkv_title: Some(GOOD.into()),
            ..Default::default()
        };
        assert_eq!(
            decide_name(&container),
            Some((GOOD.to_string(), "mkv-title"))
        );
    }

    /// A container Title that is not a release name renames nothing -
    /// the muxer default, the human title, the path fragment.
    #[test]
    fn an_unconvincing_container_title_is_declined() {
        for t in [
            "video",
            "Sintel",
            "Episode 3",
            "encoded by Handbrake",
            "a/b.mkv",
        ] {
            let f = Facts {
                posted: OBF.into(),
                mkv_title: Some(t.into()),
                ..Default::default()
            };
            assert_eq!(decide_name(&f), None, "{t:?}");
        }
        // …and neither does no oracle at all.
        assert_eq!(
            decide_name(&Facts {
                posted: OBF.into(),
                ..Default::default()
            }),
            None
        );
    }

    /// A name that agrees with the one we already have is not news, and
    /// recording it would put a redundant second name on every history
    /// row.
    #[test]
    fn an_answer_that_agrees_with_the_posted_name_is_not_recorded() {
        let f = Facts {
            posted: GOOD.into(),
            srr: srr(GOOD),
            ..Default::default()
        };
        assert_eq!(decide_name(&f), None);
        let f = Facts {
            posted: GOOD.into(),
            srr: srr(&GOOD.to_ascii_lowercase()),
            ..Default::default()
        };
        assert_eq!(decide_name(&f), None);
    }

    /// A path is not a release name, whichever oracle offered it - and
    /// the srrdb rung does not go through `looks_like_release_name`, so
    /// the refusal has to live in the decision itself. Sanitising it
    /// instead would leave ".. etc Example.Movie.2019-GRP": no longer an
    /// escape, but a hidden dotfile made out of a string that was never
    /// a name.
    #[test]
    fn an_oracle_cannot_hand_back_a_path() {
        for bad in [
            "../../etc/Example.Movie.2019-GRP",
            "..\\..\\Example.Movie.2019-GRP",
            ".hidden.Movie.2019.1080p-GRP",
            "/absolute/Example.Movie.2019-GRP",
        ] {
            let f = Facts {
                posted: OBF.into(),
                srr: srr(bad),
                ..Default::default()
            };
            assert_eq!(decide_name(&f), None, "{bad}");
            let f = Facts {
                posted: OBF.into(),
                mkv_title: Some(bad.into()),
                ..Default::default()
            };
            assert_eq!(decide_name(&f), None, "{bad}");
        }
    }

    /// The two disk readers. Both run on a finished download's own
    /// directory, so what matters is that they answer on a real one and
    /// stay silent - never panic, never stall - on everything else.
    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("nzbfast-ident-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn par_fingerprints_read_a_real_sidecar_and_shrug_at_everything_else() {
        // The same checked-in par2cmdline output nzbkit's parser tests
        // use, so the two cannot drift.
        const MAIN: &[u8] = include_bytes!("../../nzbkit/tests/fixtures/par2/testset.par2");
        let d = tmpdir("par");
        assert!(
            par_fingerprints(&d).is_empty(),
            "an empty directory has no sidecar"
        );
        std::fs::write(d.join("notes.txt"), b"not a par2").unwrap();
        std::fs::write(d.join("broken.par2"), b"PAR2\0PKTnonsense").unwrap();
        assert!(
            par_fingerprints(&d).is_empty(),
            "garbage must not parse as a set"
        );
        std::fs::write(d.join("testset.par2"), MAIN).unwrap();
        let prints = par_fingerprints(&d);
        assert_eq!(prints.len(), 1, "{prints:?}");
        assert_eq!(prints[0].1, "beta.bin");
        assert_eq!(prints[0].0.len(), 32);
        // A directory that does not exist is not an error worth having.
        assert!(par_fingerprints(&d.join("gone")).is_empty());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn the_container_title_is_read_from_the_feature_only() {
        let d = tmpdir("mkv");
        assert_eq!(container_title(&d), None);
        // A non-Matroska feature has no Title to read.
        std::fs::write(d.join("movie.mp4"), vec![0u8; 4096]).unwrap();
        assert_eq!(container_title(&d), None);
        let _ = std::fs::remove_dir_all(&d);

        // The real thing, repacker credit and all.
        let d = tmpdir("mkv2");
        let mux = nzbkit::mkv::test_mux_titled(
            Some(5400.0),
            Some((1920, 1080)),
            Some("Example.Movie.2019.1080p.BluRay.x264-GRP, RMZ.cr"),
        );
        // Padded with a Void element the way a real mux is, so the
        // feature is the biggest file here and still parses.
        let mut feature = mux.clone();
        feature.extend(nzbkit::mkv::el(&[0xEC], &vec![0u8; 8000]));
        std::fs::write(d.join("movie.mkv"), &feature).unwrap();
        assert_eq!(
            container_title(&d).as_deref(),
            Some("Example.Movie.2019.1080p.BluRay.x264-GRP")
        );
        // The SAMPLE is not the feature: its Title is the sample's, and
        // reading it would name the release after a teaser.
        let sample = nzbkit::mkv::test_mux_titled(None, None, Some("Wrong.Sample.Name-XXX"));
        std::fs::write(d.join("movie-sample.mkv"), &sample).unwrap();
        assert_eq!(
            container_title(&d).as_deref(),
            Some("Example.Movie.2019.1080p.BluRay.x264-GRP")
        );
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn xrel_is_only_asked_when_it_could_help() {
        // A tagger-group release with no id: the case this exists for.
        assert_eq!(
            xrel_query("Supergirl.2026.1080P.WEB.H264-POKE", "").as_deref(),
            Some("Supergirl 2026")
        );
        // We already know the id.
        assert_eq!(
            xrel_query("Supergirl.2026.1080P.WEB.H264-POKE", "tt8814476"),
            None
        );
        // No group tag: not a release xREL indexes.
        assert_eq!(xrel_query("Supergirl 2026 1080p", ""), None);
        // Nothing to search with.
        assert_eq!(xrel_query(OBF, ""), None);
        assert_eq!(xrel_query("", ""), None);
        // A yearless release still asks, with what it has.
        assert_eq!(
            xrel_query("Some.Show.S01E02.1080p.WEB.h264-POKE", "").as_deref(),
            Some("Some Show")
        );
    }
}

//! Time+size correlation between the pre feed and obfuscated posts.
//!
//! The live public relays carry names and timestamps but no posted
//! filenames (measured, 1 Aug 2026), so exact matching can never fire
//! from them. What a pre DOES pin down is when a release existed and -
//! when a size is known - how big it is. An obfuscated post that
//! appears shortly after a pre, at the pre's size, in a group whose
//! content matches the pre's section, is *probably* that release.
//!
//! "Probably" is the operative word, and this module is the arithmetic
//! of it. The output is never a fact: it is a scored candidate, and the
//! score bands are set so that the one strong signal we can measure
//! (size agreement) is mandatory for anything automatic. Time plus
//! section alone tops out at [`SIZELESS_MAX`], below [`STRONG`], by
//! construction - at 40-200 pres an hour, "soon after" is not evidence.
//!
//! Pure functions only. The queries that feed [`CorrFeatures`] and the
//! writes that act on a score live in `index.rs`; the constants and the
//! arithmetic live here so they can be argued about (and tested) in one
//! place.
//!
//! # Correlation ships SUGGEST-ONLY. The bar for ever flipping auto
//!
//! (`predb_corr_auto`, default off - red-team of the indexer-
//! competitive bundle, 10 Aug 2026.) The only precision evidence ever
//! collected for auto-shaped candidates was ~22 hand-inspected rows
//! judged on the scorer's own inputs - zero byte-level ground truth -
//! and an independent audit showed the strong-suggestion pool was
//! dominated by a lane (single-`.7z` reposts) whose true byte-recovered
//! names provably differ from the correlated guesses. The download-time
//! revoke oracle only fires when someone downloads; the wall and the
//! newznab facade are exposed before that. So: suggestions are the
//! product, auto is an unproven extra.
//!
//! Do not enable `predb_corr_auto` by default (or advise a user to)
//! until a suggest-only production run has accumulated REAL
//! `pre_corr` verdicts - order 300+ 'confirmed' against ~0 'rejected'
//! (bounds the false-positive rate under ~1% at 95% confidence), PER
//! size bucket, with the byte-probe-nameable lanes excluded from the
//! population (they are, see `corr_naming_population`) - not another
//! eyeballed sample. `predb_corr_stats` is the meter.

use crate::release::Kind;

/// Below this a pair is not worth storing or showing.
pub const FLOOR: i32 = 55;
/// At or above: stored in `pre_corr`, surfaced as a suggestion.
pub const SUGGEST: i32 = 55;
/// At or above (AND [`CorrScore::size_pts`] >= [`STRONG_SIZE_MIN`]):
/// eligible for auto-apply, subject to the margin, mutual-best,
/// sibling and nuke gates that live index-side.
pub const STRONG: i32 = 80;
/// A STRONG score must carry at least this many size points - a tight,
/// sized match. Time can never substitute for size.
pub const STRONG_SIZE_MIN: i32 = 30;
/// Auto-apply needs best - runner_up > MARGIN. Crowded candidate sets
/// fail closed into suggestions.
pub const MARGIN: i32 = 25;
/// The most a sizeless pair can score: T(40) + C(10) + F(8). Kept as a
/// named constant because it is the safety property, and a test pins
/// it.
pub const SIZELESS_MAX: i32 = 58;

/// Posts more than this far BEFORE their pre are strangers (clock
/// slack for the rare leak that races its own announcement).
pub const DELTA_MIN: i64 = -3_600;
/// Posts more than this far AFTER the pre are strangers. Mirrors the
/// exact legs' RETRY_WINDOW: beyond it, reposts are Tier C's problem.
pub const DELTA_MAX: i64 = 14 * 86_400;

/// Sized-pair ratio acceptance range; outside it the pair is vetoed.
pub const RATIO_MIN: f64 = 0.70;
pub const RATIO_MAX: f64 = 1.45;

/// Wire bytes -> content bytes: the yEnc overhead factor.
pub const YENC_FACTOR: f64 = 1.03;

/// What a newsgroup is known to carry. Coarse on purpose: the map only
/// feeds a hard veto (a music pre cannot be a post in a video group)
/// and a small agreement bonus, so "unknown" must stay the common,
/// harmless answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupKind {
    Video,
    Music,
    Software,
    Book,
    Unknown,
}

/// Static newsgroup-name map. Substring/token matching over the group
/// name - newsgroups advertise their content in their names or not at
/// all, and a group this map cannot read simply contributes nothing.
pub fn group_kind(grp: &str) -> GroupKind {
    let g = grp.to_ascii_lowercase();
    let has_tok = |t: &str| g.split('.').any(|seg| seg == t);
    // Substrings that are unambiguous wherever they appear.
    if g.contains("x264")
        || g.contains("x265")
        || g.contains("hdtv")
        || g.contains("bluray")
        || g.contains("blu-ray")
        || g.contains("moovee")
        || g.contains("teevee")
        || g.contains("movie")
        || g.contains("dvdr")
        || has_tok("tv")
        || has_tok("series")
        || has_tok("uhd")
        || has_tok("hdr")
        || g.contains("multimedia")
    {
        return GroupKind::Video;
    }
    if g.contains("mp3")
        || g.contains("flac")
        || g.contains("lossless")
        || has_tok("music")
        || has_tok("sounds")
        || has_tok("audio")
    {
        return GroupKind::Music;
    }
    if g.contains("ebook")
        || g.contains("e-book")
        || has_tok("books")
        || has_tok("comics")
        || has_tok("mags")
    {
        return GroupKind::Book;
    }
    if has_tok("games")
        || has_tok("console")
        || has_tok("apps")
        || has_tok("software")
        || has_tok("warez")
        || g.contains("0day")
        || has_tok("iso")
    {
        return GroupKind::Software;
    }
    GroupKind::Unknown
}

/// Collapse a release kind (from classifying the pre's title, or from a
/// predb section string) into the group map's vocabulary.
pub fn kind_class(k: &Kind) -> GroupKind {
    match k {
        Kind::Movie | Kind::Tv => GroupKind::Video,
        Kind::Music => GroupKind::Music,
        Kind::Book => GroupKind::Book,
        Kind::Software => GroupKind::Software,
        Kind::Other | Kind::Custom(_) => GroupKind::Unknown,
    }
}

/// A predb section string ("TV-WEB-HD-X264", "MP3-WEB", "FLAC-ViNYL",
/// "NSW", "EBOOK") mapped the same way. More trustworthy than
/// classifying the title when both exist - the section is the pre
/// ecosystem's own filing.
pub fn section_class(section: &str) -> GroupKind {
    let s = section.to_ascii_uppercase();
    if s.contains("MP3") || s.contains("FLAC") || s.contains("MUSIC") || s.contains("AUDIO") {
        return GroupKind::Music;
    }
    if s.contains("EBOOK") || s.contains("ABOOK") || s.contains("COMIC") {
        return GroupKind::Book;
    }
    if s.contains("X264")
        || s.contains("X265")
        || s.contains("H264")
        || s.contains("H265")
        || s.contains("XVID")
        || s.contains("TV")
        || s.contains("BLURAY")
        || s.contains("DVDR")
        || s.contains("MDVDR")
        || s.contains("SPORTS")
        || s.contains("MOVIE")
    {
        return GroupKind::Video;
    }
    if s.contains("GAME")
        || s.contains("NSW")
        || s.contains("PS3")
        || s.contains("PS4")
        || s.contains("PS5")
        || s.contains("XBOX")
        || s.contains("0DAY")
        || s.contains("APP")
    {
        return GroupKind::Software;
    }
    GroupKind::Unknown
}

/// Everything the scorer looks at, gathered by the caller. All facts,
/// no queries.
#[derive(Debug, Clone)]
pub struct CorrFeatures {
    /// `release.first_posted - pre.pt`, seconds. Positive = the post
    /// trails the pre, the normal direction.
    pub delta: i64,
    /// The pre's announced size in bytes (0 = the feed did not say).
    pub sz: u64,
    /// The release's estimated CONTENT bytes: wire bytes minus
    /// identified par2, divided by [`YENC_FACTOR`].
    pub est_content: u64,
    /// Whether any par2 was identified and subtracted. When false, the
    /// disguised-par2 pattern means a true match reads 5-18% heavy,
    /// never light - the reason the [1.00, 1.18] band exists.
    pub par2_identified: bool,
    /// The pre's content class (section string first, classified title
    /// as fallback).
    pub kind_pre: GroupKind,
    /// The release's newsgroup class from [`group_kind`].
    pub grp_kind: GroupKind,
    /// The pre's announced file count (0 = absent).
    pub fl: u32,
    /// The release's non-par2 file count.
    pub rel_files: u32,
    /// Movie/TV/Music kind parsed from the pre TITLE (not the section),
    /// with its resolution - feeds the sizeless plausibility prior.
    pub kind_title: Kind,
    pub res_pre: Option<String>,
}

/// The score, split so the auto gate can require its size component.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CorrScore {
    pub total: i32,
    pub size_pts: i32,
    /// est_content / sz (0.0 when sizeless) - stored for the audit
    /// trail.
    pub ratio_milli: u32,
}

impl CorrScore {
    pub fn strong(&self) -> bool {
        self.total >= STRONG && self.size_pts >= STRONG_SIZE_MIN
    }
    pub fn ratio(&self) -> f64 {
        self.ratio_milli as f64 / 1000.0
    }
}

/// GB in bytes, for the plausibility bands.
const GB: f64 = 1024.0 * 1024.0 * 1024.0;

/// Size band a pre's own title implies, used ONLY for sizeless pairs:
/// (min, max) content bytes, or None when the title pins nothing down.
fn plausible_band(kind: &Kind, res: Option<&str>) -> Option<(f64, f64)> {
    let r = res.unwrap_or("");
    match kind {
        Kind::Tv if matches!(r, "720p" | "1080p" | "2160p") => Some((0.3 * GB, 12.0 * GB)),
        Kind::Movie if r == "1080p" => Some((1.5 * GB, 40.0 * GB)),
        Kind::Movie if r == "2160p" => Some((4.0 * GB, 120.0 * GB)),
        Kind::Music => Some((0.05 * GB, 3.0 * GB)),
        _ => None,
    }
}

/// Score one (pre, release) pair. `None` = vetoed: the pair is not a
/// candidate at all and must not be stored, ranked, or shown.
pub fn corr_score(f: &CorrFeatures) -> Option<CorrScore> {
    // Vetoes first; every one of them is a "wrong name waiting to
    // happen" and none of them is recoverable by other signals.
    if f.delta < DELTA_MIN || f.delta > DELTA_MAX {
        return None;
    }
    let ratio = if f.sz > 0 {
        f.est_content as f64 / f.sz as f64
    } else {
        0.0
    };
    if f.sz > 0 && !(RATIO_MIN..=RATIO_MAX).contains(&ratio) {
        return None;
    }
    if f.grp_kind != GroupKind::Unknown
        && f.kind_pre != GroupKind::Unknown
        && f.grp_kind != f.kind_pre
    {
        return None;
    }

    // T - time. Fast posts are the signal; the tail is nearly flat
    // because at feed rates "three days later" barely discriminates.
    let d = f.delta;
    let t = if d < 0 {
        20 // inside the -1 h clock slack
    } else if d <= 30 * 60 {
        40
    } else if d <= 2 * 3_600 {
        34
    } else if d <= 6 * 3_600 {
        26
    } else if d <= 86_400 {
        16
    } else if d <= 3 * 86_400 {
        8
    } else {
        3
    };

    // S - size, the only strong signal. First matching band wins; the
    // [1.00, 1.18] band is the disguised-par2 asymmetry: when the par2
    // volumes could not be identified they are still IN est_content, so
    // a true match reads heavy, never light.
    let s = if f.sz == 0 {
        0
    } else {
        let dev = (ratio - 1.0).abs();
        if dev <= 0.03 {
            40
        } else if dev <= 0.08 {
            30
        } else if (1.0..=1.18).contains(&ratio) && !f.par2_identified {
            22
        } else if dev <= 0.20 {
            8
        } else {
            0
        }
    };

    // C - section/kind agreement (contradiction was a veto above).
    let c = if f.grp_kind != GroupKind::Unknown && f.grp_kind == f.kind_pre {
        10
    } else {
        0
    };

    // F - file count. Weak on purpose: a reposter's 7z re-container
    // does not preserve the scene RAR set's file count, so F may only
    // corroborate or mildly object, never kill.
    let fcnt = if f.fl > 0 {
        let diff = (i64::from(f.fl) - i64::from(f.rel_files)).unsigned_abs();
        let tol = std::cmp::max(2, (f.fl as u64).div_ceil(4));
        if diff <= tol {
            8
        } else if u64::from(f.rel_files) > 3 * u64::from(f.fl)
            || u64::from(f.fl) > 3 * u64::from(f.rel_files)
        {
            -10
        } else {
            0
        }
    } else {
        0
    };

    // P - plausibility prior, sizeless pairs only: a pre whose title
    // says "2160p movie" against a 300 MB post is not a candidate worth
    // suggesting, even though nothing above can prove it wrong.
    let p = if f.sz == 0 {
        match plausible_band(&f.kind_title, f.res_pre.as_deref()) {
            Some((lo, hi)) => {
                let e = f.est_content as f64;
                if e < lo || e > hi { -12 } else { 0 }
            }
            None => 0,
        }
    } else {
        0
    };

    Some(CorrScore {
        total: t + s + c + fcnt + p,
        size_pts: s,
        ratio_milli: (ratio * 1000.0).round().clamp(0.0, u32::MAX as f64) as u32,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> CorrFeatures {
        CorrFeatures {
            delta: 600,
            sz: 0,
            est_content: 5 << 30,
            par2_identified: false,
            kind_pre: GroupKind::Video,
            grp_kind: GroupKind::Video,
            fl: 0,
            rel_files: 40,
            kind_title: Kind::Other,
            res_pre: None,
        }
    }

    /// THE safety property: no sizeless pair may reach STRONG, ever.
    /// Sweeps the whole sizeless input space (every band of every other
    /// term) rather than trusting the arithmetic comment.
    #[test]
    fn a_sizeless_pair_can_never_reach_strong() {
        let mut worst = i32::MIN;
        for delta in [
            -3599,
            0,
            60,
            1800,
            3600,
            7200,
            21600,
            86400,
            259200,
            86400 * 13,
        ] {
            for (grp, pre) in [
                (GroupKind::Video, GroupKind::Video),
                (GroupKind::Unknown, GroupKind::Video),
                (GroupKind::Unknown, GroupKind::Unknown),
            ] {
                for (fl, rel) in [(0u32, 40u32), (40, 40), (40, 41), (3, 200), (200, 3)] {
                    let f = CorrFeatures {
                        delta,
                        sz: 0,
                        grp_kind: grp,
                        kind_pre: pre,
                        fl,
                        rel_files: rel,
                        ..base()
                    };
                    if let Some(s) = corr_score(&f) {
                        assert_eq!(s.size_pts, 0);
                        assert!(!s.strong(), "sizeless STRONG at {f:?}");
                        worst = worst.max(s.total);
                    }
                }
            }
        }
        assert_eq!(worst, SIZELESS_MAX, "the ceiling moved - re-derive it");
        assert!(SIZELESS_MAX < STRONG);
    }

    #[test]
    fn the_vetoes_veto() {
        // Post predates the pre by more than the clock slack.
        assert!(
            corr_score(&CorrFeatures {
                delta: -3601,
                ..base()
            })
            .is_none()
        );
        // Post trails by more than the window.
        assert!(
            corr_score(&CorrFeatures {
                delta: DELTA_MAX + 1,
                ..base()
            })
            .is_none()
        );
        // Sized and wildly off, both directions.
        let sz = 10u64 << 30;
        for est in [(6u64) << 30, 15 << 30] {
            assert!(
                corr_score(&CorrFeatures {
                    sz,
                    est_content: est,
                    ..base()
                })
                .is_none(),
                "ratio {} escaped the veto",
                est as f64 / sz as f64
            );
        }
        // Kind contradiction: a music pre against a video group.
        assert!(
            corr_score(&CorrFeatures {
                kind_pre: GroupKind::Music,
                grp_kind: GroupKind::Video,
                ..base()
            })
            .is_none()
        );
        // ...but unknown on either side is not a contradiction.
        assert!(
            corr_score(&CorrFeatures {
                kind_pre: GroupKind::Unknown,
                grp_kind: GroupKind::Video,
                ..base()
            })
            .is_some()
        );
    }

    #[test]
    fn the_favourable_corner_is_strong_and_only_just() {
        // Fast post, exact size, agreeing section: the auto shape.
        let sz = 5u64 << 30;
        let f = CorrFeatures {
            delta: 1200,
            sz,
            est_content: sz + (sz / 100), // 1% heavy
            par2_identified: true,
            ..base()
        };
        let s = corr_score(&f).unwrap();
        assert_eq!(s.total, 40 + 40 + 10);
        assert!(s.strong());
        // Same match a day and a half later: T collapses and STRONG is
        // out of reach without file-count help - by design.
        let slow = corr_score(&CorrFeatures {
            delta: 130_000,
            ..f
        })
        .unwrap();
        assert_eq!(slow.total, 8 + 40 + 10);
        assert!(!slow.strong());
    }

    #[test]
    fn the_hidden_par2_band_is_asymmetric() {
        let sz = 10u64 << 30;
        // 12% heavy with unidentified par2: the disguised-recovery shape.
        let heavy = CorrFeatures {
            sz,
            est_content: sz + sz * 12 / 100,
            par2_identified: false,
            ..base()
        };
        assert_eq!(corr_score(&heavy).unwrap().size_pts, 22);
        // Same deviation LIGHT: no such excuse exists - falls to the
        // wide band.
        let light = CorrFeatures {
            sz,
            est_content: sz - sz * 12 / 100,
            par2_identified: false,
            ..base()
        };
        assert_eq!(corr_score(&light).unwrap().size_pts, 8);
        // And with par2 identified, 12% heavy has no excuse either.
        let claimed = CorrFeatures {
            par2_identified: true,
            ..heavy
        };
        assert_eq!(corr_score(&claimed).unwrap().size_pts, 8);
    }

    #[test]
    fn file_count_corroborates_but_cannot_kill() {
        let close = corr_score(&CorrFeatures {
            fl: 40,
            rel_files: 42,
            ..base()
        })
        .unwrap();
        let absurd = corr_score(&CorrFeatures {
            fl: 40,
            rel_files: 200,
            ..base()
        })
        .unwrap();
        let absent = corr_score(&CorrFeatures {
            fl: 0,
            rel_files: 200,
            ..base()
        })
        .unwrap();
        assert_eq!(close.total - absent.total, 8);
        assert_eq!(absent.total - absurd.total, 10);
        // The 7z-recontainer case: fl known, count off but not 3x -
        // neither bonus nor penalty.
        let recontained = corr_score(&CorrFeatures {
            fl: 40,
            rel_files: 80,
            ..base()
        })
        .unwrap();
        assert_eq!(recontained.total, absent.total);
    }

    #[test]
    fn sizeless_implausibility_costs_and_size_supersedes() {
        // A "2160p movie" pre against a 500 MB post, sizeless: penalized.
        let poor = CorrFeatures {
            est_content: 500 << 20,
            kind_title: Kind::Movie,
            res_pre: Some("2160p".into()),
            ..base()
        };
        let with = corr_score(&poor).unwrap();
        let without = corr_score(&CorrFeatures {
            kind_title: Kind::Other,
            ..poor.clone()
        })
        .unwrap();
        assert_eq!(without.total - with.total, 12);
        // The moment a size exists, P stands down (S owns plausibility).
        let sized = corr_score(&CorrFeatures {
            sz: 480 << 20,
            ..poor
        })
        .unwrap();
        assert!(sized.size_pts > 0);
    }

    #[test]
    fn negative_delta_inside_slack_scores_the_leak_band() {
        let s = corr_score(&CorrFeatures {
            delta: -600,
            ..base()
        })
        .unwrap();
        // T=20, C=10.
        assert_eq!(s.total, 30);
    }

    #[test]
    fn group_and_section_maps_read_the_obvious_names() {
        assert_eq!(group_kind("alt.binaries.x264"), GroupKind::Video);
        assert_eq!(group_kind("alt.binaries.hdtv.x265"), GroupKind::Video);
        assert_eq!(group_kind("alt.binaries.teevee"), GroupKind::Video);
        assert_eq!(group_kind("alt.binaries.sounds.mp3"), GroupKind::Music);
        assert_eq!(group_kind("alt.binaries.e-books"), GroupKind::Book);
        assert_eq!(
            group_kind("alt.binaries.games.nintendo"),
            GroupKind::Software
        );
        assert_eq!(group_kind("alt.binaries.misc"), GroupKind::Unknown);
        // "tv" must match as a token, not a substring - a.b.hdtv is
        // already caught above, but "furtive" must not read as TV.
        assert_eq!(group_kind("alt.binaries.furtive"), GroupKind::Unknown);

        assert_eq!(section_class("TV-WEB-HD-X264"), GroupKind::Video);
        assert_eq!(section_class("X265-HD"), GroupKind::Video);
        assert_eq!(section_class("MP3-WEB"), GroupKind::Music);
        assert_eq!(section_class("FLAC-ViNYL"), GroupKind::Music);
        assert_eq!(section_class("NSW"), GroupKind::Software);
        assert_eq!(section_class("EBOOK"), GroupKind::Book);
        assert_eq!(section_class(""), GroupKind::Unknown);
    }
}

//! User-definable categories (TODO 24D).
//!
//! The built-in classifier only knows Movie / Tv / Software / Other, so
//! sport, motorsport, wrestling, podcasts, audiobooks and comics all land
//! in Movie or Other - the same root cause as the F1 dupe bug (279f787),
//! where `Formula1.2026.Round11...` parsed as Movie{"Formula1", 2026} and
//! every session of a season collapsed to one identity.
//!
//! A `CustomCategory` is a user-defined kind: a display name, a slug that
//! becomes the stored `kind` value, match rules riding the SAME
//! regex-or-keyword engine as Smart Folders (`pat_match` here is the one
//! implementation; smart.rs delegates to it), and a declared BASE
//! BEHAVIOR that answers the finalize_names coupling explicitly: does a
//! release in this category inherit movie-like cleanup/rename, tv-like
//! filing, or neither.
//!
//! Classification: `classify(stem, cats)` parses as usual, then the first
//! matching category (list order = priority, like Smart Folders) rewrites
//! `Parsed.kind` to `Kind::Custom(slug)` and rebuilds the dedupe key so
//! date/event releases never collapse by title+year - the key keeps the
//! identity tail (`extra`) the built-in movie key throws away.

use serde::{Deserialize, Serialize};

use crate::release::{self, Kind, Parsed};

/// Which built-in behavior a custom category inherits at completion time
/// (junk sweep / keep-media-only / auto-rename / Season filing) and for
/// anything else gated on Movie|Tv. Explicit, because a kind that is
/// neither silently loses those behaviors - that coupling produced bugs
/// twice in the week this was designed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BaseBehavior {
    /// Movie-like: junk sweep / keep-media-only apply; auto-rename may
    /// build "Title (Year)" names (it still declines event posts whose
    /// identity lives after the year - the F1 guard).
    Movie,
    /// TV-like: junk sweep applies; episodes rename / Season-file.
    Tv,
    /// Neither: files are left exactly as posted (like Software/Other).
    /// The safe default - keep-media-only DELETES non-media files, which
    /// is data loss for a comics or audiobook category.
    #[default]
    None,
}

/// One user-defined category, as stored in settings.json
/// (`custom_categories`, an ordered array - first match wins).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomCategory {
    /// Stable identity: the stored `kind` value and the API filter value.
    /// Lowercase `[a-z0-9-]`, never one of the built-in four. Renaming
    /// the display name keeps the slug, so indexed rows stay reachable.
    pub slug: String,
    /// Display name, shown as-is (user text - not translated).
    #[serde(default)]
    pub name: String,
    /// Regex on the release name (case-insensitive), falling back to a
    /// plain keyword substring when it doesn't compile - identical
    /// semantics to a Smart Folder rule's `match`.
    #[serde(default, rename = "match")]
    pub pattern: String,
    /// Skip this category when THIS matches (same regex-or-keyword).
    #[serde(default)]
    pub not_match: String,
    /// Inherited completion behavior - see [`BaseBehavior`].
    #[serde(default)]
    pub base: BaseBehavior,
}

/// Case-insensitive regex match, or keyword substring if the pattern
/// isn't a valid regex. Empty pattern matches nothing HERE (a category
/// with no rule classifies nothing) - note this differs from a Smart
/// Folder rule, where an empty pattern is a catch-all route; a catch-all
/// CATEGORY would swallow the whole index.
pub fn cat_match(pattern: &str, name: &str) -> bool {
    let p = pattern.trim();
    if p.is_empty() {
        return false;
    }
    pat_match(p, name)
}

/// The shared rule-matching primitive (Smart Folders semantics): empty
/// pattern matches everything, otherwise case-insensitive regex with a
/// keyword-substring fallback. smart.rs delegates here so there is
/// exactly one rule engine in the tree.
pub fn pat_match(pattern: &str, name: &str) -> bool {
    let p = pattern.trim();
    if p.is_empty() {
        return true;
    }
    match regex_lite::RegexBuilder::new(p)
        .case_insensitive(true)
        .build()
    {
        Ok(re) => re.is_match(name),
        Err(_) => name.to_ascii_lowercase().contains(&p.to_ascii_lowercase()),
    }
}

/// What a rule's pattern is actually going to do, for the editor to show.
///
/// [`pat_match`] deliberately never fails: a pattern that will not compile
/// falls back to a plain keyword search, and that fallback is what makes
/// the documented "plain keywords work too" true. The cost is that both
/// ways of getting a rule wrong are silent, and they fail in OPPOSITE
/// directions, which is why one verdict is not enough:
///
/// - `*anime*` does not compile (nothing to repeat before the first `*`),
///   so it becomes a literal search for those seven characters and can
///   never match anything. A rule that quietly does nothing looks exactly
///   like a rule that has not fired yet, so it can sit broken for weeks.
/// - `!*` DOES compile - as "zero or more `!`" - so it matches every
///   release there is. Smart Folders is first-match-wins and a match
///   overrides an *arr's explicit `cat=`, so one rule like that at the top
///   of the list silently misroutes the whole queue.
///
/// Nothing here changes what matches. It reports what the engine already
/// decided, so a row can be marked. Reported by `get_config` alongside
/// each rule rather than stored on it - see `smart_folders` in
/// serve/settings.rs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PatternVerdict {
    /// Compiled, and selective. Nothing to say.
    Ok,
    /// Did not compile, so it is being searched for as literal text.
    Literal,
    /// Compiled, and matches every possible name.
    MatchesEverything,
}

/// Classify a pattern the way [`pat_match`] will treat it.
///
/// An empty pattern is [`PatternVerdict::Ok`], not `MatchesEverything`:
/// for a Smart Folder that is the documented catch-all (a size-only rule
/// has no `match`), and for a category `cat_match` rejects it outright.
/// Flagging it would be a warning on the one shape that is deliberate.
///
/// "Matches everything" is decided by asking whether the compiled regex
/// matches the EMPTY string. `is_match` is an unanchored search, so a
/// pattern that can match nothing-at-all necessarily also matches every
/// input that contains it, which is all of them. That catches `!*`, `.*`,
/// `a?` and anything else of the shape without a list of special cases.
pub fn pat_verdict(pattern: &str) -> PatternVerdict {
    let p = pattern.trim();
    if p.is_empty() {
        return PatternVerdict::Ok;
    }
    match regex_lite::RegexBuilder::new(p)
        .case_insensitive(true)
        .build()
    {
        Ok(re) if re.is_match("") => PatternVerdict::MatchesEverything,
        Ok(_) => PatternVerdict::Ok,
        Err(_) => PatternVerdict::Literal,
    }
}

/// WHY a pattern is [`PatternVerdict::Literal`], in the engine's words.
///
/// The verdict says what is happening; this says what to fix. regex_lite
/// keeps its reasons to one plain sentence ("uncounted repetition
/// operator must be applied to a sub-expression" for `*anime*`), which is
/// exactly the size a save answer can carry, so the compile error is
/// reported rather than paraphrased - a hand-written summary would drift
/// from the engine the moment the dependency moved.
///
/// `None` for anything [`pat_match`] will treat as a regex, including an
/// empty pattern: only the fallback-to-keyword shape has an error to
/// report. The same builder configuration as `pat_match` on purpose -
/// judging a different compilation than the one that runs would be worse
/// than saying nothing.
pub fn pat_compile_error(pattern: &str) -> Option<String> {
    let p = pattern.trim();
    if p.is_empty() {
        return None;
    }
    regex_lite::RegexBuilder::new(p)
        .case_insensitive(true)
        .build()
        .err()
        .map(|e| e.to_string())
}

impl CustomCategory {
    /// Does this category claim the release name?
    pub fn matches(&self, name: &str) -> bool {
        if !cat_match(&self.pattern, name) {
            return false;
        }
        if !self.not_match.trim().is_empty() && pat_match(&self.not_match, name) {
            return false;
        }
        true
    }
}

/// The built-in `kind` values a slug may never shadow. Music and book
/// arrived with the audio/ebook parser and were missed here, so a
/// category named "Music" slugged to "music", validated, and then
/// collided with the built-in: the wall drew two identically-named tabs,
/// every built-in music card took the user's category label, and the
/// enricher ran MusicBrainz against a CUSTOM category - which the
/// provider chain promises never to do, because "Formula 1 Round 11" has
/// no meaningful identity at any metadata provider.
pub const RESERVED_KINDS: [&str; 6] = ["movie", "tv", "software", "other", "music", "book"];

/// Rename any slug that a LATER release turned into a built-in kind.
///
/// "music" and "book" only became reserved when the audio/ebook parser
/// landed, so a user could already have saved a category slugged that
/// way. Without this the whole saved list fails validation at startup
/// and is discarded with a log line, taking every OTHER category they
/// configured with it - a silent, total loss of their work for one
/// newly-conflicting name.
///
/// Renaming rather than dropping is the right direction: the colliding
/// category was already misbehaving (two identically-named tabs, and the
/// enricher treating it as a built-in kind), so a distinct slug is a
/// strict improvement AND keeps their rules. Returns the renames so the
/// caller can tell them what happened.
pub fn migrate_reserved_slugs(cats: &mut [CustomCategory]) -> Vec<(String, String)> {
    let taken: Vec<String> = cats.iter().map(|c| c.slug.clone()).collect();
    let mut changed = Vec::new();
    for c in cats.iter_mut() {
        if !RESERVED_KINDS.contains(&c.slug.as_str()) {
            continue;
        }
        let mut candidate = format!("{}-custom", c.slug);
        let mut n = 2;
        while RESERVED_KINDS.contains(&candidate.as_str()) || taken.iter().any(|t| t == &candidate)
        {
            candidate = format!("{}-custom{n}", c.slug);
            n += 1;
        }
        changed.push((c.slug.clone(), candidate.clone()));
        c.slug = candidate;
    }
    changed
}

/// Slug from a display name: lowercase, alnum runs joined by '-'
/// ("Formula 1" → "formula-1"). Empty when nothing survives.
pub fn slugify(name: &str) -> String {
    name.to_lowercase()
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|t| !t.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

/// Validate a category list as a whole (the settings API rejects a save
/// that fails). Checks: non-empty valid slugs, no reserved names, no
/// duplicates, and every regex either compiles or reads as a keyword
/// (which always "compiles" - so only emptiness can fail a pattern).
pub fn validate(cats: &[CustomCategory]) -> Result<(), String> {
    let mut seen = std::collections::HashSet::new();
    for c in cats {
        if c.slug.is_empty()
            || !c
                .slug
                .chars()
                .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-')
        {
            return Err(format!(
                "category slug {:?} is invalid (lowercase letters, digits and '-' only)",
                c.slug
            ));
        }
        if RESERVED_KINDS.contains(&c.slug.as_str()) {
            return Err(format!("category slug {:?} is a built-in kind", c.slug));
        }
        if !seen.insert(c.slug.clone()) {
            return Err(format!("duplicate category slug {:?}", c.slug));
        }
        if c.pattern.trim().is_empty() {
            return Err(format!(
                "category {:?} has no match rule (it would classify nothing)",
                if c.name.is_empty() { &c.slug } else { &c.name }
            ));
        }
    }
    Ok(())
}

/// Order-independent fingerprint-of-record for a category config: any
/// change to it (order included - order is priority) yields a new value.
/// The indexer stamps it in `kv` so a settings change triggers exactly
/// one re-classification pass.
pub fn config_hash(cats: &[CustomCategory]) -> String {
    // Stable serde output; a hash would need a new dependency and the
    // full JSON is small and just as comparable.
    serde_json::to_string(cats).unwrap_or_default()
}

/// Parse a release name and apply the user's categories: the first
/// matching category (order = priority, ahead of nothing else - the
/// built-in classifier already ran and its facts are kept) rewrites the
/// kind and the dedupe key.
///
/// Key shape, and why (the F1 lesson): the built-in movie key
/// "m:title:year" collapses every event of a season. A custom key keeps
/// every identity-bearing fact the parse found:
/// - season-marked releases group by title, like TV:  `c:<slug>:<title>`
///   (the season/episode facts tell the episodes apart downstream)
/// - daily-DATED releases add the date:  `c:<slug>:<title>:<yyyymmdd>`,
///   because a football or wrestling category is a stream of dated
///   events and title alone collapsed a whole season onto one identity;
///   the built-in TV key deliberately does not do this (a show's
///   episodes belong on one card)
/// - everything else:  `c:<slug>:<title>[:<year>][:<extra…>]` where
///   `extra` is the identity tail after the year ("round11 hungary
///   qualifying"), so two sessions never share a key.
pub fn classify(stem: &str, cats: &[CustomCategory]) -> Parsed {
    let mut p = release::parse_release(stem);
    apply_custom(&mut p, stem, cats);
    p
}

/// The override half of [`classify`], for callers that already parsed.
/// `stem` is matched raw (rules see the poster's name, not the parsed
/// title, same as Smart Folders matching the NZB name).
pub fn apply_custom(p: &mut Parsed, stem: &str, cats: &[CustomCategory]) {
    let Some(cat) = cats.iter().find(|c| c.matches(stem)) else {
        return;
    };
    let mut key = format!("c:{}:{}", cat.slug, release::norm_title(&p.title));
    // Season-marked and daily-dated posts already carry their identity in
    // season/episode/date facts and group by title, like TV. A daily
    // parse has kind Tv with no season.
    let tv_like = p.season.is_some() || (p.kind == Kind::Tv && p.episode.is_none());
    if tv_like {
        // ...except a dated post, where the date IS the identity: every
        // match of a football season, every episode of a dated wrestling
        // show. Without it "EPL.2026.08.15.Arsenal.vs.Chelsea" and
        // "EPL.2026.08.22.Liverpool.vs.Everton" were both "c:football:epl"
        // and the watchlist grabbed one fixture per season.
        if let Some(d) = &p.date {
            key.push(':');
            key.push_str(d);
            // ...and after the date, which event of that day it is:
            // "Arsenal.vs.Spurs" against "Liverpool.vs.Everton", both
            // played on the 22nd. Same role `extra` plays after a
            // movie-year for an F1 session.
            if !p.extra.is_empty() {
                key.push(':');
                key.push_str(&release::norm_title(&p.extra.join(" ")));
            }
        }
    } else {
        if let Some(y) = p.year {
            key.push_str(&format!(":{y}"));
        }
        if !p.extra.is_empty() {
            key.push(':');
            key.push_str(&release::norm_title(&p.extra.join(" ")));
        }
    }
    p.kind = Kind::Custom(cat.slug.clone());
    p.key = key;
}

/// The completion behavior for a parsed kind: built-ins map to
/// themselves, a custom kind to its declared base (or None when the
/// category has since been deleted - files untouched is the safe read).
pub fn base_of(kind: &Kind, cats: &[CustomCategory]) -> BaseBehavior {
    match kind {
        Kind::Movie => BaseBehavior::Movie,
        Kind::Tv => BaseBehavior::Tv,
        // Music and books get no completion behaviour: the junk sweep
        // and auto-rename are built around a film's or an episode's file
        // layout, and an album folder of numbered tracks is neither.
        Kind::Software | Kind::Other | Kind::Music | Kind::Book => BaseBehavior::None,
        Kind::Custom(slug) => cats
            .iter()
            .find(|c| &c.slug == slug)
            .map(|c| c.base)
            .unwrap_or(BaseBehavior::None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn f1() -> Vec<CustomCategory> {
        vec![CustomCategory {
            slug: "formula-1".into(),
            name: "Formula 1".into(),
            pattern: r"^formula\.?1\.".into(),
            not_match: String::new(),
            base: BaseBehavior::Movie,
        }]
    }

    #[test]
    fn f1_sessions_get_distinct_keys_in_their_category() {
        let cats = f1();
        let quali = classify(
            "Formula1.2026.Round11.Hungary.Qualifying.F1TV.WEB-DL.2160p.HLG.H265.DDP5.1.English-MWR",
            &cats,
        );
        let show = classify(
            "Formula1.2026.Round11.Hungary.Post-Qualifying.Show.F1TV.WEB-DL.1080p.H264.English-MWR",
            &cats,
        );
        let race12 = classify("Formula1.2026.Round12.Spa.Race.1080p.WEB-DL-MWR", &cats);
        assert_eq!(quali.kind, Kind::Custom("formula-1".into()));
        assert_eq!(show.kind, Kind::Custom("formula-1".into()));
        // The whole point: three releases, three keys - not one
        // "m:formula1:2026" for the entire season.
        assert_ne!(quali.key, show.key);
        assert_ne!(quali.key, race12.key);
        assert!(
            quali.key.starts_with("c:formula-1:formula1:2026:"),
            "{}",
            quali.key
        );
        // Same session in two qualities = one key (furniture never
        // differentiates - carried over from the built-in keys).
        let quali720 = classify(
            "Formula1.2026.Round11.Hungary.Qualifying.F1TV.WEB-DL.720p.H264.English-GRP",
            &cats,
        );
        assert_eq!(quali.key, quali720.key);
    }

    #[test]
    fn unmatched_stems_keep_builtin_classification() {
        let cats = f1();
        let m = classify("The.Matrix.1999.1080p.BluRay.x264-GRP", &cats);
        assert_eq!(m.kind, Kind::Movie);
        assert_eq!(m.key, "m:the matrix:1999");
        // And with no categories at all, classify == parse_release.
        let p = classify("Severance.S02E03.1080p.WEB-DL", &[]);
        assert_eq!(p.kind, Kind::Tv);
        assert_eq!(p.key, "t:severance");
    }

    #[test]
    fn season_marked_customs_group_by_title_like_tv() {
        let cats = vec![CustomCategory {
            slug: "wrestling".into(),
            name: "Wrestling".into(),
            pattern: "wwe|aew".into(),
            not_match: String::new(),
            base: BaseBehavior::Tv,
        }];
        let a = classify("WWE.Raw.S2026E015.1080p.WEB.h264-GRP", &cats);
        let b = classify("WWE.Raw.S2026E016.1080p.WEB.h264-GRP", &cats);
        assert_eq!(a.kind, Kind::Custom("wrestling".into()));
        // Episodes of one show share a card; season/episode facts remain.
        assert_eq!(a.key, b.key);
        assert_eq!(a.key, "c:wrestling:wwe raw");
        assert_eq!((a.season, a.episode), (Some(2026), Some(15)));
    }

    #[test]
    fn daily_dated_customs_key_per_date() {
        let cats = vec![CustomCategory {
            slug: "podcasts".into(),
            name: "Podcasts".into(),
            pattern: "daily.show".into(),
            not_match: String::new(),
            base: BaseBehavior::None,
        }];
        let a = classify("The.Daily.Show.2026.07.21.Guest.1080p.WEB.h264-GRP", &cats);
        let b = classify("The.Daily.Show.2026.07.22.Other.1080p.WEB.h264-GRP", &cats);
        assert_eq!(a.kind, Kind::Custom("podcasts".into()));
        // The date is the identity: two days, two keys. (The built-in TV
        // key stays title-only - a show's episodes share a wall card.)
        // The tail after the date rides along, which is what separates
        // two events of ONE day; the cost is that a same-day repost
        // described differently ("…07.21.Jon.Stewart") reads as another
        // event. Deliberate: a second copy is visible and recoverable,
        // a whole matchday silently reduced to one fixture is not.
        assert_eq!(a.key, "c:podcasts:the daily show:20260721:guest");
        assert_ne!(a.key, b.key);
        assert_eq!(
            release::parse_release("The.Daily.Show.2026.07.21.Guest.1080p").key,
            "t:the daily show"
        );
        // Same day in two qualities is still one identity.
        let a720 = classify("The.Daily.Show.2026.07.21.Guest.720p.WEB.h264-OTHER", &cats);
        assert_eq!(a.key, a720.key);
        // The compact convention normalizes to the same shape.
        let compact = classify("The.Daily.Show.260721.Guest.1080p.WEB-GRP", &cats);
        assert_eq!(compact.key, a.key);

        // A whole football season: every fixture its own identity, which
        // is what makes a sports watchlist possible at all.
        let foot = vec![CustomCategory {
            slug: "football".into(),
            name: "Football".into(),
            pattern: "^epl".into(),
            not_match: String::new(),
            base: BaseBehavior::None,
        }];
        let m1 = classify(
            "EPL.2026.08.15.Arsenal.vs.Chelsea.1080p.WEB.h264-VERUM",
            &foot,
        );
        let m2 = classify(
            "EPL.2026.08.22.Liverpool.vs.Everton.1080p.WEB.h264-VERUM",
            &foot,
        );
        let m3 = classify("EPL.2026.08.22.Arsenal.vs.Spurs.720p.WEB.h264-VERUM", &foot);
        assert_eq!(m1.key, "c:football:epl:20260815:arsenal vs chelsea");
        assert_ne!(m1.key, m2.key);
        // Two fixtures on ONE Saturday are two events, not one.
        assert_ne!(m2.key, m3.key);
        // The same fixture in another quality is still one event: only
        // identity tokens reach the tail, never resolution or group.
        let m3_hd = classify(
            "EPL.2026.08.22.Arsenal.vs.Spurs.1080p.WEB.h264-OTHER",
            &foot,
        );
        assert_eq!(m3.key, m3_hd.key);
    }

    #[test]
    fn first_match_wins_and_not_match_skips() {
        let cats = vec![
            CustomCategory {
                slug: "motogp".into(),
                name: "MotoGP".into(),
                pattern: "motogp".into(),
                not_match: "moto2|moto3".into(),
                base: BaseBehavior::Movie,
            },
            CustomCategory {
                slug: "motorsport".into(),
                name: "Motorsport".into(),
                pattern: "motogp|moto2|moto3|formula".into(),
                not_match: String::new(),
                base: BaseBehavior::Movie,
            },
        ];
        let gp = classify("MotoGP.2026.Round05.France.Race.1080p.WEB-DL-GRP", &cats);
        assert_eq!(gp.kind, Kind::Custom("motogp".into()));
        // not_match diverts Moto2 to the broader second category.
        let m2 = classify("MotoGP.Moto2.2026.Round05.France.Race.1080p.WEB-GRP", &cats);
        assert_eq!(m2.kind, Kind::Custom("motorsport".into()));
    }

    #[test]
    fn keyword_fallback_and_bad_regex() {
        let cats = vec![CustomCategory {
            slug: "audiobooks".into(),
            name: "Audiobooks".into(),
            pattern: "audiobook[".into(), // invalid regex → keyword
            not_match: String::new(),
            base: BaseBehavior::None,
        }];
        let p = classify("Some.Author.Title.Audiobook[.MP3-GRP", &cats);
        assert_eq!(p.kind, Kind::Custom("audiobooks".into()));
    }

    #[test]
    fn base_behavior_resolution() {
        let cats = f1();
        assert_eq!(base_of(&Kind::Movie, &cats), BaseBehavior::Movie);
        assert_eq!(base_of(&Kind::Tv, &cats), BaseBehavior::Tv);
        assert_eq!(base_of(&Kind::Software, &cats), BaseBehavior::None);
        assert_eq!(base_of(&Kind::Other, &cats), BaseBehavior::None);
        assert_eq!(
            base_of(&Kind::Custom("formula-1".into()), &cats),
            BaseBehavior::Movie
        );
        // Deleted category → behaviors off, files left as posted.
        assert_eq!(
            base_of(&Kind::Custom("gone".into()), &cats),
            BaseBehavior::None
        );
    }

    #[test]
    fn validation_rejects_bad_slugs_and_dupes() {
        let ok = f1();
        assert!(validate(&ok).is_ok());
        let mut bad = f1();
        bad[0].slug = "movie".into();
        assert!(validate(&bad).unwrap_err().contains("built-in"));
        let mut bad = f1();
        bad[0].slug = "Formula 1".into();
        assert!(validate(&bad).is_err());
        let mut two = f1();
        two.push(two[0].clone());
        assert!(validate(&two).unwrap_err().contains("duplicate"));
        let mut empty_rule = f1();
        empty_rule[0].pattern = "  ".into();
        assert!(validate(&empty_rule).unwrap_err().contains("no match rule"));
        // Empty list is fine (the feature off).
        assert!(validate(&[]).is_ok());
    }

    #[test]
    fn slugify_shapes() {
        assert_eq!(slugify("Formula 1"), "formula-1");
        assert_eq!(slugify("  Comics & Manga!"), "comics-manga");
        assert_eq!(slugify("日本語"), "");
    }

    #[test]
    fn settings_round_trip() {
        let cats = f1();
        let json = serde_json::to_string(&cats).unwrap();
        // The rule field serializes as "match", riding the Smart Folder
        // syntax users already know.
        assert!(json.contains("\"match\""), "{json}");
        let back: Vec<CustomCategory> = serde_json::from_str(&json).unwrap();
        assert_eq!(back, cats);
        // Minimal form: base defaults to none (the safe behavior).
        let min: Vec<CustomCategory> =
            serde_json::from_str(r#"[{"slug":"comics","match":"cbz|cbr"}]"#).unwrap();
        assert_eq!(min[0].base, BaseBehavior::None);
        assert_eq!(config_hash(&cats), config_hash(&f1()));
        assert_ne!(config_hash(&cats), config_hash(&min));
    }

    /// "music"/"book" only became reserved when the audio/ebook parser
    /// landed. A user could already have saved a category slugged that
    /// way, and validate() rejects the LIST as a whole, so the startup
    /// path would have discarded every OTHER category they configured.
    #[test]
    fn a_newly_reserved_slug_is_renamed_not_dropped() {
        let mk = |slug: &str, name: &str| CustomCategory {
            slug: slug.into(),
            name: name.into(),
            pattern: r"^x\.".into(),
            not_match: String::new(),
            base: BaseBehavior::Movie,
        };
        let mut cats = vec![mk("music", "Music"), mk("formula-1", "Formula 1")];
        assert!(
            validate(&cats).is_err(),
            "the collision must be a validation error"
        );

        let renamed = migrate_reserved_slugs(&mut cats);
        assert_eq!(
            renamed,
            vec![("music".to_string(), "music-custom".to_string())]
        );
        assert_eq!(cats[0].slug, "music-custom");
        assert_eq!(cats[1].slug, "formula-1", "other categories are untouched");
        validate(&cats).expect("after migration the whole list must load");

        // And it must not collide with a slug the user already has.
        let mut taken = vec![mk("book", "Book"), mk("book-custom", "Book Custom")];
        migrate_reserved_slugs(&mut taken);
        assert_eq!(taken[0].slug, "book-custom2");
        validate(&taken).expect("dedup must produce a loadable list");
    }
}

#[cfg(test)]
mod pattern_verdict_tests {
    use super::*;

    /// The two silent failures the verdict exists for, and the proof that
    /// they are opposites: the literal one matches NOTHING, the
    /// everything one matches a name it has no business matching.
    #[test]
    fn the_two_silent_failures_are_reported_and_still_behave_as_before() {
        // Will not compile -> searched for as literal text -> never fires.
        assert_eq!(pat_verdict("*anime*"), PatternVerdict::Literal);
        assert!(!pat_match("*anime*", "Some.Anime.S01E01.1080p"));
        // ...and the fallback is still a real substring search, which is
        // what makes "plain keywords work too" true.
        assert!(pat_match("*anime*", "weird [*anime*] release"));

        // Compiles, as "zero or more !", so it matches everything.
        assert_eq!(pat_verdict("!*"), PatternVerdict::MatchesEverything);
        assert!(pat_match("!*", "Nothing.To.Do.With.It"));
    }

    #[test]
    fn an_ordinary_rule_says_nothing() {
        for p in ["1080p", "Formula1", ".*anime.*x265", "S01E0[1-9]"] {
            assert_eq!(pat_verdict(p), PatternVerdict::Ok, "{p}");
        }
    }

    /// The compile error exists exactly when the verdict is Literal, and
    /// it is the engine's own sentence, not a paraphrase - the save-time
    /// warning ships it verbatim (#18).
    #[test]
    fn compile_error_tracks_the_literal_verdict() {
        for p in ["*anime*", "(unclosed", "[a-"] {
            assert_eq!(pat_verdict(p), PatternVerdict::Literal, "{p}");
            let err = pat_compile_error(p).unwrap_or_else(|| panic!("{p} must carry an error"));
            assert!(!err.trim().is_empty(), "{p}: empty error");
            assert!(
                !err.contains('\n'),
                "{p}: a save answer carries one line, got {err:?}"
            );
        }
        // Everything pat_match treats as a regex has nothing to report -
        // including the dangerous-but-valid catch-all and the deliberate
        // empty pattern.
        for p in ["1080p", "!*", ".*", "", "   "] {
            assert_eq!(pat_compile_error(p), None, "{p:?}");
        }
    }

    /// Empty is the one shape that matches everything ON PURPOSE - a
    /// size-only Smart Folder rule - so it must not be marked.
    #[test]
    fn empty_is_not_a_warning() {
        assert_eq!(pat_verdict(""), PatternVerdict::Ok);
        assert_eq!(pat_verdict("   "), PatternVerdict::Ok);
        assert!(pat_match("", "anything at all"));
    }

    /// Every shape that can match the empty string matches every input,
    /// which is why the check is "does it match empty" and not a list.
    #[test]
    fn the_everything_check_generalises_past_the_reported_case() {
        for p in [".*", "a?", "(foo)?", "x{0,3}", ".*|1080p"] {
            assert_eq!(pat_verdict(p), PatternVerdict::MatchesEverything, "{p}");
            assert!(pat_match(p, "Completely.Unrelated.Name"), "{p}");
        }
    }
}

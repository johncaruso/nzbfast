//! Built-in header indexer (design: M12): scan groups via OVER, cluster
//! posts into releases, store in SQLite, search, and synthesize an NZB on
//! demand - browse Usenet like a catalogue instead of pasting NZBs.
//!
//! Clustering is the proven make-release-nzb logic generalized: files
//! group by (poster, release stem); a release is complete when every seen
//! file has all its parts. Incremental scans resume from each group's
//! stored high-water mark.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;

use rusqlite::{Connection, OptionalExtension};

use crate::extract::release_stem;
use crate::nntp::OverEntry;

pub struct Index {
    db: Connection,
    /// Ingest gate: release stem → keep? None = keep everything. Policy
    /// (year/kind/quality/language rules) lives in the caller; the index
    /// only applies the verdict, once per cluster.
    gate: Option<Box<dyn Fn(&str) -> bool + Send>>,
    /// FTS5 available and rel_fts created - search/browse take the
    /// index path; false falls back to the LIKE scans.
    fts: bool,
    /// people_fts created. Tracked separately from `fts` on purpose: the
    /// name-search leg is an OR inside the main browse predicate, so if
    /// that table were missing every search on the wall would fail, not
    /// just the people half.
    people_fts: bool,
    /// TODO 24D user categories, installed by the daemon (empty = off).
    /// Every ingest-time classification runs through these ahead of the
    /// built-in kinds; `reclassify_custom` reconciles stored rows after
    /// a config change.
    custom: Vec<crate::categories::CustomCategory>,
}

/// One indexed release (search result row).
#[derive(Debug, Clone)]
pub struct Release {
    pub id: i64,
    pub stem: String,
    pub poster: String,
    pub grp: String,
    pub total_bytes: u64,
    pub files: u32,
    pub has_par2: bool,
    pub complete: bool,
    /// Unix time of the earliest article seen (upload date).
    pub first_posted: i64,
    /// Unix time we first indexed it.
    pub first_seen: i64,
    /// Parsed classification, stored at ingest: "movie" / "tv" /
    /// "software" / "other" ('' on rows the backfill hasn't touched).
    pub kind: String,
    /// Parsed resolution ("2160p", "1080p", …; '' = unknown).
    pub res: String,
    /// Exact segment tally across the release's files - the browse
    /// view's completeness percentage (complete is the binary verdict).
    pub have_parts: u64,
    pub need_parts: u64,
    /// Parsed video codec / strongest audio track / dynamic range
    /// ('' = the name didn't say). What tells two encodes of the same
    /// film apart once resolution has tied.
    pub vcodec: String,
    pub acodec: String,
    pub hdr: String,
}

/// Column list every Release row read shares (search + browse).
const REL_COLS: &str = "id, stem, poster, grp, total_bytes, files, has_par2, complete,
     first_posted, first_seen, kind, res, have_parts, need_parts,
     vcodec, acodec, hdr";

/// How many candidate rows an NZBLNK header lookup will look at per
/// rung before giving up. Bounds both the FTS verification pass and the
/// unindexed filename scan; a header that matches this many things was
/// never distinctive enough to identify one posting.
const FIND_SCAN_CAP: u32 = 500;

fn release_from_row(r: &rusqlite::Row) -> rusqlite::Result<Release> {
    Ok(Release {
        id: r.get(0)?,
        stem: r.get(1)?,
        poster: r.get(2)?,
        grp: r.get(3)?,
        total_bytes: r.get::<_, i64>(4)? as u64,
        files: r.get(5)?,
        has_par2: r.get(6)?,
        complete: r.get(7)?,
        first_posted: r.get(8)?,
        first_seen: r.get(9)?,
        kind: r.get(10)?,
        res: r.get(11)?,
        have_parts: r.get::<_, i64>(12)? as u64,
        need_parts: r.get::<_, i64>(13)? as u64,
        vcodec: r.get(14)?,
        acodec: r.get(15)?,
        hdr: r.get(16)?,
    })
}

/// Browse-view filter/sort/page request (M25). Defaults: everything,
/// newest-first, first page.
#[derive(Debug, Clone)]
pub struct BrowseQuery {
    /// Substring terms over the stem ('' = all).
    pub q: String,
    /// Exact kind filter ("movie"/"tv"/"software"/"other").
    pub kind: Option<String>,
    /// Exact resolution filter ("2160p", …).
    pub res: Option<String>,
    pub complete_only: bool,
    /// Minimum total_bytes (0 = unbounded).
    pub min_bytes: u64,
    /// first_posted cutoff, unix seconds (0 = unbounded).
    pub newer_than: i64,
    pub sort: BrowseSort,
    /// true = descending (the default direction for every sort).
    pub desc: bool,
    pub limit: u32,
    pub offset: u32,
    /// M28: hide releases whose junk score is >= this (None = show all).
    pub max_junk: Option<u32>,
    /// M28: restrict to one grid card's releases (exact parse-key match).
    pub title_key: Option<String>,
    /// M30: apply the user's wall curation (per-title hides + hide
    /// rules). Wall/list views set this; API facades (newznab, *arrs)
    /// stay uncurated.
    pub curated: bool,
    /// M30: genre substring filter over the enriched metadata (cards
    /// only - unenriched cards drop out while it's active).
    pub genre: Option<String>,
    /// M30: original-year range filter (decade chips), inclusive.
    /// 0 = unbounded on that side. Cards only (uses the enriched year
    /// with the movie parse-key fallback).
    pub year_min: u32,
    pub year_max: u32,
    /// M29 3c: when set, keep only releases whose availability verdict is
    /// "ok". Pushed into SQL as a real predicate (so `total` and the page
    /// agree), evaluated by the `oracle` verdict logic - not a page trim.
    pub verdict_ok: Option<VerdictFilter>,
}

/// M29 3c: the availability-verdict filter carried on a [`BrowseQuery`].
/// Bundles the (tiny) ledger snapshot, the user's enabled backbones, and
/// `now`, so `browse` can register a SQL scalar function that reuses the
/// single source of truth in [`crate::oracle::Snapshot::verdict`] - no
/// Wilson math or family-fallback logic is duplicated into SQL.
#[derive(Debug, Clone, Default)]
pub struct VerdictFilter {
    pub snap: crate::oracle::Snapshot,
    pub backbones: Vec<String>,
    pub now: i64,
}

impl Default for BrowseQuery {
    fn default() -> Self {
        BrowseQuery {
            q: String::new(),
            kind: None,
            res: None,
            complete_only: false,
            min_bytes: 0,
            newer_than: 0,
            sort: BrowseSort::Posted,
            desc: true,
            limit: 50,
            offset: 0,
            max_junk: None,
            title_key: None,
            curated: false,
            genre: None,
            year_min: 0,
            year_max: 0,
            verdict_ok: None,
        }
    }
}

/// M30: one hidden title in the Hidden view.
#[derive(Debug, Clone)]
pub struct HiddenTitle {
    pub key: String,
    pub title: String,
    pub poster: String,
    pub kind: String,
    pub at: i64,
    pub n_releases: u32,
}

/// M30: one hide rule (manual or accepted suggestion).
#[derive(Debug, Clone)]
pub struct WallRule {
    pub id: i64,
    pub field: String,
    pub value: String,
    pub added: i64,
    pub auto: bool,
}

/// M30: a suggested rule derived from the user's hides.
#[derive(Debug, Clone)]
pub struct Suggestion {
    pub field: String,
    pub value: String,
    /// How many hidden titles share this signal.
    pub n: u32,
    /// Up to 3 hidden titles that triggered it (for the banner text).
    pub sample: Vec<String>,
}

/// Answer to "has anything landed on the wall since I last looked?".
#[derive(Debug, Default, Clone, PartialEq)]
pub struct TipInfo {
    /// Newest `first_seen` in the index - the client hands this back as
    /// `since` next poll, so the window never drifts against clock skew
    /// between the browser and the daemon.
    pub latest: i64,
    /// Distinct wall-visible titles newer than `since`.
    pub new_keys: u32,
    /// Up to `limit` of those keys, newest first, so arriving cards can
    /// be marked without re-deriving which ones they were.
    pub keys: Vec<String>,
}

/// M28: one poster-grid card - a title_key group's aggregates joined to
/// its cached metadata (titles table), built entirely in SQL so the
/// wall pages instead of materializing the whole index per load.
#[derive(Debug, Clone)]
pub struct Card {
    pub title_key: String,
    /// Representative kind ("movie"/"tv"/…).
    pub kind: String,
    /// Release count grouped under this card.
    pub n_releases: u32,
    pub latest_posted: i64,
    pub any_complete: bool,
    pub max_bytes: u64,
    /// Best resolution seen ("2160p" > "1080p" > …; '' = unknown).
    pub best_res: String,
    /// Newest stem in the group (fallback display name for unmatched
    /// cards; also what the detail sheet parses for title/year).
    pub rep_stem: String,
    /// The newest release's newsgroup - the M29 oracle verdict keys off
    /// its group family.
    pub rep_grp: String,
    // Joined titles metadata ('' / 0 until the enricher lands it).
    pub title: String,
    pub year: u32,
    pub rating: f64,
    pub genres: String,
    pub overview: String,
    pub poster_art: String,
    pub backdrop_art: String,
    pub checked: i64,
    pub actors: String,
    /// Enriched release / first-air date, ISO `YYYY-MM-DD` ('' = unknown).
    pub air_date: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CardSort {
    /// Latest upload in the group (the wall default).
    Latest,
    /// Newest to THIS index - when we first saw it, not when it was
    /// uploaded. The two come apart more than they look: a release's
    /// posted time is its FIRST article's, so a set that only finishes
    /// arriving now can be hours old and sorts nowhere near the top
    /// under Latest. Measured on a live scratch index, releases the tip
    /// watcher had just picked up sat past position 400 of 5,718. This
    /// is the order the "new arrivals" pill sends you to, and on its own
    /// it answers "what showed up while I was away".
    Arrived,
    Rating,
    Title,
    /// Group release count (how actively posted).
    Releases,
    Size,
    /// Original release year (enriched year, falling back to the year
    /// baked into a movie parse key) - "original date" vs Latest's
    /// upload date.
    Year,
    /// Full release / first-air date, to the day. Answers "what actually
    /// came out this week", which Year can only answer to the year and
    /// Latest confuses with re-uploads of old titles. Falls back to the
    /// card's year for rows enriched before air_date existed (or whose
    /// provider had no date), so nothing sinks for lack of metadata.
    Aired,
    /// M31b "your wall": rank by a weighted match against the user's
    /// demonstrated taste (see AffinityCtx). Falls back to Releases when
    /// no profile is supplied (cold start).
    Affinity,
}

impl CardSort {
    pub fn parse(s: &str) -> CardSort {
        match s {
            "arrived" => CardSort::Arrived,
            "rating" => CardSort::Rating,
            "title" => CardSort::Title,
            "releases" => CardSort::Releases,
            "size" => CardSort::Size,
            "year" => CardSort::Year,
            "aired" => CardSort::Aired,
            "affinity" => CardSort::Affinity,
            _ => CardSort::Latest,
        }
    }
}

/// M31b: the taste inputs `browse_cards` scores an Affinity sort against.
/// Built daemon-side from the user's completed history + watchlist; the
/// weights are pre-scaled so a strong genre/kind/decade match outranks a
/// weak one and owned titles sink below everything.
#[derive(Debug, Clone, Default)]
pub struct AffinityCtx {
    /// (genre substring, weight) - the profile's top genres, weight
    /// already scaled for the ORDER BY. Matched with a `LIKE '%g%'`
    /// against the enriched `titles.genres` list.
    pub genres: Vec<(String, f32)>,
    /// (favoured kind "tv"/"movie", weight), or None if undetermined.
    pub fav_kind: Option<(String, f32)>,
    /// Weighted-mean release year of the taste set, or None.
    pub decade_center: Option<i32>,
    /// Weight applied when a card's year sits within +/-10 of the centre.
    pub decade_weight: f32,
    /// title_keys the user already owns (completed history + queue).
    /// These sink to the bottom - "more like this, but you have it" -
    /// rather than being hidden.
    pub owned: std::collections::HashSet<String>,
}

impl AffinityCtx {
    /// Nothing to rank by (no genres, kind, or decade) - the caller
    /// should treat this like a cold start.
    pub fn is_empty(&self) -> bool {
        self.genres.is_empty() && self.fav_kind.is_none() && self.decade_center.is_none()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowseSort {
    /// Upload date (first_posted) - the browse default.
    Posted,
    /// When WE first indexed it (first_seen) - "recently added" as
    /// opposed to Posted's upload date. 24C ships added-vs-posted as a
    /// sort option rather than a second date column.
    Seen,
    Size,
    Name,
    /// File count - the Releases table's Files column.
    Files,
    /// Category column: kind first, resolution as the within-kind order
    /// so one category's rows read best-first.
    Kind,
    /// have_parts/need_parts ratio.
    Completeness,
}

impl BrowseSort {
    /// API-string form ("posted"/"seen"/"size"/"name"/"files"/"kind"/
    /// "completeness").
    pub fn parse(s: &str) -> BrowseSort {
        match s {
            "seen" | "added" => BrowseSort::Seen,
            "size" => BrowseSort::Size,
            "name" => BrowseSort::Name,
            "files" => BrowseSort::Files,
            "kind" | "category" => BrowseSort::Kind,
            "completeness" => BrowseSort::Completeness,
            _ => BrowseSort::Posted,
        }
    }
}

/// M28: 0-100 curation score computed at ingest - how likely this
/// release is wall noise. 0 = clean; the default wall hides >= 50.
/// Recomputed on every ingest touch, so a cluster that starts tiny and
/// grows sheds the size penalty as its parts arrive.
/// SQL predicate: does a `files.filename` look like a Windows executable?
/// Shared by the ingest aggregate and the junk_v5 re-score so the two
/// can never disagree.
pub(crate) const EXE_FILE_SQL: &str = "(LOWER(filename) LIKE '%.exe' \
     OR LOWER(filename) LIKE '%.scr' OR LOWER(filename) LIKE '%.lnk' \
     OR LOWER(filename) LIKE '%.bat' OR LOWER(filename) LIKE '%.cmd' \
     OR LOWER(filename) LIKE '%.com' OR LOWER(filename) LIKE '%.msi' \
     OR LOWER(filename) LIKE '%.vbs' OR LOWER(filename) LIKE '%.pif')";

pub fn junk_score(
    stem: &str,
    p: &crate::release::Parsed,
    total_bytes: u64,
    has_exe: bool,
) -> i64 {
    use crate::release::Kind;
    let mut s: i64 = match p.kind {
        // Unparseable stems.
        Kind::Other => 70,
        // Keygen/crack/app-spam markers.
        Kind::Software => 55,
        _ => 0,
    };
    // Hash/blob names - parse_release can still guess a Kind for these,
    // so ask the obfuscation detector directly (sans a short extension
    // token, which would break its all-token rules).
    let bare = stem
        .rsplit_once('.')
        .filter(|(b, ext)| !b.is_empty() && ext.len() <= 4 && ext.chars().all(|c| c.is_ascii_alphanumeric()))
        .map(|(b, _)| b)
        .unwrap_or(stem);
    if crate::release::looks_obfuscated(bare) {
        s = s.max(70);
    }
    // Multi-token blobs the single-token detector misses
    // ("NGKzwg4lCQF_vMr95eoDx2X9NxbLi", "[ff63de8461]_[newzNZB]_…"):
    // a mixed-case-with-digits token ≥8 chars, or a ≥10-char hex run,
    // is no word from any title - but only damn a stem that parsed NO
    // real structure (year/season/resolution), so scene names with
    // hashes next to real markers survive.
    if p.year.is_none() && p.season.is_none() && p.res.is_none() {
        let blobbish = |t: &str| {
            let (up, lo, di) = t.chars().fold((false, false, false), |(u, l, d), c| {
                (u || c.is_ascii_uppercase(), l || c.is_ascii_lowercase(), d || c.is_ascii_digit())
            });
            (t.len() >= 8 && t.chars().all(|c| c.is_ascii_alphanumeric()) && up && lo && di)
                || (t.len() >= 10 && di && t.chars().all(|c| c.is_ascii_hexdigit()))
                // Scattered internal caps, no digits ("gUSbVwIDqhrR") -
                // same signal as the single-token detector, per token.
                || (t.len() >= 9
                    && t.chars().all(|c| c.is_ascii_alphabetic())
                    && t.chars().skip(1).filter(|c| c.is_ascii_uppercase()).count() >= 3)
        };
        if bare
            .split(|c: char| !c.is_ascii_alphanumeric())
            .any(blobbish)
            // Nothing but digits and separators ("12895-1.11").
            || !bare.chars().any(|c| c.is_ascii_alphabetic())
        {
            s = s.max(70);
        }
    }
    // junk_v6: evidence-free "media". A real scene/P2P post virtually
    // always carries at least one technical marker (year, S/E, res,
    // source, codec, remux). A media extension on bare words
    // ("aula.mp4", "misfits-wegedeutschensd") is a course rip, personal
    // file, or spam - nothing an indexer would list. The trailing
    // -group token deliberately does NOT count as evidence: any
    // "words-blob" name grows one for free.
    let no_evidence = p.year.is_none()
        && p.season.is_none()
        && p.episode.is_none()
        && p.res.is_none()
        && p.source.is_none()
        && p.vcodec.is_none()
        && p.acodec.is_none()
        && !p.remux;
    if no_evidence && matches!(p.kind, Kind::Movie | Kind::Tv) {
        s = s.max(60);
    }
    // junk_v6: numbered-lecture prefix ("003 - Estômago.mp4",
    // "056 - Ortografia II") - course/track dumps open with a short
    // track number; scene names never start "NNN - ". Fires even when a
    // stray year parses later in the name, but never on anything that
    // parsed a season/episode.
    if p.season.is_none() && p.episode.is_none() {
        let t = bare.trim_start();
        let nd = t.chars().take_while(|c| c.is_ascii_digit()).count();
        if (1..=3).contains(&nd)
            && t[nd..].trim_start_matches(' ').starts_with("- ")
        {
            s = s.max(60);
        }
    }
    // junk_v6: leading bracketed pure-hex tag ("[a1911f7bca]_[newzNZB]_
    // name") - repost-bot spam whose inner name looks real and would
    // otherwise pollute a genuine title's card. Anime subgroup brackets
    // ("[SubsPlease]") are words, not hex, and survive.
    if let Some(rest) = bare.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            let tag = &rest[..end];
            if tag.len() >= 8 && tag.chars().all(|c| c.is_ascii_hexdigit()) {
                s = s.max(60);
            }
        }
    }
    // junk_v6: a parsed MOVIE claiming HD on a sub-200 MB post is spam
    // or a fake repost - a real 720p+ feature is never that small.
    // Mid-uploads shed this as their parts arrive (scores recompute on
    // every ingest touch). TV is exempt: short-form episodes can be
    // legitimately tiny.
    if matches!(p.kind, Kind::Movie)
        && p.res.is_some()
        && total_bytes > 0
        && total_bytes < 200 << 20
    {
        s = s.max(55);
    }
    // Media-shaped title on a tiny post: indexer spam or nfo-only. A
    // parsed movie/episode name claiming <10 MB is never the media
    // itself - hide it outright (55 crosses the default-50 line). A
    // custom category is exempt in BOTH directions: its payloads can be
    // legitimately tiny (comics, podcasts), so tiny is not evidence of
    // anything there. Books and music are exempt for the same reason and
    // it is not a nicety: an epub is about a megabyte and a single
    // track a few, so scoring them by film sizes would have hidden the
    // whole lane the moment the parser started producing it.
    if total_bytes > 0 && total_bytes < 10 << 20 {
        s = match p.kind {
            Kind::Movie | Kind::Tv => s.max(55),
            Kind::Custom(_) | Kind::Music | Kind::Book => s,
            _ => s + 40,
        };
    }
    // Furniture posted as its own "release": nfo/srr/sfv/sample/subs
    // riding a real release's name. These filled the newest-first list
    // with 0.00 GB rows no indexer site would show.
    let lower = stem.to_ascii_lowercase();
    const FURNITURE: [&str; 8] =
        [".nfo", ".srr", ".sfv", ".nzb", ".idx", ".sub", ".srt", ".sample"];
    if FURNITURE.iter().any(|e| lower.ends_with(e)) {
        s = s.max(60);
    }
    // "sample"/"proof" as a NAME token is only furniture when the post is
    // sample-SIZED (M32: name-only matching wrongly damns
    // full releases with 'sample' in the title). Real samples are tens of
    // MB; past 300 MB the token is part of a title, not a role.
    if total_bytes < 300 << 20
        && lower.split(['.', '_', '-', ' ']).any(|t| t == "sample" || t == "proof")
    {
        s = s.max(60);
    }
    // M32 (Prowlarr#2329): an executable riding a media-shaped release is
    // the classic malware shape - no legitimate movie/episode/music post
    // carries an .exe. Software releases legitimately do, so only their
    // Kind escapes the hammer.
    if has_exe && !matches!(p.kind, Kind::Software) {
        s = s.max(85);
    }
    s.min(100)
}

/// Resolution as a sortable rank. `res` is TEXT, so ordering the column
/// itself is lexicographic: descending gives 720p, 480p, 2160p, 1080p,
/// putting 720p above 4K. Anything that wants "best encode first" has to
/// rank it. Unknown ('') sorts below every real resolution rather than
/// above it, so a blank never leads a category.
///
/// Used by `browse`'s Category sort. The wall's card query needs the
/// same ranking but wraps it in `MAX(...)` over an aliased row, so it
/// spells it out separately - keep the two in step if the vocabulary
/// ever gains a resolution.
const RES_RANK_SQL: &str = "CASE res WHEN '2160p' THEN 4 WHEN '1080p' THEN 3
                                     WHEN '720p' THEN 2 WHEN '' THEN 0 ELSE 1 END";

/// M30: a card's original year in SQL - enriched year first, else the
/// ":YYYY" suffix a movie parse key carries. Shared by the Year sort
/// and the decade-range filter.
const CARD_YEAR_SQL: &str = "COALESCE(NULLIF(t.year,0),
    CASE WHEN r.title_key GLOB 'm:*:[0-9][0-9][0-9][0-9]'
         THEN CAST(substr(r.title_key,-4) AS INTEGER) ELSE 0 END)";

/// Sort key for the to-the-day release-date sort. ISO dates order
/// chronologically as plain strings, so a card with only a year is padded
/// to "YYYY-00-00": it sorts alongside its year but beneath every dated
/// card in it, which is the honest position for "sometime that year".
/// Unknown-year rows become "0000-00-00" and sink (or lead, ascending).
fn card_aired_sql() -> String {
    format!(
        "CASE WHEN COALESCE(t.air_date,'') <> '' THEN t.air_date
              ELSE printf('%04d-00-00', {CARD_YEAR_SQL}) END"
    )
}

/// M30: readable form of a raw parse key - "m:barclays premier league
/// 2011:2012" → "Barclays Premier League 2011 (2012)". Used wherever an
/// unenriched title would otherwise surface its key.
fn pretty_key(key: &str) -> String {
    // Custom keys are "c:<slug>:<title>[:<year>][:<extra>]" - drop the
    // prefix AND the slug, space the rest out ("formula1 2026 round11
    // hungary qualifying"), title-cased below like any other key.
    let custom_owned;
    let base = if let Some(rest) = key.strip_prefix("c:") {
        custom_owned =
            rest.split_once(':').map_or(rest, |(_, t)| t).replace(':', " ");
        custom_owned.as_str()
    } else {
        key.strip_prefix("t:")
            .or_else(|| key.strip_prefix("m:"))
            .unwrap_or(key)
    };
    let (name, yr) = match base.rsplit_once(':') {
        Some((w, y)) if !y.is_empty() && y.chars().all(|c| c.is_ascii_digit()) => {
            (w, Some(y))
        }
        _ => (base, None),
    };
    let mut t = name
        .split_whitespace()
        .map(|w| {
            let mut cs = w.chars();
            match cs.next() {
                Some(c) => c.to_uppercase().collect::<String>() + cs.as_str(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ");
    if let Some(y) = yr {
        t.push_str(&format!(" ({y})"));
    }
    t
}

/// FTS5 MATCH string for user query terms: each term quoted (embedded
/// quotes doubled) with a `*` prefix marker - "kill bill" → `"kill"* "bill"*`
/// (space = implicit AND). Empty when the query has no usable terms.
fn fts_match(query: &str) -> String {
    query
        .split(|c: char| !c.is_alphanumeric())
        .filter(|t| !t.is_empty())
        .map(|t| format!("\"{}\"*", t.replace('"', "\"\"")))
        .collect::<Vec<_>>()
        .join(" ")
}

/// A title with at least one release the wall would actually show.
///
/// Enrichment is the scarcest thing the daemon does - MusicBrainz allows
/// one request a second, and Wikimedia 429s at three - so spending it on
/// a card nobody can see is the most expensive kind of waste. Measured
/// on a live 7,755-title index before this existed: of 5,243 lookups
/// that cost a network call, **3,910 (75%) went to titles with no
/// release passing the junk gate**. They are not rare edge cases; they
/// are most of the budget.
///
/// `junk < 50` is the wall's own default threshold, so this asks exactly
/// "would the wall list this?" rather than inventing a second policy.
///
/// It defers rather than drops. Junk scores are recomputed on every
/// ingest touch and a mid-upload release sheds junk as its parts arrive,
/// so a title that is invisible now and becomes visible later is simply
/// picked up on a later pass - it stays `checked=0` throughout. Nothing
/// is permanently skipped, which matters because the enricher's one-shot
/// `checked` stamp has no way back (see the tri-state plan in
/// research/indexer-realtime-and-enrichment-plan-2026-07-26.md §11.1).
const VISIBLE: &str =
    "EXISTS (SELECT 1 FROM releases r WHERE r.title_key = t.key AND r.junk < 50)";

/// One enricher lane. Each runs on its own thread against its own set
/// of providers, because the rate limits are per provider: a serial loop
/// made every TV title queue behind the movie crawl, and adding music
/// and books to the TV lane would have put a 1-request-per-second
/// MusicBrainz backlog in front of every new episode.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Lane {
    /// Wikidata / Wikipedia / OMDb.
    Movies,
    /// TVmaze, plus the junk and custom-category rows that touch no
    /// provider at all and are only stamped.
    Shows,
    /// MusicBrainz / Cover Art Archive / OpenLibrary.
    MusicBooks,
}

impl Lane {
    /// This lane's slice of `titles`, as a SQL fragment. Static text
    /// only - it is interpolated into the query, so it must never carry
    /// a caller-supplied value.
    fn sql(self) -> &'static str {
        match self {
            Lane::Movies => "kind = 'movie'",
            Lane::MusicBooks => "kind IN ('music','book')",
            // Everything the other two lanes do not claim, so a kind
            // added later still gets enriched by SOMETHING rather than
            // falling down a gap between lanes and never being looked at.
            Lane::Shows => "kind NOT IN ('movie','music','book')",
        }
    }
}

/// SQL value for a parsed kind (lowercase, stable - stored in the db).
/// A custom category stores its slug directly; slugs can never shadow
/// the built-in four (`categories::validate` reserves them).
pub fn kind_str(k: &crate::release::Kind) -> &str {
    match k {
        crate::release::Kind::Movie => "movie",
        crate::release::Kind::Tv => "tv",
        crate::release::Kind::Software => "software",
        crate::release::Kind::Music => "music",
        crate::release::Kind::Book => "book",
        crate::release::Kind::Other => "other",
        crate::release::Kind::Custom(slug) => slug,
    }
}

impl Index {
    pub fn open(path: &Path) -> rusqlite::Result<Index> {
        let mut db = Connection::open(path)?;
        // Several connections share this db (scan scratch, API queries,
        // wall enricher, IMDb refresher). Without a busy timeout a
        // schema-creation or checkpoint race fails INSTANTLY with
        // "database is locked" - which made the daemon's first scan pass
        // silently skip a whole interval (the long-standing
        // scan_loop_populates_index_live "flake").
        db.busy_timeout(std::time::Duration::from_secs(10))?;
        // Only journal_mode was ever set, so every chunk commit paid a
        // full fsync and the page cache stayed at SQLite's 2 MB default
        // against a multi-gigabyte index.
        //
        // synchronous=NORMAL is the one that matters for ingest. In WAL
        // mode it cannot corrupt the database - the documented exposure
        // is losing the last commits on a power cut or OS crash, which
        // for an index rebuildable from Usenet is the right trade. A
        // scan pass simply re-fetches the headers whose commit was lost;
        // the high-water mark only advances over a contiguous prefix.
        db.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=NORMAL;
             PRAGMA temp_store=MEMORY;
             PRAGMA cache_size=-262144;
             PRAGMA mmap_size=1073741824;
             CREATE TABLE IF NOT EXISTS releases(
                id INTEGER PRIMARY KEY,
                stem TEXT NOT NULL,
                poster TEXT NOT NULL,
                grp TEXT NOT NULL,
                total_bytes INTEGER NOT NULL DEFAULT 0,
                files INTEGER NOT NULL DEFAULT 0,
                has_par2 INTEGER NOT NULL DEFAULT 0,
                complete INTEGER NOT NULL DEFAULT 0,
                first_posted INTEGER NOT NULL DEFAULT 0,
                first_seen INTEGER NOT NULL DEFAULT 0,
                UNIQUE(stem, poster, grp));
             CREATE TABLE IF NOT EXISTS files(
                release_id INTEGER NOT NULL,
                filename TEXT NOT NULL,
                total_parts INTEGER NOT NULL,
                bytes INTEGER NOT NULL DEFAULT 0,
                segments TEXT NOT NULL DEFAULT '[]',
                UNIQUE(release_id, filename));
             CREATE TABLE IF NOT EXISTS marks(
                -- A8 multi-server indexing: article NUMBERS are assigned
                -- per server spool (message-ids are the portable half),
                -- so scan coverage is tracked per (group, server). The
                -- server key is the lowercased host; '' marks rows from
                -- the single-server era, adopted by the historical
                -- primary via adopt_legacy_marks.
                grp TEXT NOT NULL,
                server TEXT NOT NULL DEFAULT '',
                high INTEGER NOT NULL,
                low INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY(grp, server));
             CREATE INDEX IF NOT EXISTS idx_rel_stem ON releases(stem);
             CREATE TABLE IF NOT EXISTS spots(
                id INTEGER PRIMARY KEY,
                msgid TEXT NOT NULL UNIQUE,
                title TEXT NOT NULL,
                category INTEGER NOT NULL DEFAULT 0,
                subcats TEXT NOT NULL DEFAULT '',
                size INTEGER NOT NULL DEFAULT 0,
                date INTEGER NOT NULL DEFAULT 0,
                spotter_id TEXT NOT NULL DEFAULT '',
                verified INTEGER NOT NULL DEFAULT 0,
                hashcash_ok INTEGER NOT NULL DEFAULT 1,
                nzb_msgids TEXT NOT NULL DEFAULT '[]');
             CREATE INDEX IF NOT EXISTS idx_spots_title ON spots(title);
             CREATE TABLE IF NOT EXISTS titles(
                key TEXT PRIMARY KEY,
                kind TEXT NOT NULL,
                title TEXT NOT NULL,
                year INTEGER NOT NULL DEFAULT 0,
                tmdb_id INTEGER NOT NULL DEFAULT 0,
                overview TEXT NOT NULL DEFAULT '',
                rating REAL NOT NULL DEFAULT 0,
                genres TEXT NOT NULL DEFAULT '',
                poster TEXT NOT NULL DEFAULT '',
                backdrop TEXT NOT NULL DEFAULT '',
                checked INTEGER NOT NULL DEFAULT 0);
             CREATE TABLE IF NOT EXISTS imdb_ratings(
                tconst TEXT PRIMARY KEY,
                rating REAL NOT NULL,
                votes INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS kv(
                k TEXT PRIMARY KEY,
                v TEXT NOT NULL);
             -- M30 wall curation: per-title 'Not interested' hides,
             -- learned/manual hide rules, and suggestion dismissals
             -- (so a declined suggestion never nags again).
             CREATE TABLE IF NOT EXISTS wall_hidden(
                -- NOT NULL is explicit: a non-INTEGER PRIMARY KEY is NOT
                -- implicitly NOT NULL in SQLite, and a single NULL key here
                -- makes `key NOT IN (SELECT key FROM wall_hidden)` (used by
                -- the pruners AND the wall curation filter) evaluate to NULL
                -- for every row - silently disabling pruning and blanking
                -- the whole wall.
                key TEXT PRIMARY KEY NOT NULL,
                at INTEGER NOT NULL);
             CREATE TABLE IF NOT EXISTS wall_rules(
                id INTEGER PRIMARY KEY,
                field TEXT NOT NULL,
                value TEXT NOT NULL,
                added INTEGER NOT NULL,
                auto INTEGER NOT NULL DEFAULT 0,
                UNIQUE(field, value));
             CREATE TABLE IF NOT EXISTS wall_dismissed(
                field TEXT NOT NULL,
                value TEXT NOT NULL,
                PRIMARY KEY(field, value));
             -- Repost fingerprints: the PAR2 hash16k of a member file
             -- (an OUTER volume) of a download we managed to name,
             -- against the name we gave it. A later obfuscated post
             -- whose sidecar presents the same hash is the same bytes,
             -- so it can be told what it is. The identity is read from
             -- the .par2 sidecar and never from the archive, which is
             -- why it survives RAR header encryption - the one naming
             -- path in the pipeline that does.
             --
             -- Only names REPOSTS, so the yield grows with the age of
             -- the table and is zero on a fresh install. It costs ~80
             -- bytes per volume of every named download, which is why
             -- there is no expiry: an old fingerprint is exactly the
             -- one worth having.
             CREATE TABLE IF NOT EXISTS par_hashes(
                hash16k TEXT PRIMARY KEY NOT NULL,
                -- The release name we knew this by.
                name TEXT NOT NULL,
                -- The wall's identity for it, when the name parsed to
                -- one ('' when it did not).
                title_key TEXT NOT NULL DEFAULT '',
                at INTEGER NOT NULL);",
        )?;
        // Columns added after the titles table first shipped - ALTER has
        // no IF NOT EXISTS, so failed re-adds are expected and harmless.
        for ddl in [
            "ALTER TABLE titles ADD COLUMN imdb TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE titles ADD COLUMN actors TEXT NOT NULL DEFAULT ''",
            // Full release / first-air date (ISO). Rows enriched before
            // this column existed keep '' and sort by `year` instead -
            // they only gain a real date when re-enriched.
            "ALTER TABLE titles ADD COLUMN air_date TEXT NOT NULL DEFAULT ''",
            // Whether a provider has been ASKED for this title's date.
            // Distinct from a non-empty air_date: plenty of titles have
            // no date to give, and without this the backfill lane would
            // re-ask them forever. Rows enriched before air_date existed
            // default to 0, which is what makes them eligible for it.
            "ALTER TABLE titles ADD COLUMN air_tried INTEGER NOT NULL DEFAULT 0",
            // Scan low-water mark (history auto-deepen).
            "ALTER TABLE marks ADD COLUMN low INTEGER NOT NULL DEFAULT 0",
            // M25 browse view: classification + exact part counts, so
            // SQL can filter "movie AND 2160p" and sort by completeness
            // without re-parsing every stem per request.
            "ALTER TABLE releases ADD COLUMN kind TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE releases ADD COLUMN res TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE releases ADD COLUMN have_parts INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE releases ADD COLUMN need_parts INTEGER NOT NULL DEFAULT 0",
            // M28 indexer v2: the parse key ("t:breaking bad" /
            // "m:inception:2010") persisted so the poster grid groups in
            // SQL, plus a 0-100 junk score for default-wall curation.
            "ALTER TABLE releases ADD COLUMN title_key TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE releases ADD COLUMN junk INTEGER NOT NULL DEFAULT 0",
            // M29 availability oracle: when the idle STAT sampler last
            // probed this release (0 = never) - oldest-verdict-first.
            "ALTER TABLE releases ADD COLUMN oracle_at INTEGER NOT NULL DEFAULT 0",
            // M30 curation: audio-language tags from the stem, space-
            // joined lowercase ("german" / "german multi"; '' = untagged
            // = English by scene convention). Filled at ingest and by
            // the junk_v6 re-score pass, queried by language hide rules.
            "ALTER TABLE releases ADD COLUMN langs TEXT NOT NULL DEFAULT ''",
            // Cached `json_array_length(segments)`. The completeness
            // aggregate called that twice per file row of a release, on
            // every chunk that touched it - so a 210-file release with
            // 13 MB of segments JSON re-parsed all of it just to count
            // parts. Measured on the live index: 16.3 ms with the JSON
            // calls, 0.3 ms without. Written alongside `segments`, so
            // the two cannot drift.
            "ALTER TABLE files ADD COLUMN nsegs INTEGER NOT NULL DEFAULT 0",
            // What separates two encodes of the same film once resolution
            // ties: the release name already carries these, and the parser
            // already read them, but until now they were parsed and thrown
            // away. '' = the name said nothing (or the row predates the
            // columns and the quality_v8 pass hasn't reached it).
            "ALTER TABLE releases ADD COLUMN vcodec TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE releases ADD COLUMN acodec TEXT NOT NULL DEFAULT ''",
            "ALTER TABLE releases ADD COLUMN hdr TEXT NOT NULL DEFAULT ''",
            // Monotonic wall-arrival cursor. A release id alone is not a
            // safe cursor because SQLite may reuse the highest rowid after
            // eviction deletes it.
            "ALTER TABLE releases ADD COLUMN arrival_seq INTEGER NOT NULL DEFAULT 0",
            // A8 targeted gap-fill: when a secondary-server window scan
            // last tried to complete this release (0 = never) - oldest
            // first, like oracle_at.
            "ALTER TABLE releases ADD COLUMN gapfill_at INTEGER NOT NULL DEFAULT 0",
        ] {
            let _ = db.execute(ddl, []);
        }
        // A8: rebuild a single-server-era marks table (PRIMARY KEY(grp))
        // to the (grp, server) shape. SQLite cannot ALTER a primary key,
        // so this is the standard rebuild - one-time; the PRAGMA guard
        // keeps every later open from bumping the schema version. Rows
        // keep server='' until adopt_legacy_marks assigns them to the
        // server that actually built them. Non-fatal like the other
        // migrations: on failure the next open retries, and the worst a
        // lost marks table costs is a rescan (ingest is idempotent).
        let has_server_col = db
            .prepare("SELECT 1 FROM pragma_table_info('marks') WHERE name='server'")
            .and_then(|mut s| s.exists([]))
            .unwrap_or(false);
        if !has_server_col {
            // A real Transaction object, not a BEGIN/COMMIT batch: a
            // mid-batch failure would otherwise leave the transaction
            // open on this connection, and every later statement in this
            // open() would silently run (and hold the write lock) inside
            // it. The drop of an uncommitted Transaction rolls back.
            let rebuild = db.unchecked_transaction().and_then(|tx| {
                tx.execute_batch(
                    "DROP TABLE IF EXISTS marks_v2;
                     CREATE TABLE marks_v2(
                        grp TEXT NOT NULL,
                        server TEXT NOT NULL DEFAULT '',
                        high INTEGER NOT NULL,
                        low INTEGER NOT NULL DEFAULT 0,
                        PRIMARY KEY(grp, server));
                     INSERT INTO marks_v2(grp, server, high, low)
                       SELECT grp, '', high, low FROM marks;
                     DROP TABLE marks;
                     ALTER TABLE marks_v2 RENAME TO marks;",
                )?;
                tx.commit()
            });
            let _ = rebuild;
        }
        // Existing rows receive their current id as an initial cursor.
        // New inserts advance a persistent counter in the same SQLite write
        // transaction, so same-second arrivals and rowid reuse both remain
        // visible to an already-open wall.
        // Non-fatal, like every other migration in this function. This
        // batch ENDS in an unconditional `UPDATE kv ... WHERE
        // k='wall_arrival_seq'`, which always matches a row, so every
        // single `Index::open` takes the SQLite write lock. A scan pass
        // opens up to 8 handles concurrently while a foreground ingest
        // chunk holds the writer, so exceeding the busy timeout is a
        // routine event, not a corrupt database - and propagating it made
        // `with_index` hand back None, which skips a whole group's scan
        // for the interval and answers wall/browse/search with nothing.
        // Every statement here is idempotent and self-healing: a later
        // open re-runs it, and rows that missed the trigger keep
        // arrival_seq=0 until the first line above claims them.
        let _ = db.execute_batch(
            "UPDATE releases SET arrival_seq=id WHERE arrival_seq=0;
             INSERT OR IGNORE INTO kv(k, v)
               VALUES('wall_arrival_seq',
                      (SELECT CAST(COALESCE(MAX(arrival_seq), 0) AS TEXT) FROM releases));
             UPDATE kv
                SET v=CAST(MAX(CAST(v AS INTEGER),
                               (SELECT COALESCE(MAX(arrival_seq), 0) FROM releases)) AS TEXT)
              WHERE k='wall_arrival_seq';
             -- The COALESCE is what keeps this trigger fail-SAFE rather
             -- than fail-DEAD. `arrival_seq` is NOT NULL, so if the kv
             -- row is ever absent the SELECT yields NULL, the UPDATE
             -- violates the constraint, and the constraint takes the
             -- whole ingest transaction with it - every insert into
             -- `releases` fails for as long as the row is gone. Nothing
             -- deletes it today, but three places do `DELETE FROM kv
             -- WHERE k=...` and one mistyped key would make the index
             -- permanently unwritable. Falling back to the row id costs
             -- at worst a cursor value shared with an evicted row, and
             -- the statements above restore the counter from
             -- MAX(arrival_seq) on the very next open.
             --
             -- Suffixed `_v2` rather than DROP+CREATEd: the drop of the
             -- old name is a no-op once it has run, so an already
             -- migrated database does not bump its schema version (and
             -- invalidate every other connection's prepared statements)
             -- on every single open.
             DROP TRIGGER IF EXISTS rel_arrival_seq_ai;
             CREATE TRIGGER IF NOT EXISTS rel_arrival_seq_ai_v2
               AFTER INSERT ON releases WHEN new.arrival_seq=0 BEGIN
                 UPDATE kv SET v=CAST(CAST(v AS INTEGER)+1 AS TEXT)
                   WHERE k='wall_arrival_seq';
                 UPDATE releases
                    SET arrival_seq=COALESCE(
                          CAST((SELECT v FROM kv
                                WHERE k='wall_arrival_seq') AS INTEGER),
                          new.id)
                  WHERE id=new.id;
               END;",
        );
        // M28: browse-path indexes - every filter/sort was a full scan
        // (only idx_rel_stem existed).
        let _ = db.execute_batch(
            "CREATE INDEX IF NOT EXISTS idx_rel_posted ON releases(first_posted);
             CREATE INDEX IF NOT EXISTS idx_rel_kind ON releases(kind, first_posted);
             CREATE INDEX IF NOT EXISTS idx_rel_title_key ON releases(title_key);
             CREATE INDEX IF NOT EXISTS idx_rel_size ON releases(total_bytes);
             -- The arrival signal orders by when WE saw a release, not
             -- when it was posted: a backfill leg discovers genuinely old
             -- uploads, and those are not arrivals. Without this index
             -- `wall_tip` is a full scan on every poll.
             CREATE INDEX IF NOT EXISTS idx_rel_seen ON releases(first_seen);
             CREATE INDEX IF NOT EXISTS idx_rel_arrival ON releases(arrival_seq);",
        );
        // M28: FTS5 over raw stems (unicode61 tokenizer already treats
        // ./-/_ as separators, so no normalized shadow column is needed).
        // External-content table + triggers stay in sync with prune
        // deletes; stems are immutable so no UPDATE trigger. Wrapped in
        // is_ok() so a non-FTS build just keeps the LIKE path.
        let fts = db
            .execute_batch(
                "CREATE VIRTUAL TABLE IF NOT EXISTS rel_fts
                   USING fts5(stem, content='releases', content_rowid='id');
                 CREATE TRIGGER IF NOT EXISTS rel_fts_ai AFTER INSERT ON releases BEGIN
                   INSERT INTO rel_fts(rowid, stem) VALUES(new.id, new.stem); END;
                 CREATE TRIGGER IF NOT EXISTS rel_fts_ad AFTER DELETE ON releases BEGIN
                   INSERT INTO rel_fts(rel_fts, rowid, stem)
                     VALUES('delete', old.id, old.stem); END;",
            )
            .is_ok();
        // Cast and crew as entities rather than a rendered string.
        // `titles.actors` stays exactly as it is - it is what every card
        // renders today, and nothing may regress while this join table
        // fills in behind it. The join table is what the person page,
        // name search and cast-overlap affinity read.
        db.execute_batch(
            "CREATE TABLE IF NOT EXISTS people(
                id           INTEGER PRIMARY KEY,
                name         TEXT NOT NULL,
                imdb         TEXT NOT NULL DEFAULT '',
                -- The two filmography handles. TVmaze's person id answers
                -- 'what else did they do on TV'; the Wikidata Q-id answers
                -- the film half. Neither source covers the other, so a
                -- person legitimately carries both.
                tvmaze_id    INTEGER NOT NULL DEFAULT 0,
                wikidata_qid TEXT NOT NULL DEFAULT '',
                bio          TEXT NOT NULL DEFAULT '',
                born         TEXT NOT NULL DEFAULT '',
                -- The provider's headshot URL, and unlike titles.poster
                -- it stays a URL. The cached file is evictable (a large
                -- index would otherwise quietly fill a NAS with
                -- headshots), and after an eviction the URL is the only
                -- thing that can fetch it back.
                photo        TEXT NOT NULL DEFAULT '',
                checked      INTEGER NOT NULL DEFAULT 0);
             CREATE TABLE IF NOT EXISTS title_people(
                key       TEXT NOT NULL,
                person_id INTEGER NOT NULL,
                role      TEXT NOT NULL DEFAULT 'actor',
                character TEXT NOT NULL DEFAULT '',
                ord       INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY(key, person_id, role));
             CREATE INDEX IF NOT EXISTS idx_tp_person ON title_people(person_id, ord);
             -- Partial uniques, so the handle-first upsert cannot race two
             -- threads into two rows for one person. They must stay
             -- partial: the default 0 / '' is 'no handle', and a plain
             -- UNIQUE would let exactly one person exist without one.
             CREATE UNIQUE INDEX IF NOT EXISTS idx_people_tvmaze
               ON people(tvmaze_id) WHERE tvmaze_id > 0;
             CREATE UNIQUE INDEX IF NOT EXISTS idx_people_qid
               ON people(wikidata_qid) WHERE wikidata_qid <> '';
             -- Same rule for the IMDb id, and safe to add to an existing
             -- database: nothing ever wrote this column before the
             -- Wikidata P345 lane did, so every pre-existing row holds
             -- '' and falls outside the partial index. It carries the
             -- same trade the other two already do - the blank-fill
             -- UPDATE can collide when the handle-first lookup lands on
             -- a row whose blank belongs to another row's id, which
             -- fails that one title's credit write and lets the next
             -- enrichment retry it. Duplicate Wikidata items for one
             -- person, which is the common way two rows share an nm id,
             -- resolve through the lookup instead and merge cleanly.
             CREATE UNIQUE INDEX IF NOT EXISTS idx_people_imdb
               ON people(imdb) WHERE imdb <> '';
             CREATE INDEX IF NOT EXISTS idx_people_name ON people(name COLLATE NOCASE);",
        )?;
        // Name search. Unlike rel_fts there IS an UPDATE trigger: a
        // person row's name improves when a second provider supplies a
        // better-cased or fuller spelling, and an external-content FTS
        // that missed the update returns the row under a name it no
        // longer has.
        let people_fts = db.execute_batch(
            "CREATE VIRTUAL TABLE IF NOT EXISTS people_fts
               USING fts5(name, content='people', content_rowid='id');
             CREATE TRIGGER IF NOT EXISTS people_fts_ai AFTER INSERT ON people BEGIN
               INSERT INTO people_fts(rowid, name) VALUES(new.id, new.name); END;
             CREATE TRIGGER IF NOT EXISTS people_fts_ad AFTER DELETE ON people BEGIN
               INSERT INTO people_fts(people_fts, rowid, name)
                 VALUES('delete', old.id, old.name); END;
             CREATE TRIGGER IF NOT EXISTS people_fts_au
               AFTER UPDATE OF name ON people BEGIN
               INSERT INTO people_fts(people_fts, rowid, name)
                 VALUES('delete', old.id, old.name);
               INSERT INTO people_fts(rowid, name) VALUES(new.id, new.name); END;",
        );
        let people_fts = fts && people_fts.is_ok();
        // One-time retroactive recompute after the completeness-rule
        // change (nfiles >= 2 → >= 1): existing rows only re-evaluate
        // when a scan touches them, which for finished uploads is never.
        let rule: Option<String> =
            db.query_row("SELECT v FROM kv WHERE k='complete_rule'", [], |r| r.get(0)).ok();
        if rule.as_deref() != Some("2") {
            // One transaction, and the done-flag only lands if the
            // recompute did: as two autocommit statements, a SQLITE_BUSY
            // on the big UPDATE (discarded) with the tiny insert
            // succeeding stamped the migration done while every
            // completeness flag stayed stale - permanently.
            let _ = (|| -> rusqlite::Result<()> {
                let tx = db.unchecked_transaction()?;
                tx.execute(
                    "UPDATE releases SET complete =
                       EXISTS(SELECT 1 FROM files f WHERE f.release_id=releases.id)
                       AND NOT EXISTS(SELECT 1 FROM files f WHERE f.release_id=releases.id
                                      AND json_array_length(f.segments) < f.total_parts)",
                    [],
                )?;
                tx.execute(
                    "INSERT INTO kv(k, v) VALUES('complete_rule','2')
                     ON CONFLICT(k) DO UPDATE SET v='2'",
                    [],
                )?;
                tx.commit()
            })();
        }
        // Retroactive fill of `nsegs` for rows written before the column
        // existed. Finished uploads are never re-ingested, so without
        // this they would take the JSON-parsing fallback above forever.
        //
        // Chunked with a kv rowid cursor, and time-bounded, for two
        // reasons learned the hard way. A single UPDATE over the whole
        // files table (1.6 M rows on the live index) loses the write
        // lock to a running scanner and is silently discarded - the
        // junk_v6 re-score did exactly that. And an unbounded loop here
        // would block daemon startup for minutes, since every scan task
        // opens its own Index. Whatever is left resumes on the next
        // open; the read side is correct throughout either way.
        let filled: Option<String> =
            db.query_row("SELECT v FROM kv WHERE k='nsegs_fill'", [], |r| r.get(0)).ok();
        if filled.as_deref() != Some("1") {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            let _ = (|| -> rusqlite::Result<()> {
                loop {
                    // Acquire the writer reservation BEFORE reading the
                    // cursor. Several scan connections open the index at
                    // once; a deferred transaction let two of them read
                    // the same cursor, then a delayed one could overwrite
                    // a later cursor with its stale lower value.
                    let tx = db.transaction_with_behavior(
                        rusqlite::TransactionBehavior::Immediate,
                    )?;
                    let cursor: i64 = tx
                        .query_row("SELECT v FROM kv WHERE k='nsegs_at'", [], |r| {
                            r.get::<_, String>(0)
                        })
                        .ok()
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(0);
                    // Advance by rowid, never by "nsegs = 0": a row whose
                    // segments JSON will not parse stays 0 forever and
                    // would be re-selected every pass, spinning here.
                    let next: Option<i64> = tx.query_row(
                        "SELECT MAX(rowid) FROM
                           (SELECT rowid FROM files WHERE rowid > ?1 ORDER BY rowid LIMIT 5000)",
                        [cursor],
                        |r| r.get(0),
                    )?;
                    let Some(next) = next else {
                        tx.execute(
                            "INSERT INTO kv(k, v) VALUES('nsegs_fill','1')
                             ON CONFLICT(k) DO UPDATE SET v='1'",
                            [],
                        )?;
                        tx.commit()?;
                        return Ok(());
                    };
                    tx.execute(
                        "UPDATE files SET nsegs = COALESCE(json_array_length(segments), 0)
                         WHERE rowid > ?1 AND rowid <= ?2",
                        [cursor, next],
                    )?;
                    // Cursor moves with the rows, in the same
                    // transaction: a busy failure rolls back both and
                    // the chunk is simply redone.
                    tx.execute(
                        "INSERT INTO kv(k, v) VALUES('nsegs_at', ?1)
                         ON CONFLICT(k) DO UPDATE SET v=excluded.v",
                        [next.to_string()],
                    )?;
                    tx.commit()?;
                    if std::time::Instant::now() >= deadline {
                        return Ok(());
                    }
                }
            })();
        }
        // M25 browse view: retroactive fill of the new kind/res/part
        // columns for rows indexed before they existed. Same shape as
        // the complete_rule migration: one transaction, flag stamped
        // only if the fill landed, so SQLITE_BUSY just retries next open.
        let done: Option<String> =
            db.query_row("SELECT v FROM kv WHERE k='browse_cols'", [], |r| r.get(0)).ok();
        if done.as_deref() != Some("1") {
            let _ = (|| -> rusqlite::Result<()> {
                let tx = db.unchecked_transaction()?;
                tx.execute(
                    "UPDATE releases SET
                       have_parts = COALESCE((SELECT SUM(json_array_length(segments))
                                              FROM files WHERE release_id=releases.id), 0),
                       need_parts = COALESCE((SELECT SUM(total_parts)
                                              FROM files WHERE release_id=releases.id), 0)",
                    [],
                )?;
                {
                    let mut sel = tx.prepare("SELECT id, stem FROM releases WHERE kind=''")?;
                    let mut upd =
                        tx.prepare("UPDATE releases SET kind=?2, res=?3 WHERE id=?1")?;
                    let rows: Vec<(i64, String)> = sel
                        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                        .collect::<rusqlite::Result<_>>()?;
                    for (id, stem) in rows {
                        let p = crate::release::parse_release(&stem);
                        upd.execute(rusqlite::params![id, kind_str(&p.kind), p.res.unwrap_or_default()])?;
                    }
                }
                tx.execute(
                    "INSERT INTO kv(k, v) VALUES('browse_cols','1')
                     ON CONFLICT(k) DO UPDATE SET v='1'",
                    [],
                )?;
                tx.commit()
            })();
        }
        // M28: one-time FTS backfill for rows inserted before the
        // triggers existed - 'rebuild' re-reads the whole content table.
        // Same stamped-in-transaction shape as the migrations above.
        if fts {
            let done: Option<String> =
                db.query_row("SELECT v FROM kv WHERE k='fts_v1'", [], |r| r.get(0)).ok();
            if done.as_deref() != Some("1") {
                let _ = (|| -> rusqlite::Result<()> {
                    let tx = db.unchecked_transaction()?;
                    tx.execute("INSERT INTO rel_fts(rel_fts) VALUES('rebuild')", [])?;
                    tx.execute(
                        "INSERT INTO kv(k, v) VALUES('fts_v1','1')
                         ON CONFLICT(k) DO UPDATE SET v='1'",
                        [],
                    )?;
                    tx.commit()
                })();
            }
        }
        // M28: retroactive title_key + junk fill (rows only re-parse when
        // a scan touches them, which for finished uploads is never).
        let done: Option<String> =
            db.query_row("SELECT v FROM kv WHERE k='browse2'", [], |r| r.get(0)).ok();
        if done.as_deref() != Some("1") {
            let _ = (|| -> rusqlite::Result<()> {
                let tx = db.unchecked_transaction()?;
                {
                    let mut sel = tx.prepare(
                        "SELECT id, stem, total_bytes FROM releases WHERE title_key=''",
                    )?;
                    let mut upd =
                        tx.prepare("UPDATE releases SET title_key=?2, junk=?3 WHERE id=?1")?;
                    let rows: Vec<(i64, String, i64)> = sel
                        .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                        .collect::<rusqlite::Result<_>>()?;
                    for (id, stem, bytes) in rows {
                        let p = crate::release::parse_release(&stem);
                        upd.execute(rusqlite::params![
                            id,
                            p.key,
                            junk_score(&stem, &p, bytes as u64, false)
                        ])?;
                    }
                }
                tx.execute(
                    "INSERT INTO kv(k, v) VALUES('browse2','1')
                     ON CONFLICT(k) DO UPDATE SET v='1'",
                    [],
                )?;
                tx.commit()
            })();
        }
        // quality_v8 (26 Jul, was junk_v7): junk_v6's rules plus a full
        // re-parse - title_key/kind/res so ROT13 rescues that the parser
        // newly decodes regroup under their real titles, and now
        // vcodec/acodec/hdr, which rows indexed before those columns
        // existed have never carried. The kv key names the CURRENT
        // version; bumping it re-parses every row exactly once, which is
        // what backfills the new columns - free, because this pass
        // already parses every stem. CHUNKED with a
        // persisted id cursor - the
        // one-big-tx shape could never win the write lock against
        // parallel scanners on a live daemon (SQLITE_BUSY → silently
        // skipped forever). 10k rows per transaction interleaves with
        // scan ingest; a partial pass resumes from the cursor on the
        // next open.
        let done: Option<String> =
            db.query_row("SELECT v FROM kv WHERE k='quality_v8'", [], |r| r.get(0)).ok();
        if done.as_deref() != Some("1") {
            let _ = (|| -> rusqlite::Result<()> {
                let mut cursor: i64 = db
                    .query_row("SELECT v FROM kv WHERE k='quality_v8_cursor'", [], |r| {
                        r.get::<_, String>(0)
                    })
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0);
                loop {
                    // IMMEDIATE, like the nsegs, reclassify and ingest
                    // transactions: this reads a cursor and writes it
                    // back, and a deferred lock upgrade does NOT get the
                    // busy timeout - it returns SQLITE_BUSY at once. A
                    // deferred wrapper here meant a contended pass
                    // abandoned mid-chunk and left the cursor parked.
                    let tx = rusqlite::Transaction::new_unchecked(
                        &db,
                        rusqlite::TransactionBehavior::Immediate,
                    )?;
                    let rows: Vec<(i64, String, i64, bool)> = {
                        let mut sel = tx.prepare_cached(&format!(
                            "SELECT id, stem, total_bytes,
                                    EXISTS(SELECT 1 FROM files
                                           WHERE release_id=releases.id AND {EXE_FILE_SQL})
                             FROM releases WHERE id > ?1 ORDER BY id LIMIT 10000"
                        ))?;
                        sel.query_map([cursor], |r| {
                            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
                        })?
                        .collect::<rusqlite::Result<_>>()?
                    };
                    if rows.is_empty() {
                        tx.execute(
                            "INSERT INTO kv(k, v) VALUES('quality_v8','1')
                             ON CONFLICT(k) DO UPDATE SET v='1'",
                            [],
                        )?;
                        tx.commit()?;
                        break;
                    }
                    {
                        // `parse_release` is CUSTOM-BLIND: `Index::open`
                        // runs before `set_custom`, by construction (the
                        // constructor hardcodes an empty category list),
                        // so this pass cannot know the user's categories.
                        // Re-parsing a row that `reclassify_custom`
                        // classified would therefore rewrite kind and
                        // title_key back to the built-in answer - every
                        // session of an F1 season collapsing onto one
                        // movie card, out of the category tab, and losing
                        // the Custom junk exemption. Worse, it does not
                        // heal: `reclassify_custom` sees an unchanged
                        // fingerprint and no cursor and returns Ok(0) on
                        // every later start.
                        //
                        // So the classification columns are written only
                        // for rows still carrying a built-in kind. The
                        // rest - the codec/resolution/language backfill
                        // this pass exists for - is unconditional, and is
                        // correct for custom rows too, because
                        // `apply_custom` mutates ONLY kind and key.
                        // '' is in the list deliberately: a row that has
                        // never been classified still needs its first
                        // parse.
                        let mut upd = tx.prepare_cached(
                            "UPDATE releases SET langs=?2, res=?3,
                                    vcodec=?4, acodec=?5, hdr=?6
                             WHERE id=?1 AND (langs<>?2 OR res<>?3
                                    OR vcodec<>?4 OR acodec<>?5 OR hdr<>?6)",
                        )?;
                        let mut upd_class = tx.prepare_cached(
                            "UPDATE releases SET junk=?2, title_key=?3, kind=?4
                             WHERE id=?1
                               AND kind IN ('movie','tv','music','book',
                                            'software','other','')
                               AND (junk<>?2 OR title_key<>?3 OR kind<>?4)",
                        )?;
                        for (id, stem, bytes, has_exe) in &rows {
                            let p = crate::release::parse_release(stem);
                            upd.execute(rusqlite::params![
                                id,
                                p.langs.join(" "),
                                p.res.as_deref().unwrap_or_default(),
                                p.vcodec.as_deref().unwrap_or_default(),
                                p.acodec.as_deref().unwrap_or_default(),
                                p.hdr.as_deref().unwrap_or_default()
                            ])?;
                            upd_class.execute(rusqlite::params![
                                id,
                                junk_score(stem, &p, *bytes as u64, *has_exe),
                                p.key,
                                kind_str(&p.kind)
                            ])?;
                        }
                    }
                    cursor = rows.last().unwrap().0;
                    tx.execute(
                        "INSERT INTO kv(k, v) VALUES('quality_v8_cursor', ?1)
                         ON CONFLICT(k) DO UPDATE SET v=?1",
                        [cursor.to_string()],
                    )?;
                    tx.commit()?;
                }
                Ok(())
            })();
        }
        // M29 availability oracle: (backbone, family, age-bucket) ledger.
        let _ = crate::oracle::ensure_schema(&db);
        Ok(Index { db, gate: None, fts, people_fts, custom: Vec::new() })
    }

    /// A read-only connection for query handlers, so an interactive
    /// wall/search/browse request never queues behind whoever is holding
    /// a read-write connection through a long ingest or maintenance
    /// pass. The database is WAL, so this connection's reads run
    /// concurrently with the writer and each query begins a fresh read
    /// transaction - it always sees the latest committed data without
    /// being reopened.
    ///
    /// Skips every migration `open` runs (a read-only handle cannot run
    /// them, and must not need to): callers open this only after a
    /// read-write `open` has brought the schema up to date. Fails if the
    /// database file does not exist yet - it must never be the call that
    /// creates the file.
    pub fn open_read_only(path: &Path) -> rusqlite::Result<Index> {
        let db = Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
                | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX
                | rusqlite::OpenFlags::SQLITE_OPEN_URI,
        )?;
        // Readers in WAL only ever wait on the brief WAL-reset window of
        // a checkpoint, but "brief" still deserves a timeout rather than
        // an instant "database is locked".
        db.busy_timeout(std::time::Duration::from_secs(10))?;
        // The per-connection tuning half of open()'s pragmas; query_only
        // makes any write that sneaks onto this connection fail loudly
        // instead of contending for the write lock.
        db.execute_batch(
            "PRAGMA query_only=ON;
             PRAGMA temp_store=MEMORY;
             PRAGMA cache_size=-262144;
             PRAGMA mmap_size=1073741824;",
        )?;
        // FTS availability is detected, not created: the tables exist iff
        // the read-write open that ran the schema managed to create them.
        let has = |name: &str| {
            db.query_row(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1",
                [name],
                |_| Ok(()),
            )
            .is_ok()
        };
        let fts = has("rel_fts");
        let people_fts = fts && has("people_fts");
        // No gate and no custom categories: both are ingest-time policy,
        // and ingest cannot happen on a query_only connection.
        Ok(Index { db, gate: None, fts, people_fts, custom: Vec::new() })
    }

    // ---- M29 availability oracle -------------------------------------

    /// Fold a batch of hit/miss samples into the oracle ledger.
    pub fn oracle_ingest(
        &self,
        samples: &[crate::oracle::Sample],
        now: i64,
    ) -> rusqlite::Result<()> {
        crate::oracle::ingest(&self.db, samples, now)
    }

    /// The whole ledger (tiny by construction) for verdict computation.
    pub fn oracle_snapshot(&self) -> rusqlite::Result<crate::oracle::Snapshot> {
        crate::oracle::Snapshot::load(&self.db)
    }

    /// Releases the idle STAT sampler should probe next: never-sampled
    /// first, then stalest verdict, newest post first within a tier.
    /// Returns (id, group, first_posted).
    pub fn oracle_pick(&self, limit: u32) -> rusqlite::Result<Vec<(i64, String, i64)>> {
        // Sample what users can actually SEE (junk < 50) - stalest-first
        // over the whole table drowned the sampler in the endless stream
        // of freshly-scanned obfuscated rows: every probe was a 0-day
        // article, bucket 0 was the only bucket that ever learned, and
        // old-post availability (the interesting question) stayed
        // unknown forever. Random tiebreak inside the stalest half
        // spreads picks across post ages.
        let mut stmt = self.db.prepare(
            "SELECT id, grp, first_posted FROM releases
             WHERE junk < 50
             ORDER BY oracle_at ASC, (id * 2654435761) % 4294967296 LIMIT ?1",
        )?;
        let rows = stmt.query_map([limit], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        rows.collect()
    }

    /// Up to `max` probe message-ids for a release, spread evenly across
    /// its files' segments (bracketed, STAT-ready).
    pub fn oracle_msgids(&self, release_id: i64, max: usize) -> rusqlite::Result<Vec<String>> {
        let mut stmt = self
            .db
            .prepare("SELECT segments FROM files WHERE release_id=?1 ORDER BY filename")?;
        let segs: Vec<String> = stmt
            .query_map([release_id], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        let mut ids: Vec<String> = Vec::new();
        for s in segs {
            let parsed: Vec<(u32, String, u64)> = serde_json::from_str(&s).unwrap_or_default();
            ids.extend(parsed.into_iter().map(|(_, id, _)| id));
        }
        if ids.is_empty() || max == 0 {
            return Ok(Vec::new());
        }
        // Even spread over the whole release - head-only sampling would
        // miss partial takedowns of the tail.
        let step = (ids.len() as f64 / max.min(ids.len()) as f64).max(1.0);
        let mut out = Vec::with_capacity(max.min(ids.len()));
        let mut at = 0.0f64;
        while (at as usize) < ids.len() && out.len() < max {
            let id = &ids[at as usize];
            let b = if id.starts_with('<') { id.clone() } else { format!("<{id}>") };
            out.push(b);
            at += step;
        }
        Ok(out)
    }

    /// Stamp a release as sampled now (rotates the pick order).
    pub fn oracle_mark(&self, release_id: i64, now: i64) -> rusqlite::Result<()> {
        self.db.execute(
            "UPDATE releases SET oracle_at=?2 WHERE id=?1",
            rusqlite::params![release_id, now],
        )?;
        Ok(())
    }

    /// A8 targeted gap-fill: incomplete releases worth re-hunting on the
    /// other backbones, least-recently-tried first (gapfill_at 0 =
    /// never). Junk-gated like the sampler - the endless obfuscated
    /// stream must not eat the budget users could see spent on real
    /// cards. Releases first seen in the last hour are skipped: their
    /// missing parts are usually still propagating (or still uploading),
    /// and the next tip pass gets them for free.
    /// Returns (id, group, first_posted).
    pub fn gapfill_pick(&self, limit: u32, now: i64) -> rusqlite::Result<Vec<(i64, String, i64)>> {
        let mut stmt = self.db.prepare(
            "SELECT id, grp, first_posted FROM releases
             WHERE complete=0 AND junk < 50 AND first_posted > 0
               AND first_seen < ?2
             ORDER BY gapfill_at ASC, (id * 2654435761) % 4294967296 LIMIT ?1",
        )?;
        let rows = stmt
            .query_map(rusqlite::params![limit, now - 3600], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })?;
        rows.collect()
    }

    /// Stamp a release as gap-fill-tried now (rotates the pick order).
    pub fn gapfill_mark(&self, release_id: i64, now: i64) -> rusqlite::Result<()> {
        self.db.execute(
            "UPDATE releases SET gapfill_at=?2 WHERE id=?1",
            rusqlite::params![release_id, now],
        )?;
        Ok(())
    }

    /// Is this release complete? (gap-fill measures its own success by
    /// the flip.)
    pub fn is_complete(&self, release_id: i64) -> bool {
        self.db
            .query_row(
                "SELECT complete FROM releases WHERE id=?1",
                [release_id],
                |r| r.get(0),
            )
            .unwrap_or(false)
    }

    /// Tiny persisted key/value pairs (dataset refresh stamps and such).
    pub fn kv_get(&self, k: &str) -> Option<String> {
        self.db
            .query_row("SELECT v FROM kv WHERE k=?1", [k], |r| r.get(0))
            .ok()
    }

    pub fn kv_set(&self, k: &str, v: &str) -> rusqlite::Result<()> {
        self.db.execute(
            "INSERT INTO kv(k, v) VALUES(?1, ?2)
             ON CONFLICT(k) DO UPDATE SET v=excluded.v",
            [k, v],
        )?;
        Ok(())
    }

    /// Replace the whole IMDb ratings snapshot (nightly dataset ingest).
    /// One transaction; returns rows kept.
    pub fn imdb_ratings_replace(
        &mut self,
        rows: impl Iterator<Item = (String, f64, u64)>,
    ) -> rusqlite::Result<u64> {
        let tx = self.db.transaction()?;
        tx.execute("DELETE FROM imdb_ratings", [])?;
        let mut n = 0u64;
        {
            let mut ins = tx.prepare(
                "INSERT INTO imdb_ratings(tconst, rating, votes) VALUES(?1, ?2, ?3)",
            )?;
            for (t, r, v) in rows {
                ins.execute(rusqlite::params![t, r, v as i64])?;
                n += 1;
            }
        }
        tx.commit()?;
        Ok(n)
    }

    /// (rating, votes) for an IMDb tconst, if the snapshot holds it.
    pub fn imdb_rating(&self, tconst: &str) -> Option<(f64, u64)> {
        self.db
            .query_row(
                "SELECT rating, votes FROM imdb_ratings WHERE tconst=?1",
                [tconst],
                |r| Ok((r.get(0)?, r.get::<_, i64>(1)? as u64)),
            )
            .ok()
    }

    /// Install an ingest gate (see the `gate` field).
    pub fn set_gate(&mut self, gate: Box<dyn Fn(&str) -> bool + Send>) {
        self.gate = Some(gate);
    }

    /// Install the user's custom categories (see the `custom` field).
    pub fn set_custom(&mut self, cats: Vec<crate::categories::CustomCategory>) {
        self.custom = cats;
    }

    /// Ingest-time parse: built-in classifier plus the installed custom
    /// categories. Every site that WRITES kind/title_key must call this,
    /// not `parse_release`, or custom rows would flap back to their
    /// built-in kind on the next re-ingest touch.
    fn classify(&self, stem: &str) -> crate::release::Parsed {
        crate::categories::classify(stem, &self.custom)
    }

    /// TODO 24D: chunked re-classification of stored rows after the
    /// category config changed. Same shape as the quality_v8 migration
    /// (10k-row transactions, persisted cursor, write-only-on-change) so
    /// it can run against a live db without starving parallel scanners.
    /// The current config's fingerprint is stamped in `kv`; calling this
    /// again with an unchanged config is a cheap no-op. Returns the
    /// number of rows whose classification changed.
    pub fn reclassify_custom(&self) -> rusqlite::Result<u64> {
        let want = crate::categories::config_hash(&self.custom);
        let have: Option<String> =
            self.db.query_row("SELECT v FROM kv WHERE k='custom_cats_cfg'", [], |r| r.get(0)).ok();
        let cursor_key = "custom_cats_cursor";
        let mut cursor: i64 = if have.as_deref() == Some(want.as_str()) {
            // Same config: either done (no cursor) or resuming a pass
            // that a restart interrupted.
            match self
                .db
                .query_row("SELECT v FROM kv WHERE k=?1", [cursor_key], |r| r.get::<_, String>(0))
                .ok()
                .and_then(|v| v.parse().ok())
            {
                Some(c) => c,
                None => return Ok(0),
            }
        } else {
            // New config: stamp it and start from the top. Stamping
            // FIRST is deliberate - an interrupted pass resumes from the
            // cursor rather than restarting, exactly like quality_v8.
            // The fingerprint and cursor are ONE state transition. Two
            // autocommit writes left a crash window where the new
            // fingerprint existed without a cursor; every later call then
            // read that as "already finished" and skipped reclassification
            // forever.
            // IMMEDIATE, not the deferred `unchecked_transaction`: this
            // reads a cursor and writes it back, and a deferred lock
            // upgrade does NOT get the busy timeout - it returns
            // SQLITE_BUSY at once (the same trap the nsegs migration
            // above documents). Losing it costs no data, but the retry is
            // a whole scan interval away, so a category change looks like
            // it did nothing.
            let tx = rusqlite::Transaction::new_unchecked(
                &self.db,
                rusqlite::TransactionBehavior::Immediate,
            )?;
            tx.execute(
                "INSERT INTO kv(k, v) VALUES('custom_cats_cfg', ?1)
                 ON CONFLICT(k) DO UPDATE SET v=?1",
                [&want],
            )?;
            tx.execute(
                "INSERT INTO kv(k, v) VALUES(?1, '0')
                 ON CONFLICT(k) DO UPDATE SET v='0'",
                [cursor_key],
            )?;
            tx.commit()?;
            0
        };
        let mut changed = 0u64;
        loop {
            let tx = rusqlite::Transaction::new_unchecked(
                &self.db,
                rusqlite::TransactionBehavior::Immediate,
            )?;
            let rows: Vec<(i64, String, i64, bool)> = {
                let mut sel = tx.prepare_cached(&format!(
                    "SELECT id, stem, total_bytes,
                            EXISTS(SELECT 1 FROM files
                                   WHERE release_id=releases.id AND {EXE_FILE_SQL})
                     FROM releases WHERE id > ?1 ORDER BY id LIMIT 10000"
                ))?;
                sel.query_map([cursor], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
                })?
                .collect::<rusqlite::Result<_>>()?
            };
            if rows.is_empty() {
                tx.execute("DELETE FROM kv WHERE k=?1", [cursor_key])?;
                tx.commit()?;
                break;
            }
            {
                let mut upd = tx.prepare_cached(
                    "UPDATE releases SET kind=?2, title_key=?3, junk=?4
                     WHERE id=?1 AND (kind<>?2 OR title_key<>?3 OR junk<>?4)",
                )?;
                for (id, stem, bytes, has_exe) in &rows {
                    let p = self.classify(stem);
                    changed += upd.execute(rusqlite::params![
                        id,
                        kind_str(&p.kind),
                        p.key,
                        junk_score(stem, &p, *bytes as u64, *has_exe),
                    ])? as u64;
                }
            }
            cursor = rows.last().unwrap().0;
            tx.execute(
                "INSERT INTO kv(k, v) VALUES(?1, ?2) ON CONFLICT(k) DO UPDATE SET v=?2",
                rusqlite::params![cursor_key, cursor.to_string()],
            )?;
            tx.commit()?;
        }
        Ok(changed)
    }

    /// Canonical marks identity for a server: the lowercased host.
    /// Precise on purpose - even same-backbone resellers get their own
    /// rows, because nothing guarantees two spools share numbering.
    pub fn server_key(host: &str) -> String {
        host.trim().to_ascii_lowercase()
    }

    /// One-time adoption of single-server-era marks rows (server=''):
    /// they were built against whichever server was `servers[0]`, so the
    /// caller passes that host and the rows become its. A group that
    /// already has a row for this server keeps it (the fresher of the
    /// two); its legacy row is dropped either way. Idempotent - after
    /// the first call there are no '' rows left.
    pub fn adopt_legacy_marks(&self, host: &str) -> rusqlite::Result<()> {
        let server = Self::server_key(host);
        if server.is_empty() {
            return Ok(());
        }
        self.db.execute(
            "UPDATE marks SET server=?1
              WHERE server=''
                AND grp NOT IN (SELECT grp FROM marks WHERE server=?1)",
            [&server],
        )?;
        self.db.execute("DELETE FROM marks WHERE server=''", [])?;
        Ok(())
    }

    /// Deepest article this group's history has been scanned back to on
    /// `server` (0 = never recorded). The scan loop's auto-deepen
    /// extends this downward a bounded slice per pass.
    pub fn low_water(&self, grp: &str, server: &str) -> u64 {
        self.db
            .query_row(
                "SELECT low FROM marks WHERE grp=?1 AND server=?2",
                [grp, &Self::server_key(server)],
                |r| r.get::<_, i64>(0),
            )
            .map(|v| v as u64)
            .unwrap_or(0)
    }

    pub fn set_low_water(&self, grp: &str, server: &str, low: u64) -> rusqlite::Result<()> {
        self.db.execute(
            "INSERT INTO marks(grp, server, high, low) VALUES(?1, ?2, 0, ?3)
             ON CONFLICT(grp, server) DO UPDATE SET low=excluded.low",
            rusqlite::params![grp, Self::server_key(server), low as i64],
        )?;
        Ok(())
    }

    pub fn high_water(&self, grp: &str, server: &str) -> u64 {
        self.db
            .query_row(
                "SELECT high FROM marks WHERE grp=?1 AND server=?2",
                [grp, &Self::server_key(server)],
                |r| r.get::<_, i64>(0),
            )
            .map(|v| v as u64)
            .unwrap_or(0)
    }

    pub fn set_high_water(&self, grp: &str, server: &str, high: u64) -> rusqlite::Result<()> {
        self.db.execute(
            "INSERT INTO marks(grp, server, high) VALUES(?1, ?2, ?3)
             ON CONFLICT(grp, server) DO UPDATE SET high=excluded.high",
            rusqlite::params![grp, Self::server_key(server), high as i64],
        )?;
        Ok(())
    }

    /// Ingest one batch of OVER entries for `grp`. Returns releases whose
    /// completeness changed to complete in this batch.
    pub fn ingest(&mut self, grp: &str, entries: &[OverEntry], now: i64) -> rusqlite::Result<u32> {
        // Cluster the batch in memory first: (poster, stem) → filename →
        // (total, parts: number → (msgid, bytes)).
        type Parts = BTreeMap<u32, (String, u64)>;
        let mut clusters: HashMap<(String, String), HashMap<String, (u32, Parts)>> = HashMap::new();
        // Earliest article Date per cluster → the release's upload time.
        let mut posted: HashMap<(String, String), i64> = HashMap::new();
        for e in entries {
            let (base, part, total) =
                split_subject(&e.subject).unwrap_or_else(|| (e.subject.clone(), 1, 1));
            if e.message_id.is_empty() || part == 0 || total == 0 {
                continue;
            }
            let Some(fname) = quoted_name(&base) else { continue };
            let stem = release_stem(&fname);
            if stem.is_empty() {
                continue;
            }
            let key = (e.from.clone(), stem);
            if e.date > 0 {
                // Clamp a future Date: header to the scan time. A garbled or
                // hostile far-future date would otherwise pin the release to
                // the top of the "newest" sort forever AND make it immune to
                // age-retention pruning (first_posted < cutoff never holds).
                let d = e.date.min(now);
                let p = posted.entry(key.clone()).or_insert(d);
                *p = (*p).min(d);
            }
            clusters
                .entry(key)
                .or_default()
                .entry(fname)
                .or_insert_with(|| (total, BTreeMap::new()))
                .1
                .insert(part, (e.message_id.clone(), e.bytes));
        }
        if let Some(gate) = &self.gate {
            clusters.retain(|(_, stem), _| gate(stem));
        }

        // IMMEDIATE, not the default DEFERRED. A deferred transaction takes
        // its write lock lazily, on the first write statement, and SQLite
        // does NOT apply the busy timeout to that upgrade - it returns
        // SQLITE_BUSY immediately. The `?` then aborts the whole scan pass
        // for that group until the next interval. Every group scan opens
        // its own Index and the shared handle is replaced after each pass,
        // so there is one vulnerable ingest per group per pass, forever.
        let tx = self
            .db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let mut completed = 0u32;
        for ((poster, stem), files) in clusters {
            // Real upload time when the batch carried Dates; scan time
            // otherwise. MIN on conflict lets an older batch (backfill
            // runs newest-first) walk first_posted back to the truth.
            // Clamp to now + 1 day of clock skew: the Date comes from an
            // untrusted OVER header, and a far-future date would pin the release
            // atop every Latest/Posted view for years AND dodge both retention
            // prunes (they only delete rows OLDER than a cutoff).
            let up = posted
                .get(&(poster.clone(), stem.clone()))
                .copied()
                .unwrap_or(now)
                .min(now + 86_400);
            tx.prepare_cached(
                "INSERT INTO releases(stem, poster, grp, first_seen, first_posted)
                 VALUES(?1, ?2, ?3, ?4, ?5)
                 ON CONFLICT(stem, poster, grp) DO UPDATE SET
                   first_posted=MIN(first_posted, excluded.first_posted)",
            )?
            .execute(rusqlite::params![stem, poster, grp, now, up])?;
            let rid: i64 = tx
                .prepare_cached("SELECT id FROM releases WHERE stem=?1 AND poster=?2 AND grp=?3")?
                .query_row(rusqlite::params![stem, poster, grp], |r| r.get(0))?;
            for (fname, (total, parts)) in files {
                // Merge with existing segments (batches split arbitrarily).
                let existing: Option<(String, u32)> = tx
                    .prepare_cached(
                        "SELECT segments, total_parts FROM files
                          WHERE release_id=?1 AND filename=?2",
                    )?
                    .query_row(rusqlite::params![rid, fname], |r| Ok((r.get(0)?, r.get(1)?)))
                    .ok();
                // A file's "(x/y)" total does not change within one posting.
                // If it disagrees with what we already hold, these are two
                // DIFFERENT postings that happen to reuse a filename - most
                // often a re-rar at a new volume size. Unioning their part
                // numbers used to satisfy `nsegs >= total_parts` from two
                // incompatible sets at once, so the release went complete
                // and make_nzb emitted message-ids from both generations:
                // a "complete" download that extracts to garbage.
                //
                // Keep the generation already established and drop the
                // conflicting batch for this file. Being wrong that way
                // costs a release that reads incomplete until a rescan;
                // being wrong the other way hands the user a corrupt file
                // and calls it done. It also means a single garbled
                // subject line cannot wipe an accumulated set.
                //
                // The real fix is a generation identity on `files` so both
                // postings can be indexed side by side, which needs a
                // schema migration. Pinned by the D3 regression test.
                if let Some((_, prev_total)) = &existing {
                    if *prev_total > 0 && total > 0 && *prev_total != total {
                        eprintln!(
                            "[index] {fname}: ignoring a batch claiming {total} parts, \
                             already tracking {prev_total} - reused filename, different posting"
                        );
                        continue;
                    }
                }
                let mut merged: BTreeMap<u32, (String, u64)> = existing
                    .and_then(|(s, _)| serde_json::from_str::<Vec<(u32, String, u64)>>(&s).ok())
                    .map(|v| v.into_iter().map(|(n, id, b)| (n, (id, b))).collect())
                    .unwrap_or_default();
                for (n, v) in parts {
                    merged.insert(n, v);
                }
                let bytes: u64 = merged.values().map(|v| v.1).sum();
                let seg_json = serde_json::to_string(
                    &merged
                        .iter()
                        .map(|(n, (id, b))| (*n, id.clone(), *b))
                        .collect::<Vec<_>>(),
                )
                .unwrap();
                tx.prepare_cached(
                    "INSERT INTO files(release_id, filename, total_parts, bytes, segments, nsegs)
                     VALUES(?1, ?2, ?3, ?4, ?5, ?6)
                     ON CONFLICT(release_id, filename) DO UPDATE SET
                       total_parts=excluded.total_parts, bytes=excluded.bytes,
                       segments=excluded.segments, nsegs=excluded.nsegs",
                )?
                .execute(rusqlite::params![
                    rid,
                    fname,
                    total,
                    bytes as i64,
                    seg_json,
                    merged.len() as i64
                ])?;
            }
            // Recompute release aggregates.
            let (nfiles, tbytes, ncomplete, npar2, have, need, nexe): (
                u32,
                i64,
                u32,
                u32,
                i64,
                i64,
                u32,
            ) = tx
                .prepare_cached(&format!(
                    "SELECT COUNT(*), COALESCE(SUM(bytes),0),
                            SUM(CASE WHEN nsegs > 0 THEN nsegs
                                     ELSE json_array_length(segments) END >= total_parts),
                            SUM(LOWER(filename) LIKE '%.par2'),
                            COALESCE(SUM(CASE WHEN nsegs > 0 THEN nsegs
                                              ELSE json_array_length(segments) END),0),
                            COALESCE(SUM(total_parts),0),
                            SUM({EXE_FILE_SQL})
                     FROM files WHERE release_id=?1"
                ))?
                .query_row([rid], |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                    ))
                })?;
            // A release is complete when every file we've seen has all
            // its parts. Single-file posts (one mkv/iso, no par2 set)
            // are common and legitimate - the old `nfiles >= 2` rule
            // froze them all as incomplete forever (measured 55% of a
            // live teevee+moovee index). Indexer-spam tiny posts are the
            // size gate's job (gates min_size), not this flag's.
            let complete = nfiles >= 1 && ncomplete == nfiles;
            let was: bool = tx
                .prepare_cached("SELECT complete FROM releases WHERE id=?1")?
                .query_row([rid], |r| r.get(0))?;
            // kind/res parse once per touched cluster - cheap (pure text)
            // and idempotent, so re-ingest keeps them current. Runs
            // through the installed custom categories (24D) so a user
            // kind survives re-ingest touches. (Field access, not
            // self.classify - `tx` holds the &mut borrow of self.db.)
            let p = crate::categories::classify(&stem, &self.custom);
            tx.prepare_cached(
                "UPDATE releases SET files=?2, total_bytes=?3, has_par2=?4, complete=?5,
                        kind=?6, res=?7, have_parts=?8, need_parts=?9,
                        title_key=?10, junk=?11, langs=?12,
                        vcodec=?13, acodec=?14, hdr=?15
                 WHERE id=?1",
            )?
            .execute(rusqlite::params![
                    rid,
                    nfiles,
                    tbytes as i64,
                    npar2 > 0,
                    complete,
                    kind_str(&p.kind),
                    p.res.as_deref().unwrap_or_default(),
                    have,
                    need,
                    p.key,
                    junk_score(&stem, &p, tbytes as u64, nexe > 0),
                    p.langs.join(" "),
                    p.vcodec.as_deref().unwrap_or_default(),
                    p.acodec.as_deref().unwrap_or_default(),
                    p.hdr.as_deref().unwrap_or_default()
            ])?;
            if complete && !was {
                completed += 1;
            }
        }
        tx.commit()?;
        Ok(completed)
    }

    /// Search by substring over the stem (case-insensitive), newest first.
    pub fn search(&self, query: &str, limit: u32) -> rusqlite::Result<Vec<Release>> {
        // Separator-insensitive, multi-term AND search: stems are stored
        // dotted ("Show.Name.S01E02") but *arr clients query with spaces
        // ("show name s01e02"), so normalize both sides to spaces and
        // require every query word to appear. Empty query = everything.
        let norm = |s: &str| {
            s.to_ascii_lowercase()
                .replace(['.', '_', '-'], " ")
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
        };
        let terms: Vec<String> = norm(query).split(' ').filter(|t| !t.is_empty()).map(String::from).collect();
        // M28: FTS path - prefix-match every term against the stem index
        // instead of a triple-REPLACE full scan per request. Gate on the
        // FTS expression itself, not `terms`: a punctuation-only query
        // ("!!!") yields a non-empty `terms` but an EMPTY fts_match, and
        // `rel_fts MATCH ''` is a hard FTS5 error - fall through to the
        // LIKE scan instead (mirrors browse()).
        let m = if self.fts { fts_match(query) } else { String::new() };
        if !m.is_empty() {
            let mut stmt = self.db.prepare(&format!(
                "SELECT {REL_COLS} FROM releases
                 WHERE id IN (SELECT rowid FROM rel_fts WHERE rel_fts MATCH ?1)
                 ORDER BY first_seen DESC LIMIT ?2"
            ))?;
            let rows = stmt.query_map(rusqlite::params![m, limit], release_from_row)?;
            return rows.collect();
        }
        // "REPLACE(REPLACE(REPLACE(LOWER(stem)…))" mirrors `norm` in SQL.
        const NS: &str = "REPLACE(REPLACE(REPLACE(LOWER(stem),'.',' '),'_',' '),'-',' ')";
        let where_clause = if terms.is_empty() {
            "1=1".to_string()
        } else {
            terms
                .iter()
                .enumerate()
                .map(|(i, _)| format!("{NS} LIKE '%' || ?{} || '%'", i + 1))
                .collect::<Vec<_>>()
                .join(" AND ")
        };
        let sql = format!(
            "SELECT {REL_COLS} FROM releases WHERE {where_clause}
             ORDER BY first_seen DESC LIMIT ?{}",
            terms.len() + 1
        );
        let mut stmt = self.db.prepare(&sql)?;
        let mut params: Vec<&dyn rusqlite::ToSql> = terms
            .iter()
            .map(|t| t as &dyn rusqlite::ToSql)
            .collect();
        params.push(&limit);
        let rows = stmt.query_map(params.as_slice(), release_from_row)?;
        rows.collect()
    }

    /// Find the release an NZBLNK header names, best candidate first.
    ///
    /// An NZBLNK carries no article ids: `h` is a string distinctive
    /// enough to identify one posting in a raw-header index, which is
    /// exactly what we are. The header is usually the obfuscated release
    /// name itself, so it turns up as a release stem; on posts whose
    /// subject was scrambled per-file it turns up as a FILENAME instead.
    /// Both surfaces are tried, cheapest first:
    ///
    /// 1. `stem` equality, which `idx_rel_stem` answers outright;
    /// 2. the FTS index, verified afterwards by normalized containment
    ///    (FTS matches by token prefix, so an unverified hit would let
    ///    "abc" claim "abcdefgh");
    /// 3. `files.filename`, anchored at the start.
    ///
    /// Rung 3 is a table scan - no index covers `filename` alone - so it
    /// only ever runs when the two indexed rungs missed, and a header
    /// too short to identify anything (< 4 characters) is refused before
    /// it can pay for one.
    ///
    /// Callers get whole [`Release`] rows and decide for themselves;
    /// [`Self::make_nzb`] then emits a complete NZB from the segment
    /// ids the scan already stored.
    pub fn find_by_header(&self, header: &str, limit: u32) -> rusqlite::Result<Vec<Release>> {
        let header = header.trim();
        if header.chars().count() < 4 {
            return Ok(Vec::new());
        }
        // Same normalization `search` uses: stems are stored dotted and
        // a header may be spelled with spaces (or the other way round).
        let norm = |s: &str| {
            s.to_ascii_lowercase()
                .replace(['.', '_', '-'], " ")
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
        };
        let want = norm(header);
        let mut out: Vec<Release> = Vec::new();
        let mut seen: std::collections::HashSet<i64> = std::collections::HashSet::new();
        let mut push = |rows: Vec<Release>, out: &mut Vec<Release>| {
            for r in rows {
                if seen.insert(r.id) {
                    out.push(r);
                }
            }
        };

        // Every rung below stops the ladder the moment ANYTHING answers.
        // The gates used to be `out.len() >= limit` with the caller passing
        // limit=8, and a distinctive header resolves to exactly one row, so
        // one was never eight and EVERY lookup ran every rung - on a hit as
        // well as a miss. Measured on a 16.5M-release / 17.7M-file index:
        // 1.7 s for a SUCCESSFUL resolution, 2.4 s warm and 4.3 s cold for
        // one that matches nothing, all of it holding the single shared
        // read connection that every other index reader queues behind.
        // A hit is now sub-millisecond on that same index (the indexed
        // equality alone); only a genuine miss pays for the scans.
        //
        // 1a. Exact stem, served from idx_rel_stem.
        let mut stmt = self
            .db
            .prepare(&format!("SELECT {REL_COLS} FROM releases WHERE stem = ?1 LIMIT ?2"))?;
        let rows: Vec<Release> = stmt
            .query_map(rusqlite::params![header, limit], release_from_row)?
            .collect::<Result<_, _>>()?;
        push(rows, &mut out);
        if !out.is_empty() {
            out.truncate(limit as usize);
            return Ok(out);
        }

        // 1b. Case-insensitively, so a board that SHOUTS the header still
        //     finds the row. Its own statement rather than a UNION ALL arm:
        //     idx_rel_stem is BINARY so this cannot use it, and inside a
        //     UNION ALL under `LIMIT 8` SQLite must evaluate it to look for
        //     the other seven even when the exact arm already matched - so
        //     the full scan ran on every hit. Now it runs only when 1a
        //     found nothing, which is the case the comment always claimed.
        let mut stmt = self.db.prepare(&format!(
            "SELECT {REL_COLS} FROM releases WHERE stem = ?1 COLLATE NOCASE LIMIT ?2"
        ))?;
        let rows: Vec<Release> = stmt
            .query_map(rusqlite::params![header, limit], release_from_row)?
            .collect::<Result<_, _>>()?;
        push(rows, &mut out);
        if !out.is_empty() {
            out.truncate(limit as usize);
            return Ok(out);
        }

        // 2. FTS (or the LIKE fallback on a database without it), then
        //    verify: only a stem that really contains the header counts.
        let m = if self.fts { fts_match(header) } else { String::new() };
        let cands: Vec<Release> = if !m.is_empty() {
            let mut stmt = self.db.prepare(&format!(
                "SELECT {REL_COLS} FROM releases
                  WHERE id IN (SELECT rowid FROM rel_fts WHERE rel_fts MATCH ?1)
                  ORDER BY first_seen DESC LIMIT ?2"
            ))?;
            stmt.query_map(rusqlite::params![m, FIND_SCAN_CAP], release_from_row)?
                .collect::<Result<_, _>>()?
        } else {
            const NS: &str = "REPLACE(REPLACE(REPLACE(LOWER(stem),'.',' '),'_',' '),'-',' ')";
            let mut stmt = self.db.prepare(&format!(
                "SELECT {REL_COLS} FROM releases WHERE {NS} LIKE '%' || ?1 || '%'
                  ORDER BY first_seen DESC LIMIT ?2"
            ))?;
            stmt.query_map(rusqlite::params![want, FIND_SCAN_CAP], release_from_row)?
                .collect::<Result<_, _>>()?
        };
        push(cands.into_iter().filter(|r| norm(&r.stem).contains(&want)).collect(), &mut out);
        // Same reasoning as rung 1: rung 3 is a full scan of `files`, which
        // is the bigger table, so it must run only when nothing at all has
        // answered - not merely when fewer than `limit` things have.
        if !out.is_empty() {
            out.truncate(limit as usize);
            return Ok(out);
        }

        // 3. Filenames, anchored. The header's own LIKE metacharacters
        //    are escaped - an obfuscated name is allowed to contain `_`,
        //    and unescaped that is a single-character wildcard.
        let esc = header.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_");
        let mut stmt = self.db.prepare(&format!(
            "SELECT {REL_COLS} FROM releases WHERE id IN (
                 SELECT release_id FROM files
                  WHERE filename LIKE ?1 || '%' ESCAPE '\\' LIMIT ?2)
              ORDER BY first_seen DESC"
        ))?;
        let rows: Vec<Release> = stmt
            .query_map(rusqlite::params![esc, FIND_SCAN_CAP], release_from_row)?
            .collect::<Result<_, _>>()?;
        push(rows, &mut out);
        out.truncate(limit as usize);
        Ok(out)
    }

    /// Resolve a newznab `imdbid` to the parse-key its releases carry,
    /// so an id-based Radarr search can be answered from the enriched
    /// `titles` table instead of a title substring.
    ///
    /// Newznab carries the bare number (`imdbid=0468569`) while we store
    /// the canonical `tt`-prefixed form, and IMDb widened from 7 digits
    /// to 8 - so both the zero-padded and the as-given widths are tried.
    /// `None` means "we hold nothing for that id", which the facade must
    /// answer with an empty feed rather than an unfiltered one.
    pub fn title_key_for_imdb(&self, imdb: &str) -> rusqlite::Result<Option<String>> {
        let digits: String = imdb.chars().filter(|c| c.is_ascii_digit()).collect();
        if digits.is_empty() {
            return Ok(None);
        }
        let padded = format!("tt{digits:0>7}");
        let bare = format!("tt{digits}");
        self.db
            .query_row(
                "SELECT key FROM titles WHERE imdb=?1 OR imdb=?2 LIMIT 1",
                rusqlite::params![padded, bare],
                |r| r.get(0),
            )
            .optional()
    }

    /// Resolve a newznab `tmdbid` to its parse-key - the
    /// [`Self::title_key_for_imdb`] counterpart for the id Radarr sends
    /// when it has no IMDb id for a title.
    ///
    /// MOVIE rows only, and that is the whole point. `titles.tmdb_id`
    /// carries a TMDB movie id on a movie row and a TVmaze SHOW id on a
    /// TV row - two unrelated numbering schemes sharing one column, both
    /// small dense integers, so collisions are not a corner case but the
    /// expected state of a populated index. Unfiltered, a Radarr
    /// `t=movie&tmdbid=N` could resolve a TV series that merely happens
    /// to be TVmaze #N and answer with its episodes; with both rows
    /// present, `LIMIT 1` picked between them arbitrarily.
    ///
    /// An id we hold no MOVIE for answers None, which the caller turns
    /// into an empty feed - never a fall-through to the other namespace.
    pub fn title_key_for_tmdb(&self, tmdb: i64) -> rusqlite::Result<Option<String>> {
        if tmdb <= 0 {
            return Ok(None);
        }
        self.db
            .query_row(
                "SELECT key FROM titles WHERE tmdb_id=?1 AND kind='movie' LIMIT 1",
                rusqlite::params![tmdb],
                |r| r.get(0),
            )
            .optional()
    }

    /// The one year the index knows a movie title by - or None when it
    /// knows none, or more than one. The renamer asks this for a
    /// yearless post, and the ambiguity rule is the whole safety story:
    /// a remade title ("The Thing") has two keys with two years, and
    /// guessing between them names the file after the wrong film. Keys
    /// are `m:<norm>` (yearless parse, year filled by enrichment) and
    /// `m:<norm>:<year>`; `norm_title` output is alphanumeric+spaces,
    /// so the LIKE pattern needs no escaping.
    pub fn movie_year(&self, norm: &str) -> rusqlite::Result<Option<u32>> {
        if norm.is_empty() {
            return Ok(None);
        }
        let key = format!("m:{norm}");
        let mut stmt = self.db.prepare(
            "SELECT DISTINCT year FROM titles
              WHERE (key = ?1 OR key LIKE ?1 || ':%')
                AND kind = 'movie' AND year > 0
              LIMIT 2",
        )?;
        let years: Vec<u32> =
            stmt.query_map([&key], |r| r.get(0))?.collect::<Result<_, _>>()?;
        Ok(match years.as_slice() {
            [y] => Some(*y),
            _ => None,
        })
    }

    /// M25 browse view: filtered, sorted, paginated release listing -
    /// what the wall's list mode and the Newznab facade page through.
    /// Returns (rows, total matching rows) so the UI can paginate.
    pub fn browse(&self, q: &BrowseQuery) -> rusqlite::Result<(Vec<Release>, u64)> {
        // Every predicate is written with `{}` where the table alias
        // goes: the page filters `releases` unqualified, and the
        // representative-copy subquery at the bottom has to apply the
        // SAME filters to its own alias `d`. One list, two renderings -
        // a hand-written second copy would drift. Both renderings cite
        // the same ?N, so nothing below has to renumber.
        let mut wheres: Vec<String> = Vec::new();
        let mut params: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
        let bind = |params: &mut Vec<Box<dyn rusqlite::ToSql>>, v: Box<dyn rusqlite::ToSql>| {
            params.push(v);
            format!("?{}", params.len())
        };
        let alias = |wheres: &[String], pfx: &str| {
            wheres
                .iter()
                .map(|w| w.replace("{}", pfx))
                .collect::<Vec<_>>()
                .join(" AND ")
        };
        if let Some(kind) = &q.kind {
            let p = bind(&mut params, Box::new(kind.clone()));
            wheres.push(format!("{{}}kind = {p}"));
        }
        if let Some(res) = &q.res {
            let p = bind(&mut params, Box::new(res.clone()));
            wheres.push(format!("{{}}res = {p}"));
        }
        if q.complete_only {
            wheres.push("{}complete".into());
        }
        if q.min_bytes > 0 {
            let p = bind(&mut params, Box::new(q.min_bytes as i64));
            wheres.push(format!("{{}}total_bytes >= {p}"));
        }
        if q.newer_than > 0 {
            let p = bind(&mut params, Box::new(q.newer_than));
            wheres.push(format!("{{}}first_posted >= {p}"));
        }
        // M28: junk ceiling (curation) - None = no filter.
        if let Some(max) = q.max_junk {
            let p = bind(&mut params, Box::new(max as i64));
            wheres.push(format!("{{}}junk < {p}"));
        }
        // M28: exact card filter (the detail sheet lists one title's
        // releases via its stored parse key).
        if let Some(tk) = &q.title_key {
            let p = bind(&mut params, Box::new(tk.clone()));
            wheres.push(format!("{{}}title_key = {p}"));
        }
        // M30: user curation (hides + rules). It already takes the alias
        // as an argument, so the placeholder passes straight through.
        if q.curated {
            self.curation_wheres("{}", &mut wheres, &mut params)?;
        }
        // M29 3c: availability verdict as a real SQL predicate. A scalar
        // function backed by the oracle Snapshot keeps ALL verdict logic
        // (Wilson bounds, family fallback, blind-spot demotion) in one
        // place; because the same predicate feeds both the COUNT and the
        // page SELECT below, `total` and the returned rows always agree
        // (the old page-level trim left `total` unfiltered - broken paging).
        let verdict_fn = q.verdict_ok.is_some();
        if let Some(vf) = &q.verdict_ok {
            let snap = vf.snap.clone();
            let bbs = vf.backbones.clone();
            let now = vf.now;
            self.db.create_scalar_function(
                "oracle_ok",
                2,
                rusqlite::functions::FunctionFlags::SQLITE_UTF8,
                move |ctx| {
                    let grp = ctx.get_raw(0).as_str().unwrap_or("");
                    let first_posted: i64 = ctx.get(1)?;
                    // Undated release (no post date): age is UNKNOWN, not
                    // "20000 days old". Treat as no verdict (not ok) rather
                    // than mis-bucketing it as ancient - matches the write
                    // side, which no longer records undated jobs.
                    if first_posted <= 0 {
                        return Ok(0i64);
                    }
                    let age = ((now - first_posted).max(0) / 86_400) as u32;
                    let fam = crate::oracle::group_family(grp);
                    let ok = matches!(
                        snap.verdict(&bbs, &fam, age),
                        Some(crate::oracle::Verdict::Ok)
                    );
                    Ok(ok as i64)
                },
            )?;
            wheres.push("oracle_ok({}grp, {}first_posted) = 1".into());
        }
        // Same separator-insensitive multi-term AND match as search() -
        // FTS prefix match when available, LIKE full-scan fallback.
        let fts_m = if self.fts { fts_match(&q.q) } else { String::new() };
        if !fts_m.is_empty() {
            let p = bind(&mut params, Box::new(fts_m));
            wheres.push(format!(
                "{{}}id IN (SELECT rowid FROM rel_fts WHERE rel_fts MATCH {p})"
            ));
        } else {
            const NS: &str = "REPLACE(REPLACE(REPLACE(LOWER({}stem),'.',' '),'_',' '),'-',' ')";
            for term in q
                .q
                .to_ascii_lowercase()
                .replace(['.', '_', '-'], " ")
                .split_whitespace()
            {
                let p = bind(&mut params, Box::new(term.to_string()));
                wheres.push(format!("{NS} LIKE '%' || {p} || '%'"));
            }
        }
        // Cross-posted releases (same stem in teevee AND moovee, or two
        // posters) are separate index rows; a flat list wants ONE. Keep
        // the best copy per stem: complete beats incomplete, then part
        // ratio, then size (idx_rel_stem makes the correlated lookup
        // cheap). The page's own filters go in here too, so the pick is
        // the best copy AMONG the ones this query accepts: a
        // representative that fails a filter would otherwise satisfy no
        // row at all, dropping the release from the list AND from
        // `total` while the grid still showed its card.
        let rep = alias(&wheres, "d.");
        let rep = if rep.is_empty() { String::new() } else { format!(" AND {rep}") };
        wheres.push(format!(
            "id = (SELECT d.id FROM releases d WHERE d.stem = releases.stem{rep}
                   ORDER BY d.complete DESC,
                            CAST(d.have_parts AS REAL)/MAX(d.need_parts,1) DESC,
                            d.total_bytes DESC, d.id LIMIT 1)"
        ));
        let where_clause = alias(&wheres, "");
        // Sort key is a fixed vocabulary (never interpolated user text).
        let dir = if q.desc { "DESC" } else { "ASC" };
        // Build the full ORDER BY prefix. SQL applies a direction PER term,
        // so a two-column key like "(ratio), complete" would leave the
        // ratio (the real sort key) at the default ASC while only `complete`
        // took {dir} - inverting "Most complete". Attach {dir} to every
        // completeness column explicitly.
        let order_key = match q.sort {
            BrowseSort::Posted => format!("first_posted {dir}"),
            BrowseSort::Seen => format!("first_seen {dir}"),
            BrowseSort::Size => format!("total_bytes {dir}"),
            BrowseSort::Name => format!("stem COLLATE NOCASE {dir}"),
            BrowseSort::Files => format!("files {dir}"),
            // Kind is TEXT; res gets the same direction so each
            // category's rows lead with the best (or worst) encode.
            // `res` is TEXT, so ordering it directly sorts lexicographically
            // and puts 720p above 2160p - the opposite of "best encode
            // first". Rank it the way the wall's own card query does.
            BrowseSort::Kind => format!("kind {dir}, {RES_RANK_SQL} {dir}"),
            // Completeness ratio; complete flag breaks ties so verified-
            // complete singles sort above 100%-but-unconfirmed rows.
            BrowseSort::Completeness => format!(
                "(CAST(have_parts AS REAL) / MAX(need_parts, 1)) {dir}, complete {dir}"
            ),
        };
        let total: u64 = self
            .db
            .query_row(
                &format!("SELECT COUNT(*) FROM releases WHERE {where_clause}"),
                rusqlite::params_from_iter(params.iter().map(|b| b.as_ref())),
                |r| r.get::<_, i64>(0),
            )
            .map(|n| n as u64)?;
        let sql = format!(
            "SELECT {REL_COLS} FROM releases WHERE {where_clause}
             ORDER BY {order_key}, id DESC LIMIT ?{} OFFSET ?{}",
            params.len() + 1,
            params.len() + 2
        );
        params.push(Box::new(q.limit.min(500)));
        params.push(Box::new(q.offset));
        let mut stmt = self.db.prepare(&sql)?;
        let rows = stmt.query_map(
            rusqlite::params_from_iter(params.iter().map(|b| b.as_ref())),
            release_from_row,
        )?;
        let out = rows.collect::<rusqlite::Result<_>>()?;
        // Drop the per-request verdict function so a stale snapshot never
        // lingers on the shared connection (no-op if it was never set).
        if verdict_fn {
            let _ = self.db.remove_function("oracle_ok", 2);
        }
        Ok((out, total))
    }

    /// M28: the poster grid's data, paged in SQL. Groups releases by
    /// their stored parse key, joins each group to its cached metadata,
    /// and returns (cards, total groups) - the wall no longer
    /// materializes the whole index per load. `matched_only` keeps only
    /// cards whose enrichment landed art (the wall's default toggle).
    pub fn browse_cards(
        &self,
        q: &BrowseQuery,
        sort: CardSort,
        matched_only: bool,
        // M30: cluster by kind (tv/movie/apps/other) with `sort` as the
        // within-category sub-sort.
        group_by_kind: bool,
        // M31b: taste inputs for the Affinity sort (ignored by every other
        // sort). None on cold start -> Affinity degrades to Releases.
        affinity: Option<&AffinityCtx>,
    ) -> rusqlite::Result<(Vec<Card>, u64)> {
        // Per-release predicates are written with `{}` where the releases
        // alias goes, the same way browse() does: the page renders them
        // against `r.`, and the representative subqueries at the bottom
        // render the SAME list against their own alias `s.`. A card's
        // rep_stem / rep_grp would otherwise be taken from the title's
        // newest release even when this view excludes it - an obfuscated
        // junk stem driving the parse and the enrichment seed, a "have"
        // badge keyed on the wrong dupe, an oracle verdict computed for a
        // group the page filtered out. Both renderings cite the same ?N,
        // so nothing below has to renumber.
        let mut wheres: Vec<String> = vec!["{}title_key != ''".into()];
        // Title-level predicates (the `titles` join, and the year
        // expression built on it): constant for every release sharing a
        // title_key, so repeating them inside the per-title subquery would
        // buy nothing. They stay out of the aliased list.
        let mut title_wheres: Vec<String> = Vec::new();
        let mut params: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
        let bind = |params: &mut Vec<Box<dyn rusqlite::ToSql>>, v: Box<dyn rusqlite::ToSql>| {
            params.push(v);
            format!("?{}", params.len())
        };
        let alias = |wheres: &[String], pfx: &str| {
            wheres
                .iter()
                .map(|w| w.replace("{}", pfx))
                .collect::<Vec<_>>()
                .join(" AND ")
        };
        if let Some(kind) = &q.kind {
            let p = bind(&mut params, Box::new(kind.clone()));
            wheres.push(format!("{{}}kind = {p}"));
        }
        if let Some(res) = &q.res {
            let p = bind(&mut params, Box::new(res.clone()));
            wheres.push(format!("{{}}res = {p}"));
        }
        if q.complete_only {
            wheres.push("{}complete".into());
        }
        if q.min_bytes > 0 {
            let p = bind(&mut params, Box::new(q.min_bytes as i64));
            wheres.push(format!("{{}}total_bytes >= {p}"));
        }
        if q.newer_than > 0 {
            let p = bind(&mut params, Box::new(q.newer_than));
            wheres.push(format!("{{}}first_posted >= {p}"));
        }
        if let Some(max) = q.max_junk {
            let p = bind(&mut params, Box::new(max as i64));
            wheres.push(format!("{{}}junk < {p}"));
        }
        // 24C: exact-card fetch. The Releases surface asks for ONE
        // title's card (hover preview, group-by-title header row) by
        // its stored parse key instead of re-deriving it from a page
        // query - same field browse() already honors.
        if let Some(tk) = &q.title_key {
            let p = bind(&mut params, Box::new(tk.clone()));
            wheres.push(format!("{{}}title_key = {p}"));
        }
        // The people leg. Release stems are all the FTS index covers, so
        // "tom cruise" used to find nothing at all unless a filename
        // happened to say it. A title credited to a matching person is
        // just as much a hit as one whose stem matches, hence OR rather
        // than a separate query - one search box, one result set.
        let people_m = if self.people_fts && !q.title_key.is_some() {
            fts_match(&q.q)
        } else {
            String::new()
        };
        let people_leg = |params: &mut Vec<Box<dyn rusqlite::ToSql>>| -> String {
            if people_m.is_empty() {
                return String::new();
            }
            params.push(Box::new(people_m.clone()));
            let n = params.len();
            format!(
                " OR {{}}title_key IN (SELECT tp.key FROM title_people tp
                    WHERE tp.person_id IN
                          (SELECT rowid FROM people_fts WHERE people_fts MATCH ?{n}))"
            )
        };
        let fts_m = if self.fts { fts_match(&q.q) } else { String::new() };
        if !fts_m.is_empty() {
            let p = bind(&mut params, Box::new(fts_m));
            let leg = people_leg(&mut params);
            wheres.push(format!(
                "({{}}id IN (SELECT rowid FROM rel_fts WHERE rel_fts MATCH {p}){leg})"
            ));
        } else if !q.q.trim().is_empty() {
            const NS: &str =
                "REPLACE(REPLACE(REPLACE(LOWER({}stem),'.',' '),'_',' '),'-',' ')";
            // Every term must appear in the stem - but a people match
            // satisfies the whole query at once, so it wraps the lot
            // rather than being ANDed in term by term.
            let mut terms: Vec<String> = Vec::new();
            for term in q
                .q
                .to_ascii_lowercase()
                .replace(['.', '_', '-'], " ")
                .split_whitespace()
            {
                let p = bind(&mut params, Box::new(term.to_string()));
                terms.push(format!("{NS} LIKE '%' || {p} || '%'"));
            }
            if !terms.is_empty() {
                let leg = people_leg(&mut params);
                let joined = terms.join(" AND ");
                wheres.push(format!("(({joined}){leg})"));
            }
        }
        if matched_only {
            // LEFT JOIN NULLs fail both predicates, so unmatched groups
            // drop out here too.
            title_wheres.push("t.checked > 0 AND t.poster != ''".into());
        }
        // M30: genre chip filter - substring over the enriched genre
        // list ("Drama, Comedy"); unenriched cards drop out while a
        // chip is active (their genre is unknown).
        if let Some(g) = q.genre.as_deref().filter(|g| !g.trim().is_empty()) {
            let p = bind(&mut params, Box::new(g.trim().to_string()));
            title_wheres.push(format!("t.genres LIKE '%' || {p} || '%'"));
        }
        // M30: decade chips - original-year range over the same
        // enriched-year-with-parse-key-fallback expression the Year
        // sort uses.
        if q.year_min > 0 {
            let p = bind(&mut params, Box::new(q.year_min as i64));
            title_wheres.push(format!("{CARD_YEAR_SQL} >= {p}"));
        }
        if q.year_max > 0 {
            let p = bind(&mut params, Box::new(q.year_max as i64));
            title_wheres.push(format!("{CARD_YEAR_SQL} <= {p} AND {CARD_YEAR_SQL} > 0"));
        }
        // M30: user curation (hides + rules). Rules filter individual
        // releases pre-GROUP BY, so a card only disappears when every
        // one of its releases is excluded (a German dub next to an
        // English encode never hides the whole title). It already takes
        // the alias as an argument, so the placeholder passes straight
        // through and the rules reach the representative pick too.
        if q.curated {
            self.curation_wheres("{}", &mut wheres, &mut params)?;
        }
        // The representative pick: the same per-release predicates,
        // re-rendered against the subquery's alias. `wheres` is never
        // empty (it is seeded with the title_key test), so the AND always
        // has a left side.
        let rep_where = alias(&wheres, "s.");
        let where_clause = {
            let mut all = alias(&wheres, "r.");
            for w in &title_wheres {
                all.push_str(" AND ");
                all.push_str(w);
            }
            all
        };
        // The COUNT runs on the WHERE params ALONE, so it must happen
        // before the Affinity ORDER BY binds any of its own params (those
        // belong to the paged query only).
        let total: u64 = self
            .db
            .query_row(
                &format!(
                    "SELECT COUNT(DISTINCT r.title_key)
                     FROM releases r LEFT JOIN titles t ON t.key = r.title_key
                     WHERE {where_clause}"
                ),
                rusqlite::params_from_iter(params.iter().map(|b| b.as_ref())),
                |r| r.get::<_, i64>(0),
            )
            .map(|n| n as u64)?;
        // Fixed vocabulary - never user text. Direction is the caller's
        // call (the API defaults title→asc, everything else→desc).
        let key: String = match sort {
            CardSort::Latest => "latest".into(),
            CardSort::Arrived => "MAX(r.first_seen)".into(),
            CardSort::Rating => "COALESCE(t.rating, 0)".into(),
            CardSort::Title => {
                "COALESCE(NULLIF(t.title,''), r.title_key) COLLATE NOCASE".into()
            }
            CardSort::Releases => "n".into(),
            CardSort::Size => "max_bytes".into(),
            // Enriched year first; movies without metadata still carry
            // their year in the parse key's ":YYYY" suffix.
            CardSort::Year => CARD_YEAR_SQL.into(),
            CardSort::Aired => card_aired_sql(),
            // M31b: weighted taste match. Cold start (no/empty profile)
            // degrades to Releases ("most posted") so the option is still
            // useful before any signal exists.
            CardSort::Affinity => match affinity.filter(|a| !a.is_empty()) {
                None => "n".into(),
                Some(aff) => {
                    let mut terms: Vec<String> = Vec::new();
                    for (g, w) in &aff.genres {
                        let pg = bind(&mut params, Box::new(g.clone()));
                        // COALESCE: an unmatched card (LEFT JOIN miss) has
                        // NULL genres, and `NULL LIKE .. * w` is NULL, which
                        // would nullify the WHOLE score sum (dropping the
                        // kind/decade signal for that card). Mirror the
                        // COALESCE the SELECT projection already uses.
                        terms.push(format!(
                            "(COALESCE(t.genres,'') LIKE '%' || {pg} || '%') * {w:.5}"
                        ));
                    }
                    if let Some((k, w)) = &aff.fav_kind {
                        let pk = bind(&mut params, Box::new(k.clone()));
                        terms.push(format!("(MAX(r.kind) = {pk}) * {w:.5}"));
                    }
                    if let Some(centre) = aff.decade_center {
                        terms.push(format!(
                            "(CASE WHEN {CARD_YEAR_SQL} BETWEEN {} AND {} \
                             THEN 1 ELSE 0 END) * {:.5}",
                            centre - 10,
                            centre + 10,
                            aff.decade_weight
                        ));
                    }
                    // Sink what you already own beneath every ranked card
                    // (the -1000 swamps the largest possible positive
                    // score) without hiding it.
                    if !aff.owned.is_empty() {
                        // Cap the IN(...) list: each owned key is one bound
                        // parameter and SQLite hard-limits a statement to
                        // 32766 variables - an install with more completed
                        // downloads than that would make prepare() fail and
                        // silently break the whole "For you" sort. The cap
                        // is far above any real library; the demotion is a
                        // soft "you have it" nudge, so dropping a few is
                        // harmless.
                        const OWNED_IN_CAP: usize = 10_000;
                        let ph: Vec<String> = aff
                            .owned
                            .iter()
                            .take(OWNED_IN_CAP)
                            .map(|k| bind(&mut params, Box::new(k.clone())))
                            .collect();
                        terms.push(format!(
                            "(r.title_key IN ({})) * -1000.0",
                            ph.join(",")
                        ));
                    }
                    format!("({})", terms.join(" + "))
                }
            },
        };
        let dir = if q.desc { "DESC" } else { "ASC" };
        // M30: category grouping - a fixed kind order leads the sort so
        // the grid clusters TV / movies / the rest, and the chosen key
        // becomes the within-category sub-sort. The client draws section
        // headers where the kind changes.
        // Custom categories (any kind that is none of the built-in
        // ones) cluster after music and books, each custom kind
        // contiguous (the MAX(r.kind) tiebreak) so the client's
        // header-on-change rendering draws one section per category.
        let group_prefix = if group_by_kind {
            "CASE MAX(r.kind) WHEN 'tv' THEN 0 WHEN 'movie' THEN 1
                              WHEN 'music' THEN 2 WHEN 'book' THEN 3
                              WHEN 'software' THEN 5
                              WHEN 'other' THEN 6 ELSE 4 END ASC,
             MAX(r.kind) ASC, "
        } else {
            ""
        };
        // The two representative subqueries carry an IDENTICAL predicate
        // list and an identical, fully deterministic ORDER BY (the id
        // tiebreak settles same-second posts), so rep_stem and rep_grp
        // can never come from two different rows.
        let sql = format!(
            "SELECT r.title_key, MAX(r.kind), COUNT(*) AS n,
                    MAX(r.first_posted) AS latest, MAX(r.complete),
                    MAX(r.total_bytes) AS max_bytes,
                    MAX(CASE r.res WHEN '2160p' THEN 4 WHEN '1080p' THEN 3
                                   WHEN '720p' THEN 2 WHEN '' THEN 0 ELSE 1 END),
                    (SELECT s.stem FROM releases s
                      WHERE s.title_key = r.title_key AND {rep_where}
                      ORDER BY s.first_posted DESC, s.id DESC LIMIT 1),
                    (SELECT s.grp FROM releases s
                      WHERE s.title_key = r.title_key AND {rep_where}
                      ORDER BY s.first_posted DESC, s.id DESC LIMIT 1),
                    COALESCE(t.title,''), COALESCE(t.year,0), COALESCE(t.rating,0),
                    COALESCE(t.genres,''), COALESCE(t.overview,''),
                    COALESCE(t.poster,''), COALESCE(t.backdrop,''),
                    COALESCE(t.checked,0), COALESCE(t.actors,''),
                    COALESCE(t.air_date,'')
             FROM releases r LEFT JOIN titles t ON t.key = r.title_key
             WHERE {where_clause}
             GROUP BY r.title_key
             ORDER BY {group_prefix}{key} {dir}, latest DESC
             LIMIT ?{} OFFSET ?{}",
            params.len() + 1,
            params.len() + 2
        );
        params.push(Box::new(q.limit.min(500)));
        params.push(Box::new(q.offset));
        let mut stmt = self.db.prepare(&sql)?;
        let rows = stmt.query_map(
            rusqlite::params_from_iter(params.iter().map(|b| b.as_ref())),
            |r| {
                Ok(Card {
                    title_key: r.get(0)?,
                    kind: r.get(1)?,
                    n_releases: r.get(2)?,
                    latest_posted: r.get(3)?,
                    any_complete: r.get(4)?,
                    max_bytes: r.get::<_, i64>(5)? as u64,
                    best_res: match r.get::<_, i64>(6)? {
                        4 => "2160p",
                        3 => "1080p",
                        2 => "720p",
                        _ => "",
                    }
                    .to_string(),
                    rep_stem: r.get(7)?,
                    rep_grp: r.get(8)?,
                    title: r.get(9)?,
                    year: r.get::<_, i64>(10)? as u32,
                    rating: r.get(11)?,
                    genres: r.get(12)?,
                    overview: r.get(13)?,
                    poster_art: r.get(14)?,
                    backdrop_art: r.get(15)?,
                    checked: r.get(16)?,
                    actors: r.get(17)?,
                    air_date: r.get(18)?,
                })
            },
        )?;
        Ok((rows.collect::<rusqlite::Result<_>>()?, total))
    }

    // ---- M30 wall curation: hides, rules, suggestions ----------------

    /// Appends the wall-curation predicates (per-title hides + hide
    /// rules) to a query's WHERE list. `pfx` is the releases alias
    /// ("r." in the card query, "" in the flat browse).
    fn curation_wheres(
        &self,
        pfx: &str,
        wheres: &mut Vec<String>,
        params: &mut Vec<Box<dyn rusqlite::ToSql>>,
    ) -> rusqlite::Result<()> {
        wheres.push(format!("{pfx}title_key NOT IN (SELECT key FROM wall_hidden)"));
        let rules: Vec<(String, String)> = {
            let mut stmt = self.db.prepare_cached("SELECT field, value FROM wall_rules")?;
            let r = stmt
                .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<rusqlite::Result<_>>()?;
            r
        };
        for (field, value) in rules {
            let n = params.len() + 1;
            match field.as_str() {
                "lang" => {
                    params.push(Box::new(format!(" {} ", value.to_lowercase())));
                    wheres.push(format!("INSTR(' '||{pfx}langs||' ', ?{n}) = 0"));
                }
                "kind" => {
                    params.push(Box::new(value));
                    wheres.push(format!("{pfx}kind <> ?{n}"));
                }
                "group" => {
                    params.push(Box::new(value));
                    wheres.push(format!("{pfx}grp <> ?{n}"));
                }
                // Whole titles whose enriched genre list carries the
                // value ("reality", "sports", ...) - resolved through a
                // titles subquery so the flat list filters identically
                // to the card grid.
                "genre" => {
                    params.push(Box::new(value));
                    wheres.push(format!(
                        "{pfx}title_key NOT IN (SELECT key FROM titles
                          WHERE genres LIKE '%' || ?{n} || '%')"
                    ));
                }
                // Exact-token stem match via the FTS index (unicode61
                // already splits ./-/_), LIKE word-boundary fallback on
                // non-FTS builds.
                "word" if self.fts => {
                    params.push(Box::new(format!("\"{}\"", value.replace('"', "\"\""))));
                    wheres.push(format!(
                        "{pfx}id NOT IN (SELECT rowid FROM rel_fts WHERE rel_fts MATCH ?{n})"
                    ));
                }
                "word" => {
                    params.push(Box::new(format!("% {} %", value.to_lowercase())));
                    wheres.push(format!(
                        "' '||REPLACE(REPLACE(REPLACE(LOWER({pfx}stem),'.',' '),'_',' '),'-',' ')||' ' NOT LIKE ?{n}"
                    ));
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Remember what a set of PAR2 member fingerprints was called, so a
    /// later repost of the same bytes under an obfuscated name can be
    /// told. `pairs` is `(hash16k hex, member name)` from
    /// [`Par2Set::member_hash16k`](crate::par2::Par2Set::member_hash16k);
    /// the member names are not stored (they are volume names, not
    /// identities) - `name` is the release the whole set belongs to.
    ///
    /// First writer wins. A fingerprint already on file was recorded
    /// when we named that release, and the later download of the same
    /// bytes has no better claim - overwriting would let one badly
    /// named repost erase the good name for every future one.
    pub fn par_hash_remember(
        &self,
        pairs: &[(String, String)],
        name: &str,
        title_key: &str,
        now: i64,
    ) -> rusqlite::Result<usize> {
        if name.trim().is_empty() {
            return Ok(0);
        }
        let mut stmt = self.db.prepare_cached(
            "INSERT INTO par_hashes(hash16k, name, title_key, at) VALUES(?1, ?2, ?3, ?4)
             ON CONFLICT(hash16k) DO NOTHING",
        )?;
        let mut n = 0;
        for (hash, _member) in pairs {
            n += stmt.execute(rusqlite::params![hash, name, title_key, now])?;
        }
        Ok(n)
    }

    /// What we last called a release carrying any of these member
    /// fingerprints. Returns `(name, title_key)` for the first hash that
    /// is on file, in the order given - a set's volumes all belong to
    /// one release, so one hit answers for the set.
    pub fn par_hash_lookup(
        &self,
        pairs: &[(String, String)],
    ) -> rusqlite::Result<Option<(String, String)>> {
        let mut stmt = self
            .db
            .prepare_cached("SELECT name, title_key FROM par_hashes WHERE hash16k = ?1")?;
        for (hash, _member) in pairs {
            let hit = stmt
                .query_row([hash], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
                .optional()?;
            if hit.is_some() {
                return Ok(hit);
            }
        }
        Ok(None)
    }

    /// "Not interested": hide one title (all its releases) from every
    /// curated wall/list view. Idempotent.
    pub fn hide_title(&self, key: &str) -> rusqlite::Result<()> {
        self.db.execute(
            "INSERT INTO wall_hidden(key, at) VALUES(?1, strftime('%s','now'))
             ON CONFLICT(key) DO NOTHING",
            [key],
        )?;
        Ok(())
    }

    pub fn unhide_title(&self, key: &str) -> rusqlite::Result<()> {
        self.db.execute("DELETE FROM wall_hidden WHERE key = ?1", [key])?;
        Ok(())
    }

    /// The Hidden view: every hidden title with enough display context
    /// to render an unhide row (title falls back to the parse key).
    pub fn hidden_titles(&self) -> rusqlite::Result<Vec<HiddenTitle>> {
        let mut stmt = self.db.prepare_cached(
            "SELECT h.key, COALESCE(NULLIF(t.title,''), h.key), COALESCE(t.poster,''),
                    COALESCE(NULLIF(t.kind,''),
                             CASE WHEN h.key LIKE 't:%' THEN 'tv' ELSE 'movie' END),
                    h.at,
                    (SELECT COUNT(*) FROM releases r WHERE r.title_key = h.key)
             FROM wall_hidden h LEFT JOIN titles t ON t.key = h.key
             ORDER BY h.at DESC",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(HiddenTitle {
                key: r.get(0)?,
                title: r.get(1)?,
                poster: r.get(2)?,
                kind: r.get(3)?,
                at: r.get(4)?,
                n_releases: r.get(5)?,
            })
        })?;
        let rows: Vec<HiddenTitle> = rows.collect::<rusqlite::Result<_>>()?;
        // Unenriched titles fall back to the raw parse key - present
        // those readably instead.
        Ok(rows
            .into_iter()
            .map(|mut h| {
                if h.title == h.key {
                    h.title = pretty_key(&h.key);
                }
                h
            })
            .collect())
    }

    pub fn rules_list(&self) -> rusqlite::Result<Vec<WallRule>> {
        let mut stmt = self.db.prepare_cached(
            "SELECT id, field, value, added, auto FROM wall_rules ORDER BY added DESC",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(WallRule {
                id: r.get(0)?,
                field: r.get(1)?,
                value: r.get(2)?,
                added: r.get(3)?,
                auto: r.get(4)?,
            })
        })?;
        rows.collect()
    }

    /// Add a hide rule. `auto` marks rules created from an accepted
    /// suggestion (vs typed by hand). Unknown fields are rejected so a
    /// typo can't create a dead rule that silently filters nothing.
    pub fn rule_add(&self, field: &str, value: &str, auto: bool) -> rusqlite::Result<()> {
        if !matches!(field, "lang" | "word" | "kind" | "group" | "genre") {
            return Err(rusqlite::Error::InvalidParameterName(format!(
                "unknown rule field '{field}'"
            )));
        }
        let value = value.trim().to_lowercase();
        if value.is_empty() {
            return Err(rusqlite::Error::InvalidParameterName("empty rule value".into()));
        }
        self.db.execute(
            "INSERT INTO wall_rules(field, value, added, auto)
             VALUES(?1, ?2, strftime('%s','now'), ?3)
             ON CONFLICT(field, value) DO NOTHING",
            rusqlite::params![field, value, auto],
        )?;
        // Accepting a rule supersedes any earlier "no thanks".
        self.db.execute(
            "DELETE FROM wall_dismissed WHERE field=?1 AND value=?2",
            rusqlite::params![field, value],
        )?;
        Ok(())
    }

    pub fn rule_delete(&self, id: i64) -> rusqlite::Result<()> {
        self.db.execute("DELETE FROM wall_rules WHERE id = ?1", [id])?;
        Ok(())
    }

    /// "No thanks" on a suggestion - never offer this (field, value)
    /// again.
    pub fn suggestion_dismiss(&self, field: &str, value: &str) -> rusqlite::Result<()> {
        self.db.execute(
            "INSERT INTO wall_dismissed(field, value) VALUES(?1, LOWER(?2))
             ON CONFLICT DO NOTHING",
            rusqlite::params![field, value],
        )?;
        Ok(())
    }

    /// Pattern detection over the user's hides: when >= 3 hidden titles
    /// share a language tag, or >= 3 share a rare title word, suggest a
    /// one-click rule. Existing rules and dismissed suggestions are
    /// excluded; strongest (most hides) first, capped at 3.
    pub fn hide_suggestions(&self) -> rusqlite::Result<Vec<Suggestion>> {
        use std::collections::{HashMap, HashSet};
        let taken: HashSet<(String, String)> = {
            let mut stmt = self.db.prepare_cached(
                "SELECT field, value FROM wall_rules
                 UNION SELECT field, value FROM wall_dismissed",
            )?;
            let r = stmt
                .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
                .collect::<rusqlite::Result<_>>()?;
            r
        };
        // One pass over the hidden titles' releases: per-title language
        // tags and display names.
        let mut stmt = self.db.prepare_cached(
            "SELECT h.key, COALESCE(NULLIF(t.title,''), h.key),
                    (SELECT COALESCE(GROUP_CONCAT(DISTINCT r.langs), '')
                     FROM releases r WHERE r.title_key = h.key),
                    COALESCE(t.genres, '')
             FROM wall_hidden h LEFT JOIN titles t ON t.key = h.key",
        )?;
        let hidden: Vec<(String, String, String, String)> = stmt
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
            .collect::<rusqlite::Result<Vec<(String, String, String, String)>>>()?
            .into_iter()
            .map(|(key, disp, langs, genres)| {
                let disp = if disp == key { pretty_key(&key) } else { disp };
                (key, disp, langs, genres)
            })
            .collect();
        let mut by_lang: HashMap<String, Vec<&str>> = HashMap::new();
        let mut by_word: HashMap<String, Vec<&str>> = HashMap::new();
        let mut by_genre: HashMap<String, Vec<&str>> = HashMap::new();
        // Title-key words already come normalized (lowercase, separator-
        // collapsed). Generic words never make a good rule.
        const STOP: [&str; 24] = [
            "the", "and", "of", "a", "an", "to", "in", "on", "at", "with", "for", "from",
            "der", "die", "das", "les", "los", "las", "una", "del", "you", "not", "all",
            "one",
        ];
        for (key, disp, langs, genres) in &hidden {
            let mut seen_l: HashSet<&str> = HashSet::new();
            for l in langs.split([',', ' ']).filter(|l| !l.is_empty()) {
                if seen_l.insert(l) {
                    by_lang.entry(l.to_string()).or_default().push(disp);
                }
            }
            let mut seen_g: HashSet<String> = HashSet::new();
            for g in genres.split(',').map(|g| g.trim().to_lowercase()) {
                if !g.is_empty() && seen_g.insert(g.clone()) {
                    by_genre.entry(g).or_default().push(disp);
                }
            }
            let base = key
                .strip_prefix("t:")
                .or_else(|| key.strip_prefix("m:"))
                .unwrap_or(key);
            let words = match base.rsplit_once(':') {
                Some((w, y)) if y.chars().all(|c| c.is_ascii_digit()) => w,
                _ => base,
            };
            let mut seen_w: HashSet<&str> = HashSet::new();
            for w in words.split_whitespace() {
                if w.len() >= 3 && !STOP.contains(&w) && seen_w.insert(w) {
                    by_word.entry(w.to_string()).or_default().push(disp);
                }
            }
        }
        let mut out: Vec<Suggestion> = Vec::new();
        for (lang, titles) in by_lang {
            if titles.len() >= 3 && !taken.contains(&("lang".into(), lang.clone())) {
                out.push(Suggestion {
                    field: "lang".into(),
                    value: lang,
                    n: titles.len() as u32,
                    sample: titles.iter().take(3).map(|s| s.to_string()).collect(),
                });
            }
        }
        for (genre, titles) in by_genre {
            // Genres are broad (half a wall can be "Drama") - demand a
            // stronger signal than lang/word before suggesting.
            if titles.len() >= 4 && !taken.contains(&("genre".into(), genre.clone())) {
                out.push(Suggestion {
                    field: "genre".into(),
                    value: genre,
                    n: titles.len() as u32,
                    sample: titles.iter().take(3).map(|s| s.to_string()).collect(),
                });
            }
        }
        for (word, titles) in by_word {
            if titles.len() < 3 || taken.contains(&("word".into(), word.clone())) {
                continue;
            }
            // Rarity gate: a word that matches half the index is a
            // stopword we missed, not a taste signal. FTS count of
            // distinct titles carrying the token, capped at 500.
            if self.fts {
                let global: i64 = self
                    .db
                    .query_row(
                        "SELECT COUNT(DISTINCT title_key) FROM releases
                         WHERE id IN (SELECT rowid FROM rel_fts WHERE rel_fts MATCH ?1)",
                        [format!("\"{}\"", word.replace('"', "\"\""))],
                        |r| r.get(0),
                    )
                    .unwrap_or(i64::MAX);
                if global > 500 {
                    continue;
                }
            }
            out.push(Suggestion {
                field: "word".into(),
                value: word,
                n: titles.len() as u32,
                sample: titles.iter().take(3).map(|s| s.to_string()).collect(),
            });
        }
        out.sort_by(|a, b| b.n.cmp(&a.n).then(a.value.cmp(&b.value)));
        out.truncate(3);
        Ok(out)
    }

    /// M13 title-metadata cache (dumb storage - TMDB lookups live in the
    /// daemon; this just remembers results, including "looked, found
    /// nothing" so a missing title is fetched once, not every poll).
    /// Insert a pending row for a parsed title if we've never seen it.
    pub fn title_seed(&self, key: &str, kind: &str, title: &str, year: u32) -> rusqlite::Result<()> {
        self.db.execute(
            "INSERT OR IGNORE INTO titles(key, kind, title, year) VALUES(?1, ?2, ?3, ?4)",
            rusqlite::params![key, kind, title, year],
        )?;
        Ok(())
    }

    fn title_row(r: &rusqlite::Row) -> rusqlite::Result<TitleRow> {
        Ok(TitleRow {
            key: r.get(0)?,
            kind: r.get(1)?,
            title: r.get(2)?,
            year: r.get::<_, i64>(3)? as u32,
            tmdb_id: r.get(4)?,
            overview: r.get(5)?,
            rating: r.get(6)?,
            genres: r.get(7)?,
            poster: r.get(8)?,
            backdrop: r.get(9)?,
            checked: r.get(10)?,
            imdb: r.get(11)?,
            actors: r.get(12)?,
            air_date: r.get(13)?,
        })
    }

    const TITLE_COLS: &'static str =
        "key, kind, title, year, tmdb_id, overview, rating, genres,
         poster, backdrop, checked, imdb, actors, air_date";

    /// All cached title rows (the wall joins them to parsed releases).
    pub fn titles(&self) -> rusqlite::Result<Vec<TitleRow>> {
        let mut stmt = self
            .db
            .prepare(&format!("SELECT {} FROM titles", Self::TITLE_COLS))?;
        let rows = stmt.query_map([], |r| Self::title_row(r))?;
        rows.collect()
    }

    /// Titles never looked up (checked=0), oldest-seeded first.
    pub fn titles_pending(&self, limit: u32) -> rusqlite::Result<Vec<TitleRow>> {
        let mut stmt = self.db.prepare(&format!(
            "SELECT {} FROM titles WHERE checked=0 LIMIT ?1",
            Self::TITLE_COLS
        ))?;
        let rows = stmt.query_map([limit], |r| Self::title_row(r))?;
        rows.collect()
    }

    /// Pending titles split into the enricher's lanes: one thread each,
    /// because every provider's rate limit is independent and a serial
    /// loop makes each kind queue behind the slowest one.
    pub fn titles_pending_lane(
        &self,
        limit: u32,
        lane: Lane,
    ) -> rusqlite::Result<Vec<TitleRow>> {
        // M28: enrich in the order the wall shows cards - newest upload
        // first (idx_rel_title_key makes the correlated MAX cheap), junk
        // groups last. Fresh titles used to queue behind the whole
        // historical backlog in rowid order, so a new post's art could
        // be hours away on a big index.
        let mut stmt = self.db.prepare(&format!(
            "SELECT {} FROM titles t WHERE checked=0 AND {} AND {VISIBLE}
             ORDER BY COALESCE((SELECT MAX(r.first_posted) FROM releases r
                                WHERE r.title_key=t.key AND r.junk < 50), 0) DESC
             LIMIT ?1",
            Self::TITLE_COLS,
            lane.sql()
        ))?;
        let rows = stmt.query_map(rusqlite::params![limit], |r| Self::title_row(r))?;
        rows.collect()
    }

    /// M30: viewport-priority enrichment - the still-pending subset of
    /// `keys` (what the wall is showing right now) for one lane.
    ///
    /// Deliberately NOT filtered by `VISIBLE`, unlike the backlog query:
    /// these keys are cards the user has on screen this moment, which is
    /// the strongest possible evidence a title is wanted. A junk-scored
    /// card only reaches here when they have turned "show hidden" on and
    /// are looking straight at it - enriching that is answering a
    /// request, not spending the budget on nobody.
    pub fn titles_hot(
        &self,
        keys: &[String],
        lane: Lane,
    ) -> rusqlite::Result<Vec<TitleRow>> {
        let mut out = Vec::new();
        let mut stmt = self.db.prepare_cached(&format!(
            "SELECT {} FROM titles t WHERE key=?1 AND checked=0 AND {}",
            Self::TITLE_COLS,
            lane.sql()
        ))?;
        for k in keys {
            let mut rows = stmt.query_map(rusqlite::params![k], |r| {
                Self::title_row(r)
            })?;
            if let Some(row) = rows.next() {
                out.push(row?);
            }
        }
        Ok(out)
    }

    /// M30: seed titles rows for recent, wall-visible releases that
    /// have none - the enricher only works from the titles table, and
    /// after M28 nothing seeded it except a wall page view. Called
    /// after each scan pass; newest first, bounded per call. Returns
    /// how many were seeded.
    pub fn seed_missing_titles(&self, max_age_days: u32, limit: u32) -> rusqlite::Result<u32> {
        let rows: Vec<(String, String, String)> = {
            let mut stmt = self.db.prepare_cached(
                "SELECT r.title_key, r.kind, MAX(r.stem)
                 FROM releases r
                 WHERE r.junk < 50 AND r.title_key != ''
                   AND r.kind NOT IN ('software','other','')
                   AND r.first_posted > strftime('%s','now') - ?1 * 86400
                   AND NOT EXISTS(SELECT 1 FROM titles t WHERE t.key = r.title_key)
                 GROUP BY r.title_key
                 ORDER BY MAX(r.first_posted) DESC LIMIT ?2",
            )?;
            let r = stmt
                .query_map(rusqlite::params![max_age_days, limit], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?))
                })?
                .collect::<rusqlite::Result<_>>()?;
            r
        };
        let mut n = 0;
        for (key, kind, stem) in rows {
            let p = crate::release::parse_release(&stem);
            self.title_seed(&key, &kind, &p.title, p.year.unwrap_or(0))?;
            n += 1;
        }
        Ok(n)
    }

    /// M30: merge one card into another - every release under `src`
    /// re-keys to `dst`, then src's title row (and any hide) goes away.
    /// The classic fix for a parser split ("Show (Alt Title)" vs
    /// "Show") that left two cards for one series.
    pub fn merge_title(&self, src: &str, dst: &str) -> rusqlite::Result<u64> {
        if src == dst || src.is_empty() || dst.is_empty() {
            return Ok(0);
        }
        // All five statements or none. They used to autocommit one by
        // one, and the failure is unrecoverable rather than merely
        // untidy: if the releases re-key and the credit copy commit but
        // the DELETE then loses a race for the writer (a scan chunk or a
        // retention prune holding it past the 10 s busy timeout), the
        // credits exist under BOTH keys and src's titles row survives -
        // while every release has already moved to dst, so the src card
        // has vanished from the wall and nothing will ever prompt a
        // re-merge. The orphans are permanent, and they inflate the
        // visible credit counts on the destination.
        let tx = self.db.unchecked_transaction()?;
        let n = tx.execute(
            "UPDATE releases SET title_key=?2 WHERE title_key=?1",
            rusqlite::params![src, dst],
        )?;
        // Credits follow their releases. OR IGNORE because the two cards
        // may already share a person in the same role (the usual reason a
        // card split is a parser artifact of ONE title), and the
        // destination's own credit is the one to keep.
        tx.execute(
            "INSERT OR IGNORE INTO title_people(key, person_id, role, character, ord)
             SELECT ?2, person_id, role, character, ord FROM title_people WHERE key=?1",
            rusqlite::params![src, dst],
        )?;
        tx.execute("DELETE FROM title_people WHERE key=?1", [src])?;
        tx.execute("DELETE FROM titles WHERE key=?1", [src])?;
        tx.execute("DELETE FROM wall_hidden WHERE key=?1", [src])?;
        tx.commit()?;
        Ok(n as u64)
    }

    /// One title row by key (the fix/scrub endpoints read-modify-write).
    pub fn title_get(&self, key: &str) -> rusqlite::Result<Option<TitleRow>> {
        let mut stmt = self.db.prepare(&format!(
            "SELECT {} FROM titles WHERE key=?1",
            Self::TITLE_COLS
        ))?;
        let mut rows = stmt.query_map([key], |r| Self::title_row(r))?;
        rows.next().transpose()
    }

    /// M31b: fetch the cached rows for a set of title_keys in one prepared
    /// pass (the taste-profile build needs genres/kind/year for a few
    /// hundred keys). Missing keys are simply absent from the map.
    pub fn titles_for_keys(
        &self,
        keys: &[String],
    ) -> rusqlite::Result<std::collections::HashMap<String, TitleRow>> {
        let mut out = std::collections::HashMap::with_capacity(keys.len());
        let mut stmt = self
            .db
            .prepare(&format!("SELECT {} FROM titles WHERE key=?1", Self::TITLE_COLS))?;
        for k in keys {
            if out.contains_key(k) {
                continue;
            }
            let mut rows = stmt.query_map([k], Self::title_row)?;
            if let Some(row) = rows.next().transpose()? {
                out.insert(k.clone(), row);
            }
        }
        Ok(out)
    }

    /// M16 wall-fix: overwrite a title's IDENTITY (kind/title/year - what
    /// lookups search under and the wall displays) without touching the
    /// cached metadata/art columns. Upserts so it also works for keys the
    /// enricher hasn't seeded yet.
    pub fn title_set_identity(
        &self,
        key: &str,
        kind: &str,
        title: &str,
        year: u32,
    ) -> rusqlite::Result<()> {
        self.db.execute(
            "INSERT INTO titles(key, kind, title, year) VALUES(?1, ?2, ?3, ?4)
             ON CONFLICT(key) DO UPDATE SET kind=?2, title=?3, year=?4",
            rusqlite::params![key, kind, title, year],
        )?;
        Ok(())
    }

    /// M16 wall-refresh: wipe a title's cached metadata and mark it
    /// pending (checked=0) so the enricher fetches it fresh. Identity and
    /// the release rows are untouched. Returns whether the row existed.
    pub fn title_reset(&self, key: &str) -> rusqlite::Result<bool> {
        let n = self.db.execute(
            "UPDATE titles SET tmdb_id=0, overview='', rating=0, genres='',
                    poster='', backdrop='', imdb='', actors='', air_date='',
                    air_tried=0, checked=0
             WHERE key=?1",
            [key],
        )?;
        Ok(n > 0)
    }

    /// M16: reset EVERY title's metadata (fresh enrichment pass over the
    /// whole wall). Returns how many rows were reset.
    pub fn titles_reset_all(&self) -> rusqlite::Result<usize> {
        self.db.execute(
            "UPDATE titles SET tmdb_id=0, overview='', rating=0, genres='',
                    poster='', backdrop='', imdb='', actors='', air_date='',
                    air_tried=0, checked=0",
            [],
        )
    }

    /// Titles the enricher already matched but has never asked for a
    /// release date - rows written before air_date existed. The backfill
    /// lane drains these when it has nothing pending, so the release-date
    /// sort becomes useful on an existing library instead of only on
    /// titles indexed from here on. tmdb_id<>0 skips the rows no provider
    /// recognised: there is no date to go and fetch for those.
    pub fn titles_missing_date(
        &self,
        limit: u32,
        lane: Lane,
    ) -> rusqlite::Result<Vec<TitleRow>> {
        let mut stmt = self.db.prepare(&format!(
            "SELECT {} FROM titles t
             WHERE checked > 0 AND air_tried = 0 AND air_date = ''
               AND tmdb_id <> 0 AND {} AND {VISIBLE}
             ORDER BY COALESCE((SELECT MAX(r.first_posted) FROM releases r
                                WHERE r.title_key=t.key AND r.junk < 50), 0) DESC
             LIMIT ?1",
            Self::TITLE_COLS,
            lane.sql()
        ))?;
        let rows = stmt.query_map(rusqlite::params![limit], |r| Self::title_row(r))?;
        rows.collect()
    }

    /// Store a backfilled release date. An empty `date` records only that
    /// the provider was asked and had none, which is what stops the
    /// backfill lane asking about the same title on every pass.
    pub fn title_set_air_date(&self, key: &str, date: &str) -> rusqlite::Result<()> {
        self.db.execute(
            "UPDATE titles SET air_date=?2, air_tried=1 WHERE key=?1",
            rusqlite::params![key, date],
        )?;
        Ok(())
    }

    /// Record a lookup result (tmdb_id=0 ⇒ nothing found; checked stamps
    /// the attempt either way).
    pub fn title_fill(&self, key: &str, m: &TitleFill<'_>, now: i64) -> rusqlite::Result<()> {
        self.db.execute(
            "UPDATE titles SET tmdb_id=?2, overview=?3, rating=?4, genres=?5,
                    poster=?6, backdrop=?7, imdb=?8, actors=?9, air_date=?10,
                    air_tried=1, checked=?11
             WHERE key=?1",
            rusqlite::params![
                key,
                m.tmdb_id,
                m.overview,
                m.rating,
                m.genres,
                m.poster,
                m.backdrop,
                m.imdb,
                m.actors,
                m.air_date,
                now
            ],
        )?;
        Ok(())
    }

    // ---- cast and crew as entities -----------------------------------

    /// Resolve a credit to a `people.id`, creating or completing the row.
    ///
    /// Handles win over names, in the order a provider can be trusted: a
    /// TVmaze person id, a Wikidata Q-id and an IMDb `nm…` id each
    /// identify exactly one human, so any one of them matching IS the
    /// person. Only when a credit carries no handle at all (OMDb and
    /// TMDB give bare names) does the name decide - and then only
    /// against a row that contradicts none of what the credit knows.
    ///
    /// **Why the name fallback has to allow a cross-handle match.** The
    /// two provider handles live in disjoint id spaces: nothing TVmaze
    /// publishes about a person appears in Wikidata and vice versa, so a
    /// human seen by both arrives as a name plus a tvmaze id on one side
    /// and a name plus a qid on the other. Refusing that match forks one
    /// human into two rows, which is what
    /// `people_identity_credits_and_the_search_leg` pins against.
    ///
    /// **Why that used to fuse two different people** (finding D2): the
    /// same shape - a name plus one handle on each side - is also what
    /// two same-named strangers look like, and until both sides carried
    /// a fact in a SHARED vocabulary there was nothing to tell the cases
    /// apart. `born` is that shared fact, and it is here because it is
    /// the one both cast providers actually publish: TVmaze hands the
    /// birthday over in the cast payload itself, and Wikidata's P569
    /// rides along with P345 in one batched query.
    ///
    /// The IMDb id would have been the better join, and `imdb` is
    /// populated and matched for exactly that reason - but only Wikidata
    /// can supply it. Measured 27 Jul 2026 against the live API: TVmaze
    /// exposes no IMDb id for a person anywhere (no `externals` on the
    /// person object embedded or standalone, `/lookup/people?imdb=` is
    /// 404, and the public person page carries no IMDb link), and
    /// Wikidata has no TVmaze *person* property either - P8600 and
    /// friends are series, season, episode and character only. So `imdb`
    /// alone would have separated only people the qid already separated.
    ///
    /// Both disagreement tests are one-sided on purpose: a blank on
    /// either side never blocks a match, so a provider that gave us
    /// nothing cannot fork a person it simply failed to describe.
    ///
    /// Two residual risks, both accepted:
    ///
    /// - Two same-named people with no handles and no birth dates still
    ///   merge. That is the behaviour `titles.actors` already had (it is
    ///   a plain string of names), and unlike a wrong split it is
    ///   visible and fixable.
    /// - Two providers disagreeing on one real person's birthday split
    ///   them. Day-precision only (see `parse_person_facts`) keeps the
    ///   common "Wikidata knows only the year" case out of the
    ///   comparison entirely, which is where the disagreements were.
    pub fn person_upsert(&self, c: &Credit) -> rusqlite::Result<i64> {
        let name = c.name.trim();
        if name.is_empty() {
            return Err(rusqlite::Error::InvalidParameterName("empty person name".into()));
        }
        let mut existing: Option<i64> = None;
        if c.tvmaze_id > 0 {
            existing = self
                .db
                .query_row("SELECT id FROM people WHERE tvmaze_id=?1", [c.tvmaze_id], |r| {
                    r.get(0)
                })
                .optional()?;
        }
        if existing.is_none() && !c.wikidata_qid.is_empty() {
            existing = self
                .db
                .query_row(
                    "SELECT id FROM people WHERE wikidata_qid=?1",
                    [&c.wikidata_qid],
                    |r| r.get(0),
                )
                .optional()?;
        }
        if existing.is_none() && !c.imdb.is_empty() {
            existing = self
                .db
                .query_row("SELECT id FROM people WHERE imdb=?1", [&c.imdb], |r| r.get(0))
                .optional()?;
        }
        if existing.is_none() {
            // Name fallback, guarded by every fact both sides hold. Each
            // clause reads "one of us does not know, or we agree", so a
            // blank never blocks a match and a contradiction always
            // does.
            //
            // The two handle clauses can only ever refuse a row whose
            // SAME handle differs - a TVmaze credit says nothing about a
            // Wikidata row - which is why the name match still crosses
            // handle types, and why it used to fuse two same-named
            // people. `imdb` and `born` are the clauses that carry
            // across: both come from vocabularies a provider does not
            // own, so a Wikidata-identified row and a TVmaze-identified
            // credit finally have something to disagree about. See the
            // doc comment for why `born` does the cross-provider work
            // and `imdb` mostly does not.
            existing = self
                .db
                .query_row(
                    "SELECT id FROM people
                      WHERE name=?1 COLLATE NOCASE
                        AND (?2 = 0  OR tvmaze_id = 0     OR tvmaze_id = ?2)
                        AND (?3 = '' OR wikidata_qid = '' OR wikidata_qid = ?3)
                        AND (?4 = '' OR imdb = ''         OR imdb = ?4)
                        AND (?5 = '' OR born = ''         OR born = ?5)
                      ORDER BY id LIMIT 1",
                    rusqlite::params![name, c.tvmaze_id, c.wikidata_qid, c.imdb, c.born],
                    |r| r.get(0),
                )
                .optional()?;
        }
        let Some(id) = existing else {
            self.db.execute(
                "INSERT INTO people(name, imdb, tvmaze_id, wikidata_qid, born, photo)
                 VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![name, c.imdb, c.tvmaze_id, c.wikidata_qid, c.born, c.photo],
            )?;
            return Ok(self.db.last_insert_rowid());
        };
        // Fill blanks only. A second provider adds the handle the first
        // one lacked; it never overwrites one that is already set, or a
        // photo the user may have replaced.
        self.db.execute(
            "UPDATE people SET
                imdb         = CASE WHEN imdb=''         THEN ?2 ELSE imdb END,
                tvmaze_id    = CASE WHEN tvmaze_id=0     THEN ?3 ELSE tvmaze_id END,
                wikidata_qid = CASE WHEN wikidata_qid='' THEN ?4 ELSE wikidata_qid END,
                born         = CASE WHEN born=''         THEN ?5 ELSE born END,
                photo        = CASE WHEN photo=''        THEN ?6 ELSE photo END
              WHERE id=?1",
            rusqlite::params![id, c.imdb, c.tvmaze_id, c.wikidata_qid, c.born, c.photo],
        )?;
        Ok(id)
    }

    /// Replace one title's credits. Whole-set replacement, in one
    /// transaction: a re-enrichment that found fewer people must not
    /// leave the ones it no longer believes in behind, and a half-written
    /// cast is worse than the old one.
    pub fn title_credits_set(&self, key: &str, credits: &[Credit]) -> rusqlite::Result<()> {
        let tx = self.db.unchecked_transaction()?;
        tx.execute("DELETE FROM title_people WHERE key=?1", [key])?;
        for c in credits {
            if c.name.trim().is_empty() {
                continue;
            }
            let id = self.person_upsert(c)?;
            // OR REPLACE, not OR IGNORE: (key, person, role) is the
            // primary key, so an actor credited twice (dual role) keeps
            // the later character rather than failing the whole set.
            tx.execute(
                "INSERT OR REPLACE INTO title_people(key, person_id, role, character, ord)
                 VALUES(?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    key,
                    id,
                    if c.role.is_empty() { "actor" } else { &c.role },
                    c.character,
                    c.ord
                ],
            )?;
        }
        tx.commit()
    }

    /// One title's credits, billing order first (the detail sheet's cast
    /// chips). Crew follow the cast, since `ord` is 0 for them.
    pub fn title_credits(&self, key: &str, limit: u32) -> rusqlite::Result<Vec<PersonCredit>> {
        let mut stmt = self.db.prepare_cached(
            "SELECT p.id, p.name, p.photo, tp.role, tp.character, tp.ord
               FROM title_people tp JOIN people p ON p.id = tp.person_id
              WHERE tp.key = ?1
              ORDER BY (tp.role <> 'actor'), tp.ord, p.name
              LIMIT ?2",
        )?;
        let rows = stmt.query_map(rusqlite::params![key, limit], |r| {
            Ok(PersonCredit {
                person_id: r.get(0)?,
                name: r.get(1)?,
                photo: r.get(2)?,
                role: r.get(3)?,
                character: r.get(4)?,
                ord: r.get(5)?,
            })
        })?;
        rows.collect()
    }

    pub fn person_get(&self, id: i64) -> rusqlite::Result<Option<PersonRow>> {
        self.db
            .query_row(
                "SELECT id, name, imdb, tvmaze_id, wikidata_qid, bio, born, photo
                   FROM people WHERE id=?1",
                [id],
                |r| {
                    Ok(PersonRow {
                        id: r.get(0)?,
                        name: r.get(1)?,
                        imdb: r.get(2)?,
                        tvmaze_id: r.get(3)?,
                        wikidata_qid: r.get(4)?,
                        bio: r.get(5)?,
                        born: r.get(6)?,
                        photo: r.get(7)?,
                    })
                },
            )
            .optional()
    }

    /// The person page's "in your index" half: every title they are
    /// credited on that the wall would actually show.
    ///
    /// Curation is not optional here. A title hidden with "Not
    /// interested", or filtered out by a learned language/group rule,
    /// must stay gone on this surface too - otherwise clicking a cast
    /// member is a way to walk straight back into what the user just
    /// told us to stop showing them.
    pub fn person_titles(&self, id: i64) -> rusqlite::Result<Vec<PersonTitle>> {
        let mut wheres: Vec<String> = vec!["r.junk < 50".into()];
        let mut params: Vec<Box<dyn rusqlite::ToSql>> = vec![Box::new(id)];
        self.curation_wheres("r.", &mut wheres, &mut params)?;
        // Undated titles sort last rather than heading a date-ordered
        // list - a Wikidata film with no P577 is not "the newest".
        // GROUPed by title, not one row per credit: someone who both
        // stars in a show and produces it holds two `title_people` rows,
        // and listing their own filmography twice is a bug the join
        // produces for free. The roles collapse into one comma-joined
        // list and the character comes from the acting credit.
        let sql = format!(
            "SELECT t.key, t.kind, t.title, t.year, t.poster, t.air_date,
                    GROUP_CONCAT(DISTINCT tp.role),
                    MAX(CASE WHEN tp.role='actor' THEN tp.character ELSE '' END),
                    MIN(tp.ord),
                    (SELECT COUNT(*) FROM releases r2
                      WHERE r2.title_key = t.key AND r2.junk < 50)
               FROM title_people tp JOIN titles t ON t.key = tp.key
              WHERE tp.person_id = ?1
                AND EXISTS(SELECT 1 FROM releases r
                            WHERE r.title_key = t.key AND {})
              GROUP BY t.key
              ORDER BY (COALESCE(NULLIF(t.air_date,''),
                                 NULLIF(CAST(t.year AS TEXT),'0')) IS NULL),
                       COALESCE(NULLIF(t.air_date,''),
                                NULLIF(CAST(t.year AS TEXT),'0')) DESC,
                       t.title",
            wheres.join(" AND ")
        );
        let mut stmt = self.db.prepare(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(params.iter()), |r| {
            Ok(PersonTitle {
                key: r.get(0)?,
                kind: r.get(1)?,
                title: r.get(2)?,
                year: r.get::<_, i64>(3)? as u32,
                poster: r.get(4)?,
                air_date: r.get(5)?,
                role: r.get(6)?,
                character: r.get(7)?,
                ord: r.get(8)?,
                n_releases: r.get(9)?,
            })
        })?;
        rows.collect()
    }

    /// Name search over `people`. FTS5 prefix match so "tom cru" finds
    /// Tom Cruise mid-type; the LIKE arm keeps a non-FTS build working.
    /// Only people with at least one visible credit are returned - a
    /// crew name from a title the user has hidden is not a search hit.
    pub fn people_search(&self, q: &str, limit: u32) -> rusqlite::Result<Vec<PersonHit>> {
        let q = q.trim();
        if q.is_empty() {
            return Ok(Vec::new());
        }
        let credited = "(SELECT COUNT(*) FROM title_people tp
                          WHERE tp.person_id = p.id
                            AND EXISTS(SELECT 1 FROM releases r
                                        WHERE r.title_key = tp.key AND r.junk < 50
                                          AND r.title_key NOT IN
                                              (SELECT key FROM wall_hidden)))";
        let (sql, param): (String, Box<dyn rusqlite::ToSql>) = if self.people_fts {
            // Quote every token and append * to the last: FTS5 syntax
            // characters in a user's query would otherwise be operators
            // (or a parse error that returns nothing).
            let mut toks: Vec<String> = q
                .split_whitespace()
                .map(|w| format!("\"{}\"", w.replace('"', "\"\"")))
                .collect();
            if let Some(last) = toks.last_mut() {
                last.push('*');
            }
            (
                format!(
                    "SELECT p.id, p.name, p.photo, {credited} n
                       FROM people_fts f JOIN people p ON p.id = f.rowid
                      WHERE people_fts MATCH ?1 AND n > 0
                      ORDER BY n DESC, p.name LIMIT ?2"
                ),
                Box::new(toks.join(" ")),
            )
        } else {
            (
                format!(
                    "SELECT p.id, p.name, p.photo, {credited} n
                       FROM people p
                      WHERE p.name LIKE ?1 AND n > 0
                      ORDER BY n DESC, p.name LIMIT ?2"
                ),
                Box::new(format!("%{q}%")),
            )
        };
        let mut stmt = self.db.prepare(&sql)?;
        let binds: Vec<Box<dyn rusqlite::ToSql>> = vec![param, Box::new(limit as i64)];
        let rows = stmt.query_map(rusqlite::params_from_iter(binds.iter()), |r| {
            Ok(PersonHit {
                id: r.get(0)?,
                name: r.get(1)?,
                photo: r.get(2)?,
                n_titles: r.get(3)?,
            })
        })?;
        rows.collect()
    }

    /// Title keys a set of people are credited on, curated - the search
    /// leg that turns "tom cruise" into the cards the user actually has.
    pub fn titles_for_people(
        &self,
        ids: &[i64],
        limit: u32,
    ) -> rusqlite::Result<Vec<String>> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let mut wheres: Vec<String> = vec!["r.junk < 50".into()];
        let mut params: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
        self.curation_wheres("r.", &mut wheres, &mut params)?;
        // ids are i64 read from our own table, so inlining them cannot
        // carry a caller string into the SQL.
        let list = ids.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(",");
        params.push(Box::new(limit as i64));
        let n = params.len();
        let sql = format!(
            "SELECT tp.key FROM title_people tp
              WHERE tp.person_id IN ({list})
                AND EXISTS(SELECT 1 FROM releases r
                            WHERE r.title_key = tp.key AND {})
              GROUP BY tp.key
              ORDER BY MIN(tp.ord), tp.key LIMIT ?{n}",
            wheres.join(" AND ")
        );
        let mut stmt = self.db.prepare(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(params.iter()), |r| r.get(0))?;
        rows.collect()
    }

    /// (id, headshot URL) for people credited on a visible title, paged
    /// by id - the headshot lane's work queue.
    ///
    /// An id cursor rather than "most credited first": the caller skips
    /// the ones already on disk, and a popularity order would re-offer
    /// the same top rows on every pass and never reach the tail.
    pub fn people_photo_queue(
        &self,
        after_id: i64,
        limit: u32,
    ) -> rusqlite::Result<Vec<(i64, String)>> {
        let mut stmt = self.db.prepare_cached(
            "SELECT p.id, p.photo FROM people p
              WHERE p.id > ?1 AND p.photo LIKE 'http%'
                AND EXISTS(SELECT 1 FROM title_people tp
                            JOIN releases r ON r.title_key = tp.key
                           WHERE tp.person_id = p.id AND r.junk < 50)
              ORDER BY p.id LIMIT ?2",
        )?;
        let rows = stmt.query_map(rusqlite::params![after_id, limit], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })?;
        rows.collect()
    }

    /// Drop a headshot URL that will never work (404, not an image), so
    /// the queue stops offering it.
    pub fn person_clear_photo(&self, id: i64) -> rusqlite::Result<()> {
        self.db.execute("UPDATE people SET photo='' WHERE id=?1", [id])?;
        Ok(())
    }

    /// One release's name, by id. `None` when there is no such row.
    /// Grabbing from the wall needs exactly this and nothing else: the
    /// stem becomes the job name, and through it the output directory,
    /// the spool file, the history label and the duplicate key.
    pub fn stem_by_id(&self, release_id: i64) -> rusqlite::Result<Option<String>> {
        self.db
            .query_row("SELECT stem FROM releases WHERE id=?1", [release_id], |r| {
                r.get(0)
            })
            .optional()
    }

    /// Synthesize an NZB for a release.
    pub fn make_nzb(&self, release_id: i64) -> rusqlite::Result<String> {
        let (grp, poster, posted): (String, String, i64) = self.db.query_row(
            "SELECT grp, poster, first_posted FROM releases WHERE id=?1",
            [release_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        let mut stmt = self
            .db
            .prepare("SELECT filename, total_parts, segments FROM files WHERE release_id=?1 ORDER BY filename")?;
        let mut xml = String::from(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
        );
        let rows = stmt.query_map([release_id], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, u32>(1)?,
                r.get::<_, String>(2)?,
            ))
        })?;
        for row in rows {
            let (fname, total, seg_json) = row?;
            let segs: Vec<(u32, String, u64)> =
                serde_json::from_str(&seg_json).unwrap_or_default();
            // date carries the release's real post time: the pool's
            // retention routing and the availability ledger's age
            // buckets both key off it (date="0" recorded every
            // index-grab as a 0-day-old post).
            xml.push_str(&format!(
                "  <file poster=\"{}\" date=\"{posted}\" subject=\"{}\">\n    <groups><group>{}</group></groups>\n    <segments>\n",
                xml_escape(&poster),
                xml_escape(&format!("\"{fname}\" yEnc (1/{total})")),
                xml_escape(&grp)
            ));
            for (num, msgid, bytes) in segs {
                xml.push_str(&format!(
                    "      <segment bytes=\"{bytes}\" number=\"{num}\">{}</segment>\n",
                    xml_escape(msgid.trim_matches(['<', '>']))
                ));
            }
            xml.push_str("    </segments>\n  </file>\n");
        }
        xml.push_str("</nzb>\n");
        Ok(xml)
    }

    /// Delete releases outside [min,max] total bytes (0 = unbounded).
    /// Oversize releases can only grow, so they go immediately; undersize
    /// ones are pruned once FULLY PRESENT (every seen file has all its
    /// parts - the upload finished and it's still tiny, which is exactly
    /// what indexer spam looks like: one 1 MB .m3u/.nfo posted solo).
    /// A release still missing parts may be mid-upload, so it stays.
    /// Rare boundary miss: a release straddling two scan runs with only
    /// its smallest file landed can lose that file's rows - the next
    /// scan re-adds the rest, so the cost is one sibling file, not the
    /// release. Returns rows removed.
    pub fn prune_size(&self, min: u64, max: u64) -> rusqlite::Result<usize> {
        // One transaction: releases.id has no AUTOINCREMENT, so SQLite
        // reuses max(rowid)+1 - exactly the just-pruned oversize ids. As
        // separate autocommit statements, a crash (or the n>0 gate)
        // between delete and sweep left orphan files rows that the next
        // ingest's recycled id ADOPTED: wrong counts/complete flag, and
        // make_nzb synthesized an NZB from another release's segments.
        let tx = self.db.unchecked_transaction()?;
        let mut n = 0;
        if max > 0 {
            n += tx.execute("DELETE FROM releases WHERE total_bytes > ?1", [max as i64])?;
        }
        if min > 0 {
            n += tx.execute(
                "DELETE FROM releases WHERE total_bytes < ?1 AND NOT EXISTS (
                     SELECT 1 FROM files WHERE release_id = releases.id
                     AND json_array_length(segments) < total_parts)",
                [min as i64],
            )?;
        }
        // Unconditional: also clears orphans left by an earlier crash.
        tx.execute(
            "DELETE FROM files WHERE release_id NOT IN (SELECT id FROM releases)",
            [],
        )?;
        tx.commit()?;
        Ok(n)
    }

    pub fn stats(&self) -> rusqlite::Result<(u64, u64)> {
        self.db.query_row(
            "SELECT COUNT(*), COALESCE(SUM(complete),0) FROM releases",
            [],
            |r| Ok((r.get::<_, i64>(0)? as u64, r.get::<_, i64>(1)? as u64)),
        )
    }

    /// M31a: delete a batch of release ids and their files rows in one
    /// transaction. Files first so no orphan is left if we crash between;
    /// the `rel_fts_ad` trigger keeps FTS in sync on the releases delete.
    /// Returns rows removed from `releases`.
    fn prune_batch(&self, ids: &[i64]) -> rusqlite::Result<usize> {
        if ids.is_empty() {
            return Ok(0);
        }
        let list = ids.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(",");
        let tx = self.db.unchecked_transaction()?;
        tx.execute(&format!("DELETE FROM files WHERE release_id IN ({list})"), [])?;
        let n = tx.execute(&format!("DELETE FROM releases WHERE id IN ({list})"), [])?;
        tx.commit()?;
        Ok(n)
    }

    /// M31a: age-based retention. Deletes releases older than the window,
    /// EXCEPT unknown-date rows (`first_posted` 0, whose OVER Date failed
    /// to parse) and titles the user has hidden (the Hidden panel must
    /// keep showing them). Chunked so a big first prune never holds the
    /// write lock past the parallel scanners' 10 s busy timeout. Freed
    /// pages get reused by later scans, so the DB size plateaus even
    /// without VACUUM. Returns rows removed.
    ///
    /// Note: an owned release older than the window IS pruned from the
    /// INDEX - the downloaded file and history entry are untouched
    /// (have-badges compute from daemon history, not the index), and a
    /// re-scan re-adds it if it's still within the ingest gate.
    pub fn prune_age(&self, max_age_secs: i64, now: i64) -> rusqlite::Result<usize> {
        if max_age_secs <= 0 {
            return Ok(0);
        }
        let cutoff = now - max_age_secs;
        let mut removed = 0;
        loop {
            let ids: Vec<i64> = {
                let mut stmt = self.db.prepare_cached(
                    "SELECT id FROM releases
                     WHERE first_posted > 0 AND first_posted < ?1
                       AND title_key NOT IN (SELECT key FROM wall_hidden)
                     LIMIT 8000",
                )?;
                stmt.query_map([cutoff], |r| r.get(0))?
                    .collect::<rusqlite::Result<_>>()?
            };
            if ids.is_empty() {
                break;
            }
            removed += self.prune_batch(&ids)?;
        }
        Ok(removed)
    }

    /// What has landed on the wall since `since` - the poll behind the
    /// "N new" pill. Deliberately cheap: the wall's own query is far too
    /// expensive to run every few seconds just to find out whether
    /// anything changed, so this answers only that question and the real
    /// fetch happens when the answer is yes.
    ///
    /// An arrival is BOTH inserted after the caller's persistent sequence
    /// cursor (`arrival_seq > since`) AND recently posted
    /// (`first_posted > posted_after`).
    /// The cursor cannot be `first_seen`: it has whole-second resolution,
    /// so a release inserted later in the same second as the prior poll
    /// would otherwise be skipped forever. Both halves are load-
    /// bearing, and getting this wrong is what live-testing caught:
    ///
    /// - `first_seen` alone counts the history deepen leg's finds. Those
    ///   are new to the index but they are years-old uploads, so the
    ///   pill cries wolf every backfill pass.
    /// - Worse, it cries wolf *invisibly*: the wall's default sort is by
    ///   posted date, so a decade-old upload the pill just announced sits
    ///   thousands of cards down. Clicking "4 new arrivals" showed a wall
    ///   with nothing new on it. Requiring recent `first_posted` means an
    ///   announced arrival is always near the top where the user is
    ///   looking.
    ///
    /// Curation-aware to the same degree as the default wall: junk and
    /// explicitly-hidden titles never count. Learned `wall_rules` are
    /// NOT applied - they need the browse path's whole filter machinery,
    /// and over-counting a badge by a rule-hidden title is a far smaller
    /// sin than making this poll expensive.
    pub fn wall_tip(
        &self,
        since: i64,
        posted_after: i64,
        limit: u32,
    ) -> rusqlite::Result<TipInfo> {
        // Read the persistent counter, not MAX(releases.arrival_seq).
        // Eviction can empty the table; the next inserted release must
        // still advance beyond a browser's zero/current cursor.
        let latest: i64 = self
            .db
            .query_row(
                "SELECT COALESCE(
                    (SELECT CAST(v AS INTEGER) FROM kv WHERE k='wall_arrival_seq'), 0
                 )",
                [],
                |r| r.get(0),
            )
            .unwrap_or(0);
        const VISIBLE: &str = "arrival_seq > ?1 AND first_posted > ?2
             AND junk < 50 AND title_key <> ''
             AND title_key NOT IN (SELECT key FROM wall_hidden)";
        let new_keys: u32 = self.db.query_row(
            &format!("SELECT COUNT(*) FROM (SELECT DISTINCT title_key FROM releases WHERE {VISIBLE})"),
            [since, posted_after],
            |r| r.get(0),
        )?;
        let mut stmt = self.db.prepare(&format!(
            "SELECT title_key FROM releases WHERE {VISIBLE}
             GROUP BY title_key ORDER BY MAX(arrival_seq) DESC LIMIT ?3"
        ))?;
        let keys = stmt
            .query_map(rusqlite::params![since, posted_after, limit], |r| {
                r.get::<_, String>(0)
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(TipInfo { latest, new_keys, keys })
    }

    /// M31a: reap dead junk fragments regardless of max_age - the bulk
    /// of a raw a.b.teevee/moovee index is single-segment fragments of
    /// obfuscated posts that never form a complete release (measured on
    /// the live 800k-row index: ~87% are junk-hidden, tiny, incomplete).
    /// prune_size spares anything missing parts forever (can't tell a
    /// mid-upload from a dead one), so this is where they die.
    ///
    /// DELIBERATELY gated on `junk >= 50` (already hidden from the wall)
    /// so the always-on reaper NEVER touches wall-visible content - a
    /// release is reaped only when it is already-junk AND older than the
    /// settle window (so not a live mid-upload; Usenet propagation is
    /// hours, not days) AND still missing parts (confirmed incomplete on
    /// the server). Wall-visible old content is the opt-in age prune's
    /// job, never this one's. Same chunking + hidden protection.
    /// Returns rows removed.
    pub fn prune_stale_partials(
        &self,
        settle_secs: i64,
        now: i64,
    ) -> rusqlite::Result<usize> {
        let cutoff = now - settle_secs;
        let mut removed = 0;
        loop {
            let ids: Vec<i64> = {
                let mut stmt = self.db.prepare_cached(
                    // first_seen (when WE indexed it) is the settle clock, not
                    // first_posted (the post's own age). During history backfill
                    // every post is old by definition, so gating only on
                    // first_posted reaped releases still being assembled across
                    // scan slices. Require BOTH: settled by post age AND known to
                    // the index for the settle window.
                    "SELECT id FROM releases
                     WHERE junk >= 50 AND first_posted > 0 AND first_posted < ?1
                       AND first_seen > 0 AND first_seen < ?1
                       AND title_key NOT IN (SELECT key FROM wall_hidden)
                       AND EXISTS (SELECT 1 FROM files f
                                   WHERE f.release_id = releases.id
                                     AND json_array_length(f.segments) < f.total_parts)
                     LIMIT 8000",
                )?;
                stmt.query_map([cutoff], |r| r.get(0))?
                    .collect::<rusqlite::Result<_>>()?
            };
            if ids.is_empty() {
                break;
            }
            removed += self.prune_batch(&ids)?;
        }
        Ok(removed)
    }

    /// M31a: reclaim freed pages to disk. Exclusive-locks and rewrites
    /// the whole file - the caller MUST ensure no scan pass or download
    /// is in flight. Returns bytes freed (before - after file size).
    pub fn compact(&self) -> rusqlite::Result<()> {
        self.db.execute_batch("VACUUM")
    }

    /// A handle another thread can use to abort whatever statement this
    /// connection is currently running.
    ///
    /// It exists for `compact()`. On a multi-GB index a VACUUM is minutes
    /// of synchronous rewriting, and it is held under the same gate that
    /// a starting download waits on - so a job that arrives one moment
    /// after the "is anything downloading?" check sits in `Downloading`,
    /// making no progress and logging nothing, until the rewrite ends.
    /// VACUUM is a single transaction, so aborting it leaves the database
    /// exactly as it was and costs only the work done so far.
    ///
    /// Interrupting is per-CONNECTION, not per-statement: only call this
    /// while you know the statement you mean to stop is the one running.
    pub fn interrupt_handle(&self) -> rusqlite::InterruptHandle {
        self.db.get_interrupt_handle()
    }

    // -- M32: size cap + eviction (types and SQL near the end of the file) --

    /// Current on-disk size: page_count * page_size, including the freelist.
    ///
    /// This is what the user sees in Finder/`ls`, so it is what the cap
    /// is expressed against - even though the freelist part of it is
    /// space DELETE has already released for reuse and only `compact()`
    /// can hand back to the filesystem.
    pub fn db_bytes(&self) -> rusqlite::Result<u64> {
        let pages: i64 = self.db.query_row("PRAGMA page_count", [], |r| r.get(0))?;
        let size: i64 = self.db.query_row("PRAGMA page_size", [], |r| r.get(0))?;
        Ok(pages.max(0) as u64 * size.max(0) as u64)
    }

    /// Bytes of the file that still hold live content: `db_bytes()` minus
    /// the freelist. This - not `db_bytes()` - is what eviction can move,
    /// and it is the size the file WOULD have after a `compact()`, so it
    /// is the honest quantity to compare against the user's cap.
    ///
    /// It over-states live content by the free space stranded inside
    /// partially-emptied pages, which the freelist does not count. For
    /// this schema that error is small: the bulk of the bytes are the
    /// `files.segments` blobs, which live on overflow chains that are
    /// released whole when their row goes.
    ///
    /// PUBLIC, and deliberately so: the daemon compares the user's cap
    /// against THIS, not against `db_bytes()`. Comparing against the raw
    /// file size meant an evicted database never got back under its cap
    /// (DELETE frees pages to the freelist without shortening the file),
    /// so automatic eviction re-fired on every scan pass forever.
    pub fn live_bytes(&self) -> rusqlite::Result<u64> {
        let pages: i64 = self.db.query_row("PRAGMA page_count", [], |r| r.get(0))?;
        let free: i64 = self.db.query_row("PRAGMA freelist_count", [], |r| r.get(0))?;
        let size: i64 = self.db.query_row("PRAGMA page_size", [], |r| r.get(0))?;
        Ok((pages - free).max(0) as u64 * size.max(0) as u64)
    }

    /// Evict until the database would fit in `target_bytes`, honouring the
    /// policy order and never touching anything in `protected`.
    /// `target_bytes == 0` means unlimited: return immediately, remove nothing.
    ///
    /// Deletes go through `prune_batch`, so the `files` cascade, the
    /// single transaction and the FTS trigger behave exactly as they do
    /// for the age/size pruners.
    ///
    /// `bytes_after` will usually EQUAL `bytes_before`: DELETE in SQLite
    /// moves pages to the freelist, it does not shorten the file. That is
    /// correct and expected, and is the entire reason `needs_compact`
    /// exists - `compact()` takes an exclusive lock and rewrites the whole
    /// file, so the daemon schedules it for an idle window rather than
    /// having eviction do it inline.
    ///
    /// If the protected set (plus the kinds filter) leaves too little to
    /// delete, eviction stops early: the target is simply not reached and
    /// `removed` reports how far it got. Protection outranks the cap.
    pub fn evict_to(
        &self,
        target_bytes: u64,
        policy: &EvictPolicy,
        protected: &Protected,
    ) -> rusqlite::Result<EvictReport> {
        let before = self.db_bytes()?;
        let live_before = self.live_bytes()?;
        // 0 = unlimited. Do this before anything else touches the db.
        if target_bytes == 0 {
            return Ok(EvictReport {
                removed: 0,
                bytes_before: before,
                bytes_after: before,
                live_before,
                live_after: live_before,
                needs_compact: false,
                blocked: false,
            });
        }
        let low = target_bytes / EVICT_LOW_WATER_DEN * EVICT_LOW_WATER_NUM;

        // The authoritative protection check. The `NOT IN` binds below are
        // an optimisation that keeps protected rows out of the candidate
        // pages when the set is small enough to bind; these two sets are
        // what actually decides, and they hold EVERYTHING the caller
        // passed, with no cap.
        //
        // An empty title_key is dropped deliberately: `releases.title_key`
        // defaults to '' for rows that predate M28 or never parsed, so a
        // stray '' in the protected list would silently protect every
        // unclassified row in the index and wedge eviction shut.
        let prot_ids: std::collections::HashSet<i64> =
            protected.release_ids.iter().copied().collect();
        let prot_keys: std::collections::HashSet<&str> = protected
            .title_keys
            .iter()
            .map(|s| s.as_str())
            .filter(|s| !s.is_empty())
            .collect();

        // -- candidate query, built once --
        let mut params: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
        let mut wheres: Vec<String> = Vec::new();
        if !policy.kinds.is_empty() {
            // Bound parameters, never interpolated - `kinds` comes off the
            // settings API. Note an unclassified row (kind = '') matches no
            // filter, so a kind-restricted eviction spares it: protect
            // more, never less.
            let ph: Vec<String> = policy
                .kinds
                .iter()
                .map(|k| {
                    params.push(Box::new(k.clone()));
                    format!("?{}", params.len())
                })
                .collect();
            wheres.push(format!("r.kind IN ({})", ph.join(",")));
        }
        // NULL TRAP: the schema comment on `wall_hidden` records that one
        // NULL key makes `x NOT IN (SELECT ...)` evaluate NULL for every
        // row and silently disable the whole prune. These `NOT IN` lists
        // are immune by construction - they are bound literals from Rust
        // `i64`/`String`, never a subquery and never NULL - and the left
        // sides (`releases.id` PRIMARY KEY, `releases.title_key` NOT NULL)
        // cannot be NULL either. No subquery form is used anywhere in this
        // path for exactly that reason.
        let mut budget = EVICT_PROTECT_BIND_CAP;
        for chunk in protected.release_ids.chunks(EVICT_PROTECT_CHUNK) {
            if budget == 0 {
                break;
            }
            let take = chunk.len().min(budget);
            budget -= take;
            let ph: Vec<String> = chunk[..take]
                .iter()
                .map(|id| {
                    params.push(Box::new(*id));
                    format!("?{}", params.len())
                })
                .collect();
            wheres.push(format!("r.id NOT IN ({})", ph.join(",")));
        }
        for chunk in protected.title_keys.chunks(EVICT_PROTECT_CHUNK) {
            if budget == 0 {
                break;
            }
            let keys: Vec<&String> = chunk.iter().filter(|s| !s.is_empty()).collect();
            let take = keys.len().min(budget);
            if take == 0 {
                continue;
            }
            budget -= take;
            let ph: Vec<String> = keys[..take]
                .iter()
                .map(|k| {
                    params.push(Box::new((*k).clone()));
                    format!("?{}", params.len())
                })
                .collect();
            wheres.push(format!("r.title_key NOT IN ({})", ph.join(",")));
        }
        let where_sql = if wheres.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", wheres.join(" AND "))
        };
        let limit_ph = params.len() + 1;
        let offset_ph = params.len() + 2;
        let sql = format!(
            "SELECT r.id, r.title_key, {EVICT_PAYLOAD_SQL} FROM releases r
             {where_sql} ORDER BY {} LIMIT ?{limit_ph} OFFSET ?{offset_ph}",
            evict_order_sql(policy.order)
        );

        // -- the eviction loop --
        //
        // Two independent stop signals, and EITHER can stop us, because
        // over-deleting is the one failure mode that costs the user data:
        //
        //  measured  - live_bytes() re-read from the file after every
        //              batch. Ground truth, but blind to space stranded
        //              in partly-emptied pages, so it can lag reality.
        //  predicted - starts at the measured size and walks down by the
        //              estimated payload of what we delete. Immune to
        //              that lag, but only as good as the estimate.
        //
        // `scale` lifts the raw payload estimate to real page cost
        // (b-tree fanout, idx_rel_stem, idx_rel_kind, FTS5). It is fitted
        // from the previous batch's observed drop rather than from a
        // whole-table scan, which on an 800k-row index would mean reading
        // every segments blob just to decide what to delete. It is
        // clamped at >= 1.0 because a deleted row's own bytes are a hard
        // floor on what a later VACUUM reclaims, and <= 4.0 so one odd
        // batch cannot make `predicted` fall off a cliff.
        //
        // ERROR BOUND, measured (see the tests at the end of this file):
        //  * blob-dominated rows, the shape that actually fills this
        //    database - real page cost / raw payload = 0.997 to 1.010.
        //    The estimate is essentially exact.
        //  * 200-byte rows, where per-row and index overhead dominates -
        //    1.18 to 1.25. The seed of 1.0 makes the FIRST batch of a
        //    call take up to ~20% more rows than it needed; every batch
        //    after it uses the fitted value.
        // A batch stops the moment the estimate reaches the low water
        // mark, so a call's overshoot is its LAST batch's overshoot, and
        // is bounded by EVICT_PAGE rows regardless of what the estimate
        // does. On top of that sits the indivisible-row floor: the row
        // that crosses the line is deleted whole, so a single 256 MB
        // release can carry the file well past the mark on its own.
        // End to end that put the test fixtures at 75-84% of the cap
        // instead of the 90% low water mark - inside the hysteresis band
        // by construction, and never near emptying the index.
        //
        // Under-shooting (the estimate claiming more freed than really
        // was) is self-correcting and costs nothing: the daemon's next
        // pass sees the file still over the cap and evicts again.
        let mut removed = 0usize;
        let mut offset = 0usize; // protected rows already stepped over
        let mut scale = 1.0f64;
        let mut predicted = self.live_bytes()? as f64;
        let mut guard = 0u32;
        // Set at every exit that is NOT "we got under the low water mark".
        // Reconciled against the real size once the loop is done.
        let mut blocked = false;
        loop {
            guard += 1;
            if guard > 100_000 {
                blocked = true;
                break;
            }
            let measured = self.live_bytes()? as f64;
            let effective = measured.min(predicted);
            if effective <= low as f64 {
                break;
            }
            let need = effective - low as f64;

            let page: Vec<(i64, String, i64)> = {
                let mut stmt = self.db.prepare_cached(&sql)?;
                let mut binds: Vec<&dyn rusqlite::ToSql> =
                    params.iter().map(|b| b.as_ref()).collect();
                let lim = EVICT_PAGE as i64;
                let off = offset as i64;
                binds.push(&lim);
                binds.push(&off);
                stmt.query_map(binds.as_slice(), |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                    .collect::<rusqlite::Result<_>>()?
            };
            if page.is_empty() {
                blocked = true;
                break; // nothing left we are allowed to touch
            }
            let exhausted = page.len() < EVICT_PAGE;

            let mut ids: Vec<i64> = Vec::new();
            let mut payload = 0f64;
            let mut skipped = 0usize;
            for (id, key, pl) in &page {
                if prot_ids.contains(id) || prot_keys.contains(key.as_str()) {
                    // Survives, and stays in the table - so the next page
                    // must start past it or we would re-read it forever.
                    skipped += 1;
                    continue;
                }
                ids.push(*id);
                payload += (*pl).max(0) as f64;
                if payload * scale >= need {
                    break;
                }
            }
            offset += skipped;
            if ids.is_empty() {
                if exhausted {
                    blocked = true;
                    break; // every remaining candidate is protected
                }
                continue; // whole page was protected; offset advanced
            }

            removed += self.prune_batch(&ids)?;
            let after = self.live_bytes()? as f64;
            if payload > 0.0 {
                scale = ((measured - after) / payload).clamp(1.0, 4.0);
            }
            predicted = (predicted - payload * scale).max(0.0);
        }

        let after = self.db_bytes()?;
        let live_after = self.live_bytes()?;
        Ok(EvictReport {
            removed,
            bytes_before: before,
            bytes_after: after,
            live_before,
            live_after,
            needs_compact: removed > 0,
            // Stopping early only counts as blocked if it actually left
            // the database over the target. Stopping between the low
            // water mark and the target is the hysteresis band doing its
            // job, not a failure.
            blocked: blocked && live_after > target_bytes,
        })
    }

    // -- Spotnet spots (M14j) - curated metadata layered over the raw index --

    /// Insert one verified spot; `Ok(true)` if it was new, `Ok(false)` if
    /// the message-id was already indexed.
    pub fn insert_spot(&self, s: &Spot) -> rusqlite::Result<bool> {
        let n = self.db.execute(
            "INSERT INTO spots(msgid, title, category, subcats, size, date,
                               spotter_id, verified, hashcash_ok, nzb_msgids)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT(msgid) DO NOTHING",
            rusqlite::params![
                s.msgid,
                s.title,
                s.category,
                s.subcats,
                s.size as i64,
                s.date,
                s.spotter_id,
                s.verified,
                s.hashcash_ok,
                serde_json::to_string(&s.nzb_msgids).unwrap(),
            ],
        )?;
        Ok(n > 0)
    }

    /// Search spots by title substring (case-insensitive), newest first.
    pub fn spot_search(&self, query: &str, limit: u32) -> rusqlite::Result<Vec<Spot>> {
        let mut stmt = self.db.prepare(
            "SELECT id, msgid, title, category, subcats, size, date,
                    spotter_id, verified, hashcash_ok, nzb_msgids
             FROM spots WHERE title LIKE '%' || ?1 || '%'
             ORDER BY date DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(rusqlite::params![query, limit], spot_from_row)?;
        rows.collect()
    }

    /// A Browse page of spots: newest first, with paging and a total.
    ///
    /// `include_adult` is off by default because a third of free.pt is
    /// erotica (4,884 of 15,258 spots measured on a live scan) and it
    /// would otherwise be most of what a first search returns. The
    /// marker is the `d75` subcategory, which separates cleanly - it is
    /// what the poster themselves filed the spot under.
    pub fn spot_browse(&self, q: &SpotQuery) -> rusqlite::Result<(Vec<Spot>, u64)> {
        let mut where_sql = String::from(" WHERE 1=1");
        let mut args: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
        if !q.q.trim().is_empty() {
            where_sql.push_str(" AND title LIKE '%' || ? || '%'");
            args.push(Box::new(q.q.trim().to_string()));
        }
        if let Some(c) = q.category {
            where_sql.push_str(" AND category = ?");
            args.push(Box::new(c));
        }
        if !q.include_adult {
            where_sql.push_str(&format!(" AND ',' || subcats || ',' NOT LIKE '%,{ADULT_SUBCAT},%'"));
        }
        // Moderation records are no longer stored (nzbkit::spot::is_moderation),
        // but a database scanned before that are still full of them, and they
        // read like releases. Cheaper to exclude here than to migrate.
        where_sql.push_str(" AND title NOT LIKE 'DISPOSE %'");
        let params: Vec<&dyn rusqlite::ToSql> = args.iter().map(|b| b.as_ref()).collect();

        let total: i64 = self.db.query_row(
            &format!("SELECT COUNT(*) FROM spots{where_sql}"),
            params.as_slice(),
            |r| r.get(0),
        )?;

        let mut page = params.clone();
        let (limit, offset) = (q.limit.clamp(1, 500) as i64, q.offset as i64);
        page.push(&limit);
        page.push(&offset);
        let mut stmt = self.db.prepare(&format!(
            "SELECT id, msgid, title, category, subcats, size, date,
                    spotter_id, verified, hashcash_ok, nzb_msgids
             FROM spots{where_sql} ORDER BY date DESC, id DESC LIMIT ? OFFSET ?"
        ))?;
        let rows = stmt.query_map(page.as_slice(), spot_from_row)?;
        Ok((rows.collect::<rusqlite::Result<Vec<_>>>()?, total as u64))
    }

    pub fn spot_by_msgid(&self, msgid: &str) -> rusqlite::Result<Option<Spot>> {
        let mut stmt = self.db.prepare(
            "SELECT id, msgid, title, category, subcats, size, date,
                    spotter_id, verified, hashcash_ok, nzb_msgids
             FROM spots WHERE msgid=?1",
        )?;
        let mut rows = stmt.query_map([msgid], spot_from_row)?;
        rows.next().transpose()
    }

    /// Cache the NZB payload segment ids once a spot has been fetched.
    pub fn set_spot_nzb(&self, msgid: &str, segment_ids: &[String]) -> rusqlite::Result<()> {
        self.db.execute(
            "UPDATE spots SET nzb_msgids=?2 WHERE msgid=?1",
            rusqlite::params![msgid, serde_json::to_string(segment_ids).unwrap()],
        )?;
        Ok(())
    }

    pub fn spot_stats(&self) -> rusqlite::Result<u64> {
        self.db
            .query_row("SELECT COUNT(*) FROM spots", [], |r| r.get::<_, i64>(0))
            .map(|n| n as u64)
    }

    /// Every title key currently classified into `kind`. Used by eviction
    /// protection for a watch item that intentionally names a whole custom
    /// category (empty title): protecting only a 200-card browse page would
    /// make the rest of that category disappear under size pressure.
    pub fn title_keys_for_kind(&self, kind: &str) -> rusqlite::Result<Vec<String>> {
        let mut stmt = self.db.prepare(
            "SELECT DISTINCT title_key FROM releases
             WHERE kind=?1 AND title_key <> ''",
        )?;
        stmt.query_map([kind], |r| r.get(0))?
            .collect::<rusqlite::Result<Vec<_>>>()
    }
}

/// What a lookup learned about one title. A struct rather than the ten
/// positional arguments this used to take: the "found nothing" callers
/// passed a row of bare `""`s in which nothing said which field was
/// which, and every new field made that worse.
#[derive(Debug, Clone, Default)]
pub struct TitleFill<'a> {
    pub tmdb_id: i64,
    pub overview: &'a str,
    pub rating: f64,
    pub genres: &'a str,
    /// Local art FILENAMES, not provider URLs - the caller downloads the
    /// images before filling.
    pub poster: &'a str,
    pub backdrop: &'a str,
    pub imdb: &'a str,
    pub actors: &'a str,
    /// ISO `YYYY-MM-DD`, or empty when the provider had no date.
    pub air_date: &'a str,
}

/// One person's credit on one title, as a provider gave it to us.
///
/// The identity fields are what make this more than the comma-joined
/// name string `titles.actors` already holds: TVmaze hands over a person
/// id and Wikidata a Q-id, and each is the handle its own filmography
/// endpoint takes. A provider that gives neither (OMDb, TMDB) still
/// produces a usable credit - it just cannot be followed off-index.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Credit {
    pub name: String,
    /// actor | director | writer | composer | creator | producer | …
    /// Free text, because crew vocabularies differ per provider and
    /// flattening them to an enum loses the useful ones ("Director of
    /// Photography"). Empty is stored as "actor".
    pub role: String,
    /// The part they played, when the provider models it (TVmaze
    /// `character.name`, Wikidata's P453 qualifier). Empty for crew.
    pub character: String,
    /// Billing order, lower first. 0 when unranked.
    pub ord: i64,
    pub tvmaze_id: i64,
    pub wikidata_qid: String,
    /// IMDb `nm…` id. Unlike the two handles above this one is shared
    /// vocabulary rather than a provider's own numbering, so it is the
    /// only field that can identify the same human across providers.
    pub imdb: String,
    /// Date of birth, ISO `YYYY-MM-DD`, empty when unknown. Not an
    /// identifier - it is the disambiguator `person_upsert` uses to tell
    /// two same-named people apart, and it earns that job by being the
    /// one fact BOTH cast providers publish (TVmaze `person.birthday`,
    /// Wikidata P569).
    pub born: String,
    /// Headshot: a provider URL as parsed, swapped for the local
    /// art-cache filename once the enricher has fetched it.
    pub photo: String,
}

/// A credit joined to its resolved person (what the detail sheet shows).
#[derive(Debug, Clone)]
pub struct PersonCredit {
    pub person_id: i64,
    pub name: String,
    pub photo: String,
    pub role: String,
    pub character: String,
    pub ord: i64,
}

#[derive(Debug, Clone, Default)]
pub struct PersonRow {
    pub id: i64,
    pub name: String,
    pub imdb: String,
    pub tvmaze_id: i64,
    pub wikidata_qid: String,
    pub bio: String,
    pub born: String,
    pub photo: String,
}

/// One title on a person page's "in your index" half.
#[derive(Debug, Clone)]
pub struct PersonTitle {
    pub key: String,
    pub kind: String,
    pub title: String,
    pub year: u32,
    pub poster: String,
    pub air_date: String,
    /// Every role they hold on this title, comma-joined - one person can
    /// star in a show AND produce it.
    pub role: String,
    /// The part they played, from the acting credit; empty for crew-only.
    pub character: String,
    pub ord: i64,
    pub n_releases: i64,
}

#[derive(Debug, Clone)]
pub struct PersonHit {
    pub id: i64,
    pub name: String,
    pub photo: String,
    /// How many visible titles they are credited on - the ranking signal
    /// and the honest answer to "is this person actually in my index".
    pub n_titles: i64,
}

/// One cached title-metadata row (M13 wall).
#[derive(Debug, Clone)]
pub struct TitleRow {
    pub key: String,
    pub kind: String,
    pub title: String,
    pub year: u32,
    pub tmdb_id: i64,
    pub overview: String,
    pub rating: f64,
    pub genres: String,
    pub poster: String,
    pub backdrop: String,
    pub checked: i64,
    /// IMDb tconst ("tt0133093") when a provider resolved one - joins
    /// against the imdb_ratings snapshot at wall time.
    pub imdb: String,
    /// Top-billed cast, comma-joined.
    pub actors: String,
    /// Original release / first-air date, ISO `YYYY-MM-DD`, or empty when
    /// the provider had none. `year` is the coarse fallback.
    pub air_date: String,
}

/// The Spotnet subcategory a poster files erotica under. Hidden from
/// Browse unless asked for; see [`Index::spot_browse`].
pub const ADULT_SUBCAT: &str = "d75";

/// A Browse query over the spots table.
#[derive(Debug, Clone, Default)]
pub struct SpotQuery {
    pub q: String,
    /// 0-based Spotnet category: 0 video, 1 music, 2 game, 3 application.
    pub category: Option<u8>,
    pub include_adult: bool,
    pub limit: u32,
    pub offset: u32,
}

/// Does this spot carry the adult subcategory?
pub fn spot_is_adult(subcats: &str) -> bool {
    subcats.split(',').any(|s| s.trim() == ADULT_SUBCAT)
}

/// The four Spotnet categories as our own content kinds. Spotnet does not
/// separate film from television - both are category 0 - so video maps to
/// the generic kind and the title parser does the rest downstream.
pub fn spot_kind(category: u8) -> &'static str {
    match category {
        0 => "video",
        1 => "music",
        2 => "game",
        3 => "app",
        _ => "other",
    }
}

/// One ingested Spotnet spot (M14j).
#[derive(Debug, Clone)]
pub struct Spot {
    pub id: i64,
    /// With angle brackets, as seen in OVER.
    pub msgid: String,
    pub title: String,
    /// Spotnet category, 0-based: 0 video, 1 music, 2 game, 3 application.
    pub category: u8,
    /// Comma-joined subcategory runs, e.g. `a09,b04`.
    pub subcats: String,
    pub size: u64,
    /// Unix timestamp from the spot record.
    pub date: i64,
    pub spotter_id: String,
    /// RSA signature verified (always true for stored spots today).
    pub verified: bool,
    /// V2 hashcash proof-of-work passed (warning flag when false).
    pub hashcash_ok: bool,
    /// NZB payload segment ids, cached after the first fetch.
    pub nzb_msgids: Vec<String>,
}

fn spot_from_row(r: &rusqlite::Row) -> rusqlite::Result<Spot> {
    Ok(Spot {
        id: r.get(0)?,
        msgid: r.get(1)?,
        title: r.get(2)?,
        category: r.get(3)?,
        subcats: r.get(4)?,
        size: r.get::<_, i64>(5)? as u64,
        date: r.get(6)?,
        spotter_id: r.get(7)?,
        verified: r.get(8)?,
        hashcash_ok: r.get(9)?,
        nzb_msgids: serde_json::from_str(&r.get::<_, String>(10)?).unwrap_or_default(),
    })
}

/// `… "name" yEnc (n/m)` → (subject minus counter, n, m).
///
/// The counter is the RIGHTMOST group that actually parses as one:
/// `(n/m)`, `[n/m]`, or `(n of m)`. Taking the last `(` unconditionally
/// broke on trailing tags - `… (5/50) (German)` or `… (5/50) (4.2 GB)`
/// returned None, every part collapsed to (1,1), and a 50-part file
/// indexed as one segment yet counted "complete".
pub fn split_subject(subject: &str) -> Option<(String, u32, u32)> {
    let opens: Vec<(usize, char, char)> = subject
        .char_indices()
        .filter_map(|(i, c)| match c {
            '(' => Some((i, '(', ')')),
            '[' => Some((i, '[', ']')),
            _ => None,
        })
        .collect();
    for &(open, _, close_ch) in opens.iter().rev() {
        let Some(close) = subject[open..].find(close_ch).map(|j| j + open) else {
            continue;
        };
        let inner = &subject[open + 1..close];
        let sep = inner.find('/').map(|i| (i, 1)).or_else(|| {
            inner.to_ascii_lowercase().find(" of ").map(|i| (i, 4))
        });
        let Some((si, sl)) = sep else { continue };
        let (Ok(n), Ok(m)) = (
            inner[..si].trim().parse::<u32>(),
            inner[si + sl..].trim().parse::<u32>(),
        ) else {
            continue;
        };
        let mut base = String::new();
        base.push_str(subject[..open].trim_end());
        base.push_str(subject[close + close_ch.len_utf8()..].trim_end());
        return Some((base, n, m));
    }
    None
}

/// Filename from a counter-stripped subject: the quoted name, else - for
/// the unquoted convention `Release.Name.part01.rar yEnc` - the first
/// whitespace token with a plausible extension (all-digit `.001`-style,
/// or letter-led 2-5 alphanumerics, or `.7z`). Quote-only parsing made
/// entire unquoted releases invisible to the indexer.
pub fn quoted_name(s: &str) -> Option<String> {
    if let Some(name) = crate::nzb::quoted_filename(s) {
        return Some(name.to_string());
    }
    s.split_whitespace()
        .find(|t| {
            // Poster furniture ("[#a.b.group]", "<foo.bar>") is not a
            // filename even when it carries a dotted extension shape.
            if !t.starts_with(|c: char| c.is_ascii_alphanumeric()) || t.contains('@') {
                return false;
            }
            let Some(dot) = t.rfind('.') else { return false };
            let ext = &t[dot + 1..];
            dot > 0
                && ((ext.len() >= 2 && ext.bytes().all(|c| c.is_ascii_digit()))
                    || (ext.len() >= 2
                        && ext.len() <= 5
                        && ext.as_bytes()[0].is_ascii_alphabetic()
                        && ext.bytes().all(|c| c.is_ascii_alphanumeric()))
                    || ext.eq_ignore_ascii_case("7z"))
        })
        .map(str::to_string)
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

// ===== M32: user-chosen index size cap, with automatic eviction =====

/// Which releases give way first when the index has to shrink.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EvictOrder {
    /// Default. An ordered ladder, not a single rule: reap what nobody
    /// would miss before touching anything they would.
    ///
    ///   rung 0  junk AND incomplete - dead obfuscated fragments
    ///   rung 1  junk but complete
    ///   rung 2  incomplete but not junk (a stalled/abandoned post)
    ///   rung 3  everything else - real, complete, wall-visible content
    ///
    /// and within a rung, oldest by `first_posted` first, then largest
    /// by `total_bytes` (free the most for the fewest deletions).
    /// Measured on the live index ~87% of rows sit on rungs 0-1, so in
    /// practice the ladder absorbs the whole cap before rung 3 is ever
    /// reached.
    #[default]
    Ladder,
    /// Single-key orders. No ladder, no junk/completeness preference.
    Oldest,
    Newest,
    Largest,
    Smallest,
}

#[derive(Debug, Clone, Default)]
pub struct EvictPolicy {
    pub order: EvictOrder,
    /// Restrict eviction to these kinds ("movie"/"tv"/"software"/"other").
    /// Empty = all kinds.
    pub kinds: Vec<String>,
}

/// What the daemon forbids evicting. index.rs NEVER reaches out for this -
/// the daemon owns the queue, watchlist and history and passes it in.
#[derive(Debug, Clone, Default)]
pub struct Protected {
    pub title_keys: Vec<String>,
    pub release_ids: Vec<i64>,
}

#[derive(Debug, Clone, Default)]
pub struct EvictReport {
    pub removed: usize,
    /// Raw file size (`db_bytes()`) either side of the call. This is what
    /// the user sees in Finder, so it is what the daemon reports - but it
    /// barely moves, because DELETE frees pages to the freelist rather
    /// than shortening the file. Do NOT test progress with it.
    pub bytes_before: u64,
    pub bytes_after: u64,
    /// `live_bytes()` either side of the call: the honest figure, and the
    /// one to compare against the target. `live_after <= target` is what
    /// "we got there" means.
    pub live_before: u64,
    pub live_after: u64,
    /// True when rows were deleted, so the caller should schedule a compact.
    pub needs_compact: bool,
    /// True when eviction stopped with the database still above its
    /// target because it ran out of rows it was ALLOWED to delete - every
    /// remaining candidate is protected, or the kinds filter excludes it.
    ///
    /// Without this the caller cannot tell "there was nothing left to do"
    /// from "we were stopped", and a still-oversized database looks like a
    /// success. `live_after` says how far it got; this says it stopped
    /// short on purpose rather than because the target was met.
    pub blocked: bool,
}

/// Evict down to this fraction of the cap rather than to the cap itself.
///
/// HYSTERESIS. Without a gap, a database sitting one page over the cap
/// would be trimmed back to exactly the cap, the next scan pass would
/// push it one page over again, and every pass from then on would take
/// the write lock, delete a handful of rows and set `needs_compact` -
/// a permanent grind at the boundary that also means a permanent VACUUM
/// backlog. Emptying to 90% buys roughly a tenth of the cap of headroom,
/// so on a 2 GB cap the index has ~200 MB to refill before eviction is
/// due again - hours of scanning, not one pass.
const EVICT_LOW_WATER_NUM: u64 = 9;
const EVICT_LOW_WATER_DEN: u64 = 10;

/// Rows examined (and at most deleted) per batch. Bounds how long one
/// `prune_batch` holds the write lock against the parallel scanners'
/// 10 s busy timeout, and bounds how far a single batch can overshoot
/// the low-water mark. `prune_age` uses 8000; eviction re-measures the
/// file between batches, so it wants smaller, more frequent steps.
///
/// The cost of the smaller step is that each batch re-runs the candidate
/// query, and no index can serve the ladder's CASE expression, so that is
/// a scan-and-sort of `releases` every time. Measured: a 266 MB / 60k-row
/// index evicts 12_440 rows (7 batches) in 616 ms. That is fine for the
/// scheduled maintenance pass this is; if it ever stops being fine, the
/// fix is to fetch ids in much larger pages and pull the per-row payload
/// only for the chunk about to be deleted - one sort per page instead of
/// one per batch, with the byte-accurate stop point kept intact.
const EVICT_PAGE: usize = 2_000;

/// How many protected entries we are willing to push into the candidate
/// SQL as bound `NOT IN` parameters. SQLite hard-limits a statement to
/// 32766 variables, and the existing `OWNED_IN_CAP` picks 10_000 for the
/// same reason. Anything past the cap is NOT dropped: the SQL filter is
/// only an optimisation, and every candidate row is re-checked in Rust
/// against the FULL protected set before it can be deleted (see
/// `evict_to`). Overflowing the cap therefore costs a little scan work,
/// never a lost protection.
const EVICT_PROTECT_BIND_CAP: usize = 10_000;

/// Bound parameters per `NOT IN (...)` clause; several clauses are ANDed
/// so the cap above can be spent without any one list going near the
/// per-statement variable limit.
const EVICT_PROTECT_CHUNK: usize = 500;

/// Per-release payload estimate, in SQL. The bulk of this database is
/// the `files.segments` JSON blobs, which run from a few bytes to
/// hundreds of KB per release, so a row count is a useless proxy for
/// bytes - the estimate has to read the actual value lengths.
///
/// `LENGTH()` on a TEXT column counts characters, not bytes; `segments`
/// and `filename` are ASCII JSON / ASCII-ish names, so the two agree in
/// practice, and the constants below (24 bytes per `files` row, 96 per
/// `releases` row) stand in for the record headers, rowid keys and the
/// small fixed integer columns. Everything the estimate cannot see -
/// b-tree interior pages, `idx_rel_stem` / `idx_rel_kind`, the FTS5
/// index - is folded in by the runtime scale factor in `evict_to`.
const EVICT_PAYLOAD_SQL: &str = "(SELECT COALESCE(SUM(LENGTH(f.segments) \
     + LENGTH(f.filename) + 24), 0) FROM files f WHERE f.release_id = r.id) \
     + LENGTH(r.stem) + LENGTH(r.poster) + LENGTH(r.grp) + LENGTH(r.title_key) \
     + LENGTH(r.res) + LENGTH(r.kind) + LENGTH(r.langs) + 96";

/// The ORDER BY that turns a policy into an eviction sequence.
///
/// `first_posted = 0` means the post's OVER Date failed to parse, not
/// that it is from 1970. `prune_age` spares those rows outright; here
/// they cannot be spared (the cap is a hard limit), so instead the
/// leading `(r.first_posted = 0) ASC` term parks them at the BACK of
/// every date-driven order - unknown-date rows are the last thing an
/// age-shaped policy touches, in both directions. `r.id` closes every
/// order so the sequence is total and a paged scan is stable.
fn evict_order_sql(order: EvictOrder) -> &'static str {
    match order {
        // `junk` is the M28 0-100 curation score, not a flag; >= 50 is
        // the established "already hidden from the wall" threshold that
        // `prune_stale_partials` reaps on, reused here so the two can
        // never disagree about what "junk" means.
        EvictOrder::Ladder => {
            "CASE WHEN r.junk >= 50 AND r.complete = 0 THEN 0 \
                  WHEN r.junk >= 50 THEN 1 \
                  WHEN r.complete = 0 THEN 2 \
                  ELSE 3 END ASC, \
             (r.first_posted = 0) ASC, r.first_posted ASC, \
             r.total_bytes DESC, r.id ASC"
        }
        EvictOrder::Oldest => "(r.first_posted = 0) ASC, r.first_posted ASC, r.id ASC",
        EvictOrder::Newest => "(r.first_posted = 0) ASC, r.first_posted DESC, r.id DESC",
        EvictOrder::Largest => "r.total_bytes DESC, r.id ASC",
        EvictOrder::Smallest => "r.total_bytes ASC, r.id ASC",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Tear a fixture down, closing the index BEFORE removing its directory.
    ///
    /// Taking `ix` by value is the whole point: it makes the close
    /// impossible to forget, because the directory cannot be named for
    /// removal until the index has been surrendered.
    ///
    /// The close is load-bearing, not tidiness. `Index` holds an open SQLite
    /// connection to `dir/index.db` (plus its -wal and -shm), and SQLite
    /// opens its files without FILE_SHARE_DELETE, so Windows refuses to
    /// remove the directory underneath it: "The process cannot access the
    /// file because it is being used by another process" (os error 32). Unix
    /// unlinks an open file quite happily, which is why 29 tests in this
    /// module carried this invisibly for as long as the suite only ever ran
    /// on Linux and macOS. Every product assertion in all of them passed
    /// first - the teardown line was the only thing Windows objected to.
    ///
    /// Beware a SHADOWED index: `let mut ix = ...; let ix = ...;` leaves the
    /// first connection open until the end of the block, so a fixture that
    /// reopens must either scope the first one in an inner block or drop it
    /// by name.
    pub(super) fn teardown(dir: &Path, ix: Index) {
        drop(ix);
        std::fs::remove_dir_all(dir).unwrap();
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

    #[test]
    fn split_subject_conventions() {
        // Canonical (n/m).
        assert_eq!(
            split_subject(r#"x - "f.rar" yEnc (5/50)"#),
            Some((r#"x - "f.rar" yEnc"#.to_string(), 5, 50))
        );
        // Trailing parenthesized tag must not shadow the counter.
        assert_eq!(
            split_subject(r#"x - "f.rar" yEnc (5/50) (German)"#).map(|(_, n, m)| (n, m)),
            Some((5, 50))
        );
        assert_eq!(
            split_subject(r#"x - "f.rar" yEnc (5/50) (4.2 GB)"#).map(|(_, n, m)| (n, m)),
            Some((5, 50))
        );
        // Bracketed and "of" counters.
        assert_eq!(
            split_subject("Release.part01.rar yEnc [1/50]").map(|(_, n, m)| (n, m)),
            Some((1, 50))
        );
        assert_eq!(
            split_subject(r#"x - "f.rar" yEnc (1 of 50)"#).map(|(_, n, m)| (n, m)),
            Some((1, 50))
        );
        // No counter at all.
        assert_eq!(split_subject("just a subject (German)"), None);
    }

    #[test]
    fn quoted_name_conventions() {
        // Quoted, with a decoy quoted run first.
        assert_eq!(
            quoted_name(r#""S01E01" - "Show.part01.rar" yEnc"#),
            Some("Show.part01.rar".to_string())
        );
        // Unquoted convention.
        assert_eq!(
            quoted_name("Release.Name.part01.rar yEnc"),
            Some("Release.Name.part01.rar".to_string())
        );
        assert_eq!(
            quoted_name("Backup.7z.001 yEnc"),
            Some("Backup.7z.001".to_string())
        );
        // Size fragments and version dots are not filenames.
        assert_eq!(quoted_name("Big Release 4.2GB yEnc"), None);
        assert_eq!(quoted_name("Release v1.0 done"), None);
    }

    /// The repost table: remember once, recognise later, and never let a
    /// second download rewrite what the first one taught us.
    #[test]
    fn par_hashes_remember_first_and_recognise_reposts() {
        let dir =
            std::env::temp_dir().join(format!("nzbfast-index-ph-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ix = Index::open(&dir.join("index.db")).unwrap();
        let pairs = |hs: &[&str]| -> Vec<(String, String)> {
            hs.iter().map(|h| ((*h).to_string(), format!("{h}.r00"))).collect()
        };

        // Nothing known yet.
        assert_eq!(ix.par_hash_lookup(&pairs(&["aa", "bb"])).unwrap(), None);

        let named = pairs(&["aa", "bb", "cc"]);
        assert_eq!(
            ix.par_hash_remember(&named, "Example.Movie.2019.1080p-GRP", "m:example movie:2019", 100)
                .unwrap(),
            3
        );
        // A repost whose sidecar shares ONE volume fingerprint is the
        // same bytes, and one hit answers for the whole set.
        assert_eq!(
            ix.par_hash_lookup(&pairs(&["zz", "cc"])).unwrap(),
            Some(("Example.Movie.2019.1080p-GRP".into(), "m:example movie:2019".into()))
        );

        // The obfuscated repost must NOT overwrite the good name: the
        // first writer knew what it was, and every future repost depends
        // on that answer staying put.
        assert_eq!(
            ix.par_hash_remember(&named, "8a7f2c1b9d0e4f", "", 200).unwrap(),
            0,
            "a later download rewrote a fingerprint it did not name"
        );
        assert_eq!(
            ix.par_hash_lookup(&pairs(&["aa"])).unwrap().unwrap().0,
            "Example.Movie.2019.1080p-GRP"
        );

        // A nameless job records nothing at all rather than a blank row
        // that would then shadow the real name forever.
        assert_eq!(ix.par_hash_remember(&pairs(&["dd"]), "  ", "", 300).unwrap(), 0);
        assert_eq!(ix.par_hash_lookup(&pairs(&["dd"])).unwrap(), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `titles.tmdb_id` holds a TMDB movie id on a movie row and a
    /// TVmaze SHOW id on a TV row. Both namespaces are small dense
    /// integers, so a collision is the expected state of a populated
    /// index rather than a corner case - and unfiltered, a Radarr
    /// `t=movie&tmdbid=N` resolved whichever row `LIMIT 1` happened to
    /// reach and could answer a movie search with a TV series.
    #[test]
    fn a_tmdb_lookup_never_crosses_into_the_tv_namespace() {
        let dir =
            std::env::temp_dir().join(format!("nzbfast-index-tmdb-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ix = Index::open(&dir.join("index.db")).unwrap();
        let put = |key: &str, kind: &str, id: i64| {
            ix.db
                .execute(
                    "INSERT INTO titles(key, kind, title, year, tmdb_id)
                     VALUES(?1, ?2, ?3, 0, ?4)",
                    rusqlite::params![key, kind, "x", id],
                )
                .unwrap();
        };
        // The collision: TMDB movie 1399 and TVmaze show 1399 are
        // completely unrelated titles sharing one column.
        put("t:a series", "tv", 1399);
        put("m:a film", "movie", 1399);
        assert_eq!(
            ix.title_key_for_tmdb(1399).unwrap().as_deref(),
            Some("m:a film"),
            "the movie row is the only one a tmdbid may resolve to"
        );

        // An id we hold only a TV row for is NOT a movie we have. The
        // caller turns None into an empty feed; falling through to the
        // TV row would answer a movie search with episodes.
        put("t:another series", "tv", 82856);
        assert_eq!(ix.title_key_for_tmdb(82856).unwrap(), None);

        // A movie-only id still resolves, which is the ordinary case.
        put("m:another film", "movie", 603);
        assert_eq!(
            ix.title_key_for_tmdb(603).unwrap().as_deref(),
            Some("m:another film")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The read-only connection behind the daemon's interactive query
    /// endpoints: it reads what the writer commits WITHOUT being
    /// reopened (WAL - each query is a fresh read transaction), and any
    /// write that sneaks onto it fails instead of contending for the
    /// write lock.
    #[test]
    fn read_only_connection_sees_fresh_commits_and_refuses_writes() {
        let dir =
            std::env::temp_dir().join(format!("nzbfast-index-ro-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("index.db");
        let mut rw = Index::open(&db).unwrap();
        rw.ingest(
            "alt.binaries.test",
            &[entry(r#""First.Release.S01E01.720p-GRP.rar" yEnc (1/1)"#, "p@x", "ro1", 900)],
            1000,
        )
        .unwrap();

        let ro = Index::open_read_only(&db).unwrap();
        assert_eq!(ro.search("first", 10).unwrap().len(), 1);

        // A commit AFTER the read-only open, visible without a reopen.
        rw.ingest(
            "alt.binaries.test",
            &[entry(r#""Second.Release.S01E02.720p-GRP.rar" yEnc (1/1)"#, "p@x", "ro2", 900)],
            1000,
        )
        .unwrap();
        assert_eq!(ro.search("second", 10).unwrap().len(), 1);

        // query_only: the connection refuses writes rather than taking
        // the write lock.
        assert!(ro.kv_set("k", "v").is_err());
        // And it must never be the open that CREATES a database.
        assert!(Index::open_read_only(&dir.join("absent.db")).is_err());
    }

    #[test]
    fn a_movie_year_answers_only_when_unambiguous() {
        let dir =
            std::env::temp_dir().join(format!("nzbfast-index-my-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ix = Index::open(&dir.join("index.db")).unwrap();
        let put = |key: &str, kind: &str, year: u32| {
            ix.db
                .execute(
                    "INSERT INTO titles(key, kind, title, year) VALUES(?1, ?2, ?3, ?4)",
                    rusqlite::params![key, kind, "x", year],
                )
                .unwrap();
        };
        // One title, one year - via the yearless enriched key.
        put("m:example film", "movie", 2019);
        assert_eq!(ix.movie_year("example film").unwrap(), Some(2019));
        // The yeared key spelling answers too.
        put("m:other film:2007", "movie", 2007);
        assert_eq!(ix.movie_year("other film").unwrap(), Some(2007));
        // A remake means two distinct years: refuse to guess.
        put("m:the remake:1982", "movie", 1982);
        put("m:the remake:2011", "movie", 2011);
        assert_eq!(ix.movie_year("the remake").unwrap(), None);
        // Duplicate keys carrying the SAME year stay unambiguous.
        put("m:same year", "movie", 1999);
        put("m:same year:1999", "movie", 1999);
        assert_eq!(ix.movie_year("same year").unwrap(), Some(1999));
        // Unenriched (year 0) and non-movie rows say nothing.
        put("m:unchecked", "movie", 0);
        assert_eq!(ix.movie_year("unchecked").unwrap(), None);
        put("t:show title", "tv", 2020);
        assert_eq!(ix.movie_year("show title").unwrap(), None);
        // A title that PREFIXES another must not inherit its year:
        // "alien" and "aliens" share no key, and the ':'-anchored LIKE
        // keeps "m:alien" from matching "m:aliens" rows... which it
        // cannot anyway, but the guard worth pinning is the space case.
        put("m:alien nation:1988", "movie", 1988);
        assert_eq!(ix.movie_year("alien").unwrap(), None);
        assert_eq!(ix.movie_year("").unwrap(), None);
    }

    #[test]
    fn curation_hides_rules_and_suggestions() {
        let dir =
            std::env::temp_dir().join(format!("nzbfast-index-cur-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut ix = Index::open(&dir.join("index.db")).unwrap();
        let mk = |f: &str, from: &str, id: &str| {
            entry(&format!("\"{f}\" yEnc (1/1)"), from, id, 4 << 30)
        };
        ix.ingest(
            "alt.binaries.test",
            &[
                mk("Inception.2010.1080p.BluRay.x264-GRP.mkv", "a@a", "c1"),
                // Same title, German dub - lang rule must drop only this
                // release, never the whole card.
                mk("Inception.2010.German.1080p.BluRay.x264-DEU.mkv", "b@b", "c2"),
                mk("Der.Film.2019.German.1080p.WEB.x264-DEU.mkv", "c@c", "c3"),
                mk("Anderes.Werk.2021.German.720p.WEB.x264-DEU.mkv", "d@d", "c4"),
                mk("Drittes.Ding.2022.German.2160p.WEB.x265-DEU.mkv", "e@e", "c5"),
                mk("WWE.Raw.2026.03.01.720p.HDTV.x264-GRP.mkv", "f@f", "c6"),
            ],
            1_000,
        )
        .unwrap();
        let cur = BrowseQuery { curated: true, ..Default::default() };
        let (_, base_total) = ix.browse(&cur).unwrap();
        assert_eq!(base_total, 6);

        // "Not interested" on one title.
        let key = crate::release::parse_release("Der.Film.2019.German.1080p.WEB.x264-DEU").key;
        ix.hide_title(&key).unwrap();
        let (_, total) = ix.browse(&cur).unwrap();
        assert_eq!(total, 5, "hidden title's releases drop out");
        // Uncurated paths (newznab, *arrs) are untouched.
        let (_, raw) = ix.browse(&BrowseQuery::default()).unwrap();
        assert_eq!(raw, 6);
        let hid = ix.hidden_titles().unwrap();
        assert_eq!(hid.len(), 1);
        assert_eq!(hid[0].key, key);

        // Language rule: German releases vanish, but Inception keeps its
        // card via the English encode.
        ix.rule_add("lang", "german", false).unwrap();
        let (rows, total) = ix.browse(&cur).unwrap();
        assert_eq!(total, 2, "{rows:?}"); // english Inception + WWE
        let (cards, _) = ix
            .browse_cards(&cur, CardSort::Latest, false, false, None)
            .unwrap();
        assert!(
            cards.iter().any(|c| c.title_key.starts_with("m:inception")),
            "mixed-language card survives: {cards:?}"
        );
        assert!(cards.iter().all(|c| !c.title_key.contains("anderes")), "{cards:?}");

        // Word rule via FTS: exact token, not substring.
        ix.rule_add("word", "wwe", false).unwrap();
        let (rows, total) = ix.browse(&cur).unwrap();
        assert_eq!(total, 1, "{rows:?}");
        assert!(rows[0].stem.contains("Inception"), "{rows:?}");

        // Rule management round-trip.
        let rules = ix.rules_list().unwrap();
        assert_eq!(rules.len(), 2);
        ix.rule_delete(rules.iter().find(|r| r.field == "word").unwrap().id).unwrap();
        let (_, total) = ix.browse(&cur).unwrap();
        assert_eq!(total, 2);

        // Suggestions: three hidden German-tagged titles → lang rule
        // suggestion (drop the rule first so it isn't "taken").
        ix.rule_delete(ix.rules_list().unwrap()[0].id).unwrap();
        for stem in [
            "Anderes.Werk.2021.German.720p.WEB.x264-DEU",
            "Drittes.Ding.2022.German.2160p.WEB.x265-DEU",
        ] {
            ix.hide_title(&crate::release::parse_release(stem).key).unwrap();
        }
        let sug = ix.hide_suggestions().unwrap();
        assert!(
            sug.iter().any(|s| s.field == "lang" && s.value == "german" && s.n == 3),
            "{sug:?}"
        );
        // Dismissed → never again.
        ix.suggestion_dismiss("lang", "german").unwrap();
        assert!(
            ix.hide_suggestions().unwrap().iter().all(|s| s.value != "german"),
            "dismissed suggestion must not return"
        );
        // Accepting a rule clears the dismissal and takes effect.
        ix.rule_add("lang", "german", true).unwrap();
        let (_, total) = ix.browse(&cur).unwrap();
        assert_eq!(total, 2);
        // Unhide restores.
        ix.unhide_title(&key).unwrap();
        let (_, total) = ix.browse(&cur).unwrap();
        assert_eq!(total, 2, "unhidden title's German release stays rule-hidden");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A cross-posted release must not disappear from the list because
    /// the copy the dedupe picks to represent it is the copy a filter
    /// hides. The other copy is right there and passes.
    #[test]
    fn a_filtered_copy_does_not_take_the_whole_release_with_it() {
        let dir =
            std::env::temp_dir().join(format!("nzbfast-index-rep-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut ix = Index::open(&dir.join("index.db")).unwrap();
        let mk = |f: &str, id: &str, bytes: u64| {
            entry(&format!("\"{f}\" yEnc (1/1)"), "a@a", id, bytes)
        };
        // ONE release, cross-posted to two groups. The moovee copy is the
        // fatter one, so it is the copy the representative pick takes.
        let dune = "Dune.Part.Two.2024.1080p.BluRay.x264-GRP.mkv";
        ix.ingest("alt.binaries.moovee", &[mk(dune, "d1", 8 << 30)], 1_000).unwrap();
        ix.ingest("alt.binaries.teevee", &[mk(dune, "d2", 4 << 30)], 1_000).unwrap();
        // ...and a release only the hidden group carries, so the test can
        // tell "the filter works" from "the filter eats everything".
        ix.ingest(
            "alt.binaries.moovee",
            &[mk("Other.Film.2023.1080p.BluRay.x264-GRP.mkv", "o1", 8 << 30)],
            1_000,
        )
        .unwrap();

        let cur = BrowseQuery { curated: true, ..Default::default() };
        let (rows, total) = ix.browse(&cur).unwrap();
        assert_eq!(total, 2, "the two copies collapse onto one row: {rows:?}");

        // Hide the group the representative copy lives in.
        ix.rule_add("group", "alt.binaries.moovee", false).unwrap();
        let (rows, total) = ix.browse(&cur).unwrap();
        let kept: Vec<&Release> = rows.iter().filter(|r| r.stem.starts_with("Dune")).collect();
        assert_eq!(kept.len(), 1, "the cross-posted release keeps its allowed copy: {rows:?}");
        assert_eq!(kept[0].grp, "alt.binaries.teevee", "and it is that copy: {rows:?}");
        // The rule still rules: a release the hidden group alone carries
        // stays gone, and the count agrees with the page.
        assert!(
            !rows.iter().any(|r| r.stem.starts_with("Other")),
            "a release only the hidden group carries must stay hidden: {rows:?}"
        );
        assert_eq!(total, 1, "{rows:?}");
        assert_eq!(rows.len() as u64, total, "page and total must count the same: {rows:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn browse_verdict_ok_is_a_sql_predicate() {
        // M29 3c: verdict=ok must filter in SQL so `total` and the page
        // agree - the old page-level trim left `total` unfiltered, which
        // broke paging.
        let dir =
            std::env::temp_dir().join(format!("nzbfast-index-verdict-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut ix = Index::open(&dir.join("index.db")).unwrap();
        let mk = |f: &str, id: &str| entry(&format!("\"{f}\" yEnc (1/1)"), "a@a", id, 4 << 30);

        // Two fresh releases (→ age bucket 1) and one ancient (→ bucket 6),
        // all in the teevee family. first_posted = the ingest `now`.
        let base: i64 = 1_700_000_000;
        let now = base + 3 * 86_400; // verdict "now": fresh pair is 3d old
        ix.ingest(
            "alt.binaries.teevee",
            &[mk("Fresh.Show.S01E01.1080p-A.mkv", "f1"), mk("Fresh.Show.S01E02.1080p-A.mkv", "f2")],
            base,
        )
        .unwrap();
        ix.ingest(
            "alt.binaries.teevee",
            &[mk("Ancient.Show.S01E01.1080p-A.mkv", "o1")],
            base - 2_000 * 86_400, // ~5.5y old at `now` → bucket 6
        )
        .unwrap();

        // Ledger: omicron is confidently green for teevee/bucket-1, and
        // has nothing at bucket 6 (so the ancient release is verdict None).
        ix.oracle_ingest(
            &[crate::oracle::Sample {
                host: "news.eweka.nl".into(), // → omicron
                family: "teevee".into(),
                bucket: 1,
                hits: 200,
                misses: 0,
            }],
            now,
        )
        .unwrap();
        let snap = ix.oracle_snapshot().unwrap();
        let filt = |bbs: &[&str]| VerdictFilter {
            snap: snap.clone(),
            backbones: bbs.iter().map(|s| s.to_string()).collect(),
            now,
        };

        // Baseline: all three visible.
        let (_, total_all) = ix.browse(&BrowseQuery::default()).unwrap();
        assert_eq!(total_all, 3);

        // verdict=ok on omicron: only the two fresh (green) releases, and
        // `total` reflects the filter - not the unfiltered 3.
        let q = BrowseQuery { verdict_ok: Some(filt(&["omicron"])), ..Default::default() };
        let (rows, total) = ix.browse(&q).unwrap();
        assert_eq!(total, 2, "total counts only ok rows");
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|r| r.stem.starts_with("Fresh")), "{rows:?}");

        // Paging over the filtered set: page size 1 walks the 2 ok rows,
        // never the ancient one, and `total` stays 2 on every page.
        let mut seen = std::collections::HashSet::new();
        for off in 0..2 {
            let q = BrowseQuery {
                verdict_ok: Some(filt(&["omicron"])),
                limit: 1,
                offset: off,
                ..Default::default()
            };
            let (rows, total) = ix.browse(&q).unwrap();
            assert_eq!(total, 2, "total stable across pages");
            assert_eq!(rows.len(), 1);
            assert!(rows[0].stem.starts_with("Fresh"), "page {off}: {rows:?}");
            seen.insert(rows[0].stem.clone());
        }
        assert_eq!(seen.len(), 2, "both ok rows reachable by paging");

        // No enabled backbones → verdict null for all → nothing is "ok".
        let q = BrowseQuery { verdict_ok: Some(filt(&[])), ..Default::default() };
        let (rows, total) = ix.browse(&q).unwrap();
        assert_eq!(total, 0);
        assert!(rows.is_empty());

        // A subsequent plain browse (no verdict filter) must be unaffected
        // by the per-request function registration/removal.
        let (_, total_all) = ix.browse(&BrowseQuery::default()).unwrap();
        assert_eq!(total_all, 3);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn browse_verdict_ok_treats_undated_as_unknown() {
        // A release with no post date (first_posted <= 0) has UNKNOWN age -
        // it must not be read out of the "ancient" (bucket 6) cell the raw
        // `(now-0)/86400` math would land in. Even with that cell green, an
        // undated release must be excluded from verdict=ok.
        let dir =
            std::env::temp_dir().join(format!("nzbfast-index-undated-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut ix = Index::open(&dir.join("index.db")).unwrap();
        let mk = |f: &str, id: &str| entry(&format!("\"{f}\" yEnc (1/1)"), "a@a", id, 4 << 30);
        // Ingest with now=0 and undated articles → first_posted = 0.
        ix.ingest("alt.binaries.teevee", &[mk("Undated.Show.S01E01-A.mkv", "u1")], 0)
            .unwrap();
        // Ledger: teevee is confidently GREEN in bucket 6 (3y+) - exactly
        // the bucket the pre-fix `(now-0)/86400` misread would target.
        ix.oracle_ingest(
            &[crate::oracle::Sample {
                host: "news.eweka.nl".into(), // omicron
                family: "teevee".into(),
                bucket: 6,
                hits: 200,
                misses: 0,
            }],
            1_700_000_000,
        )
        .unwrap();
        let snap = ix.oracle_snapshot().unwrap();
        let q = BrowseQuery {
            verdict_ok: Some(VerdictFilter {
                snap,
                backbones: vec!["omicron".into()],
                now: 1_700_000_000,
            }),
            ..Default::default()
        };
        let (rows, total) = ix.browse(&q).unwrap();
        assert_eq!(total, 0, "undated release must not be verdict=ok: {rows:?}");
        assert!(rows.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The to-the-day release-date sort: dated cards order by their full
    /// date, and a card with only a year sits below every dated card in
    /// that same year rather than sinking to the bottom of the wall.
    #[test]
    fn cards_aired_sort_orders_by_day_then_falls_back_to_year() {
        let dir =
            std::env::temp_dir().join(format!("nzbfast-index-aired-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut ix = Index::open(&dir.join("index.db")).unwrap();
        let mk = |f: &str, from: &str, id: &str| {
            entry(&format!("\"{f}\" yEnc (1/1)"), from, id, 4 << 30)
        };
        ix.ingest(
            "alt.binaries.test",
            &[
                mk("Undated.Film.2026.1080p.WEB.x264-GRP.mkv", "a@a", "g1"),
                mk("July.Film.2026.1080p.WEB.x264-GRP.mkv", "b@b", "g2"),
                mk("January.Film.2026.1080p.WEB.x264-GRP.mkv", "c@c", "g3"),
                mk("Ancient.Film.1994.1080p.BluRay.x264-GRP.mkv", "d@d", "g4"),
            ],
            1_000,
        )
        .unwrap();
        for (key, title, date) in [
            ("m:july film:2026", "July Film", "2026-07-20"),
            ("m:january film:2026", "January Film", "2026-01-05"),
        ] {
            ix.title_seed(key, "movie", title, 2026).unwrap();
            ix.title_fill(key, &TitleFill { air_date: date, ..Default::default() }, 1)
                .unwrap();
        }
        let q = BrowseQuery { desc: true, ..Default::default() };
        let (cards, _) = ix.browse_cards(&q, CardSort::Aired, false, false, None).unwrap();
        let keys: Vec<&str> = cards.iter().map(|c| c.title_key.as_str()).collect();
        assert_eq!(
            keys,
            [
                "m:july film:2026",
                "m:january film:2026",
                "m:undated film:2026",
                "m:ancient film:1994",
            ],
            "{cards:?}"
        );
        // The date rides along on the card so the UI can show it.
        assert_eq!(cards[0].air_date, "2026-07-20");
        assert!(cards[2].air_date.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cards_group_by_kind_year_sort_and_genre_filter() {
        let dir =
            std::env::temp_dir().join(format!("nzbfast-index-grp-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut ix = Index::open(&dir.join("index.db")).unwrap();
        let mk = |f: &str, from: &str, id: &str| {
            entry(&format!("\"{f}\" yEnc (1/1)"), from, id, 4 << 30)
        };
        ix.ingest(
            "alt.binaries.test",
            &[
                mk("Old.Film.1994.1080p.BluRay.x264-GRP.mkv", "a@a", "g1"),
                mk("New.Film.2026.1080p.WEB.x264-GRP.mkv", "b@b", "g2"),
                mk("Some.Show.S01E01.1080p.WEB.x264-GRP.mkv", "c@c", "g3"),
            ],
            1_000,
        )
        .unwrap();
        // Grouped: TV cluster leads, movies follow; Year sub-sort puts
        // the newer film first inside its cluster (parse-key fallback -
        // nothing is enriched here).
        let q = BrowseQuery { desc: true, ..Default::default() };
        let (cards, _) = ix.browse_cards(&q, CardSort::Year, false, true, None).unwrap();
        let kinds: Vec<&str> = cards.iter().map(|c| c.kind.as_str()).collect();
        assert_eq!(kinds, ["tv", "movie", "movie"], "{cards:?}");
        assert!(cards[1].title_key.contains("2026"), "{cards:?}");
        assert!(cards[2].title_key.contains("1994"), "{cards:?}");
        // Genre filter: nothing enriched → everything drops out.
        let gq = BrowseQuery { genre: Some("Drama".into()), ..Default::default() };
        let (_, total) = ix.browse_cards(&gq, CardSort::Latest, false, false, None).unwrap();
        assert_eq!(total, 0);
        // Enrich one row with a genre and it comes back.
        ix.title_seed("m:new film:2026", "movie", "New Film", 2026).unwrap();
        ix.db
            .execute(
                "UPDATE titles SET genres='Drama, Thriller', checked=1
                 WHERE key='m:new film:2026'",
                [],
            )
            .unwrap();
        let (cards, total) = ix.browse_cards(&gq, CardSort::Latest, false, false, None).unwrap();
        assert_eq!(total, 1, "{cards:?}");
        assert_eq!(cards[0].title_key, "m:new film:2026");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn affinity_ranks_favoured_genre_and_sinks_owned() {
        let dir =
            std::env::temp_dir().join(format!("nzbfast-index-aff-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut ix = Index::open(&dir.join("index.db")).unwrap();
        let mk = |f: &str, from: &str, id: &str| {
            entry(&format!("\"{f}\" yEnc (1/1)"), from, id, 4 << 30)
        };
        ix.ingest(
            "alt.binaries.test",
            &[
                mk("Drama One.2020.1080p.WEB.x264-GRP.mkv", "a@a", "a1"),
                mk("Drama Two.2019.1080p.WEB.x264-GRP.mkv", "b@b", "a2"),
                mk("Comedy Pick.2021.1080p.WEB.x264-GRP.mkv", "c@c", "a3"),
            ],
            1_000,
        )
        .unwrap();
        // Enrich all three with genres so the affinity join has data.
        for (key, genres) in [
            ("m:drama one:2020", "Drama, Thriller"),
            ("m:drama two:2019", "Drama"),
            ("m:comedy pick:2021", "Comedy"),
        ] {
            ix.title_seed(key, "movie", "T", 2020).unwrap();
            ix.db
                .execute(
                    "UPDATE titles SET genres=?2, checked=1 WHERE key=?1",
                    rusqlite::params![key, genres],
                )
                .unwrap();
        }
        // Taste skewed hard to Drama; user already owns "Drama One".
        let mut owned = std::collections::HashSet::new();
        owned.insert("m:drama one:2020".to_string());
        let aff = AffinityCtx {
            genres: vec![("Drama".into(), 10.0)],
            fav_kind: Some(("movie".into(), 2.0)),
            decade_center: None,
            decade_weight: 1.0,
            owned,
        };
        let q = BrowseQuery { desc: true, ..Default::default() };
        let (cards, _) =
            ix.browse_cards(&q, CardSort::Affinity, false, false, Some(&aff)).unwrap();
        let order: Vec<&str> = cards.iter().map(|c| c.title_key.as_str()).collect();
        // Drama (unowned) leads; Comedy in the middle; owned Drama sinks last.
        assert_eq!(
            order,
            ["m:drama two:2019", "m:comedy pick:2021", "m:drama one:2020"],
            "{cards:?}"
        );
        // Cold start (no profile) → Affinity degrades to Releases order,
        // still returning every card rather than erroring.
        let (cards, total) =
            ix.browse_cards(&q, CardSort::Affinity, false, false, None).unwrap();
        assert_eq!(total, 3, "{cards:?}");
        assert_eq!(cards.len(), 3);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn retention_prune_reaps_old_spares_recent_hidden_and_undated() {
        let dir =
            std::env::temp_dir().join(format!("nzbfast-index-ret-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut ix = Index::open(&dir.join("index.db")).unwrap();
        const DAY: i64 = 86_400;
        let now = 1_000 * DAY;
        // now: full-size rows at various ages + one undated + one hidden.
        let mut old = entry("\"Ancient.Movie.2001.1080p.mkv\" yEnc (1/1)", "p@x", "r1", 4 << 30);
        old.date = now - 800 * DAY;
        let mut recent = entry("\"Fresh.Movie.2026.1080p.mkv\" yEnc (1/1)", "p@x", "r2", 4 << 30);
        recent.date = now - 10 * DAY;
        let mut hidden = entry("\"Hidden.Movie.2000.1080p.mkv\" yEnc (1/1)", "p@x", "r3", 4 << 30);
        hidden.date = now - 900 * DAY;
        let undated = entry("\"Undated.Movie.2010.1080p.mkv\" yEnc (1/1)", "p@x", "r4", 4 << 30);
        ix.ingest("alt.test", &[old, recent, hidden, undated], now).unwrap();
        ix.hide_title(&crate::release::parse_release("Hidden.Movie.2000.1080p").key).unwrap();

        // Keep 2 years (~730 days): the 800/900-day rows are candidates,
        // but the 900-day one is hidden and must survive.
        let removed = ix.prune_age(730 * DAY, now).unwrap();
        assert_eq!(removed, 1, "only the old non-hidden row");
        assert_eq!(ix.search("ancient", 10).unwrap().len(), 0, "old reaped");
        assert_eq!(ix.search("fresh", 10).unwrap().len(), 1, "recent kept");
        assert_eq!(ix.search("hidden movie", 10).unwrap().len(), 1, "hidden kept");
        assert_eq!(ix.search("undated", 10).unwrap().len(), 1, "unknown-date kept");
        // FTS index stayed in sync (rowid count == releases count) and no
        // orphan files rows survived the batch delete.
        let (rels, _) = ix.stats().unwrap();
        let fts_rows: i64 = ix
            .db
            .query_row("SELECT COUNT(*) FROM rel_fts", [], |r| r.get(0))
            .unwrap();
        assert_eq!(fts_rows as u64, rels, "FTS in sync");
        let orphans: i64 = ix
            .db
            .query_row(
                "SELECT COUNT(*) FROM files WHERE release_id NOT IN (SELECT id FROM releases)",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(orphans, 0, "no orphan files rows");
        teardown(&dir, ix);
    }

    #[test]
    fn stale_partials_reaps_dead_junk_spares_wall_and_settle() {
        let dir =
            std::env::temp_dir().join(format!("nzbfast-index-stale-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut ix = Index::open(&dir.join("index.db")).unwrap();
        const DAY: i64 = 86_400;
        let now = 1_000 * DAY;
        // Obfuscated hash name -> junk>=50, missing parts, OLD -> dead, reaped.
        let mut dead =
            entry("\"ugpoqs3l6bthdkgbn1ktwkl2wwxju8.part1.rar\" yEnc (1/9)", "p@x", "s1", 750_000);
        dead.date = now - 30 * DAY;
        // Same junk shape and an OLD POST, but only just indexed (mid-backfill
        // into history): first_seen is recent, so the reaper must spare it - the
        // settle clock is index age, not post age. (The old code reaped this.)
        let mut fresh =
            entry("\"zzq9x2m7v5t8k1n3b6h4j0w2e5r7y9.part1.rar\" yEnc (1/9)", "p@x", "s2", 750_000);
        fresh.date = now - 30 * DAY;
        // Wall-visible (parses clean, junk<50), missing parts, OLD -> the
        // always-on reaper must NOT touch it (opt-in age prune's job).
        let mut real =
            entry("\"Real.Show.S01E01.720p.WEB.x264-GRP.mkv\" yEnc (1/9)", "p@x", "s3", 400 << 20);
        real.date = now - 30 * DAY;
        // Junk + COMPLETE + old -> not this reaper (spares complete blobs).
        let mut donejunk =
            entry("\"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3.mkv\" yEnc (1/1)", "p@x", "s4", 750_000);
        donejunk.date = now - 30 * DAY;
        // dead/real/donejunk were indexed long ago (first_seen old); `fresh`
        // is indexed now, so its settle window has not elapsed.
        ix.ingest("alt.test", &[dead, real, donejunk], now - 30 * DAY).unwrap();
        ix.ingest("alt.test", &[fresh], now).unwrap();

        let removed = ix.prune_stale_partials(7 * DAY, now).unwrap();
        assert_eq!(removed, 1, "only the old junk missing-parts row");
        assert_eq!(ix.search("ugpoqs3l6bthdkgbn1ktwkl2wwxju8", 10).unwrap().len(), 0, "dead junk reaped");
        assert_eq!(ix.search("zzq9x2m7v5t8k1n3b6h4j0w2e5r7y9", 10).unwrap().len(), 1, "in settle window");
        assert_eq!(ix.search("real show", 10).unwrap().len(), 1, "wall-visible spared");
        assert_eq!(ix.search("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3", 10).unwrap().len(), 1, "complete junk spared");
        teardown(&dir, ix);
    }

    #[test]
    fn junk_v6_evidence_free_media_and_lecture_dumps() {
        let score = |stem: &str, bytes: u64| {
            let p = crate::release::parse_release(stem);
            junk_score(stem, &p, bytes, false)
        };
        // Course/lecture dumps (real leaks from a live teevee+moovee
        // index): numbered tracks and bare-words media files.
        assert!(score("003 - Estômago.mp4", 100 << 20) >= 50);
        assert!(score("056 - Ortografia II.mp4", 200 << 20) >= 50);
        assert!(score("aula.mp4", 700 << 20) >= 50);
        assert!(score("Configurando Dsers.mp4", 80 << 20) >= 50);
        assert!(score("misfits-wegedeutschensd", 100 << 20) >= 50);
        // Track prefix wins even when a year parses further in.
        assert!(score("065 - Estatística RLM 2019.mp4", 400 << 20) >= 50);
        // Bracket-hex repost spam - inner name parses real, still junk.
        assert!(score("[3b9550c02c]_[newzNZB]_atlanta.s01e10.1080p.hdtv.x264-xpert", 50 << 20) >= 50);
        // Anime subgroup brackets are words, not hex - clean.
        assert!(score("[SubsPlease] Frieren - S01E01 (1080p) [ABCD1234]", 1 << 30) < 50);
        // Real releases with any single marker survive.
        assert!(score("Some.Documentary.2020.mp4", 2 << 30) < 50);
        assert!(score("slings.and.arrows.s01e03.proper.dvdrip.xvid-nodlabs", 300 << 20) < 50);
        assert!(score("Robin.Hood.2010.Theatrical.Cut.BluRay.1080p.DTS-X.7.1.AVC.HYBRID.REMUX-FraMeSToR.mkv", 33 << 30) < 50);
        // "24.S01E01" style: leading digits but a parsed episode - clean.
        assert!(score("24.S01E01.1080p.WEB.h264-GRP", 2 << 30) < 50);
        // Evidence-free software-ish name is hidden by the same rule.
        assert!(score("Topaz Video AI Pro 8.1.6", 500 << 20) >= 50);
        // Sub-200 MB "HD movie" posts are fakes; a real small movie
        // without an HD claim (old SD rip) survives, and TV stays
        // exempt (short-form episodes are legitimately tiny).
        assert!(score("Dont.Breathe.2016.1080p.WEB-DL.DD5.1.H264-FGT", 180 << 20) >= 50);
        assert!(score("Old.Short.Film.1962.DVDRip.XviD-GRP", 180 << 20) < 50);
        assert!(score("some.show.s01e04.720p.hdtv.x264-grp", 150 << 20) < 50);
    }

    #[test]
    fn executable_content_junks_media_releases() {
        // M32 (Prowlarr#2329): an .exe inside a movie/TV-shaped release is
        // flagged past the default-hide line; Software releases keep their
        // normal score (executables are their content).
        let dir =
            std::env::temp_dir().join(format!("nzbfast-index-exe-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut ix = Index::open(&dir.join("index.db")).unwrap();
        let mk = |f: &str, from: &str, id: &str| {
            entry(&format!("\"{f}\" yEnc (1/1)"), from, id, 4 << 30)
        };
        ix.ingest(
            "alt.binaries.test",
            &[
                mk("Some.Movie.2026.1080p.BluRay.x264-GRP.exe", "a@a", "x1"),
                mk("Clean.Movie.2026.1080p.BluRay.x264-GRP.mkv", "b@b", "x2"),
            ],
            1_000,
        )
        .unwrap();
        // Both rows exist, but the junk ceiling hides the exe-carrying one.
        let (_, total_all) = ix.browse(&BrowseQuery::default()).unwrap();
        assert_eq!(total_all, 2);
        let (rows, total) =
            ix.browse(&BrowseQuery { max_junk: Some(50), ..Default::default() }).unwrap();
        assert_eq!(total, 1, "exe-carrying movie must be junk-hidden: {rows:?}");
        assert!(rows[0].stem.contains("Clean.Movie"), "{rows:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sample_token_only_junks_sample_sized_posts() {
        // M32: a full-size release with "sample"
        // in its TITLE is not furniture; a tens-of-MB one is.
        let dir =
            std::env::temp_dir().join(format!("nzbfast-index-smp-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut ix = Index::open(&dir.join("index.db")).unwrap();
        ix.ingest(
            "alt.binaries.test",
            &[
                entry(
                    "\"The.Free.Sample.2026.1080p.BluRay.x264-GRP.mkv\" yEnc (1/1)",
                    "a@a",
                    "s1",
                    4 << 30,
                ),
                entry(
                    "\"Other.Movie.2026.1080p-GRP.sample.mkv\" yEnc (1/1)",
                    "b@b",
                    "s2",
                    60 << 20,
                ),
            ],
            1_000,
        )
        .unwrap();
        let (rows, total) =
            ix.browse(&BrowseQuery { max_junk: Some(50), ..Default::default() }).unwrap();
        assert_eq!(total, 1, "only the real sample is hidden: {rows:?}");
        assert!(rows[0].stem.contains("Free.Sample"), "{rows:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn people_identity_credits_and_the_search_leg() {
        let dir =
            std::env::temp_dir().join(format!("nzbfast-index-people-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut ix = Index::open(&dir.join("index.db")).unwrap();
        assert!(ix.people_fts, "bundled sqlite is expected to ship FTS5");
        let mk = |f: &str, from: &str, id: &str| {
            entry(&format!("\"{f}\" yEnc (1/1)"), from, id, 4 << 30)
        };
        ix.ingest(
            "alt.binaries.test",
            &[
                mk("Top.Gun.Maverick.2022.1080p.BluRay.x264-GRP.mkv", "a@a", "t1"),
                mk("Mission.Impossible.1996.1080p.BluRay.x264-GRP.mkv", "b@b", "m1"),
                mk("Breaking.Bad.S01E01.720p.WEB.x264-GRP.mkv", "c@c", "b1"),
            ],
            1_000,
        )
        .unwrap();
        let key = |s: &str| {
            ix.browse_cards(&BrowseQuery::default(), CardSort::Latest, false, false, None)
                .unwrap()
                .0
                .into_iter()
                .find(|c| c.title_key.contains(s))
                .unwrap_or_else(|| panic!("no card for {s}"))
                .title_key
        };
        let (tg, mi, bb) = (key("maverick"), key("mission"), key("breaking"));
        for (k, kind, title, year) in [
            (&tg, "movie", "Top Gun Maverick", 2022),
            (&mi, "movie", "Mission Impossible", 1996),
            (&bb, "tv", "Breaking Bad", 0),
        ] {
            ix.title_seed(k, kind, title, year).unwrap();
            ix.title_fill(k, &TitleFill { tmdb_id: 1, ..Default::default() }, 5).unwrap();
        }

        // A person seen first by Wikidata and later by TVmaze is ONE
        // person: the second provider fills the handle the first lacked
        // rather than forking the row.
        let cruise_wd = Credit {
            name: "Tom Cruise".into(),
            role: "actor".into(),
            character: "Maverick".into(),
            ord: 1,
            wikidata_qid: "Q37079".into(),
            ..Default::default()
        };
        ix.title_credits_set(&tg, &[cruise_wd.clone()]).unwrap();
        ix.title_credits_set(
            &mi,
            &[Credit {
                name: "Tom Cruise".into(),
                role: "actor".into(),
                character: "Ethan Hunt".into(),
                ord: 1,
                tvmaze_id: 555,
                photo: "https://example.invalid/tc.jpg".into(),
                ..Default::default()
            }],
        )
        .unwrap();
        let n_people: i64 =
            ix.db.query_row("SELECT COUNT(*) FROM people", [], |r| r.get(0)).unwrap();
        assert_eq!(n_people, 1, "one person, two providers");
        let p = ix.people_search("tom cru", 5).unwrap();
        assert_eq!(p.len(), 1, "prefix name search: {p:?}");
        assert_eq!((p[0].name.as_str(), p[0].n_titles), ("Tom Cruise", 2));
        let pid = p[0].id;
        let row = ix.person_get(pid).unwrap().unwrap();
        assert_eq!((row.tvmaze_id, row.wikidata_qid.as_str()), (555, "Q37079"),
                   "both handles landed on the one row");

        // The person page's in-index half, newest release first.
        let mine = ix.person_titles(pid).unwrap();
        assert_eq!(mine.len(), 2);
        assert_eq!(mine[0].title, "Top Gun Maverick", "ordered by release date: {mine:?}");
        assert_eq!(mine[0].character, "Maverick");

        // The search leg: "tom cruise" appears in no stem at all, so
        // before this it matched nothing.
        let found = |q: &str| {
            ix.browse_cards(
                &BrowseQuery { q: q.into(), max_junk: Some(50), curated: true, ..Default::default() },
                CardSort::Latest,
                false,
                false,
                None,
            )
            .unwrap()
            .1
        };
        assert_eq!(found("tom cruise"), 2, "the people leg found no titles");
        // …and it is an OR, so stem search is untouched.
        assert_eq!(found("maverick"), 1);
        assert_eq!(found("nobody at all"), 0);

        // Curation is not optional on person surfaces: hiding a title
        // must remove it from the person page and from the search leg,
        // or a cast chip is a way back into what the user just hid.
        ix.hide_title(&tg).unwrap();
        assert_eq!(ix.person_titles(pid).unwrap().len(), 1, "hidden title still listed");
        assert_eq!(found("tom cruise"), 1, "hidden title still searchable by cast");
        assert_eq!(ix.people_search("tom cru", 5).unwrap()[0].n_titles, 1);
        ix.unhide_title(&tg).unwrap();

        // A DIFFERENT person who happens to share the name must not be
        // absorbed once either side carries a handle.
        ix.title_credits_set(
            &bb,
            &[Credit {
                name: "Tom Cruise".into(),
                role: "actor".into(),
                tvmaze_id: 999,
                ..Default::default()
            }],
        )
        .unwrap();
        let n_people: i64 =
            ix.db.query_row("SELECT COUNT(*) FROM people", [], |r| r.get(0)).unwrap();
        assert_eq!(n_people, 2, "a conflicting handle forks, it does not merge");
        // They stay separate people with separate filmographies, but a
        // name search legitimately matches both - the searcher typed a
        // name, not an identity.
        assert_eq!(ix.person_titles(pid).unwrap().len(), 2, "the fork stole a credit");
        assert_eq!(found("tom cruise"), 3);

        // Re-enrichment replaces the whole set rather than accumulating
        // credits the provider no longer believes in.
        ix.title_credits_set(&tg, &[cruise_wd]).unwrap();
        assert_eq!(ix.title_credits(&tg, 40).unwrap().len(), 1);

        // A merged card keeps its credits.
        ix.merge_title(&mi, &tg).unwrap();
        assert!(ix.person_titles(pid).unwrap().iter().any(|t| t.key == tg));
        assert_eq!(
            ix.db
                .query_row("SELECT COUNT(*) FROM title_people WHERE key=?1", [&mi], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            0,
            "the merged-away key still holds credits"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn fts_search_cards_and_junk() {
        let dir = std::env::temp_dir().join(format!("nzbfast-index-m28-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut ix = Index::open(&dir.join("index.db")).unwrap();
        assert!(ix.fts, "bundled sqlite is expected to ship FTS5");

        let mk = |f: &str, from: &str, id: &str| {
            entry(&format!("\"{f}\" yEnc (1/1)"), from, id, 4 << 30)
        };
        ix.ingest(
            "alt.binaries.test",
            &[
                // Same movie from two posters → one card, two releases.
                mk("Inception.2010.1080p.BluRay.x264-GRP.mkv", "a@a", "i1"),
                mk("Inception.2010.2160p.WEB.x265-OTHER.mkv", "b@b", "i2"),
                mk("Breaking.Bad.S01E01.720p.WEB.x264-GRP.mkv", "c@c", "b1"),
                // Obfuscated hash stem → junk >= 50, hidden by default.
                mk("0a1b2c3d4e5f60718293a4b5.mkv", "d@d", "j1"),
            ],
            1_000,
        )
        .unwrap();

        // FTS prefix search, separator-insensitive both ways.
        assert_eq!(ix.search("inception", 10).unwrap().len(), 2);
        assert_eq!(ix.search("breaking bad s01", 10).unwrap().len(), 1);
        assert_eq!(ix.search("nosuchthing", 10).unwrap().len(), 0);

        // Browse with the junk ceiling: the hash stem drops out.
        let q = BrowseQuery { max_junk: Some(50), ..Default::default() };
        let (rows, total) = ix.browse(&q).unwrap();
        assert_eq!(total, 3, "junk hidden: {rows:?}");
        let (_, total_all) = ix.browse(&BrowseQuery::default()).unwrap();
        assert_eq!(total_all, 4);

        // Cards: inception's two posters group under one key.
        let (cards, ctotal) = ix
            .browse_cards(&BrowseQuery { max_junk: Some(50), ..Default::default() }, CardSort::Latest, false, false, None)
            .unwrap();
        assert_eq!(ctotal, 2, "cards: {cards:?}");
        let inception = cards.iter().find(|c| c.title_key.starts_with("m:inception")).unwrap();
        assert_eq!(inception.n_releases, 2);
        assert_eq!(inception.best_res, "2160p");
        assert_eq!(inception.kind, "movie");
        // Card-scoped browse (detail sheet) sees both copies.
        let (rows, n) = ix
            .browse(&BrowseQuery {
                title_key: Some(inception.title_key.clone()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!((rows.len(), n), (2, 2));

        // FTS query text is filtered per-term.
        let (_, n) = ix
            .browse(&BrowseQuery { q: "inception \"2010".into(), ..Default::default() })
            .unwrap();
        assert_eq!(n, 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `entry()` hardcodes date=0 and its 4th argument is BYTES, so it
    /// cannot express "posted at time T" - and a tiny payload scores as
    /// junk (55), which the wall hides. This one sets a real Date and a
    /// plausible size.
    fn dated_entry(subject: &str, id: &str, posted: i64) -> OverEntry {
        OverEntry {
            number: 0,
            subject: subject.into(),
            from: "poster@example".into(),
            message_id: format!("<{id}>"),
            bytes: 4_000_000_000,
            date: posted,
        }
    }

    /// The property the arrivals pill depends on and that the default
    /// sort does NOT give it: the thing we saw most recently comes
    /// first, even when something else was POSTED more recently. These
    /// two orders really do disagree - a release is posted-dated by its
    /// first article, so a set that only finishes arriving now can be
    /// hours old.
    #[test]
    fn arrived_sort_orders_by_when_we_saw_it_not_when_it_was_posted() {
        let dir = std::env::temp_dir().join(format!("nzbfast-arrsort-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut ix = Index::open(&dir.join("index.db")).unwrap();

        // Posted LATER (t=95_000) but seen FIRST (t=100_000).
        ix.ingest(
            "alt.test",
            &[dated_entry("\"Posted.Later.2020.mkv\" yEnc (1/1)", "p1", 95_000)],
            100_000,
        )
        .unwrap();
        // Posted EARLIER (t=91_000) but seen LAST (t=110_000) - the
        // slow-to-complete set that Latest buries.
        ix.ingest(
            "alt.test",
            &[dated_entry("\"Seen.Later.2020.mkv\" yEnc (1/1)", "s1", 91_000)],
            110_000,
        )
        .unwrap();

        let q = BrowseQuery { limit: 10, ..Default::default() };
        let first = |sort| {
            let (cards, _) = ix.browse_cards(&q, sort, false, false, None).unwrap();
            cards[0].title_key.clone()
        };
        assert!(
            first(CardSort::Latest).contains("posted later"),
            "Latest must lead with the newest UPLOAD"
        );
        assert!(
            first(CardSort::Arrived).contains("seen later"),
            "Arrived must lead with the newest thing WE SAW - this is the \
             whole reason the arrivals pill switches to it"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `nsegs` caches what `json_array_length(segments)` used to
    /// recompute on every touch. Two things must hold: it tracks the
    /// merged part set exactly, and completeness stays right for rows
    /// the backfill has not reached yet (an unfilled row reads 0, which
    /// would otherwise flip a complete release to incomplete).
    #[test]
    fn nsegs_tracks_segments_and_survives_a_half_done_backfill() {
        let dir = std::env::temp_dir().join(format!("nzbfast-nsegs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("index.db");
        let mut ix = Index::open(&path).unwrap();

        // Split across batches so the merge path runs: part 2 arrives
        // after part 1, and nsegs has to end at 2, not 1.
        ix.ingest("alt.test", &[entry("\"Film.2020.part1.rar\" yEnc (1/2)", "p@x", "a1", 900)], 1000)
            .unwrap();
        let count = |ix: &Index| -> i64 {
            ix.db
                .query_row("SELECT nsegs FROM files WHERE filename LIKE 'Film%'", [], |r| r.get(0))
                .unwrap()
        };
        assert_eq!(count(&ix), 1, "first batch: one part seen");
        assert_eq!(
            ix.ingest("alt.test", &[entry("\"Film.2020.part1.rar\" yEnc (2/2)", "p@x", "a2", 900)], 1001)
                .unwrap(),
            1,
            "merging the second part completes the release"
        );
        assert_eq!(count(&ix), 2, "nsegs follows the MERGED set, not the batch");
        assert!(ix.db
            .query_row("SELECT complete FROM releases LIMIT 1", [], |r| r.get::<_, bool>(0))
            .unwrap());

        // Simulate a row the chunked backfill has not reached: nsegs
        // back to 0 with the JSON intact, which is exactly the state
        // every pre-existing row is in on first open after upgrading.
        ix.db.execute("UPDATE files SET nsegs = 0", []).unwrap();
        ix.db.execute("UPDATE kv SET v='0' WHERE k='nsegs_fill'", []).ok();
        ix.ingest("alt.test", &[entry("\"Other.2020.mkv\" yEnc (1/1)", "p@y", "b1", 900)], 1002)
            .unwrap();
        let still_complete: bool = ix.db
            .query_row(
                "SELECT complete FROM releases WHERE stem LIKE 'Film%'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(
            still_complete,
            "a release whose files the backfill has not reached must not \
             be flipped to incomplete by the cached count reading 0"
        );

        // Re-opening runs the backfill and fills them in.
        drop(ix);
        let ix = Index::open(&path).unwrap();
        assert_eq!(count(&ix), 2, "backfill restored the cached count");
        let done: String = ix.db
            .query_row("SELECT v FROM kv WHERE k='nsegs_fill'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(done, "1", "backfill stamped itself complete");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn wall_tip_counts_arrivals_not_backfill() {
        let dir = std::env::temp_dir().join(format!("nzbfast-tip-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut ix = Index::open(&dir.join("index.db")).unwrap();

        // Clock: a release is POSTED before it is SEEN (ingest clamps a
        // future Date: header to scan time, so the reverse is not
        // expressible). "Recently posted" here means after t=90_000.
        const RECENT: i64 = 90_000;

        // Posted t=91_000, first seen t=100_000.
        ix.ingest(
            "alt.test",
            &[dated_entry("\"Old.Show.S01E01.mkv\" yEnc (1/1)", "o1", 91_000)],
            100_000,
        )
        .unwrap();
        assert_eq!(ix.wall_tip(0, RECENT, 10).unwrap().latest, 1);
        // Nothing inserted after release row 1.
        let none = ix.wall_tip(1, RECENT, 10).unwrap();
        assert_eq!((none.new_keys, none.keys.len()), (0, 0));

        // A genuine arrival: newly seen AND recently posted.
        ix.ingest(
            "alt.test",
            &[dated_entry("\"New.Show.S02E02.mkv\" yEnc (1/1)", "n1", 95_000)],
            101_000,
        )
        .unwrap();
        let tip = ix.wall_tip(1, RECENT, 10).unwrap();
        assert_eq!((tip.new_keys, tip.latest), (1, 2));
        assert!(tip.keys[0].contains("new show"), "got {:?}", tip.keys);

        // A second release arriving in the SAME whole second still moves
        // the row-id cursor. A first_seen cursor used to miss this forever.
        ix.ingest(
            "alt.test",
            &[dated_entry("\"Other.Show.S03E03.mkv\" yEnc (1/1)", "n2", 95_001)],
            101_000,
        )
        .unwrap();
        let same_second = ix.wall_tip(2, RECENT, 10).unwrap();
        assert_eq!((same_second.new_keys, same_second.latest), (1, 3));

        // Eviction can delete the highest SQLite rowid, which SQLite then
        // reuses. The persistent sequence must still advance past 3.
        let same_key = same_second.keys[0].clone();
        ix.db
            .execute(
                "DELETE FROM files WHERE release_id IN
                   (SELECT id FROM releases WHERE title_key=?1)",
                [&same_key],
            )
            .unwrap();
        ix.db
            .execute("DELETE FROM releases WHERE title_key=?1", [&same_key])
            .unwrap();
        ix.ingest(
            "alt.test",
            &[dated_entry("\"Replacement.Show.S04E04.mkv\" yEnc (1/1)", "n3", 95_002)],
            101_000,
        )
        .unwrap();
        let reused_id = ix.wall_tip(3, RECENT, 10).unwrap();
        assert_eq!((reused_id.new_keys, reused_id.latest), (1, 4));

        // THE ONE THAT MATTERS. The history deepen leg ingests an
        // ancient upload right now: newly seen, posted long ago. It must
        // NOT be announced as an arrival. Counting it both cried wolf
        // every backfill pass AND sent the user to a wall sorted by
        // posted date, where the thing just announced sat thousands of
        // cards down and could not be found at all.
        ix.ingest(
            "alt.test",
            &[dated_entry("\"Ancient.Film.2009.mkv\" yEnc (1/1)", "a1", 100)],
            102_000,
        )
        .unwrap();
        let after_backfill = ix.wall_tip(4, RECENT, 10).unwrap();
        assert_eq!(
            (after_backfill.new_keys, after_backfill.keys.len()),
            (0, 0),
            "a backfilled old upload is new to the index but is not an arrival"
        );
        assert_eq!(after_backfill.latest, 5, "the mark still advances");

        // Re-seeing a release we already hold is not an arrival either
        // (first_seen is set on insert only, so the mark does not move).
        ix.ingest(
            "alt.test",
            &[dated_entry("\"New.Show.S02E02.mkv\" yEnc (1/1)", "n1", 95_000)],
            103_000,
        )
        .unwrap();
        assert_eq!(ix.wall_tip(5, RECENT, 10).unwrap().new_keys, 0);

        // Hiding the title removes it from the count.
        ix.hide_title(&tip.keys[0]).unwrap();
        assert_eq!(ix.wall_tip(1, RECENT, 10).unwrap().new_keys, 1);

        // An empty releases table must not reset the opaque cursor. A
        // wall opened while empty keeps cursor 5, then sees sequence 6.
        ix.db.execute("DELETE FROM files", []).unwrap();
        ix.db.execute("DELETE FROM releases", []).unwrap();
        assert_eq!(ix.wall_tip(5, RECENT, 10).unwrap().latest, 5);
        ix.ingest(
            "alt.test",
            &[dated_entry("\"After.Empty.S01E01.mkv\" yEnc (1/1)", "z1", 95_003)],
            104_000,
        )
        .unwrap();
        let after_empty = ix.wall_tip(5, RECENT, 10).unwrap();
        assert_eq!((after_empty.new_keys, after_empty.latest), (1, 6));

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The arrivals counter lives in `kv`, and three separate code paths
    /// do `DELETE FROM kv WHERE k=...`. If that row ever went missing the
    /// trigger's `SELECT v FROM kv` yielded NULL, the `UPDATE releases
    /// SET arrival_seq=NULL` hit the NOT NULL constraint, and the whole
    /// ingest transaction rolled back - one mistyped key away from an
    /// index that can never be written to again. The fallback makes the
    /// worst case a duplicate cursor value, not a dead database.
    #[test]
    fn arrival_seq_trigger_survives_a_missing_counter_row() {
        let dir = std::env::temp_dir().join(format!("nzbfast-arrseq-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut ix = Index::open(&dir.join("index.db")).unwrap();

        ix.ingest(
            "alt.test",
            &[dated_entry("\"Before.Wipe.S01E01.mkv\" yEnc (1/1)", "b1", 91_000)],
            100_000,
        )
        .unwrap();

        // Somebody's kv cleanup took the counter with it.
        ix.db.execute("DELETE FROM kv WHERE k='wall_arrival_seq'", []).unwrap();

        ix.ingest(
            "alt.test",
            &[dated_entry("\"After.Wipe.S02E02.mkv\" yEnc (1/1)", "a1", 95_000)],
            101_000,
        )
        .expect("a missing kv row must not take the ingest transaction down with it");

        // The release really landed, and it carries a usable cursor
        // value rather than the 0 that means "not yet claimed".
        let (n, seq): (i64, i64) = ix
            .db
            .query_row(
                "SELECT COUNT(*), COALESCE(MAX(arrival_seq), 0) FROM releases",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(n, 2, "both releases are in the table");
        assert!(seq > 0, "the fallback gave the new row a real cursor, got {seq}");

        // An index that predates this fix carries the old trigger, so the
        // upgrade has to replace it - a database still running the
        // original definition is still fail-dead.
        let old: i64 = ix
            .db
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                  WHERE type='trigger' AND name='rel_arrival_seq_ai'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(old, 0, "the pre-fix trigger must be dropped on open");

        // And the counter heals itself on the next open, so the id
        // fallback stays a one-insert stopgap rather than the new normal.
        drop(ix);
        let ix = Index::open(&dir.join("index.db")).unwrap();
        let restored: i64 = ix
            .db
            .query_row("SELECT CAST(v AS INTEGER) FROM kv WHERE k='wall_arrival_seq'", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(restored, seq, "re-open restored the counter from MAX(arrival_seq)");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A VACUUM is minutes of synchronous rewriting on a multi-GB index,
    /// and the daemon holds it under the same gate a starting download
    /// waits on - so the rewrite has to be abortable, or a job that
    /// arrives mid-compact stalls for its whole duration. The property
    /// that makes aborting safe: VACUUM is one transaction, so the
    /// database is exactly as it was.
    #[test]
    fn a_compact_can_be_aborted_and_leaves_the_database_intact() {
        let dir = std::env::temp_dir().join(format!("nzbfast-vacabort-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("index.db");
        let ix = Index::open(&path).unwrap();

        // Enough freed pages that the rewrite is not instantaneous: the
        // interrupt below lands 5 ms in, against a rewrite measured in
        // hundreds of milliseconds.
        let payload = vec![7u8; 4096];
        ix.db.execute_batch("CREATE TABLE IF NOT EXISTS vac_ballast(id INTEGER PRIMARY KEY, b BLOB)")
            .unwrap();
        {
            let tx = ix.db.unchecked_transaction().unwrap();
            for _ in 0..20_000 {
                tx.execute("INSERT INTO vac_ballast(b) VALUES(?1)", [&payload]).unwrap();
            }
            tx.commit().unwrap();
        }
        ix.db.execute("DELETE FROM vac_ballast WHERE id % 2 = 0", []).unwrap();

        let handle = ix.interrupt_handle();
        let stop = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(5));
            handle.interrupt();
        });
        let r = ix.compact();
        stop.join().unwrap();
        assert!(r.is_err(), "the rewrite must abort rather than run to completion");

        // Nothing was lost: the odd-id half is still all there, and the
        // index is usable straight afterwards.
        let n: i64 =
            ix.db.query_row("SELECT COUNT(*) FROM vac_ballast", [], |r| r.get(0)).unwrap();
        assert_eq!(n, 10_000, "an aborted VACUUM must not cost a single row");
        assert!(ix.db_bytes().unwrap() > 0, "the connection still works after the abort");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The NZBLNK ladder's first rung: a header the board handed out,
    /// resolved against our own scan data and turned back into an NZB.
    #[test]
    fn find_by_header_resolves_a_link_from_our_own_scan() {
        let dir = std::env::temp_dir().join(format!("nzbfast-hdr-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut ix = Index::open(&dir.join("index.db")).unwrap();

        // The common shape: the whole posting is named after the header,
        // so the header IS the release stem.
        ix.ingest(
            "alt.binaries.boneless",
            &[
                entry("\"7f3ac91e88.part01.rar\" yEnc (1/2)", "p@x", "s1", 1000),
                entry("\"7f3ac91e88.part01.rar\" yEnc (2/2)", "p@x", "s2", 1000),
                entry("\"7f3ac91e88.part02.rar\" yEnc (1/1)", "p@x", "s3", 800),
                entry("\"7f3ac91e88.par2\" yEnc (1/1)", "p@x", "s4", 200),
            ],
            1000,
        )
        .unwrap();
        // A decoy that shares the header's leading characters: an
        // unverified FTS prefix hit would hand the user this instead.
        ix.ingest(
            "alt.binaries.boneless",
            &[entry("\"7f3ac91e88ff00.mkv\" yEnc (1/1)", "q@x", "d1", 4000)],
            1000,
        )
        .unwrap();

        let hits = ix.find_by_header("7f3ac91e88", 10).unwrap();
        assert_eq!(hits[0].stem, "7f3ac91e88", "exact stem must win: {hits:?}");
        assert!(hits[0].complete && hits[0].has_par2);

        // And it emits a whole NZB from the segments the scan stored.
        let nzb = ix.make_nzb(hits[0].id).unwrap();
        let parsed = crate::nzb::Nzb::parse(nzb.as_bytes()).unwrap();
        assert_eq!(parsed.files.len(), 3);
        assert_eq!(parsed.files.iter().map(|f| f.segments.len()).sum::<usize>(), 4);

        // Case and separator spelling do not matter.
        assert_eq!(ix.find_by_header("7F3AC91E88", 10).unwrap()[0].stem, "7f3ac91e88");

        // The other shape: per-file obfuscation, where the header names
        // a FILE inside a release whose stem is something else.
        ix.db
            .execute(
                "INSERT INTO releases(stem, poster, grp, files, complete, first_posted,
                                      first_seen)
                 VALUES('Die.Hard.Umlaut.German','p2@x','alt.binaries.misc',1,1,50,50)",
                [],
            )
            .unwrap();
        let rid = ix.db.last_insert_rowid();
        ix.db
            .execute(
                "INSERT INTO files(release_id, filename, total_parts, bytes, segments, nsegs)
                 VALUES(?1, 'ab_cd%ef-9911.part1.rar', 1, 500, '[[1,\"f1\",500]]', 1)",
                [rid],
            )
            .unwrap();
        // LIKE metacharacters in the header are escaped, not honoured.
        let hits = ix.find_by_header("ab_cd%ef-9911", 10).unwrap();
        assert_eq!(hits.len(), 1, "filename rung missed: {hits:?}");
        assert_eq!(hits[0].stem, "Die.Hard.Umlaut.German");
        assert!(ix.find_by_header("ab-cd-ef-9911", 10).unwrap().is_empty(),
            "the wildcards were live");

        // Nothing to resolve, and nothing distinctive enough to try.
        assert!(ix.find_by_header("nosuchheaderatall", 10).unwrap().is_empty());
        assert!(ix.find_by_header("7f3", 10).unwrap().is_empty(), "too short to identify");
        teardown(&dir, ix);
    }

    #[test]
    fn ingest_cluster_search_synthesize() {
        let dir = std::env::temp_dir().join(format!("nzbfast-index-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut ix = Index::open(&dir.join("index.db")).unwrap();

        // Two batches split mid-file: merging must complete the release.
        let b1 = vec![
            entry("\"Show.S01E01.part1.rar\" yEnc (1/2)", "p@x", "a1", 1000),
            entry("\"Show.S01E01.part2.rar\" yEnc (1/1)", "p@x", "b1", 900),
            entry("\"Show.S01E01.par2\" yEnc (1/1)", "p@x", "c1", 100),
        ];
        let b2 = vec![entry("\"Show.S01E01.part1.rar\" yEnc (2/2)", "p@x", "a2", 1000)];
        assert_eq!(ix.ingest("alt.test", &b1, 1000).unwrap(), 0); // part1 incomplete
        assert_eq!(ix.ingest("alt.test", &b2, 1001).unwrap(), 1); // now complete

        // Separator-insensitive, multi-term AND search: a dotted stem
        // must match a space-separated *arr query (and vice-versa).
        assert_eq!(ix.search("show.s01e01", 10).unwrap().len(), 1);
        assert_eq!(ix.search("show s01e01", 10).unwrap().len(), 1);
        assert_eq!(ix.search("SHOW", 10).unwrap().len(), 1);
        assert_eq!(ix.search("s01e01 show", 10).unwrap().len(), 1); // order-free
        assert_eq!(ix.search("show s09e09", 10).unwrap().len(), 0); // term absent
        assert_eq!(ix.search("", 10).unwrap().len(), 1); // empty = all

        let hits = ix.search("show.s01e01", 10).unwrap();
        assert_eq!(hits.len(), 1);
        let r = &hits[0];
        assert!(r.complete && r.has_par2);
        assert_eq!(r.files, 3);
        assert_eq!(r.total_bytes, 3000);

        // NZB synthesis parses and carries every segment.
        let nzb = ix.make_nzb(r.id).unwrap();
        let parsed = crate::nzb::Nzb::parse(nzb.as_bytes()).unwrap();
        assert_eq!(parsed.files.len(), 3);
        assert_eq!(
            parsed.files.iter().map(|f| f.segments.len()).sum::<usize>(),
            4
        );

        // High-water marks persist, independently per server (A8:
        // article numbers are per-server, message-ids are not).
        ix.set_high_water("alt.test", "News.EXAMPLE.com", 42).unwrap();
        assert_eq!(ix.high_water("alt.test", "news.example.com"), 42);
        assert_eq!(ix.high_water("alt.test", "other.example.com"), 0);
        assert_eq!(ix.stats().unwrap(), (1, 1));
        teardown(&dir, ix);
    }

    #[test]
    fn title_identity_reset_roundtrip() {
        let dir = std::env::temp_dir().join(format!("nzbfast-titles-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ix = Index::open(&dir.join("index.db")).unwrap();

        // Upsert works with no prior seed, then survives a later seed
        // attempt (INSERT OR IGNORE must not clobber the correction).
        ix.title_set_identity("m:matrix", "movie", "The Matrix", 1999).unwrap();
        ix.title_seed("m:matrix", "other", "matrix", 0).unwrap();
        let t = ix.title_get("m:matrix").unwrap().unwrap();
        assert_eq!((t.kind.as_str(), t.title.as_str(), t.year), ("movie", "The Matrix", 1999));
        assert_eq!(t.checked, 0); // never looked up → pending

        // Fill, then re-scrub identity: metadata columns are preserved.
        ix.title_fill(
            "m:matrix",
            &TitleFill {
                tmdb_id: 603,
                overview: "Neo.",
                rating: 8.7,
                genres: "Sci-Fi",
                poster: "p.jpg",
                backdrop: "b.jpg",
                imdb: "tt0133093",
                actors: "Keanu",
                air_date: "1999-03-30",
            },
            111,
        )
        .unwrap();
        ix.title_set_identity("m:matrix", "movie", "The Matrix", 1998).unwrap();
        let t = ix.title_get("m:matrix").unwrap().unwrap();
        assert_eq!((t.year, t.tmdb_id, t.overview.as_str()), (1998, 603, "Neo."));
        assert_eq!(t.checked, 111);
        assert_eq!(t.air_date, "1999-03-30");

        // Reset wipes metadata (incl. imdb/actors) but keeps identity,
        // and flags pending.
        assert!(ix.title_reset("m:matrix").unwrap());
        let t = ix.title_get("m:matrix").unwrap().unwrap();
        assert_eq!((t.title.as_str(), t.year), ("The Matrix", 1998));
        assert_eq!((t.tmdb_id, t.checked), (0, 0));
        assert!(t.overview.is_empty() && t.poster.is_empty());
        assert!(t.imdb.is_empty() && t.actors.is_empty() && t.air_date.is_empty());
        assert!(!ix.title_reset("nope").unwrap());

        // Reset-all counts rows and pends everything.
        ix.title_seed("t:show", "tv", "Show", 0).unwrap();
        ix.title_fill(
            "t:show",
            &TitleFill { tmdb_id: 7, overview: "x", rating: 1.0, ..Default::default() },
            5,
        )
        .unwrap();
        assert_eq!(ix.titles_reset_all().unwrap(), 2);
        assert_eq!(ix.titles_pending(10).unwrap().len(), 2);

        // Enricher lanes partition `titles` - every pending row must be
        // claimed by exactly one lane, or a kind silently stops being
        // enriched (which is what happened to music and books).
        ix.title_seed("o:junk", "other", "junk", 0).unwrap();
        ix.title_seed("s:app", "software", "App", 0).unwrap();
        ix.title_seed("mu:album", "music", "Artist - Album", 0).unwrap();
        ix.title_seed("bk:book", "book", "Author - Book", 0).unwrap();
        // Every one needs a listable release: the backlog lane only
        // considers titles the wall would show, and a titles row with no
        // releases behind it is not a state the indexer ever produces.
        for (i, key) in
            ["m:matrix", "t:show", "o:junk", "s:app", "mu:album", "bk:book"]
                .iter()
                .enumerate()
        {
            ix.db
                .execute(
                    "INSERT INTO releases(stem, poster, grp, title_key, junk, first_posted)
                     VALUES(?1,'p','g',?2,0,?3)",
                    rusqlite::params![format!("rel{i}"), key, 100 - i as i64],
                )
                .unwrap();
        }
        let lane = |l: Lane| -> Vec<String> {
            ix.titles_pending_lane(10, l).unwrap().into_iter().map(|t| t.key).collect()
        };
        assert_eq!(lane(Lane::Movies), ["m:matrix"]);
        let mut media = lane(Lane::MusicBooks);
        media.sort();
        assert_eq!(media, ["bk:book", "mu:album"]);
        let shows = lane(Lane::Shows);
        assert_eq!(shows.len(), 3);
        for k in ["m:matrix", "mu:album", "bk:book"] {
            assert!(!shows.contains(&k.to_string()), "{k} is in two lanes");
        }
        // The partition must be total: no pending row belongs to none.
        let all = ix.titles_pending(10).unwrap().len();
        assert_eq!(all, lane(Lane::Movies).len() + media.len() + shows.len());
        teardown(&dir, ix);
    }

    /// Enrichment is the scarcest resource here, and 75% of it was going
    /// to titles the wall would never list. The backlog query asks for a
    /// release that passes the junk gate; the viewport query deliberately
    /// does not (see `titles_hot`).
    #[test]
    fn the_backlog_lane_skips_titles_the_wall_would_not_show() {
        let dir = std::env::temp_dir().join(format!("nzbfast-vis-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("index.db");
        let ix = Index::open(&db).unwrap();

        // Two titles, both pending: one with a listable release, one
        // whose only release is junk-gated.
        for (key, stem, junk) in [
            ("m:seen:2024", "Seen.Film.2024.1080p.BluRay.x264-GRP", 0),
            ("m:hidden:2024", "Hidden.Film.2024.1080p.BluRay.x264-GRP", 70),
        ] {
            ix.title_seed(key, "movie", "x", 2024).unwrap();
            ix.db
                .execute(
                    "INSERT INTO releases(stem, poster, grp, title_key, kind, junk,
                                          first_posted)
                     VALUES(?1,'p','g',?2,'movie',?3,100)",
                    rusqlite::params![stem, key, junk],
                )
                .unwrap();
        }
        let pending: Vec<String> = ix
            .titles_pending_lane(10, Lane::Movies)
            .unwrap()
            .into_iter()
            .map(|t| t.key)
            .collect();
        assert_eq!(pending, ["m:seen:2024"], "a junk-only title cost a lookup");

        // Viewport priority ignores the filter: on screen means wanted.
        let hot: Vec<String> = ix
            .titles_hot(&["m:hidden:2024".to_string()], Lane::Movies)
            .unwrap()
            .into_iter()
            .map(|t| t.key)
            .collect();
        assert_eq!(hot, ["m:hidden:2024"], "an on-screen card must still enrich");

        // Deferred, not dropped: junk is recomputed on every ingest touch
        // and a mid-upload release sheds it as parts arrive, so the title
        // must become eligible the moment it would be listed.
        ix.db
            .execute("UPDATE releases SET junk=0 WHERE title_key='m:hidden:2024'", [])
            .unwrap();
        let pending: Vec<String> = ix
            .titles_pending_lane(10, Lane::Movies)
            .unwrap()
            .into_iter()
            .map(|t| t.key)
            .collect();
        assert!(
            pending.contains(&"m:hidden:2024".to_string()),
            "a title that became visible was skipped for good: {pending:?}"
        );
        teardown(&dir, ix);
    }

    #[test]
    fn browse_filters_sorts_and_backfills() {
        let dir = std::env::temp_dir().join(format!("nzbfast-browse-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("index.db");
        {
            let mut ix = Index::open(&db).unwrap();
            let mut mk = |subj: &str, id: &str, bytes: u64, date: i64| {
                let mut e = entry(subj, "p@x", id, bytes);
                e.date = date;
                e
            };
            ix.ingest(
                "alt.test",
                &[
                    mk("\"Big.Film.2020.2160p.WEB.mkv\" yEnc (1/1)", "m1", 5000, 100),
                    mk("\"Small.Film.2021.1080p.BluRay.mkv\" yEnc (1/1)", "m2", 1000, 300),
                    mk("\"Show.S01E01.1080p.WEB.part1.rar\" yEnc (1/2)", "t1", 800, 200),
                ],
                1000,
            )
            .unwrap();
            // Ingest stored classification + part tallies.
            let all = ix.search("", 10).unwrap();
            let big = all.iter().find(|r| r.stem.starts_with("Big.Film")).unwrap();
            assert_eq!((big.kind.as_str(), big.res.as_str()), ("movie", "2160p"));
            assert_eq!((big.have_parts, big.need_parts), (1, 1));
            let show = all.iter().find(|r| r.stem.starts_with("Show.")).unwrap();
            assert_eq!(show.kind, "tv");
            assert_eq!((show.have_parts, show.need_parts), (1, 2));

            // Kind + res filters.
            let (movies, total) = ix
                .browse(&BrowseQuery { kind: Some("movie".into()), ..Default::default() })
                .unwrap();
            assert_eq!((movies.len(), total), (2, 2));
            let (uhd, _) = ix
                .browse(&BrowseQuery { res: Some("2160p".into()), ..Default::default() })
                .unwrap();
            assert_eq!(uhd.len(), 1);
            assert!(uhd[0].stem.starts_with("Big.Film"));

            // complete_only drops the half-uploaded show.
            let (done, _) =
                ix.browse(&BrowseQuery { complete_only: true, ..Default::default() }).unwrap();
            assert!(done.iter().all(|r| r.complete));
            assert_eq!(done.len(), 2);

            // Sorts: posted (default, newest first), size, completeness.
            let (by_date, _) = ix.browse(&BrowseQuery::default()).unwrap();
            assert!(by_date[0].stem.starts_with("Small.Film")); // date 300
            let (by_size, _) = ix
                .browse(&BrowseQuery { sort: BrowseSort::Size, ..Default::default() })
                .unwrap();
            assert!(by_size[0].stem.starts_with("Big.Film"));
            let (by_comp, _) = ix
                .browse(&BrowseQuery {
                    sort: BrowseSort::Completeness,
                    desc: false,
                    ..Default::default()
                })
                .unwrap();
            assert!(by_comp[0].stem.starts_with("Show.")); // 50% sorts first ASC
            // "Most complete" (desc, the only direction the wall UI sends):
            // the ratio column must honor DESC, not just the tie-break.
            let (by_comp_desc, _) = ix
                .browse(&BrowseQuery {
                    sort: BrowseSort::Completeness,
                    desc: true,
                    ..Default::default()
                })
                .unwrap();
            assert!(
                !by_comp_desc[0].stem.starts_with("Show."),
                "desc completeness put the 50% release first: {}",
                by_comp_desc[0].stem
            );

            // Pagination: limit 1 pages through, total stays 3.
            let (p1, total) = ix
                .browse(&BrowseQuery { limit: 1, ..Default::default() })
                .unwrap();
            let (p2, _) = ix
                .browse(&BrowseQuery { limit: 1, offset: 1, ..Default::default() })
                .unwrap();
            assert_eq!(total, 3);
            assert_ne!(p1[0].id, p2[0].id);

            // Substring q composes with filters.
            let (hits, _) = ix
                .browse(&BrowseQuery {
                    q: "big film".into(),
                    kind: Some("movie".into()),
                    ..Default::default()
                })
                .unwrap();
            assert_eq!(hits.len(), 1);

            // Simulate a pre-M25 database: blank the columns, clear the
            // migration flag.
            ix.db
                .execute_batch(
                    "UPDATE releases SET kind='', res='', have_parts=0, need_parts=0;
                     DELETE FROM kv WHERE k='browse_cols';",
                )
                .unwrap();
        }
        // Re-open runs the backfill.
        let ix = Index::open(&db).unwrap();
        assert_eq!(ix.kv_get("browse_cols").as_deref(), Some("1"));
        let all = ix.search("", 10).unwrap();
        let big = all.iter().find(|r| r.stem.starts_with("Big.Film")).unwrap();
        assert_eq!((big.kind.as_str(), big.res.as_str()), ("movie", "2160p"));
        let show = all.iter().find(|r| r.stem.starts_with("Show.")).unwrap();
        assert_eq!((show.have_parts, show.need_parts), (1, 2));
        teardown(&dir, ix);
    }

    /// Codec / audio / dynamic range land on ingest, and rows indexed
    /// before those columns existed get them from the quality_v8 re-parse
    /// on the next open - the whole point of bumping the version key.
    #[test]
    fn codec_audio_hdr_stored_and_backfilled() {
        let dir = std::env::temp_dir().join(format!("nzbfast-qual-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("index.db");
        let stem = "Dune.Part.Two.2024.2160p.UHD.BluRay.REMUX.DV.HDR.HEVC.TrueHD.Atmos-GRP";
        {
            let mut ix = Index::open(&db).unwrap();
            ix.ingest(
                "alt.binaries.test",
                &[entry(&format!("\"{stem}.mkv\" yEnc (1/1)"), "a@a", "g1", 40 << 30)],
                1_000,
            )
            .unwrap();
            let r = &ix.search("", 10).unwrap()[0];
            assert_eq!(
                (r.res.as_str(), r.vcodec.as_str(), r.acodec.as_str(), r.hdr.as_str()),
                ("2160p", "x265", "Atmos", "DV"),
                "ingest should store what the parser already read"
            );
            // Simulate a database written before the columns existed.
            ix.db
                .execute_batch(
                    "UPDATE releases SET vcodec='', acodec='', hdr='';
                     DELETE FROM kv WHERE k='quality_v8';",
                )
                .unwrap();
        }
        let ix = Index::open(&db).unwrap();
        assert_eq!(ix.kv_get("quality_v8").as_deref(), Some("1"));
        let r = &ix.search("", 10).unwrap()[0];
        assert_eq!(
            (r.vcodec.as_str(), r.acodec.as_str(), r.hdr.as_str()),
            ("x265", "Atmos", "DV"),
            "re-open should have backfilled from the stem"
        );
        teardown(&dir, ix);
    }

    /// 24C Releases surface: the added (first_seen), files and kind
    /// sorts, plus browse_cards' exact-key filter (hover preview /
    /// group-by-title fetch one title's card).
    #[test]
    fn browse_seen_files_kind_sorts_and_card_key() {
        let dir = std::env::temp_dir().join(format!("nzbfast-brsort-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut ix = Index::open(&dir.join("index.db")).unwrap();
        let mut mk = |subj: &str, id: &str, date: i64| {
            let mut e = entry(subj, "p@x", id, 900);
            e.date = date;
            e
        };
        // Three scans at distinct times: first_seen orders by SCAN time,
        // first_posted by article date - deliberately opposite here so
        // the two sorts cannot pass by accident.
        ix.ingest(
            "alt.test",
            &[
                mk("\"Alpha.Movie.2020.1080p.WEB.part1.rar\" yEnc (1/1)", "a1", 900),
                mk("\"Alpha.Movie.2020.1080p.WEB.part2.rar\" yEnc (1/1)", "a2", 900),
            ],
            1000,
        )
        .unwrap();
        ix.ingest(
            "alt.test",
            &[mk("\"Beta.Show.S01E01.720p.HDTV.mkv\" yEnc (1/1)", "b1", 500)],
            2000,
        )
        .unwrap();
        ix.ingest(
            "alt.test",
            &[mk("\"Gamma.Tool.v3.2.x64.Setup.rar\" yEnc (1/1)", "g1", 100)],
            3000,
        )
        .unwrap();

        // Seen desc = most recently INDEXED first (Gamma), even though
        // its post date is the oldest.
        let (by_seen, _) = ix
            .browse(&BrowseQuery { sort: BrowseSort::Seen, ..Default::default() })
            .unwrap();
        assert!(by_seen[0].stem.starts_with("Gamma."), "{:?}", by_seen[0].stem);
        assert!(by_seen[2].stem.starts_with("Alpha."), "{:?}", by_seen[2].stem);
        // ...and posted desc still leads with Alpha (date 900).
        let (by_posted, _) = ix.browse(&BrowseQuery::default()).unwrap();
        assert!(by_posted[0].stem.starts_with("Alpha."), "{:?}", by_posted[0].stem);

        // Files desc: the two-part Alpha release carries 2 files.
        let (by_files, _) = ix
            .browse(&BrowseQuery { sort: BrowseSort::Files, ..Default::default() })
            .unwrap();
        assert!(by_files[0].stem.starts_with("Alpha."), "{:?}", by_files[0].stem);
        assert_eq!(by_files[0].files, 2);

        // Kind asc groups the category column: movie < software < tv.
        let (by_kind, _) = ix
            .browse(&BrowseQuery { sort: BrowseSort::Kind, desc: false, ..Default::default() })
            .unwrap();
        let kinds: Vec<&str> = by_kind.iter().map(|r| r.kind.as_str()).collect();
        assert_eq!(kinds, ["movie", "software", "tv"], "{by_kind:?}");

        // browse_cards: no filter = three cards; an exact title_key
        // returns just that card with total agreeing.
        let (cards, total) =
            ix.browse_cards(&Default::default(), CardSort::Latest, false, false, None).unwrap();
        assert_eq!((cards.len(), total), (3, 3), "{cards:?}");
        let alpha = cards.iter().find(|c| c.rep_stem.starts_with("Alpha.")).unwrap();
        let (one, total) = ix
            .browse_cards(
                &BrowseQuery { title_key: Some(alpha.title_key.clone()), ..Default::default() },
                CardSort::Latest,
                false,
                false,
                None,
            )
            .unwrap();
        assert_eq!((one.len(), total), (1, 1), "{one:?}");
        assert_eq!(one[0].title_key, alpha.title_key);
        assert_eq!(one[0].n_releases, 1);
        teardown(&dir, ix);
    }

    /// N9: a card's representative (rep_stem / rep_grp - what drives the
    /// title parse, the enrichment seed, the "have" dupe key and the
    /// oracle verdict) has to come from a release THIS view accepts. The
    /// title's newest release is the wrong answer when the active filters
    /// exclude it.
    #[test]
    fn card_representative_obeys_the_active_filters() {
        let dir = std::env::temp_dir().join(format!("nzbfast-repfilt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ix = Index::open(&dir.join("index.db")).unwrap();
        // Two releases of one title, written straight to SQL so junk /
        // group / post date are exact. The NEWER one is the junk copy
        // from the group a rule will hide.
        let key = "m:rep filter:2020";
        let rel = |id: i64, stem: &str, grp: &str, junk: i64, posted: i64| {
            ix.db
                .execute(
                    "INSERT INTO releases(id, stem, poster, grp, total_bytes, files,
                         has_par2, complete, first_posted, first_seen, kind, res,
                         have_parts, need_parts, title_key, junk, oracle_at, langs)
                     VALUES(?1, ?2, 'p@p', ?3, 4096, 1, 0, 1, ?4, ?4, 'movie',
                            '1080p', 1, 1, ?5, ?6, 0, '')",
                    rusqlite::params![id, stem, grp, posted, key, junk],
                )
                .unwrap();
        };
        rel(1, "Rep.Filter.2020.1080p.WEB.x264-GOOD", "alt.binaries.good", 0, 100);
        rel(2, "0a1b2c3d4e5f60718293a4b5", "alt.binaries.junk", 90, 900);

        let cards = |q: BrowseQuery| -> Card {
            let (c, total) = ix
                .browse_cards(&q, CardSort::Latest, false, false, None)
                .unwrap();
            assert_eq!((c.len(), total), (1, 1), "{c:?}");
            c.into_iter().next().unwrap()
        };

        // Unfiltered: the newest release IS the representative.
        let all = cards(BrowseQuery::default());
        assert_eq!(all.n_releases, 2);
        assert_eq!(all.rep_stem, "0a1b2c3d4e5f60718293a4b5");
        assert_eq!(all.rep_grp, "alt.binaries.junk");

        // Junk ceiling: the newest release is excluded, so the card must
        // describe itself with the one release the view kept.
        let clean = cards(BrowseQuery { max_junk: Some(50), ..Default::default() });
        assert_eq!(clean.n_releases, 1);
        assert_eq!(clean.rep_stem, "Rep.Filter.2020.1080p.WEB.x264-GOOD", "{clean:?}");
        assert_eq!(clean.rep_grp, "alt.binaries.good", "{clean:?}");

        // Same for a per-release curation rule (hide one group).
        ix.rule_add("group", "alt.binaries.junk", false).unwrap();
        let curated = cards(BrowseQuery { curated: true, ..Default::default() });
        assert_eq!(curated.n_releases, 1);
        assert_eq!(curated.rep_stem, "Rep.Filter.2020.1080p.WEB.x264-GOOD", "{curated:?}");
        assert_eq!(curated.rep_grp, "alt.binaries.good", "{curated:?}");

        // ...and a row-level filter that excludes the OLDER release still
        // leaves the newest one as the representative.
        let big = cards(BrowseQuery { newer_than: 500, ..Default::default() });
        assert_eq!(big.n_releases, 1);
        assert_eq!(big.rep_grp, "alt.binaries.junk", "{big:?}");

        // Title-level filters are constant per card, so they must not
        // strand the representative: an unenriched card is dropped whole
        // by matched_only rather than losing its rep.
        let (none, total) = ix
            .browse_cards(&Default::default(), CardSort::Latest, true, false, None)
            .unwrap();
        assert_eq!((none.len(), total as usize), (0, 0));

        // The flat browse() path is unchanged: it filters and dedupes by
        // stem exactly as before.
        let (rows, total) = ix.browse(&BrowseQuery::default()).unwrap();
        assert_eq!((rows.len(), total), (2, 2));
        let (rows, total) = ix
            .browse(&BrowseQuery { max_junk: Some(50), ..Default::default() })
            .unwrap();
        assert_eq!((rows.len(), total), (1, 1));
        assert_eq!(rows[0].stem, "Rep.Filter.2020.1080p.WEB.x264-GOOD");
        let (rows, _) = ix
            .browse(&BrowseQuery { curated: true, ..Default::default() })
            .unwrap();
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(rows[0].grp, "alt.binaries.good");
        teardown(&dir, ix);
    }

    #[test]
    fn dates_gate_and_prune() {
        let dir = std::env::temp_dir().join(format!("nzbfast-gate-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut ix = Index::open(&dir.join("index.db")).unwrap();

        // first_posted = earliest article Date, walked back by later
        // batches (backfill scans newest-first); scan time is fallback.
        let mut a = entry("\"Old.Film.1999.part1.rar\" yEnc (1/1)", "p@x", "d1", 500);
        a.date = 2000;
        ix.ingest("alt.test", &[a], 9999).unwrap();
        assert_eq!(ix.search("old film", 10).unwrap()[0].first_posted, 2000);
        let mut b = entry("\"Old.Film.1999.par2\" yEnc (1/1)", "p@x", "d2", 100);
        b.date = 1500;
        ix.ingest("alt.test", &[b], 9999).unwrap();
        assert_eq!(ix.search("old film", 10).unwrap()[0].first_posted, 1500);
        let undated = entry("\"No.Date.2001.mkv\" yEnc (1/1)", "p@x", "d3", 500);
        ix.ingest("alt.test", &[undated], 9999).unwrap();
        assert_eq!(ix.search("no date", 10).unwrap()[0].first_posted, 9999);

        // Gate: clusters whose stem is refused never reach the DB.
        ix.set_gate(Box::new(|stem| !stem.to_ascii_lowercase().contains("blocked")));
        let g = entry("\"Blocked.Thing.2020.mkv\" yEnc (1/1)", "p@x", "g1", 500);
        ix.ingest("alt.test", &[g], 9999).unwrap();
        assert_eq!(ix.search("blocked", 10).unwrap().len(), 0);

        // Prune: oversize goes immediately; undersize goes once fully
        // present (all parts of every seen file) - the spam-single case.
        // A release still missing parts survives even when tiny.
        let big = entry("\"Huge.Rel.2020.part1.rar\" yEnc (1/1)", "p@x", "h1", 9000);
        let partial = entry("\"Grow.Ing.2020.part1.rar\" yEnc (1/9)", "p@x", "h2", 400);
        ix.ingest("alt.test", &[big, partial], 9999).unwrap();
        // Huge.Rel oversize + No.Date a fully-present undersize single.
        assert_eq!(ix.prune_size(600, 5000).unwrap(), 2);
        assert_eq!(ix.search("huge", 10).unwrap().len(), 0);
        assert_eq!(ix.search("no date", 10).unwrap().len(), 0);
        assert_eq!(ix.search("grow ing", 10).unwrap().len(), 1); // mid-upload, spared
        // Old.Film (600 bytes, complete): not < 600, spared - then pruned.
        assert_eq!(ix.search("old film", 10).unwrap().len(), 1);
        assert_eq!(ix.prune_size(601, 0).unwrap(), 1);
        assert_eq!(ix.search("old film", 10).unwrap().len(), 0);
        teardown(&dir, ix);
    }

    // ===== M32: size cap + eviction =====

    /// One fixture release, written straight to SQL so every column the
    /// eviction orders read (junk / complete / first_posted / total_bytes
    /// / kind / title_key) can be set exactly. `blob` is the size of the
    /// fake `segments` payload, which is what actually makes the database
    /// file grow - `total_bytes` is only metadata about the Usenet post.
    fn ev_rel(
        ix: &Index,
        id: i64,
        junk: i64,
        complete: i64,
        posted: i64,
        total_bytes: i64,
        kind: &str,
        title_key: &str,
        blob: usize,
    ) {
        ix.db
            .execute(
                "INSERT INTO releases(id, stem, poster, grp, total_bytes, files,
                     has_par2, complete, first_posted, first_seen, kind, res,
                     have_parts, need_parts, title_key, junk, oracle_at, langs)
                 VALUES(?1, ?2, 'p@p', 'alt.test', ?3, 1, 0, ?4, ?5, ?5, ?6,
                        '1080p', 1, 1, ?7, ?8, 0, '')",
                rusqlite::params![
                    id,
                    format!("Fixture.Release.{id}.1080p.WEB.x264-EV"),
                    total_bytes,
                    complete,
                    posted,
                    kind,
                    title_key,
                    junk
                ],
            )
            .unwrap();
        ix.db
            .execute(
                "INSERT INTO files(release_id, filename, total_parts, bytes, segments)
                 VALUES(?1, ?2, 1, ?3, ?4)",
                rusqlite::params![id, format!("f{id}.mkv"), total_bytes, "x".repeat(blob)],
            )
            .unwrap();
    }

    fn ev_open(tag: &str) -> (std::path::PathBuf, Index) {
        let dir = std::env::temp_dir()
            .join(format!("nzbfast-index-ev-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ix = Index::open(&dir.join("index.db")).unwrap();
        (dir, ix)
    }

    fn ev_ids(ix: &Index) -> Vec<i64> {
        let mut stmt = ix.db.prepare("SELECT id FROM releases ORDER BY id").unwrap();
        let v: Vec<i64> = stmt
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        v
    }

    /// Every deleted id must come from the front of `expected` and every
    /// survivor from the back - i.e. eviction walked the policy order and
    /// stopped somewhere, never picked out of sequence.
    fn assert_prefix_evicted(expected: &[i64], survivors: &[i64]) {
        let cut = expected.len() - survivors.len();
        let want_tail: Vec<i64> = expected[cut..].to_vec();
        let mut got = survivors.to_vec();
        let mut want = want_tail.clone();
        got.sort_unstable();
        want.sort_unstable();
        assert_eq!(
            got, want,
            "survivors must be the tail of the policy order\n  order:     {expected:?}\n  survivors: {survivors:?}"
        );
    }

    /// 8 uniform-payload releases. `total_bytes` is deliberately shuffled
    /// against `first_posted` so the size orders and the date orders are
    /// different permutations and cannot be confused for each other.
    const EV_BLOB: usize = 64 * 1024;
    const EV_SIZES: [i64; 8] = [500, 800, 100, 700, 300, 900, 200, 400];

    fn ev_eight(ix: &Index) {
        for i in 1..=8i64 {
            ev_rel(
                ix,
                i,
                0,
                1,
                1000 * i,
                EV_SIZES[(i - 1) as usize],
                "movie",
                &format!("m:fixture {i}:2020"),
                EV_BLOB,
            );
        }
    }

    /// Target that forces roughly a third of the file away - enough that
    /// several releases must go, not so much that everything does.
    fn ev_target(ix: &Index) -> u64 {
        ix.db_bytes().unwrap() * 3 / 4
    }

    #[test]
    fn evict_target_zero_is_unlimited_and_removes_nothing() {
        let (dir, ix) = ev_open("zero");
        ev_eight(&ix);
        let before = ix.db_bytes().unwrap();
        let rep = ix
            .evict_to(0, &EvictPolicy::default(), &Protected::default())
            .unwrap();
        assert_eq!(rep.removed, 0);
        assert_eq!(rep.bytes_before, before);
        assert_eq!(rep.bytes_after, before);
        assert!(!rep.needs_compact);
        assert_eq!(ev_ids(&ix).len(), 8, "no row may be touched when unlimited");
        teardown(&dir, ix);
    }

    #[test]
    fn evict_single_key_orders_follow_their_key() {
        // (order, the exact sequence eviction must walk)
        let cases: [(EvictOrder, [i64; 8]); 4] = [
            (EvictOrder::Oldest, [1, 2, 3, 4, 5, 6, 7, 8]),
            (EvictOrder::Newest, [8, 7, 6, 5, 4, 3, 2, 1]),
            // total_bytes DESC: 900,800,700,500,400,300,200,100
            (EvictOrder::Largest, [6, 2, 4, 1, 8, 5, 7, 3]),
            (EvictOrder::Smallest, [3, 7, 5, 8, 1, 4, 2, 6]),
        ];
        for (order, expected) in cases {
            let (dir, ix) = ev_open(&format!("ord{order:?}"));
            ev_eight(&ix);
            let target = ev_target(&ix);
            let policy = EvictPolicy { order, kinds: vec![] };
            let rep = ix.evict_to(target, &policy, &Protected::default()).unwrap();
            let left = ev_ids(&ix);
            assert!(rep.removed > 0, "{order:?} must evict something");
            assert!(!left.is_empty(), "{order:?} must not empty the index");
            assert_eq!(rep.removed, 8 - left.len(), "{order:?} removed count");
            assert!(rep.needs_compact, "{order:?} deleted rows, so compact is due");
            assert_prefix_evicted(&expected, &left);
            teardown(&dir, ix);
        }
    }

    #[test]
    fn evict_ladder_climbs_junk_then_incomplete_then_age_then_size() {
        let (dir, ix) = ev_open("ladder");
        // rung 0: junk AND incomplete, oldest first, then largest.
        ev_rel(&ix, 1, 80, 0, 5_000, 100, "movie", "m:a:2020", EV_BLOB);
        ev_rel(&ix, 2, 80, 0, 9_000, 900, "movie", "m:b:2020", EV_BLOB);
        // rung 1: junk but complete.
        ev_rel(&ix, 3, 80, 1, 1_000, 900, "movie", "m:c:2020", EV_BLOB);
        // rung 2: incomplete but clean - note it is the OLDEST row in the
        // whole fixture, so a plain age sort would take it first.
        ev_rel(&ix, 4, 0, 0, 100, 900, "movie", "m:d:2020", EV_BLOB);
        // rung 3: real content. Older first, then bigger first on a tie.
        ev_rel(&ix, 5, 0, 1, 2_000, 100, "movie", "m:e:2020", EV_BLOB);
        ev_rel(&ix, 6, 0, 1, 7_000, 900, "movie", "m:f:2020", EV_BLOB);
        ev_rel(&ix, 7, 0, 1, 7_000, 100, "movie", "m:g:2020", EV_BLOB);
        // rung 3 with an unparsed date: parked at the very back, exactly
        // as prune_age spares first_posted = 0.
        ev_rel(&ix, 8, 0, 1, 0, 900, "movie", "m:h:2020", EV_BLOB);
        let expected = [1i64, 2, 3, 4, 5, 6, 7, 8];

        let target = ev_target(&ix);
        let rep = ix
            .evict_to(target, &EvictPolicy::default(), &Protected::default())
            .unwrap();
        let left = ev_ids(&ix);
        assert!(rep.removed > 0);
        assert!(!left.is_empty());
        assert_prefix_evicted(&expected, &left);
        // The ladder's whole point: junk goes before real content does.
        assert!(!left.contains(&1), "junk+incomplete must go first");
        assert!(left.contains(&8), "unknown-date real content goes last");
        teardown(&dir, ix);
    }

    #[test]
    fn evict_protection_is_absolute_even_at_maximum_pressure() {
        let (dir, ix) = ev_open("prot");
        ev_eight(&ix);
        // Protect id 4 by id and id 6 by title_key. Then ask for a cap of
        // one byte: every other release must go, and the two protected
        // ones must survive even though they are then the ONLY thing left
        // that could possibly free another byte.
        let prot = Protected {
            title_keys: vec!["m:fixture 6:2020".into()],
            release_ids: vec![4],
        };
        let rep = ix.evict_to(1, &EvictPolicy::default(), &prot).unwrap();
        let left = ev_ids(&ix);
        assert_eq!(left, vec![4, 6], "protected rows survive maximum pressure");
        assert_eq!(rep.removed, 6);
        // It could not reach the target, and says so by leaving the file
        // above it rather than by deleting the protected rows anyway.
        assert!(
            ix.db_bytes().unwrap() > 1,
            "target unreachable: the report is `removed`, not a lie about size"
        );

        // A second run at the same impossible target must be a no-op, not
        // a retry that grinds through the protected rows.
        let again = ix.evict_to(1, &EvictPolicy::default(), &prot).unwrap();
        assert_eq!(again.removed, 0);
        assert!(!again.needs_compact);
        assert_eq!(ev_ids(&ix), vec![4, 6]);
        teardown(&dir, ix);
    }

    #[test]
    fn evict_hysteresis_second_call_removes_nothing() {
        let (dir, ix) = ev_open("hyst");
        ev_eight(&ix);
        let target = ev_target(&ix);
        let first = ix
            .evict_to(target, &EvictPolicy::default(), &Protected::default())
            .unwrap();
        assert!(first.removed > 0);
        let after_first = ev_ids(&ix);

        // Same cap, immediately again: the low-water mark left headroom,
        // so there is nothing to do. Without hysteresis this call would
        // shave another row off at the boundary on every single pass.
        let second = ix
            .evict_to(target, &EvictPolicy::default(), &Protected::default())
            .unwrap();
        assert_eq!(second.removed, 0, "hysteresis: no boundary thrash");
        assert!(!second.needs_compact);
        assert_eq!(ev_ids(&ix), after_first);

        // And the file really is under the cap (not merely under the
        // low-water estimate) once the freed pages are given back.
        ix.compact().unwrap();
        assert!(
            ix.db_bytes().unwrap() <= target,
            "post-compact size {} must fit the cap {target}",
            ix.db_bytes().unwrap()
        );
        teardown(&dir, ix);
    }

    #[test]
    fn evict_kinds_filter_restricts_to_listed_kinds() {
        let (dir, ix) = ev_open("kinds");
        for i in 1..=4i64 {
            ev_rel(&ix, i, 0, 1, 1000 * i, 100, "tv", &format!("t:s{i}"), EV_BLOB);
        }
        for i in 5..=8i64 {
            ev_rel(&ix, i, 0, 1, 1000 * i, 100, "movie", &format!("m:f{i}"), EV_BLOB);
        }
        // A legacy row that never got classified. It matches no filter, so
        // a kind-restricted eviction must leave it alone.
        ev_rel(&ix, 9, 90, 0, 10, 100, "", "", EV_BLOB);

        // Impossible cap, but only "tv" may be touched.
        let policy = EvictPolicy { order: EvictOrder::Oldest, kinds: vec!["tv".into()] };
        let rep = ix.evict_to(1, &policy, &Protected::default()).unwrap();
        assert_eq!(rep.removed, 4);
        assert_eq!(ev_ids(&ix), vec![5, 6, 7, 8, 9], "only tv rows were eligible");
        teardown(&dir, ix);
    }

    #[test]
    fn evict_protected_set_past_the_bind_limit_still_protects_everything() {
        let (dir, ix) = ev_open("bindcap");
        ev_eight(&ix);
        // 30_000 protected ids - far past both EVICT_PROTECT_BIND_CAP and
        // SQLite's 32766-variable ceiling - with the ids that actually
        // exist deliberately placed at the END, past anything the SQL
        // `NOT IN` binds can reach. Only the Rust-side check can save
        // them, which is exactly the fallback being tested.
        let mut ids: Vec<i64> = (1_000_000..1_030_000).collect();
        ids.extend([1i64, 2, 3, 4, 5, 6, 7, 8]);
        let mut keys: Vec<String> = (0..30_000).map(|i| format!("m:filler {i}:1999")).collect();
        keys.push("m:fixture 1:2020".into());
        let prot = Protected { title_keys: keys, release_ids: ids };

        let rep = ix.evict_to(1, &EvictPolicy::default(), &prot).unwrap();
        assert_eq!(rep.removed, 0, "nothing may be deleted when all is protected");
        assert!(!rep.needs_compact);
        assert_eq!(ev_ids(&ix), vec![1, 2, 3, 4, 5, 6, 7, 8]);

        // Same oversized set, but now one row is genuinely unprotected:
        // eviction must still make progress rather than stall on the
        // protected rows it keeps scanning past.
        let mut ids2: Vec<i64> = (1_000_000..1_030_000).collect();
        ids2.extend([1i64, 2, 3, 4, 5, 6, 7]); // 8 left out
        let prot2 = Protected {
            title_keys: (0..30_000).map(|i| format!("m:filler {i}:1999")).collect(),
            release_ids: ids2,
        };
        let rep2 = ix.evict_to(1, &EvictPolicy::default(), &prot2).unwrap();
        assert_eq!(rep2.removed, 1);
        assert_eq!(ev_ids(&ix), vec![1, 2, 3, 4, 5, 6, 7]);
        teardown(&dir, ix);
    }

    /// THE size-cap blocker, pinned. `db_bytes()` cannot fall after a
    /// DELETE, so a caller that compares the user's cap against it never
    /// sees the database get back under the cap and re-evicts forever.
    /// `live_bytes()` is the quantity that actually moves, which is why it
    /// is public and why the daemon compares against it.
    #[test]
    fn live_bytes_falls_after_a_delete_where_db_bytes_cannot() {
        let (dir, ix) = ev_open("livebytes");
        ev_uneven(&ix);
        ix.compact().unwrap();
        let db_before = ix.db_bytes().unwrap();
        let live_before = ix.live_bytes().unwrap();

        let rep = ix
            .evict_to(
                db_before / 2,
                &EvictPolicy { order: EvictOrder::Oldest, kinds: vec![] },
                &Protected::default(),
            )
            .unwrap();
        assert!(rep.removed > 0);

        assert_eq!(
            ix.db_bytes().unwrap(),
            db_before,
            "the file cannot shrink until a compact runs - the whole trap"
        );
        assert!(
            ix.live_bytes().unwrap() < live_before,
            "live_bytes must fall as rows go: {} !< {live_before}",
            ix.live_bytes().unwrap()
        );
        assert_eq!(rep.live_before, live_before);
        assert_eq!(rep.live_after, ix.live_bytes().unwrap());
        assert!(rep.live_after < rep.bytes_after, "the gap a compact would reclaim");
        teardown(&dir, ix);
    }

    /// `blocked` is the difference between "done" and "stopped", and the
    /// caller cannot tell them apart from `removed` alone: both can be 0.
    #[test]
    fn evict_reports_blocked_only_when_it_was_stopped_short() {
        let (dir, ix) = ev_open("blocked");
        ev_eight(&ix);

        // Everything protected, impossible target: stopped short.
        let all: Vec<i64> = (1..=8).collect();
        let rep = ix
            .evict_to(1, &EvictPolicy::default(), &Protected {
                title_keys: vec![],
                release_ids: all,
            })
            .unwrap();
        assert_eq!(rep.removed, 0);
        assert!(rep.blocked, "every candidate was protected: {rep:?}");
        assert!(rep.live_after > 1);

        // Nothing protected, generous target already met: done, not
        // stopped - even though `removed` is 0 here too.
        let big = ix.live_bytes().unwrap() * 4;
        let rep = ix.evict_to(big, &EvictPolicy::default(), &Protected::default()).unwrap();
        assert_eq!(rep.removed, 0);
        assert!(!rep.blocked, "already under the target is not blocked: {rep:?}");

        // Unlimited is never blocked either.
        let rep = ix.evict_to(0, &EvictPolicy::default(), &Protected::default()).unwrap();
        assert!(!rep.blocked);
        assert_eq!(rep.live_before, rep.live_after);
        teardown(&dir, ix);
    }

    /// Not a behaviour gate so much as a standing measurement: how close
    /// does the estimator land to the size the file really takes once the
    /// freed pages are handed back? Asserted loosely (the exact ratio
    /// moves with page size and fixture shape), printed so a regression
    /// in the estimator is visible in `cargo test -- --nocapture`.
    fn ev_uneven(ix: &Index) {
        // Wildly uneven payloads: the case a row count gets badly wrong.
        // 24 releases, blob sizes cycling 4K / 64K / 16K / 256K.
        for i in 1..=24i64 {
            let blob = match i % 4 {
                0 => 256 * 1024,
                1 => 4 * 1024,
                2 => 64 * 1024,
                _ => 16 * 1024,
            };
            ev_rel(ix, i, 0, 1, 1000 * i, 100, "movie", &format!("m:e{i}:2020"), blob);
        }
    }

    /// The other size regime, and the only test that spans more than one
    /// batch. 4000 releases with 200-byte segments: the payload estimate
    /// no longer dominates, so the b-tree, `idx_rel_stem`, `idx_rel_kind`
    /// and the FTS5 index carry most of the real page cost (measured
    /// scale here: 1.18-1.25, against ~1.00 when the blobs are large).
    /// This is what the runtime-fitted scale factor exists for.
    #[test]
    fn evict_spans_batches_when_row_overhead_dominates() {
        let (dir, ix) = ev_open("manyrows");
        for i in 1..=4000i64 {
            ev_rel(&ix, i, 0, 1, i, 100, "movie", &format!("m:s{i}:2020"), 200);
        }
        ix.compact().unwrap();
        let before = ix.db_bytes().unwrap();
        let target = before / 2;
        let policy = EvictPolicy { order: EvictOrder::Oldest, kinds: vec![] };
        let rep = ix.evict_to(target, &policy, &Protected::default()).unwrap();
        assert!(
            rep.removed > EVICT_PAGE,
            "fixture must force more than one batch, removed {}",
            rep.removed
        );
        let left = ev_ids(&ix);
        assert_eq!(rep.removed, 4000 - left.len());
        // Oldest == id order here, so the survivors are the high ids.
        assert_eq!(left.first().copied(), Some(rep.removed as i64 + 1));
        ix.compact().unwrap();
        let actual = ix.db_bytes().unwrap();
        assert!(actual <= target, "must reach the cap: {actual} > {target}");
        assert!(
            left.len() >= 1000,
            "over-eviction: only {} of 4000 rows left to free half the file",
            left.len()
        );
        teardown(&dir, ix);
    }

    #[test]
    fn evict_estimator_lands_near_the_target_after_compact() {
        let (dir, ix) = ev_open("estim");
        ev_uneven(&ix);
        ix.compact().unwrap();
        let before = ix.db_bytes().unwrap();
        let target = before / 2;
        let rep = ix
            .evict_to(target, &EvictPolicy { order: EvictOrder::Oldest, kinds: vec![] }, &Protected::default())
            .unwrap();
        assert!(rep.removed > 0);
        assert_eq!(
            rep.bytes_after, rep.bytes_before,
            "DELETE does not shorten a SQLite file - that is what needs_compact is for"
        );
        assert!(rep.needs_compact);
        ix.compact().unwrap();
        let actual = ix.db_bytes().unwrap();
        let low = target / EVICT_LOW_WATER_DEN * EVICT_LOW_WATER_NUM;
        println!(
            "estimator: cap {before} -> target {target} (low water {low}), \
             removed {} rows, real post-compact size {actual} = {:.1}% of target",
            rep.removed,
            actual as f64 / target as f64 * 100.0
        );
        // The contract that matters: it got under the cap.
        assert!(actual <= target, "must reach the cap: {actual} > {target}");
        assert!(!ev_ids(&ix).is_empty());

        // MINIMALITY, the assertion that actually guards user data. The
        // landing point sits below the low-water mark, but only because a
        // release is indivisible - the row that crosses the line here is
        // a 256 KB one. Prove that is granularity and not over-eviction
        // by replaying the same fixture with ONE FEWER deletion in the
        // same order: it must still be above the low-water mark, i.e.
        // every row eviction took was a row it had to take.
        let (dir2, ix2) = ev_open("estim-minimal");
        ev_uneven(&ix2);
        ix2.compact().unwrap();
        let keep_one_more: Vec<i64> = (1..rep.removed as i64).collect(); // Oldest = id order
        ix2.prune_batch(&keep_one_more).unwrap();
        ix2.compact().unwrap();
        let one_fewer = ix2.db_bytes().unwrap();
        assert!(
            one_fewer > low,
            "over-eviction: stopping one row earlier ({one_fewer}) would already \
             have been under the low water mark ({low})"
        );
        teardown(&dir, ix);
        teardown(&dir2, ix2);
    }

    fn f1_cats() -> Vec<crate::categories::CustomCategory> {
        vec![crate::categories::CustomCategory {
            slug: "formula-1".into(),
            name: "Formula 1".into(),
            pattern: r"^formula\.?1\.".into(),
            not_match: String::new(),
            base: crate::categories::BaseBehavior::Movie,
        }]
    }

    /// 24D end-to-end at the index level: define a category, ingest
    /// matching releases, see them under the category's kind in browse
    /// AND as separate wall cards (the F1 dedupe lesson).
    #[test]
    fn custom_category_ingest_browse_and_cards() {
        let dir = std::env::temp_dir().join(format!("nzbfast-cats-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut ix = Index::open(&dir.join("index.db")).unwrap();
        ix.set_custom(f1_cats());
        ix.ingest(
            "alt.test",
            &[
                entry("\"Formula1.2026.Round11.Hungary.Qualifying.F1TV.WEB-DL.1080p-MWR.mkv\" yEnc (1/1)", "p@x", "f1", 900 << 20),
                entry("\"Formula1.2026.Round11.Hungary.Post-Qualifying.Show.F1TV.WEB-DL.1080p-MWR.mkv\" yEnc (1/1)", "p@x", "f2", 900 << 20),
                entry("\"The.Matrix.1999.1080p.BluRay.x264-GRP.mkv\" yEnc (1/1)", "p@x", "m1", 900 << 20),
            ],
            100,
        )
        .unwrap();
        // The category's kind filter finds exactly its releases.
        let (f1, total) = ix
            .browse(&BrowseQuery { kind: Some("formula-1".into()), ..Default::default() })
            .unwrap();
        assert_eq!(total, 2, "{f1:?}");
        assert!(f1.iter().all(|r| r.kind == "formula-1"), "{f1:?}");
        // The two sessions keep DISTINCT dedupe keys (pre-24D both were
        // "m:formula1:2026") → two wall cards, and the movie is untouched.
        let keys: std::collections::HashSet<String> = ix
            .search("formula1", 10)
            .unwrap()
            .iter()
            .map(|r| {
                ix.db.query_row(
                    "SELECT title_key FROM releases WHERE id=?1",
                    [r.id],
                    |row| row.get(0),
                )
                .unwrap()
            })
            .collect();
        assert_eq!(keys.len(), 2, "{keys:?}");
        assert!(keys.iter().all(|k| k.starts_with("c:formula-1:")), "{keys:?}");
        let (cards, _) = ix
            .browse_cards(
                &BrowseQuery { kind: Some("formula-1".into()), ..Default::default() },
                CardSort::Latest,
                false,
                false,
                None,
            )
            .unwrap();
        assert_eq!(cards.len(), 2, "{cards:?}");
        assert!(cards.iter().all(|c| c.kind == "formula-1"));
        let (movie, _) = ix
            .browse(&BrowseQuery { kind: Some("movie".into()), ..Default::default() })
            .unwrap();
        assert_eq!(movie.len(), 1);
        assert_eq!(movie[0].kind, "movie");
        // Custom titles get seeded for the wall (pretty names), and the
        // custom key renders readably.
        assert!(ix.seed_missing_titles(365000, 100).unwrap() >= 2);
        assert_eq!(
            pretty_key("c:formula-1:formula1:2026:round11 hungary qualifying f1tv"),
            "Formula1 2026 Round11 Hungary Qualifying F1tv"
        );
        teardown(&dir, ix);
    }

    /// 24D reclassification: rows indexed BEFORE a category existed move
    /// under it when the config changes, the pass is fingerprint-stamped
    /// (unchanged config = no-op), and deleting the category moves them
    /// back to their built-in kind.
    #[test]
    fn reclassify_custom_reconciles_stored_rows() {
        let dir = std::env::temp_dir().join(format!("nzbfast-recat-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut ix = Index::open(&dir.join("index.db")).unwrap();
        // No categories yet: both sessions collapse onto one movie key -
        // the exact pre-24D failure.
        ix.ingest(
            "alt.test",
            &[
                entry("\"Formula1.2026.Round11.Hungary.Qualifying.F1TV.WEB-DL.1080p-MWR.mkv\" yEnc (1/1)", "p@x", "f1", 900 << 20),
                entry("\"Formula1.2026.Round12.Spa.Race.F1TV.WEB-DL.1080p-MWR.mkv\" yEnc (1/1)", "p@x", "f2", 900 << 20),
            ],
            100,
        )
        .unwrap();
        let (rows, _) = ix
            .browse(&BrowseQuery { kind: Some("movie".into()), ..Default::default() })
            .unwrap();
        assert_eq!(rows.len(), 2);
        // Define the category and reconcile.
        ix.set_custom(f1_cats());
        assert_eq!(ix.reclassify_custom().unwrap(), 2);
        // Same config again: fingerprint no-op.
        assert_eq!(ix.reclassify_custom().unwrap(), 0);
        let (rows, _) = ix
            .browse(&BrowseQuery { kind: Some("formula-1".into()), ..Default::default() })
            .unwrap();
        assert_eq!(rows.len(), 2);
        // Delete the category: rows return to the built-in classifier.
        ix.set_custom(Vec::new());
        assert_eq!(ix.reclassify_custom().unwrap(), 2);
        let (rows, _) = ix
            .browse(&BrowseQuery { kind: Some("movie".into()), ..Default::default() })
            .unwrap();
        assert_eq!(rows.len(), 2);
        teardown(&dir, ix);
    }

    /// `Index::open`'s quality_v8 backfill re-parses every stem, and it
    /// runs BEFORE `set_custom` by construction - the constructor
    /// hardcodes an empty category list, so the pass cannot see the
    /// user's categories however the caller is written. Left unguarded it
    /// rewrote every row a custom category had claimed back to the
    /// built-in answer: each F1 session collapsing onto one movie card,
    /// out of the category tab, and losing the Custom junk exemption.
    ///
    /// And it did not heal. `reclassify_custom` reads an unchanged
    /// fingerprint with no cursor and returns Ok(0) on every later start,
    /// so the damage stood until the user happened to edit the category
    /// config. Bumping the kv key - which the comment above the pass
    /// advertises as the ordinary way to backfill a new column - would
    /// re-inflict it on every install.
    #[test]
    fn the_quality_backfill_leaves_custom_classifications_alone() {
        let dir = std::env::temp_dir().join(format!("nzbfast-qv8-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("index.db");
        {
            let mut ix = Index::open(&path).unwrap();
            ix.ingest(
                "alt.test",
                &[
                    entry("\"Formula1.2026.Round11.Hungary.Qualifying.F1TV.WEB-DL.1080p-MWR.mkv\" yEnc (1/1)", "p@x", "f1", 900 << 20),
                    entry("\"Formula1.2026.Round12.Spa.Race.F1TV.WEB-DL.1080p-MWR.mkv\" yEnc (1/1)", "p@x", "f2", 900 << 20),
                    entry("\"The.Matrix.1999.1080p.BluRay.x264-GRP.mkv\" yEnc (1/1)", "p@x", "m1", 900 << 20),
                ],
                100,
            )
            .unwrap();
            ix.set_custom(f1_cats());
            assert_eq!(ix.reclassify_custom().unwrap(), 2, "both sessions claimed");

            // An install whose backfill has not run yet - either it never
            // did, or the key was bumped to pick up a new column.
            ix.db
                .execute("DELETE FROM kv WHERE k IN ('quality_v8','quality_v8_cursor')", [])
                .unwrap();
            // ...and blank a built-in row's resolution, so the pass has
            // something to prove it still does its job.
            ix.db.execute("UPDATE releases SET res='' WHERE kind='movie'", []).unwrap();
        }

        // The next open runs the pass with no categories installed, which
        // is the only state `Index::open` can be in.
        let ix = Index::open(&path).unwrap();
        // Scoped: a live `Statement` borrows the connection, so `teardown`
        // could not take the index while this was still in hand - and the
        // statement holds SQLite resources of its own that want releasing
        // before the connection anyway.
        let rows: Vec<(String, String)> = {
            let mut stmt = ix
                .db
                .prepare(
                    "SELECT kind, title_key FROM releases WHERE stem LIKE 'Formula1%' ORDER BY id",
                )
                .unwrap();
            stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
                .unwrap()
                .collect::<rusqlite::Result<_>>()
                .unwrap()
        };
        assert_eq!(rows.len(), 2);
        for (kind, key) in &rows {
            assert_eq!(kind, "formula-1", "the backfill unclassified a custom row");
            assert!(
                key.starts_with("c:formula-1:"),
                "the backfill rewrote a custom title key to {key:?} - every session of \
                 the season then collapses onto one card"
            );
        }
        // The two sessions must still be SEPARATE cards, which is the
        // whole point of the category.
        assert_ne!(rows[0].1, rows[1].1);

        // ...and the pass still backfilled the built-in row it is for.
        let res: String = ix
            .db
            .query_row("SELECT res FROM releases WHERE kind='movie'", [], |r| r.get(0))
            .unwrap();
        assert_eq!(res, "1080p", "the backfill must still fill built-in rows");

        teardown(&dir, ix);
    }

    /// The fingerprint and the cursor are ONE state transition, and this
    /// is what happens when they are not: an interruption between the two
    /// writes leaves the new config stamped with no cursor, which every
    /// later call reads as "already finished". Reclassification is then
    /// skipped forever - the user's new category never reaches the rows
    /// already in the index, and nothing short of hand-editing `kv` gets
    /// it back.
    ///
    /// The interruption is a trigger that aborts the cursor write rather
    /// than a killed process: same window, made deterministic. What is
    /// asserted is the recovery, not the mechanism - after the failure,
    /// the next call must still have the work to do.
    #[test]
    fn an_interrupted_reclassify_stamp_does_not_declare_the_work_done() {
        let dir = std::env::temp_dir().join(format!("nzbfast-recat-crash-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut ix = Index::open(&dir.join("index.db")).unwrap();
        ix.ingest(
            "alt.test",
            &[
                entry("\"Formula1.2026.Round11.Hungary.Qualifying.F1TV.WEB-DL.1080p-MWR.mkv\" yEnc (1/1)", "p@x", "f1", 900 << 20),
                entry("\"Formula1.2026.Round12.Spa.Race.F1TV.WEB-DL.1080p-MWR.mkv\" yEnc (1/1)", "p@x", "f2", 900 << 20),
            ],
            100,
        )
        .unwrap();

        // Crash the cursor write, leave the fingerprint write alone.
        ix.db
            .execute_batch(
                "CREATE TRIGGER kv_lose_the_cursor BEFORE INSERT ON kv
                   WHEN new.k='custom_cats_cursor'
                   BEGIN SELECT RAISE(ABORT, 'interrupted before the cursor landed'); END;",
            )
            .unwrap();
        ix.set_custom(f1_cats());
        assert!(
            ix.reclassify_custom().is_err(),
            "the interrupted pass must report the failure, not swallow it"
        );
        ix.db.execute_batch("DROP TRIGGER kv_lose_the_cursor").unwrap();

        // The machine is back. The category config is still new to this
        // index, so its rows must still be reclassified.
        assert_eq!(
            ix.reclassify_custom().unwrap(),
            2,
            "a half-written stamp made the index believe it had already \
             reclassified these rows"
        );
        let (rows, _) = ix
            .browse(&BrowseQuery { kind: Some("formula-1".into()), ..Default::default() })
            .unwrap();
        assert_eq!(rows.len(), 2);
        teardown(&dir, ix);
    }
}

#[cfg(test)]
mod obfuscated_posts_are_unindexable {
    /// Why a header-scanning index cannot see a fully obfuscated release,
    /// however many groups it scans.
    ///
    /// Traced from a real one: Supergirl.2026.2160p, which downloaded
    /// perfectly and which DOGnzb lists, but which does not appear in our
    /// index. Every theory about coverage was wrong - the article range WAS
    /// scanned (1,933 neighbours from the same hour are stored), the
    /// neighbours ARE obfuscated so obfuscation alone is not disqualifying,
    /// and servers[0] DOES carry the articles.
    ///
    /// The nzb lies. Its <groups>, subject= and poster= are all indexer
    /// metadata, not what is on the wire. Fetched live from the provider,
    /// the same message-id carries:
    ///
    ///   Newsgroups: alt.binaries.encrypted   (nzb said alt.binaries.teevee)
    ///   Subject:    ZvbiaQJJpLvLZpY          (nzb said "30fb7ada….10" yEnc (1/260))
    ///   From:       wQXbPchc1NPZZqPmbWr5 …   (nzb said e24e6f0f… )
    ///
    /// So it is in a group nobody would index for TV, under a subject with
    /// no filename, no part marker and no relationship to the release. The
    /// indexers that list it are not scanning headers - they hold a
    /// message-id mapping from the uploader.
    #[test]
    fn a_real_obfuscated_subject_carries_nothing_to_index_on() {
        // What the nzb claims: parses fine, which is why this looked
        // indexable right up until the article itself was read.
        let claimed = "\"30fb7ada0c0b15e12135927afe355933.10\" yEnc (1/260)";
        let (base, part, total) = super::split_subject(claimed)
            .unwrap_or_else(|| (claimed.to_string(), 1, 1));
        assert!(part != 0 && total != 0);
        assert!(super::quoted_name(&base).is_some(), "the nzb's version is parseable");

        // What is actually on the wire. ingest() requires a quoted filename
        // and skips the entry without one, so this can never become a row -
        // no filename, no part marker, nothing to key a release on.
        let real = "ZvbiaQJJpLvLZpY";
        let (rbase, _, _) =
            super::split_subject(real).unwrap_or_else(|| (real.to_string(), 1, 1));
        assert!(
            super::quoted_name(&rbase).is_none(),
            "the real subject has no quoted filename, so ingest skips it"
        );
    }

}

#[cfg(test)]
mod multi_server_indexing {
    use super::tests::teardown;
    use crate::index::{BrowseQuery, Index};
    use crate::nntp::OverEntry;

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

    /// A8: a single-server-era marks table (PRIMARY KEY on grp alone)
    /// migrates to the (grp, server) shape with its coverage intact, and
    /// adopt_legacy_marks hands the '' rows to the historical primary
    /// without ever clobbering a row that server has since written.
    #[test]
    fn marks_migrate_to_per_server_and_adoption_never_clobbers() {
        let dir = std::env::temp_dir().join(format!("nzbfast-marksmig-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("index.db");
        {
            // Build the old shape by hand, exactly as v1.0.10 left it.
            let db = rusqlite::Connection::open(&db_path).unwrap();
            db.execute_batch(
                "CREATE TABLE marks(grp TEXT PRIMARY KEY, high INTEGER NOT NULL);
                 ALTER TABLE marks ADD COLUMN low INTEGER NOT NULL DEFAULT 0;
                 INSERT INTO marks(grp, high, low) VALUES('alt.old', 500, 100);
                 INSERT INTO marks(grp, high, low) VALUES('spots:free.pt', 77, 0);",
            )
            .unwrap();
        }
        let ix = Index::open(&db_path).unwrap();
        // Migrated rows are visible to no server until adopted.
        assert_eq!(ix.high_water("alt.old", "news.first.example"), 0);
        ix.adopt_legacy_marks("News.FIRST.Example").unwrap();
        assert_eq!(ix.high_water("alt.old", "news.first.example"), 500);
        assert_eq!(ix.low_water("alt.old", "news.first.example"), 100);
        // Spot marks migrate the same way (they share the table).
        assert_eq!(ix.high_water("spots:free.pt", "news.first.example"), 77);
        // Adoption never clobbers what the server has since written: a
        // straggling legacy row for an already-claimed group is dropped.
        ix.set_high_water("alt.old", "news.first.example", 900).unwrap();
        ix.db
            .execute("INSERT INTO marks(grp, server, high, low) VALUES('alt.old', '', 1, 1)", [])
            .unwrap();
        ix.adopt_legacy_marks("news.first.example").unwrap();
        assert_eq!(ix.high_water("alt.old", "news.first.example"), 900);
        // Idempotent: nothing legacy left.
        ix.adopt_legacy_marks("news.first.example").unwrap();
        // Per-server independence - the whole point of the migration.
        ix.set_high_water("alt.old", "other.example", 42).unwrap();
        assert_eq!(ix.high_water("alt.old", "other.example"), 42);
        assert_eq!(ix.high_water("alt.old", "news.first.example"), 900);
        // A fresh database gets the new shape directly (no rebuild): the
        // reopen must not have bumped anything - just prove reads work.
        drop(ix);
        let ix2 = Index::open(&db_path).unwrap();
        assert_eq!(ix2.high_water("alt.old", "news.first.example"), 900);
        teardown(&dir, ix2);
    }

    /// A8: two servers scanning the same group merge into one release -
    /// message-ids are portable, so a part the first server's spool
    /// never received completes the release when another backbone's
    /// headers land. Overlap must not double-count.
    #[test]
    fn coverage_scans_from_two_servers_merge_and_complete() {
        let dir = std::env::temp_dir().join(format!("nzbfast-covmerge-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut ix = Index::open(&dir.join("index.db")).unwrap();
        let grp = "alt.binaries.teevee";
        // Server A saw parts 1 and 2 of 3 (a propagation hole ate #3).
        let a = [
            entry(r#""Show.S01E02.720p-GRP.mkv" yEnc (1/3)"#, "p@x", "s1e2.p1", 700_000),
            entry(r#""Show.S01E02.720p-GRP.mkv" yEnc (2/3)"#, "p@x", "s1e2.p2", 700_000),
        ];
        ix.ingest(grp, &a, 1_000).unwrap();
        let (r, _) = ix.browse(&BrowseQuery::default()).unwrap();
        assert_eq!(r.len(), 1);
        assert!(!r[0].complete, "two of three parts is incomplete");
        // Server B carries parts 2 and 3 - same message-ids for the
        // overlap, which must merge rather than duplicate.
        let b = [
            entry(r#""Show.S01E02.720p-GRP.mkv" yEnc (2/3)"#, "p@x", "s1e2.p2", 700_000),
            entry(r#""Show.S01E02.720p-GRP.mkv" yEnc (3/3)"#, "p@x", "s1e2.p3", 700_000),
        ];
        let flipped = ix.ingest(grp, &b, 1_000).unwrap();
        assert_eq!(flipped, 1, "the merge is what completes the release");
        let (r, _) = ix.browse(&BrowseQuery::default()).unwrap();
        assert_eq!(r.len(), 1, "still one release, not one per server");
        assert!(r[0].complete);
        let nzb = ix.make_nzb(r[0].id).unwrap();
        let parsed = crate::nzb::Nzb::parse(nzb.as_bytes()).unwrap();
        assert_eq!(
            parsed.files.iter().map(|f| f.segments.len()).sum::<usize>(),
            3,
            "the overlapping part must not be emitted twice"
        );
        teardown(&dir, ix);
    }

    /// A8 gap-fill pick: only incomplete, junk-gated, settled releases
    /// are worth re-hunting, and the stamp rotates the pick.
    #[test]
    fn gapfill_pick_gates_and_rotates() {
        let dir = std::env::temp_dir().join(format!("nzbfast-gapfill-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut ix = Index::open(&dir.join("index.db")).unwrap();
        let grp = "alt.binaries.teevee";
        let now = 1_000_000i64;
        let old = now - 100_000;
        // Eligible: incomplete, seen long ago.
        ix.ingest(grp, &[entry(r#""Old.Show.S01E01.720p-GRP.mkv" yEnc (1/2)"#, "p@x", "old.p1", 300_000_000)], old)
            .unwrap();
        // Complete: nothing to hunt.
        ix.ingest(grp, &[entry(r#""Done.Show.S01E01.720p-GRP.mkv" yEnc (1/1)"#, "p@x", "done.p1", 300_000_000)], old)
            .unwrap();
        // Too fresh: parts are usually still propagating.
        ix.ingest(grp, &[entry(r#""New.Show.S01E01.720p-GRP.mkv" yEnc (1/2)"#, "p@x", "new.p1", 300_000_000)], now - 60)
            .unwrap();
        // Junk-hidden: must not eat the budget.
        ix.ingest(grp, &[entry(r#""Junky.Show.S01E01.720p-GRP.mkv" yEnc (1/2)"#, "p@x", "junk.p1", 300_000_000)], old)
            .unwrap();
        ix.db
            .execute("UPDATE releases SET junk=90 WHERE stem LIKE 'Junky%'", [])
            .unwrap();
        let picks = ix.gapfill_pick(10, now).unwrap();
        assert_eq!(picks.len(), 1, "only the settled incomplete release qualifies");
        let (id, g, posted) = &picks[0];
        assert_eq!(g, grp);
        assert_eq!(*posted, old);
        assert!(!ix.is_complete(*id) );
        // The stamp rotates: a marked release yields to unmarked ones.
        ix.ingest(grp, &[entry(r#""Also.Old.S01E01.720p-GRP.mkv" yEnc (1/2)"#, "p@x", "also.p1", 300_000_000)], old)
            .unwrap();
        ix.gapfill_mark(*id, now).unwrap();
        let picks2 = ix.gapfill_pick(1, now).unwrap();
        assert_eq!(picks2.len(), 1);
        assert_ne!(picks2[0].0, *id, "the stamped release rotates to the back");
        teardown(&dir, ix);
    }}

//! Scene release-name parsing (moved from nzbfast's wall module so the
//! indexer can classify releases at ingest - M25 browse view).
//!
//! Pure text → structured facts: title / year / SxxEyy / resolution /
//! source / language / release group, plus a dedupe key so five encodes
//! of one film group under one card. Handles ROT13/ROT18-obfuscated
//! stems, software posts, daily datecodes, and hyphen-separated stems.

// ---------------------------------------------------------------------------
// Release-name parsing
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    Movie,
    Tv,
    /// Software / installer posts (version tokens, keygen vocabulary) -
    /// never enriched, shown only under the wall's "Other" tab.
    Software,
    /// Music posts - scene albums ("Artist-Album-2021-GROUP") and the
    /// tagged form ("Artist - Album (2021) [FLAC]"). `title` carries
    /// "Artist - Album" so the card reads correctly before any provider
    /// answers; `credit_split` recovers the two halves for MusicBrainz.
    Music,
    /// Books / ebooks ("Author - Title (2019) [epub]"). Same
    /// "Credit - Work" title convention as Music.
    Book,
    /// Obfuscated / unparseable - hidden from the wall by default.
    Other,
    /// A user-defined category (TODO 24D): the slug is the stored `kind`
    /// value ("formula-1"). Never produced by `parse_release` itself -
    /// only `categories::classify` / `apply_custom` rewrite a parse into
    /// this, so the pure parser stays rule-free. Completion behavior
    /// (junk sweep / rename) comes from the category's declared
    /// `BaseBehavior`, resolved via `categories::base_of` - a custom kind
    /// is NEVER implicitly movie-like.
    Custom(String),
}

#[derive(Debug, Clone)]
pub struct Parsed {
    pub kind: Kind,
    pub title: String,
    pub year: Option<u32>,
    pub season: Option<u32>,
    pub episode: Option<u32>,
    /// Second episode of a multi-episode post ("S01E01E02" /
    /// "S01E01-E02") - the covered range is episode..=episode2.
    pub episode2: Option<u32>,
    /// "2160p", "1080p", …
    pub res: Option<String>,
    pub remux: bool,
    /// "BluRay" / "WEB" / "HDTV" / "DVD"
    pub source: Option<String>,
    /// Video codec, friendly form: "x265" / "x264" / "AV1" / "XviD" / …
    pub vcodec: Option<String>,
    /// Audio codec, friendly form (strongest track wins): "Atmos" /
    /// "TrueHD" / "DTS-HD" / "DDP" / "AC3" / "AAC" / …
    pub acodec: Option<String>,
    /// Dynamic range, friendly form: "DV" / "HDR10+" / "HDR10" / "HDR" /
    /// "HLG". A DV release almost always carries an HDR10 base layer and
    /// says so, so the richest format wins rather than the first seen.
    /// None = the name said nothing (or said SDR, which is the absence).
    pub hdr: Option<String>,
    /// Audio-language tags found in the stem ("german", "multi", …).
    /// Empty = untagged, which by scene convention means English.
    pub langs: Vec<String>,
    pub group: Option<String>,
    /// Identity-bearing tokens the title had to drop: what sits between
    /// a movie year and the first piece of release furniture. Empty for
    /// an ordinary film, whose year is followed straight by quality tags
    /// ("The.Matrix.1999.1080p.BluRay"). Non-empty for event posts, where
    /// the year is only the SEASON and the real identity comes after it
    /// ("Formula1.2026.Round11.Hungary.Post-Qualifying.Show.…" → Round11,
    /// Hungary, Post-Qualifying, Show). A non-empty `extra` means
    /// "title + year" is NOT a faithful reduction of this release.
    pub extra: Vec<String>,
    /// The episode DATE of a daily-dated post, normalized to
    /// "yyyymmdd" - the identity of a match, a race, a show of that day.
    /// Set for both conventions the parser knows ("At.Midnight.150615"
    /// and "The.Daily.Show.2026.07.21"); None for everything else.
    ///
    /// The built-in TV key deliberately ignores it (a show's episodes
    /// all group under one card), but without it stored, nothing
    /// downstream could tell two days of a dated post apart - which is
    /// how a whole football season keyed onto one identity.
    pub date: Option<String>,
    /// Dedupe key: movies "m:<title>:<year>", tv "t:<title>" (a show's
    /// seasons and episodes all group under one card).
    pub key: String,
    /// True when this parse came from the ROT13/ROT18 rescue - the raw
    /// stem on the wire is rotated gibberish and `title` is the decoded
    /// name (UIs can show the readable form).
    pub rescued: bool,
}

fn is_year(tok: &str) -> bool {
    tok.len() == 4 && tok.chars().all(|c| c.is_ascii_digit()) && {
        let y: u32 = tok.parse().unwrap_or(0);
        (1900..2100).contains(&y)
    }
}

/// SxxEyy / Sxx / NxNN → (season, episode, second episode of a
/// multi-episode marker - "S01E01E02" / "S01E01-E02" / "S01E01-02").
fn tv_marker(tok: &str) -> Option<(u32, Option<u32>, Option<u32>)> {
    let t = tok.to_ascii_lowercase();
    if let Some(rest) = t.strip_prefix('s') {
        let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        // 1-2 digit seasons, plus year-as-season ("S2026E015" - annual
        // sports/soaps) when an episode follows; bare "S2026" stays a
        // year, not a season pack.
        let year_season = digits.len() == 4
            && is_year(&digits)
            && rest[digits.len()..].starts_with('e');
        if digits.is_empty() || (digits.len() > 2 && !year_season) {
            return None;
        }
        let season = digits.parse().ok()?;
        let after = &rest[digits.len()..];
        if after.is_empty() {
            return Some((season, None, None)); // season pack
        }
        if let Some(ep) = after.strip_prefix('e') {
            let ed: String = ep.chars().take_while(|c| c.is_ascii_digit()).collect();
            if !ed.is_empty() && ed.len() <= 3 {
                let e1: u32 = ed.parse().ok()?;
                // Double-episode tail: "e02", "-e02" or "-02" right after
                // the first episode's digits, and the token must END
                // there ("s01e01-720p" is quality furniture, not E720).
                // Only a HIGHER number counts - "E05-E03" is a typo, not
                // a range.
                let tail = &ep[ed.len()..];
                let tail = tail.strip_prefix('-').unwrap_or(tail);
                let tail = tail.strip_prefix('e').unwrap_or(tail);
                let e2 = ((2..=3).contains(&tail.len())
                    && tail.bytes().all(|c| c.is_ascii_digit()))
                .then(|| tail.parse::<u32>().ok())
                .flatten()
                .filter(|&e2| e2 > e1);
                return Some((season, Some(e1), e2));
            }
        }
        return None;
    }
    // Bare episode marker "E06" (season unknown).
    if let Some(ed) = t.strip_prefix('e') {
        if (2..=3).contains(&ed.len()) && ed.chars().all(|c| c.is_ascii_digit()) {
            return Some((0, ed.parse().ok(), None));
        }
    }
    // 3x07 form.
    if let Some((s, e)) = t.split_once('x') {
        if !s.is_empty()
            && s.len() <= 2
            && s.chars().all(|c| c.is_ascii_digit())
            && (2..=3).contains(&e.len())
            && e.chars().all(|c| c.is_ascii_digit())
        {
            return Some((s.parse().ok()?, e.parse().ok(), None));
        }
    }
    None
}

/// Token ends the title region / marks release furniture.
fn is_tag(tok: &str) -> bool {
    const TAGS: &[&str] = &[
        // resolution
        "2160p", "1080p", "1080i", "720p", "576p", "480p", "4k", "uhd",
        // source
        "bluray", "blu", "bdrip", "brrip", "remux", "web", "web-dl", "webdl",
        "dl", "webrip", "hdtv", "dvdrip", "dvd", "hddvd", "hdrip", "camrip",
        "ts",
        // codec
        "x264", "x265", "h264", "h265", "h", "hevc", "avc", "av1", "xvid",
        "divx", "vc-1", "vc1",
        // audio
        "dts", "dts-hd", "dtshd", "dts-x", "dtsx", "truehd", "atmos", "aac",
        "ac3", "eac3", "dd5", "ddp", "ddp5", "flac", "opus", "mp3", "ma",
        // misc release furniture
        "proper", "repack", "rerip", "extended", "unrated", "internal",
        "limited", "complete", "multi", "dual", "subbed", "dubbed", "vostfr",
        "hdr", "hdr10", "hdr10+", "dv", "dovi", "sdr", "imax", "remastered",
        "criterion", "3d", "10bit", "8bit", "retail", "readnfo", "hybrid",
        "season", "series", "amzn", "nf", "dsnp", "hulu", "atvp", "max",
        // sibling-file noise (nfo/sfv/samples post as their own "releases")
        "nfo", "sfv", "srr", "srs", "sample", "proof", "subs", "par2", "nzb",
        "rar", "mkv", "mp4", "avi", "m2ts", "iso", "img", "jpg", "png", "txt",
        "diz", "vob",
        // language / region / broadcast furniture
        "german", "french", "dutch", "spanish", "italian", "swedish",
        "danish", "norwegian", "flemish", "nordic", "english", "pal", "ntsc",
        "dvdr", "pdtv", "sdtv", "ws", "nlsubbed", "dl-subbed",
    ];
    TAGS.contains(&tok.to_ascii_lowercase().as_str())
}

fn res_of(tok: &str) -> Option<&'static str> {
    match tok.to_ascii_lowercase().as_str() {
        "2160p" | "4k" | "uhd" => Some("2160p"),
        "1080p" | "1080i" => Some("1080p"),
        "720p" => Some("720p"),
        "576p" => Some("576p"),
        "480p" => Some("480p"),
        _ => None,
    }
}

fn source_of(tok: &str) -> Option<&'static str> {
    match tok.to_ascii_lowercase().as_str() {
        "bluray" | "blu" | "bdrip" | "brrip" => Some("BluRay"),
        "web" | "web-dl" | "webdl" | "webrip" => Some("WEB"),
        "hdtv" => Some("HDTV"),
        "dvdrip" | "dvd" => Some("DVD"),
        _ => None,
    }
}

/// Audio-language markers only - subtitle tags (VOSTFR, NLSUBBED) keep
/// the original audio, so they don't name a language here. Only checked
/// AFTER the title region, so a film titled "Rus" stays untagged.
fn lang_of(tok: &str) -> Option<&'static str> {
    match tok.to_ascii_lowercase().as_str() {
        "german" | "ger" => Some("german"),
        "french" | "fre" | "fra" => Some("french"),
        "dutch" | "flemish" => Some("dutch"),
        "spanish" | "castellano" | "latino" => Some("spanish"),
        "italian" | "ita" => Some("italian"),
        "swedish" => Some("swedish"),
        "danish" => Some("danish"),
        "norwegian" => Some("norwegian"),
        "nordic" => Some("nordic"),
        "korean" | "kor" => Some("korean"),
        "japanese" | "jpn" => Some("japanese"),
        "chinese" | "mandarin" | "cantonese" => Some("chinese"),
        "russian" | "rus" => Some("russian"),
        "polish" => Some("polish"),
        "hungarian" => Some("hungarian"),
        "czech" => Some("czech"),
        "turkish" => Some("turkish"),
        "finnish" => Some("finnish"),
        "hindi" => Some("hindi"),
        "portuguese" => Some("portuguese"),
        "english" | "eng" => Some("english"),
        "multi" | "dual" => Some("multi"),
        _ => None,
    }
}

/// Video codec token → friendly display form. x264/x265 are the encoder
/// names scene encodes use; h264/avc and h265/hevc fold onto them so the
/// rendered name stays consistent whether the post said "x265" or "HEVC".
fn vcodec_of(tok: &str) -> Option<&'static str> {
    match tok.to_ascii_lowercase().as_str() {
        "x265" | "h265" | "hevc" => Some("x265"),
        "x264" | "h264" | "avc" => Some("x264"),
        "av1" => Some("AV1"),
        "xvid" => Some("XviD"),
        "divx" => Some("DivX"),
        "vc-1" | "vc1" => Some("VC-1"),
        _ => None,
    }
}

/// Audio codec token → (priority, friendly form). A release lists several
/// tracks ("AC3 … DTS-HD"); we surface the strongest, so the caller keeps
/// the highest-priority match rather than the first seen.
fn acodec_of(tok: &str) -> Option<(u8, &'static str)> {
    match tok.to_ascii_lowercase().as_str() {
        "atmos" => Some((100, "Atmos")),
        "truehd" => Some((90, "TrueHD")),
        "dts-x" | "dtsx" => Some((85, "DTS-X")),
        "dts-hd" | "dtshd" => Some((80, "DTS-HD")),
        "dts" => Some((70, "DTS")),
        "ddp" | "ddp5" | "eac3" => Some((60, "DDP")),
        "dd5" | "ac3" => Some((50, "AC3")),
        "flac" => Some((45, "FLAC")),
        "aac" => Some((40, "AAC")),
        "opus" => Some((35, "Opus")),
        "mp3" => Some((30, "MP3")),
        _ => None,
    }
}

/// Dynamic-range token → (priority, friendly form). Dolby Vision is
/// shipped as a layer on top of HDR10, so a DV release names both; the
/// caller keeps the highest priority rather than the first seen. "SDR"
/// deliberately maps to nothing: it states the absence, and recording it
/// would make a plain encode look like it carries a format.
fn hdr_of(tok: &str) -> Option<(u8, &'static str)> {
    match tok.to_ascii_lowercase().as_str() {
        "dv" | "dovi" | "dolbyvision" => Some((100, "DV")),
        "hdr10+" | "hdr10plus" => Some((80, "HDR10+")),
        "hdr10" => Some((70, "HDR10")),
        "hdr" => Some((60, "HDR")),
        "hlg" => Some((50, "HLG")),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Token roles after the identity marker
//
// Everything a release name puts AFTER its year is either furniture
// (quality/source/codec/edition/group - the stuff that must NOT tell two
// downloads apart) or identity (the round, stage, week, session or event
// that makes this post a different thing from the last one). Callers that
// need to know which is which - the friendly rename, the downloader's
// dupe key - share this one verdict.
// ---------------------------------------------------------------------------

/// What a token sitting after a release's year contributes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenRole {
    /// Quality / source / codec / container / edition / provenance noise.
    /// Nothing from here to the end of the stem identifies the release,
    /// so a scan can stop at the first one.
    HardFurniture,
    /// Language and region markers. On their own they are furniture (the
    /// same film dubbed twice is still one film), but they must not END
    /// the identity region - "…2026.Hungarian.Grand.Prix.Race…" would
    /// otherwise lose the whole event name to one language tag.
    SoftFurniture,
    /// Part of what makes this release itself.
    Identity,
}

/// Furniture that neither `is_tag` nor the codec tables carry. Only ever
/// consulted for tokens AFTER the year, so title words are never at risk:
/// a film called "Cut" or "Ultimate" still parses by its leading tokens.
const HARD_EXTRA: &[&str] = &[
    // audio spellings TAGS doesn't list ("DD.5.1" splits to a bare "dd")
    "dd", "dd2", "dd7", "ddp7", "dtsma", "lpcm", "pcm", "mp2", "ac4",
    // edition markers ("Director's Cut", "Ultimate Edition", "Uncut")
    "directors", "director", "theatrical", "uncut", "uncensored",
    "restored", "anniversary", "collectors", "collector", "definitive",
    "ultimate", "edition", "cut", "dc",
    // print provenance
    "int", "scr", "screener", "dvdscr", "r5", "tc", "telesync", "telecine",
    "cam", "hdcam", "workprint", "hc", "korsub", "cd",
    // resolution / colour words TAGS doesn't list
    "hd", "fhd", "qhd", "sd", "ultra", "hdr10plus", "hlg", "12bit", "vp9",
    // broadcast platforms beyond the TAGS set
    "hmax", "pcok", "ip",
];

/// Dub / subtitle markers the language table doesn't carry.
const SOFT_EXTRA: &[&str] = &["truefrench", "vff", "vfq", "vfi", "vf", "vo", "subfrench"];

fn is_hard_furniture(t: &str) -> bool {
    if is_tag(t)
        || res_of(t).is_some()
        || source_of(t).is_some()
        || vcodec_of(t).is_some()
        || acodec_of(t).is_some()
        || HARD_EXTRA.contains(&t)
    {
        return true;
    }
    // A SECOND four-digit year is furniture: the identity marker was the
    // first one ("Blade.Runner.2049.2017.2160p" keys on 2049).
    if is_year(t) {
        return true;
    }
    // Counted furniture with the number in front ("6ch", "60fps", "v2").
    let counted = |n: &str| !n.is_empty() && n.bytes().all(|c| c.is_ascii_digit());
    t.strip_suffix("ch").or_else(|| t.strip_suffix("fps")).is_some_and(counted)
        || t.strip_prefix('v').is_some_and(|n| n.len() <= 2 && counted(n))
}

/// Role of a token that follows a release's identity marker.
pub fn token_role(tok: &str) -> TokenRole {
    let t = tok.to_ascii_lowercase();
    // Languages first: several of them ("german", "english") are also in
    // TAGS, and for identity purposes the softer verdict has to win.
    if lang_of(&t).is_some() || SOFT_EXTRA.contains(&t.as_str()) {
        return TokenRole::SoftFurniture;
    }
    if is_hard_furniture(&t) {
        return TokenRole::HardFurniture;
    }
    // A known tag with a channel count glued on ("AAC5", "DTS5", "DDP51").
    // Trailing digits alone never decide - stripping them leaves nothing
    // for a bare number, so "Round11" / "Week05" / "Stage11" stay identity.
    let stem = t.trim_end_matches(|c: char| c.is_ascii_digit());
    if stem.len() < t.len() && !stem.is_empty() && is_hard_furniture(stem) {
        return TokenRole::HardFurniture;
    }
    TokenRole::Identity
}

/// The identity tokens between a release's year and its furniture, in
/// order. Stops at the first piece of hard furniture; language tags are
/// carried along but a run of NOTHING but language tags is furniture too
/// ("Der.Film.2019.German.DL.1080p" is still one film, so it must reduce
/// to nothing here).
pub fn identity_tail<'a, I: IntoIterator<Item = &'a str>>(after_year: I) -> Vec<&'a str> {
    let mut tail: Vec<&str> = Vec::new();
    let mut any_ident = false;
    for tok in after_year {
        match token_role(tok) {
            TokenRole::HardFurniture => break,
            TokenRole::SoftFurniture => tail.push(tok),
            TokenRole::Identity => {
                any_ident = true;
                tail.push(tok);
            }
        }
    }
    if any_ident { tail } else { Vec::new() }
}

/// Junk a reposter appends AFTER the real group tag
/// ("…x264-GRP-Obfuscated", "…-Rakuvfinhel"). Matched whole, so a group
/// that merely contains one of the words ("-RPGroup") is not one of these.
fn is_reposter_tag(tag: &str) -> bool {
    const TAGS: &[&str] = &[
        "obfuscated", "obfuscation", "scrambled", "sample", "postbot",
        "xpost", "buymore", "asrequested", "alternativetorequested",
        "gerov", "z0ids3n", "chamele0n", "4planet", "altezachen",
        "repackpost", "nzbgeek", "rp",
    ];
    let low = tag.to_ascii_lowercase();
    TAGS.contains(&low.as_str())
        || (low.starts_with("rakuv")
            && low[5..].chars().all(|c| c.is_ascii_alphanumeric()))
}

/// Strip those tags off the end of a stem. Repeatedly: they chain
/// ("…-GRP-xpost-Obfuscated"). A stem that is nothing but tags strips to
/// empty, which leaves the parse with no group at all - the caller keeps
/// the stem as posted. Bare "-1" is deliberately not in the list, too many
/// real groups and part numbers end that way.
fn strip_reposter_tags(stem: &str) -> &str {
    let mut s = stem;
    while let Some((head, tag)) = s.rsplit_once('-') {
        if !is_reposter_tag(tag.trim()) {
            break;
        }
        s = head.trim_end_matches(['.', '_', ' ']);
    }
    s
}

/// Release-group tag: the text after the LAST hyphen when it reads as a
/// group rather than release furniture ("…x264-FGT" → "FGT", but
/// "…WEB-DL" → None). Returns the body with the tag removed, and the tag.
fn split_group(stem: &str) -> (&str, Option<&str>) {
    let stem = strip_reposter_tags(stem);
    match stem.rsplit_once('-') {
        Some((b, g)) => {
            let g = g.trim();
            let ok = (2..=20).contains(&g.len())
                && g.chars().all(|c| c.is_ascii_alphanumeric())
                && !g.chars().all(|c| c.is_ascii_digit())
                && !is_tag(g)
                && res_of(g).is_none();
            if ok { (b, Some(g)) } else { (stem, None) }
        }
        None => (stem, None),
    }
}

/// Just the release-group tag - see `split_group`. Exposed so the
/// downloader's dupe key can drop a group tag it would otherwise mistake
/// for part of an event name.
pub fn group_of(stem: &str) -> Option<&str> {
    split_group(stem).1
}

/// Obfuscated stems: hex hashes, base64-ish blobs - nothing to present.
/// pub(crate): the index's junk score reuses the same verdict (M28).
pub fn looks_obfuscated(stem: &str) -> bool {
    let toks: Vec<&str> = stem
        .split(['.', '_', ' ', '-'])
        .filter(|t| !t.is_empty())
        .collect();
    if toks.is_empty() {
        return true;
    }
    // All tokens long hex → hash name ("2137d880a074…").
    if toks.iter().all(|t| t.len() >= 8 && t.chars().all(|c| c.is_ascii_hexdigit())) {
        return true;
    }
    // Fixed-width HEX blob the whole way across ("d41d8cd98f00b204…"):
    // md5-shaped renames that carry no digits and only a capital or two,
    // so every rule below misses them. Anchored on the whole stem, which
    // means a real title cannot match - titles carry separators.
    //
    // Hex, not alnum: an md5 is hex by definition, and the wider test
    // swallowed a 32-character concatenated title
    // ("ThelordoftheringsReturnoftheking") that every other rule here
    // deliberately passes.
    if stem.len() == 32 && stem.chars().all(|c| c.is_ascii_hexdigit()) {
        return true;
    }
    if toks.len() != 1 {
        return false;
    }
    // Single token with no letters at all ("141444") is nothing to present.
    if !toks[0].chars().any(|c| c.is_ascii_alphabetic()) {
        return true;
    }
    // Single mixed-alnum blob with digits ("n1iY94U6fTpMVY9GPD", "2EBoCStAISS").
    if toks[0].len() >= 10
        && toks[0].chars().any(|c| c.is_ascii_digit())
        && toks[0].chars().all(|c| c.is_ascii_alphanumeric())
    {
        return true;
    }
    // Digit-free blob with scattered internal capitals ("MQHeRbSCIoPs",
    // "jvfrZItzZsNF") - real one-word titles cap the first letter only
    // ("Inception"), and even "RoboCop" has just one internal cap.
    if toks[0].len() >= 10
        && toks[0]
            .chars()
            .skip(1)
            .filter(|c| c.is_ascii_uppercase())
            .count()
            >= 3
    {
        return true;
    }
    // Long single-case alphabetic blob ("nzqymzflnjiyztgyntcynzzytq") -
    // lowercase base32 output, which carries no digits and no internal
    // capitals so every rule above misses it. Twenty characters is past
    // any one-word title anybody posts, and the cost of being wrong here
    // is one wasted article fetch.
    toks[0].len() >= 20
        && toks[0].chars().all(|c| c.is_ascii_alphabetic())
        && (toks[0].chars().all(|c| c.is_ascii_lowercase())
            || toks[0].chars().all(|c| c.is_ascii_uppercase()))
}

/// Does this string read as a RELEASE NAME rather than a human title or
/// a muxer's own furniture?
///
/// The question is asked of strings that arrive from outside the posted
/// name - a container's Title tag, a naming oracle's canonical name -
/// and the bar is deliberately high, because a wrong answer renames the
/// user's file. "Sintel" and "Episode 3" are titles, not releases;
/// "Big.Buck.Bunny.2008.1080p.BluRay.x264-GRP" is a release.
///
/// The test is the parser's own furniture, counted: a release name
/// carries at least two independent scene signals, and the muxers that
/// write a plain human title carry none of them. `looks_obfuscated`
/// keeps out the hash-shaped strings a reposter may have written there
/// instead.
pub fn looks_like_release_name(s: &str) -> bool {
    let s = s.trim();
    // Long enough to be a name, short enough to be a filename stem.
    if !(6..=180).contains(&s.len()) || looks_obfuscated(s) {
        return false;
    }
    // A path, or a filename with its extension still on it, is not a
    // release name - it is a member of one, and using it would file the
    // payload under a container name.
    if s.contains('/') || s.contains('\\') {
        return false;
    }
    let p = parse_release(s);
    if p.title.trim().is_empty() {
        return false;
    }
    let signals = [
        p.year.is_some(),
        p.res.is_some(),
        p.source.is_some(),
        p.group.is_some(),
        p.season.is_some() || p.episode.is_some() || p.date.is_some(),
        p.vcodec.is_some(),
        p.remux,
    ]
    .iter()
    .filter(|b| **b)
    .count();
    signals >= 2
}

/// Software / non-video posts ("CCleaner Professional Plus v6.36.11041
/// x64 Setup"): returns the index of the first software marker, which
/// doubles as the title cut point. A version token or a strong keyword
/// decides alone; weak installer vocabulary needs two hits so movie
/// titles containing "Setup" or "The Professional" survive.
fn software_marker(toks: &[&str]) -> Option<usize> {
    let strong = |t: &str| {
        matches!(t, "keygen" | "keymaker" | "activator" | "preactivated" | "regged")
    };
    // Weak vocabulary splits in two: "namey" words are usually part of
    // the product name itself ("Office Professional Plus") and stay in
    // the title; "furniture" words ("Incl", "x64", "Setup") end it.
    let namey = |t: &str| matches!(t, "pro" | "plus" | "professional" | "edition");
    let furniture = |t: &str| {
        matches!(
            t,
            "crack" | "cracked" | "patch" | "serial" | "portable" | "installer"
                | "setup" | "x64" | "x86" | "win32" | "win64" | "windows"
                | "macos" | "linux" | "multilingual" | "software" | "incl"
                | "build"
        )
    };
    // "v6.36" as one token, or "v6" whose dot-split successor is a bare
    // number ("v6" "36" "11041") - but never "v2" followed by a year or
    // a word, which is how a title would use it.
    let version = |i: usize, t: &str| {
        t.len() >= 2
            && t.starts_with('v')
            && t[1..].chars().all(|c| c.is_ascii_digit() || c == '.')
            && t[1..].chars().any(|c| c.is_ascii_digit())
            && (t[1..].contains('.')
                || toks.get(i + 1).is_some_and(|n| {
                    !n.is_empty()
                        && n.chars().all(|c| c.is_ascii_digit())
                        && !is_year(n)
                }))
    };
    let mut first_furniture: Option<usize> = None;
    let mut weak_hits = 0;
    for (i, t) in toks.iter().enumerate() {
        let lt = t.to_ascii_lowercase();
        if strong(&lt) || version(i, &lt) {
            // Cut at the earliest furniture marker ("Some.App.Incl.
            // Keygen" → "Some App"), else at the strong marker itself.
            return Some(first_furniture.map_or(i, |w| w.min(i)));
        }
        if namey(&lt) {
            weak_hits += 1;
        } else if furniture(&lt) {
            weak_hits += 1;
            first_furniture.get_or_insert(i);
        }
    }
    // Without a strong marker, two weak hits decide - but at least one
    // must be furniture, or "Pro" and "Plus" in a film title would do it.
    (weak_hits >= 2).then_some(first_furniture).flatten()
}

// ---------------------------------------------------------------------------
// Music and book posts
//
// Usenet carries a great deal of both. Until these kinds existed such a
// post was guessed at by the film rules - an album usually came out
// `Movie` with the artist and title mashed into one name - and no
// provider that knows about albums or books was ever consulted, so the
// card could never be more than a bare stem.
//
// Detection is deliberately conservative: a format marker alone
// decides, but ONLY when the stem carries no video evidence at all. A
// concert BluRay says FLAC too, and it is not an album - measured on a
// live index, 191 of the 221 FLAC-bearing stems were video remuxes.
// ---------------------------------------------------------------------------

/// Audio-format markers strong enough to call a post music on their own.
/// Deliberately excludes the tokens a video release legitimately carries
/// as its audio track (AAC, AC3, DTS, Opus): those name one stream
/// inside a film, not the whole payload. FLAC and MP3 are on the list
/// because the video releases that carry them are excluded earlier, by
/// the no-video-evidence gate.
fn audio_marker(tok: &str) -> bool {
    matches!(
        tok,
        "flac" | "mp3" | "m4a" | "alac" | "aiff" | "wavpack" | "webflac"
            | "web-flac" | "ogg" | "wma" | "24bit" | "cdda" | "cdm" | "cds"
            | "cdr" | "vinyl" | "vbr" | "320kbps" | "256kbps" | "192kbps"
            | "128kbps"
    )
}

/// Ebook-format markers. `cbr` is deliberately absent: it means both
/// "comic book RAR" and "constant bit rate", so it would drag albums
/// into the book lane.
fn book_marker(tok: &str) -> bool {
    matches!(
        tok,
        "epub" | "epub3" | "mobi" | "azw" | "azw3" | "fb2" | "djvu" | "cbz"
            | "ebook" | "ebooks" | "audiobook" | "audiobooks"
    )
}

/// True when the stem shows no sign of being a video release. Music and
/// book detection is gated on this, so a concert BluRay ("…2019.1080p.
/// BluRay.FLAC…") stays a movie and an episode stays TV no matter what
/// audio format it names.
fn no_video_evidence(
    res: &Option<String>,
    vcodec: &Option<String>,
    source: &Option<String>,
    remux: bool,
    season: Option<u32>,
    daily: bool,
) -> bool {
    res.is_none()
        && vcodec.is_none()
        && !remux
        && season.is_none()
        && !daily
        // WEB is not video evidence - "WEB" and "WEB-FLAC" are how a
        // digital-store album is tagged. Every other source is a
        // physical or broadcast VIDEO medium.
        && !matches!(source.as_deref(), Some("BluRay") | Some("HDTV") | Some("DVD"))
}

/// Index of the first music/book format marker (the title cut point),
/// searched from index 1 so a release whose FIRST word happens to be one
/// of these ("Vinyl.S01E01…", a film called "Ebook") keeps its title.
/// Books are checked first: an audiobook says both "audiobook" and
/// "MP3", and OpenLibrary is the provider that knows it.
fn media_marker(toks: &[&str]) -> Option<(Kind, usize)> {
    let mut audio: Option<usize> = None;
    for (i, t) in toks.iter().enumerate().skip(1) {
        let lt = t.to_ascii_lowercase();
        // A marker can ride inside a hyphenated token ("WEB-FLAC").
        for part in std::iter::once(lt.as_str()).chain(lt.split('-')) {
            if book_marker(part) {
                return Some((Kind::Book, i));
            }
            if audio.is_none() && audio_marker(part) {
                audio = Some(i);
            }
        }
    }
    audio.map(|i| (Kind::Music, i))
}

/// The scene's music convention is field-structured in a way the normal
/// tokenizer cannot see: hyphens separate FIELDS and underscores stand
/// in for spaces ("Pink_Floyd-The_Dark_Side_Of_The_Moon-1973-EOS"), so
/// splitting on `.`/`_`/` ` alone glues the year onto the last title
/// word ("Moon-1973") and the release reads as one long movie name.
///
/// Fires on `body` (the stem with its group tag already removed) when
/// the fields are hyphen-separated, carry no video evidence, and either
///
/// - a bare year appears from the third field on AND the body uses
///   underscores for spaces - the `Artist-Album-YEAR-GROUP` shape. Not
///   "the LAST field": scene stems trail furniture behind the year
///   ("…-2011-REMASTERED-GRP"); or
/// - a music/book format marker appears from the third field on -
///   `Artist-Album-CD-FLAC-2019-GROUP`.
///
/// The underscore requirement is what keeps `the-matrix-1999-FGT` a
/// film: a fully hyphenated stem with no underscore anywhere is the
/// downloader's own lowercase movie convention, and it has exactly the
/// same field count and trailing year. The cost is that a scene album
/// whose artist AND title are both single words ("Adele-30-2021-C4")
/// is not recognised by this rule - it has no underscore to prove the
/// convention - and falls through to the movie path as it does today.
fn scene_media(body: &str) -> Option<(Kind, String, String, Option<u32>)> {
    if body.contains(['.', ' ']) {
        return None;
    }
    let mut fields: Vec<&str> = body.split('-').filter(|f| !f.is_empty()).collect();
    // Scene music leads with a disc/track number field, which is how the
    // sidecars and the individual tracks of an album are numbered
    // ("00-piero_piccioni-the_light_at_the_edge_of_the_world-cd-flac-2014",
    // "101-chris_brown-run_it"). Measured on a live index: leaving it in
    // made the artist "00" and the album the artist's name.
    if fields.len() > 3
        && (1..=3).contains(&fields[0].len())
        && fields[0].bytes().all(|c| c.is_ascii_digit())
    {
        fields.remove(0);
    }
    if fields.len() < 3 {
        return None;
    }
    // Any video marker anywhere disqualifies: "the-flash-s01e01-720p"
    // has this exact field shape and is an episode.
    fn word_of(f: &str) -> Vec<&str> {
        f.split('_').filter(|w| !w.is_empty()).collect()
    }
    for f in &fields {
        for w in word_of(f) {
            let lw = w.to_ascii_lowercase();
            if tv_marker(&lw).is_some()
                || res_of(&lw).is_some()
                || vcodec_of(&lw).is_some()
                || matches!(source_of(&lw), Some("BluRay") | Some("HDTV") | Some("DVD"))
                || lw == "remux"
            {
                return None;
            }
        }
    }
    // A format marker from the third field on names the kind outright.
    let marker = fields.iter().skip(2).find_map(|f| {
        word_of(f).into_iter().find_map(|w| {
            let lw = w.to_ascii_lowercase();
            if book_marker(&lw) {
                Some(Kind::Book)
            } else if audio_marker(&lw) {
                Some(Kind::Music)
            } else {
                None
            }
        })
    });
    // A bare year from the third field on. Not "the LAST field" - scene
    // stems trail furniture behind the year ("…-2011-REMASTERED-GRP"),
    // and insisting on the final position made the rule miss those.
    let dated = fields.iter().skip(2).any(|f| is_year(f));
    // Books are named by their marker, so a book stem that reached here
    // by the year rule alone would be mislabelled - the bare
    // `Artist-Album-YEAR-GROUP` shape is the music convention.
    let kind = match marker {
        Some(k) => k,
        None if dated && body.contains('_') => Kind::Music,
        None => return None,
    };
    let year = fields.iter().skip(2).find(|f| is_year(f)).and_then(|f| f.parse().ok());
    let credit = word_of(fields[0]).join(" ");
    let work = word_of(fields[1]).join(" ");
    if credit.is_empty() || work.is_empty() {
        return None;
    }
    Some((kind, credit, work, year))
}

/// Dedupe key for a music/book card. Deliberately carries NO year,
/// unlike the movie key: the year in a scene album stem is the year of
/// that EDITION ("…-2021-GROUP" on a 1973 record), so keying on it would
/// scatter the remaster, the vinyl rip and the original across three
/// cards for one album. Artist+album is the identity, as it is for a
/// show's seasons under "t:".
fn media_key(kind: &Kind, title: &str) -> String {
    let prefix = if matches!(kind, Kind::Book) { "bk" } else { "mu" };
    format!("{prefix}:{}", norm_title(title))
}

/// Split a "Credit - Work" title into its halves - the artist/author and
/// the album/book. Scene music and book stems name the credit first, and
/// we keep both in `title` so a card reads properly before any provider
/// answers; the providers need them apart. Splits on the FIRST separator:
/// an album or book title may contain one ("Artist - Live - 1975"), an
/// artist name almost never does.
pub fn credit_split(title: &str) -> Option<(&str, &str)> {
    let (credit, work) = title.split_once(" - ")?;
    let (credit, work) = (credit.trim(), work.trim());
    (!credit.is_empty() && !work.is_empty()).then_some((credit, work))
}

// ---------------------------------------------------------------------------
// ROT13 rescue: many obfuscated posts are the real name letter-rotated
// (and some rotate digits by 5 as well - ROT18 - so "720p" hides as
// "275c"). Both variants are tried; a decode is only believed when it
// parses into a clean scene name with real furniture AND reads like
// English, so genuine titles never get mangled by accident.
// ---------------------------------------------------------------------------

fn rot13(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'a'..='z' => (((c as u8 - b'a' + 13) % 26) + b'a') as char,
            'A'..='Z' => (((c as u8 - b'A' + 13) % 26) + b'A') as char,
            _ => c,
        })
        .collect()
}

fn rot5_digits(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '0'..='9' => (((c as u8 - b'0' + 5) % 10) + b'0') as char,
            _ => c,
        })
        .collect()
}

/// Common English words that survive into almost every real title -
/// a decode containing one is strong evidence it isn't coincidence.
const COMMON_WORDS: &[&str] = &[
    "the", "a", "an", "and", "of", "to", "in", "on", "at", "is", "it",
    "for", "with", "from", "my", "who", "what", "war", "world", "man",
    "men", "girl", "boy", "king", "queen", "day", "night", "dead", "love",
    "life", "star", "dark", "black", "white", "story", "game", "house",
    "big", "little", "new", "last", "first", "one", "two",
];

/// (every word pronounceable, contains a common English word). A word
/// of 3+ letters with no vowel at all ("qrs", "xkcd") sinks the decode.
fn english_words(title: &str) -> (bool, bool) {
    let mut any = false;
    let mut common = false;
    for w in title.split(' ') {
        let w = w.to_ascii_lowercase();
        if w.is_empty() || !w.chars().all(|c| c.is_ascii_alphabetic()) {
            continue;
        }
        if w.len() >= 3 && !w.chars().any(|c| "aeiouy".contains(c)) {
            return (false, false);
        }
        any = true;
        if COMMON_WORDS.contains(&w.as_str()) {
            common = true;
        }
    }
    (any, common)
}

/// Try both rotation variants and keep the decode with the most scene
/// furniture. Acceptance bar: parses as movie/tv, reads as English, and
/// carries either 2+ furniture tokens (year/SxxEyy/res/source/remux) or
/// 1 plus a common English word - one lucky token alone proves nothing.
fn rot13_rescue(stem: &str) -> Option<Parsed> {
    let letters = rot13(stem);
    let both = rot5_digits(&letters);
    let mut best: Option<(u32, Parsed)> = None;
    for decoded in [letters, both] {
        if looks_obfuscated(&decoded) {
            continue;
        }
        let p = parse_one(&decoded);
        if !matches!(p.kind, Kind::Movie | Kind::Tv) {
            continue;
        }
        let signals = [
            p.year.is_some(),
            p.season.is_some(),
            p.episode.is_some(),
            p.res.is_some(),
            p.source.is_some(),
            p.remux,
        ]
        .iter()
        .filter(|b| **b)
        .count() as u32;
        let (pronounceable, common) = english_words(&p.title);
        if !pronounceable || signals == 0 || (signals < 2 && !common) {
            continue;
        }
        // Season plausibility breaks ties between the letters-only and
        // ROT18 variants: both decode "qiqevc"→"dvdrip" identically and
        // differ only in digits, so "f58r69" scored the same as S58E69
        // (letters kept) and S03E14 (ROT18) - and the wrong one shipped.
        // A sane season number is the extra bit of evidence.
        let plausible = p.season.map_or(0, |s| u32::from((1..=40).contains(&s)));
        let score = signals * 2 + plausible;
        if best.as_ref().map_or(true, |(s, _)| score > *s) {
            best = Some((score, p));
        }
    }
    best.map(|(_, p)| p)
}

/// Normalized dedupe key body: lowercase alnum words joined by spaces.
/// Unicode-aware on purpose: an ASCII-only filter mapped every CJK,
/// Cyrillic and Greek character to a space, so e.g. every Japanese TV
/// title normalized to "" and collapsed onto the single `titles` row
/// "t:" - one poster and overview shared by unrelated shows. ASCII input
/// is unaffected (`to_lowercase`/`is_alphanumeric` agree with the ASCII
/// forms over ASCII); accented Latin now keeps its letters too.
pub fn norm_title(t: &str) -> String {
    t.to_lowercase()
        .chars()
        .map(|c| if c.is_alphanumeric() { c } else { ' ' })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

// ---------------------------------------------------------------------------
// Reversed stems. A reposter writes the whole name backwards
// ("PRG-462x.p0801.4202.eivoM.elpmaxE"), which defeats every furniture
// rule above because none of the tokens read forwards. Only a token that
// could not be anything BUT backwards triggers the flip, and the flipped
// parse has to be strictly better than the forward one to be believed.
// ---------------------------------------------------------------------------

/// A whole token that only makes sense read backwards: a resolution
/// ("p027" = 720p, "p0801" = 1080p) or an SxxEyy marker ("20E10S" =
/// S01E02, "210E10S" = S01E012). Whole-token only, so a real word that
/// merely contains one of these is not one.
fn reads_backwards(tok: &str) -> bool {
    // Every shape below is 4 ("p084") to 7 ("210E10S") characters, and
    // this runs over every token of every furniture-less stem the index
    // scans - so the width decides before anything allocates.
    if !(4..=7).contains(&tok.len()) {
        return false;
    }
    let t = tok.to_ascii_lowercase();
    let b = t.as_bytes();
    // Reversed resolution. Derived from `res_of` rather than listed, so
    // the two cannot drift apart, and shaped so only the "<digits>p"
    // resolutions qualify - "4k" backwards is two characters of nothing.
    let reversed_res = t.strip_prefix('p').is_some_and(|digits| {
        (3..=4).contains(&digits.len())
            && digits.bytes().all(|c| c.is_ascii_digit())
            && res_of(&t.chars().rev().collect::<String>()).is_some()
    });
    if reversed_res {
        return true;
    }
    // Reversed episode marker: episode digits, 'e', season digits, 's'.
    (6..=7).contains(&b.len())
        && b[b.len() - 1] == b's'
        && b[b.len() - 4] == b'e'
        && b[..b.len() - 4].iter().all(u8::is_ascii_digit)
        && b[b.len() - 3..b.len() - 1].iter().all(u8::is_ascii_digit)
}

/// Flip the stem and keep the flipped parse only when it is strictly
/// more informative: the forward parse found NO scene furniture at all,
/// and the flipped one found a pronounceable title plus enough facts to
/// rule out coincidence. Without the title test a flip that recovers a
/// resolution but leaves a bare number for a name would be believed.
///
/// "Forward furniture" has to mean every identity signal, not just the
/// two the flip is hunting for: a year, a source or an air date all say
/// the stem already reads forwards, and "Christmas.p0801.Home.Movies.
/// 2019" flipped to "9102 seivoM emoH".
///
/// The English test cannot carry the rest on its own, because vowels
/// survive a reversal - "epaT" reads as pronounceably as "Tape" - so the
/// acceptance bar is `rot13_rescue`'s furniture count, raised to two
/// signals with no one-plus-a-common-word escape: a reversed title keeps
/// real English words, so the common-word tell that works for ROT13
/// proves nothing here. Season and episode come from ONE SxxEyy token
/// and so count once between them, and only when the season reads
/// plausibly - otherwise the single page marker in
/// "Lecture.Notes.12e34s.Extra" flips it to S43E21 of "artxE".
fn reversed_rescue(stem: &str, direct: &Parsed) -> Option<Parsed> {
    if direct.res.is_some()
        || direct.season.is_some()
        || direct.episode.is_some()
        || direct.year.is_some()
        || direct.source.is_some()
        || direct.date.is_some()
        || direct.group.is_some()
        || direct.remux
    {
        return None;
    }
    if !stem.split(|c: char| !c.is_ascii_alphanumeric()).any(reads_backwards) {
        return None;
    }
    let p = parse_one(&stem.chars().rev().collect::<String>());
    if !matches!(p.kind, Kind::Movie | Kind::Tv) || !english_words(&p.title).0 {
        return None;
    }
    let episode = (p.season.is_some() || p.episode.is_some())
        && p.season.map_or(true, |s| (1..=40).contains(&s));
    let signals = [episode, p.year.is_some(), p.res.is_some(), p.source.is_some(), p.remux]
        .iter()
        .filter(|b| **b)
        .count();
    if signals < 2 {
        return None;
    }
    (p.res.is_some() || p.season.is_some() || p.episode.is_some()).then_some(p)
}

pub fn parse_release(stem: &str) -> Parsed {
    let direct = parse_one(stem);
    if let Some(mut p) = reversed_rescue(stem, &direct) {
        p.rescued = true;
        return p;
    }
    // ROT13 rescue: only worth trying when the direct parse found NO
    // scene furniture at all - any recognized year/SxxEyy/res/source
    // token means the stem is already plain text, and rotating a real
    // name can only make it worse.
    // A bare Exx token is NOT disqualifying evidence: rotated RAR part
    // suffixes (".e64" = a rot13'd ".rNN") parse as a bare episode, and
    // that alone kept whole obfuscated sets from ever being rescued.
    let bare_ep_only = direct.episode.is_some() && direct.season.unwrap_or(0) == 0;
    if direct.kind != Kind::Software
        && direct.year.is_none()
        && (direct.season.is_none() || bare_ep_only)
        && (direct.episode.is_none() || bare_ep_only)
        && direct.res.is_none()
        && direct.source.is_none()
        && !direct.remux
    {
        if let Some(mut p) = rot13_rescue(stem) {
            p.rescued = true;
            return p;
        }
    }
    direct
}

fn parse_one(stem: &str) -> Parsed {
    let other = |title: &str| Parsed {
        kind: Kind::Other,
        title: title.to_string(),
        year: None,
        season: None,
        episode: None,
        episode2: None,
        res: None,
        remux: false,
        source: None,
        vcodec: None,
        acodec: None,
        hdr: None,
        langs: Vec::new(),
        rescued: false,
        group: None,
        extra: Vec::new(),
        date: None,
        key: format!("o:{}", norm_title(title)),
    };
    if looks_obfuscated(stem) {
        return other(stem);
    }

    // Release group: text after the LAST hyphen, if it looks like a tag.
    let (body, group) = split_group(stem);
    let group = group.map(str::to_string);

    // Tokenize on dot/underscore/space; hyphens survive inside tokens
    // ("Spider-Man", "WEB-DL"). Exception: stems with NO other separator
    // and several hyphens are hyphen-separated ("the-flash-s01e01-720p").
    let all_hyphen =
        !body.contains(['.', '_', ' ']) && body.matches('-').count() >= 3;
    let seps: &[char] = if all_hyphen { &['-'] } else { &['.', '_', ' '] };
    let toks: Vec<&str> = body
        .split(seps)
        .map(|t| t.trim_matches(|c: char| "[]()".contains(c)))
        .filter(|t| !t.is_empty())
        .collect();
    if toks.is_empty() {
        return other(stem);
    }

    // Software posts get their own kind: never enriched as a film, and
    // segregated onto the wall's "Other" tab instead of Movies/TV.
    if let Some(cut) = software_marker(&toks) {
        let title_toks = if cut == 0 { &toks[..] } else { &toks[..cut] };
        let title = title_toks.join(" ");
        return Parsed {
            kind: Kind::Software,
            key: format!("s:{}", norm_title(&title)),
            title,
            year: None,
            season: None,
            episode: None,
            episode2: None,
            rescued: false,
            res: None,
            remux: false,
            source: None,
            vcodec: None,
            acodec: None,
            hdr: None,
            langs: Vec::new(),
            extra: Vec::new(),
            date: None,
            group,
        };
    }

    // Scene music: hyphen-separated fields the normal tokenizer would
    // glue together. Checked before tokenizing because the whole point
    // is that this shape needs a different split.
    if let Some((kind, credit, work, year)) = scene_media(body) {
        let title = format!("{credit} - {work}");
        return Parsed {
            key: media_key(&kind, &title),
            kind,
            title,
            year,
            season: None,
            episode: None,
            episode2: None,
            // A datecode is an episode's identity; an album's is its
            // artist and title, and the year it carries is an edition
            // marker the key deliberately ignores (see `media_key`).
            date: None,
            rescued: false,
            res: None,
            remux: false,
            source: None,
            vcodec: None,
            acodec: None,
            hdr: None,
            langs: Vec::new(),
            extra: Vec::new(),
            group,
        };
    }

    let mut season = None;
    let mut episode = None;
    let mut episode2 = None;
    let mut res = None;
    let mut source = None;
    let mut vcodec = None;
    let mut acodec: Option<String> = None;
    let mut arank = 0u8;
    let mut hdr: Option<String> = None;
    let mut hrank = 0u8;
    let mut langs: Vec<String> = Vec::new();
    let mut remux = false;
    // Daily shows date-code instead of SxxEyy ("At.Midnight.150615.720p").
    let mut daily = false;
    let mut date: Option<String> = None;
    // Index of the first token AFTER the date, so the identity tail can
    // start there (the same trick the movie-year arm uses).
    let mut date_end: Option<usize> = None;
    let is_datecode = |t: &str| {
        (t.len() == 6 || t.len() == 8) && t.chars().all(|c| c.is_ascii_digit())
    };
    // A 2-digit month or day in range. At eight digits the daily flag is
    // deliberately looser than this (any run of that width reads as a
    // datecode); only a date that validates becomes an identity.
    let d2 = |s: &str, max: u32| {
        s.len() == 2
            && s.bytes().all(|c| c.is_ascii_digit())
            && s.parse::<u32>().is_ok_and(|v| (1..=max).contains(&v))
    };
    // The normalized "yyyymmdd" a datecode reads as, or None when it is
    // not a date. Six digits are held to a much harder bar than eight:
    // that width is also how ids, sizes and part counts look, and YYMMDD
    // has only one sane reading (20YY, near enough to now to be a real
    // air date). Anything short of that is left alone as an ordinary
    // word rather than guessed at.
    let datecode_of = |t: &str| -> Option<String> {
        let (y, md) = t.split_at(t.len() - 4);
        let (mth, day) = md.split_at(2);
        if !d2(mth, 12) || !d2(day, 31) {
            return None;
        }
        if y.len() == 4 {
            return Some(format!("{y}{mth}{day}"));
        }
        if !y.parse::<u32>().is_ok_and(|v| v <= 39) {
            return None;
        }
        // A four-digit year or an SxxEyy marker anywhere in the stem
        // names the release better than a bare six-digit run ever could,
        // so a stem carrying either is not read as YYMMDD at all. Walked
        // here, at the one token that needs the answer, rather than up
        // front for every stem the index parses.
        let competing = toks
            .iter()
            .enumerate()
            .any(|(j, x)| (j > 0 && is_year(x)) || tv_marker(x).is_some());
        (!competing).then(|| format!("20{y}{mth}{day}"))
    };
    // First tag / TV-marker index = hard end of the title region.
    let mut boundary = toks.len();
    for (i, t) in toks.iter().enumerate() {
        if let Some((s, e, e2)) = tv_marker(t) {
            season.get_or_insert(s);
            if let Some(e) = e {
                if episode.is_none() {
                    episode2 = e2; // pairs with the episode that owns the slot
                }
                episode.get_or_insert(e);
            }
            boundary = boundary.min(i);
        } else if is_tag(t) {
            boundary = boundary.min(i);
        } else if i > 0 && is_datecode(t) && (t.len() == 8 || datecode_of(t).is_some()) {
            daily = true;
            // "150615" (YYMMDD) and "20150615" both normalize to
            // yyyymmdd, so the two conventions compare equal.
            if let Some(d) = datecode_of(t).filter(|_| date.is_none()) {
                date = Some(d);
                date_end = Some(i + 1);
            }
            boundary = boundary.min(i);
        } else if i > 0
            && is_year(t)
            && toks.get(i + 1).is_some_and(|m| {
                m.len() == 2 && m.parse::<u32>().is_ok_and(|v| (1..=12).contains(&v))
            })
            && toks.get(i + 2).is_some_and(|d| {
                d.len() == 2 && d.parse::<u32>().is_ok_and(|v| (1..=31).contains(&v))
            })
        {
            // Dotted daily date ("The.Daily.Show.2026.07.21…") - the
            // year token alone otherwise reads as a movie year and the
            // episode identity (the date) is lost.
            daily = true;
            if date.is_none() {
                date = Some(format!("{t}{}{}", toks[i + 1], toks[i + 2]));
                date_end = Some(i + 3);
            }
            boundary = boundary.min(i);
        } else if i > 0
            && t.len() == 4
            && t.starts_with('0')
            && t.chars().all(|c| c.is_ascii_digit())
        {
            // Leading-zero SSEE code ("0601" = S06E01) - can't be a year.
            season.get_or_insert(t[..2].parse().unwrap_or(0));
            episode.get_or_insert(t[2..].parse().unwrap_or(0));
            boundary = boundary.min(i);
        }
        // Quality facts can hide inside hyphenated tokens when a group
        // wasn't split off ("1080p-REMUX"); check parts too.
        for part in t.split('-') {
            if let Some(r) = res_of(part) {
                res.get_or_insert(r.to_string());
            }
            if let Some(s) = source_of(part) {
                source.get_or_insert(s.to_string());
            }
            if part.eq_ignore_ascii_case("remux") {
                remux = true;
            }
        }
        // Codecs: check the WHOLE token first so hyphenated names
        // ("DTS-HD", "DTS-X", "VC-1") aren't split apart, then the parts
        // for combined furniture ("x265-DTS"). The strongest audio wins.
        for cand in std::iter::once(*t).chain(t.split('-')) {
            if let Some(v) = vcodec_of(cand) {
                vcodec.get_or_insert(v.to_string());
            }
            if let Some((rank, a)) = acodec_of(cand) {
                if rank > arank {
                    arank = rank;
                    acodec = Some(a.to_string());
                }
            }
            if let Some((rank, h)) = hdr_of(cand) {
                if rank > hrank {
                    hrank = rank;
                    hdr = Some(h.to_string());
                }
            }
        }
    }

    // Music / book format markers ("…(1965) [epub]", "…[FLAC]"). Most of
    // them are already release furniture to `is_tag`, but the ebook ones
    // are not, so the marker also has to close the title region - "Frank
    // Herbert - Dune 1965 epub" must not keep "epub" in its title.
    let media = media_marker(&toks).filter(|_| {
        no_video_evidence(&res, &vcodec, &source, remux, season, daily)
    });
    if let Some((_, i)) = &media {
        boundary = boundary.min(*i);
    }

    // Year: the LAST year-like token before the boundary, never index 0
    // ("2012.2009.1080p" → title "2012", year 2009; "Blade.Runner.2049.
    // 2017.2160p" → title "Blade Runner 2049", year 2017).
    let year_idx = toks[..boundary]
        .iter()
        .enumerate()
        .rev()
        .find(|(i, t)| *i > 0 && is_year(t))
        .map(|(i, _)| i);
    let cut = year_idx.unwrap_or(boundary).min(boundary);
    let year: Option<u32> = year_idx.and_then(|i| toks[i].parse().ok());

    // Language tags live in the furniture after the title region - only
    // look there, so a film titled "Rus" or "Ita" stays untagged.
    for t in &toks[cut..] {
        for part in t.split('-') {
            if let Some(l) = lang_of(part) {
                if !langs.iter().any(|x| x == l) {
                    langs.push(l.to_string());
                }
            }
        }
    }

    let title_toks = &toks[..cut];
    if title_toks.is_empty() {
        return other(stem);
    }
    let mut title = title_toks.join(" ");
    // Single-case stems (ALLCAPS shouting or all-lowercase mumbling) fold
    // to title case; mixed case is left exactly as the poster wrote it.
    if title.chars().filter(|c| c.is_ascii_alphabetic()).count() > 3
        && !(title.chars().any(|c| c.is_ascii_lowercase())
            && title.chars().any(|c| c.is_ascii_uppercase()))
    {
        // Words the plain fold mangles: roman numerals ("PLANET.EARTH.II"
        // became "Planet Earth Ii") and household acronyms ("THE.OFFICE.US"
        // became "The Office Us"). Only multi-word titles qualify - the
        // 2019 film "Us" must stay "Us", and there a lone "us"/"ii" token
        // IS the title, not a suffix. I, V and X are left out on purpose:
        // as single letters they are far more often initials than numerals.
        const KEEP_UPPER: [&str; 28] = [
            "ii", "iii", "iv", "vi", "vii", "viii", "ix", "xi", "xii", "xiii", "xiv", "xv",
            "us", "uk", "usa", "wwe", "nhl", "nba", "nfl", "ufc", "fbi", "cia", "swat",
            "nasa", "bbc", "cnn", "espn", "uefa",
        ];
        let multi = title_toks.len() > 1;
        title = title
            .split(' ')
            .map(|w| {
                let lower = w.to_ascii_lowercase();
                if multi && KEEP_UPPER.contains(&lower.as_str()) {
                    return lower.to_ascii_uppercase();
                }
                let mut cs = w.chars();
                match cs.next() {
                    Some(f) => f.to_ascii_uppercase().to_string() + &cs.as_str().to_ascii_lowercase(),
                    None => String::new(),
                }
            })
            .collect::<Vec<_>>()
            .join(" ");
    }

    let kind = match &media {
        Some((k, _)) => k.clone(),
        None if season.is_some() || daily => Kind::Tv,
        None => Kind::Movie,
    };
    // What the title had to leave behind. Only meaningful for a movie
    // whose title was cut AT its year: that is the shape where the year
    // can be a season rather than a release date, and everything that
    // tells one post from the next ("Round11.Hungary.Post-Qualifying")
    // sits after it. TV already carries its identity in season/episode,
    // and a yearless title was cut at the first tag, so both stay empty.
    //
    // Note this deliberately does NOT change `kind`: these are still
    // Movie posts as far as the rest of the app is concerned, and
    // `finalize_names` gates the junk sweep on Movie | Tv, so demoting
    // them to Other would quietly stop PAR2 cleanup for exactly the
    // releases this field exists to describe.
    let extra: Vec<String> = if kind == Kind::Movie && year_idx == Some(cut) {
        identity_tail(toks[cut + 1..].iter().copied())
            .into_iter()
            .map(str::to_string)
            .collect()
    } else if let Some(end) = date_end {
        // A dated post's identity continues AFTER the date: which
        // fixture, which session, which guest ("EPL.2026.08.22.Arsenal.
        // vs.Spurs"). Two fixtures on one Saturday are not the same
        // event, and the date alone said they were.
        identity_tail(toks[end..].iter().copied())
            .into_iter()
            .map(str::to_string)
            .collect()
    } else {
        Vec::new()
    };
    let key = match kind {
        Kind::Tv => format!("t:{}", norm_title(&title)),
        Kind::Music | Kind::Book => media_key(&kind, &title),
        _ => match year {
            Some(y) => format!("m:{}:{y}", norm_title(&title)),
            None => format!("m:{}", norm_title(&title)),
        },
    };
    Parsed {
        kind,
        title,
        year,
        rescued: false,
        season,
        episode,
        episode2,
        res,
        remux,
        source,
        vcodec,
        acodec,
        hdr,
        langs,
        extra,
        group,
        date,
        key,
    }
}

/// Short quality label for card badges: "2160p REMUX", "1080p WEB", …
pub fn quality_label(p: &Parsed) -> String {
    let mut s = p.res.clone().unwrap_or_default();
    if p.remux {
        if !s.is_empty() {
            s.push(' ');
        }
        s.push_str("REMUX");
    } else if let Some(src) = &p.source {
        if !s.is_empty() {
            s.push(' ');
        }
        s.push_str(src);
    }
    s
}

// ---------------------------------------------------------------------------
// Friendly-name builder (auto-rename): reassemble a clean, informative name
// from the parsed facts. Shared so downloader and indexer name alike.
// ---------------------------------------------------------------------------

/// Which quality facts a friendly name should carry. Title + year are
/// always present; each of these is an independent user toggle.
#[derive(Debug, Clone, Copy, Default)]
pub struct NameStyle {
    pub resolution: bool,
    pub video_codec: bool,
    pub audio_codec: bool,
    /// Source medium (BluRay/WEB/…) or REMUX.
    pub source: bool,
    /// Trailing release-group tag ("-FGT").
    pub group: bool,
    /// Wrap the year in parentheses: "Title (1999)" rather than
    /// "Title 1999". Off by default. Note that "Title (Year)" is the
    /// folder shape Plex, Jellyfin and Radarr match against, so anyone
    /// feeding a media server usually wants this on.
    pub year_parens: bool,
    /// Wrap the quality facts in square brackets: "… [1080p x265]" rather
    /// than "… 1080p x265". Off by default.
    pub quality_brackets: bool,
    /// Carry the words the parser did not recognise into the name, so
    /// releases that differ only in those words stay distinguishable:
    /// "Formula1 2026 Round11 Hungary Race" and "… Hungary Qualifying"
    /// rather than two folders both called "Formula1 (2026)".
    ///
    /// Only ever adds words to a name we would otherwise DECLINE to
    /// build (see movie_name) - it cannot reshape a film that already
    /// names cleanly, because a film that parses cleanly leaves nothing
    /// in `extra`.
    pub extra_words: bool,
}

/// Quality suffix built from the style-enabled facts, e.g.
/// " [1080p x265 DTS-HD]" (or " 1080p x265 DTS-HD" without
/// `style.quality_brackets`), plus a "-GROUP" tail when `style.group`.
/// Empty string when nothing is enabled or nothing is known - the caller
/// appends it directly to a base name.
pub fn quality_suffix(p: &Parsed, style: &NameStyle) -> String {
    let mut parts: Vec<String> = Vec::new();
    if style.resolution {
        if let Some(r) = &p.res {
            parts.push(r.clone());
        }
    }
    if style.source {
        if p.remux {
            parts.push("REMUX".to_string());
        } else if let Some(s) = &p.source {
            parts.push(s.clone());
        }
    }
    if style.video_codec {
        if let Some(v) = &p.vcodec {
            parts.push(v.clone());
        }
    }
    if style.audio_codec {
        if let Some(a) = &p.acodec {
            parts.push(a.clone());
        }
    }
    let mut out = String::new();
    if !parts.is_empty() {
        out.push(' ');
        if style.quality_brackets {
            out.push('[');
        }
        out.push_str(&parts.join(" "));
        if style.quality_brackets {
            out.push(']');
        }
    }
    if style.group {
        if let Some(g) = &p.group {
            out.push_str(&format!("-{g}"));
        }
    }
    out
}

/// Split a [`Parsed::date`] ("20260721") into the year a daily show is
/// filed under and the dotted air date its episode is named after
/// ("2026", "2026.07.21") - the `{Series Title} - {Air-Date}` convention
/// every library uses for a show that has no season/episode numbers.
///
/// None unless the string is exactly the normalized 8-digit shape
/// `parse_release` produces AND reads as a real calendar date, so a
/// caller building a filename declines rather than emit half a date.
/// This is deliberately stricter than the `daily` flag: that flag only
/// has to decide "TV, not a movie", while a name written to disk has to
/// be right.
pub fn air_date_parts(date: &str) -> Option<(String, String)> {
    if date.len() != 8 || !date.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let (year, md) = date.split_at(4);
    let (month, day) = md.split_at(2);
    let num = |s: &str| s.parse::<u32>().ok().filter(|v| *v >= 1);
    let (y, m, d) = (num(year)?, num(month)?, num(day)?);
    if m > 12 || d > days_in_month(y, m) {
        return None;
    }
    Some((year.to_string(), format!("{year}.{month}.{day}")))
}

/// Length of a Gregorian month. The day check used to be a flat
/// `1..=31`, so `Show.2026.02.31` was filed as a daily episode under
/// `Show/Season 2026/Show - 2026.02.31` - a date that does not exist,
/// written into a library, from a name this function's own contract
/// promises to have read as a real calendar date.
fn days_in_month(year: u32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        // Proleptic Gregorian, which is what a four-digit year in a
        // release name means: every 4th year, except centuries, except
        // every 400th.
        2 if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) => 29,
        2 => 28,
        _ => 0,
    }
}

/// Friendly base name (no extension) for a movie / loose file:
/// "The Matrix (1999)" plus the style suffix. Path-safe. Returns None when
/// there's nothing better to offer than the original - an obfuscated /
/// unparseable stem, or an empty title.
pub fn movie_name(p: &Parsed, style: &NameStyle) -> Option<String> {
    if p.kind == Kind::Other {
        return None;
    }
    let title = p.title.trim();
    if title.is_empty() {
        return None;
    }
    // A release whose identity lives AFTER the year is not a film with a
    // release date - it is one event in a season ("Formula1.2026.Round11.
    // Hungary.Post-Qualifying.Show.F1TV.WEB-DL.1080p…"). Reducing it to
    // "Title (Year)" renames every round and every session of the year to
    // the same string, which collides on disk.
    //
    // The words that tell those apart are sitting right there in `extra`
    // - "Round11 Hungary Race" vs "Round11 Hungary Qualifying" - so with
    // extra_words on we keep them and the collision never arises. With it
    // off we decline as before and the poster's own name survives, which
    // is the safer default for anyone who does not want tokens the parser
    // failed to understand appearing in their filenames.
    //
    // Note this arm cannot touch an ordinary film: a film that parses
    // cleanly leaves `extra` EMPTY (measured across editions, cuts, AKA
    // titles, foreign-language and scene-noise shapes), so everything
    // below only ever fires on releases we would otherwise refuse to
    // name at all.
    let mut extra = String::new();
    if !p.extra.is_empty() {
        match extra_words(p) {
            // Either the option is off, or nothing presentable survived
            // the filter and we would be back to the bare colliding
            // "Title (Year)". Both mean: leave it as the poster named it.
            Some(w) if style.extra_words => extra = w,
            _ => return None,
        }
    }
    let suffix = quality_suffix(p, style);
    // Only rename when there's an anchor that makes the name more
    // informative - a year (the hallmark of a real movie post), at least
    // one enabled quality fact, or the event words we just kept. A bare,
    // yearless, quality-less stem ("somefile") could be anything; leave
    // it as the poster named it.
    if p.year.is_none() && suffix.is_empty() && extra.is_empty() {
        return None;
    }
    let mut base = match p.year {
        Some(y) if style.year_parens => format!("{title} ({y})"),
        Some(y) => format!("{title} {y}"),
        None => title.to_string(),
    };
    if !extra.is_empty() {
        base.push(' ');
        base.push_str(&extra);
    }
    base.push_str(&suffix);
    // Nothing nameable survived sanitisation (a title that was all
    // punctuation): decline, as everywhere else here, so the poster's own
    // name stands rather than a placeholder.
    let name = sanitize_name(&base);
    if name.is_empty() { None } else { Some(name) }
}

/// The unrecognised words of a release, filtered down to what is worth
/// putting in a filename, or None if nothing is.
///
/// "Not a codec or a format" needs no list here: anything the parser
/// recognised as resolution, codec, source, language, edition or group
/// was consumed into a typed field and never reaches `extra`. What is
/// left is the release's own vocabulary - "Round11", "Hungary", "Race",
/// "Chiefs", "vs", "Sinner" - plus the occasional scrap. So this filters
/// for presentability rather than meaning: no dictionary, because the
/// useful words here are overwhelmingly proper nouns, event jargon and
/// numbered rounds that no dictionary contains.
fn extra_words(p: &Parsed) -> Option<String> {
    /// Enough to tell two events apart without rebuilding the whole
    /// release name; past this a post is padding, not describing.
    const MAX_WORDS: usize = 6;
    const MAX_LEN: usize = 24;

    let group = p.group.as_deref().unwrap_or_default();
    let mut out: Vec<&str> = Vec::new();
    for w in &p.extra {
        let w = w.trim_matches(|c: char| !c.is_ascii_alphanumeric());
        if w.is_empty() || w.len() > MAX_LEN {
            continue;
        }
        // The group already has its own opt-in tag; don't duplicate it.
        if !group.is_empty() && w.eq_ignore_ascii_case(group) {
            continue;
        }
        if w.chars().all(|c| c.is_ascii_digit()) {
            // Short bare numbers are half of an event's identity ("03"
            // in "Week 03", "311" in a UFC card), so keep them - but
            // NOT via looks_obfuscated, which judges whole stems and
            // rightly calls any letterless string unpresentable. A long
            // bare number is a size, a date fragment or an id.
            if w.len() > 4 {
                continue;
            }
        } else if looks_obfuscated(w) {
            // A hash or a scrambled blob describes nothing.
            continue;
        }
        out.push(w);
        if out.len() == MAX_WORDS {
            break;
        }
    }
    if out.is_empty() {
        return None;
    }
    Some(out.join(" "))
}

/// Spell a colon out as a separator instead of losing it. A colon is
/// illegal on Windows and carries path meaning there, but in a title it
/// is doing real work ("Alien: Romulus", "Dune: Part Two"), and blanking
/// it to a space read as two titles run together. The convention every
/// library uses: ": " becomes " - ", a bare ":" becomes "-".
fn expand_colons(t: &str) -> String {
    let mut out = String::with_capacity(t.len() + 2);
    let mut chars = t.chars().peekable();
    while let Some(c) = chars.next() {
        if c != ':' {
            out.push(c);
            continue;
        }
        if chars.peek() == Some(&' ') {
            chars.next();
            out.push_str(" - ");
        } else {
            out.push('-');
        }
    }
    out
}

/// Collapse a separator run that colon expansion doubled up ("Title - -
/// Sub", "Title--Sub") back down to one. Only runs of TWO OR MORE hyphens
/// are touched, so a hyphenated word ("Spider-Man") and an ordinary
/// " - " are left exactly as they were.
fn collapse_separators(t: &str) -> String {
    let chars: Vec<char> = t.chars().collect();
    let mut out = String::with_capacity(t.len());
    let mut i = 0;
    while i < chars.len() {
        if chars[i] != '-' {
            out.push(chars[i]);
            i += 1;
            continue;
        }
        let start = i;
        let (mut hyphens, mut spaced) = (0, false);
        while i < chars.len() && (chars[i] == '-' || chars[i] == ' ') {
            if chars[i] == '-' {
                hyphens += 1;
            } else {
                spaced = true;
            }
            i += 1;
        }
        if hyphens < 2 {
            out.extend(&chars[start..i]);
        } else if spaced {
            out.push_str(" - ");
        } else {
            out.push('-');
        }
    }
    out
}

/// Strip path-hostile characters and collapse whitespace for a file/dir
/// name. Keeps brackets/parens (used by the quality suffix).
///
/// The result then goes through the same strong guarantees enqueue-time
/// folder naming uses ([`crate::disk::sanitize_filename`]), with the
/// Windows rules forced ON regardless of host: a finished tree gets moved
/// to a NAS/SMB share, so a leading dot (hidden), a trailing dot (silently
/// truncated) or a reserved device stem ("CON") is a problem everywhere,
/// not just on a Windows box. Without this, stage 4 could emit names that
/// enqueue-time naming had already been fixed to reject.
///
/// Returns an EMPTY string when nothing nameable survives, so callers
/// decline rather than emit `sanitize_filename`'s "unnamed" placeholder or
/// a bare-dot component.
pub fn sanitize_name(t: &str) -> String {
    let expanded = collapse_separators(&expand_colons(t));
    let mapped: String = expanded
        .chars()
        .map(|c| if "/\\:*?\"<>|".contains(c) { ' ' } else { c })
        .collect();
    let collapsed = mapped.split_whitespace().collect::<Vec<_>>().join(" ");
    // A colon at the very start or end leaves a dangling separator behind.
    let collapsed = collapsed.trim_start_matches("- ").trim_end_matches(" -").trim();
    if !collapsed.chars().any(|c| c.is_alphanumeric()) {
        return String::new();
    }
    crate::disk::sanitize_filename_for(collapsed, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(stem: &str) -> Parsed {
        parse_release(stem)
    }

    /// The words that tell one event from another are the ones the
    /// parser could not classify, so keeping `extra` is what stops a
    /// whole season collapsing onto one name.
    #[test]
    fn extra_words_keep_events_apart() {
        let on = NameStyle { resolution: true, extra_words: true, ..Default::default() };
        let off = NameStyle { resolution: true, ..Default::default() };

        let race = p("Formula1.2026.Round11.Hungary.Race.F1TV.WEB-DL.2160p.HLG.H265.DDP5.1.English-MWR");
        let quali = p("Formula1.2026.Round11.Hungary.Qualifying.F1TV.WEB-DL.1080p.H264-MWR");
        let next = p("Formula1.2026.Round12.Belgium.Race.F1TV.WEB-DL.2160p.HLG.H265.DDP5.1-MWR");

        // Off: decline, exactly as before, so the poster's name survives.
        assert_eq!(movie_name(&race, &off), None);
        assert_eq!(movie_name(&quali, &off), None);

        // On: three names, three distinct strings.
        let a = movie_name(&race, &on).unwrap();
        let b = movie_name(&quali, &on).unwrap();
        let c = movie_name(&next, &on).unwrap();
        assert_eq!(a, "Formula1 2026 Round11 Hungary Race F1TV 2160p");
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert!(b.contains("Qualifying"));
        assert!(c.contains("Round12") && c.contains("Belgium"));

        // Short numbers carry meaning and must survive ("Week 03").
        let nfl = p("NFL.2025.Week.03.Chiefs.vs.Bills.1080p.WEB.h264-SPORTSNET");
        assert_eq!(movie_name(&nfl, &on).unwrap(), "NFL 2025 Week 03 Chiefs vs Bills 1080p");
    }

    /// The option must not reach an ordinary film. It cannot, because a
    /// film that parses cleanly leaves `extra` empty - this pins that.
    #[test]
    fn extra_words_never_touch_a_clean_film() {
        let on = NameStyle { resolution: true, extra_words: true, ..Default::default() };
        for stem in [
            "Example.Movie.2024.1080p.BluRay.x265-GRP",
            "Another.Film.2019.EXTENDED.2160p.UHD.BluRay.x265.DTS-HD.MA.7.1-FGT",
            "A.Film.2020.PROPER.REPACK.1080p.WEB-DL.DD5.1.H264-GRP",
            "Film.AKA.Other.Name.2015.1080p.BluRay.x264-GRP",
            "Le.Film.Francais.2019.FRENCH.1080p.BluRay.x264-GRP",
            "Film.Name.2017.1080p.WEBRip.x264-[YTS.AM]",
        ] {
            let parsed = p(stem);
            assert!(parsed.extra.is_empty(), "{stem} leaked {:?} into extra", parsed.extra);
            assert_eq!(movie_name(&parsed, &on), movie_name(&parsed, &NameStyle { resolution: true, ..Default::default() }),
                "{stem} renamed differently with extra words on");
        }
    }

    #[test]
    fn extra_words_filters_noise_and_declines_when_nothing_is_left() {
        let on = NameStyle { resolution: true, extra_words: true, ..Default::default() };
        // Group tag is not repeated; it has its own opt-in.
        let mut m = p("Formula1.2026.Round11.Hungary.Race.1080p-MWR");
        m.extra.push("MWR".into());
        let name = movie_name(&m, &on).unwrap();
        assert_eq!(name.matches("MWR").count(), 0, "group duplicated: {name}");

        // A hash and a long bare number describe nothing.
        let mut n = p("Something.2020.1080p-GRP");
        n.extra = vec!["b9320de1deb550b9f2f70716eabbcb19".into(), "1234567890".into()];
        assert_eq!(movie_name(&n, &on), None, "noise-only extra must decline, not collide");

        // Cap: a padded post does not rebuild the whole release name.
        let mut many = p("Event.2020.1080p-GRP");
        many.extra = (1..=12).map(|i| format!("Word{i}")).collect();
        let capped = movie_name(&many, &on).unwrap();
        assert!(capped.contains("Word6") && !capped.contains("Word7"), "{capped}");
    }

    #[test]
    fn codecs_extracted_friendly() {
        let m = p("Example.Movie.2024.1080p.BluRay.x265.DTS-HD.MA-FGT");
        assert_eq!(m.res.as_deref(), Some("1080p"));
        assert_eq!(m.vcodec.as_deref(), Some("x265"));
        assert_eq!(m.acodec.as_deref(), Some("DTS-HD"));
        assert_eq!(m.source.as_deref(), Some("BluRay"));
        assert_eq!(m.group.as_deref(), Some("FGT"));
        // h264/avc fold to x264; strongest audio wins over a weaker track.
        let a = p("Some.Show.2020.720p.WEB.h264.AC3.DDP5.1-GRP");
        assert_eq!(a.vcodec.as_deref(), Some("x264"));
        assert_eq!(a.acodec.as_deref(), Some("DDP"));
        // Atmos outranks TrueHD regardless of token order.
        assert_eq!(
            p("Film.2021.2160p.TrueHD.Atmos.x265-X").acodec.as_deref(),
            Some("Atmos")
        );
    }

    #[test]
    fn dynamic_range_extracted() {
        // A real DV release names its HDR10 base layer too - the richer
        // format has to win, whichever order the tokens come in.
        let dv = p("Dune.Part.Two.2024.2160p.WEB-DL.DDP5.1.Atmos.DV.HDR.H.265-FLUX");
        assert_eq!(dv.hdr.as_deref(), Some("DV"));
        assert_eq!(dv.acodec.as_deref(), Some("Atmos"));
        assert_eq!(dv.title, "Dune Part Two");
        assert_eq!(
            p("Film.2021.2160p.HDR.DoVi.x265-X").hdr.as_deref(),
            Some("DV")
        );
        // Plain HDR flavours, most specific first.
        assert_eq!(p("A.2020.2160p.HDR10+.x265-G").hdr.as_deref(), Some("HDR10+"));
        assert_eq!(p("A.2020.2160p.HDR10.x265-G").hdr.as_deref(), Some("HDR10"));
        assert_eq!(p("A.2020.2160p.HDR.x265-G").hdr.as_deref(), Some("HDR"));
        assert_eq!(p("A.2020.2160p.HLG.x265-G").hdr.as_deref(), Some("HLG"));
        // SDR states an absence: recording it would make a plain encode
        // look like it carries a format.
        assert_eq!(p("A.2020.1080p.SDR.x264-G").hdr, None);
        assert_eq!(p("A.2020.1080p.BluRay.x264-G").hdr, None);
        // Capturing these must not change what the title parse drops -
        // they were already stripped as furniture.
        assert_eq!(p("A.2020.2160p.HDR.DV.x265-G").title, "A");
    }

    #[test]
    fn friendly_name_builder() {
        let m = p("Example.Movie.2024.1080p.BluRay.x265.DTS-HD.MA-FGT");
        // Default: title + year + resolution only.
        // Brackets around the year and the quality facts are OFF by
        // default, so this is the shipped shape.
        let def = NameStyle { resolution: true, ..Default::default() };
        assert_eq!(movie_name(&m, &def).as_deref(), Some("Example Movie 2024 1080p"));
        // Both bracket styles on: the shape nzbfast produced before they
        // were options, and the one Plex/Jellyfin/Radarr match films on.
        let brk = NameStyle {
            resolution: true,
            year_parens: true,
            quality_brackets: true,
            ..Default::default()
        };
        assert_eq!(movie_name(&m, &brk).as_deref(), Some("Example Movie (2024) [1080p]"));
        // Everything on.
        let full = NameStyle {
            resolution: true,
            video_codec: true,
            audio_codec: true,
            source: true,
            group: true,
            year_parens: true,
            quality_brackets: true,
            extra_words: true,
        };
        assert_eq!(
            movie_name(&m, &full).as_deref(),
            Some("Example Movie (2024) [1080p BluRay x265 DTS-HD]-FGT")
        );
        // Nothing enabled → clean title + year, unbracketed.
        assert_eq!(
            movie_name(&m, &NameStyle::default()).as_deref(),
            Some("Example Movie 2024")
        );
        // No year → title alone; REMUX shows in the source slot.
        let r = p("Some.Movie.2160p.BluRay.REMUX.HEVC-GRP");
        let src = NameStyle { resolution: true, source: true, ..Default::default() };
        assert_eq!(movie_name(&r, &src).as_deref(), Some("Some Movie 2160p REMUX"));
        // Obfuscated → no friendly name, keep the original.
        assert_eq!(movie_name(&p("2137d880a074fa4075a65ce4e21d2f95"), &full), None);
    }

    /// An event post's year is its SEASON, not a release date: everything
    /// that identifies it ("Round11.Hungary.Post-Qualifying.Show") comes
    /// after the year and the title drops it. Reduced to "Title (Year)"
    /// every session of every round of 2026 rendered the same filename
    /// and collided on disk, so we decline to rename those at all and the
    /// poster's own name survives. Both stems are the user's real NZBs.
    #[test]
    fn event_releases_are_not_renamed_to_title_year() {
        let style = NameStyle { resolution: true, ..Default::default() };
        let show = p("Formula1.2026.Round11.Hungary.Post-Qualifying.Show.F1TV.WEB-DL.1080p.H264.English-MWR");
        let quali =
            p("Formula1.2026.Round11.Hungary.Qualifying.F1TV.WEB-DL.2160p.HLG.H265.DDP5.1.English-MWR");
        // Both used to render "Formula1 (2026) [1080p]".
        assert_eq!(show.title, "Formula1");
        assert_eq!(show.extra, ["Round11", "Hungary", "Post-Qualifying", "Show", "F1TV"]);
        assert_eq!(quali.extra, ["Round11", "Hungary", "Qualifying", "F1TV"]);
        // Which is the point: two different sessions no longer render one
        // filename. Neither is renamed under any style, so each keeps the
        // distinct name it was posted under.
        for s in [&NameStyle::default(), &style] {
            assert_eq!(movie_name(&show, s), None);
            assert_eq!(movie_name(&quali, s), None);
        }
        // Same for other event shapes.
        assert_eq!(movie_name(&p("MotoGP.2026.Round05.France.Race.1080p.WEB-DL-GRP"), &style), None);
        assert_eq!(movie_name(&p("NFL.2026.Week.05.Bears.at.Packers.1080p.WEB-DL-GRP"), &style), None);
        // And the guard is not really about sport: it declines whenever
        // "Title (Year)" would not name the release uniquely, which is
        // just as true of an edition the tag table doesn't know - a
        // "Final Cut" renamed to "Movie (2024)" collides with the
        // theatrical cut of the same year.
        assert_eq!(movie_name(&p("Some.Movie.2024.Final.Cut.1080p.BluRay-GRP"), &style), None);
    }

    /// Declining the RENAME must not change the KIND. `finalize_names`
    /// gates its junk sweep on `Movie | Tv`, so an event post demoted to
    /// `Other` (or flipped to `Tv`) would silently stop getting its PAR2
    /// litter cleaned up - a non-obvious coupling, pinned here because a
    /// future refactor of `extra` could so easily break it.
    #[test]
    fn declining_to_rename_an_event_leaves_it_a_movie() {
        for stem in [
            "Formula1.2026.Round11.Hungary.Post-Qualifying.Show.F1TV.WEB-DL.1080p.H264.English-MWR",
            "Formula1.2026.Round11.Hungary.Qualifying.F1TV.WEB-DL.2160p.HLG.H265.DDP5.1.English-MWR",
            "MotoGP.2026.Round05.France.Race.1080p.WEB-DL-GRP",
            "Some.Movie.2024.Final.Cut.1080p.BluRay-GRP",
        ] {
            let r = p(stem);
            assert_eq!(r.kind, Kind::Movie, "{stem}");
            assert!(!r.extra.is_empty(), "{stem}");
            assert_eq!(movie_name(&r, &NameStyle::default()), None, "{stem}");
        }
    }

    /// The opposite half: an ordinary film's year IS its release date and
    /// everything after it is furniture, so `extra` stays empty and the
    /// friendly rename behaves exactly as it always did - including for
    /// dubs, editions and split channel tokens.
    #[test]
    fn ordinary_movies_still_reduce_to_title_year() {
        let style = NameStyle { resolution: true, ..Default::default() };
        for s in [
            "The.Matrix.1999.1080p.BluRay.x264-GROUP",
            "The.Matrix.1999.2160p.UHD.BluRay.REMUX.HDR.HEVC.TrueHD.Atmos-FraMeSToR",
            "The.Matrix.1999.EXTENDED.1080p.BluRay.x264-GRP",
            "The.Matrix.1999.Directors.Cut.1080p.BluRay.x264-GRP",
            "The.Matrix.1999.German.DL.1080p.BluRay.x264-DEU",
            "The.Matrix.1999.MULTi.TRUEFRENCH.1080p.WEB.DD.5.1.H.264-GRP",
            "The.Matrix.1999.720p.BluRay.x264.AAC5.1-YTSMX",
            // Audio ahead of every other tag: only the trailing-digit
            // rule keeps "AAC5"/"DDP51" from reading as identity here.
            "The.Matrix.1999.AAC5.1.1080p.WEB-GRP",
            "The.Matrix.1999.DDP51.2160p.WEB-GRP",
        ] {
            let m = p(s);
            assert_eq!(m.kind, Kind::Movie, "{s}");
            assert!(m.extra.is_empty(), "{s}: extra={:?}", m.extra);
            assert_eq!(
                movie_name(&m, &NameStyle::default()).as_deref(),
                Some("The Matrix 1999"),
                "{s}"
            );
        }
        // And the bracketed shape is still one flag away.
        assert_eq!(
            movie_name(&p("The.Matrix.1999.1080p.BluRay.x264-GROUP"), &style).as_deref(),
            Some("The Matrix 1999 1080p")
        );
        let brk = NameStyle { resolution: true, year_parens: true, quality_brackets: true,
            ..Default::default() };
        assert_eq!(
            movie_name(&p("The.Matrix.1999.1080p.BluRay.x264-GROUP"), &brk).as_deref(),
            Some("The Matrix (1999) [1080p]")
        );
    }

    /// The token verdict the rename and the dupe key both stand on.
    #[test]
    fn token_roles_split_furniture_from_identity() {
        use TokenRole::*;
        // Quality, source, codec, container, edition, provenance: hard.
        for t in ["1080p", "WEB-DL", "x265", "REMUX", "HDR", "mkv", "Directors", "Cut", "HLG"] {
            assert_eq!(token_role(t), HardFurniture, "{t}");
        }
        // Languages are soft: dropped from a key, but never a stopper.
        for t in ["German", "English", "Hungarian", "MULTi", "TRUEFRENCH"] {
            assert_eq!(token_role(t), SoftFurniture, "{t}");
        }
        // A tag with a channel count glued on folds onto the tag…
        for t in ["AAC5", "DTS5", "DDP51", "DD5"] {
            assert_eq!(token_role(t), HardFurniture, "{t}");
        }
        // …but trailing digits alone decide nothing, so an event counter
        // stays identity. This is the whole reason the strip checks that
        // something is LEFT after the digits go.
        for t in ["Round11", "Week05", "Stage11", "Hungary", "F1TV", "11", "05"] {
            assert_eq!(token_role(t), Identity, "{t}");
        }
        // A run of nothing but language tags is furniture; the same run
        // alongside real identity tokens is carried whole.
        assert!(identity_tail(["German", "DL", "1080p"]).is_empty());
        assert_eq!(
            identity_tail(["Hungarian", "Grand", "Prix", "Race", "1080p", "WEB"]),
            ["Hungarian", "Grand", "Prix", "Race"]
        );
    }

    #[test]
    fn non_ascii_titles_keep_distinct_dedupe_keys() {
        // §5 phase 2c: norm_title used to drop every non-ASCII character,
        // so all Japanese TV titles shared the key "t:" - one `titles`
        // row, one poster, for unrelated shows.
        let a = p("進撃の巨人.S04E28.1080p.WEB.H264-GRP");
        let b = p("涼宮ハルヒの憂鬱.S01E01.720p");
        assert_eq!(a.kind, Kind::Tv);
        assert_eq!(a.title, "進撃の巨人");
        assert_eq!(a.season, Some(4));
        assert_eq!(a.episode, Some(28));
        assert_ne!(a.key, b.key);
        assert_eq!(a.key, "t:進撃の巨人");
        // Movies too - and Cyrillic/Greek, already-shipped UI locales.
        assert_eq!(p("君の名は.2016.1080p.BluRay.x264").key, "m:君の名は:2016");
        assert_ne!(p("Брат.1997.1080p").key, p("Брат2.2000.1080p").key);
        // ASCII normalization is unchanged.
        assert_eq!(norm_title("The.Daily-Show!"), "the daily show");
    }

    #[test]
    fn daily_dotted_date_is_tv_not_movie() {
        // Dotted daily dates parsed as Movie-of-2026 before; compact
        // datecodes already worked.
        let d = p("The.Daily.Show.2026.07.21.Guest.1080p.WEB.h264-GRP");
        assert_eq!(d.kind, Kind::Tv);
        assert_eq!(d.title, "The Daily Show");
        assert_eq!(d.year, None);
        // Movies with a trailing year stay movies.
        let m = p("Blade.Runner.2049.2017.2160p.WEB-DL");
        assert_eq!(m.kind, Kind::Movie);
        assert_eq!(m.year, Some(2017));
    }

    /// The air date is a daily show's whole identity, so the split that
    /// turns it into a folder year and a filename has to refuse anything
    /// that is not a real date rather than emit half of one.
    #[test]
    fn air_dates_split_into_a_year_and_a_name() {
        let parts = air_date_parts;
        assert_eq!(parts("20260721"), Some(("2026".into(), "2026.07.21".into())));
        assert_eq!(parts("20150615"), Some(("2015".into(), "2015.06.15".into())));
        // Both conventions the parser normalizes reach the same name.
        assert_eq!(
            air_date_parts(p("At.Midnight.150615.720p.HDTV-GRP").date.as_deref().unwrap()),
            air_date_parts(p("At.Midnight.20150615.720p.HDTV-GRP").date.as_deref().unwrap())
        );
        assert_eq!(
            parts(p("The.Daily.Show.2026.07.21.1080p.WEB-GRP").date.as_deref().unwrap()),
            Some(("2026".into(), "2026.07.21".into()))
        );
        // Declines: wrong width, non-digits, out-of-range fields.
        for s in ["", "2026072", "202607211", "2026-07-21", "2026o721", "20261321", "20260732",
                  "20260700", "20260021", "00000101"] {
            assert_eq!(air_date_parts(s), None, "{s:?} is not an air date");
        }
        // And declines dates that pass a flat 1..=31 day check but do
        // not exist. These were filed as real episodes, under a season
        // folder named after a day that never happened.
        for s in ["20260231", "20260431", "20260631", "20260931", "20261131", "20260230"] {
            assert_eq!(air_date_parts(s), None, "{s:?} is not a day that exists");
        }
        // February is the leap rule, in all three of its cases.
        assert!(air_date_parts("20240229").is_some(), "2024 is a leap year");
        assert_eq!(air_date_parts("20260229"), None, "2026 is not");
        assert_eq!(air_date_parts("19000229"), None, "a century is not, unless…");
        assert!(air_date_parts("20000229").is_some(), "…it divides by 400");
        // The month lengths themselves, at their real boundaries.
        assert!(air_date_parts("20260430").is_some());
        assert!(air_date_parts("20261231").is_some());
    }

    #[test]
    fn year_as_season_marker_is_tv() {
        // "S2026E015" (annual sports/soaps) parsed as Movie before -
        // while dupe_key already treated it as TV.
        let r = p("WWE.Raw.S2026E015.1080p.WEB.h264-GRP");
        assert_eq!(r.kind, Kind::Tv);
        assert_eq!((r.season, r.episode), (Some(2026), Some(15)));
        // A bare "S2026" (no episode) stays a year, not a season pack.
        let m = p("Escape.From.S2026.2160p.WEB-DL");
        assert_eq!(m.kind, Kind::Movie);
    }

    #[test]
    fn movie_with_year_and_quality() {
        let m = p("The.Matrix.1999.2160p.UHD.BluRay.REMUX.HDR.HEVC.TrueHD.Atmos-FraMeSToR");
        assert_eq!(m.kind, Kind::Movie);
        assert_eq!(m.title, "The Matrix");
        assert_eq!(m.year, Some(1999));
        assert_eq!(m.res.as_deref(), Some("2160p"));
        assert!(m.remux);
        assert_eq!(m.group.as_deref(), Some("FraMeSToR"));
        assert_eq!(m.key, "m:the matrix:1999");
        assert_eq!(quality_label(&m), "2160p REMUX");
    }

    #[test]
    fn tv_episode_and_season_pack_share_a_key() {
        let e = p("Severance.S02E03.1080p.WEB-DL.DDP5.1.H.264-NTb");
        assert_eq!(e.kind, Kind::Tv);
        assert_eq!(e.title, "Severance");
        assert_eq!((e.season, e.episode), (Some(2), Some(3)));
        assert_eq!(e.source.as_deref(), Some("WEB"));
        let s = p("Severance.S01.2160p.ATVP.WEB-DL.DDP5.1.DV.HEVC-CasStudio");
        assert_eq!((s.season, s.episode), (Some(1), None));
        assert_eq!(e.key, s.key);
    }

    #[test]
    fn multi_episode_markers() {
        // §7b: S01E01E02 / S01E01-E02 / S01E01-02 carry a second episode.
        for stem in [
            "Show.Name.S01E01E02.1080p.WEB.h264-GRP",
            "Show.Name.S01E01-E02.1080p.WEB.h264-GRP",
            "Show.Name.S01E01-02.1080p.WEB.h264-GRP",
        ] {
            let p = p(stem);
            assert_eq!(p.kind, Kind::Tv, "{stem}");
            assert_eq!((p.season, p.episode, p.episode2), (Some(1), Some(1), Some(2)), "{stem}");
        }
        // Quality furniture glued to the episode is NOT a second episode,
        // and a lower second number is a typo, not a range.
        assert_eq!(p("Show.S01E05-720p.HDTV").episode2, None);
        assert_eq!(p("Show.S01E05-E03.1080p.WEB").episode2, None);
        // Single episodes and packs stay episode2-free.
        assert_eq!(p("Severance.S02E03.1080p.WEB-DL").episode2, None);
        assert_eq!(p("Severance.S01.2160p.WEB-DL").episode2, None);
    }

    #[test]
    fn title_that_is_a_year() {
        let m = p("2012.2009.1080p.BluRay.x264-METiS");
        assert_eq!(m.title, "2012");
        assert_eq!(m.year, Some(2009));
        let br = p("Blade.Runner.2049.2017.2160p.WEB-DL.x265-XX");
        assert_eq!(br.title, "Blade Runner 2049");
        assert_eq!(br.year, Some(2017));
    }

    #[test]
    fn no_year_movie_cuts_at_first_tag() {
        let m = p("Inception.1080p.BluRay.x264-SPARKS");
        assert_eq!(m.title, "Inception");
        assert_eq!(m.year, None);
        assert_eq!(m.key, "m:inception");
    }

    #[test]
    fn nxnn_form_and_hyphen_title() {
        let e = p("Spider-Man.Into.the.Spider-Verse.2018.1080p.BluRay.x264-GROUP");
        assert_eq!(e.title, "Spider-Man Into the Spider-Verse");
        let t = p("The.Wire.3x07.720p.HDTV.x264-BATV");
        assert_eq!((t.season, t.episode), (Some(3), Some(7)));
        assert_eq!(t.title, "The Wire");
    }

    #[test]
    fn obfuscated_stems_are_other() {
        assert_eq!(p("2137d880a074fa4075a65ce4e21d2f95").kind, Kind::Other);
        assert_eq!(p("n1iY94U6fTpMVY9GPD").kind, Kind::Other);
        assert_eq!(p("abcdef12.34567890abcdef12.deadbeef99").kind, Kind::Other);
        // …but a real name with a digit-bearing word is NOT obfuscated.
        assert_eq!(p("Apollo.13.1995.1080p.BluRay.x264-XX").kind, Kind::Movie);
    }

    #[test]
    fn rot13_letter_rotated_stem_is_rescued() {
        // Letters ROT13, digits posted as-is - the classic obfuscation.
        // ("The.Wire.3x07.720p.HDTV.x264-BATV" rotated.)
        let t = p("Gur.Jver.3k07.720c.UQGI.k264-ONGI");
        assert_eq!(t.kind, Kind::Tv);
        assert_eq!(t.title, "The Wire");
        assert_eq!((t.season, t.episode), (Some(3), Some(7)));
        assert_eq!(t.res.as_deref(), Some("720p"));
        assert_eq!(t.source.as_deref(), Some("HDTV"));
        assert_eq!(t.group.as_deref(), Some("BATV"));
        assert_eq!(t.key, "t:the wire");
    }

    #[test]
    fn rot18_rotated_stem_is_rescued() {
        // Reported example: letters ROT13 AND digits ROT5 ("275c" →
        // "720p", "K719" → "X264"). Under that same decode "F56r53" is
        // S01E08 - the digits rotate with everything else.
        let t = p("Gur Ovoyr F56r53 275c Oyhenl K719-trpxbf");
        assert_eq!(t.kind, Kind::Tv);
        assert_eq!(t.title, "The Bible");
        assert_eq!((t.season, t.episode), (Some(1), Some(8)));
        assert_eq!(t.res.as_deref(), Some("720p"));
        assert_eq!(t.source.as_deref(), Some("BluRay"));
        assert_eq!(t.group.as_deref(), Some("geckos"));
        assert_eq!(t.key, "t:the bible");

        // Movie form: "The.Matrix.1999.1080p.BluRay.x264-GRP" in ROT18.
        // The letters-only decode also parses (BluRay survives) but the
        // ROT18 decode carries more furniture (year + res) and wins.
        let m = p("Gur.Zngevk.6444.6535c.Oyhenl.k719-TEC");
        assert_eq!(m.kind, Kind::Movie);
        assert_eq!(m.title, "The Matrix");
        assert_eq!(m.year, Some(1999));
        assert_eq!(m.res.as_deref(), Some("1080p"));
        assert_eq!(m.source.as_deref(), Some("BluRay"));
    }

    #[test]
    fn rot18_wins_digit_ties_and_part_suffix_never_blocks_rescue() {
        // "rzretrapl.f58r69.qiqevc.kivq" = ROT18 "emergency.s03e14.
        // dvdrip.xvid". Letters-only decoding scores the same signals
        // (S58E69) - the plausible season must win the tie.
        let p = parse_release("rzretrapl.f58r69.qiqevc.kivq.vag-jcv");
        assert!(p.rescued, "{p:?}");
        assert_eq!(p.title.to_lowercase(), "emergency");
        assert_eq!((p.season, p.episode), (Some(3), Some(14)), "{p:?}");
        // A rotated RAR part suffix (".e64") parses as a bare episode -
        // that alone must not block the rescue.
        let p = parse_release("rzretrapl.f58r69.qiqevc.kivq.vag-jcv.e64");
        assert!(p.rescued, "{p:?}");
        assert_eq!((p.season, p.episode), (Some(3), Some(14)), "{p:?}");
        // A letters-only ROT13 post (digits NOT rotated: "f01r01" =
        // s01e01) keeps its plain numbers - the ROT18 variant would
        // read S56E56, implausible, and loses the tie.
        let p = parse_release("gur.jver.f01r01.qiqevc.kivq");
        assert!(p.rescued, "{p:?}");
        assert_eq!(p.title.to_lowercase(), "the wire");
        assert_eq!((p.season, p.episode), (Some(1), Some(1)), "{p:?}");
    }

    #[test]
    fn rot13_rescue_never_fires_on_plain_names() {
        // Real furniture in the direct parse ⇒ no rescue attempted.
        let m = p("The.Matrix.1999.2160p.UHD.BluRay.REMUX.HDR.HEVC.TrueHD.Atmos-FraMeSToR");
        assert_eq!(m.title, "The Matrix");
        // A bare title with no furniture stays itself: its rotation is
        // unpronounceable garbage with no scene tokens.
        let bare = p("Inception");
        assert_eq!((bare.kind.clone(), bare.title.as_str()), (Kind::Movie, "Inception"));
        // Hash and blob names stay Other - their decodes carry no
        // furniture either.
        assert_eq!(p("2137d880a074fa4075a65ce4e21d2f95").kind, Kind::Other);
        assert_eq!(p("abcdef12.34567890abcdef12.deadbeef99").kind, Kind::Other);
    }

    #[test]
    fn software_posts_get_their_own_kind() {
        let s = p("CCleaner.Professional.Plus.v6.36.11041.x64.Setup");
        assert_eq!(s.kind, Kind::Software);
        assert_eq!(s.title, "CCleaner Professional Plus");
        assert_eq!(s.key, "s:ccleaner professional plus");
        let a = p("Adobe.Photoshop.2025.v26.3.Multilingual.x64-TEAM");
        assert_eq!(a.kind, Kind::Software);
        assert_eq!(a.title, "Adobe Photoshop 2025");
        // Strong keyword alone decides; the title cuts at the earliest
        // marker, weak or strong.
        let k = p("Some.App.Incl.Keygen-GROUP");
        assert_eq!(k.kind, Kind::Software);
        assert_eq!(k.title, "Some App");
    }

    #[test]
    fn movies_with_software_ish_words_stay_movies() {
        assert_eq!(p("Setup.2011.1080p.BluRay.x264-GRP").kind, Kind::Movie);
        assert_eq!(p("Leon.The.Professional.1994.1080p.BluRay.x264-GRP").kind, Kind::Movie);
        assert_eq!(p("V.For.Vendetta.2006.1080p.BluRay.x264-GRP").kind, Kind::Movie);
        assert_eq!(p("The.Matrix.1999.1080p.BluRay.x264-GRP").kind, Kind::Movie);
    }

    #[test]
    fn scene_music_splits_on_its_fields() {
        // The shape the normal tokenizer cannot see: hyphens separate
        // fields, underscores stand in for spaces.
        let m = p("Pink_Floyd-The_Dark_Side_Of_The_Moon-1973-EOS");
        assert_eq!(m.kind, Kind::Music);
        assert_eq!(m.title, "Pink Floyd - The Dark Side Of The Moon");
        assert_eq!(m.year, Some(1973));
        assert_eq!(m.group.as_deref(), Some("EOS"));
        assert_eq!(m.key, "mu:pink floyd the dark side of the moon");
        // Format marker in a later field decides without a trailing year
        // rule, and picks the kind.
        let f = p("Massive_Attack-Mezzanine-CD-FLAC-1998-GROUP");
        assert_eq!(f.kind, Kind::Music);
        assert_eq!(f.title, "Massive Attack - Mezzanine");
        assert_eq!(f.year, Some(1998));
        // Various-artists compilations use the same convention.
        let va = p("VA-Now_Thats_What_I_Call_Music_100-2018-NOiR");
        assert_eq!(va.kind, Kind::Music);
        assert_eq!(va.title, "VA - Now Thats What I Call Music 100");
        // A leading disc/track-number field is scene convention, and
        // measured on a live index it is the common case - without
        // dropping it the artist parses as "00".
        let n = p("00-piero_piccioni-the_light_at_the_edge_of_the_world-cd-flac-2014-GRP");
        assert_eq!(n.kind, Kind::Music);
        assert_eq!(n.title, "piero piccioni - the light at the edge of the world");
        let t = p("000-va-bravo_hits_57-2cd-flac-2007-GRP");
        assert_eq!(t.title, "va - bravo hits 57");
    }

    #[test]
    fn tagged_music_and_books_parse() {
        let m = p("Pink Floyd - The Dark Side of the Moon (1973) [FLAC]");
        assert_eq!(m.kind, Kind::Music);
        assert_eq!(m.title, "Pink Floyd - The Dark Side of the Moon");
        assert_eq!(m.year, Some(1973));
        let mp3 = p("Adele - 30 (2021) [MP3 320]");
        assert_eq!(mp3.kind, Kind::Music);
        assert_eq!(mp3.title, "Adele - 30");
        // "epub" is not release furniture to is_tag, so the marker has to
        // close the title region itself or it lands in the title.
        let b = p("Frank Herbert - Dune (1965) [epub]");
        assert_eq!(b.kind, Kind::Book);
        assert_eq!(b.title, "Frank Herbert - Dune");
        assert_eq!(b.year, Some(1965));
        assert_eq!(b.key, "bk:frank herbert dune");
        for stem in [
            "Andy Weir - Project Hail Mary (2021) [mobi]",
            "Andy Weir - Project Hail Mary (2021) [azw3]",
        ] {
            let x = p(stem);
            assert_eq!(x.kind, Kind::Book, "{stem}");
            assert_eq!(x.title, "Andy Weir - Project Hail Mary", "{stem}");
        }
        // Both halves come back apart for the providers.
        assert_eq!(credit_split(&b.title), Some(("Frank Herbert", "Dune")));
        assert_eq!(credit_split("no separator here"), None);
    }

    #[test]
    fn music_keys_ignore_the_edition_year() {
        // A remaster, a vinyl rip and the original are one album, so
        // they have to land on one card - unlike movies, whose year is
        // part of their identity.
        let a = p("Pink_Floyd-The_Dark_Side_Of_The_Moon-1973-EOS");
        let b = p("Pink_Floyd-The_Dark_Side_Of_The_Moon-2011-REMASTERED-GRP");
        assert_eq!(a.key, b.key);
    }

    #[test]
    fn video_evidence_beats_any_audio_marker() {
        // A concert BluRay says FLAC and is still a film; an episode is
        // still an episode. This gate is the whole safety margin for
        // claiming FLAC/MP3 as music markers at all.
        assert_eq!(p("Some.Concert.2019.1080p.BluRay.FLAC.x264-GRP").kind, Kind::Movie);
        assert_eq!(p("Some.Show.S01E01.720p.WEB.FLAC-GRP").kind, Kind::Tv);
        assert_eq!(p("Some.Doc.2019.2160p.REMUX.FLAC-GRP").kind, Kind::Movie);
        // The downloader's own lowercase movie convention has the exact
        // field count and trailing year of a scene album, and is saved
        // only by having no underscore.
        assert_eq!(p("the-matrix-1999-FGT").kind, Kind::Movie);
        assert_eq!(p("the-flash-s01e01-720p").kind, Kind::Tv);
        // A film whose FIRST word is a format marker keeps its title -
        // markers are only read from index 1 on.
        assert_eq!(p("Vinyl.S01E01.720p.WEB-GRP").kind, Kind::Tv);
        assert_eq!(p("Mobi.2019.1080p.WEB-GRP").kind, Kind::Movie);
    }

    #[test]
    fn allcaps_folds_to_title_case() {
        assert_eq!(p("KILL.BILL.VOL.1.2003.2160p-iVy").title, "Kill Bill Vol 1");
    }

    #[test]
    fn fold_preserves_numerals_and_acronyms() {
        // Roman numerals and household acronyms survive the fold...
        assert_eq!(p("PLANET.EARTH.II.2016.2160p.WEB-GRP").title, "Planet Earth II");
        assert_eq!(p("the.office.us.s01e01.720p.web-grp").title, "The Office US");
        assert_eq!(p("WWE.MONDAY.NIGHT.RAW.2026.720p.WEB-GRP").title, "WWE Monday Night Raw");
        assert_eq!(p("US.MARSHALS.1998.1080p.BluRay-GRP").title, "US Marshals");
        // ...but a single-word title is a TITLE, not a suffix: Peele's
        // "Us" must not become "US". (The fold's own >3-letters gate
        // already leaves a lone lowercase "us" untouched - pinned here
        // so a widened fold can't quietly turn it into an acronym.)
        assert_eq!(p("us.2019.1080p.web-grp").title, "us");
        // Mixed-case stems still pass through byte-for-byte.
        assert_eq!(p("Us.2019.1080p.WEB-GRP").title, "Us");
    }

    #[test]
    fn languages_come_from_furniture_not_title() {
        assert_eq!(p("Der.Untergang.2004.German.1080p.BluRay.x264-GRP").langs, ["german"]);
        assert_eq!(p("Drama.Show.E178.2001.KOR.CATV.DivX-EyeMaX").langs, ["korean"]);
        assert_eq!(p("Some.Film.2020.MULTi.1080p.WEB").langs, ["multi"]);
        // A film titled "Rus" is not Russian; untagged stays empty.
        assert!(p("Rus.2019.1080p.WEB").langs.is_empty());
        assert!(p("Plain.Film.2020.1080p.WEB").langs.is_empty());
    }

    #[test]
    fn group_rejects_years_tags_and_numbers() {
        assert_eq!(p("Movie.Name.2003.1080p-2003").group, None);
        assert_eq!(p("Movie.Name.2003.1080p-REMUX").group, None);
        let ok = p("Movie.Name.2003.1080p.WEB-NTb");
        assert_eq!(ok.group.as_deref(), Some("NTb"));
        // WEB-DL's DL must not be eaten as a group when it ends the stem.
        let dl = p("Show.S01E01.1080p.WEB-DL");
        assert_eq!(dl.group, None);
        assert_eq!(dl.source.as_deref(), Some("WEB"));
    }


    /// Reposters append their own tag after the real group, and with
    /// `NameStyle::group` on it would land in the filename.
    #[test]
    fn reposter_tags_never_become_the_group() {
        let g = |s: &str| p(s).group;
        assert_eq!(g("Example.Movie.2024.1080p.x264-GRP-Obfuscated").as_deref(), Some("GRP"));
        assert_eq!(g("Example.Movie.2024.1080p.x264-Obfuscated"), None);
        // They chain, in any case, in any order.
        assert_eq!(
            g("Example.Movie.2024.1080p.x264-GRP-xpost-Obfuscated").as_deref(),
            Some("GRP")
        );
        assert_eq!(
            g("Example.Movie.2024.1080p.x264-GRP-NZBGeek-postbot-RP").as_deref(),
            Some("GRP")
        );
        assert_eq!(g("Example.Movie.2024.1080p.x264-GRP-RAKUVFINHEL").as_deref(), Some("GRP"));
        assert_eq!(g("Example.Movie.2024.1080p.x264-GRP-AlteZachen").as_deref(), Some("GRP"));
        assert_eq!(g("Example.Movie.2024.1080p.x264-GRP.-Chamele0n").as_deref(), Some("GRP"));
        // A real group that merely CONTAINS one of the words is untouched.
        assert_eq!(g("Example.Movie.2024.1080p.x264-RPGroup").as_deref(), Some("RPGroup"));
        assert_eq!(g("Example.Movie.2024.1080p.x264-Sampler").as_deref(), Some("Sampler"));
        assert_eq!(g("Example.Movie.2024.1080p.x264-GEROVA").as_deref(), Some("GEROVA"));
        // Sonarr strips a bare "-1" too; we do not, it is too risky - so
        // the tail keeps hiding the group instead of exposing a wrong one.
        assert_eq!(g("Example.Movie.2024.1080p.x264-GRP-1"), None);
        // Nothing but tags: no group, and the stem survives as the title.
        assert_eq!(group_of("-Obfuscated"), None);
        assert_eq!(p("-Obfuscated").title, "-Obfuscated");
        // The tag leaves no trace in the rest of the parse either.
        let m = p("Example.Movie.2024.1080p.x264-GRP-Obfuscated");
        assert_eq!(m.title, "Example Movie");
        assert_eq!(m.year, Some(2024));
        assert!(!m.extra.iter().any(|w| w.eq_ignore_ascii_case("obfuscated")));
    }

    /// Fixed-width hash renames seen in the wild, full-stem anchored.
    #[test]
    fn obfuscated_hash_shapes_are_caught() {
        for s in [
            "ABCDEFGHIJK123",                   // 11 caps + 3 digits
            "abcdefghijkl123",                  // 12 lowercase + 3 digits
            "d41d8cd98f00b204e9800998ecf8427e", // 32 hex, md5
            "abcdefabcdefabcdefabcdefabcdefAb", // 32 hex, no digits, one cap
            "abcdefghijklmnopqrstuvwx",         // 24 lowercase
            "a1b2c3d4e5f6g7h8i9j0k1l2",         // 24 alnum
        ] {
            assert!(looks_obfuscated(s), "should be obfuscated: {s}");
        }
        // Real names of the same length are separated, and separators are
        // what the anchored shapes cannot contain.
        for s in [
            "The Lord of the Rings The Two Tow", // 33 chars with spaces
            "Everything Everywhere All At Once", // 33 chars with spaces
            "Pirates.Of.The.Caribbean.At.Worl",  // 32 chars, dotted
            "The.Matrix.Reloaded.2003.1080p.BluRay.x264-AMIABLE",
            "Show.S01E01.1080p.WEB-DL.DD5.1.H264-NTb",
            "Week 03",
            // 32 characters of run-together title. The md5 rule is
            // anchored on hex for exactly this: it is unpresentable
            // hex-shaped renames we are after, not any 32-character run
            // of letters somebody typed without separators.
            "ThelordoftheringsReturnoftheking",
        ] {
            assert!(!looks_obfuscated(s), "should NOT be obfuscated: {s}");
        }
    }

    /// Real stems from the live index. The lowercase-base32 shape was
    /// missed by every earlier rule: no digits, no internal capitals.
    #[test]
    fn obfuscated_lowercase_blobs_are_caught() {
        for s in [
            "nzqymzflnjiyztgyntcynzzytq",
            "MI4WGMRRMI4DAZBWME3GMOLEMDKNRZ",
            "c1bceab2fac4d74f47b0a0e18311ec5c53",
            "ZO01uZT4YhQAGrDQLC3U1",
        ] {
            assert!(looks_obfuscated(s), "should be obfuscated: {s}");
        }
        for s in [
            "Oppenheimer",
            "Interstellar",
            "The.Matrix.1999.1080p.BluRay.x264-GROUP",
            "Nirvana-Nevermind-1991-FAF",
        ] {
            assert!(!looks_obfuscated(s), "should NOT be obfuscated: {s}");
        }
    }

    // Hostile-input fuzz: the indexer runs parse_release over every scraped
    // subject, which an attacker controls. The parser byte-indexes &str in
    // several spots (tv_marker, the version closure, the leading-zero SSEE
    // case), so a subject engineered to place a multi-byte UTF-8 char at a
    // slice boundary would panic the scan thread (DoS) if any of those sites
    // were unguarded. Throw adversarial unicode, control chars, ROT13 bait,
    // and pathological separator runs at every public entry point and assert
    // it never panics (a panic here fails the test = a real finding).
    #[test]
    fn parser_never_panics_on_hostile_input() {
        // Cheap deterministic LCG so the corpus is reproducible.
        let mut state: u64 = 0x9e3779b97f4a7c15;
        let mut next = || {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            (state >> 33) as u32
        };
        // Bytes chosen to stress char-boundary math: multi-byte UTF-8 leads,
        // scene separators, digits, and the S/E/v/x markers that drive the
        // byte-slicing branches.
        let alphabet: &[&str] = &[
            "s", "e", "v", "x", "S", "E", "0", "1", "2", "6", "9", ".", "_", "-", " ",
            "[", "]", "(", ")", "é", "ß", "λ", "中", "日", "\u{200f}", "\u{0301}", "🎬",
            "\u{feff}", "\t", "\n", "web", "dl", "1080p", "x265", "2024", "s01e01",
        ];
        // A few fixed adversarial seeds alongside the random corpus.
        let seeds = [
            "",
            "s01ée01",           // multi-byte char right after the season 's'
            "vé.6",              // version closure: 'v' then a multi-byte char
            "0é01",              // leading-zero SSEE lookalike with a wide char
            "中文.2024.1080p.WEB-中",
            "\u{feff}s2026é015",
            "----",
            "a-b-c-d-e-f",
            "s99999999999999999999e88888888888888888888",
            &"x".repeat(5000),
            &"1.".repeat(2000),
        ];
        let run = |stem: &str| {
            let parsed = parse_release(stem);
            // Exercise the downstream formatters too - they slice on the
            // parsed fields.
            let _ = norm_title(stem);
            let _ = sanitize_name(stem);
            let _ = quality_label(&parsed);
            let style = NameStyle::default();
            let _ = quality_suffix(&parsed, &style);
            let _ = movie_name(&parsed, &style);
        };
        for s in seeds {
            run(s);
        }
        for _ in 0..20_000 {
            let len = (next() % 40) as usize;
            let mut stem = String::new();
            for _ in 0..len {
                stem.push_str(alphabet[(next() as usize) % alphabet.len()]);
            }
            run(&stem);
        }
    }

    /// Stage 4 writes real files and folders, and a finished tree gets
    /// moved to a NAS/SMB share, so the Windows rules apply whatever host
    /// produced the name. Enqueue-time folder naming had these guarantees
    /// already; the friendly renamer did not, and could emit a hidden
    /// name, a name Windows silently truncates, or a device stem.
    #[test]
    fn a_friendly_name_is_portable() {
        // Leading dot: hidden on macOS/Linux, and not what anyone asked
        // for on Windows either.
        assert_eq!(sanitize_name(".Hidden Movie (2024)"), "Hidden Movie (2024)");
        assert_eq!(sanitize_name("..Hidden Movie (2024)"), "Hidden Movie (2024)");
        // Trailing dot / space: Windows strips them, so the name on disk
        // stops matching the name we recorded.
        assert_eq!(sanitize_name("Movie (2024)."), "Movie (2024)");
        assert_eq!(sanitize_name("Movie (2024). "), "Movie (2024)");
        // Reserved DOS device stems: creating one opens the device.
        assert_eq!(sanitize_name("CON"), "_CON");
        assert_eq!(sanitize_name("com1"), "_com1");
        assert_eq!(sanitize_name("nul.mkv"), "_nul.mkv");
        // Path separators and the rest of the illegal set never survive.
        for s in ["../../etc/passwd", "a\\b", "Movie <2024>", "Q|A?", "x\u{7}y"] {
            let out = sanitize_name(s);
            assert_eq!(
                std::path::Path::new(&out).components().count(),
                1,
                "not a single component: {s:?} -> {out:?}"
            );
            assert!(!out.chars().any(|c| c.is_control()), "{s:?} -> {out:?}");
        }
        // Nothing nameable left: an empty name, so the caller declines.
        for s in ["", "...", " . . ", "----", ":"] {
            assert_eq!(sanitize_name(s), "", "{s:?} should be unnameable");
        }
    }

    /// A colon separates a title from its subtitle, so it has to be
    /// SPELLED OUT, not blanked - "Alien Romulus" reads as one title.
    #[test]
    fn a_colon_becomes_a_separator() {
        assert_eq!(sanitize_name("Alien: Romulus"), "Alien - Romulus");
        assert_eq!(sanitize_name("Alien:Romulus"), "Alien-Romulus");
        assert_eq!(sanitize_name("Alien : Romulus"), "Alien - Romulus");
        // Doubled separators the expansion creates are collapsed back.
        assert_eq!(sanitize_name("Alien:: Romulus"), "Alien - Romulus");
        assert_eq!(sanitize_name("Alien -: Romulus"), "Alien - Romulus");
        // A dangling colon leaves no dangling separator behind.
        assert_eq!(sanitize_name("Alien: "), "Alien");
        // A hyphen that was always there is not a separator run and is
        // left exactly as the poster wrote it.
        assert_eq!(sanitize_name("Spider-Man: Homecoming"), "Spider-Man - Homecoming");
        assert_eq!(sanitize_name("Mission Impossible - Fallout"), "Mission Impossible - Fallout");
    }

    /// The same guarantees through the real movie entry point, and a
    /// legitimately-named release left byte-for-byte alone.
    #[test]
    fn movie_names_are_portable() {
        let style = NameStyle { resolution: true, year_parens: true, ..Default::default() };
        let name = |s: &str| movie_name(&p(s), &style);

        assert_eq!(
            name("Alien: Romulus 2024 1080p WEB-DL x264-GRP").as_deref(),
            Some("Alien - Romulus (2024) 1080p")
        );
        // "CON (2024) 1080p" is not a device stem, but the title alone
        // is - so the guard has to survive the whole build, not just the
        // title. With no year and no quality facts movie_name declines
        // anyway, which is the other half of the same safety.
        assert_eq!(name("CON 2024 1080p x264-GRP").as_deref(), Some("CON (2024) 1080p"));
        assert_eq!(name("CON"), None);
        // Negative: an ordinary release is not reshaped by any of this.
        assert_eq!(
            name("The.Matrix.1999.1080p.BluRay.x264-AMIABLE").as_deref(),
            Some("The Matrix (1999) 1080p")
        );
        // Whatever the shape, what comes out is a usable component.
        for s in [".Hidden.2024.1080p", "Movie..2024.1080p", "CON.2024.1080p", "..2024.1080p"] {
            if let Some(n) = name(s) {
                assert!(!n.starts_with('.') && !n.ends_with('.'), "{s:?} -> {n:?}");
                assert!(!n.ends_with(' '), "{s:?} -> {n:?}");
                assert!(!n.is_empty());
            }
        }
    }

    /// A reversed stem has to land on EXACTLY the parse its forward form
    /// would have given - a flip that recovers the resolution but drops
    /// half the name is not a rescue.
    #[test]
    fn reversed_stems_parse_as_their_forward_form() {
        let same = |fwd: &str| {
            let want = p(fwd);
            let backwards: String = fwd.chars().rev().collect();
            let mut got = p(&backwards);
            assert!(got.rescued, "not rescued: {backwards}");
            got.rescued = want.rescued; // the only field that may differ
            assert_eq!(format!("{got:?}"), format!("{want:?}"), "{backwards}");
        };
        same("Example.Movie.2024.1080p.x264-GRP");
        same("Show.Name.S01E02.720p.HDTV.x264-GRP");
        same("Show.Name.S01E012.2160p.WEB-DL.x265-GRP");
        same("The.Big.Show.2024.480p.DVDRip.XviD-GRP");
        // The shape as posted, group tag left forwards - the flip reads
        // it as "PRG", which is what a whole-stem reversal can promise.
        let m = p("GRP-462x.p0801.4202.eivoM.elpmaxE");
        assert_eq!(m.title, "Example Movie");
        assert_eq!(m.year, Some(2024));
        assert_eq!(m.res.as_deref(), Some("1080p"));
        assert!(m.rescued);
    }

    /// And the other half: an ordinary name is never flipped, and a
    /// backwards-looking token alone is not enough to believe one.
    #[test]
    fn forward_names_are_never_reversed() {
        for s in [
            "The.Matrix.1999.1080p.BluRay.x264-AMIABLE",
            "Show.S01E01.1080p.WEB-DL.DD5.1.H264-NTb",
            "Frank Herbert - Dune 1965 epub",
            "Formula1.2026.Round11.Hungary.Race.1080p-GRP",
            // "p027" inside a word is not a token, so nothing triggers.
            "Chapter.Mp027x.Notes",
            "Series.Movies.Codeps.Notes",
            // A real trigger token whose flip says nothing: the reversed
            // "title" is the bare number 4202, so the flip is refused
            // and the poster's own name stands.
            "Chapter.p027.2024",
        ] {
            assert!(!p(s).rescued, "should not have flipped: {s}");
        }
        assert_eq!(p("The.Matrix.1999.1080p.BluRay.x264-AMIABLE").title, "The Matrix");
        assert_eq!(p("Chapter.p027.2024").title, "Chapter p027");
    }

    /// A forward name that happens to carry ONE backwards-shaped token -
    /// a page or catalog marker ("p027", "p0801"), an "NNeNNs" reference
    /// - is still a forward name. Reversal keeps vowels, so the flipped
    /// title reads as English too and the English test cannot tell the
    /// two apart; these are the stems that flipped anyway and renamed a
    /// legitimately-named file to "epaT 1080p".
    #[test]
    fn one_backwards_token_does_not_flip_a_forward_name() {
        let style = NameStyle { resolution: true, ..Default::default() };
        for s in [
            // Only the marker flips, and one resolution is not two facts.
            "Concert.Bootleg.p0801.Tape",
            "Label.Sampler.p027.Promo",
            // A forward YEAR, a forward SOURCE and a forward air date all
            // say the stem already reads forwards.
            "Christmas.p0801.Home.Movies.2019",
            "Example.Movie.DVDRip-p0801",
            "Podcast.p027.260721.Notes",
            // Flips to S43E21: two fields, one token, and a season nobody
            // has ever posted.
            "Lecture.Notes.12e34s.Extra",
        ] {
            assert!(!p(s).rescued, "should not have flipped: {s}");
        }
        // Nothing to offer, so nothing is renamed - and the kind stays
        // Movie rather than being demoted (see finalize_names).
        let tape = p("Concert.Bootleg.p0801.Tape");
        assert_eq!(tape.title, "Concert Bootleg p0801 Tape");
        assert_eq!(movie_name(&tape, &style), None);
        assert_eq!(p("Lecture.Notes.12e34s.Extra").kind, Kind::Movie);
        // Where a name IS offered it is built from the poster's own
        // words forwards, never "9102 seivoM emoH 1080p".
        assert_eq!(
            movie_name(&p("Christmas.p0801.Home.Movies.2019"), &style).as_deref(),
            Some("Christmas p0801 Home Movies 2019")
        );
    }

    /// A bare YYMMDD run is a daily show's whole identity, but six digits
    /// are also how ids and part counts look - so it only reads as a date
    /// when it validates AND nothing stronger already named the release.
    #[test]
    fn six_digit_datecodes_read_as_air_dates() {
        let d = |s: &str| p(s).date;
        let show = p("Show.Name.260721.1080p.WEB.x264-GRP");
        assert_eq!(show.date.as_deref(), Some("20260721"));
        assert_eq!(show.kind, Kind::Tv);
        assert_eq!(show.title, "Show Name");
        assert_eq!(show.year, None);
        // Both conventions normalize to the same identity.
        assert_eq!(d("Show.Name.260721.1080p.WEB.x264-GRP"),
                   d("Show.Name.20260721.1080p.WEB.x264-GRP"));

        // Not a date: month or day out of range, or a year that reads as
        // decades away. The token is left alone as an ordinary word, and
        // a release with no other TV evidence stays a Movie.
        for s in [
            "Show.Name.261321.1080p.WEB-GRP", // month 13
            "Show.Name.260732.1080p.WEB-GRP", // day 32
            "Show.Name.260021.1080p.WEB-GRP", // month 00
            "Show.Name.260700.1080p.WEB-GRP", // day 00
            "Show.Name.123456.1080p.WEB-GRP", // an id, not a date
            "Show.Name.991231.1080p.WEB-GRP", // 2099 is not an air date
        ] {
            assert_eq!(d(s), None, "{s}");
            assert_eq!(p(s).kind, Kind::Movie, "{s}");
            assert!(p(s).title.contains(&s[10..16]), "{s} -> {}", p(s).title);
        }

        // Six digits that are part of an id are not a token at all.
        for s in ["Show.Name.ID260721.1080p.WEB-GRP", "Show.Name.260721x.1080p.WEB-GRP"] {
            assert_eq!(d(s), None, "{s}");
        }
        // …and neither is a leading run, which is the title.
        assert_eq!(d("260721.1080p.WEB-GRP"), None);

        // Stronger signals win outright: a four-digit year or an SxxEyy
        // marker means the release is not naming its episode by day.
        let m = p("Example.Movie.2024.260721.1080p.WEB-GRP");
        assert_eq!(m.date, None);
        assert_eq!(m.kind, Kind::Movie);
        assert_eq!((m.title.as_str(), m.year), ("Example Movie", Some(2024)));
        let t = p("Show.Name.S01E02.260721.1080p.WEB-GRP");
        assert_eq!(t.date, None);
        assert_eq!((t.season, t.episode), (Some(1), Some(2)));
        // Eight digits stay unambiguous, so a year alongside is fine.
        assert_eq!(d("Show.Name.2024.20260721.1080p.WEB-GRP").as_deref(), Some("20260721"));
    }

    /// The gate every out-of-band name has to pass before it may rename
    /// a user's file: a container Title, a naming oracle's answer. The
    /// NO cases are the ones that matter - each of them is a string a
    /// real muxer or a real API has handed back.
    #[test]
    fn release_names_are_told_from_human_titles() {
        for s in [
            "Example.Movie.2019.1080p.BluRay.x264-GRP",
            "Show.Name.S01E02.1080p.WEB.h264-POKE",
            "Example Movie 2019 1080p BluRay x264-GRP",
            "Dune.Part.Two.2024.1080p.WEB.h264-ETHEL",
            "Example.Movie.2019.2160p.WEB-DL.DDP5.1.HDR.H.265-BYNDR",
        ] {
            assert!(looks_like_release_name(s), "{s} should read as a release");
        }
        for s in [
            "",
            "Sintel",
            "Episode 3",
            "The Movie",           // a human title: no furniture at all
            "Big Buck Bunny",
            "encoded by Handbrake",
            "video",
            // A member of a release, not the release.
            "Example.Movie.2019.1080p.BluRay.x264-GRP/movie.mkv",
            // Hash-shaped: what a reposter writes when it writes anything.
            "d41d8cd98f00b204e9800998ecf8427e",
            "n1iY94U6fTpMVY9GPD",
        ] {
            assert!(!looks_like_release_name(s), "{s:?} should NOT read as a release");
        }
        // One signal is not enough - a year alone is how plenty of
        // muxers title a film, and renaming on it would lose the name
        // the poster actually gave.
        assert!(!looks_like_release_name("The Movie 2019"));
    }
}

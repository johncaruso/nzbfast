//! Smart Folders + cleanup rules (two organizational features in the
//! spirit of Usenapp's).
//!
//! - A rules engine evaluated at enqueue: each rule matches the NZB name
//!   (regex, falling back to plain keyword) plus optional size bounds,
//!   and routes the job to a category (= out_root subfolder). First
//!   match wins. A rule can additionally ask for TV filing: at
//!   completion the job is moved to `[Show]/Season NN/` and its video
//!   renamed `Show - S01E02.ext`, reusing wall.rs's scene-name parser.
//! - Cleanup rules: a list of file extensions deleted from a job's
//!   folder after it completes successfully.

use std::path::{Path, PathBuf};
use tracing::{info, warn};

use crate::MutexExt;
use serde::{Deserialize, Serialize};

/// One Smart Folder rule as stored in settings.json ("smart_folders").
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    #[serde(default)]
    pub name: String,
    /// Regex on the NZB name (case-insensitive). A pattern that doesn't
    /// compile is used as a plain keyword substring instead, so
    /// "matrix" and "^The\.Bear\." both do what they look like.
    #[serde(default, rename = "match")]
    pub pattern: String,
    /// Skip the rule when THIS matches (same regex-or-keyword rules).
    #[serde(default)]
    pub not_match: String,
    /// Size bounds in bytes, 0 = unbounded. The UI sends SAB-style
    /// strings ("200M"); both forms deserialize.
    #[serde(default, deserialize_with = "de_size")]
    pub min_size: u64,
    #[serde(default, deserialize_with = "de_size")]
    pub max_size: u64,
    /// Category to file the job under (empty = keep the caller's).
    #[serde(default)]
    pub category: String,
    /// File as TV at completion: [Show]/Season NN/ + video rename.
    #[serde(default)]
    pub tv_sort: bool,
}

/// Accept a byte count or a "200M"-style string (what the row editor
/// sends verbatim from its text input).
fn de_size<'de, D: serde::Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
    struct V;
    impl serde::de::Visitor<'_> for V {
        type Value = u64;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("bytes or a size string like 200M")
        }
        fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<u64, E> {
            Ok(v)
        }
        fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<u64, E> {
            Ok(v.max(0) as u64)
        }
        fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<u64, E> {
            Ok(v.max(0.0) as u64)
        }
        fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<u64, E> {
            if s.trim().is_empty() {
                return Ok(0);
            }
            crate::serve::parse_size(s).ok_or_else(|| E::custom(format!("bad size {s:?}")))
        }
    }
    d.deserialize_any(V)
}

/// Case-insensitive regex match, or keyword substring if the pattern
/// isn't a valid regex. Empty pattern matches everything. The one
/// implementation lives in nzbkit::categories (user categories ride the
/// same rule syntax - 24D); this delegate keeps every caller here
/// byte-compatible.
fn pat_match(pattern: &str, name: &str) -> bool {
    nzbkit::categories::pat_match(pattern, name)
}

impl Rule {
    pub fn matches(&self, name: &str, size: u64) -> bool {
        if !pat_match(&self.pattern, name) {
            return false;
        }
        if !self.not_match.trim().is_empty() && pat_match(&self.not_match, name) {
            return false;
        }
        if self.min_size > 0 && size < self.min_size {
            return false;
        }
        if self.max_size > 0 && size > self.max_size {
            return false;
        }
        true
    }
}

/// First rule matching this job, or None. Rule order IS priority.
pub fn first_match<'a>(rules: &'a [Rule], name: &str, size: u64) -> Option<&'a Rule> {
    rules.iter().find(|r| r.matches(name, size))
}

/// "par2, sfv, .srr" → ["par2", "sfv", "srr"] (lowercased, dots and
/// leading wildcards stripped - people paste "*.par2" from other apps).
pub fn parse_ext_list(v: &str) -> Vec<String> {
    v.split(',')
        .map(|e| e.trim().trim_start_matches(['*', '.']).to_ascii_lowercase())
        .filter(|e| !e.is_empty())
        .collect()
}

/// Archive-password conventions in a submitted NZB name, most explicit
/// first: `Name{{pw}}` (SAB/NZBGet), `Name password=pw`, `Name{pw}`
/// (single brace - some indexers). Returns (password, cleaned name);
/// the wrapper ALWAYS comes off the name so a password never leaks into
/// the display name or the output folder.
pub fn name_password(name: &str) -> Option<(String, String)> {
    if let (Some(a), Some(b)) = (name.find("{{"), name.rfind("}}"))
        && b > a + 2
    {
        let pw = name[a + 2..b].to_string();
        let clean = format!("{}{}", &name[..a], &name[b + 2..])
            .trim()
            .to_string();
        return Some((pw, clean));
    }
    if let Some(i) = name.to_ascii_lowercase().find("password=") {
        let pw = name[i + 9..].trim().trim_end_matches('}').to_string();
        if !pw.is_empty() {
            let clean = name[..i]
                .trim_end_matches(['{', ' ', '.', '-', '_'])
                .trim()
                .to_string();
            return Some((pw, clean));
        }
    }
    if let (Some(a), Some(b)) = (name.find('{'), name.rfind('}'))
        && b > a + 1
    {
        let pw = &name[a + 1..b];
        if !pw.is_empty() && !pw.contains(['{', '}']) {
            let clean = format!("{}{}", &name[..a], &name[b + 1..])
                .trim()
                .to_string();
            return Some((pw.to_string(), clean));
        }
    }
    None
}

/// TV filing target for a release stem, from wall.rs's parser:
/// subdirectory ("The Bear/Season 03") plus, when a specific episode is
/// known, the rename base ("The Bear - S03E05"). None = not confidently
/// TV (movies, obfuscated names, unknown season) - the job stays where it
/// landed rather than being mis-filed.
///
/// A daily show carries no season/episode numbers at all, only the air
/// date ("The.Daily.Show.2026.07.21.1080p.WEB.x264-GRP"), and requiring a
/// season left every one of them unfiled and unrenamed. Their identity IS
/// the date, so they file under `Show/Season YYYY` as
/// `Show - YYYY.MM.DD` - the convention Sonarr and every library reads
/// back. Only a date that survives [`nzbkit::release::air_date_parts`]
/// counts, and a title that reads as a hash is refused outright: the
/// parser's `daily` flag fires on any 8-digit run, which is enough to
/// say "not a movie" but not enough to write a name with.
pub fn tv_path(stem: &str) -> Option<(String, Option<String>)> {
    tv_path_as(stem, sanitize)
}

/// [`tv_path`] as the builds before the strong sanitiser computed it:
/// the show's path-hostile glyphs blanked to a space and nothing else,
/// so a colon left "Star Trek Discovery" where today it leaves
/// "Star Trek - Discovery".
///
/// A library filed by one of those builds is still on disk under the old
/// spelling, and both the delete and the play path RECOMPUTE the base
/// from the stem at call time - so without this an episode filed last
/// week stopped being recognised as its own job's file: delete-with-files
/// removed nothing and Play reported no playable file. Filing consults it
/// too, or the same show would start a second tree beside the first.
fn legacy_tv_path(stem: &str) -> Option<(String, Option<String>)> {
    tv_path_as(stem, legacy_sanitize)
}

fn tv_path_as(stem: &str, show_of: impl Fn(&str) -> String) -> Option<(String, Option<String>)> {
    let p = crate::wall::parse_release(stem);
    if p.kind != crate::wall::Kind::Tv {
        return None;
    }
    let show = show_of(&p.title);
    if show.is_empty() {
        return None;
    }
    let Some(season) = p.season.filter(|&s| s > 0) else {
        if title_is_unpresentable(&p.title) {
            return None;
        }
        let (year, air) = nzbkit::release::air_date_parts(p.date.as_deref()?)?;
        return Some((
            format!("{show}/Season {year}"),
            Some(format!("{show} - {air}")),
        ));
    };
    let dir = format!("{show}/Season {season:02}");
    // Multi-episode posts keep the whole range in the filed name
    // ("Show - S01E01-E02") so the second episode isn't silently
    // dropped from the library.
    let base = p.episode.map(|e| match p.episode2 {
        Some(e2) => format!("{show} - S{season:02}E{e:02}-E{e2:02}"),
        None => format!("{show} - S{season:02}E{e:02}"),
    });
    Some((dir, base))
}

// ---------------------------------------------------------------------------
// Episode titles in TV names (TODO 78) - the last *arr rename parity piece.
// ---------------------------------------------------------------------------

/// What TV filing wrote after the episode base, as the job recorded it at
/// the moment it wrote it: the episode-title segment (`" - Children"`,
/// empty unless the `rename_episode_titles` setting was on AND the cache
/// knew the title) and the quality suffix (`" [1080p]"`).
///
/// The two travel together because ownership of a name inside a SHARED
/// season folder is decided by the WHOLE tail - see
/// [`is_filed_episode_file`]. A delete that knew only the suffix half
/// matched nothing at all once a title was in the name, which silently
/// turned "delete this episode" and "play this episode" into no-ops.
///
/// A struct rather than two more `&str` parameters for the reason
/// [`crate::serve::FinalizeJob`] is one: they are the same type, and a
/// caller that swapped them would have compiled.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FiledTail {
    pub title: String,
    pub suffix: String,
}

impl FiledTail {
    /// The quality suffix alone - every filed job carried exactly this
    /// before episode titles existed, and a record written back then
    /// still means it.
    ///
    /// Tests only: production builds this from the job record, where the
    /// title half comes from the same place and cannot be forgotten.
    #[cfg(test)]
    pub fn suffix(suffix: &str) -> Self {
        Self {
            title: String::new(),
            suffix: suffix.to_string(),
        }
    }

    fn lowered(&self) -> Self {
        Self {
            title: self.title.to_ascii_lowercase(),
            suffix: self.suffix.to_ascii_lowercase(),
        }
    }
}

/// Bytes one path component gets on every filesystem this lands on -
/// ext4, APFS, NTFS, and the SMB/NFS shares `move_completed` writes to.
const COMPONENT_BYTES: usize = 255;

/// Room held back from [`COMPONENT_BYTES`] for the extension chain, so
/// the title's budget depends only on the episode base and the quality
/// suffix.
///
/// It has to. The title is RECORDED ([`FiledTail`]) and later matched
/// literally, while the extension differs between files of one episode -
/// a `.mkv` feature beside its `.en.srt`. Budgeting against the real
/// extension would truncate the two differently and the record could
/// only hold one of the answers.
const EXT_RESERVE: usize = 16;

/// How many episodes one post may claim before we stop collecting titles
/// for it. A double or triple is ordinary; a range in the dozens is a
/// season pack wearing an episode's clothes, and joining 24 titles
/// produces a name that is all truncation and no information.
const MAX_EP_SPAN: u32 = 8;

/// The separator between the episode base and its title, which is
/// Sonarr's default and what Plex, Jellyfin and Emby read back.
const TITLE_SEP: &str = " - ";

/// Episode titles for ONE show, read out of the enrichment cache before
/// any renaming starts.
///
/// Cache-only by construction: this owns its answers already, so no
/// rename can reach the network however obscure the show is or however
/// long the job runs. That is the house rule stated in `tasks.rs` -
/// network lives on the enricher threads - and it is also why a cache
/// miss simply produces the name we produced before this existed, rather
/// than a deferred second rename. A rename that lands after an *arr has
/// imported the file breaks the import (memory `nzbfast-auto-rename`).
///
/// Empty is the ordinary case, and means every name below is
/// byte-identical to what it was.
#[derive(Clone, Debug, Default)]
pub struct EpisodeTitles {
    by_num: std::collections::HashMap<(u32, u32), String>,
}

impl EpisodeTitles {
    /// Build from `(season, episode, title)` triples - the shape
    /// `wall::EpInfo` carries out of the `eplist:*` cache blob. Blank
    /// titles are dropped here so no caller has to test for them.
    pub fn new(eps: impl IntoIterator<Item = (u32, u32, String)>) -> Self {
        Self {
            by_num: eps
                .into_iter()
                .filter(|(_, _, name)| !name.trim().is_empty())
                .map(|(s, e, name)| ((s, e), name))
                .collect(),
        }
    }

    /// The `" - Episode Title"` segment for a release stem, ready to sit
    /// between `base` and `suffix`, or an empty string when there is no
    /// title to write.
    ///
    /// `base` and `suffix` are passed only for their LENGTH: the finished
    /// component has to fit a filesystem name, and the title is the part
    /// that gives way (the base identifies the episode and the suffix
    /// tells one release from another - neither can be shortened without
    /// breaking something).
    pub fn segment(&self, stem: &str, base: &str, suffix: &str) -> String {
        if self.by_num.is_empty() {
            return String::new();
        }
        let Some((season, ep, ep2)) = confident_episode(stem) else {
            return String::new();
        };
        let Some(joined) = self.joined(season, ep, ep2) else {
            return String::new();
        };
        // The same strong, colon-aware sanitiser the show name gets: a
        // title arrives from a third party and can hold anything a
        // human typed, including "/" and a trailing dot.
        let title = nzbkit::release::sanitize_name(&joined);
        if title.is_empty() {
            return String::new();
        }
        let spent = base.len() + TITLE_SEP.len() + suffix.len() + EXT_RESERVE;
        let title = fit_title(&title, COMPONENT_BYTES.saturating_sub(spent));
        if title.is_empty() {
            return String::new();
        }
        format!("{TITLE_SEP}{title}")
    }

    /// Every title this post covers, as one string.
    ///
    /// Sonarr's conventions, because the libraries downstream were built
    /// against them: distinct titles join with `" + "`, and a post that
    /// covers both halves of a two-parter collapses to the shared stem
    /// ("The Ceremony (1)" + "The Ceremony (2)" -> "The Ceremony")
    /// rather than repeating it. Episodes the cache doesn't know are
    /// skipped, so a partly-known double still gets the title it has.
    fn joined(&self, season: u32, ep: u32, ep2: Option<u32>) -> Option<String> {
        let last = ep2
            .filter(|&e2| e2 > ep)
            .unwrap_or(ep)
            .min(ep.saturating_add(MAX_EP_SPAN - 1));
        let titles: Vec<&str> = (ep..=last)
            .filter_map(|e| self.by_num.get(&(season, e)))
            .map(|t| t.trim())
            .filter(|t| !t.is_empty())
            .collect();
        let first = *titles.first()?;
        // Part collapse. Judged on ALL of them, and only when what is
        // left still says something: a two-parter titled bare "Part 1" /
        // "Part 2" strips to nothing, and joining those is the honest
        // answer.
        if titles.len() > 1 {
            let stem = strip_part_marker(first);
            if !stem.is_empty()
                && titles
                    .iter()
                    .all(|t| strip_part_marker(t).eq_ignore_ascii_case(stem))
            {
                return Some(stem.to_string());
            }
        }
        let mut out: Vec<&str> = Vec::with_capacity(titles.len());
        for t in titles {
            if !out.iter().any(|seen| seen.eq_ignore_ascii_case(t)) {
                out.push(t);
            }
        }
        Some(out.join(" + "))
    }
}

/// The episode-title segment filing wrote for a job's OWN episode, which
/// is what [`FiledTail`] has to record so a later delete or play can find
/// the file again.
///
/// Computed from the same inputs `tv_organize` computes it from, so for
/// the single-episode jobs that ownership matching applies to at all it
/// is the same string. (A season pack has no single episode base -
/// [`filed_bases`] is empty for one - so it never reaches a matcher.)
///
/// One seam is deliberately not chased: a show still filed under a
/// PRE-sanitiser folder name ([`legacy_tv_path`]) has a base of a
/// different length, so a title long enough to be truncated could be
/// truncated by one word more or less there. The consequence is a name
/// this stops recognising, which leaves a file behind - the cheap
/// mistake this whole matcher exists to prefer.
pub fn filed_title_segment(stem: &str, suffix: &str, titles: &EpisodeTitles) -> String {
    match tv_path(stem) {
        Some((_, Some(base))) => titles.segment(stem, &base, suffix),
        _ => String::new(),
    }
}

/// The season and episode numbers behind a release stem, but only when
/// [`tv_path`] would also have built a specific episode base from it.
///
/// Kept in step with `tv_path_as`'s confident arm on purpose: a title may
/// only ever decorate a name that already names one episode. A dated
/// show (no season, no number) is deliberately excluded - the cache is
/// keyed by season and number, and matching one by airdate is the
/// separate piece of work TODO 78 records as a follow-up.
fn confident_episode(stem: &str) -> Option<(u32, u32, Option<u32>)> {
    let p = crate::wall::parse_release(stem);
    if p.kind != crate::wall::Kind::Tv {
        return None;
    }
    let season = p.season.filter(|&s| s > 0)?;
    Some((season, p.episode?, p.episode2))
}

/// A title with its trailing part marker removed: "The Ceremony (2)",
/// "The Ceremony: Part 2", "The Ceremony, Part Two" all reduce to "The
/// Ceremony". Returns the title unchanged when it carries no marker.
///
/// Only a marker at the END counts, and only a recognised NUMBER after
/// the word: "Part of the Plan" and "Parting Shot" are titles, not
/// halves of one.
fn strip_part_marker(title: &str) -> &str {
    let s = title.trim_end();
    // "The Ceremony (2)"
    if let Some(body) = s.strip_suffix(')')
        && let Some(open) = body.rfind('(')
        && is_part_number(&body[open + 1..])
    {
        return trim_marker_sep(&body[..open]);
    }
    // "The Ceremony: Part 2" and every separator it is written with.
    // `to_ascii_lowercase` preserves byte length, so the offset it finds
    // indexes the original.
    let lower = s.to_ascii_lowercase();
    if let Some(at) = lower.rfind("part ")
        && is_part_number(&s[at + "part ".len()..])
    {
        return trim_marker_sep(&s[..at]);
    }
    s
}

fn trim_marker_sep(s: &str) -> &str {
    s.trim_end().trim_end_matches([':', '-', ',']).trim_end()
}

/// Does this read as a part number - "2", "Two", "II"? Closed lists, not
/// a parser: everything it accepts is a word we DELETE from the user's
/// filename, so a false positive costs information that was in the title.
fn is_part_number(tok: &str) -> bool {
    let t = tok.trim();
    if !t.is_empty() && t.len() <= 3 && t.bytes().all(|b| b.is_ascii_digit()) {
        return true;
    }
    matches!(
        t.to_ascii_lowercase().as_str(),
        "one" | "two" | "three" | "four" | "five" | "six" | "i" | "ii" | "iii" | "iv" | "v" | "vi"
    )
}

/// Cut a title down to `room` BYTES at a word boundary, or to nothing
/// when no useful piece of it fits.
///
/// Bytes, not characters: the limit filesystems enforce is on the encoded
/// name, and a Cyrillic or Japanese title spends two or three bytes per
/// character. Never splits a UTF-8 sequence, and prefers a whole-word cut
/// so the result reads as a shortened title rather than as damage.
fn fit_title(title: &str, room: usize) -> String {
    if title.len() <= room {
        return title.to_string();
    }
    // Longest prefix inside the budget that is also a character boundary.
    let mut end = room.min(title.len());
    while end > 0 && !title.is_char_boundary(end) {
        end -= 1;
    }
    let cut = &title[..end];
    // Back off to the last word boundary, unless that would leave a
    // fragment too short to say anything - a single word longer than the
    // whole budget is better cut mid-word than dropped.
    let at_word = cut.rfind(' ').unwrap_or(0);
    let kept = if at_word * 2 >= end {
        &cut[..at_word]
    } else {
        cut
    };
    // Truncation can expose a trailing separator or a dot, which is what
    // `sanitize_name` had already removed from the end of the full title.
    kept.trim_end()
        .trim_end_matches([',', ':', ';', '-', '_', '.', '('])
        .trim_end()
        .to_string()
}

/// Delete the file(s) a completed job was TV-filed to, WITHOUT touching
/// the shared `Show/Season NN` directory or any sibling episode.
///
/// After TV filing a job's `out_dir` is the shared season folder, so
/// `remove_dir_all` on it wipes the whole season (bug sweep: an "upgrade"
/// or a history "delete files" destroyed every episode). We instead match
/// only files whose name begins with this release's episode-unique base
/// (`Show - S03E05.`), which catches the renamed video and any sidecar
/// sharing that stem (see [`is_rename_tail`] for the sidecars it can't
/// reach) but never a sibling - E06's files begin `Show - S03E06.`.
///
/// The episode base alone is NOT release-specific: an upgrade files the
/// better copy into the same season folder under the same
/// `Show - S03E05` base, differing only in the quality suffix
/// [`tv_organize`] appended. Matching on the base plus ANY rename tail is
/// therefore quality-blind, and deleting the superseded copy took the
/// freshly-downloaded replacement with it - the user ended up with
/// neither. `suffix` is THIS release's [`nzbkit::release::quality_suffix`]
/// (recomputed by the caller from the job's own stem and the live
/// NameStyle, exactly as filing computed it), and the tail must begin with
/// it before any of the checks below run. An empty `suffix` means
/// auto-rename was off, so the base alone is all filing had - today's
/// behaviour.
///
/// Returns how many files went, and the first refusal if any (see
/// [`FiledDelete`]). Removes 0 (a deliberate no-op, never a broad delete)
/// when the episode can't be identified confidently - a release that
/// didn't parse as a specific episode, or a filed name that didn't follow
/// the rename (season-pack / collision fallback / a suffix that no longer
/// matches because the naming settings changed).
pub fn delete_filed_episode(dir: &Path, stem: &str, tail: &FiledTail) -> FiledDelete {
    let bases = filed_bases(stem);
    if bases.is_empty() {
        return FiledDelete::default();
    }
    // Read once, for the whole delete: see `remove_user_file`.
    // Inline rather than parked with the sweeps' deferred worker ON
    // PURPOSE: this deletes inside the user's LIBRARY, where a hidden
    // staging folder is not ours to create - and it is one file, bounded
    // by TRASH_DEADLINE plus the latch.
    let recoverable = delete_to_trash();
    let tail_lower = tail.lowered();
    let Ok(rd) = std::fs::read_dir(dir) else {
        return FiledDelete::default();
    };
    let mut out = FiledDelete::default();
    // Optimistic until the first removal, then only as strong as the
    // weakest one: a set of files where some reached a Trash and some
    // did not is not recoverable, and saying so would send the user
    // looking for a file that is not there.
    let mut all_trashed = true;
    let mut any_removed = false;
    for entry in rd.flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default();
        if is_filed_episode_file(&name, &bases, &tail_lower) {
            match remove_user_file(&path, recoverable) {
                Ok(how) => {
                    out.removed += 1;
                    any_removed = true;
                    all_trashed &= how == Removed::Trashed;
                }
                Err(e) => {
                    warn!(target: "smart", "delete filed {}: {e}", path.display());
                    // First refusal only: they all carry the same reason
                    // (one volume, one Trash), and the caller shows this
                    // to a person rather than listing every file.
                    out.kept.get_or_insert_with(|| e.to_string());
                }
            }
        }
    }
    out.removed_as = if any_removed && all_trashed {
        Removed::Trashed
    } else {
        Removed::Gone
    };
    out
}

/// What one [`delete_filed_episode`] managed to do.
///
/// The count alone was enough while a failed delete could only be a
/// permanent-delete error nobody could act on. Now a recoverable delete
/// the Trash refuses LEAVES the episode in the user's library (see
/// [`remove_user_file`]) while its History row goes, so the reason has to
/// travel back to whoever can put it in front of them.
pub struct FiledDelete {
    /// How many files were removed.
    pub removed: usize,
    /// Why at least one file is still in the library, when one is.
    pub kept: Option<String>,
    /// What the removals actually were. `Gone` unless EVERY one of them
    /// was verified into a Trash: a mixed outcome must not be reported
    /// as recoverable, because the half the user goes looking for may be
    /// the half that is not there.
    pub removed_as: Removed,
}

impl Default for FiledDelete {
    fn default() -> Self {
        FiledDelete {
            removed: 0,
            kept: None,
            // Nothing was removed, so there is nothing to promise back.
            removed_as: Removed::Gone,
        }
    }
}

/// Every spelling of this release's filed episode base, ASCII-lowercased:
/// the one filing would write today, plus the one an older build wrote
/// for the same release when the show name reshapes (see
/// [`legacy_tv_path`]). Empty when the stem doesn't name one episode.
fn filed_bases(stem: &str) -> Vec<String> {
    let mut out = Vec::with_capacity(2);
    for path in [tv_path(stem), legacy_tv_path(stem)] {
        if let Some((_, Some(base))) = path {
            let base = base.to_ascii_lowercase();
            if !out.contains(&base) {
                out.push(base);
            }
        }
    }
    out
}

/// Does `name` belong to the release filed under one of `bases` with
/// `tail`?
///
/// The one rule that decides ownership inside a SHARED season folder, so
/// both the delete ([`delete_filed_episode`]) and the play
/// ([`find_filed_episode_media`]) paths ask it rather than each carrying
/// their own idea of "this job's file": match "Show - S03E05", then the
/// episode title THIS job wrote (when it wrote one), then THIS release's
/// own quality suffix, then only a tail our own rename can produce -
/// never another quality of the same episode, a sibling ("…E06"), a
/// longer episode number ("…E050"), or the user's own Sonarr/Plex file.
///
/// The title is matched LITERALLY, from the job's own record of what it
/// wrote ([`FiledTail`]), never recomputed: the cache behind it is
/// refreshed every 12 hours and a provider that re-spells an episode
/// would otherwise re-point this at a file that no longer exists - or,
/// worse, at a neighbouring one. A record that carries no title (every
/// job filed before this existed, and every job filed with the setting
/// off) leaves this exactly as it was.
///
/// All arguments arrive ASCII-lowercased.
fn is_filed_episode_file(name: &str, bases: &[String], tail_lower: &FiledTail) -> bool {
    /// An empty part of the tail matches without consuming anything -
    /// which is what makes "no title recorded" mean "as it was before".
    fn strip<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
        if prefix.is_empty() {
            Some(s)
        } else {
            s.strip_prefix(prefix)
        }
    }
    bases.iter().any(|base_lower| {
        name.strip_prefix(base_lower.as_str())
            .and_then(|rest| strip(rest, &tail_lower.title))
            .and_then(|rest| strip(rest, &tail_lower.suffix))
            .is_some_and(is_rename_tail)
    })
}

/// The video file a TV-filed job actually owns in its shared
/// `Show/Season NN` folder, for playing back a completed history row.
///
/// "The biggest media file in `out_dir`" is the right answer for an
/// unfiled job, whose directory is private, and the wrong one here: a
/// filed job's `out_dir` is the whole season, so pressing Play on E01
/// served whichever episode happened to be largest - usually E02. Ownership
/// in a shared folder is exactly what [`is_filed_episode_file`] decides for
/// the delete path, so this asks the same question and serves what it
/// names.
///
/// Top level only, and videos only: filing renames the episode to
/// `Show - S03E05 [1080p].mkv` in the season folder itself, while any
/// subdirectory the job shipped (`Subs/`, `extras/`) moved in under its own
/// name and is not ours to claim. Symlinks are never served (see
/// [`is_real_file`]) - a RAR can carry one, and "the file matching this
/// name" would otherwise resolve a planted link to anything the daemon can
/// read.
///
/// Returns None when nothing matches - a season pack, a collision
/// fallback, files moved away by hand, or naming settings that changed
/// since filing. The caller reports "no playable file" rather than falling
/// back to a guess, because every guess here is a sibling episode.
pub fn find_filed_episode_media(dir: &Path, stem: &str, tail: &FiledTail) -> Option<PathBuf> {
    let bases = filed_bases(stem);
    if bases.is_empty() {
        return None;
    }
    let tail_lower = tail.lowered();
    let mut hits: Vec<PathBuf> = std::fs::read_dir(dir)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            is_real_file(p)
                && VIDEO_EXTS.contains(&ext_of(p).as_str())
                && p.file_name().is_some_and(|n| {
                    is_filed_episode_file(
                        &n.to_string_lossy().to_ascii_lowercase(),
                        &bases,
                        &tail_lower,
                    )
                })
        })
        .collect();
    // Sorted, not largest-first: "the biggest match" is the quality-blind
    // pick that [`delete_filed_episode`]'s doc comment describes going
    // wrong, and the suffix has already narrowed this to one release. Sort
    // only so a directory listing's arbitrary order cannot make two calls
    // disagree.
    hits.sort();
    hits.into_iter().next()
}

/// Is `rest` - everything after the episode base in a filed file's name -
/// a tail OUR rename produced, rather than part of a longer title?
///
/// The only shapes [`nzbkit::release::quality_suffix`] can emit are the
/// empty string, `" [tokens]"`, `"-Group"`, and `" [tokens]-Group"`, always
/// followed by `"."` and an extension. That tail belongs to the VIDEO file
/// [`tv_organize`] renamed - and to any sidecar that happens to share the
/// renamed stem, since `.srt`/`.nfo` are matched by the same base. Sidecars
/// are NOT generally renamed, though: `tv_organize` rewrites only
/// [`VIDEO_EXTS`], so a subtitle posted as `Show.S03E05.720p-GRP.en.srt`
/// keeps that name in the shared season folder and never matches this tail.
/// The limitation is [`delete_filed_episode`]'s: it leaves such a sidecar
/// behind. Deliberate - an unmatched name cannot be proven to be ours, and
/// a stray subtitle is a far cheaper mistake than a deleted episode.
///
/// Accepting a bare leading space instead matched the DEFAULT Sonarr/Plex
/// layout - `The Bear - S03E05 - Children.mkv` leaves `" - Children.mkv"` -
/// so deleting a job filed into the user's real library season folder
/// deleted the user's own copy of the episode, which we never downloaded
/// and cannot replace.
///
/// Whatever follows the base is refused when it reads as the second
/// episode of a range, in EVERY separator the convention is written with:
/// our own multi-episode name is `Show - S03E05-E06`, and the user's
/// library may hold `-06`, `.06`, `.E06`, `.S03E06`, `x06` or `_06`. Each
/// of those files carries E06's only copy as well, and we never downloaded
/// E06. Only `-` and `.` can reach an accepting arm at all; the rest fall
/// through to the final refusal, and are pinned by test.
///
/// `rest` arrives ASCII-lowercased from [`delete_filed_episode`]; the
/// `e`-prefix checks assume that.
fn is_rename_tail(rest: &str) -> bool {
    // Optional " [1080p WEB h264]".
    let rest = match rest.strip_prefix(" [") {
        Some(r) => match r.split_once(']') {
            Some((_, tail)) => tail,
            None => return false,
        },
        None => rest,
    };
    if let Some(tail) = rest.strip_prefix('.') {
        // Our own tail is nothing but the extension chain (".mkv",
        // ".en.srt"), so only the FIRST segment could be a range's second
        // episode - later ones are the extension. A dot-spelled range
        // ("Show - S03E05.06.mkv") lands here rather than in the group
        // arm below, so it needs the same refusal.
        let first = tail.split('.').next().unwrap_or_default();
        let token = first.split([' ', '[']).next().unwrap_or_default();
        return !tail.is_empty() && !reads_as_episode_number(token);
    }
    // Optional "-GRP". A group token is one word, so a space anywhere in
    // it means this is a title, not our suffix.
    let Some(g) = rest.strip_prefix('-') else {
        return false;
    };
    let Some((group, ext)) = g.split_once('.') else {
        return false;
    };
    !group.is_empty()
        && !ext.is_empty()
        && !group.contains([' ', '[', ']'])
        && !(group.starts_with('e') && group[1..].starts_with(|c: char| c.is_ascii_digit()))
        // A group that reads as an episode number is the second episode of
        // a range ("Show - S03E05-06"), never a release group. Groups that
        // merely BEGIN with a digit ("3LT0N", "2HD") are real and stay ours.
        && !reads_as_episode_number(group)
}

/// Does this lowercased token read as an episode number - the second half
/// of a multi-episode range - rather than as part of our own suffix?
///
/// The three spellings a range's second episode takes once its separator
/// has been consumed: bare `06`, `e06`, and the full `s03e06`. A token that
/// merely CONTAINS digits is not one, which is what keeps real release
/// groups (`3lt0n`, `2hd`) and quality tokens (`x264`, `1080p`) ours.
fn reads_as_episode_number(tok: &str) -> bool {
    fn digits(s: &str) -> bool {
        !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
    }
    if digits(tok) {
        return true;
    }
    if let Some(ep) = tok.strip_prefix('e') {
        return digits(ep);
    }
    match tok.strip_prefix('s').and_then(|r| r.split_once('e')) {
        Some((season, ep)) => digits(season) && digits(ep),
        None => false,
    }
}

/// Does this parsed title read as a hash rather than a show name?
///
/// [`nzbkit::release::looks_obfuscated`] judges a stem as posted, but a
/// title reaches us AFTER the parser has title-cased a single-case stem
/// ("nzqymzflnjiyztgyntcynzzytq" -> "Nzqymzflnjiyztgyntcynzzytq"), which
/// is exactly the transformation its single-case rule can no longer see
/// through. Judging the lowered form as well restores it; a real title
/// carries separators and is refused by every anchored rule whatever its
/// case.
fn title_is_unpresentable(title: &str) -> bool {
    nzbkit::release::looks_obfuscated(title)
        || nzbkit::release::looks_obfuscated(&title.to_ascii_lowercase())
}

/// Strip path-hostile characters from a show title. The show directory
/// and every episode name below are built on it, so it gets the same
/// strong, colon-aware treatment as the movie path - see
/// [`nzbkit::release::sanitize_name`]. Empty means nothing nameable
/// survived, and [`tv_path`] declines.
fn sanitize(t: &str) -> String {
    nzbkit::release::sanitize_name(t)
}

/// What [`sanitize`] was before it grew colon expansion and the strong
/// filename rules: path-hostile glyphs blanked, whitespace collapsed.
/// Never used to write a new name - only to RECOGNISE the names older
/// builds already wrote (see [`legacy_tv_path`]).
fn legacy_sanitize(t: &str) -> String {
    t.chars()
        .map(|c| if "/\\:*?\"<>|".contains(c) { ' ' } else { c })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// Video payload. Disc images (`iso`/`img`) count: they ARE the feature for
/// a disc rip, so they must be recognised as the largest video (the sample
/// gate measures against it) as well as kept.
const VIDEO_EXTS: &[&str] = &[
    "mkv", "mp4", "avi", "m4v", "mov", "wmv", "mpg", "mpeg", "ts", "m2ts", "webm", "flv", "divx",
    "vob", "iso", "img",
];

/// Disc-structure and companion-track files that belong to a video payload
/// without being one: a BDMV/VIDEO_TS tree is unplayable with any of them
/// missing, and an external audio track is the release's whole point when
/// the video ships without it. Kept by `keep_media_only`, which would
/// otherwise leave a disc rip that cannot be opened.
/// The audio list has to stay ahead of what releases actually ship. It
/// carried ac3 and dts but not eac3, which is what nearly every current
/// Atmos or DD+ remux posts its external track as - so keep-media-only
/// deleted the one file the release existed for, reported Completed, and
/// left the user no copy anywhere. When in doubt add the extension:
/// keeping a stray audio file costs disk, deleting a wanted one is
/// unrecoverable.
const MEDIA_COMPANION_EXTS: &[&str] = &[
    "bdmv", "mpls", "clpi", "ifo", "bup", "sup", // disc structure and subs
    "mka", "m4a", "ac3", "eac3", "ec3", "dts", "dtshd", "truehd", "thd", "flac", "aac", "opus",
    "mp3", "wav", // external audio tracks
];

/// Subtitle sidecars - kept alongside the media by every cleanup mode.
const SUBTITLE_EXTS: &[&str] = &["srt", "sub", "idx", "ass", "ssa", "vtt", "smi"];

/// Payload that is not video and never clutter: music, audiobooks,
/// books, comics, and the cue/log sheet a lossless rip is verified with.
///
/// `keep_media_only` guards a video-less job by refusing to run at all,
/// which was enough while every release was a film or an episode. User
/// categories (24D) broke that premise: a comics or audiobook category
/// declaring base Movie, shipping ONE bonus .mp4 beside fifty .cbz
/// files, passed the guard and lost the fifty. `.flac`, `.m4a` and
/// `.cbr` survived only by accident - the first two sit in the companion
/// list, and a .cbr is a RAR to `is_packed_archive`. Extension lists are
/// the wrong place to be lucky, so the payload formats are named.
const PAYLOAD_EXTS: &[&str] = &[
    // audio
    "mp3", "m4b", "opus", "ogg", "oga", "wav", "aiff", "aif", "wma", "alac", "ape", "wv", "cue",
    "log", // books and comics
    "epub", "mobi", "azw", "azw3", "pdf", "cbz", "cbr", "cb7", "djvu",
];

/// Usenet furniture removed by `sweep_junk`: PAR2 recovery, the posted
/// NZB, checksum/verification files, scene .nfo/.txt, and website droppings.
/// Deliberately excludes archives (.rar/.7z - a job that still needs them
/// isn't done) and executables (software payloads).
const JUNK_EXTS: &[&str] = &[
    "par2", "nzb", "sfv", "nfo", "url", "txt", "srr", "srs", "diz", "md5", "sha", "sha256",
    "website",
];

/// Is this extension Usenet furniture rather than payload?
///
/// The one reader of [`JUNK_EXTS`] outside this module is the post-drain
/// census (issue #23): a metadata file the recovery set does not cover
/// must not fail a download whose payload is whole. Exposed as a
/// predicate rather than the list so the exclusions that make the list
/// safe - archives and executables are NOT here - travel with it.
pub fn is_junk_ext(ext: &str) -> bool {
    JUNK_EXTS.contains(&ext)
}

fn ext_of(p: &Path) -> String {
    p.extension()
        .map(|e| e.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default()
}

/// A still-packed archive volume or part: RAR (`.rar`/`.rNN`, rollover
/// and numeric volumes by magic, or extensionless by magic), 7z (`.7z`,
/// `.7z.NNN`, obfuscated), or any zip shape [`nzbkit::zip`] knows.
///
/// `sweep_junk` gets this for free by simply not listing archives in
/// `JUNK_EXTS`, but `keep_media_only` deletes everything that is not
/// media, and an archive we could not unpack is the ONLY copy of the
/// payload. Deleting it left the user with an empty folder, a job marked
/// Completed, and one log line to explain it - the exact shape a zip post
/// used to fail in. Anything still packed stays; the user needs it.
///
/// The extensionless RAR sniff closes the last hole in that rule. An
/// obfuscated post strips extensions and renames its volumes to hashes,
/// so `looks_like_named_rar` - a pure name grammar - sees nothing, while
/// the 7z and zip collectors beside it already sniff exactly this shape.
/// A set we could not unpack (encrypted with no password, unrepairable,
/// a format we don't read) was therefore kept when it was named and
/// deleted when it was obfuscated, and obfuscated is the common case: the
/// whole payload went, with the recovery volumes that could have rebuilt
/// it, on the single most-encountered release shape on usenet.
///
/// Sniffing only where there is NO extension is the same standing rule
/// `nzbkit::zip::is_container` and `sevenz_archive_part` follow: a payload
/// that carries a name (`.mkv`, `.cbz`) is judged on that name and is
/// never opened by this path.
///
/// `zip_parts` is the directory's zip membership from [`zip_part_set`],
/// because some parts cannot answer for themselves: see there.
fn is_packed_archive(p: &Path, zip_parts: &std::collections::HashSet<PathBuf>) -> bool {
    crate::looks_like_named_rar(p)
        || (p.extension().is_none() && crate::rar_magic(p))
        || crate::sevenz_archive_part(p)
        || zip_parts.contains(p)
        || nzbkit::zip::is_container(p)
}

/// Does an EXTENSIONLESS file begin like a video container?
///
/// keep-media-only decides by extension, and anything unrecognised is
/// deleted - so a hash-named payload with no extension at all was
/// removed outright. The no-video guard did not save it either: one
/// properly named video in the same folder is enough to arm the sweep,
/// and an obfuscated post that decodes to one named file plus one
/// hash-named one is an ordinary shape. The archive check above already
/// rescues the packed case; this covers the unpacked one.
///
/// Same standing rule as `is_packed_archive`: sniffing happens ONLY
/// where there is no extension. A file that carries a name is judged on
/// that name and is never opened here.
fn looks_like_video_bytes(p: &Path) -> bool {
    use std::io::Read;
    if p.extension().is_some() {
        return false;
    }
    let mut b = [0u8; 12];
    if std::fs::File::open(p)
        .and_then(|mut f| f.read_exact(&mut b))
        .is_err()
    {
        return false;
    }
    // Matroska/WebM (EBML), MP4/MOV family (....ftyp), AVI (RIFF....AVI ),
    // MPEG program stream, and the MPEG-TS 0x47 sync byte.
    b[..4] == [0x1A, 0x45, 0xDF, 0xA3]
        || &b[4..8] == b"ftyp"
        || (&b[..4] == b"RIFF" && &b[8..12] == b"AVI ")
        || b[..4] == [0x00, 0x00, 0x01, 0xBA]
        || b[0] == 0x47
}

/// Every file in `dir` that belongs to a zip container, asked as SETS.
///
/// A bare-numeric split zip (`movie.001`, `.002`, `.003`) carries the
/// magic in part 1 only - the rest are raw continuation bytes with
/// nothing in the name or the head to identify them. Asking each file on
/// its own therefore spared `.001` and deleted `.002` onward, leaving a
/// fragment that can never be opened beside a note telling the user the
/// verified archive was waiting for them. `nzbkit::zip::scan` gates the
/// whole set on part 1 and hands back every member, which is the same
/// collector the reporting path uses.
fn zip_part_set(dir: &Path) -> std::collections::HashSet<PathBuf> {
    nzbkit::zip::scan(dir)
        .into_iter()
        .flat_map(|f| f.parts)
        .collect()
}

/// Does the file start with the `PAR2\0PKT` packet magic? Obfuscated
/// posts name their recovery volumes as hashes with no extension - the
/// NZB subject may still read `…vol-01.par2`, but the on-disk name comes
/// from the yEnc header, so `ext_of` sees nothing and the extension list
/// below can't recognise them. The magic is unambiguous (no media
/// container starts with it), so it decides where the name can't. Same
/// detection main.rs's `dir_has_par2` uses for the repair side.
fn par2_magic(p: &Path) -> bool {
    use std::io::Read as _;
    let mut head = [0u8; 8];
    std::fs::File::open(p)
        .and_then(|mut f| f.read_exact(&mut head))
        .map(|()| &head == b"PAR2\x00PKT")
        .unwrap_or(false)
}

fn stem_lower(p: &Path) -> String {
    p.file_stem()
        .map(|s| s.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default()
}

/// A "sample"/"proof"-named video. Name only - NOT sufficient on its own to
/// delete a file (see `is_deletable_sample`); used by the non-destructive
/// rename paths to leave a likely teaser un-renamed.
fn is_sample_clip(p: &Path) -> bool {
    let s = stem_lower(p);
    (s.contains("sample") || s.contains("proof")) && VIDEO_EXTS.contains(&ext_of(p).as_str())
}

/// Fraction of the feature's size below which a "sample"/"proof"-named video
/// is treated as a throwaway teaser. A real teaser is a tiny slice of the
/// feature; a same-size file that merely has "proof"/"sample" in its title
/// (the 2005 film "Proof", a "Proof" season pack, or a job that is itself
/// only a sample) is NOT a teaser. Name alone silently deleted real content.
const SAMPLE_MAX_FRACTION: f64 = 0.15;

/// A deletable teaser: sample/proof-named AND much smaller than the feature.
/// With `feature_len == 0` (no feature to compare against) nothing qualifies,
/// so a lone sample-named download is never destroyed.
fn is_deletable_sample(p: &Path, feature_len: u64) -> bool {
    if feature_len == 0 || !is_sample_clip(p) {
        return false;
    }
    let len = p.metadata().map(|m| m.len()).unwrap_or(0);
    if (len as f64) >= (feature_len as f64) * SAMPLE_MAX_FRACTION {
        return false;
    }
    // Name and size both say sample; the container gets a veto. A real
    // episode with "sample" in its title sits small beside a
    // double-length special, but its own header says it runs like an
    // episode - nothing that long is deleted on a name.
    if matches!(ext_of(p).as_str(), "mkv" | "webm")
        && let Some(i) = nzbkit::mkv::probe(p)
        && i.duration_secs.is_some_and(|d| d >= 15.0 * 60.0)
    {
        return false;
    }
    true
}

/// A real directory - NOT a symlink pointing at one.
///
/// `Path::is_dir` follows symlinks, and every walker below pairs it with
/// `read_dir` and then deletes what it finds. A completed job containing
/// `extras -> /media/shared` therefore had its cleanup pass walk into the
/// real target and delete files there: removing `job/extras/file.nfo`
/// resolves through the link to `/media/shared/file.nfo`. Native extraction
/// never materialises a symlink, but an external extractor or pre-existing
/// filesystem state can, and "we don't create them" is not a boundary.
fn is_real_dir(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|m| m.is_dir())
}

/// A real file - NOT a symlink pointing at one. Same reason as
/// [`is_real_dir`]: the walkers delete what they classify, and following a
/// link means deleting outside the job.
fn is_real_file(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|m| m.is_file())
}

/// Deepest directory nesting [`prune_empty_dirs`] will walk. Our own
/// extraction cannot nest at all (`sanitize_filename` maps the path
/// separators out of archive entry names), so this only ever bounds a tree
/// something else built, and bounds the recursion with it.
const PRUNE_MAX_DEPTH: u32 = 8;

/// Finder metadata macOS drops into any folder it has looked at: the
/// per-folder `.DS_Store`, and the `._name` AppleDouble carrying the
/// resource fork of a file copied to a non-native filesystem.
///
/// Neither is content. Left in place they keep a swept `Sample/` husk
/// alive forever - `.DS_Store` has no extension to match (`ext_of` gives
/// "" for a dotfile, so `JUNK_EXTS` never sees it) and at 6148 bytes it is
/// over `is_nameless_scrap`'s 4 KB ceiling, so nothing in the junk sweep
/// can reach it and `prune_empty_dirs` then finds the directory non-empty.
/// A real file, a subdirectory and a symlink all still count as content.
///
/// `.DS_Store` is decided on the name alone - that name is Finder's, and
/// nothing else writes it. `._name` is NOT: the prefix is a convention, not
/// a reservation, and a mis-packed archive or a poster-named extra can
/// carry a real payload called `._something.mkv`. Since the caller deletes
/// what this classifies, and deletes it permanently
/// ([`drop_finder_droppings`]), an AppleDouble must also LOOK like one.
/// Size is the check that costs nothing and cannot be spoofed by a name: a
/// genuine AppleDouble holds a resource fork plus xattrs, which is a few
/// KB in the ordinary case and a few hundred KB in the worst one, so
/// [`APPLEDOUBLE_MAX`] sits an order of magnitude above anything real
/// while still excluding every payload worth losing.
fn is_finder_dropping(p: &Path) -> bool {
    let Some(name) = p.file_name().map(|n| n.to_string_lossy().into_owned()) else {
        return false;
    };
    if !is_real_file(p) {
        return false;
    }
    if name == ".DS_Store" {
        return true;
    }
    name.starts_with("._") && p.metadata().is_ok_and(|m| m.len() <= APPLEDOUBLE_MAX)
}

/// Largest `._name` file still treated as an AppleDouble sidecar rather
/// than content. See [`is_finder_dropping`].
const APPLEDOUBLE_MAX: u64 = 1024 * 1024;

/// Is every remaining entry of `d` a Finder dropping? (True for an already
/// empty directory, which the caller then removes on its own.)
fn only_finder_droppings(d: &Path) -> bool {
    std::fs::read_dir(d).is_ok_and(|rd| rd.flatten().all(|e| is_finder_dropping(&e.path())))
}

/// Delete the Finder droppings in `d` so the husk can go.
///
/// A plain `remove_file`, deliberately NOT `remove_user_file`: this is the
/// OS's own metadata about a folder that is about to stop existing, not
/// anything the user downloaded or could want back, and routing it to the
/// Trash would put `.DS_Store` files in front of them for no reason.
fn drop_finder_droppings(d: &Path) {
    let Ok(rd) = std::fs::read_dir(d) else { return };
    for entry in rd.flatten() {
        let path = entry.path();
        if is_finder_dropping(&path)
            && let Err(e) = std::fs::remove_file(&path)
        {
            warn!(target: "cleanup", "{}: {e}", path.display());
        }
    }
}

/// Remove subdirectories of `dir` that a sweep just emptied: the `Sample/`
/// or `Proof/` folder whose clips have gone, plus any now-empty parent
/// above it. The sweeps delete files one subdirectory deep but left the
/// husk behind, and a completed job still showing a `Sample` folder reads
/// as though the sweep never ran - NZBGet's DeleteSamples takes the
/// directory too.
///
/// Only a directory whose whole subtree is empty goes. Anything holding a
/// file stays, and so does every parent above it. A symlink counts as
/// content and is never followed or removed: it is not ours, and
/// `remove_dir` on the parent would be the least of what walking into it
/// could cost (see [`is_real_dir`]).
///
/// "Empty" tolerates Finder metadata - see [`is_finder_dropping`]. On
/// macOS the sweep took the sample clip and left `Sample/.DS_Store`, so
/// the husk this exists to remove survived every download.
///
/// `dir` itself is never removed however empty it ends up - the job owns
/// it, and the state that a job's own output directory is missing is one
/// the rest of post-processing does not expect. Returns how many
/// directories went; deliberately NOT folded into the sweeps' file counts.
fn prune_empty_dirs(dir: &Path, depth: u32) -> usize {
    if depth >= PRUNE_MAX_DEPTH {
        return 0;
    }
    let mut removed = 0;
    let Ok(rd) = std::fs::read_dir(dir) else {
        return 0;
    };
    for entry in rd.flatten() {
        let path = entry.path();
        if !is_real_dir(&path) {
            continue;
        }
        // Depth-first: emptying a child can empty its parent.
        removed += prune_empty_dirs(&path, depth + 1);
        if only_finder_droppings(&path) {
            drop_finder_droppings(&path);
        }
        if std::fs::read_dir(&path).is_ok_and(|mut r| r.next().is_none()) {
            match std::fs::remove_dir(&path) {
                Ok(()) => {
                    info!(target: "cleanup", "empty dir {}", path.display());
                    removed += 1;
                }
                Err(e) => warn!(target: "cleanup", "{}: {e}", path.display()),
            }
        }
    }
    removed
}

/// The largest video file in `dir` (top level + one subdir deep), or None.
/// The main feature - protected from the junk sweep regardless of its name,
/// so a film or season titled "Proof"/"Sample" is still recognised as the
/// feature and never deleted.
/// The resolution the payload's own container reports, when the job has
/// a Matroska main video. The subject line's claim is the poster's; the
/// header is the file's, and where the two disagree the header wins
/// (see `finalize_names`). One bounded head read; anything unreadable
/// returns None and the claim stands.
pub fn measured_res(dir: &Path) -> Option<&'static str> {
    let video = main_video(dir)?;
    if !matches!(ext_of(&video).as_str(), "mkv" | "webm") {
        return None;
    }
    let i = nzbkit::mkv::probe(&video)?;
    Some(nzbkit::mkv::res_bucket(i.width?, i.height?))
}

/// The job's feature: the biggest video in the finished directory, with
/// the sample clip ruled out. What every "ask the payload itself"
/// question is asked of, so they all agree on which file they mean.
pub fn main_video(dir: &Path) -> Option<PathBuf> {
    largest_video(dir).filter(|v| !is_sample_clip(v))
}

fn largest_video(dir: &Path) -> Option<PathBuf> {
    let mut best: Option<(u64, PathBuf)> = None;
    let mut consider = |path: PathBuf| {
        if !is_real_file(&path) || !VIDEO_EXTS.contains(&ext_of(&path).as_str()) {
            return;
        }
        let len = path.metadata().map(|m| m.len()).unwrap_or(0);
        if best.as_ref().is_none_or(|(b, _)| len > *b) {
            best = Some((len, path));
        }
    };
    let tops: Vec<PathBuf> = std::fs::read_dir(dir)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .collect();
    for path in tops {
        if is_real_dir(&path) {
            if let Ok(rd) = std::fs::read_dir(&path) {
                for e in rd.flatten() {
                    consider(e.path());
                }
            }
        } else {
            consider(path);
        }
    }
    best.map(|(_, p)| p)
}

/// Delete files whose extension is in `exts` from `dir` (top level plus
/// one subdirectory level - where extraction puts things). Logs each
/// removal; returns `(total, par2)` - how many files went, and how many
/// of those were `.par2` recovery files. The split exists for the
/// history drawer's one-line cleanup report: recovery files are deleted
/// by a default most users never chose (`par_cleanup`), so "12 of those
/// were par2" is the half of the count that answers "where did my
/// recovery data go".
pub fn cleanup(dir: &Path, exts: &[String]) -> (usize, usize) {
    let mut removed = 0;
    let mut par2 = 0;
    // Read once, for the whole sweep: see `remove_user_file`.
    let recoverable = cleanup_recoverable();
    let staging = trash_staging_dir(dir);
    let mut sweep = |d: &Path| {
        let Ok(rd) = std::fs::read_dir(d) else { return };
        for entry in rd.flatten() {
            let path = entry.path();
            if !is_real_file(&path) {
                continue;
            }
            let ext = path
                .extension()
                .map(|e| e.to_string_lossy().to_ascii_lowercase())
                .unwrap_or_default();
            if exts.contains(&ext) {
                match remove_swept_file(&path, recoverable, staging.as_deref()) {
                    Ok(_) => {
                        info!(target: "cleanup", "removed {}", path.display());
                        removed += 1;
                        if ext == "par2" {
                            par2 += 1;
                        }
                    }
                    Err(e) => warn!(target: "cleanup", "{}: {e}", path.display()),
                }
            }
        }
    };
    sweep(dir);
    if let Ok(rd) = std::fs::read_dir(dir) {
        for entry in rd.flatten() {
            let path = entry.path();
            if is_real_dir(&path) {
                sweep(&path);
            }
        }
    }
    (removed, par2)
}

/// Auto-rename companion: remove usenet furniture (`.par2`/`.nzb`/`.sfv`/
/// `.nfo`/…, see `JUNK_EXTS`) and sample/proof clips left beside the media,
/// top level + one subdir deep. Never deletes a subtitle, and never the
/// main feature (the largest video) - so a film literally titled "Sample"
/// survives. Returns how many files went.
/// Recoverable delete for anything that came out of a user's download.
///
/// The cleanup passes used to call `remove_file` directly, so a file the
/// junk heuristics got wrong was gone for good - and those heuristics are
/// exactly the kind that get things wrong (obfuscated posts have no
/// reliable names, and "Proof" once cost a real release). The Trash makes
/// every one of those calls reversible by the person best placed to judge
/// it, which is the whole difference between a wrong guess and data loss.
///
/// Deliberately NOT used for our own spool, journals or placeholders:
/// those are internal churn, and routing them here would bury the user's
/// Trash under files they never saw and cannot act on.
///
/// A recoverable delete NEVER becomes a permanent one. When no Trash will
/// take the path this returns an error and the file stays exactly where it
/// is - see [`trash_attempt`]. It used to hard-delete instead, on the
/// reasoning that leaving clutter forever was worse; that reasoning had it
/// backwards. Every caller of this is a heuristic ("this looks like junk",
/// "this looks like a sample"), the Trash is the only thing that makes a
/// wrong guess survivable, and "the Trash refused, so destroy it" turns
/// the one failure the setting promised to soften into the very outcome it
/// promised to prevent. A user who genuinely wants permanent deletes turns
/// `delete_to_trash` off - the NAS/seedbox default on Linux - and that
/// path is untouched.
///
/// `recoverable` is passed IN rather than read from the process-global
/// here, so one sweep decides once (at its entry) and every file it touches
/// is treated the same way. Re-reading the flag per file meant a settings
/// change - or, in the test suite, another test's `set_delete_to_trash` -
/// landed halfway through a sweep and split it between the two behaviours.
pub fn remove_user_file(path: &Path, recoverable: bool) -> std::io::Result<Removed> {
    if recoverable {
        return match trash_attempt(path) {
            TrashVerdict::Took => Ok(Removed::Trashed),
            TrashVerdict::TookButGone | TrashVerdict::NotFound => Ok(Removed::Gone),
            TrashVerdict::Refused(why) => Err(refusal(&why)),
        };
    }
    // A bounded call that gave up may STILL be running, and Finder may
    // yet move the file to the Trash behind us. Then this direct delete
    // races it and loses with NotFound - which is the outcome we wanted
    // (the file is gone), not a failure to report to the caller.
    match std::fs::remove_file(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Removed::Gone),
        Err(e) => Err(e),
        Ok(()) => Ok(Removed::Gone),
    }
}

/// [`remove_user_file`] for a whole DIRECTORY: a completed job's private
/// output folder, deleted as one recoverable unit. One Trash call moves
/// the folder intact - the user gets "the download I deleted" back as a
/// single restorable item, not a thousand loose files - and it costs the
/// same one bounded call a single file does.
///
/// This is what makes the "Deleted files go to the Trash" promise hold
/// for the deletes users actually perform: history "delete + files", a
/// queue delete with files, and the watchlist delete_old upgrade all end
/// at a job directory, and every one of them used to be a bare
/// `remove_dir_all` that no setting could soften.
///
/// This is the delete where refusing to hard-delete matters most: the
/// argument in [`remove_user_file`] applies to a stray `.nfo`, and here it
/// applies to an entire finished download. A `remove_dir_all` behind a
/// failed Trash call is unrecoverable by anyone, and it lands on the user
/// who ASKED for recoverable deletes. The directory is left alone and the
/// caller says so instead.
pub fn remove_user_dir(path: &Path, recoverable: bool) -> std::io::Result<Removed> {
    if recoverable {
        return match trash_attempt(path) {
            TrashVerdict::Took => Ok(Removed::Trashed),
            TrashVerdict::TookButGone | TrashVerdict::NotFound => Ok(Removed::Gone),
            TrashVerdict::Refused(why) => Err(refusal(&why)),
        };
    }
    // NotFound tolerated for the same race as remove_user_file - and for
    // the ordinary case of a job whose directory was never created.
    match std::fs::remove_dir_all(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Removed::Gone),
        Err(e) => Err(e),
        Ok(()) => Ok(Removed::Gone),
    }
}

/// What one recoverable-delete attempt settled on.
/// What a removal actually DID, as opposed to what the setting asked
/// for.
///
/// The distinction is load-bearing and was missing: "its files went to
/// the Trash" used to be reconstructed by the callers from two globals
/// (`delete_to_trash()` and `!trash_unresponsive()`), never from what
/// happened to those files. On 4 Aug that told a user a 14 GB download
/// was recoverable while it had in fact been destroyed outright - the
/// setting was on, nothing had timed out, and the backend returned Ok.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Removed {
    /// In a Trash it can be restored from. Only ever reported when that
    /// has been CHECKED, never inferred from the setting.
    Trashed,
    /// Gone, with no promise of getting it back. Covers a deliberate
    /// permanent delete, a path that was already absent, and the case
    /// above: a Trash route that reported success and left nothing
    /// recoverable behind it.
    Gone,
}

/// Did `path` actually land somewhere it can be restored from?
///
/// Asked AFTER a Trash route reports success, because that success means
/// only "a backend returned Ok". macOS has two routes and both can
/// answer Ok while the bytes are gone: on a volume whose per-user Trash
/// is not usable - an external disk mounted `noowners` is the ordinary
/// way to get one - Finder's scripted `delete` performs the delete
/// -immediately behaviour its GUI would warn about, and says it worked.
///
/// Deliberately biased towards claiming recoverable: only a positive
/// look in the expected place, coming back empty, downgrades the answer.
/// Anything we cannot determine stays `Trashed`, because crying wolf on
/// a delete that WAS recoverable is its own harm.
/// What the Trash roots held that could be mistaken for this delete,
/// taken BEFORE it happens.
///
/// Without it the check answers "recoverable" for a name that was
/// already sitting there: `~/.Trash` keeps things for weeks, so the
/// second delete of `Movie.mkv` - or a delete of anything whose name
/// starts with a stem already in there - matched an entry from days
/// ago and reported a hard delete as restorable. The claim has to be
/// about an entry that appeared, not one that exists.
#[cfg(target_os = "macos")]
#[derive(Default)]
struct TrashBefore {
    /// The exact target name already present in some root.
    exact: bool,
    /// Every stem-prefixed name already present, across all roots.
    names: std::collections::HashSet<std::ffi::OsString>,
}

#[cfg(target_os = "macos")]
fn trash_snapshot(path: &Path) -> TrashBefore {
    let mut before = TrashBefore::default();
    let Some(name) = path.file_name() else {
        return before;
    };
    let stem = path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| name.to_string_lossy().into_owned());
    for root in trash_roots(path) {
        if root.join(name).exists() {
            before.exact = true;
        }
        let Ok(entries) = std::fs::read_dir(&root) else {
            continue;
        };
        for e in entries.take(4096).flatten() {
            if e.file_name().to_string_lossy().starts_with(&stem) {
                before.names.insert(e.file_name());
            }
        }
    }
    before
}

/// The two places macOS puts a trashed item: the boot volume's per-user
/// Trash, and a per-volume `.Trashes/<uid>` for anything else. A path
/// under /Volumes/<name> is checked against its own volume first, then
/// the home one - a cross-volume trash lands in the latter.
#[cfg(target_os = "macos")]
fn trash_roots(path: &Path) -> Vec<std::path::PathBuf> {
    let mut roots: Vec<std::path::PathBuf> = Vec::new();
    let comps: Vec<_> = path.components().collect();
    if comps.len() > 2 && path.starts_with("/Volumes") {
        let vol: std::path::PathBuf = comps[..3].iter().collect();
        roots.push(
            vol.join(".Trashes")
                .join(unsafe { libc::getuid() }.to_string()),
        );
    }
    if let Some(home) = std::env::var_os("HOME") {
        roots.push(std::path::PathBuf::from(home).join(".Trash"));
    }
    roots
}

#[cfg(target_os = "macos")]
fn landed_in_a_trash(path: &Path, before: &TrashBefore) -> bool {
    let Some(name) = path.file_name().map(|n| n.to_string_lossy().into_owned()) else {
        return true;
    };
    let roots = trash_roots(path);
    if roots.is_empty() {
        return true;
    }
    // Finder disambiguates a name collision by appending to the stem, so
    // an exact hit is the common case and a prefix match covers the
    // rest. Bounded: a long-untended Trash must not turn one delete into
    // a directory walk of tens of thousands of entries.
    //
    // Matched against the BEFORE snapshot throughout: an entry that was
    // already there is somebody else's old delete, and it is the whole
    // reason this check could say "recoverable" about files that had
    // just been destroyed outright.
    for root in &roots {
        if !before.exact && root.join(&name).exists() {
            return true;
        }
        let Ok(entries) = std::fs::read_dir(root) else {
            continue;
        };
        let stem = path
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| name.clone());
        for e in entries.take(4096).flatten() {
            if e.file_name().to_string_lossy().starts_with(&stem)
                && !before.names.contains(&e.file_name())
            {
                return true;
            }
        }
    }
    false
}

/// Every other platform's backend is a real XDG Trash or Recycle Bin,
/// which does not have the "reported success, deleted anyway" mode this
/// guards against. Nothing to second-guess.
#[cfg(not(target_os = "macos"))]
#[derive(Default)]
struct TrashBefore;

#[cfg(not(target_os = "macos"))]
fn trash_snapshot(_path: &Path) -> TrashBefore {
    TrashBefore
}

#[cfg(not(target_os = "macos"))]
fn landed_in_a_trash(_path: &Path, _before: &TrashBefore) -> bool {
    true
}

enum TrashVerdict {
    /// A Trash route took `path` and it was found afterwards in a Trash
    /// it can be restored from.
    Took,
    /// A Trash route reported success, but nothing recoverable is there:
    /// the path is gone for good. The files ARE removed - the caller
    /// asked for that - but nothing may claim they can be restored.
    TookButGone,
    /// There was nothing at `path` to take.
    NotFound,
    /// No Trash route would take it. Carries the reason for the log. The
    /// caller must NOT fall back to a permanent delete: see
    /// [`remove_user_file`].
    Refused(String),
}

/// The error a refused recoverable delete comes back as. Worded to be
/// READ: a user who asked for recoverable deletes needs to know why their
/// files are still there and what to change, not just that something
/// failed. It reaches them through the dashboard's kept-files notice as
/// well as the log now, so it has to stand up in front of a person.
///
/// Deliberately does NOT name the path, though it once did. Every caller
/// already prints it - `remove_job_files`, the filed-episode sweep, the
/// deferred-trash drain and the watch-folder ingest all log
/// `<path>: <this>` - so the path came out twice in a row on every line,
/// and the notice repeats it a third time in its own sentence.
fn refusal(why: &str) -> std::io::Error {
    std::io::Error::other(format!(
        "the Trash would not take it ({why}). Turn off \"Deleted files go \
         to the Trash\" in Settings if you want files removed outright \
         rather than left alone"
    ))
}

/// One recoverable attempt against the Trash.
fn trash_attempt(path: &Path) -> TrashVerdict {
    // Nothing there to bin. Checked BEFORE the backend on purpose: macOS's
    // Finder route reports a path it cannot see as a CLASS error
    // ("Handler can't handle objects of this class", -10010), not as "not
    // found" - the crate only canonicalizes the parent, so a missing leaf
    // sails through to the AppleScript. That produced a live WARN reading
    // "could not move <a user's download> to the Trash - deleting it
    // instead" for a directory that had already gone, which is the most
    // alarming line we could print about a no-op. It is also the shape of
    // the race the old direct-delete fallback swallowed as NotFound.
    // NotFound only. `is_err()` swallowed every other stat failure too -
    // EACCES on a parent that lost search permission, EIO/ESTALE on a
    // dropped SMB or NFS mount - and reported each as "the Trash took
    // it": `Ok(())` out of `remove_user_dir`, `FilesGone::Yes`, no
    // `note_delete_kept`, no warning, and the history row dropped. A NAS
    // user reclaiming space from a share that had just gone away was
    // told the files were deleted while the whole payload was still
    // sitting there, named by nothing - the exact failure class the
    // kept-files notice exists to close. The non-recoverable arms
    // already tolerate only NotFound; this one is now consistent with
    // them.
    if std::fs::symlink_metadata(path).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound) {
        return TrashVerdict::NotFound;
    }
    if trash_unresponsive() {
        return TrashVerdict::Refused("the Trash is not responding".to_string());
    }
    // Taken BEFORE the call: "is it in the Trash now" cannot tell a
    // fresh entry from one that was already sitting there under the
    // same name.
    let before = trash_snapshot(path);
    match trash_delete_gated(|| trash_delete_bounded(path)) {
        // Ok from the backend is not the answer on its own - see
        // `landed_in_a_trash`.
        Ok(()) => {
            if landed_in_a_trash(path, &before) {
                TrashVerdict::Took
            } else {
                warn!(
                    target: "files",
                    "the Trash reported success for {} but nothing restorable is there - \
                     reporting it as deleted, because that is what happened. A volume \
                     whose per-user Trash is unusable (an external disk mounted \
                     `noowners` is the common one) deletes outright and says it worked.",
                    path.display()
                );
                TrashVerdict::TookButGone
            }
        }
        // Another caller was inside the process's first Trash call when we
        // arrived, and it came back unresponsive. We never made a call of
        // our own, but the verdict is the same one we would have got.
        Err(None) => TrashVerdict::Refused("the Trash is not responding".to_string()),
        Err(Some(e)) => {
            // On a headless Mac the crate's Finder/AppleScript backend
            // does not fail fast: every call blocks ~2 minutes before
            // "AppleEvent timed out (-1712)". A queue of three jobs
            // carries dozens of par2/nfo cleanup files, and those
            // serialized stalls measured as 720 s of a 863 s job - the
            // job is not done until its cleanup is. One timeout means
            // every later call will stall the same way, so the rest of
            // the process stops asking - `trash_delete_gated` has already
            // latched that, before it let anyone else past, and all that
            // is left here is to say so. Ordinary failures (a volume with
            // no trash at all) stay per-path: they are instant and the
            // next file may live somewhere else entirely.
            if looks_like_a_trash_timeout(&e) {
                warn!(
                    target: "cleanup",
                    "the Trash is not responding (headless session?) - \
                     not asking it again this run"
                );
            }
            first_refusal_hint();
            TrashVerdict::Refused(e)
        }
    }
}

/// Said once per process, the first time a recoverable delete is refused.
///
/// The per-path errors go where the caller logs them (a sweep line, a job
/// line), and each one on its own reads like a transient hiccup. This is
/// the sentence that explains the pattern: files are being LEFT, on
/// purpose, and there are exactly two ways out. Once, not per file - a
/// junk sweep refused is a dozen lines by itself.
fn first_refusal_hint() {
    static SAID: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if SAID.swap(true, std::sync::atomic::Ordering::Relaxed) {
        return;
    }
    warn!(
        target: "cleanup",
        "the Trash refused a delete, so files are being left in place \
         rather than permanently deleted. Turn off \"Deleted files go to \
         the Trash\" in Settings if you want them removed outright"
    );
}

/// How long a single Trash call may hold up a finished job before we stop
/// waiting for it. Only meaningful on macOS - see `trash_delete_bounded`.
///
/// Generous ON PURPOSE. The Trash is what makes a wrong junk-heuristic
/// guess reversible by the user, which is the whole reason cleanup routes
/// through it, so treating a merely SLOW Finder as a dead one would trade
/// that away for the rest of the process. A healthy Finder answers in
/// milliseconds; nothing legitimate takes half a minute.
#[cfg(target_os = "macos")]
const TRASH_DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);

/// `trash::delete`, but it cannot hold a finished job hostage.
///
/// On macOS the crate's backend asks Finder over AppleScript and waits
/// with no application-level timeout, so on a headless session (ssh, a
/// launchd daemon, a login window nobody has touched) every call blocks
/// for about two minutes before returning "AppleEvent timed out (-1712)".
/// Cleanup runs INSIDE post-processing and a job is not filed to history
/// until it returns, so those stalls are wall-clock the user sees as a
/// download that finished but never appeared: one measured job spent
/// 720 s of its 863 s exactly here. `TRASH_UNRESPONSIVE` already stops
/// the SECOND call paying it, but the first one still did.
///
/// So: run the call on its own thread and stop waiting at
/// `TRASH_DEADLINE`. The thread is left to finish on its own - AppleEvent
/// has no cancel, and abandoning it is the point. The caller then leaves
/// the file alone, and tolerates the race where Finder eventually wins
/// (the path is simply gone next time anyone looks).
///
/// Every other platform calls straight through: the XDG and Windows
/// backends are local filesystem work with no interprocess wait to bound,
/// and a thread per file would be cost for nothing.
///
/// macOS has a SECOND route, and this is where it is taken. See
/// [`trash_via_file_manager`]. The other two platforms have exactly one
/// each, and both fail for reasons no retry would fix - a Windows volume
/// with the Recycle Bin turned off, a mapped network drive that has none,
/// an item too big for the bin's quota; a freedesktop trash on a
/// read-only or foreign-uid mount. Those come back as a refusal and the
/// file stays, which is the same answer this reaches on macOS when both
/// routes are out: the platforms differ in how many chances they get, not
/// in what happens when they are spent.
fn trash_delete_bounded(path: &Path) -> Result<(), String> {
    // No `return`: on non-mac targets the macos block below is stripped,
    // making this block the tail expression - a `return` here trips
    // clippy's needless_return on the Linux CI runner, the only clippy
    // that ever compiles this arm.
    #[cfg(not(any(target_os = "macos", target_os = "android", target_os = "ios")))]
    {
        trash::delete(path).map_err(|e| e.to_string())
    }
    // Android and iOS have no system trash; refuse and the file stays,
    // exactly like the other platforms when their routes are spent.
    #[cfg(any(target_os = "android", target_os = "ios"))]
    {
        let _ = path;
        Err("no system trash on this platform".to_string())
    }
    #[cfg(target_os = "macos")]
    {
        if !finder_is_out() {
            match trash_via_finder(path) {
                Ok(()) => return Ok(()),
                Err(e) => {
                    warn!(
                        target: "cleanup",
                        "Finder would not bin {} ({e}) - using the volume's \
                         own Trash from now on",
                        path.display()
                    );
                    FINDER_IS_OUT.store(true, std::sync::atomic::Ordering::Relaxed);
                }
            }
        }
        trash_via_file_manager(path)
    }
}

/// The Finder/AppleScript route, bounded. First choice on macOS because it
/// is the only one that records "Put Back", so a user restoring a wrongly
/// swept file gets it back WHERE IT WAS rather than having to know where
/// that was.
#[cfg(target_os = "macos")]
fn trash_via_finder(path: &Path) -> Result<(), String> {
    use trash::macos::{DeleteMethod, TrashContextExtMacos};
    let p = path.to_path_buf();
    match run_bounded(TRASH_DEADLINE, move || {
        let mut ctx = trash::TrashContext::new();
        ctx.set_delete_method(DeleteMethod::Finder);
        ctx.delete(&p).map_err(|e| e.to_string())
    }) {
        Some(r) => r,
        None => {
            warn!(
                target: "cleanup",
                "Finder did not answer within {}s for {} (headless session?)",
                TRASH_DEADLINE.as_secs(),
                path.display()
            );
            Err("timed out".to_string())
        }
    }
}

/// `NSFileManager.trashItemAtURL`, the route Finder cannot refuse on our
/// behalf: it moves the item into the OWNING VOLUME's `.Trashes/<uid>`
/// itself, with no Finder, no AppleScript and no GUI session in the way.
///
/// It exists here because the Finder route fails in ways that have nothing
/// to do with whether a Trash is available:
///  * `-10010` ("Handler can't handle objects of this class") for a path
///    Finder cannot resolve. Seen live on 3 Aug 2026 against a directory
///    on an external volume;
///  * `-1712` (AppleEvent timed out) on a headless session, which used to
///    condemn the whole process to permanent deletes for its lifetime;
///  * an automation permission prompt nobody is there to answer.
///
/// Measured against an external APFS volume on Apple silicon: Finder
/// 259 ms for one directory, this 40 ms, both landing in the volume's own
/// `/Volumes/<vol>/.Trashes/<uid>`. The one thing it does not do
/// is record Put Back (a macOS bug the crate documents), which is why it
/// is the SECOND choice and not the first - a restore is a drag out of the
/// Trash rather than one menu item, and that is a far smaller loss than
/// the delete it replaces.
///
/// Bounded like the Finder call: this one has no interprocess wait to
/// hang on, but a stale network mount can still block a filesystem call,
/// and a bounded failure now means "leave the file", not "destroy it".
#[cfg(target_os = "macos")]
fn trash_via_file_manager(path: &Path) -> Result<(), String> {
    use trash::macos::{DeleteMethod, TrashContextExtMacos};
    let p = path.to_path_buf();
    match run_bounded(TRASH_DEADLINE, move || {
        let mut ctx = trash::TrashContext::new();
        ctx.set_delete_method(DeleteMethod::NsFileManager);
        ctx.delete(&p).map_err(|e| e.to_string())
    }) {
        Some(r) => r,
        None => Err("timed out".to_string()),
    }
}

/// Latched the first time the Finder route fails, for any reason: every
/// later call on this volume - and most likely every later call at all -
/// goes straight to [`trash_via_file_manager`]. Deliberately never reset,
/// like `TRASH_UNRESPONSIVE`: re-probing costs up to `TRASH_DEADLINE` per
/// delete and buys nothing but a Put Back entry.
///
/// Note what this latch does NOT mean: the Trash is still working. Only
/// `TRASH_UNRESPONSIVE` says there is no route at all.
#[cfg(target_os = "macos")]
static FINDER_IS_OUT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
#[cfg(target_os = "macos")]
fn finder_is_out() -> bool {
    FINDER_IS_OUT.load(std::sync::atomic::Ordering::Relaxed)
}

/// Run `f` on its own thread and give up waiting after `deadline`.
/// `None` means it had not finished in time; the thread keeps running.
///
/// Split out from `trash_delete_bounded` so the give-up path is testable
/// without a Finder to hang: the whole point of this code is the case
/// that cannot be reproduced on a healthy developer machine.
///
/// `test` as well as `macos` in the gate: only the macOS path calls this
/// at runtime, but the tests below cover it on every platform, and
/// without `test` here a Linux or Windows build warns it is unused.
#[cfg(any(target_os = "macos", test))]
fn run_bounded<T: Send + 'static>(
    deadline: std::time::Duration,
    f: impl FnOnce() -> T + Send + 'static,
) -> Option<T> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        // The receiver is gone once we time out; that send failing is the
        // expected outcome, not an error worth surfacing.
        let _ = tx.send(f());
    });
    rx.recv_timeout(deadline).ok()
}

/// Make one Trash call, with the process's FIRST one serialized so a dead
/// Finder is probed once and not once per concurrent caller.
///
/// `TRASH_UNRESPONSIVE` stops a second call paying the deadline - but only
/// once the first has finished paying it. The check and the latch are not
/// atomic, so any two callers that overlap both read it clear, both start
/// a probe, and both pay `TRASH_DEADLINE` in full. A queue soak on a
/// headless bench box caught exactly that: "the Trash is not responding"
/// printed twice in one leg, ~60 s added to a 208 s queue.
///
/// That soak ran before §64, when the finalize sweeps still called the
/// Trash inline, and two jobs finishing together was the way to reproduce
/// it. They park now (`remove_swept_file`), so sweeps are no longer the
/// overlap - but four callers still reach the Trash directly and three of
/// them are on different threads: the `deferred_trash` worker draining its
/// queue, `delete_filed_episode` filing into the user's library, the
/// watch-dir delete in `serve/tasks.rs`, and a sweep whose park failed
/// (read-only tree, EXDEV, no parent) falling back inline. A worker
/// mid-probe while an episode is filed is the same 2 x 30 s.
///
/// So whoever gets here first probes alone and everyone else waits for the
/// verdict instead of asking again. `Err(None)` is that verdict coming
/// back unresponsive: the caller made no call at all and must delete
/// directly. The latch is set before the gate is released, so a waiter
/// always sees it.
///
/// The gate costs a healthy Trash nothing beyond that first call: any
/// answer - even a failure - proves the backend is alive, and from then on
/// the gate is never taken again and deletes run as concurrently as they
/// always did. Deliberately not `cfg(macos)`: only macOS bounds the call,
/// but every platform reads the latch, and `trash::delete` is what it is.
///
/// The call is passed in rather than made here so the tests can supply one
/// that hangs - same reason `run_bounded` is split out. A Finder that does
/// not answer is the one case a healthy developer machine cannot produce.
fn trash_delete_gated(call: impl FnOnce() -> Result<(), String>) -> Result<(), Option<String>> {
    let _gate = if trash_answered() {
        None
    } else {
        let held = FIRST_TRASH_CALL.lock_ok();
        // Settled while we queued: the thread ahead of us got an answer, so
        // there is nothing left to serialize. Hand the gate straight on
        // rather than holding it across our own call.
        if trash_answered() { None } else { Some(held) }
    };
    // The check that got the caller here is stale - the thread ahead of us
    // may have latched the Trash off while we waited on the gate.
    if trash_unresponsive() {
        return Err(None);
    }
    let outcome = call();
    match &outcome {
        Err(e) if looks_like_a_trash_timeout(e) => {
            // Under the gate on purpose: every thread queued behind us
            // reads this the moment it wakes, and skips the Trash.
            TRASH_UNRESPONSIVE.store(true, std::sync::atomic::Ordering::Relaxed);
        }
        _ => TRASH_ANSWERED.store(true, std::sync::atomic::Ordering::Relaxed),
    }
    outcome.map_err(Some)
}

/// The two shapes a Trash call that gave up comes back as: the crate's own
/// wording, and the raw AppleEvent code behind it.
fn looks_like_a_trash_timeout(msg: &str) -> bool {
    msg.contains("timed out") || msg.contains("-1712")
}

/// Held for the duration of the process's first Trash call - see
/// `trash_delete_gated`. Never taken again once `TRASH_ANSWERED` is set.
static FIRST_TRASH_CALL: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Set once any Trash call has come back, success or ordinary failure:
/// proof the backend answers, and the point past which the first-call gate
/// has nothing left to protect.
static TRASH_ANSWERED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
fn trash_answered() -> bool {
    TRASH_ANSWERED.load(std::sync::atomic::Ordering::Relaxed)
}

/// The flags below are process-global and the trash tests write them, so
/// those tests take this first and run one at a time. Without it `cargo
/// test` runs them together and one test's latch - or its reset - lands
/// inside another test's delete: `a_junk_delete_is_recoverable_and_the_
/// opt_out_is_not` then finds its fixture hard-deleted rather than binned.
/// Lives out here, not in one test module, because both of them need it.
///
/// A writer excluding only other writers was not enough: every delete in
/// the suite READS these globals (`delete_to_trash` at its entry, the
/// latch inside the gate), so a delete-asserting test that overlapped a
/// writer's window saw `TRASH` on and its delete came back refused - the
/// file it asserted gone was still there, roughly one full-suite run in
/// four. Worse, a reader that caught the window made a REAL Trash call,
/// which set `TRASH_ANSWERED` under nobody's lock and broke
/// `concurrent_callers_probe_a_dead_trash_only_once` from across the
/// module. So this is a reader-writer lock: flag-writing tests take the
/// write side, and every test whose delete reads the flags holds
/// [`trash_globals_steady`] across the delete and its asserts - shared
/// among themselves, exclusive against any writer.
#[cfg(test)]
fn trash_globals_lock() -> &'static std::sync::RwLock<()> {
    static SERIAL: std::sync::RwLock<()> = std::sync::RwLock::new(());
    &SERIAL
}

/// Exclusive side, for tests that WRITE the trash globals.
#[cfg(test)]
pub(crate) fn one_trash_test_at_a_time() -> std::sync::RwLockWriteGuard<'static, ()> {
    // Poison is nothing here: each test sets the flags it cares about on
    // the way in, so a panicking predecessor leaves nothing to inherit.
    crate::RwLockExt::write_ok(trash_globals_lock())
}

/// Shared side, for tests whose deletes READ the trash globals: any test
/// that asserts what a `remove_user_file`-family delete left on disk.
/// Take it before creating fixtures and hold it past the last assert.
#[cfg(test)]
pub(crate) fn trash_globals_steady() -> std::sync::RwLockReadGuard<'static, ()> {
    crate::RwLockExt::read_ok(trash_globals_lock())
}

/// Pretend every Trash route has given up, for tests that need a REFUSED
/// recoverable delete without a machine that has one. The refusal is the
/// interesting case - it is what leaves a user's download on disk after
/// they asked for it to go - and it is otherwise unreachable from a test:
/// the real latch only sets after a backend blows `TRASH_DEADLINE`.
///
/// Take [`one_trash_test_at_a_time`] first, and set it back on the way
/// out: this is the same process-global every other trash test reads.
#[cfg(test)]
pub(crate) fn force_trash_unresponsive(v: bool) {
    TRASH_UNRESPONSIVE.store(v, std::sync::atomic::Ordering::Relaxed);
}

/// Latched when a Trash call gives up waiting - and on macOS only once
/// BOTH routes have (`trash_delete_bounded` falls through to
/// `NSFileManager` before it reports a failure at all). Deliberately never
/// reset: a backend that timed out once will do it again, and each probe
/// costs up to `TRASH_DEADLINE` of a live job.
///
/// Read publicly as "is a recoverable delete actually available", which is
/// why a Finder failure must not set it: `FINDER_IS_OUT` covers that, and
/// the volume's own Trash still works.
static TRASH_UNRESPONSIVE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
pub fn trash_unresponsive() -> bool {
    TRASH_UNRESPONSIVE.load(std::sync::atomic::Ordering::Relaxed)
}

/// Where a sweep of `dir` parks recoverable deletes: a hidden folder
/// BESIDE the swept directory, so the park is a same-volume rename.
///
/// Beside, not inside, for two reasons that are both load-bearing. Inside
/// the swept tree the sweep's own one-level descent would walk into it and
/// re-delete what it just parked. And `finalize_names` may move the whole
/// job directory (onto a NAS, into a season folder) the moment the sweep
/// returns - a parked file must stay put while that happens, or the queued
/// path goes stale and the junk rides along into the library.
/// pub(crate): the engine-side sweeps (spent obfuscated volumes,
/// consumed adoption sources in get.rs/unpack.rs) park the same way the
/// finalize sweeps do, for the same §64 reason - their deletes run in a
/// job's tail, and an inline Trash call is a Finder wait the job pays.
pub(crate) fn trash_staging_dir(dir: &Path) -> Option<PathBuf> {
    Some(dir.parent()?.join(".nzbfast-trash"))
}

/// The sweeps' delete: like `remove_user_file`, but a recoverable delete
/// is parked in `staging` for the background worker instead of talking to
/// the Trash inline. The rename is what actually empties the job
/// directory, and it is instant - so a slow Finder can no longer hold
/// `finalize_completed` (and with it the job's history entry) hostage.
/// See §64: the first Trash call of a headless process used to cost the
/// finalize path 30 s, and before the bound, minutes per file.
///
/// Any staging failure (no parent, EXDEV, a read-only tree) falls through
/// to the inline delete, which still works everywhere it used to.
pub(crate) fn remove_swept_file(
    path: &Path,
    recoverable: bool,
    staging: Option<&Path>,
) -> std::io::Result<Removed> {
    // When the latch is set there is no Trash to park FOR: the inline path
    // refuses and leaves the file, and a staging folder full of files
    // nobody will ever dispose of is worse than the file where it was.
    if recoverable
        && !trash_unresponsive()
        && let Some(root) = staging
        && deferred_trash::stage(path, root).is_ok()
    {
        // Staged, not yet disposed of. The worker decides the real
        // outcome later, so this promises nothing: the sweeps that use
        // this path do not report a fate to the user.
        return Ok(Removed::Gone);
    }
    remove_user_file(path, recoverable)
}

/// One background worker owns every conversation with the Trash, so no
/// job's finalize ever waits on Finder.
///
/// A file is handed over by RENAME into a staging folder first - that is
/// the synchronous part, and the reason a directory move immediately
/// after a sweep cannot race the delete: by the time the sweep returns,
/// the file is already out of the tree. The worker then does the real
/// recoverable delete at its leisure, inheriting the bounded call and the
/// unresponsive latch from `remove_user_file`.
mod deferred_trash {
    use crate::MutexExt;
    use std::path::{Path, PathBuf};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::{Mutex, OnceLock, mpsc};
    use tracing::warn;

    static SENDER: OnceLock<mpsc::Sender<PathBuf>> = OnceLock::new();
    /// Staging roots this process has already drained of leftovers.
    static SEEN: OnceLock<Mutex<std::collections::HashSet<PathBuf>>> = OnceLock::new();
    /// Disambiguates same-named files from different jobs (every job has
    /// a `.par2`, most have an `.nfo`).
    static SEQ: AtomicU64 = AtomicU64::new(0);

    fn sender() -> &'static mpsc::Sender<PathBuf> {
        SENDER.get_or_init(|| {
            let (tx, rx) = mpsc::channel::<PathBuf>();
            std::thread::Builder::new()
                .name("trash-worker".into())
                .spawn(move || {
                    for p in rx {
                        // The setting is re-read at disposal time, not
                        // frozen at park time: the file already left the
                        // user's tree when the sweep decided to delete it,
                        // so only its disposition (Trash vs gone) is at
                        // stake here - and under cfg(test) the default-off
                        // global keeps the suite out of the developer's
                        // real Trash, exactly like every sweep. Read
                        // through cleanup_recoverable: everything staged
                        // here came from a GARBAGE sweep, so its
                        // disposition follows the garbage setting, not
                        // the download-delete one.
                        // NotFound is Ok here (a double-enqueue after a
                        // leftover drain, or Finder finishing behind us).
                        //
                        // A REFUSED delete leaves the file staged, which is
                        // the one place this differs from an inline sweep:
                        // the file has already left the user's tree, so the
                        // log has to name where it is now or it is simply
                        // missing. Staged is still recoverable - a visible
                        // file on the same volume - and the next drain of
                        // this root retries it.
                        if let Err(e) = super::remove_user_file(&p, super::cleanup_recoverable()) {
                            warn!(target: "cleanup", "deferred trash {}: {e}", p.display());
                        }
                        // Leave nothing behind when the queue drains: an
                        // empty staging folder is clutter beside the
                        // user's downloads. Non-empty simply refuses.
                        if let Some(root) = p.parent() {
                            let _ = std::fs::remove_dir(root);
                        }
                    }
                })
                .expect("spawn trash worker");
            tx
        })
    }

    /// Move `path` into `root` and queue it for the worker. The caller
    /// treats any Err as "park unavailable" and deletes inline instead.
    pub(super) fn stage(path: &Path, root: &Path) -> std::io::Result<()> {
        let name = path
            .file_name()
            .ok_or_else(|| std::io::Error::other("no file name"))?;
        std::fs::create_dir_all(root)?;
        let n = SEQ.fetch_add(1, Ordering::Relaxed);
        let mut staged_name = std::ffi::OsString::from(format!("{}-{n}-", std::process::id()));
        staged_name.push(name);
        let dest = root.join(staged_name);
        std::fs::rename(path, &dest)?;
        // First touch of a root this process: sweep up leftovers a
        // crashed predecessor parked and never got to. The listing
        // includes `dest`, so nothing extra to send; later touches send
        // just their own file. A racing second stager double-sends at
        // worst, and the worker tolerates NotFound.
        let fresh = SEEN
            .get_or_init(|| Mutex::new(std::collections::HashSet::new()))
            .lock_ok()
            .insert(root.to_path_buf());
        let tx = sender();
        if fresh {
            if let Ok(rd) = std::fs::read_dir(root) {
                for e in rd.flatten() {
                    let _ = tx.send(e.path());
                }
            }
        } else {
            let _ = tx.send(dest);
        }
        Ok(())
    }
}

/// Is the Trash somewhere the user can actually find and empty?
///
/// On macOS and Windows, yes: one Trash, one Recycle Bin, both in front
/// of the person the recoverability is for.
///
/// On Linux, no - and worse than no. When the download volume is not the
/// volume the home trash lives on (which is every NAS, every container,
/// every seedbox), the freedesktop rules send the file to a
/// `.Trash-<uid>` directory the crate CREATES at the top of the download
/// volume. So "recoverable" quietly means "moved to another folder on
/// the same disk, forever": the space never comes back, nothing in the
/// UI says where it went, and no desktop is running to empty it. It cost
/// a user their SSD a directory at a time, reported from Unraid on
/// 2 Aug 2026, and they left for another downloader over it.
///
/// So the recoverable default follows the platform, and Linux installs
/// delete outright unless the operator turns `delete_to_trash` back on.
/// Cleanup still tells the log what it removed either way.
const fn trash_suits_this_platform() -> bool {
    !cfg!(target_os = "linux")
}

/// Process-global so the free functions in here need no Daemon handle.
///
/// Defaults OFF under `cfg(test)`: the cleanup suites delete hundreds of
/// fixture files, and with the Trash on they would empty them into the
/// developer's real ~/.Trash and race each other through this one flag.
/// The test that covers the Trash path opts in explicitly.
static TRASH: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(!cfg!(test) && trash_suits_this_platform());
pub fn set_delete_to_trash(on: bool) {
    TRASH.store(on, std::sync::atomic::Ordering::Relaxed);
}
pub fn delete_to_trash() -> bool {
    TRASH.load(std::sync::atomic::Ordering::Relaxed)
}

/// Where CLEANUP deletes go - the garbage class: spent archive volumes
/// after a successful unpack, consumed adoption sources, sniffed
/// recovery files, and the junk sweep. Separate from `delete_to_trash`
/// (which keeps governing deletes of the downloads THEMSELVES - queue
/// and history deletes, watchlist upgrades, library episode drops)
/// because the two classes pull opposite ways: garbage is high-volume
/// and worthless-by-verdict (50 GB of spent volumes fills a Trash
/// nobody empties), while a deleted download is the user's own data.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CleanupMode {
    /// Ride `delete_to_trash`, exactly the pre-setting behavior.
    Follow,
    /// Always recoverable, even when download deletes are permanent.
    Trash,
    /// Always permanent, even when download deletes go to the Trash.
    Delete,
}

impl CleanupMode {
    pub fn as_str(self) -> &'static str {
        match self {
            CleanupMode::Follow => "follow",
            CleanupMode::Trash => "trash",
            CleanupMode::Delete => "delete",
        }
    }
    pub fn parse(v: &str) -> Option<CleanupMode> {
        match v {
            "follow" => Some(CleanupMode::Follow),
            "trash" => Some(CleanupMode::Trash),
            "delete" => Some(CleanupMode::Delete),
            _ => None,
        }
    }
}

/// Process-global like `TRASH`, for the same reason. 0=follow 1=trash
/// 2=delete; default `follow` so an upgrade changes nobody's behavior.
static CLEANUP_MODE: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);
pub fn set_cleanup_mode(m: CleanupMode) {
    let v = match m {
        CleanupMode::Follow => 0,
        CleanupMode::Trash => 1,
        CleanupMode::Delete => 2,
    };
    CLEANUP_MODE.store(v, std::sync::atomic::Ordering::Relaxed);
}
pub fn cleanup_mode() -> CleanupMode {
    match CLEANUP_MODE.load(std::sync::atomic::Ordering::Relaxed) {
        1 => CleanupMode::Trash,
        2 => CleanupMode::Delete,
        _ => CleanupMode::Follow,
    }
}

/// The `recoverable` flag a GARBAGE sweep should pass to
/// [`remove_user_file`] / [`remove_swept_file`]. Read once at a sweep's
/// entry, same contract as `delete_to_trash`.
pub fn cleanup_recoverable() -> bool {
    match cleanup_mode() {
        CleanupMode::Follow => delete_to_trash(),
        CleanupMode::Trash => true,
        CleanupMode::Delete => false,
    }
}

/// A scrap left inside an archive: no extension at all, and far too small
/// to be anything a user asked for, sitting next to an identified feature.
///
/// Found via a Supergirl release whose junk sweep left a 56-byte file
/// called `GqRTzbOIvUzZg1hqbipRind85vn` beside a 20 GB mkv. It is not in
/// the nzb - every POSTED file there is `30fb7ada….NN` or `.par2`, fully
/// obfuscated - so it came out of the RAR, packed by whoever made the
/// release. Nothing else in `sweep_junk` could see it: no extension to
/// match, not PAR2 magic, and not sample-shaped.
///
/// Kept deliberately narrow, because this is the rule most likely to eat
/// something real:
///  * no extension WHATSOEVER - an unknown extension is somebody's file,
///    and a subtitle or a companion track always has one;
///  * a hard byte ceiling, not a ratio - "small next to a 20 GB feature"
///    would cover a 20 MB file;
///  * only where a feature video was actually identified, so this cannot
///    fire on a music, book or software release, which is exactly where
///    extensionless files are legitimate;
///  * never anything that starts with an archive or media magic number,
///    however small.
fn is_nameless_scrap(p: &Path, ext: &str, feature_len: u64, recoverable: bool) -> bool {
    // ONLY when the delete can be undone. `sweep_junk_drops_extensionless_par2_by_magic`
    // pins the opposite rule - a hash-named blob that is NOT par2 stays,
    // because the magic decides and not the shape of the name - and that
    // invariant was written when a wrong guess was permanent. It still
    // holds wherever it still matters: with the Trash off (NAS, container)
    // this rule is simply not applied, and behaviour is exactly as before.
    if !recoverable || !ext.is_empty() || feature_len == 0 {
        return false;
    }
    let Ok(md) = std::fs::metadata(p) else {
        return false;
    };
    if md.len() > 4096 {
        return false;
    }
    let mut head = [0u8; 8];
    let read = std::fs::File::open(p)
        .and_then(|mut f| {
            use std::io::Read;
            f.read(&mut head)
        })
        .unwrap_or(0);
    let head = &head[..read];
    const MAGIC: &[&[u8]] = &[
        b"Rar!",
        b"PK\x03\x04",
        b"7z\xbc\xaf",
        b"\x1f\x8b",
        b"BZh",
        b"\xfd7zXZ",
        b"\x1aE\xdf\xa3",
        b"RIFF",
        b"%PDF",
        b"\x89PNG",
        b"\xff\xd8\xff",
        b"ID3",
    ];
    !MAGIC.iter().any(|m| head.starts_with(m))
}

pub fn sweep_junk(dir: &Path) -> usize {
    let recoverable = cleanup_recoverable();
    let staging = trash_staging_dir(dir);
    let keep = largest_video(dir);
    let keep_len = keep
        .as_ref()
        .and_then(|p| p.metadata().ok())
        .map(|m| m.len())
        .unwrap_or(0);
    let mut removed = 0;
    let mut sweep = |d: &Path| {
        let Ok(rd) = std::fs::read_dir(d) else { return };
        for entry in rd.flatten() {
            let path = entry.path();
            if !is_real_file(&path) || keep.as_ref() == Some(&path) {
                continue;
            }
            let ext = ext_of(&path);
            // Magic sniff only where the name has already failed to
            // identify the file: never open a video or a subtitle, so a
            // payload can't be reached by this path however it decodes.
            let sniffable =
                !VIDEO_EXTS.contains(&ext.as_str()) && !SUBTITLE_EXTS.contains(&ext.as_str());
            let junk = JUNK_EXTS.contains(&ext.as_str())
                || (sniffable && par2_magic(&path))
                || is_deletable_sample(&path, keep_len)
                || is_nameless_scrap(&path, &ext, keep_len, recoverable);
            if junk {
                match remove_swept_file(&path, recoverable, staging.as_deref()) {
                    Ok(_) => {
                        info!(target: "cleanup", "junk {}", path.display());
                        removed += 1;
                    }
                    Err(e) => warn!(target: "cleanup", "{}: {e}", path.display()),
                }
            }
        }
    };
    sweep(dir);
    if let Ok(rd) = std::fs::read_dir(dir) {
        for entry in rd.flatten() {
            let path = entry.path();
            if is_real_dir(&path) {
                sweep(&path);
            }
        }
    }
    prune_empty_dirs(dir, 0);
    removed
}

/// Aggressive cleanup: delete everything in `dir` that is NOT a video, a
/// subtitle / companion-track file, or a still-packed archive (top level +
/// one subdir deep). Keeps ALL real videos - a season pack stays whole -
/// but drops sample/proof clips. Returns the number of files removed.
///
/// A job with no video at all is left completely alone: see the guard.
pub fn keep_media_only(dir: &Path) -> usize {
    let mut removed = 0;
    // Read once, for the whole sweep: see `remove_user_file`.
    let recoverable = cleanup_recoverable();
    let staging = trash_staging_dir(dir);
    // The feature size gates sample deletion: a same-size episode in a
    // "Proof"/"Sample" season pack is kept, only a small teaser is dropped.
    let Some(feature) = largest_video(dir) else {
        // No video anywhere in the job, so this function's premise - "keep
        // the media, drop the clutter beside it" - does not hold: there is
        // nothing here it can tell payload from clutter BY, so a music
        // album, an audiobook, a comic or an ebook release would be
        // deleted in full and the job would still report Completed over an
        // empty folder. Reached whenever a user category with base Movie
        // or Tv holds non-video content, which is most of them.
        //
        // This guard is necessary but NOT sufficient: one bonus .mp4 in
        // such a job passes it. That is what PAYLOAD_EXTS is for.
        info!(
            target: "cleanup",
            "keep-media-only: no video in {} - left alone",
            dir.display()
        );
        return 0;
    };
    let feature_len = feature.metadata().map(|m| m.len()).unwrap_or(0);
    let mut sweep = |d: &Path| {
        // Once per directory, not once per file: split sets are only
        // recognisable as sets.
        let zip_parts = zip_part_set(d);
        let Ok(rd) = std::fs::read_dir(d) else { return };
        for entry in rd.flatten() {
            let path = entry.path();
            if !is_real_file(&path) {
                continue;
            }
            let ext = ext_of(&path);
            let is_media =
                VIDEO_EXTS.contains(&ext.as_str()) && !is_deletable_sample(&path, feature_len);
            // Subtitles plus the disc-structure / companion-track files a
            // video payload is incomplete without - see MEDIA_COMPANION_EXTS.
            let is_companion = SUBTITLE_EXTS.contains(&ext.as_str())
                || MEDIA_COMPANION_EXTS.contains(&ext.as_str())
                || PAYLOAD_EXTS.contains(&ext.as_str());
            // An archive still sitting here is payload we could not
            // unpack, not clutter - see `is_packed_archive`. An
            // extensionless file that opens like a video is payload too,
            // just unpacked - see `looks_like_video_bytes`.
            if is_media
                || is_companion
                || is_packed_archive(&path, &zip_parts)
                || looks_like_video_bytes(&path)
            {
                continue;
            }
            match remove_swept_file(&path, recoverable, staging.as_deref()) {
                Ok(_) => {
                    info!(target: "cleanup", "non-media {}", path.display());
                    removed += 1;
                }
                Err(e) => warn!(target: "cleanup", "{}: {e}", path.display()),
            }
        }
    };
    sweep(dir);
    if let Ok(rd) = std::fs::read_dir(dir) {
        for entry in rd.flatten() {
            let path = entry.path();
            if is_real_dir(&path) {
                sweep(&path);
            }
        }
    }
    prune_empty_dirs(dir, 0);
    removed
}

/// Move a finished job's tree into `dst`, merging with whatever is
/// already there (a Season folder on a NAS accumulates episodes across
/// jobs). Same-filesystem with no pre-existing destination = one rename;
/// a same-filesystem merge goes entry by entry, which is again nothing
/// but renames. Different filesystems - a NAS share is the whole point
/// of this helper - means the bytes have to be copied, so the tree is
/// staged beside the destination and published only once it is whole:
/// see [`staged_move`]. A name collision keeps the existing destination
/// file and lands ours beside it with a " (n)" suffix - completed
/// downloads are never overwritten. Empty source dirs are removed as
/// they drain.
/// Distinguishes the staging directories of concurrent moves that share a
/// destination. See [`move_tree`].
static MOVE_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Dark knob: run the copy half of a move at background disk-I/O
/// priority. `NZBFAST_MOVE_IOPOL=throttle|utility|off` - unset means off
/// until the default is priced (see research/MOVE-INTERFERENCE-2026-08-05.md).
///
/// Only the COPY side is ever demoted. Renames are metadata and never
/// contend with a download's writes; the clone that `std::fs::copy` makes
/// on same-volume APFS is one too (measured: 4 GiB in 0.05 s with zero
/// foreground impact).
fn move_iopol() -> Option<&'static str> {
    match std::env::var("NZBFAST_MOVE_IOPOL").ok()?.as_str() {
        "throttle" => Some("throttle"),
        "utility" => Some("utility"),
        _ => None,
    }
}

/// Lower the calling thread's disk-I/O priority while a bulk copy runs,
/// and RESTORE it on drop: moves run on tokio's blocking pool, whose
/// threads are reused, so a policy left set would demote whatever
/// unrelated work lands on this thread next (a spool write, a directory
/// sweep, another job's unlock).
///
/// macOS: `setiopolicy_np(IOPOL_TYPE_DISK, IOPOL_SCOPE_THREAD, ..)` -
/// the mechanism Time Machine and Spotlight use, enforced in the kernel's
/// I/O scheduler. Linux: `ioprio_set` to the idle class, best effort (it
/// only shapes traffic under the CFQ/BFQ/mq-deadline schedulers; on none
/// it is a no-op, which is fine for an opt-in knob). Windows: not
/// implemented - `THREAD_MODE_BACKGROUND_BEGIN` also drops memory and
/// scheduling priority, which is a bigger hammer than this knob promises,
/// so it stays out until someone measures it.
struct BackgroundIo {
    #[cfg(target_os = "macos")]
    prev: i32,
    #[cfg(target_os = "linux")]
    prev: i64,
}

#[cfg(target_os = "macos")]
mod iopol {
    pub const IOPOL_TYPE_DISK: i32 = 0;
    pub const IOPOL_SCOPE_THREAD: i32 = 1;
    pub const IOPOL_THROTTLE: i32 = 3;
    pub const IOPOL_UTILITY: i32 = 4;
    unsafe extern "C" {
        pub fn getiopolicy_np(iotype: i32, scope: i32) -> i32;
        pub fn setiopolicy_np(iotype: i32, scope: i32, policy: i32) -> i32;
    }
}

impl BackgroundIo {
    /// Demote this thread per the knob; `None` when the knob is off (or
    /// the platform has nothing to set), which callers hold just the same.
    fn engage() -> Option<Self> {
        let which = move_iopol()?;
        #[cfg(target_os = "macos")]
        {
            let policy = if which == "throttle" {
                iopol::IOPOL_THROTTLE
            } else {
                iopol::IOPOL_UTILITY
            };
            unsafe {
                let prev = iopol::getiopolicy_np(iopol::IOPOL_TYPE_DISK, iopol::IOPOL_SCOPE_THREAD);
                if iopol::setiopolicy_np(iopol::IOPOL_TYPE_DISK, iopol::IOPOL_SCOPE_THREAD, policy)
                    != 0
                {
                    return None;
                }
                Some(Self { prev })
            }
        }
        #[cfg(target_os = "linux")]
        {
            // Both spellings demote to the idle class: Linux has no
            // in-between the knob's two names map onto cleanly, and
            // "utility" meaning "idle" beats the surprise of a knob that
            // works on one platform and silently not the other.
            let _ = which;
            const IOPRIO_WHO_PROCESS: i64 = 1;
            const IOPRIO_CLASS_IDLE: i64 = 3;
            unsafe {
                let prev = libc::syscall(libc::SYS_ioprio_get, IOPRIO_WHO_PROCESS, 0i64);
                if libc::syscall(
                    libc::SYS_ioprio_set,
                    IOPRIO_WHO_PROCESS,
                    0i64,
                    IOPRIO_CLASS_IDLE << 13,
                ) != 0
                {
                    return None;
                }
                Some(Self { prev })
            }
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            let _ = which;
            None
        }
    }
}

impl Drop for BackgroundIo {
    fn drop(&mut self) {
        #[cfg(target_os = "macos")]
        unsafe {
            let _ =
                iopol::setiopolicy_np(iopol::IOPOL_TYPE_DISK, iopol::IOPOL_SCOPE_THREAD, self.prev);
        }
        #[cfg(target_os = "linux")]
        unsafe {
            const IOPRIO_WHO_PROCESS: i64 = 1;
            let _ = libc::syscall(libc::SYS_ioprio_set, IOPRIO_WHO_PROCESS, 0i64, self.prev);
        }
    }
}

pub fn move_tree(src: &Path, dst: &Path) -> std::io::Result<()> {
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent)?;
    }
    if !dst.exists() {
        // Fast path: same filesystem, nothing to merge.
        if std::fs::rename(src, dst).is_ok() {
            return Ok(());
        }
    }
    // Staging is a sibling of the destination, so it shares the
    // destination's filesystem and everything published out of it is a
    // plain rename.
    //
    // The name identifies this MOVE, not the destination. Two jobs can
    // share a `dst` - with TV filing, every episode of a season lands in
    // the same `Season NN` folder - and their post-processing tails run
    // concurrently. A name derived from `dst` alone gave both of them one
    // staging directory, and each cleared it before staging its own tree:
    // one payload was published into the other's place, the loser's source
    // was then drained, and both jobs reported success. A hard kill now
    // leaves its staging directory behind rather than having the next move
    // to the same folder clear it, which costs disk space until it is
    // deleted and never costs a payload.
    let mut staging_name = std::ffi::OsString::from(".");
    staging_name.push(
        dst.file_name()
            .unwrap_or_else(|| std::ffi::OsStr::new("job")),
    );
    staging_name.push(format!(
        ".moving.{}.{}",
        std::process::id(),
        MOVE_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ));
    let staging = dst.with_file_name(staging_name);
    if !rename_reaches(src, &staging) {
        return staged_move(src, dst, &staging);
    }
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        // `is_real_dir`, not `is_dir`: the latter follows symlinks, so a
        // job containing `extras -> /external` used to make this function
        // read_dir THROUGH the link and move the target's children into the
        // completed destination, deleting them from where they actually
        // lived. A link is moved as the link object it is, never walked.
        if is_real_dir(&from) {
            move_tree(&from, &to)?;
        } else {
            let target = reserve_free_name(&to)?;
            if std::fs::rename(&from, &target).is_err() {
                if is_symlink(&from) {
                    // Cross-device and a symlink: `copy` would follow it and
                    // write the TARGET's bytes here, so leave the link where
                    // it is rather than silently turning it into a fat copy
                    // of something outside the job.
                    let _ = std::fs::remove_file(&target); // our placeholder
                    warn!(
                        target: "move",
                        "left symlink in place (cross-device): {}",
                        from.display()
                    );
                    continue;
                }
                // One filesystem and the rename STILL failed, so fall back
                // to a copy for this file alone; make it durable before the
                // source goes. A failure in either half leaves `target`
                // holding zero, partial or unflushed bytes under the
                // payload's own file name, and an importer scanning the
                // destination would take that as the episode. The source
                // has not been touched yet at this point, so dropping our
                // half-written copy can never cost the only copy - the file
                // simply has not moved.
                let _bg = BackgroundIo::engage();
                let copied =
                    copy_verified(&from, &target).and_then(|()| sync_written_file(&target));
                if let Err(e) = copied {
                    if let Err(rm) = std::fs::remove_file(&target) {
                        // Whatever broke the copy can break the unlink too
                        // (a share that dropped answers both with EIO), so
                        // say the fragment may still be sitting there.
                        warn!(
                            target: "move",
                            "could not remove the partial copy {}: {rm}",
                            target.display()
                        );
                    }
                    return Err(e);
                }
                std::fs::remove_file(&from)?;
            }
        }
    }
    let _ = std::fs::remove_dir(src); // only removes if now empty
    Ok(())
}

/// Can a rename move things out of `src` and into `probe_dst`'s directory,
/// or do the two sit on different filesystems?
///
/// Asked with an EMPTY directory of our own, never with payload: the probe
/// is created inside `src` and renamed to where the staging directory would
/// go. It decides only which of two correct routes [`move_tree`] takes, so
/// a wrong answer costs speed, not data - which is why this asks the
/// filesystem the exact question rather than approximating it from device
/// numbers that Windows does not expose.
fn rename_reaches(src: &Path, probe_dst: &Path) -> bool {
    let probe = src.join(".nzbfast-moving-probe");
    let _ = std::fs::remove_dir(&probe); // abandoned by an earlier crash
    if std::fs::create_dir(&probe).is_err() {
        return false;
    }
    let same = std::fs::rename(&probe, probe_dst).is_ok();
    let _ = std::fs::remove_dir(if same { probe_dst } else { &probe });
    same
}

/// The cross-device half of [`move_tree`]: copy the whole tree into
/// `staging`, publish it, and only then delete the source.
///
/// Copying file by file straight into `dst` is what used to SPLIT a payload
/// across two filesystems. Each source file was deleted the moment its copy
/// landed, so a failure partway (ENOSPC, EIO, a share that dropped) left
/// some episodes on the NAS and the rest in the download folder, while the
/// caller reported one directory as the job's home - an importer then took
/// whichever fragment it was pointed at as the whole release. Staging keeps
/// the source whole until the destination is, so a failure costs the move
/// and never the payload. It is the shape the spool migration already uses.
fn staged_move(src: &Path, dst: &Path, staging: &Path) -> std::io::Result<()> {
    // Held for the whole copy: this is the multi-GB bulk transfer that
    // competes with a live download's write side. Dropped before the
    // publish renames and the source drain - they are metadata and the
    // download should not have to wait behind an idle-class unlink queue.
    let bg = BackgroundIo::engage();
    let mut copied = std::collections::HashSet::new();
    if let Err(e) = copy_tree_into(src, staging, &mut copied).and_then(|()| {
        drop(bg);
        publish_staged(staging, dst)
    }) {
        // Nothing in `src` has been deleted, so the payload is still whole
        // where it was and the caller is right to report the move as not
        // taken. Drop what is still staged; note this cannot un-publish a
        // merge that failed part way, so `dst` may keep the entries that
        // were already renamed into it, under the payload's own names.
        // They are copies - the originals are all still in `src`.
        let _ = std::fs::remove_dir_all(staging);
        return Err(e);
    }
    drain_copied(src, &copied);
    Ok(())
}

/// Publish a staged tree into its final home. `staging` is a sibling of
/// `dst`, so every step is a same-filesystem rename: ONE for the whole
/// directory when nothing is there yet, and otherwise entry by entry so a
/// Season folder already holding episodes keeps them.
fn publish_staged(staging: &Path, dst: &Path) -> std::io::Result<()> {
    if !dst.exists() && std::fs::rename(staging, dst).is_ok() {
        // Persist the name before the caller deletes the source.
        return sync_dir(dst.parent().unwrap_or(dst));
    }
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(staging)? {
        let entry = entry?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if is_real_dir(&from) {
            publish_staged(&from, &to)?;
        } else {
            let target = reserve_free_name(&to)?;
            if let Err(e) = std::fs::rename(&from, &target) {
                let _ = std::fs::remove_file(&target); // our placeholder
                return Err(e);
            }
        }
    }
    let _ = std::fs::remove_dir(staging); // only removes if now empty
    sync_dir(dst)
}

/// Delete what [`copy_tree`] reproduced at the destination and leave what
/// it skipped. Symlinks are the reason it is not a `remove_dir_all`:
/// `copy_tree` does not follow them, so the link object here is still the
/// only one and stays put, exactly as a cross-device move has always left
/// it.
///
/// `copied` is the manifest [`copy_tree_into`] filled in, and ONLY those
/// files are deleted. Re-walking the source instead deleted whatever the
/// walk found, including files that appeared AFTER the copy pass - a
/// post-processing script's output, a user's drop-in - which were therefore
/// deleted having never been copied anywhere, so they existed nowhere
/// afterwards. Anything not in the manifest stays where it is.
///
/// Best effort by design. The payload is already whole and durable at the
/// destination by the time this runs, so a source file that will not go is
/// clutter to report - failing the move over it would tell the caller
/// nothing had moved when everything had.
fn drain_copied(src: &Path, copied: &std::collections::HashSet<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(src) else {
        return;
    };
    for entry in rd.flatten() {
        let from = entry.path();
        if is_real_dir(&from) {
            drain_copied(&from, copied);
        } else if is_real_file(&from) {
            if !copied.contains(&from) {
                warn!(
                    target: "move",
                    "appeared after the copy, so it stays where it is: {}",
                    from.display()
                );
                continue;
            }
            if let Err(e) = std::fs::remove_file(&from) {
                warn!(
                    target: "move",
                    "copied, but the source stays: {} ({e})",
                    from.display()
                );
            }
        } else {
            warn!(
                target: "move",
                "left symlink in place (cross-device): {}",
                from.display()
            );
        }
    }
    let _ = std::fs::remove_dir(src); // only removes if now empty
}

/// Recursively COPY `src` into `dst`, fsyncing every file as it lands.
///
/// The copying twin of [`move_tree`], and the engine of its cross-device
/// path: for anything that must be able to fail without having touched the
/// source. Deleting each source file as soon as its copy is durable is what
/// leaves half the state at the destination and half at the source with no
/// single complete copy, so callers copy first and publish second.
/// Symlinks are skipped rather than followed, for the reason in
/// [`is_real_dir`].
pub fn copy_tree(src: &Path, dst: &Path) -> std::io::Result<()> {
    copy_tree_into(src, dst, &mut std::collections::HashSet::new())
}

/// [`copy_tree`], recording every SOURCE file it actually reproduced in
/// `copied`. The record is what lets [`drain_copied`] delete exactly what
/// was copied and nothing that arrived later.
fn copy_tree_into(
    src: &Path,
    dst: &Path,
    copied: &mut std::collections::HashSet<PathBuf>,
) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if is_real_dir(&from) {
            copy_tree_into(&from, &to, copied)?;
        } else if is_real_file(&from) {
            copy_verified(&from, &to)?;
            sync_written_file(&to)?;
            copied.insert(from);
        }
    }
    sync_dir(dst)
}

/// `std::fs::copy`, refusing to call a short copy done. The source is
/// only ever deleted against what this wrote, so the check runs before
/// anything downstream can trust the destination: a filesystem that
/// silently truncated (an SMB share at quota, a FUSE layer that dropped
/// a write) must fail the move while the source is still whole, not be
/// discovered by the player. Sizes, not hashes - the byte-for-byte cost
/// belongs to the transports that are known to lie, and none of the
/// failures seen in the field so far kept the length intact.
fn copy_verified(from: &Path, to: &Path) -> std::io::Result<()> {
    let wrote = std::fs::copy(from, to)?;
    let want = std::fs::metadata(from)?.len();
    if wrote != want {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("short copy: wrote {wrote} of {want} bytes"),
        ));
    }
    Ok(())
}

/// fsync a directory, so the names created in it survive power loss.
///
/// Syncing a file persists its CONTENTS; the directory entry pointing at it
/// is separate metadata and needs its own flush. Without this a rename can be
/// reported successful and still be absent after a crash. Unix only - Windows
/// has no directory handle to flush this way, and `File::open` on a directory
/// fails there, so it is a deliberate no-op.
pub fn sync_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        std::fs::File::open(dir)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        Ok(())
    }
}

/// fsync a file we have just written, addressed by its path.
///
/// The handle has to be WRITABLE. Unix flushes a read-only descriptor quite
/// happily, so `File::open(p)?.sync_all()` looked correct here for as long
/// as this code existed - but Windows answers `FlushFileBuffers` on a
/// read-only handle with ERROR_ACCESS_DENIED, and that one difference broke
/// every cross-device move and the spool migration on Windows. `copy_tree`
/// failed on the FIRST file it copied, so `staged_move` returned "Access is
/// denied." having moved nothing, and `spool_dir` logged that it could not
/// move the daemon state out of the download folder and carried on using
/// the old location. Neither ever lost a byte - both are written to fail
/// with the source still whole - but on Windows neither could ever succeed,
/// and a download folder and a library on two different drives is the
/// ordinary Windows setup.
///
/// Measured directly on x86-64 Windows (rustc 1.97.1): a read-only handle
/// gives os error 5, a writable one gives Ok(()).
fn sync_written_file(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        // Deliberately unchanged: a read-only descriptor is a valid fsync
        // target here, and it flushes a mode-444 file, which opening for
        // write would not even be allowed to touch.
        std::fs::File::open(path)?.sync_all()
    }
    #[cfg(not(unix))]
    {
        match std::fs::OpenOptions::new().write(true).open(path) {
            Ok(f) => return f.sync_all(),
            // `fs::copy` reproduces the source's read-only ATTRIBUTE, and
            // such a file cannot be flushed through ANY handle on Windows.
            // Clear the bit, flush, put it back: we own this copy, and
            // skipping the flush instead would hand the caller an
            // undurable destination to delete the source against, which is
            // the one failure staging exists to prevent.
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {}
            Err(e) => return Err(e),
        }
        let md = std::fs::metadata(path)?;
        let mut relaxed = md.permissions();
        // clippy::permissions_set_readonly_false objects that this leaves a
        // file world-writable, which is a statement about Unix modes, and
        // this arm is `cfg(not(unix))`. On Windows it clears the read-only
        // ATTRIBUTE - the entire point of the block - and the original
        // permissions go back on after the flush. std exposes no other
        // stable way to touch that attribute.
        #[allow(clippy::permissions_set_readonly_false)]
        relaxed.set_readonly(false);
        std::fs::set_permissions(path, relaxed)?;
        let flushed = std::fs::OpenOptions::new()
            .write(true)
            .open(path)
            .and_then(|f| f.sync_all());
        std::fs::set_permissions(path, md.permissions())?;
        flushed
    }
}

/// Is this path a symlink (rather than what it points at)?
fn is_symlink(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|m| m.file_type().is_symlink())
}

/// CLAIM the first free variant of `path`: itself, else "stem (2).ext",
/// "stem (3).ext", … The returned path exists as an empty file that this
/// call created and therefore owns.
///
/// Reserving matters because `exists()` is not an ownership primitive. The
/// old version only *looked* for a free name, so two movers racing the same
/// destination both saw "free" and both picked it: on unix the second
/// `rename` silently replaced the first's bytes, and both sources were then
/// deleted, so one payload was gone with both movers reporting success.
/// `create_new` is atomic, so exactly one caller can win each name.
fn reserve_free_name(path: &Path) -> std::io::Result<PathBuf> {
    use std::io::ErrorKind;
    let mut candidate = path.to_path_buf();
    let stem = path
        .file_stem()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    let ext = path
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy()))
        .unwrap_or_default();
    let parent = path.parent().unwrap_or(Path::new(""));
    for n in 2.. {
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(_) => return Ok(candidate),
            Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                candidate = parent.join(format!("{stem} ({n}){ext}"));
            }
            Err(e) => return Err(e),
        }
    }
    unreachable!()
}

/// File a completed TV job: move everything in `out_dir` into
/// `dest_parent/[Show]/Season NN/`, renaming video files to
/// "Show - S01E02[ suffix].ext" (each video's own name is parsed first, so
/// a season pack renames per episode; samples keep their names). `suffix`
/// is the auto-rename quality tag (" [1080p]"), or "" for none. Existing
/// targets are never overwritten. Returns the new directory, or None if
/// the stem didn't parse as TV (job left untouched).
///
/// `titles` decorates each episode with its own name when the cache knows
/// it ("Show - S01E02 - Children [1080p].mkv"); an empty one is the
/// ordinary case and leaves every name exactly as it was.
pub fn tv_organize(
    dest_parent: &Path,
    stem: &str,
    out_dir: &Path,
    suffix: &str,
    titles: &EpisodeTitles,
) -> Option<PathBuf> {
    let (subdir, job_base) = match tv_path(stem) {
        Some(t) => t,
        None => {
            info!(target: "smart", "{stem:?} didn't parse as TV - leaving it in place");
            return None;
        }
    };
    // A show already filed under the pre-sanitiser spelling of its name
    // ("Star Trek Discovery", before ": " became " - ") keeps that
    // folder: starting a second tree beside it splits the show in the
    // user's library. Judged on the SHOW folder, not the season one, so
    // a new season joins the show too - and only when today's spelling
    // has no folder yet and the old one does.
    let show_dir = |sub: &str| dest_parent.join(sub.split('/').next().unwrap_or(sub));
    let legacy = legacy_tv_path(stem)
        .filter(|(sub, _)| *sub != subdir && !show_dir(&subdir).is_dir() && show_dir(sub).is_dir());
    let filed_as_legacy = legacy.is_some();
    let (subdir, job_base) = legacy.unwrap_or((subdir, job_base));
    let dest = dest_parent.join(&subdir);
    if dest == out_dir {
        return None;
    }
    if let Err(e) = std::fs::create_dir_all(&dest) {
        warn!(target: "smart", "create {}: {e}", dest.display());
        return None;
    }
    let entries: Vec<PathBuf> = std::fs::read_dir(out_dir)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .collect();
    // Plan the whole filing before moving anything. A canonical target
    // that already exists belongs to somebody else (usually the user's
    // existing library), and the old fallback moved our file under its raw
    // release name while later cleanup deleted that pre-existing canonical
    // file. On any collision, keep this job in its private directory where
    // ownership is exact and delete-with-files remains safe.
    let mut planned = Vec::with_capacity(entries.len());
    let mut targets = std::collections::HashSet::new();
    for path in entries {
        let orig_name = match path.file_name() {
            Some(n) => n.to_string_lossy().into_owned(),
            None => continue,
        };
        let mut new_name = orig_name.clone();
        // True only when this entry became the canonical "Show - S01E02"
        // episode name; everything else keeps the name it arrived with.
        let mut is_canonical_video = false;
        if path.is_file() {
            let ext = path
                .extension()
                .map(|e| e.to_string_lossy().to_ascii_lowercase())
                .unwrap_or_default();
            let file_stem = path
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default();
            let is_sample = file_stem.to_ascii_lowercase().contains("sample");
            if VIDEO_EXTS.contains(&ext.as_str()) && !is_sample {
                // The file's own name wins (season packs), else the job's
                // - spelled the way the folder we are filing into is.
                let own = if filed_as_legacy {
                    legacy_tv_path(&file_stem)
                } else {
                    tv_path(&file_stem)
                };
                // Which stem the base came from decides which episode's
                // title belongs on it: a season pack's files each name
                // their own episode, and only when none of them does
                // (a single-episode job) does the job's stem answer.
                let (base, titled_by) = match own.and_then(|(_, b)| b) {
                    Some(b) => (Some(b), file_stem.as_str()),
                    None => (job_base.clone(), stem),
                };
                if let Some(b) = base {
                    let title = titles.segment(titled_by, &b, suffix);
                    new_name = format!("{b}{title}{suffix}.{ext}");
                    is_canonical_video = true;
                }
            }
        }
        let target = dest.join(&new_name);
        if target.exists() || !targets.insert(target.clone()) {
            // The canonical EPISODE name colliding means the season slot
            // belongs to somebody else - usually the user's existing
            // library. Filing beside it under a raw name is what let
            // cleanup delete their copy, so the whole job stays put.
            if is_canonical_video {
                info!(
                    target: "smart",
                    "{} already exists (or two job files map there) - \
                     leaving {:?} in its private folder",
                    target.display(),
                    stem
                );
                return None;
            }
            // Anything else - a shared Subs/ folder, a generic .nfo - is
            // not ours to own and is not what the delete bug was about.
            // Aborting the whole job for one of these silently stopped
            // every later episode of a season from filing at all: these
            // entries keep their original name, so the second episode
            // shipping Subs/ collided forever, with no UI signal.
            info!(
                target: "smart",
                "{} already exists - leaving it behind, still filing {:?}",
                target.display(),
                stem
            );
            continue;
        }
        planned.push((path, target));
    }
    // Returning Some() here is what makes the caller set `filed`, which
    // tells every later "delete this job's files" that this job OWNS the
    // canonical name in the shared season folder. A job that moved
    // nothing must never make that claim: cleanup matches by NAME, so it
    // would delete whichever episode really is there - the exact data
    // loss this planning step exists to prevent. Renames do fail in
    // ordinary life: a NAS blipping read-only, EXDEV on a category
    // folder symlinked to another volume, or a media server holding the
    // file open on Windows.
    let mut done: Vec<(PathBuf, PathBuf)> = Vec::with_capacity(planned.len());
    let mut failed = None;
    for (path, target) in planned {
        // The plan's exists() check happened above, and `rename` REPLACES
        // an existing destination file. Finalize tails run on independent
        // tasks and can overlap - the runner tail, the idle sidecar tail,
        // the set_password unlock tail - so two jobs filing the same
        // episode both saw the slot free, the second silently overwrote
        // the first's bytes, and the first's private folder had already
        // been drained and removed. One payload gone, both jobs claiming
        // filed. Claim the name atomically first, the way move_tree does,
        // then rename over the placeholder we own.
        //
        // Files only. Renaming a directory onto a non-empty one fails
        // rather than replacing it, so a directory entry has nothing to
        // lose, and a placeholder FILE would break the rename outright.
        let mut placeholder = false;
        if !path.is_dir() {
            match std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&target)
            {
                Ok(_) => placeholder = true,
                Err(e) => {
                    warn!(
                        target: "smart",
                        "{} was taken before {} could be filed: {e}",
                        target.display(),
                        path.display()
                    );
                    failed = Some(e);
                    break;
                }
            }
        }
        match std::fs::rename(&path, &target) {
            Ok(()) => done.push((path, target)),
            Err(e) => {
                warn!(
                    target: "smart",
                    "move {} → {}: {e}",
                    path.display(),
                    target.display()
                );
                // Our own placeholder would otherwise be left behind as a
                // zero-byte file wearing the episode's canonical name,
                // which later cleanup matches by name.
                if placeholder {
                    let _ = std::fs::remove_file(&target);
                }
                failed = Some(e);
                break;
            }
        }
    }
    if let Some(e) = failed {
        // Put back whatever did land, so the job is left exactly as it
        // was rather than split across two directories with an owner
        // nobody can determine. A rollback that itself fails is logged
        // and still refuses the claim - leaking a file is recoverable,
        // deleting the user's episode is not.
        for (path, target) in done.iter().rev() {
            if let Err(e2) = std::fs::rename(target, path) {
                warn!(
                    target: "smart",
                    "could not undo {} → {}: {e2} (file left in the season folder)",
                    path.display(),
                    target.display()
                );
            }
        }
        info!(
            target: "smart",
            "filing {stem:?} failed ({e}) - left in its private folder, \
             not claiming the season folder"
        );
        return None;
    }
    // Filing NOTHING is not filing. `planned` is empty whenever the job
    // has no entries left to place - most easily an all-junk repost
    // (NFOFIX/DIRFIX/PROOF: only .nfo/.sfv/.par2), because sweep_junk
    // runs first and empties out_dir. Falling through here returned the
    // shared season folder, which makes the caller set `filed`, and
    // delete_filed_episode then matches by canonical NAME and removes the
    // user's real copy of that episode for a job that moved zero bytes.
    //
    // This is the same ownership invariant as the rollback above - the
    // earlier fix enforced only its failed-rename half.
    if done.is_empty() {
        info!(
            target: "smart",
            "nothing to file for {stem:?} - leaving it in its private folder \
             rather than claiming {}",
            dest.display()
        );
        return None;
    }
    let moved = done.len();
    // Only vanishes if everything left it.
    let _ = std::fs::remove_dir(out_dir);
    info!(target: "smart", "filed {moved} item(s) → {}", dest.display());
    Some(dest)
}

/// Auto-rename for TV when the job ISN'T being Season-filed: rename video
/// files IN PLACE to "Show - S01E02[ title][ suffix].ext" (season packs
/// rename per episode; samples untouched). Never overwrites an existing
/// target. Returns how many files were renamed.
pub fn tv_rename(dir: &Path, stem: &str, suffix: &str, titles: &EpisodeTitles) -> usize {
    let job_base = tv_path(stem).and_then(|(_, b)| b);
    let Ok(rd) = std::fs::read_dir(dir) else {
        return 0;
    };
    let mut renamed = 0;
    for entry in rd.flatten() {
        let path = entry.path();
        if !path.is_file() || !VIDEO_EXTS.contains(&ext_of(&path).as_str()) || is_sample_clip(&path)
        {
            continue;
        }
        let file_stem = path
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        // As in `tv_organize`: the stem that named the episode is the
        // stem whose title belongs on it.
        let (base, titled_by) = match tv_path(&file_stem).and_then(|(_, b)| b) {
            Some(b) => (Some(b), file_stem.as_str()),
            None => (job_base.clone(), stem),
        };
        let Some(b) = base else { continue };
        let title = titles.segment(titled_by, &b, suffix);
        let ext = ext_of(&path);
        let target = dir.join(format!("{b}{title}{suffix}.{ext}"));
        if target == path || target.exists() {
            continue;
        }
        match std::fs::rename(&path, &target) {
            Ok(()) => renamed += 1,
            Err(e) => warn!(
                target: "smart",
                "rename {} → {}: {e}",
                path.display(),
                target.display()
            ),
        }
    }
    renamed
}

/// A file stem that carries no identity at all: the encoder's default
/// output name, or a bare index from a batch. Exact, case-insensitive,
/// closed list plus one- and two-digit stems - nothing fuzzier, because
/// every entry here is a licence to overwrite a name someone may have
/// chosen. "Movie 2024" and "video_final" are NOT generic; they say
/// something, so they stand.
fn is_generic_stem(stem: &str) -> bool {
    let s = stem.trim();
    if matches!(s.len(), 1 | 2) && s.bytes().all(|b| b.is_ascii_digit()) {
        return true;
    }
    matches!(
        s.to_ascii_lowercase().as_str(),
        "movie" | "video" | "film" | "output" | "encoded" | "media"
    )
}

/// The part of a sidecar's filename that follows the video's stem
/// (".en.srt"), or None when the sidecar is not this video's at all.
///
/// The boundary is the whole point: a bare `strip_prefix` was safe only
/// while the stem had to be a long obfuscated blob, and with generic
/// stems ([`is_generic_stem`]) in play the video "1.mkv" claimed
/// "10.srt" and "12.srt" and fused their leftover digit onto the new
/// name ("Example.Movie.2024…-GRP0.srt"). The remainder has to start at
/// an extension boundary for the sidecar to be ours.
fn sidecar_tail<'a>(fname: &'a str, stem: &str) -> Option<&'a str> {
    fname
        .strip_prefix(stem)
        .filter(|rest| rest.starts_with('.'))
}

/// Does this release name say enough to be worth stamping onto a
/// payload? A non-empty parsed title plus at least one hard provenance
/// fact - resolution, source or group. Port of Sonarr's scene-title
/// check, and like it we prefer false negatives: a name that fails here
/// costs the user an ugly filename, a name that wrongly passes costs
/// them a wrong one.
fn names_the_release(name: &str) -> bool {
    let p = crate::wall::parse_release(name);
    !p.title.trim().is_empty() && (p.res.is_some() || p.source.is_some() || p.group.is_some())
}

/// Last resort for a payload we could not name cleverly: if the main
/// video is still wearing an obfuscated stem, give it the release's own
/// name.
///
/// The smart renamers decline on purpose in several places - an event
/// post whose identity lives after the year ("Formula1.2026.Round11…"),
/// a release with no year and no quality facts, a category that declared
/// no base behaviour. Every one of those declines rests on the same
/// assumption: that leaving the file alone means leaving the POSTER'S
/// name on it, which is a name a human chose. When the post is
/// obfuscated that assumption is simply false, and declining hands the
/// user "1fRbH6e0eX8v5hv7fSyXgBb.mkv" while the folder beside it reads
/// perfectly. So: no clever name available AND nothing worth keeping ->
/// use the release name, which is informative and, unlike a reduced
/// "Title (Year)", still unique per round/episode/event.
///
/// The same argument covers the stem that is not obfuscated but says
/// nothing either: "movie.mkv", "video.mkv", "1.mkv". Those are the
/// encoder's default output name, not a name a human chose for THIS
/// post, so there is nothing to preserve. The list is exact and closed
/// (see [`is_generic_stem`]) - a stem we do not recognise keeps its name.
///
/// Widening what we fire on has to be paid for on the other side, so the
/// release name now has to earn the job: it must parse to a non-empty
/// title AND carry at least one hard provenance fact (resolution, source
/// or group). "Example Movie" with no facts is somebody's folder label,
/// and stamping it onto the payload is not an improvement worth the risk
/// of being wrong.
///
/// Returns true when it renamed something. Deliberately narrow: one
/// non-sample video, a stem worth replacing, and a target that does not
/// already exist.
pub fn rename_obfuscated_video(out_dir: &Path, base: &str) -> bool {
    if base.trim().is_empty() || nzbkit::release::looks_obfuscated(base) {
        return false; // nothing better to offer than what is already there
    }
    if !names_the_release(base) {
        return false; // too little in the release name to trust it
    }
    rename_nameless_video(out_dir, base)
}

/// The lone still-nameless feature video in `dir`, or `None`.
///
/// "Nameless" is the exact condition [`rename_obfuscated_video`] fires
/// on - one non-sample video whose stem is either obfuscated or one of
/// the encoder defaults that say nothing - factored out because
/// synthesised naming has to ask the same question BEFORE it spends any
/// network: there is no point identifying a film whose file already
/// carries a name a human chose.
pub fn nameless_video(dir: &Path) -> Option<PathBuf> {
    let videos: Vec<PathBuf> = std::fs::read_dir(dir)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_file() && VIDEO_EXTS.contains(&ext_of(p).as_str()) && !is_sample_clip(p))
        .collect();
    // More than one and we cannot tell which is the feature; renaming
    // either would be a guess, and CD1/CD2 sets collide.
    let [video] = videos.as_slice() else {
        return None;
    };
    let name = video.file_name()?.to_string_lossy().into_owned();
    let stem = name
        .strip_suffix(&format!(".{}", ext_of(video)))
        .unwrap_or(&name)
        .to_string();
    // The poster named it something: that name stands, whatever a
    // catalogue might have offered.
    (nzbkit::release::looks_obfuscated(&stem) || is_generic_stem(&stem)).then(|| video.clone())
}

/// Put `base` on the lone still-nameless video in `out_dir`, carrying
/// its subtitle sidecars.
///
/// Split from [`rename_obfuscated_video`] so that synthesised naming
/// reaches the same apply path. The two differ only in where the name
/// came from and therefore in what has to be proven about it first: a
/// release name has to earn the job by carrying provenance facts (see
/// [`names_the_release`]), while an identified film's name has already
/// been earned by the acceptance gate - which is a far higher bar, and
/// one a title like "Supergirl 2026" could never clear by grammar
/// alone.
pub fn rename_nameless_video(out_dir: &Path, base: &str) -> bool {
    let files: Vec<PathBuf> = match std::fs::read_dir(out_dir) {
        Ok(rd) => rd
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.is_file())
            .collect(),
        Err(_) => return false,
    };
    let Some(video) = nameless_video(out_dir) else {
        return false;
    };
    let video = &video;
    let ext = ext_of(video);
    let Some(old_name) = video.file_name().map(|n| n.to_string_lossy().into_owned()) else {
        return false;
    };
    let old_stem = old_name
        .strip_suffix(&format!(".{ext}"))
        .unwrap_or(&old_name)
        .to_string();
    let clean = nzbkit::release::sanitize_name(base);
    if clean.is_empty() {
        return false; // nothing nameable survived sanitisation
    }
    let target = out_dir.join(format!("{clean}.{ext}"));
    if target == *video || target.exists() {
        return false;
    }
    if let Err(e) = std::fs::rename(video, &target) {
        warn!(
            target: "smart",
            "rename {} -> {}: {e}",
            video.display(),
            target.display()
        );
        return false;
    }
    info!(target: "smart", "de-obfuscated {} -> {}", old_name, target.display());
    // Carry subtitle sidecars along, keeping their language tail.
    for f in &files {
        if !SUBTITLE_EXTS.contains(&ext_of(f).as_str()) {
            continue;
        }
        let Some(fname) = f.file_name().map(|n| n.to_string_lossy().into_owned()) else {
            continue;
        };
        if let Some(rest) = sidecar_tail(&fname, &old_stem) {
            let subtarget = out_dir.join(format!("{clean}{rest}"));
            if subtarget != *f && !subtarget.exists() {
                let _ = std::fs::rename(f, &subtarget);
            }
        }
    }
    true
}

/// Auto-rename a completed MOVIE / loose-file job to the friendly `base`
/// (already computed by `wall::movie_name`, path-safe, no extension):
/// 1. if the job has exactly ONE top-level feature video, rename it to
///    `base.ext` and re-stem its subtitle sidecars (`.en.srt` kept);
///    multiple videos (CD1/CD2 etc.) are left alone to avoid collisions;
/// 2. rename the job folder to `parent/base`, with `.2`/`.3` collision
///    suffixes - an existing folder is never overwritten.
/// Returns the new out_dir when the folder moved, else None (caller keeps
/// the current path).
pub fn rename_movie(parent: &Path, out_dir: &Path, base: &str) -> Option<PathBuf> {
    // `base` arrives path-safe from `movie_name`, but this is the last
    // point before it becomes a real file stem AND a real folder name, and
    // callers other than finalize_names reach it. Re-running the sanitiser
    // is idempotent, so the cost is one pass over a short string.
    let clean = nzbkit::release::sanitize_name(base);
    if clean.is_empty() {
        return None;
    }
    let base = clean.as_str();
    let files: Vec<PathBuf> = std::fs::read_dir(out_dir)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_file())
        .collect();
    let videos: Vec<&PathBuf> = files
        .iter()
        .filter(|p| VIDEO_EXTS.contains(&ext_of(p).as_str()) && !is_sample_clip(p))
        .collect();
    if videos.len() == 1 {
        let video = videos[0];
        let ext = ext_of(video);
        let old_name = video
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())?;
        // Strip the trailing ".ext" to get the stem prefix subtitles share.
        let old_stem = old_name
            .strip_suffix(&format!(".{ext}"))
            .unwrap_or(&old_name)
            .to_string();
        let target = out_dir.join(format!("{base}.{ext}"));
        if target != *video
            && !target.exists()
            && let Err(e) = std::fs::rename(video, &target)
        {
            warn!(
                target: "smart",
                "rename {} → {}: {e}",
                video.display(),
                target.display()
            );
        }
        // Subtitle sidecars whose name starts with the old video stem:
        // "Stem.en.srt" → "base.en.srt", preserving the language tail.
        for f in &files {
            if !SUBTITLE_EXTS.contains(&ext_of(f).as_str()) {
                continue;
            }
            let fname = match f.file_name() {
                Some(n) => n.to_string_lossy().into_owned(),
                None => continue,
            };
            if let Some(rest) = sidecar_tail(&fname, &old_stem) {
                let subtarget = out_dir.join(format!("{base}{rest}"));
                if subtarget != *f && !subtarget.exists() {
                    let _ = std::fs::rename(f, &subtarget);
                }
            }
        }
    }
    // Rename the folder itself.
    let want = parent.join(base);
    if want == out_dir {
        return None;
    }
    let mut target = want;
    let mut n = 2;
    while target.exists() {
        target = parent.join(format!("{base}.{n}"));
        n += 1;
    }
    match std::fs::rename(out_dir, &target) {
        Ok(()) => {
            info!(
                target: "smart",
                "renamed {} → {}",
                out_dir.display(),
                target.display()
            );
            Some(target)
        }
        // Windows refuses to rename a DIRECTORY while any file inside it is
        // open, and at this point the extractor still holds the payload: it
        // keeps its output writers for the streaming endpoint and stays alive
        // past completion. So this failed with "Access is denied." on every
        // Windows install, and because the payload FILE had already been
        // renamed above (Rust opens with FILE_SHARE_DELETE, which permits
        // renaming a file but not its parent), an obfuscated download was
        // left as `complete/movies/<hash>/Example Movie 2019 1080p.mkv` -
        // half-renamed, which is the worst of both.
        //
        // Moving the CONTENTS across works where moving the container does
        // not, for that same reason: each entry is renamed individually and an
        // open handle does not stop it - proven by the payload rename above
        // succeeding. Handles stay valid afterwards (they follow the file, not
        // the path), so streaming a job whose folder was just renamed keeps
        // working, which is why this is done here rather than by closing the
        // writers: closing them makes a /stream request that is waiting for
        // them hang instead (`stream_of_library_job_triggers_download`).
        //
        // Unix renames directories around open descriptors happily, so it
        // takes the branch above and never reaches this.
        Err(e) => match move_dir_contents(out_dir, &target) {
            Ok(()) => {
                info!(
                    target: "smart",
                    "renamed {} → {} (entry by entry: {e})",
                    out_dir.display(),
                    target.display()
                );
                Some(target)
            }
            Err(e2) => {
                warn!(
                    target: "smart",
                    "rename dir {} → {}: {e} (and entry by entry: {e2})",
                    out_dir.display(),
                    target.display()
                );
                None
            }
        },
    }
}

/// Move everything in `from` into a fresh `to`, then drop the empty `from`.
///
/// The fallback for a directory rename that the platform will not do as one
/// operation - see the call site. `to` must not already exist; the caller
/// picked a free name.
///
/// Every entry moves with a plain rename, so this stays same-filesystem and
/// never copies payload: `to` is a sibling of `from`. A partial failure
/// leaves entries in BOTH places and reports the error, which the caller
/// turns into "the folder was not renamed" - the files are all still present
/// under one name or the other, and nothing is deleted here except the
/// emptied directory itself.
fn move_dir_contents(from: &Path, to: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(to)?;
    for entry in std::fs::read_dir(from)? {
        let entry = entry?;
        std::fs::rename(entry.path(), to.join(entry.file_name()))?;
    }
    // Only removes it if it really is empty, so a missed entry surfaces as a
    // leftover directory rather than as a deletion.
    std::fs::remove_dir(from)
}

// ---------------------------------------------------------------------------
// M24 passworded archives (the survey's #2 Usenapp borrow)
// ---------------------------------------------------------------------------

/// Read a SAB/NZBGet-compatible passwords file: plain text, one
/// password per line, tried top to bottom. Surrounding whitespace is
/// stripped and blank lines are skipped - SABnzbd's exact reading
/// (`misc.get_all_passwords` strips `"\r\n "`), and a superset of
/// NZBGet's (UnpackController trims trailing CR/LF only), so one file
/// serves all three programs. No comment syntax on purpose: both
/// competitors treat every non-blank line as a password, and a `#`
/// convention here would make a shared file try that line there.
/// A missing or unreadable file is an empty list, never an error - the
/// file is optional and the operator may delete it.
pub fn read_password_file(path: &Path) -> Vec<String> {
    std::fs::read_to_string(path)
        .map(|text| {
            text.lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(String::from)
                .collect()
        })
        .unwrap_or_default()
}

/// First password-protected volume in a completed job's folder (top
/// level), or None. Merely-compressed leftovers don't count - those
/// failed for other reasons (e.g. no unrar) and a password won't help.
pub fn encrypted_rar(dir: &Path) -> Option<PathBuf> {
    let mut rars: Vec<PathBuf> = std::fs::read_dir(dir)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_file() && p.extension().is_some_and(|x| x.eq_ignore_ascii_case("rar")))
        .collect();
    rars.sort();
    rars.into_iter().find(|p| nzbkit::rar::needs_password(p))
}

/// Unlock a password-protected set: unrar with the password, and on
/// success delete the volume files (the unpacked content is the
/// deliverable, matching the engine's post-extraction behavior).
pub fn unlock(dir: &Path, password: &str) -> bool {
    // Native path first: encrypted STORE sets (the obfuscated-release
    // norm) re-extract and AES-decrypt without unrar, deleting their
    // volumes on success. Compressed or RAR4-encrypted sets fall through
    // to unrar inside reextract_dir; a wrong password fails both.
    // Volume deletion belongs to the extraction, not to this function.
    // `reextract_dir` removes exactly what it CONSUMED on every success path
    // (the streaming pass sweeps the set it fed, the native and unrar paths
    // sweep against a proof-of-output snapshot), so a RAR-named file still
    // present afterwards is one of three things, and deleting any of them is
    // wrong:
    //
    //   - a file the extraction just PUBLISHED - an encrypted outer set whose
    //     payload is the release's own inner RAR set unlocks to
    //     `inner.partNN.rar`, and sweeping them left a Completed job with no
    //     payload at all;
    //   - a volume the spent-proof deliberately refused to delete;
    //   - the volumes of ANOTHER top-level set in the same directory that
    //     this password did not unlock. `reextract_dir`'s directory-level
    //     answer is existential - one set unpacking makes it true - so with
    //     encrypted sets A and B and a password for A only, the sweep deleted
    //     B's only copy. That is the shape this whole path exists to protect.
    //
    // So: count what the extraction removed, delete nothing.
    let vol_snapshot = |dir: &Path| -> std::collections::HashSet<PathBuf> {
        std::fs::read_dir(dir)
            .map(|rd| {
                rd.flatten()
                    .map(|e| e.path())
                    .filter(|p| {
                        let name = p
                            .file_name()
                            .unwrap_or_default()
                            .to_string_lossy()
                            .to_lowercase();
                        // .rar plus split continuations (.r00, .r01, …).
                        name.ends_with(".rar")
                            || name.rfind('.').is_some_and(|i| {
                                let t = &name[i + 1..];
                                t.len() >= 3
                                    && t.starts_with('r')
                                    && t[1..].bytes().all(|c| c.is_ascii_digit())
                            })
                    })
                    .collect()
            })
            .unwrap_or_default()
    };
    let before = vol_snapshot(dir);
    if !crate::reextract_dir(dir, Some(password)).unwrap_or(false) {
        return false;
    }
    let removed = before.difference(&vol_snapshot(dir)).count();
    info!(
        target: "unlock",
        "{} unpacked - {removed} volume file(s) spent",
        dir.display()
    );
    true
}

#[cfg(test)]
mod tests {

    use super::*;

    /// The move-I/O demotion must RESTORE the thread's policy on drop:
    /// moves run on tokio's pooled blocking threads, so a policy left set
    /// would demote whatever unrelated work that thread picks up next.
    #[cfg(target_os = "macos")]
    #[test]
    fn background_io_restores_the_thread_policy() {
        // Own thread: the assertion is about THIS thread's policy, and the
        // test harness's threads are shared.
        std::thread::spawn(|| unsafe {
            let before = iopol::getiopolicy_np(iopol::IOPOL_TYPE_DISK, iopol::IOPOL_SCOPE_THREAD);
            let prev = before;
            let guard = BackgroundIo { prev };
            assert_eq!(
                iopol::setiopolicy_np(
                    iopol::IOPOL_TYPE_DISK,
                    iopol::IOPOL_SCOPE_THREAD,
                    iopol::IOPOL_THROTTLE
                ),
                0
            );
            assert_eq!(
                iopol::getiopolicy_np(iopol::IOPOL_TYPE_DISK, iopol::IOPOL_SCOPE_THREAD),
                iopol::IOPOL_THROTTLE
            );
            drop(guard);
            assert_eq!(
                iopol::getiopolicy_np(iopol::IOPOL_TYPE_DISK, iopol::IOPOL_SCOPE_THREAD),
                before
            );
        })
        .join()
        .unwrap();
    }

    /// A copy whose destination holds every byte passes; the verify is
    /// what runs between "copied" and "the source may now be deleted".
    #[test]
    fn copy_verified_accepts_a_whole_copy() {
        let dir = std::env::temp_dir().join(format!("copy-verified-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let from = dir.join("a.bin");
        let to = dir.join("b.bin");
        std::fs::write(&from, vec![7u8; 1 << 20]).unwrap();
        copy_verified(&from, &to).unwrap();
        assert_eq!(std::fs::metadata(&to).unwrap().len(), 1 << 20);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Poll until `f()` holds or ~10 s pass: the deferred-trash worker is
    /// asynchronous on purpose, so its outcomes need a bounded wait.
    fn eventually(f: impl Fn() -> bool) -> bool {
        for _ in 0..200 {
            if f() {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        f()
    }

    #[test]
    fn staged_delete_leaves_the_tree_synchronously() {
        let _steady = trash_globals_steady();
        // The §64 contract: by the time `stage` returns, the file is OUT
        // of the job tree - so finalize can move the directory the very
        // next instant without racing the delete - and the worker disposes
        // of the parked copy behind us. Under cfg(test) the trash global
        // defaults off, so the disposal is a direct delete rather than a
        // real Trash conversation.
        let parent = std::env::temp_dir().join(format!("defer-trash-{}", std::process::id()));
        let job = parent.join("job");
        std::fs::create_dir_all(&job).unwrap();
        let f = job.join("junk.par2");
        std::fs::write(&f, b"x").unwrap();
        let staging = trash_staging_dir(&job).unwrap();
        let r = deferred_trash::stage(&f, &staging);
        assert!(r.is_ok(), "stage: {r:?}");
        assert!(!f.exists(), "the rename must be synchronous");
        assert!(
            eventually(|| !staging.exists()),
            "the worker must dispose of the parked file and prune the empty staging dir"
        );
        let _ = std::fs::remove_dir_all(&parent);
    }

    #[test]
    fn first_stage_drains_a_predecessors_leftovers() {
        let _steady = trash_globals_steady();
        // A crash between park and disposal strands files in the staging
        // folder. The first stage into that folder after a restart queues
        // whatever it finds, so leftovers cannot accumulate forever.
        let parent = std::env::temp_dir().join(format!("defer-leftover-{}", std::process::id()));
        let job = parent.join("job");
        std::fs::create_dir_all(&job).unwrap();
        let staging = trash_staging_dir(&job).unwrap();
        std::fs::create_dir_all(&staging).unwrap();
        let leftover = staging.join("99999-0-stranded.nfo");
        std::fs::write(&leftover, b"x").unwrap();
        let f = job.join("junk.nfo");
        std::fs::write(&f, b"x").unwrap();
        deferred_trash::stage(&f, &staging).unwrap();
        assert!(
            eventually(|| !leftover.exists() && !staging.exists()),
            "the leftover must go with the freshly staged file"
        );
        let _ = std::fs::remove_dir_all(&parent);
    }

    #[test]
    fn latched_swept_delete_stays_inline() {
        // With the latch set there is no Trash to park FOR, so the sweep
        // must not create a staging folder: a hidden folder beside the
        // user's downloads that nobody will ever drain is exactly the
        // Unraid `.Trash-<uid>` complaint in our own handwriting.
        //
        // Serialized with the other latch-writing tests: this one leaves
        // TRASH_UNRESPONSIVE set for the length of a delete, and
        // `a_junk_delete_is_recoverable_and_the_opt_out_is_not` deletes
        // into the real Trash and fails if it reads the latch set.
        let _serial = one_trash_test_at_a_time();
        let parent = std::env::temp_dir().join(format!("defer-latched-{}", std::process::id()));
        let job = parent.join("job");
        std::fs::create_dir_all(&job).unwrap();
        let f = job.join("junk.sfv");
        std::fs::write(&f, b"x").unwrap();
        let staging = trash_staging_dir(&job).unwrap();
        TRASH_UNRESPONSIVE.store(true, std::sync::atomic::Ordering::Relaxed);
        let r = remove_swept_file(&f, true, Some(&staging));
        TRASH_UNRESPONSIVE.store(false, std::sync::atomic::Ordering::Relaxed);
        assert!(!staging.exists(), "no staging dir on the latched path");
        assert!(r.is_err(), "a refused sweep must report, not claim success");
        assert!(
            f.exists(),
            "and the file it could not bin must still be there"
        );
        let _ = std::fs::remove_dir_all(&parent);
    }

    /// The rule this whole path exists for: a delete the user asked to be
    /// RECOVERABLE never becomes a permanent one behind their back.
    ///
    /// It used to. Any Trash failure - a headless Finder timing out, or
    /// (live, 3 Aug 2026) a `-10010` from a directory on an external
    /// volume - fell through to `remove_file`/`remove_dir_all`, so the one
    /// setting that promised a wrong guess could be undone became the
    /// thing that made it permanent. Both shapes are covered: a swept junk
    /// file, and a whole finished download.
    #[test]
    fn a_refused_trash_leaves_the_files_alone() {
        let _serial = one_trash_test_at_a_time();
        let dir = std::env::temp_dir().join(format!("trash-refused-{}", std::process::id()));
        let job = dir.join("Some.Release.2026");
        std::fs::create_dir_all(&job).unwrap();
        let f = dir.join("junk.par2");
        std::fs::write(&f, b"x").unwrap();
        std::fs::write(job.join("feature.mkv"), b"payload").unwrap();

        TRASH_UNRESPONSIVE.store(true, std::sync::atomic::Ordering::Relaxed);
        let file = remove_user_file(&f, true);
        let whole_job = remove_user_dir(&job, true);
        TRASH_UNRESPONSIVE.store(false, std::sync::atomic::Ordering::Relaxed);

        assert!(file.is_err(), "a refused file delete must report it");
        assert!(f.exists(), "the file must survive a Trash that refused it");
        assert!(
            whole_job.is_err(),
            "a refused directory delete must report it"
        );
        assert!(
            job.join("feature.mkv").exists(),
            "a finished download must survive a Trash that refused it"
        );
        // It has to say what happened and what to do, not just that
        // something went wrong: this string is read by a person, in the
        // log and in the dashboard's kept-files notice. It no longer
        // repeats the outcome ("left where they are") - both surfaces put
        // this after a line that has already said the files are still
        // there, and it said the same thing three times over.
        let said = whole_job.unwrap_err().to_string();
        assert!(
            said.contains("the Trash would not take it")
                && said.contains("Deleted files go to the Trash"),
            "the error must name the cause and the setting: {said}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A path that is already gone is a no-op, not a Trash failure.
    ///
    /// macOS's Finder route reports an unresolvable path as `-10010`
    /// ("Handler can't handle objects of this class"), because the crate
    /// canonicalizes only the PARENT and a missing leaf reaches the
    /// AppleScript intact. That printed "could not move <a user's
    /// download> to the Trash - deleting it instead" for a directory that
    /// had already gone - the live line that started all this. With the
    /// refusal rule it would be worse than noise: a delete would come back
    /// as an error for work already done.
    #[test]
    fn a_path_that_is_already_gone_is_not_a_refusal() {
        let _serial = one_trash_test_at_a_time();
        let dir = std::env::temp_dir().join(format!("trash-ghost-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let ghost_file = dir.join("already-binned.nfo");
        let ghost_dir = dir.join("already-deleted-job");
        // Deliberately never created - and the latch is NOT set, so a
        // regression here reaches the real backend rather than short-
        // circuiting on it.
        assert!(
            remove_user_file(&ghost_file, true).is_ok(),
            "a file that is already gone is a success"
        );
        assert!(
            remove_user_dir(&ghost_dir, true).is_ok(),
            "a directory that is already gone is a success"
        );
        let _ = std::fs::remove_dir(&dir);
    }

    /// The give-up path, which is the entire point of the change and the
    /// one case a healthy developer machine cannot produce: a Trash call
    /// that never comes back must not hold the caller.
    #[test]
    fn a_hanging_trash_call_does_not_hold_the_caller() {
        let started = std::time::Instant::now();
        let out = run_bounded(std::time::Duration::from_millis(150), || {
            std::thread::sleep(std::time::Duration::from_secs(30));
            "finished"
        });
        assert!(
            out.is_none(),
            "a call past its deadline must report giving up"
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "the caller waited {:?} on a call it had given up on",
            started.elapsed()
        );
    }

    /// ...and a call that DOES answer in time is passed straight through,
    /// so bounding it costs a healthy Finder nothing.
    #[test]
    fn a_prompt_trash_call_is_returned_unchanged() {
        let out = run_bounded(std::time::Duration::from_secs(30), || 7);
        assert_eq!(out, Some(7), "a prompt call must return its own result");
    }

    /// After giving up, the direct delete races the abandoned Finder call.
    /// If Finder wins, the file is already gone and `remove_file` fails
    /// NotFound - the outcome we wanted, so it must not surface as an
    /// error. Without this the job would report a cleanup failure for a
    /// file that was successfully binned.
    #[test]
    fn losing_the_race_to_the_trash_is_not_a_failure() {
        let _serial = one_trash_test_at_a_time();
        let dir = std::env::temp_dir().join(format!("trash-race-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let gone = dir.join("already-binned.nfo");
        // Never created: stands in for the file the abandoned call binned
        // a moment before we got to it.
        TRASH_UNRESPONSIVE.store(true, std::sync::atomic::Ordering::Relaxed);
        let r = remove_user_file(&gone, true);
        TRASH_UNRESPONSIVE.store(false, std::sync::atomic::Ordering::Relaxed);
        assert!(
            r.is_ok(),
            "a file that is already gone is a success, not {r:?}"
        );
        let _ = std::fs::remove_dir(&dir);
    }

    /// The bug the gate exists for: callers that overlap each read the
    /// latch before any of them set it, so each started its own probe and
    /// each paid the full deadline. Observed on a headless bench box as
    /// the "not responding" line printed twice and ~60 s added to a 208 s
    /// queue. One probe for the process, however many callers overlap -
    /// the deferred worker, a library delete and the watch dir can all be
    /// in here at once.
    #[test]
    fn concurrent_callers_probe_a_dead_trash_only_once() {
        use std::sync::atomic::Ordering::Relaxed;
        let _serial = one_trash_test_at_a_time();
        TRASH_UNRESPONSIVE.store(false, Relaxed);
        TRASH_ANSWERED.store(false, Relaxed);

        const CALLERS: usize = 4;
        const PROBE: std::time::Duration = std::time::Duration::from_millis(300);
        let probes = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let start = std::sync::Arc::new(std::sync::Barrier::new(CALLERS));
        let began = std::time::Instant::now();
        let callers: Vec<_> = (0..CALLERS)
            .map(|_| {
                let probes = probes.clone();
                let start = start.clone();
                std::thread::spawn(move || {
                    // All four inside the check-then-call window together,
                    // which is what made the real callers each probe.
                    start.wait();
                    trash_delete_gated(|| {
                        probes.fetch_add(1, Relaxed);
                        // Stands in for a Finder that never answers: the
                        // real one is bounded at TRASH_DEADLINE and comes
                        // back exactly like this.
                        std::thread::sleep(PROBE);
                        Err("timed out".to_string())
                    })
                })
            })
            .collect();
        let verdicts: Vec<_> = callers.into_iter().map(|c| c.join().unwrap()).collect();
        let elapsed = began.elapsed();
        TRASH_UNRESPONSIVE.store(false, Relaxed);
        TRASH_ANSWERED.store(false, Relaxed);

        assert_eq!(
            probes.load(Relaxed),
            1,
            "{CALLERS} concurrent callers must cost one probe, not one each"
        );
        assert_eq!(
            verdicts.iter().filter(|v| matches!(v, Err(None))).count(),
            CALLERS - 1,
            "every caller but the prober must be told to delete directly: {verdicts:?}"
        );
        assert!(
            elapsed < PROBE * 2,
            "the callers took {elapsed:?} - a single {PROBE:?} probe should cover all {CALLERS}"
        );
    }

    fn rule(pattern: &str) -> Rule {
        Rule {
            name: String::new(),
            pattern: pattern.into(),
            not_match: String::new(),
            min_size: 0,
            max_size: 0,
            category: String::new(),
            tv_sort: false,
        }
    }

    #[test]
    fn keyword_and_regex_matching() {
        // Keyword (valid trivial regex) - case-insensitive substring.
        assert!(rule("matrix").matches("The.Matrix.1999.1080p.BluRay-GRP", 0));
        assert!(!rule("matrix").matches("Inception.2010.1080p", 0));
        // Real regex.
        assert!(rule(r"^The\.Bear\.S\d+E\d+").matches("The.Bear.S03E05.1080p.WEB-X", 0));
        assert!(!rule(r"^The\.Bear\.S\d+E\d+").matches("Not.The.Bear.S03E05", 0));
        // Alternation.
        assert!(rule("2160p|1080p").matches("Show.S01E01.2160p.WEB", 0));
        // Invalid regex falls back to keyword substring.
        assert!(rule("kill bill (").matches("My.Kill Bill (.Collection", 0));
        assert!(!rule("kill bill (").matches("Kill.Bill.2003", 0));
        // Empty pattern matches everything (size-only rules).
        assert!(rule("").matches("anything", 123));
    }

    #[test]
    fn not_match_and_sizes() {
        let mut r = rule("1080p");
        r.not_match = "x265".into();
        assert!(r.matches("Show.S01E01.1080p.x264-GRP", 0));
        assert!(!r.matches("Show.S01E01.1080p.x265-GRP", 0));
        let mut r = rule("");
        r.min_size = 200_000_000;
        r.max_size = 4_000_000_000;
        assert!(!r.matches("small", 100_000_000));
        assert!(r.matches("mid", 1_000_000_000));
        assert!(!r.matches("big", 5_000_000_000));
    }

    #[test]
    fn first_match_wins() {
        let mut a = rule("1080p");
        a.category = "tv-hd".into();
        let mut b = rule("1080p");
        b.category = "tv".into();
        let rules = [a, b];
        assert_eq!(
            first_match(&rules, "Show.S01E01.1080p", 0)
                .unwrap()
                .category,
            "tv-hd"
        );
        assert!(first_match(&rules, "Show.S01E01.720p", 0).is_none());
    }

    #[test]
    fn size_strings_deserialize() {
        let r: Rule = serde_json::from_str(
            r#"{"name":"x","match":"a","min_size":"200M","max_size":4000000000,"category":"tv"}"#,
        )
        .unwrap();
        assert_eq!(r.min_size, 200_000_000);
        assert_eq!(r.max_size, 4_000_000_000);
        let r: Rule = serde_json::from_str(r#"{"match":"a","min_size":""}"#).unwrap();
        assert_eq!(r.min_size, 0);
    }

    #[test]
    fn tv_rename_mapping() {
        assert_eq!(
            tv_path("The.Bear.S03E05.1080p.WEB.h264-GRP"),
            Some((
                "The Bear/Season 03".into(),
                Some("The Bear - S03E05".into())
            ))
        );
        // Multi-episode posts keep the full range in the filed name
        // (§7b: the second episode used to vanish from the library).
        assert_eq!(
            tv_path("The.Bear.S03E05E06.1080p.WEB.h264-GRP"),
            Some((
                "The Bear/Season 03".into(),
                Some("The Bear - S03E05-E06".into())
            ))
        );
        assert_eq!(
            tv_path("The.Bear.S03E05-E06.1080p.WEB.h264-GRP"),
            Some((
                "The Bear/Season 03".into(),
                Some("The Bear - S03E05-E06".into())
            ))
        );
        // Season pack: directory but no rename base.
        assert_eq!(
            tv_path("Severance.S02.2160p.WEB-DL.COMPLETE-X"),
            Some(("Severance/Season 02".into(), None))
        );
        // 3x07 form.
        assert_eq!(
            tv_path("the-flash-3x07-720p-hdtv-x264"),
            Some((
                "The Flash/Season 03".into(),
                Some("The Flash - S03E07".into())
            ))
        );
        // Movies and obfuscated names refuse.
        assert_eq!(tv_path("Inception.2010.1080p.BluRay.x264-GRP"), None);
        assert_eq!(tv_path("2137d880a074ab31de52"), None);
    }

    /// A daily show has no season or episode number, only an air date -
    /// so requiring a season left every one of them where it landed,
    /// under its raw release name.
    #[test]
    fn dated_shows_file_by_air_date() {
        // Dotted date.
        assert_eq!(
            tv_path("The.Daily.Show.2026.07.21.1080p.WEB.x264-GRP"),
            Some((
                "The Daily Show/Season 2026".into(),
                Some("The Daily Show - 2026.07.21".into())
            ))
        );
        // Compact YYMMDD datecode - the other convention the parser
        // knows, normalized to the same name.
        assert_eq!(
            tv_path("At.Midnight.150615.720p.HDTV.x264-GRP"),
            Some((
                "At Midnight/Season 2015".into(),
                Some("At Midnight - 2015.06.15".into())
            ))
        );
        // Full YYYYMMDD datecode.
        assert_eq!(
            tv_path("At.Midnight.20150615.720p.HDTV.x264-GRP"),
            Some((
                "At Midnight/Season 2015".into(),
                Some("At Midnight - 2015.06.15".into())
            ))
        );
        // A compact YYMMDD the parser had to fix up on its own (no
        // four-digit year to lean on) files exactly like the dotted form.
        assert_eq!(
            tv_path("At.Midnight.260721.1080p.WEB.x264-GRP"),
            Some((
                "At Midnight/Season 2026".into(),
                Some("At Midnight - 2026.07.21".into())
            ))
        );
        // A numbered season still wins: a show that carries both is not
        // filed by date.
        assert_eq!(
            tv_path("Show.S03E05.2026.07.21.1080p.WEB-GRP"),
            Some(("Show/Season 03".into(), Some("Show - S03E05".into())))
        );
        assert_eq!(
            tv_path("Show.S03E05.260721.1080p.WEB-GRP"),
            Some(("Show/Season 03".into(), Some("Show - S03E05".into())))
        );
        // A one-word show is a real title, not a blob - the hash guard
        // must not swallow it.
        assert_eq!(
            tv_path("Newsnight.2026.07.21.1080p.WEB-GRP"),
            Some((
                "Newsnight/Season 2026".into(),
                Some("Newsnight - 2026.07.21".into())
            ))
        );
        // The show title gets the same portability treatment as every
        // other emitted component.
        let (dir, base) = tv_path("Alien: Romulus 2026.07.21 1080p WEB-GRP").unwrap();
        assert_eq!(dir, "Alien - Romulus/Season 2026");
        assert_eq!(base.as_deref(), Some("Alien - Romulus - 2026.07.21"));
        for part in dir.split('/') {
            assert_portable(part);
        }
        assert_portable(&base.unwrap());
    }

    /// The declines. The `daily` flag fires on ANY 8-digit run because
    /// all it has to decide is "not a movie"; a name written to disk
    /// needs more than that, so anything short of a real date and a
    /// presentable title stays where it landed. A six-digit run that is
    /// not a date never even reaches here - the parser leaves it in the
    /// title and the release stays a Movie.
    #[test]
    fn a_shaky_date_never_files() {
        // Digit runs that are not calendar dates.
        for stem in [
            "Blob.999999.1080p.WEB-GRP",   // month 99
            "Blob.20261332.1080p.WEB-GRP", // month 13, day 32
            "Blob.150600.1080p.WEB-GRP",   // day 00
            "Blob.150015.1080p.WEB-GRP",   // month 00
            "Blob.123456.1080p.WEB-GRP",   // an id, not a date
        ] {
            assert_eq!(tv_path(stem), None, "{stem}");
        }
        // A real date under a title that is a hash: nothing to present,
        // so the poster's own name stands.
        assert_eq!(
            tv_path("1fRbH6e0eX8v5hv7fSyXgBb.2026.07.21.1080p.WEB-GRP"),
            None
        );
        assert_eq!(tv_path("nzqymzflnjiyztgyntcynzzytq.150615.720p-GRP"), None);
        // A film with a release year is not a dated episode.
        assert_eq!(tv_path("Inception.2010.1080p.BluRay.x264-GRP"), None);
        assert_eq!(tv_path("Blade.Runner.2049.2017.2160p.WEB-DL-GRP"), None);
        // Sports and event posts keep whatever kind they parse as; the
        // ones that read as Movie are the movie path's business and must
        // not be dragged into TV filing by this.
        for stem in [
            "Formula1.2026.Round11.Hungary.Race.F1TV.WEB-DL.2160p.H265-MWR",
            "NFL.2025.Week.03.Chiefs.vs.Bills.1080p.WEB.h264-SPORTSNET",
        ] {
            assert_eq!(tv_path(stem), None, "{stem}");
        }
    }

    /// Filing a dated episode must not teach the delete/play matcher to
    /// read a date as an episode number - a neighbouring air date in the
    /// same year folder is a different episode, and the only copy of it.
    #[test]
    fn date_shapes_are_not_episode_numbers() {
        let _steady = trash_globals_steady();
        // Unchanged verdicts: a bare digit run is an episode number
        // whatever its width, and a dotted date is not a single token.
        assert!(reads_as_episode_number("2026"));
        assert!(reads_as_episode_number("07"));
        assert!(!reads_as_episode_number("2026.07.21"));
        assert!(!reads_as_episode_number("07.21"));
        // Our own tail after a dated base is still just the extension.
        assert!(is_rename_tail(".mkv"));
        assert!(is_rename_tail(" [1080p].mkv"));
        // What follows a dated base in someone else's library is not.
        assert!(!is_rename_tail(" - Guest Name.mkv"));
        assert!(!is_rename_tail(".2026.07.22.mkv"));
        assert!(!is_rename_tail("-2026.07.22.mkv"));

        // And end to end: a job filed for the 21st never touches the
        // 22nd, or the user's own copy of the 21st.
        let root = scratch("dailydel");
        for f in [
            "The Daily Show - 2026.07.21 [1080p].mkv",
            "The Daily Show - 2026.07.22 [1080p].mkv",
            "The Daily Show - 2026.07.21 - Guest Name.mkv",
        ] {
            std::fs::write(root.join(f), b"v").unwrap();
        }
        let stem = "The.Daily.Show.2026.07.21.1080p.WEB.x264-GRP";
        assert_eq!(
            delete_filed_episode(&root, stem, &FiledTail::suffix(" [1080p]")).removed,
            1
        );
        assert!(
            !root
                .join("The Daily Show - 2026.07.21 [1080p].mkv")
                .exists()
        );
        assert!(
            root.join("The Daily Show - 2026.07.22 [1080p].mkv")
                .exists()
        );
        assert!(
            root.join("The Daily Show - 2026.07.21 - Guest Name.mkv")
                .exists()
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Stage 4's shape for a daily: Season-filed under the air year when
    /// tv_sort is on, renamed in place when it is off.
    #[test]
    fn a_dated_episode_files_and_renames() {
        let stem = "The.Daily.Show.2026.07.21.1080p.WEB.x264-GRP";

        let root = scratch("dailyfile");
        let out = root.join("job");
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(out.join("1fRbH6e0eX8v5hv7fSyXgBb.mkv"), b"v").unwrap();
        let dest = tv_organize(
            &root.join("tv"),
            stem,
            &out,
            " [1080p]",
            &EpisodeTitles::default(),
        )
        .unwrap();
        assert_eq!(
            dest,
            root.join("tv").join("The Daily Show").join("Season 2026")
        );
        assert!(
            dest.join("The Daily Show - 2026.07.21 [1080p].mkv")
                .exists()
        );
        let _ = std::fs::remove_dir_all(&root);

        // tv_sort off: same name, in place.
        let dir = scratch("dailyren");
        std::fs::write(dir.join("1fRbH6e0eX8v5hv7fSyXgBb.mkv"), b"v").unwrap();
        std::fs::write(dir.join("sample.mkv"), b"s").unwrap();
        assert_eq!(
            tv_rename(&dir, stem, " [1080p]", &EpisodeTitles::default()),
            1
        );
        assert!(dir.join("The Daily Show - 2026.07.21 [1080p].mkv").exists());
        assert!(dir.join("sample.mkv").exists(), "samples keep their names");

        // Running it again is a no-op - the target is already there.
        assert_eq!(
            tv_rename(&dir, stem, " [1080p]", &EpisodeTitles::default()),
            0
        );
        let _ = std::fs::remove_dir_all(&dir);

        // Per-file stem beats the job stem, exactly as for numbered
        // seasons: a batch of dailies renames each to its own air date.
        let dir = scratch("dailybatch");
        std::fs::write(
            dir.join("The.Daily.Show.2026.07.22.1080p.WEB.x264-GRP.mkv"),
            b"v",
        )
        .unwrap();
        assert_eq!(
            tv_rename(&dir, stem, " [1080p]", &EpisodeTitles::default()),
            1
        );
        assert!(dir.join("The Daily Show - 2026.07.22 [1080p].mkv").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn delete_filed_episode_spares_siblings() {
        let _steady = trash_globals_steady();
        let dir = std::env::temp_dir().join(format!("nzbfast-filed-del-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // A shared season folder holding several episodes + a sidecar.
        for f in [
            "The Bear - S03E04.mkv",
            "The Bear - S03E05.mkv",
            "The Bear - S03E05.en.srt",
            "The Bear - S03E06.mkv",
        ] {
            std::fs::write(dir.join(f), b"x").unwrap();
        }
        // Delete only the E05 the old release filed to. Empty suffix =
        // auto-rename off, so the episode base is all filing had to go on.
        let n = delete_filed_episode(&dir, "The.Bear.S03E05.720p.HDTV-A", &FiledTail::suffix(""))
            .removed;
        assert_eq!(n, 2, "should remove the E05 video and its .srt sidecar");
        assert!(!dir.join("The Bear - S03E05.mkv").exists());
        assert!(!dir.join("The Bear - S03E05.en.srt").exists());
        // Siblings survive - this is the data-loss bug the fix prevents.
        assert!(dir.join("The Bear - S03E04.mkv").exists());
        assert!(dir.join("The Bear - S03E06.mkv").exists());
        // A release that doesn't parse to a specific episode is a no-op,
        // never a broad delete.
        assert_eq!(
            delete_filed_episode(&dir, "2137d880a074ab31de52", &FiledTail::suffix("")).removed,
            0
        );
        assert!(dir.join("The Bear - S03E04.mkv").exists());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Regression: pressing Play on a completed filed TV row served
    /// "the biggest media file in out_dir", and out_dir is the whole
    /// SHARED season folder - so E01's history row played E02 whenever the
    /// sibling was the larger file. Ownership is decided exactly as the
    /// delete decides it.
    #[test]
    fn find_filed_episode_media_serves_this_episode_not_a_bigger_sibling() {
        let dir = std::env::temp_dir().join(format!("nzbfast-filed-play-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // E06 is deliberately the biggest file in the folder.
        std::fs::write(dir.join("The Bear - S03E04.mkv"), vec![0u8; 2048]).unwrap();
        std::fs::write(dir.join("The Bear - S03E05.mkv"), vec![0u8; 1024]).unwrap();
        std::fs::write(dir.join("The Bear - S03E06.mkv"), vec![0u8; 8192]).unwrap();
        std::fs::write(dir.join("The Bear - S03E05.en.srt"), b"subs").unwrap();
        let got =
            find_filed_episode_media(&dir, "The.Bear.S03E05.720p.HDTV-A", &FiledTail::suffix(""));
        assert_eq!(
            got.as_deref(),
            Some(dir.join("The Bear - S03E05.mkv").as_path())
        );
        // A stem that doesn't parse as a specific episode owns nothing
        // here, so there is nothing safe to play: no fallback guess.
        assert_eq!(
            find_filed_episode_media(&dir, "2137d880a074ab31de52", &FiledTail::suffix("")),
            None
        );
        // Neither does an episode that was never filed into this folder.
        assert_eq!(
            find_filed_episode_media(&dir, "The.Bear.S03E09.720p.HDTV-A", &FiledTail::suffix("")),
            None
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The quality suffix is what makes the match release-specific: two
    /// copies of the same episode live in one season folder while an
    /// upgrade lands, and the row that asked must not play the other one.
    #[test]
    fn find_filed_episode_media_matches_this_releases_suffix() {
        let dir = std::env::temp_dir().join(format!("nzbfast-filed-sfx-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("The Bear - S03E05 [720p].mkv"), vec![0u8; 1024]).unwrap();
        std::fs::write(
            dir.join("The Bear - S03E05 [1080p]-GRP.mkv"),
            vec![0u8; 4096],
        )
        .unwrap();
        let stem = "The.Bear.S03E05.720p.HDTV-A";
        assert_eq!(
            find_filed_episode_media(&dir, stem, &FiledTail::suffix(" [720p]")).as_deref(),
            Some(dir.join("The Bear - S03E05 [720p].mkv").as_path()),
            "the smaller file is the one this row downloaded"
        );
        assert_eq!(
            find_filed_episode_media(&dir, stem, &FiledTail::suffix(" [1080p]-GRP")).as_deref(),
            Some(dir.join("The Bear - S03E05 [1080p]-GRP.mkv").as_path())
        );
        // A suffix that matches nothing on disk (the naming settings
        // changed since filing) reports nothing rather than guessing.
        assert_eq!(
            find_filed_episode_media(&dir, stem, &FiledTail::suffix(" [2160p]")),
            None
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Only a video is playable, and only the season folder itself is
    /// ours: a subdirectory that moved in with the job keeps its own name
    /// and may hold anybody's episode.
    #[test]
    fn find_filed_episode_media_ignores_sidecars_and_subdirs() {
        let dir = std::env::temp_dir().join(format!("nzbfast-filed-side-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("Subs")).unwrap();
        std::fs::write(dir.join("The Bear - S03E05.en.srt"), b"subs").unwrap();
        std::fs::write(dir.join("The Bear - S03E05.nfo"), b"info").unwrap();
        std::fs::write(dir.join("Subs/The Bear - S03E05.mkv"), vec![0u8; 4096]).unwrap();
        assert_eq!(
            find_filed_episode_media(&dir, "The.Bear.S03E05.720p.HDTV-A", &FiledTail::suffix("")),
            None
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Regression: the delete matched the episode base followed by ANY
    /// space, which is the DEFAULT Sonarr/Plex layout ("The Bear - S03E05 -
    /// Children.mkv"). With M33 filing a job into the user's real library
    /// season folder, an upgrade or a history "delete files" therefore
    /// deleted the user's own copy of the episode - a file we never
    /// downloaded and cannot fetch again.
    #[test]
    fn delete_filed_episode_spares_the_users_own_library_file() {
        let _steady = trash_globals_steady();
        let dir = std::env::temp_dir().join(format!("nzbfast-filed-lib-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ours = [
            "The Bear - S03E05 [1080p].mkv",
            "The Bear - S03E05 [1080p WEB h264].mkv",
            "The Bear - S03E05-GRP.mkv",
            // Real groups that merely START with a digit are still ours -
            // refusing these would leave our own files behind forever.
            "The Bear - S03E05-3LT0N.mkv",
            "The Bear - S03E05-2HD.mkv",
            "The Bear - S03E05.en.srt",
            "The Bear - S03E05.nfo",
        ];
        let theirs = [
            // Sonarr / Plex default naming, pre-existing in the library.
            "The Bear - S03E05 - Children.mkv",
            "The Bear - S03E05 - Children [Bluray-1080p].mkv",
            "The Bear - S03E05 - Children.en.srt",
            // Our own multi-episode name carries E06's only copy too.
            "The Bear - S03E05-E06.mkv",
            // …and so does the bare-number multi-episode convention, which
            // reads as a release group unless all-digit groups are refused.
            "The Bear - S03E05-06.mkv",
            // Every other separator the same convention is written with.
            // The dot spellings reach the extension arm rather than the
            // group arm, so they were accepted as ours and deleted.
            "The Bear - S03E05.06.mkv",
            "The Bear - S03E05.E06.mkv",
            "The Bear - S03E05.S03E06.mkv",
            "The Bear - S03E05 [1080p].06.mkv",
            "The Bear - S03E05-S03E06.mkv",
            "The Bear - S03E05x06.mkv",
            "The Bear - S03E05_06.mkv",
            // Siblings.
            "The Bear - S03E06.mkv",
        ];
        for f in ours.iter().chain(theirs.iter()) {
            std::fs::write(dir.join(f), b"x").unwrap();
        }
        let n = delete_filed_episode(
            &dir,
            "The.Bear.S03E05.1080p.WEB.h264-GRP",
            &FiledTail::suffix(""),
        )
        .removed;
        assert_eq!(n, ours.len(), "every file this job filed, and only those");
        for f in ours {
            assert!(!dir.join(f).exists(), "{f} is ours and should have gone");
        }
        for f in theirs {
            assert!(dir.join(f).exists(), "{f} is not ours to delete");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// BUG (HIGH, data loss): a watchlist upgrade deletes the replacement
    /// it just downloaded.
    ///
    /// The upgrade files the BETTER copy into the same `Show/Season NN`
    /// folder under the same episode base - `Show - S03E05` - differing
    /// only in the quality suffix. Matching the base plus ANY rename tail
    /// is therefore quality-blind, so the delete of the superseded copy
    /// swept up the freshly-downloaded one beside it and the user was left
    /// with neither.
    ///
    /// Both names are built from the REAL `quality_suffix` for each
    /// release, so the test breaks if the naming and the matching ever
    /// drift apart.
    #[test]
    fn delete_filed_episode_spares_the_upgrade_that_replaced_it() {
        let _steady = trash_globals_steady();
        let dir = std::env::temp_dir().join(format!("nzbfast-filed-up-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let style = crate::wall::NameStyle {
            resolution: true,
            video_codec: true,
            audio_codec: false,
            source: true,
            group: true,
            // This test is about the suffix DIFFERING between qualities,
            // not about its punctuation, so exercise the bracketed shape:
            // it is the one with delimiters that a tail match could trip on.
            year_parens: true,
            quality_brackets: true,
            extra_words: true,
        };
        let old_stem = "The.Bear.S03E05.720p.HDTV-A";
        let new_stem = "The.Bear.S03E05.1080p.WEB.h264-GRP";
        let suffix =
            |stem: &str| crate::wall::quality_suffix(&crate::wall::parse_release(stem), &style);
        let (old_sfx, new_sfx) = (suffix(old_stem), suffix(new_stem));
        assert!(
            !old_sfx.is_empty(),
            "auto-rename is on, so filing appended a suffix"
        );
        assert_ne!(old_sfx, new_sfx, "the upgrade is a different quality");

        let old_file = format!("The Bear - S03E05{old_sfx}.mkv");
        let new_file = format!("The Bear - S03E05{new_sfx}.mkv");
        let sibling = "The Bear - S03E06 [1080p WEB h264]-GRP.mkv";
        for f in [old_file.as_str(), new_file.as_str(), sibling] {
            std::fs::write(dir.join(f), b"x").unwrap();
        }

        // The upgrade landed; drop the copy it supersedes.
        let n = delete_filed_episode(&dir, old_stem, &FiledTail::suffix(&old_sfx)).removed;
        assert_eq!(n, 1, "exactly the superseded release, and nothing else");
        assert!(!dir.join(&old_file).exists(), "the superseded copy is gone");
        assert!(
            dir.join(&new_file).exists(),
            "the replacement we just downloaded must survive its own upgrade"
        );
        assert!(
            dir.join(sibling).exists(),
            "a sibling episode is never touched"
        );

        // And the other direction: deleting the NEW record later must not
        // reach back to a copy that carries a different suffix.
        std::fs::write(dir.join(&old_file), b"x").unwrap();
        assert_eq!(
            delete_filed_episode(&dir, new_stem, &FiledTail::suffix(&new_sfx)).removed,
            1
        );
        assert!(
            dir.join(&old_file).exists(),
            "the other quality is not this record's"
        );

        // A suffix that no longer matches what is on disk (the user changed
        // the naming settings after filing) is a no-op, never a guess: a
        // leftover beats a destroyed episode.
        assert_eq!(
            delete_filed_episode(&dir, old_stem, &FiledTail::suffix(" [2160p REMUX]-ZZZ")).removed,
            0
        );
        assert!(dir.join(&old_file).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The `-Group` arm of the rename tail, at the granularity the file-level
    /// test can't reach. `delete_filed_episode` lowercases the whole file name
    /// before calling this, so every case here is lowercase.
    #[test]
    fn rename_tail_group_arm() {
        // Ours: a group is one word, and may begin with a digit.
        assert!(is_rename_tail("-grp.mkv"));
        assert!(is_rename_tail("-3lt0n.mkv"));
        assert!(is_rename_tail("-2hd.mkv"));
        assert!(is_rename_tail(" [1080p web h264]-3lt0n.mkv"));
        // Ours: no group at all, and a sidecar on the renamed stem.
        assert!(is_rename_tail(".mkv"));
        assert!(is_rename_tail(" [1080p].mkv"));
        assert!(is_rename_tail(".en.srt"));
        // Not ours: an all-digit "group" is the second episode of a range
        // ("Show - S03E05-06.mkv"), whose only copy of E06 this would delete.
        assert!(!is_rename_tail("-06.mkv"));
        assert!(!is_rename_tail("-6.mkv"));
        assert!(!is_rename_tail(" [1080p]-06.mkv"));
        // Not ours: the E-prefixed spelling of the same range.
        assert!(!is_rename_tail("-e06.mkv"));
        // Not ours: the user's own Sonarr/Plex episode title.
        assert!(!is_rename_tail(" - children.mkv"));
        assert!(!is_rename_tail(" - children [bluray-1080p].mkv"));
        // Not ours: a longer episode number, or no extension at all.
        assert!(!is_rename_tail("0.mkv"));
        assert!(!is_rename_tail("-grp"));
    }

    /// Every spelling of a multi-episode range, at tail granularity.
    ///
    /// The `-` arm was hardened first (`-E06`, then bare `-06`), but the
    /// SAME convention is written with other separators, and the ones that
    /// put a dot there ("The Bear - S03E05.06.mkv") landed in the extension
    /// arm instead, which accepted any non-empty tail. Such a file is the
    /// only copy of E06 as well, and we never downloaded E06.
    #[test]
    fn rename_tail_refuses_every_range_spelling() {
        // Dot-separated range: reached the extension arm, not the `-` arm.
        assert!(!is_rename_tail(".06.mkv"));
        assert!(!is_rename_tail(".6.mkv"));
        assert!(!is_rename_tail(".e06.mkv"));
        assert!(!is_rename_tail(".s03e06.mkv"));
        // …with our quality suffix in front, or the user's behind.
        assert!(!is_rename_tail(" [1080p].06.mkv"));
        assert!(!is_rename_tail(" [1080p].e06.mkv"));
        assert!(!is_rename_tail(".06 [1080p].mkv"));
        // …on a sidecar sharing the stem, and with no extension at all.
        assert!(!is_rename_tail(".06.en.srt"));
        assert!(!is_rename_tail(".06"));
        // A three-episode range: only the FIRST segment can be episode two.
        assert!(!is_rename_tail(".06.07.mkv"));
        // The `-` arm, including the full-code spelling it used to accept.
        assert!(!is_rename_tail("-06.mkv"));
        assert!(!is_rename_tail("-6.mkv"));
        assert!(!is_rename_tail("-e06.mkv"));
        assert!(!is_rename_tail("-s03e06.mkv"));
        assert!(!is_rename_tail(" [1080p]-06.mkv"));
        assert!(!is_rename_tail("-06 [1080p].mkv"));
        // Separators that never reach either arm - refused already, pinned
        // here so a future "simplification" can't quietly re-admit them.
        assert!(!is_rename_tail("x06.mkv"));
        assert!(!is_rename_tail("_06.mkv"));
        assert!(!is_rename_tail("e06.mkv"));
        assert!(!is_rename_tail(" - e06.mkv"));
        assert!(!is_rename_tail(" 06.mkv"));
        assert!(!is_rename_tail("+06.mkv"));
        assert!(!is_rename_tail("&06.mkv"));
        assert!(!is_rename_tail(",06.mkv"));
    }

    /// The other half of the same bug: narrowing the tail must not strand
    /// our OWN files, or every filed episode leaves orphans behind.
    #[test]
    fn rename_tail_still_accepts_our_own_output() {
        assert!(is_rename_tail(".mkv"));
        assert!(is_rename_tail(" [1080p].mkv"));
        assert!(is_rename_tail(" [1080p web h264]-3lt0n.mkv"));
        assert!(is_rename_tail("-grp.mkv"));
        // Real groups that merely BEGIN with a digit.
        assert!(is_rename_tail("-3lt0n.mkv"));
        assert!(is_rename_tail("-2hd.mkv"));
        // Sidecars on the renamed stem.
        assert!(is_rename_tail(".en.srt"));
        assert!(is_rename_tail(".nfo"));
        assert!(is_rename_tail(".eng.forced.srt"));
        // An extension that merely STARTS with a digit is not an episode
        // number - "3gp" has a non-digit in it, "264" would not.
        assert!(is_rename_tail(".3gp"));
        // Quality tokens are not episode numbers either.
        assert!(is_rename_tail(".x264.mkv"));
        assert!(is_rename_tail(".1080p.mkv"));
    }

    #[test]
    fn ext_list_parsing() {
        assert_eq!(
            parse_ext_list("par2, SFV, *.srr, .url, ,"),
            vec!["par2", "sfv", "srr", "url"]
        );
        assert!(parse_ext_list("").is_empty());
    }

    #[test]
    fn encrypted_rar_scan() {
        let dir = std::env::temp_dir().join(format!("nzbfast-smart-enc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // Plain store volume → nothing to unlock.
        std::fs::write(
            dir.join("plain.rar"),
            nzbkit::rar::fixtures::rar4_volume(&[("a.bin", 4, b"data", false, false)]),
        )
        .unwrap();
        std::fs::write(dir.join("video.mkv"), b"x").unwrap();
        assert_eq!(encrypted_rar(&dir), None);
        // Add an encrypted-header volume → found.
        std::fs::write(
            dir.join("locked.rar"),
            nzbkit::rar::fixtures::rar4_encrypted_headers(64),
        )
        .unwrap();
        assert_eq!(encrypted_rar(&dir), Some(dir.join("locked.rar")));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cleanup_two_levels() {
        let _steady = trash_globals_steady();
        let dir = std::env::temp_dir().join(format!("nzbfast-smart-clean-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        for p in [
            "a.mkv",
            "a.par2",
            "a.vol00+1.PAR2",
            "a.sfv",
            "sub/b.par2",
            "sub/b.mkv",
        ] {
            std::fs::write(dir.join(p), b"x").unwrap();
        }
        let (n, par2) = cleanup(&dir, &parse_ext_list("par2, sfv"));
        assert_eq!(n, 4);
        // 3 of the 4 were .par2 - the drawer's "(M par2 recovery files)"
        // half of the count.
        assert_eq!(par2, 3);
        assert!(dir.join("a.mkv").exists());
        assert!(dir.join("sub/b.mkv").exists());
        assert!(!dir.join("a.par2").exists());
        assert!(!dir.join("a.vol00+1.PAR2").exists());
        assert!(!dir.join("sub/b.par2").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tv_organize_moves_and_renames() {
        let root = std::env::temp_dir().join(format!("nzbfast-smart-org-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let stem = "My.Show.S01E02.1080p.WEB.x264-TEST";
        let out = root.join("tv").join(stem);
        std::fs::create_dir_all(out.join("extras")).unwrap();
        std::fs::write(out.join(format!("{stem}.mkv")), b"video").unwrap();
        std::fs::write(out.join(format!("{stem}.nfo")), b"info").unwrap();
        std::fs::write(out.join("sample.mkv"), b"s").unwrap();
        std::fs::write(out.join("extras/x.srt"), b"subs").unwrap();
        let dest = tv_organize(
            &root.join("tv"),
            stem,
            &out,
            " [1080p]",
            &EpisodeTitles::default(),
        )
        .unwrap();
        assert_eq!(dest, root.join("tv/My Show/Season 01"));
        assert_eq!(
            std::fs::read(dest.join("My Show - S01E02 [1080p].mkv")).unwrap(),
            b"video"
        );
        assert!(
            dest.join(format!("{stem}.nfo")).exists(),
            "non-video keeps its name"
        );
        assert!(
            dest.join("sample.mkv").exists(),
            "sample moved but not renamed"
        );
        assert!(dest.join("extras/x.srt").exists(), "subdir moved whole");
        assert!(!out.exists(), "emptied job dir removed");
        // A movie stem refuses and leaves the directory alone.
        let mout = root.join("Movie.2020.1080p");
        std::fs::create_dir_all(&mout).unwrap();
        assert!(
            tv_organize(
                &root,
                "Movie.2020.1080p",
                &mout,
                "",
                &EpisodeTitles::default()
            )
            .is_none()
        );
        assert!(mout.exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn tv_organize_collision_spares_the_existing_library_file() {
        let root =
            std::env::temp_dir().join(format!("nzbfast-tv-collision-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let out = root.join("job");
        let season = root.join("tv/Show/Season 01");
        std::fs::create_dir_all(&out).unwrap();
        std::fs::create_dir_all(&season).unwrap();
        std::fs::write(out.join("posted.release.mkv"), b"ours").unwrap();
        let canonical = season.join("Show - S01E02 1080p.mkv");
        std::fs::write(&canonical, b"library").unwrap();

        assert!(
            tv_organize(
                &root.join("tv"),
                "Show.S01E02.1080p.WEB.x265-GRP",
                &out,
                " 1080p",
                &EpisodeTitles::default(),
            )
            .is_none(),
            "a collision must keep the job private"
        );
        assert_eq!(std::fs::read(&canonical).unwrap(), b"library");
        assert_eq!(
            std::fs::read(out.join("posted.release.mkv")).unwrap(),
            b"ours"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    /// Filing NOTHING must not claim the shared season folder. An
    /// all-junk repost (NFOFIX/DIRFIX: only .nfo/.sfv/.par2) is emptied by
    /// sweep_junk before tv_organize runs, so `planned` is empty - and the
    /// tail fell straight through to Some(dest). That sets `filed`, and
    /// delete_filed_episode then matches by canonical NAME in the shared
    /// folder and removes the user's real episode for a job that moved
    /// zero bytes. Reachable from a history delete-with-files and from
    /// both watchlist upgrade paths, the last two with no user action.
    #[test]
    fn tv_organize_refuses_the_season_folder_when_there_was_nothing_to_file() {
        let root = std::env::temp_dir().join(format!("nzbfast-tv-empty-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let out = root.join("job");
        let season = root.join("tv/Show/Season 01");
        std::fs::create_dir_all(&out).unwrap();
        std::fs::create_dir_all(&season).unwrap();
        // The user's real episode already lives there.
        let theirs = season.join("Show - S01E05 1080p.mkv");
        std::fs::write(&theirs, b"library").unwrap();

        // Our job has nothing left to place at all.
        assert!(
            tv_organize(
                &root.join("tv"),
                "Show.S01E05.1080p.WEB-GRP",
                &out,
                " 1080p",
                &EpisodeTitles::default(),
            )
            .is_none(),
            "a job with nothing to file must not claim the season folder"
        );
        assert_eq!(
            std::fs::read(&theirs).unwrap(),
            b"library",
            "the user's episode must be untouched"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    /// A shared subfolder must not stop the episode filing. The
    /// collision abort was whole-job and covered directories, so the
    /// SECOND episode of a season shipping a `Subs/` folder never filed
    /// at all - silently, since the caller records nothing when filing
    /// returns None. Scene TV ships `Subs/` constantly, and sweep_junk
    /// preserves subtitles by design, so this hit ordinary users.
    #[test]
    fn tv_organize_shared_subfolder_does_not_block_the_episode() {
        let root = std::env::temp_dir().join(format!("nzbfast-tv-subs-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let out = root.join("job");
        let season = root.join("tv/Show/Season 01");
        std::fs::create_dir_all(out.join("Subs")).unwrap();
        // The season folder already has a Subs/ from an earlier episode.
        std::fs::create_dir_all(season.join("Subs")).unwrap();
        std::fs::write(out.join("posted.release.mkv"), b"ours").unwrap();
        std::fs::write(out.join("Subs/en.srt"), b"subs").unwrap();

        let dest = tv_organize(
            &root.join("tv"),
            "Show.S01E03.1080p.WEB-GRP",
            &out,
            " 1080p",
            &EpisodeTitles::default(),
        )
        .expect("a shared Subs/ folder must not stop the episode filing");
        assert_eq!(dest, season);
        assert!(
            season.join("Show - S01E03 1080p.mkv").is_file(),
            "the episode itself must reach the season folder"
        );
        // The colliding folder is left behind rather than merged - not
        // ours to own, and no data is lost either way.
        assert!(out.join("Subs/en.srt").is_file());
        std::fs::remove_dir_all(root).unwrap();
    }

    /// A job that moved NOTHING must not claim the shared season folder.
    /// The caller turns Some(dest) into `filed`, and cleanup then deletes
    /// by canonical NAME - so a failed move made "delete this job" delete
    /// whichever episode really was there. Renames fail in ordinary life
    /// (NAS read-only blip, EXDEV, a media server holding the file open).
    #[test]
    #[cfg(unix)]
    fn tv_organize_refuses_the_season_folder_when_nothing_moved() {
        use std::os::unix::fs::PermissionsExt;
        let root = std::env::temp_dir().join(format!("nzbfast-tv-nomove-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let out = root.join("job");
        let season = root.join("tv/Show/Season 01");
        std::fs::create_dir_all(&out).unwrap();
        std::fs::create_dir_all(&season).unwrap();
        std::fs::write(out.join("posted.release.mkv"), b"ours").unwrap();
        // The rename must fail WITHOUT the target existing, or the
        // collision branch handles it and this never reaches the move
        // loop at all. (A directory at the canonical name does not work:
        // `target.exists()` is true for a directory, so the first draft
        // of this test passed against the unfixed code.) A read-only
        // season folder is the honest reproduction of the NAS blip.
        let mut perms = std::fs::metadata(&season).unwrap().permissions();
        perms.set_mode(0o555);
        std::fs::set_permissions(&season, perms).unwrap();

        assert!(
            tv_organize(
                &root.join("tv"),
                "Show.S01E04.1080p.WEB-GRP",
                &out,
                " 1080p",
                &EpisodeTitles::default(),
            )
            .is_none(),
            "a job whose move failed must not claim the season folder"
        );
        assert_eq!(
            std::fs::read(out.join("posted.release.mkv")).unwrap(),
            b"ours",
            "and its file stays where it was"
        );
        let mut perms = std::fs::metadata(&season).unwrap().permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&season, perms).unwrap();
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn move_tree_renames_when_dest_absent() {
        let root = std::env::temp_dir().join(format!("nzbfast-mv1-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let src = root.join("out/movies/Film.2020");
        std::fs::create_dir_all(src.join("extras")).unwrap();
        std::fs::write(src.join("Film.mkv"), b"v").unwrap();
        std::fs::write(src.join("extras/x.srt"), b"s").unwrap();
        let dst = root.join("nas/movies/Film.2020");
        move_tree(&src, &dst).unwrap();
        assert_eq!(std::fs::read(dst.join("Film.mkv")).unwrap(), b"v");
        assert_eq!(std::fs::read(dst.join("extras/x.srt")).unwrap(), b"s");
        assert!(!src.exists(), "source dir gone after move");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A completed job containing `extras -> /external` must not make the
    /// mover walk into the link and relocate files that live outside the job.
    /// `Path::is_dir` follows symlinks, so it used to do exactly that: the
    /// external directory's children were moved into the destination and
    /// deleted from where they actually were.
    #[cfg(unix)]
    #[test]
    fn move_tree_does_not_walk_through_a_directory_symlink() {
        let root = std::env::temp_dir().join(format!("nzbfast-mvlink-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let external = root.join("external");
        std::fs::create_dir_all(&external).unwrap();
        std::fs::write(external.join("someone-elses.txt"), b"not yours").unwrap();

        let src = root.join("job");
        let dst = root.join("done");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("payload.mkv"), b"v").unwrap();
        std::os::unix::fs::symlink(&external, src.join("extras")).unwrap();

        move_tree(&src, &dst).unwrap();

        assert_eq!(
            std::fs::read(external.join("someone-elses.txt")).unwrap(),
            b"not yours",
            "a file outside the job was moved or deleted through the link"
        );
        assert!(external.join("someone-elses.txt").exists());
        assert_eq!(std::fs::read(dst.join("payload.mkv")).unwrap(), b"v");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Same hole on the delete side: the cleanup walkers classified with
    /// `is_file`/`is_dir`, both of which resolve links, and then deleted what
    /// they found - so removing `job/extras/x.nfo` reached the real file.
    #[cfg(unix)]
    #[test]
    fn cleanup_walkers_do_not_delete_through_a_directory_symlink() {
        let _steady = trash_globals_steady();
        let root = std::env::temp_dir().join(format!("nzbfast-cleanlink-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let external = root.join("external");
        std::fs::create_dir_all(&external).unwrap();
        std::fs::write(external.join("keep.nfo"), b"outside").unwrap();
        std::fs::write(external.join("keep.mkv"), b"outside").unwrap();

        let job = root.join("job");
        std::fs::create_dir_all(&job).unwrap();
        std::fs::write(job.join("real.nfo"), b"inside").unwrap();
        std::os::unix::fs::symlink(&external, job.join("extras")).unwrap();

        cleanup(&job, &["nfo".to_string()]);
        assert!(
            external.join("keep.nfo").exists(),
            "cleanup deleted outside the job"
        );

        sweep_junk(&job);
        assert!(
            external.join("keep.nfo").exists(),
            "sweep_junk deleted outside the job"
        );

        keep_media_only(&job);
        assert!(
            external.join("keep.nfo").exists(),
            "keep_media_only deleted outside the job"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// `exists()` is not an ownership primitive: two movers racing the same
    /// destination both saw the name as free and both took it, so one
    /// payload was overwritten and both sources deleted - with both movers
    /// reporting success. Reservation is atomic, so each caller gets its own.
    #[test]
    fn reserving_a_name_never_hands_the_same_path_to_two_callers() {
        let root = std::env::temp_dir().join(format!("nzbfast-reserve-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let wanted = root.join("Episode.mkv");

        let mut claimed = Vec::new();
        for _ in 0..5 {
            claimed.push(reserve_free_name(&wanted).unwrap());
        }
        let unique: std::collections::HashSet<_> = claimed.iter().collect();
        assert_eq!(
            unique.len(),
            claimed.len(),
            "a name was handed out twice: {claimed:?}"
        );
        assert_eq!(
            claimed[0], wanted,
            "the first caller still gets the plain name"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn move_tree_merges_and_uncollides() {
        let root = std::env::temp_dir().join(format!("nzbfast-mv2-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        // Destination Season dir already holds an earlier episode AND a
        // same-named file - merge must keep both bytes.
        let src = root.join("out/tv/My Show/Season 01");
        let dst = root.join("nas/tv/My Show/Season 01");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::create_dir_all(&dst).unwrap();
        std::fs::write(src.join("E02.mkv"), b"new").unwrap();
        std::fs::write(src.join("E01.mkv"), b"ours").unwrap();
        std::fs::write(dst.join("E01.mkv"), b"theirs").unwrap();
        move_tree(&src, &dst).unwrap();
        assert_eq!(std::fs::read(dst.join("E02.mkv")).unwrap(), b"new");
        assert_eq!(
            std::fs::read(dst.join("E01.mkv")).unwrap(),
            b"theirs",
            "existing destination file kept"
        );
        assert_eq!(
            std::fs::read(dst.join("E01 (2).mkv")).unwrap(),
            b"ours",
            "colliding file lands beside it"
        );
        assert!(!src.exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The cross-device route, driven directly - a unit test cannot conjure
    /// a second filesystem. Everything is copied into staging first and
    /// published in one pass, so merge and collision behaviour has to match
    /// the rename route exactly.
    #[test]
    fn a_staged_move_publishes_the_whole_tree_then_drains_the_source() {
        let root = std::env::temp_dir().join(format!("nzbfast-stage1-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let src = root.join("out/tv/My Show/Season 01");
        let dst = root.join("nas/tv/My Show/Season 01");
        std::fs::create_dir_all(src.join("Subs")).unwrap();
        std::fs::write(src.join("E01.mkv"), b"ours").unwrap();
        std::fs::write(src.join("Subs/E01.srt"), b"s").unwrap();
        // The Season folder already holds an earlier episode AND a file of
        // the same name as ours.
        std::fs::create_dir_all(&dst).unwrap();
        std::fs::write(dst.join("E02.mkv"), b"earlier").unwrap();
        std::fs::write(dst.join("E01.mkv"), b"theirs").unwrap();

        let staging = dst.with_file_name(".Season 01.moving");
        staged_move(&src, &dst, &staging).unwrap();

        assert_eq!(std::fs::read(dst.join("E02.mkv")).unwrap(), b"earlier");
        assert_eq!(
            std::fs::read(dst.join("E01.mkv")).unwrap(),
            b"theirs",
            "existing kept"
        );
        assert_eq!(
            std::fs::read(dst.join("E01 (2).mkv")).unwrap(),
            b"ours",
            "ours beside it"
        );
        assert_eq!(
            std::fs::read(dst.join("Subs/E01.srt")).unwrap(),
            b"s",
            "subdir published"
        );
        assert!(!src.exists(), "drained source dir removed");
        assert!(!staging.exists(), "staging cleaned up");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Regression: the drain re-walked the source and deleted every file it
    /// found, rather than the ones the copy pass actually reproduced. A file
    /// created between the two - a post-processing script's output, a user's
    /// drop-in - was therefore deleted without ever having been copied, so
    /// it existed nowhere afterwards.
    #[test]
    fn a_staged_move_does_not_drain_what_it_never_copied() {
        let root = std::env::temp_dir().join(format!("nzbfast-stage3-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let src = root.join("out/Film.2020");
        let dst = root.join("nas/Film.2020");
        std::fs::create_dir_all(src.join("Subs")).unwrap();
        std::fs::write(src.join("Film.mkv"), b"v").unwrap();
        std::fs::write(src.join("Subs/Film.srt"), b"s").unwrap();
        let staging = dst.with_file_name(".Film.2020.moving");

        // Stand in for the window between the copy pass and the drain: copy
        // and publish by hand, drop a new file in, then drain.
        let mut copied = std::collections::HashSet::new();
        copy_tree_into(&src, &staging, &mut copied).unwrap();
        publish_staged(&staging, &dst).unwrap();
        std::fs::write(src.join("post-process.log"), b"late").unwrap();
        std::fs::write(src.join("Subs/late.srt"), b"late").unwrap();
        drain_copied(&src, &copied);

        assert_eq!(
            std::fs::read(dst.join("Film.mkv")).unwrap(),
            b"v",
            "payload published"
        );
        assert_eq!(std::fs::read(dst.join("Subs/Film.srt")).unwrap(), b"s");
        assert!(!src.join("Film.mkv").exists(), "what was copied is drained");
        assert_eq!(
            std::fs::read(src.join("post-process.log")).unwrap(),
            b"late",
            "arrived after the copy: never copied, so never deleted"
        );
        assert_eq!(std::fs::read(src.join("Subs/late.srt")).unwrap(), b"late");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Regression: a cross-device move that failed partway had already
    /// deleted every source file whose copy had landed, so the payload was
    /// SPLIT across two filesystems while the caller was told nothing had
    /// moved - and an importer pointed at either half took the fragment for
    /// the whole release. Staging fails whole: the source keeps every byte
    /// and the destination gains nothing.
    #[test]
    fn a_failed_staged_move_leaves_the_source_whole() {
        let root = std::env::temp_dir().join(format!("nzbfast-stage2-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let src = root.join("out/Film.2020");
        let dst = root.join("nas/Film.2020");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("Film.mkv"), b"v").unwrap();
        std::fs::write(src.join("Film.nfo"), b"n").unwrap();
        std::fs::create_dir_all(root.join("nas")).unwrap();
        // A plain file where staging wants a directory: the copy cannot
        // start, standing in for the share that drops mid-move.
        let staging = dst.with_file_name(".Film.2020.moving");
        std::fs::write(&staging, b"in the way").unwrap();

        assert!(staged_move(&src, &dst, &staging).is_err());
        assert_eq!(
            std::fs::read(src.join("Film.mkv")).unwrap(),
            b"v",
            "source untouched"
        );
        assert_eq!(
            std::fs::read(src.join("Film.nfo")).unwrap(),
            b"n",
            "source untouched"
        );
        assert!(!dst.exists(), "nothing half-published at the destination");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The Supergirl case: a 56-byte extensionless scrap packed inside the
    /// RAR, left beside a 20 GB feature because nothing could classify it.
    /// Tests the predicate directly - driving sweep_junk would mean
    /// toggling the process-global Trash flag, which races other tests.
    #[test]
    fn a_nameless_scrap_is_junk_only_when_the_delete_can_be_undone() {
        let dir = std::env::temp_dir().join(format!("nzbfast-scrap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let feat = 20_000_000_000u64;
        let mk = |name: &str, body: &[u8]| {
            let p = dir.join(name);
            std::fs::write(&p, body).unwrap();
            p
        };

        let scrap = mk("GqRTzbOIvUzZg1hqbipRind85vn", &[b'x'; 56]);
        assert!(
            is_nameless_scrap(&scrap, "", feat, true),
            "the reported leftover"
        );
        // The whole point of the gate: permanent delete, so do not guess.
        assert!(!is_nameless_scrap(&scrap, "", feat, false));
        // No feature identified = music/books/software, where extensionless
        // files are legitimate.
        assert!(!is_nameless_scrap(&scrap, "", 0, true));

        // Must never fire on these.
        let big = mk("NoExtensionButBig", &vec![0u8; 8192]);
        assert!(
            !is_nameless_scrap(&big, "", feat, true),
            "8 KB is over the ceiling"
        );
        let named = mk("notes.xyz", b"hi");
        assert!(
            !is_nameless_scrap(&named, "xyz", feat, true),
            "an unknown ext is somebody's file"
        );
        for (n, magic) in [
            ("tiny_rar", &b"Rar!\x1a\x07\x00"[..]),
            ("tiny_zip", &b"PK\x03\x04xxxx"[..]),
            ("tiny_mkv", &b"\x1aE\xdf\xa3xxxx"[..]),
            ("tiny_pdf", &b"%PDF-1.7xx"[..]),
        ] {
            let f = mk(n, magic);
            assert!(
                !is_nameless_scrap(&f, "", feat, true),
                "{n}: magic must save it"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sweep_junk_keeps_media_and_feature() {
        let _steady = trash_globals_steady();
        let dir = std::env::temp_dir().join(format!("nzbfast-sweep-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("sub")).unwrap();
        // Feature is small here, but it's the largest video → protected even
        // though its name contains no "sample".
        std::fs::write(dir.join("The.Feature.mkv"), vec![0u8; 4096]).unwrap();
        std::fs::write(dir.join("The.Feature.en.srt"), b"subs").unwrap();
        for j in ["a.par2", "a.nzb", "a.sfv", "a.nfo", "info.txt", "read.url"] {
            std::fs::write(dir.join(j), b"x").unwrap();
        }
        std::fs::write(dir.join("sample.mkv"), b"clip").unwrap();
        std::fs::write(dir.join("sub/proof.mkv"), b"clip").unwrap();
        let n = sweep_junk(&dir);
        assert_eq!(n, 8, "6 furniture files + 2 sample/proof clips");
        assert!(dir.join("The.Feature.mkv").exists(), "feature kept");
        assert!(dir.join("The.Feature.en.srt").exists(), "subtitle kept");
        assert!(!dir.join("sample.mkv").exists());
        assert!(!dir.join("sub/proof.mkv").exists());
        assert!(!dir.join("a.par2").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Obfuscated posts write hash-named, extensionless recovery volumes
    /// (the yEnc header name wins over the NZB subject), which the
    /// extension list alone can't see. Reported in the wild: a whole
    /// 7-volume PAR2 set left beside the episode with junk-sweep on.
    #[test]
    fn sweep_junk_drops_extensionless_par2_by_magic() {
        let _steady = trash_globals_steady();
        let dir = std::env::temp_dir().join(format!("nzbfast-obfpar2-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("Show.S01E02.mkv"), vec![0u8; 4096]).unwrap();
        // Hash-named recovery volumes, exactly as they land on disk.
        for h in [
            "a3fe9c80619b8674f7630bf390f2dc32",
            "f72b9763eb8f689acefad6891cbf876c",
        ] {
            let mut body = b"PAR2\x00PKT".to_vec();
            body.extend_from_slice(&[0u8; 64]);
            std::fs::write(dir.join(h), body).unwrap();
        }
        // A hash-named file that is NOT par2 stays: the magic decides,
        // not the shape of the name.
        std::fs::write(
            dir.join("cc1a4c408b0b5990ca51a83ec219bca2"),
            b"not a par2 file",
        )
        .unwrap();
        let n = sweep_junk(&dir);
        assert_eq!(n, 2, "both obfuscated recovery volumes swept");
        assert!(dir.join("Show.S01E02.mkv").exists(), "episode kept");
        assert!(!dir.join("a3fe9c80619b8674f7630bf390f2dc32").exists());
        assert!(!dir.join("f72b9763eb8f689acefad6891cbf876c").exists());
        assert!(
            dir.join("cc1a4c408b0b5990ca51a83ec219bca2").exists(),
            "non-par2 blob is not swept on name shape alone"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn keep_media_only_spares_all_episodes() {
        let _steady = trash_globals_steady();
        let dir = std::env::temp_dir().join(format!("nzbfast-keepmedia-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // Season pack: every episode must survive, not just the largest.
        for v in ["ep01.mkv", "ep02.mkv", "ep03.mkv"] {
            std::fs::write(dir.join(v), vec![0u8; 4096]).unwrap();
        }
        std::fs::write(dir.join("ep01.srt"), b"subs").unwrap();
        for junk in ["poster.jpg", "a.par2", "notes.txt", "sample.mkv"] {
            std::fs::write(dir.join(junk), b"x").unwrap();
        }
        let n = keep_media_only(&dir);
        assert_eq!(n, 4, "jpg + par2 + txt + the sample clip");
        assert!(dir.join("ep01.mkv").exists());
        assert!(dir.join("ep02.mkv").exists());
        assert!(dir.join("ep03.mkv").exists());
        assert!(dir.join("ep01.srt").exists(), "subtitle kept");
        assert!(!dir.join("poster.jpg").exists());
        assert!(!dir.join("sample.mkv").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Regression: keep-media-only deleted every non-video file, so an
    /// archive we could not unpack - the ONLY copy of the payload - was
    /// destroyed by the tidy-up that ran right after we told the user to
    /// unpack it by hand. Job Completed, folder empty, nothing to show.
    #[test]
    fn keep_media_only_spares_still_packed_archives() {
        let _steady = trash_globals_steady();
        let dir = std::env::temp_dir().join(format!("nzbfast-keeparc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("movie.mkv"), vec![0u8; 4096]).unwrap();
        for packed in ["extras.zip", "bonus.rar", "more.7z", "split.zip.001"] {
            std::fs::write(dir.join(packed), b"PK\x03\x04still packed").unwrap();
        }
        std::fs::write(dir.join("poster.jpg"), b"x").unwrap();
        let n = keep_media_only(&dir);
        assert_eq!(n, 1, "only the poster goes");
        for packed in ["extras.zip", "bonus.rar", "more.7z", "split.zip.001"] {
            assert!(
                dir.join(packed).exists(),
                "{packed} is payload we could not unpack"
            );
        }
        // A .cbz is the deliverable, not packaging - but it is also not
        // media, so keep-media-only is still allowed to sweep it.
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Regression: the same job as `keep_media_only_spares_still_packed_archives`
    /// in its OBFUSCATED dress - hash names, no extensions, which is how the
    /// majority of real posts arrive. `looks_like_named_rar` is a name
    /// grammar, so it saw nothing here and keep-media-only deleted the entire
    /// volume set: the only copy of a payload we had just told the user we
    /// could not unpack. The 7z and zip shapes beside it were already sniffed;
    /// only RAR was judged on its name.
    ///
    /// This is the negative case that matters for any spent-volume cleanup:
    /// the extraction did NOT succeed here (the feature beside them is a
    /// sample, not the payload), so the volumes are the whole download and
    /// must survive every sweep.
    #[test]
    fn keep_media_only_spares_obfuscated_rar_volumes() {
        let _steady = trash_globals_steady();
        let dir = std::env::temp_dir().join(format!("nzbfast-keepobf-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // The set we could not unpack: hash-named, extensionless, Rar! magic.
        let vols = [
            "301c0186f3bbdc58ac03a8739f989391c4",
            "a845657a411e3164c9d1e3f2c93235de3c",
            "6d248ae899f4e2bbe7b8778510c80e6053",
        ];
        for v in vols {
            let mut body = b"Rar!\x1a\x07\x01\x00".to_vec();
            body.extend_from_slice(&[0u8; 64]);
            std::fs::write(dir.join(v), body).unwrap();
        }
        // A video has to be present or the sweep declines to run at all
        // (see `keep_media_only_leaves_a_video_less_job_alone`).
        std::fs::write(dir.join("teaser.mkv"), vec![0u8; 4096]).unwrap();
        std::fs::write(dir.join("poster.jpg"), b"x").unwrap();
        // A hash-named blob that is NOT a RAR is still clutter: the magic
        // decides, never the shape of the name.
        std::fs::write(
            dir.join("cc98d076ce474159bec6a0fe670059ee32"),
            b"not an archive",
        )
        .unwrap();
        let n = keep_media_only(&dir);
        assert_eq!(n, 2, "the poster and the non-archive blob go, nothing else");
        for v in vols {
            assert!(dir.join(v).exists(), "{v} is the only copy of the payload");
        }
        assert!(dir.join("teaser.mkv").exists());
        assert!(!dir.join("poster.jpg").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The junk sweep never removes an archive - named or obfuscated -
    /// because it cannot tell a volume the job has finished with from the
    /// only copy of a payload nothing unpacked. Spent volumes are the
    /// extraction pass's own to remove, from its own record of what it
    /// consumed; nothing that only sees the finished directory may guess.
    #[test]
    fn sweep_junk_never_removes_an_archive() {
        let _steady = trash_globals_steady();
        let dir = std::env::temp_dir().join(format!("nzbfast-sweeparc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("Feature.mkv"), vec![0u8; 4096]).unwrap();
        let mut body = b"Rar!\x1a\x07\x01\x00".to_vec();
        body.extend_from_slice(&[0u8; 64]);
        std::fs::write(dir.join("301c0186f3bbdc58ac03a8739f989391c4"), &body).unwrap();
        std::fs::write(dir.join("Feature.part01.rar"), &body).unwrap();
        std::fs::write(dir.join("Feature.nfo"), b"x").unwrap();
        let n = sweep_junk(&dir);
        assert_eq!(n, 1, "only the nfo is furniture");
        assert!(dir.join("301c0186f3bbdc58ac03a8739f989391c4").exists());
        assert!(dir.join("Feature.part01.rar").exists());
        assert!(dir.join("Feature.mkv").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Regression: a bare-numeric split zip carries the magic in part 1
    /// only, so the per-file guard spared `.001` and deleted `.002`
    /// onward - a third of an archive, left behind a history note telling
    /// the user the verified archive was waiting in the folder.
    #[test]
    fn keep_media_only_spares_every_part_of_a_split_zip() {
        let _steady = trash_globals_steady();
        let dir = std::env::temp_dir().join(format!("nzbfast-keepsplit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let parts = ["Movie.2019.1080p-TEST.001", "Movie.2019.1080p-TEST.002"];
        std::fs::write(dir.join(parts[0]), b"PK\x03\x04first part").unwrap();
        std::fs::write(dir.join(parts[1]), b"raw continuation bytes").unwrap();
        std::fs::write(dir.join("a.par2"), b"x").unwrap();
        // An extracted feature beside the split set the extractor could not
        // open: without a video present the sweep now declines to run at all
        // (see `keep_media_only_leaves_a_video_less_job_alone`), and this
        // test is about the zip parts, not that guard.
        std::fs::write(dir.join("Movie.2019.1080p-TEST.mkv"), vec![0u8; 4096]).unwrap();
        let n = keep_media_only(&dir);
        assert_eq!(n, 1, "only the par2 goes");
        for p in parts {
            assert!(dir.join(p).exists(), "{p} is a part of the only payload");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Regression: keep-media-only kept videos, subtitles and still-packed
    /// archives and deleted everything else with no backstop, so a release
    /// whose payload is not a recognised video - a disc image, a music
    /// album, an ebook - was deleted IN FULL and the job still reported
    /// Completed over an empty folder. nzbkit classifies everything as
    /// Movie/Tv, so a FLAC album passes the kind gate that guards this.
    #[test]
    fn keep_media_only_leaves_a_video_less_job_alone() {
        let _steady = trash_globals_steady();
        let root = std::env::temp_dir().join(format!("nzbfast-keepnovid-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);

        // A disc image is the payload, and its .nfo/.jpg are beside it.
        let iso = root.join("Movie.2019.BluRay.ISO");
        std::fs::create_dir_all(&iso).unwrap();
        for f in ["movie.iso", "movie.nfo", "cover.jpg"] {
            std::fs::write(iso.join(f), vec![0u8; 4096]).unwrap();
        }
        assert_eq!(
            keep_media_only(&iso),
            2,
            "the .iso IS the video; the nfo and jpg go"
        );
        assert!(iso.join("movie.iso").exists(), "the payload");
        assert!(!iso.join("cover.jpg").exists());
        assert!(!iso.join("movie.nfo").exists());

        // A music album: no video at all, so the sweep declines to run.
        let album = root.join("Adele - 30 (2021) FLAC");
        std::fs::create_dir_all(&album).unwrap();
        let tracks = [
            "01 - Strangers By Nature.flac",
            "02 - Easy On Me.flac",
            "album.cue",
            "cover.jpg",
        ];
        for f in tracks {
            std::fs::write(album.join(f), vec![0u8; 4096]).unwrap();
        }
        assert_eq!(
            keep_media_only(&album),
            0,
            "nothing here is safe to classify"
        );
        for f in tracks {
            assert!(album.join(f).exists(), "{f} is the payload, not clutter");
        }

        // Same for a book release, whatever the extension.
        let book = root.join("Some.Author.-.Some.Book.epub");
        std::fs::create_dir_all(&book).unwrap();
        std::fs::write(book.join("book.epub"), vec![0u8; 4096]).unwrap();
        std::fs::write(book.join("book.pdf"), vec![0u8; 4096]).unwrap();
        assert_eq!(keep_media_only(&book), 0);
        assert!(book.join("book.epub").exists());
        assert!(book.join("book.pdf").exists());

        // The case the no-video guard cannot catch, and the one a user
        // category makes ordinary: non-video payload WITH a video beside
        // it. A comics category declaring base Movie ships fifty .cbz
        // files and one bonus .mp4; the guard passes, and before
        // PAYLOAD_EXTS the fifty were deleted as "non-media".
        let comics = root.join("Some.Comic.Vol.01-03.2026.COMIC-GRP");
        std::fs::create_dir_all(&comics).unwrap();
        let keep = [
            "vol01.cbz",
            "vol02.cbr",
            "vol03.pdf",
            "extras.mp3",
            "read.epub",
            "album.cue",
            "bonus.mp4",
        ];
        for f in keep {
            std::fs::write(comics.join(f), vec![0u8; 4096]).unwrap();
        }
        std::fs::write(comics.join("cover.jpg"), vec![0u8; 4096]).unwrap();
        std::fs::write(comics.join("info.nfo"), vec![0u8; 4096]).unwrap();
        assert_eq!(
            keep_media_only(&comics),
            2,
            "only the jpg and nfo are clutter"
        );
        for f in keep {
            assert!(comics.join(f).exists(), "{f} is payload and was deleted");
        }

        // An audiobook set beside a bonus video: same shape, same rule.
        let audio = root.join("Author.-.Book.Audiobook.M4B");
        std::fs::create_dir_all(&audio).unwrap();
        for f in ["part1.m4b", "part2.m4b", "interview.mkv"] {
            std::fs::write(audio.join(f), vec![0u8; 4096]).unwrap();
        }
        std::fs::write(audio.join("thumbs.db"), vec![0u8; 4096]).unwrap();
        assert_eq!(keep_media_only(&audio), 1);
        assert!(audio.join("part1.m4b").exists() && audio.join("part2.m4b").exists());

        let _ = std::fs::remove_dir_all(&root);
    }

    /// A disc rip is unplayable with any of its structure files missing,
    /// and an external audio track can be the point of the release.
    #[test]
    fn keep_media_only_keeps_disc_structure_and_companion_tracks() {
        let _steady = trash_globals_steady();
        let dir = std::env::temp_dir().join(format!("nzbfast-keepdisc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("feature.m2ts"), vec![0u8; 4096]).unwrap();
        let keep = [
            "index.bdmv",
            "00800.mpls",
            "VTS_01_0.ifo",
            "VTS_01_0.bup",
            "track.mka",
        ];
        for f in keep {
            std::fs::write(dir.join(f), b"x").unwrap();
        }
        std::fs::write(dir.join("cover.jpg"), b"x").unwrap();
        assert_eq!(keep_media_only(&dir), 1, "only the jpg goes");
        for f in keep {
            assert!(dir.join(f).exists(), "{f} belongs to the disc");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// keep-media-only judges by extension and deletes what it does not
    /// recognise, so a hash-named payload with NO extension was removed
    /// outright. One properly named video in the same folder is enough to
    /// arm the sweep, and "one named file plus one hash-named one" is an
    /// ordinary obfuscated-post shape - so the user lost a file with no
    /// copy anywhere.
    #[test]
    fn keep_media_only_spares_extensionless_video_payload() {
        let _steady = trash_globals_steady();
        let dir = std::env::temp_dir().join(format!("nzbfast-keepext-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // A named video arms the sweep.
        std::fs::write(dir.join("Show.S01E05.1080p.WEB.mkv"), vec![0u8; 4096]).unwrap();

        // Extensionless payload, one per container magic we accept.
        let mut mkv = vec![0x1A, 0x45, 0xDF, 0xA3];
        mkv.extend(std::iter::repeat_n(0u8, 4096));
        std::fs::write(dir.join("0aF3xQ"), &mkv).unwrap();
        let mut mp4 = vec![0u8; 4];
        mp4.extend_from_slice(b"ftypisom");
        mp4.extend(std::iter::repeat_n(0u8, 4096));
        std::fs::write(dir.join("9zZq11"), &mp4).unwrap();
        let mut avi = Vec::from(*b"RIFF\0\0\0\0AVI ");
        avi.extend(std::iter::repeat_n(0u8, 4096));
        std::fs::write(dir.join("kk22ww"), &avi).unwrap();

        // Extensionless junk that is NOT a container still goes.
        std::fs::write(dir.join("readme_no_ext"), b"just some text here").unwrap();

        let removed = keep_media_only(&dir);
        assert!(dir.join("0aF3xQ").exists(), "matroska payload must survive");
        assert!(dir.join("9zZq11").exists(), "mp4 payload must survive");
        assert!(dir.join("kk22ww").exists(), "avi payload must survive");
        assert!(
            !dir.join("readme_no_ext").exists(),
            "non-container junk still goes"
        );
        assert_eq!(removed, 1, "only the junk file");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Regression: the companion list carried ac3 and dts but not eac3,
    /// which is what nearly every current Atmos or DD+ remux ships its
    /// external track as. keep-media-only deleted it, the job reported
    /// Completed, and the user was left with a video missing the audio
    /// the release existed for - with no copy anywhere to restore from.
    #[test]
    fn keep_media_only_keeps_modern_external_audio_tracks() {
        let _steady = trash_globals_steady();
        let dir = std::env::temp_dir().join(format!("nzbfast-keepaudio-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("Film.2024.2160p.REMUX.mkv"), vec![0u8; 4096]).unwrap();
        let tracks = [
            "Film.2024.eac3",
            "Film.2024.ec3",
            "Film.2024.truehd",
            "Film.2024.thd",
            "Film.2024.dtshd",
            "Film.2024.aac",
            "Film.2024.opus",
            "Film.2024.mp3",
            "Film.2024.wav",
        ];
        for f in tracks {
            std::fs::write(dir.join(f), b"x").unwrap();
        }
        std::fs::write(dir.join("poster.jpg"), b"x").unwrap();
        assert_eq!(keep_media_only(&dir), 1, "only the jpg should go");
        for f in tracks {
            assert!(
                dir.join(f).exists(),
                "{f} is the release's audio and cannot be recovered once deleted"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sweep_junk_keeps_feature_titled_proof() {
        let _steady = trash_globals_steady();
        // Regression: the 2005 film "Proof" - the feature's name contains
        // "proof" but it is the whole download and must never be swept.
        let dir = std::env::temp_dir().join(format!("nzbfast-proof-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let feat = "Proof.2005.1080p.BluRay.x264-GRP.mkv";
        std::fs::write(dir.join(feat), vec![0u8; 4096]).unwrap();
        for j in ["a.par2", "a.nfo", "info.txt"] {
            std::fs::write(dir.join(j), b"x").unwrap();
        }
        let n = sweep_junk(&dir);
        assert_eq!(n, 3, "only the 3 furniture files");
        assert!(dir.join(feat).exists(), "feature titled Proof kept");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sweep_junk_keeps_proof_season_pack() {
        let _steady = trash_globals_steady();
        // Regression: a "Proof" season pack - every episode name contains
        // "proof" and all are feature-sized. The old substring rule deleted
        // every episode (largest_video returned None -> keep=None).
        let dir = std::env::temp_dir().join(format!("nzbfast-proofpack-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let eps = [
            "Proof.S01E01.1080p.mkv",
            "Proof.S01E02.1080p.mkv",
            "Proof.S01E03.1080p.mkv",
        ];
        for ep in eps {
            std::fs::write(dir.join(ep), vec![0u8; 4096]).unwrap();
        }
        std::fs::write(dir.join("a.par2"), b"x").unwrap();
        let n = sweep_junk(&dir);
        assert_eq!(n, 1, "only the par2 file");
        for ep in eps {
            assert!(dir.join(ep).exists(), "episode {ep} kept");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sweep_junk_still_drops_a_real_sample() {
        let _steady = trash_globals_steady();
        // A genuine teaser (tiny) beside a full-size feature is still swept.
        let dir = std::env::temp_dir().join(format!("nzbfast-realsample-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("The.Movie.2024.1080p.mkv"), vec![0u8; 8192]).unwrap();
        std::fs::write(dir.join("sample.mkv"), vec![0u8; 64]).unwrap(); // <15% of feature
        let n = sweep_junk(&dir);
        assert_eq!(n, 1, "the tiny sample");
        assert!(dir.join("The.Movie.2024.1080p.mkv").exists());
        assert!(!dir.join("sample.mkv").exists(), "tiny teaser swept");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sweep_junk_takes_the_emptied_sample_folder_too() {
        let _steady = trash_globals_steady();
        // The husk of a swept `Sample/` folder used to survive the sweep,
        // so a tidied job still looked untidied. A folder that still holds
        // something - here the subtitle sidecars - stays.
        let dir = std::env::temp_dir().join(format!("nzbfast-emptydir-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("Sample")).unwrap();
        std::fs::create_dir_all(dir.join("Subs")).unwrap();
        std::fs::create_dir_all(dir.join("Proof/inner")).unwrap();
        std::fs::write(dir.join("The.Movie.2024.1080p.mkv"), vec![0u8; 8192]).unwrap();
        std::fs::write(dir.join("Sample/sample.mkv"), vec![0u8; 64]).unwrap();
        std::fs::write(dir.join("Subs/english.srt"), b"1").unwrap();

        let n = sweep_junk(&dir);

        assert_eq!(n, 1, "the sample clip");
        assert!(!dir.join("Sample").exists(), "emptied sample folder pruned");
        assert!(
            !dir.join("Proof").exists(),
            "empty folder and its empty child pruned"
        );
        assert!(dir.join("Subs/english.srt").exists(), "subtitle kept");
        assert!(
            dir.join("Subs").exists(),
            "folder that still holds a file stays"
        );
        assert!(
            dir.join("The.Movie.2024.1080p.mkv").exists(),
            "feature kept"
        );
        assert!(dir.exists(), "the job's own directory is never pruned");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// macOS drops a `.DS_Store` into every folder the Finder has opened,
    /// and nothing in the junk sweep can see it (no extension for
    /// `JUNK_EXTS`, 6148 bytes is over `is_nameless_scrap`'s ceiling), so
    /// the swept `Sample/` husk survived every download on a Mac.
    #[test]
    fn prune_takes_a_folder_left_holding_only_finder_droppings() {
        let dir = std::env::temp_dir().join(format!("nzbfast-dsstore-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("Sample")).unwrap();
        std::fs::create_dir_all(dir.join("Proof")).unwrap();
        std::fs::write(dir.join("Sample/.DS_Store"), vec![0u8; 6148]).unwrap();
        std::fs::write(dir.join("Proof/._clip.mkv"), b"resource fork").unwrap();
        // The job's own directory keeps its .DS_Store: it is never pruned,
        // so there is nothing to clear it out of the way for.
        std::fs::write(dir.join(".DS_Store"), vec![0u8; 6148]).unwrap();

        let n = prune_empty_dirs(&dir, 0);

        assert_eq!(n, 2, "both husks");
        assert!(
            !dir.join("Sample").exists(),
            "a folder holding only .DS_Store is empty"
        );
        assert!(
            !dir.join("Proof").exists(),
            "…and so is one holding only an AppleDouble"
        );
        assert!(
            dir.join(".DS_Store").exists(),
            "the job's own dir is left alone"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A `._name` big enough to BE something is content, whatever the
    /// prefix says. The husk sweep deletes permanently, so a mis-packed
    /// archive member or a poster-named extra called `._big.mkv` must
    /// survive its own folder rather than be classified away by name.
    #[test]
    fn prune_keeps_a_folder_holding_a_payload_sized_appledouble() {
        let dir = std::env::temp_dir().join(format!("nzbfast-adbig-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("Big")).unwrap();
        std::fs::create_dir_all(dir.join("Small")).unwrap();
        std::fs::write(dir.join("Big/._big.mkv"), vec![0u8; 2 * 1024 * 1024]).unwrap();
        // The genuine article, in the same sweep: still swept.
        std::fs::write(dir.join("Small/._clip.mkv"), b"resource fork").unwrap();

        let n = prune_empty_dirs(&dir, 0);

        assert_eq!(n, 1, "only the husk");
        assert!(
            dir.join("Big/._big.mkv").exists(),
            "2 MiB is not a resource fork"
        );
        assert!(dir.join("Big").exists(), "…so its folder is not empty");
        assert!(!dir.join("Small").exists(), "a real AppleDouble still goes");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// …but a dropping beside real content is not licence to delete the
    /// folder, and the dropping itself stays where the folder stays.
    #[test]
    fn prune_keeps_a_folder_where_finder_droppings_sit_beside_content() {
        let dir = std::env::temp_dir().join(format!("nzbfast-dskeep-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("Subs")).unwrap();
        std::fs::write(dir.join("Subs/.DS_Store"), vec![0u8; 6148]).unwrap();
        std::fs::write(dir.join("Subs/english.srt"), b"1").unwrap();

        assert_eq!(prune_empty_dirs(&dir, 0), 0);

        assert!(dir.join("Subs/english.srt").exists(), "content kept");
        assert!(
            dir.join("Subs/.DS_Store").exists(),
            "not ours to remove while the folder lives"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn prune_stops_at_the_depth_cap() {
        // Bounds the recursion on a tree we did not build. At the cap the
        // walk simply stops: deeper empties stay, nothing panics.
        let dir = std::env::temp_dir().join(format!("nzbfast-prunedepth-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let mut deep = dir.clone();
        for i in 0..(PRUNE_MAX_DEPTH + 2) {
            deep = deep.join(format!("d{i}"));
        }
        std::fs::create_dir_all(&deep).unwrap();
        prune_empty_dirs(&dir, 0);
        assert!(
            deep.exists(),
            "below the cap the walk stops rather than recursing"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tv_rename_in_place_with_suffix() {
        let _steady = trash_globals_steady();
        let dir = std::env::temp_dir().join(format!("nzbfast-tvrename-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let stem = "My.Show.S01E02.1080p.WEB.x264-TEST";
        std::fs::write(dir.join(format!("{stem}.mkv")), b"v").unwrap();
        std::fs::write(dir.join("sample.mkv"), b"s").unwrap();
        let n = tv_rename(&dir, stem, " [1080p]", &EpisodeTitles::default());
        assert_eq!(n, 1);
        assert!(dir.join("My Show - S01E02 [1080p].mkv").exists());
        assert!(dir.join("sample.mkv").exists(), "sample untouched");
        // delete_filed_episode still finds the suffixed name.
        assert_eq!(
            delete_filed_episode(&dir, stem, &FiledTail::suffix(" [1080p]")).removed,
            1
        );
        assert!(!dir.join("My Show - S01E02 [1080p].mkv").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn rename_movie_file_and_folder() {
        let root = std::env::temp_dir().join(format!("nzbfast-mvren-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let stem = "Example.Movie.2024.1080p.BluRay.x264-FGT";
        let out = root.join(stem);
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(out.join(format!("{stem}.mkv")), b"video").unwrap();
        std::fs::write(out.join(format!("{stem}.en.srt")), b"subs").unwrap();
        std::fs::write(out.join("sample.mkv"), b"s").unwrap();
        let dest = rename_movie(&root, &out, "Example Movie (2024) [1080p]").unwrap();
        assert_eq!(dest, root.join("Example Movie (2024) [1080p]"));
        assert!(
            dest.join("Example Movie (2024) [1080p].mkv").exists(),
            "feature renamed"
        );
        assert!(
            dest.join("Example Movie (2024) [1080p].en.srt").exists(),
            "sub re-stemmed"
        );
        assert!(dest.join("sample.mkv").exists(), "sample untouched");
        assert!(!out.exists(), "old folder gone");
        // Collision: a second job renaming to the same base gets ".2".
        let out2 = root.join(format!("{stem}.dup"));
        std::fs::create_dir_all(&out2).unwrap();
        std::fs::write(out2.join(format!("{stem}.mkv")), b"video2").unwrap();
        let dest2 = rename_movie(&root, &out2, "Example Movie (2024) [1080p]").unwrap();
        assert_eq!(dest2, root.join("Example Movie (2024) [1080p].2"));
        // Two videos → folder renamed, files left as-is (no fold-to-one).
        let outm = root.join("Double.Feature.2001.1080p");
        std::fs::create_dir_all(&outm).unwrap();
        std::fs::write(outm.join("cd1.mkv"), b"a").unwrap();
        std::fs::write(outm.join("cd2.mkv"), b"b").unwrap();
        let destm = rename_movie(&root, &outm, "Double Feature (2001)").unwrap();
        assert!(destm.join("cd1.mkv").exists() && destm.join("cd2.mkv").exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A single emitted path component, held to the rules a Windows box
    /// or an SMB share applies - which is every finished tree's fate, so
    /// the host that wrote the name is beside the point.
    fn assert_portable(name: &str) {
        assert!(!name.is_empty(), "empty component");
        assert!(!name.starts_with('.'), "hidden: {name:?}");
        assert!(
            !name.ends_with('.') && !name.ends_with(' '),
            "Windows truncates: {name:?}"
        );
        assert!(!name.starts_with(' '), "leading space: {name:?}");
        assert!(!name.contains(':'), "drive/ADS meaning: {name:?}");
        let stem = name.split('.').next().unwrap_or(name).to_ascii_uppercase();
        assert!(
            !matches!(
                stem.as_str(),
                "CON" | "PRN" | "AUX" | "NUL" | "COM1" | "LPT1"
            ),
            "reserved device: {name:?}"
        );
    }

    /// Stage 4's movie leg emits a file stem AND a folder name. Both used
    /// to go through a sanitiser that only blanked illegal glyphs, so a
    /// hidden name, a name Windows truncates, or a device stem all got
    /// through - while enqueue-time folder naming had already been fixed.
    #[test]
    fn movie_rename_emits_portable_names() {
        for (base, want) in [
            (".Hidden Movie (2024)", "Hidden Movie (2024)"),
            ("Movie (2024). ", "Movie (2024)"),
            ("CON", "_CON"),
            ("Alien: Romulus (2024)", "Alien - Romulus (2024)"),
        ] {
            let root = scratch("mvsafe");
            let out = root.join("job");
            std::fs::create_dir_all(&out).unwrap();
            std::fs::write(out.join("blob.mkv"), b"v").unwrap();
            std::fs::write(out.join("blob.en.srt"), b"s").unwrap();

            let dest = rename_movie(&root, &out, base).unwrap();
            assert_eq!(dest, root.join(want), "folder for {base:?}");
            assert!(
                dest.join(format!("{want}.mkv")).exists(),
                "feature for {base:?}"
            );
            assert!(
                dest.join(format!("{want}.en.srt")).exists(),
                "sidecar for {base:?}"
            );
            assert_portable(want);
            let _ = std::fs::remove_dir_all(&root);
        }

        // Negative: an ordinary base is passed through untouched, glyph
        // for glyph - hardening must not reshape a name that was fine.
        let root = scratch("mvplain");
        let out = root.join("job");
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(out.join("blob.mkv"), b"v").unwrap();
        let plain = "The Matrix (1999) [1080p BluRay x264]-AMIABLE";
        assert_eq!(rename_movie(&root, &out, plain).unwrap(), root.join(plain));
        let _ = std::fs::remove_dir_all(&root);

        // Nothing nameable in the base: decline rather than invent a
        // placeholder folder for the job.
        let root = scratch("mvnone");
        let out = root.join("job");
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(out.join("blob.mkv"), b"v").unwrap();
        assert!(rename_movie(&root, &out, "...").is_none());
        assert!(out.join("blob.mkv").exists(), "payload untouched");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The de-obfuscation fallback names the video after the RELEASE, and
    /// a release name is whatever the poster typed - including a leading
    /// dot or a device stem.
    #[test]
    fn de_obfuscation_emits_a_portable_name() {
        let out = &scratch("deobf-safe");
        std::fs::write(out.join("1fRbH6e0eX8v5hv7fSyXgBb.mkv"), b"v").unwrap();
        assert!(rename_obfuscated_video(
            out,
            ".The Movie: Part 2 2024 1080p."
        ));
        assert!(out.join("The Movie - Part 2 2024 1080p.mkv").exists());
        assert_portable("The Movie - Part 2 2024 1080p");

        // A release whose FIRST dotted component is a device name: on
        // Windows "CON.2024.….mkv" opens the console, extension and all.
        let out = &scratch("deobf-dev");
        std::fs::write(out.join("1fRbH6e0eX8v5hv7fSyXgBb.mkv"), b"v").unwrap();
        assert!(rename_obfuscated_video(out, "CON.2024.1080p.WEB.x264-GRP"));
        assert!(out.join("_CON.2024.1080p.WEB.x264-GRP.mkv").exists());

        // Nothing nameable in the release name: leave the blob alone
        // rather than rename it to a placeholder.
        let out = &scratch("deobf-none");
        std::fs::write(out.join("1fRbH6e0eX8v5hv7fSyXgBb.mkv"), b"v").unwrap();
        assert!(!rename_obfuscated_video(out, ". . ."));
        assert!(out.join("1fRbH6e0eX8v5hv7fSyXgBb.mkv").exists());
    }

    /// The TV leg emits a show directory, a season directory and an
    /// episode stem, all built on the show title, so the same rules apply
    /// - and a device-named show directory cannot be created at all on
    /// Windows.
    #[test]
    fn tv_paths_are_portable() {
        let (dir, base) = tv_path("CON S01E02 1080p WEB-GRP").unwrap();
        assert_eq!(dir, "_CON/Season 01");
        assert_eq!(base.as_deref(), Some("_CON - S01E02"));

        let (dir, base) = tv_path("Alien: Romulus S01E02 1080p WEB-GRP").unwrap();
        assert_eq!(dir, "Alien - Romulus/Season 01");
        assert_eq!(base.as_deref(), Some("Alien - Romulus - S01E02"));

        // Negative: an ordinary show is filed exactly as it always was.
        let (dir, base) = tv_path("The.Bear.S03E05.1080p.WEB-DL-GRP").unwrap();
        assert_eq!(dir, "The Bear/Season 03");
        assert_eq!(base.as_deref(), Some("The Bear - S03E05"));

        // Whatever the stem, every component we emit is usable. The
        // parser strips the dot shapes before they reach the sanitiser;
        // this pins that they cannot come back.
        for stem in [
            ". Hidden Show S01E02 1080p",
            "Show. S01E02 1080p",
            "CON S01E02 1080p",
            "COM1 S01E02 1080p",
            "Alien: Romulus S01E02 1080p",
        ] {
            let (dir, base) = tv_path(stem).unwrap();
            for part in dir.split('/') {
                assert_portable(part);
            }
            assert_portable(&base.unwrap());
        }
    }

    /// Filing and un-filing must agree on the emitted shape: the season
    /// folder, the episode name and `delete_filed_episode`'s matcher all
    /// derive from the same sanitised title, so a title carrying a colon
    /// must round-trip.
    #[test]
    fn a_sanitised_show_still_files_and_unfiles() {
        let _steady = trash_globals_steady();
        let root = scratch("tvsafe");
        let stem = "Alien: Romulus S01E02 1080p WEB-GRP";
        let out = root.join("job");
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(out.join("blob.mkv"), b"v").unwrap();

        let dest = tv_organize(
            &root.join("tv"),
            stem,
            &out,
            " [1080p]",
            &EpisodeTitles::default(),
        )
        .unwrap();
        assert_eq!(
            dest,
            root.join("tv").join("Alien - Romulus").join("Season 01")
        );
        assert!(dest.join("Alien - Romulus - S01E02 [1080p].mkv").exists());

        assert_eq!(
            delete_filed_episode(&dest, stem, &FiledTail::suffix(" [1080p]")).removed,
            1
        );
        assert!(!dest.join("Alien - Romulus - S01E02 [1080p].mkv").exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    // -----------------------------------------------------------------
    // TODO 78: episode titles in TV names.
    // -----------------------------------------------------------------

    /// A show whose episode list the enrichment cache already holds.
    fn titles_of(eps: &[(u32, u32, &str)]) -> EpisodeTitles {
        EpisodeTitles::new(eps.iter().map(|&(s, e, n)| (s, e, n.to_string())))
    }

    /// The shape the whole feature exists to produce, end to end: the
    /// title lands in the filed name, the job's own record of what it
    /// wrote agrees with what is on disk, and both the delete and the
    /// play path can still find the file afterwards.
    #[test]
    fn an_episode_title_reaches_the_filed_name_and_stays_findable() {
        let _steady = trash_globals_steady();
        let root = scratch("eptitle");
        let stem = "My.Show.S01E02.1080p.WEB.x264-TEST";
        let out = root.join("tv").join(stem);
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(out.join(format!("{stem}.mkv")), b"video").unwrap();
        // A subtitle posted under the release name. `tv_organize` renames
        // VIDEO_EXTS only, so this keeps the name it arrived with - the
        // documented limit of `is_rename_tail`, unchanged by titles.
        std::fs::write(out.join(format!("{stem}.en.srt")), b"subs").unwrap();
        let titles = titles_of(&[(1, 1, "Pilot"), (1, 2, "The Ceremony")]);

        let dest = tv_organize(&root.join("tv"), stem, &out, " [1080p]", &titles).unwrap();
        let filed = dest.join("My Show - S01E02 - The Ceremony [1080p].mkv");
        assert!(filed.is_file(), "the title is in the name");
        assert!(
            dest.join(format!("{stem}.en.srt")).exists(),
            "a sidecar keeps its posted name, exactly as before titles"
        );

        // What the job records is what filing wrote - the whole basis of
        // matching the file again later.
        let tail = FiledTail {
            title: filed_title_segment(stem, " [1080p]", &titles),
            suffix: " [1080p]".into(),
        };
        assert_eq!(tail.title, " - The Ceremony");
        assert_eq!(
            find_filed_episode_media(&dest, stem, &tail).as_deref(),
            Some(filed.as_path()),
            "play finds the titled episode"
        );
        assert_eq!(delete_filed_episode(&dest, stem, &tail).removed, 1);
        assert!(!filed.exists(), "and delete takes it");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The ordinary case, and the one that must never regress: the cache
    /// does not know this episode, so the name is the one we have always
    /// written - byte for byte. An empty [`EpisodeTitles`] (the setting
    /// off) takes the same path.
    #[test]
    fn a_cache_miss_files_exactly_as_it_did_before() {
        for titles in [
            EpisodeTitles::default(),
            // Knows the show, but not this episode.
            titles_of(&[(1, 1, "Pilot"), (2, 2, "Wrong Season")]),
        ] {
            let root = scratch("epmiss");
            let stem = "My.Show.S01E02.1080p.WEB.x264-TEST";
            let out = root.join("tv").join(stem);
            std::fs::create_dir_all(&out).unwrap();
            std::fs::write(out.join(format!("{stem}.mkv")), b"video").unwrap();

            let dest = tv_organize(&root.join("tv"), stem, &out, " [1080p]", &titles).unwrap();
            assert!(dest.join("My Show - S01E02 [1080p].mkv").is_file());
            assert_eq!(filed_title_segment(stem, " [1080p]", &titles), "");
            let _ = std::fs::remove_dir_all(&root);
        }
    }

    /// Multi-episode posts, Sonarr's conventions: distinct titles join
    /// with " + ", and a post carrying both halves of a two-parter says
    /// the shared title once.
    #[test]
    fn multi_episode_titles_join_and_two_parters_collapse() {
        let seg = |stem: &str, titles: &EpisodeTitles| {
            let base = tv_path(stem).and_then(|(_, b)| b).unwrap();
            titles.segment(stem, &base, " [1080p]")
        };

        let distinct = titles_of(&[(1, 1, "Pilot"), (1, 2, "Second Chances")]);
        assert_eq!(
            seg("My.Show.S01E01E02.1080p.WEB-GRP", &distinct),
            " - Pilot + Second Chances"
        );
        // The other spelling of the same range.
        assert_eq!(
            seg("My.Show.S01E01-E02.1080p.WEB-GRP", &distinct),
            " - Pilot + Second Chances"
        );

        // Two-parters, in each spelling the providers use.
        for pair in [
            ("The Ceremony (1)", "The Ceremony (2)"),
            ("The Ceremony: Part 1", "The Ceremony: Part 2"),
            ("The Ceremony, Part One", "The Ceremony, Part Two"),
            ("The Ceremony - Part I", "The Ceremony - Part II"),
        ] {
            let t = titles_of(&[(1, 1, pair.0), (1, 2, pair.1)]);
            assert_eq!(
                seg("My.Show.S01E01E02.1080p.WEB-GRP", &t),
                " - The Ceremony",
                "{pair:?} should collapse to the shared title"
            );
        }

        // A title that merely starts with "Part" is a title.
        let t = titles_of(&[(1, 1, "Part of the Plan"), (1, 2, "Parting Shot")]);
        assert_eq!(
            seg("My.Show.S01E01E02.1080p.WEB-GRP", &t),
            " - Part of the Plan + Parting Shot"
        );

        // A two-parter with nothing BUT the marker keeps both halves:
        // stripping leaves nothing to say.
        let t = titles_of(&[(1, 1, "Part 1"), (1, 2, "Part 2")]);
        assert_eq!(
            seg("My.Show.S01E01E02.1080p.WEB-GRP", &t),
            " - Part 1 + Part 2"
        );

        // A repeated title is said once; a half-known double uses what
        // the cache has.
        let t = titles_of(&[(1, 1, "Reunion"), (1, 2, "Reunion")]);
        assert_eq!(seg("My.Show.S01E01E02.1080p.WEB-GRP", &t), " - Reunion");
        let t = titles_of(&[(1, 1, "Reunion")]);
        assert_eq!(seg("My.Show.S01E01E02.1080p.WEB-GRP", &t), " - Reunion");
    }

    /// An episode title is a third party's free text. It reaches a
    /// filename, so it gets the same treatment the show name does.
    #[test]
    fn a_hostile_episode_title_is_still_a_safe_filename() {
        let seg = |title: &str| {
            let t = titles_of(&[(1, 2, title)]);
            t.segment("My.Show.S01E02.1080p.WEB-GRP", "My Show - S01E02", "")
        };
        // Path separators cannot survive: this is one component.
        assert_eq!(seg("9/11: The Long Road"), " - 9 11 - The Long Road");
        assert_eq!(seg("Up\\Down"), " - Up Down");
        // Windows strips a trailing dot silently, so we strip it first.
        assert_eq!(seg("The End."), " - The End");
        // Colons expand the way Sonarr's "Smart" rule does.
        assert_eq!(seg("Endgame: Part of It"), " - Endgame - Part of It");
        // Non-ASCII is a title, not a hazard.
        assert_eq!(seg("Le Déluge"), " - Le Déluge");
        // Nothing nameable survives - no segment, and no bare separator
        // left dangling in the filename.
        assert_eq!(seg("///"), "");
        assert_eq!(seg("   "), "");
    }

    /// The filename budget. A title is the part that gives way: the
    /// episode base identifies the episode and the suffix tells one
    /// release from another, so neither can be shortened.
    #[test]
    fn a_long_episode_title_gives_way_to_the_name_around_it() {
        let long = "The Extremely Long Episode Title That Simply Refuses To Stop Going On \
                    And On About Whatever It Is That Happened In This Particular Instalment \
                    Of The Programme Which Nobody Could Reasonably Be Expected To Read All \
                    The Way Through In A File Manager Window";
        let titles = titles_of(&[(1, 2, long)]);
        let base = "My Show - S01E02";
        let seg = titles.segment("My.Show.S01E02.1080p.WEB-GRP", base, " [1080p]");
        let name = format!("{base}{seg} [1080p].mkv");
        assert!(
            name.len() <= COMPONENT_BYTES,
            "{} bytes is over the component limit",
            name.len()
        );
        assert!(name.ends_with(" [1080p].mkv"), "suffix and extension kept");
        assert!(
            long.starts_with(seg.trim_start_matches(TITLE_SEP)),
            "the kept part is a prefix of the real title"
        );
        assert!(
            !seg.ends_with(' ') && long[seg.len() - TITLE_SEP.len()..].starts_with(' '),
            "cut at a word boundary: {seg:?}"
        );

        // A single word longer than the whole budget is cut rather than
        // dropped - something of the title is better than none.
        let wall = "A".repeat(400);
        let titles = titles_of(&[(1, 2, &wall)]);
        let seg = titles.segment("My.Show.S01E02.1080p.WEB-GRP", base, " [1080p]");
        assert!(!seg.is_empty() && seg.len() < 240);

        // No room at all: the title is dropped, never the extension.
        let base = "X".repeat(240);
        let titles = titles_of(&[(1, 2, "Anything")]);
        assert_eq!(
            titles.segment("My.Show.S01E02.1080p.WEB-GRP", &base, ""),
            ""
        );
    }

    /// A title can contain anything a release name contains - "1080",
    /// "S02", a group-shaped word. Filing must still find the same
    /// episode when it re-reads the name it wrote, or a second
    /// post-processing pass (a password unlock re-runs one) would rename
    /// the file again.
    #[test]
    fn a_title_full_of_release_words_does_not_confuse_the_next_parse() {
        let root = scratch("eproundtrip");
        let stem = "My.Show.S01E02.1080p.WEB.x264-TEST";
        let out = root.join("job");
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(out.join(format!("{stem}.mkv")), b"v").unwrap();
        let titles = titles_of(&[(1, 2, "1080 Miles to S02 BluRay")]);

        assert_eq!(tv_rename(&out, stem, " [1080p]", &titles), 1);
        let filed = out.join("My Show - S01E02 - 1080 Miles to S02 BluRay [1080p].mkv");
        assert!(filed.is_file(), "{:?}", std::fs::read_dir(&out).unwrap());

        // Re-reading our own output finds the SAME episode, so the
        // second pass is a no-op rather than a second rename.
        let written = filed.file_stem().unwrap().to_string_lossy().into_owned();
        assert_eq!(
            tv_path(&written).and_then(|(_, b)| b).as_deref(),
            Some("My Show - S01E02"),
            "the episode base survives its own title"
        );
        assert_eq!(tv_rename(&out, stem, " [1080p]", &titles), 0, "idempotent");
        assert!(filed.is_file());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The reason the title is RECORDED rather than recomputed, and the
    /// reason `is_rename_tail` refuses a bare " - Something" tail: with
    /// titles on, our filename is the same shape as the one Sonarr and
    /// Plex write, and the user's own copy of the episode is sitting in
    /// the same folder. Only the file we wrote may be touched.
    #[test]
    fn the_users_own_copy_of_the_episode_is_never_ours() {
        let _steady = trash_globals_steady();
        let root = scratch("eptheirs");
        let season = root.join("The Bear/Season 03");
        std::fs::create_dir_all(&season).unwrap();
        let theirs = season.join("The Bear - S03E05 - Children.mkv");
        let ours = season.join("The Bear - S03E05 - Children [1080p].mkv");
        // Their whole-season library, in Sonarr's default layout.
        let sibling = season.join("The Bear - S03E06 - Doors.mkv");
        for f in [&theirs, &ours, &sibling] {
            std::fs::write(f, b"x").unwrap();
        }

        let stem = "The.Bear.S03E05.1080p.WEB.h264-GRP";
        let tail = FiledTail {
            title: " - Children".into(),
            suffix: " [1080p]".into(),
        };
        assert_eq!(
            find_filed_episode_media(&season, stem, &tail).as_deref(),
            Some(ours.as_path()),
            "play serves the copy we downloaded, not theirs"
        );
        assert_eq!(delete_filed_episode(&season, stem, &tail).removed, 1);
        assert!(!ours.exists(), "ours went");
        assert!(theirs.exists(), "their copy of the same episode survives");
        assert!(sibling.exists(), "and so does the sibling episode");

        // A record with no title recorded (filed before this existed, or
        // with the setting off) matches nothing here rather than
        // guessing - a leftover, never somebody else's episode.
        assert_eq!(
            delete_filed_episode(&season, stem, &FiledTail::suffix(" [1080p]")).removed,
            0
        );
        assert!(theirs.exists() && sibling.exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A season pack renames per episode, so each file gets ITS OWN
    /// title - the job's stem names no single episode and cannot answer
    /// for any of them.
    #[test]
    fn a_season_pack_gives_every_episode_its_own_title() {
        let root = scratch("eppack");
        let stem = "My.Show.S01.1080p.WEB.x264-TEST";
        let out = root.join("tv").join(stem);
        std::fs::create_dir_all(&out).unwrap();
        for f in [
            "My.Show.S01E01.1080p.WEB.x264-TEST",
            "My.Show.S01E02.1080p.WEB.x264-TEST",
        ] {
            std::fs::write(out.join(format!("{f}.mkv")), b"v").unwrap();
        }
        let titles = titles_of(&[(1, 1, "Pilot"), (1, 2, "The Ceremony")]);

        let dest = tv_organize(&root.join("tv"), stem, &out, " [1080p]", &titles).unwrap();
        assert!(dest.join("My Show - S01E01 - Pilot [1080p].mkv").is_file());
        assert!(
            dest.join("My Show - S01E02 - The Ceremony [1080p].mkv")
                .is_file()
        );
        // The pack itself records no title: it owns no single episode
        // name, and `filed_bases` refuses it for the same reason.
        assert_eq!(filed_title_segment(stem, " [1080p]", &titles), "");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A library filed BEFORE the show name reshaped ("Star Trek
    /// Discovery", when ':' was blanked rather than expanded) is still on
    /// disk under the old spelling, and delete and play recompute the
    /// base at call time. Both must still recognise it, and a new episode
    /// must land in that folder rather than starting a second tree.
    #[test]
    fn a_show_filed_under_the_old_spelling_is_still_ours() {
        let _steady = trash_globals_steady();
        let root = scratch("tvlegacy");
        let stem = "Star Trek: Discovery S01E05 1080p WEB h264-GRP";
        let tv = root.join("tv");
        let old = tv.join("Star Trek Discovery").join("Season 01");
        std::fs::create_dir_all(&old).unwrap();
        let filed = old.join("Star Trek Discovery - S01E05 [1080p].mkv");
        std::fs::write(&filed, b"v").unwrap();

        // Play finds the episode it filed, under either spelling.
        assert_eq!(
            find_filed_episode_media(&old, stem, &FiledTail::suffix(" [1080p]")).as_ref(),
            Some(&filed)
        );

        // A later episode joins the show it belongs to.
        let out = root.join("job");
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(out.join("blob.mkv"), b"v").unwrap();
        let dest = tv_organize(
            &tv,
            "Star Trek: Discovery S01E06 1080p WEB h264-GRP",
            &out,
            " [1080p]",
            &EpisodeTitles::default(),
        )
        .unwrap();
        assert_eq!(dest, old);
        assert!(
            old.join("Star Trek Discovery - S01E06 [1080p].mkv")
                .exists()
        );
        assert!(!tv.join("Star Trek - Discovery").exists(), "no second tree");

        // A NEW season of the same show joins it as well: the folder that
        // decides is the show's, not the season's.
        let out = root.join("job2");
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(out.join("blob.mkv"), b"v").unwrap();
        let dest = tv_organize(
            &tv,
            "Star Trek: Discovery S02E01 1080p WEB h264-GRP",
            &out,
            " [1080p]",
            &EpisodeTitles::default(),
        )
        .unwrap();
        assert_eq!(dest, tv.join("Star Trek Discovery").join("Season 02"));
        assert!(
            !tv.join("Star Trek - Discovery").exists(),
            "still no second tree"
        );

        // ...and delete-with-files removes the old-spelling episode
        // rather than reporting zero and leaving it behind. E06 stays.
        assert_eq!(
            delete_filed_episode(&old, stem, &FiledTail::suffix(" [1080p]")).removed,
            1
        );
        assert!(!filed.exists());
        assert!(
            old.join("Star Trek Discovery - S01E06 [1080p].mkv")
                .exists()
        );

        // Nothing on disk to inherit: today's spelling is what we write.
        let fresh = scratch("tvfresh");
        let out = fresh.join("job");
        std::fs::create_dir_all(&out).unwrap();
        std::fs::write(out.join("blob.mkv"), b"v").unwrap();
        let dest = tv_organize(
            &fresh.join("tv"),
            stem,
            &out,
            " [1080p]",
            &EpisodeTitles::default(),
        )
        .unwrap();
        assert_eq!(
            dest,
            fresh
                .join("tv")
                .join("Star Trek - Discovery")
                .join("Season 01")
        );
        assert!(
            dest.join("Star Trek - Discovery - S01E05 [1080p].mkv")
                .exists()
        );
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&fresh);
    }

    /// Scratch dir without pulling a dev-dependency into the binary
    /// target (smart.rs's tests live in the bin, which has none).
    #[test]
    fn the_container_outranks_the_name() {
        // The main video's own header answers; the name's claim is the
        // caller's business (finalize_names decides what to do with a
        // disagreement).
        let dir = scratch("measured");
        std::fs::write(
            dir.join("Example.Movie.2024.1080p.mkv"),
            nzbkit::mkv::test_mux(Some(5400.0), Some((1280, 720))),
        )
        .unwrap();
        assert_eq!(measured_res(&dir), Some("720p"));

        // Non-Matroska main video: never probed, never guessed.
        let dir = scratch("measured-mp4");
        std::fs::write(
            dir.join("Example.Movie.2024.mp4"),
            b"\x00\x00\x00\x20ftypisom",
        )
        .unwrap();
        assert_eq!(measured_res(&dir), None);

        // A Matroska that does not parse keeps the claim standing.
        let dir = scratch("measured-junk");
        std::fs::write(dir.join("Example.Movie.2024.mkv"), b"not matroska").unwrap();
        assert_eq!(measured_res(&dir), None);
    }

    #[test]
    fn a_sample_name_running_like_an_episode_survives() {
        let dir = scratch("sample-veto");
        // Small beside the feature, "sample" in the name - but its own
        // header says 50 minutes. That is an episode, not a clip.
        let episode = dir.join("Show.S01E02.sample.mkv");
        std::fs::write(
            &episode,
            nzbkit::mkv::test_mux(Some(50.0 * 60.0), Some((1920, 1080))),
        )
        .unwrap();
        assert!(!is_deletable_sample(&episode, 1 << 30));

        // A real 45-second clip with the same shape still goes.
        let clip = dir.join("Show.S01E02.sample2.mkv");
        std::fs::write(&clip, nzbkit::mkv::test_mux(Some(45.0), Some((1920, 1080)))).unwrap();
        assert!(is_deletable_sample(&clip, 1 << 30));

        // No readable duration: the old name+size verdict stands.
        let blob = dir.join("Show.S01E02.sample3.mkv");
        std::fs::write(&blob, b"junk").unwrap();
        assert!(is_deletable_sample(&blob, 1 << 30));
    }

    fn scratch(tag: &str) -> PathBuf {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let d =
            std::env::temp_dir().join(format!("nzbfast-smart-{}-{tag}-{n}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// The 1.0.9 report: an F1 round finished as
    /// "1fRbH6e0eX8v5hv7fSyXgBb.mkv" with every rename option ticked.
    /// movie_name declines on event posts by design (renaming each round
    /// to "Formula1 (2026)" would collide), but declining must not leave
    /// an obfuscated stem when the release name is right there.
    #[test]
    fn obfuscated_video_takes_the_release_name() {
        let out = &scratch("f1");
        let rel =
            "Formula1.2026.Round11.Hungary.Race.F1TV.WEB-DL.2160p.HLG.H265.DDP5.1.English-MWR";
        std::fs::write(out.join("1fRbH6e0eX8v5hv7fSyXgBb.mkv"), b"video").unwrap();
        std::fs::write(out.join("1fRbH6e0eX8v5hv7fSyXgBb.en.srt"), b"subs").unwrap();

        assert!(rename_obfuscated_video(out, rel));
        assert!(
            out.join(format!("{rel}.mkv")).exists(),
            "video takes the release name"
        );
        assert!(
            out.join(format!("{rel}.en.srt")).exists(),
            "sidecar follows, keeping .en"
        );
        assert!(!out.join("1fRbH6e0eX8v5hv7fSyXgBb.mkv").exists());
    }

    #[test]
    fn de_obfuscation_leaves_named_and_ambiguous_payloads_alone() {
        let out = &scratch("keep");
        let rel = "Formula1.2026.Round11.Hungary.Race.F1TV.WEB-DL.2160p-MWR";

        // A stem the poster actually chose is never overwritten.
        let posted = "Formula1.2026.Round11.Hungary.Race.1080p.mkv";
        std::fs::write(out.join(posted), b"v").unwrap();
        assert!(!rename_obfuscated_video(out, rel));
        assert!(out.join(posted).exists());

        // Two videos: we cannot tell which is "the" file, so do nothing.
        std::fs::remove_file(out.join(posted)).unwrap();
        std::fs::write(out.join("aQ7bZ1x9KpLmNv.mkv"), b"v").unwrap();
        std::fs::write(out.join("bR8cY2y0LqMnOw.mkv"), b"v").unwrap();
        assert!(!rename_obfuscated_video(out, rel));
        assert!(out.join("aQ7bZ1x9KpLmNv.mkv").exists());

        // An obfuscated RELEASE name is no better than the file's own.
        std::fs::remove_file(out.join("bR8cY2y0LqMnOw.mkv")).unwrap();
        assert!(!rename_obfuscated_video(out, "n1iY94U6fTpMVY9GPD"));
        assert!(out.join("aQ7bZ1x9KpLmNv.mkv").exists());

        // A run-together title that happens to be 32 characters long is
        // a name somebody chose, not an md5 - the hash shape is hex.
        let out = &scratch("keep32");
        let long = "ThelordoftheringsReturnoftheking.mkv";
        std::fs::write(out.join(long), b"v").unwrap();
        assert!(!rename_obfuscated_video(out, rel));
        assert!(out.join(long).exists());
    }

    /// The question synthesised naming asks BEFORE it spends a disk read
    /// or a request: is there anything here still wearing a hash?
    ///
    /// It has to answer exactly what `rename_obfuscated_video` fires on,
    /// because the two now share an apply path - a disagreement would
    /// mean the identifier looked up a film it could never rename, or
    /// skipped one it could.
    #[test]
    fn nameless_video_finds_only_what_is_actually_nameless() {
        // Obfuscated stem: nameless.
        let out = &scratch("nameless-hash");
        std::fs::write(out.join("n1iY94U6fTpMVY9GPD.mkv"), b"v").unwrap();
        assert_eq!(
            nameless_video(out).unwrap().file_name().unwrap(),
            "n1iY94U6fTpMVY9GPD.mkv"
        );

        // Encoder default: nameless too.
        let out = &scratch("nameless-generic");
        std::fs::write(out.join("movie.mp4"), b"v").unwrap();
        assert!(nameless_video(out).is_some());

        // A name a human chose stands, whatever a catalogue might offer.
        let out = &scratch("nameless-named");
        std::fs::write(out.join("Example.Movie.2024.1080p.WEB.x264-GRP.mkv"), b"v").unwrap();
        assert_eq!(nameless_video(out), None);

        // Two videos: we cannot tell which is the feature, so neither is
        // renamed and no lookup is worth making.
        let out = &scratch("nameless-two");
        std::fs::write(out.join("aaaaaaaaaaaaaaaaaa.mkv"), b"v").unwrap();
        std::fs::write(out.join("bbbbbbbbbbbbbbbbbb.mkv"), b"v").unwrap();
        assert_eq!(nameless_video(out), None);

        // A sample clip is not the feature and never counts as one.
        let out = &scratch("nameless-sample");
        std::fs::write(out.join("n1iY94U6fTpMVY9GPD.mkv"), b"v").unwrap();
        std::fs::write(out.join("sample.mkv"), b"v").unwrap();
        assert!(nameless_video(out).is_some());

        // Nothing video-shaped at all.
        let out = &scratch("nameless-none");
        std::fs::write(out.join("readme.nfo"), b"n").unwrap();
        assert_eq!(nameless_video(out), None);
    }

    /// An identified film's name reaches the payload through the bare
    /// apply path, NOT through the release-name one - "Supergirl 2026"
    /// carries no resolution, source or group, so `names_the_release`
    /// refuses it and always would. The gate is what earned it.
    #[test]
    fn an_identified_title_renames_where_a_release_name_could_not() {
        let title = "Supergirl 2026";
        let out = &scratch("identified");
        std::fs::write(out.join("n1iY94U6fTpMVY9GPD.mkv"), b"v").unwrap();
        std::fs::write(out.join("n1iY94U6fTpMVY9GPD.en.srt"), b"s").unwrap();

        // The release-name path declines it, as designed.
        assert!(!rename_obfuscated_video(out, title));
        assert!(out.join("n1iY94U6fTpMVY9GPD.mkv").exists(), "nothing moved");

        // The identified path applies it, sidecar and all.
        assert!(rename_nameless_video(out, title));
        assert!(out.join("Supergirl 2026.mkv").exists());
        assert!(
            out.join("Supergirl 2026.en.srt").exists(),
            "sidecar follows"
        );

        // ...and it still refuses a payload that was never nameless, so
        // a wrong verdict cannot overwrite a name the poster gave.
        let out = &scratch("identified-named");
        std::fs::write(out.join("Example.Movie.2024.1080p.WEB-GRP.mkv"), b"v").unwrap();
        assert!(!rename_nameless_video(out, title));
        assert!(out.join("Example.Movie.2024.1080p.WEB-GRP.mkv").exists());
    }

    /// A stem that is not obfuscated but says nothing - the encoder's
    /// default output name - is the other half of the same problem, and
    /// the widened gate has to pay for itself on the release side.
    #[test]
    fn de_obfuscation_replaces_a_generic_stem() {
        let rel = "Example.Movie.2024.1080p.WEB.x264-GRP";

        // "movie.mkv" beside a release name carrying real facts.
        let out = &scratch("generic");
        std::fs::write(out.join("movie.mkv"), b"v").unwrap();
        std::fs::write(out.join("movie.en.srt"), b"s").unwrap();
        assert!(rename_obfuscated_video(out, rel));
        assert!(out.join(format!("{rel}.mkv")).exists());
        assert!(
            out.join(format!("{rel}.en.srt")).exists(),
            "sidecar follows"
        );

        for stem in ["video", "FILM", "output", "encoded", "media", "1", "07"] {
            let out = &scratch("generic-list");
            std::fs::write(out.join(format!("{stem}.mkv")), b"v").unwrap();
            assert!(rename_obfuscated_video(out, rel), "{stem}");
            assert!(out.join(format!("{rel}.mkv")).exists(), "{stem}");
        }

        // Negative: a real name is not generic, so it stands - even
        // though it names the same release we would have written.
        let out = &scratch("generic-real");
        std::fs::write(out.join("Example.Movie.2024.mkv"), b"v").unwrap();
        assert!(!rename_obfuscated_video(out, rel));
        assert!(out.join("Example.Movie.2024.mkv").exists());

        // Negative: near-misses of the generic list keep their names -
        // the list is exact, not a prefix or substring match.
        for stem in [
            "movie2",
            "video_final",
            "Movie 2024",
            "encode",
            "media server",
        ] {
            let out = &scratch("generic-near");
            std::fs::write(out.join(format!("{stem}.mkv")), b"v").unwrap();
            assert!(!rename_obfuscated_video(out, rel), "{stem}");
            assert!(out.join(format!("{stem}.mkv")).exists(), "{stem}");
        }
    }

    /// A one-digit generic stem is a PREFIX of its numbered neighbours,
    /// so the sidecar carry has to stop at an extension boundary: "1.mkv"
    /// owns "1.srt" and nothing else. Before the boundary check "10.srt"
    /// came out as "…-GRP0.srt" - a mangled name for a subtitle that was
    /// never this video's.
    #[test]
    fn sidecars_are_carried_only_at_an_extension_boundary() {
        let rel = "Example.Movie.2024.1080p.WEB.x264-GRP";
        let out = &scratch("sidecar-boundary");
        std::fs::write(out.join("1.mkv"), b"v").unwrap();
        std::fs::write(out.join("1.srt"), b"s").unwrap();
        std::fs::write(out.join("1.en.srt"), b"s").unwrap();
        std::fs::write(out.join("10.srt"), b"s").unwrap();
        std::fs::write(out.join("12.srt"), b"s").unwrap();

        assert!(rename_obfuscated_video(out, rel));
        assert!(out.join(format!("{rel}.mkv")).exists());
        assert!(
            out.join(format!("{rel}.srt")).exists(),
            "its own sidecar follows"
        );
        assert!(
            out.join(format!("{rel}.en.srt")).exists(),
            "language tail kept"
        );
        // The neighbours are untouched, and no fused name was emitted.
        assert!(out.join("10.srt").exists());
        assert!(out.join("12.srt").exists());
        assert!(!out.join(format!("{rel}0.srt")).exists());
        assert!(!out.join(format!("{rel}2.srt")).exists());

        // Same rule on the movie path, which had the latent form.
        let parent = &scratch("sidecar-boundary-movie");
        let out = &parent.join("job");
        std::fs::create_dir_all(out).unwrap();
        std::fs::write(out.join("1.mkv"), b"v").unwrap();
        std::fs::write(out.join("1.srt"), b"s").unwrap();
        std::fs::write(out.join("10.srt"), b"s").unwrap();
        rename_movie(parent, out, "Example Movie (2024)");
        let dest = parent.join("Example Movie (2024)");
        assert!(dest.join("Example Movie (2024).srt").exists());
        assert!(dest.join("10.srt").exists());
        assert!(!dest.join("Example Movie (2024)0.srt").exists());
    }

    /// The widened firing condition is only safe because the release
    /// name now has to earn it: a title with no resolution, no source
    /// and no group is a folder label, not a release, and we decline.
    #[test]
    fn a_factless_release_name_never_renames() {
        for rel in ["Example Movie", "Some Show", "Holiday 2024"] {
            let out = &scratch("factless");
            std::fs::write(out.join("movie.mkv"), b"v").unwrap();
            assert!(!rename_obfuscated_video(out, rel), "{rel}");
            assert!(out.join("movie.mkv").exists(), "{rel}");

            // Same gate, obfuscated stem: widening did not weaken the
            // long-standing path, it tightened it.
            let out = &scratch("factless-obf");
            std::fs::write(out.join("1fRbH6e0eX8v5hv7fSyXgBb.mkv"), b"v").unwrap();
            assert!(!rename_obfuscated_video(out, rel), "{rel}");
        }

        // Positive control: one hard fact is enough.
        for rel in [
            "Example Movie 1080p",
            "Example Movie WEB-DL",
            "Example.Movie-GRP",
        ] {
            let out = &scratch("factful");
            std::fs::write(out.join("movie.mkv"), b"v").unwrap();
            assert!(rename_obfuscated_video(out, rel), "{rel}");
        }
    }

    #[test]
    fn name_password_conventions() {
        // Double brace (SAB/NZBGet) - the long-standing convention.
        assert_eq!(
            name_password("Rel.Name.2020{{s3cret}}"),
            Some(("s3cret".into(), "Rel.Name.2020".into()))
        );
        // §7b: single brace and password= are recognized AND stripped so
        // the wrapper can't leak a password into the output folder name.
        assert_eq!(
            name_password("Rel.Name.2020{s3cret}"),
            Some(("s3cret".into(), "Rel.Name.2020".into()))
        );
        assert_eq!(
            name_password("Rel.Name.2020 password=s3cret"),
            Some(("s3cret".into(), "Rel.Name.2020".into()))
        );
        assert_eq!(
            name_password("Rel.Name.2020{password=s3cret}"),
            Some(("s3cret".into(), "Rel.Name.2020".into()))
        );
        // Double brace wins when nested; plain names pass through.
        assert_eq!(name_password("Rel{{a}}").map(|(p, _)| p), Some("a".into()));
        assert_eq!(name_password("Plain.Release.2020.1080p"), None);
        assert_eq!(name_password("Rel{}"), None); // empty braces = nothing
    }
}

#[cfg(test)]
mod trash_tests {

    /// A removal only claims "recoverable" when the file was FOUND in a
    /// Trash afterwards.
    ///
    /// The backend returning Ok is not that claim: macOS has two routes
    /// and both can report success while deleting outright, which is how
    /// a 14 GB download was reported restorable on 4 Aug when it was
    /// gone. This pins the check that catches it - a name that is in no
    /// Trash answers false - and the permanent-delete arm, which must
    /// never claim `Trashed`.
    #[test]
    fn a_removal_reports_what_it_actually_did() {
        let dir = std::env::temp_dir().join(format!("nzbfast-removed-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // An opt-out delete is permanent by definition and says so.
        let f = dir.join("plain.bin");
        std::fs::write(&f, b"x").unwrap();
        assert_eq!(
            super::remove_user_file(&f, false).unwrap(),
            super::Removed::Gone,
            "a permanent delete must never report itself recoverable"
        );
        assert!(!f.exists());

        // A path that was never there is gone, not trashed - there is
        // nothing to restore and nothing may promise otherwise.
        assert_eq!(
            super::remove_user_file(&dir.join("never-existed.bin"), true).unwrap(),
            super::Removed::Gone
        );

        // The verification itself: a file sitting in an ordinary
        // directory has not landed in any Trash.
        #[cfg(target_os = "macos")]
        {
            let never = dir.join("nzbfast-not-in-any-trash-9f3a.bin");
            std::fs::write(&never, b"x").unwrap();
            assert!(
                !super::landed_in_a_trash(&never, &super::trash_snapshot(&never)),
                "a file that was never trashed must not read as recoverable"
            );

            // A NAME that was already in the Trash is not evidence about
            // THIS delete. Simulated by putting the would-be match into
            // the before-snapshot: on a `noowners` volume Finder deletes
            // outright and reports success, and a `Movie.mkv` binned
            // last week then made the destroyed one read as restorable.
            if let Some(home) = std::env::var_os("HOME") {
                let root = std::path::PathBuf::from(home).join(".Trash");
                let planted = root.join("nzbfast-stale-trash-probe-4b21.bin");
                if std::fs::create_dir_all(&root).is_ok()
                    && std::fs::write(&planted, b"old").is_ok()
                {
                    let target = dir.join("nzbfast-stale-trash-probe-4b21.bin");
                    let before = super::trash_snapshot(&target);
                    assert!(
                        !super::landed_in_a_trash(&target, &before),
                        "an entry that was ALREADY in the Trash must not \
                         vouch for a delete that just happened"
                    );
                    // And a genuinely new arrival still counts.
                    assert!(
                        super::landed_in_a_trash(&target, &super::TrashBefore::default()),
                        "a newly arrived entry must still read as recoverable"
                    );
                    let _ = std::fs::remove_file(&planted);
                }
            }
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
    use super::*;

    /// Did a file this test just deleted actually reach the Trash, under
    /// the name it had? Purges it when it did, so the suite never leaves
    /// fixtures in the developer's real Trash. `None` on a platform with no
    /// way to look.
    ///
    /// Asked per platform because "the Trash" is three different
    /// mechanisms, and the old version of this test assumed one of them:
    /// `std::env::var("HOME").unwrap()` joined with `.Trash`. HOME is not
    /// set on Windows - USERPROFILE is, which is why the product itself
    /// reads that - so the test panicked with `NotPresent` there before it
    /// asserted anything, and `~/.Trash` would have been the wrong place to
    /// look anyway. Windows has a real recoverable delete: `trash::delete`
    /// moves the file to the Recycle Bin, verified on x86-64 Windows, where
    /// `os_limited::list()` returns it with its original_parent intact. So
    /// this checks the behaviour there rather than gating the test away.
    /// `os_limited` covers the freedesktop platforms too, which makes the
    /// Linux leg a real assertion instead of the vacuous one it was.
    fn still_recoverable(name: &str) -> Option<bool> {
        // macOS: `trash` has no enumeration API there, so read the folder.
        #[cfg(target_os = "macos")]
        {
            let trashed = std::path::PathBuf::from(std::env::var("HOME").expect("HOME on macOS"))
                .join(".Trash")
                .join(name);
            let found = trashed.exists();
            let _ = std::fs::remove_file(&trashed);
            Some(found)
        }
        // Windows' Recycle Bin and the freedesktop trash directories, read
        // through the real thing. The cfg mirrors `trash::os_limited`'s own.
        #[cfg(any(
            target_os = "windows",
            all(
                unix,
                not(target_os = "macos"),
                not(target_os = "ios"),
                not(target_os = "android")
            )
        ))]
        {
            // `expect`, not `.ok()?`: a platform that HAS an enumeration
            // API and cannot answer is a finding, not a reason to skip. We
            // have already asserted the delete succeeded, so the trash
            // exists - swallowing an error here would make the assertion
            // below silently vacuous, which is the failure mode this whole
            // test is guarding against.
            let items = trash::os_limited::list().expect("enumerate the trash");
            let mine: Vec<_> = items.into_iter().filter(|i| i.name == *name).collect();
            let found = !mine.is_empty();
            let _ = trash::os_limited::purge_all(mine);
            Some(found)
        }
        #[cfg(not(any(
            target_os = "macos",
            target_os = "windows",
            all(
                unix,
                not(target_os = "macos"),
                not(target_os = "ios"),
                not(target_os = "android")
            )
        )))]
        {
            let _ = name;
            None
        }
    }

    /// Both halves in ONE test, and neither touches the process-global.
    ///
    /// `remove_user_file` takes the flag as an argument now, so the two
    /// cases are just two calls: nothing here can flip a sweep running in
    /// a parallel test, and nothing here leaves the flag somewhere the
    /// tests scheduled after it do not expect (this test used to restore
    /// it to TRUE, which turned the Trash ON for the rest of the process
    /// and made `sweep_junk_takes_the_emptied_sample_folder_too` fail
    /// depending on test order).
    #[test]
    fn a_junk_delete_is_recoverable_and_the_opt_out_is_not() {
        // This one really does reach the Trash, so it must not overlap a
        // test that latches the Trash off underneath it.
        let _serial = one_trash_test_at_a_time();
        let dir = std::env::temp_dir().join(format!("nzbfast-trash-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // Recoverable: the file leaves the download folder but is still
        // there to be put back. Asserting only that it is GONE would pass
        // just as well for a permanent delete, which is the whole point.
        let name = format!("nzbfast-trash-probe-{}.par2", std::process::id());
        let f = dir.join(&name);
        std::fs::write(&f, b"junk").unwrap();
        remove_user_file(&f, true).expect("trash delete");
        assert!(!f.exists(), "the file must leave the download folder");
        if let Some(found) = still_recoverable(&name) {
            // The file being GONE proves nothing on its own - a permanent
            // delete looks identical from the download folder. This is the
            // assertion that separates the two.
            assert!(
                found,
                "not recoverable: nothing named {name} reached the Trash"
            );
        }

        // Opted out: a real delete, not a silent Trash.
        let name2 = format!("nzbfast-notrash-probe-{}.par2", std::process::id());
        let g = dir.join(&name2);
        std::fs::write(&g, b"junk").unwrap();
        remove_user_file(&g, false).unwrap();
        assert!(!g.exists());
        if let Some(found) = still_recoverable(&name2) {
            assert!(!found, "opt-out still used the Trash");
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The directory delete behind "delete + files" and the watchlist
    /// delete_old upgrade: recoverable moves the WHOLE folder to the
    /// Trash as one restorable item, opt-out is a real remove_dir_all,
    /// and a directory that never existed is Ok (jobs that never
    /// downloaded have no folder).
    #[test]
    fn a_job_dir_delete_is_recoverable_and_the_opt_out_is_not() {
        let _serial = one_trash_test_at_a_time();
        let root = std::env::temp_dir().join(format!("nzbfast-trashdir-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);

        let name = format!("nzbfast-trashdir-probe-{}", std::process::id());
        let d = root.join(&name);
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("payload.mkv"), b"x").unwrap();
        remove_user_dir(&d, true).expect("trash delete");
        assert!(!d.exists(), "the folder must leave the download tree");
        if let Some(found) = still_recoverable(&name) {
            assert!(
                found,
                "not recoverable: nothing named {name} reached the Trash"
            );
        }
        // still_recoverable purges a FILE from the macOS Trash; a folder
        // needs the recursive form or the probe lingers there forever.
        #[cfg(target_os = "macos")]
        if let Ok(home) = std::env::var("HOME") {
            let _ = std::fs::remove_dir_all(std::path::Path::new(&home).join(".Trash").join(&name));
        }

        let name2 = format!("nzbfast-notrashdir-probe-{}", std::process::id());
        let g = root.join(&name2);
        std::fs::create_dir_all(&g).unwrap();
        std::fs::write(g.join("payload.mkv"), b"x").unwrap();
        remove_user_dir(&g, false).unwrap();
        assert!(!g.exists());
        if let Some(found) = still_recoverable(&name2) {
            assert!(!found, "opt-out still used the Trash");
        }

        // A directory that is not there is a finished delete, not an
        // error - remove_job_files runs on jobs that never started.
        remove_user_dir(&root.join("never-existed"), true).unwrap();
        remove_user_dir(&root.join("never-existed"), false).unwrap();

        let _ = std::fs::remove_dir_all(&root);
    }

    /// macOS's second route, exercised for real: `NSFileManager` must bin
    /// a file with no Finder involved, and `trash_delete_bounded` must
    /// reach it once the Finder latch is set.
    ///
    /// This is the fix for the live 3 Aug 2026 line, where Finder answered
    /// `-10010` for a directory on an external volume and the delete
    /// became permanent. Finder failing is not the same as having no
    /// Trash, and the volume's own `.Trashes` was there the whole time.
    ///
    /// The latch is process-global and never reset in production, so the
    /// test restores it by hand and serializes with the other latch tests.
    #[cfg(target_os = "macos")]
    #[test]
    fn the_volume_trash_takes_over_when_finder_will_not() {
        let _serial = one_trash_test_at_a_time();
        let dir = std::env::temp_dir().join(format!("nzbfast-nsfm-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        // Directly first: the route itself has to work before the
        // fall-through to it means anything.
        let name = format!("nzbfast-nsfm-probe-{}.par2", std::process::id());
        let f = dir.join(&name);
        std::fs::write(&f, b"junk").unwrap();
        trash_via_file_manager(&f).expect("NSFileManager must bin a file with no Finder");
        assert!(!f.exists());
        assert_eq!(
            still_recoverable(&name),
            Some(true),
            "NSFileManager did not put {name} anywhere recoverable"
        );

        // Then through the real entry point with Finder latched out, which
        // is the state a -10010 or a headless timeout leaves behind.
        let name2 = format!("nzbfast-nsfm-latched-{}.par2", std::process::id());
        let g = dir.join(&name2);
        std::fs::write(&g, b"junk").unwrap();
        let was_out = finder_is_out();
        FINDER_IS_OUT.store(true, std::sync::atomic::Ordering::Relaxed);
        let r = remove_user_file(&g, true);
        FINDER_IS_OUT.store(was_out, std::sync::atomic::Ordering::Relaxed);
        r.expect("a latched Finder must not stop the delete");
        assert!(!g.exists());
        assert_eq!(
            still_recoverable(&name2),
            Some(true),
            "with Finder out the delete went somewhere unrecoverable"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    // No test toggles TRASH any more, deliberately. Turning it on for even
    // one assertion turns it on for whatever sweep is running in parallel,
    // which empties that test's fixtures into the developer's real Trash.
    // The setting itself is one atomic store, and the sweeps now read it
    // once at their entry and pass the answer down (see `remove_user_file`).
}

/// Put the configured permissions on a finished download (#20).
///
/// `umask` is the same number the shell and the linuxserver containers
/// use, because that is what every guide about this prints: directories
/// get `0o777 & !umask`, files `0o666 & !umask`, so the recommended `002`
/// gives 775/664 and today's `0022` gives 755/644.
///
/// `root` is the job's final directory and is walked in full. `up_to` is
/// the download root, and the directories BETWEEN the two get the
/// directory mode as well - non-recursively, so nothing else living under
/// them is touched. That part is not decoration: to import by renaming,
/// an *arr has to unlink the job directory out of its parent, and unlink
/// needs write permission on the PARENT, not on the directory being
/// moved. Setting only the job's own tree produces a download the *arr
/// can read and still cannot import.
///
/// Errors are logged once and otherwise swallowed. A mode we could not
/// set is a slower import, while refusing to finish the job over it would
/// turn a permissions preference into a failed download.
#[cfg(unix)]
pub fn apply_out_umask(root: &std::path::Path, up_to: Option<&std::path::Path>, umask: u32) {
    use std::os::unix::fs::PermissionsExt;
    let dir_mode = 0o777 & !umask;
    let file_mode = 0o666 & !umask;
    let mut failed: Option<String> = None;
    let mut chmod = |p: &std::path::Path, mode: u32| {
        if let Err(e) = std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode))
            && failed.is_none()
        {
            failed = Some(format!("{}: {e}", p.display()));
        }
    };
    // The job's own tree.
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        chmod(&dir, dir_mode);
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for ent in rd.flatten() {
            let p = ent.path();
            // symlink_metadata: never follow a link out of the tree and
            // re-mode whatever it points at.
            match std::fs::symlink_metadata(&p) {
                Ok(m) if m.is_dir() => stack.push(p),
                Ok(m) if m.is_file() => chmod(&p, file_mode),
                _ => {}
            }
        }
    }
    // ...and every directory between it and the download root, so the
    // *arr can rename the job out of the one holding it.
    if let Some(stop) = up_to {
        let mut cur = root.parent();
        while let Some(p) = cur {
            if !p.starts_with(stop) {
                break;
            }
            chmod(p, dir_mode);
            if p == stop {
                break;
            }
            cur = p.parent();
        }
    }
    if let Some(first) = failed {
        tracing::warn!(target: "disk", "could not set output permissions ({first})");
    }
}

/// Windows has no mode bits; the setting is stored and reported so a
/// config survives a round trip through either platform.
#[cfg(not(unix))]
pub fn apply_out_umask(_root: &std::path::Path, _up_to: Option<&std::path::Path>, _umask: u32) {}

#[cfg(all(test, unix))]
mod out_umask_tests {
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    fn mode(p: &Path) -> u32 {
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    fn scratch(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("nzbfast-umask-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// The whole job tree, at both depths, files and directories.
    #[test]
    fn the_job_tree_gets_the_configured_modes() {
        let root = scratch("tree");
        let out = root.join("downloads");
        let job = out.join("tv").join("Show.S01E01");
        std::fs::create_dir_all(job.join("Subs")).unwrap();
        std::fs::write(job.join("ep.mkv"), b"x").unwrap();
        std::fs::write(job.join("Subs").join("en.srt"), b"x").unwrap();
        for p in [
            &job,
            &job.join("Subs"),
            &job.join("ep.mkv"),
            &job.join("Subs").join("en.srt"),
        ] {
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700)).unwrap();
        }

        super::apply_out_umask(&job, Some(&out), 0o002);

        assert_eq!(mode(&job), 0o775, "job dir");
        assert_eq!(mode(&job.join("Subs")), 0o775, "nested dir");
        assert_eq!(mode(&job.join("ep.mkv")), 0o664, "file");
        assert_eq!(mode(&job.join("Subs").join("en.srt")), 0o664, "nested file");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The reason the parent walk exists: an *arr imports by renaming the
    /// job directory out of its parent, and unlink needs write on the
    /// PARENT. A version that only did the job's own tree would leave a
    /// download that is readable and still cannot be imported.
    #[test]
    fn the_parents_up_to_the_download_root_are_opened_too() {
        let root = scratch("parents");
        let out = root.join("downloads");
        let job = out.join("tv").join("Show.S01E01");
        std::fs::create_dir_all(&job).unwrap();
        for p in [&out, &out.join("tv")] {
            std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        // Above the download root, and none of our business.
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();

        super::apply_out_umask(&job, Some(&out), 0o002);

        assert_eq!(mode(&out.join("tv")), 0o775, "category dir");
        assert_eq!(mode(&out), 0o775, "download root");
        assert_eq!(
            mode(&root),
            0o700,
            "the walk climbed PAST the download root"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// A sibling under the same parents must be left exactly as it was:
    /// the parent walk is non-recursive on purpose.
    #[test]
    fn a_neighbouring_job_is_not_touched() {
        let root = scratch("sibling");
        let out = root.join("downloads");
        let mine = out.join("tv").join("Mine");
        let theirs = out.join("tv").join("Theirs");
        std::fs::create_dir_all(&mine).unwrap();
        std::fs::create_dir_all(&theirs).unwrap();
        std::fs::write(theirs.join("keep.mkv"), b"x").unwrap();
        std::fs::set_permissions(&theirs, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(
            theirs.join("keep.mkv"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();

        super::apply_out_umask(&mine, Some(&out), 0o002);

        assert_eq!(mode(&theirs), 0o700, "a sibling job was re-moded");
        assert_eq!(mode(&theirs.join("keep.mkv")), 0o600, "a sibling's file");
        let _ = std::fs::remove_dir_all(&root);
    }

    /// 022 is what a container already gives, so choosing it must produce
    /// exactly the modes that install has today - the proof that the
    /// default-off path and the explicit-022 path agree.
    #[test]
    fn the_container_default_reproduces_todays_modes() {
        let root = scratch("default");
        let job = root.join("downloads").join("Job");
        std::fs::create_dir_all(&job).unwrap();
        std::fs::write(job.join("a.mkv"), b"x").unwrap();

        super::apply_out_umask(&job, None, 0o022);

        assert_eq!(mode(&job), 0o755);
        assert_eq!(mode(&job.join("a.mkv")), 0o644);
        let _ = std::fs::remove_dir_all(&root);
    }
}

// Child module file, not inline: smart.rs sits under a size-gate
// baseline (TODO 106) and test growth belongs beside it, same pattern
// as pool/unit_tests.rs.
#[cfg(test)]
mod cleanup_mode_tests;

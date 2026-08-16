//! Plain split files: HJSplit-style `.001/.002/…` and `.1/.2/…` runs that
//! carry NO archive header at all, where the whole "extraction" is a
//! concatenation in numeric order.
//!
//! A poster who byte-splits a raw `Movie.mkv` into `Movie.mkv.001`,
//! `Movie.mkv.002`, … posts something no archive arm on the ladder can
//! open, because there is no archive: every part is payload bytes. SABnzbd
//! joins these in its post-processing joiner; we used to land the parts
//! loose and leave the user to `cat` them by hand. This module is the
//! missing arm, and it is deliberately the LAST one - see
//! [`collect_split_sets`] for why the detector refuses far more than it
//! accepts.
//!
//! This is emphatically NOT the numeric-volume handling in `rarfix.rs`
//! (`numeric_vol_base`, `stem_volume_set`). Those group `.001` parts that
//! DO carry the `Rar!` magic, and requiring the magic is what stops a
//! `.7z.001` or `.zip.001` part owned by another arm forming a bogus RAR
//! group. Here the magic is the disqualifier rather than the entry ticket:
//! a part carrying any archive head belongs to whichever arm owns that
//! head, never to this one.

use crate::*;

/// One accepted split-file set: the joined output's name, and its parts in
/// numeric order (part 1 first). Only ever produced by
/// [`collect_split_sets`], so every invariant it checks holds here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SplitSet {
    /// The joined file's name - the part names with the numeric tail
    /// stripped, in part 1's original case.
    pub(crate) base: String,
    /// Parts 1..=n in numeric order.
    pub(crate) parts: Vec<PathBuf>,
    /// The parts' total size as MEASURED during detection. The join
    /// compares the bytes it copied against this, so a part that changed
    /// under us between detection and join refuses instead of publishing
    /// a file that is not the payload.
    pub(crate) total: u64,
}

/// The numeric tail of a split part: `Movie.mkv.001` -> (`Movie.mkv`, 1, 3).
/// The third field is the tail's WIDTH, which the set-level check uses to
/// refuse a directory mixing `.1` and `.01` for one base.
///
/// Width 1-4 covers every splitter in the wild (`.1`…`.9`, `.001`…`.9999`).
/// Wider than that is not a split tail, it is a name that happens to end in
/// digits (`Movie.2019.12345`).
fn numeric_tail(name: &str) -> Option<(&str, u32, usize)> {
    let p = name.rfind('.')?;
    let tail = &name[p + 1..];
    if !(1..=4).contains(&tail.len()) || !tail.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    Some((&name[..p], tail.parse().ok()?, tail.len()))
}

/// Does this name's base belong to some OTHER arm of the ladder, or to no
/// arm at all? The magic check is the real gate - this is the name-level
/// twin of it, so the last-resort routing is visible in the names too and
/// does not rest on a head read alone.
///
/// Refused:
/// * a base another extractor owns (`.rar`, `.7z`, `.zip`/`.zipx`, a
///   `.rNN`/`.zNN` volume tail). A genuine one of those carries its magic
///   and is refused anyway; refusing by name as well means a HEADERLESS
///   `payload.zip.001` (a truncated or decoy first part) is still left for
///   the zip arm to report as the gap it is, rather than silently joined
///   into a file nothing can open.
/// * PAR2 recovery data in every spelling - `.par2`/`.par` and the
///   `.volNNN+NNN` slice marker anywhere in the base. Recovery volumes are
///   an INPUT to repair, and this function's caller deletes what it joins.
/// * `.rev` recovery volumes, for the same reason.
/// * a base that is itself a numeric tail (`Movie.001.001`), a hidden name,
///   a name with no alphanumeric character in it, or anything carrying a
///   path separator. No splitter writes those, and the base becomes an
///   output filename.
fn plausible_base(base: &str) -> bool {
    if base.is_empty() || base.starts_with('.') || base.contains(std::path::is_separator) {
        return false;
    }
    if !base.chars().any(char::is_alphanumeric) {
        return false;
    }
    if numeric_tail(base).is_some() {
        return false;
    }
    let lower = base.to_ascii_lowercase();
    // Extensions other arms own, plus the recovery/verification sidecars.
    for owned in [
        ".rar", ".7z", ".zip", ".zipx", ".par2", ".par", ".rev", ".sfv",
    ] {
        if lower.ends_with(owned) {
            return false;
        }
    }
    // `.rNN` / `.sNN`.. rollover / `.zNN` spanned-zip volume tails, in the
    // letter-plus-TWO-digits spelling every one of those actually uses.
    // `looks_like_named_rar` accepts wider tails (`.r100`); widening it here
    // would eat a release name ending `.x264`, and refusing THAT costs a
    // legitimate join while the magic check - the real gate - already covers
    // any of these that is genuinely an archive.
    if let Some((_, tail)) = lower.rsplit_once('.')
        && tail.len() == 3
        && matches!(tail.as_bytes()[0], b'r'..=b'z')
        && tail[1..].bytes().all(|c| c.is_ascii_digit())
    {
        return false;
    }
    // `name.vol000+01` - a PAR2 slice whose `.par2` was stripped or
    // renamed. Segment-scoped so an innocent `Vol.3` release name survives
    // (the marker is `vol` immediately followed by digits).
    !lower.split('.').any(|seg| {
        seg.strip_prefix("vol")
            .is_some_and(|rest| rest.starts_with(|c: char| c.is_ascii_digit()))
    })
}

/// Does this file open with a head that names it as some other arm's work?
/// RAR, 7-Zip, PAR2 and zip, plus `nzbkit::zip`'s own per-path verdict so
/// the zip arm's grammar (spanned `.zNN`, byte-split `.zip.NNN`) is asked
/// in its own words rather than reimplemented here.
///
/// Checked on EVERY part, not just the first. Only part 1 can carry the
/// joined file's real head, so a later part matching is either a coincidence
/// (~1 in 4 billion, and it costs us a refusal, never a bad join) or a sign
/// the run is not what it looks like. Refusing is free: the parts stay.
///
/// `zip_is_the_payload` is set when the SET'S BASE names a ZIP-backed
/// final payload (`comic.cbz`, `book.epub`, an office document - see
/// `nzbkit::zip::is_final_file`). A `.cbz` IS a zip container, so its
/// first part carrying zip magic is what the deliverable's own bytes look
/// like, not a sign that some other arm owns the set. Refusing on it left
/// `comic.cbz` unwritten while the zip arm extracted the pages instead
/// (read-only sweep 2 M11). Only the ZIP families are forgiven, and only
/// because the NAME said to expect them: a `Rar!`, 7-Zip or PAR2 head
/// under a `.cbz` base is still somebody else's, and still refuses.
fn carries_archive_magic(path: &std::path::Path, zip_is_the_payload: bool) -> bool {
    use std::io::Read;
    if rar_magic(path) || sevenz_magic(path) || file_starts_with_par2_magic(path) {
        return true;
    }
    if zip_is_the_payload {
        return false;
    }
    if nzbkit::zip::is_container(path) {
        return true;
    }
    let mut head = [0u8; 4];
    std::fs::File::open(path)
        .and_then(|mut f| f.read_exact(&mut head))
        .is_ok_and(|()| matches!(&head, b"PK\x03\x04" | b"PK\x05\x06" | b"PK\x07\x08"))
}

/// Every plain split-file set in `dir` that is safe to join, in name order.
///
/// Conservative by construction: a set that fails ANY check below is not
/// reported, and an unreported set is simply left on disk exactly as it
/// arrived. The checks, per candidate base:
///
/// 1. **Gapless from 1.** The parts present must be exactly 1..=n. A
///    missing MIDDLE part (`.001 .002 .004`) leaves a hole in that run and
///    refuses the whole set - joining it would publish a silently truncated
///    file over a set the user could still fix by hand. (A missing FINAL
///    part is not detectable from names alone; nothing can be, and PAR2 has
///    already spoken for completeness by the time this runs.)
/// 2. **No duplicate index.** On a case-sensitive filesystem `Movie.001`
///    and `movie.001` are two files claiming to be part 1. We cannot know
///    which, and the caller deletes what it joins.
/// 3. **Consistent numbering width.** Either every tail is the same width
///    (`.001 .002`), or every tail is minimal (`.1 … .9 .10`, which is how
///    an unpadded splitter rolls over). A mix is not a set we understand.
/// 4. **Uniform part sizes.** Every part but the last is the same non-zero
///    size, and the last is non-empty and no larger. That is what a byte
///    splitter produces, and it is the cheapest evidence that these files
///    are one payload rather than a coincidence of names.
/// 5. **No archive head on any part** ([`carries_archive_magic`]) and a
///    **plausible base** ([`plausible_base`]) - the two halves of "some
///    other arm owns this".
/// 6. **The output does not already exist.** Joining is never an overwrite -
///    and it is what keeps the one-digit `.1`/`.2` form honest, because the
///    other thing that spells names that way is a duplicate-download suffix
///    (`notes.txt`, `notes.txt.1`), which by construction leaves the
///    unsuffixed original sitting right there.
pub(crate) fn collect_split_sets(dir: &std::path::Path) -> Result<Vec<SplitSet>> {
    use std::collections::BTreeMap;
    // base (lowercased, for grouping) -> index -> (path, base as written, size, tail width)
    type Part = (PathBuf, String, u64, usize);
    let mut groups: BTreeMap<String, BTreeMap<u32, Vec<Part>>> = BTreeMap::new();
    for e in std::fs::read_dir(dir)?.flatten() {
        if !e.file_type().is_ok_and(|t| t.is_file()) {
            continue;
        }
        let path = e.path();
        let name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        let Some((base, idx, width)) = numeric_tail(&name) else {
            continue;
        };
        let Ok(md) = e.metadata() else {
            continue;
        };
        groups
            .entry(base.to_ascii_lowercase())
            .or_default()
            .entry(idx)
            .or_default()
            .push((path, base.to_string(), md.len(), width));
    }
    let mut out = Vec::new();
    for (_key, indexed) in groups {
        // (2) one file per index, or we cannot say what part 1 is.
        if indexed.values().any(|v| v.len() != 1) {
            continue;
        }
        let parts: Vec<&Part> = indexed.values().filter_map(|v| v.first()).collect();
        // (1) exactly 1..=n, in order - a hole anywhere refuses the set.
        let n = parts.len();
        if n < 2 || !indexed.keys().copied().eq(1..=(n as u32)) {
            continue;
        }
        // (3) all one width, or all minimal.
        let uniform = parts.iter().all(|p| p.3 == parts[0].3);
        let minimal = parts
            .iter()
            .enumerate()
            .all(|(i, p)| p.3 == (i + 1).to_string().len());
        if !uniform && !minimal {
            continue;
        }
        // (4) every part but the last the same non-zero size; the last
        //     non-empty and no bigger (an evenly divided payload makes the
        //     last part full-size, so this is `<=`, not `<`).
        let chunk = parts[0].2;
        if chunk == 0
            || parts[..n - 1].iter().any(|p| p.2 != chunk)
            || parts[n - 1].2 == 0
            || parts[n - 1].2 > chunk
        {
            continue;
        }
        // (5) name and head both have to say "nobody else owns this" -
        //     with the base's own extension deciding which heads that
        //     rules out, so a split `.cbz`/`.epub`/office payload is
        //     rebuilt rather than opened. The name is RECOVERED from
        //     under the numeric suffix, never sniffed: `nzbkit::zip`'s
        //     standing rules (never magic-sniff a named file, never touch
        //     a final payload) are what this is applying, not widening.
        let base = parts[0].1.clone();
        let zip_is_the_payload = nzbkit::zip::is_final_file(std::path::Path::new(&base));
        if !plausible_base(&base)
            || parts
                .iter()
                .any(|p| carries_archive_magic(&p.0, zip_is_the_payload))
        {
            continue;
        }
        // (6) never an overwrite.
        if dir.join(&base).exists() {
            continue;
        }
        out.push(SplitSet {
            base,
            parts: parts.iter().map(|p| p.0.clone()).collect(),
            total: parts.iter().map(|p| p.2).sum(),
        });
    }
    Ok(out)
}

/// Join every set in `sets`, consuming the parts of each one that
/// succeeds. Returns true only when every set produced its file.
///
/// The join lands in an [`ExtractStaging`] dir and is published by rename,
/// the same dance the zip and 7z arms use and for the same reason: a
/// half-written join must never be visible in the output directory, and on
/// any failure the staging dir's `Drop` takes the partial file with it
/// while every part stays exactly where it was. Parts are removed only
/// AFTER the publish, through [`remove_spent_volumes`] - so a failure
/// anywhere leaves the user with precisely what they had before.
pub(crate) fn join_split_sets(dir: &std::path::Path, sets: &[SplitSet]) -> bool {
    let mut all_ok = true;
    for set in sets {
        println!(
            "joining {} split part(s) into {}…",
            set.parts.len(),
            set.base
        );
        match join_one(dir, set) {
            Ok(bytes) => {
                println!(
                    "split join complete ✔ ({:.1} MiB)",
                    bytes as f64 / (1u64 << 20) as f64
                );
                remove_spent_volumes(&set.parts);
            }
            Err(e) => {
                println!("⚠ could not join {} - {e}", set.base);
                all_ok = false;
            }
        }
    }
    all_ok
}

/// Concatenate one set into `dir`, returning the joined size.
///
/// `concat_files` is the 7z arm's join, reused verbatim: a byte-split 7z
/// container is reassembled the same way, and one concatenation in the
/// codebase is one place for it to be wrong.
fn join_one(dir: &std::path::Path, set: &SplitSet) -> Result<u64> {
    let staging = ExtractStaging::new(dir)?;
    let target = staging.path().join(&set.base);
    concat_files(&set.parts, &target).with_context(|| format!("writing {}", target.display()))?;
    let written = std::fs::metadata(&target)
        .with_context(|| format!("sizing {}", target.display()))?
        .len();
    // Measured at detection, compared after the copy: a part that grew,
    // shrank or vanished under us means something else is writing to this
    // directory and the joined file is not the payload. Refuse rather than
    // publish it - and refusing is what keeps the parts.
    if written != set.total {
        anyhow::bail!(
            "the parts changed size while joining ({written} of {} bytes)",
            set.total
        );
    }
    staging.publish_into(dir)?;
    Ok(written)
}

#[cfg(test)]
#[path = "splitjoin_tests.rs"]
mod splitjoin_tests;

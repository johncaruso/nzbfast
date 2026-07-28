//! Zip container detection: the one place that answers "is there a zip
//! here, and which files make it up".
//!
//! Detection lived in three hand-rolled copies scattered through the
//! extraction paths, and they disagreed. The disagreements were not
//! cosmetic: a byte-split `name.zip.001` set matched none of them, so a
//! job whose entire payload was still packed completed *silently*, and
//! a zip sitting in a release subfolder was never looked at because the
//! recursion only seeded subdirs holding RAR or 7z magic. One detector
//! that every path shares is what keeps those shapes from reappearing.
//!
//! Shapes recognised:
//! - single `.zip` / `.zipx` container;
//! - obfuscated single container - extension stripped, identified by
//!   magic (the same trick the RAR and 7z paths use);
//! - WinZip-spanned sets: `.z01`, `.z02`, … with the *final* segment
//!   named `.zip` (that trailing `.zip` is the one holding the central
//!   directory, so it sorts LAST, not first);
//! - byte-split sets: `name.zip.001`/`.002`, or bare `.001`/`.002` where
//!   the first part carries the magic.
//!
//! Two rules the detectors must never break, both learned from real
//! posts:
//!
//! 1. **A named file is never magic-sniffed.** Comics, ebooks, office
//!    documents and java/android bundles are all zip containers wearing
//!    a different extension, and unpacking one destroys the very file
//!    the user downloaded. Sniffing is for files whose name has already
//!    failed to identify them - extensionless, or a bare numeric part.
//! 2. **`.cbz` and friends are payload, not packaging.** Even if a
//!    future caller starts sniffing more widely, [`is_final_name`] is
//!    the explicit stop.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Zip container start signatures we accept at offset 0.
///
/// - `PK\x03\x04` local file header: the ordinary case.
/// - `PK\x07\x08` and `PK00`: spanning markers, written ahead of the
///   first local header in the first segment of a spanned set.
///
/// `PK\x05\x06` (end-of-central-directory) is deliberately absent: alone
/// it means an EMPTY archive, and four bytes is too weak a signal to
/// spend on a container with nothing in it.
const MAGICS: [&[u8; 4]; 3] = [b"PK\x03\x04", b"PK\x07\x08", b"PK00"];

/// Extensions whose bytes ARE a zip container but whose file is the
/// deliverable. Unpacking one is data loss, not extraction.
const FINAL_FILE_EXTS: &[&str] = &[
    "cbz", "epub", "docx", "xlsx", "pptx", "docm", "xlsm", "pptm", "odt", "ods", "odp",
    "odg", "jar", "war", "aar", "apk", "ipa", "xpi", "crx", "vsix", "whl", "kra", "ora",
    "sketch", "usdz",
];

/// How the container is laid out on disk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shape {
    /// One self-contained file (named, or obfuscated by magic).
    Single,
    /// WinZip-spanned: `.z01`, `.z02`, …, `.zip`.
    Spanned,
    /// Raw byte split: `.zip.001`/`.002`, or bare `.001`/`.002`.
    ByteSplit,
}

impl Shape {
    /// Short label for logs and the dashboard note.
    pub fn label(self) -> &'static str {
        match self {
            Shape::Single => "zip",
            Shape::Spanned => "spanned zip",
            Shape::ByteSplit => "split zip",
        }
    }
}

/// One zip container found in a directory: every on-disk part that forms
/// it, in the order they must be read.
#[derive(Debug, Clone)]
pub struct Finding {
    /// The name to show a user - the recognisable member of the set
    /// (the trailing `.zip` for a spanned set, else the first part).
    pub name: String,
    /// Parts in read order. Single containers hold exactly one.
    pub parts: Vec<PathBuf>,
    pub shape: Shape,
}

/// Does the file start with a zip container signature? Reads 4 bytes.
///
/// Callers must have established that the NAME does not already identify
/// the file (see the module note on never sniffing named files).
pub fn has_magic(path: &Path) -> bool {
    use std::io::Read;
    let mut b = [0u8; 4];
    std::fs::File::open(path)
        .and_then(|mut f| f.read_exact(&mut b))
        .is_ok_and(|()| MAGICS.iter().any(|m| *m == &b))
}

/// A zip-container file whose extension marks it as the payload itself
/// (`.cbz`, `.epub`, `.docx`, …). Never unpack one.
pub fn is_final_file(path: &Path) -> bool {
    path.file_name()
        .is_some_and(|n| is_final_name(&n.to_string_lossy().to_ascii_lowercase()))
}

/// [`is_final_file`] over an already-lowercased file name.
fn is_final_name(lower: &str) -> bool {
    Path::new(lower)
        .extension()
        .is_some_and(|e| FINAL_FILE_EXTS.contains(&&*e.to_string_lossy()))
}

/// WinZip-spanned continuation part: `.z01` … (letter z + at least two
/// digits). `.zip` itself is the set's LAST segment and is matched
/// separately - `ip` is not digits, so it never lands here.
fn spanned_part(lower: &str) -> Option<(String, u32)> {
    let (head, tail) = lower.rsplit_once('.')?;
    let digits = tail.strip_prefix('z')?;
    if digits.len() < 2 || !digits.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    Some((head.to_string(), digits.parse().ok()?))
}

/// Byte-split part of a named zip: `movie.zip.001`. Mirrors the 7z
/// `split_7z_part` grammar exactly, with `.zip`/`.zipx` as the stem.
fn split_part(lower: &str) -> Option<(String, u32)> {
    let (head, tail) = lower.rsplit_once('.')?;
    if tail.is_empty() || !tail.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    (head.ends_with(".zip") || head.ends_with(".zipx"))
        .then(|| (head.to_string(), tail.parse().ok().unwrap_or(u32::MAX)))
}

/// Bare numeric part: `movie.001`. Ambiguous by name alone (RAR numeric
/// volumes and hjsplit use the same grammar), so the caller gates the
/// set on the first part carrying zip magic.
fn numeric_part(lower: &str) -> Option<(String, u32)> {
    let (head, tail) = lower.rsplit_once('.')?;
    if !(2..=4).contains(&tail.len()) || !tail.bytes().all(|c| c.is_ascii_digit()) {
        return None;
    }
    Some((head.to_string(), tail.parse().ok()?))
}

/// Is this single path part of a zip container? Name-identified shapes
/// answer without touching the disk; extensionless files and bare
/// numeric parts need the magic.
///
/// This is the per-path predicate the extraction recursion uses to
/// decide "is there something extractable here", so it deliberately says
/// yes to a lone member of a split set - a directory holding only
/// `movie.zip.002` still has an archive problem worth reporting.
pub fn is_container(path: &Path) -> bool {
    let Some(name) = path.file_name() else {
        return false;
    };
    let lower = name.to_string_lossy().to_ascii_lowercase();
    if is_final_name(&lower) {
        return false;
    }
    if lower.ends_with(".zip") || lower.ends_with(".zipx") {
        return true;
    }
    if spanned_part(&lower).is_some() || split_part(&lower).is_some() {
        return true;
    }
    let sniffable = path.extension().is_none() || numeric_part(&lower).is_some();
    sniffable && has_magic(path)
}

/// Name-only test, for deciding BEFORE anything is on disk whether a
/// post is zip-packed (the NZB's file list at enqueue). Magic-only
/// shapes - obfuscated containers, bare numeric parts - cannot be
/// answered from a name and are deliberately not guessed here.
pub fn name_is_zip_shaped(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    if is_final_name(&lower) {
        return false;
    }
    lower.ends_with(".zip")
        || lower.ends_with(".zipx")
        || spanned_part(&lower).is_some()
        || split_part(&lower).is_some()
}

/// Every zip container directly under `dir` (one level, like the 7z
/// collector), each with its parts in read order.
pub fn scan(dir: &Path) -> Vec<Finding> {
    // `.zip`/`.zipx` singles, keyed by stem so a spanned set can claim
    // its trailing segment back out of here.
    let mut named: BTreeMap<String, PathBuf> = BTreeMap::new();
    let mut spanned: BTreeMap<String, BTreeMap<u32, PathBuf>> = BTreeMap::new();
    let mut split: BTreeMap<String, BTreeMap<u32, PathBuf>> = BTreeMap::new();
    let mut numeric: BTreeMap<String, BTreeMap<u32, PathBuf>> = BTreeMap::new();
    let mut obfuscated: Vec<PathBuf> = Vec::new();

    let Ok(rd) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    for e in rd.flatten() {
        if !e.file_type().is_ok_and(|t| t.is_file()) {
            continue;
        }
        let path = e.path();
        let lower = e.file_name().to_string_lossy().to_ascii_lowercase();
        if is_final_name(&lower) {
            continue;
        }
        if let Some((stem, n)) = spanned_part(&lower) {
            spanned.entry(stem).or_default().insert(n, path);
        } else if let Some((stem, n)) = split_part(&lower) {
            split.entry(stem).or_default().insert(n, path);
        } else if lower.ends_with(".zip") || lower.ends_with(".zipx") {
            let stem = lower.rsplit_once('.').map(|(h, _)| h.to_string()).unwrap_or(lower);
            named.insert(stem, path);
        } else if let Some((stem, n)) = numeric_part(&lower) {
            numeric.entry(stem).or_default().insert(n, path);
        } else if path.extension().is_none() && has_magic(&path) {
            obfuscated.push(path);
        }
    }

    let mut out = Vec::new();
    // Spanned first, so each one can take its trailing `.zip` before the
    // singles pass sees it.
    for (stem, parts) in spanned {
        let mut parts: Vec<PathBuf> = parts.into_values().collect();
        let tail = named.remove(&stem);
        let name = match &tail {
            Some(z) => file_name(z),
            None => file_name(&parts[0]),
        };
        parts.extend(tail);
        out.push(Finding { name, parts, shape: Shape::Spanned });
    }
    for (_stem, parts) in split {
        let parts: Vec<PathBuf> = parts.into_values().collect();
        out.push(Finding { name: file_name(&parts[0]), parts, shape: Shape::ByteSplit });
    }
    // Bare numeric parts are only a zip set if the first part says so -
    // `.001` is also how RAR numeric volumes and hjsplit name themselves.
    for (_stem, parts) in numeric {
        let parts: Vec<PathBuf> = parts.into_values().collect();
        if !has_magic(&parts[0]) {
            continue;
        }
        out.push(Finding { name: file_name(&parts[0]), parts, shape: Shape::ByteSplit });
    }
    for (_stem, path) in named {
        out.push(Finding { name: file_name(&path), parts: vec![path], shape: Shape::Single });
    }
    for path in obfuscated {
        out.push(Finding { name: file_name(&path), parts: vec![path], shape: Shape::Single });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

/// The first zip container in `dir`, if any - the question every
/// reporting path asks.
pub fn first(dir: &Path) -> Option<Finding> {
    scan(dir).into_iter().next()
}

fn file_name(p: &Path) -> String {
    p.file_name().unwrap_or_default().to_string_lossy().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(dir: &Path, name: &str, head: &[u8]) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, head).unwrap();
        p
    }

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("nzbkit-zip-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    const PK: &[u8] = b"PK\x03\x04rest of a local file header";

    #[test]
    fn single_named_zip() {
        let d = tmp("single");
        write(&d, "movie.zip", PK);
        let f = scan(&d);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].shape, Shape::Single);
        assert_eq!(f[0].name, "movie.zip");
    }

    #[test]
    fn final_files_are_never_containers() {
        let d = tmp("final");
        for n in ["comic.cbz", "book.epub", "sheet.xlsx", "app.apk", "lib.jar"] {
            write(&d, n, PK);
        }
        assert!(scan(&d).is_empty(), "payload formats must never be unpacked");
        assert!(!is_container(&d.join("comic.cbz")));
        assert!(!name_is_zip_shaped("comic.cbz"));
    }

    #[test]
    fn named_non_zip_is_never_sniffed() {
        // A .bin/.dat that happens to start with PK is not ours to open:
        // sniffing named files is exactly how a .cbz gets destroyed.
        let d = tmp("named");
        write(&d, "payload.bin", PK);
        assert!(scan(&d).is_empty());
        assert!(!is_container(&d.join("payload.bin")));
    }

    #[test]
    fn spanned_set_puts_the_zip_last() {
        // The trailing `.zip` holds the central directory: read order is
        // z01, z02, …, zip - NOT lexical order.
        let d = tmp("spanned");
        write(&d, "movie.z02", b"part two");
        write(&d, "movie.zip", b"central directory");
        write(&d, "movie.z01", PK);
        let f = scan(&d);
        assert_eq!(f.len(), 1, "one set, not three containers");
        assert_eq!(f[0].shape, Shape::Spanned);
        assert_eq!(f[0].name, "movie.zip");
        let names: Vec<String> = f[0].parts.iter().map(|p| file_name(p)).collect();
        assert_eq!(names, ["movie.z01", "movie.z02", "movie.zip"]);
    }

    #[test]
    fn byte_split_named_parts() {
        // The shape that matched nothing before and completed silently.
        let d = tmp("split");
        write(&d, "movie.zip.002", b"two");
        write(&d, "movie.zip.001", PK);
        let f = scan(&d);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].shape, Shape::ByteSplit);
        let names: Vec<String> = f[0].parts.iter().map(|p| file_name(p)).collect();
        assert_eq!(names, ["movie.zip.001", "movie.zip.002"]);
    }

    #[test]
    fn bare_numeric_parts_need_the_magic() {
        let d = tmp("numeric");
        write(&d, "movie.001", PK);
        write(&d, "movie.002", b"two");
        // A RAR numeric set in the same directory must not be claimed.
        write(&d, "other.001", b"Rar!\x1a\x07\x01\x00");
        write(&d, "other.002", b"two");
        let f = scan(&d);
        assert_eq!(f.len(), 1, "only the PK-headed set is a zip");
        assert_eq!(f[0].name, "movie.001");
        let names: Vec<String> = f[0].parts.iter().map(|p| file_name(p)).collect();
        assert_eq!(names, ["movie.001", "movie.002"]);
    }

    #[test]
    fn obfuscated_extensionless_container() {
        let d = tmp("obf");
        write(&d, "a3f9c1d2e", PK);
        write(&d, "b7e2", b"not an archive at all");
        let f = scan(&d);
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].name, "a3f9c1d2e");
    }

    #[test]
    fn spanning_markers_count_as_magic() {
        let d = tmp("marker");
        write(&d, "marked", b"PK\x07\x08rest");
        write(&d, "marked2", b"PK00rest");
        assert_eq!(scan(&d).len(), 2);
    }

    #[test]
    fn empty_archive_signature_is_not_enough() {
        let d = tmp("eocd");
        write(&d, "nothing", b"PK\x05\x06\x00\x00\x00\x00");
        assert!(scan(&d).is_empty());
    }

    #[test]
    fn two_independent_zips_are_two_findings() {
        let d = tmp("two");
        write(&d, "a.zip", PK);
        write(&d, "b.zip", PK);
        assert_eq!(scan(&d).len(), 2);
    }

    #[test]
    fn name_shape_covers_what_a_nzb_can_show() {
        for n in ["Movie.zip", "MOVIE.ZIP", "movie.zipx", "movie.z01", "movie.zip.001"] {
            assert!(name_is_zip_shaped(n), "{n} should read as zip-packed");
        }
        for n in ["movie.rar", "movie.r01", "movie.7z", "movie.7z.001", "movie.001", "movie"] {
            assert!(!name_is_zip_shaped(n), "{n} must not read as zip-packed");
        }
    }
}

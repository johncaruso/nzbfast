//! SFX self-extractors: an `.exe`/`.bin`/`.sfx` with a real archive
//! appended behind a launcher stub. Detection, the entry gate, the
//! extraction arm and the stub carve - split out of unpack.rs whole
//! (size gate; nothing here changed in the move).
//!
//! The two callers are `extract_one_level` step 3 (depth 0, the offline
//! `extract` command's top level) and the get tail's downloaded-slot arm.
//! Neither is reachable from the nested pass by design: a payload's own
//! `setup.exe` is very often a legitimate WinRAR SFX installer, and must
//! never be auto-exploded.

use crate::*;

/// How much of a candidate's head is scanned for an appended archive.
///
/// 4 MiB, not 1: a 7-Zip PE stub alone is ~200 KB and RAR's own installer
/// stubs run past a megabyte, so the old window could sit entirely inside
/// the stub and conclude "not an archive".
const SFX_SCAN_WINDOW: usize = 4 << 20;

/// Is this file an SFX self-extractor - an executable-ish name whose head
/// carries an archive signature past the launcher stub?
///
/// The extension gate comes first because it is free, and because it is
/// also the SAFETY gate: the head scan is a substring search, and running
/// it over every file in a release would eventually match a data file
/// that happens to contain `Rar!` or the 7z magic.
///
/// A signature AT offset 0 is a bare archive wearing the wrong name, not
/// a self-extractor - there is no stub to carve, `carve_sfx` declines it,
/// and the SFX arm would report a failure over a file the ordinary paths
/// can open. Both families are held to that rule; only RAR was before, so
/// a bare 7z named `.exe` was collected as an SFX and then failed.
///
/// One head read per candidate, so this is cheap enough for a directory
/// gate: a release carries a handful of executables at most.
pub(crate) fn is_sfx_archive(path: &std::path::Path) -> bool {
    let sfx_ext = path.extension().is_some_and(|x| {
        let x = x.to_string_lossy().to_lowercase();
        x == "exe" || x == "bin" || x == "sfx"
    });
    if !sfx_ext {
        return false;
    }
    let head = read_head(path, SFX_SCAN_WINDOW);
    matches!(sfx_payload_at(&head), Some((off, _)) if off > 0)
}

/// Read up to `cap` bytes from the start of `path`, looping until the
/// buffer is full or the file ends. A single `read` may legally return
/// short of a 4 MiB request, and a signature sitting past that boundary
/// would then read as "no archive here" on some runs and not others.
fn read_head(path: &std::path::Path, cap: usize) -> Vec<u8> {
    use std::io::Read;
    let mut buf = vec![0u8; cap];
    let mut n = 0;
    if let Ok(mut f) = std::fs::File::open(path) {
        while n < buf.len() {
            match f.read(&mut buf[n..]) {
                Ok(0) => break,
                Ok(k) => n += k,
                Err(_) => break,
            }
        }
    }
    buf.truncate(n);
    buf
}

/// SFX self-extractor candidates sitting directly in `dir`.
pub(crate) fn collect_sfx_archives(dir: &std::path::Path) -> Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir)?.flatten() {
        let path = e.path();
        if e.file_type().is_ok_and(|t| t.is_file()) && is_sfx_archive(&path) {
            out.push(path);
        }
    }
    out.sort();
    Ok(out)
}

/// Where an SFX stub's real archive starts, and which kind it is.
///
/// An SFX is an executable with an archive appended, so the payload is
/// found by SIGNATURE, not by extension - and it is never at offset 0
/// (that is a bare archive, which the caller has already routed
/// elsewhere). Both families ship one: WinRAR writes `Rar!` and 7-Zip
/// writes the 7z magic after their respective stubs.
///
/// Only RAR was recognised before, so a 7z SFX was not merely
/// unextractable, it was invisible: nothing collected it and nothing
/// said why. The 12 Aug competitor round found no client that unpacks
/// either shape.
pub(crate) fn sfx_payload_at(head: &[u8]) -> Option<(usize, SfxKind)> {
    let rar = head
        .windows(7)
        .position(|w| w == b"Rar!\x1a\x07\x00" || w == b"Rar!\x1a\x07\x01")
        .map(|p| (p, SfxKind::Rar));
    let sevenz = head
        .windows(6)
        .position(|w| w == nzbkit::nameprobe::SEVENZ_MAGIC)
        .map(|p| (p, SfxKind::SevenZ));
    // The EARLIER signature wins: a 7z stub can mention "Rar!" in its
    // own error strings, and vice versa, so trusting whichever comes
    // first past the stub beats trusting a fixed order.
    match (rar, sevenz) {
        (Some(r), Some(s)) => Some(if r.0 <= s.0 { r } else { s }),
        (r, s) => r.or(s),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SfxKind {
    Rar,
    SevenZ,
}

/// Extract each SFX archive standalone (rars locates the archive past the
/// stub itself).
pub(crate) fn extract_sfx(
    dir: &std::path::Path,
    archives: &[PathBuf],
    password: Option<&str>,
) -> bool {
    let options = nzbkit::mem::rar_read_options(password.map(str::as_bytes));
    let mut all_ok = true;
    for path in archives {
        println!(
            "unpacking SFX archive {} natively…",
            path.file_name().unwrap_or_default().to_string_lossy()
        );
        let direct = rars::ArchiveReader::read_path_with_options(path, options)
            .map_err(|e| anyhow::anyhow!("{e}"))
            .and_then(|archive| write_archives_to(dir, &[archive], password));
        match direct {
            Ok(()) => {
                println!("SFX unpack complete ✔");
                continue;
            }
            Err(e) => {
                // The reader could not seek past this stub - or the
                // payload is a 7z, which it cannot read at all. Carve
                // the archive out by signature and extract THAT. Kept
                // as a fallback rather than the first move so the
                // common case still streams through rars without
                // writing a second copy of the payload to disk.
                match carve_sfx(path) {
                    Some((carved, kind)) => {
                        let carved_path = carved.dir.join(match kind {
                            SfxKind::Rar => "carved.rar",
                            SfxKind::SevenZ => "carved.7z",
                        });
                        let ok = match kind {
                            SfxKind::Rar => {
                                rars::ArchiveReader::read_path_with_options(&carved_path, options)
                                    .map_err(|e| anyhow::anyhow!("{e}"))
                                    .and_then(|a| write_archives_to(dir, &[a], password))
                                    .is_ok()
                            }
                            SfxKind::SevenZ => crate::rarfix::extract_sevenz(
                                dir,
                                &[vec![carved_path.clone()]],
                                password,
                            ),
                        };
                        if ok {
                            println!("SFX unpack complete ✔ (carved past the stub)");
                        } else {
                            println!(
                                "⚠ SFX unpack failed ({e}), and the carved archive \
                                      did not extract either"
                            );
                            all_ok = false;
                        }
                    }
                    None => {
                        println!("⚠ SFX unpack failed ({e})");
                        all_ok = false;
                    }
                }
            }
        }
    }
    all_ok
}

/// Copy an SFX's appended archive out to its own file, dropping the
/// executable stub in front of it.
///
/// Returns the scratch copy (deleted when the handle drops) and what
/// kind of archive it holds. None when no signature is found, which for
/// a file this far down the path means it was never an SFX.
///
/// The whole tail is copied because both readers want a file they can
/// seek within, and the stub is the only part that must go: an offset
/// reader would be leaner but would have to be threaded through two
/// unrelated extractors, and an SFX payload is bounded by the post we
/// already downloaded.
fn carve_sfx(path: &std::path::Path) -> Option<(ExtractStaging, SfxKind)> {
    use std::io::{Read, Seek, SeekFrom, Write};
    let (off, kind) = sfx_payload_at(&read_head(path, SFX_SCAN_WINDOW))?;
    let mut f = std::fs::File::open(path).ok()?;
    if off == 0 {
        // Already a bare archive: the direct read above failed for some
        // other reason and carving would just copy it verbatim.
        return None;
    }
    // Beside the payload, on the same filesystem, under the `.nzbfast`
    // prefix the nested pass's walkers already skip as scratch.
    let scratch = ExtractStaging::new(path.parent()?).ok()?;
    let out = scratch.dir.join(match kind {
        SfxKind::Rar => "carved.rar",
        SfxKind::SevenZ => "carved.7z",
    });
    f.seek(SeekFrom::Start(off as u64)).ok()?;
    let mut w = std::io::BufWriter::new(std::fs::File::create(&out).ok()?);
    let mut buf = vec![0u8; 1 << 20];
    loop {
        match f.read(&mut buf) {
            Ok(0) => break,
            Ok(k) => w.write_all(&buf[..k]).ok()?,
            Err(_) => return None,
        }
    }
    w.flush().ok()?;
    println!(
        "  carved {} archive from the SFX stub at offset {off}",
        match kind {
            SfxKind::Rar => "RAR",
            SfxKind::SevenZ => "7-Zip",
        }
    );
    Some((scratch, kind))
}

#[cfg(test)]
mod sfx_tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("nzbfast-sfx-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    /// Build a self-extractor the way the real ones are built: an
    /// executable stub with the archive appended. Synthesised rather
    /// than vendored so the test owns its inputs (and no third-party
    /// fixture rides into this repo for it).
    fn sfx_from(fixture: &str, out: &std::path::Path, stub_len: usize) {
        let arch = std::fs::read(fixture).unwrap();
        let mut stub = vec![0x4du8, 0x5a]; // "MZ", so it looks like a PE
        stub.extend(std::iter::repeat_n(0x90u8, stub_len));
        stub.extend(arch);
        std::fs::write(out, stub).unwrap();
    }

    /// The payload is found by SIGNATURE and past the stub. RAR was the
    /// only family recognised before, so a 7z SFX was invisible: nothing
    /// collected it and nothing said why (12 Aug competitor round -
    /// advO, which NO client unpacked).
    #[test]
    fn a_stubbed_archive_is_located_by_signature_for_both_families() {
        let rar = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../vendor/rars/tests/fixtures/rar50/solid.rar"
        ))
        .unwrap();
        let mut buf = vec![0x90u8; 4096];
        buf.extend(&rar);
        assert_eq!(sfx_payload_at(&buf), Some((4096, SfxKind::Rar)));

        let sevenz = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../nzbkit/tests/fixtures/sevenz/store-single.7z"
        ))
        .unwrap();
        let mut buf = vec![0x90u8; 2048];
        buf.extend(&sevenz);
        assert_eq!(sfx_payload_at(&buf), Some((2048, SfxKind::SevenZ)));

        // A bare archive is not an SFX: offset 0 is the caller's other
        // path, and carve_sfx declines it rather than copying it.
        assert_eq!(sfx_payload_at(&rar), Some((0, SfxKind::Rar)));
        assert_eq!(sfx_payload_at(b"no archive in here at all"), None);
    }

    /// Collection keys on the signature, not the extension's promise -
    /// and the window has to outrun the stub. A 7-Zip PE stub alone is
    /// ~200 KB and the old 1 MiB read could sit entirely inside one.
    #[test]
    fn a_seven_zip_sfx_is_collected_and_a_deep_stub_still_found() {
        let dir = tmp("collect");
        sfx_from(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../nzbkit/tests/fixtures/sevenz/store-single.7z"
            ),
            &dir.join("release.exe"),
            1_500_000,
        );
        let found = collect_sfx_archives(&dir).unwrap();
        assert_eq!(found.len(), 1, "a 7z SFX past 1 MiB of stub must be seen");
        assert!(found[0].ends_with("release.exe"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The ENTRY gate, which is what advO actually needed: a post whose
    /// only members are SFX executables used to finish as "2 files
    /// complete" with two `.exe`s as the payload, because nothing
    /// upstream of the extractor recognised the shape - the in-stream
    /// mapper sniffs offset 0, and a stub reads as a plain data file.
    ///
    /// The extension is a SAFETY gate, not a convenience: the head scan
    /// is a substring search, so run over arbitrary payload it would
    /// eventually match a data file that merely contains the bytes.
    #[test]
    fn the_entry_gate_takes_an_sfx_and_leaves_plain_files_alone() {
        let dir = tmp("gate");
        let sevenz = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../nzbkit/tests/fixtures/sevenz/store-single.7z"
        );
        sfx_from(sevenz, &dir.join("release.exe"), 4096);
        assert!(is_sfx_archive(&dir.join("release.exe")));

        // Same bytes under a payload extension: never scanned, never
        // exploded. A `.mkv` carrying an appended archive is a `.mkv`.
        sfx_from(sevenz, &dir.join("movie.mkv"), 4096);
        assert!(!is_sfx_archive(&dir.join("movie.mkv")));

        // A bare archive that happens to be named .exe is the normal
        // path's business (magic at offset 0), not this one.
        std::fs::copy(sevenz, dir.join("bare.exe")).unwrap();
        assert!(
            !is_sfx_archive(&dir.join("bare.exe")),
            "offset 0 is not a stub"
        );
        // ...and the OTHER half of that sentence, which is the
        // user-visible consequence: SFX routing runs BEFORE the normal 7z
        // magic path, so a bare archive this gate wrongly claimed was not
        // merely mis-labelled - the direct read failed, `carve_sfx`
        // declined offset 0, and extraction reported false without the
        // plain path ever seeing the file. Every one of these extensions,
        // because the gate lists three (Codex sweep 12 Aug F13).
        for name in ["bare2.bin", "bare3.sfx"] {
            std::fs::copy(sevenz, dir.join(name)).unwrap();
            assert!(!is_sfx_archive(&dir.join(name)), "{name}: offset 0");
        }
        let claimed = crate::rarfix::collect_sevenz_archives(&dir).unwrap();
        assert_eq!(
            claimed.len(),
            3,
            "the normal 7z path must claim all three bare copies: {claimed:?}"
        );
        // The rule is about offset 0, not about 7-Zip: a bare RAR under
        // an SFX extension is the RAR path's business the same way.
        std::fs::copy(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../vendor/rars/tests/fixtures/rar50/solid.rar"
            ),
            dir.join("movie.exe"),
        )
        .unwrap();
        assert!(
            !is_sfx_archive(&dir.join("movie.exe")),
            "a bare RAR named .exe is not a stub either"
        );
        // Nothing above left a candidate behind, at any extension.
        assert!(
            collect_sfx_archives(&dir)
                .unwrap()
                .iter()
                .all(|p| p.file_name().is_some_and(|n| n == "release.exe")),
            "only the real self-extractor is collected"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The boundary the depth-0 restriction rests on. `is_extractable_
    /// archive` drives nested DESCENT - `is_new_nested_archive`,
    /// `dir_has_nested_extractable`, and `entry_archives`, whose
    /// spent-intermediate sweep DELETES what it lists. Teaching it about
    /// SFX would make a release's own `setup.exe` a nested layer and then
    /// disposable furniture, so the SFX gate stays separate and is only
    /// ever applied to files we know were DOWNLOADED.
    #[test]
    fn an_sfx_is_never_a_nested_descent_target() {
        let dir = tmp("descent");
        let exe = dir.join("setup.exe");
        sfx_from(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../vendor/rars/tests/fixtures/rar50/solid.rar"
            ),
            &exe,
            4096,
        );
        assert!(is_sfx_archive(&exe));
        assert!(
            !is_extractable_archive(&exe),
            "a produced setup.exe must never be re-exploded by the nested pass"
        );
        assert!(!dir_has_nested_extractable(&dir).unwrap());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The carve drops the stub and leaves a plain archive the readers
    /// can open, with the scratch dir cleaning up after itself.
    #[test]
    fn carving_yields_a_readable_archive_and_cleans_up() {
        let dir = tmp("carve");
        let exe = dir.join("payload.exe");
        sfx_from(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../vendor/rars/tests/fixtures/rar50/solid.rar"
            ),
            &exe,
            8192,
        );
        let scratch_dir;
        {
            let (scratch, kind) = carve_sfx(&exe).expect("signature is present");
            assert_eq!(kind, SfxKind::Rar);
            let carved = scratch.dir.join("carved.rar");
            scratch_dir = scratch.dir.clone();
            let head = std::fs::read(&carved).unwrap();
            assert!(head.starts_with(b"Rar!"), "the stub must be gone");
            assert!(
                rars::ArchiveReader::read_path_with_options(
                    &carved,
                    nzbkit::mem::rar_read_options(None)
                )
                .is_ok(),
                "the carved archive must open"
            );
        }
        assert!(!scratch_dir.exists(), "scratch must not outlive the carve");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

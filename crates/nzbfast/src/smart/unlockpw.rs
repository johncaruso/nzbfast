//! Spending a password we hold on a locked archive: where the
//! operator's passwords file lives for code that cannot reach the
//! daemon, and the non-RAR half of [`super::unlock`].
//!
//! A child module file rather than inline: smart.rs sits under a
//! size-gate baseline (TODO 106) and the numbers only go down.

use super::*;

/// Where the operator's passwords file lives, for the code that cannot
/// reach the daemon to ask.
///
/// The file is a daemon setting, and the paths that need it most are
/// free functions in `unpack` - the on-disk extraction ladder, which runs
/// under the CLI too and holds no `Daemon` handle. Threading an
/// `Option<&[String]>` down through every extraction signature to reach
/// `harvest_password_candidates` would touch a dozen functions to deliver
/// one process-wide fact, so the fact is stored process-wide, the way
/// `eatvol`'s mode already is.
///
/// Set at startup and again whenever the setting changes; None on a CLI
/// run, which is why every reader treats "no file" as an empty list and
/// never as an error.
static OPERATOR_PASSWORD_FILE: std::sync::Mutex<Option<PathBuf>> = std::sync::Mutex::new(None);

/// Point the extraction ladder at the operator's passwords file (or
/// clear it). Called wherever `hub.unpack_password_file` is set.
pub fn set_operator_password_file(path: Option<PathBuf>) {
    *OPERATOR_PASSWORD_FILE.lock_ok() = path;
}

/// The operator's passwords, read FRESH on every call.
///
/// Fresh is the point, not an accident: a line added while the download
/// was still running is exactly the case this serves, and a cached list
/// would make the operator restart the daemon to be believed. A missing
/// file is an empty list (see [`super::read_password_file`]).
pub fn operator_passwords() -> Vec<String> {
    let path = OPERATOR_PASSWORD_FILE.lock_ok().clone();
    path.map(|p| read_password_file(&p)).unwrap_or_default()
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

/// First password-protected archive of ANY kind we can unlock (RAR
/// volume or 7-Zip container) left in a finished job's folder.
///
/// This is what post-processing must ask, and it used to ask
/// [`encrypted_rar`]: a header-encrypted 7z therefore never set
/// `password_required`, and the job died as a generic local "could not
/// be unpacked" with the real reason (`PasswordRequired`) visible only in
/// the log. RAR keeps first claim so the common case pays no extra
/// probe, and so the name reported to the UI stays the one the existing
/// copy expects.
pub fn encrypted_archive(dir: &Path) -> Option<PathBuf> {
    if let Some(rar) = encrypted_rar(dir) {
        return Some(rar);
    }
    let mut sevenz: Vec<PathBuf> = std::fs::read_dir(dir)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_file() && p.extension().is_some_and(|x| x.eq_ignore_ascii_case("7z")))
        .collect();
    sevenz.sort();
    if let Some(z) = sevenz
        .into_iter()
        .find(|p| nzbkit::nameprobe::sevenz_needs_password(p))
    {
        return Some(z);
    }
    // Encrypted zip, last of the three. It was invisible here until the
    // 12 Aug correctness round: a job whose only locked archive was a zip
    // never set `password_required`, so the 🔑 affordance was missing on
    // the one job whose entire remedy is a password. Last because it is
    // the rarest lock on Usenet and the scan reads each container's
    // central directory - RAR and 7z answer from a header.
    //
    // A container whose content already sits beside it is NOT reported:
    // the disk ladder unlocks encrypted zips from the passwords file
    // now, and the spent container survives whenever two sets share a
    // directory (the intermediate sweep refuses to guess which is
    // consumed). Reporting it asked the tail to unlock what it had
    // already delivered, and would have put a 🔑 on a job with nothing
    // left to unlock.
    nzbkit::zip::scan(dir)
        .into_iter()
        .find(|f| {
            nzbkit::zip::needs_password(&f.parts) && !crate::diag::zip_already_delivered(dir, f)
        })
        .and_then(|f| f.parts.into_iter().next())
}

/// Spend `password` on the locked NON-RAR shapes in `dir`: a 7-Zip
/// container, then a zip. `None` means there was nothing of either shape
/// to try, which is what lets the caller tell "no attempt" apart from
/// "attempted and the password was wrong".
///
/// Only containers that actually ASK for a password are attempted. 7-Zip
/// and zip both ignore a password they do not need, so an unrelated
/// plain container in the same folder (a sample, an obfuscated sidecar -
/// `collect_sevenz_archives` picks those up by magic under any name)
/// extracted cleanly and reported the wrong password as the one that
/// worked: prompt cleared, "the password worked" toast, the locked set
/// still packed. A multipart 7z cannot be probed part by part - its
/// header lives in the last part - so it still gets the attempt.
pub(super) fn unlock_non_rar(dir: &Path, password: &str) -> Option<bool> {
    let sevenz: Vec<Vec<PathBuf>> = crate::rarfix::collect_sevenz_archives(dir)
        .unwrap_or_default()
        .into_iter()
        .filter(|parts| {
            parts.len() > 1
                || parts
                    .first()
                    .is_some_and(|p| nzbkit::nameprobe::sevenz_needs_password(p))
        })
        .collect();
    if !sevenz.is_empty() {
        if !crate::rarfix::extract_sevenz(dir, &sevenz, Some(password)) {
            return Some(false);
        }
        info!(target: "unlock", "{}: 7-Zip container unlocked", dir.display());
        return Some(true);
    }
    let zips: Vec<nzbkit::zip::Finding> = nzbkit::zip::scan(dir)
        .into_iter()
        .filter(|f| nzbkit::zip::needs_password(&f.parts))
        .collect();
    if zips.is_empty() {
        return None;
    }
    if !crate::rarfix::extract_zip(dir, &zips, Some(password)) {
        return Some(false);
    }
    info!(target: "unlock", "{}: zip container unlocked", dir.display());
    Some(true)
}

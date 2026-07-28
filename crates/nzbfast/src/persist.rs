//! Crash-safe file persistence for the daemon's JSON state (queue.json,
//! settings.json, quota.json, …). Two halves:
//!
//! * `write_atomic` - tmp-write + rename (the tools.rs binary-extraction
//!   pattern, extracted). ENOSPC or a crash mid-write can only tear the
//!   temp file; the previous good file survives intact.
//! * `load_json_with_backup` - refreshes a `.bak` of the last good parse
//!   on every successful load, and on a parse failure REFUSES to report
//!   the file as "empty" (the next save would make the loss permanent):
//!   the corrupt bytes are set aside as `.corrupt` and the `.bak` is
//!   restored instead, loudly.

use serde_json::Value;
use std::path::{Path, PathBuf};

/// `queue.json` → `queue.json.bak` (same directory, so the pair travels
/// together with the spool).
fn sibling(path: &Path, suffix: &str) -> PathBuf {
    let mut os = path.as_os_str().to_owned();
    os.push(suffix);
    PathBuf::from(os)
}

/// Write `bytes` at `path` atomically: write a same-directory temp file,
/// then rename over the target (rename replaces on Windows too). The
/// counter keeps concurrent writers in this process off each other's
/// temp file; the pid does the same across processes.
pub(crate) fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)?;
    }
    let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let tmp = sibling(path, &format!(".{}.{n}.tmp", std::process::id()));
    // fsync the temp file BEFORE the rename commits: a rename is metadata,
    // journaled independently of the data blocks, so on power loss the target
    // (and its .bak, written through here too) could otherwise come back
    // 0-byte/torn. State files are daemon-private and can hold credentials, so
    // create them mode 0600 on unix.
    let done = (|| -> std::io::Result<()> {
        use std::io::Write;
        #[cfg(unix)]
        let mut f = {
            use std::os::unix::fs::OpenOptionsExt;
            std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)?
        };
        #[cfg(not(unix))]
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, path)?;
        // ...and fsync the DIRECTORY, because the rename that just published
        // those bytes is itself only a directory entry. Syncing the file
        // persists its contents; the name pointing at them is separate
        // metadata with its own flush. Without this the function could return
        // success and the file still be absent after power loss - which for
        // queue/settings/quota/usage state means the next start rebuilds from
        // defaults and saves them over whatever survived.
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            let _ = crate::smart::sync_dir(dir);
        }
        Ok(())
    })();
    if done.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    done
}

/// Read `path` as JSON. `None` means "no data on disk" - a missing file
/// (fresh start, or a deliberate delete-to-reset, which must stay
/// effective). A file that EXISTS but won't parse is never reported as
/// that: its bytes are preserved at `<path>.corrupt`, and the `.bak` of
/// the last good parse is loaded - and written back to `path` so the
/// daemon self-heals rather than logging forever.
/// True when `path` (or its `.bak`) is on disk but NEITHER yields usable
/// JSON. Distinct from "absent" and from "parsed fine but empty": this is
/// the state where a store that MAY have held data silently loaded as
/// nothing. `load_json_with_backup` deliberately degrades to an empty map
/// there so one torn file cannot erase every other setting - correct for
/// settings, dangerous for a credential, so the caller can ask.
pub(crate) fn json_store_unreadable(path: &Path) -> bool {
    let bak = sibling(path, ".bak");
    let readable = |p: &Path| {
        std::fs::read(p).ok().and_then(|b| serde_json::from_slice::<Value>(&b).ok()).is_some()
    };
    // `.corrupt` counts as evidence the primary once existed: an
    // unparseable primary is RENAMED there, so by the next start the
    // primary looks merely absent.
    let existed = path.exists() || bak.exists() || sibling(path, ".corrupt").exists();
    existed && !readable(path) && !readable(&bak)
}

pub(crate) fn load_json_with_backup(path: &Path) -> Option<Value> {
    let bak = sibling(path, ".bak");
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        // A genuinely-absent file with NO backup means "no data" (fresh
        // start, or a deliberate reset).
        //
        // An absent primary WITH a good backup is a different story: that is
        // what a crash between the temp write and the rename leaves behind,
        // and returning None there makes the caller rebuild from defaults and
        // then save those defaults over the last good state - turning a
        // recoverable interruption into permanent loss. Recover, and say so.
        //
        // Resetting therefore means removing the .bak too; the message says
        // which file to remove.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let recovered = std::fs::read(&bak)
                .ok()
                .and_then(|b| serde_json::from_slice::<Value>(&b).ok());
            return match recovered {
                Some(v) => {
                    eprintln!(
                        "[persist] {} is missing but {} is intact - recovering from it \
                         (delete {} too if you meant to reset)",
                        path.display(),
                        bak.display(),
                        bak.display()
                    );
                    let _ = write_atomic(path, &serde_json::to_vec(&v).unwrap_or_default());
                    Some(v)
                }
                None => None,
            };
        }
        Err(_) => {
            return std::fs::read(&bak)
                .ok()
                .and_then(|b| serde_json::from_slice(&b).ok());
        }
    };
    match serde_json::from_slice::<Value>(&bytes) {
        Ok(v) => {
            if std::fs::read(&bak).map_or(true, |b| b != bytes) {
                let _ = write_atomic(&bak, &bytes);
            }
            Some(v)
        }
        Err(e) => {
            let kept = sibling(path, ".corrupt");
            let _ = std::fs::rename(path, &kept);
            eprintln!(
                "[persist] {} won't parse ({e}) - bytes kept at {}",
                path.display(),
                kept.display()
            );
            let good = std::fs::read(&bak)
                .ok()
                .and_then(|b| Some((serde_json::from_slice::<Value>(&b).ok()?, b)));
            match good {
                Some((v, b)) => {
                    eprintln!("[persist] restored last good state from {}", bak.display());
                    let _ = write_atomic(path, &b);
                    Some(v)
                }
                None => {
                    eprintln!(
                        "[persist] no usable {} - starting empty ({} has the old bytes)",
                        bak.display(),
                        kept.display()
                    );
                    None
                }
            }
        }
    }
}

/// Like [`load_json_with_backup`] but for a USER-supplied config path that
/// may legitimately NOT be JSON - the runtime also accepts a SABnzbd `.ini`.
/// A parse failure here must NEVER quarantine the file: renaming a user's
/// live config to `.corrupt` on a mere read (server-editor open, setup
/// wizard) silently destroys it. Refreshes `.bak` on a good JSON parse;
/// returns None (leaving the file untouched) on anything else.
pub(crate) fn load_json_config(path: &Path) -> Option<Value> {
    let bytes = std::fs::read(path).ok()?;
    match serde_json::from_slice::<Value>(&bytes) {
        Ok(v) => {
            let bak = sibling(path, ".bak");
            if std::fs::read(&bak).map_or(true, |b| b != bytes) {
                let _ = write_atomic(&bak, &bytes);
            }
            Some(v)
        }
        // Not JSON (e.g. a SABnzbd .ini) - do not touch the file.
        Err(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("nzbfast-persist-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn round_trip_and_bak_refresh() {
        let dir = scratch("rt");
        let p = dir.join("state.json");
        write_atomic(&p, b"{\"a\":1}").unwrap();
        assert_eq!(load_json_with_backup(&p), Some(json!({"a": 1})));
        // The load refreshed the .bak with the good bytes.
        assert_eq!(std::fs::read(sibling(&p, ".bak")).unwrap(), b"{\"a\":1}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_file_is_a_quiet_fresh_start() {
        let dir = scratch("fresh");
        assert_eq!(load_json_with_backup(&dir.join("state.json")), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A crash between the temp write and the rename leaves no primary but an
    /// intact `.bak`. Returning None there made the caller rebuild from
    /// defaults and then save them over the last good state, so a survivable
    /// interruption became permanent loss.
    #[test]
    fn missing_primary_recovers_from_an_intact_backup() {
        let dir = scratch("missing-primary");
        let p = dir.join("state.json");
        write_atomic(&p, br#"{"queue": [7, 8, 9]}"#).unwrap();
        load_json_with_backup(&p).unwrap(); // seeds the .bak
        std::fs::remove_file(&p).unwrap(); // the rename never landed

        let got = load_json_with_backup(&p).expect("must recover from .bak");
        assert_eq!(got["queue"][0], 7);
        assert!(p.exists(), "recovery should also restore the primary");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// ...but a genuine reset - both files gone - still resets.
    #[test]
    fn removing_both_files_is_still_a_reset() {
        let dir = scratch("full-reset");
        let p = dir.join("state.json");
        write_atomic(&p, br#"{"queue": [1]}"#).unwrap();
        load_json_with_backup(&p).unwrap();
        std::fs::remove_file(&p).unwrap();
        std::fs::remove_file(sibling(&p, ".bak")).unwrap();

        assert_eq!(load_json_with_backup(&p), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn torn_file_falls_back_to_bak_and_next_save_keeps_data() {
        let dir = scratch("torn");
        let p = dir.join("state.json");
        write_atomic(&p, br#"{"queue": [1, 2, 3]}"#).unwrap();
        load_json_with_backup(&p).unwrap(); // seeds the .bak
        // ENOSPC / crash mid-write: the file survives truncated.
        let full = std::fs::read(&p).unwrap();
        std::fs::write(&p, &full[..full.len() / 2]).unwrap();
        // The loader refuses the torn file and serves the last good parse…
        assert_eq!(load_json_with_backup(&p), Some(json!({"queue": [1, 2, 3]})));
        // …quarantines the torn bytes, and self-heals the main file.
        assert!(sibling(&p, ".corrupt").is_file());
        assert_eq!(std::fs::read(&p).unwrap(), full);
        // The usual mutate-and-save cycle now writes last-good + the
        // change - nothing erased.
        let mut v = load_json_with_backup(&p).unwrap();
        v["extra"] = json!(true);
        write_atomic(&p, serde_json::to_string(&v).unwrap().as_bytes()).unwrap();
        let re = load_json_with_backup(&p).unwrap();
        assert_eq!(re["queue"], json!([1, 2, 3]));
        assert_eq!(re["extra"], json!(true));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn zero_byte_file_without_bak_preserves_bytes() {
        let dir = scratch("zero");
        let p = dir.join("state.json");
        std::fs::write(&p, b"").unwrap(); // torn to nothing, no .bak yet
        assert_eq!(load_json_with_backup(&p), None);
        // The (empty) evidence is set aside, not silently overwritten.
        assert!(sibling(&p, ".corrupt").is_file());
        assert!(!p.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }
}

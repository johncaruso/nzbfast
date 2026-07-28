//! Watch-folder dedupe against HISTORY, not just the live queue.
//!
//! The watcher deletes an ingested .nzb, and that deletion is the durable
//! "consumed" marker. When it cannot happen - a read-only share, a NAS
//! that refuses the unlink, a user who keeps the file deliberately - the
//! only thing standing between the release and a second full download is
//! the nzb_sha check. That check asked the live queue and nothing else,
//! so the moment the job finished and moved to history the answer went
//! back to "no" and the next daemon start re-downloaded the whole thing.
//! The in-process skip list covers the running process only.
//!
//! Both directions are asserted here: a completed history row stops the
//! re-ingest, and an install with no such row still ingests normally (so
//! a passing skip test cannot be a watcher that simply never ran).

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap().port()
}

struct KillOnDrop(Child);
impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct Running {
    _child: KillOnDrop,
    log: PathBuf,
}

impl Running {
    fn log(&self) -> String {
        std::fs::read_to_string(&self.log).unwrap_or_default()
    }

    /// Wait for `needle` to appear in the daemon's own output.
    fn wait_for(&self, needle: &str) -> String {
        for _ in 0..200 {
            let l = self.log();
            if l.contains(needle) {
                return l;
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        panic!("never saw {needle:?}\n--- log ---\n{}", self.log());
    }
}

/// A minimal but COMPLETE nzb - the watcher refuses anything without a
/// closing tag, and the whole point of this test is what happens after it
/// is accepted.
fn sample_nzb() -> String {
    "<?xml version=\"1.0\"?>\n\
     <nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n  \
     <file poster=\"x\" date=\"0\" subject=\"&quot;dedupe.bin&quot; yEnc (1/1)\">\n    \
     <groups><group>g</group></groups>\n    \
     <segments>\n      \
     <segment bytes=\"1000\" number=\"1\">dedupe@x</segment>\n    \
     </segments>\n  </file>\n</nzb>\n"
        .to_string()
}

fn sha_of(bytes: &[u8]) -> String {
    use sha2::Digest as _;
    format!("{:x}", sha2::Sha256::digest(bytes))
}

/// A config dir, a watch dir with one .nzb in it, and the sha the daemon
/// will compute for that file.
fn scratch(name: &str) -> (PathBuf, PathBuf, String) {
    let dir = std::env::temp_dir()
        .join(format!("nzbfast-watchdedupe-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let watch = dir.join("watch");
    std::fs::create_dir_all(&watch).unwrap();
    // No servers: nothing here is allowed to reach a provider.
    std::fs::write(dir.join("config.json"), "{\"servers\":[]}").unwrap();
    // ...and no Trash either. Ingesting a watched .nzb DELETES it, and
    // `smart::TRASH` defaults ON outside a `cfg(test)` build - which the
    // daemon spawned below is not - so two of the tests here were filing
    // release.nzb into the developer's own ~/.Trash on every `cargo test`.
    // The daemon reads this key from settings.json on startup, next to the
    // config, and there is no flag for it.
    std::fs::write(dir.join("settings.json"), "{\"delete_to_trash\":false}").unwrap();
    let nzb = sample_nzb();
    std::fs::write(watch.join("release.nzb"), &nzb).unwrap();
    (dir, watch, sha_of(nzb.as_bytes()))
}

/// Seed `.spool/queue.json` with one history record, exactly as the
/// daemon would have persisted it after finishing this release.
fn seed_history(dir: &Path, sha: &str, state: &str) {
    let spool = dir.join(".spool");
    std::fs::create_dir_all(&spool).unwrap();
    let record = serde_json::json!({
        "nzo_id": "SABnzbd_nzo_seed",
        "name": "release.nzb",
        "nzb_path": spool.join("release.nzb").to_string_lossy(),
        "out_dir": dir.join("complete/release").to_string_lossy(),
        "state": state,
        "nzb_sha": sha,
    });
    let v = serde_json::json!({ "next_id": 2, "queue": [], "history": [record] });
    std::fs::write(spool.join("queue.json"), serde_json::to_string_pretty(&v).unwrap()).unwrap();
}

/// Start the daemon watching `watch`, loopback-bound and keyless (the
/// assertions here are about the watch poller, not about auth).
fn serve(dir: &Path, watch: &Path) -> Running {
    let log = dir.join("daemon.log");
    let out = std::fs::File::create(&log).unwrap();
    let err = out.try_clone().unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_nzbfast"))
        .env("NZBFAST_NO_ENRICH", "1")
        .env("NZBFAST_OPEN", "1")
        .arg("--config")
        .arg(dir.join("config.json"))
        .arg("serve")
        .arg("--port")
        .arg(free_port().to_string())
        .arg("--bind")
        .arg("127.0.0.1")
        .arg("--out")
        .arg(dir.join("complete"))
        .arg("--watch")
        .arg(watch)
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err))
        .spawn()
        .unwrap();
    Running { _child: KillOnDrop(child), log }
}

/// THE REGRESSION: an unremovable watched .nzb whose release is already
/// in history must be left alone, not downloaded a second time.
#[test]
fn a_completed_history_row_stops_a_watched_nzb_being_ingested_again() {
    let (dir, watch, sha) = scratch("completed");
    seed_history(&dir, &sha, "Completed");

    let r = serve(&dir, &watch);
    let log = r.wait_for("has already been downloaded");
    assert!(
        !log.contains("release.nzb rejected"),
        "the skip must be the history check, not a parse failure\n{log}"
    );
    // The user's file is the thing at stake: still there, untouched.
    assert!(
        watch.join("release.nzb").exists(),
        "a skipped file must be left where the user put it\n{log}"
    );
    // ...and nothing was queued behind it.
    std::thread::sleep(std::time::Duration::from_millis(500));
    let queued = std::fs::read_to_string(dir.join(".spool/queue.json")).unwrap_or_default();
    assert!(
        !queued.contains("\"origin\": \"watch\""),
        "the release was enqueued despite already being in history\n{queued}"
    );

    drop(r);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The control: with nothing in history, the same file is ingested and
/// the source is taken away as usual. Without this, a watcher that never
/// ran at all would pass the test above.
#[test]
fn a_watched_nzb_with_no_history_is_still_ingested() {
    let (dir, watch, _sha) = scratch("fresh");

    let r = serve(&dir, &watch);
    for _ in 0..200 {
        if !watch.join("release.nzb").exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    assert!(
        !watch.join("release.nzb").exists(),
        "an unseen .nzb should have been ingested and its source removed\n--- log ---\n{}",
        r.log()
    );

    drop(r);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A FAILED row must NOT suppress the file: a takedown that later
/// refills, or a provider outage, is exactly the case where the user
/// keeps the .nzb around so it can be retried.
#[test]
fn a_failed_history_row_still_lets_the_file_be_retried() {
    let (dir, watch, sha) = scratch("failed");
    seed_history(&dir, &sha, "Failed");

    let r = serve(&dir, &watch);
    for _ in 0..200 {
        if !watch.join("release.nzb").exists() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
    let log = r.log();
    assert!(
        !log.contains("has already been downloaded"),
        "a failed job must not become a permanent refusal to look at the file\n{log}"
    );
    assert!(
        !watch.join("release.nzb").exists(),
        "the retry should have been ingested\n{log}"
    );

    drop(r);
    let _ = std::fs::remove_dir_all(&dir);
}

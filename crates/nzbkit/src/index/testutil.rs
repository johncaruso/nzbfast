//! Shared test fixtures for the index/ modules (TODO 106 phase 2.2):
//! the WALK budget, the close-before-remove teardown, and the OverEntry
//! builders. One home, so no test module reaches into another.

use super::*;

/// A budget the split-merge and sidecar-fold walks can never spend
/// on a test-sized index: tests exercise the cursor logic, not the
/// per-call time bound.
pub(super) const WALK: std::time::Duration = std::time::Duration::from_secs(60);

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

pub(super) fn entry(subject: &str, from: &str, id: &str, bytes: u64) -> OverEntry {
    OverEntry {
        number: 0,
        subject: subject.into(),
        from: from.into(),
        message_id: format!("<{id}>"),
        bytes,
        date: 0,
    }
}

/// `entry()` hardcodes date=0 and its 4th argument is BYTES, so it
/// cannot express "posted at time T" - and a tiny payload scores as
/// junk (55), which the wall hides. This one sets a real Date and a
/// plausible size.
pub(super) fn dated_entry(subject: &str, id: &str, posted: i64) -> OverEntry {
    OverEntry {
        number: 0,
        subject: subject.into(),
        from: "poster@example".into(),
        message_id: format!("<{id}>"),
        bytes: 4_000_000_000,
        date: posted,
    }
}

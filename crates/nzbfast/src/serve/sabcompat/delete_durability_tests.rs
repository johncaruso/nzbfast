//! The JSON-RPC delete verbs' queue-to-history handover: a record this
//! facade removes from the queue must never be absent from BOTH stores
//! on disk, however the process dies.
//!
//! Its own file rather than `sabcompat.rs`'s, for the size gate (TODO
//! 106) - the parent is at its 3,000-line ceiling. Same module.

use super::*;

/// A second Daemon over the same spool, restored from whatever is on
/// disk RIGHT NOW - the crash harness's restart half. The assertion is
/// made against bytes a stop actually would have left, not a fixture
/// written to match a belief about them.
fn restart(d: &Arc<Daemon>) -> Arc<Daemon> {
    let dir = d.spool.parent().expect("spool has a parent").to_path_buf();
    let d2 = crate::serve::testutil::test_daemon(&dir);
    d2.load_queue();
    d2
}

/// `GroupDelete` on an ACTIVE job takes the row out of the queue, drops
/// the lock, and only then writes the durable history placeholder that
/// replaces it - the write is a file write and cannot go under the
/// queue mutex. Any OTHER mutation's `save_queue` landing in that gap
/// published a queue.json the record had already left while nothing in
/// history named it yet, and the coalescing saver runs on a thread of
/// its own, so it needs no user to land there. A stop right there lost
/// the record from both stores: no DELETED/MANUAL row for the dupe
/// check or the retry button, and under `GroupParkDelete` - whose whole
/// contract is "files KEPT" - a full payload on disk that nothing names
/// (read-only sweep 2, M8).
///
/// The existing regression for this shape (`histstore.rs`) writes the
/// prewrite FIRST by hand: it models the intended order rather than the
/// handler's, so it could not see this. This one drives the handler.
#[test]
fn an_active_delete_never_publishes_absence_before_its_history_row() {
    let dir = std::env::temp_dir().join(format!("nzbfast-sabdel-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let d = crate::serve::testutil::test_daemon(&dir);

    let job = Arc::new(Mutex::new(
        job_from_json(&json!({
            "nzo_id": "SABnzbd_nzo_9911", "name": "Cancelled.Release",
            "out_dir": d.out_dir().join("Cancelled.Release").to_string_lossy(),
            "nzb_path": dir.join("c.nzb").to_string_lossy(), "state": "Downloading",
        }))
        .expect("job"),
    ));
    // Every nonterminal state restores as Queued through the wire form,
    // so the live state goes on by hand.
    job.lock_ok().state = JobState::Downloading;
    d.queue.lock_ok().push_back(job.clone());
    assert!(d.save_queue(), "the queue snapshot the delete starts from");

    let open = Arc::new(std::sync::Barrier::new(2));
    let release = Arc::new(std::sync::Barrier::new(2));
    *DELETE_PREWRITE_BARRIER.lock_ok() =
        Some((d.spool.display().to_string(), open.clone(), release.clone()));

    let d2 = d.clone();
    let handler = std::thread::spawn(move || {
        let mut rpc_error = None;
        jr_editqueue(
            &d2,
            &[json!("GroupDelete"), json!(0), json!([9911])],
            &mut rpc_error,
        );
        rpc_error
    });

    // The row has left the queue and its replacement is still ahead.
    open.wait();
    // Something else saves the queue - a settings change, a priority
    // edit, the coalescing saver's own thread.
    let (tx, rx) = std::sync::mpsc::channel();
    let d3 = d.clone();
    let saver = std::thread::spawn(move || {
        let ok = d3.save_queue();
        let _ = tx.send(ok);
        ok
    });
    // It either lands here (and publishes the absence) or it is held
    // off until the replacement row is durable. Both answers are read
    // the same way: by asking what a restart would find RIGHT NOW.
    let landed = rx
        .recv_timeout(std::time::Duration::from_millis(1_500))
        .unwrap_or(false);
    {
        let d4 = restart(&d);
        let found = d4
            .queue
            .lock_ok()
            .iter()
            .chain(d4.history.lock_ok().iter())
            .any(|j| j.lock_ok().nzo_id == "SABnzbd_nzo_9911");
        assert!(
            found,
            "a save published the queue without the record before anything in \
             history named it ({}), so a stop here lost it from both stores",
            if landed {
                "the save landed"
            } else {
                "no save landed"
            }
        );
    }
    release.wait();
    assert!(handler.join().expect("delete handler").is_none());
    *DELETE_PREWRITE_BARRIER.lock_ok() = None;
    // The hold must be given back, or the first save after any delete
    // would wedge the daemon for good.
    assert!(
        saver.join().expect("the held save"),
        "the delete never released the queue-write hold"
    );

    // ...and the ordinary outcome is unchanged: the record is filed.
    let d5 = restart(&d);
    let row = d5
        .history
        .lock_ok()
        .iter()
        .find(|j| j.lock_ok().nzo_id == "SABnzbd_nzo_9911")
        .cloned()
        .expect("the deleted record must end up in history");
    let g = row.lock_ok();
    assert_eq!(g.delete_status, "MANUAL", "and must say why it is there");
    assert_eq!(g.state, JobState::Failed);
    drop(g);
    assert!(
        d5.queue.lock_ok().is_empty(),
        "and must not come back as a queued job as well"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

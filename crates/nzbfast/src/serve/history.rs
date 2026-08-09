//! The history view: the JSON the dashboard and the SAB-compatible
//! clients read, and the recategorize that relabels a finished job and
//! moves its payload to where the new category would have put it.
//!
//! Split out of serve/mod.rs by TODO 106 phase 4 - the code is verbatim,
//! only visibility changed.

use super::*;

/// Change the category of a job that already finished: relabel the
/// history entry and, when the payload sits in a folder of its own, move
/// that folder to where the new category would have put it - the
/// per-category override first, then the global completed destination,
/// then the download root, mirroring `relocate_completed`'s ladder.
///
/// A Failed job moves too - retry reuses `out_dir` when it is free, so
/// the article journal travels with the partial payload and the rerun
/// both resumes AND completes into the right place - but only under the
/// download root: the completed-move destinations are for finished
/// payloads, not in-progress state. One case relabels WITHOUT moving,
/// said out loud in the reply: a TV-filed job, whose files are
/// interleaved with other jobs' in a shared Show/Season folder, so
/// moving `out_dir` would drag innocent siblings along. The move
/// happens with no locks held - `move_tree` on a NAS is seconds, and
/// the queue must not stall behind it.
pub(super) fn history_change_cat(d: &Daemon, id: &str, cat: &str) -> Value {
    let target = d.history.lock_ok().iter().find_map(|j| {
        let g = j.lock_ok();
        (g.nzo_id == id).then(|| {
            (
                j.clone(),
                g.state,
                g.category.clone(),
                g.out_dir.clone(),
                g.filed,
                g.finalizing,
            )
        })
    });
    let Some((job, state, current, out_dir, filed, finalizing)) = target else {
        return json!({"status": false,
            "error": "no job with that nzo_id (a job still downloading keeps its category until it finishes)"});
    };
    if finalizing {
        return json!({"status": false,
            "error": "post-processing is still running for this job - try again when it settles"});
    }
    if current == cat {
        return json!({"status": true});
    }
    // Claim the job for the duration. `finalizing` above is a snapshot
    // and stops being true the moment it is read; this is a live marker
    // retry and delete both consult, so nothing can pull the record out
    // from under a move that has already started. Dropped on EVERY exit
    // below, including the early error returns.
    struct MoveClaim<'a>(&'a Daemon, String);
    impl Drop for MoveClaim<'_> {
        fn drop(&mut self) {
            self.0.moving.lock_ok().remove(&self.1);
        }
    }
    if !d.moving.lock_ok().insert(id.to_string()) {
        return json!({"status": false,
            "error": "this job's files are already being moved - try again when it settles"});
    }
    let _claim = MoveClaim(d, id.to_string());
    // The snapshot above happened BEFORE the claim went up, so re-verify
    // both of its gates now that it has: a delete that slipped into the
    // window has already removed the record (deleting files this move
    // would race), and a password unlock that slipped in has raised
    // `finalizing` (it checks `moving` only after raising, so exactly
    // one of the two proceeds). Checked before any filesystem work.
    if !d.history.lock_ok().iter().any(|j| Arc::ptr_eq(j, &job)) {
        return json!({"status": false,
            "error": "no job with that nzo_id (it was removed just now)"});
    }
    if job.lock_ok().finalizing {
        return json!({"status": false,
            "error": "post-processing is still running for this job - try again when it settles"});
    }
    let mut split_error: Option<String> = None;
    // Nothing on disk to move: relabel and stop. Otherwise move_tree fails
    // (read_dir on a missing source is ENOENT) and the category could never
    // be corrected at all - for a job whose pre-flight verdict failed it
    // before out_dir was ever created, a folder the user tidied by hand, or
    // a move_completed share that is not mounted right now. Worse, every
    // attempt left a stray empty category directory behind, because
    // move_tree's first act is create_dir_all(dst.parent()). Relabelling is
    // the one part that needs no filesystem work, so do just that.
    let source_missing = !filed && !out_dir.is_dir();
    let moved = if !filed && !source_missing {
        let base = if state == JobState::Completed {
            let cat_root = d
                .move_completed_cats
                .read()
                .unwrap()
                .iter()
                .find(|(c, _)| *c == cat)
                .map(|(_, p)| p.clone());
            match (cat_root, d.move_completed.read_ok().clone()) {
                // The override IS that category's root - no repeated component.
                (Some(root), _) => root,
                (None, Some(root)) if !cat.is_empty() => root.join(cat),
                (None, Some(root)) => root,
                (None, None) if !cat.is_empty() => d.out_dir().join(cat),
                (None, None) => d.out_dir(),
            }
        } else if cat.is_empty() {
            d.out_dir()
        } else {
            d.out_dir().join(cat)
        };
        // Pick a free name rather than merging blind. The queued-job arm
        // goes through refile_out_dir with dir_claim, and retry does the
        // same, for the reason its comment gives: re-using a claimed
        // directory would put two live jobs in it. Without this, re-adding
        // the same NZB under another category (which claims the folder while
        // held as a duplicate) and then recategorising the finished one
        // merges a whole payload into the claimed directory - and both
        // history records then name it, so plan_history_delete marks each as
        // the other's claimant and "Remove and delete files" silently
        // refuses for both, leaving a folder undeletable from the UI.
        let stem = out_dir
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        // Under the same lock the enqueue and retry paths pick THEIR
        // directories with, and reserved before the lock goes: a free
        // name is only free until somebody takes it, and no record will
        // name this one until the move below finishes.
        struct Reservation<'a>(&'a Daemon, PathBuf);
        impl Drop for Reservation<'_> {
            fn drop(&mut self) {
                self.0.reserved.lock_ok().remove(&self.1);
            }
        }
        let dest = {
            let _publish = d.add_lock.lock_ok();
            let dest = choose_out_dir(&base.join(&stem), &stem, &|p| d.dir_claim(p)).0;
            d.reserved.lock_ok().insert(dest.clone());
            dest
        };
        let _reservation = Reservation(d, dest.clone());
        // Same aliasing guard as relocate_completed: a dest that IS the
        // current folder through case or symlinks must not self-merge.
        let same = dest == out_dir
            || matches!((dest.canonicalize(), out_dir.canonicalize()),
                        (Ok(a), Ok(b)) if a == b);
        if same {
            None
        } else {
            // Count first: move_tree's same-filesystem merge moves entry by
            // entry and propagates the first error, so a failure can leave
            // the payload split across both folders. Without this the whole
            // failure is indistinguishable from "nothing happened".
            let before = file_count(&out_dir);
            match crate::smart::move_tree(&out_dir, &dest) {
                Ok(()) => {
                    info!(target: "move", "recategorized → {}", dest.display());
                    Some(dest)
                }
                Err(e) => {
                    // Same split detection relocate_completed does. A
                    // partial move is the ordinary Windows case: the
                    // whole-directory rename is refused while a child is
                    // open, the merge path runs, and it stops at the open
                    // file having already moved the siblings.
                    let moved_some = file_count(&out_dir) < before;
                    error!(
                        target: "move",
                        "{} → {}: {e}\n[move] {}",
                        out_dir.display(),
                        dest.display(),
                        if moved_some {
                            format!(
                                "the payload is now SPLIT - some files moved before this \
                                 failed. Check both {} and {} before deleting either.",
                                out_dir.display(),
                                dest.display()
                            )
                        } else {
                            format!(
                                "nothing moved - the download is still at {}",
                                out_dir.display()
                            )
                        }
                    );
                    if moved_some {
                        // The files that moved exist nowhere else, so the
                        // record has to follow the bytes even though the
                        // call failed - leaving it on the half-emptied
                        // source points the dashboard, a later delete and
                        // the *arr import at a folder they have left.
                        // Reported as a failure below, after the state is
                        // updated, so the user is told rather than shown a
                        // success over a split payload.
                        split_error = Some(format!(
                            "the files are now SPLIT between {} and {} because the move \
                             failed part way ({e}). Check both before deleting either.",
                            out_dir.display(),
                            dest.display()
                        ));
                        Some(dest)
                    } else {
                        // Nothing moved: leave the category alone too. A
                        // label saying "movies" over files still sitting in
                        // tv/ is a lie that outlives the error message.
                        return json!({"status": false,
                            "error": format!("could not move the files: {e}")});
                    }
                }
            }
        }
    } else {
        None
    };
    // Commit under the history lock, against a record that is still the
    // one we snapshotted. The `moving` marker keeps retry and delete
    // off this job, but the check is cheap and it is the last chance to
    // notice that the record went somewhere else - a job the user
    // deleted just before the marker went up, say. Writing `out_dir`
    // into a detached Arc would point nothing at the bytes we just
    // moved, and `save_queue` would not persist it either.
    {
        let h = d.history.lock_ok();
        if !h.iter().any(|j| Arc::ptr_eq(j, &job)) {
            let where_ = moved.clone().unwrap_or_else(|| out_dir.clone());
            return json!({"status": false,
                "error": format!(
                    "the history entry was removed while its files were being moved - \
                     they are now at {}",
                    where_.display()),
                "path": where_.to_string_lossy()});
        }
        let mut g = job.lock_ok();
        g.category = cat.to_string();
        if let Some(p) = &moved {
            g.out_dir = p.clone();
        }
        // UX §18: a recategorize that stopped part way leaves the
        // payload in two directories, and `out_dir` has just followed
        // the bytes that made it. The error below tells whoever pressed
        // the button, once - it was the ONLY witness, and it does not
        // survive a page reload. Record the source the way the
        // completion path records it, so the row keeps warning and a
        // later delete has something to reach the other half by.
        //
        // SET, never cleared: a job that was already split by its
        // completion move still is - this relocation only touched
        // `out_dir`, and the source half it knows about is untouched.
        if split_error.is_some() {
            g.move_split = out_dir.to_string_lossy().to_string();
        }
    }
    d.register_cat(cat);
    // The record commit is PART of the move: a recategorize that
    // physically relocated the payload and then could not persist the
    // record restores the OLD one at restart, pointing every later
    // delete/retry/import at the emptied source while the bytes sit
    // unclaimed at the destination (Codex sweep 5 Aug M5). The live
    // record is right either way - what failed is durability, and the
    // caller has to hear it with both paths in hand. §129 1a: the
    // record lives in the history store now, so THAT append is the
    // durability that matters here.
    let durability = (!d.history_upsert(std::slice::from_ref(&job))).then(|| match &moved {
        Some(dest) => format!(
            "the updated record could not be written to the history store - after \
             a restart the history points at {} again while the files are at {}. \
             Check free space and write permission on the data folder, then use \
             Save queue",
            out_dir.display(),
            dest.display()
        ),
        None => format!(
            "the new category could not be written to the history store - it \
             reverts at the next restart. Check free space and write permission \
             on the data folder, then use Save queue ({cat} is live for now)"
        ),
    });
    // Reported only now: the record above had to be updated first so it
    // points at where the bytes actually are, but the caller must still be
    // told this failed rather than shown a success over a split payload.
    if let Some(msg) = split_error {
        return json!({"status": false,
            "error": match &durability {
                Some(dur) => format!("{msg} Also: {dur}."),
                None => msg,
            },
            "path": moved.map(|p| p.to_string_lossy().to_string())});
    }
    if let Some(dur) = durability {
        return json!({"status": false,
            "error": dur,
            "moved": moved.as_ref().map(|p| p.to_string_lossy().to_string()),
            "path": moved.unwrap_or(out_dir).to_string_lossy()});
    }
    let note = if filed {
        "relabeled only: the files were filed into a shared TV folder and stayed there"
    } else {
        ""
    };
    // `path` is what the dashboard's toast names; kept even when nothing
    // moved so the message can still say where the files live.
    let path = moved.clone().unwrap_or(out_dir);
    json!({"status": true,
           "moved": moved.map(|p| p.to_string_lossy().to_string()),
           "path": path.to_string_lossy(),
           "note": note})
}

/// The window and filters one history read answers. §129 1a: parsed
/// once, served by ONE pass over the records - filtering, facet counts
/// and row building all under a single job-lock acquisition per record,
/// with the GLOBAL history lock held only long enough to clone the Arc
/// list (a pointer copy per record). Before this, every read held the
/// global lock across an O(all-time) JSON build, which is what a
/// one-year history turns into a wedge.
pub(super) struct HistQuery {
    pub failed_only: bool,
    pub category: Option<String>,
    pub ids: Option<std::collections::HashSet<String>>,
    /// Case-insensitive substring over the names a user knows a
    /// download by: posted name, category, oracle identity, filed-as.
    /// SAB's history API takes `search` too, so the param is
    /// compat-shaped rather than invented.
    pub search: Option<String>,
    /// The dashboard's chip buckets: "done" / "failed" / "locked"
    /// (anything else = all). Narrower than `failed_only` and additive
    /// to it; the facet counts are computed before either applies.
    pub bucket: Option<String>,
    pub start: usize,
    /// 0 = everything (SAB semantics).
    pub limit: usize,
}

impl HistQuery {
    pub(super) fn from_params(params: &std::collections::HashMap<String, String>) -> Self {
        HistQuery {
            failed_only: params.get("failed_only").map(String::as_str) == Some("1"),
            category: params
                .get("category")
                .filter(|c| !c.is_empty() && *c != "*")
                .cloned(),
            ids: nzo_ids_param(params),
            search: params
                .get("search")
                .map(|s| s.trim().to_lowercase())
                .filter(|s| !s.is_empty()),
            bucket: params
                .get("bucket")
                .filter(|b| matches!(b.as_str(), "done" | "failed" | "locked"))
                .cloned(),
            start: params
                .get("start")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0),
            limit: params
                .get("limit")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0),
        }
    }
}

/// One history read: `(slots, noofslots, counts)`. `summary` picks the
/// compact per-row shape (`mode=dashboard`'s list) over the full SAB
/// facade row; `noofslots` counts everything the filters matched, not
/// the window; `counts` are the bucket facets (all/done/failed/locked)
/// over the search/category/ids-filtered set - the client's chips need
/// them and must not need the whole payload to compute them any more.
pub(super) fn history_page(d: &Daemon, q: &HistQuery, summary: bool) -> (Vec<Value>, usize, Value) {
    // Snapshot the Arcs; drop the global lock before any job lock.
    let arcs: Vec<Arc<Mutex<Job>>> = d.history.lock_ok().clone();
    let (mut all, mut done, mut failed, mut locked) = (0usize, 0usize, 0usize, 0usize);
    // What the header's one-click clear would take: Completed and not
    // password-locked (locked rows survive the value=completed sweep).
    let mut clearable = 0usize;
    let mut matched = 0usize;
    let mut slots: Vec<Value> = Vec::new();
    for j in arcs.iter().rev() {
        let j = j.lock_ok();
        // §91: selected, counted and rendered under ONE lock on the
        // record. Taking it twice - once to test the filter, again to
        // build the row - let the two see different states: a Failed
        // job whose auto-retry cooldown came due between them is pulled
        // back out of history and reset to Queued, so `failed_only=1`
        // answered with a row saying `"status": "Queued"` and an empty
        // `fail_kind` / `fail_action`. An *arr asking for failures is
        // entitled to get only failures back, and the remedy keys it
        // reads to act on one must be there.
        if !q.category.as_ref().is_none_or(|c| j.category == *c)
            || !q.ids.as_ref().is_none_or(|s| s.contains(j.nzo_id.as_str()))
        {
            continue;
        }
        if let Some(needle) = &q.search {
            let hit = j.name.to_lowercase().contains(needle)
                || j.category.to_lowercase().contains(needle)
                || j.identity_name.to_lowercase().contains(needle)
                || j.filed_base
                    .as_ref()
                    .is_some_and(|b| b.to_lowercase().contains(needle));
            if !hit {
                continue;
            }
        }
        // Facets over the search/category set, BEFORE the failed_only
        // bucket narrows it - they are what the bucket chips display.
        all += 1;
        if j.state == JobState::Failed {
            failed += 1;
        } else {
            done += 1;
        }
        if j.password_required {
            locked += 1;
        }
        if j.state == JobState::Completed && !j.password_required {
            clearable += 1;
        }
        if q.failed_only && j.state != JobState::Failed {
            continue;
        }
        match q.bucket.as_deref() {
            Some("done") if j.state != JobState::Completed => continue,
            Some("failed") if j.state != JobState::Failed => continue,
            Some("locked") if !j.password_required => continue,
            _ => {}
        }
        let idx = matched;
        matched += 1;
        // Direct id selection bypasses the window (SAB semantics: a
        // named id is always findable, whatever page is showing).
        if q.ids.is_none() && q.limit > 0 && (idx < q.start || idx >= q.start + q.limit) {
            continue;
        }
        if q.ids.is_none() && q.limit == 0 && idx < q.start {
            continue;
        }
        slots.push(if summary {
            history_summary(d, &j)
        } else {
            history_row(d, &j)
        });
    }
    let counts = json!({"all": all, "done": done, "failed": failed, "locked": locked,
                        "clearable": clearable});
    (slots, matched, counts)
}

/// §129 1b: the compact row `mode=dashboard` lists. What the LIST
/// renders and nothing else - the drawer fetches the full row on demand
/// via `mode=history&nzo_ids=`. Keys are a subset of the facade row's,
/// under the same names, so the client renders both with one template.
fn history_summary(d: &Daemon, j: &Job) -> Value {
    json!({
        "nzo_id": j.nzo_id,
        "name": j.name,
        "category": if j.category.is_empty() { "*" } else { &j.category },
        "status": match j.state { JobState::Completed => "Completed", JobState::Failed => "Failed", _ => "Queued" },
        "bytes": j.total_bytes,
        "size": format!("{:.1} MB", j.total_bytes as f64 / API_MB),
        "completed": j.finished_unix.unwrap_or(0),
        "origin": j.origin,
        "retry": j.retries,
        "library": j.library,
        "fail_message": j.fail_message,
        "fail_kind": if j.state == JobState::Failed {
            fail_kind_token(fail_kind(&j.fail_message))
        } else {
            ""
        },
        "fail_action": if j.state == JobState::Failed {
            fail_action(
                fail_kind(&j.fail_message),
                fail_hint(&j.fail_message),
                &j.fail_message,
                j.password_required,
            )
        } else {
            ""
        },
        "auto_retry_at": j.auto_retry_at,
        "password_required": j.password_required,
        "has_password": j.password.is_some(),
        "media": j.media,
        "archive_shape": j.archive_shape,
        "identity_name": j.identity_name,
        "downloaded_bytes": j.downloaded_bytes,
        "elapsed_secs": (j.elapsed_secs * 10.0).round() / 10.0,
        "bad_blocks": j.bad_blocks,
        "verify_blocks": j.verify_blocks,
        "unpack_blocked_by": j.unpack_blocked_by,
        "move_split": j.move_split,
        "move_failed": j.move_failed,
        "move_attempts": j.move_attempts,
        "move_pending": j.move_pending,
        "moved_to": if j.out_dir.starts_with(d.out_dir()) {
            String::new()
        } else {
            j.out_dir.to_string_lossy().into_owned()
        },
        "storage": j.out_dir.to_string_lossy(),
    })
}

pub(super) fn history_json(
    d: &Daemon,
    params: &std::collections::HashMap<String, String>,
) -> Value {
    let q = HistQuery::from_params(params);
    let (slots, n, counts) = history_page(d, &q, false);
    json!({"history": {"slots": slots, "noofslots": n, "counts": counts}})
}

/// The full SAB facade row - the pre-§129 key set, byte-stable for
/// external clients (pinned by tests/dashboard_rev.rs). Built under the
/// caller's job lock.
fn history_row(d: &Daemon, j: &Job) -> Value {
    {
        // Truth-audit I: what this download is CALLED on disk, when
        // that is not what it was posted as. A de-obfuscation rename
        // left the history row saying "a4f9c2e1" and the folder
        // saying "Example.Movie.2019.1080p-GRP", with nothing
        // anywhere connecting the two - so a user who went looking
        // for their download could not tell which folder was it.
        // Empty when the two agree, so the drawer shows the row only
        // when there is something to reconcile.
        let filed_as = {
            let disk = if j.filed {
                // A TV-filed job's directory is the SHARED season
                // folder, so its name says nothing about this
                // episode. The stem the episode files were written
                // under is the answer.
                j.filed_base.clone().unwrap_or_else(|| j.name.clone())
            } else {
                j.out_dir
                    .file_name()
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_default()
            };
            if disk == j.name { String::new() } else { disk }
        };
        // ...and whether `move_completed` put the payload somewhere
        // the download folder does not contain. The completion toast
        // announced a finished download and said nothing about the
        // files having gone to a NAS. Empty for everything still
        // under the download root.
        let moved_to = if j.out_dir.starts_with(d.out_dir()) {
            String::new()
        } else {
            j.out_dir.to_string_lossy().into_owned()
        };
        json!({
            "nzo_id": j.nzo_id,
            "name": j.name,
            "nzb_name": format!("{}.nzb", j.name),
            "origin": j.origin,
            "nzb_path": j.nzb_path.to_string_lossy(),
            "category": if j.category.is_empty() { "*" } else { &j.category },
            "status": match j.state { JobState::Completed => "Completed", JobState::Failed => "Failed", _ => "Queued" },
            "fail_message": j.fail_message,
            "fail_detail": j.fail_detail,
            // This failure was a full disk, decided by the same
            // matcher the NZBGet SPACE verdict uses. Its own key so
            // the drawer can pair the row with the LIVE free-space
            // number instead of string-matching a sentence: the fix
            // is entirely in the user's hands, and Retry re-runs
            // just the unpack (the article journal re-fetches
            // nothing while the volumes are intact).
            "disk_full": j.state == JobState::Failed && disk_full_failure(&j.fail_message),
            // What the retry actually needs FREE, which is not the
            // set size: the volumes are already on the disk, so the
            // room owed is the extracted payload - and, for an
            // ENCRYPTED set, the finish decrypt's temp copy beside
            // it as well. The drawer used to gate its Retry button
            // on `bytes` alone and would have lit it up one whole
            // payload too early on exactly the shape that hit this
            // (RAR5 encrypted, a tester, 2 Aug).
            "space_needed": unpack_space_needed(0, j.total_bytes, &j.archive_shape),
            // The failure classifier as a token, so the drawer can
            // say what to DO per kind - and suppress Retry for the
            // two kinds the daemon itself knows retrying cannot fix
            // (gone, preflight). Empty on anything not Failed.
            "fail_kind": if j.state == JobState::Failed {
                fail_kind_token(fail_kind(&j.fail_message))
            } else {
                ""
            },
            // M32: when the daemon has already scheduled its own
            // retry, say so - the user was shown a hard failure and
            // then watched the row silently resurrect. Unix seconds,
            // null when no retry is armed.
            "auto_retry_at": j.auto_retry_at,
            // ...and WHAT it is waiting for ("transport" or
            // "propagation"), which is also why the cooldown is the
            // length it is. Null when no retry is armed.
            "auto_retry_why": j.auto_retry_why,
            // The sub-cause inside the message, for the ONE remedy
            // button the drawer offers beside the reason. Two
            // failures can share a fail_kind and need opposite next
            // moves - see `fail_hint`. Empty on anything not Failed.
            "fail_hint": if j.state == JobState::Failed {
                fail_hint(&j.fail_message)
            } else {
                ""
            },
            // ...and the single action that answers it. One key so
            // the page never has to re-derive the rule, and so the
            // rule itself is testable.
            "fail_action": if j.state == JobState::Failed {
                fail_action(
                    fail_kind(&j.fail_message),
                    fail_hint(&j.fail_message),
                    &j.fail_message,
                    j.password_required,
                )
            } else {
                ""
            },
            "retry": j.retries,
            // This job came out of the local index rather than from
            // an NZB the user holds. It matters on a failure: a
            // "gone" verdict here means the post rotted out of the
            // library, nothing was ever written to disk, and the
            // copy must not talk about resuming what downloaded.
            "library": j.library,
            "duplicate_key": j.dupe_key.as_deref().unwrap_or(""),
            "storage": j.out_dir.to_string_lossy(),
            "path": j.out_dir.to_string_lossy(),
            "bytes": j.total_bytes,
            "size": format!("{:.1} MB", j.total_bytes as f64 / API_MB),
            // Stats (0 until a download actually ran): bytes ÷ secs
            // is the average network speed for this job.
            "downloaded_bytes": j.downloaded_bytes,
            "elapsed_secs": (j.elapsed_secs * 10.0).round() / 10.0,
            // SAB's native key for "when did this finish", unix
            // seconds. 0 for spool entries that predate
            // `finished_unix` - clients treat that as "unknown",
            // never as 1970.
            "completed": j.finished_unix.unwrap_or(0),
            // NULL when nothing verified this download (no PAR2 in
            // the post, or a resume that mapped no block) - the
            // dashboard says "not verified" for that and keeps it
            // out of the clean count. A number is a real verdict,
            // and `verify_blocks` is how many blocks produced it.
            "bad_blocks": j.bad_blocks,
            "verify_blocks": j.verify_blocks,
            // M24: the value never leaves the daemon - only the facts.
            "password_required": j.password_required,
            "has_password": j.password.is_some(),
            // Completed, but something in it is still packed. SAB has
            // no field for "succeeded with a caveat", so the archive
            // NAME rides in its own key (the dashboard composes the
            // sentence in the user's own language) while an English
            // one goes in the SAB-native `script_line` - the single
            // free-text slot a Completed history item has, and one
            // existing clients already surface beside the status.
            "unpack_blocked_by": j.unpack_blocked_by,
            // UX §18: the move to the completed folder stopped part
            // way and the payload is in TWO directories - this one
            // and `storage`. Its own key beside `unpack_blocked_by`
            // and for the same reason: SAB has no "succeeded with a
            // caveat", so the PATH rides here and the dashboard
            // composes the sentence in the user's own language.
            // Empty on everything that moved whole or never moved.
            "move_split": j.move_split,
            "move_failed": j.move_failed,
            // How many tries the ladder has spent. The drawer says
            // "tried N times" off this, and says the daemon has
            // stopped once it reaches the give-up count.
            "move_attempts": j.move_attempts,
            "move_pending": j.move_pending,
            "archive_shape": j.archive_shape,
            // §76: the same quality chip the queue row carries,
            // latched during the download and kept. Another additive
            // key - a client that does not know it ignores it.
            "media": j.media,
            // What an identity oracle said this release is, beside
            // the name it was posted under. Additive keys: `name`
            // stays exactly what every SAB client already matches
            // on, and a client that does not know these ignores
            // them.
            "identity_name": j.identity_name,
            "identity_imdb": j.identity_imdb,
            "identity_src": j.identity_src,
            "filed_as": filed_as,
            // The Smart Folder rule that chose its category, same
            // reason: "why is this in Films?" is answerable only by
            // the rule that decided it.
            "smart_rule": j.smart_rule,
            "moved_to": moved_to,
            // What the post-processing sweeps removed from this
            // job's directory, and whether the deletes were
            // recoverable when they ran. Additive keys; zero means
            // no drawer line.
            "cleaned_files": j.cleaned_files,
            "cleaned_par2": j.cleaned_par2,
            "cleaned_trash": j.cleaned_trash,
            // ...and when no oracle could name it, what synthesised
            // naming made of the payload: the file's own facts, then
            // the shortlist. English, and deliberately so - film
            // titles are not ours to translate, and the runtimes and
            // codecs in it are not words. See Job::identify.
            "identify": j.identify,
            "script_line": if j.unpack_blocked_by.is_empty() {
                String::new()
            } else {
                format!(
                    "{} could not be unpacked: it is damaged, encrypted, or uses \
                     a compression method this build does not carry. The verified \
                     archive is in the output folder.",
                    j.unpack_blocked_by
                )
            },
        })
    }
}

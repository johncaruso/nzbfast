//! What counts as a duplicate at add time, and what the add reply says
//! about it.
//!
//! Three questions that are really one: does this stem collide with a
//! release already known (`dupe_collision`), does it collide through an
//! enriched ALIAS of the same show rather than a matching string
//! (`dupe_alias_collision`), and did the job we just added end up parked
//! as a held alternative rather than queued (`held_as_duplicate`, which
//! is read back because `enqueue`'s signature is shared by sixteen call
//! sites).
//!
//! Split out of `serve/daemon.rs` whole (TODO 106 size gate) - the code
//! is verbatim, only its home changed. `pub(super)` and `pub(crate)`
//! mean here exactly what they meant there: this file is another child
//! of `crate::serve`.

use super::*;

impl Daemon {
    /// Where an equivalent release already lives, if anywhere: `("queue" |
    /// "history", that job's name)`. This is the M14f identity check,
    /// lifted out of `enqueue` so the UI can ASK before it adds rather
    /// than only discovering the hold afterwards - a wall Play that
    /// silently became a paused duplicate looked, from the outside, like
    /// a download that simply never started.
    ///
    /// PROPERs are never duplicates, and a stem with no derivable key is
    /// never one either. Same rules the hold itself applies, because it
    /// is the same code.
    pub(crate) fn dupe_collision(&self, stem: &str) -> Option<DupeCollision> {
        if is_proper(stem) {
            return None;
        }
        // dupe_scope = "exact" (#41): only a re-add of the same release
        // name is a duplicate, compared through `exact_dupe_key` so
        // separator styles still meet. The smart key stays on the job
        // either way - held alternatives keep auto-promoting by
        // identity, this only narrows what collides at add time.
        let exact = self.dupe_scope.lock_ok().as_str() == "exact";
        let smart_k = dupe_key(stem);
        let exact_k = exact_dupe_key(stem);
        if exact {
            if exact_k.is_empty() {
                return None;
            }
        } else {
            smart_k.as_ref()?;
        }
        let hit = |g: &Job| {
            if exact {
                exact_dupe_key(&g.name) == exact_k
            } else {
                g.dupe_key == smart_k
            }
        };
        let queued = self.queue.lock_ok().iter().find_map(|j| {
            let g = j.lock_ok();
            hit(&g).then(|| DupeCollision {
                where_: "queue",
                name: g.name.clone(),
                nzo_id: g.nzo_id.clone(),
            })
        });
        if queued.is_some() {
            return queued;
        }
        let done = self.history.lock_ok().iter().find_map(|j| {
            let g = j.lock_ok();
            (hit(&g) && g.state == JobState::Completed).then(|| DupeCollision {
                where_: "history",
                name: g.name.clone(),
                nzo_id: g.nzo_id.clone(),
            })
        });
        if done.is_some() {
            return done;
        }
        if exact {
            return None;
        }
        self.dupe_alias_collision(stem, &smart_k?)
    }

    /// The alias arm of the smart duplicate check: the SAME episode of
    /// the SAME show, posted under a different spelling of the show's
    /// name ("Show.S01E06" vs "Show.The.Full.Subtitle.S01E06"). The two
    /// spellings flatten to different dupe keys, so the key comparison
    /// above can never meet them - Gary downloaded one episode twice on
    /// 14 Aug 2026 exactly this way.
    ///
    /// "Same show" is never guessed from the strings. A prefix or
    /// containment rule would also match a spin-off whose name extends
    /// its parent's, and a false duplicate silently SKIPS a wanted
    /// download - strictly worse than the duplicate it prevents. The
    /// only accepted witness is the index's enrichment record: both
    /// title keys resolved, independently, to the same TVmaze show id.
    /// No index, no enrichment yet, or either title unresolved → not a
    /// duplicate, same as before this arm existed.
    fn dupe_alias_collision(&self, stem: &str, smart_k: &str) -> Option<DupeCollision> {
        // Only the SxxEyy identity. Movie years and daily dates carry
        // their own aliasing questions; this arm answers the one that
        // bit.
        let (head, ep) = smart_k.rsplit_once('/')?;
        let digits = ep.strip_prefix('s')?;
        let (s, e) = digits.split_once('e')?;
        if s.is_empty()
            || e.is_empty()
            || !s.bytes().all(|c| c.is_ascii_digit())
            || !e.bytes().all(|c| c.is_ascii_digit())
        {
            return None;
        }
        // Candidates first, index lookups after: collected under the
        // queue/history locks (cheap clones only - the index read must
        // not run under either), a job is a candidate when its key
        // names the same episode of a DIFFERENT title.
        let same_ep = |g: &Job| {
            g.dupe_key
                .as_deref()
                .and_then(|k| k.rsplit_once('/'))
                .is_some_and(|(h, other)| other == ep && h != head)
        };
        let mut cands: Vec<DupeCollision> = self
            .queue
            .lock_ok()
            .iter()
            .filter_map(|j| {
                let g = j.lock_ok();
                same_ep(&g).then(|| DupeCollision {
                    where_: "queue",
                    name: g.name.clone(),
                    nzo_id: g.nzo_id.clone(),
                })
            })
            .collect();
        cands.extend(self.history.lock_ok().iter().filter_map(|j| {
            let g = j.lock_ok();
            (same_ep(&g) && g.state == JobState::Completed).then(|| DupeCollision {
                where_: "history",
                name: g.name.clone(),
                nzo_id: g.nzo_id.clone(),
            })
        }));
        if cands.is_empty() {
            return None;
        }
        let parsed = nzbkit::release::parse_release(stem);
        if parsed.kind != nzbkit::release::Kind::Tv {
            return None;
        }
        // The add's own show id gates everything: unresolved means no
        // candidate can be proven the same show, so no lookups run at
        // all and the ordinary add pays nothing here.
        let my_id = self.tv_show_id(&parsed.key)?;
        cands.into_iter().find(|c| {
            let q = nzbkit::release::parse_release(&c.name);
            q.kind == nzbkit::release::Kind::Tv && self.tv_show_id(&q.key) == Some(my_id)
        })
    }

    /// Does the collision `dupe_collision` picked still exist?
    ///
    /// Admission holds `add_lock`, but deletion does not - a queue
    /// delete takes the queue lock and a history delete the history
    /// lock, and neither asks the adder's permission. So the original
    /// an add chose to hold against can be gone by the time that add
    /// publishes, and the alternative lands paused with `held_for`
    /// naming a record nobody will ever fail: park promotion is what
    /// releases a hold, and a job that no longer exists never parks.
    ///
    /// By id and by STORE, exactly as the pick was made: a history hit
    /// only counts while it is still `Completed` (a record retried back
    /// into the queue is no longer the finished copy that made this a
    /// duplicate). See `enqueue`, which re-asks this under the queue
    /// lock it publishes with.
    pub(super) fn dupe_collision_stands(&self, c: &DupeCollision) -> bool {
        if c.where_ == "queue" {
            self.queue
                .lock_ok()
                .iter()
                .any(|j| j.lock_ok().nzo_id == c.nzo_id)
        } else {
            self.history.lock_ok().iter().any(|j| {
                let g = j.lock_ok();
                g.nzo_id == c.nzo_id && g.state == JobState::Completed
            })
        }
    }

    // `enqueue` lives in daemon_enqueue.rs (TODO 106 size-gate split),
    // a child module declared at the top of this file.

    /// Truth-audit I: did this job park as a held ALTERNATIVE instead of
    /// joining the queue to run? Read back rather than returned out of
    /// `enqueue`, whose signature sixteen call sites share; the job is in
    /// the queue by the time any caller can ask, and reading it here also
    /// answers correctly for the paths that add through
    /// `enqueue_fetched`.
    ///
    /// Without this the add reply said "Added to the queue" for a job that
    /// is paused at Duplicate priority and will not download until the
    /// original fails - the single most confusing thing the add flow could
    /// say, because the row then sits there doing nothing with no
    /// explanation the user asked for.
    pub(super) fn held_as_duplicate(&self, nzo_id: &str) -> bool {
        self.queue.lock_ok().iter().any(|j| {
            let g = j.lock_ok();
            g.nzo_id == nzo_id && g.paused && g.priority == DUPE_PRIORITY
        })
    }
}

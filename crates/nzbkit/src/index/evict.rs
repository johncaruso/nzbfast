//! Size-pressure eviction (TODO 106 phase 2.2, cut 1): the policy
//! ladder, the protected set, and `evict_to` itself. Bodies are verbatim
//! moves from the old index.rs; see research/SEAM-TABLE-index-rs-2026-08-05.md.

use super::*;

impl Index {
    /// Evict until the database would fit in `target_bytes`, honouring the
    /// policy order and never touching anything in `protected`.
    /// `target_bytes == 0` means unlimited: return immediately, remove nothing.
    ///
    /// Deletes go through `prune_batch`, so the `files` cascade, the
    /// single transaction and the FTS trigger behave exactly as they do
    /// for the age/size pruners.
    ///
    /// `bytes_after` will usually EQUAL `bytes_before`: DELETE in SQLite
    /// moves pages to the freelist, it does not shorten the file. That is
    /// correct and expected, and is the entire reason `needs_compact`
    /// exists - `compact()` takes an exclusive lock and rewrites the whole
    /// file, so the daemon schedules it for an idle window rather than
    /// having eviction do it inline.
    ///
    /// If the protected set (plus the kinds filter) leaves too little to
    /// delete, eviction stops early: the target is simply not reached and
    /// `removed` reports how far it got. Protection outranks the cap.
    pub fn evict_to(
        &self,
        target_bytes: u64,
        policy: &EvictPolicy,
        protected: &Protected,
    ) -> rusqlite::Result<EvictReport> {
        let before = self.db_bytes()?;
        let live_before = self.live_bytes()?;
        // 0 = unlimited. Do this before anything else touches the db.
        if target_bytes == 0 {
            return Ok(EvictReport {
                removed: 0,
                bytes_before: before,
                bytes_after: before,
                live_before,
                live_after: live_before,
                needs_compact: false,
                blocked: false,
            });
        }
        let low = target_bytes / EVICT_LOW_WATER_DEN * EVICT_LOW_WATER_NUM;

        // The authoritative protection check. The `NOT IN` binds below are
        // an optimisation that keeps protected rows out of the candidate
        // pages when the set is small enough to bind; these two sets are
        // what actually decides, and they hold EVERYTHING the caller
        // passed, with no cap.
        //
        // An empty title_key is dropped deliberately: `releases.title_key`
        // defaults to '' for rows that predate M28 or never parsed, so a
        // stray '' in the protected list would silently protect every
        // unclassified row in the index and wedge eviction shut.
        let prot_ids: std::collections::HashSet<i64> =
            protected.release_ids.iter().copied().collect();
        let prot_keys: std::collections::HashSet<&str> = protected
            .title_keys
            .iter()
            .map(|s| s.as_str())
            .filter(|s| !s.is_empty())
            .collect();

        // -- candidate query, built once --
        let mut params: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
        let mut wheres: Vec<String> = Vec::new();
        if !policy.kinds.is_empty() {
            // Bound parameters, never interpolated - `kinds` comes off the
            // settings API. Note an unclassified row (kind = '') matches no
            // filter, so a kind-restricted eviction spares it: protect
            // more, never less.
            let ph: Vec<String> = policy
                .kinds
                .iter()
                .map(|k| {
                    params.push(Box::new(k.clone()));
                    format!("?{}", params.len())
                })
                .collect();
            wheres.push(format!("r.kind IN ({})", ph.join(",")));
        }
        // NULL TRAP: the schema comment on `wall_hidden` records that one
        // NULL key makes `x NOT IN (SELECT ...)` evaluate NULL for every
        // row and silently disable the whole prune. These `NOT IN` lists
        // are immune by construction - they are bound literals from Rust
        // `i64`/`String`, never a subquery and never NULL - and the left
        // sides (`releases.id` PRIMARY KEY, `releases.title_key` NOT NULL)
        // cannot be NULL either. No subquery form is used anywhere in this
        // path for exactly that reason.
        let mut budget = EVICT_PROTECT_BIND_CAP;
        for chunk in protected.release_ids.chunks(EVICT_PROTECT_CHUNK) {
            if budget == 0 {
                break;
            }
            let take = chunk.len().min(budget);
            budget -= take;
            let ph: Vec<String> = chunk[..take]
                .iter()
                .map(|id| {
                    params.push(Box::new(*id));
                    format!("?{}", params.len())
                })
                .collect();
            wheres.push(format!("r.id NOT IN ({})", ph.join(",")));
        }
        for chunk in protected.title_keys.chunks(EVICT_PROTECT_CHUNK) {
            if budget == 0 {
                break;
            }
            let keys: Vec<&String> = chunk.iter().filter(|s| !s.is_empty()).collect();
            let take = keys.len().min(budget);
            if take == 0 {
                continue;
            }
            budget -= take;
            let ph: Vec<String> = keys[..take]
                .iter()
                .map(|k| {
                    params.push(Box::new((*k).clone()));
                    format!("?{}", params.len())
                })
                .collect();
            wheres.push(format!("r.title_key NOT IN ({})", ph.join(",")));
        }
        let where_sql = if wheres.is_empty() {
            String::new()
        } else {
            format!("WHERE {}", wheres.join(" AND "))
        };
        let limit_ph = params.len() + 1;
        let offset_ph = params.len() + 2;
        let sql = format!(
            "SELECT r.id, r.title_key, {EVICT_PAYLOAD_SQL} FROM releases r
             {where_sql} ORDER BY {} LIMIT ?{limit_ph} OFFSET ?{offset_ph}",
            evict_order_sql(policy.order)
        );

        // -- the eviction loop --
        //
        // Two independent stop signals, and EITHER can stop us, because
        // over-deleting is the one failure mode that costs the user data:
        //
        //  measured  - live_bytes() re-read from the file after every
        //              batch. Ground truth, but blind to space stranded
        //              in partly-emptied pages, so it can lag reality.
        //  predicted - starts at the measured size and walks down by the
        //              estimated payload of what we delete. Immune to
        //              that lag, but only as good as the estimate.
        //
        // `scale` lifts the raw payload estimate to real page cost
        // (b-tree fanout, idx_rel_stem, idx_rel_kind, FTS5). It is fitted
        // from the previous batch's observed drop rather than from a
        // whole-table scan, which on an 800k-row index would mean reading
        // every segments blob just to decide what to delete. It is
        // clamped at >= 1.0 because a deleted row's own bytes are a hard
        // floor on what a later VACUUM reclaims, and <= 4.0 so one odd
        // batch cannot make `predicted` fall off a cliff.
        //
        // ERROR BOUND, measured (see the tests at the end of this file):
        //  * blob-dominated rows, the shape that actually fills this
        //    database - real page cost / raw payload = 0.997 to 1.010.
        //    The estimate is essentially exact.
        //  * 200-byte rows, where per-row and index overhead dominates -
        //    1.18 to 1.25. The seed of 1.0 makes the FIRST batch of a
        //    call take up to ~20% more rows than it needed; every batch
        //    after it uses the fitted value.
        // A batch stops the moment the estimate reaches the low water
        // mark, so a call's overshoot is its LAST batch's overshoot, and
        // is bounded by EVICT_PAGE rows regardless of what the estimate
        // does. On top of that sits the indivisible-row floor: the row
        // that crosses the line is deleted whole, so a single 256 MB
        // release can carry the file well past the mark on its own.
        // End to end that put the test fixtures at 75-84% of the cap
        // instead of the 90% low water mark - inside the hysteresis band
        // by construction, and never near emptying the index.
        //
        // Under-shooting (the estimate claiming more freed than really
        // was) is self-correcting and costs nothing: the daemon's next
        // pass sees the file still over the cap and evicts again.
        let mut removed = 0usize;
        let mut offset = 0usize; // protected rows already stepped over
        let mut scale = 1.0f64;
        let mut predicted = self.live_bytes()? as f64;
        let mut guard = 0u32;
        // Set at every exit that is NOT "we got under the low water mark".
        // Reconciled against the real size once the loop is done.
        let mut blocked = false;
        loop {
            guard += 1;
            if guard > 100_000 {
                blocked = true;
                break;
            }
            let measured = self.live_bytes()? as f64;
            let effective = measured.min(predicted);
            if effective <= low as f64 {
                break;
            }
            let need = effective - low as f64;

            let page: Vec<(i64, String, i64)> = {
                let mut stmt = self.db.prepare_cached(&sql)?;
                let mut binds: Vec<&dyn rusqlite::ToSql> =
                    params.iter().map(|b| b.as_ref()).collect();
                let lim = EVICT_PAGE as i64;
                let off = offset as i64;
                binds.push(&lim);
                binds.push(&off);
                stmt.query_map(binds.as_slice(), |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                    .collect::<rusqlite::Result<_>>()?
            };
            if page.is_empty() {
                blocked = true;
                break; // nothing left we are allowed to touch
            }
            let exhausted = page.len() < EVICT_PAGE;

            let mut ids: Vec<i64> = Vec::new();
            let mut payload = 0f64;
            let mut skipped = 0usize;
            for (id, key, pl) in &page {
                if prot_ids.contains(id) || prot_keys.contains(key.as_str()) {
                    // Survives, and stays in the table - so the next page
                    // must start past it or we would re-read it forever.
                    skipped += 1;
                    continue;
                }
                ids.push(*id);
                payload += (*pl).max(0) as f64;
                if payload * scale >= need {
                    break;
                }
            }
            offset += skipped;
            if ids.is_empty() {
                if exhausted {
                    blocked = true;
                    break; // every remaining candidate is protected
                }
                continue; // whole page was protected; offset advanced
            }

            removed += self.prune_batch(&ids)?;
            let after = self.live_bytes()? as f64;
            if payload > 0.0 {
                scale = ((measured - after) / payload).clamp(1.0, 4.0);
            }
            predicted = (predicted - payload * scale).max(0.0);
        }

        let after = self.db_bytes()?;
        let live_after = self.live_bytes()?;
        Ok(EvictReport {
            removed,
            bytes_before: before,
            bytes_after: after,
            live_before,
            live_after,
            needs_compact: removed > 0,
            // Stopping early only counts as blocked if it actually left
            // the database over the target. Stopping between the low
            // water mark and the target is the hysteresis band doing its
            // job, not a failure.
            blocked: blocked && live_after > target_bytes,
        })
    }

    // -- Spotnet spots (M14j) - curated metadata layered over the raw index --
}

/// Which releases give way first when the index has to shrink.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EvictOrder {
    /// Default. An ordered ladder, not a single rule: reap what nobody
    /// would miss before touching anything they would.
    ///
    ///   rung 0  junk AND incomplete - dead obfuscated fragments
    ///   rung 1  junk but complete
    ///   rung 2  incomplete but not junk (a stalled/abandoned post)
    ///   rung 3  everything else - real, complete, wall-visible content
    ///
    /// and within a rung, oldest by `first_posted` first, then largest
    /// by `total_bytes` (free the most for the fewest deletions).
    /// Measured on the live index ~87% of rows sit on rungs 0-1, so in
    /// practice the ladder absorbs the whole cap before rung 3 is ever
    /// reached.
    #[default]
    Ladder,
    /// Single-key orders. No ladder, no junk/completeness preference.
    Oldest,
    Newest,
    Largest,
    Smallest,
}

#[derive(Debug, Clone, Default)]
pub struct EvictPolicy {
    pub order: EvictOrder,
    /// Restrict eviction to these kinds ("movie"/"tv"/"software"/"other").
    /// Empty = all kinds.
    pub kinds: Vec<String>,
}

/// What the daemon forbids evicting. index.rs NEVER reaches out for this -
/// the daemon owns the queue, watchlist and history and passes it in.
#[derive(Debug, Clone, Default)]
pub struct Protected {
    pub title_keys: Vec<String>,
    pub release_ids: Vec<i64>,
}

#[derive(Debug, Clone, Default)]
pub struct EvictReport {
    pub removed: usize,
    /// Raw file size (`db_bytes()`) either side of the call. This is what
    /// the user sees in Finder, so it is what the daemon reports - but it
    /// barely moves, because DELETE frees pages to the freelist rather
    /// than shortening the file. Do NOT test progress with it.
    pub bytes_before: u64,
    pub bytes_after: u64,
    /// `live_bytes()` either side of the call: the honest figure, and the
    /// one to compare against the target. `live_after <= target` is what
    /// "we got there" means.
    pub live_before: u64,
    pub live_after: u64,
    /// True when rows were deleted, so the caller should schedule a compact.
    pub needs_compact: bool,
    /// True when eviction stopped with the database still above its
    /// target because it ran out of rows it was ALLOWED to delete - every
    /// remaining candidate is protected, or the kinds filter excludes it.
    ///
    /// Without this the caller cannot tell "there was nothing left to do"
    /// from "we were stopped", and a still-oversized database looks like a
    /// success. `live_after` says how far it got; this says it stopped
    /// short on purpose rather than because the target was met.
    pub blocked: bool,
}

/// Evict down to this fraction of the cap rather than to the cap itself.
///
/// HYSTERESIS. Without a gap, a database sitting one page over the cap
/// would be trimmed back to exactly the cap, the next scan pass would
/// push it one page over again, and every pass from then on would take
/// the write lock, delete a handful of rows and set `needs_compact` -
/// a permanent grind at the boundary that also means a permanent VACUUM
/// backlog. Emptying to 90% buys roughly a tenth of the cap of headroom,
/// so on a 2 GB cap the index has ~200 MB to refill before eviction is
/// due again - hours of scanning, not one pass.
const EVICT_LOW_WATER_NUM: u64 = 9;
const EVICT_LOW_WATER_DEN: u64 = 10;

/// Rows examined (and at most deleted) per batch. Bounds how long one
/// `prune_batch` holds the write lock against the parallel scanners'
/// 10 s busy timeout, and bounds how far a single batch can overshoot
/// the low-water mark. `prune_age` uses 8000; eviction re-measures the
/// file between batches, so it wants smaller, more frequent steps.
///
/// The cost of the smaller step is that each batch re-runs the candidate
/// query, and no index can serve the ladder's CASE expression, so that is
/// a scan-and-sort of `releases` every time. Measured: a 266 MB / 60k-row
/// index evicts 12_440 rows (7 batches) in 616 ms. That is fine for the
/// scheduled maintenance pass this is; if it ever stops being fine, the
/// fix is to fetch ids in much larger pages and pull the per-row payload
/// only for the chunk about to be deleted - one sort per page instead of
/// one per batch, with the byte-accurate stop point kept intact.
const EVICT_PAGE: usize = 2_000;

/// How many protected entries we are willing to push into the candidate
/// SQL as bound `NOT IN` parameters. SQLite hard-limits a statement to
/// 32766 variables, and the existing `OWNED_IN_CAP` picks 10_000 for the
/// same reason. Anything past the cap is NOT dropped: the SQL filter is
/// only an optimisation, and every candidate row is re-checked in Rust
/// against the FULL protected set before it can be deleted (see
/// `evict_to`). Overflowing the cap therefore costs a little scan work,
/// never a lost protection.
const EVICT_PROTECT_BIND_CAP: usize = 10_000;

/// Bound parameters per `NOT IN (...)` clause; several clauses are ANDed
/// so the cap above can be spent without any one list going near the
/// per-statement variable limit.
const EVICT_PROTECT_CHUNK: usize = 500;

/// Per-release payload estimate, in SQL. The bulk of this database is
/// the `files.segments` JSON blobs, which run from a few bytes to
/// hundreds of KB per release, so a row count is a useless proxy for
/// bytes - the estimate has to read the actual value lengths.
///
/// `LENGTH()` on a TEXT column counts characters, not bytes; `segments`
/// and `filename` are ASCII JSON / ASCII-ish names, so the two agree in
/// practice, and the constants below (24 bytes per `files` row, 96 per
/// `releases` row) stand in for the record headers, rowid keys and the
/// small fixed integer columns. Everything the estimate cannot see -
/// b-tree interior pages, `idx_rel_stem` / `idx_rel_kind`, the FTS5
/// index - is folded in by the runtime scale factor in `evict_to`.
const EVICT_PAYLOAD_SQL: &str = "(SELECT COALESCE(SUM(LENGTH(f.segments) \
     + LENGTH(f.filename) + 24), 0) FROM files f WHERE f.release_id = r.id) \
     + LENGTH(r.stem) + LENGTH(r.poster) + LENGTH(r.grp) + LENGTH(r.title_key) \
     + LENGTH(r.res) + LENGTH(r.kind) + LENGTH(r.langs) + 96";

/// The ORDER BY that turns a policy into an eviction sequence.
///
/// `first_posted = 0` means the post's OVER Date failed to parse, not
/// that it is from 1970. `prune_age` spares those rows outright; here
/// they cannot be spared (the cap is a hard limit), so instead the
/// leading `(r.first_posted = 0) ASC` term parks them at the BACK of
/// every date-driven order - unknown-date rows are the last thing an
/// age-shaped policy touches, in both directions. `r.id` closes every
/// order so the sequence is total and a paged scan is stable.
fn evict_order_sql(order: EvictOrder) -> &'static str {
    match order {
        // `junk` is the M28 0-100 curation score, not a flag; >= 50 is
        // the established "already hidden from the wall" threshold that
        // `prune_stale_partials` reaps on, reused here so the two can
        // never disagree about what "junk" means.
        EvictOrder::Ladder => {
            "CASE WHEN r.junk >= 50 AND r.complete = 0 THEN 0 \
                  WHEN r.junk >= 50 THEN 1 \
                  WHEN r.complete = 0 THEN 2 \
                  ELSE 3 END ASC, \
             (r.first_posted = 0) ASC, r.first_posted ASC, \
             r.total_bytes DESC, r.id ASC"
        }
        EvictOrder::Oldest => "(r.first_posted = 0) ASC, r.first_posted ASC, r.id ASC",
        EvictOrder::Newest => "(r.first_posted = 0) ASC, r.first_posted DESC, r.id DESC",
        EvictOrder::Largest => "r.total_bytes DESC, r.id ASC",
        EvictOrder::Smallest => "r.total_bytes ASC, r.id ASC",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::testutil::teardown;

    /// One fixture release, written straight to SQL so every column the
    /// eviction orders read (junk / complete / first_posted / total_bytes
    /// / kind / title_key) can be set exactly. `blob` is the size of the
    /// fake `segments` payload, which is what actually makes the database
    /// file grow - `total_bytes` is only metadata about the Usenet post.
    fn ev_rel(
        ix: &Index,
        id: i64,
        junk: i64,
        complete: i64,
        posted: i64,
        total_bytes: i64,
        kind: &str,
        title_key: &str,
        blob: usize,
    ) {
        ix.db
            .execute(
                "INSERT INTO releases(id, stem, poster, grp, total_bytes, files,
                     has_par2, complete, first_posted, first_seen, kind, res,
                     have_parts, need_parts, title_key, junk, oracle_at, langs)
                 VALUES(?1, ?2, 'p@p', 'alt.test', ?3, 1, 0, ?4, ?5, ?5, ?6,
                        '1080p', 1, 1, ?7, ?8, 0, '')",
                rusqlite::params![
                    id,
                    format!("Fixture.Release.{id}.1080p.WEB.x264-EV"),
                    total_bytes,
                    complete,
                    posted,
                    kind,
                    title_key,
                    junk
                ],
            )
            .unwrap();
        ix.db
            .execute(
                "INSERT INTO files(release_id, filename, total_parts, bytes, segments)
                 VALUES(?1, ?2, 1, ?3, ?4)",
                rusqlite::params![id, format!("f{id}.mkv"), total_bytes, "x".repeat(blob)],
            )
            .unwrap();
    }

    fn ev_open(tag: &str) -> (std::path::PathBuf, Index) {
        let dir =
            std::env::temp_dir().join(format!("nzbfast-index-ev-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ix = Index::open(&dir.join("index.db")).unwrap();
        (dir, ix)
    }

    fn ev_ids(ix: &Index) -> Vec<i64> {
        let mut stmt = ix
            .db
            .prepare("SELECT id FROM releases ORDER BY id")
            .unwrap();
        let v: Vec<i64> = stmt
            .query_map([], |r| r.get(0))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap();
        v
    }

    /// Every deleted id must come from the front of `expected` and every
    /// survivor from the back - i.e. eviction walked the policy order and
    /// stopped somewhere, never picked out of sequence.
    fn assert_prefix_evicted(expected: &[i64], survivors: &[i64]) {
        let cut = expected.len() - survivors.len();
        let want_tail: Vec<i64> = expected[cut..].to_vec();
        let mut got = survivors.to_vec();
        let mut want = want_tail.clone();
        got.sort_unstable();
        want.sort_unstable();
        assert_eq!(
            got, want,
            "survivors must be the tail of the policy order\n  order:     {expected:?}\n  survivors: {survivors:?}"
        );
    }

    /// 8 uniform-payload releases. `total_bytes` is deliberately shuffled
    /// against `first_posted` so the size orders and the date orders are
    /// different permutations and cannot be confused for each other.
    const EV_BLOB: usize = 64 * 1024;
    const EV_SIZES: [i64; 8] = [500, 800, 100, 700, 300, 900, 200, 400];

    fn ev_eight(ix: &Index) {
        for i in 1..=8i64 {
            ev_rel(
                ix,
                i,
                0,
                1,
                1000 * i,
                EV_SIZES[(i - 1) as usize],
                "movie",
                &format!("m:fixture {i}:2020"),
                EV_BLOB,
            );
        }
    }

    /// Target that forces roughly a third of the file away - enough that
    /// several releases must go, not so much that everything does.
    fn ev_target(ix: &Index) -> u64 {
        ix.db_bytes().unwrap() * 3 / 4
    }

    #[test]
    fn evict_target_zero_is_unlimited_and_removes_nothing() {
        let (dir, ix) = ev_open("zero");
        ev_eight(&ix);
        let before = ix.db_bytes().unwrap();
        let rep = ix
            .evict_to(0, &EvictPolicy::default(), &Protected::default())
            .unwrap();
        assert_eq!(rep.removed, 0);
        assert_eq!(rep.bytes_before, before);
        assert_eq!(rep.bytes_after, before);
        assert!(!rep.needs_compact);
        assert_eq!(ev_ids(&ix).len(), 8, "no row may be touched when unlimited");
        teardown(&dir, ix);
    }

    #[test]
    fn evict_single_key_orders_follow_their_key() {
        // (order, the exact sequence eviction must walk)
        let cases: [(EvictOrder, [i64; 8]); 4] = [
            (EvictOrder::Oldest, [1, 2, 3, 4, 5, 6, 7, 8]),
            (EvictOrder::Newest, [8, 7, 6, 5, 4, 3, 2, 1]),
            // total_bytes DESC: 900,800,700,500,400,300,200,100
            (EvictOrder::Largest, [6, 2, 4, 1, 8, 5, 7, 3]),
            (EvictOrder::Smallest, [3, 7, 5, 8, 1, 4, 2, 6]),
        ];
        for (order, expected) in cases {
            let (dir, ix) = ev_open(&format!("ord{order:?}"));
            ev_eight(&ix);
            let target = ev_target(&ix);
            let policy = EvictPolicy {
                order,
                kinds: vec![],
            };
            let rep = ix.evict_to(target, &policy, &Protected::default()).unwrap();
            let left = ev_ids(&ix);
            assert!(rep.removed > 0, "{order:?} must evict something");
            assert!(!left.is_empty(), "{order:?} must not empty the index");
            assert_eq!(rep.removed, 8 - left.len(), "{order:?} removed count");
            assert!(
                rep.needs_compact,
                "{order:?} deleted rows, so compact is due"
            );
            assert_prefix_evicted(&expected, &left);
            teardown(&dir, ix);
        }
    }

    #[test]
    fn evict_ladder_climbs_junk_then_incomplete_then_age_then_size() {
        let (dir, ix) = ev_open("ladder");
        // rung 0: junk AND incomplete, oldest first, then largest.
        ev_rel(&ix, 1, 80, 0, 5_000, 100, "movie", "m:a:2020", EV_BLOB);
        ev_rel(&ix, 2, 80, 0, 9_000, 900, "movie", "m:b:2020", EV_BLOB);
        // rung 1: junk but complete.
        ev_rel(&ix, 3, 80, 1, 1_000, 900, "movie", "m:c:2020", EV_BLOB);
        // rung 2: incomplete but clean - note it is the OLDEST row in the
        // whole fixture, so a plain age sort would take it first.
        ev_rel(&ix, 4, 0, 0, 100, 900, "movie", "m:d:2020", EV_BLOB);
        // rung 3: real content. Older first, then bigger first on a tie.
        ev_rel(&ix, 5, 0, 1, 2_000, 100, "movie", "m:e:2020", EV_BLOB);
        ev_rel(&ix, 6, 0, 1, 7_000, 900, "movie", "m:f:2020", EV_BLOB);
        ev_rel(&ix, 7, 0, 1, 7_000, 100, "movie", "m:g:2020", EV_BLOB);
        // rung 3 with an unparsed date: parked at the very back, exactly
        // as prune_age spares first_posted = 0.
        ev_rel(&ix, 8, 0, 1, 0, 900, "movie", "m:h:2020", EV_BLOB);
        let expected = [1i64, 2, 3, 4, 5, 6, 7, 8];

        let target = ev_target(&ix);
        let rep = ix
            .evict_to(target, &EvictPolicy::default(), &Protected::default())
            .unwrap();
        let left = ev_ids(&ix);
        assert!(rep.removed > 0);
        assert!(!left.is_empty());
        assert_prefix_evicted(&expected, &left);
        // The ladder's whole point: junk goes before real content does.
        assert!(!left.contains(&1), "junk+incomplete must go first");
        assert!(left.contains(&8), "unknown-date real content goes last");
        teardown(&dir, ix);
    }

    #[test]
    fn evict_protection_is_absolute_even_at_maximum_pressure() {
        let (dir, ix) = ev_open("prot");
        ev_eight(&ix);
        // Protect id 4 by id and id 6 by title_key. Then ask for a cap of
        // one byte: every other release must go, and the two protected
        // ones must survive even though they are then the ONLY thing left
        // that could possibly free another byte.
        let prot = Protected {
            title_keys: vec!["m:fixture 6:2020".into()],
            release_ids: vec![4],
        };
        let rep = ix.evict_to(1, &EvictPolicy::default(), &prot).unwrap();
        let left = ev_ids(&ix);
        assert_eq!(left, vec![4, 6], "protected rows survive maximum pressure");
        assert_eq!(rep.removed, 6);
        // It could not reach the target, and says so by leaving the file
        // above it rather than by deleting the protected rows anyway.
        assert!(
            ix.db_bytes().unwrap() > 1,
            "target unreachable: the report is `removed`, not a lie about size"
        );

        // A second run at the same impossible target must be a no-op, not
        // a retry that grinds through the protected rows.
        let again = ix.evict_to(1, &EvictPolicy::default(), &prot).unwrap();
        assert_eq!(again.removed, 0);
        assert!(!again.needs_compact);
        assert_eq!(ev_ids(&ix), vec![4, 6]);
        teardown(&dir, ix);
    }

    #[test]
    fn evict_hysteresis_second_call_removes_nothing() {
        let (dir, ix) = ev_open("hyst");
        ev_eight(&ix);
        let target = ev_target(&ix);
        let first = ix
            .evict_to(target, &EvictPolicy::default(), &Protected::default())
            .unwrap();
        assert!(first.removed > 0);
        let after_first = ev_ids(&ix);

        // The headroom the low-water mark bought, stated the way the
        // DAEMON reads it: `evict_pass` acts only when live_bytes is over
        // the cap, so landing anywhere inside the band means the next
        // scan pass does nothing at all. This is the anti-thrash promise.
        let live_after_first = ix.live_bytes().unwrap();
        assert!(
            live_after_first <= target,
            "first call left {live_after_first} over the cap {target}, so every \
             scan pass would evict again - the grind hysteresis exists to stop"
        );

        // Calling evict_to again at the same target is a stricter probe
        // than the daemon ever makes, and it is NOT promised to be a
        // no-op: the loop exits on `min(measured, predicted)`, so a
        // prediction that under-shot by less than one row leaves the file
        // a few bytes above the low-water mark and a second call shaves
        // that one row. What must hold is that it CONVERGES rather than
        // walking the file down a row per call.
        //
        // This used to be asserted as `second.removed == 0`, which passed
        // on page-boundary luck: measured on this fixture, the first call
        // landed 1228 bytes UNDER the mark before §95 gave the database a
        // pointer-map page, and 103 bytes OVER it after - a 1.3 KB swing
        // on a 540 KB fixture, decided entirely by 4 KB page granularity
        // and never by hysteresis.
        let second = ix
            .evict_to(target, &EvictPolicy::default(), &Protected::default())
            .unwrap();
        assert!(
            second.removed <= 1,
            "a second call at the same target took {} rows - that is a grind, \
             not a boundary rounding",
            second.removed
        );
        let third = ix
            .evict_to(target, &EvictPolicy::default(), &Protected::default())
            .unwrap();
        assert_eq!(third.removed, 0, "hysteresis: no boundary thrash");
        assert!(!third.needs_compact);
        if second.removed == 0 {
            assert_eq!(ev_ids(&ix), after_first);
        }

        // And the file really is under the cap (not merely under the
        // low-water estimate) once the freed pages are given back.
        ix.compact().unwrap();
        assert!(
            ix.db_bytes().unwrap() <= target,
            "post-compact size {} must fit the cap {target}",
            ix.db_bytes().unwrap()
        );
        teardown(&dir, ix);
    }

    #[test]
    fn evict_kinds_filter_restricts_to_listed_kinds() {
        let (dir, ix) = ev_open("kinds");
        for i in 1..=4i64 {
            ev_rel(
                &ix,
                i,
                0,
                1,
                1000 * i,
                100,
                "tv",
                &format!("t:s{i}"),
                EV_BLOB,
            );
        }
        for i in 5..=8i64 {
            ev_rel(
                &ix,
                i,
                0,
                1,
                1000 * i,
                100,
                "movie",
                &format!("m:f{i}"),
                EV_BLOB,
            );
        }
        // A legacy row that never got classified. It matches no filter, so
        // a kind-restricted eviction must leave it alone.
        ev_rel(&ix, 9, 90, 0, 10, 100, "", "", EV_BLOB);

        // Impossible cap, but only "tv" may be touched.
        let policy = EvictPolicy {
            order: EvictOrder::Oldest,
            kinds: vec!["tv".into()],
        };
        let rep = ix.evict_to(1, &policy, &Protected::default()).unwrap();
        assert_eq!(rep.removed, 4);
        assert_eq!(
            ev_ids(&ix),
            vec![5, 6, 7, 8, 9],
            "only tv rows were eligible"
        );
        teardown(&dir, ix);
    }

    #[test]
    fn evict_protected_set_past_the_bind_limit_still_protects_everything() {
        let (dir, ix) = ev_open("bindcap");
        ev_eight(&ix);
        // 30_000 protected ids - far past both EVICT_PROTECT_BIND_CAP and
        // SQLite's 32766-variable ceiling - with the ids that actually
        // exist deliberately placed at the END, past anything the SQL
        // `NOT IN` binds can reach. Only the Rust-side check can save
        // them, which is exactly the fallback being tested.
        let mut ids: Vec<i64> = (1_000_000..1_030_000).collect();
        ids.extend([1i64, 2, 3, 4, 5, 6, 7, 8]);
        let mut keys: Vec<String> = (0..30_000).map(|i| format!("m:filler {i}:1999")).collect();
        keys.push("m:fixture 1:2020".into());
        let prot = Protected {
            title_keys: keys,
            release_ids: ids,
        };

        let rep = ix.evict_to(1, &EvictPolicy::default(), &prot).unwrap();
        assert_eq!(
            rep.removed, 0,
            "nothing may be deleted when all is protected"
        );
        assert!(!rep.needs_compact);
        assert_eq!(ev_ids(&ix), vec![1, 2, 3, 4, 5, 6, 7, 8]);

        // Same oversized set, but now one row is genuinely unprotected:
        // eviction must still make progress rather than stall on the
        // protected rows it keeps scanning past.
        let mut ids2: Vec<i64> = (1_000_000..1_030_000).collect();
        ids2.extend([1i64, 2, 3, 4, 5, 6, 7]); // 8 left out
        let prot2 = Protected {
            title_keys: (0..30_000).map(|i| format!("m:filler {i}:1999")).collect(),
            release_ids: ids2,
        };
        let rep2 = ix.evict_to(1, &EvictPolicy::default(), &prot2).unwrap();
        assert_eq!(rep2.removed, 1);
        assert_eq!(ev_ids(&ix), vec![1, 2, 3, 4, 5, 6, 7]);
        teardown(&dir, ix);
    }

    /// THE size-cap blocker, pinned. `db_bytes()` cannot fall after a
    /// DELETE, so a caller that compares the user's cap against it never
    /// sees the database get back under the cap and re-evicts forever.
    /// `live_bytes()` is the quantity that actually moves, which is why it
    /// is public and why the daemon compares against it.
    #[test]
    fn live_bytes_falls_after_a_delete_where_db_bytes_cannot() {
        let (dir, ix) = ev_open("livebytes");
        ev_uneven(&ix);
        ix.compact().unwrap();
        let db_before = ix.db_bytes().unwrap();
        let live_before = ix.live_bytes().unwrap();

        let rep = ix
            .evict_to(
                db_before / 2,
                &EvictPolicy {
                    order: EvictOrder::Oldest,
                    kinds: vec![],
                },
                &Protected::default(),
            )
            .unwrap();
        assert!(rep.removed > 0);

        assert_eq!(
            ix.db_bytes().unwrap(),
            db_before,
            "the file cannot shrink until a compact runs - the whole trap"
        );
        assert!(
            ix.live_bytes().unwrap() < live_before,
            "live_bytes must fall as rows go: {} !< {live_before}",
            ix.live_bytes().unwrap()
        );
        assert_eq!(rep.live_before, live_before);
        assert_eq!(rep.live_after, ix.live_bytes().unwrap());
        assert!(
            rep.live_after < rep.bytes_after,
            "the gap a compact would reclaim"
        );
        teardown(&dir, ix);
    }

    /// `blocked` is the difference between "done" and "stopped", and the
    /// caller cannot tell them apart from `removed` alone: both can be 0.
    #[test]
    fn evict_reports_blocked_only_when_it_was_stopped_short() {
        let (dir, ix) = ev_open("blocked");
        ev_eight(&ix);

        // Everything protected, impossible target: stopped short.
        let all: Vec<i64> = (1..=8).collect();
        let rep = ix
            .evict_to(
                1,
                &EvictPolicy::default(),
                &Protected {
                    title_keys: vec![],
                    release_ids: all,
                },
            )
            .unwrap();
        assert_eq!(rep.removed, 0);
        assert!(rep.blocked, "every candidate was protected: {rep:?}");
        assert!(rep.live_after > 1);

        // Nothing protected, generous target already met: done, not
        // stopped - even though `removed` is 0 here too.
        let big = ix.live_bytes().unwrap() * 4;
        let rep = ix
            .evict_to(big, &EvictPolicy::default(), &Protected::default())
            .unwrap();
        assert_eq!(rep.removed, 0);
        assert!(
            !rep.blocked,
            "already under the target is not blocked: {rep:?}"
        );

        // Unlimited is never blocked either.
        let rep = ix
            .evict_to(0, &EvictPolicy::default(), &Protected::default())
            .unwrap();
        assert!(!rep.blocked);
        assert_eq!(rep.live_before, rep.live_after);
        teardown(&dir, ix);
    }

    /// Not a behaviour gate so much as a standing measurement: how close
    /// does the estimator land to the size the file really takes once the
    /// freed pages are handed back? Asserted loosely (the exact ratio
    /// moves with page size and fixture shape), printed so a regression
    /// in the estimator is visible in `cargo test -- --nocapture`.
    fn ev_uneven(ix: &Index) {
        // Wildly uneven payloads: the case a row count gets badly wrong.
        // 24 releases, blob sizes cycling 4K / 64K / 16K / 256K.
        for i in 1..=24i64 {
            let blob = match i % 4 {
                0 => 256 * 1024,
                1 => 4 * 1024,
                2 => 64 * 1024,
                _ => 16 * 1024,
            };
            ev_rel(
                ix,
                i,
                0,
                1,
                1000 * i,
                100,
                "movie",
                &format!("m:e{i}:2020"),
                blob,
            );
        }
    }

    /// The other size regime, and the only test that spans more than one
    /// batch. 4000 releases with 200-byte segments: the payload estimate
    /// no longer dominates, so the b-tree, `idx_rel_stem`, `idx_rel_kind`
    /// and the FTS5 index carry most of the real page cost (measured
    /// scale here: 1.18-1.25, against ~1.00 when the blobs are large).
    /// This is what the runtime-fitted scale factor exists for.
    #[test]
    fn evict_spans_batches_when_row_overhead_dominates() {
        let (dir, ix) = ev_open("manyrows");
        for i in 1..=4000i64 {
            ev_rel(&ix, i, 0, 1, i, 100, "movie", &format!("m:s{i}:2020"), 200);
        }
        ix.compact().unwrap();
        let before = ix.db_bytes().unwrap();
        let target = before / 2;
        let policy = EvictPolicy {
            order: EvictOrder::Oldest,
            kinds: vec![],
        };
        let rep = ix.evict_to(target, &policy, &Protected::default()).unwrap();
        assert!(
            rep.removed > EVICT_PAGE,
            "fixture must force more than one batch, removed {}",
            rep.removed
        );
        let left = ev_ids(&ix);
        assert_eq!(rep.removed, 4000 - left.len());
        // Oldest == id order here, so the survivors are the high ids.
        assert_eq!(left.first().copied(), Some(rep.removed as i64 + 1));
        ix.compact().unwrap();
        let actual = ix.db_bytes().unwrap();
        assert!(actual <= target, "must reach the cap: {actual} > {target}");
        assert!(
            left.len() >= 1000,
            "over-eviction: only {} of 4000 rows left to free half the file",
            left.len()
        );
        teardown(&dir, ix);
    }

    #[test]
    fn evict_estimator_lands_near_the_target_after_compact() {
        let (dir, ix) = ev_open("estim");
        ev_uneven(&ix);
        ix.compact().unwrap();
        let before = ix.db_bytes().unwrap();
        let target = before / 2;
        let rep = ix
            .evict_to(
                target,
                &EvictPolicy {
                    order: EvictOrder::Oldest,
                    kinds: vec![],
                },
                &Protected::default(),
            )
            .unwrap();
        assert!(rep.removed > 0);
        assert_eq!(
            rep.bytes_after, rep.bytes_before,
            "DELETE does not shorten a SQLite file - that is what needs_compact is for"
        );
        assert!(rep.needs_compact);
        ix.compact().unwrap();
        let actual = ix.db_bytes().unwrap();
        let low = target / EVICT_LOW_WATER_DEN * EVICT_LOW_WATER_NUM;
        println!(
            "estimator: cap {before} -> target {target} (low water {low}), \
             removed {} rows, real post-compact size {actual} = {:.1}% of target",
            rep.removed,
            actual as f64 / target as f64 * 100.0
        );
        // The contract that matters: it got under the cap.
        assert!(actual <= target, "must reach the cap: {actual} > {target}");
        assert!(!ev_ids(&ix).is_empty());

        // MINIMALITY, the assertion that actually guards user data. The
        // landing point sits below the low-water mark, but only because a
        // release is indivisible - the row that crosses the line here is
        // a 256 KB one. Prove that is granularity and not over-eviction
        // by replaying the same fixture with ONE FEWER deletion in the
        // same order: it must still be above the low-water mark, i.e.
        // every row eviction took was a row it had to take.
        let (dir2, ix2) = ev_open("estim-minimal");
        ev_uneven(&ix2);
        ix2.compact().unwrap();
        let keep_one_more: Vec<i64> = (1..rep.removed as i64).collect(); // Oldest = id order
        ix2.prune_batch(&keep_one_more).unwrap();
        ix2.compact().unwrap();
        let one_fewer = ix2.db_bytes().unwrap();
        assert!(
            one_fewer > low,
            "over-eviction: stopping one row earlier ({one_fewer}) would already \
             have been under the low water mark ({low})"
        );
        teardown(&dir, ix);
        teardown(&dir2, ix2);
    }
}

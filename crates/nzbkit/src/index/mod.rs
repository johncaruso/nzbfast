//! Built-in header indexer (design: M12): scan groups via OVER, cluster
//! posts into releases, store in SQLite, search, and synthesize an NZB on
//! demand - browse Usenet like a catalogue instead of pasting NZBs.
//!
//! Clustering is the proven make-release-nzb logic generalized: files
//! group by (poster, release stem); a release is complete when every seen
//! file has all its parts. Incremental scans resume from each group's
//! stored high-water mark.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use tracing::warn;

use rusqlite::{Connection, OptionalExtension};

/// SQLite's per-CONNECTION cancellation handle, re-exported so callers
/// outside this crate (the daemon's maintenance watchers) can hold one
/// without taking a direct rusqlite dependency.
pub use rusqlite::InterruptHandle;

use crate::extract::release_stem;
use crate::nntp::OverEntry;

mod browse;
mod cards;
mod claims;
mod encrypted;
mod evict;
mod ingest;
mod maintenance;
mod nzbimport;
mod pesto;
mod predb;
#[cfg(test)]
mod predb_tests;
mod probe;
mod query;
mod schema;
mod scoreboard;
mod searchlog;
mod spots;
#[cfg(test)]
mod testutil;
mod titles;

pub use browse::*;
pub use cards::*;
pub use claims::{MSGID_KEYS_PER_FILE, NameClaim, NameEvidence, ProvenOutcome, msgid_set_key};
pub use encrypted::{ENC_CLASS, EncKind};
pub use evict::*;
pub use ingest::*;
pub use maintenance::*;
pub use nzbimport::*;
pub use pesto::*;
pub use probe::*;
pub use scoreboard::*;
pub use searchlog::*;
pub use spots::*;
pub use titles::*;

pub struct Index {
    db: Connection,
    /// Ingest gate: release stem → keep? None = keep everything. Policy
    /// (year/kind/quality/language rules) lives in the caller; the index
    /// only applies the verdict, once per cluster.
    gate: Option<Box<dyn Fn(&str) -> bool + Send>>,
    /// FTS5 available and rel_fts created - search/browse take the
    /// index path; false falls back to the LIKE scans.
    fts: bool,
    /// pre_fts created - the small FTS index over pre-feed names. Its own
    /// flag rather than riding on `fts`: it is created later than
    /// `rel_fts`, so an index built before this feature existed has one
    /// and not the other until the next open.
    pre_fts: bool,
    /// people_fts created. Tracked separately from `fts` on purpose: the
    /// name-search leg is an OR inside the main browse predicate, so if
    /// that table were missing every search on the wall would fail, not
    /// just the people half.
    people_fts: bool,
    /// TODO 24D user categories, installed by the daemon (empty = off).
    /// Every ingest-time classification runs through these ahead of the
    /// built-in kinds; `reclassify_custom` reconciles stored rows after
    /// a config change.
    custom: Vec<crate::categories::CustomCategory>,
    /// Does the pre feed hold anything? Read once at open so that on the
    /// overwhelmingly common install - the feed is off, the table is
    /// empty - ingest pays nothing at all for the naming lookup. An
    /// install that switches the feed on gets the lookup from the next
    /// re-open, which the scan loop does after every pass.
    predb: bool,
    /// Names the caller wants told about the moment a release gains or
    /// changes one: release name → interesting? None = tell me nothing,
    /// which costs a single null check per touched release. Same
    /// arrangement as `gate` - the index applies a verdict it does not
    /// author (here it is the daemon's watchlist).
    watch: Option<Box<dyn Fn(&str) -> bool + Send>>,
    /// What `watch` said yes to since the caller last drained it. Behind
    /// a RefCell because the naming legs run on `&self`; the index is
    /// single-threaded behind the daemon's mutex either way.
    hits: std::cell::RefCell<WatchHits>,
}

/// A release a batch just touched that [`Index::set_watch_names`] said
/// the caller cares about. Deliberately thin: it answers "is this worth
/// waking the watchlist for", and every decision that follows is made by
/// the watchlist pass against the database, not against this.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchHit {
    pub id: i64,
    /// The name the release is known by NOW - the fed name where one has
    /// been applied, the posted stem otherwise.
    pub name: String,
    /// Every file seen has all its parts. A fresh arrival is usually
    /// false for its first few batches: the post is still going up.
    pub complete: bool,
}

/// The journal behind [`Index::take_watch_hits`], with the cap that
/// keeps a backfill from growing it without bound.
#[derive(Default)]
struct WatchHits {
    list: Vec<WatchHit>,
    /// Hits thrown away because the journal was full. Reported so a
    /// dropped arrival is a number somebody can see rather than silence.
    dropped: u32,
}

/// How many un-drained hits the journal holds. A tip tick drains after
/// every chunk, so this is only ever reached by a leg that names
/// thousands of releases at once (a correlation backlog sweep over a
/// freshly seeded pre corpus). Losing the overflow costs latency, never
/// coverage: the periodic watchlist pass sees the same releases.
const WATCH_HITS_CAP: usize = 512;

/// One indexed release (search result row).
#[derive(Debug, Clone)]
pub struct Release {
    pub id: i64,
    pub stem: String,
    pub poster: String,
    pub grp: String,
    pub total_bytes: u64,
    pub files: u32,
    pub has_par2: bool,
    pub complete: bool,
    /// Unix time of the earliest article seen (upload date).
    pub first_posted: i64,
    /// Unix time we first indexed it.
    pub first_seen: i64,
    /// Parsed classification, stored at ingest: "movie" / "tv" /
    /// "software" / "other" ('' on rows the backfill hasn't touched).
    pub kind: String,
    /// Parsed resolution ("2160p", "1080p", …; '' = unknown).
    pub res: String,
    /// Exact segment tally across the release's files - the browse
    /// view's completeness percentage (complete is the binary verdict).
    pub have_parts: u64,
    pub need_parts: u64,
    /// Parsed video codec / strongest audio track / dynamic range
    /// ('' = the name didn't say). What tells two encodes of the same
    /// film apart once resolution has tied.
    pub vcodec: String,
    pub acodec: String,
    pub hdr: String,
    /// The real release name a pre feed gave this post ('' = never
    /// named that way). When set, this is what the UI should show: the
    /// stem beside it is the obfuscated string it was posted under.
    pub pre_title: String,
    /// Where that name came from, so the claim can be attributed rather
    /// than presented as something we read off the wire.
    pub pre_source: String,
}

/// Column list every Release row read shares (search + browse).
const REL_COLS: &str = "id, stem, poster, grp, total_bytes, files, has_par2, complete,
     first_posted, first_seen, kind, res, have_parts, need_parts,
     vcodec, acodec, hdr, pre_title, pre_source";

/// How many candidate rows an NZBLNK header lookup will look at per
/// rung before giving up. Bounds both the FTS verification pass and the
/// unindexed filename scan; a header that matches this many things was
/// never distinctive enough to identify one posting.
const FIND_SCAN_CAP: u32 = 500;

fn release_from_row(r: &rusqlite::Row) -> rusqlite::Result<Release> {
    Ok(Release {
        id: r.get(0)?,
        stem: r.get(1)?,
        poster: r.get(2)?,
        grp: r.get(3)?,
        total_bytes: r.get::<_, i64>(4)? as u64,
        files: r.get(5)?,
        has_par2: r.get(6)?,
        complete: r.get(7)?,
        first_posted: r.get(8)?,
        first_seen: r.get(9)?,
        kind: r.get(10)?,
        res: r.get(11)?,
        have_parts: r.get::<_, i64>(12)? as u64,
        need_parts: r.get::<_, i64>(13)? as u64,
        vcodec: r.get(14)?,
        acodec: r.get(15)?,
        hdr: r.get(16)?,
        pre_title: r.get(17)?,
        pre_source: r.get(18)?,
    })
}

impl Release {
    /// What to show a person: the fed name when we have one, otherwise
    /// the posted stem. One function so the API, the classifier and
    /// anything else that renders a release agree on which string is the
    /// name.
    pub fn display_name(&self) -> &str {
        if self.pre_title.is_empty() {
            &self.stem
        } else {
            &self.pre_title
        }
    }
}

/// M30: readable form of a raw parse key - "m:barclays premier league
/// 2011:2012" → "Barclays Premier League 2011 (2012)". Used wherever an
/// unenriched title would otherwise surface its key.
fn pretty_key(key: &str) -> String {
    // Custom keys are "c:<slug>:<title>[:<year>][:<extra>]" - drop the
    // prefix AND the slug, space the rest out ("formula1 2026 round11
    // hungary qualifying"), title-cased below like any other key.
    let custom_owned;
    let base = if let Some(rest) = key.strip_prefix("c:") {
        custom_owned = rest
            .split_once(':')
            .map_or(rest, |(_, t)| t)
            .replace(':', " ");
        custom_owned.as_str()
    } else {
        key.strip_prefix("t:")
            .or_else(|| key.strip_prefix("m:"))
            .unwrap_or(key)
    };
    let (name, yr) = match base.rsplit_once(':') {
        Some((w, y)) if !y.is_empty() && y.chars().all(|c| c.is_ascii_digit()) => (w, Some(y)),
        _ => (base, None),
    };
    let mut t = name
        .split_whitespace()
        .map(|w| {
            let mut cs = w.chars();
            match cs.next() {
                Some(c) => c.to_uppercase().collect::<String>() + cs.as_str(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ");
    if let Some(y) = yr {
        t.push_str(&format!(" ({y})"));
    }
    t
}

/// One enricher lane. Each runs on its own thread against its own set
/// of providers, because the rate limits are per provider: a serial loop
/// made every TV title queue behind the movie crawl, and adding music
/// and books to the TV lane would have put a 1-request-per-second
/// MusicBrainz backlog in front of every new episode.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Lane {
    /// Wikidata / Wikipedia / OMDb.
    Movies,
    /// TVmaze, plus the junk and custom-category rows that touch no
    /// provider at all and are only stamped.
    Shows,
    /// MusicBrainz / Cover Art Archive / OpenLibrary.
    MusicBooks,
}

impl Lane {
    /// This lane's slice of `titles`, as a SQL fragment. Static text
    /// only - it is interpolated into the query, so it must never carry
    /// a caller-supplied value.
    fn sql(self) -> &'static str {
        match self {
            Lane::Movies => "kind = 'movie'",
            Lane::MusicBooks => "kind IN ('music','book')",
            // Everything the other two lanes do not claim, so a kind
            // added later still gets enriched by SOMETHING rather than
            // falling down a gap between lanes and never being looked at.
            Lane::Shows => "kind NOT IN ('movie','music','book')",
        }
    }
}

/// SQL value for a parsed kind (lowercase, stable - stored in the db).
/// A custom category stores its slug directly; slugs can never shadow
/// the built-in four (`categories::validate` reserves them).
pub fn kind_str(k: &crate::release::Kind) -> &str {
    match k {
        crate::release::Kind::Movie => "movie",
        crate::release::Kind::Tv => "tv",
        crate::release::Kind::Software => "software",
        crate::release::Kind::Music => "music",
        crate::release::Kind::Book => "book",
        crate::release::Kind::Other => "other",
        crate::release::Kind::Custom(slug) => slug,
    }
}

impl Index {
    // ---- M29 availability oracle -------------------------------------

    /// Fold a batch of hit/miss samples into the oracle ledger.
    pub fn oracle_ingest(
        &self,
        samples: &[crate::oracle::Sample],
        now: i64,
    ) -> rusqlite::Result<()> {
        crate::oracle::ingest(&self.db, samples, now)
    }

    /// The whole ledger (tiny by construction) for verdict computation.
    pub fn oracle_snapshot(&self) -> rusqlite::Result<crate::oracle::Snapshot> {
        crate::oracle::Snapshot::load(&self.db)
    }

    /// Releases the idle STAT sampler should probe next: never-sampled
    /// first, then stalest verdict, newest post first within a tier.
    /// Returns (id, group, first_posted).
    pub fn oracle_pick(&self, limit: u32) -> rusqlite::Result<Vec<(i64, String, i64)>> {
        // Sample what users can actually SEE (junk < 50) - stalest-first
        // over the whole table drowned the sampler in the endless stream
        // of freshly-scanned obfuscated rows: every probe was a 0-day
        // article, bucket 0 was the only bucket that ever learned, and
        // old-post availability (the interesting question) stayed
        // unknown forever. Random tiebreak inside the stalest half
        // spreads picks across post ages.
        let mut stmt = self.db.prepare(
            "SELECT id, grp, first_posted FROM releases
             WHERE junk < 50
             ORDER BY oracle_at ASC, (id * 2654435761) % 4294967296 LIMIT ?1",
        )?;
        let rows = stmt.query_map([limit], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?;
        rows.collect()
    }

    /// Up to `max` probe message-ids for a release, spread evenly across
    /// its files' segments (bracketed, STAT-ready).
    pub fn oracle_msgids(&self, release_id: i64, max: usize) -> rusqlite::Result<Vec<String>> {
        let mut stmt = self
            .db
            .prepare("SELECT segments FROM files WHERE release_id=?1 ORDER BY filename")?;
        let segs: Vec<String> = stmt
            .query_map([release_id], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        let mut ids: Vec<String> = Vec::new();
        for s in segs {
            let parsed: Vec<(u32, String, u64)> = serde_json::from_str(&s).unwrap_or_default();
            ids.extend(parsed.into_iter().map(|(_, id, _)| id));
        }
        if ids.is_empty() || max == 0 {
            return Ok(Vec::new());
        }
        // Even spread over the whole release - head-only sampling would
        // miss partial takedowns of the tail.
        let step = (ids.len() as f64 / max.min(ids.len()) as f64).max(1.0);
        let mut out = Vec::with_capacity(max.min(ids.len()));
        let mut at = 0.0f64;
        while (at as usize) < ids.len() && out.len() < max {
            let id = &ids[at as usize];
            let b = if id.starts_with('<') {
                id.clone()
            } else {
                format!("<{id}>")
            };
            out.push(b);
            at += step;
        }
        Ok(out)
    }

    /// Stamp a release as sampled now (rotates the pick order).
    pub fn oracle_mark(&self, release_id: i64, now: i64) -> rusqlite::Result<()> {
        self.db.execute(
            "UPDATE releases SET oracle_at=?2 WHERE id=?1",
            rusqlite::params![release_id, now],
        )?;
        Ok(())
    }

    /// A8 targeted gap-fill: incomplete releases worth re-hunting on the
    /// other backbones, least-recently-tried first (gapfill_at 0 =
    /// never). Junk-gated like the sampler - the endless obfuscated
    /// stream must not eat the budget users could see spent on real
    /// cards. Releases first seen in the last hour are skipped: their
    /// missing parts are usually still propagating (or still uploading),
    /// and the next tip pass gets them for free.
    /// Returns (id, group, first_posted).
    pub fn gapfill_pick(&self, limit: u32, now: i64) -> rusqlite::Result<Vec<(i64, String, i64)>> {
        let mut stmt = self.db.prepare(
            "SELECT id, grp, first_posted FROM releases
             WHERE complete=0 AND junk < 50 AND first_posted > 0
               AND first_seen < ?2
             ORDER BY gapfill_at ASC, (id * 2654435761) % 4294967296 LIMIT ?1",
        )?;
        let rows = stmt.query_map(rusqlite::params![limit, now - 3600], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })?;
        rows.collect()
    }

    /// Stamp a release as gap-fill-tried now (rotates the pick order).
    pub fn gapfill_mark(&self, release_id: i64, now: i64) -> rusqlite::Result<()> {
        self.db.execute(
            "UPDATE releases SET gapfill_at=?2 WHERE id=?1",
            rusqlite::params![release_id, now],
        )?;
        Ok(())
    }

    /// Is this release complete? (gap-fill measures its own success by
    /// the flip.)
    pub fn is_complete(&self, release_id: i64) -> bool {
        self.db
            .query_row(
                "SELECT complete FROM releases WHERE id=?1",
                [release_id],
                |r| r.get(0),
            )
            .unwrap_or(false)
    }

    /// Tiny persisted key/value pairs (dataset refresh stamps and such).
    pub fn kv_get(&self, k: &str) -> Option<String> {
        self.db
            .query_row("SELECT v FROM kv WHERE k=?1", [k], |r| r.get(0))
            .ok()
    }

    pub fn kv_set(&self, k: &str, v: &str) -> rusqlite::Result<()> {
        self.db.execute(
            "INSERT INTO kv(k, v) VALUES(?1, ?2)
             ON CONFLICT(k) DO UPDATE SET v=excluded.v",
            [k, v],
        )?;
        Ok(())
    }

    /// Replace the whole IMDb ratings snapshot (nightly dataset ingest).
    /// One transaction; returns rows kept.
    pub fn imdb_ratings_replace(
        &mut self,
        rows: impl Iterator<Item = (String, f64, u64)>,
    ) -> rusqlite::Result<u64> {
        let tx = self.db.transaction()?;
        tx.execute("DELETE FROM imdb_ratings", [])?;
        let mut n = 0u64;
        {
            let mut ins =
                tx.prepare("INSERT INTO imdb_ratings(tconst, rating, votes) VALUES(?1, ?2, ?3)")?;
            for (t, r, v) in rows {
                ins.execute(rusqlite::params![t, r, v as i64])?;
                n += 1;
            }
        }
        tx.commit()?;
        Ok(n)
    }

    /// (rating, votes) for an IMDb tconst, if the snapshot holds it.
    pub fn imdb_rating(&self, tconst: &str) -> Option<(f64, u64)> {
        self.db
            .query_row(
                "SELECT rating, votes FROM imdb_ratings WHERE tconst=?1",
                [tconst],
                |r| Ok((r.get(0)?, r.get::<_, i64>(1)? as u64)),
            )
            .ok()
    }

    /// Install an ingest gate (see the `gate` field).
    pub fn set_gate(&mut self, gate: Box<dyn Fn(&str) -> bool + Send>) {
        self.gate = Some(gate);
    }

    /// Install the user's custom categories (see the `custom` field).
    pub fn set_custom(&mut self, cats: Vec<crate::categories::CustomCategory>) {
        self.custom = cats;
    }

    /// Install the arrival watch (see the `watch` field): a cheap
    /// name test the index runs over every release a batch touches, so
    /// the caller learns about the ones it cares about AS THEY LAND
    /// rather than by re-scanning the table on a timer.
    ///
    /// The predicate must be cheap and permissive - it runs once per
    /// touched release inside the ingest transaction, and its only job is
    /// to keep the journal short. Saying yes too often costs a wasted
    /// look; saying no wrongly loses the arrival entirely.
    pub fn set_watch_names(&mut self, watch: Option<Box<dyn Fn(&str) -> bool + Send>>) {
        self.watch = watch;
        if self.watch.is_none() {
            *self.hits.borrow_mut() = Default::default();
        }
    }

    /// Take everything the arrival watch has collected since the last
    /// call, plus how many hits were dropped for want of room.
    pub fn take_watch_hits(&self) -> (Vec<WatchHit>, u32) {
        let mut h = self.hits.borrow_mut();
        (std::mem::take(&mut h.list), std::mem::take(&mut h.dropped))
    }

    /// Offer one touched release to the arrival watch. Costs a null check
    /// when nothing is installed, which is every install that has no
    /// watchlist.
    fn note_watch(&self, id: i64, name: &str, complete: bool) {
        let Some(watch) = &self.watch else { return };
        if watch(name) {
            self.push_watch_hit(WatchHit {
                id,
                name: name.to_string(),
                complete,
            });
        }
    }

    /// Journal a hit the predicate has already accepted, dropping it (and
    /// counting the drop) once the journal is full.
    fn push_watch_hit(&self, hit: WatchHit) {
        let mut h = self.hits.borrow_mut();
        if h.list.len() >= WATCH_HITS_CAP {
            h.dropped = h.dropped.saturating_add(1);
            return;
        }
        h.list.push(hit);
    }
}

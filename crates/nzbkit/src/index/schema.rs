//! Schema creation and the migration ladder (TODO 106 phase 2.2, cut 6):
//! `open` decomposed at its own comment seams into sequential step fns,
//! plus `open_read_only`. Except for the step-fn plumbing every line is a
//! verbatim move from the old index.rs open(); each step keeps its error
//! handling identical - non-fatal `let _ =` migrations STAY non-fatal
//! (a failed step is retried by the next open), and the people schema
//! keeps its fatal `?`. Call order is load-bearing; see
//! research/SEAM-TABLE-index-rs-2026-08-05.md.

use super::*;

/// The base tables, pragmas aside: everything `CREATE TABLE IF NOT
/// EXISTS` so it is a no-op on an existing database.
fn create_base_schema(db: &Connection) -> rusqlite::Result<()> {
    // Only journal_mode was ever set, so every chunk commit paid a
    // full fsync and the page cache stayed at SQLite's 2 MB default
    // against a multi-gigabyte index.
    //
    // synchronous=NORMAL is the one that matters for ingest. In WAL
    // mode it cannot corrupt the database - the documented exposure
    // is losing the last commits on a power cut or OS crash, which
    // for an index rebuildable from Usenet is the right trade. A
    // scan pass simply re-fetches the headers whose commit was lost;
    // the high-water mark only advances over a contiguous prefix.
    db.execute_batch(
        // §95: FIRST, and before any CREATE TABLE. Incremental
        // auto-vacuum is what lets `compact_chunk` reclaim space in
        // bounded, abortable pieces instead of one VACUUM that a
        // starting download cannot reliably stop. SQLite only
        // accepts the change on a database with no tables yet, so
        // this line does the whole job for a fresh install and is a
        // silent no-op on an existing one - those migrate on their
        // next compact (see `Index::compact`).
        //
        // The cost is pointer-map pages: one per ~800 pages, so
        // ~0.1% of the file, plus a ptrmap write when a page is
        // allocated or freed. Cheap against a multi-GB index that
        // otherwise blocks a download for minutes.
        "PRAGMA auto_vacuum=INCREMENTAL;
         PRAGMA journal_mode=WAL;
         PRAGMA synchronous=NORMAL;
         PRAGMA temp_store=MEMORY;
         PRAGMA cache_size=-262144;
         PRAGMA mmap_size=1073741824;
         CREATE TABLE IF NOT EXISTS releases(
            id INTEGER PRIMARY KEY,
            stem TEXT NOT NULL,
            poster TEXT NOT NULL,
            grp TEXT NOT NULL,
            total_bytes INTEGER NOT NULL DEFAULT 0,
            files INTEGER NOT NULL DEFAULT 0,
            has_par2 INTEGER NOT NULL DEFAULT 0,
            complete INTEGER NOT NULL DEFAULT 0,
            first_posted INTEGER NOT NULL DEFAULT 0,
            first_seen INTEGER NOT NULL DEFAULT 0,
            UNIQUE(stem, poster, grp));
         CREATE TABLE IF NOT EXISTS files(
            release_id INTEGER NOT NULL,
            filename TEXT NOT NULL,
            total_parts INTEGER NOT NULL,
            bytes INTEGER NOT NULL DEFAULT 0,
            segments TEXT NOT NULL DEFAULT '[]',
            UNIQUE(release_id, filename));
         CREATE TABLE IF NOT EXISTS marks(
            -- A8 multi-server indexing: article NUMBERS are assigned
            -- per server spool (message-ids are the portable half),
            -- so scan coverage is tracked per (group, server). The
            -- server key is the lowercased host; '' marks rows from
            -- the single-server era, adopted by the historical
            -- primary via adopt_legacy_marks.
            grp TEXT NOT NULL,
            server TEXT NOT NULL DEFAULT '',
            high INTEGER NOT NULL,
            low INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY(grp, server));
         CREATE INDEX IF NOT EXISTS idx_rel_stem ON releases(stem);
         CREATE TABLE IF NOT EXISTS spots(
            id INTEGER PRIMARY KEY,
            msgid TEXT NOT NULL UNIQUE,
            title TEXT NOT NULL,
            category INTEGER NOT NULL DEFAULT 0,
            subcats TEXT NOT NULL DEFAULT '',
            size INTEGER NOT NULL DEFAULT 0,
            date INTEGER NOT NULL DEFAULT 0,
            spotter_id TEXT NOT NULL DEFAULT '',
            verified INTEGER NOT NULL DEFAULT 0,
            hashcash_ok INTEGER NOT NULL DEFAULT 1,
            nzb_msgids TEXT NOT NULL DEFAULT '[]');
         CREATE INDEX IF NOT EXISTS idx_spots_title ON spots(title);
         CREATE TABLE IF NOT EXISTS titles(
            key TEXT PRIMARY KEY,
            kind TEXT NOT NULL,
            title TEXT NOT NULL,
            year INTEGER NOT NULL DEFAULT 0,
            tmdb_id INTEGER NOT NULL DEFAULT 0,
            overview TEXT NOT NULL DEFAULT '',
            rating REAL NOT NULL DEFAULT 0,
            genres TEXT NOT NULL DEFAULT '',
            poster TEXT NOT NULL DEFAULT '',
            backdrop TEXT NOT NULL DEFAULT '',
            checked INTEGER NOT NULL DEFAULT 0);
         CREATE TABLE IF NOT EXISTS imdb_ratings(
            tconst TEXT PRIMARY KEY,
            rating REAL NOT NULL,
            votes INTEGER NOT NULL);
         CREATE TABLE IF NOT EXISTS kv(
            k TEXT PRIMARY KEY,
            v TEXT NOT NULL);
         -- M30 wall curation: per-title 'Not interested' hides,
         -- learned/manual hide rules, and suggestion dismissals
         -- (so a declined suggestion never nags again).
         CREATE TABLE IF NOT EXISTS wall_hidden(
            -- NOT NULL is explicit: a non-INTEGER PRIMARY KEY is NOT
            -- implicitly NOT NULL in SQLite, and a single NULL key here
            -- makes `key NOT IN (SELECT key FROM wall_hidden)` (used by
            -- the pruners AND the wall curation filter) evaluate to NULL
            -- for every row - silently disabling pruning and blanking
            -- the whole wall.
            key TEXT PRIMARY KEY NOT NULL,
            at INTEGER NOT NULL);
         CREATE TABLE IF NOT EXISTS wall_rules(
            id INTEGER PRIMARY KEY,
            field TEXT NOT NULL,
            value TEXT NOT NULL,
            added INTEGER NOT NULL,
            auto INTEGER NOT NULL DEFAULT 0,
            UNIQUE(field, value));
         CREATE TABLE IF NOT EXISTS wall_dismissed(
            field TEXT NOT NULL,
            value TEXT NOT NULL,
            PRIMARY KEY(field, value));
         -- Pre feed (opt-in, off by default): one row per release a
         -- relay channel has announced. The column that earns the
         -- table is `filename` - the name the release was POSTED
         -- under, which is the only thing that can join a real title
         -- onto a deliberately obfuscated post.
         --
         -- Keyed on the title because that is what the relay treats
         -- as the identity: a NEW line announces it, and UPD lines
         -- fill fields in afterwards (very often the filename
         -- itself, minutes later). Upserts therefore only ever
         -- overwrite a field with a NON-EMPTY value.
         CREATE TABLE IF NOT EXISTS predb(
            id INTEGER PRIMARY KEY,
            title TEXT NOT NULL UNIQUE,
            -- Posted filename, as the relay sent it.
            filename TEXT NOT NULL DEFAULT '',
            -- release_stem(filename), lowercased: the exact join key.
            fnstem TEXT NOT NULL DEFAULT '',
            -- predb::match_key(fnstem): separators and case removed,
            -- the fallback join key.
            fnkey TEXT NOT NULL DEFAULT '',
            size INTEGER NOT NULL DEFAULT 0,
            files INTEGER NOT NULL DEFAULT 0,
            category TEXT NOT NULL DEFAULT '',
            source TEXT NOT NULL DEFAULT '',
            requestid TEXT NOT NULL DEFAULT '',
            grp TEXT NOT NULL DEFAULT '',
            nuked INTEGER NOT NULL DEFAULT 0,
            nuke_reason TEXT NOT NULL DEFAULT '',
            -- When the RELAY says it was pre'd (0 = it did not say).
            pre_at INTEGER NOT NULL DEFAULT 0,
            -- When WE heard it. Drives pruning; always set.
            seen_at INTEGER NOT NULL DEFAULT 0,
            -- Last time this row was swept against already-indexed
            -- releases, so the retro pass can round-robin instead of
            -- re-trying the newest rows forever.
            tried_at INTEGER NOT NULL DEFAULT 0);
         CREATE INDEX IF NOT EXISTS idx_predb_fnstem ON predb(fnstem);
         CREATE INDEX IF NOT EXISTS idx_predb_fnkey ON predb(fnkey);
         CREATE INDEX IF NOT EXISTS idx_predb_seen ON predb(seen_at);
         CREATE INDEX IF NOT EXISTS idx_predb_tried ON predb(tried_at);
         -- Phase 2: correlation candidates. One row per release -
         -- the BEST candidate only, with enough recorded to audit
         -- the decision and to rank a re-computation against it.
         -- Alternates are recomputed on demand, never stored.
         CREATE TABLE IF NOT EXISTS pre_corr(
            release_id INTEGER PRIMARY KEY,
            predb_id   INTEGER NOT NULL,
            score      INTEGER NOT NULL,
            -- first_posted - pt, seconds. The audit trail.
            delta      INTEGER NOT NULL,
            -- est_content/SZ in thousandths (0 = sizeless pair).
            ratio      INTEGER NOT NULL DEFAULT 0,
            -- Best competing score at decision time.
            runner_up  INTEGER NOT NULL DEFAULT 0,
            -- suggested | applied | confirmed | rejected | revoked
            status     TEXT NOT NULL DEFAULT 'suggested',
            at         INTEGER NOT NULL);
         CREATE INDEX IF NOT EXISTS idx_precorr_predb ON pre_corr(predb_id);
         CREATE INDEX IF NOT EXISTS idx_precorr_status ON pre_corr(status);
         -- Repost fingerprints: the PAR2 hash16k of a member file
         -- (an OUTER volume) of a download we managed to name,
         -- against the name we gave it. A later obfuscated post
         -- whose sidecar presents the same hash is the same bytes,
         -- so it can be told what it is. The identity is read from
         -- the .par2 sidecar and never from the archive, which is
         -- why it survives RAR header encryption - the one naming
         -- path in the pipeline that does.
         --
         -- Only names REPOSTS, so the yield grows with the age of
         -- the table and is zero on a fresh install. It costs ~80
         -- bytes per volume of every named download, which is why
         -- there is no expiry: an old fingerprint is exactly the
         -- one worth having.
         CREATE TABLE IF NOT EXISTS par_hashes(
            hash16k TEXT PRIMARY KEY NOT NULL,
            -- The release name we knew this by.
            name TEXT NOT NULL,
            -- The wall's identity for it, when the name parsed to
            -- one ('' when it did not).
            title_key TEXT NOT NULL DEFAULT '',
            at INTEGER NOT NULL);
         -- §131 identity substrate: every naming lane's proof about a
         -- release, kept as COMPETING claims with provenance rather
         -- than a first-writer-wins name. `tier` is the evidence
         -- strength (see index::claims::NameEvidence), `key` the
         -- proving value (a PAR2 set id, a crc32, a hash16k, a
         -- message-id-set digest), `source` which lane produced it.
         -- The UNIQUE doubles as the release_id index (leftmost
         -- column), so re-claims are idempotent and the delete
         -- trigger below stays cheap.
         CREATE TABLE IF NOT EXISTS name_claims(
            id INTEGER PRIMARY KEY,
            release_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            tier TEXT NOT NULL,
            key TEXT NOT NULL DEFAULT '',
            source TEXT NOT NULL DEFAULT '',
            at INTEGER NOT NULL,
            UNIQUE(release_id, tier, key, name));
         -- Reverse message-id lookup: 64-bit hash of a segment
         -- message-id -> the release that carries it, so a set of
         -- message-ids (a posted NZB, a spot NZB, an *arr handoff)
         -- can join to dark scan rows. Only the 3 lowest-numbered
         -- segments of each file are keyed (the query side may probe
         -- every id it has - extra probes just miss), which bounds
         -- the table at ~3 rows per file instead of one per segment.
         -- WITHOUT ROWID: the (h, release_id) pair IS the row.
         CREATE TABLE IF NOT EXISTS msgid_map(
            h INTEGER NOT NULL,
            release_id INTEGER NOT NULL,
            PRIMARY KEY(h, release_id)) WITHOUT ROWID;
         CREATE INDEX IF NOT EXISTS idx_msgid_map_rel ON msgid_map(release_id);
         -- Both tables reference release rowids, and SQLite reuses the
         -- highest rowid after an eviction deletes it - a stale row
         -- would then attach someone else's identity to a brand-new
         -- release. A trigger catches every delete path (retention
         -- prune, size-cap evict, twin dedupe, wall fix-up) including
         -- ones added later; both deletes are indexed.
         CREATE TRIGGER IF NOT EXISTS rel_identity_ad AFTER DELETE ON releases BEGIN
           DELETE FROM name_claims WHERE release_id=old.id;
           DELETE FROM msgid_map WHERE release_id=old.id;
         END;
         -- Pesto tiny-PAR2 rung (TODO 131, red-team 5a): one row per
         -- PAR2 Recovery Set parsed out of the family's tiny sidecar
         -- objects. Keyed on the set id because dedupe is mandatory -
         -- the census's 617 fetched objects collapsed to 489 sets
         -- (127 sets had multiple descriptor objects). `base_ctr` is
         -- the smallest message-id counter among the set's objects
         -- (the backward-link key C); `files` is the FileDesc list as
         -- JSON (name, exact length, full MD5, first-16k MD5).
         CREATE TABLE IF NOT EXISTS pesto_sets(
            set_id TEXT PRIMARY KEY NOT NULL,
            grp TEXT NOT NULL,
            base_ctr INTEGER NOT NULL,
            sum_len INTEGER NOT NULL,
            files TEXT NOT NULL,
            first_seen INTEGER NOT NULL,
            -- pending | named | conflict | junkname | unresolved | nopayload
            status TEXT NOT NULL DEFAULT 'pending',
            release_id INTEGER NOT NULL DEFAULT 0,
            tries INTEGER NOT NULL DEFAULT 0,
            at INTEGER NOT NULL DEFAULT 0);
         CREATE INDEX IF NOT EXISTS idx_pesto_status ON pesto_sets(status, at);
         -- Parity scoreboard (build-order #8): one row per reference
         -- release sampled from a user-configured newznab indexer,
         -- with the verdict of whether OUR index has that post and
         -- whether it is NAMED (exact title/episode parity, not mere
         -- presence). Aggregated by GROUP BY over a rolling window;
         -- volume is hundreds of rows a day, so no rollup table.
         CREATE TABLE IF NOT EXISTS scoreboard_samples(
            id INTEGER PRIMARY KEY,
            -- Reference host, so two sources never collide on a guid.
            source TEXT NOT NULL,
            category TEXT NOT NULL,
            ref_guid TEXT NOT NULL,
            ref_name TEXT NOT NULL,
            ref_size INTEGER NOT NULL DEFAULT 0,
            -- The reference's usenetdate (upload time), unix.
            ref_posted INTEGER NOT NULL DEFAULT 0,
            ref_group TEXT NOT NULL DEFAULT '',
            -- have_named | have_unnamed | missing
            verdict TEXT NOT NULL,
            matched_release_id INTEGER NOT NULL DEFAULT 0,
            -- stem | band | subject_stem ('' when missing)
            key_used TEXT NOT NULL DEFAULT '',
            -- our first_seen - ref_posted for hits, floored at 0.
            lag_secs INTEGER NOT NULL DEFAULT 0,
            at INTEGER NOT NULL,
            UNIQUE(source, ref_guid));
         CREATE INDEX IF NOT EXISTS idx_sb_at ON scoreboard_samples(at);
         CREATE INDEX IF NOT EXISTS idx_sb_cat ON scoreboard_samples(category, at);
         -- Search-miss log (TODO 131 workstream D, item D3; design
         -- research/DESIGN-D3-search-log-2026-08-11.md). What the user
         -- and their *arr clients asked this index for, and how many
         -- rows they got back - so the queries we answer with nothing
         -- can tell the scanner what to deepen or backfill next.
         --
         -- PRIVACY: this is LOCAL-ONLY behaviour data about the person
         -- running the daemon. It is never enriched (no network lookup
         -- reads it), never exported (not in the SAB or newznab
         -- facades, not in any diagnostic bundle or update payload),
         -- never aggregated across installs, and its readout sits
         -- behind the full API key. The live setting index_search_log
         -- turns recording off AND clears the table. Nothing in this
         -- table may ever leave the box.
         --
         -- One row per DISTINCT (surface, q, kind), not per search
         -- event: an *arr re-asks the same RSS query every 15 minutes
         -- and the wall's box searches as you type, so an event stream
         -- would be tens of thousands of near-duplicate rows a day.
         -- `q` is the normalized form the matcher actually sees
         -- (lowercased, separators collapsed), never the raw keystroke.
         CREATE TABLE IF NOT EXISTS search_log(
            id INTEGER PRIMARY KEY,
            -- wall | newznab. Where the query came from; a miss an
            -- *arr reports is a different problem from one a human
            -- typed, and the fixes differ.
            surface TEXT NOT NULL,
            q TEXT NOT NULL,
            -- The kind filter in force ('' when none): a movie search
            -- that misses is not the same hole as a global one.
            kind TEXT NOT NULL DEFAULT '',
            -- Times asked, and times answered with nothing (or with
            -- fewer rows than the readout's `thin` bar).
            n INTEGER NOT NULL DEFAULT 0,
            zero_n INTEGER NOT NULL DEFAULT 0,
            first_at INTEGER NOT NULL,
            last_at INTEGER NOT NULL,
            -- last_hits is the CURRENT truth; best_hits is whether we
            -- ever answered it at all. A query that missed for a week
            -- and now returns rows is a hole the scanner FILLED, and
            -- must fall out of the top-misses list rather than sit at
            -- the top of it forever on the strength of its history.
            last_hits INTEGER NOT NULL DEFAULT 0,
            best_hits INTEGER NOT NULL DEFAULT 0,
            UNIQUE(surface, q, kind));
         -- One index, serving both the retention sweep and the
         -- readout's rolling window. The ranking sort is left to
         -- SQLite: the row cap keeps this table at thousands of rows,
         -- where an index on the ordering key would cost more to
         -- maintain than the sort costs to run.
         CREATE INDEX IF NOT EXISTS idx_search_log_last ON search_log(last_at);",
    )?;
    Ok(())
}

/// Additive column migrations (ALTER has no IF NOT EXISTS - failed
/// re-adds are expected and harmless) plus the predb.pt index/backfill.
fn additive_migrations(db: &Connection) {
    // Columns added after the titles table first shipped - ALTER has
    // no IF NOT EXISTS, so failed re-adds are expected and harmless.
    for ddl in [
        "ALTER TABLE titles ADD COLUMN imdb TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE titles ADD COLUMN actors TEXT NOT NULL DEFAULT ''",
        // Full release / first-air date (ISO). Rows enriched before
        // this column existed keep '' and sort by `year` instead -
        // they only gain a real date when re-enriched.
        "ALTER TABLE titles ADD COLUMN air_date TEXT NOT NULL DEFAULT ''",
        // Whether a provider has been ASKED for this title's date.
        // Distinct from a non-empty air_date: plenty of titles have
        // no date to give, and without this the backfill lane would
        // re-ask them forever. Rows enriched before air_date existed
        // default to 0, which is what makes them eligible for it.
        "ALTER TABLE titles ADD COLUMN air_tried INTEGER NOT NULL DEFAULT 0",
        // Scan low-water mark (history auto-deepen).
        "ALTER TABLE marks ADD COLUMN low INTEGER NOT NULL DEFAULT 0",
        // M25 browse view: classification + exact part counts, so
        // SQL can filter "movie AND 2160p" and sort by completeness
        // without re-parsing every stem per request.
        "ALTER TABLE releases ADD COLUMN kind TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE releases ADD COLUMN res TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE releases ADD COLUMN have_parts INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE releases ADD COLUMN need_parts INTEGER NOT NULL DEFAULT 0",
        // M28 indexer v2: the parse key ("t:breaking bad" /
        // "m:inception:2010") persisted so the poster grid groups in
        // SQL, plus a 0-100 junk score for default-wall curation.
        "ALTER TABLE releases ADD COLUMN title_key TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE releases ADD COLUMN junk INTEGER NOT NULL DEFAULT 0",
        // M29 availability oracle: when the idle STAT sampler last
        // probed this release (0 = never) - oldest-verdict-first.
        "ALTER TABLE releases ADD COLUMN oracle_at INTEGER NOT NULL DEFAULT 0",
        // M30 curation: audio-language tags from the stem, space-
        // joined lowercase ("german" / "german multi"; '' = untagged
        // = English by scene convention). Filled at ingest and by
        // the junk_v6 re-score pass, queried by language hide rules.
        "ALTER TABLE releases ADD COLUMN langs TEXT NOT NULL DEFAULT ''",
        // Cached `json_array_length(segments)`. The completeness
        // aggregate called that twice per file row of a release, on
        // every chunk that touched it - so a 210-file release with
        // 13 MB of segments JSON re-parsed all of it just to count
        // parts. Measured on the live index: 16.3 ms with the JSON
        // calls, 0.3 ms without. Written alongside `segments`, so
        // the two cannot drift.
        "ALTER TABLE files ADD COLUMN nsegs INTEGER NOT NULL DEFAULT 0",
        // What separates two encodes of the same film once resolution
        // ties: the release name already carries these, and the parser
        // already read them, but until now they were parsed and thrown
        // away. '' = the name said nothing (or the row predates the
        // columns and the quality_v8 pass hasn't reached it).
        "ALTER TABLE releases ADD COLUMN vcodec TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE releases ADD COLUMN acodec TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE releases ADD COLUMN hdr TEXT NOT NULL DEFAULT ''",
        // Monotonic wall-arrival cursor. A release id alone is not a
        // safe cursor because SQLite may reuse the highest rowid after
        // eviction deletes it.
        "ALTER TABLE releases ADD COLUMN arrival_seq INTEGER NOT NULL DEFAULT 0",
        // A8 targeted gap-fill: when a secondary-server window scan
        // last tried to complete this release (0 = never) - oldest
        // first, like oracle_at.
        "ALTER TABLE releases ADD COLUMN gapfill_at INTEGER NOT NULL DEFAULT 0",
        // Pre feed: the real name a relay channel gave this release,
        // and where that name came from. Kept BESIDE `stem` rather
        // than replacing it - the stem is the posted identity, it is
        // half of the UNIQUE key that makes ingest idempotent, and
        // the FTS index is external-content over it with no UPDATE
        // trigger. Overwriting it would break all three and lose the
        // evidence that the two names are different things.
        //
        // '' = never named from the feed. Non-empty is a claim made
        // by somebody else, which is why `pre_source` is not
        // optional in practice: a name whose origin we cannot state
        // is a name we should not be showing.
        "ALTER TABLE releases ADD COLUMN pre_title TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE releases ADD COLUMN pre_source TEXT NOT NULL DEFAULT ''",
        // When the retro sweep last considered this row (0 = never).
        // Lets the backlog pass move through the index once instead
        // of re-examining the newest rows every tick.
        "ALTER TABLE releases ADD COLUMN pre_at INTEGER NOT NULL DEFAULT 0",
        // Phase 2 correlation: the normalized pre time - announced
        // time when the relay claimed one, arrival time otherwise.
        // A stored column rather than a CASE expression because the
        // correlation window range-scans it and an expression over
        // two columns cannot use one index.
        "ALTER TABLE predb ADD COLUMN pt INTEGER NOT NULL DEFAULT 0",
        // Byte-probe naming lane (TODO 131 B3): when the prober last
        // touched this row (0 = never, oldest-first rotation like
        // oracle_at/gapfill_at) and how many attempts it has spent.
        // Tries saturate at the give-up cap so a row that cannot be
        // probed (scrambled order, missing head, packed-out-of-reach
        // header) drops out of the pick instead of being chased -
        // chasing is the 779-fetch livelock the lane exists to avoid.
        "ALTER TABLE releases ADD COLUMN probe_at INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE releases ADD COLUMN probe_tries INTEGER NOT NULL DEFAULT 0",
        // Terminal header-encryption classification (TODO 131 rung 5,
        // research/RAR-continuation-pilot-2026-08-10): the archive's own
        // bytes say a password is required, so NO byte probe at any
        // budget will ever read a name out of it. 0 = never classified.
        //
        // A GENERATION number, not a boolean, and that is load-bearing:
        // only `enc_class == index::ENC_CLASS` counts as terminal, so
        // bumping that constant un-retires every row a wrong classifier
        // stamped, with no migration. See index/encrypted.rs for why a
        // terminal stamp is defensible here when the byte-probe lanes'
        // saturating probe_tries was not.
        "ALTER TABLE releases ADD COLUMN enc_class INTEGER NOT NULL DEFAULT 0",
        // Which container and which signature earned the stamp
        // ('rar5/head-crypt', 'rar4/mhd-password', '7z/aes-header') -
        // the evidence a later generation is argued from.
        "ALTER TABLE releases ADD COLUMN enc_kind TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE releases ADD COLUMN enc_at INTEGER NOT NULL DEFAULT 0",
        // Pesto family (TODO 131, red-team 5a): the decoded message-id
        // counter range and earliest clock of a release whose articles
        // match the pesto grammar, persisted at scan time. NULL = not
        // pesto. The counter is the per-session key the tiny-PAR2 rung
        // links backward through; the randomized Date header is NEVER
        // used for association (census, 10 Aug 2026). Nullable on
        // purpose - 0 is a legal counter value.
        "ALTER TABLE releases ADD COLUMN pesto_ctr_min INTEGER",
        "ALTER TABLE releases ADD COLUMN pesto_ctr_max INTEGER",
        "ALTER TABLE releases ADD COLUMN pesto_clock INTEGER",
        // Spot-born adult marker (TODO 131): the person who posted this
        // release filed it under the Spotnet adult subcategory. 0 = no
        // such claim, which is every scanner-born row and every spot
        // filed anywhere else - it is NOT "known not adult".
        //
        // Distinct from the wall's genre test (index/browse.rs) on
        // purpose: that one reads `titles.genres`, which only exists
        // once enrichment has reached the title, and a fresh spot-born
        // card usually has no enrichment at all - so on the one source
        // that is a third erotica the filter had nothing to read. This
        // column is the poster's own filing of their own post, written
        // at promotion time, and the two are OR'd together.
        "ALTER TABLE releases ADD COLUMN adult INTEGER NOT NULL DEFAULT 0",
        // Spot promotion (TODO 131): the release row this spot became
        // (or was found to duplicate); 0 = not resolved yet. Set once
        // the spot's NZB has been fetched and folded into `releases`,
        // so it doubles as the resolver's "done" marker.
        "ALTER TABLE spots ADD COLUMN release_id INTEGER NOT NULL DEFAULT 0",
        // NZB fetch attempts for the resolver's retry cap. A spot
        // whose payload articles are gone stops being retried after a
        // few passes instead of burning the budget forever.
        "ALTER TABLE spots ADD COLUMN nzb_tried INTEGER NOT NULL DEFAULT 0",
        // What the one corroborating STAT said about the promoted
        // release's head article (TODO 131): 0 never asked, 1 the
        // article is there, 2 it is not. A spot-born card's
        // completeness is otherwise the NZB's own declaration about
        // itself, which nothing has ever checked against a provider -
        // survivable at the tip, badly wrong at depth, where the
        // catalogue now reaches back to 2011.
        "ALTER TABLE spots ADD COLUMN stat_ok INTEGER NOT NULL DEFAULT 0",
    ] {
        let _ = db.execute(ddl, []);
    }
    // The pesto backward-link's candidate query is a (grp, counter)
    // range probe; partial so the millions of non-pesto rows cost
    // nothing. Lives after the ALTERs that guarantee the column.
    let _ = db.execute(
        "CREATE INDEX IF NOT EXISTS idx_rel_pesto
           ON releases(grp, pesto_ctr_min) WHERE pesto_ctr_min IS NOT NULL",
        [],
    );
    // The header-encryption stats group by kind over a band that is a
    // rounding error next to the whole table; partial so the millions of
    // never-classified rows cost nothing to store or maintain.
    let _ = db.execute(
        "CREATE INDEX IF NOT EXISTS idx_rel_enc
           ON releases(enc_class) WHERE enc_class>0",
        [],
    );
    // The pt index and its one-shot backfill live here, after the
    // ALTER above has guaranteed the column on every install. The
    // kv flag keeps the UPDATE from re-running on every open of a
    // large feed table; it runs BEFORE anything samples predb.
    let _ = db.execute("CREATE INDEX IF NOT EXISTS idx_predb_pt ON predb(pt)", []);
    let pt_done: bool = db
        .query_row(
            "SELECT 1 FROM kv WHERE k='predb_pt_backfill_v1'",
            [],
            |_| Ok(()),
        )
        .is_ok();
    if !pt_done {
        let done = db
            .execute(
                "UPDATE predb SET pt=CASE WHEN pre_at>0 THEN pre_at ELSE seen_at END
                  WHERE pt=0",
                [],
            )
            .is_ok();
        if done {
            let _ = db.execute(
                "INSERT OR REPLACE INTO kv(k,v) VALUES('predb_pt_backfill_v1','1')",
                [],
            );
        }
    }
}

/// A8: rebuild a single-server-era marks table to (grp, server).
fn rebuild_marks_if_needed(db: &Connection) {
    // A8: rebuild a single-server-era marks table (PRIMARY KEY(grp))
    // to the (grp, server) shape. SQLite cannot ALTER a primary key,
    // so this is the standard rebuild - one-time; the PRAGMA guard
    // keeps every later open from bumping the schema version. Rows
    // keep server='' until adopt_legacy_marks assigns them to the
    // server that actually built them. Non-fatal like the other
    // migrations: on failure the next open retries, and the worst a
    // lost marks table costs is a rescan (ingest is idempotent).
    let has_server_col = db
        .prepare("SELECT 1 FROM pragma_table_info('marks') WHERE name='server'")
        .and_then(|mut s| s.exists([]))
        .unwrap_or(false);
    if !has_server_col {
        // A real Transaction object, not a BEGIN/COMMIT batch: a
        // mid-batch failure would otherwise leave the transaction
        // open on this connection, and every later statement in this
        // open() would silently run (and hold the write lock) inside
        // it. The drop of an uncommitted Transaction rolls back.
        let rebuild = db.unchecked_transaction().and_then(|tx| {
            tx.execute_batch(
                "DROP TABLE IF EXISTS marks_v2;
                 CREATE TABLE marks_v2(
                    grp TEXT NOT NULL,
                    server TEXT NOT NULL DEFAULT '',
                    high INTEGER NOT NULL,
                    low INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY(grp, server));
                 INSERT INTO marks_v2(grp, server, high, low)
                   SELECT grp, '', high, low FROM marks;
                 DROP TABLE marks;
                 ALTER TABLE marks_v2 RENAME TO marks;",
            )?;
            tx.commit()
        });
        let _ = rebuild;
    }
}

/// The wall arrival-seq counter/trigger and the M28 browse indexes.
fn arrival_counter_and_indexes(db: &Connection) {
    // Existing rows receive their current id as an initial cursor.
    // New inserts advance a persistent counter in the same SQLite write
    // transaction, so same-second arrivals and rowid reuse both remain
    // visible to an already-open wall.
    // Non-fatal, like every other migration in this function. This
    // batch ENDS in an unconditional `UPDATE kv ... WHERE
    // k='wall_arrival_seq'`, which always matches a row, so every
    // single `Index::open` takes the SQLite write lock. A scan pass
    // opens up to 8 handles concurrently while a foreground ingest
    // chunk holds the writer, so exceeding the busy timeout is a
    // routine event, not a corrupt database - and propagating it made
    // `with_index` hand back None, which skips a whole group's scan
    // for the interval and answers wall/browse/search with nothing.
    // Every statement here is idempotent and self-healing: a later
    // open re-runs it, and rows that missed the trigger keep
    // arrival_seq=0 until the first line above claims them.
    let _ = db.execute_batch(
        "UPDATE releases SET arrival_seq=id WHERE arrival_seq=0;
         INSERT OR IGNORE INTO kv(k, v)
           VALUES('wall_arrival_seq',
                  (SELECT CAST(COALESCE(MAX(arrival_seq), 0) AS TEXT) FROM releases));
         UPDATE kv
            SET v=CAST(MAX(CAST(v AS INTEGER),
                           (SELECT COALESCE(MAX(arrival_seq), 0) FROM releases)) AS TEXT)
          WHERE k='wall_arrival_seq';
         -- The COALESCE is what keeps this trigger fail-SAFE rather
         -- than fail-DEAD. `arrival_seq` is NOT NULL, so if the kv
         -- row is ever absent the SELECT yields NULL, the UPDATE
         -- violates the constraint, and the constraint takes the
         -- whole ingest transaction with it - every insert into
         -- `releases` fails for as long as the row is gone. Nothing
         -- deletes it today, but three places do `DELETE FROM kv
         -- WHERE k=...` and one mistyped key would make the index
         -- permanently unwritable. Falling back to the row id costs
         -- at worst a cursor value shared with an evicted row, and
         -- the statements above restore the counter from
         -- MAX(arrival_seq) on the very next open.
         --
         -- Suffixed `_v2` rather than DROP+CREATEd: the drop of the
         -- old name is a no-op once it has run, so an already
         -- migrated database does not bump its schema version (and
         -- invalidate every other connection's prepared statements)
         -- on every single open.
         DROP TRIGGER IF EXISTS rel_arrival_seq_ai;
         CREATE TRIGGER IF NOT EXISTS rel_arrival_seq_ai_v2
           AFTER INSERT ON releases WHEN new.arrival_seq=0 BEGIN
             UPDATE kv SET v=CAST(CAST(v AS INTEGER)+1 AS TEXT)
               WHERE k='wall_arrival_seq';
             UPDATE releases
                SET arrival_seq=COALESCE(
                      CAST((SELECT v FROM kv
                            WHERE k='wall_arrival_seq') AS INTEGER),
                      new.id)
              WHERE id=new.id;
           END;",
    );
    // M28: browse-path indexes - every filter/sort was a full scan
    // (only idx_rel_stem existed).
    let _ = db.execute_batch(
        "CREATE INDEX IF NOT EXISTS idx_rel_posted ON releases(first_posted);
         CREATE INDEX IF NOT EXISTS idx_rel_kind ON releases(kind, first_posted);
         CREATE INDEX IF NOT EXISTS idx_rel_title_key ON releases(title_key);
         CREATE INDEX IF NOT EXISTS idx_rel_size ON releases(total_bytes);
         -- The arrival signal orders by when WE saw a release, not
         -- when it was posted: a backfill leg discovers genuinely old
         -- uploads, and those are not arrivals. Without this index
         -- `wall_tip` is a full scan on every poll.
         CREATE INDEX IF NOT EXISTS idx_rel_seen ON releases(first_seen);
         CREATE INDEX IF NOT EXISTS idx_rel_arrival ON releases(arrival_seq);",
    );
}

/// The two release FTS tables; (fts, pre_fts) availability flags.
fn ensure_fts(db: &Connection) -> (bool, bool) {
    // M28: FTS5 over raw stems (unicode61 tokenizer already treats
    // ./-/_ as separators, so no normalized shadow column is needed).
    // External-content table + triggers stay in sync with prune
    // deletes; stems are immutable so no UPDATE trigger. Wrapped in
    // is_ok() so a non-FTS build just keeps the LIKE path.
    let fts = db
        .execute_batch(
            "CREATE VIRTUAL TABLE IF NOT EXISTS rel_fts
               USING fts5(stem, content='releases', content_rowid='id');
             CREATE TRIGGER IF NOT EXISTS rel_fts_ai AFTER INSERT ON releases BEGIN
               INSERT INTO rel_fts(rowid, stem) VALUES(new.id, new.stem); END;
             CREATE TRIGGER IF NOT EXISTS rel_fts_ad AFTER DELETE ON releases BEGIN
               INSERT INTO rel_fts(rel_fts, rowid, stem)
                 VALUES('delete', old.id, old.stem); END;",
        )
        .is_ok();
    // A SECOND, tiny FTS index over the names the pre feed supplied.
    //
    // Not a column added to `rel_fts`: that is an external-content
    // table over millions of stems, and widening it means dropping,
    // recreating and rebuilding the whole thing at open - a minutes-
    // long startup stall on a large index, paid by every install
    // including the ones that never turn the feed on. This one only
    // ever holds rows that HAVE a fed name, so on a default install
    // it stays empty and costs a table definition.
    //
    // Unlike stems, a fed name arrives by UPDATE (the retro sweep
    // names a release long after it was inserted), so this one does
    // need the update trigger the stem index can do without.
    let pre_fts = db
        .execute_batch(
            "CREATE VIRTUAL TABLE IF NOT EXISTS pre_fts
               USING fts5(pre_title, content='releases', content_rowid='id');
             CREATE TRIGGER IF NOT EXISTS pre_fts_ai AFTER INSERT ON releases
               WHEN new.pre_title<>'' BEGIN
                 INSERT INTO pre_fts(rowid, pre_title)
                   VALUES(new.id, new.pre_title); END;
             CREATE TRIGGER IF NOT EXISTS pre_fts_ad AFTER DELETE ON releases
               WHEN old.pre_title<>'' BEGIN
                 INSERT INTO pre_fts(pre_fts, rowid, pre_title)
                   VALUES('delete', old.id, old.pre_title); END;
             CREATE TRIGGER IF NOT EXISTS pre_fts_au
               AFTER UPDATE OF pre_title ON releases BEGIN
                 INSERT INTO pre_fts(pre_fts, rowid, pre_title)
                   SELECT 'delete', old.id, old.pre_title WHERE old.pre_title<>'';
                 INSERT INTO pre_fts(rowid, pre_title)
                   SELECT new.id, new.pre_title WHERE new.pre_title<>''; END;",
        )
        .is_ok();
    (fts, pre_fts)
}

/// People + credits schema (fatal on failure, unlike the migrations)
/// and the people_fts index; returns whether people_fts is usable.
fn ensure_people(db: &Connection) -> rusqlite::Result<bool> {
    // Cast and crew as entities rather than a rendered string.
    // `titles.actors` stays exactly as it is - it is what every card
    // renders today, and nothing may regress while this join table
    // fills in behind it. The join table is what the person page,
    // name search and cast-overlap affinity read.
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS people(
            id           INTEGER PRIMARY KEY,
            name         TEXT NOT NULL,
            imdb         TEXT NOT NULL DEFAULT '',
            -- The two filmography handles. TVmaze's person id answers
            -- 'what else did they do on TV'; the Wikidata Q-id answers
            -- the film half. Neither source covers the other, so a
            -- person legitimately carries both.
            tvmaze_id    INTEGER NOT NULL DEFAULT 0,
            wikidata_qid TEXT NOT NULL DEFAULT '',
            bio          TEXT NOT NULL DEFAULT '',
            born         TEXT NOT NULL DEFAULT '',
            -- The provider's headshot URL, and unlike titles.poster
            -- it stays a URL. The cached file is evictable (a large
            -- index would otherwise quietly fill a NAS with
            -- headshots), and after an eviction the URL is the only
            -- thing that can fetch it back.
            photo        TEXT NOT NULL DEFAULT '',
            checked      INTEGER NOT NULL DEFAULT 0);
         CREATE TABLE IF NOT EXISTS title_people(
            key       TEXT NOT NULL,
            person_id INTEGER NOT NULL,
            role      TEXT NOT NULL DEFAULT 'actor',
            character TEXT NOT NULL DEFAULT '',
            ord       INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY(key, person_id, role));
         CREATE INDEX IF NOT EXISTS idx_tp_person ON title_people(person_id, ord);
         -- Partial uniques, so the handle-first upsert cannot race two
         -- threads into two rows for one person. They must stay
         -- partial: the default 0 / '' is 'no handle', and a plain
         -- UNIQUE would let exactly one person exist without one.
         CREATE UNIQUE INDEX IF NOT EXISTS idx_people_tvmaze
           ON people(tvmaze_id) WHERE tvmaze_id > 0;
         CREATE UNIQUE INDEX IF NOT EXISTS idx_people_qid
           ON people(wikidata_qid) WHERE wikidata_qid <> '';
         -- Same rule for the IMDb id, and safe to add to an existing
         -- database: nothing ever wrote this column before the
         -- Wikidata P345 lane did, so every pre-existing row holds
         -- '' and falls outside the partial index. It carries the
         -- same trade the other two already do - the blank-fill
         -- UPDATE can collide when the handle-first lookup lands on
         -- a row whose blank belongs to another row's id, which
         -- fails that one title's credit write and lets the next
         -- enrichment retry it. Duplicate Wikidata items for one
         -- person, which is the common way two rows share an nm id,
         -- resolve through the lookup instead and merge cleanly.
         CREATE UNIQUE INDEX IF NOT EXISTS idx_people_imdb
           ON people(imdb) WHERE imdb <> '';
         CREATE INDEX IF NOT EXISTS idx_people_name ON people(name COLLATE NOCASE);",
    )?;
    // Name search. Unlike rel_fts there IS an UPDATE trigger: a
    // person row's name improves when a second provider supplies a
    // better-cased or fuller spelling, and an external-content FTS
    // that missed the update returns the row under a name it no
    // longer has.
    let people_fts = db.execute_batch(
        "CREATE VIRTUAL TABLE IF NOT EXISTS people_fts
           USING fts5(name, content='people', content_rowid='id');
         CREATE TRIGGER IF NOT EXISTS people_fts_ai AFTER INSERT ON people BEGIN
           INSERT INTO people_fts(rowid, name) VALUES(new.id, new.name); END;
         CREATE TRIGGER IF NOT EXISTS people_fts_ad AFTER DELETE ON people BEGIN
           INSERT INTO people_fts(people_fts, rowid, name)
             VALUES('delete', old.id, old.name); END;
         CREATE TRIGGER IF NOT EXISTS people_fts_au
           AFTER UPDATE OF name ON people BEGIN
           INSERT INTO people_fts(people_fts, rowid, name)
             VALUES('delete', old.id, old.name);
           INSERT INTO people_fts(rowid, name) VALUES(new.id, new.name); END;",
    );
    Ok(people_fts.is_ok())
}

/// The one-shot, kv-stamped retroactive backfills (completeness rule,
/// nsegs, M25 kind/res, M28 FTS + title_key/junk, quality_v8).
fn retroactive_backfills(db: &mut Connection, fts: bool) {
    // One-time retroactive recompute after the completeness-rule
    // change (nfiles >= 2 → >= 1): existing rows only re-evaluate
    // when a scan touches them, which for finished uploads is never.
    let rule: Option<String> = db
        .query_row("SELECT v FROM kv WHERE k='complete_rule'", [], |r| r.get(0))
        .ok();
    if rule.as_deref() != Some("2") {
        // One transaction, and the done-flag only lands if the
        // recompute did: as two autocommit statements, a SQLITE_BUSY
        // on the big UPDATE (discarded) with the tiny insert
        // succeeding stamped the migration done while every
        // completeness flag stayed stale - permanently.
        let _ = (|| -> rusqlite::Result<()> {
            let tx = db.unchecked_transaction()?;
            tx.execute(
                "UPDATE releases SET complete =
                   EXISTS(SELECT 1 FROM files f WHERE f.release_id=releases.id)
                   AND NOT EXISTS(SELECT 1 FROM files f WHERE f.release_id=releases.id
                                  AND json_array_length(f.segments) < f.total_parts)",
                [],
            )?;
            tx.execute(
                "INSERT INTO kv(k, v) VALUES('complete_rule','2')
                 ON CONFLICT(k) DO UPDATE SET v='2'",
                [],
            )?;
            tx.commit()
        })();
    }
    // Retroactive fill of `nsegs` for rows written before the column
    // existed. Finished uploads are never re-ingested, so without
    // this they would take the JSON-parsing fallback above forever.
    //
    // Chunked with a kv rowid cursor, and time-bounded, for two
    // reasons learned the hard way. A single UPDATE over the whole
    // files table (1.6 M rows on the live index) loses the write
    // lock to a running scanner and is silently discarded - the
    // junk_v6 re-score did exactly that. And an unbounded loop here
    // would block daemon startup for minutes, since every scan task
    // opens its own Index. Whatever is left resumes on the next
    // open; the read side is correct throughout either way.
    let filled: Option<String> = db
        .query_row("SELECT v FROM kv WHERE k='nsegs_fill'", [], |r| r.get(0))
        .ok();
    if filled.as_deref() != Some("1") {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let _ = (|| -> rusqlite::Result<()> {
            loop {
                // Acquire the writer reservation BEFORE reading the
                // cursor. Several scan connections open the index at
                // once; a deferred transaction let two of them read
                // the same cursor, then a delayed one could overwrite
                // a later cursor with its stale lower value.
                let tx = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
                let cursor: i64 = tx
                    .query_row("SELECT v FROM kv WHERE k='nsegs_at'", [], |r| {
                        r.get::<_, String>(0)
                    })
                    .ok()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0);
                // Advance by rowid, never by "nsegs = 0": a row whose
                // segments JSON will not parse stays 0 forever and
                // would be re-selected every pass, spinning here.
                let next: Option<i64> = tx.query_row(
                    "SELECT MAX(rowid) FROM
                       (SELECT rowid FROM files WHERE rowid > ?1 ORDER BY rowid LIMIT 5000)",
                    [cursor],
                    |r| r.get(0),
                )?;
                let Some(next) = next else {
                    tx.execute(
                        "INSERT INTO kv(k, v) VALUES('nsegs_fill','1')
                         ON CONFLICT(k) DO UPDATE SET v='1'",
                        [],
                    )?;
                    tx.commit()?;
                    return Ok(());
                };
                tx.execute(
                    "UPDATE files SET nsegs = COALESCE(json_array_length(segments), 0)
                     WHERE rowid > ?1 AND rowid <= ?2",
                    [cursor, next],
                )?;
                // Cursor moves with the rows, in the same
                // transaction: a busy failure rolls back both and
                // the chunk is simply redone.
                tx.execute(
                    "INSERT INTO kv(k, v) VALUES('nsegs_at', ?1)
                     ON CONFLICT(k) DO UPDATE SET v=excluded.v",
                    [next.to_string()],
                )?;
                tx.commit()?;
                if std::time::Instant::now() >= deadline {
                    return Ok(());
                }
            }
        })();
    }
    // M25 browse view: retroactive fill of the new kind/res/part
    // columns for rows indexed before they existed. Same shape as
    // the complete_rule migration: one transaction, flag stamped
    // only if the fill landed, so SQLITE_BUSY just retries next open.
    let done: Option<String> = db
        .query_row("SELECT v FROM kv WHERE k='browse_cols'", [], |r| r.get(0))
        .ok();
    if done.as_deref() != Some("1") {
        let _ = (|| -> rusqlite::Result<()> {
            let tx = db.unchecked_transaction()?;
            tx.execute(
                "UPDATE releases SET
                   have_parts = COALESCE((SELECT SUM(json_array_length(segments))
                                          FROM files WHERE release_id=releases.id), 0),
                   need_parts = COALESCE((SELECT SUM(total_parts)
                                          FROM files WHERE release_id=releases.id), 0)",
                [],
            )?;
            {
                let mut sel = tx.prepare("SELECT id, stem FROM releases WHERE kind=''")?;
                let mut upd = tx.prepare("UPDATE releases SET kind=?2, res=?3 WHERE id=?1")?;
                let rows: Vec<(i64, String)> = sel
                    .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                    .collect::<rusqlite::Result<_>>()?;
                for (id, stem) in rows {
                    let p = crate::release::parse_release(&stem);
                    upd.execute(rusqlite::params![
                        id,
                        kind_str(&p.kind),
                        p.res.unwrap_or_default()
                    ])?;
                }
            }
            tx.execute(
                "INSERT INTO kv(k, v) VALUES('browse_cols','1')
                 ON CONFLICT(k) DO UPDATE SET v='1'",
                [],
            )?;
            tx.commit()
        })();
    }
    // M28: one-time FTS backfill for rows inserted before the
    // triggers existed - 'rebuild' re-reads the whole content table.
    // Same stamped-in-transaction shape as the migrations above.
    if fts {
        let done: Option<String> = db
            .query_row("SELECT v FROM kv WHERE k='fts_v1'", [], |r| r.get(0))
            .ok();
        if done.as_deref() != Some("1") {
            let _ = (|| -> rusqlite::Result<()> {
                let tx = db.unchecked_transaction()?;
                tx.execute("INSERT INTO rel_fts(rel_fts) VALUES('rebuild')", [])?;
                tx.execute(
                    "INSERT INTO kv(k, v) VALUES('fts_v1','1')
                     ON CONFLICT(k) DO UPDATE SET v='1'",
                    [],
                )?;
                tx.commit()
            })();
        }
    }
    // M28: retroactive title_key + junk fill (rows only re-parse when
    // a scan touches them, which for finished uploads is never).
    let done: Option<String> = db
        .query_row("SELECT v FROM kv WHERE k='browse2'", [], |r| r.get(0))
        .ok();
    if done.as_deref() != Some("1") {
        let _ = (|| -> rusqlite::Result<()> {
            let tx = db.unchecked_transaction()?;
            {
                let mut sel =
                    tx.prepare("SELECT id, stem, total_bytes FROM releases WHERE title_key=''")?;
                let mut upd =
                    tx.prepare("UPDATE releases SET title_key=?2, junk=?3 WHERE id=?1")?;
                let rows: Vec<(i64, String, i64)> = sel
                    .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                    .collect::<rusqlite::Result<_>>()?;
                for (id, stem, bytes) in rows {
                    let p = crate::release::parse_release(&stem);
                    upd.execute(rusqlite::params![
                        id,
                        p.key,
                        junk_score(&stem, &p, bytes as u64, false)
                    ])?;
                }
            }
            tx.execute(
                "INSERT INTO kv(k, v) VALUES('browse2','1')
                 ON CONFLICT(k) DO UPDATE SET v='1'",
                [],
            )?;
            tx.commit()
        })();
    }
    // §131 identity substrate: key existing files rows into msgid_map
    // (rows only pass through ingest when a scan touches them, which
    // for finished uploads is never). Same chunked, time-bounded,
    // cursor-resumed shape as the nsegs fill above, for the same
    // reasons: the live table is millions of rows, a single UPDATE
    // loses the write lock to a running scanner, and an unbounded
    // loop would stall daemon startup. Resumes on the next open.
    super::claims::msgid_map_backfill(db);
    // Pesto counter/clock fill for rows scanned before the columns
    // existed - same chunked, time-bounded, cursor-resumed shape, for
    // the same reasons.
    super::pesto::pesto_backfill(db);
    // quality_v8 (26 Jul, was junk_v7): junk_v6's rules plus a full
    // re-parse - title_key/kind/res so ROT13 rescues that the parser
    // newly decodes regroup under their real titles, and now
    // vcodec/acodec/hdr, which rows indexed before those columns
    // existed have never carried. The kv key names the CURRENT
    // version; bumping it re-parses every row exactly once, which is
    // what backfills the new columns - free, because this pass
    // already parses every row's effective name. CHUNKED with a
    // persisted id cursor - the
    // one-big-tx shape could never win the write lock against
    // parallel scanners on a live daemon (SQLITE_BUSY → silently
    // skipped forever). 10k rows per transaction interleaves with
    // scan ingest; a partial pass resumes from the cursor on the
    // next open.
    let done: Option<String> = db
        .query_row("SELECT v FROM kv WHERE k='quality_v8'", [], |r| r.get(0))
        .ok();
    if done.as_deref() != Some("1") {
        let _ = (|| -> rusqlite::Result<()> {
            let mut cursor: i64 = db
                .query_row("SELECT v FROM kv WHERE k='quality_v8_cursor'", [], |r| {
                    r.get::<_, String>(0)
                })
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            loop {
                // IMMEDIATE, like the nsegs, reclassify and ingest
                // transactions: this reads a cursor and writes it
                // back, and a deferred lock upgrade does NOT get the
                // busy timeout - it returns SQLITE_BUSY at once. A
                // deferred wrapper here meant a contended pass
                // abandoned mid-chunk and left the cursor parked.
                let tx = rusqlite::Transaction::new_unchecked(
                    db,
                    rusqlite::TransactionBehavior::Immediate,
                )?;
                // The effective name, NOT the raw stem: a row named
                // after ingest (`apply_named` - predb sweep, spot
                // promotion, byte probes) derived every classification
                // column from pre_title, and its stem is an obfuscated
                // hash. Re-parsing the stem here would clobber the row
                // back to the junk>=70 no-card answer, and nothing
                // would ever heal it - the naming seam refuses rows
                // whose pre_title is already set. Same COALESCE the
                // ingest and card paths use.
                let rows: Vec<(i64, String, i64, bool)> = {
                    let mut sel = tx.prepare_cached(&format!(
                        "SELECT id, COALESCE(NULLIF(pre_title,''), stem),
                                total_bytes,
                                EXISTS(SELECT 1 FROM files
                                       WHERE release_id=releases.id AND {EXE_FILE_SQL})
                         FROM releases WHERE id > ?1 ORDER BY id LIMIT 10000"
                    ))?;
                    sel.query_map([cursor], |r| {
                        Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
                    })?
                    .collect::<rusqlite::Result<_>>()?
                };
                if rows.is_empty() {
                    tx.execute(
                        "INSERT INTO kv(k, v) VALUES('quality_v8','1')
                         ON CONFLICT(k) DO UPDATE SET v='1'",
                        [],
                    )?;
                    tx.commit()?;
                    break;
                }
                {
                    // `parse_release` is CUSTOM-BLIND: `Index::open`
                    // runs before `set_custom`, by construction (the
                    // constructor hardcodes an empty category list),
                    // so this pass cannot know the user's categories.
                    // Re-parsing a row that `reclassify_custom`
                    // classified would therefore rewrite kind and
                    // title_key back to the built-in answer - every
                    // session of an F1 season collapsing onto one
                    // movie card, out of the category tab, and losing
                    // the Custom junk exemption. Worse, it does not
                    // heal: `reclassify_custom` sees an unchanged
                    // fingerprint and no cursor and returns Ok(0) on
                    // every later start.
                    //
                    // So the classification columns are written only
                    // for rows still carrying a built-in kind. The
                    // rest - the codec/resolution/language backfill
                    // this pass exists for - is unconditional, and is
                    // correct for custom rows too, because
                    // `apply_custom` mutates ONLY kind and key.
                    // '' is in the list deliberately: a row that has
                    // never been classified still needs its first
                    // parse.
                    let mut upd = tx.prepare_cached(
                        "UPDATE releases SET langs=?2, res=?3,
                                vcodec=?4, acodec=?5, hdr=?6
                         WHERE id=?1 AND (langs<>?2 OR res<>?3
                                OR vcodec<>?4 OR acodec<>?5 OR hdr<>?6)",
                    )?;
                    let mut upd_class = tx.prepare_cached(
                        "UPDATE releases SET junk=?2, title_key=?3, kind=?4
                         WHERE id=?1
                           AND kind IN ('movie','tv','music','book',
                                        'software','other','')
                           AND (junk<>?2 OR title_key<>?3 OR kind<>?4)",
                    )?;
                    for (id, name, bytes, has_exe) in &rows {
                        let p = crate::release::parse_release(name);
                        upd.execute(rusqlite::params![
                            id,
                            p.langs.join(" "),
                            p.res.as_deref().unwrap_or_default(),
                            p.vcodec.as_deref().unwrap_or_default(),
                            p.acodec.as_deref().unwrap_or_default(),
                            p.hdr.as_deref().unwrap_or_default()
                        ])?;
                        upd_class.execute(rusqlite::params![
                            id,
                            junk_score(name, &p, *bytes as u64, *has_exe),
                            p.key,
                            kind_str(&p.kind)
                        ])?;
                    }
                }
                cursor = rows.last().unwrap().0;
                tx.execute(
                    "INSERT INTO kv(k, v) VALUES('quality_v8_cursor', ?1)
                     ON CONFLICT(k) DO UPDATE SET v=?1",
                    [cursor.to_string()],
                )?;
                tx.commit()?;
            }
            Ok(())
        })();
    }
}

impl Index {
    pub fn open(path: &Path) -> rusqlite::Result<Index> {
        let mut db = Connection::open(path)?;
        // Several connections share this db (scan scratch, API queries,
        // wall enricher, IMDb refresher). Without a busy timeout a
        // schema-creation or checkpoint race fails INSTANTLY with
        // "database is locked" - which made the daemon's first scan pass
        // silently skip a whole interval (the long-standing
        // scan_loop_populates_index_live "flake").
        db.busy_timeout(std::time::Duration::from_secs(10))?;
        create_base_schema(&db)?;
        additive_migrations(&db);
        rebuild_marks_if_needed(&db);
        arrival_counter_and_indexes(&db);
        let (fts, pre_fts) = ensure_fts(&db);
        let people_fts_ok = ensure_people(&db)?;
        let people_fts = fts && people_fts_ok;
        retroactive_backfills(&mut db, fts);
        // M29 availability oracle: (backbone, family, age-bucket) ledger.
        let _ = crate::oracle::ensure_schema(&db);
        // `EXISTS` rather than a count: this only has to answer "is the
        // feed worth consulting", and on a large predb the count is a
        // full index scan at every open.
        let predb = db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM predb WHERE fnkey<>'')",
                [],
                |r| r.get::<_, bool>(0),
            )
            .unwrap_or(false);
        // The named-count's partial index rides on feed activity, not
        // on `predb` above: a title-only feed (the common live shape)
        // has no nameable rows yet still names releases through the
        // correlation legs, and the settings card asks for the count
        // either way. Any row in predb at all means the build is
        // worth paying once here, on the writer - the API's read-only
        // handle cannot create it. An install whose feed never ran
        // has an empty table and never pays.
        let feed_ever = db
            .query_row("SELECT EXISTS(SELECT 1 FROM predb)", [], |r| {
                r.get::<_, bool>(0)
            })
            .unwrap_or(false);
        if feed_ever {
            Self::ensure_named_index(&db);
        }
        Ok(Index {
            db,
            gate: None,
            fts,
            pre_fts,
            people_fts,
            custom: Vec::new(),
            predb,
            watch: None,
            hits: Default::default(),
        })
    }

    /// A read-only connection for query handlers, so an interactive
    /// wall/search/browse request never queues behind whoever is holding
    /// a read-write connection through a long ingest or maintenance
    /// pass. The database is WAL, so this connection's reads run
    /// concurrently with the writer and each query begins a fresh read
    /// transaction - it always sees the latest committed data without
    /// being reopened.
    ///
    /// Skips every migration `open` runs (a read-only handle cannot run
    /// them, and must not need to): callers open this only after a
    /// read-write `open` has brought the schema up to date. Fails if the
    /// database file does not exist yet - it must never be the call that
    /// creates the file.
    pub fn open_read_only(path: &Path) -> rusqlite::Result<Index> {
        let db = Connection::open_with_flags(
            path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
                | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX
                | rusqlite::OpenFlags::SQLITE_OPEN_URI,
        )?;
        // Readers in WAL only ever wait on the brief WAL-reset window of
        // a checkpoint, but "brief" still deserves a timeout rather than
        // an instant "database is locked".
        db.busy_timeout(std::time::Duration::from_secs(10))?;
        // The per-connection tuning half of open()'s pragmas; query_only
        // makes any write that sneaks onto this connection fail loudly
        // instead of contending for the write lock.
        //
        // cache_size is a quarter of the writer's 256 MB: the daemon
        // pools up to four of these connections and never evicts an
        // idle one, so the writer's figure here would let query bursts
        // pin ~1 GB of page cache forever - the difference between
        // fitting and swapping on a NAS. Reads mostly ride the 1 GB
        // mmap window anyway, which costs only address space.
        db.execute_batch(
            "PRAGMA query_only=ON;
             PRAGMA temp_store=MEMORY;
             PRAGMA cache_size=-65536;
             PRAGMA mmap_size=1073741824;",
        )?;
        // FTS availability is detected, not created: the tables exist iff
        // the read-write open that ran the schema managed to create them.
        let has = |name: &str| {
            db.query_row(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?1",
                [name],
                |_| Ok(()),
            )
            .is_ok()
        };
        let fts = has("rel_fts");
        let people_fts = fts && has("people_fts");
        // Same detection for the pre-feed name index. Load-bearing: this
        // is the connection every interactive search and browse runs on,
        // so if it read `false` here a release the pre feed rescued would
        // be findable by its obfuscated stem and by nothing else.
        let pre_fts = has("pre_fts");
        // `predb` gates the ingest-time naming lookup only, and ingest
        // never happens on a query_only connection.
        let predb = false;
        // No gate and no custom categories: both are ingest-time policy,
        // and ingest cannot happen on a query_only connection. Same for
        // the arrival watch - nothing arrives on a reader.
        Ok(Index {
            db,
            gate: None,
            fts,
            pre_fts,
            people_fts,
            custom: Vec::new(),
            predb,
            watch: None,
            hits: Default::default(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::testutil::entry;

    /// The read-only connection behind the daemon's interactive query
    /// endpoints: it reads what the writer commits WITHOUT being
    /// reopened (WAL - each query is a fresh read transaction), and any
    /// write that sneaks onto it fails instead of contending for the
    /// write lock.
    #[test]
    fn read_only_connection_sees_fresh_commits_and_refuses_writes() {
        let dir = std::env::temp_dir().join(format!("nzbfast-index-ro-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("index.db");
        let mut rw = Index::open(&db).unwrap();
        rw.ingest(
            "alt.binaries.test",
            &[entry(
                r#""First.Release.S01E01.720p-GRP.rar" yEnc (1/1)"#,
                "p@x",
                "ro1",
                900,
            )],
            1000,
        )
        .unwrap();

        let ro = Index::open_read_only(&db).unwrap();
        assert_eq!(ro.search("first", 10).unwrap().len(), 1);

        // A commit AFTER the read-only open, visible without a reopen.
        rw.ingest(
            "alt.binaries.test",
            &[entry(
                r#""Second.Release.S01E02.720p-GRP.rar" yEnc (1/1)"#,
                "p@x",
                "ro2",
                900,
            )],
            1000,
        )
        .unwrap();
        assert_eq!(ro.search("second", 10).unwrap().len(), 1);

        // query_only: the connection refuses writes rather than taking
        // the write lock.
        assert!(ro.kv_set("k", "v").is_err());
        // And it must never be the open that CREATES a database.
        assert!(Index::open_read_only(&dir.join("absent.db")).is_err());
    }
}

//! Title and person metadata (TODO 106 phase 2.2, cut 4): the titles
//! table (seed, fill, identity, lanes), credits, people and their photo
//! queue. Bodies are verbatim moves from the old index.rs.

use super::*;

/// A title with at least one release the wall would actually show.
///
/// Enrichment is the scarcest thing the daemon does - MusicBrainz allows
/// one request a second, and Wikimedia 429s at three - so spending it on
/// a card nobody can see is the most expensive kind of waste. Measured
/// on a live 7,755-title index before this existed: of 5,243 lookups
/// that cost a network call, **3,910 (75%) went to titles with no
/// release passing the junk gate**. They are not rare edge cases; they
/// are most of the budget.
///
/// `junk < 50` is the wall's own default threshold, so this asks exactly
/// "would the wall list this?" rather than inventing a second policy.
///
/// It defers rather than drops. Junk scores are recomputed on every
/// ingest touch and a mid-upload release sheds junk as its parts arrive,
/// so a title that is invisible now and becomes visible later is simply
/// picked up on a later pass - it stays `checked=0` throughout. Nothing
/// is permanently skipped, which matters because the enricher's one-shot
/// `checked` stamp has no way back (see the tri-state plan in
/// research/indexer-realtime-and-enrichment-plan-2026-07-26.md §11.1).
const VISIBLE: &str = "EXISTS (SELECT 1 FROM releases r WHERE r.title_key = t.key AND r.junk < 50)";

/// What a lookup learned about one title. A struct rather than the ten
/// positional arguments this used to take: the "found nothing" callers
/// passed a row of bare `""`s in which nothing said which field was
/// which, and every new field made that worse.
#[derive(Debug, Clone, Default)]
pub struct TitleFill<'a> {
    pub tmdb_id: i64,
    pub overview: &'a str,
    pub rating: f64,
    pub genres: &'a str,
    /// Local art FILENAMES, not provider URLs - the caller downloads the
    /// images before filling.
    pub poster: &'a str,
    pub backdrop: &'a str,
    pub imdb: &'a str,
    pub actors: &'a str,
    /// ISO `YYYY-MM-DD`, or empty when the provider had no date.
    pub air_date: &'a str,
}

/// One person's credit on one title, as a provider gave it to us.
///
/// The identity fields are what make this more than the comma-joined
/// name string `titles.actors` already holds: TVmaze hands over a person
/// id and Wikidata a Q-id, and each is the handle its own filmography
/// endpoint takes. A provider that gives neither (OMDb, TMDB) still
/// produces a usable credit - it just cannot be followed off-index.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Credit {
    pub name: String,
    /// actor | director | writer | composer | creator | producer | …
    /// Free text, because crew vocabularies differ per provider and
    /// flattening them to an enum loses the useful ones ("Director of
    /// Photography"). Empty is stored as "actor".
    pub role: String,
    /// The part they played, when the provider models it (TVmaze
    /// `character.name`, Wikidata's P453 qualifier). Empty for crew.
    pub character: String,
    /// Billing order, lower first. 0 when unranked.
    pub ord: i64,
    pub tvmaze_id: i64,
    pub wikidata_qid: String,
    /// IMDb `nm…` id. Unlike the two handles above this one is shared
    /// vocabulary rather than a provider's own numbering, so it is the
    /// only field that can identify the same human across providers.
    pub imdb: String,
    /// Date of birth, ISO `YYYY-MM-DD`, empty when unknown. Not an
    /// identifier - it is the disambiguator `person_upsert` uses to tell
    /// two same-named people apart, and it earns that job by being the
    /// one fact BOTH cast providers publish (TVmaze `person.birthday`,
    /// Wikidata P569).
    pub born: String,
    /// Headshot: a provider URL as parsed, swapped for the local
    /// art-cache filename once the enricher has fetched it.
    pub photo: String,
}

/// A credit joined to its resolved person (what the detail sheet shows).
#[derive(Debug, Clone)]
pub struct PersonCredit {
    pub person_id: i64,
    pub name: String,
    pub photo: String,
    pub role: String,
    pub character: String,
    pub ord: i64,
}

#[derive(Debug, Clone, Default)]
pub struct PersonRow {
    pub id: i64,
    pub name: String,
    pub imdb: String,
    pub tvmaze_id: i64,
    pub wikidata_qid: String,
    pub bio: String,
    pub born: String,
    pub photo: String,
}

/// One title on a person page's "in your index" half.
#[derive(Debug, Clone)]
pub struct PersonTitle {
    pub key: String,
    pub kind: String,
    pub title: String,
    pub year: u32,
    pub poster: String,
    pub air_date: String,
    /// Every role they hold on this title, comma-joined - one person can
    /// star in a show AND produce it.
    pub role: String,
    /// The part they played, from the acting credit; empty for crew-only.
    pub character: String,
    pub ord: i64,
    pub n_releases: i64,
}

#[derive(Debug, Clone)]
pub struct PersonHit {
    pub id: i64,
    pub name: String,
    pub photo: String,
    /// How many visible titles they are credited on - the ranking signal
    /// and the honest answer to "is this person actually in my index".
    pub n_titles: i64,
}

/// One cached title-metadata row (M13 wall).
#[derive(Debug, Clone)]
pub struct TitleRow {
    pub key: String,
    pub kind: String,
    pub title: String,
    pub year: u32,
    pub tmdb_id: i64,
    pub overview: String,
    pub rating: f64,
    pub genres: String,
    pub poster: String,
    pub backdrop: String,
    pub checked: i64,
    /// IMDb tconst ("tt0133093") when a provider resolved one - joins
    /// against the imdb_ratings snapshot at wall time.
    pub imdb: String,
    /// Top-billed cast, comma-joined.
    pub actors: String,
    /// Original release / first-air date, ISO `YYYY-MM-DD`, or empty when
    /// the provider had none. `year` is the coarse fallback.
    pub air_date: String,
}

impl Index {
    /// M13 title-metadata cache (dumb storage - TMDB lookups live in the
    /// daemon; this just remembers results, including "looked, found
    /// nothing" so a missing title is fetched once, not every poll).
    /// Insert a pending row for a parsed title if we've never seen it.
    pub fn title_seed(
        &self,
        key: &str,
        kind: &str,
        title: &str,
        year: u32,
    ) -> rusqlite::Result<()> {
        self.db.execute(
            "INSERT OR IGNORE INTO titles(key, kind, title, year) VALUES(?1, ?2, ?3, ?4)",
            rusqlite::params![key, kind, title, year],
        )?;
        Ok(())
    }

    fn title_row(r: &rusqlite::Row) -> rusqlite::Result<TitleRow> {
        Ok(TitleRow {
            key: r.get(0)?,
            kind: r.get(1)?,
            title: r.get(2)?,
            year: r.get::<_, i64>(3)? as u32,
            tmdb_id: r.get(4)?,
            overview: r.get(5)?,
            rating: r.get(6)?,
            genres: r.get(7)?,
            poster: r.get(8)?,
            backdrop: r.get(9)?,
            checked: r.get(10)?,
            imdb: r.get(11)?,
            actors: r.get(12)?,
            air_date: r.get(13)?,
        })
    }

    const TITLE_COLS: &'static str = "key, kind, title, year, tmdb_id, overview, rating, genres,
         poster, backdrop, checked, imdb, actors, air_date";

    /// All cached title rows (the wall joins them to parsed releases).
    pub fn titles(&self) -> rusqlite::Result<Vec<TitleRow>> {
        let mut stmt = self
            .db
            .prepare(&format!("SELECT {} FROM titles", Self::TITLE_COLS))?;
        let rows = stmt.query_map([], Self::title_row)?;
        rows.collect()
    }

    /// Titles never looked up (checked=0), oldest-seeded first.
    pub fn titles_pending(&self, limit: u32) -> rusqlite::Result<Vec<TitleRow>> {
        let mut stmt = self.db.prepare(&format!(
            "SELECT {} FROM titles WHERE checked=0 LIMIT ?1",
            Self::TITLE_COLS
        ))?;
        let rows = stmt.query_map([limit], Self::title_row)?;
        rows.collect()
    }

    /// Pending titles split into the enricher's lanes: one thread each,
    /// because every provider's rate limit is independent and a serial
    /// loop makes each kind queue behind the slowest one.
    pub fn titles_pending_lane(&self, limit: u32, lane: Lane) -> rusqlite::Result<Vec<TitleRow>> {
        // M28: enrich in the order the wall shows cards - newest upload
        // first (idx_rel_title_key makes the correlated MAX cheap), junk
        // groups last. Fresh titles used to queue behind the whole
        // historical backlog in rowid order, so a new post's art could
        // be hours away on a big index.
        let mut stmt = self.db.prepare(&format!(
            "SELECT {} FROM titles t WHERE checked=0 AND {} AND {VISIBLE}
             ORDER BY COALESCE((SELECT MAX(r.first_posted) FROM releases r
                                WHERE r.title_key=t.key AND r.junk < 50), 0) DESC
             LIMIT ?1",
            Self::TITLE_COLS,
            lane.sql()
        ))?;
        let rows = stmt.query_map(rusqlite::params![limit], Self::title_row)?;
        rows.collect()
    }

    /// M30: viewport-priority enrichment - the still-pending subset of
    /// `keys` (what the wall is showing right now) for one lane.
    ///
    /// Deliberately NOT filtered by `VISIBLE`, unlike the backlog query:
    /// these keys are cards the user has on screen this moment, which is
    /// the strongest possible evidence a title is wanted. A junk-scored
    /// card only reaches here when they have turned "show hidden" on and
    /// are looking straight at it - enriching that is answering a
    /// request, not spending the budget on nobody.
    pub fn titles_hot(&self, keys: &[String], lane: Lane) -> rusqlite::Result<Vec<TitleRow>> {
        let mut out = Vec::new();
        let mut stmt = self.db.prepare_cached(&format!(
            "SELECT {} FROM titles t WHERE key=?1 AND checked=0 AND {}",
            Self::TITLE_COLS,
            lane.sql()
        ))?;
        for k in keys {
            let mut rows = stmt.query_map(rusqlite::params![k], Self::title_row)?;
            if let Some(row) = rows.next() {
                out.push(row?);
            }
        }
        Ok(out)
    }

    /// M30: seed titles rows for recent, wall-visible releases that
    /// have none - the enricher only works from the titles table, and
    /// after M28 nothing seeded it except a wall page view. Called
    /// after each scan pass; newest first, bounded per call. Returns
    /// how many were seeded.
    pub fn seed_missing_titles(&self, max_age_days: u32, limit: u32) -> rusqlite::Result<u32> {
        let rows: Vec<(String, String, String)> = {
            let mut stmt = self.db.prepare_cached(
                "SELECT r.title_key, r.kind, MAX(r.stem)
                 FROM releases r
                 WHERE r.junk < 50 AND r.title_key != ''
                   AND r.kind NOT IN ('software','other','')
                   AND r.first_posted > strftime('%s','now') - ?1 * 86400
                   AND NOT EXISTS(SELECT 1 FROM titles t WHERE t.key = r.title_key)
                 GROUP BY r.title_key
                 ORDER BY MAX(r.first_posted) DESC LIMIT ?2",
            )?;

            stmt.query_map(rusqlite::params![max_age_days, limit], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })?
            .collect::<rusqlite::Result<_>>()?
        };
        let mut n = 0;
        for (key, kind, stem) in rows {
            let p = crate::release::parse_release(&stem);
            self.title_seed(&key, &kind, &p.title, p.year.unwrap_or(0))?;
            n += 1;
        }
        Ok(n)
    }

    /// M30: merge one card into another - every release under `src`
    /// re-keys to `dst`, then src's title row (and any hide) goes away.
    /// The classic fix for a parser split ("Show (Alt Title)" vs
    /// "Show") that left two cards for one series.
    pub fn merge_title(&self, src: &str, dst: &str) -> rusqlite::Result<u64> {
        if src == dst || src.is_empty() || dst.is_empty() {
            return Ok(0);
        }
        // All five statements or none. They used to autocommit one by
        // one, and the failure is unrecoverable rather than merely
        // untidy: if the releases re-key and the credit copy commit but
        // the DELETE then loses a race for the writer (a scan chunk or a
        // retention prune holding it past the 10 s busy timeout), the
        // credits exist under BOTH keys and src's titles row survives -
        // while every release has already moved to dst, so the src card
        // has vanished from the wall and nothing will ever prompt a
        // re-merge. The orphans are permanent, and they inflate the
        // visible credit counts on the destination.
        let tx = self.db.unchecked_transaction()?;
        let n = tx.execute(
            "UPDATE releases SET title_key=?2 WHERE title_key=?1",
            rusqlite::params![src, dst],
        )?;
        // Credits follow their releases. OR IGNORE because the two cards
        // may already share a person in the same role (the usual reason a
        // card split is a parser artifact of ONE title), and the
        // destination's own credit is the one to keep.
        tx.execute(
            "INSERT OR IGNORE INTO title_people(key, person_id, role, character, ord)
             SELECT ?2, person_id, role, character, ord FROM title_people WHERE key=?1",
            rusqlite::params![src, dst],
        )?;
        tx.execute("DELETE FROM title_people WHERE key=?1", [src])?;
        tx.execute("DELETE FROM titles WHERE key=?1", [src])?;
        tx.execute("DELETE FROM wall_hidden WHERE key=?1", [src])?;
        tx.commit()?;
        Ok(n as u64)
    }

    /// One title row by key (the fix/scrub endpoints read-modify-write).
    pub fn title_get(&self, key: &str) -> rusqlite::Result<Option<TitleRow>> {
        let mut stmt = self.db.prepare(&format!(
            "SELECT {} FROM titles WHERE key=?1",
            Self::TITLE_COLS
        ))?;
        let mut rows = stmt.query_map([key], Self::title_row)?;
        rows.next().transpose()
    }

    /// M31b: fetch the cached rows for a set of title_keys in one prepared
    /// pass (the taste-profile build needs genres/kind/year for a few
    /// hundred keys). Missing keys are simply absent from the map.
    pub fn titles_for_keys(
        &self,
        keys: &[String],
    ) -> rusqlite::Result<std::collections::HashMap<String, TitleRow>> {
        let mut out = std::collections::HashMap::with_capacity(keys.len());
        let mut stmt = self.db.prepare(&format!(
            "SELECT {} FROM titles WHERE key=?1",
            Self::TITLE_COLS
        ))?;
        for k in keys {
            if out.contains_key(k) {
                continue;
            }
            let mut rows = stmt.query_map([k], Self::title_row)?;
            if let Some(row) = rows.next().transpose()? {
                out.insert(k.clone(), row);
            }
        }
        Ok(out)
    }

    /// M16 wall-fix: overwrite a title's IDENTITY (kind/title/year - what
    /// lookups search under and the wall displays) without touching the
    /// cached metadata/art columns. Upserts so it also works for keys the
    /// enricher hasn't seeded yet.
    pub fn title_set_identity(
        &self,
        key: &str,
        kind: &str,
        title: &str,
        year: u32,
    ) -> rusqlite::Result<()> {
        self.db.execute(
            "INSERT INTO titles(key, kind, title, year) VALUES(?1, ?2, ?3, ?4)
             ON CONFLICT(key) DO UPDATE SET kind=?2, title=?3, year=?4",
            rusqlite::params![key, kind, title, year],
        )?;
        Ok(())
    }

    /// M16 wall-refresh: wipe a title's cached metadata and mark it
    /// pending (checked=0) so the enricher fetches it fresh. Identity and
    /// the release rows are untouched. Returns whether the row existed.
    pub fn title_reset(&self, key: &str) -> rusqlite::Result<bool> {
        let n = self.db.execute(
            "UPDATE titles SET tmdb_id=0, overview='', rating=0, genres='',
                    poster='', backdrop='', imdb='', actors='', air_date='',
                    air_tried=0, checked=0
             WHERE key=?1",
            [key],
        )?;
        Ok(n > 0)
    }

    /// M16: reset EVERY title's metadata (fresh enrichment pass over the
    /// whole wall). Returns how many rows were reset.
    pub fn titles_reset_all(&self) -> rusqlite::Result<usize> {
        self.db.execute(
            "UPDATE titles SET tmdb_id=0, overview='', rating=0, genres='',
                    poster='', backdrop='', imdb='', actors='', air_date='',
                    air_tried=0, checked=0",
            [],
        )
    }

    /// Titles the enricher already matched but has never asked for a
    /// release date - rows written before air_date existed. The backfill
    /// lane drains these when it has nothing pending, so the release-date
    /// sort becomes useful on an existing library instead of only on
    /// titles indexed from here on. tmdb_id<>0 skips the rows no provider
    /// recognised: there is no date to go and fetch for those.
    pub fn titles_missing_date(&self, limit: u32, lane: Lane) -> rusqlite::Result<Vec<TitleRow>> {
        let mut stmt = self.db.prepare(&format!(
            "SELECT {} FROM titles t
             WHERE checked > 0 AND air_tried = 0 AND air_date = ''
               AND tmdb_id <> 0 AND {} AND {VISIBLE}
             ORDER BY COALESCE((SELECT MAX(r.first_posted) FROM releases r
                                WHERE r.title_key=t.key AND r.junk < 50), 0) DESC
             LIMIT ?1",
            Self::TITLE_COLS,
            lane.sql()
        ))?;
        let rows = stmt.query_map(rusqlite::params![limit], Self::title_row)?;
        rows.collect()
    }

    /// Store a backfilled release date. An empty `date` records only that
    /// the provider was asked and had none, which is what stops the
    /// backfill lane asking about the same title on every pass.
    pub fn title_set_air_date(&self, key: &str, date: &str) -> rusqlite::Result<()> {
        self.db.execute(
            "UPDATE titles SET air_date=?2, air_tried=1 WHERE key=?1",
            rusqlite::params![key, date],
        )?;
        Ok(())
    }

    /// Record a lookup result (tmdb_id=0 ⇒ nothing found; checked stamps
    /// the attempt either way).
    pub fn title_fill(&self, key: &str, m: &TitleFill<'_>, now: i64) -> rusqlite::Result<()> {
        self.db.execute(
            "UPDATE titles SET tmdb_id=?2, overview=?3, rating=?4, genres=?5,
                    poster=?6, backdrop=?7, imdb=?8, actors=?9, air_date=?10,
                    air_tried=1, checked=?11
             WHERE key=?1",
            rusqlite::params![
                key, m.tmdb_id, m.overview, m.rating, m.genres, m.poster, m.backdrop, m.imdb,
                m.actors, m.air_date, now
            ],
        )?;
        Ok(())
    }

    // ---- cast and crew as entities -----------------------------------

    /// Resolve a credit to a `people.id`, creating or completing the row.
    ///
    /// Handles win over names, in the order a provider can be trusted: a
    /// TVmaze person id, a Wikidata Q-id and an IMDb `nm…` id each
    /// identify exactly one human, so any one of them matching IS the
    /// person. Only when a credit carries no handle at all (OMDb and
    /// TMDB give bare names) does the name decide - and then only
    /// against a row that contradicts none of what the credit knows.
    ///
    /// **Why the name fallback has to allow a cross-handle match.** The
    /// two provider handles live in disjoint id spaces: nothing TVmaze
    /// publishes about a person appears in Wikidata and vice versa, so a
    /// human seen by both arrives as a name plus a tvmaze id on one side
    /// and a name plus a qid on the other. Refusing that match forks one
    /// human into two rows, which is what
    /// `people_identity_credits_and_the_search_leg` pins against.
    ///
    /// **Why that used to fuse two different people** (finding D2): the
    /// same shape - a name plus one handle on each side - is also what
    /// two same-named strangers look like, and until both sides carried
    /// a fact in a SHARED vocabulary there was nothing to tell the cases
    /// apart. `born` is that shared fact, and it is here because it is
    /// the one both cast providers actually publish: TVmaze hands the
    /// birthday over in the cast payload itself, and Wikidata's P569
    /// rides along with P345 in one batched query.
    ///
    /// The IMDb id would have been the better join, and `imdb` is
    /// populated and matched for exactly that reason - but only Wikidata
    /// can supply it. Measured 27 Jul 2026 against the live API: TVmaze
    /// exposes no IMDb id for a person anywhere (no `externals` on the
    /// person object embedded or standalone, `/lookup/people?imdb=` is
    /// 404, and the public person page carries no IMDb link), and
    /// Wikidata has no TVmaze *person* property either - P8600 and
    /// friends are series, season, episode and character only. So `imdb`
    /// alone would have separated only people the qid already separated.
    ///
    /// Both disagreement tests are one-sided on purpose: a blank on
    /// either side never blocks a match, so a provider that gave us
    /// nothing cannot fork a person it simply failed to describe.
    ///
    /// Two residual risks, both accepted:
    ///
    /// - Two same-named people with no handles and no birth dates still
    ///   merge. That is the behaviour `titles.actors` already had (it is
    ///   a plain string of names), and unlike a wrong split it is
    ///   visible and fixable.
    /// - Two providers disagreeing on one real person's birthday split
    ///   them. Day-precision only (see `parse_person_facts`) keeps the
    ///   common "Wikidata knows only the year" case out of the
    ///   comparison entirely, which is where the disagreements were.
    pub fn person_upsert(&self, c: &Credit) -> rusqlite::Result<i64> {
        let name = c.name.trim();
        if name.is_empty() {
            return Err(rusqlite::Error::InvalidParameterName(
                "empty person name".into(),
            ));
        }
        let mut existing: Option<i64> = None;
        if c.tvmaze_id > 0 {
            existing = self
                .db
                .query_row(
                    "SELECT id FROM people WHERE tvmaze_id=?1",
                    [c.tvmaze_id],
                    |r| r.get(0),
                )
                .optional()?;
        }
        if existing.is_none() && !c.wikidata_qid.is_empty() {
            existing = self
                .db
                .query_row(
                    "SELECT id FROM people WHERE wikidata_qid=?1",
                    [&c.wikidata_qid],
                    |r| r.get(0),
                )
                .optional()?;
        }
        if existing.is_none() && !c.imdb.is_empty() {
            existing = self
                .db
                .query_row("SELECT id FROM people WHERE imdb=?1", [&c.imdb], |r| {
                    r.get(0)
                })
                .optional()?;
        }
        if existing.is_none() {
            // Name fallback, guarded by every fact both sides hold. Each
            // clause reads "one of us does not know, or we agree", so a
            // blank never blocks a match and a contradiction always
            // does.
            //
            // The two handle clauses can only ever refuse a row whose
            // SAME handle differs - a TVmaze credit says nothing about a
            // Wikidata row - which is why the name match still crosses
            // handle types, and why it used to fuse two same-named
            // people. `imdb` and `born` are the clauses that carry
            // across: both come from vocabularies a provider does not
            // own, so a Wikidata-identified row and a TVmaze-identified
            // credit finally have something to disagree about. See the
            // doc comment for why `born` does the cross-provider work
            // and `imdb` mostly does not.
            existing = self
                .db
                .query_row(
                    "SELECT id FROM people
                      WHERE name=?1 COLLATE NOCASE
                        AND (?2 = 0  OR tvmaze_id = 0     OR tvmaze_id = ?2)
                        AND (?3 = '' OR wikidata_qid = '' OR wikidata_qid = ?3)
                        AND (?4 = '' OR imdb = ''         OR imdb = ?4)
                        AND (?5 = '' OR born = ''         OR born = ?5)
                      ORDER BY id LIMIT 1",
                    rusqlite::params![name, c.tvmaze_id, c.wikidata_qid, c.imdb, c.born],
                    |r| r.get(0),
                )
                .optional()?;
        }
        let Some(id) = existing else {
            self.db.execute(
                "INSERT INTO people(name, imdb, tvmaze_id, wikidata_qid, born, photo)
                 VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![name, c.imdb, c.tvmaze_id, c.wikidata_qid, c.born, c.photo],
            )?;
            return Ok(self.db.last_insert_rowid());
        };
        // Fill blanks only. A second provider adds the handle the first
        // one lacked; it never overwrites one that is already set, or a
        // photo the user may have replaced.
        self.db.execute(
            "UPDATE people SET
                imdb         = CASE WHEN imdb=''         THEN ?2 ELSE imdb END,
                tvmaze_id    = CASE WHEN tvmaze_id=0     THEN ?3 ELSE tvmaze_id END,
                wikidata_qid = CASE WHEN wikidata_qid='' THEN ?4 ELSE wikidata_qid END,
                born         = CASE WHEN born=''         THEN ?5 ELSE born END,
                photo        = CASE WHEN photo=''        THEN ?6 ELSE photo END
              WHERE id=?1",
            rusqlite::params![id, c.imdb, c.tvmaze_id, c.wikidata_qid, c.born, c.photo],
        )?;
        Ok(id)
    }

    /// Replace one title's credits. Whole-set replacement, in one
    /// transaction: a re-enrichment that found fewer people must not
    /// leave the ones it no longer believes in behind, and a half-written
    /// cast is worse than the old one.
    pub fn title_credits_set(&self, key: &str, credits: &[Credit]) -> rusqlite::Result<()> {
        let tx = self.db.unchecked_transaction()?;
        tx.execute("DELETE FROM title_people WHERE key=?1", [key])?;
        for c in credits {
            if c.name.trim().is_empty() {
                continue;
            }
            let id = self.person_upsert(c)?;
            // OR REPLACE, not OR IGNORE: (key, person, role) is the
            // primary key, so an actor credited twice (dual role) keeps
            // the later character rather than failing the whole set.
            tx.execute(
                "INSERT OR REPLACE INTO title_people(key, person_id, role, character, ord)
                 VALUES(?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    key,
                    id,
                    if c.role.is_empty() { "actor" } else { &c.role },
                    c.character,
                    c.ord
                ],
            )?;
        }
        tx.commit()
    }

    /// One title's credits, billing order first (the detail sheet's cast
    /// chips). Crew follow the cast, since `ord` is 0 for them.
    pub fn title_credits(&self, key: &str, limit: u32) -> rusqlite::Result<Vec<PersonCredit>> {
        let mut stmt = self.db.prepare_cached(
            "SELECT p.id, p.name, p.photo, tp.role, tp.character, tp.ord
               FROM title_people tp JOIN people p ON p.id = tp.person_id
              WHERE tp.key = ?1
              ORDER BY (tp.role <> 'actor'), tp.ord, p.name
              LIMIT ?2",
        )?;
        let rows = stmt.query_map(rusqlite::params![key, limit], |r| {
            Ok(PersonCredit {
                person_id: r.get(0)?,
                name: r.get(1)?,
                photo: r.get(2)?,
                role: r.get(3)?,
                character: r.get(4)?,
                ord: r.get(5)?,
            })
        })?;
        rows.collect()
    }

    pub fn person_get(&self, id: i64) -> rusqlite::Result<Option<PersonRow>> {
        self.db
            .query_row(
                "SELECT id, name, imdb, tvmaze_id, wikidata_qid, bio, born, photo
                   FROM people WHERE id=?1",
                [id],
                |r| {
                    Ok(PersonRow {
                        id: r.get(0)?,
                        name: r.get(1)?,
                        imdb: r.get(2)?,
                        tvmaze_id: r.get(3)?,
                        wikidata_qid: r.get(4)?,
                        bio: r.get(5)?,
                        born: r.get(6)?,
                        photo: r.get(7)?,
                    })
                },
            )
            .optional()
    }

    /// The person page's "in your index" half: every title they are
    /// credited on that the wall would actually show.
    ///
    /// Curation is not optional here. A title hidden with "Not
    /// interested", or filtered out by a learned language/group rule,
    /// must stay gone on this surface too - otherwise clicking a cast
    /// member is a way to walk straight back into what the user just
    /// told us to stop showing them.
    pub fn person_titles(&self, id: i64) -> rusqlite::Result<Vec<PersonTitle>> {
        let mut wheres: Vec<String> = vec!["r.junk < 50".into()];
        let mut params: Vec<Box<dyn rusqlite::ToSql>> = vec![Box::new(id)];
        self.curation_wheres("r.", &mut wheres, &mut params)?;
        // Undated titles sort last rather than heading a date-ordered
        // list - a Wikidata film with no P577 is not "the newest".
        // GROUPed by title, not one row per credit: someone who both
        // stars in a show and produces it holds two `title_people` rows,
        // and listing their own filmography twice is a bug the join
        // produces for free. The roles collapse into one comma-joined
        // list and the character comes from the acting credit.
        let sql = format!(
            "SELECT t.key, t.kind, t.title, t.year, t.poster, t.air_date,
                    GROUP_CONCAT(DISTINCT tp.role),
                    MAX(CASE WHEN tp.role='actor' THEN tp.character ELSE '' END),
                    MIN(tp.ord),
                    (SELECT COUNT(*) FROM releases r2
                      WHERE r2.title_key = t.key AND r2.junk < 50)
               FROM title_people tp JOIN titles t ON t.key = tp.key
              WHERE tp.person_id = ?1
                AND EXISTS(SELECT 1 FROM releases r
                            WHERE r.title_key = t.key AND {})
              GROUP BY t.key
              ORDER BY (COALESCE(NULLIF(t.air_date,''),
                                 NULLIF(CAST(t.year AS TEXT),'0')) IS NULL),
                       COALESCE(NULLIF(t.air_date,''),
                                NULLIF(CAST(t.year AS TEXT),'0')) DESC,
                       t.title",
            wheres.join(" AND ")
        );
        let mut stmt = self.db.prepare(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(params.iter()), |r| {
            Ok(PersonTitle {
                key: r.get(0)?,
                kind: r.get(1)?,
                title: r.get(2)?,
                year: r.get::<_, i64>(3)? as u32,
                poster: r.get(4)?,
                air_date: r.get(5)?,
                role: r.get(6)?,
                character: r.get(7)?,
                ord: r.get(8)?,
                n_releases: r.get(9)?,
            })
        })?;
        rows.collect()
    }

    /// Name search over `people`. FTS5 prefix match so "tom cru" finds
    /// Tom Cruise mid-type; the LIKE arm keeps a non-FTS build working.
    /// Only people with at least one visible credit are returned - a
    /// crew name from a title the user has hidden is not a search hit.
    pub(super) fn people_search_once(
        &self,
        q: &str,
        limit: u32,
    ) -> rusqlite::Result<Vec<PersonHit>> {
        let q = q.trim();
        if q.is_empty() {
            return Ok(Vec::new());
        }
        let credited = "(SELECT COUNT(*) FROM title_people tp
                          WHERE tp.person_id = p.id
                            AND EXISTS(SELECT 1 FROM releases r
                                        WHERE r.title_key = tp.key AND r.junk < 50
                                          AND r.title_key NOT IN
                                              (SELECT key FROM wall_hidden)))";
        let (sql, param): (String, Box<dyn rusqlite::ToSql>) = if self.people_fts {
            // Quote every token and append * to the last: FTS5 syntax
            // characters in a user's query would otherwise be operators
            // (or a parse error that returns nothing).
            let mut toks: Vec<String> = q
                .split_whitespace()
                .map(|w| format!("\"{}\"", w.replace('"', "\"\"")))
                .collect();
            if let Some(last) = toks.last_mut() {
                last.push('*');
            }
            (
                format!(
                    "SELECT p.id, p.name, p.photo, {credited} n
                       FROM people_fts f JOIN people p ON p.id = f.rowid
                      WHERE people_fts MATCH ?1 AND n > 0
                      ORDER BY n DESC, p.name LIMIT ?2"
                ),
                Box::new(toks.join(" ")),
            )
        } else {
            (
                format!(
                    "SELECT p.id, p.name, p.photo, {credited} n
                       FROM people p
                      WHERE p.name LIKE ?1 AND n > 0
                      ORDER BY n DESC, p.name LIMIT ?2"
                ),
                Box::new(format!("%{q}%")),
            )
        };
        let mut stmt = self.db.prepare(&sql)?;
        let binds: Vec<Box<dyn rusqlite::ToSql>> = vec![param, Box::new(limit as i64)];
        let rows = stmt.query_map(rusqlite::params_from_iter(binds.iter()), |r| {
            Ok(PersonHit {
                id: r.get(0)?,
                name: r.get(1)?,
                photo: r.get(2)?,
                n_titles: r.get(3)?,
            })
        })?;
        rows.collect()
    }

    /// Title keys a set of people are credited on, curated - the search
    /// leg that turns "tom cruise" into the cards the user actually has.
    pub fn titles_for_people(&self, ids: &[i64], limit: u32) -> rusqlite::Result<Vec<String>> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let mut wheres: Vec<String> = vec!["r.junk < 50".into()];
        let mut params: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
        self.curation_wheres("r.", &mut wheres, &mut params)?;
        // ids are i64 read from our own table, so inlining them cannot
        // carry a caller string into the SQL.
        let list = ids
            .iter()
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join(",");
        params.push(Box::new(limit as i64));
        let n = params.len();
        let sql = format!(
            "SELECT tp.key FROM title_people tp
              WHERE tp.person_id IN ({list})
                AND EXISTS(SELECT 1 FROM releases r
                            WHERE r.title_key = tp.key AND {})
              GROUP BY tp.key
              ORDER BY MIN(tp.ord), tp.key LIMIT ?{n}",
            wheres.join(" AND ")
        );
        let mut stmt = self.db.prepare(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(params.iter()), |r| r.get(0))?;
        rows.collect()
    }

    /// (id, headshot URL) for people credited on a visible title, paged
    /// by id - the headshot lane's work queue.
    ///
    /// An id cursor rather than "most credited first": the caller skips
    /// the ones already on disk, and a popularity order would re-offer
    /// the same top rows on every pass and never reach the tail.
    pub fn people_photo_queue(
        &self,
        after_id: i64,
        limit: u32,
    ) -> rusqlite::Result<Vec<(i64, String)>> {
        let mut stmt = self.db.prepare_cached(
            "SELECT p.id, p.photo FROM people p
              WHERE p.id > ?1 AND p.photo LIKE 'http%'
                AND EXISTS(SELECT 1 FROM title_people tp
                            JOIN releases r ON r.title_key = tp.key
                           WHERE tp.person_id = p.id AND r.junk < 50)
              ORDER BY p.id LIMIT ?2",
        )?;
        let rows = stmt.query_map(rusqlite::params![after_id, limit], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })?;
        rows.collect()
    }

    /// Drop a headshot URL that will never work (404, not an image), so
    /// the queue stops offering it.
    pub fn person_clear_photo(&self, id: i64) -> rusqlite::Result<()> {
        self.db
            .execute("UPDATE people SET photo='' WHERE id=?1", [id])?;
        Ok(())
    }

    /// Every title key currently classified into `kind`. Used by eviction
    /// protection for a watch item that intentionally names a whole custom
    /// category (empty title): protecting only a 200-card browse page would
    /// make the rest of that category disappear under size pressure.
    pub fn title_keys_for_kind(&self, kind: &str) -> rusqlite::Result<Vec<String>> {
        let mut stmt = self.db.prepare(
            "SELECT DISTINCT title_key FROM releases
             WHERE kind=?1 AND title_key <> ''",
        )?;
        stmt.query_map([kind], |r| r.get(0))?
            .collect::<rusqlite::Result<Vec<_>>>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::testutil::{entry, teardown};

    #[test]
    fn people_identity_credits_and_the_search_leg() {
        let dir = std::env::temp_dir().join(format!("nzbfast-index-people-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut ix = Index::open(&dir.join("index.db")).unwrap();
        assert!(ix.people_fts, "bundled sqlite is expected to ship FTS5");
        let mk = |f: &str, from: &str, id: &str| {
            entry(&format!("\"{f}\" yEnc (1/1)"), from, id, 4 << 30)
        };
        ix.ingest(
            "alt.binaries.test",
            &[
                mk(
                    "Top.Gun.Maverick.2022.1080p.BluRay.x264-GRP.mkv",
                    "a@a",
                    "t1",
                ),
                mk(
                    "Mission.Impossible.1996.1080p.BluRay.x264-GRP.mkv",
                    "b@b",
                    "m1",
                ),
                mk("Breaking.Bad.S01E01.720p.WEB.x264-GRP.mkv", "c@c", "b1"),
            ],
            1_000,
        )
        .unwrap();
        let key = |s: &str| {
            ix.browse_cards(
                &BrowseQuery::default(),
                CardSort::Latest,
                false,
                false,
                None,
            )
            .unwrap()
            .0
            .into_iter()
            .find(|c| c.title_key.contains(s))
            .unwrap_or_else(|| panic!("no card for {s}"))
            .title_key
        };
        let (tg, mi, bb) = (key("maverick"), key("mission"), key("breaking"));
        for (k, kind, title, year) in [
            (&tg, "movie", "Top Gun Maverick", 2022),
            (&mi, "movie", "Mission Impossible", 1996),
            (&bb, "tv", "Breaking Bad", 0),
        ] {
            ix.title_seed(k, kind, title, year).unwrap();
            ix.title_fill(
                k,
                &TitleFill {
                    tmdb_id: 1,
                    ..Default::default()
                },
                5,
            )
            .unwrap();
        }

        // A person seen first by Wikidata and later by TVmaze is ONE
        // person: the second provider fills the handle the first lacked
        // rather than forking the row.
        let cruise_wd = Credit {
            name: "Tom Cruise".into(),
            role: "actor".into(),
            character: "Maverick".into(),
            ord: 1,
            wikidata_qid: "Q37079".into(),
            ..Default::default()
        };
        ix.title_credits_set(&tg, std::slice::from_ref(&cruise_wd))
            .unwrap();
        ix.title_credits_set(
            &mi,
            &[Credit {
                name: "Tom Cruise".into(),
                role: "actor".into(),
                character: "Ethan Hunt".into(),
                ord: 1,
                tvmaze_id: 555,
                photo: "https://example.invalid/tc.jpg".into(),
                ..Default::default()
            }],
        )
        .unwrap();
        let n_people: i64 = ix
            .db
            .query_row("SELECT COUNT(*) FROM people", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n_people, 1, "one person, two providers");
        let p = ix.people_search("tom cru", 5).unwrap();
        assert_eq!(p.len(), 1, "prefix name search: {p:?}");
        assert_eq!((p[0].name.as_str(), p[0].n_titles), ("Tom Cruise", 2));
        let pid = p[0].id;
        let row = ix.person_get(pid).unwrap().unwrap();
        assert_eq!(
            (row.tvmaze_id, row.wikidata_qid.as_str()),
            (555, "Q37079"),
            "both handles landed on the one row"
        );

        // The person page's in-index half, newest release first.
        let mine = ix.person_titles(pid).unwrap();
        assert_eq!(mine.len(), 2);
        assert_eq!(
            mine[0].title, "Top Gun Maverick",
            "ordered by release date: {mine:?}"
        );
        assert_eq!(mine[0].character, "Maverick");

        // The search leg: "tom cruise" appears in no stem at all, so
        // before this it matched nothing.
        let found = |q: &str| {
            ix.browse_cards(
                &BrowseQuery {
                    q: q.into(),
                    max_junk: Some(50),
                    curated: true,
                    ..Default::default()
                },
                CardSort::Latest,
                false,
                false,
                None,
            )
            .unwrap()
            .1
        };
        assert_eq!(found("tom cruise"), 2, "the people leg found no titles");
        // …and it is an OR, so stem search is untouched.
        assert_eq!(found("maverick"), 1);
        assert_eq!(found("nobody at all"), 0);

        // Curation is not optional on person surfaces: hiding a title
        // must remove it from the person page and from the search leg,
        // or a cast chip is a way back into what the user just hid.
        ix.hide_title(&tg).unwrap();
        assert_eq!(
            ix.person_titles(pid).unwrap().len(),
            1,
            "hidden title still listed"
        );
        assert_eq!(
            found("tom cruise"),
            1,
            "hidden title still searchable by cast"
        );
        assert_eq!(ix.people_search("tom cru", 5).unwrap()[0].n_titles, 1);
        ix.unhide_title(&tg).unwrap();

        // A DIFFERENT person who happens to share the name must not be
        // absorbed once either side carries a handle.
        ix.title_credits_set(
            &bb,
            &[Credit {
                name: "Tom Cruise".into(),
                role: "actor".into(),
                tvmaze_id: 999,
                ..Default::default()
            }],
        )
        .unwrap();
        let n_people: i64 = ix
            .db
            .query_row("SELECT COUNT(*) FROM people", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n_people, 2, "a conflicting handle forks, it does not merge");
        // They stay separate people with separate filmographies, but a
        // name search legitimately matches both - the searcher typed a
        // name, not an identity.
        assert_eq!(
            ix.person_titles(pid).unwrap().len(),
            2,
            "the fork stole a credit"
        );
        assert_eq!(found("tom cruise"), 3);

        // Re-enrichment replaces the whole set rather than accumulating
        // credits the provider no longer believes in.
        ix.title_credits_set(&tg, &[cruise_wd]).unwrap();
        assert_eq!(ix.title_credits(&tg, 40).unwrap().len(), 1);

        // A merged card keeps its credits.
        ix.merge_title(&mi, &tg).unwrap();
        assert!(ix.person_titles(pid).unwrap().iter().any(|t| t.key == tg));
        assert_eq!(
            ix.db
                .query_row(
                    "SELECT COUNT(*) FROM title_people WHERE key=?1",
                    [&mi],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
            0,
            "the merged-away key still holds credits"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn title_identity_reset_roundtrip() {
        let dir = std::env::temp_dir().join(format!("nzbfast-titles-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ix = Index::open(&dir.join("index.db")).unwrap();

        // Upsert works with no prior seed, then survives a later seed
        // attempt (INSERT OR IGNORE must not clobber the correction).
        ix.title_set_identity("m:matrix", "movie", "The Matrix", 1999)
            .unwrap();
        ix.title_seed("m:matrix", "other", "matrix", 0).unwrap();
        let t = ix.title_get("m:matrix").unwrap().unwrap();
        assert_eq!(
            (t.kind.as_str(), t.title.as_str(), t.year),
            ("movie", "The Matrix", 1999)
        );
        assert_eq!(t.checked, 0); // never looked up → pending

        // Fill, then re-scrub identity: metadata columns are preserved.
        ix.title_fill(
            "m:matrix",
            &TitleFill {
                tmdb_id: 603,
                overview: "Neo.",
                rating: 8.7,
                genres: "Sci-Fi",
                poster: "p.jpg",
                backdrop: "b.jpg",
                imdb: "tt0133093",
                actors: "Keanu",
                air_date: "1999-03-30",
            },
            111,
        )
        .unwrap();
        ix.title_set_identity("m:matrix", "movie", "The Matrix", 1998)
            .unwrap();
        let t = ix.title_get("m:matrix").unwrap().unwrap();
        assert_eq!(
            (t.year, t.tmdb_id, t.overview.as_str()),
            (1998, 603, "Neo.")
        );
        assert_eq!(t.checked, 111);
        assert_eq!(t.air_date, "1999-03-30");

        // Reset wipes metadata (incl. imdb/actors) but keeps identity,
        // and flags pending.
        assert!(ix.title_reset("m:matrix").unwrap());
        let t = ix.title_get("m:matrix").unwrap().unwrap();
        assert_eq!((t.title.as_str(), t.year), ("The Matrix", 1998));
        assert_eq!((t.tmdb_id, t.checked), (0, 0));
        assert!(t.overview.is_empty() && t.poster.is_empty());
        assert!(t.imdb.is_empty() && t.actors.is_empty() && t.air_date.is_empty());
        assert!(!ix.title_reset("nope").unwrap());

        // Reset-all counts rows and pends everything.
        ix.title_seed("t:show", "tv", "Show", 0).unwrap();
        ix.title_fill(
            "t:show",
            &TitleFill {
                tmdb_id: 7,
                overview: "x",
                rating: 1.0,
                ..Default::default()
            },
            5,
        )
        .unwrap();
        assert_eq!(ix.titles_reset_all().unwrap(), 2);
        assert_eq!(ix.titles_pending(10).unwrap().len(), 2);

        // Enricher lanes partition `titles` - every pending row must be
        // claimed by exactly one lane, or a kind silently stops being
        // enriched (which is what happened to music and books).
        ix.title_seed("o:junk", "other", "junk", 0).unwrap();
        ix.title_seed("s:app", "software", "App", 0).unwrap();
        ix.title_seed("mu:album", "music", "Artist - Album", 0)
            .unwrap();
        ix.title_seed("bk:book", "book", "Author - Book", 0)
            .unwrap();
        // Every one needs a listable release: the backlog lane only
        // considers titles the wall would show, and a titles row with no
        // releases behind it is not a state the indexer ever produces.
        for (i, key) in [
            "m:matrix", "t:show", "o:junk", "s:app", "mu:album", "bk:book",
        ]
        .iter()
        .enumerate()
        {
            ix.db
                .execute(
                    "INSERT INTO releases(stem, poster, grp, title_key, junk, first_posted)
                     VALUES(?1,'p','g',?2,0,?3)",
                    rusqlite::params![format!("rel{i}"), key, 100 - i as i64],
                )
                .unwrap();
        }
        let lane = |l: Lane| -> Vec<String> {
            ix.titles_pending_lane(10, l)
                .unwrap()
                .into_iter()
                .map(|t| t.key)
                .collect()
        };
        assert_eq!(lane(Lane::Movies), ["m:matrix"]);
        let mut media = lane(Lane::MusicBooks);
        media.sort();
        assert_eq!(media, ["bk:book", "mu:album"]);
        let shows = lane(Lane::Shows);
        assert_eq!(shows.len(), 3);
        for k in ["m:matrix", "mu:album", "bk:book"] {
            assert!(!shows.contains(&k.to_string()), "{k} is in two lanes");
        }
        // The partition must be total: no pending row belongs to none.
        let all = ix.titles_pending(10).unwrap().len();
        assert_eq!(all, lane(Lane::Movies).len() + media.len() + shows.len());
        teardown(&dir, ix);
    }

    /// Enrichment is the scarcest resource here, and 75% of it was going
    /// to titles the wall would never list. The backlog query asks for a
    /// release that passes the junk gate; the viewport query deliberately
    /// does not (see `titles_hot`).
    #[test]
    fn the_backlog_lane_skips_titles_the_wall_would_not_show() {
        let dir = std::env::temp_dir().join(format!("nzbfast-vis-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("index.db");
        let ix = Index::open(&db).unwrap();

        // Two titles, both pending: one with a listable release, one
        // whose only release is junk-gated.
        for (key, stem, junk) in [
            ("m:seen:2024", "Seen.Film.2024.1080p.BluRay.x264-GRP", 0),
            (
                "m:hidden:2024",
                "Hidden.Film.2024.1080p.BluRay.x264-GRP",
                70,
            ),
        ] {
            ix.title_seed(key, "movie", "x", 2024).unwrap();
            ix.db
                .execute(
                    "INSERT INTO releases(stem, poster, grp, title_key, kind, junk,
                                          first_posted)
                     VALUES(?1,'p','g',?2,'movie',?3,100)",
                    rusqlite::params![stem, key, junk],
                )
                .unwrap();
        }
        let pending: Vec<String> = ix
            .titles_pending_lane(10, Lane::Movies)
            .unwrap()
            .into_iter()
            .map(|t| t.key)
            .collect();
        assert_eq!(pending, ["m:seen:2024"], "a junk-only title cost a lookup");

        // Viewport priority ignores the filter: on screen means wanted.
        let hot: Vec<String> = ix
            .titles_hot(&["m:hidden:2024".to_string()], Lane::Movies)
            .unwrap()
            .into_iter()
            .map(|t| t.key)
            .collect();
        assert_eq!(
            hot,
            ["m:hidden:2024"],
            "an on-screen card must still enrich"
        );

        // Deferred, not dropped: junk is recomputed on every ingest touch
        // and a mid-upload release sheds it as parts arrive, so the title
        // must become eligible the moment it would be listed.
        ix.db
            .execute(
                "UPDATE releases SET junk=0 WHERE title_key='m:hidden:2024'",
                [],
            )
            .unwrap();
        let pending: Vec<String> = ix
            .titles_pending_lane(10, Lane::Movies)
            .unwrap()
            .into_iter()
            .map(|t| t.key)
            .collect();
        assert!(
            pending.contains(&"m:hidden:2024".to_string()),
            "a title that became visible was skipped for good: {pending:?}"
        );
        teardown(&dir, ix);
    }
}

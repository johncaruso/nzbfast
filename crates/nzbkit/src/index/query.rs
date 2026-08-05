//! Free-text search (TODO 106 phase 2.2, cut 4): the FTS MATCH builder,
//! `search`, `find_by_header`, and the imdb/tmdb/year title lookups.
//! Bodies are verbatim moves from the old index.rs; see
//! research/SEAM-TABLE-index-rs-2026-08-05.md.

use super::*;

/// FTS5 MATCH string for user query terms: each term quoted (embedded
/// quotes doubled) with a `*` prefix marker - "kill bill" → `"kill"* "bill"*`
/// (space = implicit AND). Empty when the query has no usable terms.
pub(super) fn fts_match(query: &str) -> String {
    query
        .split(|c: char| !c.is_alphanumeric())
        .filter(|t| !t.is_empty())
        .map(|t| format!("\"{}\"*", t.replace('"', "\"\"")))
        .collect::<Vec<_>>()
        .join(" ")
}

impl Index {
    /// Search by substring over the stem (case-insensitive), newest first.
    pub fn search(&self, query: &str, limit: u32) -> rusqlite::Result<Vec<Release>> {
        // Separator-insensitive, multi-term AND search: stems are stored
        // dotted ("Show.Name.S01E02") but *arr clients query with spaces
        // ("show name s01e02"), so normalize both sides to spaces and
        // require every query word to appear. Empty query = everything.
        let norm = |s: &str| {
            s.to_ascii_lowercase()
                .replace(['.', '_', '-'], " ")
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
        };
        let terms: Vec<String> = norm(query)
            .split(' ')
            .filter(|t| !t.is_empty())
            .map(String::from)
            .collect();
        // M28: FTS path - prefix-match every term against the stem index
        // instead of a triple-REPLACE full scan per request. Gate on the
        // FTS expression itself, not `terms`: a punctuation-only query
        // ("!!!") yields a non-empty `terms` but an EMPTY fts_match, and
        // `rel_fts MATCH ''` is a hard FTS5 error - fall through to the
        // LIKE scan instead (mirrors browse()).
        let m = if self.fts {
            fts_match(query)
        } else {
            String::new()
        };
        if !m.is_empty() {
            // Two indexes, one query: the stem index (what was posted)
            // and the pre-feed name index (what it was called). Without
            // the second leg a release the feed rescued is invisible to
            // every search for its real title - which is the entire
            // point of having rescued it.
            let leg = if self.pre_fts {
                "OR id IN (SELECT rowid FROM pre_fts WHERE pre_fts MATCH ?1)"
            } else {
                ""
            };
            let mut stmt = self.db.prepare(&format!(
                "SELECT {REL_COLS} FROM releases
                 WHERE id IN (SELECT rowid FROM rel_fts WHERE rel_fts MATCH ?1) {leg}
                 ORDER BY first_seen DESC LIMIT ?2"
            ))?;
            let rows = stmt.query_map(rusqlite::params![m, limit], release_from_row)?;
            return rows.collect();
        }
        // "REPLACE(REPLACE(REPLACE(LOWER(stem)…))" mirrors `norm` in SQL.
        const NS: &str = "REPLACE(REPLACE(REPLACE(LOWER(stem),'.',' '),'_',' '),'-',' ')";
        const PS: &str = "REPLACE(REPLACE(REPLACE(LOWER(pre_title),'.',' '),'_',' '),'-',' ')";
        let where_clause = if terms.is_empty() {
            "1=1".to_string()
        } else {
            // Same pairing as the FTS path above: match either the
            // posted stem or the name the feed gave it. Both chains cite
            // the same ?N, so the bind list is unchanged.
            let chain = |col: &str| {
                terms
                    .iter()
                    .enumerate()
                    .map(|(i, _)| format!("{col} LIKE '%' || ?{} || '%'", i + 1))
                    .collect::<Vec<_>>()
                    .join(" AND ")
            };
            format!("({}) OR (pre_title <> '' AND ({}))", chain(NS), chain(PS))
        };
        let sql = format!(
            "SELECT {REL_COLS} FROM releases WHERE {where_clause}
             ORDER BY first_seen DESC LIMIT ?{}",
            terms.len() + 1
        );
        let mut stmt = self.db.prepare(&sql)?;
        let mut params: Vec<&dyn rusqlite::ToSql> =
            terms.iter().map(|t| t as &dyn rusqlite::ToSql).collect();
        params.push(&limit);
        let rows = stmt.query_map(params.as_slice(), release_from_row)?;
        rows.collect()
    }

    /// Find the release an NZBLNK header names, best candidate first.
    ///
    /// An NZBLNK carries no article ids: `h` is a string distinctive
    /// enough to identify one posting in a raw-header index, which is
    /// exactly what we are. The header is usually the obfuscated release
    /// name itself, so it turns up as a release stem; on posts whose
    /// subject was scrambled per-file it turns up as a FILENAME instead.
    /// Both surfaces are tried, cheapest first:
    ///
    /// 1. `stem` equality, which `idx_rel_stem` answers outright;
    /// 2. the FTS index, verified afterwards by normalized containment
    ///    (FTS matches by token prefix, so an unverified hit would let
    ///    "abc" claim "abcdefgh");
    /// 3. `files.filename`, anchored at the start.
    ///
    /// Rung 3 is a table scan - no index covers `filename` alone - so it
    /// only ever runs when the two indexed rungs missed, and a header
    /// too short to identify anything (< 4 characters) is refused before
    /// it can pay for one.
    ///
    /// Callers get whole [`Release`] rows and decide for themselves;
    /// [`Self::make_nzb`] then emits a complete NZB from the segment
    /// ids the scan already stored.
    pub fn find_by_header(&self, header: &str, limit: u32) -> rusqlite::Result<Vec<Release>> {
        let header = header.trim();
        if header.chars().count() < 4 {
            return Ok(Vec::new());
        }
        // Same normalization `search` uses: stems are stored dotted and
        // a header may be spelled with spaces (or the other way round).
        let norm = |s: &str| {
            s.to_ascii_lowercase()
                .replace(['.', '_', '-'], " ")
                .split_whitespace()
                .collect::<Vec<_>>()
                .join(" ")
        };
        let want = norm(header);
        let mut out: Vec<Release> = Vec::new();
        let mut seen: std::collections::HashSet<i64> = std::collections::HashSet::new();
        let mut push = |rows: Vec<Release>, out: &mut Vec<Release>| {
            for r in rows {
                if seen.insert(r.id) {
                    out.push(r);
                }
            }
        };

        // Every rung below stops the ladder the moment ANYTHING answers.
        // The gates used to be `out.len() >= limit` with the caller passing
        // limit=8, and a distinctive header resolves to exactly one row, so
        // one was never eight and EVERY lookup ran every rung - on a hit as
        // well as a miss. Measured on a 16.5M-release / 17.7M-file index:
        // 1.7 s for a SUCCESSFUL resolution, 2.4 s warm and 4.3 s cold for
        // one that matches nothing, all of it holding the single shared
        // read connection that every other index reader queues behind.
        // A hit is now sub-millisecond on that same index (the indexed
        // equality alone); only a genuine miss pays for the scans.
        //
        // 1a. Exact stem, served from idx_rel_stem.
        let mut stmt = self.db.prepare(&format!(
            "SELECT {REL_COLS} FROM releases WHERE stem = ?1 LIMIT ?2"
        ))?;
        let rows: Vec<Release> = stmt
            .query_map(rusqlite::params![header, limit], release_from_row)?
            .collect::<Result<_, _>>()?;
        push(rows, &mut out);
        if !out.is_empty() {
            out.truncate(limit as usize);
            return Ok(out);
        }

        // 1b. Case-insensitively, so a board that SHOUTS the header still
        //     finds the row. Its own statement rather than a UNION ALL arm:
        //     idx_rel_stem is BINARY so this cannot use it, and inside a
        //     UNION ALL under `LIMIT 8` SQLite must evaluate it to look for
        //     the other seven even when the exact arm already matched - so
        //     the full scan ran on every hit. Now it runs only when 1a
        //     found nothing, which is the case the comment always claimed.
        let mut stmt = self.db.prepare(&format!(
            "SELECT {REL_COLS} FROM releases WHERE stem = ?1 COLLATE NOCASE LIMIT ?2"
        ))?;
        let rows: Vec<Release> = stmt
            .query_map(rusqlite::params![header, limit], release_from_row)?
            .collect::<Result<_, _>>()?;
        push(rows, &mut out);
        if !out.is_empty() {
            out.truncate(limit as usize);
            return Ok(out);
        }

        // 2. FTS (or the LIKE fallback on a database without it), then
        //    verify: only a stem that really contains the header counts.
        let m = if self.fts {
            fts_match(header)
        } else {
            String::new()
        };
        let cands: Vec<Release> = if !m.is_empty() {
            let mut stmt = self.db.prepare(&format!(
                "SELECT {REL_COLS} FROM releases
                  WHERE id IN (SELECT rowid FROM rel_fts WHERE rel_fts MATCH ?1)
                  ORDER BY first_seen DESC LIMIT ?2"
            ))?;
            stmt.query_map(rusqlite::params![m, FIND_SCAN_CAP], release_from_row)?
                .collect::<Result<_, _>>()?
        } else {
            const NS: &str = "REPLACE(REPLACE(REPLACE(LOWER(stem),'.',' '),'_',' '),'-',' ')";
            let mut stmt = self.db.prepare(&format!(
                "SELECT {REL_COLS} FROM releases WHERE {NS} LIKE '%' || ?1 || '%'
                  ORDER BY first_seen DESC LIMIT ?2"
            ))?;
            stmt.query_map(rusqlite::params![want, FIND_SCAN_CAP], release_from_row)?
                .collect::<Result<_, _>>()?
        };
        push(
            cands
                .into_iter()
                .filter(|r| norm(&r.stem).contains(&want))
                .collect(),
            &mut out,
        );
        // Same reasoning as rung 1: rung 3 is a full scan of `files`, which
        // is the bigger table, so it must run only when nothing at all has
        // answered - not merely when fewer than `limit` things have.
        if !out.is_empty() {
            out.truncate(limit as usize);
            return Ok(out);
        }

        // 3. Filenames, anchored. The header's own LIKE metacharacters
        //    are escaped - an obfuscated name is allowed to contain `_`,
        //    and unescaped that is a single-character wildcard.
        let esc = header
            .replace('\\', "\\\\")
            .replace('%', "\\%")
            .replace('_', "\\_");
        let mut stmt = self.db.prepare(&format!(
            "SELECT {REL_COLS} FROM releases WHERE id IN (
                 SELECT release_id FROM files
                  WHERE filename LIKE ?1 || '%' ESCAPE '\\' LIMIT ?2)
              ORDER BY first_seen DESC"
        ))?;
        let rows: Vec<Release> = stmt
            .query_map(rusqlite::params![esc, FIND_SCAN_CAP], release_from_row)?
            .collect::<Result<_, _>>()?;
        push(rows, &mut out);
        out.truncate(limit as usize);
        Ok(out)
    }

    /// Resolve a newznab `imdbid` to the parse-key its releases carry,
    /// so an id-based Radarr search can be answered from the enriched
    /// `titles` table instead of a title substring.
    ///
    /// Newznab carries the bare number (`imdbid=0468569`) while we store
    /// the canonical `tt`-prefixed form, and IMDb widened from 7 digits
    /// to 8 - so both the zero-padded and the as-given widths are tried.
    /// `None` means "we hold nothing for that id", which the facade must
    /// answer with an empty feed rather than an unfiltered one.
    pub fn title_key_for_imdb(&self, imdb: &str) -> rusqlite::Result<Option<String>> {
        let digits: String = imdb.chars().filter(|c| c.is_ascii_digit()).collect();
        if digits.is_empty() {
            return Ok(None);
        }
        let padded = format!("tt{digits:0>7}");
        let bare = format!("tt{digits}");
        self.db
            .query_row(
                "SELECT key FROM titles WHERE imdb=?1 OR imdb=?2 LIMIT 1",
                rusqlite::params![padded, bare],
                |r| r.get(0),
            )
            .optional()
    }

    /// Resolve a newznab `tmdbid` to its parse-key - the
    /// [`Self::title_key_for_imdb`] counterpart for the id Radarr sends
    /// when it has no IMDb id for a title.
    ///
    /// MOVIE rows only, and that is the whole point. `titles.tmdb_id`
    /// carries a TMDB movie id on a movie row and a TVmaze SHOW id on a
    /// TV row - two unrelated numbering schemes sharing one column, both
    /// small dense integers, so collisions are not a corner case but the
    /// expected state of a populated index. Unfiltered, a Radarr
    /// `t=movie&tmdbid=N` could resolve a TV series that merely happens
    /// to be TVmaze #N and answer with its episodes; with both rows
    /// present, `LIMIT 1` picked between them arbitrarily.
    ///
    /// An id we hold no MOVIE for answers None, which the caller turns
    /// into an empty feed - never a fall-through to the other namespace.
    pub fn title_key_for_tmdb(&self, tmdb: i64) -> rusqlite::Result<Option<String>> {
        if tmdb <= 0 {
            return Ok(None);
        }
        self.db
            .query_row(
                "SELECT key FROM titles WHERE tmdb_id=?1 AND kind='movie' LIMIT 1",
                rusqlite::params![tmdb],
                |r| r.get(0),
            )
            .optional()
    }

    /// The one year the index knows a movie title by - or None when it
    /// knows none, or more than one. The renamer asks this for a
    /// yearless post, and the ambiguity rule is the whole safety story:
    /// a remade title ("The Thing") has two keys with two years, and
    /// guessing between them names the file after the wrong film. Keys
    /// are `m:<norm>` (yearless parse, year filled by enrichment) and
    /// `m:<norm>:<year>`; `norm_title` output is alphanumeric+spaces,
    /// so the LIKE pattern needs no escaping.
    pub fn movie_year(&self, norm: &str) -> rusqlite::Result<Option<u32>> {
        if norm.is_empty() {
            return Ok(None);
        }
        let key = format!("m:{norm}");
        let mut stmt = self.db.prepare(
            "SELECT DISTINCT year FROM titles
              WHERE (key = ?1 OR key LIKE ?1 || ':%')
                AND kind = 'movie' AND year > 0
              LIMIT 2",
        )?;
        let years: Vec<u32> = stmt
            .query_map([&key], |r| r.get(0))?
            .collect::<Result<_, _>>()?;
        Ok(match years.as_slice() {
            [y] => Some(*y),
            _ => None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::testutil::{entry, teardown};

    /// `titles.tmdb_id` holds a TMDB movie id on a movie row and a
    /// TVmaze SHOW id on a TV row. Both namespaces are small dense
    /// integers, so a collision is the expected state of a populated
    /// index rather than a corner case - and unfiltered, a Radarr
    /// `t=movie&tmdbid=N` resolved whichever row `LIMIT 1` happened to
    /// reach and could answer a movie search with a TV series.
    #[test]
    fn a_tmdb_lookup_never_crosses_into_the_tv_namespace() {
        let dir = std::env::temp_dir().join(format!("nzbfast-index-tmdb-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ix = Index::open(&dir.join("index.db")).unwrap();
        let put = |key: &str, kind: &str, id: i64| {
            ix.db
                .execute(
                    "INSERT INTO titles(key, kind, title, year, tmdb_id)
                     VALUES(?1, ?2, ?3, 0, ?4)",
                    rusqlite::params![key, kind, "x", id],
                )
                .unwrap();
        };
        // The collision: TMDB movie 1399 and TVmaze show 1399 are
        // completely unrelated titles sharing one column.
        put("t:a series", "tv", 1399);
        put("m:a film", "movie", 1399);
        assert_eq!(
            ix.title_key_for_tmdb(1399).unwrap().as_deref(),
            Some("m:a film"),
            "the movie row is the only one a tmdbid may resolve to"
        );

        // An id we hold only a TV row for is NOT a movie we have. The
        // caller turns None into an empty feed; falling through to the
        // TV row would answer a movie search with episodes.
        put("t:another series", "tv", 82856);
        assert_eq!(ix.title_key_for_tmdb(82856).unwrap(), None);

        // A movie-only id still resolves, which is the ordinary case.
        put("m:another film", "movie", 603);
        assert_eq!(
            ix.title_key_for_tmdb(603).unwrap().as_deref(),
            Some("m:another film")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_movie_year_answers_only_when_unambiguous() {
        let dir = std::env::temp_dir().join(format!("nzbfast-index-my-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ix = Index::open(&dir.join("index.db")).unwrap();
        let put = |key: &str, kind: &str, year: u32| {
            ix.db
                .execute(
                    "INSERT INTO titles(key, kind, title, year) VALUES(?1, ?2, ?3, ?4)",
                    rusqlite::params![key, kind, "x", year],
                )
                .unwrap();
        };
        // One title, one year - via the yearless enriched key.
        put("m:example film", "movie", 2019);
        assert_eq!(ix.movie_year("example film").unwrap(), Some(2019));
        // The yeared key spelling answers too.
        put("m:other film:2007", "movie", 2007);
        assert_eq!(ix.movie_year("other film").unwrap(), Some(2007));
        // A remake means two distinct years: refuse to guess.
        put("m:the remake:1982", "movie", 1982);
        put("m:the remake:2011", "movie", 2011);
        assert_eq!(ix.movie_year("the remake").unwrap(), None);
        // Duplicate keys carrying the SAME year stay unambiguous.
        put("m:same year", "movie", 1999);
        put("m:same year:1999", "movie", 1999);
        assert_eq!(ix.movie_year("same year").unwrap(), Some(1999));
        // Unenriched (year 0) and non-movie rows say nothing.
        put("m:unchecked", "movie", 0);
        assert_eq!(ix.movie_year("unchecked").unwrap(), None);
        put("t:show title", "tv", 2020);
        assert_eq!(ix.movie_year("show title").unwrap(), None);
        // A title that PREFIXES another must not inherit its year:
        // "alien" and "aliens" share no key, and the ':'-anchored LIKE
        // keeps "m:alien" from matching "m:aliens" rows... which it
        // cannot anyway, but the guard worth pinning is the space case.
        put("m:alien nation:1988", "movie", 1988);
        assert_eq!(ix.movie_year("alien").unwrap(), None);
        assert_eq!(ix.movie_year("").unwrap(), None);
    }

    #[test]
    fn fts_search_cards_and_junk() {
        let dir = std::env::temp_dir().join(format!("nzbfast-index-m28-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut ix = Index::open(&dir.join("index.db")).unwrap();
        assert!(ix.fts, "bundled sqlite is expected to ship FTS5");

        let mk = |f: &str, from: &str, id: &str| {
            entry(&format!("\"{f}\" yEnc (1/1)"), from, id, 4 << 30)
        };
        ix.ingest(
            "alt.binaries.test",
            &[
                // Same movie from two posters → one card, two releases.
                mk("Inception.2010.1080p.BluRay.x264-GRP.mkv", "a@a", "i1"),
                mk("Inception.2010.2160p.WEB.x265-OTHER.mkv", "b@b", "i2"),
                mk("Breaking.Bad.S01E01.720p.WEB.x264-GRP.mkv", "c@c", "b1"),
                // Obfuscated hash stem → junk >= 50, hidden by default.
                mk("0a1b2c3d4e5f60718293a4b5.mkv", "d@d", "j1"),
            ],
            1_000,
        )
        .unwrap();

        // FTS prefix search, separator-insensitive both ways.
        assert_eq!(ix.search("inception", 10).unwrap().len(), 2);
        assert_eq!(ix.search("breaking bad s01", 10).unwrap().len(), 1);
        assert_eq!(ix.search("nosuchthing", 10).unwrap().len(), 0);

        // Browse with the junk ceiling: the hash stem drops out.
        let q = BrowseQuery {
            max_junk: Some(50),
            ..Default::default()
        };
        let (rows, total) = ix.browse(&q).unwrap();
        assert_eq!(total, 3, "junk hidden: {rows:?}");
        let (_, total_all) = ix.browse(&BrowseQuery::default()).unwrap();
        assert_eq!(total_all, 4);

        // Cards: inception's two posters group under one key.
        let (cards, ctotal) = ix
            .browse_cards(
                &BrowseQuery {
                    max_junk: Some(50),
                    ..Default::default()
                },
                CardSort::Latest,
                false,
                false,
                None,
            )
            .unwrap();
        assert_eq!(ctotal, 2, "cards: {cards:?}");
        let inception = cards
            .iter()
            .find(|c| c.title_key.starts_with("m:inception"))
            .unwrap();
        assert_eq!(inception.n_releases, 2);
        assert_eq!(inception.best_res, "2160p");
        assert_eq!(inception.kind, "movie");
        // Card-scoped browse (detail sheet) sees both copies.
        let (rows, n) = ix
            .browse(&BrowseQuery {
                title_key: Some(inception.title_key.clone()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!((rows.len(), n), (2, 2));

        // FTS query text is filtered per-term.
        let (_, n) = ix
            .browse(&BrowseQuery {
                q: "inception \"2010".into(),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(n, 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The NZBLNK ladder's first rung: a header the board handed out,
    /// resolved against our own scan data and turned back into an NZB.
    #[test]
    fn find_by_header_resolves_a_link_from_our_own_scan() {
        let dir = std::env::temp_dir().join(format!("nzbfast-hdr-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut ix = Index::open(&dir.join("index.db")).unwrap();

        // The common shape: the whole posting is named after the header,
        // so the header IS the release stem.
        ix.ingest(
            "alt.binaries.boneless",
            &[
                entry("\"7f3ac91e88.part01.rar\" yEnc (1/2)", "p@x", "s1", 1000),
                entry("\"7f3ac91e88.part01.rar\" yEnc (2/2)", "p@x", "s2", 1000),
                entry("\"7f3ac91e88.part02.rar\" yEnc (1/1)", "p@x", "s3", 800),
                entry("\"7f3ac91e88.par2\" yEnc (1/1)", "p@x", "s4", 200),
            ],
            1000,
        )
        .unwrap();
        // A decoy that shares the header's leading characters: an
        // unverified FTS prefix hit would hand the user this instead.
        ix.ingest(
            "alt.binaries.boneless",
            &[entry(
                "\"7f3ac91e88ff00.mkv\" yEnc (1/1)",
                "q@x",
                "d1",
                4000,
            )],
            1000,
        )
        .unwrap();

        let hits = ix.find_by_header("7f3ac91e88", 10).unwrap();
        assert_eq!(hits[0].stem, "7f3ac91e88", "exact stem must win: {hits:?}");
        assert!(hits[0].complete && hits[0].has_par2);

        // And it emits a whole NZB from the segments the scan stored.
        let nzb = ix.make_nzb(hits[0].id).unwrap();
        let parsed = crate::nzb::Nzb::parse(nzb.as_bytes()).unwrap();
        assert_eq!(parsed.files.len(), 3);
        assert_eq!(
            parsed.files.iter().map(|f| f.segments.len()).sum::<usize>(),
            4
        );

        // Case and separator spelling do not matter.
        assert_eq!(
            ix.find_by_header("7F3AC91E88", 10).unwrap()[0].stem,
            "7f3ac91e88"
        );

        // The other shape: per-file obfuscation, where the header names
        // a FILE inside a release whose stem is something else.
        ix.db
            .execute(
                "INSERT INTO releases(stem, poster, grp, files, complete, first_posted,
                                      first_seen)
                 VALUES('Die.Hard.Umlaut.German','p2@x','alt.binaries.misc',1,1,50,50)",
                [],
            )
            .unwrap();
        let rid = ix.db.last_insert_rowid();
        ix.db
            .execute(
                "INSERT INTO files(release_id, filename, total_parts, bytes, segments, nsegs)
                 VALUES(?1, 'ab_cd%ef-9911.part1.rar', 1, 500, '[[1,\"f1\",500]]', 1)",
                [rid],
            )
            .unwrap();
        // LIKE metacharacters in the header are escaped, not honoured.
        let hits = ix.find_by_header("ab_cd%ef-9911", 10).unwrap();
        assert_eq!(hits.len(), 1, "filename rung missed: {hits:?}");
        assert_eq!(hits[0].stem, "Die.Hard.Umlaut.German");
        assert!(
            ix.find_by_header("ab-cd-ef-9911", 10).unwrap().is_empty(),
            "the wildcards were live"
        );

        // Nothing to resolve, and nothing distinctive enough to try.
        assert!(
            ix.find_by_header("nosuchheaderatall", 10)
                .unwrap()
                .is_empty()
        );
        assert!(
            ix.find_by_header("7f3", 10).unwrap().is_empty(),
            "too short to identify"
        );
        teardown(&dir, ix);
    }
}

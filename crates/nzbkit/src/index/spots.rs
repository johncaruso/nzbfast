//! Spotnet rows (TODO 106 phase 2.2, cut 1): the spots table's insert,
//! search, browse and NZB-synthesis methods plus their row types. Bodies
//! are verbatim moves from the old index.rs.

use super::*;

impl Index {
    /// Insert one verified spot; `Ok(true)` if it was new, `Ok(false)` if
    /// the message-id was already indexed.
    pub fn insert_spot(&self, s: &Spot) -> rusqlite::Result<bool> {
        let n = self.db.execute(
            "INSERT INTO spots(msgid, title, category, subcats, size, date,
                               spotter_id, verified, hashcash_ok, nzb_msgids)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
             ON CONFLICT(msgid) DO NOTHING",
            rusqlite::params![
                s.msgid,
                s.title,
                s.category,
                s.subcats,
                s.size as i64,
                s.date,
                s.spotter_id,
                s.verified,
                s.hashcash_ok,
                serde_json::to_string(&s.nzb_msgids).unwrap(),
            ],
        )?;
        Ok(n > 0)
    }

    /// Search spots by title substring (case-insensitive), newest first.
    pub fn spot_search(&self, query: &str, limit: u32) -> rusqlite::Result<Vec<Spot>> {
        let mut stmt = self.db.prepare(
            "SELECT id, msgid, title, category, subcats, size, date,
                    spotter_id, verified, hashcash_ok, nzb_msgids
             FROM spots WHERE title LIKE '%' || ?1 || '%'
             ORDER BY date DESC LIMIT ?2",
        )?;
        let rows = stmt.query_map(rusqlite::params![query, limit], spot_from_row)?;
        rows.collect()
    }

    /// A Browse page of spots: newest first, with paging and a total.
    ///
    /// `include_adult` is off by default because a third of free.pt is
    /// erotica (4,884 of 15,258 spots measured on a live scan) and it
    /// would otherwise be most of what a first search returns. The
    /// marker is the `d75` subcategory, which separates cleanly - it is
    /// what the poster themselves filed the spot under.
    pub fn spot_browse(&self, q: &SpotQuery) -> rusqlite::Result<(Vec<Spot>, u64)> {
        let mut where_sql = String::from(" WHERE 1=1");
        let mut args: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
        if !q.q.trim().is_empty() {
            where_sql.push_str(" AND title LIKE '%' || ? || '%'");
            args.push(Box::new(q.q.trim().to_string()));
        }
        if let Some(c) = q.category {
            where_sql.push_str(" AND category = ?");
            args.push(Box::new(c));
        }
        if !q.include_adult {
            where_sql.push_str(&format!(
                " AND ',' || subcats || ',' NOT LIKE '%,{ADULT_SUBCAT},%'"
            ));
        }
        // Moderation records are no longer stored (nzbkit::spot::is_moderation),
        // but a database scanned before that are still full of them, and they
        // read like releases. Cheaper to exclude here than to migrate.
        where_sql.push_str(" AND title NOT LIKE 'DISPOSE %'");
        let params: Vec<&dyn rusqlite::ToSql> = args.iter().map(|b| b.as_ref()).collect();

        let total: i64 = self.db.query_row(
            &format!("SELECT COUNT(*) FROM spots{where_sql}"),
            params.as_slice(),
            |r| r.get(0),
        )?;

        let mut page = params.clone();
        let (limit, offset) = (q.limit.clamp(1, 500) as i64, q.offset as i64);
        page.push(&limit);
        page.push(&offset);
        let mut stmt = self.db.prepare(&format!(
            "SELECT id, msgid, title, category, subcats, size, date,
                    spotter_id, verified, hashcash_ok, nzb_msgids
             FROM spots{where_sql} ORDER BY date DESC, id DESC LIMIT ? OFFSET ?"
        ))?;
        let rows = stmt.query_map(page.as_slice(), spot_from_row)?;
        Ok((rows.collect::<rusqlite::Result<Vec<_>>>()?, total as u64))
    }

    pub fn spot_by_msgid(&self, msgid: &str) -> rusqlite::Result<Option<Spot>> {
        let mut stmt = self.db.prepare(
            "SELECT id, msgid, title, category, subcats, size, date,
                    spotter_id, verified, hashcash_ok, nzb_msgids
             FROM spots WHERE msgid=?1",
        )?;
        let mut rows = stmt.query_map([msgid], spot_from_row)?;
        rows.next().transpose()
    }

    /// Cache the NZB payload segment ids once a spot has been fetched.
    pub fn set_spot_nzb(&self, msgid: &str, segment_ids: &[String]) -> rusqlite::Result<()> {
        self.db.execute(
            "UPDATE spots SET nzb_msgids=?2 WHERE msgid=?1",
            rusqlite::params![msgid, serde_json::to_string(segment_ids).unwrap()],
        )?;
        Ok(())
    }

    pub fn spot_stats(&self) -> rusqlite::Result<u64> {
        self.db
            .query_row("SELECT COUNT(*) FROM spots", [], |r| r.get::<_, i64>(0))
            .map(|n| n as u64)
    }
}

/// The Spotnet subcategory a poster files erotica under. Hidden from
/// Browse unless asked for; see [`Index::spot_browse`].
pub const ADULT_SUBCAT: &str = "d75";

/// A Browse query over the spots table.
#[derive(Debug, Clone, Default)]
pub struct SpotQuery {
    pub q: String,
    /// 0-based Spotnet category: 0 video, 1 music, 2 game, 3 application.
    pub category: Option<u8>,
    pub include_adult: bool,
    pub limit: u32,
    pub offset: u32,
}

/// Does this spot carry the adult subcategory?
pub fn spot_is_adult(subcats: &str) -> bool {
    subcats.split(',').any(|s| s.trim() == ADULT_SUBCAT)
}

/// The four Spotnet categories as our own content kinds. Spotnet does not
/// separate film from television - both are category 0 - so video maps to
/// the generic kind and the title parser does the rest downstream.
pub fn spot_kind(category: u8) -> &'static str {
    match category {
        0 => "video",
        1 => "music",
        2 => "game",
        3 => "app",
        _ => "other",
    }
}

/// One ingested Spotnet spot (M14j).
#[derive(Debug, Clone)]
pub struct Spot {
    pub id: i64,
    /// With angle brackets, as seen in OVER.
    pub msgid: String,
    pub title: String,
    /// Spotnet category, 0-based: 0 video, 1 music, 2 game, 3 application.
    pub category: u8,
    /// Comma-joined subcategory runs, e.g. `a09,b04`.
    pub subcats: String,
    pub size: u64,
    /// Unix timestamp from the spot record.
    pub date: i64,
    pub spotter_id: String,
    /// RSA signature verified (always true for stored spots today).
    pub verified: bool,
    /// V2 hashcash proof-of-work passed (warning flag when false).
    pub hashcash_ok: bool,
    /// NZB payload segment ids, cached after the first fetch.
    pub nzb_msgids: Vec<String>,
}

fn spot_from_row(r: &rusqlite::Row) -> rusqlite::Result<Spot> {
    Ok(Spot {
        id: r.get(0)?,
        msgid: r.get(1)?,
        title: r.get(2)?,
        category: r.get(3)?,
        subcats: r.get(4)?,
        size: r.get::<_, i64>(5)? as u64,
        date: r.get(6)?,
        spotter_id: r.get(7)?,
        verified: r.get(8)?,
        hashcash_ok: r.get(9)?,
        nzb_msgids: serde_json::from_str(&r.get::<_, String>(10)?).unwrap_or_default(),
    })
}

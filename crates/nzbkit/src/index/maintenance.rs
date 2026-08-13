//! Database maintenance (TODO 106 phase 2.2, cut 5): pruning, split-part
//! merging, PAR2 sidecar folding, NZB synthesis, compaction/optimize and
//! the size accounting. Bodies are verbatim moves from the old index.rs.

use super::*;

/// One member row of a split-container set, as `split_merge_group`
/// reads it.
struct SplitMember {
    id: i64,
    stem: String,
    complete: bool,
    has_par2: bool,
    first_posted: i64,
    first_seen: i64,
    have_parts: i64,
    need_parts: i64,
    pre_named: bool,
}

/// One member row of a shattered posting, as `shatter_fold_group`
/// reads it.
#[derive(Clone)]
struct ShatterMember {
    id: i64,
    has_par2: bool,
    first_posted: i64,
    first_seen: i64,
    need_parts: i64,
}

/// Escape for XML - and DROP what XML 1.0 cannot carry at all.
///
/// The emitted NZB's `poster=` is the raw OVER `From:` header and
/// `subject=`/filename come from the article, so a single C0 control
/// byte makes `/getnzb/<id>.nzb` unparseable to whatever consumes it -
/// SABnzbd/expat, NZBGet/libxml2, any XML tooling. Escaping cannot help:
/// `&#1;` is illegal too, and emitting one breaks our own quick-xml
/// reader. See the twin `esc_xml` in nzbfast's serve.rs.
fn xml_escape(s: &str) -> String {
    let clean: String = s
        .chars()
        .filter(|&c| {
            matches!(c, '\t' | '\n' | '\r') || (c >= ' ' && c != '\u{FFFE}' && c != '\u{FFFF}')
        })
        .collect();
    clean
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

// ===== M32: user-chosen index size cap, with automatic eviction =====

/// §95: how this database can reclaim its freed pages. The difference
/// the caller cares about is not speed, it is whether standing down for
/// a download is prompt: a `Chunked` compaction stops between chunks and
/// keeps what it has already reclaimed, a `FullRewrite` can only be
/// asked to stop and may well refuse (see `Index::interrupt_handle`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompactStyle {
    /// Incremental auto-vacuum is on: `compact_chunk` in a loop.
    Chunked,
    /// Still in SQLite's default mode, so the only way to reclaim - and
    /// the only way to reach `Chunked` - is one full `compact()`.
    FullRewrite,
}

impl Index {
    /// Remember what a set of PAR2 member fingerprints was called, so a
    /// later repost of the same bytes under an obfuscated name can be
    /// told. `pairs` is `(hash16k hex, member name)` from
    /// [`Par2Set::member_hash16k`](crate::par2::Par2Set::member_hash16k);
    /// the member names are not stored (they are volume names, not
    /// identities) - `name` is the release the whole set belongs to.
    ///
    /// First writer wins. A fingerprint already on file was recorded
    /// when we named that release, and the later download of the same
    /// bytes has no better claim - overwriting would let one badly
    /// named repost erase the good name for every future one.
    pub fn par_hash_remember(
        &self,
        pairs: &[(String, String)],
        name: &str,
        title_key: &str,
        now: i64,
    ) -> rusqlite::Result<usize> {
        if name.trim().is_empty() {
            return Ok(0);
        }
        let mut stmt = self.db.prepare_cached(
            "INSERT INTO par_hashes(hash16k, name, title_key, at) VALUES(?1, ?2, ?3, ?4)
             ON CONFLICT(hash16k) DO NOTHING",
        )?;
        let mut n = 0;
        for (hash, _member) in pairs {
            n += stmt.execute(rusqlite::params![hash, name, title_key, now])?;
        }
        Ok(n)
    }

    /// What we last called a release carrying any of these member
    /// fingerprints. Returns `(hash16k, name, title_key)` for the first
    /// hash that is on file, in the order given - a set's volumes all
    /// belong to one release, so one hit answers for the set. The
    /// matched hash comes back with the name because it is the proving
    /// key the §131 claims layer records beside the answer.
    pub fn par_hash_lookup(
        &self,
        pairs: &[(String, String)],
    ) -> rusqlite::Result<Option<(String, String, String)>> {
        let mut stmt = self
            .db
            .prepare_cached("SELECT name, title_key FROM par_hashes WHERE hash16k = ?1")?;
        for (hash, _member) in pairs {
            let hit = stmt
                .query_row([hash], |r| {
                    Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
                })
                .optional()?;
            if let Some((name, title_key)) = hit {
                return Ok(Some((hash.clone(), name, title_key)));
            }
        }
        Ok(None)
    }

    /// One release's name, by id. `None` when there is no such row.
    /// Grabbing from the wall needs exactly this and nothing else: the
    /// stem becomes the job name, and through it the output directory,
    /// the spool file, the history label and the duplicate key.
    /// The name a release is KNOWN by - the pre feed's title when it
    /// supplied one, the posted stem otherwise. This is what names the
    /// job a grab creates, and the job name is what the duplicate hold,
    /// the watchlist's history check and the wall's "have" badge all key
    /// on, so a rescued release grabbed under its obfuscated stem would
    /// be invisible to every one of them.
    pub fn stem_by_id(&self, release_id: i64) -> rusqlite::Result<Option<String>> {
        self.db
            .query_row(
                "SELECT COALESCE(NULLIF(pre_title,''), stem) FROM releases WHERE id=?1",
                [release_id],
                |r| r.get(0),
            )
            .optional()
    }

    /// Synthesize an NZB for a release.
    pub fn make_nzb(&self, release_id: i64) -> rusqlite::Result<String> {
        let (grp, poster, posted): (String, String, i64) = self.db.query_row(
            "SELECT grp, poster, first_posted FROM releases WHERE id=?1",
            [release_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        let mut stmt = self
            .db
            .prepare("SELECT filename, total_parts, segments FROM files WHERE release_id=?1 ORDER BY filename")?;
        let mut xml = String::from(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
        );
        let rows = stmt.query_map([release_id], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, u32>(1)?,
                r.get::<_, String>(2)?,
            ))
        })?;
        for row in rows {
            let (fname, total, seg_json) = row?;
            let segs: Vec<(u32, String, u64)> = serde_json::from_str(&seg_json).unwrap_or_default();
            // date carries the release's real post time: the pool's
            // retention routing and the availability ledger's age
            // buckets both key off it (date="0" recorded every
            // index-grab as a 0-day-old post).
            xml.push_str(&format!(
                "  <file poster=\"{}\" date=\"{posted}\" subject=\"{}\">\n    <groups><group>{}</group></groups>\n    <segments>\n",
                // The stored poster may carry promote_spot's generation
                // discriminator (it lives in `poster` because the
                // UNIQUE is a table constraint); the NZB gets the real
                // From.
                xml_escape(spots::base_poster(&poster)),
                xml_escape(&format!("\"{fname}\" yEnc (1/{total})")),
                xml_escape(&grp)
            ));
            for (num, msgid, bytes) in segs {
                xml.push_str(&format!(
                    "      <segment bytes=\"{bytes}\" number=\"{num}\">{}</segment>\n",
                    xml_escape(msgid.trim_matches(['<', '>']))
                ));
            }
            xml.push_str("    </segments>\n  </file>\n");
        }
        xml.push_str("</nzb>\n");
        Ok(xml)
    }

    /// Delete releases outside [min,max] total bytes (0 = unbounded).
    /// Oversize releases can only grow, so they go immediately; undersize
    /// ones are pruned once FULLY PRESENT (every seen file has all its
    /// parts - the upload finished and it's still tiny, which is exactly
    /// what indexer spam looks like: one 1 MB .m3u/.nfo posted solo).
    /// A release still missing parts may be mid-upload, so it stays.
    /// Rare boundary miss: a release straddling two scan runs with only
    /// its smallest file landed can lose that file's rows - the next
    /// scan re-adds the rest, so the cost is one sibling file, not the
    /// release. Returns rows removed.
    pub fn prune_size(&self, min: u64, max: u64) -> rusqlite::Result<usize> {
        // One transaction: releases.id has no AUTOINCREMENT, so SQLite
        // reuses max(rowid)+1 - exactly the just-pruned oversize ids. As
        // separate autocommit statements, a crash (or the n>0 gate)
        // between delete and sweep left orphan files rows that the next
        // ingest's recycled id ADOPTED: wrong counts/complete flag, and
        // make_nzb synthesized an NZB from another release's segments.
        let tx = self.db.unchecked_transaction()?;
        let mut n = 0;
        if max > 0 {
            n += tx.execute("DELETE FROM releases WHERE total_bytes > ?1", [max as i64])?;
        }
        if min > 0 {
            n += tx.execute(
                "DELETE FROM releases WHERE total_bytes < ?1 AND NOT EXISTS (
                     SELECT 1 FROM files WHERE release_id = releases.id
                     AND json_array_length(segments) < total_parts)",
                [min as i64],
            )?;
        }
        // Unconditional: also clears orphans left by an earlier crash.
        tx.execute(
            "DELETE FROM files WHERE release_id NOT IN (SELECT id FROM releases)",
            [],
        )?;
        // Same recycled-id hazard, one table over: `pre_corr.release_id`
        // IS the primary key, so an orphaned verdict left behind here is
        // adopted whole by whatever release next takes that rowid -
        // handing a brand-new post another release's `applied`/`confirmed`
        // correlation, and with it a wrong name.
        tx.execute(
            "DELETE FROM pre_corr WHERE release_id NOT IN (SELECT id FROM releases)",
            [],
        )?;
        tx.commit()?;
        Ok(n)
    }

    pub fn stats(&self) -> rusqlite::Result<(u64, u64)> {
        self.db.query_row(
            "SELECT COUNT(*), COALESCE(SUM(complete),0) FROM releases",
            [],
            |r| Ok((r.get::<_, i64>(0)? as u64, r.get::<_, i64>(1)? as u64)),
        )
    }

    /// M31a: delete a batch of release ids and their files rows in one
    /// transaction. Files first so no orphan is left if we crash between;
    /// the `rel_fts_ad` trigger keeps FTS in sync on the releases delete.
    /// Returns rows removed from `releases`.
    pub(super) fn prune_batch(&self, ids: &[i64]) -> rusqlite::Result<usize> {
        if ids.is_empty() {
            return Ok(0);
        }
        let list = ids
            .iter()
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let tx = self.db.unchecked_transaction()?;
        tx.execute(
            &format!("DELETE FROM files WHERE release_id IN ({list})"),
            [],
        )?;
        // `pre_corr.release_id` is the primary key, and `releases.id` has
        // no AUTOINCREMENT (see `prune_size`), so a verdict left behind
        // here is inherited by the next release to reuse that rowid.
        tx.execute(
            &format!("DELETE FROM pre_corr WHERE release_id IN ({list})"),
            [],
        )?;
        let n = tx.execute(&format!("DELETE FROM releases WHERE id IN ({list})"), [])?;
        tx.commit()?;
        Ok(n)
    }

    /// Fold the fragments of a split-container set (`x.7z.001` ...)
    /// back into one release. Rows indexed before `release_stem`
    /// learned the split shapes carry one fragment each - which hides
    /// the set's true size from correlation, the wall, retention, all
    /// of it (found live 2 Aug: one obfuscated post as 122 half-GB
    /// rows). One-time and budgeted: an id-stride walk per call, kv
    /// cursor, and when the walk completes it bumps `predb_seed_gen`
    /// once so both correlation walks re-run against the real sizes.
    ///
    /// Scoped to junk>=70: those are the rows whose size is load-
    /// bearing evidence. A readable fragmented set displays fine and
    /// is left alone. Groups where any member already carries a fed
    /// name are skipped whole - identity fights are not this pass's
    /// job. Returns (groups merged, fragment rows folded, walk done).
    /// Bounded per call in TIME as well as id space, same shape as
    /// `par2_sidecar_fold`: the caller holds the shared index write
    /// mutex for the whole call, so the stride goes in sub-strides
    /// with the cursor persisted after each, and the call returns when
    /// `budget` is spent. The next tick resumes from the cursor.
    pub fn split_merge(
        &mut self,
        now: i64,
        budget: std::time::Duration,
    ) -> rusqlite::Result<(usize, usize, bool)> {
        if self.kv_get("split_merge_done_v1").is_some() {
            return Ok((0, 0, true));
        }
        const STRIDE: i64 = 100_000;
        const SUB_STRIDE: i64 = 1_000;
        let started = std::time::Instant::now();
        let mut cursor: i64 = self
            .kv_get("split_merge_cursor")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let top: i64 = self
            .db
            .query_row("SELECT COALESCE(MAX(id),0) FROM releases", [], |r| r.get(0))?;
        let call_top = cursor.saturating_add(STRIDE);
        let (mut groups, mut folded) = (0usize, 0usize);
        let mut seen_bases: std::collections::HashSet<(String, String, String)> =
            std::collections::HashSet::new();
        let done = loop {
            let hi = cursor.saturating_add(SUB_STRIDE).min(call_top);
            // Candidate fragments in this sub-stride. The LIKE
            // prefilter keeps the scan cheap; release_stem() is the
            // real test.
            let cands: Vec<(i64, String, String, String)> = {
                let mut stmt = self.db.prepare_cached(
                    "SELECT id, stem, poster, grp FROM releases
                      WHERE id>?1 AND id<=?2 AND junk>=70
                        AND (stem LIKE '%.7z.%' OR stem LIKE '%.zip.%')",
                )?;
                stmt.query_map([cursor, hi], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?))
                })?
                .collect::<rusqlite::Result<_>>()?
            };
            for (_, stem, poster, grp) in cands {
                let base = crate::extract::release_stem(&stem);
                if base == stem {
                    continue; // not a fragment shape after all
                }
                if !seen_bases.insert((base.clone(), poster.clone(), grp.clone())) {
                    continue; // this call already merged the group
                }
                let n = self.split_merge_group(&base, &poster, &grp, now)?;
                if n > 0 {
                    groups += 1;
                    folded += n;
                }
            }
            cursor = hi;
            if hi >= top {
                break true;
            }
            self.kv_set("split_merge_cursor", &cursor.to_string())?;
            if hi >= call_top || started.elapsed() >= budget {
                break false;
            }
        };
        if done {
            self.kv_set("split_merge_done_v1", "1")?;
            self.db
                .execute("DELETE FROM kv WHERE k='split_merge_cursor'", [])?;
            // The whole point: the merged rows now carry true sizes
            // worth re-correlating against.
            let g: u64 = self
                .kv_get("predb_seed_gen")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            self.kv_set("predb_seed_gen", &(g + 1).to_string())?;
        }
        Ok((groups, folded, done))
    }

    /// Merge every fragment of one (base, poster, grp) set into its
    /// lowest-id member (or the row already wearing the base stem).
    /// Returns fragment rows folded away (0 = nothing to do / skipped).
    fn split_merge_group(
        &mut self,
        base: &str,
        poster: &str,
        grp: &str,
        now: i64,
    ) -> rusqlite::Result<usize> {
        // The stem range (base||'.', base||'/') covers every fragment
        // ('.'+digits); the exact base row - already-correct rows from
        // post-fix ingest - joins via the equality arm.
        let members: Vec<SplitMember> = {
            let mut stmt = self.db.prepare_cached(
                "SELECT id, stem, complete, has_par2, first_posted, first_seen,
                        have_parts, need_parts, pre_title
                   FROM releases
                  WHERE poster=?1 AND grp=?2
                    AND (stem=?3 OR (stem>=?3||'.' AND stem<?3||'/'))",
            )?;
            stmt.query_map(rusqlite::params![poster, grp, base], |r| {
                Ok(SplitMember {
                    id: r.get(0)?,
                    stem: r.get(1)?,
                    complete: r.get(2)?,
                    has_par2: r.get(3)?,
                    first_posted: r.get(4)?,
                    first_seen: r.get(5)?,
                    have_parts: r.get(6)?,
                    need_parts: r.get(7)?,
                    pre_named: !r.get::<_, String>(8)?.is_empty(),
                })
            })?
            .collect::<rusqlite::Result<_>>()?
        };
        // Keep only true fragments of THIS base (plus the base row).
        let members: Vec<SplitMember> = members
            .into_iter()
            .filter(|m| m.stem == base || crate::extract::release_stem(&m.stem) == base)
            .collect();
        if members.len() < 2 {
            return Ok(0);
        }
        if members.iter().any(|m| m.pre_named) {
            // Somebody (feed, correlation, a human) already named a
            // member. Merging under it would silently extend that
            // claim to bytes it never covered.
            return Ok(0);
        }
        let keep = members
            .iter()
            .find(|m| m.stem == base)
            .map(|m| m.id)
            .unwrap_or_else(|| members.iter().map(|m| m.id).min().unwrap_or(0));
        let old_stem = members
            .iter()
            .find(|m| m.id == keep)
            .map(|m| m.stem.clone())
            .unwrap_or_default();
        let others: Vec<i64> = members
            .iter()
            .map(|m| m.id)
            .filter(|id| *id != keep)
            .collect();
        let list = others
            .iter()
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let tx = self.db.unchecked_transaction()?;
        // Files move to the kept row; a duplicate filename (the same
        // part posted into two fragments) keeps the kept row's copy.
        tx.execute(
            &format!("UPDATE OR IGNORE files SET release_id=?1 WHERE release_id IN ({list})"),
            [keep],
        )?;
        tx.execute(
            &format!("DELETE FROM files WHERE release_id IN ({list})"),
            [],
        )?;
        // Stale audit rows: fragment suggestions die with the
        // fragments, and the kept row's (scored against one fragment's
        // size) is wrong by construction now.
        tx.execute(
            &format!("DELETE FROM pre_corr WHERE release_id IN ({list}) OR release_id=?1"),
            [keep],
        )?;
        // §131 identity substrate: the message-id keys move WITH the
        // files. `rel_identity_ad` drops every source row's `msgid_map`
        // on the delete below, and a fold that skipped this would
        // destroy the strongest naming evidence the index holds - the
        // articles are still in the kept release, so a later posted-NZB
        // or spot lookup must still resolve them (and still reach
        // quorum) rather than miss a release that visibly survived.
        // OR IGNORE: the kept row may already hold the same key.
        tx.execute(
            &format!("UPDATE OR IGNORE msgid_map SET release_id=?1 WHERE release_id IN ({list})"),
            [keep],
        )?;
        tx.execute(&format!("DELETE FROM releases WHERE id IN ({list})"), [])?;
        let (total, nfiles, nexe): (i64, i64, i64) = tx.query_row(
            &format!(
                "SELECT COALESCE(SUM(bytes),0), COUNT(*),
                        COALESCE(SUM({EXE_FILE_SQL}),0)
                   FROM files WHERE release_id=?1"
            ),
            [keep],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        let fp = members
            .iter()
            .map(|m| m.first_posted)
            .filter(|v| *v > 0)
            .min()
            .unwrap_or(0);
        let fs = members.iter().map(|m| m.first_seen).min().unwrap_or(now);
        let complete = members.iter().all(|m| m.complete);
        let has_par2 = members.iter().any(|m| m.has_par2);
        let have: i64 = members.iter().map(|m| m.have_parts).sum();
        let need: i64 = members.iter().map(|m| m.need_parts).sum();
        let p = crate::categories::classify(base, &self.custom);
        tx.execute(
            "UPDATE releases
                SET stem=?2, total_bytes=?3, files=?4, complete=?5, has_par2=?6,
                    first_posted=?7, first_seen=?8, have_parts=?9, need_parts=?10,
                    kind=?11, res=?12, title_key=?13, junk=?14, langs=?15,
                    vcodec=?16, acodec=?17, hdr=?18
              WHERE id=?1",
            rusqlite::params![
                keep,
                base,
                total,
                nfiles,
                complete,
                has_par2,
                fp,
                fs,
                have,
                need,
                kind_str(&p.kind),
                p.res.as_deref().unwrap_or_default(),
                p.key,
                junk_score(base, &p, total.max(0) as u64, nexe > 0),
                p.langs.join(" "),
                p.vcodec.as_deref().unwrap_or_default(),
                p.acodec.as_deref().unwrap_or_default(),
                p.hdr.as_deref().unwrap_or_default()
            ],
        )?;
        // rel_fts has no UPDATE trigger (external-content over stems),
        // so the stem rewrite maintains it by hand. The fragment
        // deletions above were covered by rel_fts_ad.
        if self.fts && old_stem != base {
            tx.execute(
                "INSERT INTO rel_fts(rel_fts, rowid, stem) VALUES('delete', ?1, ?2)",
                rusqlite::params![keep, old_stem],
            )?;
            tx.execute(
                "INSERT INTO rel_fts(rowid, stem) VALUES(?1, ?2)",
                rusqlite::params![keep, base],
            )?;
        }
        tx.commit()?;
        Ok(others.len())
    }

    /// Fold a split-container set's par2 SIDECAR row into its
    /// container release. The posting habit behind it: the volumes go
    /// up as `x.7z.001`..`x.7z.121` and the recovery set as `x.par2` +
    /// `x.volNN+MM.par2`, so ingest builds TWO rows - the container on
    /// `x.7z` and a par2-only twin on the bare `x`. Measured against
    /// a 30M-row live index, this is the norm, not an edge case:
    /// 9,261 of 10,490 container rows (88%)
    /// have such a twin - 77,977 files, 4,289 GiB of spurious rows.
    /// Folding also closes a scoring leak: with its par2 in a separate
    /// row the container reads `par2_identified=false`, which opens
    /// the 22-point hidden-par2 size band for bytes that provably
    /// contain no hidden par2.
    ///
    /// The join is exact and narrow: same poster and group, twin stem
    /// equals the container stem minus its `.7z`/`.zip`, twin carries
    /// nothing but par2 files (sampled 400 of the 9,261: all pure).
    ///
    /// Unlike `split_merge` this walk can never finish for good -
    /// ingest keeps producing new pairs, because a par2 filename gives
    /// `release_stem` no way to see the `.7z` it belongs to. So the
    /// cursor parks at the top id and follows it, and each stride
    /// looks BOTH ways (a container in the stride, or a twin in the
    /// stride whose container an earlier stride already passed), so a
    /// pair folds no matter which row the walk meets first. It waits
    /// for `split_merge` to complete so the containers exist to fold
    /// into, and the first full lap bumps `predb_seed_gen` once: the
    /// folded rows carry different sizes and a true `has_par2`, worth
    /// re-correlating. Returns (pairs folded, par2 files moved, walk
    /// caught up with the top id).
    ///
    /// Bounded per call in TIME as well as id space. The caller holds
    /// the shared index write mutex for the whole call, and the twin
    /// probes make each row cost two index lookups - measured on a
    /// large live index, one 100k stride ran for tens of seconds with
    /// every other index user (ingest, the API, a starting download)
    /// parked behind it. So the walk goes in sub-strides, persisting
    /// the cursor after each, and returns when `budget` is spent; the
    /// next tick resumes where this one stopped.
    pub fn par2_sidecar_fold(
        &mut self,
        budget: std::time::Duration,
    ) -> rusqlite::Result<(usize, usize, bool)> {
        if self.kv_get("split_merge_done_v1").is_none() {
            // Containers are partly split_merge's output; walking ids
            // it has not folded yet would pass pairs it later creates.
            return Ok((0, 0, false));
        }
        const STRIDE: i64 = 100_000;
        const SUB_STRIDE: i64 = 1_000;
        let started = std::time::Instant::now();
        let top: i64 = self
            .db
            .query_row("SELECT COALESCE(MAX(id),0) FROM releases", [], |r| r.get(0))?;
        let mut cursor: i64 = self
            .kv_get("par2_fold_cursor")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        // A cursor ABOVE the top id means the fold itself deleted the
        // row it parked on (folding removes the bare twin release, and
        // that twin can be the maximum). releases.id has no
        // AUTOINCREMENT, so the next insert reuses exactly that id -
        // and a strictly-greater scan would then never visit the
        // recreated row while every later insert passed it by (Codex
        // sweep 3 Aug M3). Rewind to the surviving top; the pair logic
        // is idempotent, so re-walking a fringe of ids is only cheap
        // re-reads.
        if cursor > top {
            cursor = top;
            self.kv_set("par2_fold_cursor", &cursor.to_string())?;
        }
        if cursor >= top {
            return Ok((0, 0, true));
        }
        let call_top = cursor.saturating_add(STRIDE).min(top);
        let (mut pairs, mut moved) = (0usize, 0usize);
        let mut reached_top = false;
        loop {
            let hi = cursor.saturating_add(SUB_STRIDE).min(call_top);
            // Either half of a pair makes a row a candidate. The
            // twin-side EXISTS probes are point lookups on the
            // (stem, poster, grp) unique index, so the sub-stride
            // stays cheap.
            let cands: Vec<(String, String, String)> = {
                let mut stmt = self.db.prepare_cached(
                    "SELECT stem, poster, grp FROM releases AS t
                      WHERE t.id>?1 AND t.id<=?2 AND t.junk>=70
                        AND (t.stem LIKE '%.7z' OR t.stem LIKE '%.zip'
                             OR EXISTS(SELECT 1 FROM releases c
                                        WHERE c.stem IN (t.stem||'.7z', t.stem||'.zip')
                                          AND c.poster=t.poster AND c.grp=t.grp
                                          AND c.junk>=70))",
                )?;
                stmt.query_map([cursor, hi], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                    .collect::<rusqlite::Result<_>>()?
            };
            for (stem, poster, grp) in cands {
                let containers: Vec<String> = if stem.ends_with(".7z") || stem.ends_with(".zip") {
                    vec![stem]
                } else {
                    // Twin side: its container wears one of the two exts.
                    vec![format!("{stem}.7z"), format!("{stem}.zip")]
                };
                for cstem in &containers {
                    let n = self.par2_sidecar_fold_pair(cstem, &poster, &grp)?;
                    if n > 0 {
                        pairs += 1;
                        moved += n;
                        break;
                    }
                }
            }
            // Clamped to the max id that SURVIVED this sub-stride:
            // folding deletes bare twin rows, and if one of them was
            // the table maximum, parking the cursor on its id would let
            // SQLite hand the same id to the next insert - a row a
            // strictly-greater scan then never visits (Codex sweep
            // 3 Aug M3). The head-side rewind above only helps when the
            // recreation happens AFTER the next fold call; this clamp
            // closes the delete-and-recreate-between-folds
            // interleaving too.
            let survived: i64 =
                self.db
                    .query_row("SELECT COALESCE(MAX(id),0) FROM releases", [], |r| r.get(0))?;
            cursor = hi.min(survived);
            self.kv_set("par2_fold_cursor", &cursor.to_string())?;
            if hi >= top {
                reached_top = true;
                break;
            }
            if hi >= call_top || started.elapsed() >= budget {
                break;
            }
        }
        let done = reached_top;
        if done && self.kv_get("par2_fold_lap_v1").is_none() {
            self.kv_set("par2_fold_lap_v1", "1")?;
            // The backlog lap is what moves thousands of sizes at
            // once; later steady-state folds ride the live legs.
            let g: u64 = self
                .kv_get("predb_seed_gen")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            self.kv_set("predb_seed_gen", &(g + 1).to_string())?;
        }
        Ok((pairs, moved, done))
    }

    /// Fold one container's par2 twin, if it has one. Returns the par2
    /// files moved in (0 = no twin, twin not purely par2, or a fed
    /// name froze the pair).
    fn par2_sidecar_fold_pair(
        &mut self,
        cstem: &str,
        poster: &str,
        grp: &str,
    ) -> rusqlite::Result<usize> {
        let Some(base) = cstem
            .strip_suffix(".7z")
            .or_else(|| cstem.strip_suffix(".zip"))
            .filter(|b| !b.is_empty())
        else {
            return Ok(0);
        };
        let read = |db: &rusqlite::Connection,
                    sql: &str,
                    stem: &str|
         -> rusqlite::Result<Option<SplitMember>> {
            db.prepare_cached(sql)?
                .query_row(rusqlite::params![stem, poster, grp], |r| {
                    Ok(SplitMember {
                        id: r.get(0)?,
                        stem: r.get(1)?,
                        complete: r.get(2)?,
                        has_par2: r.get(3)?,
                        first_posted: r.get(4)?,
                        first_seen: r.get(5)?,
                        have_parts: r.get(6)?,
                        need_parts: r.get(7)?,
                        pre_named: !r.get::<_, String>(8)?.is_empty(),
                    })
                })
                .optional()
        };
        const COLS: &str = "SELECT id, stem, complete, has_par2, first_posted, first_seen,
                        have_parts, need_parts, pre_title
                   FROM releases";
        // The junk>=70 scope rides on the CONTAINER: those are the
        // obfuscated rows whose size is load-bearing correlation
        // evidence. (The twin-side arm of the walk already required
        // it; rechecking here keeps both arms identical.)
        let Some(cont) = read(
            &self.db,
            &format!("{COLS} WHERE stem=?1 AND poster=?2 AND grp=?3 AND junk>=70"),
            cstem,
        )?
        else {
            return Ok(0);
        };
        let Some(twin) = read(
            &self.db,
            &format!("{COLS} WHERE stem=?1 AND poster=?2 AND grp=?3"),
            base,
        )?
        else {
            return Ok(0);
        };
        if cont.pre_named || twin.pre_named {
            // Somebody (feed, correlation, a human) named a half.
            // Merging under it would silently extend that claim to
            // bytes it never covered.
            return Ok(0);
        }
        // The twin must be NOTHING but par2. One content file means it
        // is a genuine release that happens to share the base name.
        let (tfiles, nonpar2): (i64, i64) = self.db.query_row(
            "SELECT COUNT(*), COALESCE(SUM(LOWER(filename) NOT LIKE '%.par2'),0)
               FROM files WHERE release_id=?1",
            [twin.id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        if tfiles == 0 || nonpar2 > 0 {
            return Ok(0);
        }
        let tx = self.db.unchecked_transaction()?;
        // Files move to the container; a duplicate filename keeps the
        // container's copy.
        tx.execute(
            "UPDATE OR IGNORE files SET release_id=?1 WHERE release_id=?2",
            [cont.id, twin.id],
        )?;
        tx.execute("DELETE FROM files WHERE release_id=?1", [twin.id])?;
        // Stale audit rows: the twin's suggestions die with it, and
        // the container's were scored against a size and a
        // par2_identified flag that are both wrong now.
        tx.execute(
            "DELETE FROM pre_corr WHERE release_id IN (?1, ?2)",
            [cont.id, twin.id],
        )?;
        // The twin's message-id keys move with its par2 files, for the
        // reason spelled out in `split_merge_group`: `rel_identity_ad`
        // would otherwise drop them on the delete below and the fold
        // would erase identity for articles that are still indexed.
        tx.execute(
            "UPDATE OR IGNORE msgid_map SET release_id=?1 WHERE release_id=?2",
            [cont.id, twin.id],
        )?;
        // rel_fts_ad covers this deletion; the kept stem is untouched,
        // so no manual FTS maintenance this time.
        tx.execute("DELETE FROM releases WHERE id=?1", [twin.id])?;
        let (total, nfiles, nexe): (i64, i64, i64) = tx.query_row(
            &format!(
                "SELECT COALESCE(SUM(bytes),0), COUNT(*),
                        COALESCE(SUM({EXE_FILE_SQL}),0)
                   FROM files WHERE release_id=?1"
            ),
            [cont.id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )?;
        let fp = [cont.first_posted, twin.first_posted]
            .into_iter()
            .filter(|v| *v > 0)
            .min()
            .unwrap_or(0);
        let p = crate::categories::classify(cstem, &self.custom);
        tx.execute(
            "UPDATE releases
                SET total_bytes=?2, files=?3, complete=?4, has_par2=1,
                    first_posted=?5, first_seen=?6, have_parts=?7, need_parts=?8,
                    junk=?9
              WHERE id=?1",
            rusqlite::params![
                cont.id,
                total,
                nfiles,
                cont.complete && twin.complete,
                fp,
                cont.first_seen.min(twin.first_seen),
                cont.have_parts + twin.have_parts,
                cont.need_parts + twin.need_parts,
                junk_score(cstem, &p, total.max(0) as u64, nexe > 0),
            ],
        )?;
        tx.commit()?;
        Ok(tfiles as usize)
    }

    /// Fold releases SHATTERED by per-article poster randomization.
    ///
    /// The dominant obfuscated-poster family posts one file under a
    /// stable blob subject name while randomizing the From on every
    /// article (and rotating the group per article on top). The
    /// cluster key is (stem, poster, grp), so a 562-part file lands as
    /// up to 562 one-segment release rows, each holding one article
    /// and the true `need_parts`. Measured on a 20.5M-row live index,
    /// 13 Aug 2026: ~19.9M dark rows are ~1.08M such postings - 97% of
    /// all dark rows. The fold key is therefore the STEM ALONE, across
    /// posters AND groups.
    ///
    /// The gates keep it narrow: every member must be dark
    /// (`junk>=70`, unnamed, and the stem fails
    /// `release::stem_is_a_name` - the ONE shared verdict), a
    /// single-file row, carry a real subject part total, and agree on
    /// that total; the stem must be at least [`SHATTER_MIN_STEM`]
    /// chars so a generic readable-ish token ("1917", "Subs") can
    /// never bridge two posters' unrelated files. Members' one-file
    /// segment lists are UNIONED by part number (all rows share the
    /// filename, so repointing rows would silently drop segments).
    ///
    /// Like `par2_sidecar_fold` this can never finish for good -
    /// ingest keeps shattering new postings - so the cursor parks at
    /// the top id and follows it. Bounded per call in time and id
    /// space; the caller holds the index write mutex throughout.
    /// Returns (postings folded, rows folded away, caught up).
    pub fn shatter_fold(
        &mut self,
        now: i64,
        budget: std::time::Duration,
    ) -> rusqlite::Result<(usize, usize, bool)> {
        const STRIDE: i64 = 100_000;
        const SUB_STRIDE: i64 = 1_000;
        let started = std::time::Instant::now();
        let top: i64 = self
            .db
            .query_row("SELECT COALESCE(MAX(id),0) FROM releases", [], |r| r.get(0))?;
        let mut cursor: i64 = self
            .kv_get("shatter_fold_cursor")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        // Same id-reuse hazard as `par2_sidecar_fold`: the fold deletes
        // rows, releases.id has no AUTOINCREMENT, and a cursor parked
        // above the surviving maximum would never visit a recreated id.
        if cursor > top {
            cursor = top;
            self.kv_set("shatter_fold_cursor", &cursor.to_string())?;
        }
        if cursor >= top {
            return Ok((0, 0, true));
        }
        let call_top = cursor.saturating_add(STRIDE).min(top);
        let (mut groups, mut folded) = (0usize, 0usize);
        let mut reached_top = false;
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        loop {
            let hi = cursor.saturating_add(SUB_STRIDE).min(call_top);
            // Cheap SQL prefilter; `stem_is_a_name` is the real test
            // and runs on the Rust side. files=1 is the shattered
            // shape (one file row holding one segment).
            let cands: Vec<String> = {
                let mut stmt = self.db.prepare_cached(
                    "SELECT DISTINCT stem FROM releases
                      WHERE id>?1 AND id<=?2 AND junk>=70 AND pre_title=''
                        AND files=1 AND need_parts>0
                        AND LENGTH(stem) >= 16",
                )?;
                stmt.query_map([cursor, hi], |r| r.get(0))?
                    .collect::<rusqlite::Result<_>>()?
            };
            for stem in cands {
                if crate::release::stem_is_a_name(&stem) || !seen.insert(stem.clone()) {
                    continue;
                }
                let (g, n) = self.shatter_fold_stem(&stem, now)?;
                groups += g;
                folded += n;
            }
            // Clamp to the surviving maximum for the same
            // delete-and-recreate interleaving `par2_sidecar_fold`
            // guards against.
            let survived: i64 =
                self.db
                    .query_row("SELECT COALESCE(MAX(id),0) FROM releases", [], |r| r.get(0))?;
            cursor = hi.min(survived);
            self.kv_set("shatter_fold_cursor", &cursor.to_string())?;
            if hi >= top {
                reached_top = true;
                break;
            }
            if hi >= call_top || started.elapsed() >= budget {
                break;
            }
        }
        let done = reached_top;
        if done && self.kv_get("shatter_fold_lap_v1").is_none() {
            self.kv_set("shatter_fold_lap_v1", "1")?;
            // The folded rows are the first time this band has real
            // sizes and times - exactly what the correlation walks
            // score on. Re-open them once.
            let g: u64 = self
                .kv_get("predb_seed_gen")
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            self.kv_set("predb_seed_gen", &(g + 1).to_string())?;
        }
        Ok((groups, folded, done))
    }

    /// Fold every posting sharing `stem`, ONE FILENAME AT A TIME.
    ///
    /// `release_stem` deliberately reduces `x.part01.rar`,
    /// `x.part02.rar`, `x.vol000+01.par2` … to the same `x`: that is
    /// what makes a set one release. The shattered dark band posts a
    /// single file per stem, but an obfuscated multi-volume set does
    /// not, and those volumes are DISTINCT files with their own
    /// part-number universes. Folding them together would union two
    /// unrelated `(1/2)`/`(2/2)` pairs under whichever filename sorted
    /// first and delete the rest of the set - the same garbage-union
    /// hazard the part-total class gate exists to stop, one level up.
    /// So the filename is part of the fold key.
    ///
    /// Returns (postings folded, rows folded away).
    fn shatter_fold_stem(&mut self, stem: &str, now: i64) -> rusqlite::Result<(usize, usize)> {
        let names: Vec<String> = {
            let mut stmt = self.db.prepare_cached(
                "SELECT DISTINCT f.filename
                   FROM releases r JOIN files f ON f.release_id=r.id
                  WHERE r.stem=?1 AND r.junk>=70 AND r.pre_title=''
                    AND r.files=1 AND r.need_parts>0",
            )?;
            stmt.query_map([stem], |r| r.get(0))?
                .collect::<rusqlite::Result<_>>()?
        };
        let (mut groups, mut folded) = (0usize, 0usize);
        for name in names {
            let n = self.shatter_fold_group(stem, &name, now)?;
            if n > 0 {
                groups += 1;
                folded += n;
            }
        }
        Ok((groups, folded))
    }

    /// Fold every dark single-file row wearing `stem` and holding
    /// `fname` - across posters and groups - into the lowest-id
    /// member, unioning their segment lists by part number. Returns
    /// rows folded away (0 = nothing to do or the group failed a
    /// gate).
    fn shatter_fold_group(&mut self, stem: &str, fname: &str, now: i64) -> rusqlite::Result<usize> {
        // Hard cap keeps the id list bounded. A posting bigger than
        // the cap folds over successive PASSES of this same call (see
        // the loop below): the cursor parks at the top id once the lap
        // completes, so "it folds on a later lap" was never true for a
        // posting that has stopped arriving.
        const MEMBER_CAP: usize = 20_000;
        let mut folded = 0usize;
        loop {
            let members: Vec<ShatterMember> = {
                let mut stmt = self.db.prepare_cached(
                    "SELECT r.id, r.has_par2, r.first_posted, r.first_seen, r.need_parts
                       FROM releases r JOIN files f ON f.release_id=r.id
                      WHERE r.stem=?1 AND r.junk>=70 AND r.pre_title=''
                        AND r.files=1 AND r.need_parts>0 AND f.filename=?2
                      ORDER BY r.id LIMIT ?3",
                )?;
                stmt.query_map(rusqlite::params![stem, fname, MEMBER_CAP as i64], |r| {
                    Ok(ShatterMember {
                        id: r.get(0)?,
                        has_par2: r.get(1)?,
                        first_posted: r.get(2)?,
                        first_seen: r.get(3)?,
                        need_parts: r.get(4)?,
                    })
                })?
                .collect::<rusqlite::Result<_>>()?
            };
            let capped = members.len() >= MEMBER_CAP;
            let n = self.shatter_fold_members(stem, fname, members, now)?;
            folded += n;
            // Another cap's worth may be waiting behind this one. Stop
            // when the batch came in under the cap, or when a capped
            // batch made no progress (a gate refused it - looping
            // would spin).
            if !capped || n == 0 {
                return Ok(folded);
            }
        }
    }

    /// One capped batch of `shatter_fold_group`'s members.
    fn shatter_fold_members(
        &mut self,
        stem: &str,
        fname: &str,
        members: Vec<ShatterMember>,
        now: i64,
    ) -> rusqlite::Result<usize> {
        type Member = ShatterMember;
        // The subject's "(x/y)" total is per-posting truth: members of
        // one posting agree on it. Fold only the largest agreeing
        // class - a disagreeing minority is a different posting that
        // happens to reuse the stem, and unioning two part universes
        // is the exact garbage-download hazard the ingest D3 backstop
        // exists to stop.
        let mut by_total: std::collections::HashMap<i64, Vec<Member>> = Default::default();
        for m in members {
            by_total.entry(m.need_parts).or_default().push(m);
        }
        let Some(class) = by_total
            .into_values()
            .max_by_key(|v| (v.len(), v.first().map(|m| -m.id).unwrap_or(0)))
        else {
            return Ok(0);
        };
        if class.len() < 2 {
            return Ok(0);
        }
        let need = class[0].need_parts;
        let keep = class.iter().map(|m| m.id).min().unwrap_or(0);
        let others: Vec<i64> = class
            .iter()
            .map(|m| m.id)
            .filter(|id| *id != keep)
            .collect();
        // Union the one-file segment lists, keep's copy winning per
        // part, then ascending id order - deterministic under replay.
        let mut merged: std::collections::BTreeMap<u32, (String, u64)> = Default::default();
        let mut total_parts: i64 = 0;
        {
            // Every member holds `fname` - that is the fold key - so
            // the union needs no filename reconciliation.
            let mut stmt = self.db.prepare_cached(
                "SELECT total_parts, segments FROM files
                  WHERE release_id=?1 AND filename=?2",
            )?;
            let mut ids = vec![keep];
            ids.extend(&others);
            for id in ids {
                let Some((tp, segs)) = stmt
                    .query_row(rusqlite::params![id, fname], |r| {
                        Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))
                    })
                    .optional()?
                else {
                    continue;
                };
                total_parts = total_parts.max(tp);
                if let Ok(v) = serde_json::from_str::<Vec<(u32, String, u64)>>(&segs) {
                    for (n, id, b) in v {
                        merged.entry(n).or_insert((id, b));
                    }
                }
            }
        }
        if merged.is_empty() {
            return Ok(0);
        }
        let bytes: u64 = merged.values().map(|v| v.1).sum();
        let seg_json = serde_json::to_string(
            &merged
                .iter()
                .map(|(n, (id, b))| (*n, id.clone(), *b))
                .collect::<Vec<_>>(),
        )
        .unwrap();
        let nsegs = merged.len() as i64;
        let list = others
            .iter()
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let tx = self.db.unchecked_transaction()?;
        // Merge the pesto counter range BEFORE the source rows die -
        // aggregate MIN/MAX ignore NULLs, matching ingest's monotonic
        // merge rule.
        #[allow(clippy::type_complexity)]
        let (pmin, pmax, pck, sidx, stot): (
            Option<i64>,
            Option<i64>,
            Option<i64>,
            Option<i64>,
            Option<i64>,
        ) = tx.query_row(
            &format!(
                "SELECT MIN(pesto_ctr_min), MAX(pesto_ctr_max), MIN(pesto_clock),
                        MAX(sess_idx), MAX(sess_total)
                   FROM releases WHERE id IN ({list}) OR id=?1"
            ),
            [keep],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )?;
        // All members share the filename, so the source files rows are
        // consumed by the in-memory union above, not repointed.
        tx.execute(
            &format!("DELETE FROM files WHERE release_id IN ({list})"),
            [],
        )?;
        tx.execute(
            "UPDATE files SET total_parts=?2, bytes=?3, segments=?4, nsegs=?5
              WHERE release_id=?1 AND filename=?6",
            rusqlite::params![
                keep,
                total_parts.max(need),
                bytes as i64,
                seg_json,
                nsegs,
                fname
            ],
        )?;
        // Stale audit rows: fragment suggestions die with the rows,
        // and the kept row's were scored against one article's size.
        tx.execute(
            &format!("DELETE FROM pre_corr WHERE release_id IN ({list}) OR release_id=?1"),
            [keep],
        )?;
        // The message-id keys move WITH the articles (see
        // `split_merge_group` for why losing them would erase the
        // strongest naming evidence the index holds).
        tx.execute(
            &format!("UPDATE OR IGNORE msgid_map SET release_id=?1 WHERE release_id IN ({list})"),
            [keep],
        )?;
        tx.execute(&format!("DELETE FROM releases WHERE id IN ({list})"), [])?;
        let fp = class
            .iter()
            .map(|m| m.first_posted)
            .filter(|v| *v > 0)
            .min()
            .unwrap_or(0);
        let fs = class.iter().map(|m| m.first_seen).min().unwrap_or(now);
        let has_par2 = class.iter().any(|m| m.has_par2);
        let p = crate::categories::classify(stem, &self.custom);
        tx.execute(
            "UPDATE releases
                SET total_bytes=?2, files=1, complete=?3, has_par2=?4,
                    first_posted=?5, first_seen=?6, have_parts=?7, need_parts=?8,
                    junk=?9,
                    pesto_ctr_min=?10, pesto_ctr_max=?11, pesto_clock=?12,
                    sess_idx=?13, sess_total=?14
              WHERE id=?1",
            rusqlite::params![
                keep,
                bytes as i64,
                nsegs >= need,
                has_par2,
                fp,
                fs,
                nsegs,
                need,
                junk_score(stem, &p, bytes, false),
                pmin,
                pmax,
                pck,
                sidx,
                stot,
            ],
        )?;
        // The stem is unchanged, so rel_fts needs no manual write; the
        // row deletions above are covered by rel_fts_ad.
        tx.commit()?;
        Ok(others.len())
    }

    /// M31a: age-based retention. Deletes releases older than the window,
    /// EXCEPT unknown-date rows (`first_posted` 0, whose OVER Date failed
    /// to parse) and titles the user has hidden (the Hidden panel must
    /// keep showing them). Chunked so a big first prune never holds the
    /// write lock past the parallel scanners' 10 s busy timeout. Freed
    /// pages get reused by later scans, so the DB size plateaus even
    /// without VACUUM. Returns rows removed.
    ///
    /// Note: an owned release older than the window IS pruned from the
    /// INDEX - the downloaded file and history entry are untouched
    /// (have-badges compute from daemon history, not the index), and a
    /// re-scan re-adds it if it's still within the ingest gate.
    pub fn prune_age(&self, max_age_secs: i64, now: i64) -> rusqlite::Result<usize> {
        if max_age_secs <= 0 {
            return Ok(0);
        }
        let cutoff = now - max_age_secs;
        let mut removed = 0;
        loop {
            let ids: Vec<i64> = {
                let mut stmt = self.db.prepare_cached(
                    "SELECT id FROM releases
                     WHERE first_posted > 0 AND first_posted < ?1
                       AND title_key NOT IN (SELECT key FROM wall_hidden)
                     LIMIT 8000",
                )?;
                stmt.query_map([cutoff], |r| r.get(0))?
                    .collect::<rusqlite::Result<_>>()?
            };
            if ids.is_empty() {
                break;
            }
            removed += self.prune_batch(&ids)?;
        }
        Ok(removed)
    }

    /// M31a: reap dead junk fragments regardless of max_age - the bulk
    /// of a raw a.b.teevee/moovee index is single-segment fragments of
    /// obfuscated posts that never form a complete release (measured on
    /// the live 800k-row index: ~87% are junk-hidden, tiny, incomplete).
    /// prune_size spares anything missing parts forever (can't tell a
    /// mid-upload from a dead one), so this is where they die.
    ///
    /// DELIBERATELY gated on `junk >= 50` (already hidden from the wall)
    /// so the always-on reaper NEVER touches wall-visible content - a
    /// release is reaped only when it is already-junk AND older than the
    /// settle window (so not a live mid-upload; Usenet propagation is
    /// hours, not days) AND still missing parts (confirmed incomplete on
    /// the server). Wall-visible old content is the opt-in age prune's
    /// job, never this one's. Same chunking + hidden protection.
    /// Returns rows removed.
    pub fn prune_stale_partials(&self, settle_secs: i64, now: i64) -> rusqlite::Result<usize> {
        let cutoff = now - settle_secs;
        let mut removed = 0;
        loop {
            let ids: Vec<i64> = {
                let mut stmt = self.db.prepare_cached(
                    // first_seen (when WE indexed it) is the settle clock, not
                    // first_posted (the post's own age). During history backfill
                    // every post is old by definition, so gating only on
                    // first_posted reaped releases still being assembled across
                    // scan slices. Require BOTH: settled by post age AND known to
                    // the index for the settle window.
                    "SELECT id FROM releases
                     WHERE junk >= 50 AND first_posted > 0 AND first_posted < ?1
                       AND first_seen > 0 AND first_seen < ?1
                       AND title_key NOT IN (SELECT key FROM wall_hidden)
                       AND EXISTS (SELECT 1 FROM files f
                                   WHERE f.release_id = releases.id
                                     AND json_array_length(f.segments) < f.total_parts)
                     LIMIT 8000",
                )?;
                stmt.query_map([cutoff], |r| r.get(0))?
                    .collect::<rusqlite::Result<_>>()?
            };
            if ids.is_empty() {
                break;
            }
            removed += self.prune_batch(&ids)?;
        }
        Ok(removed)
    }

    /// M31a: reclaim freed pages to disk by rewriting the whole file.
    /// Exclusive-locks it for the duration, so the caller MUST ensure no
    /// scan pass or download is in flight.
    ///
    /// §95: this is now the SLOW path, kept for one reason - it is the
    /// only way to put an existing database into incremental
    /// auto-vacuum mode, which is what makes every later compact
    /// abortable. See `compact_chunk`. `PRAGMA auto_vacuum` is a no-op
    /// on a database that already has tables UNLESS a VACUUM follows it
    /// on the same connection, so the two belong in one batch: the
    /// migration IS a compact, and it is the last full rewrite this
    /// database ever needs.
    ///
    /// If it is interrupted the pragma does not stick either, which is
    /// the behaviour we want - `compact_pending` is sticky, so the
    /// migration simply retries at the next idle moment.
    pub fn compact(&self) -> rusqlite::Result<()> {
        self.db
            .execute_batch("PRAGMA auto_vacuum=INCREMENTAL; VACUUM")
    }

    /// Free pages this database is holding that `compact_chunk` could
    /// hand back to the filesystem, in PAGES (multiply by `PRAGMA
    /// page_size` for bytes).
    pub fn freelist_pages(&self) -> rusqlite::Result<u64> {
        let n: i64 = self
            .db
            .query_row("PRAGMA freelist_count", [], |r| r.get(0))?;
        Ok(n.max(0) as u64)
    }

    /// §95: reclaim at most `pages` freed pages, and return how many are
    /// still on the freelist afterwards (0 = fully compacted).
    ///
    /// This exists because aborting a VACUUM is a request, not a
    /// guarantee (see `interrupt_handle`), and the gap between those two
    /// is a download sitting in `Downloading` making no progress. A
    /// bounded chunk needs no abort mechanism at all: it is short by
    /// construction, so the caller just checks between chunks and stops.
    /// Nothing races, nothing is interrupted, and no phase of it is
    /// immune to being stopped - the three things wrong with doing it as
    /// one VACUUM.
    ///
    /// It is also RESUMABLE, which the VACUUM never was. Each chunk
    /// commits and truncates the file, so standing down for a download
    /// keeps every page reclaimed so far; an aborted VACUUM threw away
    /// all of its work and started from the top next time.
    ///
    /// It reclaims strictly less than a VACUUM: whole free pages go
    /// back, but free space stranded inside partly-emptied pages is not
    /// defragmented. For this schema that gap is small - the bulk of the
    /// bytes are `files.segments` blobs on overflow chains, which are
    /// released whole when their row goes - and it is the same
    /// approximation `live_bytes` already documents.
    ///
    /// Requires incremental auto-vacuum: on a database still in the
    /// default mode this is a silent no-op, which is why the caller must
    /// consult `compact_style` first.
    /// The statement is STEPPED TO COMPLETION, and that is the whole
    /// trick. `PRAGMA incremental_vacuum(N)` is a VDBE loop that frees
    /// one page per step, so `execute_batch` - which steps once and
    /// stops - frees exactly ONE page whatever N says. Measured: with a
    /// 20,000-page freelist, `execute_batch("PRAGMA
    /// incremental_vacuum(2048)")` freed 1 page; the same pragma
    /// stepped to completion freed 2048. The first shape still WORKS
    /// (the daemon loops until the freelist empties), which is what
    /// makes it dangerous - it just costs one write transaction per
    /// page, and it turned a 49 MB reclaim into 12,013 chunks.
    pub fn compact_chunk(&self, pages: u32) -> rusqlite::Result<u64> {
        let mut stmt = self
            .db
            .prepare(&format!("PRAGMA incremental_vacuum({})", pages.max(1)))?;
        let mut rows = stmt.query([])?;
        while rows.next()?.is_some() {}
        drop(rows);
        drop(stmt);
        self.freelist_pages()
    }

    /// Which compaction path this database can take right now.
    pub fn compact_style(&self) -> rusqlite::Result<CompactStyle> {
        let mode: i64 = self.db.query_row("PRAGMA auto_vacuum", [], |r| r.get(0))?;
        // 0 = NONE, 1 = FULL, 2 = INCREMENTAL. FULL is not a mode this
        // code ever sets, but a database that somehow has it already
        // reclaims on every commit and needs no compaction loop at all;
        // treating it as chunked is still correct (the freelist is
        // empty, so the loop exits at once) and costs one PRAGMA.
        Ok(if mode >= 1 {
            CompactStyle::Chunked
        } else {
            CompactStyle::FullRewrite
        })
    }

    /// Refresh the query planner's statistics.
    ///
    /// Without `sqlite_stat1` SQLite plans from built-in guesses, and on a
    /// large index those guesses go wrong in exactly one direction: it
    /// picks the index that satisfies a DISTINCT or a GROUP BY over the
    /// one that cuts the row count, and scans the whole releases table.
    /// Measured 2 Aug on the live 32M-release index, which had never been
    /// analyzed: `wall2`'s card COUNT took 85s, and 0.38s once these
    /// statistics existed - a 224x difference in one query, from a plan
    /// that flipped from "scan 32M releases, probe titles" to "scan 8.9k
    /// titles, probe releases".
    ///
    /// `analysis_limit` is what makes this affordable to run on a
    /// schedule: statistics are gathered from a bounded sample per index
    /// rather than a full pass, which is approximate and entirely good
    /// enough to get the join order right. `PRAGMA optimize` then does
    /// nothing at all on the passes where nothing has changed enough to
    /// matter - but it only reconsiders tables this connection has
    /// queried, so a database with no statistics AT ALL gets a plain
    /// ANALYZE (still under the sample limit) to guarantee a first set.
    ///
    /// Slow on the first run against a big unanalyzed database (~3
    /// minutes on the 45 GB live index) and it holds the write
    /// connection throughout, so it belongs in a maintenance leg behind
    /// the same "nothing is downloading" gate as the prune.
    pub fn optimize(&self) -> rusqlite::Result<()> {
        self.db.execute_batch("PRAGMA analysis_limit=1000")?;
        let analyzed: i64 = self.db.query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE name = 'sqlite_stat1'",
            [],
            |r| r.get(0),
        )?;
        if analyzed > 0 {
            self.db.execute_batch("PRAGMA optimize")
        } else {
            self.db.execute_batch("ANALYZE")
        }
    }

    /// A handle another thread can use to abort whatever statement this
    /// connection is currently running.
    ///
    /// It exists for `compact()`, which since §95 is only the one-time
    /// migration to incremental auto-vacuum - the routine path is
    /// `compact_chunk`, which needs no interrupt because a chunk is
    /// short by construction. Everything below is why that change was
    /// worth making, and still applies to the migration rewrite.
    ///
    /// On a multi-GB index a VACUUM is minutes
    /// of synchronous rewriting, and it is held under the same gate that
    /// a starting download waits on - so a job that arrives one moment
    /// after the "is anything downloading?" check sits in `Downloading`,
    /// making no progress and logging nothing, until the rewrite ends.
    /// VACUUM is a single transaction, so aborting it leaves the database
    /// exactly as it was and costs only the work done so far.
    ///
    /// Interrupting is per-CONNECTION, not per-statement: only call this
    /// while you know the statement you mean to stop is the one running.
    ///
    /// It also does not abort a VACUUM at an arbitrary point, which is
    /// easy to assume and wrong. The flag is only read from the VDBE, so
    /// it reaches the phase that copies live pages into the temp
    /// database and not the `sqlite3BtreeCopyFile` tail that writes the
    /// result back over the original - a job arriving during the tail
    /// still waits it out.
    ///
    /// Measured on Windows against an 80 MB index, 20 000 rows of 4 KB
    /// with half deleted (interrupt once at a fixed offset, sweep the
    /// offset - the abort test now builds a tenth of that, because a
    /// progress handler needs opcodes rather than time): the rewrite
    /// stops accepting an interrupt after the first few hundred
    /// milliseconds, out of ~2 s idle and ~6 s with the cores busy. The
    /// abortable part runs at memory speed - temp_store=MEMORY over a
    /// cache that just wrote the data - while the tail is disk-bound, so
    /// load and size both stretch the tail and leave the window where it
    /// was. The abortable FRACTION therefore shrinks exactly when the
    /// abort matters most, and on the multi-GB index this exists for it
    /// is small. Interrupting still helps and still costs nothing; it is
    /// just not the guarantee the name suggests.
    pub fn interrupt_handle(&self) -> InterruptHandle {
        self.db.get_interrupt_handle()
    }

    // -- M32: size cap + eviction (types and SQL near the end of the file) --

    /// Current on-disk size: page_count * page_size, including the freelist.
    ///
    /// This is what the user sees in Finder/`ls`, so it is what the cap
    /// is expressed against - even though the freelist part of it is
    /// space DELETE has already released for reuse and only `compact()`
    /// can hand back to the filesystem.
    pub fn db_bytes(&self) -> rusqlite::Result<u64> {
        let pages: i64 = self.db.query_row("PRAGMA page_count", [], |r| r.get(0))?;
        let size: i64 = self.db.query_row("PRAGMA page_size", [], |r| r.get(0))?;
        Ok(pages.max(0) as u64 * size.max(0) as u64)
    }

    /// Bytes of the file that still hold live content: `db_bytes()` minus
    /// the freelist. This - not `db_bytes()` - is what eviction can move,
    /// and it is the size the file WOULD have after a `compact()`, so it
    /// is the honest quantity to compare against the user's cap.
    ///
    /// It over-states live content by the free space stranded inside
    /// partially-emptied pages, which the freelist does not count. For
    /// this schema that error is small: the bulk of the bytes are the
    /// `files.segments` blobs, which live on overflow chains that are
    /// released whole when their row goes.
    ///
    /// PUBLIC, and deliberately so: the daemon compares the user's cap
    /// against THIS, not against `db_bytes()`. Comparing against the raw
    /// file size meant an evicted database never got back under its cap
    /// (DELETE frees pages to the freelist without shortening the file),
    /// so automatic eviction re-fired on every scan pass forever.
    pub fn live_bytes(&self) -> rusqlite::Result<u64> {
        let pages: i64 = self.db.query_row("PRAGMA page_count", [], |r| r.get(0))?;
        let free: i64 = self
            .db
            .query_row("PRAGMA freelist_count", [], |r| r.get(0))?;
        let size: i64 = self.db.query_row("PRAGMA page_size", [], |r| r.get(0))?;
        Ok((pages - free).max(0) as u64 * size.max(0) as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::testutil::{entry, teardown};

    /// The repost table: remember once, recognise later, and never let a
    /// second download rewrite what the first one taught us.
    #[test]
    fn par_hashes_remember_first_and_recognise_reposts() {
        let dir = std::env::temp_dir().join(format!("nzbfast-index-ph-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ix = Index::open(&dir.join("index.db")).unwrap();
        let pairs = |hs: &[&str]| -> Vec<(String, String)> {
            hs.iter()
                .map(|h| ((*h).to_string(), format!("{h}.r00")))
                .collect()
        };

        // Nothing known yet.
        assert_eq!(ix.par_hash_lookup(&pairs(&["aa", "bb"])).unwrap(), None);

        let named = pairs(&["aa", "bb", "cc"]);
        assert_eq!(
            ix.par_hash_remember(
                &named,
                "Example.Movie.2019.1080p-GRP",
                "m:example movie:2019",
                100
            )
            .unwrap(),
            3
        );
        // A repost whose sidecar shares ONE volume fingerprint is the
        // same bytes, and one hit answers for the whole set - and the
        // answer says WHICH fingerprint proved it.
        assert_eq!(
            ix.par_hash_lookup(&pairs(&["zz", "cc"])).unwrap(),
            Some((
                "cc".into(),
                "Example.Movie.2019.1080p-GRP".into(),
                "m:example movie:2019".into()
            ))
        );

        // The obfuscated repost must NOT overwrite the good name: the
        // first writer knew what it was, and every future repost depends
        // on that answer staying put.
        assert_eq!(
            ix.par_hash_remember(&named, "8a7f2c1b9d0e4f", "", 200)
                .unwrap(),
            0,
            "a later download rewrote a fingerprint it did not name"
        );
        assert_eq!(
            ix.par_hash_lookup(&pairs(&["aa"])).unwrap().unwrap().1,
            "Example.Movie.2019.1080p-GRP"
        );

        // A nameless job records nothing at all rather than a blank row
        // that would then shadow the real name forever.
        assert_eq!(
            ix.par_hash_remember(&pairs(&["dd"]), "  ", "", 300)
                .unwrap(),
            0
        );
        assert_eq!(ix.par_hash_lookup(&pairs(&["dd"])).unwrap(), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn retention_prune_reaps_old_spares_recent_hidden_and_undated() {
        let dir = std::env::temp_dir().join(format!("nzbfast-index-ret-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut ix = Index::open(&dir.join("index.db")).unwrap();
        const DAY: i64 = 86_400;
        let now = 1_000 * DAY;
        // now: full-size rows at various ages + one undated + one hidden.
        let mut old = entry(
            "\"Ancient.Movie.2001.1080p.mkv\" yEnc (1/1)",
            "p@x",
            "r1",
            4 << 30,
        );
        old.date = now - 800 * DAY;
        let mut recent = entry(
            "\"Fresh.Movie.2026.1080p.mkv\" yEnc (1/1)",
            "p@x",
            "r2",
            4 << 30,
        );
        recent.date = now - 10 * DAY;
        let mut hidden = entry(
            "\"Hidden.Movie.2000.1080p.mkv\" yEnc (1/1)",
            "p@x",
            "r3",
            4 << 30,
        );
        hidden.date = now - 900 * DAY;
        let undated = entry(
            "\"Undated.Movie.2010.1080p.mkv\" yEnc (1/1)",
            "p@x",
            "r4",
            4 << 30,
        );
        ix.ingest("alt.test", &[old, recent, hidden, undated], now)
            .unwrap();
        ix.hide_title(&crate::release::parse_release("Hidden.Movie.2000.1080p").key)
            .unwrap();

        // Keep 2 years (~730 days): the 800/900-day rows are candidates,
        // but the 900-day one is hidden and must survive.
        let removed = ix.prune_age(730 * DAY, now).unwrap();
        assert_eq!(removed, 1, "only the old non-hidden row");
        assert_eq!(ix.search("ancient", 10).unwrap().len(), 0, "old reaped");
        assert_eq!(ix.search("fresh", 10).unwrap().len(), 1, "recent kept");
        assert_eq!(
            ix.search("hidden movie", 10).unwrap().len(),
            1,
            "hidden kept"
        );
        assert_eq!(
            ix.search("undated", 10).unwrap().len(),
            1,
            "unknown-date kept"
        );
        // FTS index stayed in sync (rowid count == releases count) and no
        // orphan files rows survived the batch delete.
        let (rels, _) = ix.stats().unwrap();
        let fts_rows: i64 = ix
            .db
            .query_row("SELECT COUNT(*) FROM rel_fts", [], |r| r.get(0))
            .unwrap();
        assert_eq!(fts_rows as u64, rels, "FTS in sync");
        let orphans: i64 = ix
            .db
            .query_row(
                "SELECT COUNT(*) FROM files WHERE release_id NOT IN (SELECT id FROM releases)",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(orphans, 0, "no orphan files rows");
        teardown(&dir, ix);
    }

    #[test]
    fn stale_partials_reaps_dead_junk_spares_wall_and_settle() {
        let dir = std::env::temp_dir().join(format!("nzbfast-index-stale-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut ix = Index::open(&dir.join("index.db")).unwrap();
        const DAY: i64 = 86_400;
        let now = 1_000 * DAY;
        // Obfuscated hash name -> junk>=50, missing parts, OLD -> dead, reaped.
        let mut dead = entry(
            "\"ugpoqs3l6bthdkgbn1ktwkl2wwxju8.part1.rar\" yEnc (1/9)",
            "p@x",
            "s1",
            750_000,
        );
        dead.date = now - 30 * DAY;
        // Same junk shape and an OLD POST, but only just indexed (mid-backfill
        // into history): first_seen is recent, so the reaper must spare it - the
        // settle clock is index age, not post age. (The old code reaped this.)
        let mut fresh = entry(
            "\"zzq9x2m7v5t8k1n3b6h4j0w2e5r7y9.part1.rar\" yEnc (1/9)",
            "p@x",
            "s2",
            750_000,
        );
        fresh.date = now - 30 * DAY;
        // Wall-visible (parses clean, junk<50), missing parts, OLD -> the
        // always-on reaper must NOT touch it (opt-in age prune's job).
        let mut real = entry(
            "\"Real.Show.S01E01.720p.WEB.x264-GRP.mkv\" yEnc (1/9)",
            "p@x",
            "s3",
            400 << 20,
        );
        real.date = now - 30 * DAY;
        // Junk + COMPLETE + old -> not this reaper (spares complete blobs).
        let mut donejunk = entry(
            "\"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3.mkv\" yEnc (1/1)",
            "p@x",
            "s4",
            750_000,
        );
        donejunk.date = now - 30 * DAY;
        // dead/real/donejunk were indexed long ago (first_seen old); `fresh`
        // is indexed now, so its settle window has not elapsed.
        ix.ingest("alt.test", &[dead, real, donejunk], now - 30 * DAY)
            .unwrap();
        ix.ingest("alt.test", &[fresh], now).unwrap();

        let removed = ix.prune_stale_partials(7 * DAY, now).unwrap();
        assert_eq!(removed, 1, "only the old junk missing-parts row");
        assert_eq!(
            ix.search("ugpoqs3l6bthdkgbn1ktwkl2wwxju8", 10)
                .unwrap()
                .len(),
            0,
            "dead junk reaped"
        );
        assert_eq!(
            ix.search("zzq9x2m7v5t8k1n3b6h4j0w2e5r7y9", 10)
                .unwrap()
                .len(),
            1,
            "in settle window"
        );
        assert_eq!(
            ix.search("real show", 10).unwrap().len(),
            1,
            "wall-visible spared"
        );
        assert_eq!(
            ix.search("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3", 10)
                .unwrap()
                .len(),
            1,
            "complete junk spared"
        );
        teardown(&dir, ix);
    }

    /// The 2 Aug wedge's proximate cause was an index that had never been
    /// analyzed, so this pins the two things the daily maintenance leg
    /// needs from `optimize`: a database with no statistics at all comes
    /// out of it WITH some (the `PRAGMA optimize` path alone would not
    /// guarantee that - it only reconsiders tables the connection has
    /// queried), and calling it again on an already-analyzed database is
    /// a no-op rather than an error, because the leg runs it forever.
    #[test]
    fn optimize_creates_statistics_and_is_safe_to_repeat() {
        let dir = std::env::temp_dir().join(format!("nzbfast-analyze-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut ix = Index::open(&dir.join("index.db")).unwrap();
        let now = 1_753_000_000i64;
        let entries: Vec<crate::nntp::OverEntry> = (0..200)
            .map(|i| crate::nntp::OverEntry {
                number: i + 1,
                subject: format!("\"Stats.Test.S01E{i:02}.1080p-GRP.rar\" yEnc (1/1)"),
                from: "p@x".into(),
                date: now - (i as i64) * 3_600,
                message_id: format!("<stats{i}@x>"),
                bytes: 4096,
            })
            .collect();
        ix.ingest("alt.binaries.teevee", &entries, now).unwrap();

        let stat_rows = |ix: &Index| -> i64 {
            ix.db
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE name = 'sqlite_stat1'",
                    [],
                    |r| r.get(0),
                )
                .unwrap()
        };
        assert_eq!(stat_rows(&ix), 0, "a fresh index has never been analyzed");
        ix.optimize().expect("first optimize");
        assert_eq!(
            stat_rows(&ix),
            1,
            "the first pass must produce statistics, not defer to a query that never came"
        );
        let analyzed: i64 = ix
            .db
            .query_row("SELECT COUNT(*) FROM sqlite_stat1", [], |r| r.get(0))
            .unwrap();
        assert!(analyzed > 0, "and rows in them, not just the table");

        // Every later pass, forever. Nothing to do is the normal case.
        ix.optimize().expect("second optimize");
        ix.optimize().expect("third optimize");
        assert!(
            ix.stats().unwrap().0 > 0,
            "the index still answers after being analyzed"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A VACUUM is minutes of synchronous rewriting on a multi-GB index,
    /// and the daemon holds it under the same gate a starting download
    /// waits on - so the rewrite has to be abortable, or a job that
    /// arrives mid-compact stalls for its whole duration. The property
    /// that makes aborting safe: VACUUM is one transaction, so the
    /// database is exactly as it was.
    #[test]
    fn a_compact_can_be_aborted_and_leaves_the_database_intact() {
        let dir = std::env::temp_dir().join(format!("nzbfast-vacabort-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("index.db");
        let ix = Index::open(&path).unwrap();

        // Ballast enough that the rewrite has a VM phase worth
        // interrupting in at all. Since the interrupt is delivered from
        // a progress handler rather than on a timer, "enough" is an
        // OPCODE count, not a duration: the handler fires every
        // `num_ops` VDBE steps OF THE STATEMENT RUNNING AT THE TIME, so
        // the only requirement is that some statement inside the VACUUM
        // runs past `num_ops`. VACUUM copies each table with one
        // `INSERT INTO vacuum_db.x SELECT * FROM main.x`, which measures
        // ~5 opcodes per row, so at the 1000 below the floor is ~200
        // SURVIVING rows - 400 built, half deleted. Measured: 400 built
        // fires exactly once, 300 never fires at all.
        //
        // The 2 000 below is therefore five handler calls against a
        // floor of 1. It is NOT sized for duration, whatever the 20 000
        // it replaced suggests, so do not read it as "the rewrite must
        // last long enough to be hit" and do not tune it as a timing
        // margin. Five is ample: the floor moves only if VACUUM's copy
        // loop changes its opcodes per row, and it cannot spend fewer
        // than the ~4 it takes to step a cursor and insert a record.
        //
        // Undershooting is not a flake. Too little ballast means the
        // handler never fires at all, and `fired` below then fails
        // loudly and identically on every platform - it cannot walk the
        // interrupt somewhere subtler, because the fire point is a count
        // of opcodes within one statement rather than a moment in time.
        let payload = vec![7u8; 4096];
        ix.db
            .execute_batch("CREATE TABLE IF NOT EXISTS vac_ballast(id INTEGER PRIMARY KEY, b BLOB)")
            .unwrap();
        {
            let tx = ix.db.unchecked_transaction().unwrap();
            for _ in 0..2_000 {
                tx.execute("INSERT INTO vac_ballast(b) VALUES(?1)", [&payload])
                    .unwrap();
            }
            tx.commit().unwrap();
        }
        ix.db
            .execute("DELETE FROM vac_ballast WHERE id % 2 = 0", [])
            .unwrap();
        let free_before: i64 = ix
            .db
            .query_row("PRAGMA freelist_count", [], |r| r.get(0))
            .unwrap();
        assert!(free_before > 0, "the delete left the rewrite nothing to do");

        // The interrupt has to land inside the rewrite's VM phase, and
        // nothing about ELAPSED TIME says when that is. Only the first
        // part of a VACUUM - copying the live pages into the temp
        // database - runs in the VDBE, which is the only place the
        // interrupt flag is read; the `sqlite3BtreeCopyFile` tail that
        // writes the result back over the original checks nothing and
        // cannot be stopped. Measured on Windows against an 80 MB index
        // (see `interrupt_handle`): the window is the first few hundred
        // milliseconds of a rewrite that runs ~2 s idle and ~6 s with
        // the cores busy, because the window is memory-speed work and
        // only the tail is disk-bound. Load stretches the rewrite and
        // leaves the window where it was.
        //
        // Both earlier shapes bet on time and lost. Sleeping 5 ms and
        // interrupting once failed the Windows nightly leg on 2026-08-02
        // (it fired before VACUUM had begun). Interrupting in a 1 ms
        // loop until compact() returns failed the per-push windows-unit
        // leg on d1716767, twice including the nextest retry: a freshly
        // spawned thread on a loaded runner took longer to reach its
        // first call than the window stayed open. On a 14-core Windows
        // laptop with every core busy that first call measured 27-32 ms;
        // the margin is real but it is only ever a margin.
        //
        // So take time out of it. The progress callback runs from
        // inside the rewrite's own VM loop, so when it fires the VACUUM
        // is provably mid-flight and provably still in the phase that
        // reads the flag. It hands the job to another thread - the
        // daemon aborts a compact from another thread, and that is the
        // property worth pinning - and blocks until that thread's
        // `interrupt()` has returned, so the rewrite cannot outrun it.
        // The callback returns false: aborting is the interrupt's job
        // here, not the progress handler's, or the test would pass
        // without `interrupt_handle` working at all.
        //
        // 1000 opcodes is also what keeps the first call landing in the
        // table copy rather than in VACUUM's own preamble. Traced by
        // reporting the busy statement from inside the handler: at 1000
        // the first call is always the `INSERT INTO vacuum_db.
        // 'vac_ballast' SELECT*FROM main.'vac_ballast'`; at 100 and 10
        // it is the schema mirror; at 5 it is the `ATTACH '' AS
        // vacuum_...` that opens the temp database, which fails as
        // "unable to open database" instead of "interrupted" - still an
        // Err, so still a green test, but no longer the interrupt this
        // is here to pin.
        let handle = ix.interrupt_handle();
        let (ask, asked) = std::sync::mpsc::channel::<()>();
        let (landed, confirm) = std::sync::mpsc::channel::<()>();
        let aborter = std::thread::spawn(move || {
            if asked.recv().is_ok() {
                handle.interrupt();
                let _ = landed.send(());
            }
        });
        let fired = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let once = std::sync::Arc::clone(&fired);
        ix.db
            .progress_handler(
                1000,
                Some(move || {
                    if !once.swap(true, std::sync::atomic::Ordering::SeqCst) {
                        // A dead aborter closes the channel rather than
                        // hanging the rewrite here.
                        if ask.send(()).is_ok() {
                            let _ = confirm.recv();
                        }
                    }
                    false
                }),
            )
            .unwrap();
        let r = ix.compact();
        ix.db.progress_handler(1000, None::<fn() -> bool>).unwrap();
        aborter.join().unwrap();
        assert!(
            fired.load(std::sync::atomic::Ordering::SeqCst),
            "the rewrite never reached its VM loop, so nothing was interrupted"
        );
        assert!(
            r.is_err(),
            "the rewrite must abort rather than run to completion"
        );
        // And it aborted with work still to do. `fired` alone only says
        // the VM loop was reached; the free pages are what say the
        // interrupt beat `sqlite3BtreeCopyFile`, because a rewrite that
        // reached the copy-back has no freelist left. This is the
        // property the ballast is sized for, so it is the one that has
        // to fail if the ballast ever gets too small to hold the first
        // handler call inside the copy.
        let free_after: i64 = ix
            .db
            .query_row("PRAGMA freelist_count", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            free_after, free_before,
            "the abort landed after the rewrite, so it saved nothing"
        );

        // Nothing was lost: the odd-id half is still all there, and the
        // index is usable straight afterwards.
        let n: i64 = ix
            .db
            .query_row("SELECT COUNT(*) FROM vac_ballast", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n, 1_000, "an aborted VACUUM must not cost a single row");
        assert!(
            ix.db_bytes().unwrap() > 0,
            "the connection still works after the abort"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}

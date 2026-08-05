use super::*;

/// M13 background enricher: look up pending wall titles (TMDB with a
/// key; TVmaze/Wikidata keyless otherwise), cache posters/backdrops to
/// `.spool/art/`, record results (including "found nothing") in the
/// index db. All network happens HERE - the API thread only ever reads
/// the cache. Pacing is per PROVIDER, in `ratelimit` - every request a
/// lane makes waits for that provider's bucket, so a title that needs
/// six calls costs six slots and a title that needs one costs one. The
/// lanes used to sleep a fixed window after each TITLE instead, which
/// could not see the burst inside one: measured 27 Jul, that let the
/// movie lane spend a quarter of Wikidata's 10-request window on a
/// single title and stall ~55 s on a 429 for 3-4 titles in every 10.
///
/// Runs as THREE lanes (M21 speedup, extended): movies (Wikidata /
/// Wikipedia / OMDb), TV + junk (TVmaze), and music + books
/// (MusicBrainz / Cover Art Archive / OpenLibrary). The rate limits are
/// per-provider, so one serial loop made every TV title queue behind the
/// movie crawl - and MusicBrainz's hard 1 request/second would have put
/// an album backlog in front of every new episode had it shared a lane.
#[cfg(feature = "indexer")]
pub(super) fn wall_enricher(d: Arc<Daemon>, api_key: Option<String>) {
    use nzbkit::index::Lane;
    for lane in [Lane::Movies, Lane::MusicBooks] {
        let (d2, k2) = (d.clone(), api_key.clone());
        std::thread::spawn(move || wall_enrich_lane(d2, k2, lane));
    }
    wall_enrich_lane(d, api_key, Lane::Shows);
}

/// The `titles.kind` string as the wall's enum. Music and books used to
/// fall into the `_` arm here and land on `Kind::Other`, which returns
/// before touching any provider - so those rows were stamped "checked"
/// having never been looked up.
#[cfg(feature = "indexer")]
pub(super) fn lane_kind(kind: &str) -> crate::wall::Kind {
    match kind {
        "tv" => crate::wall::Kind::Tv,
        "movie" => crate::wall::Kind::Movie,
        "music" => crate::wall::Kind::Music,
        "book" => crate::wall::Kind::Book,
        _ => crate::wall::Kind::Other,
    }
}

#[cfg(feature = "indexer")]
pub(super) fn wall_enrich_lane(d: Arc<Daemon>, api_key: Option<String>, lane: nzbkit::index::Lane) {
    let art = d.spool.join("art");
    let _ = std::fs::create_dir_all(&art);
    let mut said_backfilling = false;
    // Titles whose whole provider chain could not be REACHED
    // (DNS, timeout, TLS, 5xx - as opposed to "answered and had
    // nothing"). Such a row deliberately stays unstamped so a later
    // pass retries it, but without memory of the failure the lane
    // offers it again on the very next batch: the live daemon spent a
    // whole night logging the same title every ~7 seconds. Each key
    // now waits BACKOFF_MIN after its first failed pass, doubling to
    // the BACKOFF_MAX ceiling, and any pass that reaches a provider
    // clears its slate. In-memory on purpose, like the photo
    // fetcher's failed set: a restart retrying at once is fine, the
    // tight loop is not. Keyed per title, so one unreachable title
    // never delays the rest of the queue.
    const BACKOFF_MIN: u64 = 60;
    const BACKOFF_MAX: u64 = 6 * 3600;
    let mut unreached: std::collections::HashMap<String, (u32, std::time::Instant)> =
        std::collections::HashMap::new();
    let backoff_after = |fails: u32| {
        std::time::Instant::now()
            + std::time::Duration::from_secs(
                BACKOFF_MIN
                    .saturating_mul(1u64 << fails.saturating_sub(1).min(9))
                    .min(BACKOFF_MAX),
            )
    };
    loop {
        if d.park_if_off(30) {
            continue;
        }
        // Entries whose wait has expired retry on sight, so dropping
        // them merely resets a counter - done only to bound the map
        // for the life of the thread.
        if unreached.len() > 2_048 {
            let now_i = std::time::Instant::now();
            unreached.retain(|_, (_, next)| *next > now_i);
        }
        // M30: what the wall is showing unenriched RIGHT NOW jumps the
        // backlog. Keys stay queued until this lane's query confirms
        // they're pending here (the other lane's keys just no-op), and
        // processed ones are removed below.
        let hot_keys: Vec<String> = d.enrich_hot.lock_ok().iter().cloned().collect();
        let hot = if hot_keys.is_empty() {
            Vec::new()
        } else {
            d.with_index(|ix| ix.titles_hot(&hot_keys, lane).ok())
                .unwrap_or_default()
        };
        let batch: Vec<_> = if !hot.is_empty() {
            {
                let mut q = d.enrich_hot.lock_ok();
                q.retain(|k| !hot.iter().any(|t| &t.key == k));
            }
            hot
        } else {
            d
                // Batch of 12 (was 6): fewer db round-trips, and it costs
                // nothing in pacing - the per-title sleeps are gone, the
                // rate now lives in the per-provider buckets, which do
                // not care how many titles a batch holds. A fresh
                // priority order is re-read every batch anyway.
                //
                // Over-fetched by the number of keys currently in
                // backoff, so a run of skipped rows at the head of the
                // priority order cannot starve the eligible rows
                // behind them.
                .with_index(|ix| {
                    ix.titles_pending_lane(12 + unreached.len().min(200) as u32, lane)
                        .ok()
                })
                .unwrap_or_default()
        };
        let now_i = std::time::Instant::now();
        let batch: Vec<_> = batch
            .into_iter()
            .filter(|r| unreached.get(&r.key).is_none_or(|(_, next)| *next <= now_i))
            .take(12)
            .collect();
        if batch.is_empty() {
            // Idle time goes on backfilling release dates onto titles
            // enriched before we stored them - otherwise the wall's
            // release-date sort would only ever work for titles indexed
            // from this version on, and an existing library would sort by
            // year forever. Only the date column is written, so artwork
            // and any hand-corrected metadata are left alone.
            let back: Vec<_> = d
                .with_index(|ix| {
                    ix.titles_missing_date(6 + unreached.len().min(200) as u32, lane)
                        .ok()
                })
                .unwrap_or_default()
                .into_iter()
                // Same backoff as the enrichment batch above: a title
                // whose backfill could not reach a provider waits its
                // turn instead of being re-asked every pass.
                .filter(|r| unreached.get(&r.key).is_none_or(|(_, next)| *next <= now_i))
                .take(6)
                .collect();
            if back.is_empty() {
                std::thread::sleep(std::time::Duration::from_secs(15));
                continue;
            }
            if !said_backfilling {
                said_backfilling = true;
                info!(
                    target: "wall",
                    "backfilling release dates for already-enriched {} titles",
                    match lane {
                        nzbkit::index::Lane::Movies => "movie",
                        nzbkit::index::Lane::MusicBooks => "music and book",
                        nzbkit::index::Lane::Shows => "TV",
                    }
                );
            }
            for row in back {
                let kind = lane_kind(&row.kind);
                crate::wall::clear_unreachable();
                let date = crate::wall::lookup(api_key.as_deref(), &kind, &row.title, row.year)
                    .map(|m| m.air_date)
                    .unwrap_or_default();
                // Written even when empty: that records "asked, provider
                // had none" and keeps this lane from re-asking forever.
                // But only when it really was ASKED - air_tried=1 is just
                // as permanent as the enricher's checked stamp, so a
                // provider we could not reach must leave the row alone.
                if date.is_empty() && crate::wall::saw_unreachable() {
                    let fails = unreached.get(&row.key).map_or(0, |(n, _)| *n) + 1;
                    let next = backoff_after(fails);
                    info!(
                        target: "wall",
                        "{}: date backfill could not reach a provider, retrying \
                         in {} min",
                        row.key,
                        next.saturating_duration_since(std::time::Instant::now())
                            .as_secs()
                            .div_ceil(60)
                    );
                    unreached.insert(row.key.clone(), (fails, next));
                } else {
                    unreached.remove(&row.key);
                    let _ = d.with_index(|ix| ix.title_set_air_date(&row.key, &date).ok());
                }
            }
            continue;
        }
        for row in batch {
            let kind = lane_kind(&row.kind);
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|t| t.as_secs() as i64)
                .unwrap_or(0);
            // Provider chain (all keyless unless a TMDB key exists):
            //   TV    → TVmaze (+/cast, +externals.imdb) → AniList
            //   Movie → OMDb when the user's free key is set (exact
            //           data + cast + imdb id in one call), else
            //           Wikidata (art + date + genres + cast + imdb id)
            //           (+Wikipedia plot when the description is empty)
            //           → AniList
            // The imdb id joins the local IMDb ratings snapshot at wall
            // time, so ratings stay fresh without re-enrichment.
            use crate::wall::{self, Kind};
            // Tracks whether the Wikidata half of the chain has already
            // run, so the OMDb-poster fallback below doesn't ask twice.
            let mut hit_wikidata = false;
            // Start this row's "did anything fail to answer" window. See
            // wall::saw_unreachable - an empty result has to mean "the
            // provider has nothing", never "we could not reach it", or
            // the stamp below retires the row for good.
            wall::clear_unreachable();
            let mut meta = match (&api_key, &kind) {
                _ if kind == Kind::Other => None,
                // Music and books before the TMDB arm, not after: TMDB
                // is a film database, so a key being configured must not
                // divert an album into a movie search.
                (_, Kind::Music) | (_, Kind::Book) => wall::media_lookup(&kind, &row.title),
                (Some(k), _) => wall::tmdb_lookup(k, &kind, &row.title, row.year),
                // ONE request, not two: the embed form returns the show,
                // its cast (with character names, person ids and
                // headshots) and its crew together, so the old
                // lookup-then-/cast pair - and the 400 ms courtesy sleep
                // between them - is gone.
                (None, Kind::Tv) => wall::tvmaze_lookup_full(&row.title),
                (None, _) => {
                    let omdb = d.omdb_key.lock_ok().clone();
                    let (mut m, mut imdb) = match &omdb {
                        // OMDb (the user's free key) is exact and
                        // complete but does not always answer, so
                        // Wikidata resolves the imdb id alongside it -
                        // independent services, independent limits.
                        Some(k) => std::thread::scope(|s| {
                            let imdb = s.spawn(|| wall::wikidata_imdb(&row.title, row.year));
                            let m = wall::omdb_lookup(k, &row.title, row.year);
                            (m, imdb.join().unwrap_or(None))
                        }),
                        // Keyless: Wikidata IS the provider now, and it
                        // returns the imdb id itself - so unlike the
                        // iTunes path it replaced, no second lookup is
                        // needed to get one.
                        None => {
                            hit_wikidata = true;
                            let m = wall::wikidata_movie(&row.title, row.year);
                            let imdb = m.as_ref().map(|x| x.imdb.clone()).filter(|s| !s.is_empty());
                            (m, imdb)
                        }
                    };
                    // OMDb title-miss but Wikidata knows the film →
                    // exact OMDb lookup by tconst.
                    if m.is_none()
                        && let (Some(k), Some(t)) = (&omdb, &imdb)
                    {
                        m = wall::omdb_lookup_imdb(k, t);
                    }
                    // OMDb configured but no answer (daily cap, niche
                    // title) → the keyless chain still applies.
                    if m.is_none() && omdb.is_some() {
                        hit_wikidata = true;
                        m = wall::wikidata_movie(&row.title, row.year);
                        if imdb.is_none() {
                            imdb = m.as_ref().map(|x| x.imdb.clone()).filter(|s| !s.is_empty());
                        }
                    }
                    // OMDb hit without a poster → Wikidata art fills in.
                    if let Some(meta) = &mut m
                        && meta.poster_url.is_empty()
                        && omdb.is_some()
                        && !hit_wikidata
                        && let Some(w) = wall::wikidata_movie(&row.title, row.year)
                    {
                        meta.poster_url = w.poster_url;
                    }
                    // Wikipedia supplies both the plot AND the poster:
                    // a film article's infobox image is the poster, and
                    // it is the only free source for one (Wikidata
                    // cannot host non-free art - see parse_wikidata_film).
                    // Fetched once and used for whichever is missing.
                    let wiki = match &m {
                        Some(meta) if meta.overview.is_empty() || meta.poster_url.is_empty() => {
                            wall::wikipedia_page(&row.title, row.year)
                        }
                        Some(_) => None,
                        None => wall::wikipedia_page(&row.title, row.year),
                    };
                    match &mut m {
                        Some(meta) => {
                            if meta.imdb.is_empty() {
                                meta.imdb = imdb.unwrap_or_default();
                            }
                            if let Some(w) = wiki {
                                if meta.overview.is_empty() {
                                    meta.overview = w.extract;
                                }
                                if meta.poster_url.is_empty() {
                                    meta.poster_url = w.image;
                                }
                            }
                        }
                        None => {
                            // No provider hit - a Wikipedia-only card
                            // (poster + plot + IMDb rating) still beats
                            // a bare stem.
                            let w = wiki.unwrap_or_default();
                            if imdb.is_some() || !w.extract.is_empty() || !w.image.is_empty() {
                                m = Some(wall::TitleMeta {
                                    tmdb_id: 0,
                                    overview: w.extract,
                                    rating: 0.0,
                                    genres: String::new(),
                                    poster_url: w.image,
                                    backdrop_url: String::new(),
                                    imdb: imdb.unwrap_or_default(),
                                    actors: String::new(),
                                    air_date: String::new(),
                                    credits: Vec::new(),
                                });
                            }
                        }
                    }
                    m
                }
            };
            // AniList is the last-chance fallback for video. It is an
            // anime database, so it is not consulted for an album or a
            // book - a fuzzy title match there would attach anime art to
            // a record, which is worse than leaving the card bare.
            if meta.is_none() && !matches!(kind, Kind::Other | Kind::Music | Kind::Book) {
                meta = wall::anilist_lookup(&row.title);
            }
            // Junk rows never touched a provider - stamp and move on;
            // sleeping 3.2 s per obfuscated stem was the old behavior
            // and made big walls take forever to settle.
            if kind == Kind::Other {
                let _ = d.with_index(|ix| ix.title_fill(&row.key, &Default::default(), now).ok());
                continue;
            }
            match meta {
                Some(m) => {
                    // A provider answered: whatever backoff this key
                    // accrued is over.
                    unreached.remove(&row.key);
                    let save = |url: &str, backdrop: bool| -> String {
                        let name = wall::art_name(&row.key, backdrop);
                        match wall::fetch_image(url) {
                            Some(bytes) if std::fs::write(art.join(&name), &bytes).is_ok() => name,
                            _ => String::new(),
                        }
                    };
                    let (poster, backdrop) = std::thread::scope(|s| {
                        let bd = s.spawn(|| save(&m.backdrop_url, true));
                        (save(&m.poster_url, false), bd.join().unwrap_or_default())
                    });
                    // Credits go in BEFORE the fill, because the fill is
                    // what stamps `checked` and that stamp is final: no
                    // lane ever offers a checked row again. The credits
                    // write used to run after it with its error dropped
                    // by .ok(), so a busy timeout behind a long retention
                    // prune left the card showing an actors string while
                    // the person pages, cast chips and cast-affinity
                    // graph permanently lacked the title, with nothing to
                    // retry it.
                    //
                    // Written only when the provider actually gave some:
                    // one that answered without a cast (OMDb, AniList)
                    // must not wipe what an earlier one supplied. Setting
                    // credits is idempotent, so re-running a pass that
                    // failed after this point simply writes them again.
                    let credits_ok = m.credits.is_empty()
                        || d.with_index(|ix| {
                            Some(ix.title_credits_set(&row.key, &m.credits).is_ok())
                        })
                        .unwrap_or(false);
                    if credits_ok {
                        let _ = d.with_index(|ix| {
                            ix.title_fill(
                                &row.key,
                                &nzbkit::index::TitleFill {
                                    tmdb_id: m.tmdb_id,
                                    overview: &m.overview,
                                    rating: m.rating,
                                    genres: &m.genres,
                                    poster: &poster,
                                    backdrop: &backdrop,
                                    imdb: &m.imdb,
                                    actors: &m.actors,
                                    air_date: &m.air_date,
                                },
                                now,
                            )
                            .ok()
                        });
                    } else {
                        info!(
                            target: "enrich",
                            "{}: could not write credits, leaving the title \
                             unstamped so a later pass retries it",
                            row.key
                        );
                    }
                }
                None => {
                    // Only stamp when the providers actually ANSWERED and
                    // had nothing. If any of them could not be reached -
                    // DNS, timeout, TLS, a 5xx, or retries exhausted -
                    // this row is unknown, not empty, and stamping it
                    // here would retire it permanently: title_fill sets
                    // checked=now and air_tried=1, and every lane query
                    // requires checked=0. A brief uplink blip used to
                    // blank every title the lane touched while it lasted.
                    if wall::saw_unreachable() {
                        // Remembered, so the retry waits out an
                        // exponential backoff instead of burning a
                        // batch slot (and this log line) every pass.
                        let fails = unreached.get(&row.key).map_or(0, |(n, _)| *n) + 1;
                        let next = backoff_after(fails);
                        info!(
                            target: "enrich",
                            "{}: no provider could be reached, leaving it for a \
                             later pass rather than recording an empty card \
                             (next try in {} min)",
                            row.key,
                            next.saturating_duration_since(std::time::Instant::now())
                                .as_secs()
                                .div_ceil(60)
                        );
                        unreached.insert(row.key.clone(), (fails, next));
                    } else {
                        // Providers answered and had nothing: the stamp
                        // below retires the row, so its backoff entry
                        // has nothing left to guard.
                        unreached.remove(&row.key);
                        let _ = d.with_index(|ix| {
                            ix.title_fill(&row.key, &Default::default(), now).ok()
                        });
                    }
                }
            }
        }
    }
}

/// How much disk the headshot cache may use. Person photos are ~15-40 KB
/// each, but a large index credits tens of thousands of people, and this
/// is the difference between a bounded cache and a NAS quietly filling up
/// with portraits. Least-recently-USED wins: the person pages someone
/// actually opens keep their art (the /art/ route touches the file on
/// each read), and the long tail is what goes.
#[cfg(feature = "indexer")]
pub(super) const PERSON_ART_CAP_BYTES: u64 = 192 * 1024 * 1024;

/// Headshot lane: fetch person photos the enricher recorded URLs for, and
/// keep the cache under its cap.
///
/// Deliberately its own thread and not part of a metadata lane. These are
/// CDN image reads, not API calls, so they must not spend any provider's
/// rate-limit budget - and a photo arriving late costs nothing, whereas a
/// card without a poster is visible.
#[cfg(feature = "indexer")]
pub(super) fn person_photo_fetcher(d: Arc<Daemon>) {
    let art = d.spool.join("art");
    let _ = std::fs::create_dir_all(&art);
    // Rows whose URL answered nothing this run. Kept in memory rather
    // than cleared in the db, because a transient CDN failure should be
    // retried next start, not treated as "this person has no photo".
    let mut failed: std::collections::HashSet<i64> = std::collections::HashSet::new();
    let mut after: i64 = 0;
    // Did this walk of the table actually fetch anything? A settled index
    // adds people rarely, so an idle walk backs off instead of re-asking
    // the same question every minute; a walk that found work resets to the
    // short interval, which is what makes a fresh enrichment show faces
    // within the minute rather than within the hour.
    let mut got_any = false;
    let mut idle_secs = 60u64;
    loop {
        // Before prune_person_art, which is a directory walk: an idle
        // walk of the art cache is exactly the disk work the switch
        // promises not to do.
        if d.park_if_off(60) {
            continue;
        }
        let batch = d
            .with_index(|ix| ix.people_photo_queue(after, 200).ok())
            .unwrap_or_default();
        if batch.is_empty() {
            // Walk done: prune, then start the cursor over so evicted
            // photos for people who are still credited come back.
            prune_person_art(&art, PERSON_ART_CAP_BYTES);
            after = 0;
            failed.clear();
            idle_secs = if got_any {
                60
            } else {
                (idle_secs * 2).min(900)
            };
            got_any = false;
            std::thread::sleep(std::time::Duration::from_secs(idle_secs));
            continue;
        }
        after = batch.last().map(|(id, _)| *id).unwrap_or(after);
        for (id, url) in batch {
            if failed.contains(&id) {
                continue;
            }
            let name = crate::wall::person_art_name(id);
            let path = art.join(&name);
            if path.is_file() {
                continue;
            }
            match crate::wall::fetch_image(&url) {
                Some(bytes) => {
                    let _ = std::fs::write(&path, &bytes);
                    got_any = true;
                }
                None => {
                    failed.insert(id);
                }
            }
            // A courtesy gap. Nothing here is urgent and a burst of image
            // requests at a provider's CDN is exactly the behaviour that
            // gets an anonymous client throttled.
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
        // Cheap to check mid-round, and it bounds the cache even when the
        // queue never empties.
        prune_person_art(&art, PERSON_ART_CAP_BYTES);
    }
}

/// Evict least-recently-used headshots until the cache fits `cap`.
///
/// Only `p<digits>.jpg` files are considered - posters and backdrops
/// share this directory and are NOT evictable (they are the wall, and
/// nothing re-fetches them on demand).
#[cfg(feature = "indexer")]
pub(super) fn prune_person_art(dir: &std::path::Path, cap: u64) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    let mut files: Vec<(std::time::SystemTime, u64, std::path::PathBuf)> = Vec::new();
    let mut total: u64 = 0;
    for e in rd.flatten() {
        let name = e.file_name();
        let Some(name) = name.to_str() else { continue };
        if !crate::wall::is_person_art_name(name) {
            continue;
        }
        let Ok(md) = e.metadata() else { continue };
        if !md.is_file() {
            continue;
        }
        total += md.len();
        // atime where the filesystem keeps it, mtime otherwise - the
        // point is "when was this last wanted", and a read-only serve
        // does not touch mtime.
        let when = md
            .accessed()
            .or_else(|_| md.modified())
            .unwrap_or(std::time::UNIX_EPOCH);
        files.push((when, md.len(), e.path()));
    }
    if total <= cap {
        return;
    }
    files.sort_by_key(|(when, _, _)| *when);
    let mut freed = 0u64;
    let mut n = 0;
    for (_, len, path) in &files {
        if total - freed <= cap {
            break;
        }
        if std::fs::remove_file(path).is_ok() {
            freed += len;
            n += 1;
        }
    }
    if n > 0 {
        info!(
            target: "wall",
            "headshot cache over {} MB - evicted {n} least-recently-used ({} MB)",
            cap / (1024 * 1024),
            freed / (1024 * 1024)
        );
    }
}

/// Nightly-ish IMDb ratings snapshot: keyless ~8 MB gz download from
/// datasets.imdbws.com, ingested wholesale into the index db. The wall
/// joins titles.imdb → imdb_ratings at query time, so every card with a
/// resolved tconst shows the real IMDb rating + vote count, offline.
#[cfg(feature = "indexer")]
pub(super) fn imdb_ratings_refresher(d: Arc<Daemon>) {
    loop {
        // MUST come before the staleness read. With no database the
        // `kv_get` below answers None, which this loop reads as "never
        // fetched" - so an indexer that is switched off would pull the
        // whole ratings dataset every six hours, forever, for a wall
        // nobody can open.
        if d.park_if_off(600) {
            continue;
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|t| t.as_secs() as i64)
            .unwrap_or(0);
        let stale = d
            .with_index(|ix| ix.kv_get("imdb_ratings_at"))
            .and_then(|s| s.parse::<i64>().ok())
            .is_none_or(|t| now - t > 20 * 3600);
        if stale {
            match crate::wall::imdb_ratings_fetch() {
                Some(rows) => {
                    let n = rows.len();
                    let ok = d
                        .with_index_mut(|ix| {
                            ix.imdb_ratings_replace(rows.into_iter()).ok()?;
                            ix.kv_set("imdb_ratings_at", &now.to_string()).ok()
                        })
                        .is_some();
                    info!(
                        target: "wall",
                        "IMDb ratings snapshot: {n} titles {}",
                        if ok { "ingested" } else { "FAILED to store" }
                    );
                }
                None => info!(target: "wall", "IMDb ratings snapshot download failed - will retry"),
            }
        }
        std::thread::sleep(std::time::Duration::from_secs(6 * 3600));
    }
}

/// The pre feed: two tasks, both inert unless the user has switched
/// it on.
///
/// Task 1 holds the IRC connection and does nothing but listen and
/// buffer. Task 2 owns every database write, so the listener never
/// takes the index write lock in the middle of a burst and cannot be
/// stalled by a scan pass holding it.
#[cfg(feature = "indexer")]
pub(super) fn spawn_predb_feed(daemon: &Arc<Daemon>) {
    {
        let daemon2 = daemon.clone();
        tokio::spawn(async move {
            // Ordinary failures - a dropped socket, a netsplit, DNS -
            // retry promptly and back off to half an hour.
            const RETRY_MIN: u64 = 30;
            const RETRY_MAX: u64 = 1_800;
            // Being told to go away is different in kind. A network that
            // has K-lined us will not change its mind in thirty seconds,
            // and a client that keeps asking is the reason bans get
            // widened. Hours, up to most of a day.
            const REJECT_MIN: u64 = 3_600;
            const REJECT_MAX: u64 = 21_600;
            // A connection that lasted this long counts as having
            // worked, so the next failure starts the ladder over.
            const SETTLED: u64 = 300;
            let mut retry = RETRY_MIN;
            let mut reject = REJECT_MIN;
            loop {
                if !daemon2.predb_feed_on() {
                    tokio::time::sleep(std::time::Duration::from_secs(15)).await;
                    continue;
                }
                let cfg = daemon2.predb_irc_config();
                if cfg.channels.is_empty() {
                    daemon2.predb_say("no channels configured");
                    tokio::time::sleep(std::time::Duration::from_secs(60)).await;
                    continue;
                }
                daemon2.predb_say(&format!("connecting to {}", cfg.host));
                let started = Instant::now();
                let heard = daemon2.clone();
                let quit = daemon2.clone();
                let stop = move || !quit.predb_feed_on();
                let reason = nzbkit::predb::run_once(
                    &cfg,
                    |m| {
                        let Some(line) = nzbkit::predb::parse_line(m.text) else {
                            return;
                        };
                        let mut pend = heard.predb_pending.lock_ok();
                        // Bounded. If the writer is wedged - a scan
                        // holding the lock through a long pass - the
                        // right failure is to lose the newest lines
                        // rather than to grow without limit inside a
                        // daemon whose memory budget is somebody's NAS.
                        if pend.len() < 20_000 {
                            pend.push(line);
                        }
                    },
                    &stop,
                )
                .await;
                let lasted = started.elapsed().as_secs();
                if lasted >= SETTLED {
                    retry = RETRY_MIN;
                    reject = REJECT_MIN;
                }
                let wait = match reason {
                    nzbkit::predb::IrcStop::Cancelled => {
                        daemon2.predb_say("stopped");
                        continue;
                    }
                    nzbkit::predb::IrcStop::Rejected(why) => {
                        // Said out loud in the log as well as the UI:
                        // this is the state where the honest advice is
                        // "leave it off", and a silent hourly retry
                        // would never say so.
                        warn!(
                            target: "predb",
                            "{} turned us away ({why}) - not trying again for {} minutes",
                            cfg.host,
                            reject / 60
                        );
                        daemon2.predb_say(&format!("refused by the server: {why}"));
                        let w = reject;
                        reject = (reject * 2).min(REJECT_MAX);
                        w
                    }
                    nzbkit::predb::IrcStop::Transient(why) => {
                        daemon2.predb_say(&format!("disconnected: {why}"));
                        let w = retry;
                        retry = (retry * 2).min(RETRY_MAX);
                        w
                    }
                };
                // Slept in slices so switching the feature off (or on
                // again) is felt in seconds rather than at the end of a
                // six-hour ban timer.
                for _ in 0..wait {
                    if !daemon2.predb_feed_on() {
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                }
            }
        });
    }
    {
        // Task 2: the only writer. Drains what the listener heard, then
        // matches it against the index - both directions - and keeps the
        // feed's own table capped.
        let daemon2 = daemon.clone();
        tokio::spawn(async move {
            // 90 days of pre lines, capped at whatever `predb_max_rows`
            // says (a quarter of a million by default). A pre line's
            // value decays with the post's retention, and at ~64 bytes
            // of keys per row the default is single-digit MB. The cap is
            // read per tick, not captured: raising it should take effect
            // without a restart, and the seed importer reads the SAME
            // number so it can refuse rather than import into a prune.
            const KEEP_SECS: i64 = 90 * 86_400;
            // Per tick. Small on purpose: this runs beside a scanner and
            // a download, and there is no deadline on naming a post.
            const SWEEP_BUDGET: u32 = 200;
            const BACKLOG_BUDGET: u32 = 200;
            // The split-merge and sidecar-fold walks hold the
            // shared index write mutex for their whole call, and the
            // pause predicate is only consulted BETWEEN legs - so the
            // per-call time budget is what keeps any single leg from
            // parking ingest, the API and a starting download behind
            // it for tens of seconds (observed live, 5 Aug).
            const WALK_BUDGET: std::time::Duration = std::time::Duration::from_secs(1);
            let mut last_prune = 0i64;
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(20)).await;
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|t| t.as_secs() as i64)
                    .unwrap_or(0);
                // Drain first and unconditionally: lines already heard
                // are cheap to store and losing them to a pause would
                // mean losing the announcement entirely. The MATCHING
                // below is what respects the pause.
                let batch: Vec<nzbkit::predb::PreLine> =
                    std::mem::take(&mut *daemon2.predb_pending.lock_ok());
                if !batch.is_empty() {
                    let n = batch.len();
                    let stored = daemon2.with_index_mut(|ix| ix.predb_store(&batch, now).ok());
                    match stored {
                        Some(nameable) => {
                            info!(
                                target: "predb",
                                "{n} pre line(s) stored, {nameable} carrying a posted filename"
                            );
                            daemon2.predb_say(&format!("listening - {n} line(s) just in"));
                        }
                        None => {
                            // The index was unavailable (switched off, or
                            // locked). Put them back rather than drop
                            // them; the cap above is what bounds this.
                            let mut pend = daemon2.predb_pending.lock_ok();
                            let keep = 20_000usize.saturating_sub(pend.len());
                            let mut back = batch;
                            back.truncate(keep);
                            back.append(&mut pend);
                            *pend = back;
                        }
                    }
                }
                if !daemon2.predb_enabled.load(Ordering::Relaxed) {
                    continue;
                }
                // Matching is index work: it stands down for a download
                // exactly like every other index maintenance leg.
                if daemon2.indexing_pause_reason().is_some() {
                    continue;
                }
                // §74 hook B: a release that gains a name here was an
                // obfuscated stem no watchlist entry could ever match, so
                // naming it IS an arrival. Installed once for the whole
                // tick and drained at the end of it - every naming leg
                // below funnels through the same seam inside the index.
                let matcher = daemon2.instant_matcher();
                daemon2.with_index_mut(|ix| {
                    install_instant_watch(ix, matcher);
                    Some(())
                });
                if let Some((tried, named)) =
                    daemon2.with_index_mut(|ix| ix.predb_sweep(SWEEP_BUDGET, now).ok())
                    && named > 0
                {
                    info!(target: "predb", "{named} indexed release(s) named from {tried} pre line(s)");
                }
                if daemon2.indexing_pause_reason().is_some() {
                    continue;
                }
                if let Some((_, named)) = daemon2
                    .with_index_mut(|ix| ix.predb_backlog(BACKLOG_BUDGET, KEEP_SECS, now).ok())
                    && named > 0
                {
                    info!(target: "predb", "{named} older release(s) named from the feed");
                }
                // One-time hygiene: fold pre-fix split-container
                // fragments back into whole releases. Independent of
                // the predb switches (fragmentation hurts everything),
                // parks permanently once the walk completes, and its
                // completion re-opens the correlation walks via the
                // seed generation.
                if daemon2.indexing_pause_reason().is_none()
                    && let Some((g, n, done)) = daemon2.with_index_mut(|ix| {
                        // An error here must be SAID: a silent Err loops
                        // forever looking exactly like "nothing to do".
                        match ix.split_merge(now, WALK_BUDGET) {
                            Ok(t) => Some(t),
                            Err(e) => {
                                warn!(target: "index", "split-set merge error: {e}");
                                None
                            }
                        }
                    })
                {
                    if g > 0 {
                        info!(
                            target: "index",
                            "split-set merge: {n} fragment(s) folded into {g} release(s)"
                        );
                    }
                    if done && g + n > 0 {
                        info!(target: "index", "split-set merge complete - correlation will re-walk");
                    }
                }
                // §87 the par2-sidecar fold: a split posting's recovery
                // set lands as its own par2-only row on the bare base
                // stem (88% of split-container rows have one). Folding
                // it in kills the junk row and gives the container a
                // true has_par2, closing the hidden-par2 scoring leak.
                // Not one-time: ingest keeps producing pairs, so the
                // walk parks at the top id and follows it.
                if daemon2.indexing_pause_reason().is_none()
                    && let Some((p, f)) = daemon2.with_index_mut(|ix| {
                        // Same rule as above: an error must be SAID.
                        match ix.par2_sidecar_fold(WALK_BUDGET) {
                            Ok((p, f, _)) => Some((p, f)),
                            Err(e) => {
                                warn!(target: "index", "par2 sidecar fold error: {e}");
                                None
                            }
                        }
                    })
                    && p > 0
                {
                    info!(
                        target: "index",
                        "par2 sidecar fold: {p} sidecar row(s) folded in ({f} par2 file(s))"
                    );
                }
                // Phase 2: the correlation legs, behind their own
                // switch. Same stand-down discipline as the exact legs;
                // budgets smaller because each row costs a window query.
                if daemon2.predb_corr_enabled.load(Ordering::Relaxed) {
                    const CORR_SWEEP_BUDGET: u32 = 100;
                    // Sized against the population, not caution: the
                    // obfuscated backlog measured 27.5M rows on the
                    // first live run, and 50/tick walks that in months.
                    // 400 evals cost well under a second inside the
                    // tick and still stand down for any download.
                    const CORR_BACKLOG_BUDGET: u32 = 400;
                    // How far back the corr backlog bothers: generous
                    // enough to cover a full seed import window.
                    const CORR_WINDOW: i64 = 366 * 86_400;
                    let auto = daemon2.predb_corr_auto.load(Ordering::Relaxed);
                    if daemon2.indexing_pause_reason().is_none()
                        && let Some((_, s, a)) = daemon2.with_index_mut(|ix| {
                            ix.predb_corr_sweep(CORR_SWEEP_BUDGET, auto, now).ok()
                        })
                        && s + a > 0
                    {
                        info!(target: "predb", "correlation (live): {s} suggestion(s), {a} auto-applied");
                    }
                    if daemon2.indexing_pause_reason().is_none()
                        && let Some((_, s, a)) = daemon2.with_index_mut(|ix| {
                            ix.predb_corr_backlog(CORR_BACKLOG_BUDGET, CORR_WINDOW, auto, now)
                                .ok()
                        })
                        && s + a > 0
                    {
                        info!(
                            target: "predb",
                            "correlation (backlog): {s} suggestion(s), {a} auto-applied"
                        );
                    }
                    // The catch-up pass: one walk over every sized pre
                    // (seeds included) per seed generation. This is the
                    // leg that actually covers a fresh import - see the
                    // population arithmetic on predb_corr_catchup.
                    const CORR_CATCHUP_BUDGET: u32 = 150;
                    if daemon2.indexing_pause_reason().is_none()
                        && let Some((n, s, a)) = daemon2.with_index_mut(|ix| {
                            ix.predb_corr_catchup(CORR_CATCHUP_BUDGET, auto, now).ok()
                        })
                        && n > 0
                        && s + a > 0
                    {
                        info!(
                            target: "predb",
                            "correlation (catch-up): {s} suggestion(s), {a} auto-applied"
                        );
                    }
                }
                if now - last_prune >= 3_600 && daemon2.index_maintenance_ok() {
                    last_prune = now;
                    let keep_rows = daemon2.predb_max_rows.load(Ordering::Relaxed);
                    // `.ok()` used to fold the error into the same None
                    // the "no index" case returns, and `last_prune` was
                    // advanced before the call - so a failure was both
                    // silent and lost for a full hour. That matters more
                    // since the prune became ONE transaction: a `?`
                    // anywhere inside rolls the whole thing back, where
                    // the old autocommitting version at least kept what
                    // its first statement had done. SQLITE_BUSY from the
                    // maintenance/VACUUM machinery is the ordinary way
                    // in, and the feed then grows past both its row cap
                    // and its retention window with nothing said.
                    match daemon2.with_index(|ix| Some(ix.predb_prune(keep_rows, KEEP_SECS, now))) {
                        Some(Ok(n)) if n > 0 => {
                            info!(
                                target: "predb",
                                "pruned {n} pre line(s) past the retention window"
                            );
                        }
                        Some(Err(e)) => {
                            // Retry sooner than the hour, but not on the
                            // next 20 s tick: whatever the prune was
                            // contending with deserves room to finish.
                            last_prune = now.saturating_sub(3_000);
                            warn!(
                                target: "predb",
                                "prune failed and rolled back, retrying in ~10 min: {e}"
                            );
                        }
                        _ => {}
                    }
                }
                // §74 hook B, the other half: whatever the naming legs
                // rescued this tick, offered to the watchlist. A named
                // release is nearly always an old post that is long
                // complete, so most of these go straight to a pass.
                if let Some((hits, dropped)) =
                    daemon2.with_index_mut(|ix| Some(ix.take_watch_hits()))
                {
                    instant_arrivals(&daemon2, hits, dropped, now);
                }
            }
        });
    }
}

/// M14g scheduler: JSON list of {days, time, action, value} entries,
/// evaluated once per minute in the machine's LOCAL timezone. On
/// startup the whole week is re-evaluated so a restart lands in the
/// state the schedule implies. Entries live in the daemon (settings
/// UI can replace them); a UI-saved schedule wins over --schedule.
pub(super) fn spawn_scheduler(
    daemon: &Arc<Daemon>,
    settings_path: &std::path::Path,
    schedule: &Option<PathBuf>,
) -> Result<()> {
    let saved_text = load_settings(settings_path)
        .get("schedule")
        .and_then(Value::as_str)
        .map(str::to_string);
    let text = match (saved_text, &schedule) {
        // Empty saved text = "no schedule" chosen in the UI.
        (Some(t), _) => (!t.is_empty()).then_some(t),
        (None, Some(path)) => Some(
            std::fs::read_to_string(path)
                .map_err(|e| anyhow::anyhow!("--schedule {}: {e}", path.display()))?,
        ),
        (None, None) => None,
    };
    if let Some(text) = text {
        let entries = parse_schedule(&text).map_err(|e| anyhow::anyhow!("schedule: {e}"))?;
        let (paused, limit) = effective_state(&entries, local_minute_of_week());
        // Through the one mutator, so a timed pause restored from the
        // spool just above cannot outlive the schedule's own verdict
        // on the current hour. No running job here for the wind-down
        // to touch, so this is otherwise unchanged.
        if let Some(p) = paused {
            apply_action(
                daemon,
                if p {
                    SchedAction::Pause
                } else {
                    SchedAction::Resume
                },
            );
            info!(
                target: "schedule",
                "startup: {}",
                if p { "paused" } else { "resumed" }
            );
        }
        if let Some(l) = limit {
            daemon.set_speed_ceiling_from(l, "schedule");
            info!(target: "schedule", "startup: speedlimit {:.1} KB/s", l as f64 / 1e3);
        }
        *daemon.schedule.lock_ok() = entries;
        *daemon.schedule_text.lock_ok() = text;
    }
    let d = daemon.clone();
    tokio::spawn(async move {
        let mut last = local_minute_of_week();
        loop {
            // Half-minute tick so every minute boundary is seen promptly.
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            let now = local_minute_of_week();
            // DST fall-back (or a clock step) moves local time
            // BACKWARDS: the forward distance around the week would be
            // huge - resync silently instead of replaying the week.
            let forward = (now + WEEK_MINUTES - last) % WEEK_MINUTES;
            if forward > 8 * 60 {
                last = now;
                continue;
            }
            let entries = d.schedule.lock_ok().clone();
            while last != now {
                last = (last + 1) % WEEK_MINUTES;
                for e in entries.iter().filter(|e| e.fires_at(last)) {
                    info!(target: "schedule", "{:?}", e.action);
                    apply_action(&d, e.action);
                }
            }
        }
    });
    Ok(())
}

/// The reasons a watch-folder file ends up listed rather than ingested.
///
/// Written as constants, and read back by [`watch_fail_kind`], because
/// four of the six are SUCCESSES: the release is queued (or was
/// downloaded weeks ago) and only the file on disk is unresolved. One
/// sentence for all six told a user their download "couldn't be read"
/// when it had in fact already finished, and offered a Delete that is
/// harmless for some of them and destroys the only copy for others.
/// Keeping the strings and the classifier in one place is what stops the
/// two drifting: an edit to a message that forgets the mapping would
/// silently demote that state back to the generic sentence.
pub(super) mod watchfail {
    /// No closing `</nzb>`, and the file has stopped growing. NOT
    /// ingested - the only state where the user must act on the file.
    pub(crate) const TRUNCATED: &str = "truncated: no closing </nzb>";
    /// The identical NZB is already sitting in the queue.
    pub(crate) const ALREADY_QUEUED: &str = "already queued";
    /// ...and this one already finished downloading.
    pub(crate) const ALREADY_DONE: &str = "already downloaded";
    /// Queued, but the queue record could not be persisted, so the file
    /// is deliberately KEPT as the recovery copy.
    pub(crate) const UNSAVED: &str = "queued, but queue.json could not be written";
    /// Queued and durable, but the source file could not be removed.
    /// Prefix: the OS error is appended.
    pub(crate) const KEPT: &str = "queued, but the file could not be removed";
}

/// Which of the six [`watchfail`] states a listed file is in, as a token
/// the dashboard switches on. `"rejected"` is the sixth: an `enqueue`
/// error, i.e. the only case besides `truncated` where the file really
/// could not be used.
/// Opaque, stable identity for one tracked watch-folder rejection
/// (Codex sweep 2, 3 Aug L1).
///
/// The queue payload names these rows by basename, which is not an
/// identity: change the watch directory and a rejected `same.nzb` can
/// be tracked in both the old and the new one, leaving the user two
/// identical-looking rows and the delete handler picking whichever
/// HashMap iteration reached first. A digest of the FULL path names the
/// row exactly. Truncated to 16 hex chars - this is a handle for a set
/// with a handful of members, not a credential - and deliberately not
/// the path itself, which the browser has no business holding.
pub(crate) fn watch_fail_id(path: &std::path::Path) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(path.as_os_str().as_encoded_bytes());
    format!("{:x}", h.finalize())[..16].to_string()
}

pub(crate) fn watch_fail_kind(msg: &str) -> &'static str {
    if msg == watchfail::TRUNCATED {
        "truncated"
    } else if msg == watchfail::ALREADY_QUEUED {
        "queued"
    } else if msg == watchfail::ALREADY_DONE {
        "done"
    } else if msg == watchfail::UNSAVED {
        "unsaved"
    } else if msg.starts_with(watchfail::KEPT) {
        "kept"
    } else {
        "rejected"
    }
}

/// Is this listed file's release actually in hand? True for the four
/// states where the queue (or history) owns it and only the file on disk
/// is unfinished business - which is exactly the set where deleting the
/// file is safe and "couldn't be read" is a lie.
pub(crate) fn watch_fail_ingested(kind: &str) -> bool {
    matches!(kind, "queued" | "done" | "unsaved" | "kept")
}

/// Watch-folder poller. Always running; the folder itself is a live
/// setting (None = idle), so the dashboard can point it elsewhere or
/// turn it off without a restart.
pub(super) fn spawn_watch_folder(daemon: &Arc<Daemon>) {
    let d = daemon.clone();
    tokio::spawn(async move {
        // (mtime, len) of every .nzb this folder held on the previous
        // pass. A file copied in over SMB/NFS is visible from its first
        // byte, and a half-written NZB still parses - the XML reader
        // simply stops at the last whole <file> - so reading on sight
        // queued a fraction of the release and then deleted the user's
        // original. A file is ingested once it is provably whole (its
        // closing </nzb> is on disk) or, failing that, once its size and
        // mtime have held still for a full pass. The
        // in-progress suffixes (.part/.tmp/.crdownload/.filepart) need
        // no list of their own - they aren't .nzb, so the extension
        // gate drops them until the writer renames.
        let mut prev_pass: std::collections::HashMap<PathBuf, (u64, u64)> =
            std::collections::HashMap::new();
        // Keep-mode processed marker: path -> (mtime, len, nzb_sha) of
        // every file ingested while "keep the .nzb" was on. Deleting
        // the file WAS the durable consumed-marker; when the file
        // stays, this set is what stops the next pass - and the next
        // daemon START, hence persisted beside the spool - from
        // re-downloading the whole folder. A re-save changes the
        // signature and falls out of the set, so "re-save it to retry"
        // stays true in keep mode too. The sha is recorded for
        // debugging only; skipping compares (mtime, len) alone, so a
        // settled file costs a stat per pass, never a read.
        let seen_path = d.spool.join("watch_seen.json");
        let mut watch_seen: std::collections::HashMap<PathBuf, (u64, u64, String)> =
            std::fs::read(&seen_path)
                .ok()
                .and_then(|b| serde_json::from_slice(&b).ok())
                .unwrap_or_default();
        fn save_watch_seen(
            path: &std::path::Path,
            seen: &std::collections::HashMap<PathBuf, (u64, u64, String)>,
        ) {
            // Best-effort like save_queue: a failed write costs one
            // re-dedupe against the queue/history shas after a restart,
            // never a wrong download.
            if let Ok(b) = serde_json::to_vec(seen) {
                let _ = std::fs::write(path, b);
            }
        }
        // Filesystem notifications, so a drop is picked up in the time
        // it takes to write the file rather than on the next poll.
        //
        // Kept deliberately dumb: every event just pokes the same loop,
        // which then does the identical pass it would have done on its
        // timer. Nothing about correctness depends on the watcher - it
        // only decides WHEN a pass happens - so a platform where it
        // silently delivers nothing degrades to exactly the old
        // behaviour rather than to a folder that is never read.
        //
        // Re-armed whenever the folder changes (it is a live setting,
        // and it starts out unset on a fresh install), and dropped with
        // the old path so a stale watch cannot keep firing.
        let mut _fs_watch: Option<notify::RecommendedWatcher> = None;
        let mut watched: Option<PathBuf> = None;
        loop {
            let dir = d.watch_dir.lock_ok().clone();
            // (Re)arm the filesystem watch when the configured folder
            // changes. Failure is not fatal and not even noteworthy on
            // a share: the poll below still runs.
            // Re-arm when the folder changes, AND retry while unarmed:
            // a failed attach used to latch forever (the arm only ran on
            // a config change), which left the watcher dead and the
            // folder on pure 5 s polling for the daemon's whole life -
            // exactly the "drops feel slow" a user reports. The warning
            // still prints once per configured path, not once per retry.
            if watched != dir || (_fs_watch.is_none() && dir.is_some()) {
                let fresh = watched != dir;
                _fs_watch = None;
                watched = dir.clone();
                if let Some(ref path) = dir {
                    // FSEvents (and inotify by-path lookups) want an
                    // absolute path: the daemon is launched with
                    // `--watch watch`, and the bare relative form failed
                    // with "No path was found" while the poll fallback
                    // masked it. Canonicalize, falling back to cwd-join
                    // for a folder that does not exist yet.
                    let abs = std::fs::canonicalize(path).unwrap_or_else(|_| {
                        std::env::current_dir()
                            .map(|c| c.join(path))
                            .unwrap_or_else(|_| path.clone())
                    });
                    let d2 = d.clone();
                    match notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
                        if res.is_ok() {
                            d2.watch_scan_now.notify_one();
                        }
                    }) {
                        Ok(mut w) => {
                            use notify::Watcher;
                            match w.watch(&abs, notify::RecursiveMode::NonRecursive) {
                                Ok(()) => {
                                    _fs_watch = Some(w);
                                    info!(
                                        target: "watch",
                                        "watching {} - drops are picked up on the event, \
                                         with a {}s polling backstop",
                                        abs.display(),
                                        d.watch_interval_secs.load(Ordering::Relaxed)
                                    );
                                }
                                Err(e) if fresh => warn!(
                                    target: "watch",
                                    "{} is polled every {}s - the filesystem \
                                     watcher could not attach ({e}); this is normal on a \
                                     network share (still retrying quietly)",
                                    abs.display(),
                                    d.watch_interval_secs.load(Ordering::Relaxed)
                                ),
                                Err(_) => {}
                            }
                        }
                        Err(e) => {
                            if fresh {
                                warn!(target: "watch", "no filesystem watcher ({e}); polling");
                            }
                        }
                    }
                }
            }
            if let Some(dir) = dir {
                // The pass is all stats and whole-file reads - and the
                // watched folder is often an SMB/NFS share, where any of
                // them can stall. It runs on a tokio worker, so demote
                // the thread for the pass (there is no await anywhere
                // inside it).
                crate::persist::blocking_db(|| {
                    if let Ok(entries) = std::fs::read_dir(&dir) {
                        let mut this_pass = std::collections::HashMap::new();
                        for e in entries.flatten() {
                            let p = e.path();
                            if !p.extension().is_some_and(|x| x.eq_ignore_ascii_case("nzb")) {
                                continue;
                            }
                            // A file that already failed is skipped until
                            // its mtime or size changes (re-saving it is
                            // the user's retry).
                            let Some(sig) = watch_sig(&p) else { continue };
                            let settled = prev_pass.get(&p) == Some(&sig);
                            this_pass.insert(p.clone(), sig);
                            // Ingested earlier with keep-mode on and unchanged
                            // since: already downloaded from here. Checked
                            // before anything reads the file, so a kept
                            // folder full of settled .nzbs costs stats, not
                            // reads - and never lands in watch_failed as an
                            // "already queued" warning it does not deserve.
                            if watch_seen.get(&p).is_some_and(|(t, l, _)| (*t, *l) == sig) {
                                continue;
                            }
                            // Completeness is now the gate, and stillness
                            // only decides when to give up waiting for it.
                            //
                            // Stillness ALONE used to be the gate, and it is
                            // not sound: a copy that stalls for two passes
                            // looks identical to a finished one, and a clean
                            // cut between </file> and </nzb> parses happily
                            // as a SHORTER release. Measured on a stalled
                            // 2-file nzb truncated after the first </file>:
                            // queued as a 1-file release, and the user's
                            // original deleted behind it - unrecoverable,
                            // and silent. That predates the watcher; it is
                            // just reachable in 5 s rather than never.
                            //
                            // So an incomplete file is never ingested. If it
                            // also stops changing, say so and stop retrying
                            // it - a visible complaint with the file still on
                            // disk beats a fragment queued in its place.
                            let complete = std::fs::read(&p)
                                .ok()
                                .is_some_and(|b| nzb_looks_complete(&b));
                            if !complete {
                                if settled {
                                    let mut failed = d.watch_failed.lock_ok();
                                    if !failed.contains_key(&p) {
                                        info!(
                                            target: "watch",
                                            "{} looks truncated - no closing </nzb> tag, \
                                             and it has stopped changing. Left alone; re-save it \
                                             to retry.",
                                            p.display()
                                        );
                                        failed.insert(
                                            p.clone(),
                                            (
                                                sig.0,
                                                sig.1,
                                                watchfail::TRUNCATED.into(),
                                                String::new(),
                                            ),
                                        );
                                    }
                                }
                                continue;
                            }
                            if d.watch_failed
                                .lock()
                                .unwrap()
                                .get(&p)
                                .is_some_and(|(t, l, _, _)| (*t, *l) == sig)
                            {
                                continue;
                            }
                            if let Ok(bytes) = std::fs::read(&p) {
                                // Re-check the signature AFTER the read.
                                // The settle test compared two passes and
                                // then read seconds later, so a re-save
                                // landing in that window was read as a
                                // torn prefix - which still parses, since
                                // the XML reader simply stops at the last
                                // whole <file> - queued as if it were the
                                // whole release, and then the user's
                                // freshly written file was DELETED below.
                                // That is the exact outcome the two-pass
                                // settle exists to prevent, surviving in
                                // the gap between the stat and the read.
                                if watch_sig(&p) != Some(sig) {
                                    info!(
                                        target: "watch",
                                        "{} changed while being read - leaving it \
                                         for the next pass",
                                        p.display()
                                    );
                                    continue;
                                }
                                // Is this exact NZB already waiting in the
                                // queue? Deleting the file was the only
                                // durable "consumed" marker, and the
                                // in-memory skip list does not survive a
                                // restart - so a share that refuses the
                                // unlink, a crash between the queue write
                                // and the delete, or a deliberately-kept
                                // file after ENOSPC all meant the next
                                // start downloaded the whole release
                                // again. A name without an SxxEyy or year
                                // has no dupe_key to catch it either.
                                // The queue IS persisted, so ask it.
                                let sha = nzb_sha(&bytes);
                                // The id, not just the fact: the strip's whole
                                // job here is to point at the record that made
                                // this file redundant, and a name lookup in the
                                // page picks the wrong row for a re-post.
                                let queued_id = d.queue.lock_ok().iter().find_map(|j| {
                                    let g = j.lock_ok();
                                    (g.nzb_sha == sha).then(|| g.nzo_id.clone())
                                });
                                if let Some(queued_id) = queued_id {
                                    info!(
                                        target: "watch",
                                        "{} is already queued - leaving the file \
                                         alone rather than downloading it twice",
                                        p.display()
                                    );
                                    d.watch_failed.lock_ok().insert(
                                        p.clone(),
                                        (sig.0, sig.1, watchfail::ALREADY_QUEUED.into(), queued_id),
                                    );
                                    continue;
                                }
                                // ...and once it finishes, it is not in the
                                // queue any more - it is in HISTORY, which is
                                // persisted through the same file and carries
                                // the same nzb_sha. Asking only the queue meant
                                // a source file that cannot be deleted (a
                                // read-only share, a NAS that refuses the
                                // unlink) was re-ingested on every single
                                // daemon start, re-downloading the whole
                                // release each time; the in-memory skip list
                                // covers the running process and nothing more.
                                //
                                // Completed rows only. A FAILED job's source
                                // file is exactly the one a user wants
                                // retried - a takedown that later refills, a
                                // provider outage - so a failure must not
                                // become a permanent refusal to look at it.
                                let done = d.history.lock_ok().iter().find_map(|j| {
                                    let j = j.lock_ok();
                                    (j.nzb_sha == sha && j.state == JobState::Completed)
                                        .then(|| j.nzo_id.clone())
                                });
                                if let Some(done_id) = done {
                                    info!(
                                        target: "watch",
                                        "{} has already been downloaded - leaving the \
                                         file alone rather than downloading it twice. To \
                                         download it again, delete its History entry first, \
                                         or add the NZB from the dashboard",
                                        p.display()
                                    );
                                    d.watch_failed.lock_ok().insert(
                                        p.clone(),
                                        (sig.0, sig.1, watchfail::ALREADY_DONE.into(), done_id),
                                    );
                                    continue;
                                }
                                let name = p
                                    .file_name()
                                    .unwrap_or_default()
                                    .to_string_lossy()
                                    .to_string();
                                // The success path is the one moment nothing
                                // explained: the file simply vanishes from
                                // the folder (a browser's download list says
                                // "Removed", and Gary read that as nzbfast
                                // deleting his download). Say it in the log,
                                // and remember it so an open dashboard can
                                // toast it - named by the folder it came
                                // from, which is what the user recognises.
                                let folder = dir
                                    .file_name()
                                    .map(|f| f.to_string_lossy().to_string())
                                    .unwrap_or_else(|| dir.display().to_string());
                                let note_pickup = || {
                                    info!(
                                        target: "watch",
                                        "picked up {name} from {folder} - queued"
                                    );
                                    let mut wp = d.watch_picked.lock_ok();
                                    wp.push_back((name.clone(), folder.clone(), unix_now()));
                                    while wp.len() > 8 {
                                        wp.pop_front();
                                    }
                                };
                                match d.enqueue(&bytes, &name, "", -100, None, "watch", false) {
                                    // Delete the user's file only once the
                                    // queue record is DURABLE.
                                    //
                                    // `enqueue` persists best-effort and
                                    // returns Ok either way, and this deleted
                                    // on Ok - so ENOSPC or EIO on queue.json
                                    // plus a later crash lost both the record
                                    // and the source, with nothing left to
                                    // recover from. The job is live in memory
                                    // regardless, so on a failed commit we
                                    // keep their .nzb and record the failure:
                                    // that stops the next scan re-enqueueing a
                                    // duplicate, and leaves the file to be
                                    // picked up if the daemon does restart.
                                    Ok(_) if d.save_queue() => {
                                        note_pickup();
                                        // Keep-mode: the user wants the file
                                        // (collectors, sharing it for a bug
                                        // report), so the durable marker is
                                        // the seen-set instead of the
                                        // deletion. Read live, per pickup.
                                        if d.watch_keep_nzb.load(Ordering::Relaxed) {
                                            watch_seen
                                                .insert(p.clone(), (sig.0, sig.1, sha.clone()));
                                            save_watch_seen(&seen_path, &watch_seen);
                                            d.watch_failed.lock_ok().remove(&p);
                                            continue;
                                        }
                                        // The queue owns the release now, so
                                        // the source goes. If it can't be
                                        // removed (read-only bind mount, no
                                        // unlink right on the share) it has
                                        // to be remembered exactly like a
                                        // failure is: otherwise every pass
                                        // re-reads the same bytes and the
                                        // release is queued - and fetched
                                        // from the provider - all over again,
                                        // once every 5 s, forever.
                                        // To the Trash, not gone: this is
                                        // the user's own .nzb, and "I dropped
                                        // it in and now I cannot find it
                                        // again" is a real complaint.
                                        match crate::smart::remove_user_file(
                                            &p,
                                            crate::smart::delete_to_trash(),
                                        ) {
                                            Ok(_) => {
                                                // Forget the signature with the
                                                // file: a re-drop of the same
                                                // .nzb at the same path would
                                                // otherwise match the record we
                                                // just ingested (mtime-
                                                // preserving copies reproduce it
                                                // exactly) and count as settled
                                                // on sight - the very thing the
                                                // pass memory exists to stop.
                                                this_pass.remove(&p);
                                                d.watch_failed.lock_ok().remove(&p);
                                            }
                                            Err(err) => {
                                                warn!(
                                                    target: "watch",
                                                    "{name} queued, but {} could not be \
                                                     removed - {err}; delete it yourself or it \
                                                     stays listed",
                                                    p.display()
                                                );
                                                d.watch_failed.lock_ok().insert(
                                                    p,
                                                    (
                                                        sig.0,
                                                        sig.1,
                                                        format!("{}: {err}", watchfail::KEPT),
                                                        String::new(),
                                                    ),
                                                );
                                            }
                                        }
                                    }
                                    Ok(_) => {
                                        // Queued in memory even though the
                                        // save failed, so the pickup is
                                        // still worth announcing.
                                        note_pickup();
                                        warn!(
                                            target: "watch",
                                            "{name} queued but the queue could not be \
                                             saved - keeping your file at {}",
                                            p.display()
                                        );
                                        d.watch_failed.lock_ok().insert(
                                            p,
                                            (
                                                sig.0,
                                                sig.1,
                                                watchfail::UNSAVED.to_string(),
                                                String::new(),
                                            ),
                                        );
                                    }
                                    Err(err) => {
                                        info!(target: "watch", "{name} rejected: {err}");
                                        d.watch_failed.lock_ok().insert(
                                            p,
                                            (sig.0, sig.1, err.to_string(), String::new()),
                                        );
                                    }
                                }
                            }
                        }
                        // Only names this pass actually saw carry over, so
                        // an ingested or deleted file leaves nothing behind.
                        prev_pass = this_pass;
                    }
                    // Files the user deleted or moved drop off the list.
                    d.watch_failed.lock_ok().retain(|p, _| p.exists());
                    // ...and off the keep-mode seen-set, so it never grows
                    // past what the folder actually holds. Persisted only
                    // when something actually left.
                    let before = watch_seen.len();
                    watch_seen.retain(|p, _| p.exists());
                    if watch_seen.len() != before {
                        save_watch_seen(&seen_path, &watch_seen);
                    }
                });
            }
            // Wake on whichever comes first: the backstop interval, or
            // the filesystem watcher saying the folder changed. The poll
            // cannot be dropped - a write made on another host to an
            // SMB/NFS mount produces no local event at all - but on a
            // real local folder the notify arm is what makes a drop feel
            // instant instead of costing up to two five-second passes.
            let every = d.watch_interval_secs.load(Ordering::Relaxed).clamp(1, 3600);
            tokio::select! {
                _ = tokio::time::sleep(std::time::Duration::from_secs(every)) => {}
                _ = d.watch_scan_now.notified() => {
                    // Let the writer finish the burst it is in the middle
                    // of rather than reading on the first CREATE event.
                    // A whole file then passes nzb_looks_complete on this
                    // very pass; a partial one waits for the next.
                    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                }
            }
        }
    });
}

/// Post-job memory trim. A finished job frees its pipeline buffers,
/// but the allocator keeps those pages resident for reuse - which
/// reads as a leak on the dashboard's RAM line. Once the daemon has
/// been idle for a full minute after a download, hand the retained
/// pages back to the OS; the next download simply faults fresh ones
/// in. One trim per idle period, none at startup.
pub(super) fn spawn_memory_trim(daemon: &Arc<Daemon>) {
    let d = daemon.clone();
    tokio::spawn(async move {
        let mut idle_since: Option<Instant> = None;
        let mut trimmed = true; // nothing worth trimming before the first job
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(15)).await;
            if d.started_at.lock_ok().is_some() {
                idle_since = None;
                trimmed = false;
                continue;
            }
            let since = *idle_since.get_or_insert_with(Instant::now);
            if !trimmed && since.elapsed() >= std::time::Duration::from_secs(60) {
                trimmed = true;
                let before = nzbkit::mem::dashboard_rss().unwrap_or(0);
                // mimalloc (macOS + Linux): force a collection - the
                // call that actually offers the pages back. On macOS the
                // system allocator's pressure_relief is a measured no-op;
                // on Linux mimalloc owns the heap so glibc malloc_trim
                // below no longer sees the pipeline arenas.
                #[cfg(any(target_os = "macos", target_os = "linux"))]
                unsafe {
                    libmimalloc_sys::mi_collect(true)
                };
                nzbkit::mem::trim(); // glibc malloc_trim; no-op under mimalloc
                let after = nzbkit::mem::dashboard_rss().unwrap_or(0);
                let freed = before.saturating_sub(after);
                if freed >= 64 << 20 {
                    info!(
                        target: "mem",
                        "idle after download - returned {:.0} MB of retained buffers to the OS",
                        freed as f64 / 1e6
                    );
                }
            }
        }
    });
}

/// M14g3 auto-speed governor: a dedicated probe connection measures
/// DATE round-trips to the first server at 1 Hz. Base RTT = 10-minute
/// sliding minimum; queueing delay = smoothed − base. While a download
/// runs (and the toggle is on) each sample drives one AIMD step of the
/// shared RateLimit, under the user/schedule ceiling. One extra NNTP
/// connection is the entire cost.
pub(super) fn spawn_auto_speed(daemon: &Arc<Daemon>, config: &std::path::Path) {
    let d = daemon.clone();
    let config = config.to_path_buf();
    tokio::spawn(async move {
        use nzbkit::nntp::Connection;
        let mut window: VecDeque<(Instant, u64)> = VecDeque::new();
        let mut smoothed: f64 = 0.0;
        loop {
            if !d.auto_speed.load(Ordering::Relaxed) {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                continue;
            }
            let server = match nzbkit::config::Config::load(&config) {
                Ok(c) => c.servers.first().cloned(),
                Err(_) => None,
            };
            let Some(server) = server else {
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                continue;
            };
            let Ok((mut conn, _)) = Connection::connect(&server).await else {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                continue;
            };
            loop {
                if !d.auto_speed.load(Ordering::Relaxed) {
                    conn.quit().await;
                    break;
                }
                let t0 = Instant::now();
                let ok = tokio::time::timeout(std::time::Duration::from_secs(5), conn.exec("DATE"))
                    .await;
                let rtt = t0.elapsed().as_millis().max(1) as u64;
                match ok {
                    Ok(Ok(_)) => {
                        let now = Instant::now();
                        window.push_back((now, rtt));
                        while window
                            .front()
                            .is_some_and(|(t, _)| now.duration_since(*t).as_secs() > 600)
                        {
                            window.pop_front();
                        }
                        let base = window.iter().map(|(_, r)| *r).min().unwrap_or(rtt);
                        smoothed = if smoothed == 0.0 {
                            rtt as f64
                        } else {
                            smoothed * 0.7 + rtt as f64 * 0.3
                        };
                        let downloading = d.started_at.lock_ok().is_some();
                        if downloading {
                            let delay = (smoothed as u64).saturating_sub(base);
                            let cap = auto_speed_step(
                                delay,
                                AUTO_SPEED_TARGET_MS,
                                d.hub.rate.get(),
                                d.speed_ceiling.load(Ordering::Relaxed),
                            );
                            d.hub.rate.set(cap);
                        }
                    }
                    _ => {
                        // Timeout under our own load IS the congestion
                        // signal at its loudest - back off before
                        // reconnecting the probe.
                        let downloading = d.started_at.lock_ok().is_some();
                        if downloading {
                            let cap = auto_speed_step(
                                u64::MAX,
                                AUTO_SPEED_TARGET_MS,
                                d.hub.rate.get(),
                                d.speed_ceiling.load(Ordering::Relaxed),
                            );
                            d.hub.rate.set(cap);
                        }
                        break;
                    }
                }
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }
    });
}

/// Newsgroup discovery catalogue: load the on-disk cache off the hot
/// path so mode=groups answers instantly after a restart (parsing
/// ~100k TSV lines is tens of ms, but not worth blocking startup on).
/// Then keep it fresh unattended: no cache on first run = fetch now;
/// after that, a refetch once a day picks up newly created groups
/// (the browser's "Newly added" chip and saved-search notices feed
/// off the first_seen stamps that diff produces).
#[cfg(feature = "indexer")]
pub(super) fn spawn_group_catalog(daemon: &Arc<Daemon>, config: &std::path::Path) {
    let d = daemon.clone();
    let config = config.to_path_buf();
    tokio::spawn(async move {
        let d2 = d.clone();
        let _ = tokio::task::spawn_blocking(move || {
            if let Some(cat) = crate::groups::Catalog::load(&d2.groups_cache_path()) {
                info!(target: "groups", "catalogue cache: {} groups", cat.groups.len());
                *d2.group_catalog.lock_ok() = Some(Arc::new(cat));
            }
            if let Some(st) = crate::groupstats::StatsCache::load(&d2.groupstats_cache_path()) {
                info!(target: "groups", "sampled profiles: {} groups", st.map.len());
                *d2.group_stats.lock_ok() = Arc::new(st);
            }
        })
        .await;
        // A cached catalogue is all the interests picked in the setup
        // wizard need, so resolve them before the 20 s settle: a user
        // who just chose "sport" should find it scanning, not waiting.
        // With no cache the fetch below finishes the job. Nothing to
        // resolve while the indexer is off - the switch re-runs this
        // when it is turned on.
        if !d.indexer_off() {
            apply_interests(&d);
        }
        // Let startup settle before the first-run fetch.
        tokio::time::sleep(std::time::Duration::from_secs(20)).await;
        // Burst state, deliberately local: it lives exactly as long as
        // this task, so "one burst window per process" needs no field
        // on Daemon and no way to be reset from outside.
        let burst_started = std::time::Instant::now();
        let mut burst_samples = 0usize;
        loop {
            // The catalogue and the group profiles exist to answer
            // "what could I index?", so the master switch takes both
            // - together they are a 111k-group LIST over NNTP plus a
            // rolling sample of the busiest groups, which is real
            // provider traffic on behalf of a browser nobody can
            // open while the indexer is off.
            //
            // The orphan sweep below is NOT indexer work (it tidies
            // the download spool), so it keeps its hourly tick and
            // this stands down around it rather than instead of it.
            let indexing = !d.indexer_off();
            let age = {
                let cat = d.group_catalog.lock_ok();
                cat.as_ref().map(|c| epoch_secs() as i64 - c.fetched_at)
            };
            if indexing && age.is_none_or(|a| a >= 24 * 3600) {
                kick_group_fetch(&d, config.clone());
            }
            let profiled = d.group_stats.lock_ok().map.len();
            let burst = indexing
                && should_burst_profiles(
                    profiled,
                    burst_samples,
                    burst_started.elapsed().as_secs(),
                );
            let started = if indexing {
                sample_top_groups(&d, &config, burst).await
            } else {
                0
            };
            if burst {
                burst_samples += started;
            } else {
                // Hourly cadence only: an orphan sweep is a directory
                // walk, and there is nothing for it to find during the
                // first hour of an install anyway.
                sweep_orphan_spool_nzbs(&d);
            }
            let nap = if burst { BURST_TICK_SECS } else { 3600 };
            tokio::time::sleep(std::time::Duration::from_secs(nap)).await;
        }
    });
}

/// M12: continuous OVER scanning - incremental per group (high-water
/// marks in the index db make re-scans cheap). Always spawned: the
/// group list / interval / backfill are live settings read each cycle,
/// so indexing can be switched on from the dashboard.
#[cfg(feature = "indexer")]
pub(super) fn spawn_index_scan(
    daemon: &Arc<Daemon>,
    config: &std::path::Path,
    index_db: &std::path::Path,
    index_pass_gate: &Arc<tokio::sync::Mutex<()>>,
) {
    // Owned: the scan task outlives this call and reopens the db by path.
    let index_db = index_db.to_path_buf();
    let config = config.to_path_buf();
    let db = index_db.to_path_buf();
    let daemon2 = daemon.clone();
    let index_pass_gate = index_pass_gate.clone();
    tokio::spawn(async move {
        loop {
            // A pass takes min(connections/par, 5) NNTP connections
            // PER concurrent group - 15 of a 20-connection account at
            // the default parallelism - plus SQLite writes on the same
            // box the download is using. Re-check every 5 s so
            // indexing resumes promptly when the queue drains.
            //
            // The two sources are switched independently, so this
            // waits only while BOTH are stopped, and each leg below
            // re-asks for itself. A spots-only install runs this
            // loop with an empty group list.
            let scan_groups = daemon2.indexing_pause_reason().is_none();
            if !scan_groups && daemon2.spot_pause_reason().is_some() {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                continue;
            }
            let groups = if scan_groups {
                daemon2.index_groups.lock_ok().clone()
            } else {
                Vec::new()
            };
            let backfill = daemon2.index_backfill.load(Ordering::Relaxed);
            let deepen = daemon2.index_deepen.load(Ordering::Relaxed);
            let coverage = daemon2.index_coverage.load(Ordering::Relaxed);
            let max_age = daemon2.index_max_age_secs.load(Ordering::Relaxed);
            let gates = daemon2.index_gates.lock_ok().1.clone();
            // 24D: custom categories, sampled per pass like gates so
            // a settings change applies from the next pass on.
            let cats = daemon2.custom_categories.read_ok().clone();
            let index_pass = index_pass_gate.lock().await;
            // A job may have started while this task waited behind
            // the tip watcher or VACUUM. The foreground worker raises
            // its guard before waiting for this same gate, so this
            // recheck hands the gate over without starting a pass.
            // Both legs are re-asked: whatever started applies to
            // both, and a pass with nothing left to do should give
            // the gate straight back.
            let scan_groups = scan_groups && daemon2.indexing_pause_reason().is_none();
            let scan_spots = daemon2.spot_pause_reason().is_none();
            if !scan_groups && !scan_spots {
                drop(index_pass);
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                continue;
            }
            let groups = if scan_groups { groups } else { Vec::new() };

            // Spotnet first. It is short (a 20k-article OVER walk is
            // ~20 s against a live server) and a spots-only install
            // should not sit behind a group pass that is not even
            // running. Same gate, same preemption contract as the
            // scans below: dropped promptly when a download starts,
            // with the high-water mark left on the last whole chunk.
            if scan_spots {
                let spot_groups = daemon2.spot_groups.lock_ok().clone();
                let backfill = daemon2.spot_backfill.load(Ordering::Relaxed);
                for g in &spot_groups {
                    if daemon2.spot_pause_reason().is_some() {
                        break;
                    }
                    // The generation this pass runs under: if the
                    // database is switched off or wiped while the
                    // scan is in flight, its connection must be
                    // dropped rather than handed back (which would
                    // reopen, and after a wipe RECREATE, the file).
                    let era = daemon2.index_era();
                    let mut scratch = match nzbkit::index::Index::open(&db) {
                        Ok(ix) => ix,
                        Err(e) => {
                            warn!(target: "spots", "open {}: {e}", db.display());
                            break;
                        }
                    };
                    let scan = crate::spot_scan_pass(&config, &mut scratch, g, backfill);
                    let pause = async {
                        loop {
                            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                            if daemon2.spot_pause_reason().is_some() {
                                break;
                            }
                        }
                    };
                    match tokio::select! {
                        result = scan => Some(result),
                        _ = pause => None,
                    } {
                        Some(Ok(sum)) if sum.new > 0 => info!(
                            target: "spots",
                            "{g}: {} new spots ({} scanned, {} verified)",
                            sum.new, sum.scanned, sum.valid
                        ),
                        Some(Ok(_)) => {}
                        Some(Err(e)) => warn!(target: "spots", "{g}: {e}"),
                        None => info!(target: "spots", "{g} paused for foreground job"),
                    }
                    drop(scratch);
                    // Republish so queries see this pass's writes.
                    if let Ok(fresh) = nzbkit::index::Index::open(&db) {
                        daemon2.publish_index(era, fresh);
                    }
                    daemon2.drop_index_read();
                }
            }
            // 24D: the category config changed (or first run since
            // start) - reconcile stored rows before this pass, so a
            // pass's own re-ingest touches never fight the sweep.
            // Chunked + fingerprint-stamped, so this is a no-op when
            // nothing actually changed.
            if daemon2.reclassify_pending.swap(false, Ordering::Relaxed) {
                let cats2 = cats.clone();
                let db2 = db.clone();
                let outcome = tokio::task::spawn_blocking(move || {
                    let mut ix = nzbkit::index::Index::open(&db2)
                        .map_err(|e| format!("open {}: {e}", db2.display()))?;
                    ix.set_custom(cats2);
                    ix.reclassify_custom().map_err(|e| e.to_string())
                })
                .await;
                let changed = match outcome {
                    Ok(Ok(n)) => n,
                    Ok(Err(e)) => {
                        warn!(target: "cats", "reclassify failed: {e} - will retry");
                        daemon2.reclassify_pending.store(true, Ordering::Relaxed);
                        0
                    }
                    Err(e) => {
                        warn!(target: "cats", "reclassify task failed: {e} - will retry");
                        daemon2.reclassify_pending.store(true, Ordering::Relaxed);
                        0
                    }
                };
                if changed > 0 {
                    info!(target: "cats", "reclassified {changed} releases under the new category rules");
                    // Freshly re-keyed cards need titles rows for the
                    // wall; the seeder below only covers recent posts,
                    // so republish + seed now.
                    let era = daemon2.index_era();
                    if let Ok(fresh) = nzbkit::index::Index::open(&db) {
                        daemon2.publish_index(era, fresh);
                    }
                    daemon2.drop_index_read();
                    let _ = daemon2.with_index(|ix| ix.seed_missing_titles(3650, 2000).ok());
                }
            }
            // One-off deep-backfill override (index_scan_now&value=N).
            // Taking it with a swap consumes it, so a pass preempted
            // by a download that starts seconds after the user clicks
            // dropped the request on the floor: the deep leg never
            // ran, nothing said so, and the next passes went back to
            // normal depth. Remember it and put it back if this pass
            // does not get to finish.
            let deep_taken = daemon2.scan_deep.swap(0, Ordering::Relaxed);
            let deep = (deep_taken > 0).then_some(deep_taken);
            let preempted = Arc::new(AtomicBool::new(false));
            // M30 turbo: an idle line belongs to the scanner - passes
            // that start with no download active fan out deeper
            // (per-group conn clamp 10 vs 5; the account-limit ÷
            // parallelism budget still applies).
            let turbo = daemon2.started_at.lock_ok().is_none();
            // M28: groups scan CONCURRENTLY (they were strictly
            // sequential - wall-clock scaled with group count). Each
            // task gets its own connection into the shared WAL db;
            // ingest transactions are per-chunk so writer-lock waits
            // stay inside the 10s busy timeout. The per-scan NNTP
            // connection budget divides the account limit by the
            // parallelism (`share`), so N groups never exceed it.
            let par = (daemon2.index_scan_par.load(Ordering::Relaxed) as usize)
                .clamp(1, 8)
                .min(groups.len().max(1));
            let sem = Arc::new(tokio::sync::Semaphore::new(par));
            daemon2.scan_active.store(true, Ordering::Relaxed);
            let mut set = tokio::task::JoinSet::new();
            for g in groups.clone() {
                let sem = sem.clone();
                let config = config.clone();
                let db = db.clone();
                let daemon3 = daemon2.clone();
                let gates = gates.clone();
                let cats = cats.clone();
                let preempted2 = preempted.clone();
                set.spawn(async move {
                    let _permit = sem.acquire_owned().await.expect("scan semaphore");
                    // The generation this pass belongs to. A pass runs
                    // for minutes; the switch and the wipe are one
                    // click. Publishing without checking this is how a
                    // switched-off indexer got a live connection back
                    // and a wiped database got recreated.
                    let era = daemon3.index_era();
                    // Scan into a dedicated connection, then republish
                    // - keeps the OVER round-trips off the lock that
                    // query handlers need.
                    let mut scratch = match nzbkit::index::Index::open(&db) {
                        Ok(ix) => ix,
                        Err(e) => {
                            warn!(target: "index", "open {}: {e}", db.display());
                            return;
                        }
                    };
                    let done = Arc::new(AtomicU64::new(0));
                    daemon3.scan_progress.lock_ok().push(ScanProgress {
                        group: g.clone(),
                        done: done.clone(),
                    });
                    // Backfill, max-age and gates are all live settings
                    // now (M12 volume control), sampled per pass.
                    // A download can begin during a long scan. Drop
                    // the scan future promptly; its owned JoinSet
                    // aborts every OVER worker, while the contiguous
                    // high-water invariant leaves the unfinished
                    // range for the next pass.
                    let scan = crate::index_scan_into(
                        &config,
                        &g,
                        backfill,
                        max_age,
                        gates.as_ref(),
                        cats,
                        &mut scratch,
                        deep,
                        deepen,
                        Some(done),
                        par,
                        turbo,
                        coverage,
                    );
                    let pause = async {
                        loop {
                            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                            if daemon3.indexing_pause_reason().is_some() {
                                break;
                            }
                        }
                    };
                    match tokio::select! {
                        result = scan => Some(result),
                        _ = pause => None,
                    } {
                        Some(Err(e)) => warn!(target: "index", "scan {g}: {e}"),
                        None => {
                            preempted2.store(true, Ordering::Relaxed);
                            info!(target: "index", "scan {g} paused for foreground job");
                        }
                        Some(Ok(())) => {}
                    }
                    daemon3
                        .scan_progress
                        .lock()
                        .unwrap()
                        .retain(|p| p.group != g);
                    drop(scratch);
                    // Re-open the shared connection so it sees this
                    // task's now-committed writes (fresh read snapshot)
                    // - unless the index was switched off or wiped
                    // while we ran, in which case there is nothing to
                    // publish to.
                    if daemon3.index_era() == era
                        && let Ok(fresh) = nzbkit::index::Index::open(&db)
                    {
                        daemon3.publish_index(era, fresh);
                    }
                    daemon3.drop_index_read();
                });
            }
            while set.join_next().await.is_some() {}
            daemon2.scan_active.store(false, Ordering::Relaxed);
            // Hand the one-off deep request back if this pass was cut
            // short before it could honour it. fetch_max so a newer
            // (or deeper) request made meanwhile is never clobbered.
            if deep_taken > 0 && preempted.load(Ordering::Relaxed) {
                daemon2.scan_deep.fetch_max(deep_taken, Ordering::Relaxed);
                info!(
                    target: "index",
                    "deep backfill of {deep_taken} was interrupted - \
                     it stays queued for the next pass"
                );
            }
            // A job that interrupted this pass is waiting for the
            // gate. Skip every post-pass SQLite task and release it
            // immediately; indexing resumes from its marks later.
            //
            // `scan_groups &&` matters on a spots-only install: with
            // the indexer switched off this reason is permanently
            // "off", and short-circuiting on it would skip the
            // interval sleep at the bottom of the loop and re-scan
            // free.pt as fast as the server would answer. Every
            // post-pass task below is already a no-op with no groups.
            if scan_groups && daemon2.indexing_pause_reason().is_some() {
                drop(index_pass);
                continue;
            }
            // M30: fresh posts get titles rows (→ enrichment) right
            // after the pass that indexed them - a wall page view
            // used to be the only seeder.
            if !groups.is_empty() {
                let seeded = daemon2
                    .with_index(|ix| ix.seed_missing_titles(14, 500).ok())
                    .unwrap_or(0);
                if seeded > 0 {
                    info!(target: "wall", "seeded {seeded} new titles for enrichment");
                }
            }
            // A8: targeted gap-fill - re-hunt a few incomplete
            // releases' posting windows on the OTHER backbones.
            // Runs under the pass gate (the tip watcher stands
            // down), aborts between chunks the moment a download
            // starts, and skips entirely while one is active.
            let gapfill = daemon2.index_gapfill.load(Ordering::Relaxed) as u32;
            if gapfill > 0
                && coverage
                && !groups.is_empty()
                && daemon2.indexing_pause_reason().is_none()
            {
                let gates2 = daemon2.index_gates.lock_ok().1.clone();
                let cats2 = daemon2.custom_categories.read_ok().clone();
                // Same contract as the scan tasks above: this owns a
                // dedicated connection for the length of the pass, so
                // it may only publish if the index it belongs to is
                // still the current one.
                let era = daemon2.index_era();
                match nzbkit::index::Index::open(&db) {
                    Ok(mut scratch) => {
                        install_live_ingest_policy(&mut scratch, gates2, cats2);
                        let d3 = daemon2.clone();
                        // Same preemption contract as the scan tasks:
                        // a starting job raises its guard then waits
                        // on the pass gate this section holds, so
                        // dropping the future promptly (never
                        // mid-transaction - ingest holds no await
                        // point) is what keeps job start snappy. The
                        // stop() closure is the cheap between-chunks
                        // early-out; the select is the hard bound.
                        let gap = crate::index_gapfill_pass(&config, &mut scratch, gapfill, || {
                            d3.indexing_pause_reason().is_some()
                        });
                        let pause = async {
                            loop {
                                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                                if daemon2.indexing_pause_reason().is_some() {
                                    break;
                                }
                            }
                        };
                        match tokio::select! {
                            r = gap => Some(r),
                            _ = pause => None,
                        } {
                            Some(Ok((tried, done))) if tried > 0 => {
                                info!(
                                    target: "gapfill",
                                    "{tried} incomplete releases re-hunted, {done} completed"
                                );
                            }
                            Some(Ok(_)) => {}
                            Some(Err(e)) => warn!(target: "gapfill", "{e}"),
                            None => {
                                info!(target: "gapfill", "paused for foreground job")
                            }
                        }
                        drop(scratch);
                        if daemon2.index_era() == era
                            && let Ok(fresh) = nzbkit::index::Index::open(&db)
                        {
                            daemon2.publish_index(era, fresh);
                        }
                        daemon2.drop_index_read();
                    }
                    Err(e) => warn!(target: "gapfill", "open {}: {e}", db.display()),
                }
            }
            // M31a: retention prune - cap unbounded index growth.
            // Throttled to once/hour (a kv timestamp), skipped while a
            // download is active so it never fights for the write
            // lock during a job. The stale-partial reaper runs
            // whenever indexing is on; the age prune only when
            // retention is enabled AND a max-age window is set.
            if !groups.is_empty() && daemon2.index_maintenance_ok() {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|t| t.as_secs() as i64)
                    .unwrap_or(0);
                let last: i64 = daemon2
                    .with_index(|ix| ix.kv_get("retention_at").and_then(|v| v.parse().ok()))
                    .unwrap_or(0);
                if now - last >= 3_600 {
                    let max_age = daemon2.index_max_age_secs.load(Ordering::Relaxed) as i64;
                    let retention = daemon2.index_retention.load(Ordering::Relaxed);
                    let (aged, stale) = daemon2
                        .with_index(|ix| {
                            // Age prune (wall-visible content) is
                            // opt-in via the retention setting + a
                            // window; the stale-partial junk reaper
                            // is always on (touches only junk-hidden
                            // dead fragments).
                            let aged = if retention && max_age > 0 {
                                ix.prune_age(max_age, now).unwrap_or(0)
                            } else {
                                0
                            };
                            let stale = ix.prune_stale_partials(7 * 86_400, now).unwrap_or(0);
                            let _ = ix.kv_set("retention_at", &now.to_string());
                            Some((aged, stale))
                        })
                        .unwrap_or((0, 0));
                    if aged + stale > 0 {
                        info!(
                            target: "index",
                            "retention pruned {aged} old + {stale} stale-partial rows"
                        );
                        // Republish so queries see the smaller db.
                        let era = daemon2.index_era();
                        if let Ok(fresh) = nzbkit::index::Index::open(&index_db) {
                            daemon2.publish_index(era, fresh);
                        }
                        daemon2.drop_index_read();
                    }
                }
                // Query-planner statistics, on the same gate and a
                // slower clock. Daily rather than hourly because the
                // shape of the data - a few thousand titles against
                // tens of millions of releases - is what the planner
                // needs, and that ratio moves over weeks, not hours.
                //
                // Not optional maintenance: an index with no statistics
                // plans `wall2` as a full scan of every release, which
                // is how a 45 GB index came to spend 85s answering one
                // card query (2 Aug). See `Index::optimize`.
                let last_opt: i64 = daemon2
                    .with_index(|ix| ix.kv_get("analyze_at").and_then(|v| v.parse().ok()))
                    .unwrap_or(0);
                if now - last_opt >= 86_400 {
                    let started = std::time::Instant::now();
                    // The first run on a big never-analyzed database is
                    // minutes of synchronous work holding the write
                    // connection, under the same pass gate a starting
                    // download rendezvouses on - the exact stall §95
                    // removed from compaction. Same cure: a blocking
                    // thread, an interrupt handle, and a watcher that
                    // aborts the statement the moment a job appears. An
                    // aborted refresh is NOT stamped, so it retries at
                    // the next idle hour.
                    // The handle is taken INSIDE the blocking closure,
                    // under the guard that runs the statement - see
                    // MaintenanceArm. Taken out here (an earlier, since
                    // released with_index) it belonged to a connection
                    // some other writer could be using by the time the
                    // watcher fired.
                    let arm = Arc::new(super::daemon::MaintenanceArm::default());
                    let done = Arc::new(AtomicBool::new(false));
                    let watch = {
                        let jobs = daemon2.index_jobs_active.clone();
                        let done = done.clone();
                        let arm = arm.clone();
                        tokio::spawn(abort_compact_when_job_starts(jobs, done, move || {
                            arm.abort();
                        }))
                    };
                    let d3 = daemon2.clone();
                    let done2 = done.clone();
                    let arm2 = arm.clone();
                    let outcome = tokio::task::spawn_blocking(move || {
                        d3.with_index(|ix| {
                            if !arm2.arm(ix.interrupt_handle()) {
                                // A download started before we got the
                                // guard: do not begin at all.
                                done2.store(true, Ordering::Release);
                                return None;
                            }
                            let r = ix.optimize();
                            arm2.disarm();
                            // Inside the closure for the same reason as
                            // the VACUUM path: the watcher must never
                            // see "running" on a connection somebody
                            // else has already started using.
                            done2.store(true, Ordering::Release);
                            Some(r)
                        })
                    })
                    .await;
                    done.store(true, Ordering::Release);
                    let aborted = matches!(watch.await, Ok(true));
                    match outcome {
                        _ if aborted => {
                            info!(
                                target: "index",
                                "statistics refresh stood down for a download - \
                                 it will run again at the next idle hour"
                            );
                        }
                        Ok(Some(Ok(()))) => {
                            let _ = daemon2
                                .with_index(|ix| ix.kv_set("analyze_at", &now.to_string()).ok());
                            // Only worth a line when it actually took
                            // time - the daily no-op pass is silent.
                            if started.elapsed() >= std::time::Duration::from_secs(1) {
                                info!(
                                    target: "index",
                                    "query planner statistics refreshed in {:.1}s",
                                    started.elapsed().as_secs_f64()
                                );
                            }
                        }
                        Ok(Some(Err(e))) => {
                            // Stamped even on error: a database that
                            // cannot be analyzed must not retry it
                            // every hour forever.
                            let _ = daemon2
                                .with_index(|ix| ix.kv_set("analyze_at", &now.to_string()).ok());
                            warn!(target: "index", "ANALYZE: {e}");
                        }
                        Ok(None) | Err(_) => {}
                    }
                }
            }
            // M34: hold the database under its size cap. BETWEEN
            // passes, never inside one - the JoinSet above is fully
            // drained here, so no scan task is holding the write
            // lock or about to re-insert what we just deleted.
            //
            // evict_pass is a no-op (two atomic loads) unless the
            // user turned eviction on AND set a cap, so the common
            // install pays nothing for this. It never compacts:
            // reclaiming the freed pages is a VACUUM, and that waits
            // for the idle window in compact_loop below.
            {
                let d3 = daemon2.clone();
                // The prune is synchronous SQLite work on a shared
                // connection - off the async worker.
                let outcome = tokio::task::spawn_blocking(move || d3.evict_pass()).await;
                // Record a trim that actually removed something, so the
                // DB card can say what happened to the releases that
                // disappeared. `Nothing`/`Unavailable` removed nothing
                // and must not overwrite the last real answer.
                if let Ok(crate::serve::daemon::EvictOutcome::Ran(rep, _)) = &outcome
                    && rep.removed > 0
                {
                    *daemon2.last_auto_trim.lock_ok() = Some((
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs() as i64)
                            .unwrap_or(0),
                        rep.removed as u64,
                    ));
                }
                if daemon2.compact_pending.load(Ordering::Relaxed) {
                    // Republish so queries see the smaller db (the
                    // file is still big - the pages are free, not
                    // returned - but the rows are gone).
                    let era = daemon2.index_era();
                    if let Ok(fresh) = nzbkit::index::Index::open(&index_db) {
                        daemon2.publish_index(era, fresh);
                    }
                    daemon2.drop_index_read();
                }
            }
            drop(index_pass);
            let interval = daemon2.index_interval_secs.load(Ordering::Relaxed).max(30);
            // Interval sleep, cut short by mode=index_scan_now (a
            // notify during a pass leaves a permit - the next wait
            // returns at once, so a mid-pass click still lands).
            tokio::select! {
                _ = tokio::time::sleep(std::time::Duration::from_secs(
                    // Idle (nothing scanned): just re-check the
                    // setting soon. A spot pass IS work, so it waits
                    // out the real interval - the 15 s re-check would
                    // otherwise walk free.pt four times a minute.
                    if groups.is_empty() && !scan_spots { 15 } else { interval },
                )) => {}
                _ = daemon2.scan_now.notified() => {}
            }
        }
    });
}

/// M34: deferred compaction. Deleting rows does not shrink a SQLite
/// file - the pages go on the free list and the file stays the size
/// it grew to - so reclaiming the disk the size cap just promised
/// needs a VACUUM. VACUUM exclusive-locks and rewrites the WHOLE
/// database, which is exactly the thing that must never interrupt a
/// scan pass or a download, so it is not run where the prune raises
/// the flag. This loop waits for a genuinely idle moment instead:
/// nothing downloading, nothing scanning, and room on the volume for
/// the rebuild. If any of that fails it stays deferred and tries
/// again a minute later - a compact that never happens costs disk,
/// a compact that runs at the wrong time costs the user their
/// download.
#[cfg(feature = "indexer")]
pub(super) fn spawn_index_compact(
    daemon: &Arc<Daemon>,
    index_pass_gate: &Arc<tokio::sync::Mutex<()>>,
) {
    let d = daemon.clone();
    let index_pass_gate = index_pass_gate.clone();
    // Not `index_db` - the scan-loop task above owns that binding now.
    let db = daemon.index_db.clone();
    tokio::spawn(async move {
        // Rate-limit the "no room" line: this ticks every minute and
        // a small NAS volume can stay full for days.
        let mut last_moan = std::time::Instant::now()
            .checked_sub(std::time::Duration::from_secs(7200))
            .unwrap_or_else(std::time::Instant::now);
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            // `compact_pending` is sticky, so a prune that raised it
            // just before the indexer was switched off would still
            // rewrite a multi-GB file - the loudest disk work there
            // is, on behalf of a feature that is now off. It stays
            // raised and runs if the indexer comes back; to get the
            // space back instead, the off state offers to delete the
            // database outright.
            if !d.compact_pending.load(Ordering::Relaxed) || d.indexer_off() {
                continue;
            }
            let Ok(_index_pass) = index_pass_gate.try_lock() else {
                continue;
            };
            // A stat, but on whatever volume holds the index - demote
            // the worker like every other sync fs touch on a tokio task.
            let db_bytes = crate::persist::blocking_db(|| {
                std::fs::metadata(&db).map(|m| m.len()).unwrap_or(0)
            });
            // §95: which of the two paths this database can take, read
            // BEFORE the verdict because it decides whether the volume
            // needs room for a second copy. A fresh install has been
            // incremental since `Index::open` created it; an existing
            // one is still in SQLite's default mode and needs one full
            // rewrite to get there.
            let style = d
                .with_index(|ix| ix.compact_style().ok())
                .unwrap_or(nzbkit::index::CompactStyle::FullRewrite);
            let verdict = compact_verdict(
                true,
                !d.scan_progress.lock_ok().is_empty(),
                // This argument is `downloading`, and a true answer
                // yields Busy("a download is running"). The pause
                // PREDICATE is not that question and gets it wrong in
                // both directions: with pause-on-download switched off
                // it reads false during a job, so a multi-GB VACUUM
                // could start mid-download on the same volume; and with
                // the indexer manually paused it reads true forever, so
                // compaction never runs at exactly the moment it is
                // safest. compact_pending is sticky, so that second one
                // defers silently and permanently.
                //
                // Count jobs in flight rather than reading started_at,
                // which goes None between queued jobs while the
                // pipeline is still busy.
                d.index_jobs_active.load(Ordering::Acquire) > 0,
                db_bytes,
                crate::persist::blocking_db(|| {
                    free_bytes(db.parent().unwrap_or(std::path::Path::new(".")))
                }),
                style == nzbkit::index::CompactStyle::FullRewrite,
            );
            match verdict {
                CompactVerdict::NotNeeded | CompactVerdict::Busy(_) => continue,
                CompactVerdict::NoRoom { need, free } => {
                    if last_moan.elapsed() >= std::time::Duration::from_secs(3600) {
                        last_moan = std::time::Instant::now();
                        info!(
                            target: "index",
                            "compact deferred: rebuilding the {:.0} MB index needs \
                             ~{:.0} MB free and the volume has {:.0} MB - the pruned rows \
                             are gone, the file just hasn't shrunk yet",
                            db_bytes as f64 / (1u64 << 20) as f64,
                            need as f64 / (1u64 << 20) as f64,
                            free as f64 / (1u64 << 20) as f64,
                        );
                    }
                    continue;
                }
                CompactVerdict::Go => {}
            }
            // Clear the flag BEFORE the rewrite: if a prune lands
            // while this runs it re-raises it and we come back,
            // whereas clearing afterwards would swallow that request.
            d.compact_pending.store(false, Ordering::Relaxed);
            let d2 = d.clone();
            let path = db.clone();
            // The verdict above answers "is a download running?" a
            // moment BEFORE the rewrite starts, and the rewrite then
            // holds `index_pass_gate` - which is exactly what a
            // starting download waits on - for its whole duration.
            // A job that arrives in between sits in `Downloading`
            // making no progress and logging nothing until the
            // VACUUM ends: measured, a 175 MB index blocks a waiter
            // for ~0.5 s, so the multi-GB indexes this feature exists
            // for block it for minutes.
            //
            // So take an interrupt handle before handing the
            // connection to the blocking thread, and abort the
            // rewrite the moment a job appears. VACUUM is one
            // transaction: aborting leaves the file exactly as it
            // was, and `compact_pending` brings us back a minute
            // later. The user's rule is that compaction never
            // interrupts a download - the same rule has to hold when
            // the download turns up second.
            if style == nzbkit::index::CompactStyle::Chunked {
                chunked_compact(&d, &db).await;
                continue;
            }
            info!(
                target: "index",
                "compacting the {:.0} MB index in one pass to enable incremental \
                 reclaim - this one cannot be cut short for a download, later ones can",
                db_bytes as f64 / (1u64 << 20) as f64,
            );
            // Armed inside the blocking closure, under the guard that
            // runs the VACUUM - see MaintenanceArm. A handle taken here
            // and used later belongs to a connection an unrelated
            // writer may hold by then.
            let arm = Arc::new(super::daemon::MaintenanceArm::default());
            let done = Arc::new(AtomicBool::new(false));
            let watch = {
                let jobs = d.index_jobs_active.clone();
                let done = done.clone();
                let arm = arm.clone();
                tokio::spawn(abort_compact_when_job_starts(jobs, done, move || {
                    arm.abort();
                }))
            };
            // VACUUM is a long synchronous rewrite - it belongs on a
            // blocking thread, not on an async worker.
            let done2 = done.clone();
            let arm2 = arm.clone();
            let outcome = tokio::task::spawn_blocking(move || {
                let before = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
                let ok = d2
                    .with_index(|ix| {
                        if !arm2.arm(ix.interrupt_handle()) {
                            // A download started before we got the
                            // guard: do not begin the rewrite at all.
                            done2.store(true, Ordering::Release);
                            return None;
                        }
                        let r = ix.compact();
                        arm2.disarm();
                        // Inside the closure, so the flag is set
                        // while this thread still holds the index
                        // lock: the watcher can never see "running"
                        // for a connection somebody else has already
                        // started using.
                        done2.store(true, Ordering::Release);
                        r.ok()
                    })
                    .is_some();
                let after = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
                if ok {
                    info!(
                        target: "index",
                        "compacted at idle - {:.0} MB reclaimed",
                        before.saturating_sub(after) as f64 / (1u64 << 20) as f64
                    );
                } else {
                    d2.compact_pending.store(true, Ordering::Relaxed);
                }
                ok
            })
            .await;
            done.store(true, Ordering::Release);
            // Distinguish the two failures in the log. "Compact
            // failed" for a rewrite we deliberately aborted would
            // send the user looking for a broken database.
            if matches!(watch.await, Ok(true)) {
                info!(
                    target: "index",
                    "compact stood down for a download - the index will \
                     shrink at the next idle moment"
                );
            } else if matches!(outcome, Ok(false)) {
                warn!(target: "index", "compact failed - will retry when idle");
            }
        }
    });
}

/// §95: reclaim the freed pages in bounded chunks, stopping the moment
/// a download appears.
///
/// This is the whole point of the incremental mode. The VACUUM path
/// above can only ASK to stop - `sqlite3_interrupt` is read from the
/// VDBE, so it never reaches the rewrite's `sqlite3BtreeCopyFile` tail -
/// and measured on a 1.16 GB index, a job that arrived as the rewrite
/// started waited the full 4.8 s and every abort that did land threw
/// away all 580 MB of reclaim. Here the check is between chunks, where
/// nothing is running, so standing down is immediate and everything
/// reclaimed so far is already committed and truncated.
///
/// It stays on one blocking thread for the whole loop, but takes the
/// shared index connection PER CHUNK: scan passes are already excluded
/// for the whole iteration by `index_pass_gate` (they use scratch
/// connections and rendezvous on the gate, never this mutex), so the
/// only threads the mutex holds off are the write-side HTTP handlers -
/// wall admin edits, pre_assign, kv writes - and parking those for a
/// multi-minute pass is the 2 Aug wedge shape all over again. Between
/// chunks the mutex is free, so an admin edit waits one chunk (~100 ms),
/// not the whole compaction.
#[cfg(feature = "indexer")]
async fn chunked_compact(d: &Arc<Daemon>, db: &std::path::Path) {
    let d2 = d.clone();
    let jobs = d.index_jobs_active.clone();
    let path = db.to_path_buf();
    let outcome = tokio::task::spawn_blocking(move || {
        let before = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        let mut chunks = 0u64;
        let mut stood_down = false;
        let ran = (|| {
            let mut left = d2.with_index(|ix| ix.freelist_pages().ok())?;
            while left > 0 {
                // Between chunks: nothing is running, so this
                // needs no interrupt and cannot be ignored.
                if jobs.load(Ordering::Acquire) > 0 {
                    stood_down = true;
                    break;
                }
                let now_left = d2.with_index(|ix| ix.compact_chunk(COMPACT_CHUNK_PAGES).ok())?;
                chunks += 1;
                // A chunk that reclaimed nothing means the freelist
                // is not shrinking - pages pinned by something we
                // cannot move. Without this the loop would spin on
                // them forever, holding the gate it is meant to
                // release.
                if now_left >= left {
                    break;
                }
                left = now_left;
            }
            Some(())
        })()
        .is_some();
        let after = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
        (ran, stood_down, chunks, before.saturating_sub(after))
    })
    .await;
    let Ok((ran, stood_down, chunks, freed)) = outcome else {
        d.compact_pending.store(true, Ordering::Relaxed);
        return;
    };
    if !ran {
        // Re-raise the sticky flag or "will retry" is a lie: nothing
        // else raises it until some future eviction happens to, and an
        // index that stays under its cap never evicts again.
        d.compact_pending.store(true, Ordering::Relaxed);
        warn!(target: "index", "compact failed - will retry when idle");
        return;
    }
    let mb = freed as f64 / (1u64 << 20) as f64;
    if stood_down {
        // Unlike the VACUUM path, this is not "nothing happened": the
        // chunks that did run are committed and the file is already
        // shorter. Say so, or the next line the user reads implies the
        // work was wasted.
        d.compact_pending.store(true, Ordering::Relaxed);
        info!(
            target: "index",
            "compact stood down for a download after {chunks} chunks - {mb:.0} MB \
             reclaimed and kept, the rest at the next idle moment"
        );
    } else {
        info!(target: "index", "compacted at idle - {mb:.0} MB reclaimed");
    }
}

/// §74: install (or clear) the arrival watch on an index handle. Kept
/// beside `install_live_ingest_policy` and called from the same places
/// for the same reason: the shared handle is republished after every
/// full scan pass, so neither closure survives one.
///
/// `None` clears it, which is what an install with no watchlist - or the
/// setting switched off - must do, or a handle would keep journalling
/// hits nobody will ever drain.
#[cfg(feature = "indexer")]
pub(super) fn install_instant_watch(
    ix: &mut nzbkit::index::Index,
    matcher: Option<crate::watchlist::InstantMatcher>,
) {
    ix.set_watch_names(
        matcher
            .map(|m| Box::new(move |name: &str| m.wants(name)) as Box<dyn Fn(&str) -> bool + Send>),
    );
}

/// §74: react to what the arrival watch caught in one batch.
///
/// Complete releases wake the watchlist pass immediately. Incomplete ones
/// are held for a short re-check instead: a post seen seconds after it
/// went up is usually still going up, and the watchlist only ever
/// considers complete releases. Nothing here decides anything about a
/// release - the pass does that, with the whole ladder - so the worst a
/// wrong call costs is a wasted look or a minute of latency.
#[cfg(feature = "indexer")]
pub(super) fn instant_arrivals(
    d: &Arc<Daemon>,
    hits: Vec<nzbkit::index::WatchHit>,
    dropped: u32,
    now: i64,
) {
    if dropped > 0 {
        // Said out loud rather than swallowed: this is the one place
        // instant coverage is knowingly given up, and it must not look
        // like "nothing arrived".
        info!(
            target: "watch",
            "{dropped} arrival(s) past the instant journal's cap - \
             they wait for the next regular check"
        );
    }
    if hits.is_empty() {
        return;
    }
    let mut ready: Vec<String> = Vec::new();
    {
        let mut pending = d.instant_pending.lock_ok();
        for h in hits {
            if h.complete {
                pending.remove(&h.id);
                ready.push(h.name);
            } else {
                // First sighting wins: the clock this starts is what
                // expires the entry back to the periodic pass, and
                // re-stamping it on every batch of a large post would
                // keep it alive for as long as the post kept growing.
                pending.entry(h.id).or_insert(now);
            }
        }
    }
    if !ready.is_empty() {
        let names = ready.join(", ");
        if d.instant_kick(&ready, now) {
            info!(target: "watch", "arrived: {names} - checking the watchlist now");
        }
    }
}

/// Tip watcher: the short loop that tracks only what is NEW at the
/// head of each group.
///
/// A full scan pass is two legs - the forward tip (~20k articles) and
/// a 200,000-article backward history deepen - and the interval
/// (default 900 s) does not start until BOTH have finished. So the
/// part that matters for "something just arrived" was riding on the
/// schedule of the part that does not: measured on the live daemon,
/// ~90% of every pass is backfill, and a new post waited up to a
/// quarter of an hour to become visible.
///
/// This loop does the forward leg alone, on its own short interval,
/// over ONE connection reused across ticks. That matters more than it
/// looks: a full pass builds and tears down a connection per worker
/// per group (~33 TLS handshakes at turbo fan-out), which is fine
/// every 15 minutes and ruinous every 20 seconds. When nothing has
/// arrived a whole tick costs one GROUP command per group.
///
/// It never competes with the full pass: a group the scan loop is
/// currently working is skipped, so only one of the two ever advances
/// a given group's high-water mark. Anything the watcher does not
/// reach (a group far behind, or a tick that runs out of budget) is
/// simply picked up by the next pass, exactly as before - the mark
/// only ever advances over a contiguous prefix, so falling behind
/// costs latency, never coverage.
#[cfg(feature = "indexer")]
pub(super) fn spawn_tip_watcher(
    daemon: &Arc<Daemon>,
    config: &std::path::Path,
    index_pass_gate: &Arc<tokio::sync::Mutex<()>>,
) {
    let config = config.to_path_buf();
    let daemon2 = daemon.clone();
    let index_pass_gate = index_pass_gate.clone();
    tokio::spawn(async move {
        // A lone connection wants big OVER ranges - per-request
        // server latency, not bandwidth, is what costs (the full
        // scanner measures 82-95k hdr/s on 100k ranges against
        // 31-54k/s on 10k ones).
        const TIP_CHUNK: u64 = 20_000;
        // Further behind than this and catching up is the full
        // pass's job, not ours: it fans out over ~10 connections and
        // will cover the gap far faster than one connection can.
        const TIP_HANDOFF: u64 = 500_000;
        // A8: one connection per PRIMARY host - groups can have
        // different chosen primaries, and a mark is only valid
        // against the server whose numbering built it. With one
        // provider this degenerates to the single connection it
        // always was.
        let mut conns: std::collections::HashMap<String, nzbkit::nntp::Connection> =
            Default::default();
        let mut group_cursor = 0usize;
        loop {
            let every = daemon2.index_tip_secs.load(Ordering::Relaxed);
            let groups = daemon2.index_groups.lock_ok().clone();
            if every == 0 || groups.is_empty() {
                // Off, or nothing to watch - drop the connections
                // rather than hold them open for nothing.
                for (_, c) in conns.drain() {
                    c.quit().await;
                }
                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                continue;
            }
            // Stand down entirely while a full pass is in flight.
            // Skipping just the group being scanned is not enough:
            // both write the same SQLite file, and a 200k-article
            // deepen leg plus this loop's ingest overran the 10 s
            // busy timeout and failed a whole group's scan with
            // "database is locked". The full pass is the faster
            // catch-up anyway, so there is nothing to add here while
            // it runs.
            if daemon2.indexing_pause_reason().is_some() {
                for (_, c) in conns.drain() {
                    c.quit().await;
                }
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                continue;
            }
            if daemon2.scan_active.load(Ordering::Relaxed) {
                tokio::time::sleep(std::time::Duration::from_secs(every.min(5))).await;
                continue;
            }
            let index_pass = index_pass_gate.lock().await;
            if daemon2.indexing_pause_reason().is_some() {
                drop(index_pass);
                for (_, c) in conns.drain() {
                    c.quit().await;
                }
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                continue;
            }
            let gates = daemon2.index_gates.lock_ok().1.clone();
            let cats = daemon2.custom_categories.read_ok().clone();
            // §74: the watchlist, compiled into the cheap name test the
            // ingest below runs over each arriving release. Rebuilt every
            // tick rather than cached behind a generation counter: it is
            // a handful of string normalisations against a list a person
            // typed, once per tick, and a stale matcher would silently
            // stop reacting to an item the user just added.
            let matcher = daemon2.instant_matcher();
            let mut fresh = 0u32;
            // Set when a group still had articles waiting as the
            // tick ended - see the nap below.
            let mut behind = false;
            // The tick bounds itself by TIME, not by an article
            // count. A fixed count cannot work: measured live,
            // alt.binaries.boneless alone posts ~900 articles/s, so
            // a 20k-per-tick cap pinned the watcher at 100% duty
            // cycle and permanently ~20k behind - it never caught
            // up, and had no headroom for a slow tick. A deadline
            // tracks whatever the group actually does and still
            // guarantees the loop keeps to its own interval.
            let deadline = Instant::now() + std::time::Duration::from_secs(every.min(30));
            'groups: for offset in 0..groups.len() {
                let g = &groups[(group_cursor + offset) % groups.len()];
                // A8: follow the group's chosen primary - the full
                // pass persists its marks key. Absent = the group was
                // never scanned; seeding needs the backfill count and
                // max-age bisection only the full pass knows, so
                // leave it alone.
                let Some(pkey) = daemon2.with_index(|ix| ix.kv_get(&format!("scan_primary:{g}")))
                else {
                    continue;
                };
                let mark = daemon2
                    .with_index(|ix| Some(ix.high_water(g, &pkey)))
                    .unwrap_or(0);
                if mark == 0 {
                    continue;
                }
                if !conns.contains_key(&pkey) {
                    // The key names a server the config may have
                    // dropped since the pass; skip until the next
                    // pass re-chooses.
                    let Some(server) = crate::find_scan_server(&config, &pkey) else {
                        continue;
                    };
                    match nzbkit::nntp::Connection::connect(&server).await {
                        Ok((c, _)) => {
                            conns.insert(pkey.clone(), c);
                        }
                        Err(e) => {
                            warn!(target: "tip", "{}: connect: {e}", server.host);
                            continue;
                        }
                    }
                }
                let c = conns.get_mut(&pkey).expect("connected above");
                let high = match c.group(g).await {
                    Ok(info) => info.high,
                    // A dropped idle connection looks exactly like
                    // this; reconnect on the next tick.
                    Err(_) => {
                        conns.remove(&pkey);
                        continue;
                    }
                };
                if high <= mark || high - mark > TIP_HANDOFF {
                    continue;
                }
                let mut lo = mark.saturating_add(1);
                while lo <= high && Instant::now() < deadline {
                    if daemon2.indexing_pause_reason().is_some() {
                        for (_, c) in conns.drain() {
                            c.quit().await;
                        }
                        break 'groups;
                    }
                    let hi = lo.saturating_add(TIP_CHUNK - 1).min(high);
                    let Some(c) = conns.get_mut(&pkey) else { break };
                    let entries = match c.over(lo, hi).await {
                        Ok(es) => es,
                        Err(_) => {
                            conns.remove(&pkey);
                            break;
                        }
                    };
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs() as i64)
                        .unwrap_or(0);
                    let gates = gates.clone();
                    let cats = cats.clone();
                    let matcher = matcher.clone();
                    let done = daemon2.with_index_mut(|ix| {
                        // Gates are a live setting, so they are
                        // re-installed each time rather than once at
                        // startup. No gates configured = a closure
                        // that admits everything, which is what the
                        // absence of a gate means anyway.
                        install_live_ingest_policy(ix, gates, cats);
                        // §74: same re-install discipline for the
                        // arrival watch, and for the same reason - the
                        // handle is republished after every full pass.
                        install_instant_watch(ix, matcher);
                        let n = ix.ingest(g, &entries, now).ok()?;
                        // The mark moves only with the rows: an
                        // ingest that failed must not claim the
                        // range.
                        ix.set_high_water(g, &pkey, hi).ok()?;
                        // Drained inside the same lock hold: these are
                        // this batch's arrivals, and leaving them for
                        // later would mix them with the next one's.
                        Some((n, ix.take_watch_hits()))
                    });
                    let Some((_, (hits, dropped))) = done else {
                        break;
                    };
                    instant_arrivals(&daemon2, hits, dropped, now);
                    fresh += (hi - lo + 1) as u32;
                    lo = hi.saturating_add(1);
                }
                if lo <= high {
                    behind = true;
                }
            }
            // Every group leads one tick in turn. A sustained backlog
            // in groups[0] can consume the global deadline, but it can
            // no longer starve every quiet group behind it forever.
            group_cursor = (group_cursor + 1) % groups.len();
            if fresh > 0 && daemon2.index_maintenance_ok() {
                // Fresh posts need `titles` rows before the enricher
                // will look at them, and the wall sorts newest-first
                // - so this is what makes an arriving card get its
                // poster in seconds rather than at the next pass.
                let seeded = daemon2
                    .with_index(|ix| ix.seed_missing_titles(2, 200).ok())
                    .unwrap_or(0);
                info!(
                    target: "tip",
                    "{fresh} new headers{}",
                    if seeded > 0 {
                        format!(", {seeded} titles queued for artwork")
                    } else {
                        String::new()
                    }
                );
            }
            // The interval is how often to CHECK for arrivals, not
            // a throttle on ingesting them. Sleeping it out while a
            // group still had a backlog halved the loop's capacity -
            // measured against alt.binaries.boneless (~900
            // articles/s) that left it permanently ~47k articles
            // behind. Catching up gets a short nap instead, so busy
            // groups get continuous service and quiet ones stay
            // cheap.
            let nap = if behind { 1 } else { every };
            drop(index_pass);
            // Same stand-down as the oracle sampler: once the daemon
            // has been download-idle past the release timeout, hold
            // a session only for the pass that uses it. The steady
            // state here is one GROUP and one empty OVER per tick,
            // so the socket is idle for essentially the whole
            // interval while occupying an account slot - and against
            // a provider capping source IPs, the account.
            //
            // Skipped while `behind`, where the nap is 1 s and the
            // loop is genuinely working: reconnecting between
            // one-second catch-up passes would be churn, and a
            // backlog means the account is in use by this host
            // anyway.
            if !behind && !conns.is_empty() {
                // Config once, not once per held session: the map is
                // keyed by the index's server key, and resolving
                // each key through `find_scan_server` would re-read
                // the file every time.
                let cfg_now = nzbkit::config::Config::load(&config).ok();
                let release: Vec<String> = conns
                    .keys()
                    .filter(|k| {
                        cfg_now.as_ref().is_some_and(|c| {
                            c.servers
                                .iter()
                                .find(|s| nzbkit::index::Index::server_key(&s.host) == **k)
                                .is_some_and(|s| !daemon2.sampler_may_hold(s))
                        })
                    })
                    .cloned()
                    .collect();
                for k in release {
                    if let Some(c) = conns.remove(&k) {
                        c.quit().await;
                    }
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(nap)).await;
        }
    });
}

/// M29: idle STAT sampler - probes indexed releases' articles on one
/// spare connection per enabled server and feeds the availability
/// ledger, stalest-verdict release first. Throttled: `oracle_sample`
/// = STATs/hour/server (live setting, default 300; 0 disables). Sits
/// out whole ticks while a download is active so it never competes
/// for account connection slots.
#[cfg(feature = "indexer")]
pub(super) fn spawn_oracle_sampler(daemon: &Arc<Daemon>, config: &std::path::Path) {
    let config = config.to_path_buf();
    let d = daemon.clone();
    tokio::spawn(async move {
        let mut conns: std::collections::HashMap<String, nzbkit::nntp::Connection> =
            Default::default();
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            let rate = d.oracle_sample.load(Ordering::Relaxed);
            // The ledger it feeds is a table in the index database
            // and the releases it probes are indexed ones, so the
            // master switch takes this with it. Same `conns.clear()`
            // as the other stand-down arms: an idle session held
            // open against a provider is the account's slot, not
            // ours.
            if rate == 0
                || d.offline.load(Ordering::Relaxed)
                || d.indexer_off()
                || d.started_at.lock_ok().is_some()
            {
                // Offline joins the existing stand-down arms, which
                // already drop the map rather than hold sessions
                // open - dropping a Connection closes its socket, so
                // this is the hang-up, not just a bookkeeping reset.
                conns.clear();
                continue;
            }
            // Per-tick budget: ceil(rate/60) STATs per server - the
            // default 300/h probes 5 articles of one release a minute.
            let budget = (rate as usize).div_ceil(60);
            let servers: Vec<nzbkit::config::ServerConfig> =
                match nzbkit::config::Config::load(&config) {
                    Ok(c) => c.servers.into_iter().filter(|s| s.enabled).collect(),
                    Err(_) => continue,
                };
            if servers.is_empty() {
                continue;
            }
            conns.retain(|h, _| servers.iter().any(|s| &s.host == h));
            let picked = d.with_index(|ix| {
                let (id, grp, posted) = ix.oracle_pick(1).ok()?.into_iter().next()?;
                let ids = ix.oracle_msgids(id, budget).ok()?;
                Some((id, grp, posted, ids))
            });
            let Some((rid, grp, posted, ids)) = picked else {
                continue;
            };
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|t| t.as_secs() as i64)
                .unwrap_or(0);
            // Stamp first: even a failed probe rotates the pick, so
            // one bad release can't pin the sampler forever.
            d.with_index(|ix| ix.oracle_mark(rid, now).ok());
            if ids.is_empty() {
                continue;
            }
            let family = nzbkit::oracle::group_family(&grp);
            let bucket = nzbkit::oracle::age_bucket(((now - posted).max(0) / 86_400) as u32);
            let mut samples: Vec<nzbkit::oracle::Sample> = Vec::new();
            for s in &servers {
                if !conns.contains_key(&s.host) {
                    match nzbkit::nntp::Connection::connect(s).await {
                        Ok((c, _)) => {
                            conns.insert(s.host.clone(), c);
                        }
                        Err(e) => {
                            warn!(target: "oracle", "{}: connect: {e}", s.host);
                            continue;
                        }
                    }
                }
                let conn = conns.get_mut(&s.host).expect("just inserted");
                let probe = async {
                    for id in &ids {
                        conn.send_stat(id).await?;
                    }
                    conn.flush().await?;
                    let (mut hits, mut misses) = (0u64, 0u64);
                    for _ in &ids {
                        match conn.read_stat().await? {
                            true => hits += 1,
                            false => misses += 1,
                        }
                    }
                    Ok::<(u64, u64), nzbkit::nntp::NntpError>((hits, misses))
                };
                match tokio::time::timeout(std::time::Duration::from_secs(20), probe).await {
                    Ok(Ok((hits, misses))) => samples.push(nzbkit::oracle::Sample {
                        host: s.host.clone(),
                        family: family.clone(),
                        bucket,
                        hits,
                        misses,
                    }),
                    other => {
                        if let Ok(Err(e)) = other {
                            warn!(target: "oracle", "{}: STAT: {e}", s.host);
                        }
                        // Desynced or mute - reconnect next tick.
                        conns.remove(&s.host);
                    }
                }
            }
            if !samples.is_empty() {
                d.with_index(|ix| ix.oracle_ingest(&samples, now).ok());
            }
            // Give the slots back between ticks, per server, once
            // the daemon has been download-idle past that server's
            // release timeout. This sampler probes ~5 articles a
            // minute: holding the socket for the other 59-odd
            // seconds occupies one of the account's connections -
            // and on a provider limiting source addresses, one of
            // its one or two address slots - permanently, for a few
            // hundred milliseconds of work. Reconnecting costs five
            // round-trips a minute, which is nothing against a
            // sampler already throttled to 300 STATs an hour.
            //
            // Per server so a strict provider cannot make this churn
            // reconnects against a lax one sharing nothing with it.
            for s in &servers {
                if !d.sampler_may_hold(s)
                    && let Some(c) = conns.remove(&s.host)
                {
                    c.quit().await;
                }
            }
        }
    });
}

/// TODO §77 post-health prober: STAT a handful of a queued job's
/// articles across every configured server and hang the verdict on the
/// job, so the queue row can say "posted four days ago, on none of your
/// three servers (8 sampled)" before the bandwidth is spent rather than
/// at 97%. The scoring, and the reasons it is only ever advisory, live
/// in [`crate::health`].
///
/// Discipline copied from `spawn_oracle_sampler` above, and for the same
/// reasons (memory `nzbfast-idle-connection-holders`):
///
/// * it sits out entirely while any download is active, and abandons a
///   probe mid-flight the moment one starts - the account's connection
///   slots, and on a source-IP-capped provider its address slots, belong
///   to the job the user is waiting on;
/// * one connection per host, opened for the probe and closed after it,
///   never borrowed from an active download's pool;
/// * one job per tick, and at most [`crate::health::MAX_PROBES`] probes
///   per job ever, so a queue full of held duplicates cannot turn into a
///   STAT generator.
pub(super) fn spawn_health_prober(daemon: &Arc<Daemon>, config: &std::path::Path) {
    let config = config.to_path_buf();
    let d = daemon.clone();
    tokio::spawn(async move {
        // Jobs whose NZB could not be sampled at all (unreadable, or no
        // articles outside the PAR2 volumes). In memory rather than on
        // the record: it is a property of this file on this disk, not a
        // verdict about the post, and one retry after a restart is the
        // right amount of forgiveness for a share that was offline.
        let mut unsampleable: std::collections::HashSet<String> = Default::default();
        // Jobs whose last probe learned NOTHING (every server refused
        // the login, or none was reachable), and the unix time before
        // which they must not be tried again.
        //
        // Without this, a fruitless probe leaves `health` at None, the
        // pick treats the job as never-sampled, and the next tick
        // connects to the same dead provider - a connect storm against
        // a host that is already having a bad day, once per queued job
        // per tick. A short backoff instead of a permanent give-up: a
        // provider that was down for two minutes should get the job
        // badged when it comes back.
        let mut blind_until: std::collections::HashMap<String, i64> = Default::default();
        // Env-tunable so the daemon suite can compress the timeline, the
        // same way the slow-job watchdog's window is.
        let secs = |k: &str, def: u64| {
            std::env::var(k)
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(def)
                .max(1)
        };
        let tick = secs("NZBFAST_HEALTH_TICK_SECS", 15);
        let recheck = secs(
            "NZBFAST_HEALTH_RECHECK_SECS",
            crate::health::RECHECK_AFTER_SECS as u64,
        ) as i64;
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(tick)).await;
            if !d.post_health.load(Ordering::Relaxed)
                || d.offline.load(Ordering::Relaxed)
                || !download_idle(&d)
            {
                continue;
            }
            let now = unix_now();
            // An expired backoff is not a memory: forget it, and let the
            // job be picked again on its merits.
            blind_until.retain(|_, t| *t > now);
            // One job per tick: the next queued item that has never been
            // sampled, or that has sat here long enough to be worth
            // asking about a second time (a post that was still
            // propagating at add time has usually landed by then).
            let picked = {
                let q = d.queue.lock_ok();
                // Neither side-table may outlive the queue it describes.
                // A daemon that runs for months would otherwise
                // accumulate one entry per job it ever failed to sample,
                // and nothing would ever drop them. Guarded because the
                // set is empty on every healthy install, and the sweep
                // locks every job in the queue.
                if !unsampleable.is_empty() {
                    unsampleable.retain(|id| q.iter().any(|j| j.lock_ok().nzo_id == *id));
                }
                q.iter()
                    .find(|j| {
                        let g = j.lock_ok();
                        g.state == JobState::Queued
                            && !g.tombstone
                            // A paused job (including a held duplicate)
                            // is not going to start, so it is not worth
                            // a provider round trip until it is resumed.
                            && !g.paused
                            && !unsampleable.contains(&g.nzo_id)
                            && blind_until.get(&g.nzo_id).is_none_or(|t| now >= *t)
                            && match &g.health {
                                None => true,
                                Some(h) => {
                                    h.probes < crate::health::MAX_PROBES
                                        && now - h.checked_at >= recheck
                                }
                            }
                    })
                    .cloned()
            };
            let Some(job) = picked else { continue };
            let (nzo_id, nzb_path, total_bytes, probes) = {
                let g = job.lock_ok();
                (
                    g.nzo_id.clone(),
                    g.nzb_path.clone(),
                    g.total_bytes,
                    g.health.as_ref().map_or(0, |h| h.probes),
                )
            };
            let servers: Vec<nzbkit::config::ServerConfig> =
                match nzbkit::config::Config::load(&config) {
                    Ok(c) => c.servers.into_iter().filter(|s| s.enabled).collect(),
                    Err(_) => continue,
                };
            if servers.is_empty() {
                continue;
            }
            // Parsing an NZB is a file read plus an XML pass, and a big
            // one is tens of MB - off the runtime's workers.
            let k = crate::health::sample_size(total_bytes);
            let Ok(Some((ids, age_days))) =
                tokio::task::spawn_blocking(move || sample_ids(&nzb_path, k)).await
            else {
                // An unreadable or article-less NZB is not an error
                // worth logging on every tick: the job simply gets no
                // badge, and the download decides for itself.
                unsampleable.insert(nzo_id.clone());
                continue;
            };
            let mut answers: Vec<crate::health::ServerAnswer> = Vec::new();
            for s in &servers {
                // Re-checked per server, not just once at the top: a job
                // can start between two hosts, and when it does the rest
                // of the probe is abandoned with whatever it has.
                if !download_idle(&d) {
                    break;
                }
                answers.push(probe_server(s, &ids, &d).await);
            }
            let verdict = crate::health::score(&answers, age_days, now, probes + 1);
            {
                let mut g = job.lock_ok();
                // Never overwrite a real verdict with nothing: a probe
                // that ran into a dead network says less than the one
                // that answered an hour ago, and blanking the badge
                // would read as "we stopped worrying about this".
                if let Some(mut v) = verdict {
                    // A waiver is the user's decision about SCHEDULING, not
                    // a fact about the post, so a fresh probe replaces the
                    // evidence and never the decision. `score` always builds
                    // `waived: false`, so without carrying it forward the
                    // hourly re-check silently re-sinks a job the user had
                    // already pulled back up - which is the one thing the
                    // flag exists to prevent.
                    v.waived = g.health.as_ref().is_some_and(|h| h.waived);
                    info!(target: "health", "{nzo_id} {}: {}", v.bucket.as_str(), v.reason);
                    g.health = Some(v);
                    blind_until.remove(&nzo_id);
                } else {
                    // Nothing answered. Back off before asking again,
                    // and burn a probe against any verdict already on
                    // the record so a permanently mute fleet cannot
                    // keep re-asking on an hourly re-check either.
                    blind_until.insert(nzo_id.clone(), now + (tick * 20) as i64);
                    if let Some(h) = g.health.as_mut() {
                        h.probes += 1;
                        h.checked_at = now;
                    }
                }
            }
            d.save_queue();
        }
    });
}

/// Is nothing downloading right now? The prober's whole stand-down rule.
///
/// Both pipelines, not just the primary runner: the idle-server prefetch
/// sidecar holds live NNTP connections of its own (and in the borrow
/// case it deliberately shares a BUSY server's headroom), and the runner
/// clears `started_at` before it awaits the previous job's tail and
/// winds the sidecar down - a span that has run minutes in the field.
/// Probing through that window pipelines STATs onto servers the sidecar
/// is downloading on, which is exactly what §77 stands down to avoid.
fn download_idle(d: &Arc<Daemon>) -> bool {
    d.started_at.lock_ok().is_none() && d.sidecar.lock_ok().is_none()
}

/// The sampled message-ids for one job, and the age in days of the
/// youngest article in the post.
///
/// Stratified over the whole post - first, last and evenly spread -
/// using the same [`nzbkit::preflight::stratified_sample`] the `check`
/// command's sweep uses, over the same file set: PAR2 recovery volumes
/// are excluded because nothing fetches them unless a repair needs them,
/// so their absence says nothing about whether the job can complete.
///
/// The age is the MINIMUM over the files, matching what the failure
/// diagnosis computes (`get.rs`) - a fill or a repost tops an old NZB up
/// with fresh articles, and it is the newest posting that decides
/// whether propagation is still a live explanation.
fn sample_ids(nzb_path: &std::path::Path, k: usize) -> Option<(Vec<String>, u32)> {
    let bytes = std::fs::read(nzb_path).ok()?;
    let nzb = nzbkit::nzb::Nzb::parse(&bytes).ok()?;
    let mut ids: Vec<String> = Vec::new();
    let mut age = u32::MAX;
    for f in &nzb.files {
        if f.kind() == nzbkit::nzb::FileKind::Par2Volume {
            continue;
        }
        age = age.min(crate::nzb_age_days(f.date));
        ids.extend(f.segments.iter().map(|s| format!("<{}>", s.message_id)));
    }
    if ids.is_empty() {
        return None;
    }
    let picked = nzbkit::preflight::stratified_sample(ids.len(), k)
        .into_iter()
        .map(|i| ids[i].clone())
        .collect();
    Some((picked, if age == u32::MAX { 0 } else { age }))
}

/// STAT every sampled id on one server over a single pipelined burst.
///
/// Every failure path - refused login, a dead socket, a peer that goes
/// mute mid-batch - leaves the cells it never reached `Unknown`, which
/// [`crate::health::score`] treats as "this server did not vote" rather
/// than as evidence in either direction. Nothing here can produce a
/// miss that a server did not actually report.
async fn probe_server(
    s: &nzbkit::config::ServerConfig,
    ids: &[String],
    d: &Arc<Daemon>,
) -> crate::health::ServerAnswer {
    use crate::health::Avail;
    let mut cells = vec![Avail::Unknown; ids.len()];
    let host = s.host.clone();
    let Ok((mut conn, _)) = nzbkit::nntp::Connection::connect(s).await else {
        return crate::health::ServerAnswer { host, cells };
    };
    let probe = async {
        for id in ids {
            conn.send_stat(id).await?;
        }
        conn.flush().await?;
        for cell in cells.iter_mut() {
            // `read_stat` is the normalizer both this and the M29
            // sampler share: 223 have, 423/430 missing, and Giganews's
            // nonstandard "451 0 <msgid>" for a takedown counted as a
            // miss rather than thrown away as a protocol error. Do not
            // re-derive it here.
            *cell = match conn.read_stat().await? {
                true => Avail::Have,
                false => Avail::Missing,
            };
        }
        Ok::<(), nzbkit::nntp::NntpError>(())
    };
    // Two ways out, and both end the session immediately: the ordinary
    // 20 s ceiling, and a download starting under us. Dropping the
    // future cancels the probe outright (nothing is spawned), and
    // dropping the Connection closes the socket - so "yield the slot"
    // is not a request the provider has to wait on.
    let clean = tokio::select! {
        r = tokio::time::timeout(std::time::Duration::from_secs(20), probe) => {
            if let Ok(Err(e)) = &r {
                warn!(target: "health", "{host}: STAT: {e}");
            }
            matches!(r, Ok(Ok(())))
        }
        () = async {
            while download_idle(d) {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        } => false,
    };
    // A polite QUIT only on a session that read every reply it asked
    // for. An abandoned or timed-out probe has unread STAT statuses in
    // the socket, so the "goodbye" it would read is somebody else's
    // answer - the same reason the M29 sampler drops a desynced
    // connection rather than tidying it up. Dropping closes it.
    if clean {
        conn.quit().await;
    }
    crate::health::ServerAnswer { host, cells }
}

/// M14k RSS poller. Feeds are a LIVE setting: initial list comes from
/// --feeds (file) with a UI-saved settings.json "feeds" key winning
/// over it; the single poller task re-reads daemon.feeds each pass,
/// so dashboard edits apply without a restart. New items that pass the
/// rules are fetched and enqueued (dupe detection then holds
/// ALTERNATIVEs). Seen-guids persist in the spool so restarts don't
/// re-grab history.
pub(super) fn spawn_rss_poller(
    daemon: &Arc<Daemon>,
    settings_path: &std::path::Path,
    feeds: &Option<PathBuf>,
) -> Result<()> {
    let mut feed_list: Vec<crate::rss::FeedConfig> = Vec::new();
    if let Some(feeds_path) = &feeds {
        feed_list = serde_json::from_slice(&std::fs::read(feeds_path)?)
            .map_err(|e| anyhow::anyhow!("parsing {}: {e}", feeds_path.display()))?;
    }
    if let Some(v) = load_settings(settings_path).get("feeds") {
        match serde_json::from_value(v.clone()) {
            Ok(l) => feed_list = l,
            Err(e) => warn!(target: "rss", "ignoring saved feeds setting: {e}"),
        }
    }
    *daemon.feeds.lock_ok() = feed_list;
    // M35 pull-search indexers ride the same settings file, and the
    // daily usage counters survive a restart via the spool.
    if let Some(v) = load_settings(settings_path).get("indexers") {
        match serde_json::from_value(v.clone()) {
            Ok(l) => *daemon.indexers.lock_ok() = l,
            Err(e) => warn!(target: "indexer", "ignoring saved indexers setting: {e}"),
        }
    }
    if let Ok(b) = std::fs::read(daemon.spool.join("indexer-usage.json"))
        && let Ok(mut u) = serde_json::from_slice::<crate::newznab::Usage>(&b)
    {
        u.roll(unix_now());
        daemon.indexer_rt.lock_ok().usage = u;
    }
    let d = daemon.clone();
    tokio::spawn(async move {
        /// The RSS dedupe set: which guids have already been judged.
        ///
        /// Insertion-ordered alongside the set, and capped. It used to
        /// be a bare HashSet that never shrank under any
        /// configuration, and every single marked item re-serialised
        /// the WHOLE set and durably wrote it - `write_atomic` is
        /// write_all + sync_all + a directory fsync - so one poll cost
        /// O(items x every-guid-ever) of durable I/O. A feed producing
        /// a few hundred guids a day reaches a multi-MB file within a
        /// year, and from then on each new item costs a multi-MB
        /// rewrite plus two fsyncs: real flash wear on a NAS or Pi
        /// spool. Now it evicts the oldest and writes once per pass,
        /// the same accumulate-then-write shape the watchlist watcher
        /// in this file already uses.
        ///
        /// Evicting the oldest, never clearing: a cleared set lets old
        /// items back through the dedupe and re-grabs history, which
        /// is the one thing this file exists to prevent. The cap is
        /// far wider than any rolling feed window.
        struct SeenGuids {
            set: std::collections::HashSet<String>,
            order: std::collections::VecDeque<String>,
            dirty: bool,
        }
        impl SeenGuids {
            const MAX: usize = 20_000;
            fn contains(&self, guid: &str) -> bool {
                self.set.contains(guid)
            }
            fn insert(&mut self, guid: &str) {
                if !self.set.insert(guid.to_string()) {
                    return;
                }
                self.order.push_back(guid.to_string());
                while self.order.len() > Self::MAX {
                    if let Some(old) = self.order.pop_front() {
                        self.set.remove(&old);
                    }
                }
                self.dirty = true;
            }
            /// The on-disk form: a JSON array, byte-compatible with
            /// what the bare HashSet wrote, so an existing
            /// rss-seen.json loads unchanged - it just gains an order.
            fn take_dirty(&mut self) -> Option<Vec<u8>> {
                if !std::mem::take(&mut self.dirty) {
                    return None;
                }
                serde_json::to_vec(&self.order).ok()
            }
        }
        let seen_path = d.spool.join("rss-seen.json");
        let loaded: Vec<String> = std::fs::read(&seen_path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        let seen = Arc::new(Mutex::new(SeenGuids {
            set: loaded.iter().cloned().collect(),
            order: loaded.into(),
            dirty: false,
        }));
        // Per-feed next-poll deadlines, keyed by url (a removed feed's
        // entry just goes stale; a re-added one polls immediately).
        let mut due: std::collections::HashMap<String, Instant> = std::collections::HashMap::new();
        loop {
            let feed_list = d.feeds.lock_ok().clone();
            // §G: forget the health of feeds that are no longer
            // configured, so a removed-and-re-added url starts clean and
            // the map cannot grow across a long-running daemon.
            {
                let live: std::collections::HashSet<&str> =
                    feed_list.iter().map(|f| f.url.as_str()).collect();
                d.feed_health
                    .lock_ok()
                    .retain(|u, _| live.contains(u.as_str()));
            }
            for feed in feed_list {
                let now = Instant::now();
                if due.get(&feed.url).is_some_and(|t| *t > now) {
                    continue;
                }
                due.insert(
                    feed.url.clone(),
                    now + std::time::Duration::from_secs(feed.interval_secs.max(60)),
                );
                let polled = tokio::task::spawn_blocking({
                    let url = feed.url.clone();
                    move || {
                        // parse_feed_checked, not parse_feed: an HTTP
                        // 200 that is not a feed (the login page a
                        // revoked apikey gets) has to reach the failure
                        // arm below, not be recorded as a healthy feed
                        // with nothing new (Codex sweep 2, 3 Aug ML1).
                        let body = fetch_url(&url)?;
                        crate::rss::parse_feed_checked(&String::from_utf8_lossy(&body.bytes))
                            .map_err(|e| anyhow::anyhow!("{url}: {e}"))
                    }
                })
                .await;
                // §G: what this poll did, recorded per feed. Every one of
                // these arms used to collapse to an empty list, so a
                // revoked apikey, a 403, a dead host and a feed with
                // genuinely nothing new were the same event to everyone
                // downstream - including the user, whose settings row
                // said nothing either way.
                let items = match polled {
                    Ok(Ok(items)) => {
                        d.feed_health.lock_ok().insert(
                            feed.url.clone(),
                            crate::rss::FeedHealth::ok(unix_now(), items.len()),
                        );
                        items
                    }
                    Ok(Err(e)) => {
                        // redact_url_creds, always: a feed url essentially
                        // always embeds the indexer's apikey, and both
                        // ureq's Display and fetch_url's own bails lead
                        // with the url they were handed. This string goes
                        // to the log ring AND to the settings row.
                        let h = crate::rss::FeedHealth::failed(
                            unix_now(),
                            &e.to_string(),
                            redact_url_creds,
                        );
                        warn!(target: "rss", "feed poll failed: {}", h.last_error);
                        d.feed_health.lock_ok().insert(feed.url.clone(), h);
                        Vec::new()
                    }
                    Err(e) => {
                        // The blocking task itself died (panic, or a
                        // runtime shutting down). Nothing about the feed
                        // is known; say that rather than "no items".
                        let h = crate::rss::FeedHealth::failed(
                            unix_now(),
                            &format!("the poll did not finish: {e}"),
                            redact_url_creds,
                        );
                        warn!(target: "rss", "feed poll task failed: {}", h.last_error);
                        d.feed_health.lock_ok().insert(feed.url.clone(), h);
                        Vec::new()
                    }
                };
                for it in items {
                    if seen.lock_ok().contains(&it.guid) {
                        continue;
                    }
                    // In memory only; the pass flushes once at the end.
                    let mark_seen = |guid: &str| seen.lock_ok().insert(guid);
                    if !crate::rss::rules_accept(&feed.rules, &it) {
                        // A rules reject is final for this guid.
                        mark_seen(&it.guid);
                        continue;
                    }
                    info!(
                        target: "rss",
                        "grabbing {} ({:.2} GB)",
                        it.title,
                        it.size as f64 / 1e9
                    );
                    let link = it.link.clone();
                    let nzb = tokio::task::spawn_blocking(move || fetch_url(&link)).await;
                    // The guid is marked seen only AFTER the grab
                    // sticks: marking before the fetch meant one
                    // transient 503 permanently dropped the release
                    // (it scrolls off the rolling feed unretried).
                    match nzb {
                        Ok(Ok(fetched)) => {
                            match d.enqueue_fetched(
                                &fetched,
                                &format!("{}.nzb", it.title),
                                &feed.category,
                                -100,
                                None,
                                0,
                                // The feed's own name, so history says
                                // WHICH feed grabbed this.
                                // REDACTED at the store: an RSS feed URL
                                // is `https://indexer/rss?apikey=…`, and
                                // `origin` is emitted verbatim by
                                // `job_json`, the SAB queue and history
                                // endpoints (which every *arr polls, and
                                // logs) and persisted to the history file.
                                // The dashboard already reduces an `rss:`
                                // origin to its hostname; the API never
                                // got the same treatment.
                                &format!("rss:{}", redact_url_creds(&feed.url)),
                                false,
                            ) {
                                // Enqueue failures are content errors
                                // (bad NZB) - retrying can't help.
                                Err(e) => {
                                    warn!(target: "rss", "enqueue {}: {e}", it.title);
                                    mark_seen(&it.guid);
                                }
                                Ok(_) => mark_seen(&it.guid),
                            }
                        }
                        _ => warn!(
                            target: "rss",
                            // Strip the query string: Newznab enclosure URLs
                            // carry the indexer apikey, and this line fires on
                            // every flaky-indexer retry (secret into the logs).
                            "fetch failed (will retry next poll): {}",
                            it.link.split('?').next().unwrap_or("")
                        ),
                    }
                }
                // One durable write per feed pass, not one per item.
                // Still before the next feed is polled, so a crash
                // can lose at most the pass in flight - the same
                // exposure the per-item write had between items.
                if let Some(body) = seen.lock_ok().take_dirty() {
                    let _ = crate::persist::write_atomic(&seen_path, &body);
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        }
    });
    Ok(())
}

/// M23 watchlist watcher. The list is a live setting ("watchlist" in
/// settings.json); grab state persists in the spool so restarts don't
/// re-download what's already on disk. Each pass matches items
/// against the index the scan loop keeps fresh, so "as soon as it
/// appears in a watched group" means one scan interval + one watcher
/// tick at worst - and edits/check-now skip even that.
pub(super) fn spawn_watchlist_watcher(daemon: &Arc<Daemon>, settings_path: &std::path::Path) {
    if let Some(v) = load_settings(settings_path).get("watchlist") {
        match serde_json::from_value(v.clone()) {
            Ok(l) => *daemon.watchlist.lock_ok() = l,
            Err(e) => warn!(target: "watch", "ignoring saved watchlist setting: {e}"),
        }
    }
    let state_path = daemon.spool.join("watchlist-state.json");
    if let Some(v) = crate::persist::load_json_with_backup(&state_path) {
        match serde_json::from_value(v) {
            Ok(s) => *daemon.watch_state.lock_ok() = s,
            Err(e) => warn!(target: "watch", "ignoring {}: {e}", state_path.display()),
        }
    }
    let d = daemon.clone();
    tokio::spawn(async move {
        loop {
            // Sleep first: the initial index scan gets a head start.
            tokio::select! {
                _ = tokio::time::sleep(std::time::Duration::from_secs(60)) => {}
                _ = d.watch_now.notified() => {}
            }
            // The watchlist has TWO legs since M35 phase 2: the
            // local index, and the user's third-party indexer
            // accounts. The built-in indexer's master switch closes
            // the first, so the pass only stands down when it would
            // have nothing left to ask - otherwise a watchlist that
            // runs entirely on external indexers would silently stop
            // because a feature it does not use was switched off.
            // watchlist_external_on(), never the raw bool: the stored
            // flag only counts once the user has answered, and until
            // then the answer is "yes if you have indexer accounts".
            // Reading the bool here stood the whole pass down for the
            // commonest indexer-off setup - accounts configured, the
            // checkbox never touched - while get_config told the
            // dashboard it was ticked, so the card looked armed and
            // "Check now" reported a check that never ran.
            let local = !d.indexer_off();
            if !local && !d.watchlist_external_on() {
                continue;
            }
            let d2 = d.clone();
            // SQLite matching + enqueue (and the calendar's TVmaze
            // refresh) are blocking work.
            let _ = tokio::task::spawn_blocking(move || {
                // The calendar caches its episode lists in the index
                // database, so with no database every lookup looks
                // stale and it would re-fetch the same shows from
                // TVmaze every minute. Skip it rather than let it
                // run uncached; the pass itself does not need it.
                #[cfg(feature = "indexer")]
                if local {
                    watch_calendar_refresh(&d2);
                }
                watchlist_pass(&d2);
            })
            .await;
        }
    });
    #[cfg(feature = "indexer")]
    spawn_instant_recheck(daemon);
}

/// §74: the short re-check behind the instant path's completeness gate.
///
/// A watched release usually arrives before it has finished going up, and
/// the watchlist only grabs complete releases - so a match on an
/// incomplete post is parked here and asked again every
/// [`INSTANT_RECHECK_SECS`] until it completes or ages out to the
/// periodic pass. Nothing is ever concluded from a post staying
/// incomplete: missing articles mean "not yet", never "dead".
///
/// Cheap by construction: one indexed lookup per parked release, and the
/// loop does nothing at all while the map is empty, which is almost
/// always.
#[cfg(feature = "indexer")]
fn spawn_instant_recheck(daemon: &Arc<Daemon>) {
    let d = daemon.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(INSTANT_RECHECK_SECS)).await;
            let parked: Vec<(i64, i64)> = d
                .instant_pending
                .lock_ok()
                .iter()
                .map(|(id, at)| (*id, *at))
                .collect();
            if parked.is_empty() {
                continue;
            }
            let now = unix_now();
            let d2 = d.clone();
            let _ = tokio::task::spawn_blocking(move || {
                let mut ready: Vec<String> = Vec::new();
                let mut done: Vec<i64> = Vec::new();
                for (id, first) in parked {
                    if now - first >= INSTANT_PENDING_SECS {
                        done.push(id);
                        continue;
                    }
                    // One read per parked release; `is_complete` is a
                    // primary-key lookup.
                    let complete = d2
                        .with_index_read(|ix| Some(ix.is_complete(id)))
                        .unwrap_or(false);
                    if complete {
                        done.push(id);
                        if let Some(name) = d2.with_index_read(|ix| ix.stem_by_id(id).ok()?) {
                            ready.push(name);
                        }
                    }
                }
                {
                    let mut pending = d2.instant_pending.lock_ok();
                    for id in done {
                        pending.remove(&id);
                    }
                }
                if !ready.is_empty() {
                    let names = ready.join(", ");
                    if d2.instant_kick(&ready, now) {
                        info!(target: "watch", "finished posting: {names} - checking the watchlist now");
                    }
                }
            })
            .await;
        }
    });
}

/// Download worker: one download at a time at full pipeline speed,
/// but job N's TAIL (settle/repair/extract) overlaps job N+1's
/// download - the network never idles across queue boundaries.
pub(super) fn spawn_download_worker(
    daemon: &Arc<Daemon>,
    config: &std::path::Path,
    index_pass_gate: &Arc<tokio::sync::Mutex<()>>,
    mem_budget: nzbkit::mem::MemBudget,
) {
    let d = daemon.clone();
    let config = config.to_path_buf();
    let index_pass_gate = index_pass_gate.clone();
    // Opened lazily on the first pass with a quota set - the quota
    // (and its period) are live settings now.
    let mut ledger: Option<QuotaLedger> = None;
    tokio::spawn(async move {
        let mut guard_reason: Option<String> = None;
        // The previous job's in-flight tail (≤1 outstanding).
        let mut prev_tail: Option<tokio::task::JoinHandle<()>> = None;
        // In-flight statfs probe for the min-free guard (≤1 outstanding).
        let mut disk_probe: Option<tokio::task::JoinHandle<Option<u64>>> = None;
        loop {
            // M14g guards. Low disk stops everything (a Force job
            // can't write to a full disk either); a spent quota still
            // lets Force jobs through (SAB semantics).
            //
            // statfs on an external or network volume can hang without
            // bound (a NAS share that dropped, a sleeping USB disk), and
            // this loop IS the runner - a hung probe here stops every
            // pick. Probe on the blocking pool with a timeout; a timeout
            // means "unknown", which must not block the pick (None
            // already means the guard stands down, same as a missing
            // directory). Keep the ONE stuck probe and re-await it next
            // pass rather than stacking a new blocked thread per pass.
            let min = d.min_free.load(Ordering::Relaxed);
            let mut free_now: Option<u64> = None;
            if min > 0 {
                let mut probe = disk_probe.take().unwrap_or_else(|| {
                    let out = d.out_dir();
                    tokio::task::spawn_blocking(move || free_bytes(&out))
                });
                match tokio::time::timeout(std::time::Duration::from_secs(2), &mut probe).await {
                    Ok(res) => free_now = res.ok().flatten(),
                    Err(_) => disk_probe = Some(probe),
                }
            }
            if min > 0
                && let Some(free) = free_now
                && free < min
            {
                if guard_reason.as_deref() != Some("disk") {
                    info!(
                        target: "guard",
                        "pausing: {:.1} GB free < {:.1} GB min",
                        free as f64 / 1e9,
                        min as f64 / 1e9
                    );
                    guard_reason = Some("disk".into());
                    // Marker on the transition only - this loop re-checks
                    // every 5 s and the row strip carries the live figure.
                    d.note_event(
                        "disk",
                        format!(
                            "downloads paused - {:.1} GB free is under the {:.1} GB minimum",
                            free as f64 / 1e9,
                            min as f64 / 1e9
                        ),
                    );
                }
                // Refreshed every pass, not just on entry: the free
                // figure moves while the user clears space, and the row
                // strip shows it live.
                *d.queue_hold.lock_ok() =
                    Some(("disk".into(), free as f64 / 1e9, min as f64 / 1e9));
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                continue;
            }
            // Offline outranks everything below, INCLUDING Force.
            //
            // It has to be its own gate rather than a term in
            // `only_force`, because Force is defined as the thing that
            // walks past a paused queue - and offline only ever reached
            // this loop as a pause it set on the way through. So a
            // priority-2 job started while the header said Offline, the
            // fleet reopened, and the operator's OTHER machine was
            // refused at the account's connection cap with no reason to
            // suspect this daemon (TODO 65). Force is not even reliably
            // the user's own choice: the retry/start path hard-codes
            // `priority = 2` on its behalf.
            //
            // Offline is not a scheduling state like pause; it is a
            // promise about the network, made in absolute terms - the
            // confirm dialog says every connection is closed "so you can
            // use the account from another machine", and startup logs
            // "touching no provider". Coming back online is the only act
            // that releases it, which is one click and is what the
            // button already says.
            if d.offline.load(Ordering::Relaxed) {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                continue;
            }
            let mut only_force = d.paused.load(Ordering::Relaxed);
            let quota = d.quota.load(Ordering::Relaxed);
            let period = d.quota_period.load(Ordering::Relaxed) as char;
            if quota > 0 || ledger.is_some() {
                // (Re)open on first use or a live period change; keep
                // billing an open ledger even if the cap is lifted so
                // re-enabling sees the true window usage.
                if ledger.as_ref().is_none_or(|l| l.period != period) {
                    ledger = Some(QuotaLedger::open(&d.spool, period));
                }
            }
            if let (Some(led), true) = (ledger.as_mut(), quota > 0)
                && led.spent() >= quota
            {
                if guard_reason.as_deref() != Some("quota") {
                    info!(
                        target: "guard",
                        "quota spent ({:.1} of {:.1} GB) - only Force jobs until the period rolls over",
                        led.bytes as f64 / 1e9,
                        quota as f64 / 1e9
                    );
                    guard_reason = Some("quota".into());
                    d.note_event(
                        "quota",
                        format!(
                            "download quota spent ({:.1} of {:.1} GB) - only Force \
                             jobs run until the period rolls over",
                            led.bytes as f64 / 1e9,
                            quota as f64 / 1e9
                        ),
                    );
                }
                *d.queue_hold.lock_ok() =
                    Some(("quota".into(), led.spent() as f64 / 1e9, quota as f64 / 1e9));
                only_force = true;
            }
            if guard_reason.is_some() && !only_force {
                info!(target: "guard", "cleared");
                guard_reason = None;
                d.note_event(
                    "clear",
                    "the space and quota guards cleared - downloads resume",
                );
            }
            if guard_reason.is_none() {
                let mut h = d.queue_hold.lock_ok();
                if h.is_some() {
                    *h = None;
                }
            }
            d.run_due_auto_retries();
            let Some(job) = d.pick_job(only_force) else {
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                continue;
            };
            // Never start a primary while this job's prefetch sidecar
            // still runs (possible when a library pick bypassed the
            // job-end stop below).
            {
                let picked = job.lock_ok().nzo_id.clone();
                let holds = d
                    .sidecar
                    .lock()
                    .unwrap()
                    .as_ref()
                    .is_some_and(|s| s.nzo_id == picked);
                if holds {
                    stop_sidecar(&d).await;
                    // The sidecar may have FINISHED this job while we
                    // waited. Its success arm marks the job Completed
                    // and hands the post-processing tail to a task of
                    // its own, so that tail can be unlocking, renaming
                    // or moving `out_dir` right now. Starting the
                    // pipeline would point a fresh download at the
                    // directory being moved out from under it, so
                    // re-read what we picked on and let the job go if
                    // it is no longer waiting to run.
                    let j = job.lock_ok();
                    if j.paused || j.state != JobState::Queued {
                        continue;
                    }
                }
            }
            let (nzb_path, out_dir, total, library, nzo_id, name, prio, job_password, eat_ok) = {
                let mut j = job.lock_ok();
                j.state = JobState::Downloading;
                // Late-pick marker: the runner was free when this job
                // arrived, yet took over 2 s to start it - the signature
                // of the fixed runner-starvation bug, named so any
                // recurrence attributes itself. Taken, not read, so a
                // job that requeues can never replay a stale stamp.
                if let Some(waited) = j
                    .queued_at
                    .take()
                    .filter(|_| j.idle_at_add)
                    .map(|t| t.elapsed())
                    .filter(|w| *w > std::time::Duration::from_secs(2))
                {
                    d.note_event(
                        "late",
                        format!(
                            "{} started {:.1} s after it was added with nothing \
                             ahead of it - the runner was slow to pick it up",
                            j.name,
                            waited.as_secs_f64()
                        ),
                    );
                }
                (
                    j.nzb_path.clone(),
                    j.out_dir.clone(),
                    j.total_bytes,
                    j.library,
                    j.nzo_id.clone(),
                    j.name.clone(),
                    j.priority,
                    j.password.clone(),
                    j.eat_volumes_ok,
                )
            };
            let index_job_guard = d.begin_index_job();
            // Raise the guard first so an active scan observes it and
            // cancels, then rendezvous on the shared gate. Once this
            // lock is acquired no scan, tip ingest, eviction or
            // VACUUM can still be running beside the foreground job.
            if d.index_pause_on_download.load(Ordering::Relaxed) {
                let idle = index_pass_gate.lock().await;
                drop(idle);
            }
            // Claim the shared progress counters for THIS job, in one
            // lock section with the zeroing they describe. A queue
            // payload that reads the owner can then never pair it with
            // the next job's zeroes: it either gets the lock first and
            // sees the previous owner with the previous counters, or
            // gets it after and sees this job with this job's.
            {
                let mut owner = d.active_dl.lock_ok();
                d.progress.store(0, Ordering::Relaxed);
                d.active_total.store(total, Ordering::Relaxed);
                // The UX §15 fetch-plan pair goes with them, and the plan
                // is zeroed FIRST: a reader that catches the gap sees "no
                // plan" and falls back to the counters above, never a
                // fresh plan paired with the previous job's finished
                // count.
                d.hub.fetch_plan.store(0, Ordering::Relaxed);
                d.hub.fetch_done.store(0, Ordering::Relaxed);
                *owner = Some(nzo_id.clone());
            }
            let t_start = Instant::now();
            *d.started_at.lock_ok() = Some(t_start);

            // A /stream trigger re-queues a library entry at Force
            // priority - that's the "actually download now" signal.
            if library && prio < 2 {
                // M14i metadata-only: STAT-sample availability instead of
                // downloading. Pass → Completed + .strm pointer; the real
                // fetch happens on first /stream/<id> playback.
                d.hub.activity.lock_ok().insert(nzo_id.clone(), "preflight");
                let verdict = crate::check(&config, &nzb_path, 10, 4, 50).await;
                {
                    let mut j = job.lock_ok();
                    match verdict {
                        Ok(crate::Verdict::Impossible {
                            est_missing,
                            recovery,
                            ..
                        }) => {
                            j.state = JobState::Failed;
                            // The counts make the verdict checkable;
                            // append-only, the prefix is classified on.
                            j.fail_message = crate::with_build(format!(
                                "pre-flight: articles missing beyond repair - an \
                                 estimated {est_missing} payload segment(s) \
                                 unavailable vs {recovery} recovery block(s) in the NZB"
                            ));
                        }
                        Ok(_) => {
                            j.state = JobState::Completed;
                            if let Err(e) = write_strm(
                                &out_dir,
                                &name,
                                d.port,
                                &nzo_id,
                                &d.stream_token(&nzo_id),
                            ) {
                                warn!(target: "strm", "write for {nzo_id}: {e}");
                            }
                        }
                        Err(e) => {
                            j.state = JobState::Failed;
                            j.fail_message = e.to_string();
                        }
                    }
                    j.finished_at = Some(Instant::now());
                    j.finished_unix = Some(unix_now());
                }
                *d.started_at.lock_ok() = None;
                *d.last_download_end.lock_ok() = Instant::now();
                d.run_post_job_hooks(&job);
                d.park(job);
                continue;
            }

            // Bracket this job's console output. Everything the
            // failure diagnosis needs - the per-file segment tally,
            // the per-server table, the first transport error - is
            // PRINTED and then lost: the log ring is memory-only and
            // 2000 lines deep, so a daemon restart (or a busy hour)
            // takes it with it, and the one-line fail_message is all
            // that reaches history. Marked before any of this job's
            // work so the snapshots below are its lines, nobody else's.
            let log_mark = nzbkit::logtee::mark();

            // Opt-in pre-flight (settings.json `preflight`): sample
            // this post's articles before spending the bandwidth. A
            // post nothing carries any more is otherwise discovered
            // the slow way - every article asked of every server, at
            // full retry ladder, for a verdict a 10% STAT sample
            // reaches in seconds. Only `Impossible` stops the job:
            // "repairable" is what PAR2 is for, and an errored sweep
            // (a provider hiccup mid-probe) must never fail a job the
            // download itself might well complete.
            if d.preflight.load(Ordering::Relaxed) {
                d.hub.activity.lock_ok().insert(nzo_id.clone(), "preflight");
                match crate::check(&config, &nzb_path, 10, 4, 50).await {
                    Ok(crate::Verdict::Impossible {
                        est_missing,
                        recovery,
                        ..
                    }) => {
                        {
                            let mut j = job.lock_ok();
                            j.state = JobState::Failed;
                            j.fail_message = crate::with_build(format!(
                                "pre-flight: articles missing beyond repair - an \
                                 estimated {est_missing} payload segment(s) \
                                 unavailable vs {recovery} recovery block(s) in the NZB"
                            ));
                            j.fail_detail = crate::fail_detail_snapshot(log_mark);
                            j.finished_at = Some(Instant::now());
                            j.finished_unix = Some(unix_now());
                        }
                        *d.started_at.lock_ok() = None;
                        d.run_post_job_hooks(&job);
                        d.park(job);
                        continue;
                    }
                    Ok(_) => {}
                    Err(e) => info!(target: "preflight", "sweep failed, downloading anyway: {e}"),
                }
            }

            // Block accounts: rule exhausted hosts out of this job's
            // pool (lifetime usage ≥ the configured block size).
            {
                let cfg_now = nzbkit::config::Config::load(&config).ok();
                let excluded: Vec<String> = cfg_now
                    .as_ref()
                    .map(|c| {
                        c.servers
                            .iter()
                            .filter(|s| {
                                s.block_bytes
                                    .is_some_and(|b| b > 0 && d.usage_lifetime(&s.host) >= b)
                            })
                            .map(|s| s.host.clone())
                            .collect()
                    })
                    .unwrap_or_default();
                *d.hub.excluded_hosts.lock_ok() = excluded;
            }
            // M2c.5: allow the engine's speculative recovery prefetch
            // for the main job unless a period quota is configured -
            // same reasoning as the sidecar guard: opportunistic
            // fetches must not race a metered budget.
            d.hub
                .spec_prefetch
                .store(d.quota.load(Ordering::Relaxed) == 0, Ordering::Relaxed);
            *d.active_stream.lock_ok() = Some(nzo_id.clone());
            // Queue-row sub-line: fetching, from here until the pipeline
            // itself advances the token at its section transitions.
            d.hub.activity.lock_ok().insert(nzo_id.clone(), "fetching");
            // Clear the hub's per-job slots BEFORE the fetch spawns: if
            // get_with_progress errors before repopulating them (bad
            // NZB, config error), net_rx resolves by drop and the
            // net-drain accounting below would otherwise re-read the
            // PREVIOUS job's pool/verifier - double-billing its bytes
            // and article counts and stamping its bad blocks here.
            *d.hub.pool_live.lock_ok() = None;
            *d.hub.verifier.lock_ok() = None;
            // Same reason, for the resume credit: a leftover figure from
            // the previous job would be subtracted from THIS job's
            // network bytes, under-billing its quota and under-reporting
            // its speed.
            d.hub.resume_seeded.store(0, Ordering::Relaxed);
            // M29 oracle: fresh per-job sink - the pool records each
            // article's hit/430 into it; drained to the ledger below.
            *d.hub.oracle.lock_ok() = Some(Arc::new(nzbkit::oracle::OracleSink::default()));
            // M29 opt-in routing: install a ledger snapshot for this
            // job only when `oracle_route` is on, so get_with_progress
            // can skip providers confidently gone for the release's
            // (family, age-bucket). Off → cleared, so a plain job never
            // consults it. A wrong verdict costs only latency (the
            // engine never removes the last usable provider).
            #[cfg(feature = "indexer")]
            {
                *d.hub.route_gone.lock_ok() = if d.oracle_route.load(Ordering::Relaxed) {
                    d.with_index(|ix| ix.oracle_snapshot().ok())
                } else {
                    None
                };
            }
            // Slim build: no availability ledger, so no snapshot to route by.
            #[cfg(not(feature = "indexer"))]
            {
                *d.hub.route_gone.lock_ok() = None;
            }
            // Also drop the previous job's extractor. It is otherwise
            // left installed for post-completion streaming, but now that
            // active_stream points at THIS job, a /stream/<this id>
            // request passes the owner check while the fetch is still
            // parsing the NZB / restoring the journal (or forever, if it
            // errors first) - and pick_media would map the request onto
            // the stale extractor and serve the PREVIOUS job's file. With
            // it cleared, the stream blocks until this job installs its
            // own extractor (main.rs), which is the correct wait.
            *d.hub.extractor.lock_ok() = None;
            // And the previous job's late-attached password (C1): the
            // owner tag already keeps a stale entry from ever matching
            // this job's reads, so this is hygiene, not correctness.
            *d.hub.late_password.lock_ok() = None;
            // Same owner-tag hygiene for the live wants-a-password
            // signal and the probe's verified winner - a stale tag
            // never matches this job's slot or record.
            *d.hub.password_wanted.lock_ok() = None;
            *d.hub.password_found.lock_ok() = None;
            // And the seek handle with it: SeekCtl holds a STRONG
            // extractor reference, so a stale one would pin the
            // previous job's whole extractor graph until this job
            // happens to overwrite it - or forever, if the fetch
            // errors first or the daemon idles.
            *d.hub.seek.lock_ok() = None;
            let (net_tx, net_rx) = tokio::sync::oneshot::channel::<()>();
            let fetch = {
                let config = config.clone();
                let nzb_path = nzb_path.clone();
                let out_dir = out_dir.clone();
                let progress = d.progress.clone();
                let hub = d.hub.clone();
                let stream_owner = nzo_id.clone();
                // Live settings, sampled once per job: a dashboard
                // change applies from the NEXT download.
                let connections = d.connections.load(Ordering::Relaxed).max(1);
                let window = d.window.load(Ordering::Relaxed).max(1);
                let decoders = d.decoders.load(Ordering::Relaxed).max(1);
                let fast_verify = d.fast_verify.load(Ordering::Relaxed);
                let verify_lean = d.verify_lean.load(Ordering::Relaxed);
                let par_cleanup = d.par_cleanup.load(Ordering::Relaxed);
                tokio::spawn(async move {
                    crate::get_with_progress(
                        &config,
                        &nzb_path,
                        &out_dir,
                        connections,
                        window,
                        decoders,
                        fast_verify,
                        verify_lean,
                        false,
                        par_cleanup,
                        job_password,
                        eat_ok,
                        Some(progress),
                        Some(hub),
                        &stream_owner,
                        Some(net_tx),
                        mem_budget,
                    )
                    .await
                })
            };
            // This download runs WHILE the previous job's tail
            // finishes on disk/CPU. net_rx resolves at network-drain
            // (or is dropped by an early error - same meaning: no
            // more network work for this job).
            let _ = net_rx.await;
            // Network wall time stops HERE, not after the prev-tail
            // wait below: bytes÷seconds is the history's average speed,
            // and a stalled tail once inflated a 72 s download to a
            // recorded 121 s.
            let dl_secs = t_start.elapsed().as_secs_f64();
            // Stand the watchdog down BEFORE waiting on the previous
            // tail, not after: `started_at` means "this job's network
            // phase is live", and the wait below can be long (job N-1's
            // tail once sat minutes in a Finder-trash stall). This job
            // is still Downloading in the queue for all of it, and the
            // watchdog reading a drained pool as "one host at ~0 MB/s
            // while others wait" demoted a job that had already
            // finished - park then re-queued it after post-processing
            // had renamed its directory, and the whole release
            // downloaded a second time (31 Jul queue soak).
            *d.started_at.lock_ok() = None;
            // Phase marker: the pipeline (download AND checks) is over.
            // This is what closes the chart's "checking files" shading -
            // without it the tint would run on into the idle time after
            // the job, dressing ordinary quiet as an endless check.
            d.note_event(
                "finished",
                "job finished - the line is idle until the next download",
            );
            // Release the progress counters at the same instant and for
            // the same reason: from here this job reads 100% and its
            // phase word, and the next job is free to zero them without
            // its bar appearing on this one's row.
            *d.active_dl.lock_ok() = None;
            // The network phase is what occupies the account, so the
            // idle clock starts here rather than after the tail: the
            // post-processing that follows touches no provider.
            *d.last_download_end.lock_ok() = Instant::now();
            // ≤1 outstanding tail: the previous one had this whole
            // download's wall-clock to finish; usually a no-op await.
            if let Some(h) = prev_tail.take() {
                let _ = h.await;
            }
            // Wind down any idle-server prefetch before the next pick:
            // the next primary may be the very job the sidecar holds,
            // and two pipelines must never share an out_dir or a
            // server's connection budget. Its journal keeps the bytes.
            stop_sidecar(&d).await;
            // Decoded-byte count is final at network-drain (consumers
            // joined before the signal fires) - safe to bill the quota
            // before the next job resets the counter.
            if let Some(led) = ledger.as_mut() {
                led.add(d.progress.load(Ordering::Relaxed));
            }
            // History stats: decoded bytes + network wall time, final
            // at net-drain (the NEXT job resets the progress counter,
            // so capture before looping).
            let dl_bytes = d.progress.load(Ordering::Relaxed);
            // ...and the same figure plus whatever a resume already had
            // on disk, which is what a paused row needs to report. Read
            // here for the same reason `dl_bytes` is: the tail task
            // below runs concurrently with the next iteration, and that
            // zeroes both.
            let on_disk_bytes =
                dl_bytes.saturating_add(d.hub.resume_seeded.load(Ordering::Relaxed));
            // Bill this job's per-server bytes to the usage history
            // (pool_live is still THIS job's - the next one hasn't
            // started yet), and its article tries/430s to the
            // reliability ledger.
            let (per_server, per_server_rel): (Vec<(String, u64)>, Vec<(String, u64, u64)>) = d
                .hub
                .pool_live
                .lock()
                .unwrap()
                .as_ref()
                .map(|l| {
                    l.servers
                        .iter()
                        .map(|s| {
                            (
                                (s.host.clone(), s.bytes.load(Ordering::Relaxed)),
                                (
                                    s.host.clone(),
                                    s.articles_tried.load(Ordering::Relaxed),
                                    s.articles_missing.load(Ordering::Relaxed),
                                ),
                            )
                        })
                        .unzip()
                })
                .unwrap_or_default();
            d.add_usage(&per_server);
            d.add_reliability(&per_server_rel);
            // M29 oracle: fold this job's per-article outcomes into
            // the availability ledger (one batched transaction).
            #[cfg(feature = "indexer")]
            if let Some(sink) = d.hub.oracle.lock_ok().take() {
                let samples = sink.drain();
                if !samples.is_empty() {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|t| t.as_secs() as i64)
                        .unwrap_or(0);
                    d.with_index(|ix| ix.oracle_ingest(&samples, now).ok());
                }
            }
            // The verifier is still THIS job's too - keep the Arc so
            // the tail task reads the final in-stream bad-block count
            // even after the next job swaps the hub's slot.
            let verifier = d.hub.verifier.lock_ok().clone();
            // Same reason for the extractor: the shape is only final
            // once the tail has settled (a late demote in
            // finish/verify flips a set to "partly on disk"), and by
            // then the next job may own the hub slot.
            let shaper = d.hub.extractor_for(Some(&nzo_id));
            let d2 = d.clone();
            let job2 = job.clone();
            prev_tail = Some(tokio::spawn(async move {
                let _index_job_guard = index_job_guard;
                let res = match fetch.await {
                    Ok(r) => r,
                    Err(e) => Err(anyhow::anyhow!("download task panicked: {e}")),
                };
                // The download is over: hand the operating system back
                // every output file descriptor before anything else runs.
                //
                // `Extractor::finish` deliberately KEEPS its writers open
                // (see `park_outputs`), and the hub leaves the extractor
                // installed until the NEXT job starts - so on an idle
                // daemon a finished job's handles are held indefinitely.
                // On unix an unlinked file with a live descriptor keeps
                // its blocks, and unlinking those files is exactly what
                // happens after a download: cleanup deletes the volumes,
                // then an *arr imports the release and removes the
                // folder. The space never came back, the folder would not
                // delete over a share that cannot remove an open file,
                // and restarting the daemon was the only cure (reported
                // on Unraid, 2 Aug). A FAILED or paused job holds its
                // partial volumes open just as long, so this sits above
                // every exit path below rather than in the completed arm.
                //
                // Parking, not clearing: the extractor stays installed,
                // so the shape/CRC latch below and `writers_snapshot`
                // keep working. Nothing that serves bytes needs these
                // handles - `serve_range` opens the path itself, and a
                // finished job streams from disk through
                // `find_completed_media` - and the sweeps and renames in
                // `finalize_completed` are happier with them closed.
                if let Some(ex) = &shaper
                    && let Err(e) = ex.park_outputs()
                {
                    warn!(target: "cleanup", "could not release the output handles: {e}");
                }
                // M23e: a pause aborted this job - put it back in the
                // queue (not history) so resume continues it from the
                // journal. If it somehow completed despite the abort,
                // fall through and file it normally.
                let was_suspended = {
                    let g = job2.lock_ok();
                    g.suspended && !g.tombstone
                };
                if was_suspended && res.is_err() {
                    {
                        let mut j = job2.lock_ok();
                        j.state = JobState::Queued;
                        j.suspended = false;
                        // What is on disk, not what this run fetched:
                        // the queue row reports its percentage from this
                        // while paused, and a job paused twice would
                        // otherwise report only the second stint. It was
                        // not recorded here at all - a paused row read
                        // 0% with the full size still to go, which is
                        // the exact reading that has users deleting a
                        // job whose journal is intact.
                        j.downloaded_bytes = on_disk_bytes;
                        info!(
                            target: "pause",
                            "{} parked back in the queue ({:.2} GB already on disk)",
                            j.nzo_id,
                            on_disk_bytes as f64 / 1e9
                        );
                    }
                    d2.save_queue();
                    return;
                }
                job2.lock_ok().suspended = false;
                let demoted = {
                    let mut j = job2.lock_ok();
                    match &res {
                        Ok(_) => {
                            j.state = JobState::Completed;
                            j.fetched = true;
                        }
                        Err(e) => {
                            j.state = JobState::Failed;
                            j.fail_message = e.to_string();
                            // TODO §77: fold the pre-flight sample into
                            // the failure evidence. "It was already
                            // short when you added it" and "it rotted
                            // out from under the download" call for
                            // different things - a replacement from the
                            // indexer versus a retry - and after the
                            // fact nothing else can tell them apart.
                            //
                            // APPENDED, never prefixed: `fail_kind`, the
                            // *arr health mapping and the diag tests all
                            // key on the opening clause, exactly as the
                            // segment census does in `incomplete_reason`.
                            if let Some(h) = j.health.as_ref()
                                && crate::serve::fail_kind(&j.fail_message).post_unavailable()
                                && let Some(clause) = crate::health::failure_clause(h)
                            {
                                j.fail_message.push_str(&clause);
                            }
                            // A disk that filled up during the unpack is
                            // the one failure where the fix is entirely
                            // in the user's hands and the cost of the
                            // retry is near zero: the spent-volume sweep
                            // only removes volumes after a SUCCESSFUL
                            // extraction, so the downloaded parts are
                            // still on disk and mode=retry resumes from
                            // the article journal without re-fetching a
                            // byte. Say so, with the amount to free -
                            // the extracted payload is roughly the size
                            // of the set. APPENDED, same rule as the
                            // health clause above.
                            if crate::serve::disk_full_failure(&j.fail_message) {
                                let clause = format!(
                                    "; free about {:.1} GB on that disk and hit Retry - the downloaded archive parts are kept, so nothing is re-downloaded and only the unpack re-runs",
                                    j.total_bytes as f64 / 1e9
                                );
                                j.fail_message.push_str(&clause);
                            }
                            // Keep the console block that explains the
                            // one-liner. Failures are where a user
                            // needs the log MOST and where it is least
                            // likely to still be there when they look.
                            j.fail_detail = crate::fail_detail_snapshot(log_mark);
                        }
                    }
                    j.downloaded_bytes = dl_bytes;
                    j.elapsed_secs = dl_secs;
                    // A verdict only where something actually verified.
                    // `live_counts()` is (ok + bad, bad): no verifier at
                    // all (par2-less post) and a verifier that mapped
                    // nothing (the resume case) both check zero blocks,
                    // and neither is evidence the payload is clean. Keep
                    // an earlier run's verdict rather than overwriting it
                    // with "unknown" - a retry that maps nothing in
                    // stream must not erase what the first pass proved.
                    let (checked, bad) = verifier.as_ref().map_or((0, 0), |v| v.live_counts());
                    if checked > 0 {
                        j.bad_blocks = Some(bad);
                        j.verify_blocks = checked;
                    }
                    // Latch the shape for history. Keep whatever a
                    // previous run learned if this one recognized
                    // nothing (a resume maps nothing in-stream, and
                    // reporting "no archive" for a retried RAR5 set
                    // would be a downgrade, not an update).
                    if let Some(tag) = shaper.as_ref().and_then(|e| e.archive_shape()) {
                        j.archive_shape = tag.tag();
                    }
                    // Same latch-don't-downgrade rule, same reason:
                    // a resumed run maps nothing in-stream, and the
                    // headers this key came from are not on disk to
                    // read again.
                    if let Some((_, crc)) = shaper.as_ref().and_then(|e| e.inner_crc()) {
                        j.inner_crc = crc;
                    }
                    j.finished_at = Some(Instant::now());
                    j.finished_unix = Some(unix_now());
                    // A demotion only HAPPENED if the watchdog's abort
                    // actually took the download down. When the flag
                    // loses the race with the finish line the job is a
                    // plain completion: it gets its hooks below, and
                    // park files it to history (clearing the flag)
                    // instead of re-queueing a finished release.
                    res.is_err() && j.demote
                };
                // Feed the watchdog's reference: every job's average
                // network rate is an observed "the line can do this"
                // sample (short bursts are too noisy to count).
                if dl_secs >= 0.5 && dl_bytes > 0 {
                    let avg = (dl_bytes as f64 / dl_secs) as u64;
                    d2.best_rate_bps.fetch_max(avg, Ordering::Relaxed);
                }
                finalize_completed(&d2, &job2).await;
                // A watchdog demotion is not a completion - no
                // script and no notification; park() requeues it
                // deferred.
                if !demoted {
                    d2.run_post_job_hooks(&job2);
                }
                d2.park(job2);
            }));
        }
    });
}

/// M14i background re-verify: library entries are only pointers, so the
/// content can rot out from under them. Periodically re-sample parked
/// (never-fetched) Completed library jobs; a vanished post flips to
/// Failed and the *arrs' failed-download handling re-grabs elsewhere.
pub(super) fn spawn_library_recheck(daemon: &Arc<Daemon>, config: &std::path::Path) {
    let d = daemon.clone();
    let config = config.to_path_buf();
    tokio::spawn(async move {
        loop {
            let every = d.library_recheck_secs.load(Ordering::Relaxed).max(1);
            tokio::time::sleep(std::time::Duration::from_secs(every)).await;
            let jobs: Vec<_> = {
                let h = d.history.lock_ok();
                h.iter()
                    .filter(|job| {
                        let j = job.lock_ok();
                        j.library && !j.fetched && j.state == JobState::Completed
                    })
                    .cloned()
                    .collect()
            };
            for job in jobs {
                let nzb_path = job.lock_ok().nzb_path.clone();
                if let Ok(crate::Verdict::Impossible { .. }) =
                    crate::check(&config, &nzb_path, 10, 4, 50).await
                {
                    {
                        let mut j = job.lock_ok();
                        j.state = JobState::Failed;
                        j.fail_message = "content no longer retrievable".into();
                        info!(target: "library", "{} vanished - marked Failed", j.nzo_id);
                    }
                    d.save_queue();
                }
            }
        }
    });
}

// ---------------------------------------------------------------------------
// TODO §76: the queue-row media prober
// ---------------------------------------------------------------------------

/// How often the prober looks at the running job. Env-tunable so the
/// daemon suite can compress the timeline, like the defer watchdog's.
fn media_tick() -> std::time::Duration {
    std::time::Duration::from_millis(
        std::env::var("NZBFAST_MEDIA_TICK_MS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(5_000)
            .max(50),
    )
}
/// Attempts at the fast cadence before backing off. A container header
/// is usually readable within one or two ticks; past a minute of trying,
/// the missing region is a trailing index that arrives with the download
/// and there is nothing to gain from asking twice a minute.
const MEDIA_FAST_TRIES: u32 = 12;
const MEDIA_SLOW: std::time::Duration = std::time::Duration::from_secs(30);
/// How long a finished job stays on the final-pass list. Post-processing
/// on a large release is minutes (unpack, repair, rename, a move to a
/// NAS); half an hour covers that and stops a job that never reaches
/// history from being retried forever.
const MEDIA_FINAL_WINDOW: std::time::Duration = std::time::Duration::from_secs(1800);

/// The name a mismatch is judged against: what an identity oracle
/// concluded, when one answered, and the posted name otherwise.
///
/// This matters most on exactly the posts the feature is for. An
/// obfuscated stem claims nothing - `parse_release` finds no resolution
/// and no codec in "a4f9c2e1", so nothing can contradict it - while the
/// canonical name srrdb or xREL handed back claims everything. Judging
/// the bytes against that is free here and impossible anywhere else.
fn media_claim_name(j: &Job) -> String {
    if j.identity_name.is_empty() {
        j.name.clone()
    } else {
        j.identity_name.clone()
    }
}

/// Has this job's chip stopped changing? A partial answer is worth
/// showing - the resolution lands before the audio - but it is not worth
/// keeping. A chip owed a re-judge (the identity oracle answered after
/// pass 1 settled) is not settled either: the facts are complete but the
/// NAME they were judged against has changed.
fn media_settled(j: &Job) -> bool {
    !j.media_rejudge && j.media.as_ref().is_some_and(|m| m.complete && m.any())
}

/// Latch a probe result, never downgrading. Same rule as
/// [`Job::archive_shape`] and for the same reason: a later pass that
/// could read less (a renamed file the on-disk walk no longer finds, a
/// resumed job whose writer maps nothing) must not replace an answer
/// that was right.
fn latch_media(job: &Arc<Mutex<Job>>, facts: nzbkit::mediaprobe::MediaFacts) -> bool {
    let mut j = job.lock_ok();
    if !facts.any() && j.media.is_some() {
        return false;
    }
    if j.media.as_ref() == Some(&facts) {
        return false;
    }
    if !facts.mismatch.is_empty() {
        let list: Vec<String> = facts
            .mismatch
            .iter()
            .map(|m| format!("{} claimed, {} found", m.claimed, m.actual))
            .collect();
        info!(
            target: "media",
            "{}: the file contradicts its name - {}",
            j.nzo_id,
            list.join("; ")
        );
    }
    j.media = Some(facts);
    true
}

/// §76: read the main video's own header while it downloads, so the
/// queue row can say what the file actually IS - "2160p HEVC · DDP 5.1"
/// - and say so when that contradicts the name the post carries.
///
/// The probe itself is [`nzbkit::mediaprobe`], which §73 phase 1 built
/// for the preview panel: this task exists because the panel's answer is
/// per-open-drawer and per-request, and a queue row needs one that is
/// already computed, already durable, and shared by every client polling
/// the queue. It reads container headers only (a few hundred KB, skipping
/// every payload region by arithmetic) off an ordinary blocking thread.
///
/// Two passes, deliberately:
///
/// 1. While a job runs, over the live writer. Bytes that have not landed
///    read as a gap, never as a wait, and this pass NEVER promotes
///    articles - the preview endpoint may reorder a download because a
///    user is watching that file, but a background badge has no business
///    perturbing fetch order for every job on the queue.
/// 2. Once, on disk, after the job leaves the queue. Archive shapes that
///    unpack after the download write no media file until post-processing
///    finishes, so pass 1 sees nothing at all for them; and a shape that
///    does write one may still have been reading a trailing index that
///    only completes at the end.
pub(super) fn spawn_media_prober(daemon: &Arc<Daemon>) {
    let d = daemon.clone();
    tokio::spawn(async move {
        // The job pass 1 is watching, its attempt count, and when it is
        // next due. All task-local: nothing else needs to know, and a
        // restart correctly starts over.
        let mut watching: Option<String> = None;
        let mut tries: u32 = 0;
        let mut due = std::time::Instant::now();
        // Jobs that left the queue owing a final on-disk pass.
        let mut finals: Vec<(String, std::time::Instant)> = Vec::new();
        let tick = media_tick();
        loop {
            tokio::time::sleep(tick).await;
            // The job actually on the wire. `active_stream` alone will
            // not do: it is deliberately left pointing at the last job
            // that ran so post-completion streaming keeps working, so
            // the queue is what says whether that job is still fetching.
            let live = d.active_stream.lock_ok().clone().filter(|id| {
                d.queue_job(id)
                    .is_some_and(|job| job.lock_ok().state == JobState::Downloading)
            });
            // A different job (or none) is fetching: whatever we were
            // watching is owed its final pass.
            if watching != live
                && let Some(prev) = watching.take()
            {
                finals.push((prev, std::time::Instant::now()));
            }
            if let Some(id) = &live {
                if watching.is_none() {
                    watching = Some(id.clone());
                    tries = 0;
                    due = std::time::Instant::now();
                }
                let job = d.queue_job(id);
                let ask = job.as_ref().is_some_and(|job| {
                    let j = job.lock_ok();
                    !media_settled(&j)
                });
                if ask && std::time::Instant::now() >= due {
                    tries += 1;
                    due = std::time::Instant::now()
                        + if tries < MEDIA_FAST_TRIES {
                            tick
                        } else {
                            MEDIA_SLOW
                        };
                    let (d2, id2) = (d.clone(), id.clone());
                    // Blocking file reads, off the runtime's worker
                    // threads - the same rule the endpoint follows.
                    if let Ok(Some(facts)) =
                        tokio::task::spawn_blocking(move || probe_live_facts(&d2, &id2)).await
                        && let Some(job) = job
                        && latch_media(&job, facts)
                    {
                        d.save_queue();
                    }
                }
            }
            // Jobs whose chip settled before the identity oracle
            // answered: post-processing queued them for one more pass
            // against the canonical name (they left `finals` when they
            // settled, so they have to be re-admitted here).
            for id in d.media_rejudge.lock_ok().drain(..) {
                if !finals.iter().any(|(f, _)| f == &id) {
                    finals.push((id, std::time::Instant::now()));
                }
            }
            // Pass 2. One job per tick, and only once post-processing
            // has published the payload: `finalizing` is set for the
            // whole of unpack/rename/move, during which out_dir names a
            // directory whose contents are still arriving.
            finals.retain(|(_, at)| at.elapsed() < MEDIA_FINAL_WINDOW);
            let ready = finals.iter().position(|(id, _)| {
                d.history_job(id).is_some_and(|job| {
                    let j = job.lock_ok();
                    !j.finalizing && !media_settled(&j)
                })
            });
            match ready {
                Some(i) => {
                    let (id, _) = finals.remove(i);
                    let Some(job) = d.history_job(&id) else {
                        continue;
                    };
                    // This attempt IS the re-judge, whatever it reads:
                    // cleared before the probe so a failed read leaves
                    // the chip settled-as-judged, not owed forever.
                    job.lock_ok().media_rejudge = false;
                    let (d2, job2) = (d.clone(), job.clone());
                    if let Ok(Some(facts)) =
                        tokio::task::spawn_blocking(move || probe_disk_facts(&d2, &job2)).await
                        && latch_media(&job, facts)
                    {
                        d.save_queue();
                    }
                }
                // Nothing ready, but drop any entry that has already
                // settled (pass 1 finished the job off) or that failed
                // outright and has no payload to read.
                None => finals.retain(|(id, _)| {
                    d.history_job(id).is_none_or(|job| {
                        let j = job.lock_ok();
                        !media_settled(&j) && j.state != JobState::Failed
                    })
                }),
            }
        }
    });
}

/// Pass 1: the running job's main video, from the bytes on disk so far.
fn probe_live_facts(d: &Daemon, id: &str) -> Option<nzbkit::mediaprobe::MediaFacts> {
    let name = media_claim_name(&d.queue_job(id)?.lock_ok());
    let (file, w, mut r) = super::stream::open_live_probe(d, id)?;
    let info = nzbkit::mediaprobe::probe(
        &mut r,
        nzbkit::mediaprobe::ProbeHint {
            filename: Some(file),
            known_size: Some(w.size),
        },
    )
    .ok()?;
    Some(nzbkit::mediaprobe::facts::check(&info, &name))
}

/// Pass 2: the finished payload, whatever post-processing left behind.
fn probe_disk_facts(d: &Daemon, job: &Arc<Mutex<Job>>) -> Option<nzbkit::mediaprobe::MediaFacts> {
    let path = super::stream::finished_media_path(d, job)?;
    let name = media_claim_name(&job.lock_ok());
    let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
    let mut f = std::fs::File::open(&path).ok()?;
    let info = nzbkit::mediaprobe::probe(
        &mut f,
        nzbkit::mediaprobe::ProbeHint {
            filename: path.file_name().map(|n| n.to_string_lossy().to_string()),
            known_size: Some(size),
        },
    )
    .ok()?;
    Some(nzbkit::mediaprobe::facts::check(&info, &name))
}

/// Slow-job watchdog (auto-defer + idle-server prefetch): a queue
/// shouldn't sit behind one job whose articles live only on one slow
/// server. Over a rolling window of per-server byte deltas:
/// - PREFETCH: servers idle for the whole window (their copies of
///   this job's articles keep 430ing, or they're down) start the next
///   queued job in a restricted sidecar pipeline instead of idling -
///   the journal makes the handover free however it ends.
/// - DEFER: a job taking ≥90% of its bytes from one host at <40% of
///   the session-best rate while others wait is aborted (journal
///   keeps all landed articles) and requeued deferred at the back -
///   pick_job then runs it only when nothing faster is available.
///   Suppressed while a sidecar is progressing: with the idle
///   capacity already downloading the next job, every server is busy
///   and demoting the slow job would only idle its lone server.
/// Thresholds are env-tunable so tests can compress the timeline.
/// Transfer-stall episode tracker (Gary, 2 Aug: a mid-download 30-40 s
/// flatline resumed on its own and nothing anywhere said why). A pure
/// state machine over per-tick pool-byte totals, so the timing logic is
/// unit-testable with synthetic clocks. Observation ONLY: it produces
/// log lines and the queue row's "no data for Ns" sub-line, and never
/// touches the job - the stall watchdog that once aborted a healthy run
/// is why action stays out of scope here. Zero throughput is not zero
/// progress (a wholly-dead post moves no bytes while the pool drives
/// its refusal ladder perfectly), so an episode is a fact to report,
/// never a verdict.
pub(crate) struct StallTracker {
    threshold: std::time::Duration,
    /// (nzo_id, display name) of the fetch being observed.
    job: Option<(String, String)>,
    last_total: u64,
    /// When the pool-byte total last moved (or the job was first seen).
    last_change: Instant,
    open: bool,
}

pub(crate) enum StallEvent {
    /// Bytes have not moved for the threshold: episode starts.
    Opened { idle_secs: u64, since: Instant },
    /// Bytes moved again after an open episode.
    Cleared { idle_secs: u64 },
    /// The job went away (finished, aborted, paused) mid-episode.
    Ended { idle_secs: u64, name: String },
}

impl StallTracker {
    pub(crate) fn new(threshold: std::time::Duration) -> Self {
        Self {
            threshold,
            job: None,
            last_total: 0,
            last_change: Instant::now(),
            open: false,
        }
    }

    /// One sample: the active fetch (if any) and its pool's cumulative
    /// byte total across all servers. At most one event per call.
    pub(crate) fn observe(
        &mut self,
        now: Instant,
        job: Option<(&str, &str)>,
        total_bytes: u64,
    ) -> Option<StallEvent> {
        let ended = |s: &Self| {
            s.open.then(|| StallEvent::Ended {
                idle_secs: now.duration_since(s.last_change).as_secs(),
                name: s.job.as_ref().map(|(_, n)| n.clone()).unwrap_or_default(),
            })
        };
        let Some((id, name)) = job else {
            let ev = ended(self);
            self.job = None;
            self.open = false;
            return ev;
        };
        if self.job.as_ref().map(|(i, _)| i.as_str()) != Some(id) {
            let ev = ended(self);
            self.job = Some((id.to_string(), name.to_string()));
            self.last_total = total_bytes;
            self.last_change = now;
            self.open = false;
            return ev;
        }
        if total_bytes != self.last_total {
            self.last_total = total_bytes;
            let idle = now.duration_since(self.last_change).as_secs();
            self.last_change = now;
            if self.open {
                self.open = false;
                return Some(StallEvent::Cleared { idle_secs: idle });
            }
            return None;
        }
        if !self.open && now.duration_since(self.last_change) >= self.threshold {
            self.open = true;
            return Some(StallEvent::Opened {
                idle_secs: now.duration_since(self.last_change).as_secs(),
                since: self.last_change,
            });
        }
        None
    }
}

pub(super) fn spawn_slow_job_watchdog(
    daemon: &Arc<Daemon>,
    config: &std::path::Path,
    mem_budget: nzbkit::mem::MemBudget,
) {
    let d = daemon.clone();
    let config = config.to_path_buf();
    tokio::spawn(async move {
        let secs = |k: &str, def: u64| {
            std::env::var(k)
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(def)
                .max(1)
        };
        let warmup = secs("NZBFAST_DEFER_WARMUP_SECS", 45);
        let window = secs("NZBFAST_DEFER_WINDOW_SECS", 30);
        // Tail-prefetch experiment (dark): when the active job's article
        // queue runs dry (the pool's network tail), the flat byte window
        // below would skip the whole prefetch block - which is exactly
        // backwards, because the tail is when idle line capacity peaks.
        // With the knob on, a latched tail overrides the flat-window and
        // single-server gates; every other gate (warmup, quota, pause,
        // one-sidecar) still applies, and the fleet the byte test then
        // yields at a dry tail is the bounded BORROW fleet (all healthy
        // hosts at 1-2 connections each), never a full-budget one.
        let tail_prefetch = std::env::var("NZBFAST_TAIL_PREFETCH").is_ok_and(|v| v == "1");
        let tick = (window / 6).clamp(1, 5);
        // Rolling (time, per-host cumulative bytes) samples of the
        // ACTIVE job's pool; reset on job change. `attempted` = jobs
        // already sidecar-tried during the current active job (so a
        // job whose articles the idle servers don't hold either
        // isn't retried every tick).
        let mut win: VecDeque<(Instant, Vec<(String, u64)>)> = VecDeque::new();
        let mut cur: Option<String> = None;
        let mut attempted: std::collections::HashSet<String> = Default::default();
        // Once per active job: "every idle server has refused auth".
        let mut refusal_noted = false;
        // Transfer-stall episodes: one log line when the active fetch
        // moves no bytes for NZBFAST_STALL_LOG_SECS (default 10), one
        // when it clears - so "send me the log" captures a flatline
        // after the fact. Observation only, and always on: it runs
        // BEFORE the auto-defer/prefetch gates below.
        let mut stall = StallTracker::new(std::time::Duration::from_secs(secs(
            "NZBFAST_STALL_LOG_SECS",
            10,
        )));
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(tick)).await;
            {
                // The fetch being observed: hub owner, Downloading, not
                // pause-suspended (a pause legitimately stops bytes).
                let fetching = d
                    .started_at
                    .lock_ok()
                    .is_some()
                    .then(|| d.active_stream.lock_ok().clone())
                    .flatten();
                let job_info = fetching.and_then(|id| {
                    d.queue.lock_ok().iter().find_map(|j| {
                        let g = j.lock_ok();
                        (g.nzo_id == id && g.state == JobState::Downloading && !g.suspended)
                            .then(|| (id.clone(), g.name.clone()))
                    })
                });
                // Per-server (host, connections, bytes, refused) - the
                // states the episode lines report.
                let servers: Vec<(String, usize, u64, bool)> = d
                    .hub
                    .pool_live
                    .lock()
                    .unwrap()
                    .as_ref()
                    .map(|l| {
                        l.servers
                            .iter()
                            .map(|s| {
                                (
                                    s.host.clone(),
                                    s.connected.load(Ordering::Relaxed),
                                    s.bytes.load(Ordering::Relaxed),
                                    s.refusal.lock_ok().is_some(),
                                )
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                // §G: copy any refusal somewhere that outlives the pool.
                // The Providers card reads it from the live pool, which
                // is gone the moment the queue drains - so the one
                // sentence explaining why a paid-for provider did
                // nothing disappeared exactly when the user went looking
                // for it. Sampled here rather than in the stats handler
                // because a headless run has no dashboard polling it.
                //
                // The clear arm is deliberately "moved bytes or holds a
                // connection", not "has no refusal right now": every
                // server starts each job with an empty refusal slot, so
                // clearing on that alone would wipe the record a second
                // after the next job began and refill it a second later.
                // Bytes or a live connection are proof it authenticated.
                {
                    let live = d.hub.pool_live.lock_ok();
                    if let Some(l) = live.as_ref() {
                        let mut keep = d.last_refusals.lock_ok();
                        for s in &l.servers {
                            if let Some(r) = s.refusal.lock_ok().as_ref() {
                                keep.insert(
                                    s.host.clone(),
                                    ServerRefusal {
                                        permanent: r.permanent,
                                        line: r.line.clone(),
                                        at: unix_now(),
                                    },
                                );
                            } else if s.connected.load(Ordering::Relaxed) > 0
                                || s.bytes.load(Ordering::Relaxed) > 0
                            {
                                keep.remove(&s.host);
                            }
                        }
                    }
                }
                let states = || -> String {
                    if servers.is_empty() {
                        return "pool not up yet".into();
                    }
                    servers
                        .iter()
                        .map(|(h, c, _, r)| {
                            if *r {
                                format!("{h} refused")
                            } else {
                                format!("{h} {c} conn")
                            }
                        })
                        .collect::<Vec<_>>()
                        .join(", ")
                };
                let total: u64 = servers.iter().map(|(_, _, b, _)| *b).sum();
                let name = job_info
                    .as_ref()
                    .map(|(_, n)| n.clone())
                    .unwrap_or_default();
                match stall.observe(
                    Instant::now(),
                    job_info.as_ref().map(|(i, n)| (i.as_str(), n.as_str())),
                    total,
                ) {
                    Some(StallEvent::Opened { idle_secs, since }) => {
                        info!(
                            target: "stall",
                            "no data for {idle_secs}s on {name}; servers: {}",
                            states()
                        );
                        *d.stall_since.lock_ok() =
                            job_info.as_ref().map(|(i, _)| (i.clone(), since));
                    }
                    Some(StallEvent::Cleared { idle_secs }) => {
                        info!(
                            target: "stall",
                            "data flowing again on {name} after {idle_secs}s; servers: {}",
                            states()
                        );
                        *d.stall_since.lock_ok() = None;
                    }
                    Some(StallEvent::Ended { idle_secs, name }) => {
                        info!(
                            target: "stall",
                            "stall on {name} not resolved after {idle_secs}s (job ended)"
                        );
                        *d.stall_since.lock_ok() = None;
                    }
                    None => {}
                }
            }
            if !d.auto_defer.load(Ordering::Relaxed) && !d.auto_prefetch.load(Ordering::Relaxed) {
                win.clear();
                continue;
            }
            let Some(t0) = *d.started_at.lock_ok() else {
                win.clear();
                cur = None;
                continue;
            };
            // The job that OWNS the hub, never merely the first
            // Downloading one in the queue: job N's tail overlaps
            // job N+1's download, so N stays Downloading (and ahead
            // in the queue) while pool_live/abort/queue_ctl below
            // are already N+1's. Picking by position measured N+1's
            // pool, wrote the demote onto N and fired the abort at
            // N+1 - killing a healthy download.
            let Some(active) = d.active_stream.lock_ok().clone() else {
                win.clear();
                continue;
            };
            let Some(job) = d
                .queue
                .lock()
                .unwrap()
                .iter()
                .find(|j| {
                    let g = j.lock_ok();
                    g.nzo_id == active && g.state == JobState::Downloading
                })
                .cloned()
            else {
                win.clear();
                continue;
            };
            let (id, defer_count, demote) = {
                let g = job.lock_ok();
                (g.nzo_id.clone(), g.defer_count, g.demote)
            };
            if demote {
                continue; // abort already in flight
            }
            if cur.as_deref() != Some(id.as_str()) {
                win.clear();
                attempted.clear();
                refusal_noted = false;
                cur = Some(id.clone());
            }
            let snap: Vec<(String, u64)> = d
                .hub
                .pool_live
                .lock()
                .unwrap()
                .as_ref()
                .map(|l| {
                    l.servers
                        .iter()
                        .map(|s| (s.host.clone(), s.bytes.load(Ordering::Relaxed)))
                        .collect()
                })
                .unwrap_or_default();
            if snap.is_empty() {
                continue;
            }
            let now = Instant::now();
            win.push_back((now, snap));
            while win
                .front()
                .is_some_and(|(t, _)| now.duration_since(*t).as_secs() > window)
            {
                win.pop_front();
            }
            let Some((t_first, first)) = win.front().cloned() else {
                continue;
            };
            let span = now.duration_since(t_first).as_secs_f64();
            if span < window as f64 * 0.8 {
                continue;
            }
            let base: std::collections::HashMap<&str, u64> =
                first.iter().map(|(h, b)| (h.as_str(), *b)).collect();
            let deltas: Vec<(String, u64)> = win
                .back()
                .unwrap()
                .1
                .iter()
                .map(|(h, b)| {
                    (
                        h.clone(),
                        b.saturating_sub(base.get(h.as_str()).copied().unwrap_or(0)),
                    )
                })
                .collect();
            let total: u64 = deltas.iter().map(|(_, b)| b).sum();
            let rate = total as f64 / span;
            // Every sustained window is also a reference sample.
            d.best_rate_bps.fetch_max(rate as u64, Ordering::Relaxed);
            // Tail-prefetch experiment: a latched network tail with
            // work still in flight. Read fresh each tick - the latch
            // only ever appears once per run, and `Some(0)` (tail
            // finished) must not trigger.
            let tail_now = tail_prefetch
                && d.hub
                    .queue_ctl
                    .lock_ok()
                    .as_ref()
                    .and_then(|c| c.tail_pending())
                    .is_some_and(|p| p > 0);
            // A wholly stalled job is the pool's retry logic's
            // problem, and a single-server setup has nothing to
            // route around. (Unless the tail override is live: a dry
            // tail IS a flat window, and borrowing 1-2 connections is
            // meaningful even from a single server.)
            if (total == 0 || deltas.len() < 2) && !tail_now {
                continue;
            }
            if now.duration_since(t0).as_secs() < warmup {
                continue;
            }

            // ---- Idle-server prefetch: any host that contributed
            // <1% of the window while the job moved is idle - its
            // copies of this job's articles keep 430ing (or it's
            // down). Start the next queued job on JUST those hosts.
            // Skipped when a period quota is configured: the quota
            // ledger is the runner's, and opportunistic fetches
            // shouldn't race a metered budget.
            if d.auto_prefetch.load(Ordering::Relaxed)
                && !d.paused.load(Ordering::Relaxed)
                && d.quota.load(Ordering::Relaxed) == 0
                && d.sidecar.lock_ok().is_none()
            {
                // A server that refused to authenticate (bad
                // credential, or at its connection/IP cap) moved no
                // bytes, so by the byte test alone it reads as idle
                // capacity - and a sidecar whose whole fleet is
                // refused servers prefetches nothing while the
                // queued job it claimed sits blocked behind it.
                let refused: std::collections::HashSet<String> = d
                    .hub
                    .pool_live
                    .lock()
                    .unwrap()
                    .as_ref()
                    .map(|l| {
                        l.servers
                            .iter()
                            .filter(|s| s.refusal.lock_ok().is_some())
                            .map(|s| s.host.clone())
                            .collect()
                    })
                    .unwrap_or_default();
                let mut any_idle = false;
                let idle: Vec<String> = deltas
                    .iter()
                    .filter(|(_, b)| (*b as f64) < total as f64 * 0.01)
                    .inspect(|_| any_idle = true)
                    .filter(|(h, _)| !refused.contains(h))
                    .map(|(h, _)| h.clone())
                    .collect();
                // No healthy idle server (they all refused auth, or
                // every server is busy on the active job): borrow a
                // bounded 1-2 connection slice of the healthy BUSY
                // servers instead, so the next job's tail-overlap
                // still engages (the 31 Jul soak measured
                // 49 s line-idle of a 144 s queue without it). The
                // per-host cap lives on the sidecar hub - see
                // spawn_sidecar for the budget accounting.
                let (fleet, borrow) = if idle.is_empty() {
                    let busy: Vec<String> = deltas
                        .iter()
                        .filter(|(_, b)| (*b as f64) >= total as f64 * 0.01)
                        .filter(|(h, _)| !refused.contains(h))
                        .map(|(h, _)| h.clone())
                        .collect();
                    (busy, true)
                } else {
                    (idle, false)
                };
                if borrow && any_idle && !refusal_noted {
                    refusal_noted = true;
                    info!(
                        target: "prefetch",
                        "every idle server refused to authenticate ({}) - borrowing from the busy server(s) instead",
                        refused.iter().cloned().collect::<Vec<_>>().join(", ")
                    );
                }
                if !fleet.is_empty() {
                    // Same ordering as pick_job, minus: deferred jobs
                    // (their articles live on the BUSY server - the
                    // idle set has already rejected them), library
                    // entries, and jobs already tried this cycle.
                    let mut best: Option<(i32, Arc<Mutex<Job>>)> = None;
                    for j in d.queue.lock_ok().iter() {
                        let g = j.lock_ok();
                        if g.state != JobState::Queued
                            || g.paused
                            || g.deferred
                            || g.library
                            || attempted.contains(&g.nzo_id)
                        {
                            continue;
                        }
                        if best.as_ref().is_none_or(|(bp, _)| g.priority > *bp) {
                            best = Some((g.priority, j.clone()));
                        }
                    }
                    if let Some((_, nj)) = best {
                        spawn_sidecar(&d, &config, &nj, &fleet, &deltas, mem_budget, borrow);
                        attempted.insert(nj.lock_ok().nzo_id.clone());
                    }
                }
            }

            // The tail override above unlocks ONLY the prefetch block.
            // The defer verdict below must never see the tail shapes:
            // `share = top/total` is NaN at total == 0 and NaN slips
            // the `share < 0.90` demote gate (a healthy job would be
            // aborted at its own tail), and a single-server job has
            // nothing to route around.
            if total == 0 || deltas.len() < 2 {
                continue;
            }

            // ---- Defer verdict. Suppressed while an IDLE-server
            // sidecar runs: the idle capacity is already downloading
            // the next job, so every server is busy - demoting the
            // slow job would only idle its lone server. A BORROWED
            // sidecar claims no idle capacity (it runs on a 1-2
            // connection slice of the busy servers), so it must not
            // disarm the watchdog: with borrowing, a sidecar exists
            // almost whenever a queue does, and suppressing on it
            // would retire the defer verdict outright.
            let idle_sidecar = d
                .sidecar
                .lock()
                .unwrap()
                .as_ref()
                .is_some_and(|s| !s.borrowed);
            if defer_count >= 3 || idle_sidecar {
                continue;
            }
            let others_waiting = d.queue.lock_ok().iter().any(|j| {
                let g = j.lock_ok();
                g.state == JobState::Queued && !g.paused && !g.deferred
            });
            if !others_waiting {
                continue;
            }
            let (top_host, top_bytes) = deltas.iter().max_by_key(|(_, b)| *b).cloned().unwrap();
            let share = top_bytes as f64 / total as f64;
            let best = d.best_rate_bps.load(Ordering::Relaxed);
            if share < 0.90 || best < 1_000_000 || rate >= 0.4 * best as f64 {
                continue;
            }
            let reason = format!(
                "{:.0}% of the last {:.0}s came from {top_host} at {:.1} MB/s \
                 (session best {:.1} MB/s) - the other servers had nothing \
                 for this job",
                share * 100.0,
                span,
                rate / 1e6,
                best as f64 / 1e6
            );
            {
                let mut g = job.lock_ok();
                g.demote = true;
                g.defer_reason = reason.clone();
            }
            info!(target: "defer", "{id}: {reason} - moving to the back of the queue");
            if let Some(f) = d.hub.abort.lock_ok().as_ref() {
                f.store(true, Ordering::Relaxed);
            }
            if let Some(c) = d.hub.queue_ctl.lock_ok().as_ref() {
                c.abort();
            }
            win.clear();
        }
    });
}

/// TODO 112 (dark, NZBFAST_LIVE_TUNE=1): the live connection tuner's
/// epoch loop - one `EpochObs` per server per epoch off the live
/// gauges, fed to the pure controller in `nzbkit::livetune`, whose
/// verdict moves the per-host `ConnTarget` the pool build attached.
///
/// Everything noisy stays in `livetune` behind pinned rules; this loop
/// only OBSERVES:
/// - rate: per-host byte delta over the epoch, from `pool_live`,
/// - busy: the same pool spanned the whole epoch, bytes moved, and the
///   article queue has not latched its tail (a drying queue measures
///   the queue, not the line),
/// - rate_limited: the global limiter is set and the aggregate sat
///   near it - socket-count verdicts are meaningless at a byte cap,
/// - capacity_pressure: a "cap" ring event for this host inside the
///   epoch (481/502 refusals and the flap-keeper clamp both emit it),
/// - fleet_met: the fleet actually reached the target it was asked
///   to run.
///
/// The controller's belief lives here (per host, daemon lifetime); the
/// ceiling is re-read from config each epoch so a settings change
/// clamps within one epoch. Nothing is ever written to settings - the
/// target is state, and the dashboard's "using M of N" gauge follows
/// it through `ServerLive::budget`.
pub(super) fn spawn_live_tuner(daemon: &Arc<Daemon>, config: &std::path::Path) {
    if !crate::conntune::live_tune_on() {
        return;
    }
    let d = daemon.clone();
    let config = config.to_path_buf();
    tokio::spawn(async move {
        let epoch_secs: u64 = std::env::var("NZBFAST_LIVE_TUNE_EPOCH_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(60)
            .max(5);
        let epoch = std::time::Duration::from_secs(epoch_secs);
        info!("live-tune: epoch controller on ({epoch_secs}s epochs)");
        let mut tuners: std::collections::HashMap<String, nzbkit::livetune::ServerTuner> =
            Default::default();
        // (pool identity, per-host cumulative bytes) at epoch start.
        let mut prev: Option<(Arc<nzbkit::pool::LiveStats>, Vec<(String, u64)>)> = None;
        loop {
            tokio::time::sleep(epoch).await;
            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|t| t.as_millis() as u64)
                .unwrap_or(0);
            let live = d.hub.pool_live.lock_ok().clone();
            let Some(live) = live else {
                prev = None;
                continue;
            };
            let bytes_now: Vec<(String, u64)> = live
                .servers
                .iter()
                .map(|s| (s.host.clone(), s.bytes.load(Ordering::Relaxed)))
                .collect();
            // The epoch is only a measurement if the SAME run spanned
            // it end to end.
            let Some((plive, pbytes)) = prev.replace((live.clone(), bytes_now.clone())) else {
                continue;
            };
            if !Arc::ptr_eq(&plive, &live) {
                continue;
            }
            let tail_latched = d
                .hub
                .queue_ctl
                .lock_ok()
                .as_ref()
                .and_then(|q| q.tail_pending())
                .is_some();
            let deltas: Vec<(String, u64)> = bytes_now
                .iter()
                .zip(pbytes.iter())
                .filter(|((h1, _), (h2, _))| h1 == h2)
                .map(|((h, b1), (_, b0))| (h.clone(), b1.saturating_sub(*b0)))
                .collect();
            let total: u64 = deltas.iter().map(|(_, b)| *b).sum();
            let cap = d.hub.rate.get();
            let rate_limited = cap > 0 && (total as f64 / epoch.as_secs_f64()) >= cap as f64 * 0.85;
            // Capacity events inside this epoch, by host.
            let epoch_start_ms = now_ms.saturating_sub(epoch.as_millis() as u64);
            let cap_events: std::collections::HashSet<String> = live
                .recent_events(60)
                .into_iter()
                .filter(|e| e.kind == "cap" && e.at_ms >= epoch_start_ms)
                .map(|e| e.host)
                .collect();
            let cfg_servers = nzbkit::config::Config::load(&config)
                .map(|c| c.servers)
                .unwrap_or_default();
            let global = d.connections.load(Ordering::Relaxed).max(1);
            for (i, sl) in live.servers.iter().enumerate() {
                let target = {
                    let g = d.hub.live_targets.lock_ok();
                    g.get(&sl.host).cloned()
                };
                // No handle = pinned server, sidecar hub, or the
                // feature raced a config change: nothing to move.
                let Some(target) = target else { continue };
                let ceiling = cfg_servers
                    .iter()
                    .find(|s| s.host == sl.host)
                    .map(|s| crate::conntune::effective_limit(global, s.connections))
                    .unwrap_or_else(|| target.get());
                let tuner = tuners.entry(sl.host.clone()).or_insert_with(|| {
                    nzbkit::livetune::ServerTuner::new(target.get(), ceiling, 3)
                });
                let delta = deltas.get(i).map(|(_, b)| *b).unwrap_or(0);
                let connected = sl.connected.load(Ordering::Relaxed);
                let before = tuner.target();
                tuner.on_epoch(nzbkit::livetune::EpochObs {
                    rate_bps: delta as f64 / epoch.as_secs_f64(),
                    busy: delta > 0 && !tail_latched,
                    rate_limited,
                    capacity_pressure: cap_events.contains(&sl.host),
                    fleet_met: connected >= target.get(),
                });
                let desired = tuner.desired().min(ceiling);
                target.set(desired);
                sl.budget.store(target.get(), Ordering::Relaxed);
                if tuner.target() != before {
                    info!(
                        "live-tune: {} using {} of {ceiling} (was {before})",
                        sl.host,
                        tuner.target()
                    );
                }
            }
        }
    });
}

/// NZBFAST_NO_ENRICH=1 disables the metadata workers entirely - set by
/// the test suite (they hit the real internet: the IMDb refresher pulls
/// a ~25 MB dataset and ingests 425k rows on every fresh db, whose
/// write transaction also locked the first index scan out - the
/// long-standing scan_loop test "flake").
#[cfg(feature = "indexer")]
pub(super) fn spawn_enrichment_workers(daemon: &Arc<Daemon>, tmdb_key: &Option<String>) {
    if std::env::var_os("NZBFAST_NO_ENRICH").is_none() {
        {
            let d = daemon.clone();
            let key = tmdb_key.clone();
            let omdb = d.omdb_key.lock_ok().is_some();
            info!(
                target: "wall",
                "enrichment on via {} (posters cache to .spool/art)",
                if key.is_some() {
                    "TMDB"
                } else if omdb {
                    "TVmaze + OMDb + Wikidata/Wikipedia + AniList"
                } else {
                    "TVmaze + Wikidata/Wikipedia + AniList (keyless)"
                }
            );
            std::thread::spawn(move || wall_enricher(d, key));
        }
        {
            let d = daemon.clone();
            std::thread::spawn(move || imdb_ratings_refresher(d));
        }
        {
            let d = daemon.clone();
            std::thread::spawn(move || person_photo_fetcher(d));
        }
    }
}

/// Update checker: 90 s after start, then every 6 h. NOTIFY-ONLY:
/// finding a newer version sets the banner state and logs a line,
/// nothing more - the daemon never downloads or replaces its own
/// binary. Turn checks off entirely with the update_checks setting
/// (or an empty update_url).
pub(super) fn spawn_update_checker(daemon: &Arc<Daemon>) {
    let d = daemon.clone();
    std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_secs(90));
        loop {
            if d.update_checks.load(Ordering::Relaxed) {
                match check_update(&d) {
                    Ok(Some(m)) => {
                        let ver = m.get("version").and_then(Value::as_str).unwrap_or("?");
                        info!(
                            target: "update",
                            "v{ver} is available (running v{}) - see {DOWNLOAD_URL}",
                            env!("CARGO_PKG_VERSION")
                        );
                    }
                    Ok(None) => {}
                    Err(e) => info!(target: "update", "{e}"),
                }
            }
            std::thread::sleep(std::time::Duration::from_secs(6 * 3600));
        }
    });
}

/// Scheduled system benchmark (live setting bench_interval, hours;
/// 0 = off). Runs only while the queue is idle - a benchmark that
/// comes due mid-download waits and re-checks each minute. Every run
/// appends to .spool/bench_history.json (mode=bench_history).
pub(super) fn spawn_scheduled_bench(daemon: &Arc<Daemon>, config: &std::path::Path) {
    let d = daemon.clone();
    let cfg_path = config.to_path_buf();
    let rt = tokio::runtime::Handle::current();
    std::thread::spawn(move || {
        // Seed last-run from history so a restart doesn't re-run early.
        if let Some(ts) = d
            .bench_history()
            .last()
            .and_then(|e| e.get("ts").and_then(Value::as_u64))
        {
            d.bench_last.store(ts, Ordering::Relaxed);
        }
        loop {
            std::thread::sleep(std::time::Duration::from_secs(60));
            let hrs = d.bench_interval.load(Ordering::Relaxed);
            if hrs == 0 {
                continue;
            }
            let now = epoch_secs();
            if now.saturating_sub(d.bench_last.load(Ordering::Relaxed)) < hrs * 3600 {
                continue;
            }
            let busy = d
                .queue
                .lock()
                .unwrap()
                .iter()
                .any(|j| j.lock_ok().state == JobState::Downloading);
            if busy {
                continue; // never disturb a download; re-check in a minute
            }
            info!(target: "bench", "scheduled system benchmark (every {hrs} h)");
            d.bench_last.store(now, Ordering::Relaxed);
            match measure_system(&d, &cfg_path, &rt) {
                Ok(v) => d.bench_append(json!({
                    "ts": now, "source": "scheduled",
                    "network_gbps": v.network_gbps,
                    "compute_gbps": v.compute_gbps,
                    "disk_gbps": v.disk_gbps,
                    "expected_gbps": v.expected_gbps,
                    "bottleneck": v.bottleneck,
                })),
                Err(e) => {
                    info!(target: "bench", "scheduled benchmark failed: {e}");
                    d.bench_append(json!({"ts": now, "source": "scheduled", "error": e}));
                }
            }
        }
    });
}

/// Judge measured provider capability against the user's stated line
/// speed (`line_speed`, the Settings hint of what the connection can
/// do) and store the verdict in `tune_hint` for the dashboard. Called
/// after every ladder - auto probe or manual run.
///
/// Only judges with a FULL picture: line speed set, and every enabled
/// server probed. A missing probe reads as capability the daemon
/// can't see yet, and a false "your setup is short" is worse than
/// saying nothing.
///
/// Two ways to be wrong, so two bands: well under the line (providers
/// are the lever) and well OVER it (the setting is the lever - the
/// ladder never stops measuring at the line speed, so a stale 300M on a
/// gigabit link shows up here rather than silently capping the reading).
/// In between, the setup covers the line and the hint clears.
pub(super) fn update_tune_hint(
    d: &Daemon,
    servers: &[nzbkit::config::ServerConfig],
    tuned: &std::collections::HashMap<String, crate::conntune::Tuned>,
) {
    let expected_bps = d.line_speed.load(Ordering::Relaxed);
    let mut hint = String::new();
    let enabled: Vec<_> = servers.iter().filter(|s| s.enabled).collect();
    // Only the servers the prober will ever measure. It skips block and
    // backup accounts on purpose (a ladder would spend the user's block
    // allowance), so requiring EVERY enabled server to carry an entry
    // meant one enabled block account suppressed the line-speed verdict
    // for the whole install, permanently and with nothing in the log
    // saying why.
    let measured: Vec<_> = enabled
        .iter()
        .copied()
        .filter(|s| s.block_bytes.is_none())
        .collect();
    if expected_bps > 0
        && !measured.is_empty()
        && measured.iter().all(|s| tuned.contains_key(&s.host))
    {
        let cap_bytes: f64 = measured.iter().map(|s| tuned[&s.host].gbps).sum::<f64>() * 1e9 / 8.0;
        let pct = (100.0 * cap_bytes / expected_bps as f64).round() as u64;
        if cap_bytes > expected_bps as f64 * 1.1 {
            // The ladder deliberately measures PAST the line speed, so a
            // reading well above it is not an error - it means the number
            // in Settings is stale (an unchanged 300M after a gigabit
            // upgrade). Say so: percentage speed limits are computed from
            // it, so a low setting silently throttles them too.
            hint = format!(
                "providers measured ~{:.0} Mbps together, {pct}% of the ~{:.0} Mbps \
                 Line speed set in Settings - the setting looks low, raise it so \
                 percentage speed limits and these readings are right",
                cap_bytes * 8.0 / 1e6,
                expected_bps as f64 * 8.0 / 1e6
            );
        } else if cap_bytes < expected_bps as f64 * 0.8 {
            let meas = cap_bytes * 8.0 / 1e6;
            let want = expected_bps as f64 * 8.0 / 1e6;
            let mut tips: Vec<String> = Vec::new();
            for s in &measured {
                let t = &tuned[&s.host];
                // Against what the ladder ASKED for, not what the server
                // is configured for. The ladder stops at the knee, so on
                // a server set to 20 whose knee is 8 it may never ask
                // beyond 16 - and comparing against 20 then told the
                // user their account tier was capping them, using a
                // number nothing had requested. `asked == 0` is an entry
                // from before the field existed: unknown, so say
                // nothing.
                // The knee rung against what it was actually granted -
                // "32 asked, 21 granted" - not against the CONFIGURED
                // count. The ladder stops at the knee, so on a server set
                // to 20 whose knee is 8 it may never ask beyond 16, and
                // comparing against 20 told the user their account tier
                // was capping them using a number nothing had requested.
                // `connections` is already clamped to the granted count
                // at that rung, so the pair is exact. `asked == 0` is an
                // entry from before the field existed: unknown, so say
                // nothing.
                if t.asked > 0 && t.asked > t.connections {
                    tips.push(format!(
                        "{} granted only {} of the {} connections asked for - the \
                         account tier may cap it",
                        s.host, t.connections, t.asked
                    ));
                }
            }
            if measured.len() == 1 {
                tips.push("a second provider adds parallel headroom".into());
            } else if tips.is_empty() {
                tips.push("a faster provider (or one more) is the likely lever".into());
            }
            hint = format!(
                "providers measured ~{meas:.0} Mbps together, {pct}% of the \
                 ~{want:.0} Mbps line - well short. {}",
                tips.join("; ")
            );
        }
    }
    let mut cur = d.tune_hint.lock_ok();
    if *cur != hint {
        if hint.is_empty() {
            info!(target: "tune", "provider capability now covers the stated line speed");
        } else {
            info!(target: "tune", "{hint}");
        }
        *cur = hint;
    }
}

/// M7b.1: connection auto-tune (live setting auto_connections,
/// default ON). While the queue is idle, probe one provider whose
/// ladder result is missing or older than a week and store the knee
/// in conntune.json next to the config - every job build then caps
/// that server at min(configured, knee); over-asking measured 3-4×
/// slower than the knee (connect-flood defense). Block accounts are
/// never probed (a ladder run would eat the paid block). Probe
/// traffic is billed to the data-usage ledger like any other bytes.
pub(super) fn spawn_auto_connections(daemon: &Arc<Daemon>, config: &std::path::Path) {
    let d = daemon.clone();
    let cfg_path = config.to_path_buf();
    let rt = tokio::runtime::Handle::current();
    // Before anything else, and synchronously: sweep knees the user's
    // current settings have outgrown. This runs at boot rather than in
    // the probe thread below because a job can start inside the 120 s
    // settling sleep, and a job that starts capped by a knee the user
    // already disowned is the whole complaint (v1.0.14 field report:
    // 6 sockets of 24 asked for, ~25 MB/s on a 900 Mbps line, across
    // every download in his history). Pre-guard files on disk are only
    // ever reachable from here - a record-time guard cannot revisit
    // them.
    crate::conntune::reopen_for_install(config, d.connections.load(Ordering::Relaxed));
    std::thread::spawn(move || {
        // In-memory failure backoff so an unreachable server is
        // retried in hours, not every minute.
        let mut attempted: std::collections::HashMap<String, u64> = Default::default();
        // Let startup settle before the first probe.
        std::thread::sleep(std::time::Duration::from_secs(120));
        loop {
            std::thread::sleep(std::time::Duration::from_secs(60));
            if !d.auto_connections.load(Ordering::Relaxed) {
                continue;
            }
            let busy = d
                .queue
                .lock()
                .unwrap()
                .iter()
                .any(|j| j.lock_ok().state == JobState::Downloading);
            // An index scan or deepening pass pulls headers over the SAME
            // provider the ladder measures (field case: a 90k headers/s
            // deepening pull mid-probe reads every rung flat and fakes a
            // knee at a fraction of the true one). "Idle" must mean the
            // LINK is idle, not just the job queue.
            if busy || d.scan_active.load(Ordering::Relaxed) {
                continue;
            }
            let Ok(cfg) = nzbkit::config::Config::load(&cfg_path) else {
                continue;
            };
            let tuned = crate::conntune::load(&cfg_path);
            let now = epoch_secs();
            let Some(srv) = cfg
                .servers
                .iter()
                .find(|srv| {
                    // A disabled server must not be probed: jobs will
                    // never use its knee, and an unreachable one puts
                    // "[tune] ... connect timed out" in the log every
                    // few hours forever.
                    srv.enabled
                        && srv.block_bytes.is_none()
                        && attempted
                            .get(&srv.host)
                            .is_none_or(|&t| now.saturating_sub(t) > 6 * 3600)
                        && tuned.get(&srv.host).is_none_or(|t| {
                            // A knee that caps the server below HALF its
                            // configured connections halves the user's
                            // line if it is wrong, so it does not get a
                            // week of trust: re-probe within hours - far
                            // enough apart that the corroborating sample
                            // sees a different time of day. A genuine
                            // connect-flood knee will reproduce; a
                            // transient (congestion, a busy Mac during
                            // the 5 s samples) will not. Field case: a
                            // gigabit user tuned to 6 and ran at half the
                            // speed of a 16-connection client for days.
                            // (`suspect` flags entries written by this
                            // build; the half-check also catches knees
                            // recorded before the flag existed.)
                            // Judged against the ceiling a job would
                            // REALLY hand this server, which is what
                            // `record` used when it decided `suspect` -
                            // the global setting caps the per-server
                            // number too. Against `srv.connections`
                            // alone, a knee that is perfectly healthy
                            // under a lower global reads as
                            // "suspiciously low" forever: a default
                            // global of 8 with a server configured at 50
                            // calls a knee of 20 suspect, every probe
                            // rewrites `checked`, and the 6-hourly clock
                            // therefore never settles into the 7-day
                            // one. That is roughly 5 GB of probe traffic
                            // four times a day, billed to the user's
                            // account and metered quota, for a verdict
                            // that cannot change.
                            let ceiling = crate::conntune::effective_limit(
                                d.connections.load(Ordering::Relaxed),
                                srv.connections,
                            );
                            // The half-check applies ONLY to entries
                            // written before `suspect` existed. Left
                            // unscoped it never lets a genuinely low
                            // knee settle: global 20, server 20, true
                            // knee 8 - probe one flags it, probe two
                            // corroborates it, `suspect` clears and it
                            // is applied and correct, and then every
                            // later pass still reads 8*2 <= 20 and puts
                            // it back on the 6-hourly clock. A full
                            // ladder every six hours forever, for a
                            // verdict that has already settled and
                            // cannot change - the same cost this
                            // comment was written to prevent, arrived at
                            // from the other direction. The term
                            // conflates "unproven" with "low"; after
                            // corroboration only the first should still
                            // buy a short clock.
                            // A PARKED reading is an outstanding question
                            // and belongs on the short clock. `reconcile`
                            // deliberately leaves `suspect` false on these
                            // - the point is that the old knee stays IN
                            // FORCE while the new one waits - so reading
                            // only `suspect` here made the second opinion
                            // the whole mechanism exists to collect wait
                            // seven days instead of six hours, defeating
                            // the fix it is part of.
                            let suspicious = t.suspect
                                || t.pending.is_some()
                                || (t.v < crate::conntune::SCHEMA && t.connections * 2 <= ceiling);
                            let ttl = if suspicious {
                                crate::conntune::SUSPECT_STALE_SECS
                            } else {
                                crate::conntune::STALE_SECS
                            };
                            now.saturating_sub(t.checked) > ttl
                        })
                })
                .cloned()
            else {
                continue;
            };
            // Never probe over a manual test the user is watching (or
            // over another provider's auto probe): skip this cycle and
            // come back, rather than making two measurements wrong.
            let Some(_permit) = crate::serve::daemon::LadderPermit::try_take(&d) else {
                continue;
            };
            attempted.insert(srv.host.clone(), now);
            let grp = PROBE_GROUP;
            let cap = (srv.connections.max(1) as usize * 2).clamp(30, 100);
            // What a job would really hand this server, which is what a
            // knee has to be plausible against - not the probe cap.
            let ceiling = crate::conntune::effective_limit(
                d.connections.load(Ordering::Relaxed),
                srv.connections,
            );
            info!(target: "tune", "probing {} connection ladder (queue idle)", srv.host);
            let res = rt.block_on(async {
                tokio::time::timeout(
                    std::time::Duration::from_secs(240),
                    // The background probe publishes too: it is the one
                    // a user never asked for, so seeing WHY the number
                    // moved matters even more than on a manual run.
                    nzbkit::sysbench::conn_ladder(&srv, grp, cap, ceiling, 5, {
                        let dd = d.clone();
                        let host = srv.host.clone();
                        move |phase, at, steps| {
                            *dd.ladder_live.lock_ok() = Some(crate::serve::daemon::LadderLive {
                                host: host.clone(),
                                phase: phase.into(),
                                at,
                                steps: steps.to_vec(),
                                started: now,
                                done: false,
                            });
                            // Cancel stops whichever ladder is running,
                            // and the permit means that is exactly one.
                            !dd.ladder_cancel.load(Ordering::Acquire)
                        }
                    }),
                )
                .await
            });
            if let Some(l) = d.ladder_live.lock_ok().as_mut() {
                l.done = true;
            }
            match res {
                Ok(Ok(steps)) if !steps.is_empty() => {
                    // A jagged ladder gets its contested rungs re-measured
                    // once before anything is read off it. Costs a probe
                    // per disagreeing rung (~5 s each) and only fires when
                    // the rungs actually contradict each other - a clean
                    // curve is its own corroboration, since every rung
                    // agrees with its neighbours.
                    let contested = crate::conntune::knee_of(&steps)
                        .map(|k| (k.contested, k.gbps))
                        .filter(|(c, _)| !c.is_empty());
                    let steps = match contested {
                        None => steps,
                        Some((rungs, peak)) => {
                            info!(
                                target: "tune",
                                "{}: ladder disagrees with itself - re-measuring {:?}",
                                srv.host, rungs
                            );
                            let again = rt.block_on(async {
                                tokio::time::timeout(
                                    std::time::Duration::from_secs(120),
                                    nzbkit::sysbench::remeasure(&srv, grp, &rungs, peak, 5),
                                )
                                .await
                            });
                            match again {
                                // Not billed here: merge_samples SUMS the
                                // two samples' bytes into the merged rung,
                                // and the ledger write below bills the
                                // merged ladder. Billing `extra` as well
                                // would charge the re-measure twice.
                                Ok(Ok(extra)) => crate::conntune::merge_samples(&steps, &extra),
                                // A failed re-measure leaves the ladder as
                                // it was: still jagged, so still suspect.
                                _ => {
                                    warn!(
                                        target: "tune",
                                        "{}: re-measure failed - keeping the jagged ladder",
                                        srv.host
                                    );
                                    steps
                                }
                            }
                        }
                    };
                    d.add_usage(&[(srv.host.clone(), steps.iter().map(|s| s.bytes).sum())]);
                    // The per-rung rates in the log are the ONLY record
                    // of WHY a knee was chosen - a bare verdict left a
                    // user report ("it picked 6") undiagnosable.
                    let rungs: Vec<String> = steps
                        .iter()
                        .map(|s| {
                            format!(
                                "{}c {:.2} Gbps (granted {})",
                                s.connections, s.gbps, s.granted
                            )
                        })
                        .collect();
                    info!(target: "tune", "{} ladder: {}", srv.host, rungs.join(", "));
                    // The idle gate at the top of this loop is a ONE-SHOT
                    // pre-check, and the ladder runs for up to 180 s
                    // after it passed. A job the scheduler picked up in
                    // the meantime, or an index scan or deepening pass
                    // waking, pulls headers over this very provider and
                    // reads every rung flat - which is exactly the
                    // faked-low-knee shape the corroboration rule exists
                    // for, arriving this time from our own side. Nothing
                    // tells the ladder that happened, so ask afterwards:
                    // if the link is no longer idle the measurement
                    // cannot be trusted, and an unrecorded provider is
                    // simply re-probed where a wrongly-recorded one gets
                    // applied.
                    let still_idle = !d.scan_active.load(Ordering::Relaxed)
                        && !d
                            .queue
                            .lock_ok()
                            .iter()
                            .any(|j| j.lock_ok().state == JobState::Downloading);
                    if !still_idle {
                        info!(
                            target: "tune",
                            "{}: a download or index scan started while the ladder ran - \
                             discarding the measurement rather than recording a knee \
                             taken against a busy link",
                            srv.host
                        );
                        continue;
                    }
                    // A ladder that moved nothing is not a knee of 2 - it is
                    // no measurement at all, and recording it would cap this
                    // provider at 2 connections permanently once the next
                    // probe reproduced it and called that corroboration.
                    let Some(knee) = crate::conntune::knee_of(&steps) else {
                        warn!(
                            target: "tune",
                            "{}: ladder moved no data at any rung - the provider \
                             served no bodies, so no knee was recorded",
                            srv.host
                        );
                        continue;
                    };
                    let (best, peak) = (knee.connections, knee.gbps);
                    let granted = steps.iter().map(|s| s.granted).max().unwrap_or(0);
                    // The ceiling a job would really hand this server:
                    // the global setting caps it too, and judging the
                    // knee against the server's own number alone called
                    // a knee "low" on an install whose global setting
                    // WAS that number.
                    let limit = crate::conntune::effective_limit(
                        d.connections.load(Ordering::Relaxed),
                        srv.connections,
                    );
                    // Re-read the store rather than trust the snapshot
                    // taken before the ladder. `record` replaces the
                    // host's entry wholesale, and 180 s is long enough
                    // for the user to have run the settings-page Test
                    // and had it finish: their explicit run, documented
                    // as "their call, applied as-is", was then silently
                    // overwritten by a measurement that started before
                    // it. The fresher answer wins, and it also feeds the
                    // corroboration below - judging that against the
                    // stale snapshot meant a newer sample could not even
                    // influence the flag.
                    let fresh = crate::conntune::load(&cfg_path);
                    if fresh
                        .get(&srv.host)
                        .is_some_and(|p| p.source == "manual" && p.checked >= now)
                    {
                        info!(
                            target: "tune",
                            "{}: a manual test landed while this probe ran - keeping the \
                             user's own result",
                            srv.host
                        );
                        continue;
                    }
                    // One rule, shared with the dashboard's Test button.
                    // `is_suspect` carries the same "unproven unless a
                    // second probe agrees" logic and corroborates through
                    // `corroborates`, so a parked reading is compared
                    // against the parked value - see conntune.
                    let suspect =
                        crate::conntune::is_suspect(best, limit, knee.jagged, fresh.get(&srv.host));
                    if knee.jagged {
                        warn!(
                            target: "tune",
                            "{}: ladder is JAGGED - the rate drops below {:.0}% of \
                             peak between {}c and the {}c peak, so the link was not \
                             quiet enough to measure a knee",
                            srv.host,
                            crate::conntune::LADDER_BAR * 100.0,
                            best,
                            knee.peak_at
                        );
                    }
                    crate::conntune::record(
                        &cfg_path,
                        &srv.host,
                        crate::conntune::Tuned {
                            connections: best,
                            granted,
                            asked: knee.asked,
                            gbps: peak,
                            checked: now,
                            source: "auto".into(),
                            suspect,
                            limit,
                            v: crate::conntune::SCHEMA,
                            pending: None,
                        },
                    );
                    if suspect {
                        info!(
                            target: "tune",
                            "{}: knee {best} of {limit} configured looks LOW - \
                             not applied yet; a re-probe in ~6 h must agree first \
                             ({peak:.2} Gbps peak)",
                            srv.host
                        );
                    } else if best < limit {
                        info!(
                            target: "tune",
                            "{}: knee is {best} of {limit} configured - jobs \
                             will use {best} ({peak:.2} Gbps peak)",
                            srv.host
                        );
                    } else if best > limit {
                        info!(
                            target: "tune",
                            "{}: knee {best} is ABOVE the configured {limit} - \
                             raise the server's connections to use it ({peak:.2} Gbps peak)",
                            srv.host
                        );
                    } else {
                        info!(
                            target: "tune",
                            "{}: configured {limit} sits at the knee \
                             ({peak:.2} Gbps peak)",
                            srv.host
                        );
                    }
                    // With this probe recorded, re-judge total provider
                    // capability against the user's stated line speed.
                    update_tune_hint(&d, &cfg.servers, &crate::conntune::load(&cfg_path));
                }
                Ok(Ok(_)) => {}
                Ok(Err(e)) => info!(target: "tune", "{} ladder failed: {e}", srv.host),
                Err(_) => info!(target: "tune", "{} ladder timed out", srv.host),
            }
        }
    });
}

#[cfg(test)]
mod stall_tests {
    use super::{StallEvent, StallTracker};
    use std::time::{Duration, Instant};

    const T: Duration = Duration::from_secs(10);

    fn tick(t0: Instant, secs: u64) -> Instant {
        t0 + Duration::from_secs(secs)
    }

    #[test]
    fn opens_after_threshold_then_clears_on_bytes() {
        let t0 = Instant::now();
        let mut s = StallTracker::new(T);
        assert!(s.observe(t0, Some(("a", "job-a")), 100).is_none());
        assert!(s.observe(tick(t0, 5), Some(("a", "job-a")), 100).is_none());
        let ev = s.observe(tick(t0, 12), Some(("a", "job-a")), 100);
        assert!(matches!(ev, Some(StallEvent::Opened { idle_secs: 12, .. })));
        // Still open: no repeat event while frozen.
        assert!(s.observe(tick(t0, 17), Some(("a", "job-a")), 100).is_none());
        let ev = s.observe(tick(t0, 40), Some(("a", "job-a")), 250);
        assert!(matches!(ev, Some(StallEvent::Cleared { idle_secs: 40 })));
        // Cleared for good: moving bytes stay quiet.
        assert!(s.observe(tick(t0, 45), Some(("a", "job-a")), 400).is_none());
    }

    #[test]
    fn a_slow_but_moving_transfer_never_opens() {
        // The 31 Jul stall-watchdog lesson: slow is not stalled. Any byte
        // movement between samples resets the clock, however small.
        let t0 = Instant::now();
        let mut s = StallTracker::new(T);
        for i in 0..20u64 {
            assert!(
                s.observe(tick(t0, i * 5), Some(("a", "job-a")), 100 + i)
                    .is_none(),
                "trickle sample {i} must not open an episode"
            );
        }
    }

    #[test]
    fn job_end_mid_episode_reports_ended() {
        let t0 = Instant::now();
        let mut s = StallTracker::new(T);
        assert!(s.observe(t0, Some(("a", "job-a")), 100).is_none());
        assert!(matches!(
            s.observe(tick(t0, 15), Some(("a", "job-a")), 100),
            Some(StallEvent::Opened { .. })
        ));
        let ev = s.observe(tick(t0, 20), None, 0);
        match ev {
            Some(StallEvent::Ended { idle_secs, name }) => {
                assert_eq!(idle_secs, 20);
                assert_eq!(name, "job-a");
            }
            other => panic!("expected Ended, got {}", kind(&other)),
        }
        // Fully reset afterwards.
        assert!(s.observe(tick(t0, 25), None, 0).is_none());
    }

    #[test]
    fn job_switch_resets_the_baseline_and_ends_an_open_episode() {
        let t0 = Instant::now();
        let mut s = StallTracker::new(T);
        assert!(s.observe(t0, Some(("a", "job-a")), 100).is_none());
        assert!(matches!(
            s.observe(tick(t0, 15), Some(("a", "job-a")), 100),
            Some(StallEvent::Opened { .. })
        ));
        // New job appears with an identical byte total (fresh pool also
        // starts at whatever it starts at): the old episode ends and the
        // new job's clock starts from this sample, not the stale one.
        assert!(matches!(
            s.observe(tick(t0, 20), Some(("b", "job-b")), 100),
            Some(StallEvent::Ended { .. })
        ));
        assert!(s.observe(tick(t0, 25), Some(("b", "job-b")), 100).is_none());
        assert!(matches!(
            s.observe(tick(t0, 31), Some(("b", "job-b")), 100),
            Some(StallEvent::Opened { .. })
        ));
    }

    fn kind(ev: &Option<StallEvent>) -> &'static str {
        match ev {
            None => "None",
            Some(StallEvent::Opened { .. }) => "Opened",
            Some(StallEvent::Cleared { .. }) => "Cleared",
            Some(StallEvent::Ended { .. }) => "Ended",
        }
    }
}

#[cfg(test)]
#[path = "tasks_tests.rs"]
mod tasks_tests;
